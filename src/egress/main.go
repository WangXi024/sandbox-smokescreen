// Smokescreen 负责白名单、解析后 IP 检查和转发；本入口补上任务身份与 TLS 握手检查。
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/stripe/goproxy"
	"github.com/stripe/smokescreen/pkg/smokescreen"
	acl "github.com/stripe/smokescreen/pkg/smokescreen/acl/v1"
	"github.com/stripe/smokescreen/pkg/smokescreen/conntrack"
)

const revision = "7d0ddfa7589936fc0117b89cddb7e3a4ef72fba8"

// 每个任务拥有独立策略；来源 IP、域名和额度均由管理服务生成。
type policy struct {
	GuestIP       string   `json:"guest_ip"`
	Allowed       []string `json:"allowed_domains"`
	DNS           string   `json:"dns_server"`
	DenyRanges    []string `json:"deny_ranges"`
	FixtureIP     string   `json:"fixture_ip"`
	MaxTunnels    int      `json:"max_tunnels"`
	DNSOverHTTPS  bool     `json:"dns_over_https"`
	UploadBytes   int64    `json:"upload_bytes"`
	DownloadBytes int64    `json:"download_bytes"`
}

var label = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// goproxy 的 Hijack 路径忽略 bufio.Reader；保留提前随 CONNECT 到达的握手字节。
type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c bufferedConn) Read(b []byte) (int, error) { return c.reader.Read(b) }

type bufferedWriter struct{ http.ResponseWriter }

func (w bufferedWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	c, rw, err := w.ResponseWriter.(http.Hijacker).Hijack()
	if err != nil {
		return nil, nil, err
	}
	return bufferedConn{c, rw.Reader}, rw, nil
}

// 只允许规范域名，拒绝 IP 字面量，避免绕过域名白名单。
func validHost(host string) bool {
	if len(host) == 0 || len(host) > 253 || net.ParseIP(host) != nil {
		return false
	}
	for _, part := range strings.Split(host, ".") {
		if !label.MatchString(part) {
			return false
		}
	}
	return true
}

// 策略缺项、未知字段或多余 JSON 都拒绝启动，避免误用默认权限。
func readPolicy(path string) (policy, error) {
	var p policy
	f, err := os.Open(path)
	if err != nil {
		return p, err
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 65537))
	d.DisallowUnknownFields()
	if err = d.Decode(&p); err != nil {
		return p, err
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return p, errors.New("extra policy data")
	}
	if net.ParseIP(p.GuestIP).To4() == nil || net.ParseIP(p.DNS).To4() == nil ||
		len(p.Allowed) > 32 || p.MaxTunnels < 1 || p.MaxTunnels > 32 || len(p.DenyRanges) == 0 ||
		p.UploadBytes < 1 || p.DownloadBytes < 1 || p.UploadBytes > 128*1024*1024 || p.DownloadBytes > 128*1024*1024 {
		return p, errors.New("invalid policy")
	}
	if p.FixtureIP != "" && net.ParseIP(p.FixtureIP).To4() == nil {
		return p, errors.New("invalid fixture")
	}
	for _, host := range p.Allowed {
		if !validHost(host) {
			return p, errors.New("invalid hostname")
		}
	}
	return p, nil
}

// 组合上游 ACL、目标 IP 检查和本地 TLS/流量规则，生成任务专属代理。
func newHandler(p policy, events *diagnostics, gate *dialGate) (http.Handler, error) {
	upload, download := taskQuotas(p, gate, events)
	cfg := smokescreen.NewConfig()
	// 上游详细日志可能包含敏感字段；仅将拒绝原因映射为固定中文诊断。
	cfg.Log.SetOutput(io.Discard)
	cfg.RejectResponseHandlerWithCtx = func(ctx *smokescreen.SmokescreenContext, response *http.Response) {
		events.record(rejectionCode(ctx, response.StatusCode))
	}
	cfg.Network = "ip4"
	cfg.ConnectTimeout = 3 * time.Second
	cfg.ProxyDialTimeout = gate.dial
	cfg.DNSTimeout = 3 * time.Second
	cfg.ShuttingDown.Store(false)
	cfg.ConnTracker = conntrack.NewTracker(0, cfg.MetricsClient, cfg.Log, cfg.ShuttingDown, nil)
	cfg.TunnelLimiter = smokescreen.NewTunnelLimiter(p.MaxTunnels, cfg)
	cfg.Resolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, network, net.JoinHostPort(p.DNS, "53"))
	}}
	if p.DNSOverHTTPS {
		// 需要 DoH 时使用固定解析端点，不接收脚本指定的 DNS 服务。
		cfg.Resolver = buildResolver()
	}
	if err := cfg.SetDenyRanges(p.DenyRanges); err != nil {
		return nil, err
	}
	// 仅管理器显式 test-mode 生成的合成源站例外；正常任务没有这一字段。
	if p.FixtureIP != "" {
		if err := cfg.SetAllowAddresses([]string{p.FixtureIP + ":443"}); err != nil {
			return nil, err
		}
	}
	if err := cfg.InitializeSelfConnectionDetection(); err != nil {
		return nil, err
	}
	cfg.RoleFromRequest = func(r *http.Request) (string, error) {
		source, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil || source != p.GuestIP {
			return "", errors.New("source denied")
		}
		return "task", nil
	}
	cfg.EgressACL = &acl.ACL{Logger: cfg.Log, Rules: map[string]acl.Rule{
		"task": {Project: "sandbox", Policy: acl.Enforce, DomainGlobs: p.Allowed},
	}}
	proxy := smokescreen.BuildProxy(cfg)
	proxy.Logger = log.New(io.Discard, "", 0)
	// 这个回调由上游在 CONNECT 成功后调用；未经验证的握手不会转发给源站。
	proxy.ConnectCopyHandler = func(ctx *goproxy.ProxyCtx, client, upstream net.Conn) {
		tracked, trackErr := gate.track(client)
		if trackErr != nil {
			upstream.Close()
			return
		}
		client = tracked
		defer client.Close()
		defer upstream.Close()
		defer func() {
			if recover() != nil {
				events.record("PROXY_ERROR")
			}
		}() // 解析意外也关闭两端，不降级为直接转发。
		host, _, err := net.SplitHostPort(ctx.Req.Host)
		if err != nil {
			events.record("REQUEST_DENIED")
			return
		}
		client.SetDeadline(time.Now().Add(5 * time.Second))
		// CONNECT 声明的域名必须与 ClientHello 的 SNI 一致，才转发握手。
		wire, err := readHello(client, host)
		if err != nil {
			code := "TLS_READ_FAILED"
			if errors.Is(err, errHello) {
				code = "TLS_DENIED"
			} else if e, ok := err.(net.Error); ok && e.Timeout() {
				code = "TLS_TIMEOUT"
			}
			events.record(code)
			return
		}
		deadline := time.Now().Add(20 * time.Second)
		client.SetDeadline(deadline)
		upstream.SetDeadline(deadline)
		events.record("TUNNEL_OPEN")
		if _, err = io.Copy(quotaWriter{upstream, upload}, bytes.NewReader(wire)); err != nil {
			events.record("TUNNEL_IO_FAILED")
			return
		}
		// 上下行并行转发，任一侧结束就关闭两端，并等待另一侧退出。
		done := make(chan error, 1)
		go func() {
			_, copyErr := io.Copy(quotaWriter{upstream, upload}, client)
			upstream.Close()
			client.Close()
			done <- copyErr
		}()
		_, err = io.Copy(quotaWriter{client, download}, upstream)
		client.Close()
		upstream.Close()
		clientErr := <-done
		code := "TUNNEL_CLOSED"
		for _, copyErr := range []error{err, clientErr} {
			if e, ok := copyErr.(net.Error); ok && e.Timeout() {
				code = "TUNNEL_TIMEOUT"
				break
			}
			if copyErr != nil && !errors.Is(copyErr, net.ErrClosed) {
				code = "TUNNEL_IO_FAILED"
			}
		}
		events.record(code)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if gate.ctx.Err() != nil {
			http.Error(w, "task network closed", http.StatusForbidden)
			return
		}
		host, port, err := net.SplitHostPort(r.Host)
		host = strings.ToLower(strings.TrimSuffix(host, "."))
		if r.Method != http.MethodConnect || err != nil || port != "443" || !validHost(host) ||
			r.ContentLength > 0 || len(r.TransferEncoding) != 0 {
			events.record("REQUEST_DENIED")
			http.Error(w, "denied", http.StatusForbidden)
			return
		}
		// 不接受客户端自报角色、上游代理或转发来源；身份只取实际 TCP 源地址。
		r.Header = make(http.Header)
		r.Host = net.JoinHostPort(host, "443")
		r.URL.Host = r.Host
		proxy.ServeHTTP(bufferedWriter{w}, r)
	}), nil
}

// 诊断、撤权和健康检查共用同一二进制；常规启动才监听代理端口。
func main() {
	path := flag.String("config", "/etc/egress/policy.json", "task policy")
	health := flag.Bool("healthcheck", false, "check local listener")
	version := flag.Bool("version", false, "show pinned upstream")
	showLogs := flag.Bool("logs", false, "查看当前代理的中文诊断日志")
	revoke := flag.Bool("revoke", false, "仅供管理器撤销本代理连接")
	quotaStatus := flag.Bool("quota-status", false, "仅供管理器读取任务流量超限原因")
	flag.Parse()
	if *quotaStatus {
		data, err := os.ReadFile(quotaFile)
		if err == nil && (string(data) == "NETWORK_UPLOAD_LIMIT" || string(data) == "NETWORK_DOWNLOAD_LIMIT") {
			println(string(data))
		}
		return
	}
	if *revoke {
		if requestRevoke() != nil {
			os.Exit(1)
		}
		println("REVOKED")
		return
	}
	if *showLogs {
		if readDiagnostics(os.Stdout, diagnosticDir) != nil {
			log.Print("LOG_READ_FAILED")
			os.Exit(1)
		}
		return
	}
	if *version {
		println("smokescreen " + revision)
		return
	}
	if *health {
		c, err := net.DialTimeout("tcp", "127.0.0.1:3128", 200*time.Millisecond)
		if err != nil {
			os.Exit(1)
		}
		c.Close()
		return
	}
	events := &diagnostics{dir: diagnosticDir}
	p, err := readPolicy(*path)
	if err != nil {
		events.record("POLICY_INVALID")
		log.Print("POLICY_INVALID")
		os.Exit(1)
	}
	gate := newDialGate()
	h, err := newHandler(p, events, gate)
	if err != nil {
		events.record("PROXY_INIT_FAILED")
		log.Print("PROXY_INIT_FAILED")
		os.Exit(1)
	}
	// 管理器发送 SIGUSR1 后，先撤销连接，再写入完成标记供调用方确认。
	os.Remove(revokedFile)
	revocations := make(chan os.Signal, 1)
	signal.Notify(revocations, syscall.SIGUSR1)
	go func() {
		for range revocations {
			gate.revoke()
			if os.WriteFile(revokedFile, nil, 0600) == nil {
				events.record("PROXY_REVOKED")
			}
		}
	}()
	server := &http.Server{Addr: ":3128", Handler: h, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 8 * time.Second, WriteTimeout: 8 * time.Second, IdleTimeout: 5 * time.Second,
		MaxHeaderBytes: 8192, ErrorLog: log.New(io.Discard, "", 0)}
	listener, err := net.Listen("tcp", server.Addr)
	if err == nil {
		events.record("PROXY_READY")
		err = server.Serve(listener)
	}
	if err != nil {
		events.record("PROXY_STOPPED")
		log.Print("PROXY_STOPPED")
		os.Exit(1)
	}
}
