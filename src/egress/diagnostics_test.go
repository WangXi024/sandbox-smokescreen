// 验证诊断日志有界、可并发写入，并且不会记录请求中的敏感内容。
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stripe/smokescreen/pkg/smokescreen"
)

func diagnosticOutput(t *testing.T, d *diagnostics) string {
	t.Helper()
	var out bytes.Buffer
	if err := readDiagnostics(&out, d.dir); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

// 并发事件仍须生成完整 JSON 行，轮转后保留最新事件且权限受限。
func TestDiagnosticRotationAndConcurrentWrites(t *testing.T) {
	d := &diagnostics{dir: t.TempDir()}
	var group sync.WaitGroup
	for i := 0; i < 8; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for j := 0; j < 200; j++ {
				d.record("DOMAIN_DENIED")
			}
		}()
	}
	group.Wait()
	d.record("PROXY_READY")
	for _, name := range []string{"events.jsonl", "events.jsonl.1"} {
		info, err := os.Stat(filepath.Join(d.dir, name))
		if err != nil || info.Size() > diagnosticLimit || info.Mode().Perm() != 0600 {
			t.Fatalf("unbounded or unprotected log: %s", name)
		}
	}
	out := diagnosticOutput(t, d)
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		var event map[string]string
		if json.Unmarshal([]byte(line), &event) != nil || len(event) != 3 ||
			event["message"] != diagnosticMessages[event["code"]] {
			t.Fatal("invalid or unexpected log fields")
		}
	}
	if !strings.Contains(out, "出网代理已就绪") {
		t.Fatal("latest event lost")
	}
}

// 未知事件和写入故障都不能引出未经筛选的文本。
func TestDiagnosticUnknownInputAndWriteFailure(t *testing.T) {
	d := &diagnostics{dir: t.TempDir()}
	d.record("synthetic-secret\nFAKE_EVENT")
	out := diagnosticOutput(t, d)
	if strings.Contains(out, "synthetic-secret") || !strings.Contains(out, "PROXY_ERROR") {
		t.Fatal("untrusted event leaked")
	}
	// 存储不可写时不能 panic 或转而输出未经筛选的文本。
	d.dir = filepath.Join(d.dir, "events.jsonl", "not-a-directory")
	d.record("DOMAIN_DENIED")
}

// 合成凭据只用于检查不泄露，日志应包含拒绝类别而非原始请求。
func TestRejectedRequestsProduceSafeDiagnostics(t *testing.T) {
	for _, tc := range []struct{ name, guest, method, host, code string }{
		{"domain", "127.0.0.1", "CONNECT", "synthetic-secret.test:443", "DOMAIN_DENIED"},
		{"source", "192.0.2.1", "CONNECT", "allowed.test:443", "SOURCE_DENIED"},
		{"format", "127.0.0.1", "GET", "synthetic-secret.test:443", "REQUEST_DENIED"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := &diagnostics{dir: t.TempDir()}
			p := policy{GuestIP: tc.guest, DNS: "127.0.0.2", Allowed: []string{"allowed.test"},
				DenyRanges: []string{"127.0.0.0/8"}, MaxTunnels: 1}
			h, err := newHandler(p, d, newDialGate())
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewServer(h)
			defer server.Close()
			conn, err := net.DialTimeout("tcp", server.Listener.Addr().String(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			fmt.Fprintf(conn, "%s %s HTTP/1.1\r\nHost: %s\r\nAuthorization: Bearer synthetic-secret\r\nCookie: synthetic-secret\r\nProxy-Authorization: synthetic-secret\r\n\r\n", tc.method, tc.host, tc.host)
			resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err != nil {
				t.Fatal(err)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode < 400 {
				t.Fatal("request unexpectedly allowed")
			}
			out := diagnosticOutput(t, d)
			if !strings.Contains(out, tc.code) || strings.Contains(out, "synthetic-secret") || strings.Contains(out, tc.host) {
				t.Fatalf("wrong or unsafe diagnostic: %s", out)
			}
		})
	}
}

// 已解析地址与否决定归为连接故障还是 DNS 故障。
func TestRejectionClassification(t *testing.T) {
	for _, tc := range []struct {
		status   int
		resolved bool
		code     string
	}{
		{502, false, "DNS_FAILED"}, {504, false, "DNS_TIMEOUT"},
		{502, true, "CONNECT_FAILED"}, {504, true, "CONNECT_TIMEOUT"},
		{429, true, "TUNNEL_LIMIT"}, {500, false, "PROXY_ERROR"},
		{407, false, "POLICY_DENIED"},
	} {
		ctx := &smokescreen.SmokescreenContext{Decision: &smokescreen.ACLDecision{}}
		if tc.resolved {
			ctx.Decision.ResolvedAddr = &net.TCPAddr{}
		}
		if code := rejectionCode(ctx, tc.status); code != tc.code {
			t.Fatalf("status %d: want %s, got %s", tc.status, tc.code, code)
		}
	}
}
