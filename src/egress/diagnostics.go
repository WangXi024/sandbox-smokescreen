package main

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/stripe/smokescreen/pkg/smokescreen"
)

const diagnosticDir = "/tmp/egress-diagnostics"
const diagnosticLimit = 64 * 1024

// 只输出固定类别，不接收域名、URL、请求头、正文或原始错误文本。
var diagnosticMessages = map[string]string{
	"NETWORK_UPLOAD_LIMIT":   "任务累计上传流量已达上限，全部连接已关闭",
	"NETWORK_DOWNLOAD_LIMIT": "任务累计下载流量已达上限，全部连接已关闭",
	"PROXY_READY":            "出网代理已就绪",
	"PROXY_REVOKED":          "出网授权已撤销，连接已关闭",
	"POLICY_INVALID":         "代理策略无效，启动已停止",
	"PROXY_INIT_FAILED":      "代理初始化失败",
	"PROXY_STOPPED":          "代理监听已停止",
	"REQUEST_DENIED":         "请求格式或端口不符合出网要求",
	"SOURCE_DENIED":          "请求来源未获准",
	"DOMAIN_DENIED":          "目标域名未获准",
	"POLICY_DENIED":          "出网策略拒绝请求，请检查目标地址和授权",
	"DNS_FAILED":             "DNS 解析失败",
	"DNS_TIMEOUT":            "DNS 解析超时",
	"CONNECT_FAILED":         "连接目标服务失败",
	"CONNECT_TIMEOUT":        "连接目标服务超时",
	"TUNNEL_LIMIT":           "并发连接已达上限",
	"TLS_DENIED":             "TLS 握手不符合要求，请检查域名一致性、SNI 和 ECH",
	"TLS_TIMEOUT":            "等待 TLS 握手超时",
	"TLS_READ_FAILED":        "读取 TLS 握手失败或客户端已断开",
	"TUNNEL_OPEN":            "TLS 检查通过，开始转发",
	"TUNNEL_CLOSED":          "代理隧道已关闭",
	"TUNNEL_TIMEOUT":         "代理隧道已超时",
	"TUNNEL_IO_FAILED":       "代理隧道读写失败",
	"PROXY_ERROR":            "代理内部异常",
}

type diagnostics struct {
	mu  sync.Mutex
	dir string
}

// 事件只接受预定义代码；未知输入统一归类，不能混入请求或凭据文本。
func (d *diagnostics) record(code string) {
	if d == nil {
		return
	}
	message, ok := diagnosticMessages[code]
	if !ok {
		code, message = "PROXY_ERROR", diagnosticMessages["PROXY_ERROR"]
	}
	line, _ := json.Marshal(struct {
		Time    string `json:"time"`
		Code    string `json:"code"`
		Message string `json:"message"`
	}{time.Now().UTC().Format(time.RFC3339Nano), code, message})
	line = append(line, '\n')
	d.mu.Lock()
	defer d.mu.Unlock()
	// 容器 /tmp 已挂载 tmpfs；最多保留两份 64 KiB 日志，不启用 Docker 落盘日志。
	if os.MkdirAll(d.dir, 0700) != nil {
		return
	}
	path := filepath.Join(d.dir, "events.jsonl")
	if info, err := os.Stat(path); err == nil && info.Size()+int64(len(line)) > diagnosticLimit {
		if os.Rename(path, path+".1") != nil {
			return
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return // 日志故障不改变访问决策，也不降级为输出原始请求。
	}
	defer f.Close()
	f.Write(line)
}

// 先读取轮转文件再读取当前文件，每份读取都有大小上限。
func readDiagnostics(w io.Writer, dir string) error {
	for _, name := range []string{"events.jsonl.1", "events.jsonl"} {
		f, err := os.Open(filepath.Join(dir, name))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		_, err = io.Copy(w, io.LimitReader(f, diagnosticLimit))
		f.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

// 用状态和决策阶段区分故障，只输出固定类别，不记录上游原始错误。
func rejectionCode(ctx *smokescreen.SmokescreenContext, status int) string {
	decision := ctx.Decision
	switch status {
	case http.StatusProxyAuthRequired:
		if decision != nil {
			switch decision.Reason {
			case "Client role cannot be determined":
				return "SOURCE_DENIED"
			case "rule has enforce policy":
				return "DOMAIN_DENIED"
			}
		}
		return "POLICY_DENIED"
	case http.StatusTooManyRequests:
		return "TUNNEL_LIMIT"
	case http.StatusBadGateway, http.StatusGatewayTimeout:
		prefix := "CONNECT"
		if decision != nil && decision.ResolvedAddr == nil {
			prefix = "DNS"
		}
		if status == http.StatusGatewayTimeout {
			return prefix + "_TIMEOUT"
		}
		return prefix + "_FAILED"
	default:
		return "PROXY_ERROR"
	}
}
