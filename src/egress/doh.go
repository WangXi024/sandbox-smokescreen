package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// 构建包源和启用 DoH 的普通任务使用固定公共解析端点；不接受任务自报解析器。
// net.Resolver 对非 PacketConn 使用带长度前缀的 DNS 流，桥接为一次 HTTPS 请求。
func dohDial(ctx context.Context, client *http.Client, endpoint string) (net.Conn, error) {
	local, remote := net.Pipe()
	remote.SetDeadline(time.Now().Add(3 * time.Second))
	go func() {
		defer remote.Close()
		header := make([]byte, 2)
		if _, err := io.ReadFull(remote, header); err != nil {
			return
		}
		size := int(binary.BigEndian.Uint16(header))
		if size < 12 || size > 4096 {
			return
		}
		wire := make([]byte, size)
		if _, err := io.ReadFull(remote, wire); err != nil {
			return
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(wire))
		if err != nil {
			return
		}
		request.Header.Set("Content-Type", "application/dns-message")
		request.Header.Set("Accept", "application/dns-message")
		response, err := client.Do(request)
		if err != nil {
			return
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "application/dns-message" {
			return
		}
		// 限制响应长度并核对事务编号与响应位，错误响应直接关闭 DNS 流。
		answer, err := io.ReadAll(io.LimitReader(response.Body, 65536))
		if err != nil || len(answer) < 12 || len(answer) > 65535 || !bytes.Equal(answer[:2], wire[:2]) || answer[2]&0x80 == 0 {
			return
		}
		binary.BigEndian.PutUint16(header, uint16(len(answer)))
		if _, err = remote.Write(append(header, answer...)); err != nil {
			return
		}
	}()
	return local, nil
}

// DNS 请求直连固定端点，保留系统证书校验并拒绝 HTTP 重定向。
func buildResolver() *net.Resolver {
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return fmt.Errorf("DNS redirect refused") }}
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _ string, _ string) (net.Conn, error) {
		return dohDial(ctx, client, "https://1.1.1.1/dns-query")
	}}
}
