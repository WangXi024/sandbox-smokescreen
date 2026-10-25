// 用本地 HTTPS 测试服务核对 DoH 桥接和证书保护。
package main

import (
	"context"
	"encoding/binary"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// 成功响应保留 DNS 编号和长度帧，HTTP 失败则关闭连接。
func TestDoHFramingAndFailure(t *testing.T) {
	for _, status := range []int{200, 500} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "POST" || r.Header.Get("Content-Type") != "application/dns-message" {
				t.Error("invalid query")
			}
			wire, _ := io.ReadAll(r.Body)
			w.Header().Set("Content-Type", "application/dns-message")
			w.WriteHeader(status)
			wire[2] |= 0x80
			w.Write(wire)
		}))
		conn, _ := dohDial(context.Background(), server.Client(), server.URL)
		query := make([]byte, 14)
		binary.BigEndian.PutUint16(query, 12)
		query[2] = 17
		query[3] = 19
		conn.Write(query)
		answer := make([]byte, 14)
		_, err := io.ReadFull(conn, answer)
		if status == 200 && (err != nil || answer[2] != 17 || answer[4]&0x80 == 0) {
			t.Error("DNS response mismatch")
		}
		if status != 200 && err == nil {
			t.Error("DNS failure must close connection")
		}
		conn.Close()
		server.Close()
	}
}

// 不受信任的 TLS 证书必须导致失败，不能跳过验证继续解析。
func TestDoHRejectsUntrustedCertificate(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("untrusted endpoint reached") }))
	defer server.Close()
	conn, _ := dohDial(context.Background(), &http.Client{}, server.URL)
	defer conn.Close()
	query := make([]byte, 14)
	binary.BigEndian.PutUint16(query, 12)
	conn.Write(query)
	if _, err := conn.Read(make([]byte, 2)); err == nil {
		t.Fatal("untrusted certificate accepted")
	}
}
