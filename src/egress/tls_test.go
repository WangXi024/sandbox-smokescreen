// 使用合成 TLS 字节验证域名检查，不连接真实第三方服务。
package main

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func vector(b []byte, width int) []byte {
	out := make([]byte, width)
	for n, i := len(b), width-1; i >= 0; i-- {
		out[i] = byte(n)
		n >>= 8
	}
	return append(out, b...)
}

func extension(kind uint16, b []byte) []byte {
	return append([]byte{byte(kind >> 8), byte(kind)}, vector(b, 2)...)
}

// 构造最小 ClientHello，便于分别加入错误域名和不允许的扩展。
func hello(host string, extra []byte) []byte {
	body := append([]byte{3, 3}, make([]byte, 32)...)
	body = append(body, 0, 0, 2, 0x13, 1, 1, 0)
	var ext []byte
	if host != "" {
		ext = extension(0, vector(append([]byte{0}, vector([]byte(host), 2)...), 2))
	}
	ext = append(ext, extra...)
	body = append(body, vector(ext, 2)...)
	return append([]byte{1}, vector(body, 3)...)
}

func record(b []byte) []byte { return append([]byte{22, 3, 1}, vector(b, 2)...) }

type singleByteReader struct{ *bytes.Reader }

func (r singleByteReader) Read(b []byte) (int, error) {
	if len(b) > 1 {
		b = b[:1]
	}
	return r.Reader.Read(b)
}

// TCP 单字节读取和 TLS record 分片都应保留完整、正确的握手字节。
func TestHelloAllowAndFragmentation(t *testing.T) {
	h := hello("allowed.test", nil)
	for _, wire := range [][]byte{record(h), append(record(h[:2]), record(h[2:])...), record(hello("ALLOWED.test.", nil))} {
		got, err := readHello(singleByteReader{bytes.NewReader(wire)}, "allowed.test")
		if err != nil || !bytes.Equal(got, wire) {
			t.Fatal("valid fragmented hello rejected", err)
		}
	}
}

// 缺少或错误 SNI、加密域名扩展及损坏握手都必须拒绝。
func TestHelloRejects(t *testing.T) {
	good := record(hello("allowed.test", nil))
	badLength := append([]byte(nil), good...)
	binary.BigEndian.PutUint16(badLength[3:5], 65535)
	tests := map[string][]byte{
		"missing-sni":      record(hello("", nil)),
		"wrong-sni":        record(hello("blocked.test", nil)),
		"ip-sni":           record(hello("127.0.0.1", nil)),
		"ech":              record(hello("allowed.test", extension(0xfe0d, []byte{1}))),
		"esni":             record(hello("allowed.test", extension(0xffce, nil))),
		"duplicate":        record(hello("allowed.test", extension(0, nil))),
		"plain-http":       []byte("GET / HTTP/1.1\r\n"),
		"oversize-record":  badLength,
		"truncated":        good[:len(good)-1],
		"extra-handshake":  record(append(hello("allowed.test", nil), 0)),
		"broken-extension": record(hello("allowed.test", []byte{1, 2, 3})),
	}
	for name, wire := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := readHello(bytes.NewReader(wire), "allowed.test"); err == nil {
				t.Fatal("invalid hello accepted")
			}
		})
	}
}

// 握手检查不得预读后续应用数据，避免转发内容丢失。
func TestHelloDoesNotConsumeApplicationData(t *testing.T) {
	wire := record(hello("allowed.test", nil))
	r := bytes.NewReader(append(wire, 1, 2, 3))
	if _, err := readHello(r, "allowed.test"); err != nil {
		t.Fatal(err)
	}
	tail, _ := io.ReadAll(r)
	if !bytes.Equal(tail, []byte{1, 2, 3}) {
		t.Fatal("consumed beyond hello")
	}
}

// 不完整、未知字段和不受支持的域名策略不能被当作有效配置。
func TestPolicyRejectsIncompleteAndAmbiguousConfig(t *testing.T) {
	for _, value := range []string{`{}`, `{`, `{"guest_ip":"127.0.0.1","allowed_domains":["*.test"],"dns_server":"1.1.1.1","deny_ranges":["127.0.0.0/8"],"max_tunnels":32}`, `{"unknown":true}`} {
		p := filepath.Join(t.TempDir(), "policy.json")
		os.WriteFile(p, []byte(value), 0600)
		if _, err := readPolicy(p); err == nil {
			t.Fatal("invalid policy accepted")
		}
	}
}

// 任意字节输入不能引起解析器崩溃。
func FuzzHello(f *testing.F) {
	f.Add(record(hello("allowed.test", nil)))
	f.Add([]byte("GET /"))
	f.Fuzz(func(t *testing.T, b []byte) { readHello(bytes.NewReader(b), "allowed.test") })
}
