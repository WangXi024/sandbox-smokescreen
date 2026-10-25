// TLS 解析只检查握手结构与目标域名，业务正文保持端到端加密。
package main

import (
	"encoding/binary"
	"errors"
	"io"
	"strings"
)

var errHello = errors.New("TLS_HELLO_DENIED")

// 仅窥读有界 ClientHello，不生成证书、不解密 TLS。支持 TCP 和 TLS record 分片。
func readHello(r io.Reader, expected string) ([]byte, error) {
	var wire, hello []byte
	for len(wire) < 65536 {
		header := make([]byte, 5)
		if _, err := io.ReadFull(r, header); err != nil {
			return nil, err
		}
		n := int(binary.BigEndian.Uint16(header[3:]))
		if header[0] != 22 || header[1] != 3 || header[2] > 3 || n == 0 || n > 16384 || len(wire)+5+n > 65536 {
			return nil, errHello
		}
		body := make([]byte, n)
		if _, err := io.ReadFull(r, body); err != nil {
			return nil, err
		}
		wire = append(wire, header...)
		wire = append(wire, body...)
		hello = append(hello, body...)
		if len(hello) < 4 {
			continue
		}
		end := 4 + int(hello[1])<<16 + int(hello[2])<<8 + int(hello[3])
		if hello[0] != 1 || end > 65531 {
			return nil, errHello
		}
		if len(hello) < end {
			continue
		}
		if len(hello) != end || !validHello(hello[4:], expected) {
			return nil, errHello
		}
		return wire, nil
	}
	return nil, errHello
}

// 按长度前缀取出字段，同时推进剩余切片；长度越界即拒绝。
func takeVector(b *[]byte, width int) ([]byte, bool) {
	if len(*b) < width {
		return nil, false
	}
	n := 0
	for _, v := range (*b)[:width] {
		n = n*256 + int(v)
	}
	*b = (*b)[width:]
	if len(*b) < n {
		return nil, false
	}
	value := (*b)[:n]
	*b = (*b)[n:]
	return value, true
}

// 要求完整 TLS ClientHello 和唯一有效 SNI，隐藏域名的扩展不予放行。
func validHello(b []byte, expected string) bool {
	if len(b) < 34 || b[0] != 3 || b[1] != 3 {
		return false
	}
	b = b[34:]
	session, ok := takeVector(&b, 1)
	if !ok || len(session) > 32 {
		return false
	}
	ciphers, ok := takeVector(&b, 2)
	if !ok || len(ciphers) < 2 || len(ciphers)%2 != 0 {
		return false
	}
	compression, ok := takeVector(&b, 1)
	if !ok || len(compression) != 1 || compression[0] != 0 {
		return false
	}
	extensions, ok := takeVector(&b, 2)
	if !ok || len(b) != 0 {
		return false
	}
	seen := map[uint16]bool{}
	name := ""
	for len(extensions) > 0 {
		if len(extensions) < 4 {
			return false
		}
		kind := binary.BigEndian.Uint16(extensions)
		extensions = extensions[2:]
		// 重复扩展及 ECH/ESNI 会让域名检查不明确，因此直接拒绝。
		if seen[kind] || kind == 0xfe0d || kind == 0xffce {
			return false
		}
		seen[kind] = true
		data, ok := takeVector(&extensions, 2)
		if !ok {
			return false
		}
		if kind != 0 {
			continue
		}
		list, ok := takeVector(&data, 2)
		if !ok || len(data) != 0 || len(list) < 3 || list[0] != 0 {
			return false
		}
		list = list[1:]
		host, ok := takeVector(&list, 2)
		if !ok || len(list) != 0 {
			return false
		}
		name = strings.ToLower(strings.TrimSuffix(string(host), "."))
		if !validHost(name) {
			return false
		}
	}
	return name != "" && name == expected
}
