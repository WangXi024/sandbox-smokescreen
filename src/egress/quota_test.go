// 验证流量上限属于任务整体，不能靠并发连接或重连规避。
package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// 多个写入者共享同一预算，累计转发量必须精确停在上限。
func TestQuotaSharedAcrossConcurrentConnections(t *testing.T) {
	var total, limits atomic.Int64
	q := &byteQuota{remaining: 1000, code: "NETWORK_UPLOAD_LIMIT", onLimit: func(string) { limits.Add(1) }}
	var workers sync.WaitGroup
	for i := 0; i < 32; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			var destination bytes.Buffer
			io.Copy(quotaWriter{&destination, q}, bytes.NewReader(make([]byte, 333)))
			total.Add(int64(destination.Len()))
		}()
	}
	workers.Wait()
	if total.Load() != 1000 || limits.Load() != 1 {
		t.Fatal("quota overshot, lost, or reset across connections")
	}
	var later bytes.Buffer
	if n, err := (quotaWriter{&later, q}).Write([]byte("late")); n != 0 || err != errQuota {
		t.Fatal("new connection bypassed quota")
	}
}

// 耗尽额度后既要关掉已有连接，也要阻止后续拨号。
func TestQuotaClosesExistingConnectionsAndNewDials(t *testing.T) {
	gate := newDialGate()
	client, peer := net.Pipe()
	defer peer.Close()
	tracked, err := gate.track(client)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := tracked.Read(make([]byte, 1)); done <- err }()
	q := &byteQuota{remaining: 3, onLimit: func(string) { gate.revoke() }}
	var destination bytes.Buffer
	n, err := (quotaWriter{&destination, q}).Write([]byte("abcdef"))
	if n != 3 || err != errQuota || destination.String() != "abc" {
		t.Fatal("forwarded beyond cap")
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("connection remained open")
		}
	case <-time.After(time.Second):
		t.Fatal("revoke did not close connection")
	}
	if _, err := gate.dial(context.Background(), "tcp", "127.0.0.1:1", time.Second); err == nil {
		t.Fatal("dial accepted after exhaustion")
	}
}

// 上传和下载独立扣减，不能把一个方向的流量计入另一个方向。
func TestUploadAndDownloadAreSeparateBudgets(t *testing.T) {
	up := &byteQuota{remaining: 5, onLimit: func(string) {}}
	down := &byteQuota{remaining: 7, onLimit: func(string) {}}
	(quotaWriter{io.Discard, up}).Write([]byte("abc"))
	(quotaWriter{io.Discard, down}).Write([]byte("1234"))
	if up.remaining != 2 || down.remaining != 3 {
		t.Fatal("directions were not accounted independently")
	}
}
