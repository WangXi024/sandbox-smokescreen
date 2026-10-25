package main

import (
	"errors"
	"io"
	"os"
	"sync"
)

const quotaFile = "/tmp/egress-quota"

var errQuota = errors.New("task network quota reached")

// 两个方向分别计数，同方向所有连接共享；先限制转发长度，不能靠重连重置额度。
// 统计隧道中转发的 TLS 字节（含握手），不解密请求内容。
type byteQuota struct {
	mu        sync.Mutex
	remaining int64
	code      string
	onLimit   func(string)
}

type quotaWriter struct {
	writer io.Writer
	quota  *byteQuota
}

// 写入和扣减在同一把锁内完成，确保并发连接也不能超额转发。
func (w quotaWriter) Write(p []byte) (int, error) {
	q := w.quota
	q.mu.Lock()
	if q.remaining == 0 {
		q.mu.Unlock()
		return 0, errQuota
	}
	length := len(p)
	if int64(length) > q.remaining {
		p = p[:q.remaining]
	}
	n, err := w.writer.Write(p)
	q.remaining -= int64(n)
	exhausted := q.remaining == 0
	q.mu.Unlock()
	// 撤权可能关闭连接，回调放在额度锁外执行。
	if exhausted {
		q.onLimit(q.code)
		return n, errQuota
	}
	if n < length && err == nil {
		err = io.ErrShortWrite
	}
	return n, err
}

// 任一方向耗尽都会撤销整个任务；只记录首次触发的超限原因。
func taskQuotas(p policy, gate *dialGate, events *diagnostics) (*byteQuota, *byteQuota) {
	var once sync.Once
	onLimit := func(code string) {
		once.Do(func() {
			// 标记只由可信代理写入，先记录原因，再关闭全部上游连接。
			os.WriteFile(quotaFile, []byte(code), 0600)
			events.record(code)
			gate.revoke()
		})
	}
	return &byteQuota{remaining: p.UploadBytes, code: "NETWORK_UPLOAD_LIMIT", onLimit: onLimit},
		&byteQuota{remaining: p.DownloadBytes, code: "NETWORK_DOWNLOAD_LIMIT", onLimit: onLimit}
}
