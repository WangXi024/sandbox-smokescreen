package main

import (
	"context"
	"net"
	"os"
	"sync"
	"syscall"
	"time"
)

const revokedFile = "/tmp/egress-revoked"

// 部分 Docker Desktop 内核不支持 ss -K；在代理网络命名空间仍存活时关闭自身 TCP。
type dialGate struct {
	mu          sync.Mutex
	ctx         context.Context
	cancel      context.CancelFunc
	connections map[*trackedConn]bool
}

type trackedConn struct {
	net.Conn
	gate *dialGate
}

func newDialGate() *dialGate {
	ctx, cancel := context.WithCancel(context.Background())
	return &dialGate{ctx: ctx, cancel: cancel, connections: make(map[*trackedConn]bool)}
}

// 任务撤权同时取消尚未完成的拨号；完成的连接仍需在锁内登记。
func (g *dialGate) dial(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	stop := context.AfterFunc(g.ctx, cancel)
	defer stop()
	if g.ctx.Err() != nil {
		return nil, context.Canceled
	}
	c, err := (&net.Dialer{}).DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return g.track(c)
}

// 与撤权共用互斥锁，避免刚建立的连接漏过撤权检查。
func (g *dialGate) track(c net.Conn) (net.Conn, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.ctx.Err() != nil {
		resetConnection(c)
		return nil, context.Canceled
	}
	tracked := &trackedConn{Conn: c, gate: g}
	g.connections[tracked] = true
	return tracked, nil
}

func (c *trackedConn) Close() error {
	c.gate.mu.Lock()
	delete(c.gate.connections, c)
	c.gate.mu.Unlock()
	return c.Conn.Close()
}

// 对 TCP 设置立即复位，尽快通知远端连接已被撤销。
func resetConnection(c net.Conn) {
	if tcp, ok := c.(*net.TCPConn); ok {
		tcp.SetLinger(0)
	}
	c.Close()
}

// 锁内取消并复制连接列表，锁外关闭，避免 Close 再取同一把锁时死锁。
func (g *dialGate) revoke() {
	g.mu.Lock()
	g.cancel()
	connections := make([]*trackedConn, 0, len(g.connections))
	for c := range g.connections {
		connections = append(connections, c)
	}
	g.mu.Unlock()
	for _, c := range connections {
		resetConnection(c.Conn)
		c.Close()
	}
}

// 通过容器主进程接收信号并等待完成标记；重复调用直接成功。
func requestRevoke() error {
	if _, err := os.Stat(revokedFile); err == nil {
		return nil
	}
	if err := syscall.Kill(1, syscall.SIGUSR1); err != nil {
		return err
	}
	for end := time.Now().Add(2 * time.Second); time.Now().Before(end); {
		if _, err := os.Stat(revokedFile); err == nil {
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return context.DeadlineExceeded
}
