// 验证撤权同时覆盖存量连接、新建连接和并发拨号。
package main

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// 对端应真正断开而非等待超时，撤权后的拨号也必须失败。
func TestRevokeClosesPeerAndPreventsNewDial(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	gate := newDialGate()
	client, err := gate.dial(context.Background(), "tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	peer, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	peer.SetReadDeadline(time.Now().Add(time.Second))
	gate.revoke()
	if _, err = peer.Read(make([]byte, 1)); err == nil {
		t.Fatal("peer still connected")
	} else if e, ok := err.(net.Error); ok && e.Timeout() {
		t.Fatal("peer only timed out instead of disconnecting")
	}
	if _, err = gate.dial(context.Background(), "tcp", listener.Addr().String(), time.Second); !errors.Is(err, context.Canceled) {
		t.Fatal("new dial was not revoked")
	}
	gate.revoke() // 重复撤权幂等。
}

// 拨号与撤权竞争结束后，登记表中不能残留任何连接。
func TestRevokeRacingDialsLeaveNoConnections(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); c.SetReadDeadline(time.Now().Add(time.Second)); io.Copy(io.Discard, c) }()
		}
	}()
	gate := newDialGate()
	var group sync.WaitGroup
	for i := 0; i < 32; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			c, err := gate.dial(context.Background(), "tcp", listener.Addr().String(), time.Second)
			if err == nil {
				defer c.Close()
				c.SetReadDeadline(time.Now().Add(time.Second))
				io.Copy(io.Discard, c)
			}
		}()
	}
	gate.revoke()
	group.Wait()
	gate.mu.Lock()
	defer gate.mu.Unlock()
	if len(gate.connections) != 0 {
		t.Fatal("connections survived revoke")
	}
}
