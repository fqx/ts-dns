package utils

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestFastestPingContextAndCancellation(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	ip, _, err := FastestPingIPContext(context.Background(), []string{"127.0.0.1", "127.0.0.1"}, port, time.Second)
	if err != nil || ip != "127.0.0.1" {
		t.Fatalf("local probe failed: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := FastestPingIPContext(ctx, []string{"127.0.0.1"}, port, time.Second); !errors.Is(err, context.Canceled) {
		t.Fatal("probe lost cancellation")
	}
	listener.Close()
	<-done
}
