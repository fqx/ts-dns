package utils

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync"
	"time"

	ping "github.com/prometheus-community/pro-bing"
)

// FastestPingIPContext cancels and joins losing probes before returning, so a
// succession of background refreshes cannot accumulate detached ping goroutines.
func FastestPingIPContext(parent context.Context, addresses []string, tcpPort int, timeout time.Duration) (string, int64, error) {
	ctx, cancel := context.WithTimeout(parent, timeout)
	var wg sync.WaitGroup
	defer func() { cancel(); wg.Wait() }()
	if ctx.Err() != nil {
		return "", 0, ctx.Err()
	}
	begin := time.Now()
	const maxProbes = 15
	done := make(chan string, maxProbes)
	seen := make(map[string]bool, maxProbes)
	for _, addr := range addresses {
		if seen[addr] {
			continue
		}
		if len(seen) >= maxProbes {
			break
		}
		seen[addr] = true
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
			if err := pingIPContext(ctx, addr, tcpPort, timeout); err == nil {
				done <- addr
			}
		}(addr)
	}
	select {
	case addr := <-done:
		return addr, time.Since(begin).Milliseconds(), nil
	case <-ctx.Done():
		return "", 0, ctx.Err()
	}
}
func pingIPContext(ctx context.Context, addr string, tcpPort int, timeout time.Duration) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if tcpPort > 0 {
		conn, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", net.JoinHostPort(addr, strconv.Itoa(tcpPort)))
		if err != nil {
			return err
		}
		return conn.Close()
	}
	task, err := ping.NewPinger(addr)
	if err != nil {
		return err
	}
	task.Count, task.Timeout = 1, timeout
	task.SetPrivileged(true)
	if err := task.RunWithContext(ctx); err != nil {
		return err
	}
	if task.Statistics().PacketsRecv == 0 {
		return errors.New("packet loss")
	}
	return nil
}
