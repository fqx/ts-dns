package outbound

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/wolf-joe/go-ipset/ipset"
)

type cancelingResolver struct{ started, stopped chan struct{} }

func (*cancelingResolver) ServeDNS(dns.ResponseWriter, *dns.Msg) {
	panic("bootstrap must use contextual resolver")
}
func (r *cancelingResolver) ServeDNSContext(ctx context.Context, _ dns.ResponseWriter, _ *dns.Msg) {
	close(r.started)
	<-ctx.Done()
	close(r.stopped)
}

func TestDoHBootstrapCancellation(t *testing.T) {
	r := &cancelingResolver{started: make(chan struct{}), stopped: make(chan struct{})}
	caller, err := NewDoHCallerV2("https://resolver.example.invalid/dns-query", nil)
	if err != nil {
		t.Fatal(err)
	}
	caller.Start(r)
	defer caller.Exit()
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { _, err := caller.CallContext(ctx, q); result <- err }()
	select {
	case <-r.started:
	case <-time.After(time.Second):
		t.Fatal("bootstrap did not start")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("bootstrap lost cancellation: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("bootstrap caller blocked after cancellation")
	}
	select {
	case <-r.stopped:
	case <-time.After(time.Second):
		t.Fatal("bootstrap resolver leaked after cancellation")
	}
}
func TestDoHRequestCancellation(t *testing.T) {
	started := make(chan struct{})
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		close(started)
		<-r.Context().Done()
	}))
	defer s.Close()
	c := &DoHCallerV2{url: s.URL, clients: []*http.Client{s.Client()}}
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { _, err := c.CallContext(ctx, q); result <- err }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("DoH request did not start")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("DoH lost cancellation: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("DoH request outlived cancellation")
	}
}
func TestIPSetBackgroundCancellation(t *testing.T) {
	if os.PathSeparator == '\\' {
		t.Skip("shell fixture requires Unix")
	}
	dir := t.TempDir()
	marker := filepath.Join(dir, "started")
	script := filepath.Join(dir, "ipset")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf started > \"$TS_DNS_IPSET_MARKER\"\nexec sleep 30\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("TS_DNS_IPSET_MARKER", marker)
	wrapper := ipSetWrapper{&ipset.IPSet{Name: "test"}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- wrapper.AddContext(ctx, "192.0.2.1", 1) }()
	deadline := time.Now().Add(time.Second)
	for {
		if _, err := os.Stat(marker); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("helper did not start")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled helper succeeded")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("helper survived refresh cancellation")
	}
}
