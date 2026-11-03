package outbound

import (
	"context"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/wolf-joe/ts-dns/config"
	"github.com/wolf-joe/ts-dns/matcher"
)

type pipeDialer struct{ serve func(net.Conn) }

func (d pipeDialer) Dial(n, a string) (net.Conn, error) {
	return d.DialContext(context.Background(), n, a)
}
func (d pipeDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	c, s := net.Pipe()
	go func() { defer s.Close(); d.serve(s) }()
	return c, nil
}

func TestProxyConcurrentOwnership(t *testing.T) {
	d := pipeDialer{serve: func(c net.Conn) {
		dc := &dns.Conn{Conn: c}
		q, e := dc.ReadMsg()
		if e != nil {
			return
		}
		r := new(dns.Msg)
		r.SetReply(q)
		_ = dc.WriteMsg(r)
	}}
	caller := NewDNSCaller("unused:53", "tcp", d)
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			q := new(dns.Msg)
			q.SetQuestion("example.com.", dns.TypeA)
			q.Id = uint16(id)
			r, e := caller.Call(q)
			if e != nil || r.Id != q.Id {
				t.Errorf("call %d: %v", id, e)
			}
		}(i)
	}
	wg.Wait()
}
func TestProxyRejectsMismatch(t *testing.T) {
	for _, kind := range []string{"id", "question", "qr"} {
		t.Run(kind, func(t *testing.T) {
			d := pipeDialer{serve: func(c net.Conn) {
				dc := &dns.Conn{Conn: c}
				q, e := dc.ReadMsg()
				if e != nil {
					return
				}
				r := new(dns.Msg)
				r.SetReply(q)
				switch kind {
				case "id":
					r.Id++
				case "question":
					r.Question[0].Qtype = dns.TypeAAAA
				case "qr":
					r.Response = false
				}
				_ = dc.WriteMsg(r)
			}}
			q := new(dns.Msg)
			q.SetQuestion("example.com.", dns.TypeA)
			if _, e := NewDNSCaller("unused:53", "tcp", d).Call(q); e == nil {
				t.Fatal("accepted invalid reply")
			}
		})
	}
}
func TestDoHBoundsAndValidation(t *testing.T) {
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	for _, kind := range []string{"valid", "status", "oversize", "mismatch", "timeout"} {
		t.Run(kind, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				switch kind {
				case "status":
					w.WriteHeader(500)
				case "oversize":
					_, _ = io.WriteString(w, strings.Repeat("x", dns.MaxMsgSize+1))
				case "timeout":
					<-r.Context().Done()
				default:
					resp := new(dns.Msg)
					resp.SetReply(q)
					if kind == "mismatch" {
						resp.Id++
					}
					b, _ := resp.Pack()
					_, _ = w.Write(b)
				}
			}))
			defer s.Close()
			client := s.Client()
			client.Timeout = 50 * time.Millisecond
			c := &DoHCallerV2{url: s.URL, clients: []*http.Client{client}}
			_, e := c.Call(q)
			if (e == nil) != (kind == "valid") {
				t.Fatalf("unexpected result: %v", e)
			}
		})
	}
}
func TestGFWListRefresh(t *testing.T) {
	var body atomic.Value
	body.Store(base64.StdEncoding.EncodeToString([]byte("||old.example\n")))
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, body.Load().(string)) }))
	defer s.Close()
	groups, e := BuildGroups(config.Conf{Groups: map[string]config.Group{"g": {GFWListURL: s.URL, GFWListUpdateInterval: "10ms"}}})
	if e != nil {
		t.Fatal(e)
	}
	g := groups["g"].(*groupImpl)
	g.Start(nil)
	defer g.Stop()
	wait := func(domain string) {
		t.Helper()
		deadline := time.Now().Add(time.Second)
		q := new(dns.Msg)
		q.SetQuestion(domain, dns.TypeA)
		for !g.Match(q) {
			if time.Now().After(deadline) {
				t.Fatal("refresh not applied", domain)
			}
			time.Sleep(time.Millisecond)
		}
	}
	wait("old.example.")
	body.Store(base64.StdEncoding.EncodeToString([]byte("||new.example\n")))
	wait("new.example.")
	body.Store("invalid base64")
	time.Sleep(30 * time.Millisecond)
	wait("new.example.")
	old := new(dns.Msg)
	old.SetQuestion("old.example.", dns.TypeA)
	if g.Match(old) {
		t.Fatal("stale rules survived successful refresh")
	}
}
func TestGFWListInvalidContent(t *testing.T) {
	for _, body := range []string{"invalid", base64.StdEncoding.EncodeToString([]byte("! empty\n")), strings.Repeat("a", maxGFWListSize+1)} {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, body) }))
		g := &groupImpl{gfwListURL: s.URL}
		if _, e := g.fetchGFWList(context.Background()); e == nil {
			t.Error("accepted invalid list")
		}
		s.Close()
	}
	for _, u := range []string{"ftp://example.com/list", "://bad"} {
		if validateGFWListURL(u) == nil {
			t.Fatal("accepted invalid URL")
		}
	}
	if !matcher.NewABPByText("! empty").Empty() {
		t.Fatal("unexpected rules")
	}
}
func TestGFWListStopCancelsDownload(t *testing.T) {
	started := make(chan struct{})
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(started); <-r.Context().Done() }))
	defer s.Close()
	groups, e := BuildGroups(config.Conf{Groups: map[string]config.Group{"g": {GFWListURL: s.URL}}})
	if e != nil {
		t.Fatal(e)
	}
	g := groups["g"]
	g.Start(nil)
	<-started
	done := make(chan struct{})
	go func() { g.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("stop failed to cancel fetch")
	}
}

func TestProxyReadDeadline(t *testing.T) {
	d := pipeDialer{serve: func(c net.Conn) { _, _ = io.Copy(io.Discard, c) }}
	caller := NewDNSCaller("unused:53", "tcp", d)
	caller.client.Timeout = 30 * time.Millisecond
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	start := time.Now()
	if _, err := caller.Call(q); err == nil {
		t.Fatal("missing read timeout")
	}
	if time.Since(start) > time.Second {
		t.Fatal("deadline not enforced")
	}
}

func TestGFWListIntervalValidation(t *testing.T) {
	for _, interval := range []string{"bad", "0s", "-1h"} {
		_, err := BuildGroups(config.Conf{Groups: map[string]config.Group{"g": {GFWListURL: "https://example.com/list", GFWListUpdateInterval: interval}}})
		if err == nil {
			t.Errorf("accepted interval %q", interval)
		}
	}
}

func TestGFWListRetriesBeforeLongInterval(t *testing.T) {
	var attempts atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if attempts.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, base64.StdEncoding.EncodeToString([]byte("||recovered.example\n")))
	}))
	defer s.Close()
	groups, err := BuildGroups(config.Conf{Groups: map[string]config.Group{"g": {GFWListURL: s.URL, GFWListUpdateInterval: "24h"}}})
	if err != nil {
		t.Fatal(err)
	}
	g := groups["g"].(*groupImpl)
	g.gfwListRetryInterval = 10 * time.Millisecond
	g.Start(nil)
	defer g.Stop()
	q := new(dns.Msg)
	q.SetQuestion("recovered.example.", dns.TypeA)
	deadline := time.Now().Add(time.Second)
	for !g.Match(q) {
		if time.Now().After(deadline) {
			t.Fatal("failed to retry transient startup failure")
		}
		time.Sleep(time.Millisecond)
	}
	if attempts.Load() < 2 {
		t.Fatal("recovery did not retry")
	}
}
