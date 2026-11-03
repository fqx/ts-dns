package inbound

import (
	"encoding/base64"
	"github.com/miekg/dns"
	"github.com/wolf-joe/ts-dns/config"
	"github.com/wolf-joe/ts-dns/utils"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestGFWListRefreshReclaimsFullLongTTLCache(t *testing.T) {
	upstream := func(ip string) (string, *atomic.Int32) {
		t.Helper()
		var calls atomic.Int32
		conn, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		ready := make(chan struct{})
		server := &dns.Server{PacketConn: conn, NotifyStartedFunc: func() { close(ready) }, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
			calls.Add(1)
			r := new(dns.Msg)
			r.SetReply(q)
			a, _ := dns.NewRR(q.Question[0].Name + " 86400 IN A " + ip)
			r.Answer = []dns.RR{a}
			_ = w.WriteMsg(r)
		})}
		go func() { _ = server.ActivateAndServe() }()
		<-ready
		t.Cleanup(func() { _ = server.Shutdown() })
		return conn.LocalAddr().String(), &calls
	}
	clean, cleanCalls := upstream("192.0.2.1")
	dirty, dirtyCalls := upstream("192.0.2.2")
	update := make(chan struct{})
	var fetches atomic.Int32
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rule := "||seed.example\n"
		attempt := fetches.Add(1)
		if attempt > 2 {
			<-r.Context().Done()
			return
		}
		if attempt == 2 {
			select {
			case <-update:
				rule = "||changed.example\n"
			case <-r.Context().Done():
				return
			}
		}
		_, _ = io.WriteString(w, base64.StdEncoding.EncodeToString([]byte(rule)))
	}))
	defer source.Close()
	seed := filepath.Join(t.TempDir(), "seed.txt")
	if err := os.WriteFile(seed, []byte(base64.StdEncoding.EncodeToString([]byte("||seed.example\n"))), 0600); err != nil {
		t.Fatal(err)
	}
	h, err := newHandle(config.Conf{Cache: config.CacheConf{Size: 1, MinTTL: 86400, MaxTTL: 86400}, Groups: map[string]config.Group{
		"clean": {DNS: []string{clean}}, "dirty": {DNS: []string{dirty}, GFWListFile: seed, GFWListURL: source.URL, GFWListUpdateInterval: "10ms"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	h.start()
	defer h.stop()
	revision := func() uint64 { return h.groups["dirty"].(interface{ CacheRevision() uint64 }).CacheRevision() }
	waitRevision := func(after uint64) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for revision() <= after {
			if time.Now().After(deadline) {
				t.Fatal("routing revision did not advance")
			}
			time.Sleep(time.Millisecond)
		}
	}
	waitRevision(0)
	query := func(want string) {
		t.Helper()
		q := new(dns.Msg)
		q.SetQuestion("changed.example.", dns.TypeA)
		w := utils.NewFakeRespWriter()
		h.ServeDNS(w, q)
		if w.Msg == nil || len(w.Msg.Answer) != 1 || w.Msg.Answer[0].(*dns.A).A.String() != want {
			t.Fatalf("wanted %s, got %v", want, w.Msg)
		}
	}
	query("192.0.2.1")
	query("192.0.2.1")
	if cleanCalls.Load() != 1 {
		t.Fatal("pre-update answer was not cached")
	}
	before := revision()
	close(update)
	waitRevision(before)
	query("192.0.2.2")
	query("192.0.2.2")
	if dirtyCalls.Load() != 1 {
		t.Fatal("full old generation prevented new-route caching")
	}
}
