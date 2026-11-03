package cache

import (
	"fmt"
	"github.com/miekg/dns"
	"github.com/wolf-joe/ts-dns/config"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func staleTestCache(t *testing.T, window int) (*dnsCache, *atomic.Int64, *dns.Msg, *dns.Msg) {
	t.Helper()
	cache, err := NewDNSCache(config.Conf{Cache: config.CacheConf{Size: 2, MinTTL: 1, MaxTTL: 10, ServeStale: window, StaleTTL: 5}})
	if err != nil {
		t.Fatal(err)
	}
	c := cache.(*dnsCache)
	now := new(atomic.Int64)
	now.Store(100)
	c.now = func() time.Time { return time.Unix(now.Load(), 0) }
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	q.SetEdns0(1232, true)
	r := new(dns.Msg)
	r.SetReply(q)
	r.AuthenticatedData = true
	r.SetEdns0(1232, true)
	a, _ := dns.NewRR("example.com. 10 IN A 192.0.2.1")
	ns, _ := dns.NewRR("example.com. 10 IN NS ns.example.com.")
	extra, _ := dns.NewRR("ns.example.com. 10 IN A 192.0.2.2")
	r.Answer = []dns.RR{a}
	r.Ns = []dns.RR{ns}
	r.Extra = append(r.Extra, extra)
	return c, now, q, r
}

func TestStaleExpirationBoundaryAndTTL(t *testing.T) {
	c, now, q, r := staleTestCache(t, 20)
	c.Set(q, r, 1)
	for _, tc := range []struct {
		now     int64
		wantTTL uint32
		stale   bool
	}{{109, 1, false}, {110, 5, true}, {128, 2, true}} {
		now.Store(tc.now)
		c.cleanExpired()
		got, key := c.Lookup(q, 1)
		if got == nil || got.Answer[0].Header().Ttl != tc.wantTTL || (key != "") != tc.stale {
			t.Fatalf("time %d: %v, stale=%t", tc.now, got, key != "")
		}
		if tc.stale {
			if got.AuthenticatedData {
				t.Fatal("stale response asserted authenticated data")
			}
			if got.Ns[0].Header().Ttl != tc.wantTTL || got.Extra[1].Header().Ttl != tc.wantTTL {
				t.Fatal("stale additional records have long TTL")
			}
			if !got.IsEdns0().Do() || got.IsEdns0().UDPSize() != 1232 {
				t.Fatal("stale TTL overwrote OPT flags")
			}
		}
	}
	if item := c.items[c.cacheKey(q, 1)]; item.expiredAt != 110 {
		t.Fatal("stale lookups extended the expiration")
	}
	now.Store(130)
	if got, _ := c.Lookup(q, 1); got != nil {
		t.Fatal("served beyond stale bound")
	}
	c.cleanExpired()
	if len(c.items) != 0 {
		t.Fatal("expired stale record retained")
	}
}
func TestStaleDisabledAndIneligible(t *testing.T) {
	c, now, q, r := staleTestCache(t, 0)
	c.Set(q, r)
	now.Store(110)
	if got, key := c.Lookup(q); got != nil || key != "" {
		t.Fatal("stale serving enabled by default")
	}
	for _, kind := range []string{"truncated", "negative", "nodata", "error"} {
		t.Run(kind, func(t *testing.T) {
			c, now, q, r := staleTestCache(t, 20)
			switch kind {
			case "truncated":
				r.Truncated = true
			case "negative":
				r.Rcode = dns.RcodeNameError
			case "nodata":
				cname, _ := dns.NewRR("example.com. 86400 IN CNAME missing.example.")
				soa, _ := dns.NewRR("example. 30 IN SOA ns.example. hostmaster.example. 1 60 60 60 5")
				r.Answer = []dns.RR{cname}
				r.Ns = []dns.RR{soa}
			case "error":
				r.Rcode = dns.RcodeServerFailure
			}
			c.Set(q, r)
			now.Store(110)
			if got, _ := c.Lookup(q); got != nil {
				t.Fatal("ineligible answer served stale")
			}
		})
	}
}
func TestStaleRoutingGenerationIsolation(t *testing.T) {
	c, now, q, r := staleTestCache(t, 20)
	c.Set(q, r, 1)
	now.Store(110)
	if got, key := c.Lookup(q, 1); got == nil || key == "" {
		t.Fatal("missing eligible stale record")
	}
	if got, _ := c.Lookup(q, 2); got != nil {
		t.Fatal("stale record crossed routing generation")
	}
	c.Set(q, r, 2)
	c.Set(q, r, 1)
	if got, key := c.Lookup(q, 2); got == nil || key != "" {
		t.Fatal("late old generation replaced current fresh entry")
	}
}
func TestStaleConfigurationValidation(t *testing.T) {
	for _, conf := range []config.CacheConf{{ServeStale: -1}, {ServeStale: 86401}, {StaleTTL: -1}, {StaleTTL: 31}} {
		if _, err := NewDNSCache(config.Conf{Cache: conf}); err == nil {
			t.Fatal("accepted invalid stale bounds")
		}
	}
}

func TestNegativeRefreshInvalidatesOnlyCapturedEntry(t *testing.T) {
	for _, kind := range []string{"nxdomain", "nodata", "cname-nodata", "empty-nodata", "servfail", "refused", "transport", "truncated", "wrong-question", "referral"} {
		t.Run(kind, func(t *testing.T) {
			c, now, q, positive := staleTestCache(t, 20)
			c.Set(q, positive, 1)
			now.Store(110)
			token, ok := c.CaptureRefresh(q, 1)
			if !ok {
				t.Fatal("missing stale snapshot")
			}
			negative := new(dns.Msg)
			negative.SetReply(q)
			soa, _ := dns.NewRR("example. 30 IN SOA ns.example. hostmaster.example. 1 60 60 60 5")
			invalidate := true
			switch kind {
			case "nxdomain":
				negative.Rcode = dns.RcodeNameError
			case "nodata":
				negative.Ns = []dns.RR{soa}
			case "cname-nodata":
				negative.Ns = []dns.RR{soa}
				cname, _ := dns.NewRR("example.com. 60 IN CNAME missing.example.")
				negative.Answer = []dns.RR{cname}
			case "empty-nodata":
			case "servfail":
				negative.Rcode = dns.RcodeServerFailure
				invalidate = false
			case "refused":
				negative.Rcode = dns.RcodeRefused
				invalidate = false
			case "transport":
				negative = nil
				invalidate = false
			case "truncated":
				negative.Truncated = true
				negative.Rcode = dns.RcodeNameError
				invalidate = false
			case "wrong-question":
				negative.Question[0].Name = "other.example."
				negative.Rcode = dns.RcodeNameError
				invalidate = false
			case "referral":
				ns, _ := dns.NewRR("example. 60 IN NS ns.example.")
				negative.Ns = []dns.RR{ns}
				invalidate = false
			}
			c.InvalidateNegativeRefresh(token, q, negative)
			got, _ := c.Lookup(q, 1)
			if (got == nil) != invalidate {
				t.Fatalf("invalidated=%t, want %t", got == nil, invalidate)
			}
		})
	}
}
func TestDelayedNegativeRefreshCannotEraseNewPositive(t *testing.T) {
	for _, newRevision := range []uint64{1, 2} {
		t.Run(fmt.Sprint(newRevision), func(t *testing.T) {
			c, now, q, positive := staleTestCache(t, 20)
			c.Set(q, positive, 1)
			now.Store(110)
			token, ok := c.CaptureRefresh(q, 1)
			if !ok {
				t.Fatal("missing stale snapshot")
			}
			negative := new(dns.Msg)
			negative.SetRcode(q, dns.RcodeNameError)
			release := make(chan struct{})
			done := make(chan struct{})
			go func() { <-release; c.InvalidateNegativeRefresh(token, q, negative); close(done) }()
			newer := positive.Copy()
			newer.Answer[0].(*dns.A).A = net.ParseIP("192.0.2.9")
			c.Set(q, newer, newRevision)
			// Let the replacement expire too: identity, not merely freshness, protects it.
			now.Store(120)
			close(release)
			<-done
			got, key := c.Lookup(q, newRevision)
			if got == nil || key == "" || got.Answer[0].(*dns.A).A.String() != "192.0.2.9" {
				t.Fatal("delayed negative erased newer positive")
			}
		})
	}
}
