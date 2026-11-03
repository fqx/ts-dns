package cache

import (
	"fmt"
	"github.com/miekg/dns"
	"github.com/wolf-joe/ts-dns/config"
	"sync"
	"testing"
)

func TestCacheQueryIsolationAndResponseSemantics(t *testing.T) {
	c, e := NewDNSCache(config.Conf{Cache: config.CacheConf{Size: 10}})
	if e != nil {
		t.Fatal(e)
	}
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	r := new(dns.Msg)
	r.SetReply(q)
	r.Rcode = dns.RcodeSuccess
	r.AuthenticatedData = true
	r.RecursionAvailable = true
	a, _ := dns.NewRR("example.com. 60 IN CNAME missing.example.")
	r.Answer = []dns.RR{a}
	c.Set(q, r)
	q2 := q.Copy()
	q2.Id++
	got := c.Get(q2)
	if got == nil || got.Rcode != dns.RcodeSuccess || !got.AuthenticatedData || !got.RecursionAvailable || got.Id != q2.Id {
		t.Fatalf("lost response semantics: %v", got)
	}
	for _, kind := range []string{"class", "cd", "do", "ad", "rd", "cookie", "empty", "multi"} {
		t.Run(kind, func(t *testing.T) {
			other := q.Copy()
			switch kind {
			case "class":
				other.Question[0].Qclass = dns.ClassCHAOS
			case "cd":
				other.CheckingDisabled = true
			case "do":
				other.SetEdns0(1232, true)
			case "ad":
				other.AuthenticatedData = true
			case "rd":
				other.RecursionDesired = false
			case "cookie":
				other.SetEdns0(1232, false)
				other.IsEdns0().Option = append(other.IsEdns0().Option, &dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: "abcd"})
			case "empty":
				other.Question = nil
			case "multi":
				other.Question = append(other.Question, other.Question[0])
			}
			if c.Get(other) != nil {
				t.Fatal("cache query isolation failed")
			}
			c.Set(other, r)
		})
	}
}

func TestCacheConcurrentCapacity(t *testing.T) {
	c, err := NewDNSCache(config.Conf{Cache: config.CacheConf{Size: 4}})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			q := new(dns.Msg)
			q.SetQuestion(fmt.Sprintf("host%d.example.", i), dns.TypeA)
			r := new(dns.Msg)
			r.SetReply(q)
			rr, _ := dns.NewRR(q.Question[0].Name + " 60 IN A 192.0.2.1")
			r.Answer = []dns.RR{rr}
			c.Set(q, r)
		}(i)
	}
	close(start)
	wg.Wait()
	impl := c.(*dnsCache)
	impl.lock.RLock()
	defer impl.lock.RUnlock()
	if len(impl.items) > 4 {
		t.Fatalf("capacity exceeded: %d", len(impl.items))
	}
}

func TestCacheEDNSProfilesBothOrders(t *testing.T) {
	profiles := []int{-1, 512, 1232, 4096}
	for _, first := range profiles {
		for _, second := range profiles {
			if first == second {
				continue
			}
			t.Run(fmt.Sprintf("%d-then-%d", first, second), func(t *testing.T) {
				c, err := NewDNSCache(config.Conf{Cache: config.CacheConf{Size: 10}})
				if err != nil {
					t.Fatal(err)
				}
				query := func(size int) *dns.Msg {
					q := new(dns.Msg)
					q.SetQuestion("example.com.", dns.TypeA)
					if size >= 0 {
						q.SetEdns0(uint16(size), false)
					}
					return q
				}
				q := query(first)
				r := new(dns.Msg)
				r.SetReply(q)
				a, _ := dns.NewRR("example.com. 60 IN A 192.0.2.1")
				r.Answer = []dns.RR{a}
				if first >= 0 {
					r.SetEdns0(uint16(first), false)
				}
				c.Set(q, r)
				if c.Get(query(second)) != nil {
					t.Fatal("cache crossed EDNS profiles")
				}
				got := c.Get(query(first))
				if got == nil {
					t.Fatal("own profile missed cache")
				}
				if first < 0 {
					if got.IsEdns0() != nil {
						t.Fatal("unsolicited OPT")
					}
				} else if got.IsEdns0() == nil || got.IsEdns0().UDPSize() != uint16(first) {
					t.Fatal("wrong OPT")
				}
			})
		}
	}
}

func TestCacheRoutingRevisions(t *testing.T) {
	c, _ := NewDNSCache(config.Conf{Cache: config.CacheConf{Size: 10}})
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	r := new(dns.Msg)
	r.SetReply(q)
	a, _ := dns.NewRR("example.com. 60 IN A 192.0.2.1")
	r.Answer = []dns.RR{a}
	c.Set(q, r, 1)
	if c.Get(q, 2) != nil {
		t.Fatal("old route leaked into new revision")
	}
	// A response that finishes after the route update must still be isolated.
	c.Set(q, r, 1)
	if c.Get(q, 2) != nil {
		t.Fatal("late old-route response poisoned new revision")
	}
}

func TestCacheDoesNotStoreCNAMENXDOMAIN(t *testing.T) {
	c, _ := NewDNSCache(config.Conf{Cache: config.CacheConf{Size: 10, MinTTL: 60, MaxTTL: 86400}})
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	r := new(dns.Msg)
	r.SetReply(q)
	r.Rcode = dns.RcodeNameError
	cname, _ := dns.NewRR("example.com. 86400 IN CNAME missing.example.")
	soa, _ := dns.NewRR("example. 30 IN SOA ns.example. hostmaster.example. 1 60 60 60 5")
	r.Answer = []dns.RR{cname}
	r.Ns = []dns.RR{soa}
	c.Set(q, r)
	if c.Get(q) != nil {
		t.Fatal("NXDOMAIN cached using CNAME TTL instead of SOA negative TTL")
	}
}
