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
	r.Rcode = dns.RcodeNameError
	r.AuthenticatedData = true
	r.RecursionAvailable = true
	a, _ := dns.NewRR("example.com. 60 IN CNAME missing.example.")
	r.Answer = []dns.RR{a}
	c.Set(q, r)
	q2 := q.Copy()
	q2.Id++
	got := c.Get(q2)
	if got == nil || got.Rcode != dns.RcodeNameError || !got.AuthenticatedData || !got.RecursionAvailable || got.Id != q2.Id {
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
