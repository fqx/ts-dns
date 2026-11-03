package cache

import (
	"github.com/miekg/dns"
	"github.com/wolf-joe/ts-dns/config"
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
