package cache

import (
	"github.com/miekg/dns"
	"github.com/wolf-joe/ts-dns/config"
	"net"
	"sync/atomic"
	"testing"
)

func TestTruncatedUDPThenTCPRetry(t *testing.T) {
	c, _ := NewDNSCache(config.Conf{Cache: config.CacheConf{Size: 10}})
	var tcpMiss atomic.Bool
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		if r := c.Get(q); r != nil {
			_ = w.WriteMsg(r)
			return
		}
		r := new(dns.Msg)
		r.SetReply(q)
		_, tcp := w.RemoteAddr().(*net.TCPAddr)
		if tcp {
			tcpMiss.Store(true)
		} else {
			r.Truncated = true
		}
		a, _ := dns.NewRR("example.com. 60 IN A 192.0.2.1")
		r.Answer = []dns.RR{a}
		c.Set(q, r)
		_ = w.WriteMsg(r)
	})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	packet, err := net.ListenPacket("udp", listener.Addr().String())
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	tcpServer := &dns.Server{Listener: listener, Handler: handler}
	udpServer := &dns.Server{PacketConn: packet, Handler: handler}
	readyTCP, readyUDP := make(chan struct{}), make(chan struct{})
	tcpServer.NotifyStartedFunc = func() { close(readyTCP) }
	udpServer.NotifyStartedFunc = func() { close(readyUDP) }
	go func() { _ = tcpServer.ActivateAndServe() }()
	go func() { _ = udpServer.ActivateAndServe() }()
	<-readyTCP
	<-readyUDP
	defer tcpServer.Shutdown()
	defer udpServer.Shutdown()
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	r, _, err := (&dns.Client{Net: "udp"}).Exchange(q, listener.Addr().String())
	if err != nil || !r.Truncated {
		t.Fatalf("expected truncated UDP reply: %v", err)
	}
	r, _, err = (&dns.Client{Net: "tcp"}).Exchange(q, listener.Addr().String())
	if err != nil || r.Truncated || !tcpMiss.Load() {
		t.Fatalf("TCP retry reused truncated UDP answer: %v", err)
	}
}
