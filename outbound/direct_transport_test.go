package outbound

import (
	"crypto/tls"
	"crypto/x509"
	"github.com/miekg/dns"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDirectDNSResponseValidation(t *testing.T) {
	certServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer certServer.Close()
	roots := x509.NewCertPool()
	roots.AddCert(certServer.Certificate())
	for _, network := range []string{"udp", "tcp", "tcp-tls"} {
		for _, kind := range []string{"valid", "qr", "opcode", "question"} {
			t.Run(network+"/"+kind, func(t *testing.T) {
				server := &dns.Server{Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
					r := new(dns.Msg)
					r.SetReply(q)
					switch kind {
					case "qr":
						r.Response = false
					case "opcode":
						r.Opcode = dns.OpcodeStatus
					case "question":
						r.Question[0].Qtype = dns.TypeAAAA
					}
					_ = w.WriteMsg(r)
				})}
				var addr string
				if network == "udp" {
					packet, err := net.ListenPacket("udp", "127.0.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
					server.PacketConn = packet
					addr = packet.LocalAddr().String()
				} else {
					listener, err := net.Listen("tcp", "127.0.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
					addr = listener.Addr().String()
					if network == "tcp-tls" {
						listener = tls.NewListener(listener, certServer.TLS)
					}
					server.Listener = listener
				}
				ready := make(chan struct{})
				server.NotifyStartedFunc = func() { close(ready) }
				go func() { _ = server.ActivateAndServe() }()
				<-ready
				defer server.Shutdown()
				caller := NewDNSCaller(addr, network, nil)
				if network == "tcp-tls" {
					caller = NewDoTCaller(addr, certServer.Certificate().DNSNames[0], nil)
					caller.client.TLSConfig.RootCAs = roots
				}
				q := new(dns.Msg)
				q.SetQuestion("example.com.", dns.TypeA)
				_, err := caller.Call(q)
				if (err == nil) != (kind == "valid") {
					t.Fatalf("response %s: %v", kind, err)
				}
			})
		}
	}
}
