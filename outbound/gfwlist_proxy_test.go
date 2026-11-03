package outbound

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/wolf-joe/ts-dns/config"
)

const proxyTestUser = "proxy-user"
const proxyTestPassword = "proxy-secret"

var proxyTestList = base64.StdEncoding.EncodeToString([]byte("||proxied.example\n"))

func testGFWListGroup(t *testing.T, conf config.Group) *groupImpl {
	t.Helper()
	groups, err := BuildGroups(config.Conf{Groups: map[string]config.Group{"g": conf}})
	if err != nil {
		t.Fatal(err)
	}
	g := groups["g"].(*groupImpl)
	t.Cleanup(g.gfwListClient.CloseIdleConnections)
	return g
}
func proxyURLWithAuth(raw string) string {
	u, _ := url.Parse(raw)
	u.User = url.UserPassword(proxyTestUser, proxyTestPassword)
	return u.String()
}
func assertProxiedList(t *testing.T, g *groupImpl) {
	t.Helper()
	m, err := g.fetchGFWList(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := m.Match("proxied.example."); !ok {
		t.Fatal("proxy did not provide usable rules")
	}
}
func relayProxy(client net.Conn, reader io.Reader, upstream net.Conn) {
	defer client.Close()
	defer upstream.Close()
	done := make(chan struct{})
	go func() { _, _ = io.Copy(upstream, reader); upstream.Close(); close(done) }()
	_, _ = io.Copy(client, upstream)
	client.Close()
	<-done
}

func TestGFWListHTTPAndHTTPSProxies(t *testing.T) {
	for _, secureProxy := range []bool{false, true} {
		for _, secureTarget := range []bool{false, true} {
			t.Run(fmt.Sprintf("proxyTLS=%t/targetTLS=%t", secureProxy, secureTarget), func(t *testing.T) {
				var proxyCalls atomic.Int32
				targetHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Header.Get("Proxy-Authorization") != "" {
						t.Error("proxy credentials reached origin")
					}
					_, _ = io.WriteString(w, proxyTestList)
				})
				var target *httptest.Server
				if secureTarget {
					target = httptest.NewTLSServer(targetHandler)
				} else {
					target = httptest.NewServer(targetHandler)
				}
				defer target.Close()
				forward := http.DefaultTransport.(*http.Transport).Clone()
				forward.Proxy = nil
				defer forward.CloseIdleConnections()
				handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					proxyCalls.Add(1)
					expected := "Basic " + base64.StdEncoding.EncodeToString([]byte(proxyTestUser+":"+proxyTestPassword))
					if r.Header.Get("Proxy-Authorization") != expected {
						t.Error("missing proxy authentication")
						w.WriteHeader(407)
						return
					}
					if r.Method == http.MethodConnect {
						upstream, err := net.DialTimeout("tcp", r.Host, time.Second)
						if err != nil {
							t.Error(err)
							w.WriteHeader(502)
							return
						}
						client, rw, err := w.(http.Hijacker).Hijack()
						if err != nil {
							upstream.Close()
							t.Error(err)
							return
						}
						_, _ = rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
						_ = rw.Flush()
						relayProxy(client, rw, upstream)
						return
					}
					outgoing := r.Clone(r.Context())
					outgoing.RequestURI = ""
					outgoing.Header.Del("Proxy-Authorization")
					resp, err := forward.RoundTrip(outgoing)
					if err != nil {
						t.Error(err)
						w.WriteHeader(502)
						return
					}
					defer resp.Body.Close()
					w.WriteHeader(resp.StatusCode)
					_, _ = io.Copy(w, resp.Body)
				})
				var p *httptest.Server
				if secureProxy {
					p = httptest.NewTLSServer(handler)
				} else {
					p = httptest.NewServer(handler)
				}
				defer p.Close()
				g := testGFWListGroup(t, config.Group{GFWListURL: target.URL, GFWListProxy: proxyURLWithAuth(p.URL), Socks5: "127.0.0.1:1"})
				roots := x509.NewCertPool()
				if secureProxy {
					roots.AddCert(p.Certificate())
				}
				if secureTarget {
					roots.AddCert(target.Certificate())
				}
				g.gfwListClient.Transport.(*http.Transport).TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
				assertProxiedList(t, g)
				g.gfwListClient.CloseIdleConnections()
				if proxyCalls.Load() != 1 {
					t.Fatal("explicit proxy did not override group SOCKS5")
				}
			})
		}
	}
}

// A local SOCKS5 server forwards every requested hostname to the test origin.
// Recording the CONNECT address proves that hostname resolution is delegated.
func socksProxy(t *testing.T, target string, authenticate bool) (string, <-chan string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addresses := make(chan string, 8)
	acceptDone := make(chan struct{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	connections := map[net.Conn]bool{}
	go func() {
		defer close(acceptDone)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			connections[conn] = true
			mu.Unlock()
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer conn.Close()
				defer func() { mu.Lock(); delete(connections, conn); mu.Unlock() }()
				header := make([]byte, 2)
				if _, err := io.ReadFull(conn, header); err != nil {
					return
				}
				methods := make([]byte, int(header[1]))
				if _, err := io.ReadFull(conn, methods); err != nil {
					return
				}
				method := byte(0)
				if authenticate {
					method = 2
				}
				_, _ = conn.Write([]byte{5, method})
				if authenticate {
					if _, err := io.ReadFull(conn, header); err != nil {
						return
					}
					user := make([]byte, int(header[1]))
					if _, err := io.ReadFull(conn, user); err != nil {
						return
					}
					if _, err := io.ReadFull(conn, header[:1]); err != nil {
						return
					}
					password := make([]byte, int(header[0]))
					if _, err := io.ReadFull(conn, password); err != nil {
						return
					}
					if string(user) != proxyTestUser || string(password) != proxyTestPassword {
						_, _ = conn.Write([]byte{1, 1})
						return
					}
					_, _ = conn.Write([]byte{1, 0})
				}
				request := make([]byte, 4)
				if _, err := io.ReadFull(conn, request); err != nil {
					return
				}
				var host string
				switch request[3] {
				case 1:
					ip := make([]byte, 4)
					if _, err := io.ReadFull(conn, ip); err != nil {
						return
					}
					host = net.IP(ip).String()
				case 4:
					ip := make([]byte, 16)
					if _, err := io.ReadFull(conn, ip); err != nil {
						return
					}
					host = net.IP(ip).String()
				case 3:
					if _, err := io.ReadFull(conn, header[:1]); err != nil {
						return
					}
					name := make([]byte, int(header[0]))
					if _, err := io.ReadFull(conn, name); err != nil {
						return
					}
					host = string(name)
				default:
					return
				}
				if _, err := io.ReadFull(conn, header); err != nil {
					return
				}
				addresses <- net.JoinHostPort(host, fmt.Sprint(binary.BigEndian.Uint16(header)))
				upstream, err := net.DialTimeout("tcp", target, time.Second)
				if err != nil {
					return
				}
				_, _ = conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
				relayProxy(conn, conn, upstream)
			}()
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		<-acceptDone
		mu.Lock()
		for conn := range connections {
			conn.Close()
		}
		mu.Unlock()
		wg.Wait()
	})
	return listener.Addr().String(), addresses
}

func TestGFWListSOCKS5AndInheritance(t *testing.T) {
	for _, scheme := range []string{"socks5", "socks5h", "inherit"} {
		for _, secureTarget := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/targetTLS=%t", scheme, secureTarget), func(t *testing.T) {
				handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, proxyTestList) })
				var target *httptest.Server
				if secureTarget {
					target = httptest.NewTLSServer(handler)
				} else {
					target = httptest.NewServer(handler)
				}
				defer target.Close()
				u, _ := url.Parse(target.URL)
				address, requests := socksProxy(t, u.Host, scheme != "inherit")
				origin, expected := "http://rules.example.invalid/gfwlist", "rules.example.invalid:80"
				if secureTarget {
					host := target.Certificate().DNSNames[0]
					origin = "https://" + host + "/gfwlist"
					expected = host + ":443"
				}
				conf := config.Group{GFWListURL: origin}
				if scheme == "inherit" {
					conf.Socks5 = address
				} else {
					conf.Socks5 = "127.0.0.1:1"
					conf.GFWListProxy = proxyURLWithAuth(scheme + "://" + address)
				}
				g := testGFWListGroup(t, conf)
				if secureTarget {
					roots := x509.NewCertPool()
					roots.AddCert(target.Certificate())
					g.gfwListClient.Transport.(*http.Transport).TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
				}
				assertProxiedList(t, g)
				g.gfwListClient.CloseIdleConnections()
				select {
				case address := <-requests:
					if address != expected {
						t.Fatal("SOCKS5 did not receive origin hostname")
					}
				case <-time.After(time.Second):
					t.Fatal("SOCKS5 proxy was bypassed")
				}
			})
		}
	}
}

func TestGFWListDirectAndDefaultProxyModes(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, proxyTestList) }))
	defer target.Close()
	g := testGFWListGroup(t, config.Group{GFWListURL: target.URL, GFWListProxy: "direct", Socks5: "127.0.0.1:1"})
	if g.gfwListClient.Transport.(*http.Transport).Proxy != nil {
		t.Fatal("direct mode permits environment proxy")
	}
	assertProxiedList(t, g)
	client, err := newGFWListClient("", nil, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	req, _ := http.NewRequest(http.MethodGet, "https://rules.example.invalid/gfwlist", nil)
	expected, err := http.ProxyFromEnvironment(req)
	if err != nil {
		t.Fatal("invalid test proxy environment")
	}
	got, err := client.Transport.(*http.Transport).Proxy(req)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(expected) != fmt.Sprint(got) {
		t.Fatal("unset setting changed environment proxy behavior")
	}
}

func TestGFWListProxyValidationAndRedaction(t *testing.T) {
	for _, setting := range []string{"127.0.0.1:1080", "ftp://proxy-user:proxy-secret@localhost:21", "http://proxy-user:proxy-secret%ZZ@localhost:80", "http:///list", "http://localhost:0", "http://localhost:65536", "http://localhost:abc", "http://localhost:", "http://localhost:80/path", "http://localhost:80?key=proxy-secret", "http://localhost:80#proxy-secret", "socks5://proxy-user@localhost:1080", "socks5://:proxy-secret@localhost:1080", "socks5://" + strings.Repeat("x", 256) + ":proxy-secret@localhost:1080"} {
		t.Run(setting[:min(12, len(setting))], func(t *testing.T) {
			_, err := BuildGroups(config.Conf{Groups: map[string]config.Group{"g": {GFWListURL: "https://example.com/list", GFWListProxy: setting}}})
			if err == nil {
				t.Fatal("accepted invalid proxy configuration")
			}
			for _, secret := range []string{proxyTestUser, proxyTestPassword} {
				if strings.Contains(err.Error(), secret) {
					t.Fatal("validation disclosed proxy credentials")
				}
			}
		})
	}
	for _, scheme := range []string{"http", "https", "socks5", "socks5h"} {
		u, err := parseGFWListProxy(scheme + "://localhost")
		if err != nil || u.Port() == "" {
			t.Fatal("missing default proxy port")
		}
	}
	for _, timeout := range []string{"bad", "0s", "-1s"} {
		if _, err := BuildGroups(config.Conf{Groups: map[string]config.Group{"g": {GFWListTimeout: timeout}}}); err == nil {
			t.Fatal("accepted invalid gfwlist_timeout")
		}
	}
	// A malicious proxy error can contain its full URL or authentication data.
	secretErr := &gfwListNetworkError{operation: "fetch gfwlist", cause: fmt.Errorf("rejected %s", proxyURLWithAuth("http://localhost:80"))}
	if strings.Contains(fmt.Sprintf("%+v", secretErr), proxyTestPassword) {
		t.Fatal("runtime error disclosed proxy credentials")
	}
}

func stalledProxy(t *testing.T) (string, <-chan struct{}, <-chan struct{}) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	started, closed := make(chan struct{}), make(chan struct{})
	var conn net.Conn
	accepted := make(chan struct{})
	go func() {
		defer close(closed)
		c, err := listener.Accept()
		conn = c
		close(accepted)
		if err != nil {
			return
		}
		defer c.Close()
		reader := bufio.NewReader(c)
		if _, err := reader.ReadByte(); err != nil {
			return
		}
		close(started)
		_, _ = io.Copy(io.Discard, reader)
	}()
	t.Cleanup(func() {
		listener.Close()
		<-accepted
		if conn != nil {
			conn.Close()
		}
		<-closed
	})
	return listener.Addr().String(), started, closed
}

func TestGFWListProxyCancellationAndTimeout(t *testing.T) {
	for _, scheme := range []string{"http", "https", "socks5", "socks5h"} {
		for _, cancelRequest := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/cancel=%t", scheme, cancelRequest), func(t *testing.T) {
				address, started, closed := stalledProxy(t)
				timeout := "80ms"
				if cancelRequest {
					timeout = "5s"
				}
				g := testGFWListGroup(t, config.Group{GFWListURL: "https://rules.example.invalid/list", GFWListProxy: proxyURLWithAuth(scheme + "://" + address), GFWListTimeout: timeout})
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				result := make(chan error, 1)
				go func() { _, err := g.fetchGFWList(ctx); result <- err }()
				select {
				case <-started:
				case <-time.After(time.Second):
					t.Fatal("proxy handshake did not start")
				}
				if cancelRequest {
					cancel()
				}
				select {
				case err := <-result:
					if err == nil {
						t.Fatal("stalled proxy succeeded")
					}
					if cancelRequest {
						if !errors.Is(err, context.Canceled) {
							t.Fatalf("lost cancellation: %v", err)
						}
					} else {
						var netErr net.Error
						if !errors.As(err, &netErr) || !netErr.Timeout() {
							t.Fatalf("lost timeout: %v", err)
						}
					}
					if strings.Contains(err.Error(), proxyTestPassword) {
						t.Fatal("error disclosed credentials")
					}
				case <-time.After(time.Second):
					t.Fatal("proxy outlived cancellation/timeout")
				}
				g.gfwListClient.CloseIdleConnections()
				select {
				case <-closed:
				case <-time.After(time.Second):
					t.Fatal("canceled proxy connection remained open")
				}
			})
		}
	}
}

func TestGFWListProxyFailurePreservesRulesAndRetries(t *testing.T) {
	var attempts atomic.Int32
	first := make(chan struct{})
	recoverFetch := make(chan struct{})
	p := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if attempts.Add(1) == 1 {
			w.WriteHeader(503)
			close(first)
			return
		}
		select {
		case <-recoverFetch:
			_, _ = io.WriteString(w, proxyTestList)
		case <-r.Context().Done():
			return
		}
	}))
	defer p.Close()
	seed := filepath.Join(t.TempDir(), "gfwlist.txt")
	if err := os.WriteFile(seed, []byte(base64.StdEncoding.EncodeToString([]byte("||seed.example\n"))), 0600); err != nil {
		t.Fatal(err)
	}
	g := testGFWListGroup(t, config.Group{GFWListFile: seed, GFWListURL: "http://rules.example.invalid/list", GFWListProxy: p.URL, GFWListUpdateInterval: "24h"})
	g.gfwListRetryInterval = 10 * time.Millisecond
	g.Start(nil)
	defer g.Stop()
	select {
	case <-first:
	case <-time.After(time.Second):
		t.Fatal("proxy fetch did not run")
	}
	q := new(dns.Msg)
	q.SetQuestion("seed.example.", dns.TypeA)
	if !g.Match(q) {
		t.Fatal("proxy failure discarded local rules")
	}
	close(recoverFetch)
	q.SetQuestion("proxied.example.", dns.TypeA)
	deadline := time.Now().Add(time.Second)
	for !g.Match(q) {
		if time.Now().After(deadline) {
			t.Fatal("proxy retry did not recover")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestGFWListProxyFailureDoesNotFallBackDirectly(t *testing.T) {
	var originCalls atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originCalls.Add(1)
		_, _ = io.WriteString(w, proxyTestList)
	}))
	defer origin.Close()
	p := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusProxyAuthRequired)
		_, _ = io.WriteString(w, proxyTestPassword)
	}))
	defer p.Close()
	g := testGFWListGroup(t, config.Group{GFWListURL: origin.URL, GFWListProxy: proxyURLWithAuth(p.URL)})
	_, err := g.fetchGFWList(context.Background())
	if err == nil {
		t.Fatal("proxy authentication failure was ignored")
	}
	if strings.Contains(err.Error(), proxyTestPassword) {
		t.Fatal("proxy response disclosed credentials")
	}
	if originCalls.Load() != 0 {
		t.Fatal("failed proxy silently fell back to direct")
	}
}

func TestGFWListProxyBodyTimeoutAndStop(t *testing.T) {
	t.Run("body-timeout", func(t *testing.T) {
		p := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		}))
		defer p.Close()
		g := testGFWListGroup(t, config.Group{GFWListURL: "http://rules.example.invalid/list", GFWListProxy: p.URL, GFWListTimeout: "80ms"})
		_, err := g.fetchGFWList(context.Background())
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() {
			t.Fatalf("body read did not time out: %v", err)
		}
	})
	t.Run("stop", func(t *testing.T) {
		address, started, closed := stalledProxy(t)
		g := testGFWListGroup(t, config.Group{GFWListURL: "https://rules.example.invalid/list", GFWListProxy: "http://" + address, GFWListTimeout: "5s"})
		g.Start(nil)
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("proxy did not start")
		}
		stopped := make(chan struct{})
		go func() { g.Stop(); close(stopped) }()
		select {
		case <-stopped:
		case <-time.After(time.Second):
			t.Fatal("stop did not cancel proxy fetch")
		}
		select {
		case <-closed:
		case <-time.After(time.Second):
			t.Fatal("stop left proxy connection open")
		}
	})
}
