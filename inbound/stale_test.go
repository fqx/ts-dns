package inbound

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/miekg/dns"
	"github.com/wolf-joe/ts-dns/config"
	"github.com/wolf-joe/ts-dns/outbound"
	"github.com/wolf-joe/ts-dns/utils"
)

type staleUpstream struct {
	addr    string
	calls   atomic.Int32
	mode    atomic.Int32
	started chan struct{}
	release chan struct{}
	done    chan struct{}
}

func newStaleUpstream(t *testing.T) *staleUpstream {
	t.Helper()
	u := &staleUpstream{started: make(chan struct{}, 128), release: make(chan struct{}), done: make(chan struct{})}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	u.addr = listener.Addr().String()
	ready := make(chan struct{})
	server := &dns.Server{Listener: listener, NotifyStartedFunc: func() { close(ready) }, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		u.calls.Add(1)
		mode := u.mode.Load()
		if mode != 0 {
			select {
			case u.started <- struct{}{}:
			default:
			}
		}
		if mode == 1 {
			select {
			case <-u.release:
			case <-u.done:
				return
			}
		}
		r := new(dns.Msg)
		r.SetReply(q)
		if mode == 2 {
			r.Rcode = dns.RcodeServerFailure
		} else if mode >= 4 && mode <= 7 {
			if mode == 4 {
				r.Rcode = dns.RcodeNameError
			}
			if mode != 7 {
				soa, _ := dns.NewRR("example. 30 IN SOA ns.example. hostmaster.example. 1 60 60 60 5")
				r.Ns = []dns.RR{soa}
			}
			if mode == 6 {
				cname, _ := dns.NewRR(q.Question[0].Name + " 60 IN CNAME missing.example.")
				r.Answer = []dns.RR{cname}
			}
		} else {
			ip, ttl := "192.0.2.1", 1
			if mode != 0 {
				ip, ttl = "192.0.2.2", 60
			}
			a, _ := dns.NewRR(fmt.Sprintf("%s %d IN A %s", q.Question[0].Name, ttl, ip))
			r.Answer = []dns.RR{a}
		}
		_ = w.WriteMsg(r)
	})}
	go func() { _ = server.ActivateAndServe() }()
	<-ready
	t.Cleanup(func() { close(u.done); _ = server.Shutdown() })
	return u
}
func staleHandler(t *testing.T, u *staleUpstream, window int) (IHandler, *handlerImpl, config.Conf) {
	t.Helper()
	conf := config.Conf{Cache: config.CacheConf{Size: 128, MinTTL: 1, MaxTTL: 60, ServeStale: window, StaleTTL: 5}, Groups: map[string]config.Group{"fallback": {DNS: []string{u.addr + "/tcp"}}}}
	w, err := NewHandler(conf)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.Stop)
	h := (*handlerImpl)(atomic.LoadPointer(&w.(*handlerWrapper).handlerPtr))
	return w, h, conf
}
func staleQuery(h dns.Handler, name string) *dns.Msg {
	q := new(dns.Msg)
	q.SetQuestion(name, dns.TypeA)
	w := utils.NewFakeRespWriter()
	h.ServeDNS(w, q)
	return w.Msg
}
func assertAnswer(t *testing.T, r *dns.Msg, ip string) {
	t.Helper()
	if r == nil || len(r.Answer) != 1 || r.Answer[0].(*dns.A).A.String() != ip {
		t.Fatalf("wanted %s, got %v", ip, r)
	}
}
func waitForStale(t *testing.T, h *handlerImpl, name string) {
	t.Helper()
	q := new(dns.Msg)
	q.SetQuestion(name, dns.TypeA)
	deadline := time.Now().Add(3 * time.Second)
	for {
		if r, key := h.cache.Lookup(q, h.routingRevision()); r != nil && key != "" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("entry did not become stale")
		}
		time.Sleep(time.Millisecond)
	}
}
func waitRefreshIdle(t *testing.T, h *handlerImpl) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		h.refresh.mu.Lock()
		n := len(h.refresh.pending)
		h.refresh.mu.Unlock()
		if n == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("refresh did not finish")
		}
		time.Sleep(time.Millisecond)
	}
}
func waitFresh(t *testing.T, h *handlerImpl, name, ip string) {
	t.Helper()
	q := new(dns.Msg)
	q.SetQuestion(name, dns.TypeA)
	deadline := time.Now().Add(2 * time.Second)
	for {
		r, key := h.cache.Lookup(q, h.routingRevision())
		if r != nil && key == "" && len(r.Answer) == 1 && r.Answer[0].(*dns.A).A.String() == ip {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("refreshed result did not reach cache")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestStaleConcurrentQueriesDeduplicateRefresh(t *testing.T) {
	u := newStaleUpstream(t)
	w, h, _ := staleHandler(t, u, 10)
	assertAnswer(t, staleQuery(w, "example.com."), "192.0.2.1")
	waitForStale(t, h, "example.com.")
	u.mode.Store(1)
	assertAnswer(t, staleQuery(w, "example.com."), "192.0.2.1")
	select {
	case <-u.started:
	case <-time.After(time.Second):
		t.Fatal("background refresh did not start")
	}
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := staleQuery(w, "example.com.")
			assertAnswer(t, r, "192.0.2.1")
			if ttl := r.Answer[0].Header().Ttl; ttl < 1 || ttl > 5 {
				t.Error("stale TTL not short")
			}
		}()
	}
	wg.Wait()
	if u.calls.Load() != 2 {
		t.Fatalf("refresh not deduplicated: %d calls", u.calls.Load())
	}
	close(u.release)
	waitFresh(t, h, "example.com.", "192.0.2.2")
	waitRefreshIdle(t, h)
	assertAnswer(t, staleQuery(w, "example.com."), "192.0.2.2")
	if u.calls.Load() != 2 {
		t.Fatal("refreshed answer was not cached")
	}
}
func TestStaleFailureBoundAndRecovery(t *testing.T) {
	u := newStaleUpstream(t)
	w, h, _ := staleHandler(t, u, 1)
	assertAnswer(t, staleQuery(w, "failure.example."), "192.0.2.1")
	waitForStale(t, h, "failure.example.")
	u.mode.Store(2)
	assertAnswer(t, staleQuery(w, "failure.example."), "192.0.2.1")
	select {
	case <-u.started:
	case <-time.After(time.Second):
		t.Fatal("failure refresh did not run")
	}
	waitRefreshIdle(t, h)
	q := new(dns.Msg)
	q.SetQuestion("failure.example.", dns.TypeA)
	if r, key := h.cache.Lookup(q); r == nil || key == "" {
		t.Fatal("failure discarded eligible stale answer")
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		r, _ := h.cache.Lookup(q)
		if r == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("failure extended stale lifetime")
		}
		time.Sleep(time.Millisecond)
	}
	if r := staleQuery(w, "failure.example."); r.Rcode != dns.RcodeServerFailure || len(r.Answer) != 0 {
		t.Fatal("served stale beyond its bound")
	}
	u.mode.Store(3)
	assertAnswer(t, staleQuery(w, "failure.example."), "192.0.2.2")
	waitFresh(t, h, "failure.example.", "192.0.2.2")
}
func TestStaleRefreshStopAndReload(t *testing.T) {
	for _, reload := range []bool{false, true} {
		t.Run(fmt.Sprint(reload), func(t *testing.T) {
			u := newStaleUpstream(t)
			w, h, conf := staleHandler(t, u, 10)
			assertAnswer(t, staleQuery(w, "reload.example."), "192.0.2.1")
			waitForStale(t, h, "reload.example.")
			u.mode.Store(1)
			assertAnswer(t, staleQuery(w, "reload.example."), "192.0.2.1")
			select {
			case <-u.started:
			case <-time.After(time.Second):
				t.Fatal("refresh did not start")
			}
			done := make(chan error, 1)
			go func() {
				if reload {
					conf.Hosts = map[string]string{"reload.example": "192.0.2.3"}
					done <- w.ReloadConfig(conf)
				} else {
					w.Stop()
					done <- nil
				}
			}()
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("shutdown/reload did not cancel and join refresh")
			}
			h.refresh.mu.Lock()
			n := len(h.refresh.pending)
			stopped := h.refresh.stopped
			h.refresh.mu.Unlock()
			if n != 0 || !stopped {
				t.Fatal("old refresher remains active")
			}
			close(u.release)
			if reload {
				assertAnswer(t, staleQuery(w, "reload.example."), "192.0.2.3")
			}
		})
	}
}
func TestStaleRefreshQueueAndWorkersAreBounded(t *testing.T) {
	u := newStaleUpstream(t)
	w, h, _ := staleHandler(t, u, 10)
	u.mode.Store(1)
	for i := 0; i < 100; i++ {
		q := new(dns.Msg)
		q.SetQuestion(fmt.Sprintf("key%d.example.", i), dns.TypeA)
		r := new(dns.Msg)
		r.SetReply(q)
		a, _ := dns.NewRR(q.Question[0].Name + " 1 IN A 192.0.2.1")
		r.Answer = []dns.RR{a}
		h.cache.Set(q, r)
	}
	waitForStale(t, h, "key99.example.")
	for i := 0; i < 100; i++ {
		assertAnswer(t, staleQuery(w, fmt.Sprintf("key%d.example.", i)), "192.0.2.1")
	}
	select {
	case <-u.started:
	case <-time.After(time.Second):
		t.Fatal("no worker started")
	}
	h.refresh.mu.Lock()
	pending := len(h.refresh.pending)
	queued := len(h.refresh.queue)
	h.refresh.mu.Unlock()
	if pending > staleRefreshWorkers+staleRefreshQueue || queued > staleRefreshQueue || u.calls.Load() > staleRefreshWorkers {
		t.Fatal("refresh concurrency or queue is unbounded")
	}
	w.Stop()
	if u.calls.Load() > staleRefreshWorkers {
		t.Fatal("shutdown started queued refreshes")
	}
}

type changingStaleGroup struct {
	revision atomic.Uint64
	calls    atomic.Int32
	started  chan struct{}
	release  chan struct{}
}

func (g *changingStaleGroup) Match(*dns.Msg) bool            { return false }
func (g *changingStaleGroup) IsFallback() bool               { return true }
func (g *changingStaleGroup) Name() string                   { return "changing" }
func (g *changingStaleGroup) String() string                 { return g.Name() }
func (g *changingStaleGroup) Start(dns.Handler)              {}
func (g *changingStaleGroup) Stop()                          {}
func (g *changingStaleGroup) PostProcess(*dns.Msg, *dns.Msg) {}
func (g *changingStaleGroup) CacheRevision() uint64          { return g.revision.Load() }
func (g *changingStaleGroup) Handle(q *dns.Msg) *dns.Msg {
	return g.HandleContext(context.Background(), q)
}
func (g *changingStaleGroup) HandleContext(ctx context.Context, q *dns.Msg) *dns.Msg {
	revision := g.revision.Load()
	call := g.calls.Add(1)
	if revision == 1 && call > 1 {
		close(g.started)
		select {
		case <-g.release:
		case <-ctx.Done():
			return nil
		}
	}
	ip, ttl := "192.0.2.1", 1
	if revision == 2 {
		ip, ttl = "192.0.2.2", 60
	}
	r := new(dns.Msg)
	r.SetReply(q)
	a, _ := dns.NewRR(fmt.Sprintf("%s %d IN A %s", q.Question[0].Name, ttl, ip))
	r.Answer = []dns.RR{a}
	return r
}
func TestStaleRefreshCannotCrossRoutingGeneration(t *testing.T) {
	h, err := newHandle(config.Conf{Cache: config.CacheConf{Size: 1, MinTTL: 1, MaxTTL: 60, ServeStale: 10}, Groups: map[string]config.Group{"fallback": {}}})
	if err != nil {
		t.Fatal(err)
	}
	g := &changingStaleGroup{started: make(chan struct{}), release: make(chan struct{})}
	g.revision.Store(1)
	h.groups = map[string]outbound.IGroup{"changing": g}
	h.fallbackGroup = g
	h.start()
	defer h.stop()
	assertAnswer(t, staleQuery(h, "route.example."), "192.0.2.1")
	waitForStale(t, h, "route.example.")
	assertAnswer(t, staleQuery(h, "route.example."), "192.0.2.1")
	select {
	case <-g.started:
	case <-time.After(time.Second):
		t.Fatal("old refresh did not start")
	}
	g.revision.Store(2)
	assertAnswer(t, staleQuery(h, "route.example."), "192.0.2.2")
	close(g.release)
	waitRefreshIdle(t, h)
	assertAnswer(t, staleQuery(h, "route.example."), "192.0.2.2")
	if g.calls.Load() != 3 {
		t.Fatal("late old refresh evicted the new generation")
	}
}

func TestStoppedHandlerCannotBeResurrectedByReload(t *testing.T) {
	conf := config.Conf{Cache: config.CacheConf{Size: 1, ServeStale: 10}, Groups: map[string]config.Group{"fallback": {}}}
	handler, err := NewHandler(conf)
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Stop()
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); <-start; _ = handler.ReloadConfig(conf) }()
	}
	wg.Add(1)
	go func() { defer wg.Done(); <-start; handler.Stop() }()
	close(start)
	wg.Wait()
	if err := handler.ReloadConfig(conf); err == nil {
		t.Fatal("reload resurrected a stopped refresher")
	}
	if ptr := atomic.LoadPointer(&handler.(*handlerWrapper).handlerPtr); ptr != nil {
		t.Fatal("stopped handler retained workers")
	}
	if r := staleQuery(handler, "after-stop.example."); r == nil || r.Rcode != dns.RcodeServerFailure {
		t.Fatal("query after stop did not fail safely")
	}
}

func TestStaleNegativeRefreshInvalidatesPositive(t *testing.T) {
	for _, mode := range []int32{4, 5, 6, 7} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			u := newStaleUpstream(t)
			w, h, _ := staleHandler(t, u, 10)
			assertAnswer(t, staleQuery(w, "negative.example."), "192.0.2.1")
			waitForStale(t, h, "negative.example.")
			u.mode.Store(mode)
			assertAnswer(t, staleQuery(w, "negative.example."), "192.0.2.1")
			select {
			case <-u.started:
			case <-time.After(time.Second):
				t.Fatal("negative refresh did not run")
			}
			waitRefreshIdle(t, h)
			q := new(dns.Msg)
			q.SetQuestion("negative.example.", dns.TypeA)
			if r, _ := h.cache.Lookup(q, h.routingRevision()); r != nil {
				t.Fatal("valid negative refresh left the old positive available")
			}
			response := staleQuery(w, "negative.example.")
			if mode == 4 {
				if response.Rcode != dns.RcodeNameError {
					t.Fatal("next query did not receive NXDOMAIN")
				}
			} else if response.Rcode != dns.RcodeSuccess {
				t.Fatal("next query did not receive NOERROR/NODATA")
			}
			for _, answer := range response.Answer {
				if _, ok := answer.(*dns.A); ok {
					t.Fatal("next query received the stale positive")
				}
			}
			if r, _ := h.cache.Lookup(q, h.routingRevision()); r != nil {
				t.Fatal("negative answer was cached")
			}
		})
	}
}

type bootstrapLifecycleResolver struct{ started, stopped chan struct{} }

func (*bootstrapLifecycleResolver) ServeDNS(dns.ResponseWriter, *dns.Msg) {
	panic("expected contextual bootstrap")
}
func (r *bootstrapLifecycleResolver) ServeDNSContext(ctx context.Context, _ dns.ResponseWriter, _ *dns.Msg) {
	close(r.started)
	<-ctx.Done()
	close(r.stopped)
}

type bootstrapLifecycleGroup struct {
	caller   *outbound.DoHCallerV2
	resolver *bootstrapLifecycleResolver
}

func (*bootstrapLifecycleGroup) Match(*dns.Msg) bool            { return false }
func (*bootstrapLifecycleGroup) IsFallback() bool               { return true }
func (*bootstrapLifecycleGroup) Name() string                   { return "bootstrap" }
func (*bootstrapLifecycleGroup) String() string                 { return "bootstrap" }
func (*bootstrapLifecycleGroup) PostProcess(*dns.Msg, *dns.Msg) {}
func (g *bootstrapLifecycleGroup) Start(dns.Handler)            { g.caller.Start(g.resolver) }
func (g *bootstrapLifecycleGroup) Stop()                        { g.caller.Exit() }
func (g *bootstrapLifecycleGroup) Handle(q *dns.Msg) *dns.Msg   { r, _ := g.caller.Call(q); return r }
func (g *bootstrapLifecycleGroup) HandleContext(ctx context.Context, q *dns.Msg) *dns.Msg {
	r, _ := g.caller.CallContext(ctx, q)
	return r
}

func TestForegroundDoHBootstrapStopsAcrossReload(t *testing.T) {
	for _, reload := range []bool{false, true} {
		t.Run(fmt.Sprint(reload), func(t *testing.T) {
			conf := config.Conf{Groups: map[string]config.Group{"fallback": {}}}
			h, err := newHandle(conf)
			if err != nil {
				t.Fatal(err)
			}
			caller, err := outbound.NewDoHCallerV2("https://resolver.example.invalid/dns-query", nil)
			if err != nil {
				t.Fatal(err)
			}
			resolver := &bootstrapLifecycleResolver{started: make(chan struct{}), stopped: make(chan struct{})}
			group := &bootstrapLifecycleGroup{caller: caller, resolver: resolver}
			h.groups = map[string]outbound.IGroup{"bootstrap": group}
			h.fallbackGroup = group
			h.start()
			wrapper := &handlerWrapper{handlerPtr: unsafe.Pointer(h)}
			defer wrapper.Stop()
			result := make(chan struct{}, 3)
			call := func() { _ = staleQuery(wrapper, "bootstrap.example."); result <- struct{}{} }
			go call()
			select {
			case <-resolver.started:
			case <-time.After(time.Second):
				t.Fatal("foreground bootstrap did not start")
			}
			go call()
			go call()
			if reload {
				conf.Hosts = map[string]string{"bootstrap.example": "192.0.2.3"}
				if err := wrapper.ReloadConfig(conf); err != nil {
					t.Fatal(err)
				}
			} else {
				wrapper.Stop()
			}
			for i := 0; i < 3; i++ {
				select {
				case <-result:
				case <-time.After(time.Second):
					t.Fatal("foreground query hung during reload/stop")
				}
			}
			select {
			case <-resolver.stopped:
			case <-time.After(time.Second):
				t.Fatal("old bootstrap resolver survived lifecycle change")
			}
			if reload {
				assertAnswer(t, staleQuery(wrapper, "bootstrap.example."), "192.0.2.3")
			}
		})
	}
}
