package inbound

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/wolf-joe/ts-dns/cache"
	"github.com/wolf-joe/ts-dns/config"
	"github.com/wolf-joe/ts-dns/hosts"
	"github.com/wolf-joe/ts-dns/outbound"
	"github.com/wolf-joe/ts-dns/redirector"
)

// region interface

// IHandler ts-dns service handler
type IHandler interface {
	dns.Handler
	ReloadConfig(conf config.Conf) error
	Stop()
}

// NewHandler Build a service can handle dns request, life cycle start immediately
func NewHandler(conf config.Conf) (IHandler, error) {
	h := new(handlerWrapper)
	if err := h.ReloadConfig(conf); err != nil {
		return nil, err
	}
	return h, nil
}

// endregion

// region wrapper
var (
	_ IHandler = &handlerWrapper{}
)

// todo: add unittest
type handlerWrapper struct {
	handlerPtr unsafe.Pointer // type: *handlerImpl
	lifecycle  sync.Mutex
	stopped    bool
}

func (w *handlerWrapper) ReloadConfig(conf config.Conf) error {
	w.lifecycle.Lock()
	defer w.lifecycle.Unlock()
	if w.stopped {
		return errors.New("handler is stopped")
	}
	// create & start new handler
	h, err := newHandle(conf)
	if err != nil {
		return fmt.Errorf("make new handler failed: %w", err)
	}
	h.start()
	// Serialize lifecycle changes so concurrent reloads cannot accumulate workers
	// or resurrect a handler after Stop has returned.
	old := atomic.SwapPointer(&w.handlerPtr, unsafe.Pointer(h))
	if old != nil {
		(*handlerImpl)(old).stop()
	}
	return nil
}

func (w *handlerWrapper) ServeDNS(writer dns.ResponseWriter, req *dns.Msg) {
	ptr := atomic.LoadPointer(&w.handlerPtr)
	if ptr == nil {
		resp := new(dns.Msg)
		resp.SetRcode(req, dns.RcodeServerFailure)
		_ = writer.WriteMsg(resp)
		_ = writer.Close()
		return
	}
	(*handlerImpl)(ptr).ServeDNS(writer, req)
}

func (w *handlerWrapper) Stop() {
	w.lifecycle.Lock()
	defer w.lifecycle.Unlock()
	if w.stopped {
		return
	}
	w.stopped = true
	if old := atomic.SwapPointer(&w.handlerPtr, nil); old != nil {
		(*handlerImpl)(old).stop()
	}
}

// endregion

func newHandle(conf config.Conf) (*handlerImpl, error) {
	var err error
	h := &handlerImpl{
		disableQTypes: map[uint16]bool{},
		cache:         nil,
		hosts:         nil,
		groups:        nil,
		redirector:    nil,
	}
	// disable query types
	if conf.DisableIPv6 {
		h.disableQTypes[dns.TypeAAAA] = true
	}
	for _, qTypeStr := range conf.DisableQTypes {
		qTypeStr = strings.ToUpper(qTypeStr)
		if _, exists := dns.StringToType[qTypeStr]; !exists {
			return nil, fmt.Errorf("unknown query type: %q", qTypeStr)
		}
		h.disableQTypes[dns.StringToType[qTypeStr]] = true
	}

	// hosts & cache
	h.hosts, err = hosts.NewDNSHosts(conf)
	if err != nil {
		return nil, fmt.Errorf("build hosts failed: %w", err)
	}
	h.cache, err = cache.NewDNSCache(conf)
	if err != nil {
		return nil, fmt.Errorf("build cache failed: %w", err)
	}
	h.groups, err = outbound.BuildGroups(conf)
	if err != nil {
		return nil, fmt.Errorf("build groups failed: %w", err)
	}
	for _, group := range h.groups {
		if group.IsFallback() {
			h.fallbackGroup = group
		}
	}
	if h.fallbackGroup == nil {
		return nil, errors.New("fallback group not found")
	}
	h.redirector, err = redirector.NewRedirector(conf, h.groups)
	if err != nil {
		return nil, fmt.Errorf("build redirector failed: %w", err)
	}
	if conf.Cache.ServeStale > 0 && conf.Cache.Size > 0 {
		h.refresh = newStaleRefresher()
	}
	return h, nil
}

// region impl
type handlerImpl struct {
	disableQTypes map[uint16]bool
	cache         cache.IDNSCache
	hosts         hosts.IDNSHosts
	groups        map[string]outbound.IGroup
	fallbackGroup outbound.IGroup
	redirector    redirector.Redirector
	refresh       *staleRefresher
}

func (h *handlerImpl) ServeDNS(writer dns.ResponseWriter, req *dns.Msg) {
	resp := h.handle(writer, req)
	if resp == nil {
		resp = new(dns.Msg)
	}
	if !resp.Response {
		resp.SetReply(req)
	}
	_ = writer.WriteMsg(resp)
	_ = writer.Close()
}

func (h *handlerImpl) handle(writer dns.ResponseWriter, req *dns.Msg) *dns.Msg {
	return h.handleRequest(context.Background(), writer, req, nil)
}

// Internal DoH bootstrap queries inherit cancellation from their parent request.
func (h *handlerImpl) ServeDNSContext(ctx context.Context, writer dns.ResponseWriter, req *dns.Msg) {
	resp := h.handleRequest(ctx, writer, req, nil)
	if resp == nil {
		resp = new(dns.Msg)
	}
	if !resp.Response {
		resp.SetReply(req)
	}
	_ = writer.WriteMsg(resp)
	_ = writer.Close()
}

func (h *handlerImpl) handleRequest(ctx context.Context, writer dns.ResponseWriter, req *dns.Msg, refresh *cacheRefresh) (resp *dns.Msg) {
	if ctx.Err() != nil {
		return nil
	}
	callGroup := func(group outbound.IGroup) *dns.Msg {
		if contextual, ok := group.(interface {
			HandleContext(context.Context, *dns.Msg) *dns.Msg
		}); ok {
			return contextual.HandleContext(ctx, req)
		}
		return group.Handle(req)
	}
	// region log
	_info := struct {
		blocked  bool
		hitHosts bool
		hitCache bool
		matched  outbound.IGroup
		fallback bool
		redirect outbound.IGroup
	}{}
	begin := time.Now()
	defer func() {
		fields := logrus.Fields{
			"cost":   strconv.FormatInt(time.Since(begin).Milliseconds(), 10) + "ms",
			"remote": writer.RemoteAddr().String(),
		}
		if _info.blocked {
			fields["blocked"] = true
		}
		if _info.hitHosts {
			fields["hit_hosts"] = true
		}
		if _info.hitCache {
			fields["hit_cache"] = true
		}
		if len(req.Question) > 0 {
			fields["question"] = req.Question[0].Name
			fields["q_type"] = dns.TypeToString[req.Question[0].Qtype]
		}
		if _info.matched != nil {
			if _info.fallback {
				fields["group"] = "_" + _info.matched.Name()
			} else {
				fields["group"] = _info.matched.Name()
			}
		}
		if _info.redirect != nil {
			fields["redir"] = _info.redirect.Name()
		}
		if resp == nil {
			fields["answer"] = "nil"
		} else {
			fields["answer"] = len(resp.Answer)
		}
		if _info.blocked || _info.hitCache || _info.hitHosts {
			logrus.WithFields(fields).Debug()
		} else {
			logrus.WithFields(fields).Info()
		}
	}()
	// endregion
	for _, question := range req.Question {
		if h.disableQTypes[question.Qtype] {
			_info.blocked = true
			return nil // disabled
		}
	}
	if resp = h.hosts.Get(req); resp != nil {
		_info.hitHosts = true
		return resp
	}
	// Capture once: late old-route responses can only populate their old namespace.
	revision := h.routingRevision()
	if refresh != nil {
		if refresh.revision != revision {
			return nil
		}
		revision = refresh.revision
	} else {
		var refreshKey string
		resp, refreshKey = h.cache.Lookup(req, revision)
		if resp != nil {
			_info.hitCache = true
			if refreshKey != "" && h.refresh != nil {
				h.refresh.schedule(refreshKey, req, revision)
			}
			return resp
		}
	}

	// handle by matched group
	var matched outbound.IGroup
	for _, group := range h.groups {
		if group.Match(req) {
			matched = group
			resp = callGroup(group)
			break
		}
	}
	if matched == nil {
		matched = h.fallbackGroup
		resp = callGroup(h.fallbackGroup)
		_info.fallback = true
	}
	_info.matched = matched

	// redirect
	if h.redirector != nil {
		if group := h.redirector(matched, req, resp); group != nil {
			matched = group
			resp = callGroup(group)
			_info.redirect = group
		}
	}

	// finally
	if ctx.Err() != nil {
		return nil
	}
	if contextual, ok := matched.(interface {
		PostProcessContext(context.Context, *dns.Msg, *dns.Msg)
	}); ok {
		contextual.PostProcessContext(ctx, req, resp)
	} else {
		matched.PostProcess(req, resp)
	}
	if ctx.Err() != nil {
		return nil
	}
	if refresh != nil {
		h.cache.InvalidateNegativeRefresh(refresh.token, req, resp)
	}
	h.cache.Set(req, resp, revision)
	return resp
}

func (h *handlerImpl) start() {
	if h.refresh != nil {
		h.refresh.start(h)
	}
	for _, group := range h.groups {
		group.Start(h)
	}
	h.cache.Start()
	logrus.Debugf("start handler success")
}

func (h *handlerImpl) stop() {
	logrus.Debugf("stop handler")
	if h.refresh != nil {
		h.refresh.stop()
	}
	for _, group := range h.groups {
		group.Stop()
	}
	h.cache.Stop()
	logrus.Debugf("stop handler success")
}

// endregion
