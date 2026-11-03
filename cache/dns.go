package cache

import (
	"fmt"
	"github.com/miekg/dns"
	"github.com/valyala/fastrand"
	"github.com/wolf-joe/ts-dns/config"
	"github.com/wolf-joe/ts-dns/utils"
	"strings"
	"sync"
	"time"
)

const (
	DefaultMinTTL = time.Minute    // DefaultMinTTL 默认dns缓存最小有效期
	DefaultMaxTTL = 24 * time.Hour // DefaultMaxTTL 默认dns缓存最大有效期
)

// IDNSCache cache dns response for dns request
type IDNSCache interface {
	// Get find cached response
	Get(req *dns.Msg, revision ...uint64) *dns.Msg
	// Lookup returns a refresh key only for an eligible stale response.
	Lookup(req *dns.Msg, revision ...uint64) (*dns.Msg, string)
	CaptureRefresh(req *dns.Msg, revision ...uint64) (RefreshToken, bool)
	InvalidateNegativeRefresh(token RefreshToken, req, resp *dns.Msg)
	// Set save response to cache
	Set(req *dns.Msg, resp *dns.Msg, revision ...uint64)
	// Start life cycle begin
	Start(cleanTick ...time.Duration)
	// Stop life cycle end
	Stop()
}

func NewDNSCache(conf config.Conf) (IDNSCache, error) {
	if conf.Cache.ServeStale < 0 || conf.Cache.ServeStale > 86400 {
		return nil, fmt.Errorf("cache.serve_stale must be between 0 and 86400 seconds")
	}
	if conf.Cache.StaleTTL < 0 || conf.Cache.StaleTTL > 30 {
		return nil, fmt.Errorf("cache.stale_ttl must be between 1 and 30 seconds, or 0 for the default")
	}
	staleTTL := conf.Cache.StaleTTL
	if staleTTL == 0 {
		staleTTL = 5
	}
	minTTL, maxTTL := DefaultMinTTL, DefaultMaxTTL
	if conf.Cache.MinTTL > 0 {
		minTTL = time.Second * time.Duration(conf.Cache.MinTTL)
	}
	if conf.Cache.MaxTTL > 0 {
		maxTTL = time.Second * time.Duration(conf.Cache.MaxTTL)
	}
	if minTTL > maxTTL {
		return nil, fmt.Errorf("min ttl(%d) larger than max ttl(%d)", conf.Cache.MinTTL, conf.Cache.MaxTTL)
	}
	c := &dnsCache{
		items:       map[string]cacheItem{},
		lock:        new(sync.RWMutex),
		stopCh:      make(chan struct{}),
		stopped:     make(chan struct{}),
		maxSize:     conf.Cache.Size,
		minTTL:      minTTL,
		maxTTL:      maxTTL,
		staleWindow: int64(conf.Cache.ServeStale),
		staleTTL:    int64(staleTTL),
		now:         time.Now,
	}
	return c, nil
}

var (
	_ IDNSCache = &dnsCache{}
)

type cacheItem struct {
	resp      *dns.Msg
	expiredAt int64
}

type dnsCache struct {
	items   map[string]cacheItem
	lock    *sync.RWMutex
	stopCh  chan struct{}
	stopped chan struct{}

	revision    uint64 // protected by lock; monotonically advances for this cache lifetime
	maxSize     int
	minTTL      time.Duration
	maxTTL      time.Duration
	staleWindow int64
	staleTTL    int64
	now         func() time.Time
}

func (c *dnsCache) cacheKey(req *dns.Msg, revision ...uint64) string {
	question := req.Question[0]
	key := fmt.Sprintf("%s|%d|%d|%t|%t|%t|%t", question.Name, question.Qtype, question.Qclass, req.CheckingDisabled, req.IsEdns0() != nil && req.IsEdns0().Do(), req.AuthenticatedData, req.RecursionDesired)
	generation := routingRevision(revision)
	var udpSize uint16
	opt := req.IsEdns0()
	if opt != nil {
		udpSize = opt.UDPSize()
	}
	key += fmt.Sprintf("|routing:%d|edns:%t|udp:%d", generation, opt != nil, udpSize)
	if subnet := utils.FormatECS(req); subnet != "" {
		key += "." + subnet
	}
	return strings.ToLower(key)
}

func (c *dnsCache) Get(req *dns.Msg, revision ...uint64) *dns.Msg {
	r, _ := c.Lookup(req, revision...)
	return r
}

func (c *dnsCache) Lookup(req *dns.Msg, revision ...uint64) (*dns.Msg, string) {
	if c.maxSize <= 0 || !cacheableQuery(req) {
		return nil, ""
	}
	// check cache
	key := c.cacheKey(req, revision...)
	requested := routingRevision(revision)
	c.lock.RLock()
	item, exists := c.items[key]
	current := c.revision
	c.lock.RUnlock()
	if requested != current {
		if requested < current {
			return nil, ""
		}
		c.lock.Lock()
		if !c.advanceRevisionLocked(requested) {
			c.lock.Unlock()
			return nil, ""
		}
		item, exists = c.items[key]
		c.lock.Unlock()
	}
	if !exists {
		return nil, ""
	}
	// Never advance expiredAt when returning stale data. Only a successful Set
	// can establish a new lifetime; failure and repeat hits keep the original bound.
	now := c.now().Unix()
	ttl := item.expiredAt - now
	refreshKey := ""
	if ttl <= 0 {
		remaining := item.expiredAt + c.staleWindow - now
		if c.staleWindow <= 0 || remaining <= 0 {
			c.lock.Lock()
			if latest, ok := c.items[key]; ok && latest.expiredAt+c.staleWindow <= now {
				delete(c.items, key)
			}
			c.lock.Unlock()
			return nil, ""
		}
		refreshKey = key
		ttl = min(c.staleTTL, remaining)
	}
	r := item.resp.Copy()
	r.Id = req.Id
	r.Question = append([]dns.Question(nil), req.Question...)
	r.RecursionDesired = req.RecursionDesired
	r.CheckingDisabled = req.CheckingDisabled
	for i := 0; i < len(r.Answer); i++ {
		r.Answer[i].Header().Ttl = uint32(ttl)
	}
	if refreshKey != "" {
		r.AuthenticatedData = false
		for _, section := range [][]dns.RR{r.Ns, r.Extra} {
			for _, rr := range section {
				if rr.Header().Rrtype != dns.TypeOPT {
					rr.Header().Ttl = uint32(ttl)
				}
			}
		}
	}
	// shuffle ip
	first := uint32(len(r.Answer))
	for ; first > 0; first-- {
		if t := r.Answer[first-1].Header().Rrtype; t != dns.TypeA && t != dns.TypeAAAA {
			break
		}
	}
	if ips := r.Answer[first:]; len(ips) > 1 {
		for i := uint32(len(ips) - 1); i > 0; i-- {
			j := fastrand.Uint32n(i + 1)
			ips[i], ips[j] = ips[j], ips[i]
		}
	}
	return r, refreshKey
}

func (c *dnsCache) Set(req *dns.Msg, resp *dns.Msg, revision ...uint64) {
	if c.maxSize <= 0 || !cacheableQuery(req) || resp == nil || resp.Truncated || resp.Rcode != dns.RcodeSuccess || len(resp.Answer) == 0 || negativeSOAAnswer(req, resp) {
		return
	}
	// reset ttl
	key := c.cacheKey(req, revision...)
	var expire = c.maxTTL
	for _, answer := range resp.Answer {
		if ttl := time.Duration(answer.Header().Ttl) * time.Second; ttl < expire {
			expire = ttl
		}
	}
	if expire < c.minTTL {
		expire = c.minTTL
	}
	for i := 0; i < len(resp.Answer); i++ {
		resp.Answer[i].Header().Ttl = uint32(expire.Seconds())
	}
	// set cache
	expiredAt := c.now().Add(expire).Unix()
	c.lock.Lock()
	if !c.advanceRevisionLocked(routingRevision(revision)) {
		c.lock.Unlock()
		return
	}
	if _, exists := c.items[key]; exists || len(c.items) < c.maxSize {
		c.items[key] = cacheItem{resp: resp.Copy(), expiredAt: expiredAt}
	}
	c.lock.Unlock()
}

func (c *dnsCache) Start(_cleanTick ...time.Duration) {
	c.stopCh = make(chan struct{})
	c.stopped = make(chan struct{})
	go func() {
		cleanTick := time.Minute
		if len(_cleanTick) > 0 {
			cleanTick = _cleanTick[0]
		}
		tk := time.NewTicker(cleanTick)
		for {
			select {
			case <-tk.C:
				c.cleanExpired()
			case <-c.stopCh:
				tk.Stop()
				close(c.stopped)
				return
			}
		}
	}()
}

func (c *dnsCache) Stop() {
	close(c.stopCh)
	<-c.stopped
}

// Queries with client-specific EDNS options or signatures must not share answers.
func cacheableQuery(req *dns.Msg) bool {
	if req == nil || len(req.Question) != 1 || req.Opcode != dns.OpcodeQuery {
		return false
	}
	seenOPT := false
	for _, rr := range req.Extra {
		opt, ok := rr.(*dns.OPT)
		if !ok || opt.Version() != 0 || seenOPT {
			return false
		}
		seenOPT = true
		for _, option := range opt.Option {
			if _, ok := option.(*dns.EDNS0_SUBNET); !ok {
				return false
			}
		}
	}
	return true
}

func routingRevision(revision []uint64) uint64 {
	if len(revision) == 0 {
		return 0
	}
	return revision[0]
}

// advanceRevisionLocked reclaims obsolete entries without allowing late requests
// to roll back the generation. The caller must hold the write lock.
func (c *dnsCache) advanceRevisionLocked(revision uint64) bool {
	if revision < c.revision {
		return false
	}
	if revision > c.revision {
		c.items = make(map[string]cacheItem)
		c.revision = revision
	}
	return true
}

// Keep stale entries only while the configured grace period can still serve them.
func (c *dnsCache) cleanExpired() {
	now := c.now().Unix()
	c.lock.Lock()
	for key, item := range c.items {
		if now >= item.expiredAt+c.staleWindow {
			delete(c.items, key)
		}
	}
	c.lock.Unlock()
}

// A CNAME can appear before a NOERROR/NODATA SOA response. Its long positive
// TTL must not turn that negative result into an eligible stale cache entry.
func negativeSOAAnswer(req, resp *dns.Msg) bool {
	for _, rr := range resp.Ns {
		if rr.Header().Rrtype == dns.TypeSOA {
			for _, answer := range resp.Answer {
				if req.Question[0].Qtype == dns.TypeANY || answer.Header().Rrtype == req.Question[0].Qtype {
					return false
				}
			}
			return true
		}
	}
	return false
}

// RefreshToken retains the exact immutable cache response, preventing pointer
// reuse and ensuring a delayed negative result cannot erase a newer insertion.
type RefreshToken struct {
	key      string
	revision uint64
	response *dns.Msg
}

func (c *dnsCache) CaptureRefresh(req *dns.Msg, revision ...uint64) (RefreshToken, bool) {
	if c.maxSize <= 0 || c.staleWindow <= 0 || !cacheableQuery(req) {
		return RefreshToken{}, false
	}
	generation := routingRevision(revision)
	key := c.cacheKey(req, generation)
	now := c.now().Unix()
	c.lock.RLock()
	defer c.lock.RUnlock()
	item, ok := c.items[key]
	if !ok || c.revision != generation || item.expiredAt > now || item.expiredAt+c.staleWindow <= now {
		return RefreshToken{}, false
	}
	return RefreshToken{key: key, revision: generation, response: item.resp}, true
}

func (c *dnsCache) InvalidateNegativeRefresh(token RefreshToken, req, resp *dns.Msg) {
	if token.response == nil || !validNegativeRefresh(req, resp) || c.cacheKey(req, token.revision) != token.key {
		return
	}
	c.lock.Lock()
	defer c.lock.Unlock()
	if c.revision != token.revision {
		return
	}
	if current, ok := c.items[token.key]; ok && current.resp == token.response {
		delete(c.items, token.key)
	}
}
func validNegativeRefresh(req, resp *dns.Msg) bool {
	if !cacheableQuery(req) || resp == nil || !resp.Response || resp.Truncated || resp.Id != req.Id || resp.Opcode != req.Opcode || len(resp.Question) != 1 {
		return false
	}
	q, r := req.Question[0], resp.Question[0]
	if !strings.EqualFold(q.Name, r.Name) || q.Qtype != r.Qtype || q.Qclass != r.Qclass {
		return false
	}
	if resp.Rcode == dns.RcodeNameError {
		return true
	}
	if resp.Rcode != dns.RcodeSuccess {
		return false
	}
	// SOA identifies NODATA, including CNAME+NODATA. Empty NOERROR without
	// authority records is also NODATA; NS-only referrals are not definitive.
	return negativeSOAAnswer(req, resp) || (len(resp.Answer) == 0 && len(resp.Ns) == 0)
}
