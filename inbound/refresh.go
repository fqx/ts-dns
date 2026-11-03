package inbound

import (
	"context"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/wolf-joe/ts-dns/utils"
)

const staleRefreshWorkers = 4
const staleRefreshQueue = 64
const staleRefreshTimeout = 5 * time.Second

type cacheRefresh struct {
	key      string
	req      *dns.Msg
	revision uint64
}

type staleRefresher struct {
	mu      sync.Mutex
	pending map[string]bool
	queue   chan cacheRefresh
	ctx     context.Context
	cancel  context.CancelFunc
	stopped bool
	wg      sync.WaitGroup
}

func newStaleRefresher() *staleRefresher {
	ctx, cancel := context.WithCancel(context.Background())
	return &staleRefresher{pending: map[string]bool{}, queue: make(chan cacheRefresh, staleRefreshQueue), ctx: ctx, cancel: cancel}
}
func (h *handlerImpl) routingRevision() uint64 {
	var revision uint64
	for _, group := range h.groups {
		if versioned, ok := group.(interface{ CacheRevision() uint64 }); ok {
			revision += versioned.CacheRevision()
		}
	}
	return revision
}
func (r *staleRefresher) schedule(key string, req *dns.Msg, revision uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopped || r.pending[key] {
		return
	}
	job := cacheRefresh{key: key, req: req.Copy(), revision: revision}
	select {
	case r.queue <- job:
		r.pending[key] = true
	default:
	} // Do not block the stale reply or grow a new goroutine.
}
func (r *staleRefresher) start(h *handlerImpl) {
	for i := 0; i < staleRefreshWorkers; i++ {
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			for {
				select {
				case <-r.ctx.Done():
					return
				case job := <-r.queue:
					if r.ctx.Err() == nil && h.routingRevision() == job.revision {
						// Another refresh may already have made this entry fresh while queued.
						if _, key := h.cache.Lookup(job.req, job.revision); key == job.key {
							ctx, cancel := context.WithTimeout(r.ctx, staleRefreshTimeout)
							_ = h.handleRequest(ctx, utils.NewFakeRespWriter(), job.req, &job)
							cancel()
						}
					}
					r.mu.Lock()
					delete(r.pending, job.key)
					r.mu.Unlock()
				}
			}
		}()
	}
}
func (r *staleRefresher) stop() {
	r.mu.Lock()
	r.stopped = true
	r.cancel()
	r.mu.Unlock()
	r.wg.Wait()
	r.mu.Lock()
	clear(r.pending)
	r.queue = nil
	r.mu.Unlock()
}
