package outbound

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/sirupsen/logrus"
	"github.com/wolf-joe/ts-dns/utils"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/valyala/fastrand"
	"golang.org/x/net/proxy"
)

// Caller 上游DNS请求基类
type Caller interface {
	Call(request *dns.Msg) (r *dns.Msg, err error)
	Start(resolver dns.Handler)
	Exit()
	String() string
}

var (
	_ Caller = &DNSCaller{}
	_ Caller = &DoHCallerV2{}
)

// DNSCaller UDP/TCP/DOT请求类
type DNSCaller struct {
	client *dns.Client
	server string
	proxy  proxy.Dialer
}

func (caller *DNSCaller) Start(_ dns.Handler) {}

// Call 向目标上游DNS转发请求
func (caller *DNSCaller) Call(request *dns.Msg) (r *dns.Msg, err error) {
	if caller.proxy == nil { // 不使用代理，直接发送dns请求
		r, _, err = caller.client.Exchange(request, caller.server)
		if err != nil {
			return nil, err
		}
		if err = validateDNSResponse(request, r); err != nil {
			return nil, err
		}
		return
	}
	return caller.callProxy(context.Background(), request)
}

// CallContext owns a cancellable connection, including established reads/TLS.
func (caller *DNSCaller) CallContext(ctx context.Context, request *dns.Msg) (*dns.Msg, error) {
	if caller.proxy != nil {
		return caller.callProxy(ctx, request)
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	conn, err := caller.client.DialContext(ctx, caller.server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	resp, _, err := caller.client.ExchangeWithConnContext(ctx, request, conn)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, err
	}
	if err := validateDNSResponse(request, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (caller *DNSCaller) callProxy(parent context.Context, request *dns.Msg) (*dns.Msg, error) {
	timeout := caller.client.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	d, ok := caller.proxy.(proxy.ContextDialer)
	if !ok {
		return nil, errors.New("DNS proxy must support context cancellation")
	}
	proxyConn, err := d.DialContext(ctx, "tcp", caller.server)
	if err != nil {
		return nil, err
	}
	defer proxyConn.Close()
	stop := context.AfterFunc(ctx, func() { _ = proxyConn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if err := proxyConn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	conn := &dns.Conn{Conn: proxyConn}
	if caller.client.TLSConfig != nil {
		conn.Conn = tls.Client(proxyConn, caller.client.TLSConfig)
	}
	if err := conn.WriteMsg(request); err != nil {
		return nil, err
	}
	resp, err := conn.ReadMsg()
	if err != nil {
		return nil, err
	}
	if err := validateDNSResponse(request, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// Exit caller退出时行为
func (caller *DNSCaller) Exit() {}

// String 描述caller
func (caller *DNSCaller) String() string {
	return fmt.Sprintf("DNSCaller<%s/%s>", caller.server, caller.client.Net)
}

// NewDNSCaller 创建一个UDP/TCP Caller，需要服务器地址（ip+端口）、网络类型（udp、tcp），可选代理
func NewDNSCaller(server, network string, proxy proxy.Dialer) *DNSCaller {
	client := &dns.Client{Net: network}
	return &DNSCaller{client: client, server: server, proxy: proxy}
}

// NewDoTCaller 创建一个DoT Caller，需要服务器地址（ip+端口）、证书名称，可选代理
func NewDoTCaller(server, serverName string, proxy proxy.Dialer) *DNSCaller {
	client := &dns.Client{Net: "tcp-tls", TLSConfig: &tls.Config{ServerName: serverName}}
	return &DNSCaller{client: client, server: server, proxy: proxy}
}

// DoHCallerV2 DoT请求类，通过resolver自动解析域名
type DoHCallerV2 struct {
	host     string
	port     string
	url      string
	clients  []*http.Client
	rwMux    sync.RWMutex
	resolver dns.Handler
	dialer   proxy.Dialer

	requireCh       chan *dohClientRequest
	resolverContext context.Context
	cancelResolver  context.CancelFunc
	cancelCh        chan interface{} // stop run()
}

func (caller *DoHCallerV2) Start(resolver dns.Handler) {
	caller.resolver = resolver
	caller.resolverContext, caller.cancelResolver = context.WithCancel(context.Background())
	go caller.run(time.Hour*24, time.Second)
}

// 后台goroutine，负责定时/按需解析DoH服务器域名
func (caller *DoHCallerV2) run(resolveCycle time.Duration, timeout time.Duration) {
	tick := time.NewTicker(resolveCycle)
	for {
		select {
		case <-tick.C:
			caller.resolve(nil, timeout, caller.resolverContext)
		case job := <-caller.requireCh:
			caller.rwMux.RLock()
			empty := len(caller.clients) == 0
			caller.rwMux.RUnlock()
			if empty {
				caller.resolve(job.req, timeout, job.ctx)
			}
			close(job.done)
		case <-caller.cancelCh:
			tick.Stop()
			return
		}
	}
}

// 使用resolver，将host解析成ipv4并生成clients
func (caller *DoHCallerV2) resolve(srcReq *dns.Msg, timeout time.Duration, parents ...context.Context) {
	parent := context.Background()
	if len(parents) > 0 && parents[0] != nil {
		parent = parents[0]
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	genClient := func(ip string) *http.Client {
		return &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (conn net.Conn, err error) {
				addr := ip + ":" + caller.port // 重写addr
				if d, ok := caller.dialer.(proxy.ContextDialer); ok {
					return d.DialContext(ctx, network, addr)
				}
				return nil, errors.New("DoH dialer must support context cancellation")
			},
		}}
	}
	name := caller.host + "."
	if srcReq != nil && len(srcReq.Question) > 0 && strings.EqualFold(srcReq.Question[0].Name, name) {
		logrus.Errorf("%s resolve recursive", caller)
		return // 可能是回环解析：DoHCaller想通过ts-dns解析自身域名，但ts-dns将请求转发回DoHCaller
	}
	// 模拟dns请求
	resolveReq := &dns.Msg{
		MsgHdr:   dns.MsgHdr{Id: 0xffff, RecursionDesired: true, AuthenticatedData: true},
		Question: []dns.Question{{Name: name, Qtype: dns.TypeA, Qclass: dns.ClassINET}},
	}
	writer := utils.NewFakeRespWriter()
	done := make(chan interface{}, 1)
	contextual, contextAware := caller.resolver.(interface {
		ServeDNSContext(context.Context, dns.ResponseWriter, *dns.Msg)
	})
	go func() {
		if caller.resolver != nil {
			if contextAware {
				contextual.ServeDNSContext(ctx, writer, resolveReq)
			} else {
				caller.resolver.ServeDNS(writer, resolveReq)
			}
		}
		done <- struct{}{}
	}()
	select {
	case <-done:
	case <-ctx.Done():
		if contextAware {
			<-done
		}
		return // canceled or timed out
	}
	// 解析响应中的ipv4地址
	clients := make([]*http.Client, 0, 2)
	ips := make([]string, 0, 2)
	if writer.Msg != nil {
		for _, rr := range writer.Msg.Answer {
			switch resp := rr.(type) {
			case *dns.A:
				clients = append(clients, genClient(resp.A.String()))
				ips = append(ips, resp.A.String())
			}
		}
	}
	if len(clients) > 0 {
		caller.rwMux.Lock()
		old := caller.clients
		caller.clients = clients
		caller.rwMux.Unlock()
		for _, client := range old {
			client.CloseIdleConnections()
		}
		logrus.Debugf("%s resolve ip %s", caller, ips)
	} else {
		logrus.Warnf("%s resolve ip failed", caller)
	}
}

// 获取一个用于发送DoH查询请求的http客户端
type dohClientRequest struct {
	req  *dns.Msg
	ctx  context.Context
	done chan struct{}
}

func (caller *DoHCallerV2) getClientContext(ctx context.Context, req *dns.Msg) *http.Client {
	choose := func() *http.Client {
		caller.rwMux.RLock()
		defer caller.rwMux.RUnlock()
		if len(caller.clients) == 0 {
			return nil
		}
		return caller.clients[fastrand.Uint32n(uint32(len(caller.clients)))]
	}
	if client := choose(); client != nil {
		return client
	}
	job := &dohClientRequest{req: req, ctx: ctx, done: make(chan struct{})}
	select {
	case caller.requireCh <- job:
	case <-ctx.Done():
		return nil
	}
	select {
	case <-job.done:
		return choose()
	case <-ctx.Done():
		return nil
	}
}

// Call 向上游DNS转发请求
func (caller *DoHCallerV2) Call(request *dns.Msg) (*dns.Msg, error) {
	return caller.CallContext(context.Background(), request)
}
func (caller *DoHCallerV2) CallContext(ctx context.Context, request *dns.Msg) (r *dns.Msg, err error) {
	client := caller.getClientContext(ctx, request)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if client == nil {
		return nil, errors.New("empty client for doh caller")
	}
	// 解包dns请求
	var buf []byte
	if buf, err = request.Pack(); err != nil {
		return nil, err
	}
	// 打包http请求
	var req *http.Request
	contentType, payload := "application/dns-message", bytes.NewBuffer(buf)
	if req, err = http.NewRequest("POST", caller.url, payload); err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", contentType)
	// 发送http请求
	var resp *http.Response
	if resp, err = client.Do(req); err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH HTTP status %d", resp.StatusCode)
	}
	// 解包http响应
	var body []byte
	if body, err = io.ReadAll(io.LimitReader(resp.Body, dns.MaxMsgSize+1)); err != nil {
		return nil, err
	}
	if len(body) > dns.MaxMsgSize {
		return nil, errors.New("DoH response exceeds DNS size limit")
	}
	// 打包dns响应
	msg := new(dns.Msg)
	if err = msg.Unpack(body); err != nil {
		return nil, err
	}
	if err := validateDNSResponse(request, msg); err != nil {
		return nil, err
	}
	return msg, nil
}

// Exit 停止后台goroutine。caller退出时行为
func (caller *DoHCallerV2) Exit() {
	logrus.Debugf("stop caller %s", caller)
	if caller.cancelResolver != nil {
		caller.cancelResolver()
	}
	caller.rwMux.RLock()
	for _, client := range caller.clients {
		client.CloseIdleConnections()
	}
	caller.rwMux.RUnlock()
	caller.cancelCh <- struct{}{}
	logrus.Debugf("stop caller %s success", caller)
}

// String 描述caller
func (caller *DoHCallerV2) String() string {
	return fmt.Sprintf("DoHCallerV2<%s>", caller.url)
}

// SetResolver 为DoHCaller设置域名解析器，需要在用NewDoHCallerV2()成功后调用一次
func (caller *DoHCallerV2) SetResolver(resolver dns.Handler) {
	caller.resolver = resolver
}

// NewDoHCallerV2 创建一个DoHCaller，需要服务器url，可选代理
func NewDoHCallerV2(rawURL string, dialer proxy.Dialer) (*DoHCallerV2, error) {
	// 解析url
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if !u.IsAbs() || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
		return nil, fmt.Errorf("rawURL should be abs url")
	}
	// 提取host、port
	var host, port string
	if i := strings.LastIndex(u.Host, ":"); i == -1 {
		u.Host += ":443"
	}
	if host, port, err = net.SplitHostPort(u.Host); err != nil {
		return nil, err
	}

	if dialer == nil {
		dialer = &net.Dialer{Timeout: time.Second * 3}
	}
	caller := &DoHCallerV2{host: host, port: port, url: u.String(),
		rwMux: sync.RWMutex{}, dialer: dialer}
	caller.requireCh = make(chan *dohClientRequest, 1)
	caller.cancelCh = make(chan interface{}, 1)
	return caller, nil
}

func validateDNSResponse(req, resp *dns.Msg) error {
	if resp == nil || !resp.Response || resp.Id != req.Id || resp.Opcode != req.Opcode || len(resp.Question) != len(req.Question) {
		return errors.New("invalid DNS response")
	}
	for i, q := range req.Question {
		r := resp.Question[i]
		if !strings.EqualFold(q.Name, r.Name) || q.Qtype != r.Qtype || q.Qclass != r.Qclass {
			return errors.New("DNS response question mismatch")
		}
	}
	return nil
}
