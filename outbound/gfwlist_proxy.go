package outbound

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

const defaultGFWListTimeout = 10 * time.Second

// parseGFWListProxy deliberately does not return parser errors containing input:
// proxy URLs may carry credentials, including malformed or percent-encoded ones.
func parseGFWListProxy(setting string) (*url.URL, error) {
	if setting == "" || setting == "direct" {
		return nil, nil
	}
	u, err := url.Parse(setting)
	if err != nil {
		return nil, errors.New("invalid gfwlist_proxy URL")
	}
	defaults := map[string]string{"http": "80", "https": "443", "socks5": "1080", "socks5h": "1080"}
	port, ok := defaults[u.Scheme]
	if !ok {
		return nil, errors.New("gfwlist_proxy must be direct or an http, https, socks5 or socks5h URL")
	}
	if u.Hostname() == "" || u.Opaque != "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, errors.New("gfwlist_proxy requires a host and no path, query or fragment")
	}
	host := u.Hostname()
	if strings.HasPrefix(u.Host, "[") {
		if !strings.Contains(host, ":") || net.ParseIP(strings.SplitN(host, "%", 2)[0]) == nil {
			return nil, errors.New("invalid gfwlist_proxy IPv6 address")
		}
	} else if strings.Contains(host, ":") {
		return nil, errors.New("gfwlist_proxy IPv6 addresses must be bracketed")
	}
	if strings.HasSuffix(u.Host, ":") {
		return nil, errors.New("invalid gfwlist_proxy port")
	}
	if u.Port() != "" {
		port = u.Port()
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return nil, errors.New("invalid gfwlist_proxy port")
	}
	u.Host = net.JoinHostPort(host, port)
	u.Path = ""
	if (u.Scheme == "socks5" || u.Scheme == "socks5h") && u.User != nil {
		password, hasPassword := u.User.Password()
		if !hasPassword || len(u.User.Username()) < 1 || len(u.User.Username()) > 255 || len(password) < 1 || len(password) > 255 {
			return nil, errors.New("gfwlist_proxy SOCKS5 credentials must each contain 1 to 255 bytes")
		}
	}
	return u, nil
}

func newGFWListClient(setting string, inherited proxy.Dialer, timeout time.Duration) (*http.Client, error) {
	proxyURL, err := parseGFWListProxy(setting)
	if err != nil {
		return nil, err
	}
	if timeout <= 0 {
		return nil, errors.New("gfwlist_timeout must be positive")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	var dialer proxy.Dialer
	switch {
	case setting == "direct":
		transport.Proxy = nil
	case proxyURL != nil:
		if proxyURL.Scheme == "http" || proxyURL.Scheme == "https" {
			transport.Proxy = http.ProxyURL(proxyURL)
		} else {
			transport.Proxy = nil
			dialer, err = proxy.FromURL(proxyURL, &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second})
			if err != nil {
				return nil, errors.New("cannot configure gfwlist_proxy SOCKS5 dialer")
			}
		}
	case inherited != nil:
		transport.Proxy = nil
		dialer = inherited
	}
	if dialer != nil {
		d, ok := dialer.(proxy.ContextDialer)
		if !ok {
			return nil, errors.New("gfwlist proxy must support context cancellation")
		}
		transport.DialContext = d.DialContext
	}
	client := &http.Client{Timeout: timeout, Transport: transport}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("too many redirects")
		}
		if via[0].URL.Scheme == "https" && req.URL.Scheme != "https" {
			return errors.New("insecure redirect")
		}
		return validateGFWListURL(req.URL.String())
	}
	return client, nil
}

// Keep operational errors useful without rendering nested URLs, proxy responses,
// or credentials. Unwrap preserves errors.Is/As for cancellation and timeouts.
type gfwListNetworkError struct {
	operation string
	cause     error
}

func (e *gfwListNetworkError) Error() string {
	if errors.Is(e.cause, context.Canceled) {
		return e.operation + ": canceled"
	}
	var timeout net.Error
	if errors.Is(e.cause, context.DeadlineExceeded) || (errors.As(e.cause, &timeout) && timeout.Timeout()) {
		return e.operation + ": timed out"
	}
	return fmt.Sprintf("%s: network or proxy failure", e.operation)
}
func (e *gfwListNetworkError) Unwrap() error { return e.cause }
