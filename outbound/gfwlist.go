package outbound

import (
	"context"
	"encoding/base64"
	"fmt"
	"github.com/wolf-joe/ts-dns/matcher"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const maxGFWListSize = 8 << 20

func validateGFWListURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil {
		return fmt.Errorf("invalid gfwlist_url")
	}
	return nil
}

func (g *groupImpl) fetchGFWList(ctx context.Context) (*matcher.ABPlus, error) {
	if err := validateGFWListURL(g.gfwListURL); err != nil {
		return nil, err
	}
	client := g.gfwListClient
	if client == nil {
		var err error
		client, err = newGFWListClient("", g.proxy, defaultGFWListTimeout)
		if err != nil {
			return nil, err
		}
		defer client.CloseIdleConnections()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.gfwListURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, &gfwListNetworkError{operation: "fetch gfwlist", cause: err}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP status %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxGFWListSize+1))
	if err != nil {
		return nil, &gfwListNetworkError{operation: "read gfwlist", cause: err}
	}
	if len(raw) > maxGFWListSize {
		return nil, fmt.Errorf("gfwlist exceeds size limit")
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("decode gfwlist: %w", err)
	}
	m := matcher.NewABPByText(string(decoded))
	if m.Empty() {
		return nil, fmt.Errorf("gfwlist contains no usable rules")
	}
	return m, nil
}
