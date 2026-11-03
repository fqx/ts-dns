package outbound

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/BurntSushi/toml"
	"github.com/miekg/dns"
	"github.com/wolf-joe/ts-dns/config"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestBundledSeedStartupAndFailedRefresh(t *testing.T) {
	var metadata struct {
		SHA256 string `json:"sha256"`
		Size   int    `json:"size_bytes"`
	}
	raw, err := os.ReadFile("../gfwlist-source.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &metadata); err != nil {
		t.Fatal(err)
	}
	seed, err := os.ReadFile("../gfwlist.txt")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(seed)
	if len(seed) != metadata.Size || hex.EncodeToString(digest[:]) != metadata.SHA256 {
		t.Fatal("seed does not match provenance checksum")
	}
	for _, name := range []string{"../ts-dns.toml", "../ts-dns-full.toml"} {
		var conf config.Conf
		if _, err := toml.DecodeFile(name, &conf); err != nil {
			t.Fatal(err)
		}
		if conf.Groups["dirty"].GFWListFile != "gfwlist.txt" {
			t.Fatalf("%s lacks startup seed", name)
		}
	}
	release, err := os.ReadFile("../.goreleaser.yml")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{"gfwlist.txt", "gfwlist-source.json"} {
		if !strings.Contains(string(release), "      - "+file+"\n") {
			t.Fatalf("release does not bundle %s", file)
		}
	}
	attempted := make(chan struct{}, 1)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503); attempted <- struct{}{} }))
	defer s.Close()
	groups, err := BuildGroups(config.Conf{Groups: map[string]config.Group{"dirty": {GFWListFile: "../gfwlist.txt", GFWListURL: s.URL, GFWListUpdateInterval: "24h"}}})
	if err != nil {
		t.Fatal(err)
	}
	g := groups["dirty"]
	q := new(dns.Msg)
	q.SetQuestion("www.youtube.com.", dns.TypeA)
	if !g.Match(q) {
		t.Fatal("seed unavailable before startup fetch")
	}
	g.Start(nil)
	defer g.Stop()
	select {
	case <-attempted:
	case <-time.After(time.Second):
		t.Fatal("fetch did not start")
	}
	if !g.Match(q) {
		t.Fatal("failed fetch discarded startup seed")
	}
}
