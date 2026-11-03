package config_test

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/wolf-joe/ts-dns/cache"
	"github.com/wolf-joe/ts-dns/config"
	"github.com/wolf-joe/ts-dns/outbound"
)

func TestReadmeConfigurationAndForkLinks(t *testing.T) {
	raw, err := os.ReadFile("../README.md")
	if err != nil {
		t.Fatal(err)
	}
	readme := string(raw)
	blocks := regexp.MustCompile("(?ms)^[ \t]*```toml\\n(.*?)\\n[ \t]*```[ \t]*$").FindAllStringSubmatch(readme, -1)
	var defaults config.Conf
	if _, err := toml.DecodeFile("../ts-dns.toml", &defaults); err != nil {
		t.Fatal(err)
	}
	var sawProxy, sawStale bool
	for i, block := range blocks {
		var conf config.Conf
		if _, err := toml.Decode(block[1], &conf); err != nil {
			t.Fatalf("README TOML is invalid: %v", err)
		}
		if i == 0 && !reflect.DeepEqual(conf, defaults) {
			t.Fatal("README default example differs from ts-dns.toml")
		}
		if _, err := cache.NewDNSCache(conf); err != nil {
			t.Fatalf("README cache config is invalid: %v", err)
		}
		if conf.Cache.ServeStale > 0 {
			sawStale = true
			if conf.Cache.ServeStale != 300 || conf.Cache.StaleTTL != 5 || conf.Cache.Size <= 0 {
				t.Fatal("stale example does not enable documented behavior")
			}
		}
		if strings.Contains(block[1], "gfwlist_proxy") {
			sawProxy = true
			g := conf.Groups["dirty"]
			if g.GFWListFile != "" && !filepath.IsAbs(g.GFWListFile) {
				g.GFWListFile = filepath.Join("..", g.GFWListFile)
			}
			conf.Groups["dirty"] = g
			if _, err := outbound.BuildGroups(conf); err != nil {
				t.Fatalf("README updater config is invalid: %v", err)
			}
		}
	}
	if !sawProxy || !sawStale {
		t.Fatal("README lacks proxy or stale-cache example")
	}
	var sawRelease, sawCI bool
	for _, link := range regexp.MustCompile(`https://github\.com/[^\s)]+`).FindAllString(readme, -1) {
		if strings.Contains(link, "/releases") {
			sawRelease = true
		}
		if strings.Contains(link, "/actions/") {
			sawCI = true
		}
		if strings.Contains(link, "/releases") || strings.Contains(link, "/actions/") {
			if !strings.HasPrefix(link, "https://github.com/fqx/ts-dns/") {
				t.Fatalf("fork release/CI link points upstream: %s", link)
			}
		}
	}
	if !sawRelease || !sawCI {
		t.Fatal("README lacks fork release or CI links")
	}
	if !strings.Contains(readme, "https://github.com/wolf-joe/ts-dns") {
		t.Fatal("upstream attribution was removed")
	}
	for _, name := range []string{"../ts-dns.toml", "../ts-dns-full.toml"} {
		var conf config.Conf
		if _, err := toml.DecodeFile(name, &conf); err != nil {
			t.Fatal(err)
		}
		if conf.Cache.ServeStale != 0 || conf.Cache.StaleTTL != 5 {
			t.Fatal("distributed defaults unexpectedly enable stale serving")
		}
		if conf.Groups["dirty"].GFWListProxy != "" || conf.Groups["dirty"].GFWListTimeout != "10s" {
			t.Fatal("distributed proxy defaults drifted")
		}
	}
}
