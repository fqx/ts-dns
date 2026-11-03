package main

import (
	"bytes"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/wolf-joe/ts-dns/config"
)

const privateProxy = "http://private-proxy-user:private-proxy-password@localhost:8080"

type reloadTestHandler struct{ seen string }

func (h *reloadTestHandler) ReloadConfig(c config.Conf) error {
	h.seen = c.Groups["g"].GFWListProxy
	return nil
}
func (*reloadTestHandler) ServeDNS(dns.ResponseWriter, *dns.Msg) {}
func (*reloadTestHandler) Stop()                                 {}

func TestConfigLoggingKeepsProxyCredentialsPrivate(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "config.toml")
	contents := "[groups.g]\ngfwlist_proxy = \"" + privateProxy + "\"\n"
	if err := os.WriteFile(filename, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	previousOutput, previousLevel := logrus.StandardLogger().Out, logrus.GetLevel()
	defer logrus.SetOutput(previousOutput)
	defer logrus.SetLevel(previousLevel)
	var logs bytes.Buffer
	logrus.SetOutput(&logs)
	logrus.SetLevel(logrus.DebugLevel)
	handler := new(reloadTestHandler)
	signals := make(chan os.Signal, 1)
	signals <- syscall.SIGHUP
	close(signals)
	done := make(chan struct{})
	go func() { reloadConf(signals, &filename, handler); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("reload did not finish")
	}
	if handler.seen != privateProxy {
		t.Fatal("proxy was not loaded")
	}
	if strings.Contains(logs.String(), "private-proxy-") {
		t.Fatal("reload debug log disclosed credentials")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(executable, "-test.run=^TestConfigLoggingHelper$")
	cmd.Env = append(os.Environ(), "TS_DNS_LOGGING_HELPER=1", "TS_DNS_LOGGING_CONFIG="+filename)
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("expected helper to stop at invalid listen protocol")
	}
	if strings.Contains(string(output), "private-proxy-") {
		t.Fatal("startup debug log disclosed credentials")
	}
	if !strings.Contains(string(output), "unknown network") {
		t.Fatal("startup helper did not reach listen validation")
	}
}

func TestConfigLoggingHelper(t *testing.T) {
	if os.Getenv("TS_DNS_LOGGING_HELPER") != "1" {
		return
	}
	flag.CommandLine = flag.NewFlagSet("config-logging-helper", flag.ExitOnError)
	os.Args = []string{os.Args[0], "-c", os.Getenv("TS_DNS_LOGGING_CONFIG"), "-vv", "-listen", "127.0.0.1:0/invalid"}
	main()
}

func TestConfigParseErrorsKeepProxyCredentialsPrivate(t *testing.T) {
	for _, value := range []string{"\"" + privateProxy + "\\q\"", "[\"" + privateProxy + "\"]"} {
		filename := filepath.Join(t.TempDir(), "config.toml")
		if err := os.WriteFile(filename, []byte("[groups.g]\ngfwlist_proxy="+value+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		_, err := readConfig(filename)
		if err == nil {
			t.Fatal("accepted malformed config")
		}
		if strings.Contains(err.Error(), "private-proxy-") {
			t.Fatal("parse error disclosed credentials")
		}
	}
}
