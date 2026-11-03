package main

import (
	"errors"
	"flag"
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/wolf-joe/ts-dns/config"
	"github.com/wolf-joe/ts-dns/inbound"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
)

// VERSION 程序版本号
var VERSION = "dev"

func main() {
	// 读取命令行参数
	filename := flag.String("c", "ts-dns.toml", "config file path")
	listen := flag.String("listen", "", "listen address/port/protocol")
	showVer := flag.Bool("v", false, "show version and exit")
	debugMode := flag.Bool("vv", false, "show debug log")
	flag.Parse()
	if *showVer { // 显示版本号并退出
		fmt.Println(VERSION)
		os.Exit(0)
	}
	if *debugMode {
		logrus.SetLevel(logrus.DebugLevel)
	}
	// 读取配置文件
	conf, err := readConfig(*filename)
	if err != nil {
		logrus.Fatalf("load config file %q failed: %+v", *filename, err)
	}
	logrus.Debug("load config success")
	// 解析监听地址
	if *listen == "" {
		listen = &conf.Listen
	}
	addr, network := *listen, ""
	if parts := strings.SplitN(*listen, "/", 2); len(parts) == 2 {
		addr, network = parts[0], strings.ToLower(parts[1])
	}
	if network != "" && network != "udp" && network != "tcp" {
		logrus.Fatalf("unknown network: %q", network)
	}
	// 构建handler
	handler, err := inbound.NewHandler(conf)
	if err != nil {
		logrus.Fatalf("build handler failed: %+v", err)
	}
	// 监听SIGNUP命令
	signCh := make(chan os.Signal, 1)
	signal.Notify(signCh, syscall.SIGHUP)
	go reloadConf(signCh, filename, handler)

	// 启动服务
	wg := sync.WaitGroup{}
	runSrv := func(net string) {
		defer wg.Done()
		srv := &dns.Server{Addr: addr, Net: net, Handler: handler}
		logrus.Infof("listen on %s/%s", addr, net)
		if err := srv.ListenAndServe(); err != nil {
			logrus.Errorf("service stopped: %+v", err)
		}
	}
	if network != "" {
		wg.Add(1)
		go runSrv(network)
	} else {
		wg.Add(2)
		go runSrv("udp")
		go runSrv("tcp")
	}
	wg.Wait()
	logrus.Infof("ts-dns exists")
}

func reloadConf(ch chan os.Signal, filename *string, handler inbound.IHandler) {
	for range ch {
		conf, err := readConfig(*filename)
		if err != nil {
			logrus.Warnf("load config file %q failed: %+v", *filename, err)
			continue
		}
		logrus.Debug("reload config")
		if err := handler.ReloadConfig(conf); err != nil {
			logrus.Warnf("reload config failed: %+v", err)
			continue
		}
		logrus.Infof("reload config success")
	}
}

// Decoder messages may contain configuration values, including proxy passwords.
// Report only safe locations or filesystem causes, never raw decoder input.
func readConfig(filename string) (config.Conf, error) {
	var conf config.Conf
	_, err := toml.DecodeFile(filename, &conf)
	if err == nil {
		return conf, nil
	}
	var parseError toml.ParseError
	if errors.As(err, &parseError) {
		return config.Conf{}, fmt.Errorf("invalid TOML at line %d", parseError.Position.Line)
	}
	var pathError *os.PathError
	if errors.As(err, &pathError) {
		return config.Conf{}, fmt.Errorf("read configuration: %w", pathError.Err)
	}
	return config.Conf{}, errors.New("configuration value has an invalid type")
}
