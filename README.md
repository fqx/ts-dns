# Telescope DNS

[![GitHub release (latest by date)](https://img.shields.io/github/v/release/fqx/ts-dns)](https://github.com/fqx/ts-dns/releases)
[![Go](https://github.com/fqx/ts-dns/actions/workflows/go.yml/badge.svg)](https://github.com/fqx/ts-dns/actions/workflows/go.yml)
[![codecov](https://codecov.io/gh/fqx/ts-dns/branch/master/graph/badge.svg)](https://codecov.io/gh/fqx/ts-dns)
[![Go Report Card](https://goreportcard.com/badge/github.com/fqx/ts-dns)](https://goreportcard.com/report/github.com/fqx/ts-dns)
![GitHub](https://img.shields.io/github/license/fqx/ts-dns)

> 灵活快速的DNS分组转发器

## 设计目标
### 灵活解析
* 支持按ABP风格规则/`GFWList`对DNS请求进行分组
* 支持按CIDR对DNS请求进行重定向
* 支持DNS over UDP/TCP/TLS/HTTPS、socks5代理、ECS
* 支持将查询结果中的IPv4地址添加至IPSet
### 快速解析
* 支持并发请求上游DNS，选择最快响应
* 选择ping值最低的IPv4地址（tcp/icmp ping）
* 支持hosts/DNS缓存/屏蔽指定查询类型
* 支持热重载配置文件

## 解析流程
![arch.drawio.svg](doc/arch.drawio.svg)

```
查找hosts -> 查找缓存 -> 匹配规则 -> 指定group处理 -> 重定向 -> 设置缓存
```

## 使用说明

1. 在[Releases页面](https://github.com/fqx/ts-dns/releases)下载对应系统和平台的压缩包；
2. 解压后按需求编辑配置文件`ts-dns.toml`（可选）并运行进程：
  ```shell
  # ./ts-dns -h  # 显示命令行帮助信息
  # ./ts-dns -c ts-dns.toml  # 指定配置文件名
  ./ts-dns
  kill -SIGHUP <PID> # 重载配置文件
  ```

## 配置示例

> 完整配置文件参见`ts-dns-full.toml`

1. 默认配置（`ts-dns.toml`），开箱即用
  ```toml
  listen = "127.0.0.1:53"

  [groups]
    [groups.clean]
    dns = ["223.5.5.5", "114.114.114.114"]
    concurrent = true

    [groups.dirty]
    dns = [""] # 省略
    gfwlist_file = "gfwlist.txt"
  ```

2. 选择ping值最低的IPv4地址（启用时建议以root权限运行本程序）
  ```toml
  # ...
  [groups.clean]
    dns = ["223.5.5.5", "114.114.114.114"]
    fastest_v4 = true
  # ...
  ```

3. 指定hosts文件和自定义hosts
  ```toml
  # ...
  hosts_files = ["adaway.txt"]
  [hosts]
  "www.example.com" = "1.1.1.1"
  # ...
  ```

4. 使用socks5代理转发DNS请求
  ```toml
  # ...
    [groups.dirty]
    socks5 = "127.0.0.1:1080"
    # ...
  ```

5. 转发至上游DNS时默认附带指定ECS信息（暂不支持DOH）
  ```toml
  # ...
    [groups.clean]
    ecs = "1.2.4.0/24"
    # ...
  ```

6. 自定义域名分组
  ```toml
  # ...
    [groups.work]
    dns = ["10.1.1.1"]
    rules = ["company.com"]
    # ...
  ```

7. 动态添加IPSet记录（使用前请阅读`ts-dns-full.toml`对应说明）
  ```toml
  # ...
    [groups.dirty]
    ipset = "blocked"
    ipset_ttl = 86400
    # ...
  ```


## 未来规划

- [x] 支持定期拉取最新gfwlist
- [ ] 支持http接口管理
- [ ] 降低gfwlist的匹配优先级
- [ ] DoT/GFWList域名解析自闭环

## 特别鸣谢
* [github.com/arloan/prdns](https://github.com/arloan/prdns)
* [github.com/gfwlist/gfwlist](https://github.com/gfwlist/gfwlist)

## GFWList 自动更新

在目标组配置 `gfwlist_url` 和 `gfwlist_update_interval = "24h"`。
间隔使用 Go duration 格式（如 `30m`、`1h`、`24h`），省略时默认为 `1h`，必须大于零。
启动后立即异步拉取，此后按间隔更新；失败时保留上一次有效列表，1 分钟后重试，指数退避最多 15 分钟（不超过配置间隔）。
默认配置通过 `gfwlist_file = "gfwlist.txt"` 同步加载随包种子，再后台拉取更新。
种子来源与 SHA-256 记录于 `gfwlist-source.json`，离线启动与下载失败时仍有本地规则。
自动更新只替换内存规则，不覆盖种子文件；重启后先重新加载随包种子。
远程内容必须是 base64 编码的 GFWList，最大 8 MiB；推荐使用 HTTPS。
配置重载和停止会取消当前下载。仅配置文件时不启用下载。
首次下载完成前使用本地种子和自定义规则。自定义部署请保留种子文件，
并从配置文件与 `gfwlist.txt` 所在目录启动，或把 `gfwlist_file` 设为绝对路径。

## 安全部署

示例默认仅监听 `127.0.0.1:53`。供局域网使用时明确设置监听地址，
并通过主机/路由器防火墙仅允许受信任网段访问 TCP 和 UDP DNS 端口。
本服务不提供客户端身份认证、来源 ACL 或速率限制，请勿向互联网开放递归转发服务，
以避免被用于 DNS 放大攻击。以非特权用户运行并仅授予必要的绑定端口/ICMP/IPSet权限。

## 开发与构建

使用 Go 1.27.3 或更新的安全补丁版本；CI 与 release 使用最新的 1.27.x。运行 `go test -race -gcflags=all=-l ./...` 和 `go vet ./...`。
旧测试使用运行时函数替换，因此测试必须禁用内联；新安全回归测试使用本地服务器。
GitHub Actions 在 push/PR 运行测试、构建和 govulncheck。
Release workflow 可手动运行以生成构建产物；推送 `v*` 标签后才发布 GitHub Release。
