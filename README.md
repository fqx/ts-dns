# Telescope DNS

[![GitHub release (latest by date)](https://img.shields.io/github/v/release/fqx/ts-dns)](https://github.com/fqx/ts-dns/releases)
[![Go](https://github.com/fqx/ts-dns/actions/workflows/go.yml/badge.svg)](https://github.com/fqx/ts-dns/actions/workflows/go.yml)
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
* 支持可选的过期记录先响应、后台合并刷新
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

  [cache]
  size = 0
  serve_stale = 0
  stale_ttl = 5

  [groups]
    [groups.clean]
    dns = ["223.5.5.5", "114.114.114.114"]
    concurrent = true

    [groups.dirty]
    dns = ["208.67.222.222:5353", "176.103.130.130:5353"]
    gfwlist_file = "gfwlist.txt"
    gfwlist_url = "https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt"
    gfwlist_update_interval = "24h"
    gfwlist_proxy = ""
    gfwlist_timeout = "10s"
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
* [github.com/wolf-joe/ts-dns](https://github.com/wolf-joe/ts-dns)（上游项目）
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

### GFWList 下载代理

在使用 GFWList 的组中设置独立的 `gfwlist_proxy`，只影响规则下载：

```toml
[groups.dirty]
gfwlist_file = "gfwlist.txt"
gfwlist_url = "https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt"
gfwlist_update_interval = "24h"
gfwlist_proxy = "socks5h://127.0.0.1:1080"
gfwlist_timeout = "10s"
```

| 配置值 | 下载路径 |
| --- | --- |
| 省略或 `""` | 沿用本组 `socks5`；未配置时遵循 Go 的 `HTTP_PROXY`、`HTTPS_PROXY`、`NO_PROXY` 环境变量行为 |
| `"direct"` | 明确直连，忽略组内代理和代理环境变量 |
| `http://host:port` / `https://host:port` | 独立 HTTP 代理；HTTPS 目标使用 CONNECT；HTTPS 代理本身也通过 TLS 连接 |
| `socks5://host:port` / `socks5h://host:port` | 独立 SOCKS5 代理；两种写法均把目标域名交给代理解析 |

显式代理 URL 覆盖本组 `socks5`，并忽略 `NO_PROXY`；代理失败不会自动改为直连。
省略端口时，HTTP、HTTPS、SOCKS5 分别使用 80、443、1080。IPv6 地址需加方括号。
代理地址必须为上述 URL，不接受裸 `host:port`、路径、查询参数或片段。
代理服务器的主机名仍由本机解析；系统 DNS 若指向 ts-dns，需保证代理地址能独立解析，
或使用代理 IP，避免启动时循环依赖。SOCKS5 代理后的目标域名由代理解析。

HTTP(S) 支持 URL 用户信息形式的 Basic 认证，SOCKS5 支持用户名/密码认证，
如 `http://user:password@127.0.0.1:7890`；凭据中的特殊字符须按 URL 编码。
SOCKS5 用户名和密码解码后各为 1–255 字节。凭据保存在配置文件中，应限制文件权限；
程序不会在配置日志、校验错误或下载错误中输出凭据。HTTP 代理及 SOCKS5 的认证链路
本身不加密，远程代理优先使用 HTTPS；目标 HTTPS 和代理 HTTPS 都验证系统信任的证书。

`gfwlist_timeout` 使用正数 Go duration，默认为 `10s`，限制整次下载（包括连接、代理/TLS
握手、重定向及响应体读取）。停止和配置重载会取消当前下载。无效代理或超时配置会拒绝
启动/重载；重载失败保留原配置。网络、认证和超时失败保留当前规则并继续退避重试。

## 过期缓存先返回，后台刷新

默认关闭。启用后，如果记录刚过期且仍在宽限期内，先立即返回旧答案，同时后台向上游
刷新；刷新成功后，下一次查询使用新答案。首次查询、未命中或超过宽限期时，仍同步请求上游。

```toml
[cache]
size = 4096
min_ttl = 60
max_ttl = 86400
serve_stale = 300
stale_ttl = 5
```

| 参数 | 默认值 | 含义 |
| --- | --- | --- |
| `size` | `0` | 最大缓存条目数；非正数禁用缓存，也不会启动后台刷新 |
| `min_ttl` / `max_ttl` | `60` / `86400` 秒 | 正常缓存的 TTL 下限/上限；非正值沿用默认值 |
| `serve_stale` | `0` | 正常 TTL 到期后额外可用的秒数；`0` 关闭，允许 `1`–`86400` |
| `stale_ttl` | `5` 秒 | 旧答案返回的短 TTL；允许 `1`–`30`，`0` 沿用默认值；实际值不超过剩余宽限期 |

命中过期缓存和刷新失败都不会延长原始宽限期。只刷新已有、可缓存的正响应，
不缓存或过期返回截断响应、NXDOMAIN、SERVFAIL 等错误/负响应；带 Cookie、签名等
客户端专用选项的查询仍绕过缓存。EDNS、DNSSEC 查询属性、ECS 和路由版本继续隔离，
规则更新会回收旧版本缓存，迟到的旧刷新结果不能覆盖或挤占新版本。

同一完整缓存键（包括路由版本和查询属性）同时只安排一次刷新。每个处理器固定使用
4 个 worker、最多 64 个排队任务；队列已满时先返回仍合规的旧答案，后续查询再尝试安排。
每项刷新共享 5 秒取消预算，涵盖上游请求和 IPSet 更新；停止、配置重载会取消旧任务并等待
worker 退出。ICMP/TCP 测速最多探测 15 个不同 IP，单次等待最多 500 毫秒，并取消、回收其余探测。后台刷新失败后，宽限期内的
后续查询可再次尝试；后台请求可能因工作预算而比普通请求更早终止。

旧响应的 Answer、Authority 和非 OPT Additional 记录均使用短 TTL，OPT 控制字段保留。
过期响应会清除 AD 标记；本程序不验证 DNSSEC，验证型客户端仍可能拒绝已过期的签名。
DNS 缓存仅保存在内存中；重启或重载配置会创建新缓存，不保留旧宽限期。
该功能会在明确配置的窗口内返回可能已变化的记录，适合愿意以有限陈旧性换取低延迟和
短时上游故障容忍的场景；关闭 `serve_stale` 即恢复严格过期失效行为。

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
