# Telescope DNS

[![Release](https://img.shields.io/github/v/release/fqx/ts-dns)](https://github.com/fqx/ts-dns/releases)
[![CI](https://github.com/fqx/ts-dns/actions/workflows/go.yml/badge.svg)](https://github.com/fqx/ts-dns/actions/workflows/go.yml)
![License](https://img.shields.io/github/license/fqx/ts-dns)

Telescope DNS（ts-dns）是灵活的 DNS 分组转发器。本仓库是
[wolf-joe/ts-dns](https://github.com/wolf-joe/ts-dns) 的 fork。

## 功能与解析流程

- 按 ABP 风格规则、GFWList 分组，按 CIDR 结果重定向到其它组。
- 支持 UDP、TCP、DoT、DoH 上游，以及 SOCKS5 转发和默认 ECS。
- 支持并发查询、选择最快上游或测速最低延迟 IP、hosts、禁用查询类型和 IPSet。
- GFWList 可从本地种子启动，定时经独立代理更新，失败保留规则并退避重试。
- DNS 缓存可选“过期先返回、后台刷新”，具有固定宽限期、短 TTL 和有界刷新任务。
- 支持 SIGHUP 热重载；停止和重载会取消旧后台任务。

```text
hosts → DNS 缓存 → 规则匹配 → 分组上游 → 可选 CIDR 重定向 → 缓存结果
```

![解析架构](doc/arch.drawio.svg)

## 安装与运行

从本 fork 的 [Releases](https://github.com/fqx/ts-dns/releases) 下载对应系统和架构的压缩包，
解压后编辑 `ts-dns.toml`。包内包含 `gfwlist.txt` 和记录其来源、SHA-256 的
`gfwlist-source.json`，无需等待首次下载即可加载分流种子。

以下命令以 Linux/macOS 为例：

```sh
./ts-dns -h
./ts-dns -c ts-dns.toml
./ts-dns -c ts-dns.toml -listen 127.0.0.1:5353
./ts-dns -v
kill -SIGHUP <PID>
```

默认监听 `127.0.0.1:53`，无协议后缀时同时提供 UDP/TCP；可使用 `/udp` 或 `/tcp` 后缀。
绑定低端口、特权 ICMP 和 IPSet 需要相应权限；普通转发可改用高端口，以非特权用户运行。
`-vv` 开启调试日志，但不输出配置内容或代理凭据。

配置中的相对路径按**进程工作目录**解析，不是按 `-c` 文件目录解析。请从解压目录启动，
或为种子、hosts 和规则文件配置绝对路径。重载失败会保留原配置；成功重载会创建新 DNS 缓存。

## 配置

### 默认配置

下面与随包的 `ts-dns.toml` 一致：默认关闭 DNS 缓存和过期响应，GFWList 使用本地种子、
每 24 小时更新一次，下载代理保留兼容默认行为。

```toml
listen = "127.0.0.1:53"

[cache]
size = 0 # 默认禁用缓存；启用可设为 4096
serve_stale = 0 # 过期宽限期（秒），0 关闭；可设为 300
stale_ttl = 5 # 过期响应的短 TTL（秒）

[groups]
  [groups.clean]
  dns = ["223.5.5.5", "114.114.114.114"]
  concurrent = true

  [groups.dirty]
  dns = ["208.67.222.222:5353", "176.103.130.130:5353"]
  gfwlist_url = "https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt"
  gfwlist_update_interval = "24h"
  gfwlist_proxy = "" # 省略/空值：沿用组内 socks5，否则使用 HTTP(S)_PROXY/NO_PROXY
  gfwlist_timeout = "10s" # 整次下载的超时（包括连接、握手、重定向和读取）
  gfwlist_file = "gfwlist.txt"
```

更完整的字段说明见 [ts-dns-full.toml](ts-dns-full.toml)。该文件包含需要额外准备的
规则文件、CIDR 文件及 IPSet 示例，启用前应调整为自己的环境。后续片段应合并到现有对应配置段。

### 分组、上游和查询选项

无规则的组会作为兜底组；只允许一个兜底组和一个 GFWList 组。避免给不同组配置重叠规则，
多个命中组的优先顺序不保证。自定义域名规则可通过 `rules` 或 `rules_file` 提供。

```toml
[groups.work]
rules = ["company.com"]
dns = ["10.1.1.1"]

[groups.dirty]
dns = ["8.8.8.8", "1.1.1.1/tcp"]
dot = ["1.0.0.1:853@cloudflare-dns.com"]
doh = ["https://cloudflare-dns.com/dns-query"]
socks5 = "127.0.0.1:1080"
ecs = "1.2.4.0/24"
no_cookie = false
disable_qtypes = ["AAAA", "HTTPS"]
```

`dns` 默认端口 53，`/tcp` 指定 TCP；`dot` 使用 `地址@证书名称`，默认端口 853。
`doh` 必须是 HTTPS URL。`socks5` 是本组 **DNS 转发**的代理地址，格式为裸 `host:port`，
与下文支持 URL 和认证的 `gfwlist_proxy` 区分。`ecs` 只在请求尚未携带 ECS 时附加默认值。
`disable_qtypes` 和 `disable_ipv6` 也可设置在全局。

`concurrent = true` 可并发选择最快响应；`fastest_v4 = true` 可测速选择 IP，
`tcp_ping_port = 80` 使用 TCP 探测，非正值使用需要特权的 ICMP。测速最多探测 15 个不同 IP。
DoH 服务器域名不能依赖同一 DoH 上游来解析；可通过 hosts 提供启动 IP，避免自引用。

### GFWList 种子、更新与下载代理

`gfwlist_file` 在启动时同步加载，`gfwlist_url` 启用启动即拉取及周期更新。
文件和远程内容必须是 base64 编码的 GFWList；远程下载最多 8 MiB，拒绝无可用规则的内容，
也拒绝 HTTPS 向 HTTP 降级的重定向。建议使用 HTTPS 来源。

| 参数 | 省略时的行为 |
| --- | --- |
| `gfwlist_file` | 不加载本地种子；默认随包配置显式设置为 `gfwlist.txt` |
| `gfwlist_url` | 不下载；只有本地文件时不启用更新 |
| `gfwlist_update_interval` | `1h`；随包配置显式设为 `24h`，必须是正数 Go duration |
| `gfwlist_timeout` | `10s`；正数 Go duration，覆盖整次下载、代理/TLS 协商、重定向和读取 |
| `gfwlist_proxy` | 沿用本组 `socks5`；没有时遵循 Go 的 `HTTP_PROXY`、`HTTPS_PROXY`、`NO_PROXY` |

失败后保留当前规则，1 分钟后重试，指数退避最多 15 分钟，并且不超过配置更新间隔。
更新只替换内存，不覆盖种子文件；重启后先重新加载种子。无种子且首次下载失败时，
只能使用自定义规则和兜底组。无效代理或超时配置会拒绝启动/重载。

独立下载代理示例（不改变 DNS 转发代理）：

```toml
[groups.dirty]
gfwlist_proxy = "socks5h://127.0.0.1:1080"
gfwlist_timeout = "10s"
```

| `gfwlist_proxy` 值 | 行为 |
| --- | --- |
| 省略或 `""` | 使用上述兼容默认行为 |
| `"direct"` | 明确直连，忽略组内代理及环境代理 |
| `http://host:port` / `https://host:port` | HTTP 代理；HTTPS 目标使用 CONNECT；HTTPS 代理本身也通过 TLS |
| `socks5://host:port` / `socks5h://host:port` | SOCKS5；两种写法均由代理解析目标域名 |

显式代理覆盖组内 `socks5` 并忽略 `NO_PROXY`，失败不会回退到直连。省略端口分别使用
80、443、1080；IPv6 地址必须加方括号。不接受裸地址、非根路径、查询参数或片段。
HTTP(S) 支持 Basic 认证，SOCKS5 支持用户名/密码认证，例如
`http://user:password@127.0.0.1:7890`；凭据中的特殊字符需 URL 编码，SOCKS5 用户名和密码
各为 1–255 字节。代理地址的主机名仍由本机解析，系统 DNS 指向 ts-dns 时应保证其可独立解析，
或直接使用代理 IP。停止/重载会取消下载，连接和 SOCKS 协商都受明确的时限约束。

### DNS 缓存与过期后台刷新

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
| `size` | `0` | 最大条目数；非正值关闭缓存和后台刷新 |
| `min_ttl` / `max_ttl` | `60` / `86400` 秒 | 正常缓存 TTL 下限/上限；非正值沿用默认值 |
| `serve_stale` | `0` | 正常 TTL 到期后的额外可用秒数；`0` 关闭，允许 `1`–`86400` |
| `stale_ttl` | `5` 秒 | 旧响应 TTL，允许 `1`–`30`；`0` 沿用默认值，实际不超过剩余宽限期 |

普通 TTL 按配置下限/上限处理。启用过期刷新后，宽限期内的查询先得到旧答案，后台再取新答案；
未命中、首次查询或超过宽限期时仍同步请求上游。命中旧值和刷新失败都不会延长原始宽限期。
成功更新替换旧值；确认的 NXDOMAIN/NODATA 会使对应旧正响应失效，但不缓存该否定答案。
失效操作核对路由版本和原条目身份，迟到的否定结果不能删除较新的正响应。
网络失败、SERVFAIL 等暂时错误则保留仍在期限内的旧值。

同一完整缓存键同时只安排一次刷新；每个处理器固定 4 个 worker、最多 64 个排队任务。
队列满时仍可返回合规旧值，后续查询再尝试安排。任务共享 5 秒上下文预算，涵盖 DNS、DoT、DoH
及其启动解析和 IPSet 更新；取消后等待资源回收。测速单次最多等待 500 毫秒。
停止/重载取消旧任务并等待 worker 退出，已停止的处理器不会被并发重载重新启动。

仅缓存合规正响应，不缓存截断响应、NXDOMAIN、NODATA 或 SERVFAIL。带 Cookie、签名等
客户端专用选项的查询绕过缓存；ECS、DNSSEC 查询属性、EDNS/UDP 大小和路由版本继续隔离。
规则更新会回收旧版本条目，旧请求不能覆盖或挤占新版本。
旧响应所有普通记录使用短 TTL，OPT 控制字段保留，并清除 AD 标记；验证型客户端仍可能拒绝
已过期的 DNSSEC 签名。本程序不验证 DNSSEC。缓存仅在内存中，重启/重载不会保留旧宽限期。

### Hosts、CIDR 与 IPSet

```toml
hosts_files = ["/etc/hosts"]
[hosts]
"cloudflare-dns.com" = "1.0.0.1"
"*.company.com" = "10.0.0.1"
```

hosts 支持多个文件、显式域名和通配符。CIDR 重定向器由 `[redirectors]` 配置，
并通过组的 `redirector` 字段引用；匹配结果可转发到另一个组，详见完整配置文件。

```toml
[groups.dirty]
ipset = "blocked"
ipset6 = "blocked6"
ipset_ttl = 87060
```

IPSet 需要相应权限和系统 `ipset` 程序。初始化/重载会清空同名集合，勿复用重要现有集合。
缓存命中（包括过期命中）不会同步重新写入 IPSet；后台刷新也不能保证在客户端首个连接前
完成，因此 IPSet 项若先过期，可能出现短暂的路由缺口。要保留“立即返回”就无法同时保证
该外部写入已完成。依赖动态 IPSet 路由时，最保守的做法是关闭 `serve_stale`，并保证
IPSet TTL 覆盖正常缓存 TTL；需要启用时，应使 `ipset_ttl` 大于 `max_ttl + serve_stale`，
另留处理与网络延迟余量。例如 `86400 + 300` 的窗口可配 `87060` 秒。集合被外部清空、
重载初始化或达到容量时，这个 TTL 设置也不能提供路由完整性保证。

## 安全部署与运行限制

- 默认只监听回环地址。面向局域网时明确设置监听地址，并通过主机/路由器防火墙仅允许
  可信网段访问 TCP 和 UDP DNS 端口。服务不提供客户端认证、来源 ACL 或速率限制，勿公开递归转发。
- 按需授予绑定端口、ICMP、IPSet 权限。配置文件含认证凭据时限制其读取权限；程序不在配置、
  校验或下载错误日志中打印代理凭据。HTTP 代理及 SOCKS5 认证链路本身不加密，远程代理优先 HTTPS。
- HTTPS 来源和 HTTPS 代理都验证系统信任的证书。自签名 CA 需安装到系统信任；不提供跳过校验选项。
- 过期缓存会在明确窗口内返回可能已变化的记录；对新鲜度或 IPSet 即时一致性敏感时保持关闭。
  GFWList 域名、代理地址和 DoH 上游的启动解析也应避免依赖自身。

## 开发、检查与构建

使用 Go 1.27.3 或更新的安全补丁版本。CI 和两个 release job 使用最新的 1.27.x。

```sh
go mod verify
go vet ./...
go test -race -gcflags=all=-l -timeout=90s ./...
go build -o ts-dns ./cmd
go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...
```

旧测试使用运行时函数替换，所以测试须禁用内联。新回归测试使用本地 DNS/HTTP/代理服务器。
README 示例也参与配置和 fork 链接检查。

[GitHub Actions CI](https://github.com/fqx/ts-dns/actions/workflows/go.yml) 在 push/PR 检查格式、模块、
vet、race 测试、构建和漏洞。release workflow 手动运行只生成 snapshot，即使选择版本标签也不发布；
只有 **push `v*` 标签**且检查成功才发布 Release。本地验证打包可运行：

```sh
goreleaser check
goreleaser release --snapshot --clean
```

## 致谢

感谢 [wolf-joe/ts-dns](https://github.com/wolf-joe/ts-dns)、
[arloan/prdns](https://github.com/arloan/prdns) 和
[gfwlist/gfwlist](https://github.com/gfwlist/gfwlist)。
