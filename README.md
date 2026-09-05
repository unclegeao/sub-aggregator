# 全协议万能订阅聚合器 (Flask 版)

粘贴任意订阅源 / 节点链接 → 生成统一订阅短链，自动适配 v2rayN / Clash / sing-box(Karing) 三种客户端。

这是原版的加固/重构版本，改动点见文末「本次改进了什么」。

## 功能

- 支持协议: `vless`(reality/vision) / `vmess` / `trojan` / `ss`(含旧格式) / `hysteria2` / `tuic` / `anytls`
- 一键生成短链，三种格式随时取用: `/s/<code>`(v2rayN base64) / `?type=clash` / `?type=singbox`
- **自动去重**：多个订阅源里的重复节点（同一 server+port+凭据）只保留一份，首个来源的命名优先
- **节点存活检测（可选）**：TCP 连通性快速筛查，创建短链时传 `check_alive: true` 即可剔除明显失效的节点；同时记录 TCP 连接耗时，默认按延迟从快到慢排序，可选把延迟标进节点名称（如 `🇭🇰 HK-1 [82ms]`）
- **按地区自动分组**：Clash / sing-box 输出会按节点名称识别地区（支持中文/英文/国旗 emoji），生成地区分组 + 「全部节点」+「PROXY」三层结构，不再是一个平铺列表
- 结果缓存 5 分钟，避免每次请求都去拉上游订阅（可配置）
- 短链 30 天自动过期，后台线程每小时自动清理（可配置）
- SQLite 存储，支持多 worker 并发读写，不再有 JSON 文件并发损坏的风险
- 管理令牌(`ADMIN_TOKEN`)、按 IP 限流、SSRF 防护（含 DNS rebinding / 重定向二次校验）
- `/health` 健康检查端点，配合 Uptime 监控使用
- 结构化日志，单条节点解析失败不会导致整批请求失败

## 部署（StackHost）

`stackhost.yaml` 已配置好构建、启动命令和健康检查（注意：StackHost 要求 `runtime` 为对象格式、不允许 gunicorn 作为启动命令，平台会自动注入 `PORT`，`app.py` 的 `app.run` 会读取它）：

```yaml
name: sub-aggregator

runtime:
  image: python:3.11-slim

commands:
  package: ""
  build:
    - "pip install -r requirements.txt"
  start: "python app.py"

healthcheck:
  path: /health
  port: "$PORT"

env:
  PORT: "8080"
  LOG_LEVEL: INFO
```

部署前，务必在 StackHost 控制台的 Secrets/环境变量中设置 `ADMIN_TOKEN`（不要写进仓库或 `stackhost.yaml`），否则 `/create_short` 接口会对所有人开放。

其余可调环境变量见下表，同样在 StackHost 控制台配置。

## 环境变量

| 变量 | 说明 | 默认值 |
|---|---|---|
| `PORT` | 监听端口 | `8080` |
| `ADMIN_TOKEN` | 设置后 `POST /create_short` 必须带 `X-Admin-Token` 请求头(或 `?token=`)。**强烈建议在公网部署时设置**，未设置时会在启动日志打印警告 | 空（不建议） |
| `SHORT_LINK_TTL_DAYS` | 短链有效期（天） | `30` |
| `CACHE_TTL_SECONDS` | 节点解析结果缓存时长（秒） | `300` |
| `MAX_URLS_PER_REQUEST` | 单次请求最多接受的订阅/节点条数 | `200` |
| `MAX_NODES_TOTAL` | 单个短链最多聚合的节点数 | `5000` |
| `LOG_LEVEL` | 日志级别 | `INFO` |
| `DISABLE_HOUSEKEEPING` | 设为 `1` 关闭后台自动清理过期短链的线程 | `0` |
| `LIVENESS_CHECK_TIMEOUT` | 存活检测单个节点的 TCP 连接超时（秒） | `2.0` |
| `LIVENESS_MAX_WORKERS` | 存活检测的最大并发线程数 | `50` |

## API

| 路径 | 说明 |
|---|---|
| `POST /create_short` | body: `{"urls": [...], "check_alive": false, "sort_by_latency": true, "annotate_latency": false}` → `{"short_url": "...", "nodes": n, "skipped": m, "deduped": d, "dead": x}`。需要 `ADMIN_TOKEN`（若已设置） |
| `GET /s/<code>` | v2rayN 订阅(base64) |
| `GET /s/<code>?type=clash` | Clash YAML（含地区分组） |
| `GET /s/<code>?type=singbox` | sing-box JSON（含地区分组） |
| `GET /health` | 健康检查，返回状态和当前短链数量 |
| `POST /admin/purge_expired` | 手动触发过期短链清理，需要 `ADMIN_TOKEN` |
| `POST /admin/recheck/<code>` | 重新抓取该短链的所有来源、去重，可选 `{"check_alive": true, "sort_by_latency": true, "annotate_latency": false}` 剔除失效节点并刷新缓存。需要 `ADMIN_TOKEN` |

`urls` 数组里的每一项可以是：
- 一条完整的节点链接（如 `vless://...`），或
- 一段直接粘贴的 base64 订阅内容（自动识别并解码，标准/URL-safe 编码均可），或
- 一个订阅链接（会自动抓取，响应体兼容 base64 编码与纯文本节点列表）

节点列表无论来自哪种来源，都支持按行分隔，也支持无换行的紧凑拼接格式（部分机场的 base64 订阅解码后是这种形态）。

请求字段说明（`check_alive` 相关，仅在其为 `true` 时生效）：
- `sort_by_latency`（默认 `true`）：按 TCP 连接耗时从快到慢重新排序节点。地区分组内部的顺序也会跟着变化
- `annotate_latency`（默认 `false`）：把延迟数字追加进节点名称，例如 `🇭🇰 HK-1 [82ms]`。默认关闭，因为这会永久改变客户端里显示的节点名

响应字段说明：
- `skipped`：有多少行/订阅源解析失败，方便你发现问题而不是被静默丢弃
- `deduped`：去重时移除了多少条完全重复的节点
- `dead`：`check_alive: true` 时，TCP 连接失败被剔除的节点数（未开启则为 `null`）

**关于存活检测/延迟的诚实说明**：这只是一次 TCP 三次握手测试，只能证明端口开着，**不能**证明代理协议本身能正常工作（密码错误、账号过期但端口仍开着的情况都会被误判为"存活"）。延迟同理，只是 TCP 连接耗时，不等于加密握手 + 协议开销之后的真实代理延迟，仅作为一个粗略的排序信号。

## 项目结构

```
app.py          Flask 路由、限流、鉴权、后台清理任务
parsers.py      各协议节点链接解析（每个解析失败不影响其它节点）
converters.py   节点列表 → v2rayN / Clash / sing-box 格式（含地区分组）
dedup.py        节点去重
liveness.py     TCP 存活检测
regions.py      按节点名称识别地区并分组
storage.py      SQLite 存储层（短链 + 节点缓存）
security.py     SSRF 防护（DNS 解析校验 + IP 锁定 + 重定向逐跳校验）
```

## 本次改进了什么

相对最初的单文件 JSON 版本，这次重写主要解决了几个实际风险点：

1. **存储层**：JSON 文件 + "原子写入"在多 worker 并发下很难真正安全，换成了 SQLite（WAL 模式），天然支持并发读写和事务。
2. **SSRF 防护加强**：原版只做了"拒绝内网地址"的字符串检查，容易被 DNS rebinding（先解析到公网 IP 校验，实际连接时再解析成内网 IP）绕过。现在会先解析域名、校验解析到的真实 IP，再把连接锁定到这个已校验的 IP，并且**每一跳重定向都会重新校验**，而不是只看最初的 URL。
3. **默认更安全**：未设置 `ADMIN_TOKEN` 时会在启动日志打印醒目警告，避免公网裸奔当免费转换服务被滥用。
4. **响应体积上限**：抓取上游订阅时限制最大 5MB，避免恶意/异常订阅源撑爆内存。
5. **协议解析容错**：单个节点解析失败只跳过这一条并计入 `skipped`，不会导致整批请求 500。
6. **可观测性**：加了 `/health` 端点和结构化日志，方便接入 Uptime 监控和排查问题。
7. **一键部署**：补上了 `stackhost.yaml` 部署配置，之前只有代码没有部署方案。
8. **节点去重**：多个订阅源重叠时不再产出一堆完全重复的节点。
9. **可选存活检测**：创建/刷新短链时可以一键剔除明显失联的节点（见上方"诚实说明"其局限性）。
10. **地区自动分组**：Clash/sing-box 输出从平铺列表变成 PROXY → 地区 → 具体节点 的三层结构，客户端里选起来更方便。
11. **延迟测速**：存活检测顺带记录 TCP 连接耗时，默认按延迟排序，可选把延迟标进节点名称。
12. **Hysteria2 (hy2) 可用性修复**：聚合 hy2 节点时参数会在几个环节被悄悄破坏——`parse_qs` 会把参数里的 `+` 改写成空格（base64 字母表的混淆口令必坏）；sing-box 输出整个丢失 `obfs` 混淆配置；百分号编码的密码被原样当作真实密码写进 Clash/sing-box；重新导出 v2rayN URI 时密码/混淆口令没有百分号编码。现已全部修复并保证节点链接"解析 → 导出"往返幂等。另外存活检测不再用 TCP 探测误杀 hy2/tuic 这类 UDP/QUIC 节点，一律放行。

## 优选订阅生成器（/preferred）

把一个 Argo 节点 / 订阅源展开成多个 **CF 优选地址变体**：只替换 `server` 为不同的优选域名/IP，
其余（uuid / sni / host / path / port）保持不变，客户端即可逐个测速挑最快的。

```
GET /preferred?link=<节点链接或订阅源>&type=v2rayn|clash|singbox&port=<端口>&max=<数量>
```

- `link`  必填。单个节点链接（vless:// vmess:// trojan:// ss:// …）或订阅源 URL
- `type`  输出格式，默认 `v2rayn`
- `port`  可选，覆盖所有变体的端口（例如 Argo 隧道常用 8443）
- `max`   可选，每个节点最多生成几个变体（默认全部）

示例：

```
/preferred?link=vmess://xxx&type=v2rayn&port=8443
/preferred?link=vmess://xxx&type=clash&max=10
/preferred?link=vmess://xxx&type=singbox
```

把返回内容粘贴进 v2rayN「从剪贴板导入订阅」，或用 `?type=` 切换 Clash / sing-box。
优选域名清单来自项目内 `web_domains.txt`（每行一个，`#` 后为备注/IP，可自行增删）。

## 已知局限（诚实说明）

- 协议解析是自行实现的，没有复用 subconverter 等项目多年积累的边界情况处理，如果遇到某些机场的非标准参数格式，解析可能失败（会被计入 `skipped`，不会静默出错）。
- SQLite 适合中小规模自托管使用；如果你的实例要承载很高并发或多实例横向扩展，需要换成 Postgres/Redis。
- 限流基于内存存储（Flask-Limiter 默认），多进程/多实例部署下限流不是全局一致的，如需精确限流请接入 Redis 作为 limiter 的 storage backend。
