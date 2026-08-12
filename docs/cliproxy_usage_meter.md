# cliproxy Usage Meter sidecar（MVP）

这是一个独立的、本机绑定 `127.0.0.1` 的 Python 标准库 sidecar：

```text
client -> http://127.0.0.1:8327/v1/... -> meter -> http://127.0.0.1:8317/v1/...
```

它不修改 cliproxyapi、8317 端口、`~/.cli-proxy-api/config.yaml`、`.cds`、
`.zshrc` 或任何现有客户端的 `base_url`。默认数据库为
`datas/cliproxy_usage.sqlite`，运行时数据库及 WAL 文件均被忽略。

除了显式经过 8327 的请求，sidecar 还可以只读消费 CLIProxyAPI v7.2.125
提供的 `GET /v0/management/usage-queue`。这条路径能统计仍然直连 8317
的客户端；队列中的 `api_key` 字段会被完全丢弃，只保存 token hash/脱敏账号信息。

## 启动

先用 fake upstream 验证，再在用户明确选择时指向现有 8317：

```bash
cd <repo>
PORT=8327 UPSTREAM=http://127.0.0.1:8317 scripts/start_cliproxy_usage_meter.sh
```

长时间运行可放在 tmux 前台：

```bash
tmux new-session -s cliproxy_usage_meter \
  'cd <repo> && PORT=8327 UPSTREAM=http://127.0.0.1:8317 scripts/start_cliproxy_usage_meter.sh'
```

### 直连 8317 的 usage-queue 采集

CLIProxyAPI 的 management API 会对错误认证实施 IP 失败保护。不要把 key
写进命令行或提交到仓库；将它放入 owner-only 文件（权限必须是 `600`），例如：

这里的 key 必须是打开 CLIProxyAPI management panel 时使用的 management key，
不是 `api-keys` 下给 `/v1` 客户端用的代理 API key，也不是配置文件里以 `$2a$`
开头的 bcrypt 哈希；后两者都会得到 401。

```bash
chmod 600 "$HOME/.config/cliproxyapi-management.key"
CLIPROXY_MANAGEMENT_KEY_FILE="$HOME/.config/cliproxyapi-management.key" \
  PORT=8327 UPSTREAM=http://127.0.0.1:8317 \
  scripts/start_cliproxy_usage_meter.sh
```

也可使用 `CLIPROXY_MANAGEMENT_KEY` 环境变量，但文件方式更不容易出现在进程
列表中。没有 key 时 poller 保持 idle，不会猜 key；收到 401/403/429 后会长退避，
不会连续重试触发 CLIProxyAPI 封禁。可用参数为 `--usage-queue-count`、
`--usage-queue-poll-seconds`、`--usage-queue-timeout`，必要时用
`--no-usage-queue` 明确关闭。

如果 Chrome 已经保持 management 页面登录状态，可用本机专用启动器（凭据只在内存中
传给 sidecar，不写入 key 文件）：

```bash
cd <repo>
PORT=8327 UPSTREAM=http://127.0.0.1:8317 \
  python3 \
  scripts/start_cliproxy_usage_meter_from_chrome.py
```

本机当前运行的 8317 实例配置文件是 `/opt/homebrew/etc/cliproxyapi.conf`；该实例
的 `usage-statistics-enabled` 已为 true，因此不需要改写 `~/.cli-proxy-api/config.yaml`
或重启 8317。CLIProxyAPI v7.2.125 的 queue 源码默认只保留 60 秒、最大 3600 秒，
`GET /usage-queue` 会 destructive pop；本机未另设 retention，因此 poller 尚未启用时
已经过期的历史请求无法从该队列补回。对应源码见
[`internal/redisqueue/queue.go`](https://github.com/router-for-me/CLIProxyAPI/blob/v7.2.125/internal/redisqueue/queue.go)
和 [`management/usage.go`](https://github.com/router-for-me/CLIProxyAPI/blob/v7.2.125/internal/api/handlers/management/usage.go)。

也可以直接指定固定解释器和数据库：

```bash
python3 \
  scripts/cliproxy_usage_meter.py --serve --port 8327 \
  --upstream http://127.0.0.1:8317 --db datas/cliproxy_usage.sqlite
```

`--host` 默认 `127.0.0.1`；`--upstream-timeout` 默认 900 秒。sidecar 不会自行启动、停止或重启 8317 服务。

## 计量与身份

每次经过 8327 的 `/v1/...` 请求，以及从 8317 usage queue 读到的每条调用，都会落一条
`usage_events`，不论成功、失败、streaming 或 usage 缺失。队列事件的 `source` 为
`usage_queue`，显式 sidecar 请求的 `source` 为 `sidecar`。支持：

- Responses：`input_tokens` / `output_tokens` / `cached_tokens` / `reasoning_tokens` / `total_tokens`
- Chat Completions：`prompt_tokens` / `completion_tokens` 及对应 details
- 非 streaming JSON，以及不改写字节的 SSE streaming（尽量读取最终 usage）
- 其他 `/v1/...` 路径透明转发并计为一次调用

身份解析优先级为显式 `X-Usage-Alias`，其次是本地 `~/.codex-*/auth.json` / `~/.cli-proxy-api/codex-*.json`
中 access token 的短 hash 匹配，最后退化为 Authorization 短 hash、installation 或 session 标识。原始
Authorization、access token、refresh token、id token 和 API key 永不打印或落库；数据库只保存
`auth_fingerprint`、`account_id_hash`、`account_id_tail`。如果多个客户端共用同一个代理 key 且没有 alias header，
meter 无法凭空知道它们对应哪个订阅账号，这是已知的 best-effort 限制。

### Token 与调用口径

看板同时保留三种互不混淆的 token 口径：

- `实际消耗 Tokens` / `codex_status_tokens` =
  `max(input_tokens - cached_tokens, 0) + output_tokens`。它最接近 Codex `/status`
  的 session token 用量。
- `缓存命中 Tokens` = `cached_tokens`，是 input 的子集。
- `API 原始处理量` / `api_processed_tokens` = `input_tokens + output_tokens`，其中
  input 已包含缓存命中。它用于观察模型处理吞吐，也是旧 `total_tokens` 所表达的量。
- `reasoning_tokens` 是 output 的子集，只展示，不再加到任何 total 或成本中。

看板把 `实际消耗 Tokens` 进一步拆成“非缓存输入”和“输出”两个一级指标；两者以及
缓存输入均展示独立 USD 成本。拆分成本不是按 token 数比例分配总成本，而是逐条按事件
模型匹配 `input_per_million`、`cached_input_per_million`、`output_per_million` 后分别求和；
所以混合使用不同模型时也能保留输入/输出真实价差。三项拆分之和应与已定价事件的
`estimated_api_cost_usd` 一致，未知或不完整价格继续保持 `NULL`，不会猜算。

CLIProxyAPI 账号池可能用多个订阅账号处理同一个逻辑请求。因此调用数也分两层：

- `logical_requests`：有 `request_id` 时按其去重；没有 request id 的旧/sidecar 记录每行算一次。
- `account_attempts`：SQLite 的实际账号调用行数；`retry_attempts = attempts - logical_requests`，
  看板文案称为“额外调用”，不等同于失败数。

每个订阅卡也会单独显示总调用、成功调用、失败调用和额外调用，便于识别某个账号是否
频繁失败或被账号池反复使用。

不会删除或覆盖失败/重试行，因为它们是账号池行为和故障审计的一部分。token/cost 仍按
attempt 如实累计；逻辑请求去重仅用于调用次数展示，不能猜测哪次成功 token 可以代表整组。

## 价格与 API 等价额度

未知价格时 `estimated_api_cost_usd` 为 `NULL`，不会伪造价格。推荐从
[OpenAI 官方 API 定价页](https://developers.openai.com/api/docs/pricing)显式同步
Standard / short-context 的 input、cached input、output 单价（USD / 每百万 token）：

```bash
PY=python3
$PY scripts/cliproxy_usage_meter.py --db datas/cliproxy_usage.sqlite \
  --sync-official-prices
$PY scripts/cliproxy_usage_meter.py --db datas/cliproxy_usage.sqlite \
  --price-sync-status
$PY scripts/cliproxy_usage_meter.py --db datas/cliproxy_usage.sqlite \
  --list-prices
```

同步会记录官方 URL、抓取时间、页面 SHA256、parser 版本、同步状态、模型数和历史
补价条数。抓取或解析失败时，已生效价格原子保留，代理请求不受影响；server 启动时
不会自行联网。新同步的官方价格会用于后续请求，并对价格仍为 `NULL` 且 token 拆分
完整的已有记录补价。当前官方页明确给出 `gpt-5.6-sol` Standard 短上下文价格：
input `$5.00/M`、cached input `$0.50/M`、output `$30.00/M`。若官方页以后删除或未列出
某个模型，meter 不猜价。

也可以显式维护本地价格：

```bash
PY=python3
$PY scripts/cliproxy_usage_meter.py --db datas/cliproxy_usage.sqlite \
  --set-price 'fake-*' 1.00 2.00 --cached-input-price 0.25 \
  --price-source-note 'local test profile; replace with a reviewed source'
$PY scripts/cliproxy_usage_meter.py --db datas/cliproxy_usage.sqlite --list-prices
```

`api_equivalent_quota_usd` 只表示按 API 价格折算的观测额度，不是真实订阅余额。遇到 quota/cooldown/rate-limit
错误时自动封存周期；成功请求跟在 quota 事件之后会自动记录 reset。也可手工标记：

```bash
$PY scripts/cliproxy_usage_meter.py --db datas/cliproxy_usage.sqlite --mark-reset codex-1
$PY scripts/cliproxy_usage_meter.py --db datas/cliproxy_usage.sqlite --mark-quota-hit codex-1
```

未观察到打满时只报告 `current_cycle_observed_floor_usd`；完整周期才报告
`api_equivalent_quota_usd` 及 p20/p50/p80。

## 查询与 dashboard

```bash
$PY scripts/cliproxy_usage_meter.py --summary today
$PY scripts/cliproxy_usage_meter.py --summary 7d
$PY scripts/cliproxy_usage_meter.py --summary all
$PY scripts/cliproxy_usage_meter.py --by-account 7d
$PY scripts/cliproxy_usage_meter.py --by-account all
$PY scripts/cliproxy_usage_meter.py --by-model 7d
$PY scripts/cliproxy_usage_meter.py --by-session 7d
$PY scripts/cliproxy_usage_meter.py --by-date 30d
$PY scripts/cliproxy_usage_meter.py --by-date all
$PY scripts/cliproxy_usage_meter.py --recent 20
$PY scripts/cliproxy_usage_meter.py --quota-summary 30d
$PY scripts/cliproxy_usage_meter.py --quota-summary-by-account
```

机器读取可在上述查询中追加 `--json`。看板地址：

```text
http://127.0.0.1:8327/usage
```

看板展示今日/近 7 日/SQLite 全量累计、成功/失败/streaming、各 token 与估算成本、全量按日历史、
alias/account 与模型排行、quota 周期统计以及最近 50 条调用。页面顶部明确标出 SQLite 第一条和最后一条
记录时间，并显示 direct-8317 collector 是 active、backoff 还是因缺少 key 而 idle；
`/healthz` 也提供同样的脱敏状态。页面只读取 SQLite，不接入 cliproxyapi 本体。

新版主视图额外提供：

- 累计、今日、近 7 日的实际消耗（非缓存输入 + 输出）、缓存输入、API 原始处理量、
  输出、推理 token、缓存命中率与 API 等价成本。
- 近 7 天 token/cost 柱状趋势。
- 每个 Codex 订阅的 5 小时与周（Team 可能为月）剩余百分比、重置时间。
- 每账号当前周期已观测美元下限，以及基于 provider 周/月窗口的 API 等价满额度估值。

### 额度估算口径（2026-08-12）

API 等价额度不是订阅现金余额，而是把已观测 token 按官方 API 价折成 USD。估算优先级为：

1. 读取 Codex/WHAM 的周/月 `used_percent` 与 reset 时间，并在同一窗口内汇总逐事件冻结成本。
2. `used_percent == 100%`：使用窗口累计成本作为高置信度满额度估值。
3. `5% <= used_percent < 100%`：按 `窗口累计成本 / used_percent * 100` 做比例投影；其中
   5%～10% 标记为 `initial` 初步估算，后续快照会自动更新；例如
   已用 95%（剩余 5%）时可以反推出约 100% 的额度，并明确标注中置信度。
4. 刚重置或 `< 5%`：只显示当前已观测下限；但如果本地留有上一完整窗口（使用率至少
   50%，且对应事件消费完整），则使用上一窗口实测满额度作为 `previous_window_transfer`
   先验。完全没有这类证据时才保持“观测中”，不输出伪精确满额度。

成功请求不再自动证明 reset。若最新 provider 周/月 snapshot 仍显示接近满额，quota 后的零星
成功不会切割周期；这样 transient 429、重试和账号池路由变化不会制造 `$0.05` 一类的伪周期。

订阅卡的 `C/A` 标识也有语义：`C` 表示已绑定本机 Codex alias/`CODEX_HOME`，`A` 表示只
能由 auth/account 身份识别、没有稳定 alias。

页面视觉参考用户偏好的 `codex-resets.com` 信息语言，但为本项目重新实现：奶油纸张背景、
墨色粗边框、硬阴影、黄/粉/蓝/绿色块与圆润标题；右上角可在明暗主题之间切换，选择只保存在
浏览器 `localStorage`。页面不引用该站的字体、头像、CSS、JavaScript 或网络资源。

订阅百分比来自 Codex usage 响应里的 `used_percent`；官方 Codex 文档说明本地消息和
cloud chats 共享五小时窗口，并可能有周限额：
<https://developers.openai.com/codex/pricing>。sidecar 默认每 300 秒经 8317 的只读
`/v0/management/api-call` 刷新快照，8317 负责把所选 `auth_index` 的 token 仅在内存中
替换为 `$TOKEN$`；sidecar 不读取、打印或落盘 OAuth token。可用
`CLIPROXY_QUOTA_POLL_SECONDS` 调整刷新周期（最小 60 秒）。

SQLite 没有 7 天 retention 或自动删除。`7d` 只是看板排行的展示窗口；`all` 查询会读取全部已落库事件。
但 collector 只能从启用时刻开始持久化：CLIProxyAPI 的 usage queue 是短期内存队列，collector 启用前已从
队列消失的历史无法从 8317 反向补回；当前 v7.2.125 也没有另一份内建持久化 token 历史可供回填。

当前 8317 usage queue 的 `client_request_metadata` 没有填充 `session_id`，因此 SQLite 不能把
历史总量精确筛成某个 `codex_quant` 或其他 tmux session。页面会明确提示这是跨账号、跨 session
的汇总；它只把 token 算法对齐 `/status`，不把统计范围冒充为单 session。若未来上游提供稳定
session id，新记录会自动进入现有 `session_id` 字段，旧记录仍不可反推。

## 临时接入 Codex（不改持久配置）

先确认 meter 正在监听，再只对一次 Codex 进程使用命令行覆盖。官方 Codex 配置参考说明 `openai_base_url` 是内置
`openai` provider 的 base URL override，`-c key=value` 只覆盖本次运行；见
[Codex config reference](https://developers.openai.com/codex/config-reference/) 和
[Codex CLI reference](https://developers.openai.com/codex/cli/reference/)。例如：

```bash
CODEX_HOME="$HOME/.codex-c" codex \
  -c 'openai_base_url="http://127.0.0.1:8327/v1"'
```

这不会改写 `config.toml`；若 Authorization 与本地 auth 能匹配，meter 会自动显示账号。要强制给某个临时进程打
alias 标签，可用自定义 provider 的一次性覆盖（Codex 版本需支持该配置）：

```bash
CODEX_HOME="$HOME/.codex-c" codex \
  -c 'model_provider="meter"' \
  -c 'model_providers.meter.name="Local cliproxy meter"' \
  -c 'model_providers.meter.base_url="http://127.0.0.1:8327/v1"' \
  -c 'model_providers.meter.wire_api="responses"' \
  -c 'model_providers.meter.requires_openai_auth=true' \
  -c 'model_providers.meter.http_headers={"X-Usage-Alias"="codex-1"}'
```

先用短请求确认记录，再决定是否继续；不要自动批量改 alias 或任何现有项目的 base URL。显式测试请求会消耗真实
额度，优先使用 fake upstream。

## 安全与运维

- sidecar 默认只监听 loopback；不要把 `--host` 改为公网地址。
- 代理不会打印 headers/body，错误消息入库前会做 Bearer、JWT、`sk-` 和长 token 脱敏。
- 数据库写失败时仍优先完成透明转发，并在本地日志中只报告异常类型。
- 通过 `CLIPROXY_USAGE_ACCOUNT_SCAN=0` 或 `--no-account-scan` 可关闭本地 auth 只读扫描。
- 8317 仍由原 cliproxyapi 管理；停止 meter 只需结束自己的进程/tmux session。

## 自测

测试会在临时目录启动 fake upstream 与随机 sidecar 端口，覆盖 Responses/Chat、未知 usage、失败脱敏、SSE
原样透传、慢流式首 chunk、quota/reset、dashboard、CLI 查询、启动脚本，以及带假 management key 的
usage-queue 采集和 `api_key` 丢弃；不会请求真实 8317。官方价格解析/失败保留旧价也使用
fake HTML 和 mock fetch，不依赖测试时联网：

```bash
cd <repo>
tmux new-session -s cliproxy_usage_meter_test \
  'python3 -m unittest discover -s tests -p "test_*.py" -v'
```

## MVP 未解决项

1. streaming upstream 不提供最终 usage 时只能记录 `usage_missing=1`；不会猜 token。
2. alias/account 自动映射依赖 bearer 与本地 auth 相同，或客户端显式提供 `X-Usage-Alias`；共享代理 key 无法自动拆分。
3. 官方价格同步解析 Standard 短上下文费率；长上下文、cache-write 或官方未列出的代理别名仍保持 `NULL`，
   不做推断。建议定期显式运行 `--sync-official-prices`。
4. quota 等价额度只有观察到完整 quota/cooldown 事件才会封存；当前周期只提供 observed floor。
5. 8317 queue 当前没有 session id，所以无法从历史数据库精确还原单个 Codex/tmux session；
   只能比较同口径 token，不能比较同范围总量。
