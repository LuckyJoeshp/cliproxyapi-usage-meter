# cliproxyapi-usage-meter

[![Public repository](https://img.shields.io/badge/repository-public-2ea44f?style=flat-square)](https://github.com/LuckyJoeshp/cliproxyapi-usage-meter)
[![Python](https://img.shields.io/badge/python-3.10%2B-3776ab?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-37%20passing-2ea44f?style=flat-square)](tests/)
[![License](https://img.shields.io/badge/license-MIT-yellow?style=flat-square)](LICENSE)

**A local, token-safe Usage Observatory for CLIProxyAPI.**

See every request, split input/cache/output tokens, estimate API-equivalent
cost, observe quota resets, and understand account-pool retries from one
private-by-default dashboard. It runs as a transparent sidecar: clients can
send traffic through `8327`, while the optional read-only queue collector also
captures clients that still use `8317`.

![Usage Observatory demo — real aggregates with account IDs masked](assets/usage-dashboard-demo.png)

_The screenshot is a real dashboard render: token totals, cost estimates,
quota percentages, trends, model usage, and every account card remain visible.
Only account names/identifiers and the account column in recent tables are
replaced with neutral demo labels._

> This is an observability tool, not a billing API. It cannot read an official
> ChatGPT subscription balance. Dollar figures are API-price equivalents, and
> quota figures are observed/provider-reported windows—not invoices or
> guaranteed remaining balances.

```text
client -> 127.0.0.1:8327/v1/... -> usage meter -> 127.0.0.1:8317/v1/...
```

## Why use it

CLIProxyAPI can fan one logical request across several subscription accounts.
That makes a raw proxy log difficult to answer: **what did I actually consume,
which account handled it, how much was cached, and why did the account pool
retry?** This sidecar keeps those questions separate and auditable in SQLite.

## What it gives you

| Capability | What is tracked |
| --- | --- |
| Token accounting | Non-cached input, cached input, output, reasoning subset, and raw API processing |
| Cost estimation | Official OpenAI short/long-context price sync or reviewed local prices, split by token type |
| Account behavior | Logical requests, account attempts, retries, aliases, models, sessions, and dates |
| Quota visibility | Read-only 5-hour/week/month snapshots, reset times, cooldowns, and observed floors |
| Collection paths | Transparent `8327` proxy plus optional destructive-read `8317` usage queue |
| Dashboard | Inline, dependency-free `/usage` HTML with trend, account, model, and recent-call views |
| Privacy boundary | Loopback by default; credentials discarded; only short fingerprints are stored |

## Quick start

```bash
git clone https://github.com/LuckyJoeshp/cliproxyapi-usage-meter.git
cd cliproxyapi-usage-meter

# Keep CLIProxyAPI on 8317; point only the clients you want observed at 8327.
PORT=8327 UPSTREAM=http://127.0.0.1:8317 \
  scripts/start_cliproxy_usage_meter.sh
```

Open <http://127.0.0.1:8327/usage>.

The dashboard also monitors direct ChatGPT App Codex sessions when the local
Codex JSONL history is available. It imports only token-count and rate-limit
metadata from the `CODEX_APP_HOME` (default `~/.codex`) and matches the local
account to `codex-13`; it does not inspect prompts, code, tool output, or
credentials. A manual usage form is available on `/usage` for sessions from
another device. Dollar values are API-equivalent estimates, not Pro
subscription billing.

### Start Codex through CLIProxyAPI from any folder

The repository includes [`scripts/codex-cliproxyapi`](scripts/codex-cliproxyapi),
which follows the verified `codex-quant` profile (`cliproxy`, Responses API,
and the local CLIProxyAPI account pool) without changing the working directory.
Install it once on macOS so it is available from every folder:

```bash
install -m 755 scripts/codex-cliproxyapi /opt/homebrew/bin/codex-cliproxyapi
cd /path/to/any/project
codex-cliproxyapi
```

The command uses the current directory as Codex's workspace. It does not embed
`QuantSystem` or any other project path. CLIProxyAPI must be running on
`127.0.0.1:8317`; the existing `~/.codex/cliproxy.config.toml` profile supplies
the endpoint and reads the bearer key at runtime.

For a direct-8317 queue collector, use an external owner-only key file (never
put a management credential in this checkout):

```bash
chmod 600 /path/to/cliproxy-management.key
CLIPROXY_MANAGEMENT_KEY_FILE=/path/to/cliproxy-management.key \
  PORT=8327 UPSTREAM=http://127.0.0.1:8317 \
  scripts/start_cliproxy_usage_meter.sh
```

If Chrome already has the local CLIProxyAPI management page open,
`scripts/start_cliproxy_usage_meter_from_chrome.py` can pass its key in memory
without writing or printing it.

## Safety boundary

- It does not modify, restart or replace CLIProxyAPI, port `8317`, Codex
  config, shell aliases or existing client base URLs.
- It listens on loopback by default. Do not expose it publicly without adding
  an authentication boundary of your own.
- Authorization, API keys, OAuth tokens and management keys are never printed
  or persisted. Only short hashes, account hashes and account-ID tails are
  stored. The loopback dashboard may display each mapped subscription email
  from its local Codex `auth.json` identity claim; email is kept in memory and
  is not written to the usage/quota database or logs.
- Management credentials must come from an owner-only (`0600`) external file
  or environment variable. They are never committed here.
- SQLite files, WAL files, `.env` files, key files, caches and local paths are
  ignored. Tests use fake upstream servers and fixture credentials only.
- Unknown pricing remains `NULL`; the project does not invent a subscription
  price or balance.

## CLI examples

```bash
PYTHON_BIN="${QLAB_PYTHON_BIN:-python3}"

"$PYTHON_BIN" scripts/cliproxy_usage_meter.py --summary today
"$PYTHON_BIN" scripts/cliproxy_usage_meter.py --summary all --json
"$PYTHON_BIN" scripts/cliproxy_usage_meter.py --by-account 7d
"$PYTHON_BIN" scripts/cliproxy_usage_meter.py --by-model 7d
"$PYTHON_BIN" scripts/cliproxy_usage_meter.py --quota-summary 30d
"$PYTHON_BIN" scripts/cliproxy_usage_meter.py --list-prices
"$PYTHON_BIN" scripts/cliproxy_usage_meter.py --sync-official-prices
```

Official-price sync accepts only the documented OpenAI pricing hosts and
atomically keeps the previous table when fetch/parsing fails. Manual prices can
be set with `--set-price MODEL_PATTERN INPUT_PER_M OUTPUT_PER_M` plus
`--cached-input-price` and `--price-source-note`.

## Tests

```bash
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

The suite covers Responses and Chat Completions usage normalization, streaming
byte transparency, error redaction, account mapping, usage-queue polling,
quota/reset logic, official-price parsing, dashboard rendering and all CLI
queries. It never contacts a real `8317` service.

Detailed design and the original requirements are in
[`docs/cliproxy_usage_meter.md`](docs/cliproxy_usage_meter.md) and
[`docs/cliproxy_usage_meter_requirements.md`](docs/cliproxy_usage_meter_requirements.md).

## Privacy and data safety

The runtime SQLite database lives under `datas/` and is ignored by Git,
including WAL files. Raw authorization headers, OAuth tokens, refresh tokens,
API keys, and management keys are never persisted. The public repository
contains source, tests, documentation, and a screenshot with only account
identities masked—never local usage history or machine-specific paths.

## License

MIT. See [LICENSE](LICENSE).
