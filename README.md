# cliproxyapi-usage-meter

Local, token-safe usage and quota observability for [CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI).

This project is a sidecar, not a billing API. It records requests that pass
through `127.0.0.1:8327`, can optionally drain CLIProxyAPI's read-only
management usage queue for clients that still use `8317`, and estimates API
equivalent cost from an explicitly configured or official OpenAI price table.
It cannot read an official ChatGPT subscription balance. Any “quota” or dollar
figure is an observed/provider-reported window or an API-price estimate, never
an invoice or guaranteed remaining balance.

```text
client -> 127.0.0.1:8327/v1/... -> usage meter -> 127.0.0.1:8317/v1/...
```

## What it measures

- input, cached-input, output, reasoning and total tokens;
- successful, failed, streaming and missing-usage calls;
- logical requests versus account-pool attempts/retries;
- per alias/account, model, session and date summaries;
- read-only quota/cooldown/reset observations and cautious full-window
  API-equivalent estimates;
- an offline `/usage` HTML dashboard at `http://127.0.0.1:8327/usage`;
- optional official OpenAI API price synchronization, with source URL, page
  hash and parser version stored alongside the price table.

## Safety boundary

- It does not modify, restart or replace CLIProxyAPI, port `8317`, Codex
  config, shell aliases or existing client base URLs.
- It listens on loopback by default. Do not expose it publicly without adding
  an authentication boundary of your own.
- Authorization, API keys, OAuth tokens and management keys are never printed
  or persisted. Only short hashes, account hashes and account-ID tails are
  stored.
- Management credentials must come from an owner-only (`0600`) external file
  or environment variable. They are never committed here.
- SQLite files, WAL files, `.env` files, key files, caches and local paths are
  ignored. Tests use fake upstream servers and fixture credentials only.
- Unknown pricing remains `NULL`; the project does not invent a subscription
  price or balance.

## Install and run

Python 3.10+ and the standard library are sufficient.

```bash
git clone https://github.com/LuckyJoeshp/cliproxyapi-usage-meter.git
cd cliproxyapi-usage-meter

# Safe local proxy path; existing clients remain on 8317 unless you explicitly
# point a test client at 8327.
PORT=8327 UPSTREAM=http://127.0.0.1:8317 \
  scripts/start_cliproxy_usage_meter.sh
```

The dashboard is then available at <http://127.0.0.1:8327/usage>.

For direct `8317` usage-queue collection, provide a management key without
putting it in this checkout:

```bash
chmod 600 /path/to/cliproxy-management.key
CLIPROXY_MANAGEMENT_KEY_FILE=/path/to/cliproxy-management.key \
  PORT=8327 UPSTREAM=http://127.0.0.1:8317 \
  scripts/start_cliproxy_usage_meter.sh
```

If the local CLIProxyAPI management page is already authenticated in Chrome,
`scripts/start_cliproxy_usage_meter_from_chrome.py` can pass the key in memory
without printing or writing it. This is an optional local convenience; a
portable deployment should prefer the external `0600` key file.

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

## License

MIT. See [LICENSE](LICENSE).
