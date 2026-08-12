# ClipProxyAPI usage helpers

These two scripts are a small, local-only toolkit for maintaining Codex
subscription files consumed by [CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI).

## Safety model

- Credentials are read from your local CLIProxyAPI auth directory; no token is
  bundled with this project.
- Valid duplicates are moved to a sibling backup directory (by default
  `~/.cli-proxy-api-backups`), never below the recursively scanned auth tree.
- A lone invalid subscription is preserved as a manual re-login handle.
- Invalid duplicates are deleted only when a same-email peer exists.
- Output contains metadata only; token values and auth payloads are never
  printed.
- The optional Codex-home synchronizer is disabled unless you explicitly set
  `CLIPROXYAPI_AUTH_FIX_SCRIPT`.

## Install and run

Python 3.10+ is sufficient and the standard library is the only dependency.

```bash
python3 scripts/cliproxyapi_usage.py
python3 scripts/cliproxyapi_dedupe_codex_subscriptions.py --dry-run
python3 scripts/cliproxyapi_dedupe_codex_subscriptions.py --restart
bash scripts/cliproxyapi_fix_all.sh
```

Use `--dir /path/to/profile` for a non-default CLIProxyAPI profile.  Set
`CLIPROXYAPI_BACKUP_DIR` when you want backups in a specific external location;
the tool rejects paths inside the auth directory.

`--restart` and `cliproxyapi_fix_all.sh` use Homebrew's
`brew services restart cliproxyapi`; omit them on systems that manage the
service differently.

## Testing

```bash
python3 -m unittest discover -s tests -p 'test_*.py'
```

## License

MIT.  See [LICENSE](../LICENSE).
