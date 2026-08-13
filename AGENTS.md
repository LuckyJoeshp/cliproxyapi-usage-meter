# Repository workflow

- After completing a code, documentation, configuration, or optimization change, run the relevant tests and publish the finished change to the configured GitHub upstream unless the user explicitly requests a local-only change.
- Before every commit and push, inspect the exact staged diff for secrets and personal data. Never commit API/OAuth tokens, management keys, private keys, auth files, real email addresses, account identifiers, local absolute paths, session logs, or runtime databases.
- Use synthetic identities in tests and documentation. Keep real subscription emails and other local identity metadata in memory only.
- Stage only files that belong to the requested change. Preserve and exclude unrelated or user-owned modifications and untracked files.
- Verify `git diff --cached --check`, relevant tests, the current branch, and its upstream before pushing.
