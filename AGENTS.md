# Repository instructions

This repository is a standalone Hermes memory-provider plugin. Keep it installable at the repository root and do not modify Hermes core.

## Contract

- Provider and manifest name: `cloudflare-agent-memory`.
- Runtime: Python standard library plus modules supplied by Hermes; add no runtime dependency or Worker proxy.
- Current compatibility baseline: Hermes 0.20.5 at commit `a588685fb957a0c55de84d5bfba69ff44ebfb31b`.
- Cloudflare API contract: HTTP V4 under `/accounts/{account}/agent-memory/namespaces/{namespace}`.
- Preserve deterministic profile isolation. Model/tool arguments must never select an account, namespace, profile, platform user, or session owner.
- Send only redacted user/assistant text and strictly scanned/redacted curated memory. Never send system prompts, tools, terminal output, files, tokens, or raw user IDs.
- Keep Cloudflare failures non-fatal to normal Hermes turns. Migration remains dry-run-first, replay-safe, audited, and non-destructive to local source data; migration deletion is limited to exact stale sessions from the curated manifest.
- Keep export read-only, complete for each selected profile, atomic, and non-overwriting. Export files contain full memory content and use mode `0600`.
- The forget tool deletes only an exact memory ID returned by recall, including a migrated local entry.
- Setup makes Cloudflare the primary memory store by disabling Hermes' built-in `MEMORY.md` and `USER.md` stores. Keep the local files unchanged as explicit migration and recovery input.
- Migrated `MEMORY.md`/`USER.md` entries use the active Hermes identity's deterministic local-CLI profile. Persist failed remote session deletions and rewind generations as content-free state until confirmed; maintain the content-free curated manifest used for exact stale-session reconciliation.

## Source map

- `client.py`: HTTP transport, V4 envelope handling, limits, encoding, pagination primitives.
- `__init__.py`: provider lifecycle, identity, tools, checkpoint buffers, and legacy curated-memory mirror compatibility.
- `migration.py`: pure planning and explicit apply/reporting.
- `cli.py`: lightweight active-provider `status`, `migrate`, and `export` registration. It must remain importable before Hermes loads the provider package.
- `tests/test_cloudflare_memory.py`: standard-library HTTP double and all contract tests.
- `docs/superpowers/`: approved design and implementation plan.

## Verification

Run Python through `uv`. Test against a current Hermes source checkout:

```sh
HERMES_SOURCE=/path/to/hermes-agent
PYTHONPATH="$HERMES_SOURCE:$PWD" \
  uv run --project "$HERMES_SOURCE" python -m unittest discover -s tests -v
uv run python -m compileall -q __init__.py client.py migration.py cli.py
```

For behavior changes, add the narrowest failing `unittest` first, run it red, implement the minimal fix, then run the full suite. Use a disposable Hermes home and namespace for installation/live checks; never log credentials or delete operator data.
