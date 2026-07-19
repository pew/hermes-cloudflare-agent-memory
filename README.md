# Hermes Cloudflare Agent Memory

[Hermes memory-provider plugin](https://hermes-agent.nousresearch.com/docs/developer-guide/memory-provider-plugin) for [Cloudflare Agent Memory](https://developers.cloudflare.com/agent-memory/).

It adds explicit recall, remember, exact forget, summaries, checkpointed conversation ingestion, and a dry-run-first migration from existing Hermes memory.

## Data boundary

The plugin sends only:

- user and assistant text, after Hermes secret redaction;
- curated `MEMORY.md` and `USER.md` entries after strict threat scanning and redaction;
- opaque profile and session identifiers.

It never sends system prompts, tool calls/results, terminal output, files, API tokens, raw gateway user IDs, or other profiles' memory. Local Hermes memory remains the recovery source. Content-free failed-delete tombstones and rewind generations are kept in `$HERMES_HOME/cloudflare-agent-memory-pending.json`; a content-free curated mirror manifest is kept in `$HERMES_HOME/cloudflare-agent-memory-curated.json`. Both are bound to opaque account/namespace and profile identifiers.

## Install

Prerequisites: current Hermes, Git, a Cloudflare account with Agent Memory beta access, an Agent Memory namespace, and a dedicated account-scoped API token.

```sh
# Create a namespace once (32 characters maximum).
npx wrangler agent-memory namespace create hermes-prod

# Install this plugin from GitHub.
hermes plugins install pew/hermes-cloudflare-agent-memory --no-enable

# Store account ID + namespace in the profile config and the token in .env.
hermes memory setup cloudflare-agent-memory

# Confirm activation and live API access.
hermes memory status
hermes cloudflare-agent-memory status
```

For an automated Hermes installation: run those commands in order, ask the operator only for the Cloudflare account ID, namespace, and API token when prompted, and never print or persist the token anywhere except Hermes' profile-scoped `.env`.

Hermes writes non-secrets to `$HERMES_HOME/cloudflare-agent-memory.json` and the token to `$HERMES_HOME/.env`. Both should remain mode `0600`.

Cloudflare's public beta docs currently say the token needs “appropriate Agent Memory permissions,” but neither the Agent Memory guide nor the official permission catalog names a permission label as of 2026-07-16. Do not guess: select the Agent Memory permission exposed to your beta-enabled account or confirm it with Cloudflare beta onboarding, scope it to the target account, and verify it with the status command.

## Use

Hermes receives four model-visible tools:

- `cloudflare_memory_recall` — recall relevant prior facts;
- `cloudflare_memory_remember` — save one durable, non-secret fact;
- `cloudflare_memory_forget` — delete one exact recalled memory ID;
- `cloudflare_memory_summary` — inspect the current profile's stored summary.

Conversation text is buffered and ingested only at 500-message boundaries, session end, context compression, session switch, or shutdown. Cloudflare failures do not fail an ordinary Hermes turn; unsent checkpoint data stays buffered for a later retry while the process remains alive.

Hermes `/undo` clears unsent buffered turns and deletes the exact remote session so undone content is not retained. This also removes earlier Cloudflare extraction from that session; local Hermes history remains the source for any deliberate re-migration.

Profiles are derived from trusted Hermes runtime identity. Identified gateway users are isolated by platform and user; unidentified non-CLI callers are isolated per session; local CLI sessions share the active Hermes profile's memory.

## Migrate existing data

Migration never deletes or edits local memory or exports. It adds current entries and may delete only stale Cloudflare curated sessions previously recorded in the plugin's content-free mirror manifest.

### Import from Claude, ChatGPT, or another service

Ask the source service to format its memory with this prompt:

```text
Export the durable memory you have about me for Hermes. Return exactly two
plain-text code blocks named USER.md and MEMORY.md.

Put stable facts about me, preferences, corrections, response instructions,
and workflow habits in USER.md. Put reusable project facts, environment details,
conventions, and tool notes in MEMORY.md.

Within each block, write concise standalone entries separated by a line containing
only §. Do not include headings, bullets, numbering, commentary, duplicates,
inferred facts, secrets, or credentials. Leave a block empty if it has no entries.
```

Run `hermes backup`, merge the block contents into the active profile's `$HERMES_HOME/memories/USER.md` and `MEMORY.md`, then:

```sh
hermes cloudflare-agent-memory migrate --dry-run
hermes cloudflare-agent-memory migrate --apply
```

### Migrate Hermes memory and sessions

```sh
# Back up Hermes first.
hermes backup

# Optional historical sessions export. Hermes redacts JSONL by default.
hermes sessions export hermes-sessions.jsonl

# Dry-run is the default. Review counts and validation errors.
hermes cloudflare-agent-memory migrate --dry-run \
  --sessions-jsonl hermes-sessions.jsonl

# Apply explicitly. Rerunning is safe: ingest is idempotent and curated
# entries are checked by deterministic session ID before remember.
hermes cloudflare-agent-memory migrate --apply \
  --sessions-jsonl hermes-sessions.jsonl

# Verify connectivity/count, then ask Hermes to recall representative facts.
hermes cloudflare-agent-memory status
```

Content-free JSONL reports are written under `$HERMES_HOME/cloudflare-agent-memory-migrations/`. They record rejected source hashes, every planned operation before remote writes begin, and final applied/skipped/failed results. A nonzero exit means at least one input row or remote operation failed; fix the cause and rerun the same command.

## Roll back, update, or remove

```sh
# Immediately return to built-in-only memory. Local data is unchanged.
hermes memory off

hermes plugins update cloudflare-agent-memory
hermes plugins remove cloudflare-agent-memory
```

Disabling or removing the plugin does not delete Cloudflare data. Delete remote memories, sessions, profiles, or the namespace separately only when that is explicitly intended.

## Compatibility

Tested on 2026-07-16 against Hermes commit [`5f171e36ab8dd6f731177a2b41c572768dc517dc`](https://github.com/NousResearch/hermes-agent/commit/5f171e36ab8dd6f731177a2b41c572768dc517dc). Cloudflare's HTTP API page was last updated 2026-06-02 and its limits page 2026-06-03 when verified. Agent Memory is beta; rerun the test suite when upgrading Hermes or when Cloudflare changes the API.

```sh
HERMES_SOURCE=/path/to/hermes-agent
PYTHONPATH="$HERMES_SOURCE:$PWD" \
  uv run --project "$HERMES_SOURCE" python -m unittest discover -s tests -v
uv run python -m compileall -q __init__.py client.py migration.py cli.py
```
