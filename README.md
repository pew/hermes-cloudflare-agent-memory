# Hermes Cloudflare Agent Memory

[Hermes memory-provider plugin](https://hermes-agent.nousresearch.com/docs/developer-guide/memory-provider-plugin) for [Cloudflare Agent Memory](https://developers.cloudflare.com/agent-memory/).

It makes Cloudflare Agent Memory the primary Hermes memory store. It adds recall, remember, exact forget, summaries, checkpoint ingestion, migration, and full JSONL export.

## Data boundary

The plugin sends only:

- user and assistant text, after Hermes secret redaction;
- curated `MEMORY.md` and `USER.md` entries after strict threat scanning and redaction;
- opaque profile and session identifiers.

It never sends system prompts, tool calls/results, terminal output, files, API tokens, raw gateway user IDs, or other profiles' memory. Existing local Hermes memory remains an unchanged source for migration and recovery of those local entries. Content-free failed-delete tombstones and rewind generations are kept in `$HERMES_HOME/cloudflare-agent-memory-pending.json`; a content-free curated migration manifest is kept in `$HERMES_HOME/cloudflare-agent-memory-curated.json`. Both are bound to opaque account/namespace and profile identifiers.

## Install

Prerequisites: Hermes 0.20.5 or newer, Git, a Cloudflare account with Agent Memory beta access, an Agent Memory namespace, and a dedicated account-scoped API token.

```sh
# Create a namespace once (32 characters maximum).
npx wrangler agent-memory namespace create hermes-prod

# Install this plugin from GitHub.
hermes plugins install pew/hermes-cloudflare-agent-memory --no-enable

# Store account ID + namespace in the profile config and the token in .env.
hermes memory setup cloudflare-agent-memory

# If local MEMORY.md or USER.md contains data, review and apply its migration.
hermes cloudflare-agent-memory migrate --dry-run
hermes cloudflare-agent-memory migrate --apply

# Confirm activation and live API access.
hermes memory status
hermes cloudflare-agent-memory status
```

For an automated Hermes installation: run those commands in order, ask the operator only for the Cloudflare account ID, namespace, and API token when prompted, and never print or persist the token anywhere except Hermes' profile-scoped `.env`.

Hermes writes non-secrets to `$HERMES_HOME/cloudflare-agent-memory.json` and the token to `$HERMES_HOME/.env`. Both should remain mode `0600`.

## Use

Hermes receives four model-visible tools:

- `cloudflare_memory_recall` — recall curated and current runtime facts;
- `cloudflare_memory_remember` — save one durable, non-secret fact;
- `cloudflare_memory_forget` — delete one exact recalled memory ID;
- `cloudflare_memory_summary` — inspect curated and current runtime summaries.

Setup sets `memory.memory_enabled` and `memory.user_profile_enabled` to `false`.
This removes Hermes' built-in `memory` tool, including its local character
limits. Cloudflare tools then own all model-visible durable memory operations.
Start a new Hermes session after setup or update so the tool surface reloads.

Conversation text is buffered and ingested only at 500-message boundaries, session end, context compression, session switch, or shutdown. Cloudflare failures do not fail an ordinary Hermes turn; unsent checkpoint data stays buffered for a later retry while the process remains alive.

Hermes `/undo` clears unsent buffered turns and deletes the exact remote session so undone content is not retained. This also removes earlier Cloudflare extraction from that session; local Hermes history remains the source for any deliberate re-migration.

Profiles are derived from trusted Hermes runtime identity. Identified gateway users read only their platform and user profile; unidentified non-CLI callers are isolated per session. Local CLI sessions share the active Hermes profile's memory, including migrated local entries.

Setup does not edit or delete local `MEMORY.md` or `USER.md` files. Hermes no
longer injects them after setup. Use the migration commands to copy their
entries to Cloudflare. `cloudflare_memory_forget` can delete an exact migrated
memory after recall. A later migration will import that entry again if it still
exists in the local source file.

## Migrate existing data

Migration never deletes or edits local memory or exports. It adds current entries and may delete only stale Cloudflare curated sessions previously recorded in the plugin's content-free mirror manifest.

Use the migration command only for entries that already exist in local
`MEMORY.md` or `USER.md`:

```sh
hermes cloudflare-agent-memory migrate --dry-run
hermes cloudflare-agent-memory migrate --apply
```

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

## Export data

Export the active Hermes profile before you change memory providers:

```sh
hermes cloudflare-agent-memory export --output cloudflare-memory.jsonl
```

The first JSONL row identifies the format, version, namespace, and exported
profiles. Each remaining row contains an opaque profile name and one complete
Cloudflare memory object. The export keeps all fields that the Cloudflare API
returns, including the full memory content.

The command reads all memory pages and fetches the full content for each memory.
It does not change Cloudflare data. It writes the file atomically with mode
`0600`, and it refuses to replace an existing file.

Use `--profile` to export a known isolated gateway profile. Repeat this option
to export more than one profile:

```sh
hermes cloudflare-agent-memory export \
  --output gateway-memory.jsonl \
  --profile hermes-example-profile-one \
  --profile hermes-example-profile-two
```

The default export contains the active Hermes profile. This command exports
only that profile or the profiles selected with `--profile`. Treat every export
file as sensitive data.

## Roll back, update, or remove

```sh
# Export Cloudflare memory before a provider change.
hermes cloudflare-agent-memory export --output cloudflare-memory.jsonl

# Change to another external provider. Start a new session after setup.
hermes memory setup honcho

# Restore built-in memory before disabling the provider.
hermes config set memory.memory_enabled true
hermes config set memory.user_profile_enabled true
hermes memory off

hermes plugins update cloudflare-agent-memory
hermes memory setup cloudflare-agent-memory
hermes plugins remove cloudflare-agent-memory
```

`hermes memory off` does not change the two built-in store flags. Run both
`hermes config set` commands first when you want built-in-only memory.
Disabling or removing the plugin does not delete Cloudflare data or local
memory files. Delete remote memories, sessions, profiles, or the namespace
separately only when that is explicitly intended.
