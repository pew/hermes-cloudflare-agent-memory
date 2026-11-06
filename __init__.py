"""Cloudflare Agent Memory provider for Hermes."""

from __future__ import annotations

import hashlib
import inspect
import json
import logging
import os
import queue
import re
import threading
import time
from pathlib import Path
from typing import Any

from agent.memory_manager import sanitize_context
from agent.memory_provider import MemoryProvider
from agent.redact import redact_sensitive_text
from tools.memory_tool import MemoryStore
from tools.registry import tool_error
from tools.threat_patterns import scan_for_threats
from utils import atomic_json_write

from .client import (
    MAX_INGEST_MESSAGES,
    MAX_NAMESPACE_CHARS,
    CloudflareMemoryClient,
    CloudflareMemoryError,
    split_message,
    normalize_session_id,
)

PROVIDER_NAME = "cloudflare-agent-memory"
TOKEN_ENV = "CLOUDFLARE_AGENT_MEMORY_API_TOKEN"
CONFIG_FILENAME = "cloudflare-agent-memory.json"
PENDING_FILENAME = "cloudflare-agent-memory-pending.json"
CURATED_STATE_FILENAME = "cloudflare-agent-memory-curated.json"
REMOTE_LOCK_FILENAME = "cloudflare-agent-memory-remote"
_WRITE_STOP = object()

logger = logging.getLogger(__name__)


def _supports_cloudflare_primary_mode() -> bool:
    try:
        from tools.memory_tool import get_builtin_memory_store_flags
    except ImportError:
        return False
    return callable(get_builtin_memory_store_flags)


def derived_profile_name(
    agent_identity: str, platform: str, user_id: str, session_id: str
) -> str:
    """Derive a stable, opaque Cloudflare profile from trusted runtime identity."""
    agent_identity = agent_identity or "default"
    platform = platform or "cli"
    if user_id:
        subject = f"user:{platform}:{user_id}"
    elif platform == "cli":
        subject = "local:cli"
    else:
        subject = f"session:{platform}:{session_id}"
    digest = hashlib.sha256(f"{agent_identity}\0{subject}".encode()).hexdigest()[:24]
    prefix = re.sub(r"[^a-zA-Z0-9_-]+", "-", agent_identity).strip("-")[:40] or "default"
    return f"hermes-{prefix}-{digest}"


def curated_session_id(target: str, content: str) -> str:
    digest = hashlib.sha256(f"{target}\0{content}".encode()).hexdigest()[:48]
    return f"hermes-memory-{digest}"


def _load_config(hermes_home: str | Path) -> dict[str, str]:
    path = Path(hermes_home) / CONFIG_FILENAME
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(value, dict):
        return {}
    return {
        key: str(value.get(key) or "").strip()
        for key in ("account_id", "namespace")
    }


def _load_delete_state(
    hermes_home: str | Path,
) -> dict[tuple[str, str, str], tuple[int, bool]]:
    path = Path(hermes_home) / PENDING_FILENAME
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    rows = value.get("session_deletes", []) if isinstance(value, dict) else []
    state = {}
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict):
            continue
        destination_id = str(row.get("destination_id") or "")
        profile = str(row.get("profile") or "")
        session_id = str(row.get("session_id") or "")
        generation_value = row.get("generation", 0)
        generation = (
            generation_value
            if isinstance(generation_value, int) and not isinstance(generation_value, bool)
            else 0
        )
        pending_value = row.get("pending", True)
        pending = pending_value if isinstance(pending_value, bool) else True
        if (
            len(destination_id) == 64
            and all(char in "0123456789abcdef" for char in destination_id)
            and profile
            and len(profile) <= 100
            and session_id
            and len(session_id) <= 64
            and generation >= 0
        ):
            if pending or generation:
                state[(destination_id, profile, session_id)] = (generation, pending)
    return state


def _persist_delete_state(
    path: Path, state: dict[tuple[str, str, str], tuple[int, bool]]
) -> None:
    rows = []
    for (destination_id, profile, session_id), (generation, pending) in sorted(
        state.items()
    ):
        row = {
            "destination_id": destination_id,
            "profile": profile,
            "session_id": session_id,
            "pending": pending,
        }
        if generation:
            row["generation"] = generation
        rows.append(row)
    atomic_json_write(
        path,
        {"session_deletes": rows},
        mode=0o600,
        sort_keys=True,
    )


def curated_source_hash(target: str, content: str) -> str:
    return hashlib.sha256(f"curated\0{target}\0{content}".encode()).hexdigest()


def _load_curated_manifest(
    hermes_home: str | Path,
) -> set[tuple[str, str, str, str, str]]:
    path = Path(hermes_home) / CURATED_STATE_FILENAME
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return set()
    rows = value.get("entries", []) if isinstance(value, dict) else []
    entries = set()
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict):
            continue
        entry = tuple(
            str(row.get(key) or "")
            for key in (
                "destination_id",
                "profile",
                "target",
                "source_hash",
                "session_id",
            )
        )
        destination_id, profile, target, source_hash, session_id = entry
        if (
            len(destination_id) == 64
            and all(char in "0123456789abcdef" for char in destination_id)
            and profile
            and len(profile) <= 100
            and target in {"memory", "user"}
            and len(source_hash) == 64
            and all(char in "0123456789abcdef" for char in source_hash)
            and session_id.startswith("hermes-memory-")
            and len(session_id) <= 64
        ):
            entries.add(entry)
    return entries


def _update_curated_manifest(
    hermes_home: str | Path,
    *,
    add: tuple[str, str, str, str, str] | None = None,
    remove_session: tuple[str, str, str] | None = None,
) -> None:
    path = Path(hermes_home) / CURATED_STATE_FILENAME
    with MemoryStore._file_lock(path):
        entries = _load_curated_manifest(hermes_home)
        if add:
            entries.add(add)
        if remove_session:
            destination_id, profile, session_id = remove_session
            entries = {
                entry
                for entry in entries
                if (entry[0], entry[1], entry[4])
                != (destination_id, profile, session_id)
            }
        rows = [
            {
                "destination_id": destination_id,
                "profile": profile,
                "target": target,
                "source_hash": source_hash,
                "session_id": session_id,
            }
            for destination_id, profile, target, source_hash, session_id in sorted(entries)
        ]
        atomic_json_write(
            path,
            {"entries": rows},
            mode=0o600,
            sort_keys=True,
        )


RECALL_SCHEMA = {
    "name": "cloudflare_memory_recall",
    "description": "Recall relevant curated and runtime facts from Cloudflare memory.",
    "parameters": {
        "type": "object",
        "properties": {
            "query": {"type": "string", "description": "The question to answer from memory."}
        },
        "required": ["query"],
        "additionalProperties": False,
    },
}

REMEMBER_SCHEMA = {
    "name": "cloudflare_memory_remember",
    "description": (
        "Primary save tool for all durable, non-secret facts and instructions."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "content": {"type": "string", "description": "The durable memory to store."}
        },
        "required": ["content"],
        "additionalProperties": False,
    },
}

FORGET_SCHEMA = {
    "name": "cloudflare_memory_forget",
    "description": "Delete one memory by its exact recalled ID after an explicit user request.",
    "parameters": {
        "type": "object",
        "properties": {
            "memory_id": {
                "type": "string",
                "description": "Exact memory ID returned by recall.",
            }
        },
        "required": ["memory_id"],
        "additionalProperties": False,
    },
}

SUMMARY_SCHEMA = {
    "name": "cloudflare_memory_summary",
    "description": "Summarize curated and runtime Cloudflare memory.",
    "parameters": {
        "type": "object",
        "properties": {},
        "additionalProperties": False,
    },
}


class CloudflareAgentMemoryProvider(MemoryProvider):
    def __init__(self) -> None:
        self._hermes_home = ""
        self._agent_identity = "default"
        self._platform = "cli"
        self._user_id = ""
        self._profile = ""
        self._curated_profile = ""
        self._session_id = ""
        self._write_enabled = True
        self._client: CloudflareMemoryClient | None = None
        self._recalled_memory_profiles: dict[str, tuple[str, str]] = {}
        self._buffers: dict[str, list[dict[str, str]]] = {}
        self._buffer_profiles: dict[str, str] = {}
        self._buffer_generations: dict[str, int] = {}
        self._buffer_lock = threading.Lock()
        self._remote_session_lock = threading.RLock()
        self._curated_snapshot: dict[str, set[str]] = {"memory": set(), "user": set()}
        self._curated_state_lock = threading.RLock()
        self._write_queue: queue.Queue[object] = queue.Queue()
        self._write_worker: threading.Thread | None = None
        self._failed_curated_operations: set[tuple] = set()
        self._failed_curated_lock = threading.Lock()
        self._pending_session_deletes: set[tuple[str, str, str]] = set()
        self._session_generations: dict[tuple[str, str, str], int] = {}
        self._unsaved_delete_state: dict[tuple[str, str, str], tuple[int, bool]] = {}
        self._pending_delete_lock = threading.Lock()
        self._shutdown_timeout = 5.0

    @property
    def name(self) -> str:
        return PROVIDER_NAME

    def is_available(self) -> bool:
        from hermes_constants import get_hermes_home

        if not _supports_cloudflare_primary_mode():
            return False
        config = _load_config(get_hermes_home())
        return bool(
            config.get("account_id")
            and config.get("namespace")
            and os.environ.get(TOKEN_ENV, "").strip()
        )

    def unavailable_reason(self) -> str:
        if not _supports_cloudflare_primary_mode():
            return (
                "Cloudflare-primary memory requires current Hermes; "
                "upgrade Hermes and run setup again."
            )
        return ""

    def get_config_schema(self) -> list[dict[str, Any]]:
        return [
            {
                "key": "account_id",
                "description": "Cloudflare account ID",
                "required": True,
                "secret": False,
            },
            {
                "key": "namespace",
                "description": "Existing Cloudflare Agent Memory namespace",
                "required": True,
                "secret": False,
            },
            {
                "key": "api_token",
                "description": "Dedicated Cloudflare API token with Agent Memory access",
                "required": True,
                "secret": True,
                "env_var": TOKEN_ENV,
                "url": "https://dash.cloudflare.com/profile/api-tokens",
            },
        ]

    def save_config(self, values: dict[str, Any], hermes_home: str) -> None:
        account_id = str((values or {}).get("account_id") or "").strip()
        namespace = str((values or {}).get("namespace") or "").strip()
        if not account_id:
            raise ValueError("account_id is required")
        if not namespace:
            raise ValueError("namespace is required")
        if len(namespace) > MAX_NAMESPACE_CHARS:
            raise ValueError(f"namespace must be at most {MAX_NAMESPACE_CHARS} characters")
        atomic_json_write(
            Path(hermes_home) / CONFIG_FILENAME,
            {"account_id": account_id, "namespace": namespace},
            mode=0o600,
            sort_keys=True,
        )

    def post_setup(self, hermes_home: str, config: dict[str, Any]) -> None:
        """Run setup directly because Hermes' named-provider shortcut skips schemas."""
        if not _supports_cloudflare_primary_mode():
            print(
                "\n  Setup cancelled: upgrade Hermes to a release that can disable "
                "the built-in memory tool.\n"
            )
            return

        from hermes_cli.config import save_config
        from hermes_cli.memory_setup import _prompt, _write_env_vars

        existing = _load_config(hermes_home)
        account_id = _prompt(
            "Cloudflare account ID", default=existing.get("account_id") or None
        ).strip()
        namespace = _prompt(
            "Agent Memory namespace", default=existing.get("namespace") or None
        ).strip()
        current_token = os.environ.get(TOKEN_ENV, "").strip()
        token_label = (
            f"Cloudflare Agent Memory API token (current: ...{current_token[-4:]}, blank to keep)"
            if current_token
            else "Cloudflare Agent Memory API token"
        )
        api_token = _prompt(token_label, secret=True).strip() or current_token
        if not account_id or not namespace or not api_token:
            print("\n  Setup cancelled: account ID, namespace, and API token are required.\n")
            return

        self.save_config(
            {"account_id": account_id, "namespace": namespace}, hermes_home
        )
        env_writes = {TOKEN_ENV: api_token}
        if "hermes_home" in inspect.signature(_write_env_vars).parameters:
            _write_env_vars(env_writes, hermes_home=hermes_home)
        else:
            _write_env_vars(Path(hermes_home) / ".env", env_writes)
        os.environ[TOKEN_ENV] = api_token
        if not isinstance(config.get("memory"), dict):
            config["memory"] = {}
        config["memory"]["provider"] = self.name
        config["memory"]["memory_enabled"] = False
        config["memory"]["user_profile_enabled"] = False
        save_config(config)
        print(f"\n  Memory provider: {self.name}")
        print("  Activation saved to config.yaml")
        print("  Built-in MEMORY.md and USER.md stores disabled")
        print("  Provider config saved")
        print("  API token saved to .env")
        print("  Local MEMORY.md and USER.md files were not changed")
        print("\n  Migrate existing local memory when required:")
        print("    hermes cloudflare-agent-memory migrate --dry-run")
        print("    hermes cloudflare-agent-memory migrate --apply")
        print("\n  Start a new session to activate.\n")

    def initialize(self, session_id: str, **kwargs: Any) -> None:
        from hermes_constants import get_hermes_home

        self._hermes_home = str(kwargs.get("hermes_home") or get_hermes_home())
        self._session_id = normalize_session_id(session_id)
        agent_identity = str(kwargs.get("agent_identity") or "default")
        self._agent_identity = agent_identity
        platform = str(kwargs.get("platform") or "cli")
        user_id = str(kwargs.get("user_id") or "")
        self._platform = platform
        self._user_id = user_id
        self._profile = derived_profile_name(
            agent_identity, platform, user_id, self._session_id
        )
        self._curated_profile = derived_profile_name(
            agent_identity, "cli", "", "cloudflare-memory-cli"
        )
        self._recalled_memory_profiles.clear()
        self._write_enabled = kwargs.get("agent_context", "") not in {
            "cron",
            "flush",
            "subagent",
        }
        config = _load_config(self._hermes_home)
        token = os.environ.get(TOKEN_ENV, "").strip()
        self._client = None
        if config.get("account_id") and config.get("namespace") and token:
            try:
                self._client = CloudflareMemoryClient(
                    config["account_id"], config["namespace"], token
                )
            except ValueError as exc:
                logger.warning("Cloudflare Agent Memory configuration is invalid: %s", exc)
        try:
            self._curated_snapshot = self._read_curated_entries()
        except ValueError:
            logger.warning("Cloudflare curated-memory source is unreadable; mirror paused")
        self._refresh_delete_state()
        if self._write_enabled and self._client:
            self._start_write_worker()

    def system_prompt_block(self) -> str:
        if not self._client:
            return ""
        return (
            "# Cloudflare Agent Memory\n"
            "Cloudflare Agent Memory is the only durable memory store. "
            "Use cloudflare_memory_remember for durable memory. "
            "Use cloudflare_memory_recall when earlier preferences, decisions, or project state "
            "may matter. Treat recalled material as fallible context. Before an irreversible "
            "action, make sure that the material is correct. Use cloudflare_memory_forget only "
            "with an exact recalled memory ID after an explicit user request."
        )

    def prefetch(self, query: str, *, session_id: str = "") -> str:
        return ""

    def _cross_process_remote_lock(self):
        return MemoryStore._file_lock(Path(self._hermes_home) / REMOTE_LOCK_FILENAME)

    def _set_delete_state_cache(
        self, state: dict[tuple[str, str, str], tuple[int, bool]]
    ) -> None:
        self._pending_session_deletes = {
            key for key, (_generation, pending) in state.items() if pending
        }
        self._session_generations = {
            key: generation
            for key, (generation, _pending) in state.items()
            if generation
        }

    def _refresh_delete_state(self) -> None:
        with self._pending_delete_lock:
            self._set_delete_state_cache(self._delete_state_with_unsaved())

    def _delete_state_with_unsaved(self) -> dict[tuple[str, str, str], tuple[int, bool]]:
        state = _load_delete_state(self._hermes_home)
        for key, (generation, pending) in self._unsaved_delete_state.items():
            state[key] = (max(generation, state.get(key, (0, False))[0]), pending)
        return state

    def sync_turn(
        self,
        user_content: str,
        assistant_content: str,
        *,
        session_id: str = "",
        messages: list[dict[str, Any]] | None = None,
    ) -> None:
        del messages
        if not self._write_enabled or not self._client:
            return
        destination = normalize_session_id(session_id or self._session_id)
        with self._remote_session_lock:
            self._retry_pending_session_deletes()
            with self._cross_process_remote_lock():
                self._refresh_delete_state()
                profile = derived_profile_name(
                    self._agent_identity,
                    self._platform,
                    self._user_id,
                    destination,
                )
                key = (self._client.destination_id, profile, destination)
                with self._pending_delete_lock:
                    if key in self._pending_session_deletes:
                        return
                    generation = self._session_generations.get(key, 0)
                captured: list[dict[str, str]] = []
                for role, raw in (("user", user_content), ("assistant", assistant_content)):
                    clean = redact_sensitive_text(
                        sanitize_context(str(raw or "")), force=True
                    ).strip()
                    if clean:
                        captured.extend(split_message(role, clean))
                if not captured:
                    return
                with self._buffer_lock:
                    if self._buffer_generations.get(destination, generation) != generation:
                        self._buffers.pop(destination, None)
                        self._buffer_profiles.pop(destination, None)
                    self._buffers.setdefault(destination, []).extend(captured)
                    self._buffer_profiles.setdefault(destination, profile)
                    self._buffer_generations[destination] = generation
                    should_flush = len(self._buffers[destination]) >= MAX_INGEST_MESSAGES
            if should_flush:
                self._flush_session(destination, max_messages=MAX_INGEST_MESSAGES)

    def _flush_session(self, session_id: str, *, max_messages: int | None = None) -> bool:
        if not self._write_enabled or not self._client:
            return False
        with self._remote_session_lock:
            self._retry_pending_session_deletes()
            while True:
                with self._buffer_lock:
                    pending = self._buffers.get(session_id, [])
                    count = min(len(pending), max_messages or MAX_INGEST_MESSAGES)
                    batch = list(pending[:count])
                    profile = self._buffer_profiles.get(session_id, self._profile)
                    buffer_generation = self._buffer_generations.get(session_id, 0)
                if not batch:
                    return True
                with self._cross_process_remote_lock():
                    self._refresh_delete_state()
                    key = (self._client.destination_id, profile, session_id)
                    with self._pending_delete_lock:
                        generation = self._session_generations.get(key, 0)
                        delete_pending = key in self._pending_session_deletes
                    if buffer_generation != generation:
                        with self._buffer_lock:
                            if (
                                self._buffer_generations.get(session_id, 0)
                                == buffer_generation
                            ):
                                self._buffers.pop(session_id, None)
                                self._buffer_profiles.pop(session_id, None)
                                self._buffer_generations.pop(session_id, None)
                        return True
                    if delete_pending:
                        return False
                    try:
                        self._client.ingest(profile, batch, session_id)
                    except (CloudflareMemoryError, ValueError) as exc:
                        session_hash = hashlib.sha256(session_id.encode()).hexdigest()[:12]
                        logger.warning(
                            "Cloudflare Agent Memory ingest failed for session %s: %s",
                            session_hash,
                            exc,
                        )
                        return False
                    with self._buffer_lock:
                        current = self._buffers.get(session_id, [])
                        if current[: len(batch)] != batch:
                            logger.warning(
                                "Cloudflare Agent Memory buffer changed during flush; retry retained"
                            )
                            return False
                        del current[: len(batch)]
                        if not current:
                            self._buffers.pop(session_id, None)
                            self._buffer_profiles.pop(session_id, None)
                            self._buffer_generations.pop(session_id, None)
                if max_messages is not None:
                    return True

    def on_session_end(self, messages: list[dict[str, Any]]) -> None:
        del messages
        self._retry_failed_curated_operations()
        self._flush_session(self._session_id)

    def on_pre_compress(self, messages: list[dict[str, Any]]) -> str:
        del messages
        self._retry_failed_curated_operations()
        self._flush_session(self._session_id)
        return ""

    def on_session_switch(self, new_session_id: str, **kwargs: Any) -> None:
        destination = normalize_session_id(new_session_id)
        self._recalled_memory_profiles.clear()
        if kwargs.get("rewound"):
            with self._remote_session_lock:
                if self._write_enabled and self._client:
                    with self._cross_process_remote_lock():
                        self._refresh_delete_state()
                        key = (
                            self._client.destination_id,
                            self._profile,
                            destination,
                        )
                        self._record_rewind(key)
                        with self._buffer_lock:
                            self._buffers.pop(destination, None)
                            self._buffer_profiles.pop(destination, None)
                            self._buffer_generations.pop(destination, None)
                        self._delete_session_or_defer_locked(
                            self._profile,
                            destination,
                            require_pending=True,
                        )
                else:
                    with self._buffer_lock:
                        self._buffers.pop(destination, None)
                        self._buffer_profiles.pop(destination, None)
                        self._buffer_generations.pop(destination, None)
            return
        self._retry_failed_curated_operations()
        self._retry_pending_session_deletes()
        previous = self._session_id
        if previous and previous != destination:
            self._flush_session(previous)
        self._session_id = destination
        self._profile = derived_profile_name(
            self._agent_identity,
            self._platform,
            self._user_id,
            destination,
        )

    def _delete_session_or_defer_locked(
        self, profile: str, session_id: str, *, require_pending: bool
    ) -> bool:
        key = (self._client.destination_id, profile, session_id)
        if require_pending:
            with self._pending_delete_lock:
                if key not in self._pending_session_deletes:
                    return True
        try:
            self._client.delete_session(profile, session_id)
        except (CloudflareMemoryError, ValueError) as exc:
            if isinstance(exc, CloudflareMemoryError) and exc.status == 404:
                try:
                    self._client.get_namespace()
                except CloudflareMemoryError:
                    pass
                else:
                    state_saved = self._update_pending_delete(
                        remove=key,
                        retain_generation=bool(self._session_generations.get(key)),
                    )
                    manifest_saved = self._remove_curated_manifest_session(key)
                    return state_saved and manifest_saved
            self._update_pending_delete(add=key)
            session_hash = hashlib.sha256(session_id.encode()).hexdigest()[:12]
            logger.warning(
                "Cloudflare Agent Memory deferred session delete failed for %s: %s",
                session_hash,
                exc,
            )
            return False
        state_saved = self._update_pending_delete(
            remove=key,
            retain_generation=bool(self._session_generations.get(key)),
        )
        manifest_saved = self._remove_curated_manifest_session(key)
        return state_saved and manifest_saved

    def _record_rewind(self, key: tuple[str, str, str]) -> int:
        path = Path(self._hermes_home) / PENDING_FILENAME
        try:
            with self._pending_delete_lock:
                with MemoryStore._file_lock(path):
                    state = self._delete_state_with_unsaved()
                    generation = state.get(key, (0, False))[0] + 1
                    state[key] = (generation, True)
                    _persist_delete_state(path, state)
                    self._unsaved_delete_state.clear()
                    self._set_delete_state_cache(state)
        except OSError as exc:
            with self._pending_delete_lock:
                generation = self._session_generations.get(key, 0) + 1
                self._session_generations[key] = generation
                self._pending_session_deletes.add(key)
                self._unsaved_delete_state[key] = (generation, True)
            logger.warning(
                "Cloudflare Agent Memory could not persist rewind generation: %s",
                exc.__class__.__name__,
            )
        return generation

    def _update_pending_delete(
        self,
        *,
        add: tuple[str, str, str] | None = None,
        remove: tuple[str, str, str] | None = None,
        retain_generation: bool = False,
    ) -> bool:
        path = Path(self._hermes_home) / PENDING_FILENAME
        try:
            with self._pending_delete_lock:
                with MemoryStore._file_lock(path):
                    state = self._delete_state_with_unsaved()
                    if add:
                        generation = state.get(
                            add, (self._session_generations.get(add, 0), False)
                        )[0]
                        state[add] = (generation, True)
                    if remove:
                        generation = state.get(
                            remove,
                            (self._session_generations.get(remove, 0), False),
                        )[0]
                        if retain_generation and generation:
                            state[remove] = (generation, False)
                        else:
                            state.pop(remove, None)
                    _persist_delete_state(path, state)
                    self._unsaved_delete_state.clear()
                    self._set_delete_state_cache(state)
            return True
        except OSError as exc:
            with self._pending_delete_lock:
                if add:
                    self._pending_session_deletes.add(add)
                    self._unsaved_delete_state[add] = (
                        self._session_generations.get(add, 0), True
                    )
            logger.warning(
                "Cloudflare Agent Memory could not persist pending deletes: %s",
                exc.__class__.__name__,
            )
            return False

    def _retry_pending_session_deletes(self) -> None:
        if not self._client or not self._write_enabled:
            return
        destination_id = self._client.destination_id
        with self._cross_process_remote_lock():
            self._refresh_delete_state()
        with self._pending_delete_lock:
            pending = [
                item
                for item in self._pending_session_deletes
                if item[0] == destination_id
            ]
        for _destination_id, profile, session_id in pending:
            with self._remote_session_lock, self._cross_process_remote_lock():
                self._refresh_delete_state()
                key = (_destination_id, profile, session_id)
                if key not in self._pending_session_deletes:
                    continue
                if profile == self._curated_profile and session_id.startswith("hermes-memory-"):
                    try:
                        current = self._read_curated_entries()
                    except ValueError:
                        logger.warning("Cloudflare curated-memory source is unreadable; delete deferred")
                        continue
                    if any(
                        curated_session_id(target, content) == session_id
                        for target, entries in current.items()
                        for content in entries
                    ):
                        self._update_pending_delete(remove=key)
                        continue
                self._delete_session_or_defer_locked(
                    profile, session_id, require_pending=True
                )

    def _remove_curated_manifest_session(
        self, key: tuple[str, str, str]
    ) -> bool:
        try:
            _update_curated_manifest(self._hermes_home, remove_session=key)
            return True
        except OSError as exc:
            logger.warning(
                "Cloudflare curated-memory state cleanup failed: %s",
                exc.__class__.__name__,
            )
            return False

    def _read_curated_entries(self) -> dict[str, set[str]]:
        store = MemoryStore()
        entries = {}
        for target in ("memory", "user"):
            filename = "USER.md" if target == "user" else "MEMORY.md"
            raw, read_ok = store._read_raw_checked(
                Path(self._hermes_home) / "memories" / filename
            )
            if not read_ok:
                raise ValueError("curated memory source is unreadable")
            entries[target] = set(store._parse_entries(raw))
        return entries

    def _start_write_worker(self) -> None:
        if self._write_worker and self._write_worker.is_alive():
            return
        self._write_worker = threading.Thread(
            target=self._run_write_worker,
            name="cloudflare-agent-memory-writes",
            daemon=True,
        )
        self._write_worker.start()

    def _run_write_worker(self) -> None:
        while True:
            operation = self._write_queue.get()
            try:
                if operation is _WRITE_STOP:
                    return
                action, target, content, profile = operation
                if not self._client:
                    continue
                with self._curated_state_lock:
                    if action == "replace":
                        new_content, old_content = content
                        if not self._reconcile_curated_entry(
                            profile, target, new_content
                        ):
                            continue
                        self._reconcile_curated_entry(profile, target, old_content)
                    else:
                        self._reconcile_curated_entry(profile, target, content)
            except (CloudflareMemoryError, ValueError) as exc:
                with self._failed_curated_lock:
                    self._failed_curated_operations.add(operation)
                logger.warning("Cloudflare curated-memory mirror failed: %s", exc)
            else:
                with self._failed_curated_lock:
                    self._failed_curated_operations.discard(operation)
            finally:
                self._write_queue.task_done()

    def _reconcile_curated_entry(
        self, profile: str, target: str, content: str
    ) -> bool:
        session_id = curated_session_id(target, content)
        with self._remote_session_lock:
            with self._cross_process_remote_lock():
                current = self._read_curated_entries()
                self._refresh_delete_state()
                key = (self._client.destination_id, profile, session_id)
                if content not in current[target]:
                    return self._delete_session_or_defer_locked(
                        profile, session_id, require_pending=False
                    )
                with self._pending_delete_lock:
                    delete_pending = key in self._pending_session_deletes
                if delete_pending:
                    if not self._update_pending_delete(remove=key):
                        raise CloudflareMemoryError(
                            "curated deletion cancellation could not be persisted"
                        )
                return self._remember_curated(profile, target, content)

    def _remember_curated(self, profile: str, target: str, content: str) -> bool:
        findings = scan_for_threats(content, scope="strict")
        if findings:
            logger.warning(
                "Curated memory %s blocked by strict threat scan",
                hashlib.sha256(content.encode()).hexdigest()[:12],
            )
            return False
        redacted = redact_sensitive_text(content, force=True).strip()
        if not redacted:
            return False
        session_id = curated_session_id(target, content)
        if self._session_has_memories(profile, session_id):
            self._record_curated_manifest(profile, target, content, session_id)
            return True
        self._client.remember(
            profile,
            redacted,
            session_id,
        )
        self._record_curated_manifest(profile, target, content, session_id)
        return True

    def _record_curated_manifest(
        self, profile: str, target: str, content: str, session_id: str
    ) -> None:
        entry = (
            self._client.destination_id,
            profile,
            target,
            curated_source_hash(target, content),
            session_id,
        )
        try:
            _update_curated_manifest(self._hermes_home, add=entry)
        except OSError as exc:
            raise CloudflareMemoryError(
                f"could not persist curated mirror state: {exc.__class__.__name__}"
            ) from None

    def _session_has_memories(self, profile: str, session_id: str) -> bool:
        cursor = ""
        seen_cursors = set()
        while True:
            try:
                page = self._client.list_memories(
                    profile, session_id=session_id, cursor=cursor
                )
            except CloudflareMemoryError as exc:
                if exc.status != 404:
                    raise
                self._client.get_namespace()
                return False
            if page.get("result"):
                return True
            cursor = str((page.get("result_info") or {}).get("cursor") or "")
            if not cursor:
                return False
            if cursor in seen_cursors:
                raise CloudflareMemoryError("memory list returned a repeated cursor")
            seen_cursors.add(cursor)

    def _retry_failed_curated_operations(self) -> None:
        with self._failed_curated_lock:
            pending = list(self._failed_curated_operations)
            self._failed_curated_operations.clear()
        for operation in pending:
            self._write_queue.put(operation)

    def on_memory_write(
        self,
        action: str,
        target: str,
        content: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        del metadata
        if not self._write_enabled or not self._client or target not in {"memory", "user"}:
            return
        try:
            current = self._read_curated_entries()
        except ValueError:
            logger.warning("Cloudflare curated-memory source is unreadable; mirror paused")
            return
        with self._curated_state_lock:
            previous = self._curated_snapshot
            removed = previous[target] - current[target]
            added = current[target] - previous[target]
            self._curated_snapshot = current
            if action == "add" and added == {content}:
                self._write_queue.put(("remember", target, content, self._curated_profile))
            elif action == "remove" and len(removed) == 1 and not added:
                self._write_queue.put(
                    ("delete", target, next(iter(removed)), self._curated_profile)
                )
            elif action == "replace" and len(removed) == 1 and len(added) == 1:
                self._write_queue.put(
                    (
                        "replace",
                        target,
                        (next(iter(added)), next(iter(removed))),
                        self._curated_profile,
                    )
                )
            else:
                logger.warning("Ambiguous curated-memory diff; remote delete skipped")
        self._retry_failed_curated_operations()

    def get_tool_schemas(self) -> list[dict[str, Any]]:
        return [RECALL_SCHEMA, REMEMBER_SCHEMA, FORGET_SCHEMA, SUMMARY_SCHEMA]

    def _require_write(self) -> None:
        if not self._write_enabled:
            raise ValueError("writes are disabled outside the primary agent context")

    def _tool_recall(self, args: dict[str, Any]) -> dict:
        query = sanitize_context(str(args.get("query") or ""))
        query = redact_sensitive_text(query, force=True).strip()
        if not query:
            raise ValueError("query is required")
        try:
            result = self._client.recall(self._profile, query)
        except CloudflareMemoryError as exc:
            if exc.status != 404:
                raise
            self._client.get_namespace()
            return {"answer": "", "count": 0, "candidates": []}
        answer = str(result.get("answer") or "")
        candidates = []
        recalled_profiles: dict[str, tuple[str, str]] = {}
        curated_sessions = {
            session_id
            for destination_id, profile, _target, _source_hash, session_id in _load_curated_manifest(
                self._hermes_home
            )
            if destination_id == self._client.destination_id
            and profile == self._profile
        }
        for item in result.get("candidates") or []:
            if not isinstance(item, dict):
                continue
            scope = (
                "curated"
                if str(item.get("sessionId") or "") in curated_sessions
                else "runtime"
            )
            candidate = {
                key: item[key] for key in ("id", "summary", "score") if key in item
            }
            candidate["scope"] = scope
            candidates.append(candidate)
            memory_id = item.get("id")
            if isinstance(memory_id, str) and memory_id:
                recalled_profiles[memory_id] = (self._profile, scope)
        self._recalled_memory_profiles.update(recalled_profiles)
        return {
            "answer": f"## Runtime identity\n{answer}" if answer else "",
            "count": len(candidates),
            "candidates": candidates,
        }

    def _tool_remember(self, args: dict[str, Any]) -> dict:
        self._require_write()
        content = str(args.get("content") or "").strip()
        if not content:
            raise ValueError("content is required")
        if scan_for_threats(content, scope="strict"):
            raise ValueError("content blocked by strict threat scan")
        content = redact_sensitive_text(content, force=True).strip()
        if not content:
            raise ValueError("content is empty after redaction")
        result = self._client.remember(self._profile, content, self._session_id)
        return {key: result[key] for key in ("id", "type", "summary") if key in result}

    def _tool_forget(self, args: dict[str, Any]) -> dict:
        self._require_write()
        memory_id = str(args.get("memory_id") or "").strip()
        if not memory_id:
            raise ValueError("memory_id is required")
        recalled = self._recalled_memory_profiles.get(memory_id)
        if recalled is None:
            raise ValueError("memory_id must be an exact ID returned by recall")
        profile, _scope = recalled
        self._client.delete_memory(profile, memory_id)
        self._recalled_memory_profiles.pop(memory_id, None)
        return {"forgotten": True, "id": memory_id}

    def _tool_summary(self) -> dict[str, str]:
        try:
            summary = self._client.summary(self._profile)
        except CloudflareMemoryError as exc:
            if exc.status != 404:
                raise
            self._client.get_namespace()
            return {"summary": ""}
        return {"summary": f"## Runtime identity memory\n{summary}" if summary else ""}

    def _current_profile_delete_pending(self) -> bool:
        if not self._client:
            return False
        with self._pending_delete_lock:
            return any(
                destination_id == self._client.destination_id
                and profile == self._profile
                for destination_id, profile, _session_id in self._pending_session_deletes
            )

    def handle_tool_call(self, tool_name: str, args: dict[str, Any], **kwargs: Any) -> str:
        if not self._client:
            return tool_error("Cloudflare Agent Memory is not configured.")
        with self._remote_session_lock:
            with self._cross_process_remote_lock():
                self._refresh_delete_state()
                if self._current_profile_delete_pending():
                    return tool_error(
                        "Cloudflare Agent Memory is unavailable while a pending rewind deletion is retried."
                    )
                try:
                    if tool_name == "cloudflare_memory_recall":
                        return json.dumps(self._tool_recall(args))
                    if tool_name == "cloudflare_memory_remember":
                        return json.dumps(self._tool_remember(args))
                    if tool_name == "cloudflare_memory_forget":
                        return json.dumps(self._tool_forget(args))
                    if tool_name == "cloudflare_memory_summary":
                        return json.dumps(self._tool_summary())
                    return tool_error(f"Unknown tool: {tool_name}")
                except (CloudflareMemoryError, ValueError) as exc:
                    return tool_error(f"Cloudflare Agent Memory failed: {exc}")

    def shutdown(self) -> None:
        deadline = time.monotonic() + self._shutdown_timeout
        if self._write_enabled and self._client:
            self._retry_failed_curated_operations()
        with self._buffer_lock:
            sessions = list(self._buffers)

        if (self._write_enabled and self._client) or sessions:
            def finalize_sessions() -> None:
                if self._write_enabled and self._client:
                    self._retry_pending_session_deletes()
                for session_id in sessions:
                    self._flush_session(session_id)

            finalizer = threading.Thread(target=finalize_sessions, daemon=True)
            finalizer.start()
            finalizer.join(max(0.0, deadline - time.monotonic()))
        worker = self._write_worker
        if worker and worker.is_alive():
            self._write_queue.put(_WRITE_STOP)
            worker.join(max(0.0, deadline - time.monotonic()))


def register(ctx: Any) -> None:
    ctx.register_memory_provider(CloudflareAgentMemoryProvider())
