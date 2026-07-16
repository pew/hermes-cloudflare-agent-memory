"""Dry-run-first migration from Hermes memory exports to Cloudflare."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from agent.memory_manager import sanitize_context
from agent.redact import redact_sensitive_text
from tools.memory_tool import MemoryStore
from tools.threat_patterns import scan_for_threats

from .client import (
    MAX_INGEST_MESSAGES,
    MAX_MESSAGE_BYTES,
    CloudflareMemoryError,
    batched,
    normalize_session_id,
    split_message,
    utf8_size,
)

if TYPE_CHECKING:
    from . import CloudflareAgentMemoryProvider


@dataclass
class MigrationStats:
    planned: int = 0
    applied: int = 0
    skipped: int = 0
    failed: int = 0
    planning_errors: int = 0
    curated: int = 0
    sessions: int = 0
    messages: int = 0
    rejections: list[dict[str, str]] = field(default_factory=list)


class MigrationReportError(RuntimeError):
    """A local audit-report failure that prevents safe migration."""


def _source_hash(*parts: object) -> str:
    material = "\0".join(str(part) for part in parts)
    return hashlib.sha256(material.encode()).hexdigest()


def _reject(
    stats: MigrationStats, source_hash: str, kind: str, reason: str
) -> None:
    stats.planning_errors += 1
    stats.rejections.append(
        {"source_hash": source_hash, "kind": kind, "reason": reason}
    )


def _content_text(content: Any) -> str:
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = [_content_text(part) for part in content]
        return "\n".join(part for part in parts if part)
    if isinstance(content, dict):
        if content.get("type") not in {None, "text", "input_text", "output_text"}:
            return ""
        for key in ("text", "content"):
            value = content.get(key)
            if isinstance(value, str):
                return value
        return ""
    return ""


def _timestamp(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        raise ValueError("timestamp must be RFC 3339 or Unix seconds")
    if isinstance(value, (int, float)):
        parsed = datetime.fromtimestamp(float(value), tz=timezone.utc)
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            return ""
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("timestamp must include a timezone")
    else:
        raise ValueError("timestamp must be RFC 3339 or Unix seconds")
    return (
        parsed.astimezone(timezone.utc)
        .isoformat(timespec="auto")
        .replace("+00:00", "Z")
    )


def _curated_operations(
    provider: CloudflareAgentMemoryProvider, stats: MigrationStats
) -> list[dict]:
    from . import (
        _load_curated_manifest,
        curated_session_id,
        derived_profile_name,
    )

    store = MemoryStore()
    store.load_from_disk()
    profile = derived_profile_name(provider._agent_identity, "cli", "", "cloudflare-memory-cli")
    operations = []
    desired_sessions = set()
    for target, entries in (
        ("memory", store.memory_entries),
        ("user", store.user_entries),
    ):
        for content in entries:
            source_hash = _source_hash("curated", target, content)
            if scan_for_threats(content, scope="strict"):
                stats.skipped += 1
                _reject(stats, source_hash, "remember", "threat_detected")
                continue
            redacted = redact_sensitive_text(content, force=True).strip()
            if not redacted:
                stats.skipped += 1
                _reject(stats, source_hash, "remember", "empty_after_redaction")
                continue
            if utf8_size(redacted) > MAX_MESSAGE_BYTES:
                stats.skipped += 1
                _reject(stats, source_hash, "remember", "content_too_large")
                continue
            operations.append(
                {
                    "kind": "remember",
                    "source_hash": source_hash,
                    "profile": profile,
                    "session_id": curated_session_id(target, content),
                    "target": target,
                    "content": redacted,
                    "messages": None,
                }
            )
            desired_sessions.add(curated_session_id(target, content))
            stats.curated += 1
    destination_id = provider._client.destination_id
    for entry in sorted(_load_curated_manifest(provider._hermes_home)):
        entry_destination, entry_profile, target, source_hash, session_id = entry
        if (
            entry_destination == destination_id
            and entry_profile == profile
            and session_id not in desired_sessions
        ):
            operations.append(
                {
                    "kind": "delete",
                    "source_hash": source_hash,
                    "profile": profile,
                    "session_id": session_id,
                    "target": target,
                    "content": None,
                    "messages": None,
                }
            )
            stats.curated += 1
    return operations


def _session_operations(
    provider: CloudflareAgentMemoryProvider,
    sessions_jsonl: Path,
    stats: MigrationStats,
) -> list[dict]:
    from . import derived_profile_name

    operations = []
    try:
        lines = sessions_jsonl.open("rb")
    except OSError:
        _reject(
            stats,
            _source_hash("sessions-file", sessions_jsonl),
            "ingest",
            "sessions_file_unreadable",
        )
        return operations
    with lines:
        for raw_line in lines:
            if not raw_line.strip():
                continue
            row_hash = hashlib.sha256(b"session-row\0" + raw_line).hexdigest()
            try:
                line = raw_line.decode("utf-8")
                session = json.loads(line)
                if not isinstance(session, dict):
                    raise ValueError("session row must be an object")
                raw_session_id = str(session.get("id") or session.get("session_id") or "").strip()
                if not raw_session_id:
                    raise ValueError("session ID is required")
                raw_messages = session.get("messages")
                if not isinstance(raw_messages, list):
                    raise ValueError("messages must be a list")
                session_id = normalize_session_id(raw_session_id)
                source = str(session.get("source") or "cli")
                user_id = str(session.get("user_id") or "")
                profile = derived_profile_name(
                    provider._agent_identity, source, user_id, session_id
                )
                messages = []
                for message in raw_messages:
                    if not isinstance(message, dict):
                        continue
                    role = message.get("role")
                    if role not in {"user", "assistant"}:
                        continue
                    content = sanitize_context(_content_text(message.get("content")))
                    content = redact_sensitive_text(content, force=True).strip()
                    if not content:
                        continue
                    messages.extend(
                        split_message(
                            role,
                            content,
                            timestamp=_timestamp(message.get("timestamp")),
                        )
                    )
                if not messages:
                    stats.skipped += 1
                    _reject(stats, row_hash, "ingest", "no_text_messages")
                    continue
                for index, batch in enumerate(
                    batched(messages, MAX_INGEST_MESSAGES), start=1
                ):
                    operations.append(
                        {
                            "kind": "ingest",
                            "source_hash": _source_hash(
                                "session", raw_session_id, index, json.dumps(batch, sort_keys=True)
                            ),
                            "profile": profile,
                            "session_id": session_id,
                            "content": None,
                            "messages": batch,
                        }
                    )
                stats.sessions += 1
                stats.messages += len(messages)
            except (
                json.JSONDecodeError,
                UnicodeDecodeError,
                TypeError,
                ValueError,
                OverflowError,
            ):
                _reject(stats, row_hash, "ingest", "invalid_session_row")
    return operations


def plan_migration(
    provider: CloudflareAgentMemoryProvider, sessions_jsonl: Path | None
) -> tuple[list[dict], MigrationStats]:
    if not provider._client:
        raise ValueError("Cloudflare Agent Memory is not configured")
    stats = MigrationStats()
    operations = _curated_operations(provider, stats)
    if sessions_jsonl is not None:
        operations.extend(_session_operations(provider, Path(sessions_jsonl), stats))
    stats.planned = len(operations)
    return operations, stats


def _session_exists(provider: CloudflareAgentMemoryProvider, operation: dict) -> bool:
    cursor = ""
    while True:
        try:
            page = provider._client.list_memories(
                operation["profile"],
                session_id=operation["session_id"],
                cursor=cursor,
            )
        except CloudflareMemoryError as exc:
            if exc.status != 404:
                raise
            provider._client.get_namespace()
            return False
        if page.get("result"):
            return True
        info = page.get("result_info") or {}
        cursor = str(info.get("cursor") or "")
        if not cursor:
            return False


def _append_report(path: Path, record: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = (json.dumps(record, sort_keys=True) + "\n").encode()
    fd = os.open(path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
    try:
        os.fchmod(fd, 0o600)
        view = memoryview(encoded)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)


def _write_report(path: Path, record: dict) -> None:
    try:
        _append_report(path, record)
    except OSError as exc:
        reason = exc.strerror or exc.__class__.__name__
        raise MigrationReportError(f"migration report unavailable: {reason}") from None


def _report_record(
    operation: dict,
    *,
    status: str,
    error_code: str = "",
) -> dict:
    return {
        "source_hash": operation.get("source_hash", ""),
        "kind": operation.get("kind", ""),
        "profile": operation.get("profile", ""),
        "session_id": operation.get("session_id", ""),
        "message_count": len(operation.get("messages") or []),
        "status": status,
        "error_code": error_code,
    }


def _ingest_operation(
    provider: CloudflareAgentMemoryProvider, operation: dict
) -> None:
    with provider._remote_session_lock:
        with provider._cross_process_remote_lock():
            provider._refresh_delete_state()
            key = (
                provider._client.destination_id,
                operation["profile"],
                operation["session_id"],
            )
            with provider._pending_delete_lock:
                delete_pending = key in provider._pending_session_deletes
            if delete_pending and not provider._delete_session_or_defer_locked(
                operation["profile"],
                operation["session_id"],
                require_pending=True,
            ):
                raise CloudflareMemoryError(
                    "pending rewind deletion could not be completed"
                )
            provider._client.ingest(
                operation["profile"],
                operation["messages"],
                operation["session_id"],
            )


def apply_migration(
    provider: CloudflareAgentMemoryProvider,
    operations: list[dict],
    report_path: Path,
    *,
    rejections: list[dict[str, str]] | None = None,
) -> MigrationStats:
    from . import _update_curated_manifest

    if not provider._client:
        raise ValueError("Cloudflare Agent Memory is not configured")
    stats = MigrationStats(planned=len(operations))
    for rejection in rejections or []:
        _write_report(
            Path(report_path),
            {
                "source_hash": rejection["source_hash"],
                "kind": rejection["kind"],
                "profile": "",
                "session_id": "",
                "message_count": 0,
                "status": "rejected",
                "error_code": rejection["reason"],
            },
        )
    for operation in operations:
        _write_report(
            Path(report_path), _report_record(operation, status="planned")
        )
    blocked_ingest_sessions: set[tuple[str, str]] = set()
    for operation in operations:
        status = "failed"
        error_code = ""
        kind = operation.get("kind")
        ingest_key = (operation.get("profile", ""), operation.get("session_id", ""))
        if kind == "ingest" and ingest_key in blocked_ingest_sessions:
            stats.failed += 1
            _write_report(
                Path(report_path),
                _report_record(
                    operation,
                    status="failed",
                    error_code="prior_batch_failed",
                ),
            )
            continue
        try:
            if kind == "remember":
                if _session_exists(provider, operation):
                    status = "skipped"
                    stats.skipped += 1
                else:
                    provider._client.remember(
                        operation["profile"],
                        operation["content"],
                        operation["session_id"],
                    )
                    status = "applied"
                    stats.applied += 1
                _update_curated_manifest(
                    provider._hermes_home,
                    add=(
                        provider._client.destination_id,
                        operation["profile"],
                        operation["target"],
                        operation["source_hash"],
                        operation["session_id"],
                    ),
                )
            elif kind == "delete":
                try:
                    provider._client.delete_session(
                        operation["profile"], operation["session_id"]
                    )
                except CloudflareMemoryError as exc:
                    if exc.status != 404:
                        raise
                    provider._client.get_namespace()
                _update_curated_manifest(
                    provider._hermes_home,
                    remove_session=(
                        provider._client.destination_id,
                        operation["profile"],
                        operation["session_id"],
                    ),
                )
                status = "applied"
                stats.applied += 1
            elif kind == "ingest":
                _ingest_operation(provider, operation)
                status = "applied"
                stats.applied += 1
                stats.messages += len(operation.get("messages") or [])
            else:
                raise ValueError("unknown migration operation")
        except (CloudflareMemoryError, OSError, ValueError) as exc:
            stats.failed += 1
            if kind == "ingest":
                blocked_ingest_sessions.add(ingest_key)
            if isinstance(exc, CloudflareMemoryError) and exc.codes:
                error_code = exc.codes[0]
            else:
                error_code = exc.__class__.__name__
        _write_report(
            Path(report_path),
            _report_record(operation, status=status, error_code=error_code),
        )
    return stats
