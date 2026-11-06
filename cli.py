"""Hermes CLI commands for Cloudflare Agent Memory."""

from __future__ import annotations

import json
import os
import sys
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .client import CloudflareMemoryError

if TYPE_CHECKING:
    from . import CloudflareAgentMemoryProvider


def _load_provider() -> Any:
    from hermes_cli.profiles import get_active_profile_name
    from hermes_constants import get_hermes_home
    from plugins.memory import load_memory_provider

    provider = load_memory_provider("cloudflare-agent-memory")
    if provider is None:
        raise RuntimeError("cloudflare-agent-memory provider is not installed")
    provider.initialize(
        "cloudflare-memory-cli",
        hermes_home=str(get_hermes_home()),
        platform="cli",
        agent_context="flush",
        agent_identity=get_active_profile_name(),
        user_id="",
    )
    return provider


def _memory_count(provider: CloudflareAgentMemoryProvider) -> int:
    count = 0
    cursor = ""
    seen_cursors = set()
    while True:
        try:
            page = provider._client.list_memories(provider._profile, cursor=cursor)
        except CloudflareMemoryError as exc:
            if exc.status == 404:
                provider._client.get_namespace()
                return 0
            raise
        count += len(page.get("result") or [])
        cursor = str((page.get("result_info") or {}).get("cursor") or "")
        if not cursor:
            return count
        if cursor in seen_cursors:
            raise ValueError("memory list returned a repeated cursor")
        seen_cursors.add(cursor)


def _export_memories(
    provider: CloudflareAgentMemoryProvider,
    profiles: list[str],
    output: Path,
) -> int:
    if output.exists():
        raise ValueError(f"output already exists: {output}")
    profiles = list(dict.fromkeys(profiles))
    temporary: Path | None = None
    count = 0
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=output.parent,
            prefix=f".{output.name}.",
            delete=False,
        ) as stream:
            temporary = Path(stream.name)

            def write(row: dict) -> None:
                stream.write(
                    json.dumps(
                        row,
                        ensure_ascii=False,
                        separators=(",", ":"),
                        sort_keys=True,
                    )
                    + "\n"
                )

            write(
                {
                    "format": "cloudflare-agent-memory-export",
                    "version": 1,
                    "namespace": provider._client.namespace,
                    "profiles": profiles,
                }
            )
            for profile in profiles:
                cursor = ""
                seen_cursors = set()
                while True:
                    page = provider._client.list_memories(profile, cursor=cursor)
                    memories = page.get("result")
                    if not isinstance(memories, list):
                        raise ValueError("invalid memory list response")
                    for item in memories:
                        memory_id = item.get("id") if isinstance(item, dict) else None
                        if not isinstance(memory_id, str) or not memory_id:
                            raise ValueError("memory list entry has no ID")
                        memory = provider._client.get_memory(profile, memory_id)
                        if not memory:
                            raise ValueError(f"memory is empty: {memory_id}")
                        if memory.get("id") != memory_id:
                            raise ValueError(
                                f"memory response ID does not match: {memory_id}"
                            )
                        if not isinstance(memory.get("content"), str):
                            raise ValueError(f"memory response has no full content: {memory_id}")
                        write({"profile": profile, "memory": memory})
                        count += 1
                    cursor = str((page.get("result_info") or {}).get("cursor") or "")
                    if not cursor:
                        break
                    if cursor in seen_cursors:
                        raise ValueError("memory list returned a repeated cursor")
                    seen_cursors.add(cursor)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, output)
        except FileExistsError:
            raise ValueError(f"output already exists: {output}") from None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return count


def cloudflare_memory_command(args) -> int:
    try:
        provider = _load_provider()
    except (RuntimeError, ValueError) as exc:
        print(f"Cloudflare Agent Memory: {exc}", file=sys.stderr)
        return 1
    provider._write_enabled = False
    try:
        if args.cloudflare_memory_command == "status":
            if not provider._client:
                raise ValueError("provider is not configured")
            namespace = provider._client.get_namespace()
            count = _memory_count(provider)
            print(
                f"Connected: namespace={namespace.get('name') or provider._client.namespace} "
                f"profile={provider._profile} memories={count}"
            )
            return 0
        if args.cloudflare_memory_command == "migrate":
            from .migration import apply_migration, plan_migration

            if not provider._client:
                raise ValueError("provider is not configured")
            operations, planning = plan_migration(provider, args.sessions_jsonl)
            if not args.apply:
                print(
                    "DRY RUN: "
                    f"planned={planning.planned} curated={planning.curated} "
                    f"sessions={planning.sessions} messages={planning.messages} "
                    f"skipped={planning.skipped} errors={planning.planning_errors}"
                )
                for rejection in planning.rejections:
                    print(
                        "rejected "
                        f"source_hash={rejection['source_hash']} "
                        f"kind={rejection['kind']} reason={rejection['reason']}"
                    )
                profile_counts = Counter(
                    operation["profile"] for operation in operations
                )
                for profile, count in sorted(profile_counts.items()):
                    print(f"profile={profile} planned={count}")
                return 1 if planning.planning_errors else 0
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
            report = (
                Path(provider._hermes_home)
                / "cloudflare-agent-memory-migrations"
                / f"migration-{timestamp}.jsonl"
            )
            applied = apply_migration(
                provider,
                operations,
                report,
                rejections=planning.rejections,
            )
            print(
                "APPLY: "
                f"applied={applied.applied} skipped={applied.skipped} "
                f"failed={applied.failed} report={report}"
            )
            return 1 if planning.planning_errors or applied.failed else 0
        if args.cloudflare_memory_command == "export":
            if not provider._client:
                raise ValueError("provider is not configured")
            profiles = args.profile or [provider._profile]
            count = _export_memories(provider, profiles, args.output)
            print(f"Exported {count} memories to {args.output}")
            return 0
        print("Choose status, migrate, or export.", file=sys.stderr)
        return 1
    except (CloudflareMemoryError, OSError, RuntimeError, ValueError) as exc:
        print(f"Cloudflare Agent Memory: {exc}", file=sys.stderr)
        return 1
    finally:
        provider.shutdown()


def register_cli(subparser) -> None:
    commands = subparser.add_subparsers(dest="cloudflare_memory_command")
    commands.add_parser(
        "status", help="Check Cloudflare Agent Memory configuration and connectivity"
    )
    migrate = commands.add_parser(
        "migrate", help="Copy Hermes memory into Cloudflare Agent Memory"
    )
    mode = migrate.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--apply", action="store_true")
    migrate.add_argument("--sessions-jsonl", type=Path)
    export = commands.add_parser(
        "export", help="Export full Cloudflare memories to JSONL"
    )
    export.add_argument("--output", type=Path, required=True)
    export.add_argument(
        "--profile",
        action="append",
        help="Export this opaque profile name; repeat for more profiles",
    )
    subparser.set_defaults(func=cloudflare_memory_command)
