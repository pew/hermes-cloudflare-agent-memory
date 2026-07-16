"""Hermes CLI commands for Cloudflare Agent Memory."""

from __future__ import annotations

import sys
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
        print("Choose status or migrate.", file=sys.stderr)
        return 1
    except (CloudflareMemoryError, RuntimeError, ValueError) as exc:
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
    subparser.set_defaults(func=cloudflare_memory_command)
