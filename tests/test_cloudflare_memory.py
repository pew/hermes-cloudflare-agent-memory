from __future__ import annotations

import argparse
import contextlib
import importlib
import json
import importlib.util
import io
import os
import shutil
import stat
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from client import (
    MAX_MESSAGE_BYTES,
    CloudflareMemoryClient,
    CloudflareMemoryError,
    normalize_session_id,
    split_message,
)

ROOT = Path(__file__).resolve().parents[1]


def _load_provider_module():
    module_name = "_cloudflare_agent_memory_test_plugin"
    existing = sys.modules.get(module_name)
    if existing is not None:
        return existing
    spec = importlib.util.spec_from_file_location(
        module_name,
        ROOT / "__init__.py",
        submodule_search_locations=[str(ROOT)],
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load provider module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


class _ApiServer:
    def __init__(self) -> None:
        self.requests: list[dict] = []
        self.responses: list[tuple[int, object, str]] = []
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                self._handle()

            def do_POST(self) -> None:
                self._handle()

            def do_DELETE(self) -> None:
                self._handle()

            def _handle(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(length) if length else b""
                owner.requests.append(
                    {
                        "method": self.command,
                        "path": self.path,
                        "headers": dict(self.headers),
                        "body": json.loads(raw) if raw else None,
                    }
                )
                if owner.responses:
                    status, body, content_type = owner.responses.pop(0)
                elif self.command == "GET" and "/memories?" in self.path:
                    status = 200
                    body = {
                        "success": True,
                        "result": [],
                        "result_info": {"cursor": ""},
                        "errors": [],
                        "messages": [],
                    }
                    content_type = "application/json"
                else:
                    status = 200
                    body = {
                        "success": True,
                        "result": {"answer": "stored fact", "count": 1},
                        "errors": [],
                        "messages": [],
                    }
                    content_type = "application/json"
                encoded = body if isinstance(body, bytes) else json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)

            def log_message(self, _format: str, *_args: object) -> None:
                return

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    @property
    def api_base(self) -> str:
        host, port = self.httpd.server_address
        return f"http://{host}:{port}/client/v4"

    def start(self) -> None:
        self.thread.start()

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)

    def queue(self, status: int, body: object, content_type: str = "application/json") -> None:
        self.responses.append((status, body, content_type))


class ClientContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.server = _ApiServer()
        self.server.start()
        self.auth_value = "fixture"
        self.client = CloudflareMemoryClient(
            "account",
            "namespace",
            self.auth_value,
            api_base=self.server.api_base,
        )

    def tearDown(self) -> None:
        self.server.close()

    def test_recall_encodes_path_and_unwraps_v4_result(self) -> None:
        result = self.client.recall("person/one", "What editor?")

        self.assertEqual({"answer": "stored fact", "count": 1}, result)
        request = self.server.requests[0]
        self.assertEqual("POST", request["method"])
        self.assertIn("/profiles/person%2Fone/recall", request["path"])
        self.assertEqual(
            {
                "query": "What editor?",
                "thinkingLevel": "low",
                "responseLength": "short",
            },
            request["body"],
        )

    def test_v4_error_omits_bearer_token(self) -> None:
        self.server.queue(
            401,
            {
                "success": False,
                "result": None,
                "errors": [{"code": 10000, "message": "Authentication failed"}],
                "messages": [],
            },
        )

        with self.assertRaises(CloudflareMemoryError) as raised:
            self.client.get_namespace()

        message = str(raised.exception)
        self.assertEqual(401, raised.exception.status)
        self.assertIn("HTTP 401", message)
        self.assertIn("10000", message)
        self.assertIn("Authentication failed", message)
        self.assertNotIn(self.auth_value, message)

    def test_non_json_response_is_typed_error(self) -> None:
        self.server.queue(502, b"<html>bad gateway</html>", "text/html")

        with self.assertRaises(CloudflareMemoryError) as raised:
            self.client.get_namespace()

        self.assertIn("invalid JSON response", str(raised.exception))

    def test_abrupt_transport_failure_is_typed_error(self) -> None:
        with patch("urllib.request.urlopen", side_effect=ConnectionResetError("reset")):
            with self.assertRaises(CloudflareMemoryError) as raised:
                self.client.get_namespace()

        self.assertIn("ConnectionResetError", str(raised.exception))
        self.assertNotIn(self.auth_value, str(raised.exception))

    def test_ingest_rejects_more_than_500_messages(self) -> None:
        with self.assertRaises(ValueError):
            self.client.ingest(
                "profile",
                [{"role": "user", "content": "x"}] * 501,
                "session",
            )

        self.assertEqual([], self.server.requests)

    def test_ingest_rejects_message_over_32768_utf8_bytes(self) -> None:
        with self.assertRaises(ValueError):
            self.client.ingest(
                "profile",
                [{"role": "user", "content": "€" * 10_923}],
                "session",
            )

        self.assertEqual([], self.server.requests)

    def test_recall_rejects_query_over_1024_utf8_bytes(self) -> None:
        with self.assertRaises(ValueError):
            self.client.recall("profile", "€" * 342)

        self.assertEqual([], self.server.requests)

    def test_profile_and_session_limits_are_enforced(self) -> None:
        with self.assertRaises(ValueError):
            self.client.recall("p" * 101, "query")
        with self.assertRaises(ValueError):
            self.client.ingest("profile", [], "s" * 65)

        self.assertEqual([], self.server.requests)

    def test_list_memories_passes_session_and_cursor_query(self) -> None:
        self.server.queue(
            200,
            {
                "success": True,
                "result": [],
                "result_info": {"cursor": ""},
                "errors": [],
                "messages": [],
            },
        )

        result = self.client.list_memories(
            "profile", session_id="session/one", cursor="next cursor"
        )

        self.assertEqual({"result": [], "result_info": {"cursor": ""}}, result)
        self.assertIn("per_page=500", self.server.requests[0]["path"])
        self.assertIn("session_id=session%2Fone", self.server.requests[0]["path"])
        self.assertIn("cursor=next+cursor", self.server.requests[0]["path"])

    def test_split_message_is_utf8_safe(self) -> None:
        content = "€" * 30_000

        chunks = split_message("user", content, timestamp="2026-07-16T12:00:00Z")

        reconstructed = chunks[0]["content"] + "".join(
            chunk["content"].removeprefix("[continued] ") for chunk in chunks[1:]
        )
        self.assertEqual(content, reconstructed)
        self.assertTrue(all(len(chunk["content"].encode()) <= MAX_MESSAGE_BYTES for chunk in chunks))
        self.assertTrue(all(chunk["role"] == "user" for chunk in chunks))
        self.assertTrue(all(chunk["timestamp"] == "2026-07-16T12:00:00Z" for chunk in chunks))

    def test_normalize_session_id_preserves_short_and_hashes_long(self) -> None:
        self.assertEqual("20260716_120000_abcdef", normalize_session_id("20260716_120000_abcdef"))

        first = normalize_session_id("session-" * 20)
        second = normalize_session_id("session-" * 20)
        self.assertEqual(first, second)
        self.assertEqual(55, len(first))
        self.assertRegex(first, r"^hermes-[0-9a-f]{48}$")


class ProviderContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.plugin = _load_provider_module()

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.home = Path(self.temp.name)
        self.server = _ApiServer()
        self.server.start()
        self.config = {"account_id": "account", "namespace": "namespace"}
        (self.home / "cloudflare-agent-memory.json").write_text(json.dumps(self.config))
        self.env = patch.dict(
            os.environ,
            {
                "HERMES_HOME": str(self.home),
                "CLOUDFLARE_AGENT_MEMORY_API_TOKEN": "fixture",
            },
            clear=False,
        )
        self.env.start()
        self.provider = self.plugin.CloudflareAgentMemoryProvider()
        self.provider.initialize(
            "session-one",
            hermes_home=str(self.home),
            agent_identity="coder",
            platform="telegram",
            user_id="42",
            agent_context="primary",
        )
        self.provider._client = self.plugin.CloudflareMemoryClient(
            "account", "namespace", "fixture", api_base=self.server.api_base
        )

    def tearDown(self) -> None:
        self.provider.shutdown()
        self.env.stop()
        self.server.close()
        self.temp.cleanup()

    def test_profile_name_is_stable_and_isolates_users_platforms_and_agents(self) -> None:
        derive = self.plugin.derived_profile_name
        baseline = derive("coder", "telegram", "42", "session")
        self.assertEqual(baseline, derive("coder", "telegram", "42", "session"))
        self.assertNotEqual(baseline, derive("coder", "telegram", "43", "session"))
        self.assertNotEqual(baseline, derive("coder", "discord", "42", "session"))
        self.assertNotEqual(baseline, derive("writer", "telegram", "42", "session"))
        self.assertLessEqual(len(baseline), 100)

    def test_unidentified_non_cli_subject_is_session_isolated(self) -> None:
        derive = self.plugin.derived_profile_name
        self.assertNotEqual(
            derive("coder", "telegram", "", "one"),
            derive("coder", "telegram", "", "two"),
        )
        self.assertEqual(
            derive("coder", "cli", "", "one"),
            derive("coder", "cli", "", "two"),
        )

    def test_is_available_makes_no_http_request(self) -> None:
        self.assertTrue(self.provider.is_available())
        self.assertEqual([], self.server.requests)

        for missing in ("account_id", "namespace"):
            config = dict(self.config)
            config.pop(missing)
            (self.home / "cloudflare-agent-memory.json").write_text(json.dumps(config))
            self.assertFalse(self.plugin.CloudflareAgentMemoryProvider().is_available())
        (self.home / "cloudflare-agent-memory.json").write_text(json.dumps(self.config))
        with patch.dict(os.environ, {"CLOUDFLARE_AGENT_MEMORY_API_TOKEN": ""}):
            self.assertFalse(self.plugin.CloudflareAgentMemoryProvider().is_available())
        self.assertEqual([], self.server.requests)

    def test_save_config_is_profile_scoped_and_mode_0600(self) -> None:
        other_home = self.home / "profile-home"

        self.provider.save_config(
            {"account_id": "acct", "namespace": "hermes-prod", "api_token": "x"},
            str(other_home),
        )

        path = other_home / "cloudflare-agent-memory.json"
        self.assertEqual(
            {"account_id": "acct", "namespace": "hermes-prod"},
            json.loads(path.read_text()),
        )
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_post_setup_prompts_and_writes_activation_config_and_secret(self) -> None:
        from hermes_cli.config import load_config

        with (
            patch(
                "hermes_cli.memory_setup._prompt",
                side_effect=["new-account", "hermes-prod", "fixture"],
            ),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.provider.post_setup(str(self.home), {})

        self.assertEqual(
            {"account_id": "new-account", "namespace": "hermes-prod"},
            json.loads((self.home / "cloudflare-agent-memory.json").read_text()),
        )
        self.assertEqual(
            "CLOUDFLARE_AGENT_MEMORY_API_TOKEN=fixture\n",
            (self.home / ".env").read_text(),
        )
        self.assertEqual(0o600, stat.S_IMODE((self.home / ".env").stat().st_mode))
        self.assertEqual(
            "cloudflare-agent-memory", load_config()["memory"]["provider"]
        )

    def test_initialize_uses_runtime_identity_not_tool_arguments(self) -> None:
        expected = self.plugin.derived_profile_name("coder", "telegram", "42", "session-one")
        self.assertEqual(expected, self.provider._profile)
        for schema in self.provider.get_tool_schemas():
            self.assertNotIn("profile", schema["parameters"]["properties"])

    def test_tool_schema_names_are_exact_and_unique(self) -> None:
        names = [schema["name"] for schema in self.provider.get_tool_schemas()]
        self.assertEqual(
            [
                "cloudflare_memory_recall",
                "cloudflare_memory_remember",
                "cloudflare_memory_forget",
                "cloudflare_memory_summary",
            ],
            names,
        )
        self.assertEqual(len(names), len(set(names)))

    def test_new_memories_are_routed_to_cloudflare(self) -> None:
        prompt = self.provider.system_prompt_block()
        remember = next(
            schema
            for schema in self.provider.get_tool_schemas()
            if schema["name"] == "cloudflare_memory_remember"
        )

        self.assertIn(
            "Always use cloudflare_memory_remember for new durable memory.",
            prompt,
        )
        self.assertIn(
            "Use Hermes' built-in memory tool only to edit existing curated memory.",
            prompt,
        )
        self.assertIn("primary save tool", remember["description"].lower())

    def test_recall_returns_answer_and_candidates(self) -> None:
        self.provider._profile = self.provider._curated_profile
        self.server.queue(
            200,
            {
                "success": True,
                "result": {
                    "answer": "You use Neovim",
                    "count": 1,
                    "candidates": [{"id": "mem-1", "summary": "Uses Neovim", "score": 0.9}],
                },
                "errors": [],
                "messages": [],
            },
        )

        result = json.loads(
            self.provider.handle_tool_call("cloudflare_memory_recall", {"query": "editor"})
        )

        self.assertEqual("## Runtime identity\nYou use Neovim", result["answer"])
        self.assertEqual(
            {"id": "mem-1", "summary": "Uses Neovim", "score": 0.9, "scope": "runtime"},
            result["candidates"][0],
        )

    def test_recall_combines_curated_and_runtime_profiles(self) -> None:
        self.server.queue(
            200,
            {
                "success": True,
                "result": {
                    "answer": "You prefer concise answers.",
                    "count": 2,
                    "candidates": [
                        {"id": "durable", "summary": "Concise", "score": 0.9},
                        {"id": "shared", "summary": "Shared", "score": 0.8},
                    ],
                },
                "errors": [],
                "messages": [],
            },
        )
        self.server.queue(
            200,
            {
                "success": True,
                "result": {
                    "answer": "This session uses Neovim.",
                    "count": 2,
                    "candidates": [
                        {"id": "session", "summary": "Neovim", "score": 0.95},
                        {"id": "shared", "summary": "Shared", "score": 0.7},
                    ],
                },
                "errors": [],
                "messages": [],
            },
        )

        result = json.loads(
            self.provider.handle_tool_call("cloudflare_memory_recall", {"query": "preferences"})
        )

        self.assertEqual(
            "## Durable memory\nYou prefer concise answers.\n\n"
            "## Runtime identity\nThis session uses Neovim.",
            result["answer"],
        )
        self.assertEqual(3, result["count"])
        self.assertEqual(
            [
                {"id": "durable", "summary": "Concise", "score": 0.9, "scope": "curated"},
                {"id": "shared", "summary": "Shared", "score": 0.8, "scope": "curated"},
                {"id": "session", "summary": "Neovim", "score": 0.95, "scope": "runtime"},
            ],
            result["candidates"],
        )
        self.assertIn(f"/profiles/{self.provider._curated_profile}/recall", self.server.requests[0]["path"])
        self.assertIn(f"/profiles/{self.provider._profile}/recall", self.server.requests[1]["path"])

    def test_recall_uses_curated_when_runtime_profile_is_missing(self) -> None:
        self.server.queue(
            200,
            {
                "success": True,
                "result": {"answer": "Durable fact", "count": 0, "candidates": []},
                "errors": [],
                "messages": [],
            },
        )
        self.server.queue(
            404,
            {
                "success": False,
                "result": None,
                "errors": [{"code": 10010, "message": "Profile not found"}],
                "messages": [],
            },
        )
        self.server.queue(
            200,
            {
                "success": True,
                "result": {"name": "namespace"},
                "errors": [],
                "messages": [],
            },
        )

        result = json.loads(
            self.provider.handle_tool_call("cloudflare_memory_recall", {"query": "fact"})
        )

        self.assertEqual("## Durable memory\nDurable fact", result["answer"])
        self.assertEqual(["POST", "POST", "GET"], [r["method"] for r in self.server.requests])

    def test_recall_uses_runtime_profile_when_curated_profile_is_missing(self) -> None:
        self.server.queue(
            404,
            {
                "success": False,
                "result": None,
                "errors": [{"code": 10010, "message": "Profile not found"}],
                "messages": [],
            },
        )
        self.server.queue(
            200,
            {
                "success": True,
                "result": {"name": "namespace"},
                "errors": [],
                "messages": [],
            },
        )
        self.server.queue(
            200,
            {
                "success": True,
                "result": {"answer": "Session fact", "count": 0, "candidates": []},
                "errors": [],
                "messages": [],
            },
        )

        result = json.loads(
            self.provider.handle_tool_call("cloudflare_memory_recall", {"query": "fact"})
        )

        self.assertEqual("## Runtime identity\nSession fact", result["answer"])
        self.assertEqual(["POST", "GET", "POST"], [r["method"] for r in self.server.requests])

    def test_identical_profiles_are_recalled_once(self) -> None:
        self.provider._profile = self.provider._curated_profile
        self.server.queue(
            200,
            {
                "success": True,
                "result": {
                    "answer": "One profile",
                    "count": 1,
                    "candidates": [{"id": "one", "summary": "One", "score": 1.0}],
                },
                "errors": [],
                "messages": [],
            },
        )

        result = json.loads(
            self.provider.handle_tool_call("cloudflare_memory_recall", {"query": "fact"})
        )

        self.assertEqual("## Runtime identity\nOne profile", result["answer"])
        self.assertEqual("runtime", result["candidates"][0]["scope"])
        self.assertEqual(1, len(self.server.requests))

    def test_recall_redacts_model_generated_query_before_http(self) -> None:
        sensitive_value = "ghp_" + "A" * 36

        self.provider.handle_tool_call(
            "cloudflare_memory_recall", {"query": f"Find {sensitive_value}"}
        )

        outbound = self.server.requests[0]["body"]["query"]
        self.assertNotIn(sensitive_value, outbound)
        self.assertNotEqual(f"Find {sensitive_value}", outbound)

    def test_remember_redacts_a_registered_secret(self) -> None:
        sensitive_value = "ghp_" + "A" * 36
        self.server.queue(
            200,
            {"success": True, "result": {"id": "mem-1"}, "errors": [], "messages": []},
        )

        result = json.loads(
            self.provider.handle_tool_call(
                "cloudflare_memory_remember", {"content": f"My token is {sensitive_value}"}
            )
        )

        self.assertEqual("mem-1", result["id"])
        outbound = self.server.requests[0]["body"]["content"]
        self.assertNotIn(sensitive_value, outbound)
        self.assertNotEqual(f"My token is {sensitive_value}", outbound)

    def test_forget_requires_exact_memory_id(self) -> None:
        missing = json.loads(
            self.provider.handle_tool_call("cloudflare_memory_forget", {})
        )
        self.assertIn("error", missing)
        self.assertEqual([], self.server.requests)
        unknown = json.loads(
            self.provider.handle_tool_call(
                "cloudflare_memory_forget", {"memory_id": "mem/one"}
            )
        )
        self.assertIn("error", unknown)
        self.assertEqual([], self.server.requests)
        self.server.queue(
            200,
            {
                "success": True,
                "result": {"answer": "", "count": 0, "candidates": []},
                "errors": [],
                "messages": [],
            },
        )
        self.server.queue(
            200,
            {
                "success": True,
                "result": {
                    "answer": "Uses Neovim",
                    "count": 1,
                    "candidates": [{"id": "mem/one", "summary": "Uses Neovim", "score": 0.9}],
                },
                "errors": [],
                "messages": [],
            },
        )
        self.provider.handle_tool_call("cloudflare_memory_recall", {"query": "editor"})
        self.server.queue(
            200,
            {"success": True, "result": {"id": "mem/one"}, "errors": [], "messages": []},
        )

        result = json.loads(
            self.provider.handle_tool_call(
                "cloudflare_memory_forget", {"memory_id": "mem/one"}
            )
        )

        self.assertEqual("mem/one", result["id"])
        self.assertEqual("DELETE", self.server.requests[-1]["method"])
        self.assertIn(f"/profiles/{self.provider._profile}/memories/mem%2Fone", self.server.requests[-1]["path"])

    def test_forget_rejects_recalled_curated_memory(self) -> None:
        self.server.queue(
            200,
            {
                "success": True,
                "result": {
                    "answer": "Durable",
                    "count": 1,
                    "candidates": [{"id": "durable", "summary": "Durable", "score": 1.0}],
                },
                "errors": [],
                "messages": [],
            },
        )
        self.server.queue(
            200,
            {
                "success": True,
                "result": {"answer": "", "count": 0, "candidates": []},
                "errors": [],
                "messages": [],
            },
        )
        self.provider.handle_tool_call("cloudflare_memory_recall", {"query": "durable"})
        request_count = len(self.server.requests)

        result = json.loads(
            self.provider.handle_tool_call(
                "cloudflare_memory_forget", {"memory_id": "durable"}
            )
        )

        self.assertIn("error", result)
        self.assertIn("Hermes memory", result["error"])
        self.assertEqual(request_count, len(self.server.requests))

    def test_latest_runtime_recall_replaces_stale_curated_authorization(self) -> None:
        recall_results = [
            [{"id": "shared", "summary": "Durable", "score": 1.0}],
            [],
            [],
            [{"id": "shared", "summary": "Runtime", "score": 1.0}],
        ]
        for candidates in recall_results:
            self.server.queue(
                200,
                {
                    "success": True,
                    "result": {
                        "answer": "",
                        "count": len(candidates),
                        "candidates": candidates,
                    },
                    "errors": [],
                    "messages": [],
                },
            )
        self.server.queue(
            200,
            {"success": True, "result": {"id": "shared"}, "errors": [], "messages": []},
        )

        self.provider.handle_tool_call("cloudflare_memory_recall", {"query": "first"})
        recalled = json.loads(
            self.provider.handle_tool_call("cloudflare_memory_recall", {"query": "second"})
        )
        forgotten = json.loads(
            self.provider.handle_tool_call(
                "cloudflare_memory_forget", {"memory_id": "shared"}
            )
        )

        self.assertEqual("runtime", recalled["candidates"][0]["scope"])
        self.assertTrue(forgotten["forgotten"])
        self.assertIn(
            f"/profiles/{self.provider._profile}/memories/shared",
            self.server.requests[-1]["path"],
        )

    def test_failed_combined_recall_does_not_authorize_partial_candidates(self) -> None:
        self.server.queue(
            200,
            {
                "success": True,
                "result": {
                    "answer": "Durable",
                    "count": 1,
                    "candidates": [{"id": "not-returned", "summary": "Durable", "score": 1.0}],
                },
                "errors": [],
                "messages": [],
            },
        )
        self.server.queue(
            500,
            {
                "success": False,
                "result": None,
                "errors": [{"code": 10001, "message": "temporary failure"}],
                "messages": [],
            },
        )
        recall = json.loads(
            self.provider.handle_tool_call("cloudflare_memory_recall", {"query": "durable"})
        )

        result = json.loads(
            self.provider.handle_tool_call(
                "cloudflare_memory_forget", {"memory_id": "not-returned"}
            )
        )

        self.assertIn("error", recall)
        self.assertIn("exact ID returned by recall", result["error"])

    def test_summary_returns_markdown(self) -> None:
        self.provider._profile = self.provider._curated_profile
        self.server.queue(
            200,
            {
                "success": True,
                "result": {"summary": "## Summary\n\nUses Neovim"},
                "errors": [],
                "messages": [],
            },
        )

        result = json.loads(
            self.provider.handle_tool_call("cloudflare_memory_summary", {})
        )

        self.assertEqual(
            "## Runtime identity memory\n## Summary\n\nUses Neovim",
            result["summary"],
        )

    def test_summary_combines_curated_and_runtime_profiles(self) -> None:
        for summary in ("Durable summary", "Session summary"):
            self.server.queue(
                200,
                {
                    "success": True,
                    "result": {"summary": summary},
                    "errors": [],
                    "messages": [],
                },
            )

        result = json.loads(
            self.provider.handle_tool_call("cloudflare_memory_summary", {})
        )

        self.assertEqual(
            "## Durable curated memory\nDurable summary\n\n"
            "## Runtime identity memory\nSession summary",
            result["summary"],
        )

    def test_summary_omits_a_missing_curated_profile(self) -> None:
        self.server.queue(
            404,
            {
                "success": False,
                "result": None,
                "errors": [{"code": 10010, "message": "Profile not found"}],
                "messages": [],
            },
        )
        self.server.queue(
            200,
            {
                "success": True,
                "result": {"name": "namespace"},
                "errors": [],
                "messages": [],
            },
        )
        self.server.queue(
            200,
            {
                "success": True,
                "result": {"summary": "Session summary"},
                "errors": [],
                "messages": [],
            },
        )

        result = json.loads(
            self.provider.handle_tool_call("cloudflare_memory_summary", {})
        )

        self.assertEqual("## Runtime identity memory\nSession summary", result["summary"])

    def test_recall_and_summary_are_empty_when_profile_does_not_exist(self) -> None:
        self.provider._profile = self.provider._curated_profile
        missing = {
            "success": False,
            "result": None,
            "errors": [{"code": 10010, "message": "Profile not found"}],
            "messages": [],
        }
        namespace = {
            "success": True,
            "result": {"name": "namespace"},
            "errors": [],
            "messages": [],
        }
        self.server.queue(404, missing)
        self.server.queue(200, namespace)
        self.server.queue(404, missing)
        self.server.queue(200, namespace)

        recall = json.loads(
            self.provider.handle_tool_call(
                "cloudflare_memory_recall", {"query": "anything"}
            )
        )
        summary = json.loads(
            self.provider.handle_tool_call("cloudflare_memory_summary", {})
        )

        self.assertEqual({"answer": "", "count": 0, "candidates": []}, recall)
        self.assertEqual({"summary": ""}, summary)

    def test_cloudflare_error_becomes_json_tool_error(self) -> None:
        self.server.queue(
            500,
            {
                "success": False,
                "result": None,
                "errors": [{"code": 10001, "message": "temporary failure"}],
                "messages": [],
            },
        )

        result = json.loads(
            self.provider.handle_tool_call("cloudflare_memory_recall", {"query": "editor"})
        )

        self.assertIn("error", result)
        self.assertIn("10001", result["error"])

    def test_prefetch_is_empty_and_does_not_call_http(self) -> None:
        self.assertEqual("", self.provider.prefetch("editor"))
        self.assertEqual([], self.server.requests)

    def test_current_hermes_discovers_and_routes_provider(self) -> None:
        plugin_dir = self.home / "plugins" / "cloudflare-agent-memory"
        plugin_dir.mkdir(parents=True)
        for name in ("__init__.py", "client.py", "plugin.yaml"):
            shutil.copy2(ROOT / name, plugin_dir / name)

        from agent.memory_manager import MemoryManager
        from plugins.memory import discover_memory_providers, load_memory_provider

        discovered = {name for name, _description, _available in discover_memory_providers()}
        loaded = load_memory_provider("cloudflare-agent-memory")
        self.assertIn("cloudflare-agent-memory", discovered)
        self.assertIsNotNone(loaded)
        manager = MemoryManager()
        manager.add_provider(loaded)
        self.assertIn(loaded, manager.providers)
        self.assertEqual(
            {
                "cloudflare_memory_recall",
                "cloudflare_memory_remember",
                "cloudflare_memory_forget",
                "cloudflare_memory_summary",
            },
            manager.get_all_tool_names(),
        )


class ProviderLifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.plugin = _load_provider_module()

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.home = Path(self.temp.name)
        self.server = _ApiServer()
        self.server.start()
        (self.home / "cloudflare-agent-memory.json").write_text(
            json.dumps({"account_id": "account", "namespace": "namespace"})
        )
        self.env = patch.dict(
            os.environ,
            {
                "HERMES_HOME": str(self.home),
                "CLOUDFLARE_AGENT_MEMORY_API_TOKEN": "fixture",
            },
            clear=False,
        )
        self.env.start()
        self.provider = self.plugin.CloudflareAgentMemoryProvider()
        self.provider.initialize(
            "session-one",
            hermes_home=str(self.home),
            agent_identity="coder",
            platform="telegram",
            user_id="42",
            agent_context="primary",
        )
        self.provider._client = self.plugin.CloudflareMemoryClient(
            "account", "namespace", "fixture", api_base=self.server.api_base
        )

    def tearDown(self) -> None:
        self.provider.shutdown()
        self.env.stop()
        self.server.close()
        self.temp.cleanup()

    def _wait_for_requests(self, count: int, timeout: float = 2.0) -> None:
        deadline = time.monotonic() + timeout
        while len(self.server.requests) < count and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertGreaterEqual(len(self.server.requests), count)

    def _wait_for_writes(self, timeout: float = 2.0) -> None:
        deadline = time.monotonic() + timeout
        while self.provider._write_queue.unfinished_tasks and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertEqual(0, self.provider._write_queue.unfinished_tasks)

    def _write_entries(self, target: str, entries: list[str]) -> None:
        memory_dir = self.home / "memories"
        memory_dir.mkdir(parents=True, exist_ok=True)
        filename = "USER.md" if target == "user" else "MEMORY.md"
        (memory_dir / filename).write_text("\n§\n".join(entries), encoding="utf-8")

    def _rebuild_provider(
        self, *, memory_entries: list[str] | None = None, user_entries: list[str] | None = None
    ) -> None:
        self.provider.shutdown()
        self._write_entries("memory", memory_entries or [])
        self._write_entries("user", user_entries or [])
        self.server.requests.clear()
        self.server.responses.clear()
        self.provider = self.plugin.CloudflareAgentMemoryProvider()
        self.provider.initialize(
            "session-one",
            hermes_home=str(self.home),
            agent_identity="coder",
            platform="telegram",
            user_id="42",
            agent_context="primary",
        )
        self.provider._client = self.plugin.CloudflareMemoryClient(
            "account", "namespace", "fixture", api_base=self.server.api_base
        )

    def test_sync_turn_buffers_user_then_assistant_without_http(self) -> None:
        self.provider.sync_turn("question", "answer", session_id="session-one")

        self.assertEqual(
            [
                {"role": "user", "content": "question"},
                {"role": "assistant", "content": "answer"},
            ],
            self.provider._buffers["session-one"],
        )
        self.assertEqual([], self.server.requests)

    def test_capture_strips_memory_context_and_excludes_tool_messages(self) -> None:
        self.provider.sync_turn(
            "<memory-context>private recalled fixture</memory-context>\nReal question",
            "Real answer",
            session_id="session-one",
            messages=[
                {"role": "system", "content": "system fixture"},
                {"role": "tool", "content": "tool fixture"},
            ],
        )
        self.provider.on_session_end([])

        body = self.server.requests[0]["body"]
        serialized = json.dumps(body)
        self.assertEqual(["user", "assistant"], [item["role"] for item in body["messages"]])
        self.assertIn("Real question", serialized)
        self.assertNotIn("private recalled fixture", serialized)
        self.assertNotIn("system fixture", serialized)
        self.assertNotIn("tool fixture", serialized)

    def test_500_message_ceiling_flushes_in_order(self) -> None:
        for index in range(250):
            self.provider.sync_turn(
                f"user-{index}", f"assistant-{index}", session_id="session-one"
            )

        self.assertEqual(1, len(self.server.requests))
        messages = self.server.requests[0]["body"]["messages"]
        self.assertEqual(500, len(messages))
        self.assertEqual("user-0", messages[0]["content"])
        self.assertEqual("assistant-249", messages[-1]["content"])
        self.assertNotIn("session-one", self.provider._buffers)

    def test_session_end_flushes_and_clears_successful_batch(self) -> None:
        self.provider.sync_turn("question", "answer", session_id="session-one")

        self.provider.on_session_end([])

        self.assertEqual(1, len(self.server.requests))
        self.assertNotIn("session-one", self.provider._buffers)

    def test_failed_flush_retains_messages_for_replay(self) -> None:
        self.server.queue(
            500,
            {
                "success": False,
                "result": None,
                "errors": [{"code": 10001, "message": "temporary failure"}],
                "messages": [],
            },
        )
        self.provider.sync_turn("question", "answer", session_id="session-one")

        self.provider.on_session_end([])
        self.assertEqual(2, len(self.provider._buffers["session-one"]))
        self.provider.on_session_end([])

        self.assertEqual(2, len(self.server.requests))
        self.assertEqual(
            self.server.requests[0]["body"]["messages"],
            self.server.requests[1]["body"]["messages"],
        )
        self.assertNotIn("session-one", self.provider._buffers)

    def test_pre_compress_flushes_before_return(self) -> None:
        self.provider.sync_turn("question", "answer", session_id="session-one")

        result = self.provider.on_pre_compress([])

        self.assertEqual("", result)
        self.assertEqual(1, len(self.server.requests))

    def test_session_switch_does_not_mix_old_and_new_buffers(self) -> None:
        self.provider.sync_turn("old question", "old answer", session_id="session-one")

        self.provider.on_session_switch("session-two")
        self.provider.sync_turn("new question", "new answer", session_id="session-two")
        self.provider.on_session_end([])

        self.assertEqual(2, len(self.server.requests))
        self.assertEqual("session-one", self.server.requests[0]["body"]["sessionId"])
        self.assertEqual("session-two", self.server.requests[1]["body"]["sessionId"])
        self.assertEqual(
            ["old question", "old answer"],
            [item["content"] for item in self.server.requests[0]["body"]["messages"]],
        )
        self.assertEqual(
            ["new question", "new answer"],
            [item["content"] for item in self.server.requests[1]["body"]["messages"]],
        )

    def test_unidentified_session_switch_rederives_profile(self) -> None:
        provider = self.plugin.CloudflareAgentMemoryProvider()
        provider.initialize(
            "anonymous-one",
            hermes_home=str(self.home),
            agent_identity="coder",
            platform="telegram",
            user_id="",
            agent_context="primary",
        )
        provider._client = self.plugin.CloudflareMemoryClient(
            "account", "namespace", "fixture", api_base=self.server.api_base
        )
        first_profile = provider._profile

        provider.on_session_switch("anonymous-two")

        self.assertNotEqual(first_profile, provider._profile)
        self.assertEqual(
            self.plugin.derived_profile_name(
                "coder", "telegram", "", "anonymous-two"
            ),
            provider._profile,
        )
        provider.shutdown()

    def test_rewind_clears_pending_buffer_and_deletes_remote_session(self) -> None:
        self.provider.sync_turn("undo this", "old answer", session_id="session-one")

        self.provider.on_session_switch("session-one", rewound=True)

        self.assertNotIn("session-one", self.provider._buffers)
        self.assertEqual(1, len(self.server.requests))
        self.assertEqual("DELETE", self.server.requests[0]["method"])
        self.assertIn("/sessions/session-one", self.server.requests[0]["path"])

    def test_rewind_waits_for_inflight_ingest_before_deleting_session(self) -> None:
        ingest_started = threading.Event()
        release_ingest = threading.Event()
        operations: list[str] = []

        class BlockingClient:
            destination_id = "0" * 64

            def ingest(self, profile: str, messages: list[dict], session_id: str) -> None:
                operations.append("ingest-start")
                ingest_started.set()
                release_ingest.wait(2)
                operations.append("ingest-end")

            def delete_session(self, profile: str, session_id: str) -> None:
                operations.append("delete")

        self.provider._client = BlockingClient()
        self.provider.sync_turn("undo this", "old answer", session_id="session-one")
        flush = threading.Thread(target=self.provider.on_session_end, args=([],))
        flush.start()
        self.assertTrue(ingest_started.wait(1))

        rewind = threading.Thread(
            target=self.provider.on_session_switch,
            args=("session-one",),
            kwargs={"rewound": True},
        )
        rewind.start()
        time.sleep(0.05)
        self.assertNotIn("delete", operations)
        release_ingest.set()
        flush.join(1)
        rewind.join(1)

        self.assertFalse(flush.is_alive())
        self.assertFalse(rewind.is_alive())
        self.assertEqual(["ingest-start", "ingest-end", "delete"], operations)
        self.assertNotIn("session-one", self.provider._buffers)

    def test_rewind_waits_for_inflight_turn_capture_before_clearing_buffer(self) -> None:
        capture_started = threading.Event()
        release_capture = threading.Event()
        original_sanitize = self.plugin.sanitize_context

        def blocking_sanitize(value: str) -> str:
            capture_started.set()
            release_capture.wait(2)
            return original_sanitize(value)

        with patch.object(self.plugin, "sanitize_context", side_effect=blocking_sanitize):
            capture = threading.Thread(
                target=self.provider.sync_turn,
                args=("undo this", "old answer"),
                kwargs={"session_id": "session-one"},
            )
            capture.start()
            self.assertTrue(capture_started.wait(1))
            rewind = threading.Thread(
                target=self.provider.on_session_switch,
                args=("session-one",),
                kwargs={"rewound": True},
            )
            rewind.start()
            time.sleep(0.05)
            release_capture.set()
            capture.join(1)
            rewind.join(1)

        self.assertFalse(capture.is_alive())
        self.assertFalse(rewind.is_alive())
        self.assertNotIn("session-one", self.provider._buffers)
        self.assertEqual(["DELETE"], [request["method"] for request in self.server.requests])

    def test_rewind_still_clears_and_deletes_when_generation_write_fails(self) -> None:
        self.provider.sync_turn("undo this", "old answer", session_id="session-one")

        with patch.object(
            self.plugin, "_persist_delete_state", side_effect=OSError("disk full")
        ):
            self.provider.on_session_switch("session-one", rewound=True)

        self.assertNotIn("session-one", self.provider._buffers)
        self.assertEqual(["DELETE"], [request["method"] for request in self.server.requests])

    def test_failed_rewind_delete_retries_before_new_session_ingest(self) -> None:
        self.server.queue(
            500,
            {
                "success": False,
                "result": None,
                "errors": [{"code": 10001, "message": "temporary failure"}],
                "messages": [],
            },
        )
        self.provider.sync_turn("undo this", "old answer", session_id="session-one")
        self.provider.on_session_switch("session-one", rewound=True)
        self.assertTrue(self.provider._pending_session_deletes)
        pending_path = self.home / "cloudflare-agent-memory-pending.json"
        self.assertTrue(pending_path.exists())
        self.assertEqual(0o600, stat.S_IMODE(pending_path.stat().st_mode))

        self.provider.sync_turn("replacement", "new answer", session_id="session-one")

        self.assertFalse(self.provider._pending_session_deletes)
        self.assertEqual(["DELETE", "DELETE"], [r["method"] for r in self.server.requests])
        self.assertEqual(2, len(self.provider._buffers["session-one"]))

    def test_memory_tools_are_blocked_while_rewind_delete_is_pending(self) -> None:
        self.server.queue(
            500,
            {
                "success": False,
                "result": None,
                "errors": [{"code": 10001, "message": "temporary failure"}],
                "messages": [],
            },
        )
        self.provider.on_session_switch("session-one", rewound=True)
        request_count = len(self.server.requests)

        result = json.loads(
            self.provider.handle_tool_call(
                "cloudflare_memory_recall", {"query": "undone content"}
            )
        )

        self.assertIn("error", result)
        self.assertIn("pending rewind deletion", result["error"])
        self.assertEqual(request_count, len(self.server.requests))

    def test_profile_reads_are_blocked_by_pending_delete_from_older_session(self) -> None:
        pending = (
            self.provider._client.destination_id,
            self.provider._profile,
            "older-session",
        )
        self.provider._update_pending_delete(add=pending)

        result = json.loads(
            self.provider.handle_tool_call(
                "cloudflare_memory_recall", {"query": "removed content"}
            )
        )

        self.assertIn("error", result)
        self.assertEqual([], self.server.requests)

    def test_rewind_missing_profile_is_already_deleted(self) -> None:
        self.server.queue(
            404,
            {
                "success": False,
                "result": None,
                "errors": [{"code": 10010, "message": "Profile not found"}],
                "messages": [],
            },
        )
        self.server.queue(
            200,
            {
                "success": True,
                "result": {"name": "namespace"},
                "errors": [],
                "messages": [],
            },
        )

        self.provider.on_session_switch("session-one", rewound=True)

        self.assertFalse(self.provider._pending_session_deletes)
        self.assertEqual(["DELETE", "GET"], [r["method"] for r in self.server.requests])

    def test_pending_delete_is_not_replayed_into_new_destination(self) -> None:
        self.server.queue(
            500,
            {
                "success": False,
                "result": None,
                "errors": [{"code": 10001, "message": "temporary failure"}],
                "messages": [],
            },
        )
        self.provider.on_session_switch("session-one", rewound=True)
        request_count = len(self.server.requests)
        self.provider._client = self.plugin.CloudflareMemoryClient(
            "other-account", "other-namespace", "fixture", api_base=self.server.api_base
        )

        self.provider._retry_pending_session_deletes()

        self.assertEqual(request_count, len(self.server.requests))
        rows = json.loads(
            (self.home / "cloudflare-agent-memory-pending.json").read_text()
        )["session_deletes"]
        self.assertTrue(rows[0]["destination_id"])

    def test_pending_delete_persistence_merges_stale_process_updates(self) -> None:
        first = (
            self.provider._client.destination_id,
            self.provider._profile,
            "session-one",
        )
        self.provider._update_pending_delete(add=first)
        other = self.plugin.CloudflareAgentMemoryProvider()
        other.initialize(
            "session-two",
            hermes_home=str(self.home),
            agent_identity="coder",
            platform="telegram",
            user_id="42",
            agent_context="flush",
        )
        second = (
            other._client.destination_id,
            other._profile,
            "session-two",
        )

        other._update_pending_delete(add=second)

        rows = json.loads(
            (self.home / "cloudflare-agent-memory-pending.json").read_text()
        )["session_deletes"]
        self.assertEqual(2, len(rows))
        other.shutdown()

    def test_cross_process_rewind_generation_discards_stale_buffer(self) -> None:
        other = self.plugin.CloudflareAgentMemoryProvider()
        other.initialize(
            "session-one",
            hermes_home=str(self.home),
            agent_identity="coder",
            platform="telegram",
            user_id="42",
            agent_context="primary",
        )
        other._client = self.plugin.CloudflareMemoryClient(
            "account", "namespace", "fixture", api_base=self.server.api_base
        )
        other.sync_turn("stale question", "stale answer", session_id="session-one")

        self.provider.on_session_switch("session-one", rewound=True)
        other.on_session_end([])

        self.assertEqual(["DELETE"], [request["method"] for request in self.server.requests])
        self.assertNotIn("session-one", other._buffers)
        other.shutdown()

    def test_cross_process_readd_cancels_stale_process_delete_snapshot(self) -> None:
        other = self.plugin.CloudflareAgentMemoryProvider()
        other.initialize(
            "session-two",
            hermes_home=str(self.home),
            agent_identity="coder",
            platform="telegram",
            user_id="42",
            agent_context="primary",
        )
        other._client = self.plugin.CloudflareMemoryClient(
            "account", "namespace", "fixture", api_base=self.server.api_base
        )
        content = "Re-added across processes"
        session_id = self.plugin.curated_session_id("memory", content)
        key = (
            self.provider._client.destination_id,
            other._curated_profile,
            session_id,
        )
        self.provider._update_pending_delete(add=key)
        self._write_entries("memory", [content])
        self.server.queue(
            200,
            {
                "success": True,
                "result": [{"id": "still-present"}],
                "result_info": {"cursor": ""},
                "errors": [],
                "messages": [],
            },
        )

        other.on_memory_write("add", "memory", content)
        deadline = time.monotonic() + 2
        while other._write_queue.unfinished_tasks and time.monotonic() < deadline:
            time.sleep(0.01)
        self.provider._retry_pending_session_deletes()

        self.assertEqual(["GET"], [request["method"] for request in self.server.requests])
        self.provider._refresh_delete_state()
        self.assertNotIn(key, self.provider._pending_session_deletes)
        other.shutdown()

    def test_shutdown_flush_is_bounded(self) -> None:
        release = threading.Event()

        class BlockedClient:
            destination_id = "0" * 64

            def ingest(self, profile: str, messages: list[dict], session_id: str) -> None:
                release.wait(10)

        self.provider._client = BlockedClient()
        self.provider._shutdown_timeout = 0.05
        self.provider.sync_turn("question", "answer", session_id="session-one")

        started = time.monotonic()
        self.provider.shutdown()
        elapsed = time.monotonic() - started
        release.set()

        self.assertLess(elapsed, 0.5)

    def test_shutdown_pending_delete_retry_is_bounded(self) -> None:
        release = threading.Event()

        class BlockedDeleteClient:
            destination_id = "3" * 64

            def delete_session(self, profile: str, session_id: str) -> None:
                release.wait(2)

        self.provider._client = BlockedDeleteClient()
        self.provider._shutdown_timeout = 0.05
        self.provider._update_pending_delete(
            add=(
                self.provider._client.destination_id,
                self.provider._profile,
                "session-one",
            )
        )
        timer = threading.Timer(0.4, release.set)
        timer.start()

        started = time.monotonic()
        self.provider.shutdown()
        elapsed = time.monotonic() - started
        release.set()
        timer.cancel()

        self.assertLess(elapsed, 0.2)

    def test_non_primary_context_never_writes(self) -> None:
        for context in ("cron", "flush", "subagent"):
            provider = self.plugin.CloudflareAgentMemoryProvider()
            provider.initialize(
                f"session-{context}",
                hermes_home=str(self.home),
                agent_identity="coder",
                platform="cli",
                user_id="",
                agent_context=context,
            )
            provider._client = self.plugin.CloudflareMemoryClient(
                "account", "namespace", "fixture", api_base=self.server.api_base
            )
            provider.sync_turn("question", "answer", session_id=f"session-{context}")
            remember = json.loads(
                provider.handle_tool_call("cloudflare_memory_remember", {"content": "fact"})
            )
            forget = json.loads(
                provider.handle_tool_call(
                    "cloudflare_memory_forget", {"memory_id": "memory-id"}
                )
            )
            provider.on_memory_write("add", "memory", "fact")
            provider.shutdown()
            self.assertIn("error", remember)
            self.assertIn("error", forget)

        self.assertEqual([], self.server.requests)

    def test_curated_add_mirrors_after_local_success(self) -> None:
        self._write_entries("memory", ["Uses Neovim"])

        self.provider.on_memory_write("add", "memory", "Uses Neovim")
        self._wait_for_requests(2)

        request = self.server.requests[1]
        self.assertEqual("POST", request["method"])
        self.assertTrue(request["path"].endswith("/remember"))
        curated_profile = self.plugin.derived_profile_name(
            "coder", "cli", "", "cloudflare-memory-cli"
        )
        self.assertIn(f"/profiles/{curated_profile}/remember", request["path"])
        self.assertEqual(
            self.plugin.curated_session_id("memory", "Uses Neovim"),
            request["body"]["sessionId"],
        )

    def test_curated_replace_remembers_new_before_deleting_old_session(self) -> None:
        self._rebuild_provider(memory_entries=["Uses Vim"])
        self._write_entries("memory", ["Uses Neovim"])

        self.provider.on_memory_write("replace", "memory", "Uses Neovim")
        self._wait_for_requests(3)

        self.assertEqual("POST", self.server.requests[1]["method"])
        self.assertTrue(self.server.requests[1]["path"].endswith("/remember"))
        self.assertEqual("DELETE", self.server.requests[2]["method"])
        self.assertIn(
            self.plugin.curated_session_id("memory", "Uses Vim"),
            self.server.requests[2]["path"],
        )

    def test_curated_replace_keeps_old_session_when_remember_fails(self) -> None:
        self._rebuild_provider(memory_entries=["Uses Vim"])
        self._write_entries("memory", ["Uses Neovim"])
        self.server.queue(
            200,
            {
                "success": True,
                "result": [],
                "result_info": {"cursor": ""},
                "errors": [],
                "messages": [],
            },
        )
        self.server.queue(
            500,
            {
                "success": False,
                "result": None,
                "errors": [{"code": 10001, "message": "temporary failure"}],
                "messages": [],
            },
        )

        self.provider.on_memory_write("replace", "memory", "Uses Neovim")
        self._wait_for_writes()

        self.assertEqual(
            ["GET", "POST"], [request["method"] for request in self.server.requests]
        )

    def test_curated_remember_retry_checks_deterministic_session_first(self) -> None:
        self._write_entries("memory", ["Uses Neovim"])
        self.server.queue(
            200,
            {
                "success": True,
                "result": [],
                "result_info": {"cursor": ""},
                "errors": [],
                "messages": [],
            },
        )
        self.server.queue(
            500,
            {
                "success": False,
                "result": None,
                "errors": [{"code": 10001, "message": "response lost"}],
                "messages": [],
            },
        )
        self.provider.on_memory_write("add", "memory", "Uses Neovim")
        self._wait_for_writes()
        self.server.queue(
            200,
            {
                "success": True,
                "result": [{"id": "already-committed"}],
                "result_info": {"cursor": ""},
                "errors": [],
                "messages": [],
            },
        )

        self.provider.on_session_end([])
        self._wait_for_writes()

        self.assertEqual(
            ["GET", "POST", "GET"],
            [request["method"] for request in self.server.requests],
        )

    def test_curated_remove_deletes_exact_deterministic_session(self) -> None:
        self._rebuild_provider(memory_entries=["Uses Vim"])
        self._write_entries("memory", [])

        self.provider.on_memory_write("remove", "memory", "Uses Vim")
        self._wait_for_requests(1)

        request = self.server.requests[0]
        self.assertEqual("DELETE", request["method"])
        self.assertIn(
            self.plugin.curated_session_id("memory", "Uses Vim"), request["path"]
        )

    def test_failed_curated_delete_is_retried_at_next_checkpoint(self) -> None:
        self._rebuild_provider(memory_entries=["Uses Vim"])
        self._write_entries("memory", [])
        self.server.queue(
            500,
            {
                "success": False,
                "result": None,
                "errors": [{"code": 10001, "message": "temporary failure"}],
                "messages": [],
            },
        )

        self.provider.on_memory_write("remove", "memory", "Uses Vim")
        self._wait_for_writes()
        self.assertTrue(self.provider._pending_session_deletes)

        self.provider.on_session_end([])
        self._wait_for_writes()

        self.assertFalse(self.provider._pending_session_deletes)
        self.assertEqual(["DELETE", "DELETE"], [r["method"] for r in self.server.requests])

    def test_failed_curated_remember_is_not_replayed_after_local_removal(self) -> None:
        remember_started = threading.Event()
        release_remember = threading.Event()

        class BlockingRememberClient:
            destination_id = "1" * 64

            def __init__(self) -> None:
                self.remember_calls = 0
                self.delete_calls = 0

            def list_memories(self, profile: str, **kwargs: object) -> dict:
                return {"result": [], "result_info": {"cursor": ""}}

            def remember(self, profile: str, content: str, session_id: str) -> None:
                self.remember_calls += 1
                remember_started.set()
                if self.remember_calls == 1:
                    release_remember.wait(2)
                    raise self_error("temporary remember failure")

            def delete_session(self, profile: str, session_id: str) -> None:
                self.delete_calls += 1

        self_error = self.plugin.CloudflareMemoryError
        client = BlockingRememberClient()
        self.provider._client = client
        self._write_entries("memory", ["Transient fact"])
        self.provider.on_memory_write("add", "memory", "Transient fact")
        self.assertTrue(remember_started.wait(1))

        self._write_entries("memory", [])
        removed = threading.Thread(
            target=self.provider.on_memory_write,
            args=("remove", "memory", "Transient fact"),
        )
        removed.start()
        release_remember.set()
        removed.join(1)
        self.assertFalse(removed.is_alive())
        self._wait_for_writes()

        self.provider.on_session_end([])
        self._wait_for_writes()

        self.assertEqual(1, client.remember_calls)
        self.assertGreaterEqual(client.delete_calls, 1)

    def test_curated_worker_refreshes_disk_before_retrying_stale_snapshot(self) -> None:
        content = "Removed by another process"
        self.provider._curated_snapshot["memory"].add(content)
        self._write_entries("memory", [])

        self.provider._write_queue.put(
            ("remember", "memory", content, self.provider._curated_profile)
        )
        self._wait_for_writes()

        self.assertEqual(["DELETE"], [request["method"] for request in self.server.requests])

    def test_curated_readd_cancels_failed_delete_before_retry(self) -> None:
        delete_started = threading.Event()
        release_delete = threading.Event()

        class BlockingDeleteClient:
            destination_id = "2" * 64

            def __init__(self) -> None:
                self.delete_calls = 0
                self.remember_calls = 0

            def delete_session(self, profile: str, session_id: str) -> None:
                self.delete_calls += 1
                if self.delete_calls == 1:
                    delete_started.set()
                    release_delete.wait(2)
                    raise self_error("temporary delete failure", status=500)

            def list_memories(self, profile: str, **kwargs: object) -> dict:
                return {
                    "result": [{"id": "still-present"}],
                    "result_info": {"cursor": ""},
                }

            def remember(self, profile: str, content: str, session_id: str) -> None:
                self.remember_calls += 1

        self_error = self.plugin.CloudflareMemoryError
        self._rebuild_provider(memory_entries=["Re-added fact"])
        client = BlockingDeleteClient()
        self.provider._client = client
        self._write_entries("memory", [])
        self.provider.on_memory_write("remove", "memory", "Re-added fact")
        self.assertTrue(delete_started.wait(1))

        self._write_entries("memory", ["Re-added fact"])
        readded = threading.Thread(
            target=self.provider.on_memory_write,
            args=("add", "memory", "Re-added fact"),
        )
        readded.start()
        release_delete.set()
        readded.join(1)
        self.assertFalse(readded.is_alive())
        self._wait_for_writes()

        self.provider.on_session_end([])
        self._wait_for_writes()

        self.assertEqual(1, client.delete_calls)
        self.assertEqual(0, client.remember_calls)
        self.assertFalse(self.provider._pending_session_deletes)

    def test_ambiguous_curated_diff_never_deletes(self) -> None:
        self._rebuild_provider(memory_entries=["Fact one", "Fact two"])
        self._write_entries("memory", [])

        with self.assertLogs(self.plugin.logger, level="WARNING") as logs:
            self.provider.on_memory_write("remove", "memory", "Fact one")

        self.assertIn("Ambiguous curated-memory diff", "\n".join(logs.output))
        self.assertEqual([], self.server.requests)


class MigrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.plugin = _load_provider_module()
        cls.migration = importlib.import_module(f"{cls.plugin.__name__}.migration")

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.home = Path(self.temp.name)
        self.server = _ApiServer()
        self.server.start()
        (self.home / "cloudflare-agent-memory.json").write_text(
            json.dumps({"account_id": "account", "namespace": "namespace"})
        )
        memory_dir = self.home / "memories"
        memory_dir.mkdir()
        (memory_dir / "MEMORY.md").write_text(
            "Project uses Neovim\nwith Lua\n§\nSecond memory", encoding="utf-8"
        )
        (memory_dir / "USER.md").write_text("Prefers concise answers", encoding="utf-8")
        self.session = {
            "id": "20260716_120000_abcdef",
            "source": "telegram",
            "user_id": "12345",
            "messages": [
                {"role": "system", "content": "never send system"},
                {
                    "role": "user",
                    "content": "Remember my editor",
                    "timestamp": "2026-07-16T12:00:00Z",
                },
                {
                    "role": "assistant",
                    "content": "You use Neovim",
                    "timestamp": "2026-07-16T12:00:01Z",
                },
                {"role": "tool", "content": "never send tool"},
            ],
        }
        self.sessions_path = self.home / "sessions.jsonl"
        self.sessions_path.write_text(json.dumps(self.session) + "\n", encoding="utf-8")
        self.env = patch.dict(
            os.environ,
            {
                "HERMES_HOME": str(self.home),
                "CLOUDFLARE_AGENT_MEMORY_API_TOKEN": "fixture",
            },
            clear=False,
        )
        self.env.start()
        self.provider = self.plugin.CloudflareAgentMemoryProvider()
        self.provider.initialize(
            "cloudflare-memory-cli",
            hermes_home=str(self.home),
            agent_identity="coder",
            platform="cli",
            user_id="",
            agent_context="primary",
        )
        self.provider._client = self.plugin.CloudflareMemoryClient(
            "account", "namespace", "fixture", api_base=self.server.api_base
        )

    def tearDown(self) -> None:
        self.provider.shutdown()
        self.env.stop()
        self.server.close()
        self.temp.cleanup()

    def test_dry_run_never_writes(self) -> None:
        operations, stats = self.migration.plan_migration(
            self.provider, self.sessions_path
        )

        self.assertGreater(len(operations), 0)
        self.assertEqual(len(operations), stats.planned)
        self.assertEqual([], self.server.requests)

    def test_curated_entries_use_memory_store_and_deterministic_sessions(self) -> None:
        operations, _stats = self.migration.plan_migration(self.provider, None)

        remembered = [operation for operation in operations if operation["kind"] == "remember"]
        self.assertEqual(3, len(remembered))
        multiline = next(
            operation for operation in remembered if operation["content"].startswith("Project uses")
        )
        self.assertEqual("Project uses Neovim\nwith Lua", multiline["content"])
        self.assertEqual(
            self.plugin.curated_session_id("memory", multiline["content"]),
            multiline["session_id"],
        )
        self.assertIn(
            self.plugin.curated_session_id("user", "Prefers concise answers"),
            {operation["session_id"] for operation in remembered},
        )

    def test_oversized_curated_entry_is_rejected_during_planning(self) -> None:
        oversized = "€" * 10_923
        (self.home / "memories" / "MEMORY.md").write_text(oversized, encoding="utf-8")

        operations, stats = self.migration.plan_migration(self.provider, None)

        self.assertFalse(any(operation.get("content") == oversized for operation in operations))
        self.assertEqual(1, stats.planning_errors)
        self.assertEqual("content_too_large", stats.rejections[0]["reason"])

    def test_existing_curated_session_is_skipped(self) -> None:
        operation = self.migration.plan_migration(self.provider, None)[0][0]
        self.server.queue(
            200,
            {
                "success": True,
                "result": [{"id": "existing"}],
                "result_info": {"cursor": ""},
                "errors": [],
                "messages": [],
            },
        )

        stats = self.migration.apply_migration(
            self.provider, [operation], self.home / "report.jsonl"
        )

        self.assertEqual(1, stats.skipped)
        self.assertEqual(["GET"], [request["method"] for request in self.server.requests])

    def test_curated_manifest_plans_exact_delete_for_stale_mirror(self) -> None:
        stale_session = self.plugin.curated_session_id("memory", "Removed fact")
        manifest = {
            "entries": [
                {
                    "destination_id": self.provider._client.destination_id,
                    "profile": self.provider._curated_profile,
                    "target": "memory",
                    "source_hash": "0" * 64,
                    "session_id": stale_session,
                }
            ]
        }
        (self.home / "cloudflare-agent-memory-curated.json").write_text(
            json.dumps(manifest), encoding="utf-8"
        )

        operations, _stats = self.migration.plan_migration(self.provider, None)

        stale_delete = [
            operation
            for operation in operations
            if operation["kind"] == "delete"
            and operation["session_id"] == stale_session
        ]
        self.assertEqual(1, len(stale_delete))

    def test_applied_curated_delete_removes_manifest_record(self) -> None:
        stale_session = self.plugin.curated_session_id("memory", "Removed fact")
        manifest_path = self.home / "cloudflare-agent-memory-curated.json"
        manifest_path.write_text(
            json.dumps(
                {
                    "entries": [
                        {
                            "destination_id": self.provider._client.destination_id,
                            "profile": self.provider._curated_profile,
                            "target": "memory",
                            "source_hash": "0" * 64,
                            "session_id": stale_session,
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        operation = {
            "kind": "delete",
            "source_hash": "0" * 64,
            "profile": self.provider._curated_profile,
            "session_id": stale_session,
            "content": None,
            "messages": None,
        }

        stats = self.migration.apply_migration(
            self.provider, [operation], self.home / "report.jsonl"
        )

        self.assertEqual(1, stats.applied)
        self.assertEqual("DELETE", self.server.requests[0]["method"])
        self.assertEqual(
            [], json.loads(manifest_path.read_text(encoding="utf-8"))["entries"]
        )

    def test_missing_profile_is_treated_as_empty_for_curated_migration(self) -> None:
        operation = self.migration.plan_migration(self.provider, None)[0][0]
        self.server.queue(
            404,
            {
                "success": False,
                "result": None,
                "errors": [{"code": 10010, "message": "Profile not found"}],
                "messages": [],
            },
        )
        self.server.queue(
            200,
            {
                "success": True,
                "result": {"name": "namespace"},
                "errors": [],
                "messages": [],
            },
        )
        self.server.queue(
            200,
            {"success": True, "result": {"id": "new"}, "errors": [], "messages": []},
        )

        stats = self.migration.apply_migration(
            self.provider, [operation], self.home / "report.jsonl"
        )

        self.assertEqual(1, stats.applied)
        self.assertEqual(
            ["GET", "GET", "POST"],
            [request["method"] for request in self.server.requests],
        )

    def test_export_imports_only_user_and_assistant_text(self) -> None:
        operations, _stats = self.migration.plan_migration(
            self.provider, self.sessions_path
        )
        ingested = next(operation for operation in operations if operation["kind"] == "ingest")
        serialized = json.dumps(ingested)
        self.assertIn("Remember my editor", serialized)
        self.assertIn("You use Neovim", serialized)
        self.assertNotIn("never send system", serialized)
        self.assertNotIn("never send tool", serialized)

    def test_export_content_string_list_and_dict_are_normalized(self) -> None:
        self.session["messages"] = [
            {"role": "user", "content": "plain"},
            {
                "role": "assistant",
                "content": [{"text": "part one"}, {"content": "part two"}],
            },
            {"role": "user", "content": {"text": "dict text"}},
        ]
        self.sessions_path.write_text(json.dumps(self.session) + "\n", encoding="utf-8")

        operations, _stats = self.migration.plan_migration(
            self.provider, self.sessions_path
        )
        messages = next(
            operation["messages"] for operation in operations if operation["kind"] == "ingest"
        )

        self.assertEqual(["plain", "part one\npart two", "dict text"], [m["content"] for m in messages])

    def test_export_skips_tool_media_and_unknown_structured_blocks(self) -> None:
        self.session["messages"] = [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "safe text"},
                    {"type": "tool_use", "name": "read_file", "input": {"path": "/secret"}},
                    {"type": "image", "source": {"data": "embedded fixture"}},
                    {"unexpected": "unknown fixture"},
                ],
            },
            {"role": "assistant", "content": "safe answer"},
        ]
        self.sessions_path.write_text(json.dumps(self.session) + "\n", encoding="utf-8")

        operations, _stats = self.migration.plan_migration(
            self.provider, self.sessions_path
        )
        serialized = json.dumps(
            next(operation for operation in operations if operation["kind"] == "ingest")
        )

        self.assertIn("safe text", serialized)
        self.assertIn("safe answer", serialized)
        self.assertNotIn("read_file", serialized)
        self.assertNotIn("/secret", serialized)
        self.assertNotIn("embedded fixture", serialized)
        self.assertNotIn("unknown fixture", serialized)

    def test_export_profile_mapping_matches_runtime(self) -> None:
        operations, _stats = self.migration.plan_migration(
            self.provider, self.sessions_path
        )
        ingested = next(operation for operation in operations if operation["kind"] == "ingest")
        self.assertEqual(
            self.plugin.derived_profile_name(
                "coder", "telegram", "12345", "20260716_120000_abcdef"
            ),
            ingested["profile"],
        )

    def test_malformed_jsonl_row_is_reported_and_other_rows_continue(self) -> None:
        self.sessions_path.write_text(
            "{not-json}\n" + json.dumps(self.session) + "\n", encoding="utf-8"
        )

        operations, stats = self.migration.plan_migration(
            self.provider, self.sessions_path
        )

        self.assertEqual(1, stats.planning_errors)
        self.assertEqual(1, len(stats.rejections))
        self.assertRegex(stats.rejections[0]["source_hash"], r"^[0-9a-f]{64}$")
        self.assertNotIn("not-json", json.dumps(stats.rejections))
        self.assertTrue(any(operation["kind"] == "ingest" for operation in operations))

    def test_invalid_export_timestamp_is_reported_and_not_planned(self) -> None:
        self.session["messages"][1]["timestamp"] = "not-a-timestamp"
        self.sessions_path.write_text(json.dumps(self.session) + "\n", encoding="utf-8")

        operations, stats = self.migration.plan_migration(
            self.provider, self.sessions_path
        )

        self.assertEqual(1, stats.planning_errors)
        self.assertFalse(any(operation["kind"] == "ingest" for operation in operations))

    def test_export_preserves_fractional_timestamp(self) -> None:
        self.session["messages"][2]["timestamp"] = "2026-07-16T12:00:01.123456Z"
        self.sessions_path.write_text(json.dumps(self.session) + "\n", encoding="utf-8")

        operations, stats = self.migration.plan_migration(
            self.provider, self.sessions_path
        )

        ingested = next(operation for operation in operations if operation["kind"] == "ingest")
        self.assertEqual(0, stats.planning_errors)
        self.assertEqual(
            "2026-07-16T12:00:01.123456Z",
            ingested["messages"][1]["timestamp"],
        )

    def test_invalid_utf8_jsonl_row_is_rejected_and_later_row_continues(self) -> None:
        valid = (json.dumps(self.session) + "\n").encode()
        self.sessions_path.write_bytes(b"{\"invalid\": \"\xff\"}\n" + valid)

        operations, stats = self.migration.plan_migration(
            self.provider, self.sessions_path
        )

        self.assertEqual(1, stats.planning_errors)
        self.assertEqual("invalid_session_row", stats.rejections[0]["reason"])
        self.assertTrue(any(operation["kind"] == "ingest" for operation in operations))

    def test_apply_continues_after_session_failure_and_returns_failure_count(self) -> None:
        operations = [
            {
                "kind": "ingest",
                "source_hash": f"hash-{index}",
                "profile": self.provider._profile,
                "session_id": f"session-{index}",
                "content": None,
                "messages": [{"role": "user", "content": f"message-{index}"}],
            }
            for index in range(2)
        ]
        self.server.queue(
            500,
            {
                "success": False,
                "result": None,
                "errors": [{"code": 10001, "message": "temporary failure"}],
                "messages": [],
            },
        )

        stats = self.migration.apply_migration(
            self.provider, operations, self.home / "report.jsonl"
        )

        self.assertEqual(1, stats.failed)
        self.assertEqual(1, stats.applied)
        self.assertEqual(2, len(self.server.requests))

    def test_apply_defers_later_batches_after_same_session_failure(self) -> None:
        operations = [
            {
                "kind": "ingest",
                "source_hash": f"same-{index}",
                "profile": self.provider._profile,
                "session_id": "same-session",
                "content": None,
                "messages": [{"role": "user", "content": f"batch-{index}"}],
            }
            for index in range(2)
        ]
        operations.append(
            {
                "kind": "ingest",
                "source_hash": "other",
                "profile": self.provider._profile,
                "session_id": "other-session",
                "content": None,
                "messages": [{"role": "user", "content": "other"}],
            }
        )
        self.server.queue(
            500,
            {
                "success": False,
                "result": None,
                "errors": [{"code": 10001, "message": "temporary failure"}],
                "messages": [],
            },
        )

        stats = self.migration.apply_migration(
            self.provider, operations, self.home / "ordered-report.jsonl"
        )

        self.assertEqual(2, stats.failed)
        self.assertEqual(1, stats.applied)
        self.assertEqual(
            ["same-session", "other-session"],
            [request["body"]["sessionId"] for request in self.server.requests],
        )

    def test_apply_does_not_ingest_while_rewind_delete_is_pending(self) -> None:
        operation = {
            "kind": "ingest",
            "source_hash": "pending-rewind",
            "profile": self.provider._profile,
            "session_id": "rewound-session",
            "content": None,
            "messages": [{"role": "user", "content": "historical"}],
        }
        key = (
            self.provider._client.destination_id,
            operation["profile"],
            operation["session_id"],
        )
        self.provider._update_pending_delete(add=key)
        self.server.queue(
            500,
            {
                "success": False,
                "result": None,
                "errors": [{"code": 10001, "message": "delete unavailable"}],
                "messages": [],
            },
        )

        stats = self.migration.apply_migration(
            self.provider, [operation], self.home / "pending-report.jsonl"
        )

        self.assertEqual(1, stats.failed)
        self.assertEqual(["DELETE"], [request["method"] for request in self.server.requests])
        self.provider._refresh_delete_state()
        self.assertIn(key, self.provider._pending_session_deletes)

    def test_report_is_validated_before_remote_writes(self) -> None:
        operation = self.migration.plan_migration(self.provider, None)[0][0]
        blocker = self.home / "not-a-directory"
        blocker.write_text("fixture")

        with self.assertRaises(self.migration.MigrationReportError):
            self.migration.apply_migration(
                self.provider, [operation], blocker / "report.jsonl"
            )

        self.assertEqual([], self.server.requests)

    def test_report_records_planned_state_before_final_result(self) -> None:
        operation = next(
            operation
            for operation in self.migration.plan_migration(
                self.provider, self.sessions_path
            )[0]
            if operation["kind"] == "ingest"
        )
        report = self.home / "report.jsonl"

        self.migration.apply_migration(self.provider, [operation], report)

        rows = [json.loads(line) for line in report.read_text().splitlines()]
        self.assertEqual(["planned", "applied"], [row["status"] for row in rows])

    def test_report_contains_hashes_and_counts_but_no_content_or_user_id(self) -> None:
        operation = next(
            operation
            for operation in self.migration.plan_migration(
                self.provider, self.sessions_path
            )[0]
            if operation["kind"] == "ingest"
        )
        report = self.home / "report.jsonl"

        self.migration.apply_migration(self.provider, [operation], report)

        text = report.read_text()
        self.assertIn(operation["source_hash"], text)
        self.assertIn('"message_count": 2', text)
        self.assertNotIn("Remember my editor", text)
        self.assertNotIn("12345", text)

    def test_replayed_ingest_uses_same_profile_and_session(self) -> None:
        first = [
            operation
            for operation in self.migration.plan_migration(
                self.provider, self.sessions_path
            )[0]
            if operation["kind"] == "ingest"
        ]
        second = [
            operation
            for operation in self.migration.plan_migration(
                self.provider, self.sessions_path
            )[0]
            if operation["kind"] == "ingest"
        ]

        self.assertEqual(
            [(operation["profile"], operation["session_id"]) for operation in first],
            [(operation["profile"], operation["session_id"]) for operation in second],
        )


class ProviderCliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.plugin = _load_provider_module()
        cls.cli = importlib.import_module(f"{cls.plugin.__name__}.cli")

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.home = Path(self.temp.name)
        self.server = _ApiServer()
        self.server.start()
        (self.home / "cloudflare-agent-memory.json").write_text(
            json.dumps({"account_id": "account", "namespace": "namespace"})
        )
        memory_dir = self.home / "memories"
        memory_dir.mkdir()
        (memory_dir / "MEMORY.md").write_text("Uses Neovim", encoding="utf-8")
        self.env = patch.dict(
            os.environ,
            {
                "HERMES_HOME": str(self.home),
                "CLOUDFLARE_AGENT_MEMORY_API_TOKEN": "fixture",
            },
            clear=False,
        )
        self.env.start()
        self.provider = self.plugin.CloudflareAgentMemoryProvider()
        self.provider.initialize(
            "cloudflare-memory-cli",
            hermes_home=str(self.home),
            agent_identity="coder",
            platform="cli",
            user_id="",
            agent_context="primary",
        )
        self.provider._client = self.plugin.CloudflareMemoryClient(
            "account", "namespace", "fixture", api_base=self.server.api_base
        )
        self.parser = argparse.ArgumentParser()
        self.cli.register_cli(self.parser)

    def tearDown(self) -> None:
        self.provider.shutdown()
        self.env.stop()
        self.server.close()
        self.temp.cleanup()

    def _run(self, arguments: list[str]) -> tuple[int, str, str]:
        args = self.parser.parse_args(arguments)
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            patch.object(self.cli, "_load_provider", return_value=self.provider),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            result = args.func(args)
        return result, stdout.getvalue(), stderr.getvalue()

    def test_status_returns_nonzero_when_live_check_fails(self) -> None:
        self.server.queue(
            500,
            {
                "success": False,
                "result": None,
                "errors": [{"code": 10001, "message": "temporary failure"}],
                "messages": [],
            },
        )

        result, _stdout, stderr = self._run(["status"])

        self.assertEqual(1, result)
        self.assertIn("10001", stderr)
        self.assertNotIn("fixture", stderr)

    def test_status_reports_zero_for_namespace_without_profile(self) -> None:
        self.server.queue(
            200,
            {
                "success": True,
                "result": {"name": "namespace"},
                "errors": [],
                "messages": [],
            },
        )
        self.server.queue(
            404,
            {
                "success": False,
                "result": None,
                "errors": [{"code": 10010, "message": "Profile not found"}],
                "messages": [],
            },
        )

        result, stdout, stderr = self._run(["status"])

        self.assertEqual(0, result)
        self.assertIn("memories=0", stdout)
        self.assertEqual("", stderr)

    def test_status_shutdown_does_not_retry_pending_deletes(self) -> None:
        pending = (
            self.provider._client.destination_id,
            self.provider._profile,
            "pending-session",
        )
        self.provider._update_pending_delete(add=pending)
        self.server.queue(
            200,
            {
                "success": True,
                "result": {"name": "namespace"},
                "errors": [],
                "messages": [],
            },
        )

        result, _stdout, _stderr = self._run(["status"])

        self.assertEqual(0, result)
        self.assertNotIn("DELETE", [request["method"] for request in self.server.requests])

    def test_migrate_defaults_to_dry_run(self) -> None:
        result, stdout, _stderr = self._run(["migrate"])

        self.assertEqual(0, result)
        self.assertIn("DRY RUN", stdout)
        self.assertIn(f"profile={self.provider._curated_profile} planned=1", stdout)
        self.assertEqual([], self.server.requests)

    def test_migrate_unconfigured_returns_normal_diagnostic(self) -> None:
        self.provider._client = None

        result, _stdout, stderr = self._run(["migrate"])

        self.assertEqual(1, result)
        self.assertIn("provider is not configured", stderr)
        self.assertNotIn("Traceback", stderr)

    def test_dry_run_prints_content_free_rejection_hashes(self) -> None:
        sessions = self.home / "invalid.jsonl"
        sessions.write_text("{private-invalid-fixture}\n", encoding="utf-8")

        result, stdout, _stderr = self._run(
            ["migrate", "--sessions-jsonl", str(sessions)]
        )

        self.assertEqual(1, result)
        self.assertIn("rejected source_hash=", stdout)
        self.assertNotIn("private-invalid-fixture", stdout)

    def test_apply_requires_explicit_flag(self) -> None:
        dry_result, _stdout, _stderr = self._run(["migrate", "--dry-run"])
        self.assertEqual(0, dry_result)
        self.assertEqual([], self.server.requests)

        self.provider.initialize(
            "cloudflare-memory-cli",
            hermes_home=str(self.home),
            agent_identity="coder",
            platform="cli",
            user_id="",
            agent_context="primary",
        )
        self.provider._client = self.plugin.CloudflareMemoryClient(
            "account", "namespace", "fixture", api_base=self.server.api_base
        )
        self.server.queue(
            200,
            {
                "success": True,
                "result": [],
                "result_info": {"cursor": ""},
                "errors": [],
                "messages": [],
            },
        )
        apply_result, _stdout, _stderr = self._run(["migrate", "--apply"])

        self.assertEqual(0, apply_result)
        self.assertTrue(any(request["method"] == "POST" for request in self.server.requests))

    def test_current_hermes_discovers_cli_command_without_loading_provider_first(self) -> None:
        plugin_dir = self.home / "plugins" / "cloudflare-agent-memory"
        plugin_dir.mkdir(parents=True)
        for name in ("__init__.py", "client.py", "migration.py", "cli.py", "plugin.yaml"):
            shutil.copy2(ROOT / name, plugin_dir / name)
        (self.home / "config.yaml").write_text(
            "memory:\n  provider: cloudflare-agent-memory\n", encoding="utf-8"
        )

        from plugins.memory import discover_plugin_cli_commands

        commands = discover_plugin_cli_commands()

        self.assertEqual(["cloudflare-agent-memory"], [item["name"] for item in commands])
        parser = argparse.ArgumentParser()
        commands[0]["setup_fn"](parser)
        self.assertEqual("status", parser.parse_args(["status"]).cloudflare_memory_command)


if __name__ == "__main__":
    unittest.main()
