"""Dependency-free client for Cloudflare Agent Memory's HTTP API."""

from __future__ import annotations

import hashlib
import http.client
import json
import urllib.error
import urllib.request
from urllib.parse import quote, urlencode

MAX_INGEST_MESSAGES = 500
MAX_MESSAGE_BYTES = 32_768
MAX_QUERY_BYTES = 1_024
MAX_SESSION_ID_CHARS = 64
MAX_PROFILE_CHARS = 100
MAX_NAMESPACE_CHARS = 32


class CloudflareMemoryError(RuntimeError):
    """A sanitized Cloudflare transport or API error."""

    def __init__(
        self,
        message: str,
        *,
        status: int | None = None,
        codes: tuple[str, ...] = (),
    ):
        super().__init__(message)
        self.status = status
        self.codes = codes


def utf8_size(value: str) -> int:
    return len(value.encode("utf-8"))


def normalize_session_id(value: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError("session_id is required")
    if len(value) <= MAX_SESSION_ID_CHARS:
        return value
    return "hermes-" + hashlib.sha256(value.encode()).hexdigest()[:48]


def split_message(role: str, content: str, *, timestamp: str = "") -> list[dict]:
    """Split one message on UTF-8 boundaries while preserving its content."""
    if not isinstance(content, str):
        raise ValueError("message content must be a string")
    prefix = "[continued] "
    remaining = content.encode("utf-8")
    chunks: list[dict] = []
    while remaining:
        marker = "" if not chunks else prefix
        available = MAX_MESSAGE_BYTES - utf8_size(marker)
        end = min(len(remaining), available)
        while end and remaining[:end].decode("utf-8", errors="ignore").encode("utf-8") != remaining[:end]:
            end -= 1
        if not end:
            raise ValueError("unable to split message on a UTF-8 boundary")
        text = marker + remaining[:end].decode("utf-8")
        chunk = {"role": role, "content": text}
        if timestamp:
            chunk["timestamp"] = timestamp
        chunks.append(chunk)
        remaining = remaining[end:]
    if not chunks:
        chunk = {"role": role, "content": ""}
        if timestamp:
            chunk["timestamp"] = timestamp
        chunks.append(chunk)
    return chunks


def batched(messages: list[dict], size: int = MAX_INGEST_MESSAGES) -> list[list[dict]]:
    if size <= 0:
        raise ValueError("batch size must be positive")
    return [messages[offset : offset + size] for offset in range(0, len(messages), size)]


class CloudflareMemoryClient:
    def __init__(
        self,
        account_id: str,
        namespace: str,
        api_token: str,
        *,
        timeout: float = 10.0,
        api_base: str = "https://api.cloudflare.com/client/v4",
    ) -> None:
        if not account_id.strip():
            raise ValueError("account_id is required")
        if not namespace.strip():
            raise ValueError("namespace is required")
        if len(namespace) > MAX_NAMESPACE_CHARS:
            raise ValueError(f"namespace must be at most {MAX_NAMESPACE_CHARS} characters")
        if not api_token.strip():
            raise ValueError("api_token is required")
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self.namespace = namespace
        self.destination_id = hashlib.sha256(
            f"{account_id}\0{namespace}".encode()
        ).hexdigest()
        self._api_token = api_token
        self._timeout = timeout
        self._base_url = (
            f"{api_base.rstrip('/')}/accounts/{quote(account_id, safe='')}"
            f"/agent-memory/namespaces/{quote(namespace, safe='')}"
        )

    @staticmethod
    def _validate_profile(profile: str) -> None:
        if not isinstance(profile, str) or not profile:
            raise ValueError("profile is required")
        if len(profile) > MAX_PROFILE_CHARS:
            raise ValueError(f"profile must be at most {MAX_PROFILE_CHARS} characters")

    @staticmethod
    def _validate_session(session_id: str) -> None:
        if not isinstance(session_id, str) or not session_id:
            raise ValueError("session_id is required")
        if len(session_id) > MAX_SESSION_ID_CHARS:
            raise ValueError(f"session_id must be at most {MAX_SESSION_ID_CHARS} characters")

    def _request(
        self,
        method: str,
        segments: tuple[str, ...] = (),
        *,
        body: dict | None = None,
        query: dict[str, str | int] | None = None,
        include_result_info: bool = False,
    ) -> object:
        path = "/".join(quote(segment, safe="") for segment in segments)
        url = f"{self._base_url}/{path}" if path else self._base_url
        if query:
            url += "?" + urlencode(query)
        request = urllib.request.Request(
            url,
            data=None if body is None else json.dumps(body).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self._api_token}",
                "Content-Type": "application/json",
                "User-Agent": "hermes-cloudflare-agent-memory/0.1.0",
            },
            method=method,
        )
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:
                status = response.status
                raw = response.read()
        except urllib.error.HTTPError as exc:
            status = exc.code
            try:
                raw = exc.read()
            except (OSError, http.client.HTTPException) as read_exc:
                raise CloudflareMemoryError(
                    f"network error: {read_exc.__class__.__name__}"
                ) from None
            finally:
                exc.close()
        except (urllib.error.URLError, TimeoutError, OSError, http.client.HTTPException) as exc:
            raise CloudflareMemoryError(
                f"network error: {exc.__class__.__name__}"
            ) from None

        try:
            payload = json.loads(raw)
        except (TypeError, UnicodeDecodeError, json.JSONDecodeError):
            raise CloudflareMemoryError(
                f"HTTP {status}: invalid JSON response", status=status
            ) from None
        if not isinstance(payload, dict):
            raise CloudflareMemoryError(
                f"HTTP {status}: invalid Cloudflare response", status=status
            )
        if status >= 400 or payload.get("success") is not True:
            errors = payload.get("errors") if isinstance(payload.get("errors"), list) else []
            parsed = [item for item in errors if isinstance(item, dict)]
            codes = tuple(str(item.get("code", "unknown")) for item in parsed)
            details = "; ".join(
                f"{item.get('code', 'unknown')}: {item.get('message', 'request failed')}"
                for item in parsed
            ) or "request failed"
            raise CloudflareMemoryError(
                f"HTTP {status}: {details}", status=status, codes=codes
            )
        if include_result_info:
            info = payload.get("result_info")
            return {
                "result": payload.get("result"),
                "result_info": info if isinstance(info, dict) else {},
            }
        return payload.get("result")

    def get_namespace(self) -> dict:
        result = self._request("GET")
        return result if isinstance(result, dict) else {}

    def ingest(self, profile: str, messages: list[dict], session_id: str) -> None:
        self._validate_profile(profile)
        self._validate_session(session_id)
        if not isinstance(messages, list):
            raise ValueError("messages must be a list")
        if len(messages) > MAX_INGEST_MESSAGES:
            raise ValueError(f"ingest accepts at most {MAX_INGEST_MESSAGES} messages")
        if not messages:
            raise ValueError("at least one message is required")
        for message in messages:
            if not isinstance(message, dict):
                raise ValueError("each message must be an object")
            if message.get("role") not in {"user", "assistant"}:
                raise ValueError("message role must be user or assistant")
            content = message.get("content")
            if not isinstance(content, str):
                raise ValueError("message content must be a string")
            if utf8_size(content) > MAX_MESSAGE_BYTES:
                raise ValueError(f"message content must be at most {MAX_MESSAGE_BYTES} UTF-8 bytes")
        self._request(
            "POST",
            ("profiles", profile, "ingest"),
            body={"messages": messages, "sessionId": session_id},
        )

    def remember(self, profile: str, content: str, session_id: str) -> dict:
        self._validate_profile(profile)
        self._validate_session(session_id)
        if not isinstance(content, str) or not content.strip():
            raise ValueError("content is required")
        if utf8_size(content) > MAX_MESSAGE_BYTES:
            raise ValueError(f"content must be at most {MAX_MESSAGE_BYTES} UTF-8 bytes")
        result = self._request(
            "POST",
            ("profiles", profile, "remember"),
            body={"content": content, "sessionId": session_id},
        )
        return result if isinstance(result, dict) else {}

    def recall(self, profile: str, query: str) -> dict:
        self._validate_profile(profile)
        if not isinstance(query, str) or not query.strip():
            raise ValueError("query is required")
        if utf8_size(query) > MAX_QUERY_BYTES:
            raise ValueError(f"query must be at most {MAX_QUERY_BYTES} UTF-8 bytes")
        result = self._request(
            "POST",
            ("profiles", profile, "recall"),
            body={
                "query": query,
                "thinkingLevel": "low",
                "responseLength": "short",
            },
        )
        return result if isinstance(result, dict) else {}

    def list_memories(
        self, profile: str, *, session_id: str = "", cursor: str = ""
    ) -> dict:
        self._validate_profile(profile)
        query: dict[str, str | int] = {"per_page": 500}
        if session_id:
            self._validate_session(session_id)
            query["session_id"] = session_id
        if cursor:
            query["cursor"] = cursor
        result = self._request(
            "GET",
            ("profiles", profile, "memories"),
            query=query,
            include_result_info=True,
        )
        return result if isinstance(result, dict) else {"result": [], "result_info": {}}

    def get_memory(self, profile: str, memory_id: str) -> dict:
        self._validate_profile(profile)
        if not memory_id:
            raise ValueError("memory_id is required")
        result = self._request("GET", ("profiles", profile, "memories", memory_id))
        return result if isinstance(result, dict) else {}

    def delete_memory(self, profile: str, memory_id: str) -> dict:
        self._validate_profile(profile)
        if not memory_id:
            raise ValueError("memory_id is required")
        result = self._request("DELETE", ("profiles", profile, "memories", memory_id))
        return result if isinstance(result, dict) else {}

    def delete_session(self, profile: str, session_id: str) -> None:
        self._validate_profile(profile)
        self._validate_session(session_id)
        self._request("DELETE", ("profiles", profile, "sessions", session_id))

    def summary(self, profile: str) -> str:
        self._validate_profile(profile)
        result = self._request("POST", ("profiles", profile, "summary"), body={})
        if not isinstance(result, dict) or not isinstance(result.get("summary"), str):
            raise CloudflareMemoryError("invalid summary response")
        return result["summary"]
