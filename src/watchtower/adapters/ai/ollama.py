"""A minimal client for a local Ollama server: list models, describe one, chat.

No SDK, no streaming, no tools or function calling: the model receives text
and returns text, nothing else. Every call first approves the endpoint with
``watchtower.services.ai.endpoint.resolve_endpoint`` and connects only to the
approved address. Responses are size-capped. A reasoning ("thinking") block is
dropped before parsing and is never returned, stored or logged.
"""

from __future__ import annotations

import http.client
import json
import re
import socket
import ssl
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from watchtower.services.ai.endpoint import EndpointRefused, ResolvedEndpoint, resolve_endpoint

MAX_RESPONSE_BYTES = 4 * 1024 * 1024
_THINK = re.compile(r"<think>.*?(?:</think>|\Z)", re.S | re.I)


class AiUnavailable(Exception):
    """The model could not be used. ``kind`` is one of the connection-check outcomes."""

    def __init__(self, kind: str, message: str) -> None:
        super().__init__(message)
        self.kind = kind


@dataclass(frozen=True, slots=True)
class ChatResult:
    content: str  # reasoning removed
    done_reason: str = ""
    prompt_tokens: int = 0
    output_tokens: int = 0

    @property
    def truncated(self) -> bool:
        return self.done_reason == "length"


# transport(resolved, method, path, body, connect_timeout, read_timeout, max_bytes) -> (status, body)
Transport = Callable[[ResolvedEndpoint, str, str, bytes | None, float, float, int], tuple[int, bytes]]


class _PinnedHTTP(http.client.HTTPConnection):
    def __init__(self, resolved: ResolvedEndpoint, connect_timeout: float, read_timeout: float) -> None:
        super().__init__(resolved.endpoint.host, resolved.endpoint.port, timeout=connect_timeout)
        self._address, self._read_timeout = resolved.address, read_timeout

    def connect(self) -> None:
        self.sock = socket.create_connection((self._address, self.port), self.timeout)
        self.sock.settimeout(self._read_timeout)


class _PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, resolved: ResolvedEndpoint, connect_timeout: float, read_timeout: float) -> None:
        super().__init__(resolved.endpoint.host, resolved.endpoint.port, timeout=connect_timeout,
                         context=ssl.create_default_context())
        self._address, self._read_timeout = resolved.address, read_timeout

    def connect(self) -> None:
        sock = socket.create_connection((self._address, self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        except BaseException:
            sock.close()
            raise
        self.sock.settimeout(self._read_timeout)


def http_transport(resolved: ResolvedEndpoint, method: str, path: str, body: bytes | None,
                   connect_timeout: float, read_timeout: float, max_bytes: int) -> tuple[int, bytes]:
    cls = _PinnedHTTPS if resolved.endpoint.scheme == "https" else _PinnedHTTP
    connection = cls(resolved, connect_timeout, read_timeout)
    try:
        headers = {"Content-Type": "application/json", "Accept": "application/json", "Connection": "close"}
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        data = response.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise AiUnavailable("oversize", f"the model server sent more than {max_bytes} bytes")
        return response.status, data
    except AiUnavailable:
        raise
    except (socket.timeout, TimeoutError):
        raise AiUnavailable("timeout", "the model server did not answer in time") from None
    except (ConnectionRefusedError, ConnectionResetError):
        raise AiUnavailable("unreachable", "nothing is listening at the AI endpoint (connection refused)") from None
    except (OSError, http.client.HTTPException, ssl.SSLError) as error:
        raise AiUnavailable("unreachable", f"the AI endpoint could not be reached ({type(error).__name__})") from None
    finally:
        connection.close()


def strip_reasoning(text: str) -> str:
    return _THINK.sub("", text or "").strip()


@dataclass
class OllamaClient:
    endpoint: str
    allow_private: bool = False
    connect_timeout: float = 5.0
    request_timeout: float = 180.0
    transport: Transport = http_transport
    resolver: Callable[[str, bool], ResolvedEndpoint] | None = None
    max_response_bytes: int = MAX_RESPONSE_BYTES
    last_endpoint: ResolvedEndpoint | None = field(default=None, init=False)

    @classmethod
    def from_settings(cls, settings: Any, **overrides: Any) -> OllamaClient:
        return cls(endpoint=settings.endpoint, allow_private=settings.allow_private_endpoint,
                   connect_timeout=settings.connect_timeout_seconds, request_timeout=settings.request_timeout_seconds,
                   **overrides)

    def resolve(self) -> ResolvedEndpoint:
        """Approve the endpoint now (raises ``EndpointRefused``)."""
        if self.resolver is not None:
            resolved = self.resolver(self.endpoint, self.allow_private)
        else:
            resolved = resolve_endpoint(self.endpoint, allow_private=self.allow_private)
        self.last_endpoint = resolved
        return resolved

    def _call(self, method: str, path: str, payload: Mapping[str, Any] | None, *, timeout: float) -> Any:
        resolved = self.resolve()
        body = json.dumps(payload).encode() if payload is not None else None
        status, data = self.transport(resolved, method, path, body, self.connect_timeout, timeout,
                                      self.max_response_bytes)
        if status == 404 and path in ("/api/chat", "/api/show"):
            raise AiUnavailable("model_missing", "the model server does not have this model installed")
        if status != 200:
            raise AiUnavailable("malformed", f"the model server answered HTTP {status}")
        try:
            return json.loads(data)
        except ValueError:
            raise AiUnavailable("malformed", "the model server sent a response that is not JSON") from None

    def models(self) -> list[str]:
        data = self._call("GET", "/api/tags", None, timeout=min(30.0, self.request_timeout))
        try:
            return sorted({str(item.get("model") or item["name"]) for item in data["models"]})
        except (KeyError, TypeError, AttributeError):
            raise AiUnavailable("malformed", "the model list from the server is not in the expected format") from None

    def context_length(self, model: str) -> int | None:
        """The model's trained context length, when the server reports it."""
        try:
            data = self._call("POST", "/api/show", {"model": model}, timeout=min(30.0, self.request_timeout))
        except AiUnavailable as error:
            if error.kind in ("malformed", "model_missing"):
                return None
            raise
        info = data.get("model_info") if isinstance(data, dict) else None
        for key, value in (info or {}).items():
            if key.endswith(".context_length") and isinstance(value, int):
                return value
        return None

    def chat(self, model: str, messages: list[dict[str, str]], *, schema: Mapping[str, Any] | None,
             num_ctx: int, max_output_tokens: int, temperature: float, thinking: bool = False) -> ChatResult:
        payload: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "stream": False,
            "think": bool(thinking),
            "options": {"num_ctx": int(num_ctx), "num_predict": int(max_output_tokens),
                        "temperature": float(temperature)},
        }
        if schema is not None:
            payload["format"] = dict(schema)
        data = self._call("POST", "/api/chat", payload, timeout=self.request_timeout)
        try:
            message = data["message"]
            content = message["content"]
        except (KeyError, TypeError):
            raise AiUnavailable("malformed", "the chat response from the server is not in the expected format") from None
        if not isinstance(content, str):
            raise AiUnavailable("malformed", "the chat response content is not text")
        # message["thinking"], if present, is deliberately ignored.
        return ChatResult(strip_reasoning(content), str(data.get("done_reason") or ""),
                          int(data.get("prompt_eval_count") or 0), int(data.get("eval_count") or 0))


__all__ = ["AiUnavailable", "ChatResult", "EndpointRefused", "OllamaClient", "http_transport", "strip_reasoning"]
