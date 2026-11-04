"""Phase 1: AI settings, endpoint policy, the Ollama client and the connection check (no real model)."""

from __future__ import annotations

import http.server
import json
import threading

import pytest

from watchtower.adapters.ai.ollama import AiUnavailable, OllamaClient, strip_reasoning
from watchtower.config.settings import AiSettings, Settings, load_settings
from watchtower.security.destinations import DestinationPolicy
from watchtower.services.ai.endpoint import (
    EndpointRefused, ResolvedEndpoint, classify, parse_endpoint, resolve_endpoint, wsl_windows_host,
)
from watchtower.services.ai.status import connection_check, suggest
from watchtower.workers.egress import EgressGuard


class FakeOllama:
    """A transport that answers like Ollama and records every request."""

    def __init__(self, models=("qwen3:8b-q4_K_M", "qwen3:14b-q4_K_M"), chat=None, status=200, raw=None, error=None):
        self.models, self.chat_reply, self.status, self.raw, self.error = list(models), chat, status, raw, error
        self.requests = []

    def __call__(self, resolved, method, path, body, connect_timeout, read_timeout, max_bytes):
        self.requests.append({"address": resolved.address, "method": method, "path": path,
                              "body": json.loads(body) if body else None, "read_timeout": read_timeout})
        if self.error:
            raise self.error
        if self.raw is not None:
            return self.status, self.raw
        if path == "/api/tags":
            return self.status, json.dumps({"models": [{"name": m, "model": m} for m in self.models]}).encode()
        if path == "/api/show":
            if json.loads(body)["model"] not in self.models:
                return 404, b'{"error":"not found"}'
            return 200, json.dumps({"model_info": {"qwen3.context_length": 40960}}).encode()
        return self.status, json.dumps(self.chat_reply or {"message": {"content": "{}"}, "done_reason": "stop"}).encode()


def loopback(url, allow_private):
    return resolve_endpoint(url, allow_private=allow_private, resolve=lambda host, port: ["127.0.0.1"])


def client(fake, **settings):
    return OllamaClient(endpoint=settings.get("endpoint", "http://127.0.0.1:11434"),
                        allow_private=settings.get("allow_private", False), transport=fake)


# -- settings --------------------------------------------------------------


def test_ai_is_off_by_default_and_other_defaults_are_unchanged():
    settings = Settings()
    assert settings.ai.enabled is False
    assert settings.ai.endpoint == "http://127.0.0.1:11434"
    assert settings.ai.allow_private_endpoint is False
    assert settings.ai.thinking is False
    assert settings.ai.max_concurrent_analyses == 1
    assert settings.ai.temperature <= 0.2
    assert settings.scope == Settings().scope and settings.pipeline == Settings().pipeline


def test_ai_settings_come_from_the_environment(tmp_path):
    settings = load_settings("development", environ={
        "WATCHTOWER_PROFILE_DIR": str(tmp_path), "WATCHTOWER__AI__ENABLED": "true",
        "WATCHTOWER__AI__ENDPOINT": "http://windows-host:11434", "WATCHTOWER__AI__ALLOW_PRIVATE_ENDPOINT": "true",
        "WATCHTOWER__AI__NUM_CTX": "4096"})
    assert settings.ai.enabled and settings.ai.allow_private_endpoint
    assert settings.ai.endpoint == "http://windows-host:11434" and settings.ai.num_ctx == 4096


@pytest.mark.parametrize("url", ["ftp://127.0.0.1:11434", "http://user:pw@127.0.0.1:11434", "http://127.0.0.1:11434/api",
                                 "http://127.0.0.1:11434?x=1", "file:///etc/passwd", "127.0.0.1:11434", ""])
def test_endpoint_shapes_are_refused(url):
    with pytest.raises(EndpointRefused):
        parse_endpoint(url)
    with pytest.raises(ValueError):
        AiSettings(endpoint=url)


# -- endpoint policy -------------------------------------------------------


def test_loopback_is_accepted_and_pinned():
    resolved = resolve_endpoint("http://localhost:11434", allow_private=False, resolve=lambda h, p: ["127.0.0.1", "::1"])
    assert resolved.address == "127.0.0.1" and resolved.kind == "loopback" and resolved.pair == ("127.0.0.1", 11434)


def test_private_addresses_need_the_owner_confirmation():
    with pytest.raises(EndpointRefused, match="allow_private_endpoint"):
        resolve_endpoint("http://192.168.1.20:11434", allow_private=False)
    assert resolve_endpoint("http://192.168.1.20:11434", allow_private=True).kind == "private"


@pytest.mark.parametrize("address", ["8.8.8.8", "169.254.169.254", "0.0.0.0", "224.0.0.1", "2001:4860:4860::8888"])
def test_public_metadata_and_reserved_addresses_are_refused_even_when_private_is_allowed(address):
    host = f"[{address}]" if ":" in address else address
    with pytest.raises(EndpointRefused, match="public or reserved"):
        resolve_endpoint(f"http://{host}:11434", allow_private=True)


def test_a_hostname_that_resolves_publicly_is_refused():
    with pytest.raises(EndpointRefused):
        resolve_endpoint("http://ollama.example.com:11434", allow_private=True, resolve=lambda h, p: ["10.0.0.5", "93.184.216.34"])


def test_windows_host_is_looked_up_each_time_and_checked_as_private():
    calls = []

    def gateway():
        calls.append(1)
        return "172.24.160.1"

    with pytest.raises(EndpointRefused):
        resolve_endpoint("http://windows-host:11434", allow_private=False, windows_host=gateway)
    resolved = resolve_endpoint("http://windows-host:11434", allow_private=True, windows_host=gateway)
    assert resolved.address == "172.24.160.1" and len(calls) == 2
    with pytest.raises(EndpointRefused, match="WSL"):
        resolve_endpoint("http://windows-host:11434", allow_private=True, windows_host=lambda: None)


def test_wsl_default_gateway_is_read_from_the_route_table(tmp_path):
    routes = tmp_path / "route"
    routes.write_text("Iface\tDestination\tGateway\tFlags\n"
                      "eth0\t0010A8AC\t00000000\t0001\n"
                      "eth0\t00000000\t01A018AC\t0003\n")
    assert wsl_windows_host(str(routes)) == "172.24.160.1"
    assert wsl_windows_host(str(tmp_path / "missing")) is None


def test_classify():
    assert classify("127.0.0.5") == "loopback" and classify("::1") == "loopback"
    assert classify("10.1.2.3") == "private" and classify("::ffff:192.168.0.1") == "private"
    assert classify("100.64.0.9") == "private"
    assert classify("100.100.100.200") == "public"  # cloud metadata inside CGNAT space is never an endpoint
    assert classify("1.1.1.1") == "public" and classify("fe80::1") == "public"


# -- client ----------------------------------------------------------------


def test_models_and_context_length():
    fake = FakeOllama()
    ollama = client(fake)
    assert ollama.models() == ["qwen3:14b-q4_K_M", "qwen3:8b-q4_K_M"]
    assert ollama.context_length("qwen3:8b-q4_K_M") == 40960
    assert ollama.context_length("missing") is None
    assert all(r["address"] == "127.0.0.1" for r in fake.requests)


def test_chat_sends_num_ctx_schema_and_thinking_off_and_drops_reasoning():
    fake = FakeOllama(chat={"message": {"content": "<think>secret plan</think>{\"candidates\": []}",
                                        "thinking": "hidden chain of thought"},
                            "done_reason": "stop", "prompt_eval_count": 12, "eval_count": 3})
    result = client(fake).chat("qwen3:8b-q4_K_M", [{"role": "user", "content": "x"}], schema={"type": "object"},
                               num_ctx=8192, max_output_tokens=512, temperature=0.1)
    assert result.content == '{"candidates": []}'
    assert "hidden" not in repr(result) and "secret plan" not in repr(result)
    body = fake.requests[-1]["body"]
    assert body["options"] == {"num_ctx": 8192, "num_predict": 512, "temperature": 0.1}
    assert body["think"] is False and body["stream"] is False and body["format"] == {"type": "object"}
    assert "tools" not in body
    assert (result.prompt_tokens, result.output_tokens, result.truncated) == (12, 3, False)


def test_truncated_output_is_reported():
    fake = FakeOllama(chat={"message": {"content": "{\"cand"}, "done_reason": "length"})
    assert client(fake).chat("m", [], schema=None, num_ctx=2048, max_output_tokens=10, temperature=0).truncated


def test_strip_reasoning_handles_unterminated_blocks():
    assert strip_reasoning("<think>never closed") == ""
    assert strip_reasoning("  <THINK>a</THINK> {}  ") == "{}"


@pytest.mark.parametrize("fake, kind", [
    (FakeOllama(raw=b"<html>nginx</html>"), "malformed"),
    (FakeOllama(status=500, raw=b"{}"), "malformed"),
    (FakeOllama(raw=b'{"unexpected": true}'), "malformed"),
    (FakeOllama(error=AiUnavailable("timeout", "slow")), "timeout"),
    (FakeOllama(error=AiUnavailable("unreachable", "refused")), "unreachable"),
])
def test_client_failures_have_a_kind(fake, kind):
    with pytest.raises(AiUnavailable) as caught:
        client(fake).models()
    assert caught.value.kind == kind


class _Handler(http.server.BaseHTTPRequestHandler):
    reply = b'{"models": [{"name": "m"}]}'

    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(self.reply)

    def log_message(self, *args):
        pass


def test_real_pinned_transport_against_a_local_server_with_size_cap():
    server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        ollama = OllamaClient(endpoint=f"http://127.0.0.1:{port}")
        assert ollama.models() == ["m"]
        ollama.max_response_bytes = 5
        with pytest.raises(AiUnavailable) as caught:
            ollama.models()
        assert caught.value.kind == "oversize"
    finally:
        server.shutdown()
        server.server_close()
    with pytest.raises(AiUnavailable) as caught:
        OllamaClient(endpoint=f"http://127.0.0.1:{port}", connect_timeout=1).models()
    assert caught.value.kind == "unreachable"


# -- connection check ------------------------------------------------------


def ai(**overrides):
    return AiSettings(**{"enabled": True, **overrides})


def test_check_disabled():
    report = connection_check(AiSettings(), client=client(FakeOllama()))
    assert report.outcome == "disabled" and "Scans" in report.guidance[0]


def test_check_ready_reports_model_and_context():
    report = connection_check(ai(), client=OllamaClient(endpoint="http://127.0.0.1:11434", transport=FakeOllama()))
    assert report.outcome == "ready" and report.ready
    assert report.model == "qwen3:8b-q4_K_M" and report.context_length == 40960 and report.num_ctx == 8192
    assert report.endpoint_kind == "loopback"
    assert report.suggested_models[0] == "qwen3:14b-q4_K_M"


def test_check_model_missing_lists_installed_models_and_never_downloads():
    fake = FakeOllama(models=["llama3:8b"])
    report = connection_check(ai(), client=client(fake))
    assert report.outcome == "model_missing" and "llama3:8b" in report.message
    assert "never downloads" in report.guidance[0]
    assert not any(r["path"] in ("/api/pull", "/api/chat", "/api/generate") for r in fake.requests)


def test_check_refused_by_policy_without_any_request():
    fake = FakeOllama()
    report = connection_check(ai(endpoint="http://192.168.1.9:11434"), client=OllamaClient(
        endpoint="http://192.168.1.9:11434", transport=fake))
    assert report.outcome == "refused_by_policy" and fake.requests == []


@pytest.mark.parametrize("error, outcome", [
    (AiUnavailable("unreachable", "x"), "unreachable"), (AiUnavailable("timeout", "x"), "timeout"),
    (AiUnavailable("oversize", "x"), "malformed")])
def test_check_failures(error, outcome, monkeypatch):
    monkeypatch.setenv("WSL_DISTRO_NAME", "Ubuntu-24.04")
    report = connection_check(ai(), client=client(FakeOllama(error=error)))
    assert report.outcome == outcome
    if outcome != "malformed":
        assert any("WSL" in line for line in report.guidance)


def test_suggestions_prefer_qwen3_14b_then_other_qwen3():
    assert suggest(["llama3:8b", "qwen3:8b", "qwen3:14b-q4_K_M"]) == ["qwen3:14b-q4_K_M", "qwen3:8b", "llama3:8b"]


# -- egress ----------------------------------------------------------------


def test_analysis_guard_reaches_only_the_model_and_database():
    guard = EgressGuard(DestinationPolicy(), [("172.24.160.1", 11434), ("127.0.0.1", 5432)], only_allowed=True)
    assert guard.check("172.24.160.1", 11434) is None and guard.check("127.0.0.1", 5432) is None
    for host, port in [("172.24.160.1", 22), ("172.24.160.2", 11434), ("127.0.0.1", 11434), ("127.0.0.1", 8080),
                       ("10.0.0.1", 80), ("192.168.1.1", 443), ("169.254.169.254", 80), ("93.184.216.34", 443),
                       ("::1", 11434)]:
        assert guard.check(host, port) is not None, (host, port)


def test_default_worker_guard_is_unchanged_by_an_extra_pair():
    guard = EgressGuard(DestinationPolicy(), [("127.0.0.1", 11434)])
    assert guard.check("127.0.0.1", 11434) is None
    assert guard.check("127.0.0.1", 11435) is not None and guard.check("127.0.0.2", 11434) is not None
    assert guard.check("10.0.0.1", 80) is not None
    assert guard.check("93.184.216.34", 443) is None  # targets stay reachable for scan workers


def test_resolved_endpoint_pair_is_what_the_worker_allows():
    resolved = ResolvedEndpoint(parse_endpoint("http://windows-host:11434"), "172.24.160.1", "private")
    assert resolved.pair == ("172.24.160.1", 11434)
