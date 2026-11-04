"""The AI connection check: one plain-language answer to "can reviews use the model?".

The check lists installed models and reads the chosen model's details. It
never sends a prompt, downloads a model or contacts anything but the
configured, policy-approved endpoint. Results carry no secrets.
"""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from watchtower.adapters.ai.ollama import AiUnavailable, OllamaClient
from watchtower.services.ai.endpoint import EndpointRefused, parse_endpoint

OUTCOMES = ("disabled", "refused_by_policy", "unreachable", "timeout", "malformed", "model_missing", "ready")

WSL_NOTE = ("Running in WSL: Ollama on Windows is not always reachable at WSL's localhost. Options: install "
            "Ollama inside Ubuntu; turn on WSL mirrored networking (networkingMode=mirrored in .wslconfig) so "
            "localhost works; or let Windows Ollama listen on the WSL network (OLLAMA_HOST=0.0.0.0 plus a "
            "firewall rule for the WSL subnet only), then set ai.endpoint = \"http://windows-host:11434\" and "
            "ai.allow_private_endpoint = true to confirm it is your own machine.")

GUIDANCE = {
    "disabled": "AI review is off. Set WATCHTOWER__AI__ENABLED=true (or [ai] enabled = true in the profile) to "
                "use it. Scans, monitoring, findings and alerts work the same either way.",
    "refused_by_policy": "Devils Eyes only talks to a model on this computer or on a private address you confirm. "
                         "Check ai.endpoint and ai.allow_private_endpoint.",
    "unreachable": "Nothing answered at the AI endpoint. Start Ollama (ollama serve), check the address and port, "
                   "and check that a firewall allows this computer to reach it.",
    "timeout": "The model server did not answer in time. It may be loading a model or busy; try again, or raise "
               "ai.connect_timeout_seconds / ai.request_timeout_seconds.",
    "malformed": "Something answered at the AI endpoint, but not like Ollama. Check that ai.endpoint points at "
                 "the Ollama API (usually port 11434).",
    "model_missing": "The configured model is not installed on the server. Choose one of the installed models for "
                     "ai.model. Devils Eyes never downloads models; install one yourself with `ollama pull` if "
                     "you want a different one.",
    "ready": "Reviews can use the model.",
}


@dataclass
class CheckReport:
    outcome: str
    message: str
    endpoint: str = ""
    endpoint_kind: str = ""  # loopback | private
    model: str = ""
    installed_models: list[str] = field(default_factory=list)
    suggested_models: list[str] = field(default_factory=list)
    context_length: int | None = None
    num_ctx: int = 0
    guidance: list[str] = field(default_factory=list)

    @property
    def ready(self) -> bool:
        return self.outcome == "ready"

    def as_dict(self) -> dict[str, Any]:
        return {**asdict(self), "ready": self.ready}


def in_wsl() -> bool:
    if os.environ.get("WSL_DISTRO_NAME"):
        return True
    try:
        return "microsoft" in Path("/proc/version").read_text().lower()
    except OSError:
        return False


def suggest(models: list[str]) -> list[str]:
    """Installed models worth suggesting: the Qwen3 family first (14B, then 8B), then the rest."""
    def rank(name: str) -> tuple[int, str]:
        lower = name.lower()
        if lower.startswith("qwen3") and "14b" in lower:
            return 0, name
        if lower.startswith("qwen3"):
            return 1, name
        return 2, name
    return [name for name in sorted(models, key=rank)][:5]


def connection_check(settings: Any, *, client: OllamaClient | None = None, force: bool = False) -> CheckReport:
    """Check ``settings`` (an ``AiSettings``). ``force`` checks the endpoint even while AI is disabled."""
    report = CheckReport(outcome="ready", message="", model=settings.model, num_ctx=settings.num_ctx)
    try:
        report.endpoint = parse_endpoint(settings.endpoint).display
    except EndpointRefused as error:
        return _finish(report, "refused_by_policy", str(error))
    if not settings.enabled and not force:
        return _finish(report, "disabled", "AI review is disabled.")
    client = client or OllamaClient.from_settings(settings)
    try:
        resolved = client.resolve()
        report.endpoint_kind = resolved.kind
        report.installed_models = client.models()
        report.suggested_models = suggest(report.installed_models)
        if settings.model not in report.installed_models:
            listed = ", ".join(report.installed_models) or "none"
            return _finish(report, "model_missing",
                           f"Model {settings.model or '(none set)'} is not installed. Installed: {listed}.")
        report.context_length = client.context_length(settings.model)
    except EndpointRefused as error:
        return _finish(report, "refused_by_policy", str(error))
    except AiUnavailable as error:
        kind = error.kind if error.kind in OUTCOMES else "malformed"
        return _finish(report, kind, str(error))
    message = f"Ready: {settings.model} with a {settings.num_ctx}-token context window"
    if report.context_length and settings.num_ctx > report.context_length:
        message += f" (the model was trained for {report.context_length}; lower ai.num_ctx)"
    return _finish(report, "ready", message + ".")


def _finish(report: CheckReport, outcome: str, message: str) -> CheckReport:
    report.outcome, report.message = outcome, message
    report.guidance = [GUIDANCE[outcome]]
    if outcome in ("unreachable", "timeout", "refused_by_policy") and in_wsl():
        report.guidance.append(WSL_NOTE)
    return report
