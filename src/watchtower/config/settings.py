"""Typed configuration loaded from a profile file and environment variables.

Precedence, lowest to highest: model defaults, ``config/profiles/<profile>.toml``,
then environment variables named ``WATCHTOWER__<SECTION>__<KEY>`` (for example
``WATCHTOWER__DATABASE__URL``). The profile is chosen by ``WATCHTOWER_PROFILE``
(default ``development``). Profiles are looked up in ``WATCHTOWER_PROFILE_DIR``,
or in ``config/profiles`` under the current directory.

Secrets such as the database URL belong in the environment, not in profiles.
"""

from __future__ import annotations

import json
import os
import re
import tomllib
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator

from watchtower.domain.targets import PortSet
from watchtower.security.destinations import DestinationPolicy

ENV_PREFIX = "WATCHTOWER__"


class _Section(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class DatabaseSettings(_Section):
    url: SecretStr | None = None
    pool_size: int = Field(default=5, ge=1, le=100)
    max_overflow: int = Field(default=5, ge=0, le=100)
    statement_timeout_ms: int = Field(default=30_000, ge=0)
    echo: bool = False

    @field_validator("url")
    @classmethod
    def _postgres_only(cls, value: SecretStr | None) -> SecretStr | None:
        if value is not None and not value.get_secret_value().startswith(("postgresql://", "postgresql+psycopg://")):
            raise ValueError("database.url must be a postgresql:// or postgresql+psycopg:// URL")
        return value

    def sqlalchemy_url(self) -> str:
        if self.url is None:
            raise ValueError("database.url is not configured; set WATCHTOWER__DATABASE__URL")
        url = self.url.get_secret_value()
        if url.startswith("postgresql://"):
            url = "postgresql+psycopg://" + url.removeprefix("postgresql://")
        return url


class ScopeSettings(_Section):
    default_permitted_ports: str = "80,443"
    max_redirects: int = Field(default=0, ge=0, le=20)
    allow_https_downgrade: bool = False
    allow_private_networks: bool = False
    extra_prohibited_networks: tuple[str, ...] = ()
    extra_prohibited_hostnames: tuple[str, ...] = ()
    policy_cache_seconds: float = Field(default=5.0, ge=0, le=300)
    per_host_requests_per_minute: int = Field(default=120, ge=1, le=10000)
    per_project_requests_per_minute: int = Field(default=1200, ge=1, le=100000)
    global_requests_per_minute: int = Field(default=12000, ge=1, le=1000000)
    max_requests_per_run: int = Field(default=10000, ge=1, le=10000000)

    @field_validator("default_permitted_ports")
    @classmethod
    def _ports(cls, value: str) -> str:
        return str(PortSet.parse(value))

    @model_validator(mode="after")
    def _destinations_parse(self) -> ScopeSettings:
        self.destination_policy()
        return self

    def destination_policy(self) -> DestinationPolicy:
        return DestinationPolicy.build(
            allow_private_networks=self.allow_private_networks,
            extra_networks=self.extra_prohibited_networks,
            extra_hostnames=self.extra_prohibited_hostnames,
        )


class AuthSettings(_Section):
    token_ttl_days: int | None = Field(default=90, ge=1)
    # Open the dashboard without a token for browsers on this computer (see watchtower.api.local).
    # `watchtower serve --allow-remote` always turns it off.
    local_dashboard: bool = False
    local_owner_token_file: str = "~/.config/watchtower/dashboard-owner-token"


_KEY = r"^[a-z0-9][a-z0-9_.:-]{0,63}$"


class RuntimeSettings(_Section):
    """Workers and the job broker."""

    broker_url: SecretStr | None = None
    concurrency: int = Field(default=4, ge=1, le=256)  # jobs one worker process runs at once
    lease_seconds: int = Field(default=300, ge=30, le=86_400)
    heartbeat_seconds: int = Field(default=60, ge=5)
    limits: dict[str, int] = Field(default_factory=dict)  # concurrency_key -> max running jobs

    @field_validator("limits")
    @classmethod
    def _limits(cls, value: dict[str, int]) -> dict[str, int]:
        for key, limit in value.items():
            if not re.match(_KEY, key):
                raise ValueError(f"invalid concurrency key: {key!r}")
            if limit < 0:
                raise ValueError(f"limit for {key!r} must be >= 0")
        return value

    @model_validator(mode="after")
    def _heartbeat_within_lease(self) -> RuntimeSettings:
        if self.heartbeat_seconds * 2 > self.lease_seconds:
            raise ValueError("runtime.heartbeat_seconds must be at most half of runtime.lease_seconds")
        return self


class NotificationDestination(_Section):
    """Where notifications for one channel go. The URL embeds a credential, so it is a secret.

    ``kind = "log"`` delivers nowhere: the notifier logs the alert and marks it
    sent, so it stays in the outbox for the CLI and dashboard. It takes no URL.
    """

    name: str = Field(pattern=_KEY)  # matched against NewNotification.channel
    kind: Literal["discord", "slack", "telegram", "webhook", "log"]
    url: SecretStr | None = None
    events: tuple[str, ...] = ()  # event types to deliver; empty delivers all
    enabled: bool = True

    @model_validator(mode="after")
    def _url_for_kind(self) -> NotificationDestination:
        if self.kind == "log":
            if self.url is not None:
                raise ValueError("log destinations take no url")
        elif self.url is None:
            raise ValueError(f"{self.kind} destinations need a url")
        elif not self.url.get_secret_value().startswith("https://"):
            raise ValueError("notification URLs must use https://")
        return self


class NotificationSettings(_Section):
    destinations: tuple[NotificationDestination, ...] = ()

    @field_validator("destinations")
    @classmethod
    def _unique_names(cls, value: tuple[NotificationDestination, ...]) -> tuple[NotificationDestination, ...]:
        names = [destination.name for destination in value]
        duplicates = sorted({name for name in names if names.count(name) > 1})
        if duplicates:
            raise ValueError(f"duplicate notification destinations: {', '.join(duplicates)}")
        return value

    def destination(self, name: str) -> NotificationDestination | None:
        return next((d for d in self.destinations if d.name == name and d.enabled), None)


class PipelineSettings(_Section):
    """What the monitoring pipeline runs; see ``watchtower.services.jobs``."""

    discovery_sources: tuple[Literal["subfinder", "manual"], ...] = ("subfinder",)
    seed_file: str = ""  # hostnames, one per line, or a CSV with a hostname column; used by "manual"
    subfinder_binary: str = "subfinder"
    dns_nameservers: tuple[str, ...] = ()  # empty uses the system resolver
    http_schemes: tuple[Literal["https", "http"], ...] = ("https", "http")
    evidence_root: str = "data/evidence"
    evidence_retention_days: int = Field(default=90, ge=1, le=3650)
    check_kinds: tuple[Literal["http", "component"], ...] = ("http", "component")
    # Consecutive runs a modified or removed value must be seen before it is accepted and alerted.
    confirm_changes: dict[str, int] = Field(default_factory=lambda: {"dns": 2, "http": 2})

    @model_validator(mode="after")
    def _sources(self) -> PipelineSettings:
        if not self.discovery_sources:
            raise ValueError("pipeline.discovery_sources must name at least one source")
        if "manual" in self.discovery_sources and not self.seed_file:
            raise ValueError("pipeline.seed_file is required when discovery_sources includes manual")
        if not self.http_schemes:
            raise ValueError("pipeline.http_schemes must name at least one scheme")
        for phase, count in self.confirm_changes.items():
            if phase not in ("discovery", "dns", "http", "checks") or not 1 <= count <= 10:
                raise ValueError(f"invalid pipeline.confirm_changes entry: {phase}={count}")
        return self


class IntelligenceSettings(_Section):
    cache_root: str = "data/intelligence"
    advisory_url: str = ""
    advisory_file: str = ""  # normalized, operator-supplied vendor advisory JSON
    refresh_interval_seconds: int = Field(default=3600, ge=60)

    @field_validator("advisory_url")
    @classmethod
    def _https(cls, value: str) -> str:
        if value and not value.startswith("https://"):
            raise ValueError("advisory_url must use HTTPS")
        return value


class AiSettings(_Section):
    """The optional local AI review (``watchtower.services.ai``). Off unless ``enabled``.

    ``endpoint`` must be loopback, or a private/LAN address the owner confirms
    with ``allow_private_endpoint``. The host ``windows-host`` means the Windows
    host seen from WSL (its address changes between reboots and is looked up
    each time). Public hosts, other schemes and URLs with credentials are refused.
    """

    enabled: bool = False
    endpoint: str = "http://127.0.0.1:11434"
    allow_private_endpoint: bool = False
    model: str = "qwen3:8b-q4_K_M"  # verified against the endpoint's installed models before every use
    request_timeout_seconds: float = Field(default=180.0, ge=5, le=3600)
    connect_timeout_seconds: float = Field(default=5.0, ge=0.5, le=120)
    num_ctx: int = Field(default=8192, ge=2048, le=262_144)
    max_output_tokens: int = Field(default=1536, ge=128, le=16_384)
    temperature: float = Field(default=0.1, ge=0, le=2)
    thinking: bool = False
    max_concurrent_analyses: int = Field(default=1, ge=1, le=8)
    # Per-review limits.
    max_files: int = Field(default=20, ge=1, le=500)
    max_file_bytes: int = Field(default=512 * 1024, ge=1024, le=16 * 1024 * 1024)
    max_total_bytes: int = Field(default=4 * 1024 * 1024, ge=1024, le=256 * 1024 * 1024)
    max_chunks: int = Field(default=24, ge=1, le=1000)
    max_review_seconds: int = Field(default=1800, ge=30, le=86_400)
    max_fetch_depth: int = Field(default=1, ge=0, le=3)
    # Project memory retrieval.
    max_examples: int = Field(default=3, ge=0, le=10)
    example_token_budget: int = Field(default=800, ge=0, le=8000)
    retention_days: int = Field(default=30, ge=1, le=3650)  # retained bodies and collected scripts

    @field_validator("endpoint")
    @classmethod
    def _endpoint_shape(cls, value: str) -> str:
        from watchtower.services.ai.endpoint import parse_endpoint

        parse_endpoint(value)
        return value.rstrip("/")


class Settings(_Section):
    profile: str = "development"
    log_level: str = "INFO"
    database: DatabaseSettings = DatabaseSettings()
    scope: ScopeSettings = ScopeSettings()
    auth: AuthSettings = AuthSettings()
    runtime: RuntimeSettings = RuntimeSettings()
    notifications: NotificationSettings = NotificationSettings()
    pipeline: PipelineSettings = PipelineSettings()
    intelligence: IntelligenceSettings = IntelligenceSettings()
    ai: AiSettings = AiSettings()


def load_settings(profile: str | None = None, *, environ: Mapping[str, str] | None = None) -> Settings:
    env = os.environ if environ is None else environ
    profile = profile or env.get("WATCHTOWER_PROFILE", "development")
    if not profile.replace("-", "").replace("_", "").isalnum():
        raise ValueError(f"invalid profile name: {profile!r}")
    directory = Path(env.get("WATCHTOWER_PROFILE_DIR", "config/profiles"))
    path = directory / f"{profile}.toml"
    data: dict[str, Any] = {}
    if path.is_file():
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    elif "WATCHTOWER_PROFILE" in env or profile != "development":
        raise FileNotFoundError(f"settings profile not found: {path}")
    data = _merge(data, _from_environment(env))
    data["profile"] = profile
    return Settings.model_validate(data)


def _from_environment(env: Mapping[str, str]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, raw in env.items():
        if not name.startswith(ENV_PREFIX):
            continue
        path = [part.lower() for part in name.removeprefix(ENV_PREFIX).split("__") if part]
        if not path:
            continue
        value: Any = raw
        if raw[:1] in "[{":
            value = json.loads(raw)
        node = result
        for part in path[:-1]:
            node = node.setdefault(part, {})
        node[path[-1]] = value
    return result


def _merge(base: dict[str, Any], override: Mapping[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, Mapping) and isinstance(merged.get(key), Mapping):
            merged[key] = _merge(dict(merged[key]), value)
        else:
            merged[key] = value
    return merged
