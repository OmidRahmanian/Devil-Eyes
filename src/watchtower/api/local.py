"""The open local dashboard.

With ``auth.local_dashboard`` on, a request that carries no token acts as a
dedicated local owner: a principal that owns every active project. Only the
person at this computer qualifies. The request must come from a loopback
address, name a loopback Host (which defeats DNS rebinding), and, when the
browser says where it came from, come from the dashboard's own origin (which
stops other websites driving it). Anything else still needs a bearer token.

The local owner's token lives in a private file so the terminal can open the
same projects; it is never sent to the browser.
"""

from __future__ import annotations

import ipaddress
import os
import threading
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import Request

from watchtower.domain.errors import AuthenticationFailed
from watchtower.persistence.database import Database
from watchtower.security.auth import Principal, PrincipalKind, ProjectRole

DEFAULT_TOKEN_FILE = "~/.config/watchtower/dashboard-owner-token"
LOOPBACK_NAMES = {"localhost", "127.0.0.1", "::1"}
DISPLAY_NAME = "Local dashboard owner"


def _loopback_address(value: str | None) -> bool:
    if not value:
        return False
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return False


def _host_and_port(netloc: str) -> tuple[str, str]:
    parsed = urlsplit("//" + netloc)
    try:
        port = str(parsed.port or "")
    except ValueError:
        port = "invalid"
    return (parsed.hostname or "").lower(), port


def same_machine(request: Request) -> bool:
    """True only for the dashboard's own page, opened on this computer."""
    if not request.client or not _loopback_address(request.client.host):
        return False
    host, port = _host_and_port(request.headers.get("host", ""))
    if host not in LOOPBACK_NAMES:
        return False
    origin = request.headers.get("origin")
    if origin is not None:
        parsed = urlsplit(origin)
        if parsed.scheme != "http" or _host_and_port(parsed.netloc) != (host, port):
            return False
    return request.headers.get("sec-fetch-site", "same-origin") in ("same-origin", "none")


class LocalOwner:
    """Creates, on first use, the local owner and its unrestricted token, and keeps it an owner of every project."""

    def __init__(self, database: Database, token_file: str = DEFAULT_TOKEN_FILE) -> None:
        self.database = database
        self.path = Path(token_file).expanduser()
        self._lock = threading.Lock()
        self._token: str | None = None

    def token(self) -> str:
        with self._lock:
            if self._token is None or not self._valid(self._token):
                self._token = self._load() or self._create()
            return self._token

    def principal(self) -> Principal:
        with self.database.system() as system:
            principal, _ = system.auth.authenticate(self.token())
        return principal

    def adopt_projects(self) -> None:
        """Make the local owner an owner of active projects it does not belong to yet."""
        token = self.token()
        with self.database.system() as system:
            principal, _ = system.auth.authenticate(token)
            mine = {project_id for project_id, _ in system.auth.memberships(principal.id)}
            for project in system.projects.list():
                if project.id not in mine:
                    system.auth.set_membership(project.id, principal.id, ProjectRole.OWNER)

    def _valid(self, token: str) -> bool:
        try:
            with self.database.system() as system:
                system.auth.authenticate(token)
        except AuthenticationFailed:
            return False
        return True

    def _load(self) -> str | None:
        try:
            if self.path.stat().st_mode & 0o077:
                return None  # readable by others: never trust it
            token = self.path.read_text(encoding="utf-8").strip()
        except OSError:
            return None
        return token if token.startswith("wt_") and self._valid(token) else None

    def _create(self) -> str:
        with self.database.system() as system:
            principal = system.auth.create_principal(DISPLAY_NAME, kind=PrincipalKind.USER)
            issued = system.auth.issue_token(principal.id, "local dashboard", ttl_days=None)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        descriptor = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(issued.secret + "\n")
        os.chmod(self.path, 0o600)
        return issued.secret
