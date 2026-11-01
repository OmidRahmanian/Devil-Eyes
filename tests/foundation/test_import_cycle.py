"""Guard against the destinations/scope circular import regressing.

``watchtower.security.destinations`` imports ``watchtower.domain.targets``,
which triggers ``watchtower.domain``'s package ``__init__`` and so
``watchtower.domain.scope``. If scope imports destinations at module load,
importing destinations first fails with a partially-initialized-module
``ImportError``. Each case runs in a fresh interpreter so import order is not
masked by modules an earlier test already imported.
"""
from __future__ import annotations

import subprocess
import sys

import pytest

FIRST_IMPORTS = [
    "watchtower.security.destinations",
    "watchtower.domain.scope",
    "watchtower.domain.targets",
    "watchtower.config.settings",
]


@pytest.mark.parametrize("module", FIRST_IMPORTS)
def test_module_imports_standalone(module: str) -> None:
    result = subprocess.run(
        [sys.executable, "-c", f"import {module}"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr


def test_destination_policy_usable_when_scope_imported_first() -> None:
    script = (
        "import watchtower.domain.scope as scope\n"
        "from uuid import uuid4\n"
        "policy = scope.ScopePolicy(uuid4(), None)\n"
        # The default DestinationPolicy is created lazily in __init__; it must
        # still reject the cloud metadata address.
        "assert policy.destinations.check_address('169.254.169.254') is not None\n"
        "print('ok')\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, timeout=30
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "ok"
