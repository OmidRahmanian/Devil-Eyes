"""Where the local model lives, and whether Devils Eyes may talk to it.

The policy is enforced here, in application code, every time the endpoint is
used: loopback is accepted; a private or LAN address only when the owner
confirmed it with ``ai.allow_private_endpoint``; everything else (public
hosts, link-local and metadata addresses, other schemes, URLs that carry
credentials, paths or queries) is refused. A hostname is resolved once and the
connection is pinned to the approved address, so DNS cannot move it later.

``windows-host`` names the Windows host as seen from WSL 2 (the default
gateway of the WSL network). Its address changes between reboots, so it is
looked up on each use and then checked like any other private address.
"""

from __future__ import annotations

import ipaddress
import socket
import struct
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

WINDOWS_HOST = "windows-host"
DEFAULT_PORTS = {"http": 80, "https": 443}

_PRIVATE = tuple(ipaddress.ip_network(cidr) for cidr in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7"))
_LOOPBACK = tuple(ipaddress.ip_network(cidr) for cidr in ("127.0.0.0/8", "::1/128"))


class EndpointRefused(ValueError):
    """The configured endpoint is not allowed by policy; the message says why in plain words."""


@dataclass(frozen=True, slots=True)
class Endpoint:
    """A parsed endpoint URL: scheme, host as written, and port."""

    scheme: str
    host: str
    port: int

    @property
    def display(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{self.scheme}://{host}:{self.port}"


@dataclass(frozen=True, slots=True)
class ResolvedEndpoint:
    """An endpoint approved for use, pinned to one address."""

    endpoint: Endpoint
    address: str
    kind: str  # "loopback" or "private"

    @property
    def pair(self) -> tuple[str, int]:
        return self.address, self.endpoint.port


def parse_endpoint(url: str) -> Endpoint:
    """Check the URL's shape (not its address); raises ``EndpointRefused``."""
    try:
        parts = urlsplit((url or "").strip())
        port = parts.port
    except ValueError as error:
        raise EndpointRefused(f"the AI endpoint is not a valid URL: {error}") from None
    if parts.scheme not in DEFAULT_PORTS:
        raise EndpointRefused("the AI endpoint must start with http:// or https://")
    if parts.username is not None or parts.password is not None:
        raise EndpointRefused("the AI endpoint must not contain a user name or password")
    if not parts.hostname:
        raise EndpointRefused("the AI endpoint has no host")
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        raise EndpointRefused("the AI endpoint must be scheme, host and port only (no path or query)")
    return Endpoint(parts.scheme, parts.hostname.lower(), port or DEFAULT_PORTS[parts.scheme])


def classify(address: str) -> str:
    """``loopback``, ``private`` or ``public`` (link-local, metadata and reserved count as public: refused)."""
    ip = ipaddress.ip_address(address.split("%", 1)[0])
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if any(ip in network for network in _LOOPBACK if network.version == ip.version):
        return "loopback"
    from watchtower.security.destinations import ALWAYS_PROHIBITED_NETWORKS

    if any(ip in network for network in ALWAYS_PROHIBITED_NETWORKS if network.version == ip.version):
        return "public"  # metadata, link-local, reserved: never a model endpoint
    if any(ip in network for network in _PRIVATE if network.version == ip.version):
        return "private"
    return "public"


def wsl_windows_host(route_file: str = "/proc/net/route") -> str | None:
    """The default gateway of this Linux system, which under WSL 2 NAT is the Windows host."""
    try:
        lines = Path(route_file).read_text().splitlines()[1:]
    except OSError:
        return None
    for line in lines:
        fields = line.split()
        if len(fields) > 2 and fields[1] == "00000000" and fields[2] != "00000000":
            return socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))
    return None


def system_resolve(host: str, port: int) -> list[str]:
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return list(dict.fromkeys(info[4][0] for info in infos))


def resolve_endpoint(url: str, *, allow_private: bool,
                     resolve: Callable[[str, int], Iterable[str]] = system_resolve,
                     windows_host: Callable[[], str | None] = wsl_windows_host) -> ResolvedEndpoint:
    """Approve ``url`` for one use and pin it to an address; raises ``EndpointRefused``."""
    endpoint = parse_endpoint(url)
    if endpoint.host == WINDOWS_HOST:
        address = windows_host()
        if address is None:
            raise EndpointRefused("windows-host only works inside WSL 2 with a default route; "
                                  "no Windows host address was found")
        addresses = [address]
    else:
        try:
            addresses = [str(ipaddress.ip_address(endpoint.host))]
        except ValueError:
            try:
                addresses = list(resolve(endpoint.host, endpoint.port))
            except OSError:
                raise EndpointRefused(f"the AI endpoint host {endpoint.host} could not be resolved") from None
    if not addresses:
        raise EndpointRefused(f"the AI endpoint host {endpoint.host} resolved to no addresses")
    kinds = {classify(address) for address in addresses}
    if "public" in kinds:
        raise EndpointRefused("the AI endpoint resolves to a public or reserved address; only a local model is "
                              "allowed (loopback, or a private address you confirm)")
    if "private" in kinds and not allow_private:
        raise EndpointRefused("the AI endpoint is a private network address; set ai.allow_private_endpoint = true "
                              "to confirm it is your own machine")
    return ResolvedEndpoint(endpoint, addresses[0], "private" if "private" in kinds else "loopback")
