"""Resolving the real client address when a reverse proxy is in front.

Why this module exists
----------------------
``request.client.host`` is the address of the process that opened the TCP
connection. Directly reachable, that is the client. Behind nginx it is *nginx*
- the same address for every request in the deployment.

That would quietly break two things this project depends on:

* per-address login lockout would become a single shared bucket, so one attacker
  could lock every account out of sign-in by burning the shared budget;
* the audit trail would record the proxy for every event, destroying its value
  as evidence.

The naive fix - trusting ``X-Forwarded-For`` - is worse, because any client can
send that header. The header is therefore used only to the exact extent the
deployment says it may be, and the address is always read from the **right**,
where a client cannot reach:

    X-Forwarded-For: <anything the client made up>, 203.0.113.7
                     └── never read ──────────────┘  └── the real client,
                                                         written by the proxy

``trusted_proxy_count`` is a claim about the deployment, not about the request.
Getting it wrong in either direction is a real bug, so it is explicit and
defaults to the safe value.
"""

from __future__ import annotations

import ipaddress

__all__ = ["resolve_client_address"]


def _as_ip_literal(value: str) -> str | None:
    """Return a normalised IP literal, or ``None`` if the value is not one.

    Only values that parse as an IP address are ever returned to callers, so no
    header content reaches the audit trail verbatim: a client cannot inject
    arbitrary text, a hostname, or an unbounded string by forging the header.
    """
    candidate = value.strip()
    if not candidate:
        return None

    # Some proxies append a port: "203.0.113.7:41234", or "[2001:db8::1]:443".
    if candidate.startswith("["):
        closing = candidate.find("]")
        if closing != -1:
            candidate = candidate[1:closing]
    elif candidate.count(":") == 1:
        host, _, port = candidate.partition(":")
        if port.isdigit():
            candidate = host

    try:
        parsed = ipaddress.ip_address(candidate)
    except ValueError:
        return None

    # A client reachable over IPv4 can appear as either "203.0.113.7" or
    # "::ffff:203.0.113.7" depending on how the proxy socket was opened. Left
    # alone, the two spellings would be separate lockout buckets, so one client
    # would silently get twice the allowance.
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
        return str(parsed.ipv4_mapped)
    return str(parsed)


def _normalise_peer(peer_address: str | None) -> str | None:
    """Return the socket peer, normalised when possible and verbatim otherwise.

    The peer address is written by the operating system, never by the client, so
    there is nothing to defend against here. It is normalised when it is an IP
    literal (so one client cannot occupy two lockout buckets) and kept as-is
    otherwise, because dropping it would throw away real information - a Unix
    socket peer, or the in-process test client, is not an IP address.
    """
    if not peer_address:
        return None
    return _as_ip_literal(peer_address) or peer_address.strip()[:64] or None


def resolve_client_address(
    peer_address: str | None,
    forwarded_for: str | None,
    trusted_proxy_count: int,
) -> str | None:
    """Return the address a request should be attributed to.

    ``trusted_proxy_count`` is the number of reverse proxies between the client
    and this process:

    * ``0`` (the default) - ``X-Forwarded-For`` is ignored completely and the
      socket peer is returned. Correct when the app is reachable directly.
    * ``1`` - one proxy. The client is the last entry of the header.
    * ``n`` - the client is the ``n``-th entry from the right; everything further
      left was written by the client itself and is never read.

    Returns ``None`` only when there is no usable address at all.
    """
    peer = _normalise_peer(peer_address)

    if trusted_proxy_count <= 0 or not forwarded_for:
        return peer

    # Strict parsing applies to the header only: it is the one client-controlled
    # input here, so nothing that is not a bare IP literal is accepted from it.
    hops = [parsed for parsed in (_as_ip_literal(part) for part in forwarded_for.split(",")) if parsed]
    if not hops:
        return peer

    # Read from the right: the last `trusted_proxy_count` entries are the ones
    # written by proxies we trust. If the header carries fewer entries than the
    # configuration prescribes, the leftmost available value is the best
    # available answer - which is why this count must match the real deployment.
    return hops[-trusted_proxy_count:][0]
