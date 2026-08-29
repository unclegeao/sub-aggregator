"""
security.py
------------
SSRF protections for outbound subscription fetches.

The original design ("reject internal addresses") is easy to bypass with:
  1. DNS rebinding: a hostname that resolves to a public IP at check-time but
     a private IP at request-time.
  2. Redirects: an initially-public URL that 302s to http://169.254.169.254/...
  3. IPv6 / alternate representations of loopback and link-local addresses
     (e.g. 0177.0.0.1, ::ffff:127.0.0.1, [::1]).

This module fixes all three by:
  - Resolving the hostname ourselves and validating the resolved IP (not just
    the hostname string) before connecting.
  - Pinning the connection to the validated IP (via requests' HTTPAdapter) so
    a second DNS lookup at connect-time can't return something different.
  - Re-validating on every redirect hop instead of trusting the final URL.
"""

import ipaddress
import socket
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter

MAX_REDIRECTS = 5
FETCH_TIMEOUT = 10  # seconds
MAX_RESPONSE_BYTES = 5 * 1024 * 1024  # 5 MB cap on upstream subscription bodies

_BLOCKED_NETWORKS = [
    ipaddress.ip_network(n)
    for n in [
        "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
        "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
        "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
        "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32",
        "::1/128", "fc00::/7", "fe80::/10", "::ffff:0:0/96", "64:ff9b::/96",
    ]
]


class SSRFBlocked(Exception):
    pass


def _is_blocked_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # unparsable -> treat as unsafe
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        return True
    return any(ip in net for net in _BLOCKED_NETWORKS)


def _resolve_safe(hostname: str) -> str:
    """Resolve hostname to an IP, rejecting anything in a blocked range.
    Returns the first safe IP found."""
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as e:
        raise SSRFBlocked(f"DNS resolution failed for {hostname}: {e}")

    safe_ips = []
    for family, _, _, _, sockaddr in infos:
        ip = sockaddr[0]
        if _is_blocked_ip(ip):
            continue
        safe_ips.append(ip)

    if not safe_ips:
        raise SSRFBlocked(f"{hostname} resolves only to blocked/private addresses")
    return safe_ips[0]


class _PinnedIPAdapter(HTTPAdapter):
    """Forces the TCP connection to a specific IP we already validated,
    so a second (attacker-controlled) DNS answer can't be substituted
    between our check and the actual connect.

    The URL host is rewritten to the pinned IP, but TLS SNI and certificate
    verification must still use the original hostname -- otherwise every
    HTTPS fetch fails with SSLError because the cert is validated against the
    IP, not the domain. requests 2.32+ exposes build_connection_pool_key_attributes
    as the official subclass hook for tweaking connection pool parameters.
    """

    def __init__(self, pinned_ip: str, original_host: str, *args, **kwargs):
        self._pinned_ip = pinned_ip
        self._original_host = original_host
        super().__init__(*args, **kwargs)

    def build_connection_pool_key_attributes(self, request, verify, cert=None):
        host_params, pool_kwargs = super().build_connection_pool_key_attributes(request, verify, cert)
        pool_kwargs["server_hostname"] = self._original_host
        pool_kwargs["assert_hostname"] = self._original_host
        return host_params, pool_kwargs

    def send(self, request, **kwargs):
        parsed = urlparse(request.url)
        original_host = parsed.hostname
        # Rewrite the URL's host to the pinned IP but keep Host header correct via headers.
        request.headers.setdefault("Host", original_host)
        new_netloc = self._pinned_ip
        if parsed.port:
            new_netloc = f"{self._pinned_ip}:{parsed.port}"
        pinned_url = parsed._replace(netloc=new_netloc).geturl()
        request.url = pinned_url
        return super().send(request, **kwargs)


def safe_fetch(url: str, headers: dict | None = None) -> str:
    """Fetch a URL with SSRF protections applied at every redirect hop.
    Returns the response body as text. Raises SSRFBlocked or requests
    exceptions on failure."""
    headers = dict(headers or {})
    headers.setdefault("User-Agent", "sub-aggregator/1.0")

    current_url = url
    for _ in range(MAX_REDIRECTS + 1):
        parsed = urlparse(current_url)
        if parsed.scheme not in ("http", "https"):
            raise SSRFBlocked(f"Blocked scheme: {parsed.scheme}")
        if not parsed.hostname:
            raise SSRFBlocked("Missing hostname")

        safe_ip = _resolve_safe(parsed.hostname)

        session = requests.Session()
        session.mount("http://", _PinnedIPAdapter(safe_ip, parsed.hostname))
        session.mount("https://", _PinnedIPAdapter(safe_ip, parsed.hostname))

        resp = session.get(
            current_url,
            headers=headers,
            timeout=FETCH_TIMEOUT,
            allow_redirects=False,
            stream=True,
            verify=True,
        )

        if resp.is_redirect or resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("Location")
            if not location:
                raise SSRFBlocked("Redirect with no Location header")
            current_url = requests.compat.urljoin(current_url, location)
            continue

        # Enforce a response-size cap while streaming.
        chunks = []
        total = 0
        for chunk in resp.iter_content(chunk_size=65536):
            total += len(chunk)
            if total > MAX_RESPONSE_BYTES:
                raise SSRFBlocked("Response exceeded max allowed size")
            chunks.append(chunk)
        resp.close()
        return b"".join(chunks).decode("utf-8", errors="replace")

    raise SSRFBlocked("Too many redirects")
