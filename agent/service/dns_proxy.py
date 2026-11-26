"""
Local Filtering DNS Proxy Skeleton (Member A — `/agent/service/dns_proxy.py`).

Listens on `127.0.0.1:53` (UDP and TCP) and enforces:
1. NT6 Emergency Whitelist: Domains in `NT6_IMMUTABLE_WHITELIST_DOMAINS` (111, education portals)
   MUST ALWAYS resolve normally and NEVER be blocked.
2. DoH Countermeasure (F2):
   - Return NXDOMAIN for DoH canary domains (`use-application-dns.net`, `mask.icloud.com`, etc.)
   - Block known DoH endpoints (`dns.google`, `cloudflare-dns.com`, etc.) when `policy.block_doh_endpoints` is True.
3. SafeSearch Enforcement (F2):
   - Map `google.com`, `www.google.com`, `bing.com`, `duckduckgo.com` to SafeSearch VIPs/CNAMEs
     (e.g., `forcesafesearch.google.com`, `strict.bing.com`, `safe.duckduckgo.com`).
4. Domain & Subdomain Filtering (F2 + NT4):
   - Match exact domain OR any subdomain (`sub.tiktok.com` matches `tiktok.com`).
   - Return `0.0.0.0` / `NXDOMAIN` (or local block page IP), emit `LocalIPCBlockNotice` to Tray UI
     with `reason` + `created_by`, and enqueue NT2-compliant `blocked_domain` event (second-level domain only!).
5. Upstream Forwarding:
   - Forward allowed queries to upstream resolver (e.g., `1.1.1.1:53` or router DNS) and measure latency for M4 report.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

from contracts.shared_schemas import (
    LocalIPCBlockNotice,
    PolicyConfigPayload,
    is_nt6_protected_domain,
)


@dataclass
class DNSFilterDecision:
    allowed: bool
    action: str  # "ALLOW" | "BLOCK_NXDOMAIN" | "SAFESEARCH_CNAME" | "DOH_CANARY_NXDOMAIN"
    reason: str = ""
    created_by: str = ""
    redirect_target: Optional[str] = None


class DNSProxyServer:
    """Interface for UDP/TCP DNS proxy bound to 127.0.0.1:53."""

    def __init__(
        self,
        listen_host: str = "127.0.0.1",
        listen_port: int = 53,
        upstream_dns: str = "8.8.8.8",
        on_block_callback: Optional[Callable[[LocalIPCBlockNotice], None]] = None,
    ) -> None:
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.upstream_dns = upstream_dns
        self.on_block_callback = on_block_callback
        self._policy: Optional[PolicyConfigPayload] = None

    def update_policy(self, policy: PolicyConfigPayload) -> None:
        """Atomically swap active policy after HMAC verification."""
        self._policy = policy

    def evaluate_domain(self, qname: str) -> DNSFilterDecision:
        """
        Pure policy evaluation function (easy to unit-test with 50 test domains!).

        TODO (Member A):
        1. Normalize `qname` (lowercase, strip trailing dot).
        2. If `is_nt6_protected_domain(qname)` -> return ALLOW immediately.
        3. Check DoH canary domains -> return DOH_CANARY_NXDOMAIN.
        4. Check SafeSearch mapping when `policy.enforce_safesearch` -> return SAFESEARCH_CNAME.
        5. Check `policy.allowed_domains` -> ALLOW.
        6. Check `policy.blocked_domains` & blocked `category_rules` (including subdomains!) -> BLOCK_NXDOMAIN.
        7. Default -> ALLOW.
        """
        domain = qname.strip().lower().rstrip(".")
        if is_nt6_protected_domain(domain):
            return DNSFilterDecision(allowed=True, action="ALLOW", reason="NT6 emergency/education whitelist")
        raise NotImplementedError("Member A: complete DNSProxyServer.evaluate_domain()")

    def start(self) -> None:
        """TODO (Member A): Start UDP & TCP DNS listeners using `dnslib.server` or `socketserver`."""
        raise NotImplementedError("Member A: implement UDP/TCP listener on 127.0.0.1:53")

    def stop(self) -> None:
        """TODO (Member A): Stop DNS listeners cleanly."""
        raise NotImplementedError("Member A: implement DNSProxyServer.stop()")
