# PART IV: SECURITY AUTOMATION & SYSTEMS PROGRAMMING FOR SECURITY ENGINEERS

---

# CHAPTER 16: PYTHON 3 FOR SECURITY ENGINEERING & NETWORK AUTOMATION

An elite security engineer does not rely passively on off-the-shelf scanners when auditing custom protocols, bespoke microservice architectures, or high-throughput telemetry streams. Python 3 serves as the lingua franca of security automation, network protocol inspection, cryptographic verification, and static/dynamic security tooling. This chapter builds production-grade security automation systems from first principles: raw POSIX/BSD socket programming, TLS handshake and X.509 certificate auditing with `ssl`, high-concurrency HTTP security header and endpoint auditing with `asyncio` and `aiohttp`, Layer 2/3/4 packet crafting and PCAP forensics with `scapy`, and multi-threaded log analysis outputting standardized **SARIF (Static Analysis Results Interchange Format) v2.1.0** reports.

---

## 16.1 Low-Level Socket Programming & TLS Configuration Auditing (`socket` & `ssl`)

### 16.1.1 BSD Socket Architecture in Python 3
At the operating system kernel boundary, network communication is mediated through file descriptors managed via the Berkeley Software Distribution (BSD) socket API (`socket(2)`, `connect(2)`, `bind(2)`, `listen(2)`, `accept(2)`, `send(2)`, `recv(2)`). Python's standard `socket` module provides a thin, direct wrapper over these system calls:

- **Address Families (`domain`):**
  - `socket.AF_INET`: IPv4 networking (`(host, port)` 2-tuple).
  - `socket.AF_INET6`: IPv6 networking (`(host, port, flowinfo, scope_id)` 4-tuple).
  - `socket.AF_UNIX`: Local inter-process communication over Unix domain sockets (filesystem path or abstract namespace).
  - `socket.AF_PACKET` (Linux-only): Raw Layer 2 Ethernet frame access at the device driver level (`ETH_P_ALL`).
- **Socket Types (`type`):**
  - `socket.SOCK_STREAM`: Sequenced, reliable, two-way connection-based byte streams (**TCP**).
  - `socket.SOCK_DGRAM`: Connectionless, unreliable datagrams of fixed maximum length (**UDP**).
  - `socket.SOCK_RAW`: Raw network protocol access (e.g., crafting custom **ICMP** or **IPv4** headers; requires `CAP_NET_RAW`).

```
+-------------------------------------------------------------------------+
|                   CLIENT / AUDITOR SOCKET LIFECYCLE                     |
+-------------------------------------------------------------------------+
  socket(AF_INET, SOCK_STREAM)
       │
       ▼
  setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)  +  settimeout(3.0)
       │
       ▼
  connect((target_ip, target_port)) ──► [ Kernel TCP 3-Way Handshake ]
       │                                      SYN ──►
       │                                      ◄── SYN-ACK
       │                                      ACK ──►
       ▼
  ssl.SSLContext.wrap_socket(sock, server_hostname=sni_host)
       │                                      ClientHello (SNI, ALPN) ──►
       │                                      ◄── ServerHello, Cert, Fin
       ▼
  sendall(request_bytes) / recv(4096)
       │
       ▼
  shutdown(SHUT_RDWR) ──► close()
+-------------------------------------------------------------------------+
```

### 16.1.2 Production TCP Service Banner & TLS Cipher/Certificate Auditor
Security engineers frequently need to verify whether internal and perimeter services enforce **TLS 1.2 / TLS 1.3**, validate X.509 certificate expiration dates, inspect Subject Alternative Names (SANs), check negotiated cipher suites against weak algorithms (`RC4`, `3DES`, `CBC`, null encryption), and capture service banners without triggering intrusive exploit payloads.

Below is a complete, production-ready TCP and TLS Security Configuration Auditor written in Python 3 using `socket`, `ssl`, `concurrent.futures`, and `dataclasses`:

```python
#!/usr/bin/env python3
"""
tls_service_auditor.py
Enterprise TCP Banner & TLS/X.509 Cryptographic Posture Auditor.
Audits negotiated TLS versions, cipher suites, key bit-lengths, certificate validity,
and deprecated protocol acceptance (TLSv1.0 / TLSv1.1) across target endpoints.
"""

from __future__ import annotations
import argparse
import datetime
import json
import socket
import ssl
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional, Tuple


WEAK_CIPHER_SUBSTRINGS: Tuple[str, ...] = (
    "RC4", "DES", "3DES", "MD5", "NULL", "EXP", "ANON", "ADH", "AECDH", "CBC"
)


@dataclass
class TLSAuditFinding:
    host: str
    port: int
    sni_hostname: str
    reachable: bool
    banner: Optional[str] = None
    negotiated_tls_version: Optional[str] = None
    negotiated_cipher_name: Optional[str] = None
    cipher_bits: Optional[int] = None
    alpn_protocol: Optional[str] = None
    cert_subject: Dict[str, str] = field(default_factory=dict)
    cert_issuer: Dict[str, str] = field(default_factory=dict)
    cert_san_dns: List[str] = field(default_factory=list)
    cert_not_before: Optional[str] = None
    cert_not_after: Optional[str] = None
    days_until_expiry: Optional[int] = None
    accepts_deprecated_tls1_0: bool = False
    accepts_deprecated_tls1_1: bool = False
    security_warnings: List[str] = field(default_factory=list)
    error: Optional[str] = None


def parse_x509_name(rdn_sequence: Tuple) -> Dict[str, str]:
    """Flattens an ssl.getpeercert() RDN tuple into a readable key-value dictionary."""
    parsed: Dict[str, str] = {}
    for rdn in rdn_sequence:
        for attr_key, attr_val in rdn:
            parsed[attr_key] = attr_val
    return parsed


def grab_raw_banner(host: str, port: int, timeout: float = 2.5) -> Optional[str]:
    """Connects over raw TCP to capture an initial greeting banner (e.g., SSH, SMTP, FTP)."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            # Send a benign probe only if the server waits for client data on HTTP ports
            if port in (80, 8080, 8000, 8888):
                probe = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
                sock.sendall(probe.encode("ascii"))
            raw_bytes = sock.recv(1024)
            if raw_bytes:
                return raw_bytes.decode("utf-8", errors="replace").strip()[:256]
    except (socket.timeout, OSError):
        pass
    return None


def probe_deprecated_tls_version(
    host: str, port: int, sni: str, tls_version: ssl.TLSVersion, timeout: float = 2.5
) -> bool:
    """Tests whether the target server still accepts a deprecated TLS protocol version."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = tls_version
        ctx.maximum_version = tls_version
        with socket.create_connection((host, port), timeout=timeout) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=sni) as tls_sock:
                return tls_sock.version() is not None
    except (ssl.SSLError, socket.timeout, OSError, ValueError):
        return False


def audit_tls_endpoint(
    host: str, port: int = 443, sni_hostname: Optional[str] = None, timeout: float = 3.5
) -> TLSAuditFinding:
    """Performs a comprehensive TLS handshake, cipher, and certificate audit."""
    sni = sni_hostname or host
    finding = TLSAuditFinding(host=host, port=port, sni_hostname=sni, reachable=False)

    # Step 1: Verify TCP Reachability
    try:
        with socket.create_connection((host, port), timeout=timeout):
            finding.reachable = True
    except (socket.timeout, OSError) as exc:
        finding.error = f"TCP connection failed: {exc}"
        return finding

    # Step 2: Primary TLS Handshake with Certificate Verification
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["h2", "http/1.1"])

    try:
        with socket.create_connection((host, port), timeout=timeout) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=sni) as tls_sock:
                finding.negotiated_tls_version = tls_sock.version()
                cipher_info = tls_sock.cipher()
                if cipher_info:
                    finding.negotiated_cipher_name = cipher_info[0]
                    finding.cipher_bits = cipher_info[2]
                finding.alpn_protocol = tls_sock.selected_alpn_protocol()

                cert = tls_sock.getpeercert()
                if cert:
                    finding.cert_subject = parse_x509_name(cert.get("subject", ()))
                    finding.cert_issuer = parse_x509_name(cert.get("issuer", ()))
                    finding.cert_not_before = cert.get("notBefore")
                    finding.cert_not_after = cert.get("notAfter")
                    finding.cert_san_dns = [
                        val for key, val in cert.get("subjectAltName", ()) if key == "DNS"
                    ]

                    if finding.cert_not_after:
                        expiry_dt = datetime.datetime.strptime(
                            finding.cert_not_after, "%b %d %H:%M:%S %Y %Z"
                        ).replace(tzinfo=datetime.timezone.utc)
                        now_utc = datetime.datetime.now(datetime.timezone.utc)
                        finding.days_until_expiry = (expiry_dt - now_utc).days
                        if finding.days_until_expiry < 0:
                            finding.security_warnings.append("CRITICAL: X.509 certificate is EXPIRED.")
                        elif finding.days_until_expiry < 30:
                            finding.security_warnings.append(
                                f"WARNING: X.509 certificate expires in {finding.days_until_expiry} days."
                            )

    except ssl.SSLCertVerificationError as cert_err:
        finding.security_warnings.append(
            f"HIGH: Certificate verification failed ({cert_err.verify_message})."
        )
        # Fallback unverified inspection to still extract cipher & protocol metadata
        try:
            unverified_ctx = ssl._create_unverified_context()
            with socket.create_connection((host, port), timeout=timeout) as raw_sock:
                with unverified_ctx.wrap_socket(raw_sock, server_hostname=sni) as tls_sock:
                    finding.negotiated_tls_version = tls_sock.version()
                    cipher_info = tls_sock.cipher()
                    if cipher_info:
                        finding.negotiated_cipher_name = cipher_info[0]
                        finding.cipher_bits = cipher_info[2]
        except Exception as fallback_exc:
            finding.error = f"TLS handshake failed: {fallback_exc}"
            return finding
    except (ssl.SSLError, OSError) as tls_err:
        # Target might be a non-TLS plaintext service; grab raw banner instead
        finding.banner = grab_raw_banner(host, port, timeout=timeout)
        finding.error = f"Non-TLS or failed TLS handshake: {tls_err}"
        return finding

    # Step 3: Evaluate Cipher Suite & Protocol Strength
    if finding.negotiated_cipher_name:
        upper_cipher = finding.negotiated_cipher_name.upper()
        for weak_token in WEAK_CIPHER_SUBSTRINGS:
            if weak_token in upper_cipher:
                finding.security_warnings.append(
                    f"MEDIUM: Negotiated cipher '{finding.negotiated_cipher_name}' contains weak primitive '{weak_token}'."
                )
    if finding.cipher_bits is not None and finding.cipher_bits < 128:
        finding.security_warnings.append(
            f"HIGH: Weak symmetric key length ({finding.cipher_bits} bits < 128 bits)."
        )

    # Step 4: Probe Deprecated TLSv1.0 and TLSv1.1 Support (RFC 8996 Deprecation)
    if hasattr(ssl.TLSVersion, "TLSv1"):
        finding.accepts_deprecated_tls1_0 = probe_deprecated_tls_version(
            host, port, sni, ssl.TLSVersion.TLSv1, timeout
        )
        if finding.accepts_deprecated_tls1_0:
            finding.security_warnings.append("HIGH: Server accepts deprecated TLSv1.0 (RFC 8996).")
    if hasattr(ssl.TLSVersion, "TLSv1_1"):
        finding.accepts_deprecated_tls1_1 = probe_deprecated_tls_version(
            host, port, sni, ssl.TLSVersion.TLSv1_1, timeout
        )
        if finding.accepts_deprecated_tls1_1:
            finding.security_warnings.append("MEDIUM: Server accepts deprecated TLSv1.1 (RFC 8996).")

    return finding
```

---

## 16.2 High-Concurrency Asynchronous HTTP & API Security Auditing (`asyncio` & `aiohttp`)

### 16.2.1 Why `asyncio` Outperforms OS Threads for Network I/O
Traditional synchronous scanners spawn one operating system thread per target connection. Because each OS thread allocates stack memory and incurs kernel context-switching overhead, thread-based scanners degrade past a few hundred concurrent connections. Python's **`asyncio`** event loop uses a single-threaded cooperative multitasking architecture backed by the OS kernel's non-blocking event notification primitives (**`epoll(7)`** on Linux, **`kqueue(2)`** on BSD/macOS, **`IOCP`** on Windows). A single Python process using `asyncio` + `aiohttp` paired with an `asyncio.Semaphore` rate limiter can audit thousands of web endpoints per second with deterministic memory usage.

### 16.2.2 Production Asynchronous HTTP Security Header, CORS & Cookie Posture Auditor

```python
#!/usr/bin/env python3
"""
async_http_security_auditor.py
Asynchronous Web & API Security Posture Auditor using asyncio and aiohttp.
Audits HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy,
Permissions-Policy, CORS Origin Reflection, Server Banner Leakage, and Cookie Flags.
"""

from __future__ import annotations
import asyncio
import json
import ssl
import time
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional
import aiohttp


REQUIRED_SECURITY_HEADERS: Dict[str, str] = {
    "strict-transport-security": "Missing HSTS header (vulnerable to SSL stripping / downgrade).",
    "content-security-policy": "Missing Content-Security-Policy (CSP) header (elevated XSS impact).",
    "x-content-type-options": "Missing 'X-Content-Type-Options: nosniff' (MIME-sniffing risk).",
    "x-frame-options": "Missing X-Frame-Options header (check if CSP frame-ancestors is present).",
    "referrer-policy": "Missing Referrer-Policy header (potential URL token/parameter leakage).",
    "permissions-policy": "Missing Permissions-Policy header (browser feature restriction).",
}

INFORMATION_DISCLOSURE_HEADERS: Tuple[str, ...] = (
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
)


@dataclass
class CookieFinding:
    name: str
    secure: bool
    httponly: bool
    samesite: Optional[str]
    issues: List[str] = field(default_factory=list)


@dataclass
class EndpointSecurityReport:
    url: str
    status_code: Optional[int] = None
    response_time_ms: float = 0.0
    missing_headers: List[str] = field(default_factory=list)
    weak_header_configs: List[str] = field(default_factory=list)
    disclosed_banners: Dict[str, str] = field(default_factory=dict)
    cors_misconfiguration: Optional[str] = None
    cookie_findings: List[CookieFinding] = field(default_factory=list)
    error: Optional[str] = None


def parse_and_audit_set_cookie(raw_cookie_headers: List[str], is_https: bool) -> List[CookieFinding]:
    """Inspects raw Set-Cookie headers for Secure, HttpOnly, SameSite, and __Host- prefix compliance."""
    findings: List[CookieFinding] = []
    for raw in raw_cookie_headers:
        parts = [p.strip() for p in raw.split(";")]
        if not parts:
            continue
        name_val = parts[0].split("=", 1)
        cookie_name = name_val[0].strip()
        attrs_lower = [p.lower() for p in parts[1:]]

        has_secure = "secure" in attrs_lower
        has_httponly = "httponly" in attrs_lower
        samesite_val: Optional[str] = None
        has_domain = False
        path_val: Optional[str] = None

        for attr in attrs_lower:
            if attr.startswith("samesite="):
                samesite_val = attr.split("=", 1)[1]
            elif attr.startswith("domain="):
                has_domain = True
            elif attr.startswith("path="):
                path_val = attr.split("=", 1)[1]

        issues: List[str] = []
        if is_https and not has_secure:
            issues.append("Cookie transmitted over HTTPS lacks 'Secure' flag.")
        if not has_httponly:
            issues.append("Cookie lacks 'HttpOnly' flag (accessible to document.cookie during XSS).")
        if samesite_val is None:
            issues.append("Cookie lacks explicit 'SameSite' attribute (Strict or Lax recommended).")
        elif samesite_val == "none" and not has_secure:
            issues.append("CRITICAL: 'SameSite=None' set without 'Secure' flag.")

        if cookie_name.startswith("__Host-"):
            if not has_secure or has_domain or path_val != "/":
                issues.append("Invalid '__Host-' cookie prefix requirements (must have Secure, Path=/, and no Domain).")

        findings.append(
            CookieFinding(
                name=cookie_name,
                secure=has_secure,
                httponly=has_httponly,
                samesite=samesite_val,
                issues=issues,
            )
        )
    return findings


async def audit_single_url(
    session: aiohttp.ClientSession,
    semaphore: asyncio.Semaphore,
    url: str,
    canary_origin: str = "https://evil-cors-audit.example.com",
) -> EndpointSecurityReport:
    """Audits a single URL for HTTP security headers, cookie flags, and arbitrary CORS origin reflection."""
    report = EndpointSecurityReport(url=url)
    start_ts = time.perf_counter()

    # Send a benign request including an arbitrary Origin header to test for naive CORS reflection
    req_headers = {
        "User-Agent": "Enterprise-AppSec-Auditor/2.0 (Authorized Security Assessment)",
        "Origin": canary_origin,
    }

    async with semaphore:
        try:
            async with session.get(url, headers=req_headers, allow_redirects=True) as resp:
                report.response_time_ms = round((time.perf_counter() - start_ts) * 1000.0, 2)
                report.status_code = resp.status
                headers_lower = {k.lower(): v for k, v in resp.headers.items()}

                # 1. Check Required Security Headers
                for hdr_key, warning_msg in REQUIRED_SECURITY_HEADERS.items():
                    if hdr_key not in headers_lower:
                        # Exempt X-Frame-Options if CSP frame-ancestors is explicitly configured
                        if hdr_key == "x-frame-options" and "frame-ancestors" in headers_lower.get(
                            "content-security-policy", ""
                        ):
                            continue
                        report.missing_headers.append(f"{hdr_key}: {warning_msg}")

                # 2. Evaluate CSP Strength if Present
                csp_val = headers_lower.get("content-security-policy", "")
                if csp_val:
                    if "'unsafe-inline'" in csp_val and "'strict-dynamic'" not in csp_val:
                        report.weak_header_configs.append(
                            "CSP permits 'unsafe-inline' without 'strict-dynamic' (weakens XSS protection)."
                        )
                    if "'unsafe-eval'" in csp_val:
                        report.weak_header_configs.append(
                            "CSP permits 'unsafe-eval' (allows dynamic code evaluation via eval/Function)."
                        )

                # 3. Evaluate HSTS max-age if Present
                hsts_val = headers_lower.get("strict-transport-security", "")
                if hsts_val and "max-age=" in hsts_val.lower():
                    try:
                        max_age_str = hsts_val.lower().split("max-age=")[1].split(";")[0].strip()
                        if int(max_age_str) < 31536000:
                            report.weak_header_configs.append(
                                f"HSTS max-age ({max_age_str}s) is less than 1 year (31536000s)."
                            )
                    except ValueError:
                        pass

                # 4. Check Server & Framework Banner Disclosure
                for banner_hdr in INFORMATION_DISCLOSURE_HEADERS:
                    if banner_hdr in headers_lower:
                        report.disclosed_banners[banner_hdr] = headers_lower[banner_hdr]

                # 5. Check CORS Origin Reflection + Credentials Misconfiguration
                acao = headers_lower.get("access-control-allow-origin")
                acac = headers_lower.get("access-control-allow-credentials", "").lower()
                if acao == canary_origin and acac == "true":
                    report.cors_misconfiguration = (
                        f"CRITICAL CORS FLAW: Server reflects arbitrary Origin '{canary_origin}' "
                        f"with 'Access-Control-Allow-Credentials: true'."
                    )
                elif acao == "*" and acac == "true":
                    report.cors_misconfiguration = (
                        "HIGH CORS FLAW: Wildcard Access-Control-Allow-Origin '*' combined with Credentials."
                    )

                # 6. Audit Set-Cookie Headers
                raw_cookies = resp.headers.getall("Set-Cookie", [])
                report.cookie_findings = parse_and_audit_set_cookie(
                    raw_cookies, is_https=url.lower().startswith("https://")
                )

        except Exception as exc:
            report.response_time_ms = round((time.perf_counter() - start_ts) * 1000.0, 2)
            report.error = str(exc)

    return report


async def run_batch_http_audit(urls: List[str], concurrency: int = 25, timeout_sec: float = 8.0) -> List[EndpointSecurityReport]:
    """Executes bounded asynchronous security audits across a list of target URLs."""
    semaphore = asyncio.Semaphore(concurrency)
    timeout = aiohttp.ClientTimeout(total=timeout_sec)
    ssl_ctx = ssl.create_default_context()

    connector = aiohttp.TCPConnector(limit=concurrency, ssl=ssl_ctx)
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        tasks = [audit_single_url(session, semaphore, u) for u in urls]
        return await asyncio.gather(*tasks)
```

---

## 16.3 Packet Crafting, Protocol Dissection & PCAP Forensics with `scapy`

### 16.3.1 Scapy's Layered Packet Composition Model
**`Scapy`** represents network packets as algebraic compositions of protocol layers stacked with the `/` operator:
$$\text{Frame} = \text{Ether}() / \text{IP}() / \text{TCP}() / \text{Raw}()$$
When a lower layer is stacked with an upper layer, Scapy automatically populates binding fields (such as setting `Ether.type = 0x0800` when stacked with `IP()`, and `IP.proto = 6` when stacked with `TCP()`) and calculates checksums and payload lengths upon transmission.

| Scapy Function | Layer | Description |
| :--- | :--- | :--- |
| `send(pkt)` | Layer 3 (`IP`) | Transmits Layer 3 packets using the OS kernel routing table (does not receive replies). |
| `sendp(pkt, iface=...)` | Layer 2 (`Ether`) | Transmits raw Layer 2 Ethernet frames out a specified network interface. |
| `sr(pkt)` / `sr1(pkt)` | Layer 3 (`IP`) | Sends Layer 3 packets and receives `(answered, unanswered)` couples (`sr1` returns only the first reply packet). |
| `srp(pkt)` | Layer 2 (`Ether`) | Sends and receives Layer 2 Ethernet frames (used for ARP scanning and VLAN/STP auditing). |
| `sniff(filter=..., prn=...)` | L2 / L3 | Captures live packets matching a Berkeley Packet Filter (BPF) expression and invokes a callback function `prn`. |
| `rdpcap()` / `wrpcap()` | File I/O | Reads or writes standard `libpcap` `.pcap` capture files for offline forensics. |

### 16.3.2 Offline PCAP Anomaly & Cleartext Credential / SYN-Scan Forensics Engine
Rather than transmitting active packets, blue-team and incident-response engineers frequently use Scapy to parse forensic `.pcap` captures to detect TCP SYN port scans, ARP poisoning anomalies, and cleartext protocol exposures:

```python
#!/usr/bin/env python3
"""
pcap_forensics_analyzer.py
Offline PCAP Network Forensics & Intrusion Detection Analyzer using Scapy.
Detects:
  1. TCP Half-Open SYN Port Scanning (high unique destination ports with SYN-only flags).
  2. ARP Cache Poisoning / Gratuitous ARP MAC-to-IP conflicts.
  3. DNS Tunneling / High-Entropy Subdomain Queries.
"""

from __future__ import annotations
import math
from collections import Counter, defaultdict
from typing import Dict, List, Set
from scapy.all import ARP, DNS, DNSQR, IP, TCP, rdpcap


def shannon_entropy(data: str) -> float:
    """Computes the Shannon entropy (bits per character) of a string."""
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def analyze_pcap_capture(pcap_path: str, syn_scan_threshold: int = 25) -> Dict[str, object]:
    """Parses a PCAP file and extracts SYN scan sources, ARP conflicts, and high-entropy DNS queries."""
    packets = rdpcap(pcap_path)

    # Trackers
    syn_targets_by_src: Dict[str, Set[int]] = defaultdict(set)
    arp_ip_to_macs: Dict[str, Set[str]] = defaultdict(set)
    suspicious_dns_queries: List[Dict[str, object]] = []

    for pkt in packets:
        # 1. Inspect TCP SYN Packets (Flags == 0x02 'S' without ACK)
        if pkt.haslayer(IP) and pkt.haslayer(TCP):
            ip_layer = pkt[IP]
            tcp_layer = pkt[TCP]
            if tcp_layer.flags == "S":
                syn_targets_by_src[ip_layer.src].add(int(tcp_layer.dport))

        # 2. Inspect ARP Replies (op == 2 'is-at') for MAC Spoofing Conflicts
        if pkt.haslayer(ARP):
            arp_layer = pkt[ARP]
            if arp_layer.op == 2:  # is-at (ARP Reply)
                arp_ip_to_macs[arp_layer.psrc].add(arp_layer.hwsrc.lower())

        # 3. Inspect DNS Queries for High-Entropy Tunneling Indicators
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR) and pkt[DNS].qr == 0:
            qname_raw = pkt[DNSQR].qname
            qname = qname_raw.decode("utf-8", errors="ignore").rstrip(".")
            labels = qname.split(".")
            if len(labels) >= 3:
                subdomain = "".join(labels[:-2])
                entropy = shannon_entropy(subdomain)
                if len(subdomain) > 32 and entropy > 3.8:
                    src_ip = pkt[IP].src if pkt.haslayer(IP) else "unknown"
                    suspicious_dns_queries.append(
                        {
                            "src_ip": src_ip,
                            "qname": qname,
                            "subdomain_length": len(subdomain),
                            "shannon_entropy": round(entropy, 3),
                        }
                    )

    # Compile Alerts
    syn_scanners = {
        src_ip: len(ports)
        for src_ip, ports in syn_targets_by_src.items()
        if len(ports) >= syn_scan_threshold
    }
    arp_conflicts = {
        ip_addr: sorted(list(macs))
        for ip_addr, macs in arp_ip_to_macs.items()
        if len(macs) > 1
    }

    return {
        "total_packets_parsed": len(packets),
        "detected_syn_scanners": syn_scanners,
        "detected_arp_spoofing_conflicts": arp_conflicts,
        "suspicious_high_entropy_dns_queries": suspicious_dns_queries,
    }
```

---

## 16.4 Log Parsing, Regex Extraction & SARIF v2.1.0 Report Generation

### 16.4.1 Automated Log Anomaly & SARIF CLI Tool (`argparse` + `re`)
Modern DevSecOps pipelines (GitHub Advanced Security, GitLab Security Dashboard, DefectDojo, Azure DevOps) ingest security findings in **SARIF (Static Analysis Results Interchange Format) v2.1.0** (OASIS Standard). The following tool demonstrates how to combine `argparse`, compiled regular expressions, and structured SARIF JSON generation:

```python
#!/usr/bin/env python3
"""
sarif_secret_scanner.py
CLI Source & Config Secret Scanner that outputs OASIS SARIF v2.1.0 JSON reports.
"""

from __future__ import annotations
import argparse
import json
import pathlib
import re
import sys
from typing import Dict, List, NamedTuple, Pattern


class SecretRule(NamedTuple):
    rule_id: str
    name: str
    description: str
    cwe_id: str
    regex: Pattern[str]


SECRET_RULES: List[SecretRule] = [
    SecretRule(
        rule_id="SEC001",
        name="AWS Access Key ID",
        description="Detects hardcoded AWS IAM Access Key IDs (AKIA/ASIA).",
        cwe_id="CWE-798",
        regex=re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"),
    ),
    SecretRule(
        rule_id="SEC002",
        name="PEM Private Key Block",
        description="Detects hardcoded RSA, EC, DSA, or OpenSSH private key blocks.",
        cwe_id="CWE-321",
        regex=re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    ),
    SecretRule(
        rule_id="SEC003",
        name="Generic High-Entropy API Secret Assignment",
        description="Detects hardcoded api_key, secret_key, or jwt_secret string assignments.",
        cwe_id="CWE-798",
        regex=re.compile(
            r"(?i)\b(?:api_key|secret_key|jwt_secret|db_pass(?:word)?)\s*[:=]\s*['\"]([A-Za-z0-9_\-!@#$%^&*]{16,})['\"]"
        ),
    ),
]


def scan_directory_to_sarif(root_dir: pathlib.Path) -> Dict[str, object]:
    """Scans text files under root_dir and constructs a SARIF v2.1.0 report."""
    results: List[Dict[str, object]] = []

    for file_path in root_dir.rglob("*"):
        if not file_path.is_file() or ".git" in file_path.parts:
            continue
        try:
            lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue

        rel_uri = file_path.relative_to(root_dir).as_posix()
        for line_idx, line_content in enumerate(lines, start=1):
            for rule in SECRET_RULES:
                if rule.regex.search(line_content):
                    results.append(
                        {
                            "ruleId": rule.rule_id,
                            "level": "error",
                            "message": {"text": f"{rule.name} detected ({rule.cwe_id})."},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": rel_uri},
                                        "region": {"startLine": line_idx},
                                    }
                                }
                            ],
                        }
                    )

    sarif_report: Dict[str, object] = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "EnterpriseSecretScanner",
                        "version": "1.0.0",
                        "rules": [
                            {
                                "id": r.rule_id,
                                "name": r.name,
                                "shortDescription": {"text": r.description},
                                "properties": {"cwe": r.cwe_id},
                            }
                            for r in SECRET_RULES
                        ],
                    }
                },
                "results": results,
            }
        ],
    }
    return sarif_report


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan repository for secrets and emit SARIF v2.1.0.")
    parser.add_argument("target_dir", type=pathlib.Path, help="Path to source directory to scan")
    parser.add_argument("-o", "--output", type=pathlib.Path, help="Output SARIF file path")
    args = parser.parse_args()

    sarif_data = scan_directory_to_sarif(args.target_dir.resolve())
    sarif_json = json.dumps(sarif_data, indent=2)
    if args.output:
        args.output.write_text(sarif_json, encoding="utf-8")
    else:
        print(sarif_json)
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

---

# CHAPTER 17: JAVASCRIPT, TYPESCRIPT & NODE.JS SECURITY ENGINEERING

JavaScript and TypeScript power both the browser Document Object Model (DOM) and backend Node.js microservices. Understanding the security boundaries of the V8 engine—specifically the **Same-Origin Policy (SOP)**, cross-window `postMessage` channels, Web Storage versus `HttpOnly` cookies, **Prototype Chain (`__proto__`) mechanics**, and Abstract Syntax Tree (AST) static analysis—is essential for both application security engineers and full-stack architects.

---

## 17.1 Browser DOM Internals, Same-Origin Policy (SOP) & Storage Security

### 17.1.1 Exact Definition of an Origin (RFC 6454)
Two URLs share the **Same Origin** if and only if all three components of the tuple match identically:
$$\text{Origin} = (\text{Scheme / Protocol}, \text{Fully Qualified Hostname}, \text{Port})$$

| Candidate URL | Compared Against `https://portal.bank.lk:443/app/index.html` | Same Origin? | Reason |
| :--- | :--- | :--- | :--- |
| `https://portal.bank.lk/api/v1/user` | `https://portal.bank.lk:443/...` | **YES** | Scheme (`https`), Host (`portal.bank.lk`), and implicit Port (`443`) match. |
| `http://portal.bank.lk:443/app` | `https://portal.bank.lk:443/...` | **NO** | Different scheme (`http` vs `https`). |
| `https://portal.bank.lk:8443/app` | `https://portal.bank.lk:443/...` | **NO** | Different port (`8443` vs `443`). |
| `https://api.bank.lk/v1/status` | `https://portal.bank.lk:443/...` | **NO** | Different hostname (`api.bank.lk` vs `portal.bank.lk`). *(Note: They are **Same-Site** under eTLD+1 `bank.lk`, but **Cross-Origin**!)* |

**Crucial Distinction Between Cross-Origin Writes, Embeds, and Reads:**
1. **Cross-Origin Writes** (e.g., HTML `<form action="...">` submissions, navigations) are **generally permitted** by default—which is why **CSRF** exists and requires `SameSite` cookies or anti-CSRF tokens.
2. **Cross-Origin Embeds** (e.g., `<script src="...">`, `<img src="...">`, `<iframe src="...">`) are **generally permitted** unless restricted by `Content-Security-Policy`, `Cross-Origin-Resource-Policy (CORP)`, or `X-Frame-Options`.
3. **Cross-Origin Reads** (e.g., reading `fetch()` / `XMLHttpRequest` response bodies or accessing `iframe.contentWindow.document` across origins) are **strictly blocked by SOP** unless explicitly permitted via CORS headers.

### 17.1.2 Securing Cross-Origin `window.postMessage()` Channels
`window.postMessage(message, targetOrigin)` provides a controlled mechanism for cross-origin communication between a parent window and an embedded `<iframe>` or popup. Two classic vulnerabilities occur when `postMessage` is implemented insecurely:

1. **Sender Flaw (Wildcard `targetOrigin = "*"`):** Passing `"*"` as the second argument (`iframe.contentWindow.postMessage(sensitiveJwt, "*")`) broadcasts the secret to whatever origin the iframe has navigated to. Always specify the exact expected origin (`"https://checkout.bank.lk"`).
2. **Receiver Flaw (Missing `event.origin` Verification & Unsafe DOM Sink):** Registering `window.addEventListener("message", callback)` without verifying `event.origin` allows **any tab or iframe on the internet** to send arbitrary messages to the listener.

```typescript
// VULNERABLE postMessage Receiver (CWE-346 + DOM XSS CWE-79)
window.addEventListener("message", (event: MessageEvent) => {
    // FLAW 1: Weak substring check! Bypassed by "https://portal.bank.lk.attacker.com"
    if (event.origin.indexOf("portal.bank.lk") !== -1) {
        // FLAW 2: Unsafe DOM sink (innerHTML)
        document.getElementById("notification-banner")!.innerHTML = event.data.html;
    }
});

// REMEDIATED postMessage Receiver (Strict Origin Allowlist + Safe DOM API)
const TRUSTED_ORIGINS: ReadonlySet<string> = new Set([
    "https://portal.bank.lk",
    "https://sso.bank.lk"
]);

window.addEventListener("message", (event: MessageEvent) => {
    // 1. Strict exact-match origin verification against immutable Set
    if (!TRUSTED_ORIGINS.has(event.origin)) {
        console.warn(`Blocked untrusted postMessage from origin: ${event.origin}`);
        return;
    }

    // 2. Runtime schema & type validation
    if (typeof event.data !== "object" || event.data === null || typeof event.data.noticeText !== "string") {
        return;
    }

    // 3. Assign strictly via textContent (never innerHTML or eval)
    const banner = document.getElementById("notification-banner");
    if (banner) {
        banner.textContent = event.data.noticeText;
    }
});
```

### 17.1.3 `localStorage` / `sessionStorage` vs. `HttpOnly` Cookies for Session Tokens
| Storage Mechanism | Accessible to JavaScript (`XSS`)? | Sent Automatically on Cross-Site Requests (`CSRF`)? | Recommended Security Engineering Pattern |
| :--- | :--- | :--- | :--- |
| **`localStorage` / `sessionStorage`** | **YES (`localStorage.getItem('jwt')`)** — Any single XSS vulnerability or malicious npm frontend dependency can exfiltrate the raw token immediately. | **NO** — Must be attached manually via `Authorization: Bearer` header. | **Never store long-lived refresh tokens or high-privilege session tokens in `localStorage`.** Use only for non-sensitive UI state (theme, locale). |
| **`__Host-` Cookie with `HttpOnly; Secure; SameSite=Strict`** | **NO** — `document.cookie` cannot read or overwrite an `HttpOnly` `__Host-` cookie. | Controlled via `SameSite=Strict` / `Lax` + custom anti-CSRF header (`X-Requested-With` / CSRF token). | **Gold Standard (BFF — Backend-For-Frontend Pattern):** Store session/refresh credentials in `HttpOnly; Secure; SameSite=Lax` `__Host-` cookies. |

---

## 17.2 JavaScript Prototype Chain Mechanics & Prototype Pollution (`CWE-1321`)

### 17.2.1 How the V8 Prototype Chain Works Under the Hood
JavaScript uses **prototypal inheritance**. Every standard object `obj = {}` created via object literal syntax or `JSON.parse()` holds an internal hidden link `[[Prototype]]` (exposed via the getter/setter property **`__proto__`** or `Object.getPrototypeOf(obj)`) pointing to **`Object.prototype`**. Furthermore, `obj.constructor` points to the `Object` constructor function, and `obj.constructor.prototype` also resolves directly to **`Object.prototype`**:

```
  const user = { id: 101, name: "Kasun" };

  [ user instance ]
    ├── id: 101
    ├── name: "Kasun"
    └── [[Prototype]] (__proto__) ──────┐
                                        ▼
                        [ Object.prototype (Global Singleton) ]
                          ├── toString: function()
                          ├── hasOwnProperty: function()
                          ├── constructor: [Function: Object] ──► (.prototype points back here!)
                          └── [[Prototype]]: null
```

When JavaScript evaluates a property lookup `user.isAdmin`:
1. The engine checks if `"isAdmin"` is an **own property** on `user` itself (`Object.hasOwn(user, "isAdmin")`). It is not found.
2. The engine traverses `user.[[Prototype]]` up to **`Object.prototype`** and checks if `"isAdmin"` exists on `Object.prototype`.
3. If an attacker has polluted `Object.prototype.isAdmin = true`, then **every object in the entire Node.js process or browser tab** that does not explicitly define its own `isAdmin` property will evaluate `obj.isAdmin` as `true`!

### 17.2.2 Root Cause of Prototype Pollution in Recursive Merge & Path-Assignment Functions

```javascript
// VULNERABLE CODE: Classic Unsafe Recursive Object Merge (CWE-1321)
function unsafeDeepMerge(target, source) {
    for (const key of Object.keys(source)) {
        if (typeof source[key] === "object" && source[key] !== null) {
            if (!target[key]) {
                target[key] = {};
            }
            // FLAW: When key === "__proto__", target["__proto__"] resolves to Object.prototype!
            // Recursing into unsafeDeepMerge(Object.prototype, source["__proto__"]) mutates
            // the global Object.prototype singleton for the entire Node.js runtime!
            unsafeDeepMerge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

// Demonstration of Pollution:
const untrustedPayload = JSON.parse('{"__proto__": {"isAdmin": true, "role": "SUPERUSER"}}');
unsafeDeepMerge({}, untrustedPayload);

const normalCustomer = { username: "guest_user" };
console.log(normalCustomer.isAdmin); // Output: true  (Global Prototype Polluted!)
console.log(normalCustomer.role);    // Output: "SUPERUSER"
```

### 17.2.3 Writing Pollution-Proof TypeScript / Node.js Code
To eliminate Prototype Pollution completely across a codebase, apply four defense-in-depth engineering practices:

1. **Block Dangerous Keys (`__proto__`, `constructor`, `prototype`) & Use `Object.hasOwn()`:**
2. **Use Null-Prototype Dictionaries (`Object.create(null)`) or `Map<K, V>` for Dynamic Key-Value Lookups:**
3. **Validate Untrusted JSON Payloads with `Zod` Schema Validation (Stripping Unknown Keys):**
4. **Freeze `Object.prototype` at Application Startup (`Object.freeze(Object.prototype)`):**

```typescript
// REMEDIATED CODE: Pollution-Safe Deep Merge + Zod Schema Validation in TypeScript
import { z } from "zod";

const FORBIDDEN_PROTOTYPE_KEYS: ReadonlySet<string> = new Set([
    "__proto__",
    "constructor",
    "prototype",
]);

export function safeDeepMerge<T extends Record<string, unknown>>(
    target: T,
    source: Record<string, unknown>
): T {
    for (const key of Object.keys(source)) {
        // 1. Explicitly reject prototype-walking keys
        if (FORBIDDEN_PROTOTYPE_KEYS.has(key)) {
            throw new SecurityError(`Blocked prototype pollution attempt via key: ${key}`);
        }

        // 2. Ensure the key is a direct own property of source
        if (!Object.hasOwn(source, key)) {
            continue;
        }

        const sourceVal = source[key];
        const targetVal = Object.hasOwn(target, key) ? target[key] : undefined;

        if (
            typeof sourceVal === "object" &&
            sourceVal !== null &&
            !Array.isArray(sourceVal)
        ) {
            const nextTarget =
                typeof targetVal === "object" && targetVal !== null && !Array.isArray(targetVal)
                    ? (targetVal as Record<string, unknown>)
                    : Object.create(null); // Null-prototype object has no __proto__ chain!
            (target as Record<string, unknown>)[key] = safeDeepMerge(
                nextTarget,
                sourceVal as Record<string, unknown>
            );
        } else {
            (target as Record<string, unknown>)[key] = sourceVal;
        }
    }
    return target;
}

class SecurityError extends Error {
    constructor(message: string) {
        super(message);
        this.name = "SecurityError";
    }
}

// Strict Zod Schema Validation (rejects unknown keys and strips __proto__)
export const UpdateUserConfigSchema = z
    .object({
        displayName: z.string().min(1).max(64),
        theme: z.enum(["light", "dark", "system"]),
        notificationsEnabled: z.boolean(),
    })
    .strict();
```

---

## 17.3 Building an AST-Based Static Security Linter in Node.js

Regular-expression scanners frequently suffer from high false-positive rates because regexes cannot distinguish between code inside comments, string literals, or actual executable syntax nodes. True Static Application Security Testing (SAST) tools parse source code into an **Abstract Syntax Tree (AST)** (following the **ESTree** specification in JavaScript/TypeScript) and walk the tree to inspect `CallExpression`, `MemberExpression`, and `AssignmentExpression` nodes.

Below is a complete AST-based JavaScript Security Linter built using Node.js and `acorn` (or `@babel/parser`) that detects:
1. Dynamic code execution via `eval()` or `new Function()`.
2. OS Command Injection sinks via `child_process.exec()` / `execSync()` when passed non-literal arguments (such as template literals `` `ping ${userInput}` `` or binary string concatenations).
3. Unsafe DOM XSS assignments to `.innerHTML` or `.outerHTML`.
4. Weak cryptographic hashing (`crypto.createHash('md5')` or `'sha1'`).

```javascript
#!/usr/bin/env node
/**
 * ast_security_linter.js
 * ESTree Abstract Syntax Tree (AST) Static Application Security Testing (SAST) Linter for JS/Node.js.
 * Zero-regex AST walker that inspects CallExpressions, NewExpressions, and AssignmentExpressions.
 */

"use strict";

const fs = require("fs");
const path = require("path");
const vm = require("vm");

/**
 * Lightweight recursive ESTree AST walker.
 * @param {object} node - Current ESTree AST node
 * @param {(node: object) => void} visitor - Callback invoked on every AST node
 */
function walkAst(node, visitor) {
    if (!node || typeof node !== "object") return;
    visitor(node);
    for (const key of Object.keys(node)) {
        const child = node[key];
        if (Array.isArray(child)) {
            for (const item of child) {
                if (item && typeof item.type === "string") {
                    walkAst(item, visitor);
                }
            }
        } else if (child && typeof child.type === "string") {
            walkAst(child, visitor);
        }
    }
}

/**
 * Audits an ESTree AST for high-risk security sinks.
 * @param {object} ast - Parsed ESTree Program root node
 * @param {string} filePath - Source file name for reporting
 * @returns {Array<object>} List of discovered SAST findings
 */
function analyzeAstForVulnerabilities(ast, filePath) {
    const findings = [];

    walkAst(ast, (node) => {
        const line = node.loc ? node.loc.start.line : 0;

        // Rule 1: Detect eval(...) or setTimeout("string", ...)
        if (
            node.type === "CallExpression" &&
            node.callee.type === "Identifier" &&
            node.callee.name === "eval"
        ) {
            findings.push({
                ruleId: "JS-SAST-001",
                cwe: "CWE-95",
                severity: "HIGH",
                file: filePath,
                line,
                message: "Avoid dynamic code evaluation via 'eval()'.",
            });
        }

        // Rule 2: Detect new Function(...) constructor
        if (
            (node.type === "NewExpression" || node.type === "CallExpression") &&
            node.callee.type === "Identifier" &&
            node.callee.name === "Function"
        ) {
            findings.push({
                ruleId: "JS-SAST-002",
                cwe: "CWE-95",
                severity: "HIGH",
                file: filePath,
                line,
                message: "Avoid dynamic code generation via 'new Function()'.",
            });
        }

        // Rule 3: Detect child_process.exec / execSync with dynamic (non-Literal) argument
        if (
            node.type === "CallExpression" &&
            node.callee.type === "MemberExpression" &&
            node.callee.property.type === "Identifier" &&
            (node.callee.property.name === "exec" || node.callee.property.name === "execSync")
        ) {
            const firstArg = node.arguments && node.arguments[0];
            if (firstArg && firstArg.type !== "Literal") {
                findings.push({
                    ruleId: "JS-SAST-003",
                    cwe: "CWE-78",
                    severity: "CRITICAL",
                    file: filePath,
                    line,
                    message:
                        `Potential OS Command Injection: '${node.callee.property.name}()' invoked with ` +
                        `non-literal '${firstArg.type}'. Use 'execFile()' or 'spawn()' with an argument array.`,
                });
            }
        }

        // Rule 4: Detect DOM XSS sink assignments (.innerHTML / .outerHTML = ...)
        if (
            node.type === "AssignmentExpression" &&
            node.left.type === "MemberExpression" &&
            node.left.property.type === "Identifier" &&
            (node.left.property.name === "innerHTML" || node.left.property.name === "outerHTML")
        ) {
            if (node.right.type !== "Literal") {
                findings.push({
                    ruleId: "JS-SAST-004",
                    cwe: "CWE-79",
                    severity: "HIGH",
                    file: filePath,
                    line,
                    message:
                        `Unsafe DOM assignment to '.${node.left.property.name}'. Use '.textContent' ` +
                        `or sanitize HTML via DOMPurify before assignment.`,
                });
            }
        }

        // Rule 5: Detect weak cryptographic hashes crypto.createHash('md5' | 'sha1')
        if (
            node.type === "CallExpression" &&
            node.callee.type === "MemberExpression" &&
            node.callee.property.type === "Identifier" &&
            node.callee.property.name === "createHash"
        ) {
            const algoArg = node.arguments && node.arguments[0];
            if (
                algoArg &&
                algoArg.type === "Literal" &&
                typeof algoArg.value === "string" &&
                /^(md5|sha1)$/i.test(algoArg.value)
            ) {
                findings.push({
                    ruleId: "JS-SAST-005",
                    cwe: "CWE-328",
                    severity: "MEDIUM",
                    file: filePath,
                    line,
                    message: `Weak cryptographic hash '${algoArg.value}' passed to createHash(). Use 'sha256' or 'sha512'.`,
                });
            }
        }
    });

    return findings;
}

module.exports = { walkAst, analyzeAstForVulnerabilities };
```
