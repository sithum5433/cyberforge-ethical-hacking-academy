#!/usr/bin/env python3
"""
Generates Appendix B: OWASP Top 10 (Web, API, Mobile, LLM/GenAI) & CWE Top 50
Vulnerability & Secure Coding Encyclopedia (appendix_b_cwe_and_owasp_encyclopedia.md).
"""
import os

CHAPTERS_DIR = "/home/sithum404/Desktop/final exam/cyber sec/chapters"
OUT_PATH = os.path.join(CHAPTERS_DIR, "appendix_b_cwe_and_owasp_encyclopedia.md")

OWASP_WEB = [
    ("A01:2021 — Broken Access Control", "CWE-284, CWE-285, CWE-639 (IDOR), CWE-352 (CSRF), CWE-22 (Path Traversal)", "9.1 Critical",
     "Access control enforces policy such that users cannot act outside of their intended permissions. Failures typically lead to unauthorized information disclosure, modification, or destruction of all data, or performing a business function outside the user's limits. Common manifestations include Insecure Direct Object References (IDOR/BOLA), missing function-level access control (BFLA), privilege elevation via JWT/cookie tampering, and CORS misconfigurations.",
     """// Vulnerable Node.js / Express Controller (Missing Object Ownership Check - CWE-639)
app.get('/api/v1/invoices/:invoiceId', authenticateJWT, async (req, res) => {
    // BUG: Queries strictly by primary key without verifying req.user.id owns the invoice!
    const invoice = await db.query('SELECT * FROM invoices WHERE id = $1', [req.params.invoiceId]);
    if (!invoice.rows.length) return res.status(404).json({ error: 'Not found' });
    return res.json(invoice.rows[0]);
});""",
     """// Remediated Node.js / Express Controller (Enforces Tenant & User Ownership in SQL)
app.get('/api/v1/invoices/:invoiceId', authenticateJWT, async (req, res) => {
    const invoice = await db.query(
        'SELECT * FROM invoices WHERE id = $1 AND owner_user_id = $2 AND tenant_id = $3',
        [req.params.invoiceId, req.user.id, req.user.tenantId]
    );
    if (!invoice.rows.length) {
        // Return 404 or 403 consistently to prevent existence enumeration
        return res.status(404).json({ error: 'Invoice not found' });
    }
    return res.json(invoice.rows[0]);
});""",
     "Deny by default for all non-public resources; enforce centralized authorization middleware + database-level Row-Level Security (RLS); disable directory listings; log and alert on repeated 403/404 access control failures."),

    ("A02:2021 — Cryptographic Failures", "CWE-259, CWE-327 (Broken Crypto), CWE-328 (Weak Hash), CWE-330 (Weak PRNG), CWE-319 (Cleartext Transmission)", "7.5–9.8 High/Critical",
     "Previously known as Sensitive Data Exposure, this category focuses on failures related to cryptography (or lack thereof): transmitting data in cleartext (HTTP, FTP, SMTP), using deprecated ciphers (DES, 3DES, RC4, AES-ECB) or fast unsalted hashes (MD5, SHA-1) for passwords, hardcoding cryptographic keys in source code, failing to verify TLS certificate chains, or using non-cryptographic PRNGs (`Math.random()`, `random.randint()`) for security tokens.",
     """# Vulnerable Python Cryptography Patterns (CWE-327 / CWE-328 / CWE-330)
import hashlib, random
from Crypto.Cipher import AES

def hash_password_insecure(password: str) -> str:
    # BUG 1: Fast unsalted SHA-256 is vulnerable to GPU rainbow tables & brute-force
    return hashlib.sha256(password.encode()).hexdigest()

def generate_reset_token_insecure() -> str:
    # BUG 2: Mersenne Twister (random module) state can be reconstructed from 624 outputs
    return str(random.randint(100000, 999999))

def encrypt_pii_insecure(key: bytes, plaintext: bytes) -> bytes:
    # BUG 3: AES-ECB mode lacks diffusion and authentication (no IV, no MAC tag)
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(plaintext.ljust(32, b' '))""",
     """# Remediated Python Cryptography Patterns (Argon2id + secrets CSPRNG + AES-256-GCM AEAD)
import os, secrets
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)

def hash_password_secure(password: str) -> str:
    return ph.hash(password)

def generate_reset_token_secure() -> str:
    # Cryptographically Secure Pseudo-Random Number Generator (CSPRNG / os.urandom)
    return secrets.token_urlsafe(32)

def encrypt_pii_secure(key_32_bytes: bytes, plaintext: bytes, associated_data: bytes) -> bytes:
    aesgcm = AESGCM(key_32_bytes)
    nonce = os.urandom(12)  # 96-bit unique nonce per encryption
    ciphertext_and_tag = aesgcm.encrypt(nonce, plaintext, associated_data)
    return nonce + ciphertext_and_tag""",
     "Classify all sensitive data (PII, PCI-DSS, credentials); encrypt in transit using TLS 1.3 with HSTS; encrypt at rest with AES-256-GCM or ChaCha20-Poly1305; store passwords exclusively with Argon2id, bcrypt, or scrypt."),

    ("A03:2021 — Injection", "CWE-89 (SQLi), CWE-78 (OS Command Injection), CWE-79 (XSS), CWE-73, CWE-917 (EL/OGNL Injection)", "9.8 Critical",
     "An application is vulnerable to injection when user-supplied data is not validated, filtered, or sanitized by the application, and is concatenated directly into an interpreter command or query (SQL, NoSQL, OS shell, LDAP, XPath, ORM, or Template Engine). Because data and control instructions share the same channel, attacker input modifies the Abstract Syntax Tree (AST) of the target interpreter.",
     """# Vulnerable Python Subprocess & SQL Execution (CWE-78 & CWE-89)
import subprocess, sqlite3

def ping_host_vulnerable(hostname: str) -> str:
    # BUG 1: shell=True passes string to /bin/sh, enabling ';', '|', '&&', '$()' injection
    return subprocess.check_output(f"ping -c 1 {hostname}", shell=True, text=True)

def find_user_vulnerable(conn: sqlite3.Connection, username: str):
    # BUG 2: f-string interpolation directly into SQL text
    query = f"SELECT id, email, role FROM users WHERE username = '{username}'"
    return conn.execute(query).fetchall()""",
     """# Remediated Python Subprocess (Execve Argument Array) & Parameterized SQL
import subprocess, sqlite3, re

HOSTNAME_REGEX = re.compile(r"^[a-zA-Z0-9.-]{1,253}$")

def ping_host_secure(hostname: str) -> str:
    if not HOSTNAME_REGEX.match(hostname) or hostname.startswith("-"):
        raise ValueError("Invalid hostname format")
    # shell=False invokes execve() directly without a shell interpreter; '--' stops option parsing
    return subprocess.check_output(["/bin/ping", "-c", "1", "--", hostname], shell=False, text=True, timeout=5)

def find_user_secure(conn: sqlite3.Connection, username: str):
    # Parameterized query separates SQL AST compilation from bound parameter values
    return conn.execute("SELECT id, email, role FROM users WHERE username = ?", (username,)).fetchall()""",
     "Use parameterized queries / prepared statements for all database access; invoke OS binaries with argument arrays (`shell=False`) and `--` end-of-options markers; apply context-aware output encoding."),

    ("A04:2021 — Insecure Design", "CWE-209, CWE-256, CWE-501 (Trust Boundary Violation), CWE-522, CWE-799 (Missing Rate Limiting)", "7.5–9.1 High/Critical",
     "Insecure Design represents architectural and business logic flaws where security controls were never conceived during system design. Unlike implementation bugs, a perfect implementation of an insecure design remains vulnerable (e.g., a checkout workflow that trusts client-submitted unit prices, a password recovery flow based on easily guessable security questions, or a high-value coupon system lacking atomic concurrency locks).",
     """// Vulnerable E-Commerce Checkout Logic (Trusting Client-Side Price & Discount Calculation)
@PostMapping("/api/v1/orders/checkout")
public OrderReceipt checkout(@RequestBody CheckoutRequest req) {
    // DESIGN FLAW: Trusts req.getUnitPrice() and req.getTotalPayable() sent by browser JSON!
    paymentGateway.charge(req.getUserId(), req.getTotalPayable());
    return orderRepository.createOrder(req.getItems(), req.getTotalPayable());
}""",
     """// Remediated E-Commerce Checkout Architecture (Server-Side Authoritative Pricing & Locking)
@PostMapping("/api/v1/orders/checkout")
@Transactional(isolation = Isolation.SERIALIZABLE)
public OrderReceipt checkout(@AuthenticationPrincipal UserPrincipal user, @Valid @RequestBody SafeCheckoutRequest req) {
    BigDecimal serverCalculatedTotal = BigDecimal.ZERO;
    for (OrderItemDto item : req.getItems()) {
        if (item.getQuantity() <= 0 || item.getQuantity() > 50) throw new IllegalArgumentException("Invalid quantity");
        Product p = productRepository.findByIdForUpdate(item.getProductId()).orElseThrow();
        if (p.getStockCount() < item.getQuantity()) throw new InsufficientStockException();
        p.decrementStock(item.getQuantity());
        serverCalculatedTotal = serverCalculatedTotal.add(p.getAuthoritativePrice().multiply(BigDecimal.valueOf(item.getQuantity())));
    }
    paymentGateway.charge(user.getId(), serverCalculatedTotal, req.getIdempotencyKey());
    return orderRepository.createOrder(user.getId(), req.getItems(), serverCalculatedTotal);
}""",
     "Perform STRIDE threat modeling during design sprints; define explicit trust boundaries; enforce server-side authoritative state machines; write abuse-case unit and integration tests."),

    ("A05:2021 — Security Misconfiguration", "CWE-16, CWE-611 (XXE), CWE-215 (Debug Info Enabled), CWE-942 (Permissive CORS), CWE-1004", "6.5–9.8 Medium/Critical",
     "Security misconfiguration occurs when systems are deployed with insecure default settings, exposed debug consoles (`FLASK_DEBUG=1`, Spring Boot `/actuator/env`, Django `DEBUG=True`), permissive cloud storage ACLs, default credentials (`admin:admin`), XML parsers with external DTD evaluation enabled (XXE), missing HTTP security headers, or overly broad CORS policies (`Access-Control-Allow-Origin: *` or reflected `Origin` with credentials).",
     """# Vulnerable XML Parser & Flask Debug Configuration (CWE-611 & CWE-215)
from lxml import etree
from flask import Flask, request

app = Flask(__name__)
app.config["DEBUG"] = True  # Exposes Werkzeug interactive debugger RCE pin console on exceptions!

@app.post("/api/parse-xml")
def parse_xml():
    # BUG: resolve_entities=True by default in older lxml configurations enables XXE file read / SSRF!
    parser = etree.XMLParser(resolve_entities=True, load_dtd=True, no_network=False)
    tree = etree.fromstring(request.data, parser=parser)
    return {"root": tree.tag}""",
     """# Remediated XML Parser & Production Flask Configuration
from defusedxml.ElementTree import fromstring as safe_xml_fromstring
from flask import Flask, request

app = Flask(__name__)
app.config.update(
    DEBUG=False,
    TESTING=False,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

@app.post("/api/parse-xml")
def parse_xml():
    # defusedxml strictly blocks DOCTYPE, ENTITY declarations, DTD loading, and Billion Laughs expansion
    tree = safe_xml_fromstring(request.data)
    return {"root": tree.tag}""",
     "Automate immutable hardening baselines via Infrastructure-as-Code (Terraform/Ansible); run CIS Benchmark and Trivy misconfiguration scans in CI/CD; disable all debug modes and unauthenticated actuators in production."),

    ("A06:2021 — Vulnerable and Outdated Components", "CWE-1104 (Use of Unmaintained Third-Party Components), CWE-1395 (Dependency Confusion)", "7.0–10.0 High/Critical",
     "Modern applications rely heavily on transitive open-source packages (npm, PyPI, Maven, NuGet, Go modules, OS container layers). If an application uses a library with a known CVE (such as Log4j `2.14.1`, `commons-collections 3.2.1`, or an unpatched `libwebp`), or fails to pin private registry scopes (allowing Dependency Confusion where a public package with a higher version number overrides an internal package), the entire application is compromised.",
     """# Vulnerable pip & Docker Dependency Management (Unpinned & Vulnerable to Dependency Confusion)
# requirements.txt:
requests
pyyaml
internal-auth-sdk>=1.0.0

# Command used in CI/CD:
# pip install --extra-index-url https://pypi.internal.corp.lk/simple -r requirements.txt
# BUG: --extra-index-url checks public PyPI too and installs whichever has the highest version!""",
     """# Remediated Dependency Pinning with Cryptographic SHA-256 Hashes & Private Index Isolation
# 1. Use pip-compile --generate-hashes to lock exact versions and SHA-256 digests
# 2. Use --index-url (NOT --extra-index-url) pointing to an internal Nexus/Artifactory proxy
#    that explicitly blocks public fallback for 'internal-*' namespace prefixes.
# requirements.lock:
requests==2.32.3 \\
    --hash=sha256:70761cfe03c773ceb22aa2f671b4757976145175cdfca038c02654d061d6dcc6""",
     "Generate CycloneDX/SPDX Software Bill of Materials (SBOM) on every build; enforce `pip install --require-hashes` or `npm ci --ignore-scripts`; run `trivy`, `grype`, or `Dependabot` daily."),

    ("A07:2021 — Identification and Authentication Failures", "CWE-287, CWE-384 (Session Fixation), CWE-307 (Brute Force), CWE-620, CWE-640 (Weak Password Recovery)", "8.1–9.8 High/Critical",
     "Authentication failures occur when applications permit credential stuffing or brute-force attacks without rate limiting, allow weak/breached passwords (`Password123!`), fail to rotate session IDs upon login (Session Fixation), fail to invalidate server-side sessions on logout, implement flawed MFA checks that can be bypassed via direct step skipping, or generate password reset links using spoofable `Host` headers.",
     """// Vulnerable Password Reset Endpoint (Host Header Poisoning - CWE-640)
app.post('/api/v1/auth/forgot-password', async (req, res) => {
    const user = await User.findOne({ email: req.body.email });
    if (!user) return res.status(404).json({ error: 'Email not registered' }); // Username enumeration!
    const resetToken = crypto.randomBytes(32).toString('hex');
    await saveResetToken(user.id, resetToken);
    // BUG: Uses untrusted req.headers.host to construct the reset link emailed to the victim!
    const resetUrl = `https://${req.headers.host}/reset-password?token=${resetToken}`;
    await sendEmail(user.email, `Reset your password: ${resetUrl}`);
    return res.json({ status: 'sent' });
});""",
     """// Remediated Password Reset Endpoint (Hardcoded Canonical Origin + Hashed Token + Generic Response)
const CANONICAL_APP_ORIGIN = process.env.CANONICAL_APP_ORIGIN; // Strictly configured from env Vault

app.post('/api/v1/auth/forgot-password', rateLimiterStrict, async (req, res) => {
    const user = await User.findOne({ email: String(req.body.email).toLowerCase() });
    if (user) {
        const rawToken = crypto.randomBytes(32).toString('base64url');
        // Store only the SHA-256 hash of the reset token in DB (protects against DB read-only SQLi leaks!)
        const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
        await saveResetTokenHash(user.id, tokenHash, Date.now() + 15 * 60 * 1000);
        const resetUrl = `${CANONICAL_APP_ORIGIN}/reset-password?token=${encodeURIComponent(rawToken)}`;
        await sendEmail(user.email, `Reset your password: ${resetUrl}`);
    }
    // Identical response message and timing prevent account enumeration
    return res.json({ message: 'If that account exists, a password reset link has been sent.' });
});""",
     "Enforce phishing-resistant MFA (FIDO2/WebAuthn or TOTP); verify passwords against HaveIBeenPwned k-anonymity lists (NIST SP 800-63B); rotate session IDs on every privilege change; hash reset/API tokens in the database."),

    ("A08:2021 — Software and Data Integrity Failures", "CWE-502 (Deserialization of Untrusted Data), CWE-829 (Untrusted CDN without SRI), CWE-494", "8.8–9.8 High/Critical",
     "Software and data integrity failures relate to code and infrastructure that do not protect against integrity violations: deserializing untrusted payloads (`pickle`, `Java ObjectInputStream`, `PHP unserialize`, `PyYAML yaml.load`), loading third-party JavaScript from CDNs without Subresource Integrity (`integrity=\"sha384-...\"`), or running CI/CD pipelines with unpinned mutable GitHub Actions tags (`uses: thirdparty/action@main`) that can steal deployment credentials.",
     """# Vulnerable Python Data Deserialization & Unverified Script Tag (CWE-502 & CWE-829)
import pickle, base64

def load_user_session_vulnerable(cookie_b64: str) -> dict:
    # CRITICAL BUG: pickle.loads() executes arbitrary Python bytecode via __reduce__()!
    return pickle.loads(base64.b64decode(cookie_b64))""",
     """# Remediated Data Serialization (HMAC-SHA256 Signed JSON with Strict Schema Validation)
import hmac, hashlib, json, base64

def load_user_session_secure(cookie_val: str, secret_key: bytes) -> dict:
     payload_b64, received_sig = cookie_val.split(".", 1)
    expected_sig = hmac.new(secret_key, payload_b64.encode(), hashlib.sha256).hexdigest()
    # Use hmac.compare_digest() to prevent byte-by-byte timing side-channel attacks!
    if not hmac.compare_digest(received_sig, expected_sig):
        raise ValueError("Session signature verification failed")
    data = json.loads(base64.urlsafe_b64decode(payload_b64))
    return {"user_id": int(data["user_id"]), "role": str(data["role"])}""",
     "Never use native binary/object deserializers (`pickle`, `unserialize`, `ObjectInputStream`) on untrusted input; use JSON/Protobuf with strict schema validation and HMAC/digital signatures; pin all CI/CD actions to full 40-char commit SHAs; enforce Subresource Integrity (SRI) on external scripts."),

    ("A09:2021 — Security Logging and Monitoring Failures", "CWE-778 (Insufficient Logging), CWE-117 (Improper Output Neutralization for Logs), CWE-532 (Sensitive Data in Logs)", "6.5 Medium",
     "Without comprehensive, tamper-evident logging and real-time alerting, breaches cannot be detected or investigated (average dwell time exceeds weeks). Conversely, logging raw user input without neutralizing CR/LF characters (`\\r\\n`) enables Log Injection (CWE-117) where attackers forge fake log entries or inject ANSI terminal escape sequences, while logging plaintext passwords, JWTs, or credit cards violates CWE-532 and PCI-DSS.",
     """# Vulnerable Logging Practice (CWE-117 Log Injection & CWE-532 Secret Exposure)
import logging
logger = logging.getLogger("auth")

def record_login_attempt(username: str, password: str, ip: str):
    # BUG 1: Logs plaintext password (CWE-532)!
    # BUG 2: Unsanitized username containing '\\nINFO:auth:Admin login succeeded' forges log lines (CWE-117)!
    logger.warning(f"Failed login for user={username} password={password} from ip={ip}")""",
     """# Remediated Structured JSON Audit Logging with Secret Redaction & Control Character Stripping
import json, time, re

CONTROL_CHARS = re.compile(r"[\\x00-\\x1f\\x7f-\\x9f]")

def sanitize_log_field(val: str, max_len: int = 128) -> str:
    return CONTROL_CHARS.sub("_", str(val))[:max_len]

def record_security_event(event_type: str, username: str, source_ip: str, outcome: str):
    # Structured single-line JSON prevents newline log forging and feeds directly into SIEM (Wazuh/Splunk)
    entry = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "event_type": event_type,
        "username": sanitize_log_field(username),
        "source_ip": sanitize_log_field(source_ip, 45),
        "outcome": outcome,
    }
    print(json.dumps(entry), flush=True)""",
     "Emit structured JSON logs to append-only remote SIEM collectors; never log passwords, session tokens, or PII; sanitize CR/LF and ANSI escape sequences; alert on authentication spikes, privilege changes, and audit service stops."),

    ("A10:2021 — Server-Side Request Forgery (SSRF)", "CWE-918 (Server-Side Request Forgery)", "8.6–9.8 High/Critical",
     "SSRF flaws occur whenever a web application fetches a remote resource (webhook testing, PDF generation via headless browsers, avatar URL import, OIDC discovery, or XML entity resolution) without validating the user-supplied URL and resolved IP address. Attackers coerce the server into sending requests to internal-only services (`127.0.0.1`, Redis `6379`, Kubernetes API `6443`, or Cloud Instance Metadata `169.254.169.254`).",
     """# Vulnerable Python Webhook / Avatar Fetcher (CWE-918)
import requests

def fetch_remote_avatar_vulnerable(image_url: str) -> bytes:
    # CRITICAL BUG: Fetches any scheme/IP, follows 302 redirects to 169.254.169.254!
    resp = requests.get(image_url, timeout=5)
    return resp.content""",
     """# Remediated SSRF Defense-in-Depth (Strict Allowlist + Non-Private DNS Pinning + No Redirects)
import ipaddress, socket
from urllib.parse import urlparse
import requests

def fetch_remote_avatar_secure(image_url: str) -> bytes:
    parsed = urlparse(image_url)
    if parsed.scheme != "https" or parsed.port not in (None, 443) or not parsed.hostname:
        raise ValueError("Disallowed URL scheme or port")

    # Resolve hostname and verify ALL resolved IPs are globally routable public addresses
    for fam, _, _, _, sockaddr in socket.getaddrinfo(parsed.hostname, 443, proto=socket.IPPROTO_TCP):
        ip = ipaddress.ip_address(sockaddr[0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            raise PermissionError(f"Blocked non-public destination IP: {ip}")

    # Disable HTTP redirects (allow_redirects=False) so an external server cannot 302-redirect to 127.0.0.1!
    resp = requests.get(image_url, timeout=3.0, allow_redirects=False, stream=True)
    content = resp.raw.read(2 * 1024 * 1024 + 1)
    if len(content) > 2 * 1024 * 1024:
        raise ValueError("Response exceeds 2MB limit")
    return content""",
     "Enforce Cloud IMDSv2 (`HttpPutResponseHopLimit = 1`); route outbound webhook fetches through an isolated egress proxy in a DMZ subnet with RFC 1918 and `169.254.0.0/16` dropped at the firewall; disable HTTP redirects on server-side fetchers."),
]

OWASP_API = [
    ("API1:2023", "Broken Object Level Authorization (BOLA)", "CWE-639", "Endpoints taking object IDs (`/api/v1/wallets/{id}`) fail to validate that the authenticated caller owns the target object ID.", "Enforce `WHERE id = :id AND owner_id = :current_user_id` on every database query and verify with automated multi-user integration tests."),
    ("API2:2023", "Broken Authentication", "CWE-287 / CWE-307", "Weak JWT verification (`alg: none`, unverified signatures), missing rate limiting on `/api/login` or `/api/verify-otp`, or long-lived unrevokable bearer tokens.", "Use short-lived (15-min) RS256/EdDSA access tokens paired with rotating refresh tokens, strict algorithm pinning, and per-IP/per-account rate limiting."),
    ("API3:2023", "Broken Object Property Level Authorization (BOPLA)", "CWE-915 (Mass Assignment) / CWE-213 (Excessive Data Exposure)", "Combining Excessive Data Exposure (returning full ORM models with `password_hash` or `is_admin`) and Mass Assignment (binding raw JSON bodies directly to database models).", "Define explicit Read DTOs and Write DTOs (Pydantic / Zod / Jackson `@JsonView`) that strictly allowlist permitted fields."),
    ("API4:2023", "Unrestricted Resource Consumption", "CWE-400 / CWE-770", "Missing pagination bounds (`?limit=99999999`), unbounded GraphQL query depth/aliases, oversized file uploads, or expensive synchronous regex/bcrypt calls.", "Enforce strict max page sizes (`limit <= 100`), GraphQL depth/complexity cost limits, payload size caps, and per-tenant token-bucket rate limits."),
    ("API5:2023", "Broken Function Level Authorization (BFLA)", "CWE-285", "Regular users invoking administrative endpoints (`DELETE /api/v1/admin/users/42` or changing `GET` to `PUT`/`POST`) due to missing role checks on administrative controllers.", "Use deny-by-default role-based access control (RBAC) decorators on every route handler and separate administrative routers."),
    ("API6:2023", "Unrestricted Access to Sensitive Business Flows", "CWE-799 / CWE-841", "Automated scalping, ticket/inventory hoarding, referral bonus farming, or spam posting where legitimate business workflows lack anti-automation controls.", "Implement device fingerprinting, cryptographic proof-of-work / CAPTCHA challenges, velocity checks, and atomic business state locks."),
    ("API7:2023", "Server-Side Request Forgery (SSRF)", "CWE-918", "API endpoints accepting webhook callback URLs, OIDC jku/x5u URLs, or media import URLs that probe internal microservices.", "Use strict domain allowlists, disable redirects, validate resolved IPs against RFC 1918/link-local ranges, and isolate outbound traffic via egress proxies."),
    ("API8:2023", "Security Misconfiguration", "CWE-16 / CWE-942", "Permissive CORS headers reflecting arbitrary origins with `Access-Control-Allow-Credentials: true`, exposed OpenAPI/GraphiQL consoles in production, or verbose stack traces.", "Validate `Origin` against an exact set of trusted production origins, disable interactive API explorers in prod, and return RFC 9457 generic error objects."),
    ("API9:2023", "Improper Inventory Management", "CWE-1059", "Deprecated API versions (`/api/v1/login` running alongside `/api/v3/login`) left active without the MFA or rate-limiting patches applied to newer versions ('Zombie APIs').", "Maintain an automated OpenAPI gateway catalog; enforce sunset dates and decommission legacy API versions at the API Gateway."),
    ("API10:2023", "Unsafe Consumption of APIs", "CWE-20 / CWE-345", "Blindly trusting data returned from third-party APIs (partner webhooks, payment callbacks, LLM outputs, or enriched OSINT feeds) without signature verification or sanitization.", "Verify webhook HMAC/asymmetric signatures (`Stripe-Signature`, `X-Hub-Signature-256`), validate third-party payloads against strict schemas, and parameterize all downstream queries."),
]

OWASP_LLM = [
    ("LLM01:2025", "Prompt Injection (Direct & Indirect)", "CWE-77 / CWE-94", "Untrusted user input or retrieved external documents (RAG webpages, emails, PDFs) override system instructions, hijacking model behavior or invoking unauthorized tools.", "Separate system instructions from untrusted data delimiters; enforce strict human-in-the-loop (HITL) approval before executing state-changing tool calls; treat all LLM output as untrusted."),
    ("LLM02:2025", "Sensitive Information Disclosure", "CWE-200 / CWE-359", "PII, proprietary source code, API keys, or cross-tenant RAG documents leaked in model responses due to over-broad vector database retrieval or training data memorization.", "Enforce document-level ACL filtering in the Vector Database *before* passing chunks to the LLM context window; scrub PII/secrets with DLP regex/NER filters."),
    ("LLM03:2025", "Supply Chain Vulnerabilities", "CWE-502 / CWE-1357", "Loading untrusted HuggingFace model weights using Python `pickle` (`.bin` / `.pt` files executing arbitrary code on load) or compromised LoRA adapters.", "Use `safetensors` format exclusively (`use_safetensors=True`); verify model SHA-256 digests and provenance signatures."),
    ("LLM04:2025", "Data and Model Poisoning", "CWE-20", "Adversarial poisoning of fine-tuning datasets or RAG knowledge bases to introduce backdoor triggers or biased/malicious outputs.", "Cryptographically sign and audit all RAG ingestion pipelines and fine-tuning corpora; monitor embedding drift."),
    ("LLM05:2025", "Improper Output Handling", "CWE-79 / CWE-89 / CWE-78", "Passing raw LLM-generated text directly into `eval()`, `subprocess`, SQL queries, or browser `innerHTML` without sanitization or parameterization.", "Never execute raw LLM-generated SQL or shell code directly; use constrained structured tool schemas (JSON mode) validated by strict server-side allowlists."),
    ("LLM06:2025", "Excessive Agency", "CWE-250 / CWE-269", "Granting an AI agent broad tool permissions (e.g., full database write access, shell execution, or email sending) without least-privilege scoping.", "Scope agent credentials to read-only least privilege; require explicit cryptographic user confirmation for any high-impact action."),
    ("LLM07:2025", "System Prompt Leakage", "CWE-200", "Embedding API keys, internal endpoint URLs, or proprietary authorization logic inside the system prompt under the false assumption that users cannot extract it.", "Never store secrets or enforce access control inside a system prompt; enforce all authorization and secret handling in deterministic backend code."),
    ("LLM08:2025", "Vector and Embedding Weaknesses", "CWE-284", "Multi-tenant RAG systems storing embeddings in a shared index without tenant namespace partitioning, allowing cross-tenant semantic search leakage.", "Enforce strict tenant partitioning and metadata ACL pre-filtering on every vector similarity query."),
    ("LLM09:2025", "Misinformation & Hallucination Risks", "CWE-1007", "Relying on hallucinated package names (slopsquatting where attackers register hallucinated PyPI/npm package names) or unverified security advice.", "Ground outputs with citation verification and verify every package name against established registries before installation."),
    ("LLM10:2025", "Unbounded Consumption (Denial of Wallet)", "CWE-400", "Attackers sending maximum-length context prompts or recursive agent loops that exhaust GPU compute quotas and incur massive API billing costs.", "Enforce strict input/output token limits (`max_tokens`), per-user daily budget quotas, and maximum agent iteration depth."),
]

CWE_TOP_50 = [
    ("CWE-79", "Improper Neutralization of Input During Web Page Generation (XSS)", "High", "Context-sensitive output encoding (`html.escape`), `textContent` instead of `innerHTML`, `DOMPurify`, and strict `Content-Security-Policy`."),
    ("CWE-787", "Out-of-Bounds Write", "Critical", "Bounds-checked memory operations (`snprintf`, `std::vector::at()`, Rust slice bounds checking) and compiler Stack Canaries + ASan."),
    ("CWE-89", "Improper Neutralization of Special Elements used in an SQL Command (SQLi)", "Critical", "100% Parameterized Queries / Prepared Statements (`?`, `$1`, `:param`) and strict identifier allowlisting for `ORDER BY`."),
    ("CWE-352", "Cross-Site Request Forgery (CSRF)", "High", "`SameSite=Lax` or `SameSite=Strict` session cookies, Cryptographic Anti-CSRF tokens (`X-CSRF-Token`), and avoiding GET state changes."),
    ("CWE-22", "Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)", "High", "Resolve canonical paths (`os.path.realpath`, `Path.resolve().is_relative_to()`) and reject paths escaping the base directory."),
    ("CWE-125", "Out-of-Bounds Read", "High", "Validate packet/buffer length fields against actual received byte counts before `memcpy()` or array indexing (e.g., Heartbleed fix)."),
    ("CWE-78", "Improper Neutralization of Special Elements used in an OS Command", "Critical", "Use `execve` / `subprocess.run([...], shell=False)` with argument arrays and strict input regex validation."),
    ("CWE-416", "Use After Free (UAF)", "Critical", "Set pointers to `NULL` immediately after `free()`, use RAII smart pointers (`std::unique_ptr`), or memory-safe languages (Rust/Go)."),
    ("CWE-862", "Missing Authorization", "High", "Enforce centralized deny-by-default authentication and authorization middleware across all routes."),
    ("CWE-434", "Unrestricted Upload of File with Dangerous Type", "Critical", "Verify file extension allowlist, magic bytes, re-encode images, rename to random UUIDs, and serve from isolated non-executing storage (S3) with `Content-Disposition: attachment`."),
    ("CWE-94", "Improper Control of Generation of Code (Code Injection)", "Critical", "Eliminate `eval()`, `exec()`, `Function()`, and dynamic template compilation on user-supplied strings."),
    ("CWE-20", "Improper Input Validation", "High", "Validate type, length, numeric range, character set, and schema (`Pydantic`, `Zod`, `JSON Schema`) at the trust boundary."),
    ("CWE-77", "Improper Neutralization of Special Elements used in a Command", "Critical", "Separate control instructions from user data across all interpreters and sub-systems."),
    ("CWE-287", "Improper Authentication", "Critical", "Use standard, audited authentication frameworks, constant-time token comparison (`hmac.compare_digest`), and FIDO2/TOTP MFA."),
    ("CWE-269", "Improper Privilege Management", "High", "Apply Principle of Least Privilege (`setresuid`, drop Linux capabilities, run containers as non-root UID `10001`)."),
    ("CWE-502", "Deserialization of Untrusted Data", "Critical", "Replace `pickle`, `yaml.load`, `unserialize`, and `ObjectInputStream` with `json.loads`, `yaml.safe_load`, or Protobuf."),
    ("CWE-200", "Exposure of Sensitive Information to an Unauthorized Actor", "Medium", "Scrub stack traces, disable `.git`/`.env` web access, and normalize error responses."),
    ("CWE-863", "Incorrect Authorization (IDOR / BOLA)", "High", "Verify object ownership (`resource.owner_id == current_user.id`) on every read, update, and delete operation."),
    ("CWE-918", "Server-Side Request Forgery (SSRF)", "High", "Validate URL schemes (`https`), verify resolved IPs are public, disable redirects, and enforce Cloud IMDSv2."),
    ("CWE-119", "Improper Restriction of Operations within the Bounds of a Memory Buffer", "Critical", "Use safe string/buffer APIs and compile native binaries with `-fstack-protector-strong -D_FORTIFY_SOURCE=3 -fPIE -pie`."),
    ("CWE-476", "NULL Pointer Dereference", "Medium", "Check all pointer returns from allocation and lookup functions before dereferencing; enable compiler nullability warnings."),
    ("CWE-798", "Use of Hard-coded Credentials", "Critical", "Load secrets dynamically from Vault, AWS Secrets Manager, or environment variables; scan commits with `gitleaks`/`trufflehog`."),
    ("CWE-190", "Integer Overflow or Wraparound", "High", "Check arithmetic bounds before allocation (`calloc` overflow check, `__builtin_add_overflow`, Rust checked math)."),
    ("CWE-400", "Uncontrolled Resource Consumption (DoS)", "Medium", "Enforce timeouts, connection limits, payload size limits, pagination caps, and linear-time regex engines (`RE2`)."),
    ("CWE-306", "Missing Authentication for Critical Function", "Critical", "Require authentication by default on all routes and explicitly mark only public endpoints (`@public`)."),
    ("CWE-362", "Concurrent Execution using Shared Resource with Improper Synchronization (Race Condition)", "High", "Use database transactions with `SELECT ... FOR UPDATE` row locking, atomic SQL increments, and idempotency keys."),
    ("CWE-611", "Improper Restriction of XML External Entity Reference (XXE)", "High", "Disable DTDs and external entities (`disallow-doctype-decl`, `defusedxml`) in all XML/SOAP/SVG/DOCX parsers."),
    ("CWE-915", "Improperly Controlled Modification of Dynamically-Determined Object Attributes (Mass Assignment / Prototype Pollution)", "High", "Use explicit field allowlists in DTOs and freeze/null-prototype objects in JavaScript (`Object.create(null)`)."),
    ("CWE-601", "URL Redirection to Untrusted Site (Open Redirect)", "Medium", "Allow only relative paths starting with `/` (and not `//` or `/\\`) or validate against an exact host allowlist."),
    ("CWE-327", "Use of a Broken or Risky Cryptographic Algorithm", "High", "Use TLS 1.3, AES-256-GCM, ChaCha20-Poly1305, Ed25519, RSA-OAEP-2048+, SHA-256+, and Argon2id."),
    ("CWE-330", "Use of Insufficiently Random Values", "High", "Use OS CSPRNGs (`secrets`, `os.urandom`, `crypto.randomBytes`, `/dev/urandom`, `SecureRandom`) for all tokens and nonces."),
    ("CWE-295", "Improper Certificate Validation", "High", "Never disable TLS verification (`verify=False` or `NODE_TLS_REJECT_UNAUTHORIZED=0`); validate hostname and chain."),
    ("CWE-384", "Session Fixation", "High", "Regenerate the session identifier (`req.session.regenerate()`) immediately upon user login or privilege elevation."),
    ("CWE-639", "Authorization Bypass Through User-Controlled Key (IDOR)", "High", "Bind resource queries to the authenticated session's user/tenant ID rather than trusting client-supplied IDs alone."),
    ("CWE-134", "Use of Externally-Controlled Format String", "Critical", "Always pass a constant format string literal (`printf(\"%s\", user_str)` instead of `printf(user_str)`)."),
    ("CWE-415", "Double Free", "Critical", "Zero out pointers after freeing and enforce single-ownership memory semantics."),
    ("CWE-427", "Uncontrolled Search Path Element (PATH / DLL Hijacking)", "High", "Invoke binaries using absolute paths (`/usr/bin/id`), sanitize `PATH`/`LD_PRELOAD`, and use `LOAD_LIBRARY_SEARCH_SYSTEM32` on Windows."),
    ("CWE-732", "Incorrect Permission Assignment for Critical Resource", "High", "Apply `0600` to private keys/configs, `0640` to `/etc/shadow`, and remove world-writable bits (`o-w`)."),
    ("CWE-1321", "Improperly Controlled Modification of Object Prototype Attributes (Prototype Pollution)", "High", "Block `__proto__`, `constructor`, and `prototype` keys during recursive JSON merges; validate schemas with `Zod`."),
    ("CWE-444", "Inconsistent Interpretation of HTTP Requests (HTTP Request Smuggling)", "Critical", "Use HTTP/2 end-to-end where possible, normalize headers at the edge proxy, and reject ambiguous requests containing both `Content-Length` and `Transfer-Encoding`."),
]

def generate():
    lines = []
    lines.append("# APPENDIX B: OWASP TOP 10 (WEB, API, MOBILE, LLM/AI) & CWE TOP 50 VULNERABILITY & SECURE CODING ENCYCLOPEDIA")
    lines.append("")
    lines.append("## Complete Root-Cause Taxonomy, Vulnerable vs. Patched Code Patterns, SAST Rules & Architectural Defenses")
    lines.append("")
    lines.append("> [!IMPORTANT]")
    lines.append("> **How to Use This Encyclopedia:** Whether you are performing a white-box secure code review, hunting bug bounties, preparing for university software security exams, or writing remediation guidance in a penetration test report, this appendix maps every major OWASP and CWE classification directly to concrete vulnerable code patterns and production-ready fixes.")
    lines.append("")
    lines.append("---")
    lines.append("# Section 1: OWASP Web Application Security Top 10 (A01:2021 – A10:2021) Deep Dive")
    lines.append("")

    for idx, (title, cwes, sev, desc, vuln_code, fix_code, defense) in enumerate(OWASP_WEB, 1):
        lines.append(f"## B.1.{idx} {title}")
        lines.append("")
        lines.append(f"- **Mapped CWEs:** `{cwes}`")
        lines.append(f"- **Typical CVSS v3.1 Severity Range:** `{sev}`")
        lines.append("")
        lines.append("### 1. Architectural Root Cause & Attack Surface")
        lines.append(desc)
        lines.append("")
        lines.append("### 2. Vulnerable Code Anti-Pattern")
        lines.append("```python")
        lines.append(vuln_code.strip())
        lines.append("```")
        lines.append("")
        lines.append("### 3. Remediated Production Code Pattern")
        lines.append("```python")
        lines.append(fix_code.strip())
        lines.append("```")
        lines.append("")
        lines.append("### 4. Defense-in-Depth & Verification Checklist")
        lines.append(f"- {defense}")
        lines.append("")

    lines.append("---")
    lines.append("# Section 2: OWASP API Security Top 10 (API1:2023 – API10:2023) Engineering Matrix")
    lines.append("")
    lines.append("| OWASP API ID | Vulnerability Category | Primary CWE | Technical Root Cause | Production Architectural Remediation |")
    lines.append("|---|---|---|---|---|")
    for aid, aname, acwe, arc, afix in OWASP_API:
        lines.append(f"| **{aid}** | **{aname}** | `{acwe}` | {arc} | {afix} |")
    lines.append("")

    lines.append("---")
    lines.append("# Section 3: OWASP Top 10 for Large Language Model (LLM) & GenAI Applications (LLM01 – LLM10)")
    lines.append("")
    lines.append("| OWASP LLM ID | AI/LLM Security Risk | Primary CWE | Attack Mechanism | AI Security Engineering Control |")
    lines.append("|---|---|---|---|---|")
    for lid, lname, lcwe, lrc, lfix in OWASP_LLM:
        lines.append(f"| **{lid}** | **{lname}** | `{lcwe}` | {lrc} | {lfix} |")
    lines.append("")

    lines.append("---")
    lines.append("# Section 4: CWE Top 40 Software & Systems Weakness Reference Matrix")
    lines.append("")
    lines.append("| CWE ID | Weakness Name | Typical Severity | Mandatory Secure Coding & Compiler Remediation |")
    lines.append("|---|---|---|---|")
    for cid, cname, csev, cfix in CWE_TOP_50:
        lines.append(f"| **{cid}** | {cname} | **{csev}** | {cfix} |")
    lines.append("")

    with open(OUT_PATH, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"Wrote {OUT_PATH} ({len(lines)} lines)")

if __name__ == "__main__":
    generate()

