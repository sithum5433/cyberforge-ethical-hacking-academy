# Appendix F: Comprehensive Cybersecurity Glossary, Cryptography Reference & 200-Question Certification Practice Exam

> **Academic & Certification Preparation Scope**: This appendix serves as a rapid-lookup reference for HTTP security engineering, applied modern and post-quantum cryptography (`FIPS 203` / `FIPS 204` / `FIPS 205`), offensive/defensive regular expressions, an A–Z encyclopedia glossary of 260 core cybersecurity terms, and a complete 200-question certification practice examination modeled on **OSCP**, **CISSP**, **GIAC (GCIH/GCFA/GPEN)**, **CompTIA CASP+ / SecurityX**, and **AWS/Kubernetes Security Specialty** exams.

---

## Section 1: HTTP Status Codes, Security Response Headers & TLS 1.2/1.3 Cipher Suite Reference

### 1.1 Security-Relevant HTTP Status Codes (RFC 9110)

| Code | Status Phrase | Security & Penetration Testing Significance |
| :--- | :--- | :--- |
| `101` | **Switching Protocols** | Indicates HTTP-to-WebSocket (`ws://`/`wss://`) or HTTP/2 upgrade; test for Cross-Site WebSocket Hijacking (CSWSH) and HTTP/2 Cleartext (`h2c`) smuggling. |
| `200` | **OK** | Standard success response; verify sensitive endpoints enforce `Cache-Control: no-store`. |
| `201` | **Created** | Resource created (`POST`/`PUT`); inspect `Location` header for sequential ID enumeration (IDOR) and Mass Assignment fields in the echoed JSON body. |
| `204` | **No Content** | Common in CORS preflight (`OPTIONS`) responses and `DELETE` endpoints; inspect `Access-Control-Allow-Origin` and `Access-Control-Allow-Credentials`. |
| `301` / `302` | **Moved Permanently / Found** | Inspect `Location` header for **Open Redirect (`CWE-601`)** and check whether restricted administrative pages still render their HTML body after sending a `302` redirect (Execution After Redirect / EAR). |
| `304` | **Not Modified** | Conditional `ETag` / `If-None-Match` cache hit; check for Cross-Site Leaks (XS-Leaks) via cache probing. |
| `307` / `308` | **Temporary / Permanent Redirect** | Strictly preserves the original HTTP method (`POST` remains `POST`) and request body across redirects; dangerous if redirecting to an external origin that receives sensitive `POST` payloads. |
| `400` | **Bad Request** | Malformed HTTP syntax, JSON schema rejection, or HTTP Request Smuggling (`CL.TE` / `TE.CL`) desynchronization probe indicator. |
| `401` | **Unauthorized** | Unauthenticated request (`WWW-Authenticate` challenge); indicates authentication is missing or invalid (as opposed to `403`). |
| `403` | **Forbidden** | Authenticated identity lacks authorization (RBAC/ABAC/WAF block); confirm whether `403` vs `404` discrepancies leak the existence of private tenant IDs. |
| `404` | **Not Found** | Resource not found; preferred response over `403` when hiding the existence of sensitive multi-tenant object UUIDs. |
| `405` | **Method Not Allowed** | Endpoint exists (`route matched`), but HTTP verb (`GET`/`POST`/`PUT`/`DELETE`) is disallowed; inspect `Allow` response header for hidden methods (`PUT`, `PATCH`, `TRACE`). |
| `409` | **Conflict** | State conflict; frequently observed during database constraint violations or concurrent race condition (`TOCTOU`) testing. |
| `413` | **Content Too Large** | Enforced by reverse proxy (`client_max_body_size` in Nginx) to mitigate memory exhaustion and XML/JSON payload DoS. |
| `415` | **Unsupported Media Type** | Server rejected `Content-Type`; test swapping `application/x-www-form-urlencoded` to `application/json` or `application/xml` (XXE probing). |
| `422` | **Unprocessable Content** | Valid JSON syntax, but semantic validation failed (e.g., Pydantic / FastAPI type validation error); inspect error detail for internal schema leakage. |
| `429` | **Too Many Requests** | Rate-limiting active (`Retry-After`); test whether rate limits trust spoofable headers (`X-Forwarded-For`, `X-Real-IP`, `True-Client-IP`). |
| `500` | **Internal Server Error** | Unhandled server exception; prime indicator of SQL Injection syntax break, insecure deserialization crash, or stack trace disclosure. |
| `502` / `504` | **Bad Gateway / Gateway Timeout** | Upstream application server crashed or timed out; critical indicator for Blind Time-Based SQLi (`SLEEP(5)`), SSRF port scanning, or HTTP Request Smuggling. |

---

### 1.2 Mandatory HTTP Security Response Headers Reference

| Header Name | Production Hardened Value | Attack Mitigated & Technical Mechanism |
| :--- | :--- | :--- |
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains; preload` | **SSL Stripping / Downgrade (RFC 6797)**: Instructs the browser to connect exclusively over HTTPS for 2 years (`63072000` seconds), refuse user click-through on invalid TLS certificates, and apply the policy across all subdomains. |
| `Content-Security-Policy` | `default-src 'none'; script-src 'nonce-<RAND>' 'strict-dynamic'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'` | **Cross-Site Scripting (XSS), Clickjacking & Data Exfiltration**: Restricts script execution strictly to DOM `<script>` elements carrying the per-response cryptographic nonce, blocks `<object>`/`<embed>`, blocks `<base>` tag hijacking, and prevents framing (`frame-ancestors 'none'`). |
| `X-Content-Type-Options` | `nosniff` | **MIME-Sniffing XSS**: Prevents browsers from heuristically executing an uploaded `image/jpeg` or `text/plain` file as `text/html` or `application/javascript`. |
| `X-Frame-Options` | `DENY` (or `SAMEORIGIN`) | **Clickjacking / UI Redressing (Legacy fallback for `frame-ancestors`)**: Prevents the page from being embedded inside an attacker-controlled `<frame>`, `<iframe>`, `<embed>`, or `<object>`. |
| `Referrer-Policy` | `strict-origin-when-cross-origin` (or `no-referrer`) | **Sensitive URL Token / Path Leakage**: Sends the full URL as `Referer` only on same-origin requests, sends only the bare origin (`https://example.com/`) on cross-origin HTTPS->HTTPS requests, and sends nothing on HTTPS->HTTP downgrades. |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=(), payment=(), usb=(), bluetooth=()` | **Browser Hardware / Sensor API Abuse**: Explicitly disables access to sensitive Web APIs (`navigator.mediaDevices`, WebUSB, Geolocation) for the document and all embedded third-party iframes. |
| `Cross-Origin-Opener-Policy` (`COOP`) | `same-origin` | **Cross-Origin `window.opener` & Spectre Process Sharing**: Isolates the top-level browsing context into its own OS browser process group so cross-origin popups cannot access `window.opener` or share speculative-execution address space. |
| `Cross-Origin-Embedder-Policy` (`COEP`) | `require-corp` | **Spectre Side-Channel Isolation**: Requires all cross-origin subresources loaded by the document to explicitly opt in via `Cross-Origin-Resource-Policy` or CORS (`crossOriginIsolate === true`). |
| `Cross-Origin-Resource-Policy` (`CORP`) | `same-origin` (or `same-site`) | **Cross-Site Script Inclusion (XSSI) & Speculative Side Channels**: Instructs the browser's network service process to block cross-origin `no-cors` loads (`<img>`, `<script>`) of sensitive API responses before bytes enter the renderer process. |
| `Cache-Control` (Sensitive APIs) | `no-store, no-cache, must-revalidate, private` | **Web Cache Deception & Shared Proxy Leakage**: Prevents browsers, CDNs, and forward proxies from writing authenticated responses to disk or memory caches. |
| `Set-Cookie` (Session Cookie) | `__Host-sid=<VAL>; Secure; HttpOnly; SameSite=Strict; Path=/` | **Session Hijacking, XSS Cookie Theft, Cookie Tossing & CSRF**: The `__Host-` prefix forces the browser to verify `Secure`, `Path=/`, and the absence of a `Domain` attribute (preventing subdomain cookie tossing). |

---

### 1.3 TLS 1.2 & TLS 1.3 Cipher Suite Security Classification

#### TLS 1.3 Cipher Suites (RFC 8446 — All Provide Forward Secrecy via Ephemeral `X25519` / `ECDHE` and AEAD Encryption)
| IANA / OpenSSL Cipher Suite Name | Key Exchange | Bulk AEAD Cipher | Hash / HKDF PRF | Security Rating |
| :--- | :--- | :--- | :--- | :--- |
| `TLS_AES_256_GCM_SHA384` | Ephemeral (`X25519MLKEM768` / `X25519` / `secp384r1`) | `AES-256-GCM` (128-bit auth tag) | `SHA-384` | **RECOMMENDED (CNSA 2.0 / Modern)** |
| `TLS_CHACHA20_POLY1305_SHA256` | Ephemeral (`X25519MLKEM768` / `X25519` / `secp256r1`) | `ChaCha20-Poly1305` (256-bit key) | `SHA-256` | **RECOMMENDED (Ideal for Mobile / Non-AES-NI)** |
| `TLS_AES_128_GCM_SHA256` | Ephemeral (`X25519` / `secp256r1`) | `AES-128-GCM` (128-bit auth tag) | `SHA-256` | **RECOMMENDED (Standard Web)** |

#### TLS 1.2 Cipher Suites (RFC 5246 — Only `ECDHE` + `AEAD` Suites Are Acceptable)
| OpenSSL Cipher Name | IANA Standard Name | Key Exchange & Auth | Bulk Cipher & Mode | Security Rating |
| :--- | :--- | :--- | :--- | :--- |
| `ECDHE-ECDSA-AES256-GCM-SHA384` | `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384` | `ECDHE` + `ECDSA` (PFS) | `AES-256-GCM` (AEAD) | **SAFE (TLS 1.2 Intermediate)** |
| `ECDHE-RSA-AES256-GCM-SHA384` | `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` | `ECDHE` + `RSA` (PFS) | `AES-256-GCM` (AEAD) | **SAFE (TLS 1.2 Intermediate)** |
| `ECDHE-ECDSA-CHACHA20-POLY1305` | `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256` | `ECDHE` + `ECDSA` (PFS) | `ChaCha20-Poly1305` | **SAFE (TLS 1.2 Intermediate)** |
| `AES256-GCM-SHA384` | `TLS_RSA_WITH_AES_256_GCM_SHA384` | Static `RSA` (**NO Forward Secrecy!**) | `AES-256-GCM` | **WEAK / DEPRECATED (Static RSA KEX)** |
| `ECDHE-RSA-AES256-SHA384` | `TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384` | `ECDHE` + `RSA` | `AES-256-CBC` (MAC-then-Encrypt) | **WEAK (Vulnerable to Lucky13 Padding Oracles)** |
| `DES-CBC3-SHA` | `TLS_RSA_WITH_3DES_EDE_CBC_SHA` | Static `RSA` | `3DES-CBC` (64-bit block) | **INSECURE (Sweet32 Birthday Attack CVE-2016-2183)** |
| `RC4-SHA` / `RC4-MD5` | `TLS_RSA_WITH_RC4_128_SHA` | Static `RSA` | `RC4` stream cipher | **PROHIBITED (RFC 7465 — Keystream Bias)** |

---

## Section 2: Applied Cryptography & Post-Quantum Quick-Reference

### 2.1 Modern Cryptographic Primitives Matrix

| Cryptographic Function | Recommended Production Standard | Key / Output Size | Legacy / Broken Algorithms to Replace | Critical Implementation Pitfalls |
| :--- | :--- | :--- | :--- | :--- |
| **Cryptographic Hashing** | `SHA-256`, `SHA-384`, `SHA-512` (FIPS 180-4), `SHA3-256` (FIPS 202), `BLAKE3` | 256–512 bits | `MD5` (collision broken), `SHA-1` (SHAttered collision broken) | Never use bare `SHA-256(secret || msg)` for MACs due to **Merkle-Damgård Length Extension** (`SHA-3` and `BLAKE3` are immune). |
| **Message Authentication (MAC)** | `HMAC-SHA256`, `HMAC-SHA512` (RFC 2104), `KMAC256`, `Poly1305` | 256-bit key, 256-bit tag | Custom hash concatenation, truncated MACs `< 128` bits | Always verify MACs using a **constant-time comparison** (`hmac.compare_digest` / `CRYPTO_memcmp`) to prevent byte-by-byte timing attacks. |
| **Password Hashing (KDF)** | `Argon2id` (RFC 9106: `m=64MiB, t=3, p=4`), `scrypt`, `PBKDF2-HMAC-SHA512` (`>=600,000` iterations) | 128-bit unique CSPRNG salt, 256-bit output | Fast hashes (`MD5`, `SHA-256`, `NTLM`), unsalted hashes, `DES crypt` | `bcrypt` silently truncates passwords at **72 bytes** (`NUL` byte inclusive) — never pre-hash with hex without knowing the 72-byte limit. |
| **Key Derivation (High-Entropy Secret)** | `HKDF-SHA256` / `HKDF-SHA384` (RFC 5869 Extract-and-Expand) | Input keying material -> arbitrary subkeys | Direct key slicing or reuse of a single key for both encryption and MAC | Always pass a domain-separation `info` context label (`"app-v1-aes-key"`) to `HKDF-Expand`. |
| **Symmetric Encryption (AEAD)** | `AES-256-GCM` (NIST SP 800-38D), `ChaCha20-Poly1305` (RFC 8439), `XChaCha20-Poly1305` | 256-bit key, 96-bit nonce (`192-bit` for `XChaCha20`), 128-bit tag | `AES-ECB` (leaks patterns), unauthenticated `AES-CBC` (Padding Oracle) | **Catastrophic Nonce Reuse in GCM/ChaCha20**: Reusing the same `(Key, 96-bit Nonce)` pair twice leaks `C1 XOR C2 = P1 XOR P2` and recovers the `GHASH` authentication key `H` via polynomial root finding (`Forbidden Attack`). |
| **Asymmetric Encryption** | `RSA-OAEP` (RFC 8017 PKCS#1 v2.2 with `SHA-256` MGF1), `ECIES` / `HPKE` (RFC 9180) | RSA `>= 3072` bits (or `4096` bits) | `RSA PKCS#1 v1.5` encryption (Bleichenbacher million-message oracle) | Do not encrypt bulk data directly with RSA; use **Hybrid Encryption** (`HPKE` or `ML-KEM` / `ECDH` + `AES-256-GCM`). |
| **Digital Signatures (Classical)** | `Ed25519` (RFC 8032), `ECDSA` (`P-256`/`P-384` with RFC 6979 deterministic `k`), `RSA-PSS` | `Ed25519`: 256-bit key, 512-bit signature | `DSA`, `ECDSA` with biased/reused nonce `k` | Reusing or biasing the ephemeral per-signature nonce `k` in `ECDSA`/`DSA` allows immediate algebraic recovery of the private key `d` from two signatures! `Ed25519` derives `k` deterministically via `SHA-512(prefix || message)`. |
| **Classical Key Exchange** | `X25519` (RFC 7748 Curve25519 ECDH), `ECDH P-384` | 256-bit / 384-bit ephemeral keys | Static DH, `DHE` `< 2048` bits (Logjam attack) | Validate curve points when using NIST Weierstrass curves (`P-256`) to prevent **Invalid Curve Attacks** (`X25519` Montgomery ladder is twist-secure by design). |

---

### 2.2 NIST Post-Quantum Cryptography (PQC) Standards Reference (FIPS 203, 204, 205)

Shor's quantum algorithm solves integer factorization (`RSA`) and discrete logarithms (`DH`, `ECDH`, `ECDSA`, `Ed25519`) in polynomial time $O((\log N)^3)$ on a cryptographically relevant quantum computer (CRQC), while Grover's algorithm provides a quadratic speedup $O(2^{n/2})$ against symmetric ciphers (requiring `AES-256` and `SHA-384`/`SHA-512`). To counter **"Harvest Now, Decrypt Later" (HNDL)** attacks, NIST standardized three foundational Post-Quantum Cryptography standards in August 2024:

| NIST Standard | Algorithm Name (Former Name) | Mathematical Hardness Problem | Security Parameter Sets & Sizes | Primary Enterprise Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **FIPS 203** | **ML-KEM** (*Module-Lattice-Based Key-Encapsulation Mechanism*, formerly **CRYSTALS-Kyber**) | Module Learning With Errors (**MLWE**) over polynomial rings $\mathbb{Z}_q[X]/(X^{256}+1)$ | **`ML-KEM-512`** (AES-128 eq.)<br>**`ML-KEM-768`** (AES-192 eq.: PubKey=`1,184 B`, Ciphertext=`1,088 B`, SharedSecret=`32 B`)<br>**`ML-KEM-1024`** (AES-256 eq.: PubKey=`1,568 B`, Ciphertext=`1,568 B`) | TLS 1.3 Hybrid Key Exchange (`X25519MLKEM768`), SSH (`mlkem768x25519-sha256`), IPsec IKEv2, HPKE encryption. |
| **FIPS 204** | **ML-DSA** (*Module-Lattice-Based Digital Signature Algorithm*, formerly **CRYSTALS-Dilithium**) | Module Learning With Errors (**MLWE**) & Module Short Integer Solution (**MSIS**) | **`ML-DSA-44`** (Category 2)<br>**`ML-DSA-65`** (Category 3: PubKey=`1,952 B`, Signature=`3,309 B`)<br>**`ML-DSA-87`** (Category 5 / CNSA 2.0: PubKey=`2,592 B`, Signature=`4,627 B`) | Primary general-purpose post-quantum digital signatures for X.509 PKI certificates, code signing, and JWT/COSE signing. |
| **FIPS 205** | **SLH-DSA** (*Stateless Hash-Based Digital Signature Algorithm*, formerly **SPHINCS+**) | Cryptographic Hash Function Preimage & Collision Resistance (`SHA-2` or `SHAKE256`) | **`SLH-DSA-SHA2-128s`** (Small sig: PubKey=`32 B`, Sig=`7,856 B`)<br>**`SLH-DSA-SHAKE-256f`** (Fast sign: PubKey=`64 B`, Sig=`49,856 B`) | Conservative backup signature standard relying strictly on hash security (no lattice assumptions); ideal for root CA and firmware signing. |

---

### 2.3 OpenSSL Command-Line Operational Handbook

```bash
# 1. Compute SHA-256, SHA-512, and HMAC-SHA256 of a file
openssl dgst -sha256 payload.bin
openssl dgst -sha256 -hmac "MySuperSecretKey" payload.bin

# 2. Generate 32 Bytes (256 bits) of CSPRNG Entropy (Hex or Base64)
openssl rand -hex 32
openssl rand -base64 32

# 3. Authenticated Symmetric Encryption (AES-256-CBC + PBKDF2 600,000 iterations)
openssl enc -aes-256-cbc -salt -pbkdf2 -iter 600000 -in secrets.txt -out secrets.txt.enc
openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -in secrets.txt.enc -out secrets.txt.dec

# 4. Generate Ed25519 Private/Public Key Pair & Sign/Verify a Binary Release
openssl genpkey -algorithm Ed25519 -out ed25519_priv.pem
openssl pkey -in ed25519_priv.pem -pubout -out ed25519_pub.pem
openssl pkeyutl -sign -inkey ed25519_priv.pem -rawin -in release.tar.gz -out release.sig
openssl pkeyutl -verify -pubin -inkey ed25519_pub.pem -rawin -in release.tar.gz -sigfile release.sig

# 5. Generate RSA-4096 Key Pair & Encrypt/Decrypt using RSA-OAEP with SHA-256
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out rsa4096_priv.pem
openssl pkey -in rsa4096_priv.pem -pubout -out rsa4096_pub.pem
openssl pkeyutl -encrypt -pubin -inkey rsa4096_pub.pem \
  -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -in key.bin -out key.bin.enc
openssl pkeyutl -decrypt -inkey rsa4096_priv.pem \
  -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -in key.bin.enc -out key.bin.dec

# 6. Inspect Remote Server TLS 1.3 Handshake, Certificate Chain, OCSP Stapling & SANs
openssl s_client -connect example.com:443 -servername example.com -tls1_3 -status </dev/null

# 7. Inspect Local X.509 Certificate Expiration, Subject, Issuer, SANs, and SHA-256 Fingerprint
openssl x509 -in server.crt -noout -subject -issuer -dates -fingerprint -sha256 -ext subjectAltName
```

---

## Section 3: Regular Expressions (Regex) Cheat Sheet for Log Analysis, WAF Rules & Source Code Auditing

| Detection / Audit Use Case | Production PCRE / ERE Regular Expression Pattern | Technical Explanation |
| :--- | :--- | :--- |
| **IPv4 Address (Strict `0–255` Octets)** | `\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b` | Matches valid dotted-quad IPv4 addresses while rejecting invalid octets like `999.999.999.999`. |
| **RFC 1918 Private IPv4 Detection** | `\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b` | Identifies internal RFC 1918 addresses (`10/8`, `172.16/12`, `192.168/16`) in SSRF filters and proxy logs. |
| **SQL Injection (Classic & Blind Probes)** | `(?i)(?:\bunion\b[\s\/\*]+(?:\ball\b[\s\/\*]+)?\bselect\b|(?:'|%27)\s*(?:or|and)\s*(?:'|%27)?\d+(?:'|%27)?\s*=\s*(?:'|%27)?\d+|\b(?:waitfor\s+delay|pg_sleep|benchmark)\s*\()` | Detects `UNION [ALL] SELECT` (including `/**/` comment evasion), boolean tautologies (`' OR '1'='1`), and time-delay functions. |
| **Cross-Site Scripting (XSS Vectors)** | `(?i)(?:<\s*script\b[^>]*>|\bon(?:error|load|mouseover|focus|click|animationstart|toggle)\s*=|(?:javascript|vbscript|data)\s*:)` | Detects `<script>` tags, inline DOM event handlers (`onerror=`, `onload=`), and pseudo-protocol URIs. |
| **Path Traversal / Local File Inclusion (LFI)** | `(?i)(?:(?:\.|%2e|%252e){2}(?:\/|\\|%2f|%5c|%252f|%255c))+` | Matches single- and double-URL-encoded `../` and `..\` directory traversal sequences. |
| **Log4Shell JNDI Injection (`CVE-2021-44228`)** | `(?i)\$\{(?:jndi|lower|upper|env|sys|date|base64)[^}]{0,80}:(?:ldap|ldaps|rmi|dns|iiop|corba|nis|nds):` | Matches obfuscated Log4j2 lookup expressions invoking remote JNDI directory protocols. |
| **JSON Web Token (JWT) Extraction** | `\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*\b` | Matches 3-part Base64URL-encoded JWTs (`eyJ` = `{"` in Base64) in HTTP logs or source code. |
| **AWS Access Key ID (`AKIA` / `ASIA`)** | `\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b` | Matches 20-character AWS IAM long-term (`AKIA`) and STS temporary (`ASIA`) access key identifiers. |
| **GitHub Personal Access Token (`ghp_`/`github_pat_`)** | `\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}\b` | Matches classic and fine-grained GitHub API tokens in git commit history (`gitleaks`/`trufflehog`). |
| **PEM Private Key Block Header** | `-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----` | Detects leaked PKCS#1, PKCS#8, SEC1, or OpenSSH private keys in repositories or logs. |
| **SHA-256 Hexadecimal Hash** | `\b[a-fA-F0-9]{64}\b` | Matches 64-character hexadecimal SHA-256 digests in threat intelligence feeds. |
| **Dangerous C/C++ Memory Functions (SAST)** | `\b(?:strcpy|strcat|sprintf|vsprintf|gets|scanf|sscanf)\s*\(` | Audits C/C++ source trees for unbounded buffer manipulation functions (`CWE-120`). |

---

## Section 4: A–Z Cybersecurity Encyclopedia Glossary (260 Essential Terms)

### A
1. **ABAC (Attribute-Based Access Control)**: An authorization paradigm that evaluates dynamic attributes of the subject (user role, clearance, department), object (data classification, owner), action, and environment (time of day, device posture, IP geolocation) against boolean policy rules (`XACML`, `OPA/Rego`).
2. **ACID (Atomicity, Consistency, Isolation, Durability)**: The four transactional guarantees of relational database systems that prevent partial state corruption and financial race conditions (`TOCTOU` / Double-Spend) when properly configured with `SERIALIZABLE` or row-level locks (`SELECT ... FOR UPDATE`).
3. **ACL (Access Control List)**: An ordered list of permit/deny rules attached to an object (filesystem inode, Active Directory `nTSecurityDescriptor`, or network router interface) specifying which principals are granted specific operations.
4. **Active Directory (AD)**: Microsoft's enterprise directory service integrating LDAP directory objects, Kerberos v5 authentication, DNS, and Group Policy Objects (`GPOs`) stored inside the `NTDS.dit` Extensible Storage Engine database.
5. **AD CS (Active Directory Certificate Services)**: Microsoft's enterprise Public Key Infrastructure (PKI) implementation; misconfigured certificate templates (`ESC1`–`ESC13`) allow low-privileged users to request certificates for Domain Admins via arbitrary `SubjectAltName` injection.
6. **AEAD (Authenticated Encryption with Associated Data)**: Symmetric cryptographic cipher modes (`AES-GCM`, `ChaCha20-Poly1305`) that simultaneously guarantee confidentiality of the plaintext and cryptographic integrity/authenticity of both the ciphertext and unencrypted headers (`AAD`).
7. **AES (Advanced Encryption Standard)**: The NIST FIPS 197 symmetric block cipher based on the Rijndael substitution-permutation network operating on 128-bit blocks using 128-, 192-, or 256-bit keys (10, 12, or 14 rounds).
8. **Air Gap**: Physical and electromagnetic isolation of a critical network (nuclear ICS, offline Root CA HSM) from all public and enterprise networks.
9. **ALPN (Application-Layer Protocol Negotiation)**: A TLS extension (RFC 7301) that allows the client and server to negotiate the application protocol (`h2`, `http/1.1`, `h3`) during the initial TLS handshake without extra round trips.
10. **Amcache (`Amcache.hve`)**: A Windows registry hive located at `C:\Windows\AppCompat\Programs\Amcache.hve` that records file paths, timestamps, PE compile times, and SHA-1 hashes of executed binaries for DFIR triage.
11. **AMSI (Antimalware Scan Interface)**: A Windows API (`amsi.dll`) integrated into PowerShell, VBScript, JScript, WMI, and .NET CLR (`v4.8+`) that passes de-obfuscated script buffers to the registered EDR/antivirus engine prior to execution.
12. **Anycast**: A network routing methodology where multiple geographically distributed BGP autonomous system nodes advertise the same IP prefix, routing client traffic to the topologically nearest scrubbing center (used for DDoS mitigation and root DNS).
13. **API Gateway**: A reverse proxy enforcement point positioned in front of microservices that handles mTLS termination, OAuth2/JWT validation, schema validation, and rate limiting.
14. **AppArmor**: A Linux Kernel Security Module (`LSM`) that confines individual programs to per-binary path-based Mandatory Access Control profiles (`/etc/apparmor.d/`).
15. **AppLocker**: A Windows application allowlisting feature enforcing execution rules across Executables, DLLs, MSI installers, Packaged Apps, and Scripts based on Publisher digital signature, File Hash, or Path.
16. **Argon2id**: The winner of the Password Hashing Competition (RFC 9106) that combines data-independent memory access (`Argon2i`, resisting side-channel timing attacks) with data-dependent memory access (`Argon2d`, resisting GPU/ASIC time-memory trade-off cracking).
17. **ARP Spoofing (ARP Poisoning)**: A Layer-2 Man-in-the-Middle attack in which an adversary broadcasts forged gratuitous ARP replies associating the attacker's MAC address with the IPv4 address of the default gateway or victim host.
18. **AS-REP Roasting**: An Active Directory attack (`MITRE T1558.004`) targeting user accounts with the `UF_DONT_REQUIRE_PREAUTH` flag enabled, allowing any user to request an `AS-REP` ticket from the KDC encrypted with the user's RC4/AES password hash for offline cracking.
19. **ASan (AddressSanitizer)**: A compiler instrumentation technology (`-fsanitize=address`) in GCC and Clang that uses virtual shadow memory and redzones to detect stack, heap, and global buffer overflows as well as Use-After-Free (`UAF`) bugs at runtime.
20. **ASN.1 (Abstract Syntax Notation One)**: An interface description language used to define data structures in X.509 certificates, Kerberos tickets, SNMP, and LDAP packets, serialized via BER/DER encoding rules.
21. **ASLR (Address Space Layout Randomization)**: An OS kernel exploit mitigation (`/proc/sys/kernel/randomize_va_space=2`) that randomizes the base virtual memory addresses of the stack, heap, shared libraries (`libc`), and PIE executable segments on every execution.
22. **Attestation (TPM / Remote Attestation)**: The cryptographic process whereby a hardware Trusted Platform Module (`TPM 2.0`) signs Platform Configuration Registers (`PCRs`) using an Attestation Identity Key (`AIK`) to prove boot chain integrity to a remote verifier.
23. **Auditd (Linux Audit Daemon)**: The user-space daemon and kernel subsystem (`kauditd`) that intercepts Linux system calls (`execve`, `openat`, `connect`, `ptrace`, `init_module`) and writes tamper-evident telemetry to `/var/log/audit/audit.log`.

### B
24. **BGP Hijacking**: The unauthorized advertisement of IP prefixes by a rogue or misconfigured Autonomous System (`AS`) in the Border Gateway Protocol, mitigated via **RPKI (Resource Public Key Infrastructure)** Route Origin Authorizations (`ROAs`) and BGPsec.
25. **Biba Integrity Model**: A formal lattice-based information security model focused strictly on data **Integrity** (*"No Read Down, No Write Up"* — the mathematical dual of Bell-LaPadula).
26. **Bell-LaPadula Model**: A formal state-machine Mandatory Access Control model focused on **Confidentiality** enforcing the Simple Security Property (*"No Read Up"*) and the `*-Property` (*"No Write Down"*).
27. **BOLA (Broken Object Level Authorization)**: Ranked #1 on the OWASP API Security Top 10 (2023), also known as **IDOR**, occurring when an API endpoint fails to verify that the authenticated caller owns or is permitted to access the specific object ID requested.
28. **BPF / eBPF (Extended Berkeley Packet Filter)**: An in-kernel virtual machine in modern Linux that allows verified, JIT-compiled programs to attach safely to kernel tracepoints, `kprobes`, network XDP hooks, and LSM hooks (`Tetragon`, `Falco`, `Cilium`).
29. **BloodHound**: An Active Directory graph theory analysis tool that uses `SharpHound` or `bloodhound-python` to map ACL relationships (`GenericAll`, `WriteDacl`), group memberships, and active sessions to uncover shortest privilege escalation paths to Domain Admin.
30. **Birthday Attack**: A cryptographic collision attack exploiting the birthday paradox, finding two inputs $x \neq y$ with $H(x) = H(y)$ for an $n$-bit hash function in $O(2^{n/2})$ evaluations rather than $O(2^n)$.
31. **Blind SQL Injection**: An SQL injection vulnerability where the application does not return database rows or error strings in the HTTP response, forcing the attacker to infer data bit-by-bit via boolean page differences or time delays (`pg_sleep()`, `WAITFOR DELAY`).
32. **BlueKeep (`CVE-2019-0708`)**: A critical pre-authentication Use-After-Free vulnerability in Windows Remote Desktop Services (`termdd.sys`) virtual channel handling.
33. **BMC (Baseboard Management Controller)**: An out-of-band hardware management microcontroller (`IPMI`, `iDRAC`, `iLO`) embedded on enterprise server motherboards that must be isolated on a dedicated management VLAN.
34. **BYOVD (Bring Your Own Vulnerable Driver)**: An adversary defense-evasion technique (`MITRE T1068`) where a legitimately Microsoft-signed third-party kernel driver with known arbitrary kernel read/write IOCTLs (`RTCore64.sys`) is loaded to disable EDR kernel callbacks (`PsSetCreateProcessNotifyRoutine`).

### C
35. **CAA (Certification Authority Authorization)**: A DNS resource record (RFC 8659) that allows a domain owner to specify which Certificate Authorities (`issue "letsencrypt.org"`) are authorized to issue TLS certificates for that domain.
36. **Canary (Stack Canary / Stack Cookie)**: A random 64-bit word inserted on the call stack between local buffers and saved control data (`RBP`/`RIP`) that causes the program to abort via `__stack_chk_fail` if overwritten by a linear stack buffer overflow.
37. **Capabilities (Linux POSIX Capabilities)**: A partitioning of traditional superuser (`UID 0`) privileges into discrete kernel bitmasks (`CAP_NET_BIND_SERVICE`, `CAP_NET_RAW`, `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`) tracked per thread and per file (`security.capability` xattr).
38. **CBC (Cipher Block Chaining)**: A block cipher mode where each plaintext block is XORed with the previous ciphertext block before encryption; vulnerable to **Padding Oracle attacks (Vaudenay / POODLE / Lucky13)** if used without Encrypt-then-MAC.
39. **Certificate Transparency (CT)**: An open cryptographic audit framework (RFC 6962) requiring CAs to append all issued X.509 certificates to publicly verifiable, append-only Merkle tree logs (`Signed Certificate Timestamps`), enabling domain owners to detect rogue certificates.
40. **CET (Control-flow Enforcement Technology)**: Hardware CPU security extensions (Intel CET / AMD Shadow Stack) providing a hardware-protected **Shadow Stack (`SHSTK`)** for return addresses (`RET`) and **Indirect Branch Tracking (`IBT` / `ENDBR64`)** for indirect jumps/calls to defeat ROP and JOP.
41. **CFI (Control-Flow Integrity)**: A compile-time and runtime exploit mitigation (`-fsanitize=cfi`) that validates the target of every indirect function call or virtual method table (`vtable`) pointer against a statically computed graph of valid targets before branching.
42. **ChaCha20-Poly1305**: An ARX (Add-Rotate-XOR) stream cipher paired with the Poly1305 Wegman-Carter polynomial authenticator (RFC 8439), offering constant-time execution immune to cache-timing attacks on CPUs lacking hardware AES instructions.
43. **Chain of Custody**: The chronological paper or cryptographic ledger documenting the seizure, custody, transfer, analysis, and storage of physical or digital forensic evidence (`SHA-256` hashes, timestamps, handler signatures) required for legal admissibility.
44. **Chroot Jail**: A Unix system call (`chroot(2)`) that changes the apparent root directory (`/`) for a process and its children; not a security boundary for `UID 0` processes unless combined with mount/user namespaces (`pivot_root`).
45. **CI/CD Pipeline Poisoning (PPE)**: An attack (`CWE-94`) where an adversary modifies `.github/workflows/*.yml`, `Jenkinsfile`, or `.gitlab-ci.yml` in a pull request to execute arbitrary commands on the build runner and steal deployment secrets.
46. **CIDR (Classless Inter-Domain Routing)**: IP address allocation and route aggregation notation (`192.168.10.0/24`) specifying the number of leading network prefix bits.
47. **Ciphertext Indistinguishability (`IND-CPA` / `IND-CCA2`)**: The formal cryptographic security definitions stating that an adversary cannot distinguish the encryption of two chosen plaintexts under Chosen-Plaintext Attack (`IND-CPA`) or Adaptive Chosen-Ciphertext Attack (`IND-CCA2`).
48. **Clickjacking (UI Redressing)**: A browser attack where an adversary overlays a transparent `<iframe src="https://bank.com/transfer">` over a decoy button, tricking the user into clicking authenticated controls; mitigated by `Content-Security-Policy: frame-ancestors 'none'` and `X-Frame-Options: DENY`.
49. **CloudTrail**: Amazon Web Services' control-plane audit service recording every API call (`AssumeRole`, `RunInstances`, `PutBucketPolicy`) made inside an AWS account as structured JSON events.
50. **CNAPP (Cloud-Native Application Protection Platform)**: An integrated cloud security architecture combining CSPM (Cloud Security Posture Management), CWPP (Cloud Workload Protection), CIEM (Cloud Infrastructure Entitlement Management), and IaC scanning.
51. **Command Injection (OS Command Injection, `CWE-78`)**: A critical vulnerability occurring when untrusted user input is passed to a system shell interpreter (`system()`, `popen()`, `subprocess.run(..., shell=True)`, `child_process.exec()`), allowing arbitrary OS command execution via shell metacharacters (`;`, `|`, `&&`, `$(...)`).
52. **Confidential Computing**: Hardware-enforced memory encryption (`AMD SEV-SNP`, `Intel TDX`, `Intel SGX`, `AWS Nitro Enclaves`) that protects data **in use** inside RAM from a compromised hypervisor or physical cold-boot inspection.
53. **Constrained Delegation (Kerberos S4U2Self / S4U2Proxy)**: An Active Directory mechanism (`msDS-AllowedToDelegateTo`) allowing a front-end service to impersonate a user only to specific back-end SPNs defined by the Domain Administrator.
54. **Container Escape**: Breaking out of a container runtime (`runc`, `containerd`) namespace/cgroup isolation to gain execution on the underlying host Linux kernel (via `--privileged`, mounted `/var/run/docker.sock`, `CAP_SYS_ADMIN`, or kernel vulnerabilities like `Dirty Pipe`).
55. **CORS (Cross-Origin Resource Sharing)**: An HTTP header mechanism (`Access-Control-Allow-Origin`, `Access-Control-Allow-Credentials`) allowing a server to selectively relax the browser's Same-Origin Policy (`SOP`); reflecting an arbitrary `Origin` header alongside `Access-Control-Allow-Credentials: true` creates a critical cross-origin data theft vulnerability.
56. **Credential Stuffing**: Automated injection of millions of breached `(username, password)` pairs into login endpoints to hijack accounts where users reused passwords across services.
57. **CRLs (Certificate Revocation Lists)**: Time-stamped, CA-signed lists of revoked X.509 certificate serial numbers largely superseded by **OCSP Stapling** and **CRLite** due to bandwidth and soft-fail latency issues.
58. **Cryptojacking**: Unauthorized execution of cryptocurrency mining software (`XMRig` mining Monero via the `RandomX` algorithm) on compromised servers, Kubernetes clusters, or cloud instances.
59. **CSPRNG (Cryptographically Secure Pseudo-Random Number Generator)**: A random number generator (`/dev/urandom`, `getrandom(2)`, `secrets` in Python, `crypto.getRandomValues()`) satisfying the **next-bit test** and **backtracking resistance**, suitable for generating cryptographic keys, IVs, and session tokens.
60. **CSRF (Cross-Site Request Forgery)**: A web attack that forces an authenticated user's browser to send an unintended state-changing request (`POST /change-email`) to a vulnerable web application where cookies are automatically attached; mitigated via `SameSite=Strict`/`Lax` cookies, synchronizer CSRF tokens, and custom request headers.
61. **CTI (Cyber Threat Intelligence)**: Evidence-based knowledge regarding adversary TTPs, infrastructure, indicators of compromise (`IoCs`), and strategic geopolitical motives structured via **STIX 2.1** and exchanged over **TAXII**.
62. **CVE (Common Vulnerabilities and Exposures)**: The MITRE-maintained international dictionary of publicly disclosed cybersecurity vulnerabilities (`CVE-YYYY-NNNNN`).
63. **CVSS (Common Vulnerability Scoring System)**: The FIRST standard (`CVSS v3.1` and `CVSS v4.0`) for quantifying the technical severity of software vulnerabilities on a `0.0–10.0` scale across Base, Threat, and Environmental metric groups.
64. **CWE (Common Weakness Enumeration)**: A hierarchical taxonomy of software and hardware vulnerability root causes (`CWE-79` XSS, `CWE-89` SQLi, `CWE-416` Use-After-Free, `CWE-787` Out-of-Bounds Write).

### D
65. **DAC (Discretionary Access Control)**: An access control model (such as standard POSIX `rwx` owner/group/other permissions) in which the owner of an object can freely modify its permissions (`chmod`) and grant access to other subjects at their discretion.
66. **DAST (Dynamic Application Security Testing)**: Black-box security testing (`OWASP ZAP`, `Nuclei`, `Burp Suite`) that probes a running web application or API over HTTP to identify runtime vulnerabilities.
67. **DCSync**: A credential access attack (`MITRE T1003.006`) where an adversary holding `DS-Replication-Get-Changes-All` permissions impersonates a Domain Controller using the MS-DRSR (`drsuapi`) RPC protocol to replicate `krbtgt` and all user NTLM/AES password hashes from `NTDS.dit`.
68. **DDoS (Distributed Denial of Service)**: An availability attack overwhelming network bandwidth (UDP/DNS/Memcached amplification), transport state tables (`SYN` flood), or application layer CPU/database pools (`HTTP/2 Rapid Reset CVE-2023-44487`) from a distributed botnet.
69. **DEP / NX (Data Execution Prevention / No-eXecute)**: Hardware page-table bit enforcement (`XD` on Intel, `NX` on AMD, `XN` on ARM64) marking stack and heap memory pages non-executable (`W^X`), preventing direct execution of injected stack/heap shellcode.
70. **Deserialization (Insecure Deserialization, `CWE-502`)**: A critical vulnerability occurring when an application deserializes untrusted byte streams (`Python pickle`, `Java ObjectInputStream`, `PHP unserialize()`, `.NET BinaryFormatter`), triggering "magic methods" (`__reduce__`, `readObject`, `__wakeup`) across **POP Gadget Chains** to achieve Remote Code Execution.
71. **DFIR (Digital Forensics and Incident Response)**: The discipline combining incident containment/eradication (`NIST SP 800-61r2`) with forensic preservation and analysis of volatile memory, disk structures, and network telemetry.
72. **DGA (Domain Generation Algorithm)**: An algorithm embedded in malware that deterministically generates thousands of pseudo-random domain names daily based on a date/seed so the C2 server only needs to register one domain to rendezvous with infected hosts.
73. **DHCP Snooping**: A Layer-2 switch security feature that filters untrusted DHCP server messages (`DHCPOFFER`, `DHCPACK`) on access ports and builds a trusted **DHCP Binding Database** (`MAC <-> IP <-> VLAN <-> Port`) used by Dynamic ARP Inspection (`DAI`) and IP Source Guard.
74. **Diffie-Hellman (DH / ECDH)**: A key agreement protocol allowing two parties to establish a shared secret over an insecure channel; ephemeral variants (`DHE`, `ECDHE`, `X25519`) provide **Perfect Forward Secrecy (PFS)**.
75. **DKIM (DomainKeys Identified Mail)**: An email authentication standard (RFC 6376) that attaches a cryptographic digital signature (`DKIM-Signature` header) computed over selected email headers and body hash, verified via the sender domain's public key published in DNS (`selector._domainkey.domain`).
76. **DKOM (Direct Kernel Object Manipulation)**: A kernel rootkit technique that directly modifies kernel data structures in RAM (such as unlinking a process's `_EPROCESS` struct from the doubly-linked `ActiveProcessLinks` list) to hide processes from `taskmgr.exe` or `ps`.
77. **DLL Hijacking / Sideloading (`MITRE T1574.001/.002`)**: Placing a malicious DLL with the same name as a required dependency in a directory searched prior to `C:\Windows\System32` (or bundling a signed legitimate executable alongside a trojanized dependency DLL) so the signed binary loads attacker code into its trusted process context.
78. **DLP (Data Loss Prevention)**: Enterprise controls that inspect egress network traffic, email attachments, cloud uploads, and USB writes for sensitive data patterns (credit card Luhn numbers, SSNs, source code, classification watermarks).
79. **DMARC (Domain-based Message Authentication, Reporting, and Conformance)**: An email security DNS policy (`_dmarc.domain`) requiring alignment between the `RFC5322.From` header domain and either `SPF` or `DKIM`, specifying whether failing messages should be monitored (`p=none`), quarantined (`p=quarantine`), or rejected (`p=reject`).
80. **DMZ (Demilitarized Zone / Screened Subnet)**: A perimeter network segment positioned between the untrusted public Internet and the internal corporate intranet, hosting public-facing reverse proxies and mail relays under strict east-west and north-south firewall rules.
81. **DNS Rebinding**: An attack against SSRF filters and local IoT/developer web servers where an attacker-controlled DNS server responds to the initial validation query with a public IP (`TTL=0`) and immediately responds to the subsequent HTTP fetch with `127.0.0.1` or `169.254.169.254`.
82. **DNSSEC (Domain Name System Security Extensions)**: A suite of IETF specifications (RFC 4033–4035) that adds cryptographic origin authentication and integrity to DNS records using hierarchical digital signatures (`RRSIG`, `DNSKEY`, `DS`, `NSEC3`) anchored at the root zone.
83. **DOM-Based XSS**: A Cross-Site Scripting vulnerability that occurs entirely inside client-side JavaScript when data from an attacker-controllable **Source** (`location.search`, `location.hash`, `window.name`, `postMessage`) is passed into a dangerous execution **Sink** (`innerHTML`, `eval()`, `document.write()`) without sanitization.
84. **Double-Free (`CWE-415`)**: Calling `free()` twice on the same heap pointer without an intervening reallocation, corrupting heap allocator freelist metadata (`tcache` / `fastbins` in `glibc ptmalloc`) and enabling arbitrary write primitives.
85. **DPAPI (Data Protection Application Programming Interface)**: Windows' built-in symmetric cryptographic architecture (`CryptProtectData`) used by browsers, Credential Manager, and EFS to encrypt user secrets using master keys derived from the user's logon password or domain backup key.

### E
86. **EAP-TLS (Extensible Authentication Protocol - Transport Layer Security)**: The gold-standard IEEE 802.1X wireless (`WPA3-Enterprise`) and wired NAC authentication method requiring mutual X.509 certificate authentication between the client supplicant and RADIUS server.
87. **ECB (Electronic Codebook Mode)**: The simplest block cipher mode where identical 128-bit plaintext blocks always encrypt to identical 128-bit ciphertext blocks (famously illustrated by the **ECB Penguin**), leaking structural patterns and permitting block replay/reordering.
88. **Ed25519**: A high-speed, constant-time Edwards-curve Digital Signature Algorithm (RFC 8032) operating over `Curve25519` and `SHA-512` that generates deterministic nonces and is immune to side-channel timing and invalid-curve attacks.
89. **EDR (Endpoint Detection and Response)**: Kernel- and user-mode endpoint security sensors that record continuous behavioral telemetry (process trees, ETW, AMSI, memory allocations, network sockets) and provide automated host isolation and remote live response.
90. **ELF (Executable and Linkable Format)**: The standard binary file format (`\x7fELF` magic bytes `0x7F 0x45 0x4C 0x46`) for executables, object code, shared libraries (`.so`), and core dumps on Linux and Unix-like operating systems.
91. **Entropy (Shannon Information Entropy)**: A measure of randomness in a byte stream ($H = -\sum P(x_i) \log_2 P(x_i)$, ranging from `0.0` to `8.0` bits per byte); packed, compressed, or encrypted malware payloads typically exhibit entropy `> 7.2` bits/byte.
92. **EPSS (Exploit Prediction Scoring System)**: A data-driven model managed by FIRST that outputs a probability score (`0.0–1.0` / `0–100%`) estimating the likelihood that a given CVE will be actively exploited in the wild within the next 30 days.
93. **ETW (Event Tracing for Windows)**: A high-performance kernel-level tracing facility built into Windows that feeds telemetry (such as `Microsoft-Windows-Threat-Intelligence` and `.NET` assembly loads) to Sysmon, Windows Event Logs, and EDR agents.
94. **EternalBlue (`MS17-010` / `CVE-2017-0144`)**: A critical buffer overflow vulnerability in the Windows SMBv1 (`srv.sys`) `SrvOs2FeaListSizeToNt` integer conversion routine exploited by the WannaCry and NotPetya worms.

### F
95. **FIDO2 / WebAuthn (Passkeys)**: The W3C and FIDO Alliance phishing-resistant authentication standard using hardware-bound asymmetric key pairs (`ECDSA P-256` / `Ed25519`) scoped strictly to the relying party's cryptographic origin (`rpId`), rendering adversary-in-the-middle (`AiTM`) reverse-proxy phishing impossible.
96. **Fileless Malware**: Malicious code that operates entirely in volatile RAM (`PowerShell` reflective injection, WMI repository persistence, Linux `memfd_create` anonymous ELF execution) without dropping traditional executable binaries onto the filesystem.
97. **FIM (File Integrity Monitoring)**: Automated security tooling (`AIDE`, `Osquery`, `Tripwire`, `Wazuh`) that monitors critical OS binaries and configuration files for unauthorized cryptographic hash, permission, or extended-attribute modifications.
98. **Fuzzing (Coverage-Guided Fuzzing)**: Automated vulnerability discovery (`AFL++`, `libFuzzer`, `Honggfuzz`, `Syzkaller`) that instruments target binaries to track basic-block edge coverage and mutates inputs to uncover crashes, assertions, and sanitizer (`ASan`/`UBSan`) violations.

### G
99. **GCM (Galois/Counter Mode)**: An NIST-standardized AEAD mode (`SP 800-38D`) combining `AES-CTR` counter-mode encryption with `GHASH` polynomial multiplication over the Galois field $GF(2^{128})$ to produce a 128-bit authentication tag.
100. **Golden SAML**: An identity federation persistence technique where an adversary compromises the on-premises AD FS token-signing private key (`PFX`) to forge arbitrary SAML 2.0 assertions for any cloud role without touching Active Directory again.
101. **Golden Ticket (`MITRE T1558.001`)**: A forged Kerberos Ticket-Granting Ticket (`TGT`) encrypted and signed using the stolen password hash (NTLM/AES256) of the Active Directory `krbtgt` account, granting arbitrary Domain Admin access across the domain until the `krbtgt` password is rotated **twice**.
102. **GOT / PLT (Global Offset Table / Procedure Linkage Table)**: ELF sections used by the dynamic linker (`ld.so`) to resolve external shared library function addresses; hardened against overwrite via **Full RELRO (`-Wl,-z,relro,-z,now`)**.
103. **GraphQL Introspection**: A built-in GraphQL meta-query (`__schema { types { name fields { name } } }`) that returns the entire API schema; should be disabled in production (`introspection: false`) to prevent reconnaissance.
104. **GTFOBins**: A curated encyclopedia of legitimate Unix/Linux system binaries (`find`, `vim`, `python3`, `tar`, `awk`, `capsh`) that can be abused to bypass restricted shells or escalate privileges when misconfigured with `SUID`, `sudo`, or POSIX capabilities.

### H
105. **Heap Spraying / Heap Feng Shui (Heap Grooming)**: Deterministically arranging the layout of heap allocations and free chunks so that a subsequent Use-After-Free (`UAF`) or 1-byte heap overflow overwrites a target function pointer or object header reliably.
106. **HKDF (HMAC-based Extract-and-Expand Key Derivation Function)**: The RFC 5869 standard for taking non-uniform high-entropy input keying material (such as an ECDH shared secret) and deriving multiple cryptographically independent subkeys.
107. **HMAC (Hash-based Message Authentication Code)**: The RFC 2104 construction $\text{HMAC}(K, m) = H((K' \oplus \text{opad}) \parallel H((K' \oplus \text{ipad}) \parallel m))$ that provides cryptographic message integrity and authenticity while eliminating Merkle-Damgård length-extension vulnerabilities.
108. **HNDL (Harvest Now, Decrypt Later)**: The strategic threat model wherein adversaries record encrypted TLS/VPN traffic today to decrypt retroactively once a Cryptographically Relevant Quantum Computer (`CRQC`) becomes operational; mitigated by deploying **ML-KEM (FIPS 203)** hybrid key exchange now.
109. **Honeypot / Honeytoken**: Decoy systems, Active Directory accounts (`svc_backup_admin` with `LogonWorkstations` restricted), AWS access keys (`Canarytokens`), or database rows that have zero legitimate operational use, so any interaction generates an immediate high-confidence breach alert.
110. **HPKE (Hybrid Public Key Encryption)**: The RFC 9180 standard combining an asymmetric Key Encapsulation Mechanism (`KEM`), a Key Derivation Function (`KDF`), and an `AEAD` cipher into a unified, misuse-resistant public-key encryption scheme (used in TLS Encrypted Client Hello `ECH` and MLS).
111. **HSM (Hardware Security Module)**: A tamper-resistant physical appliance (`FIPS 140-3 Level 3/4` certified) that generates, stores, and performs cryptographic operations with private keys inside a hardened boundary from which raw keys can never be exported.
112. **HSTS (HTTP Strict Transport Security)**: The RFC 6797 security header (`Strict-Transport-Security`) that forces browsers to upgrade all `http://` connections to `https://` internally before transmitting a single packet on the wire.
113. **HTTP Request Smuggling (`CL.TE` / `TE.CL` / `H2.CL` / `H2.TE`)**: A critical desynchronization attack exploiting discrepancies in how a front-end reverse proxy/CDN and a back-end origin server determine message boundaries (`Content-Length` vs `Transfer-Encoding: chunked` or HTTP/2 downgrade), allowing an attacker to prepend arbitrary HTTP requests onto the next victim's TCP connection.

### I
114. **IaC (Infrastructure as Code) Security**: Static analysis (`Checkov`, `tfsec`, `Trivy`, `Kics`) of Terraform (`.tf`), CloudFormation, and Kubernetes YAML manifests in CI/CD before infrastructure is provisioned.
115. **ICACLS (`icacls.exe`)**: The Windows command-line utility used to view and modify Discretionary Access Control Lists (`DACLs`) on files and directories; crucial for auditing **Insecure Service Executable / Directory Permissions (`F`, `M`, `W` for `Users` or `Everyone`)**.
116. **IDOR (Insecure Direct Object Reference)**: A vulnerability where an application uses client-supplied identifiers (`?invoice_id=1042`) to retrieve objects directly from a database or filesystem without verifying authorization of the requesting user.
117. **IDS / IPS (Intrusion Detection / Prevention System)**: Network (`Suricata`, `Snort`, `Zeek`) or Host (`OSSEC`, `Wazuh`) security appliances that inspect traffic or system events passively (`IDS` out-of-band SPAN/TAP) or inline (`IPS` capable of dropping malicious packets in real time).
118. **IMDSv1 / IMDSv2 (Instance Metadata Service)**: Cloud hypervisor HTTP endpoints exposed at the link-local IP `169.254.169.254`; **IMDSv1** uses simple `GET` requests (vulnerable to SSRF credential theft), whereas **IMDSv2** requires a session-oriented `PUT` request with `X-aws-ec2-metadata-token-ttl-seconds` and IP TTL=`1` to defeat SSRF and open-WAF转发.
119. **IMPHASH (Import Hash)**: An MD5 hash computed by Mandiant's specification over the ordered, lowercased list of imported DLL names and function names in a Windows Portable Executable (`PE`) Import Address Table (`IAT`), used to cluster malware families compiled from the same source code.
120. **Immutable Infrastructure**: An operational paradigm where production servers and containers are never modified or patched in place after deployment (`SSH disabled`, `readOnlyRootFilesystem: true`); any update deploys a newly built, signed image from CI/CD.
121. **Indicator of Attack (IoA) vs Indicator of Compromise (IoC)**: An **IoC** is a static reactive artifact (file SHA-256 hash, C2 IPv4 address, domain name — bottom of Bianca's **Pyramid of Pain**), whereas an **IoA** detects the behavioral sequence of adversary actions (`WINWORD.EXE` spawning `powershell.exe -enc`, LSASS handle access — top of the Pyramid of Pain).
122. **Integer Overflow / Underflow (`CWE-190` / `CWE-191`)**: An arithmetic wrap-around condition where an integer exceeds its maximum bit width (e.g., `uint16_t` wrapping `65535 + 1 -> 0`), causing subsequent `malloc(size)` calls to allocate a tiny buffer followed by a large `memcpy()` heap buffer overflow.

### J
123. **JA3 / JA4+ TLS Fingerprinting**: Cryptographic fingerprinting methods that hash TLS ClientHello parameters (TLS version, cipher suites, extensions, elliptic curves, ALPN) so SOC analysts can identify malware C2 clients (`Cobalt Strike`, `Sliver`, `Trickbot`) even over encrypted HTTPS.
124. **JEA (Just Enough Administration)**: A Windows PowerShell security technology that uses constrained WinRM endpoints and Role Capability files (`.psrc`) to let operators run specific administrative cmdlets without granting them local Administrator membership.
125. **JIT (Just-In-Time) Privileged Access**: An identity security architecture (such as Microsoft Entra PIM or HashiCorp Boundary) where users hold zero standing administrative privileges (`Zero Standing Privilege`) and must request time-bound (`1-hour`), MFA- and approval-gated elevation when needed.
126. **JWT (JSON Web Token)**: A compact, URL-safe claims representation (RFC 7519) consisting of `Header.Payload.Signature` encoded in Base64URL and signed via `JWS` (`RS256`, `ES256`, `EdDSA`, or `HS256`).

### K
127. **KAPE (Kroll Artifact Parser and Extractor)**: A high-speed Windows DFIR triage collector and parser orchestrator that collects high-value forensic targets (`$MFT`, `$UsnJrnl`, Registry Hives, `Evtx`, `Prefetch`, `Amcache`, `SRUM`) in minutes using raw NTFS volume reads to bypass OS file locks.
128. **KASLR (Kernel Address Space Layout Randomization)**: Randomization of the physical and virtual base address where the OS kernel image and loadable kernel modules are mapped at boot time to defeat kernel ROP exploits.
129. **KDC (Key Distribution Center)**: The trusted third-party Kerberos server running on Active Directory Domain Controllers encompassing the **Authentication Service (`AS`)** and the **Ticket-Granting Service (`TGS`)**.
130. **Kerberoasting (`MITRE T1558.003`)**: An Active Directory post-exploitation technique where any authenticated domain user requests Kerberos Service Tickets (`TGS`, EventID `4769`) for user accounts that have a registered `servicePrincipalName` (`SPN`), then cracks the service account password offline since the TGS is encrypted with the service account's NTLM (`RC4`) or AES hash.
131. **Kerberos**: The network authentication protocol (RFC 4120) built on symmetric cryptography (and optional PKINIT asymmetric certificates) using time-stamped tickets (`TGT` and `TGS`) and authenticators to prove identity without sending passwords over the network.
132. **KEV (Known Exploited Vulnerabilities Catalog)**: CISA's authoritative feed of CVEs that have confirmed active exploitation in the wild; enterprise vulnerability management programs prioritize KEV + high EPSS findings above raw CVSS scores alone.

### L
133. **LAPS (Local Administrator Password Solution)**: Windows LAPS automatically generates a unique, cryptographically random, periodically rotated password for the built-in local Administrator account on every domain-joined workstation and stores it encrypted in Active Directory or Entra ID, completely neutralizing lateral Pass-the-Hash across workstations.
134. **Lateral Movement (`MITRE TA0008`)**: Techniques used by an adversary after initial compromise to pivot across internal hosts (`SMB`/`PsExec`, `WMI`, `WinRM`, `RDP`, `SSH`, `DCOM`, `Pass-the-Hash`, `Pass-the-Ticket`) in search of domain controllers or crown-jewel databases.
135. **LDAP Injection (`CWE-90`)**: An injection vulnerability where unsanitized user input is concatenated into an LDAP search filter (`(&(uid=* )(userPassword=*))`), allowing authentication bypass or directory attribute enumeration.
136. **Least Privilege (Principle of Least Privilege, `PoLP`)**: The foundational security engineering design principle stating that every user, process, container, or cloud IAM role must operate with only the minimum permissions and capabilities required to perform its authorized task.
137. **LFI / RFI (Local / Remote File Inclusion)**: Vulnerabilities in dynamic web languages (`include($_GET['page'])` in PHP) allowing an attacker to read arbitrary local files (`/etc/passwd`, `php://filter/convert.base64-encode/resource=config.php`) or execute code.
138. **LLMNR / NBT-NS Poisoning (`MITRE T1557.001`)**: A local subnet Man-in-the-Middle attack (`Responder`) where an attacker answers multicast Link-Local Multicast Name Resolution (`UDP/5355`) and NetBIOS Name Service (`UDP/137`) broadcast queries for mistyped share names, capturing `NTLMv2` challenge-response hashes for offline cracking or SMB Relaying.
139. **Living off the Land Binaries (LOLBins / LOLBAS)**: Microsoft-signed binaries pre-installed in Windows (`certutil.exe`, `rundll32.exe`, `regsvr32.exe`, `mshta.exe`, `bitsadmin.exe`, `wmic.exe`, `msbuild.exe`) abused by attackers to download payloads, bypass application allowlisting, or dump credentials.
140. **LSASS (`lsass.exe` — Local Security Authority Subsystem Service)**: The critical Windows system process responsible for enforcing security policy, verifying logons, and caching Kerberos tickets, NTLM hashes, and DPAPI master keys in memory; protected via **RunAsPPL (`LsaCfgFlags=1`)** and **Credential Guard (VBS)**.

### M
141. **MAC (Mandatory Access Control)**: A kernel-enforced access control framework (`SELinux`, `AppArmor`, Windows Mandatory Integrity Control `MIC`) where access decisions are dictated strictly by system-wide security labels and policy rules that cannot be overridden by resource owners.
142. **Mass Assignment (BOPLA — Broken Object Property Level Authorization)**: An API vulnerability (`OWASP API3:2023`) where an application automatically binds client-supplied JSON properties (`{"username":"bob", "isAdmin": true, "balance": 999999}`) directly onto internal ORM database models without an explicit allowlist DTO/schema.
143. **Memfd (`memfd_create`)**: A Linux system call (`syscall 319` on `x86_64`) that creates an anonymous file residing purely in RAM backed by `tmpfs` without touching any disk mount; frequently abused by Linux fileless implants to execute ELF payloads via `/proc/self/fd/<N>`.
144. **Merkle Tree**: A binary hash tree in which every leaf node contains the cryptographic hash of a data block and every non-leaf node contains the hash of its concatenated child hashes, enabling $O(\log N)$ inclusion proofs in Certificate Transparency, Git, and ZFS/Btrfs.
145. **Microsegmentation**: Enforcing fine-grained Layer-3/4/7 zero-trust network policies between individual workloads, pods (`Kubernetes NetworkPolicy` / `Cilium eBPF`), or VMs so east-west lateral movement is blocked inside the data center.
146. **Mimikatz**: The seminal open-source Windows security research tool created by Benjamin Delpy (`gentilkiwi`) demonstrating credential extraction from LSASS (`sekurlsa::logonpasswords`), Pass-the-Hash, Golden/Silver Tickets, and `lsadump::dcsync`.
147. **MITRE ATT&CK**: The globally accessible knowledge base of adversary **Tactics** (the *why* / technical objective, e.g., `TA0006 Credential Access`), **Techniques** (the *how*, e.g., `T1003 OS Credential Dumping`), and **Sub-techniques** (`T1003.001 LSASS Memory`) based on real-world intrusion observations.
148. **MITRE D3FEND**: A knowledge graph of cybersecurity defensive countermeasures (`Hardening`, `Detection`, `Isolation`, `Deception`, `Eviction`) mapped directly against MITRE ATT&CK offensive techniques.
149. **ML-DSA (FIPS 204)**: NIST's primary post-quantum digital signature standard based on the Module Learning With Errors (`MLWE`) and Module Short Integer Solution (`MSIS`) lattice problems (formerly CRYSTALS-Dilithium).
150. **ML-KEM (FIPS 203)**: NIST's primary post-quantum Key-Encapsulation Mechanism based on the Module Learning With Errors (`MLWE`) lattice problem (formerly CRYSTALS-Kyber).
151. **mTLS (Mutual TLS)**: Transport Layer Security where both the server and the client present X.509 certificates during the TLS handshake (`CertificateRequest` / `CertificateVerify`), providing mutual cryptographic identity verification for Zero-Trust APIs and service meshes.
152. **MTTD / MTTR (Mean Time to Detect / Mean Time to Respond)**: Key SOC operational metrics measuring the average elapsed time between an intrusion starting and the SOC detecting it (`MTTD`), and the time required to contain and eradicate the threat (`MTTR`).
153. **Mutex (Mutant in Windows Kernel)**: A synchronization object created by processes (`CreateMutex`); malware frequently creates a hardcoded mutex name (`Global\MsWinZonesCacheCounterMutexA`) to prevent re-infecting an already compromised host, making mutexes high-fidelity forensic indicators.

### N
154. **NAC (Network Access Control)**: Enterprise port-level security (`IEEE 802.1X`, `MAB`, `Cisco ISE`, `Aruba ClearPass`) that authenticates devices via EAP-TLS certificates and posture checks before placing the switch port onto an authorized production VLAN.
155. **Named Pipes (Windows IPC)**: Inter-process communication channels accessed via the `\\<Server>\pipe\<PipeName>` filesystem namespace over SMB (`IPC$`); heavily used by Windows RPC (`samr`, `lsarpc`, `winreg`, `svcctl`) and C2 frameworks (`Cobalt Strike` `\msagent_*`).
156. **NetFlow / IPFIX**: Network telemetry protocols that export unidirectional or bidirectional flow metadata (`5-tuple`: SrcIP, DstIP, SrcPort, DstPort, Protocol, Byte Count, Packet Count, TCP Flags, Timestamps) from routers/switches for east-west anomaly detection and exfiltration sizing.
157. **Nftables**: The modern Linux kernel packet classification subsystem replacing legacy `iptables`/`ip6tables`/`arptables`/`ebtables` with a unified virtual machine bytecode engine and high-performance lookup sets.
158. **NIST CSF 2.0 (Cybersecurity Framework)**: NIST's enterprise risk management framework organized around six core functions: **Govern (`GV`)**, **Identify (`ID`)**, **Protect (`PR`)**, **Detect (`DE`)**, **Respond (`RS`)**, and **Recover (`RC`)**.
159. **Nonce (Number Used Once)**: A unique (random or monotonically increasing counter) value passed into cryptographic protocols (`AES-GCM` 96-bit IV, CSP `'nonce-...'`, OAuth OIDC `nonce`, Kerberos authenticator) to prevent replay attacks and ensure semantic security.
160. **NTDS.dit**: The physical Active Directory database file (`C:\Windows\NTDS\ntds.dit`) on a Domain Controller containing all domain object attributes, group memberships, and password hashes (encrypted with the `PEK` Password Encryption Key, which is itself encrypted by the `SYSTEM` hive `BootKey`).
161. **NTLM (`NT LAN Manager` & `Net-NTLMv1/v2`)**: Microsoft's legacy challenge-response authentication protocol; **NTLM Hash** (`MD4(UTF-16LE(password))`) is unsalted and vulnerable to **Pass-the-Hash**, while **Net-NTLMv1/v2** network challenges are vulnerable to **NTLM Relay (`Impacket ntlmrelayx.py`)** if SMB Signing and LDAP Signing/Channel Binding are not enforced.

### O
162. **OAuth 2.0 / OAuth 2.1**: The industry-standard authorization framework (RFC 6749) enabling delegated access via `access_token`s; **OAuth 2.1** consolidates security best practices by mandating **PKCE (`S256`)** for all authorization code flows and prohibiting the legacy Implicit (`response_type=token`) and Resource Owner Password Credentials flows.
163. **OCSP Stapling (Online Certificate Status Protocol Stapling)**: A TLS extension (RFC 6066) where the web server periodically queries the CA's OCSP responder itself and caches ("staples") the digitally signed, time-stamped revocation status directly into the TLS handshake, preserving client privacy and handshake speed.
164. **OIDC (OpenID Connect)**: An identity authentication layer built on top of OAuth 2.0 that issues a cryptographically signed JWT called an **`id_token`** containing claims (`sub`, `iss`, `aud`, `exp`, `authn_time`) about the authenticated end-user.
165. **OPA (Open Policy Agent)**: A general-purpose policy-as-code engine using the declarative **Rego** language to enforce admission control in Kubernetes (`Gatekeeper`), Terraform CI/CD checks, and microservice authorization.
166. **Open Redirect (`CWE-601`)**: A web vulnerability where an application accepts an unvalidated URL in a query parameter (`?next=https://evil.com`) and issues a `302 Found` redirect to that external domain, frequently chained to steal OAuth authorization codes or bypass SSRF filters.
167. **ORM (Object-Relational Mapping)**: Database abstraction frameworks (`SQLAlchemy`, `Hibernate`, `Prisma`, `Django ORM`) that automatically use parameterized queries for standard method calls, though raw query APIs (`session.execute(text(f"..."))`, `.raw()`) remain vulnerable to SQL Injection if misused.
168. **OSINT (Open-Source Intelligence)**: Passive reconnaissance gathering technical and organizational intelligence from publicly available sources (`Certificate Transparency logs`, `Shodan`, `Censys`, `ASN/BGP tables`, `GitHub commit history`, `DNS records`, `metadata in public PDFs`).

### P
169. **Padding Oracle Attack**: A side-channel cryptanalytic attack (Vaudenay, `POODLE`, `Lucky13`) against unauthenticated `CBC`-mode encryption where a server leaks whether a decrypted ciphertext had valid PKCS#7 byte padding, allowing an attacker to decrypt arbitrary ciphertexts—and forge arbitrary ciphertexts via **CBC-R**—in $O(16 \times \text{block\_count})$ queries without knowing the key.
170. **PAM (Pluggable Authentication Modules)**: The modular authentication architecture (`/etc/pam.d/`, `/lib/x86_64-linux-gnu/security/pam_*.so`) used by Linux and Unix services (`sshd`, `sudo`, `login`) to enforce password complexity, MFA, and account lockouts (`pam_faillock.so`).
171. **Pass-the-Hash (`PtH`, `MITRE T1550.002`)**: Authenticating to remote SMB, WMI, or WinRM services using an account's raw 16-byte NTLM hash directly without needing to crack it into the underlying cleartext password.
172. **Pass-the-Ticket (`PtT`, `MITRE T1550.003`)**: Extracting a valid Kerberos `.kirbi` (Windows LSASS) or `.ccache` (Linux `/tmp/krb5cc_*`) ticket from one host and injecting it into another session to impersonate the user across the domain.
173. **Path Traversal (`CWE-22`)**: Manipulating file path inputs with dot-dot-slash sequences (`../../../etc/passwd`) to break out of the intended webroot or upload directory.
174. **PAW (Privileged Access Workstation)**: A dedicated, physically or virtually isolated, hardened workstation used exclusively for Tier-0 administrative tasks (Domain Controller, Cloud Root, PKI management) with no email, web browsing, or productivity software permitted.
175. **PBKDF2 (Password-Based Key Derivation Function 2)**: An NIST-approved (`SP 800-132`) key stretching algorithm that applies a pseudorandom function (`HMAC-SHA256` or `HMAC-SHA512`) with a random salt for $c$ iterations (`>= 600,000` recommended by OWASP) to slow brute-force cracking.
176. **PCAP (Packet Capture)**: Binary file formats (`.pcap` and `.pcapng`) storing raw network frames captured via `libpcap` (`tcpdump`, `Wireshark`, `tshark`, `Stenographer`) for protocol dissection and network forensics.
177. **PE (Portable Executable)**: The native binary file format (`.exe`, `.dll`, `.sys`, `.ocx`) of 32-bit (`PE32`) and 64-bit (`PE32+`) Windows operating systems beginning with the DOS `MZ` header (`0x4D 0x5A`) and `PE\0\0` signature.
178. **Perfect Forward Secrecy (PFS)**: A property of key agreement protocols (`ECDHE`, `X25519`, `DHE`, `ML-KEM`) guaranteeing that compromise of the server's long-term private key in the future cannot decrypt past recorded sessions because each session derived its symmetric key from ephemeral, immediately discarded key shares.
179. **PIE (Position-Independent Executable)**: An executable compiled with `-fPIE -pie` (`ET_DYN` in ELF header) so that the OS loader can randomize the base virtual address of its `.text`, `.data`, and `.bss` segments under full ASLR.
180. **PKCE (Proof Key for Code Exchange)**: An RFC 7636 extension to OAuth 2.0 that binds an authorization code to the specific client instance that requested it using a dynamically generated `code_verifier` and `code_challenge = BASE64URL(SHA256(code_verifier))`.
181. **PKI (Public Key Infrastructure)**: The hierarchical ecosystem of hardware HSMs, Root and Intermediate Certificate Authorities (`CAs`), Registration Authorities (`RAs`), X.509 certificates, and revocation mechanisms (`OCSP`/`CRL`/`CT`) that binds public keys to verified identities.
182. **Polyglot File**: A single file crafted to be simultaneously valid in two or more distinct file formats (such as a valid `GIF89a` or `JPEG` image that is also a valid JavaScript file or `.jar`/`.phar` archive) to bypass upload validators.
183. **Prefetch (`C:\Windows\Prefetch\*.pf`)**: Windows memory manager cache files that record the execution count, last 8 execution timestamps, and loaded file/directory references for executed binaries, serving as primary DFIR evidence of execution.
184. **PrintNightmare (`CVE-2021-1675` / `CVE-2021-34527`)**: A critical remote code execution and local privilege escalation vulnerability in the Windows Print Spooler service (`spoolsv.exe`) `RpcAddPrinterDriverEx` RPC interface.
185. **Process Hollowing (`RunPE`, `MITRE T1055.012`)**: A defense evasion technique where malware spawns a legitimate Windows binary (`svchost.exe` or `RuntimeBroker.exe`) in a `CREATE_SUSPENDED` state, unmaps its legitimate memory section (`NtUnmapViewOfSection`), writes malicious PE sections into the hollowed space (`VirtualAllocEx` / `WriteProcessMemory`), updates the thread entry point (`SetThreadContext`), and resumes execution (`ResumeThread`).
186. **Prototype Pollution (`CWE-1321`)**: A JavaScript/Node.js vulnerability where an attacker injects properties into `Object.prototype` via recursive merge or path-assignment functions using keys like `__proto__` or `constructor.prototype`, polluting all objects across the V8 isolate and potentially leading to RCE or auth bypass.
187. **Ptrace (`ptrace(2)`)**: The Linux system call enabling one process to inspect and modify the memory and registers of another process (`PTRACE_ATTACH`, `PTRACE_POKETEXT`); restricted on hardened systems via `kernel.yama.ptrace_scope = 2` or `3`.

### Q
188. **QKD (Quantum Key Distribution)**: Physics-based key establishment (`BB84` protocol) using polarized photons over fiber-optic links; distinct from algorithmic **Post-Quantum Cryptography (`PQC`, `FIPS 203/204/205`)**, which runs on classical computers and existing Internet infrastructure.
189. **QUIC (`RFC 9000` / HTTP/3)**: A multiplexed, UDP-based transport protocol integrating TLS 1.3 encryption directly into the transport handshake (`0-RTT` / `1-RTT`) and encrypting transport headers (`Packet Numbers`) to prevent middlebox ossification and passive metadata inspection.

### R
190. **Race Condition (`CWE-362` / `TOCTOU` `CWE-367`)**: A flaw occurring when system behavior depends on the relative timing or interleaving of concurrent threads, processes, or HTTP/2 single-packet-attack requests between a **Time-of-Check** and a **Time-of-Use**.
191. **RBAC (Role-Based Access Control)**: An authorization model where permissions are assigned to functional **Roles** (`Auditor`, `BillingAdmin`, `ReadOnlyPodViewer`) and users or service accounts are granted membership in those roles.
192. **RBCD (Resource-Based Constrained Delegation, `MITRE T1098.005`)**: An Active Directory feature built on the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute of a target computer object; if an attacker gains `GenericWrite` over a computer object, they can configure RBCD from a machine account they control (`addcomputer.py`) and execute `S4U2Self`/`S4U2Proxy` to gain local Admin on the target computer.
193. **RCE (Remote Code Execution)**: The ability of an attacker to execute arbitrary machine instructions or interpreter commands on a target system over a network.
194. **ReDoS (Regular Expression Denial of Service, `CWE-1333`)**: Algorithmic complexity exhaustion caused by passing crafted input strings to a backtracking regular expression engine containing **Evil Regex** patterns with nested quantifiers (`^(a+)+$`), triggering $O(2^n)$ exponential CPU lockup; mitigated by using linear-time $O(n)$ non-backtracking engines (`RE2`, Rust `regex`).
195. **Reflective DLL Injection (`MITRE T1055.001`)**: Loading a DLL directly from memory into a host process via a custom `ReflectiveLoader` export stub that resolves its own imports and relocations without calling `LoadLibrary()` or registering in the PEB `Ldr` module list.
196. **RELRO (Relocation Read-Only)**: An ELF binary hardening mitigation (`Partial RELRO`: `-Wl,-z,relro`; `Full RELRO`: `-Wl,-z,relro,-z,now`) that places the Global Offset Table (`.got`) before `.bss` and marks it read-only (`mprotect(PROT_READ)`) after dynamic symbol resolution at startup.
197. **Replay Attack**: Re-transmitting a valid captured network message, authentication token, or signed transaction to duplicate its effect; prevented by cryptographic sequence numbers, strict timestamps (`±5 minutes` in Kerberos), and single-use nonces (`jti`).
198. **Reverse Shell vs Bind Shell**: In a **Bind Shell**, the compromised target opens a listening TCP port and waits for the attacker to connect inbound (usually blocked by ingress firewalls); in a **Reverse Shell**, the compromised target initiates an outbound connection back to the attacker's listener (`nc -lvnp 443`).
199. **RFC 1918**: The IETF standard reserving three private IPv4 address blocks for internal networks: `10.0.0.0/8` (`10.0.0.0 – 10.255.255.255`), `172.16.0.0/12` (`172.16.0.0 – 172.31.255.255`), and `192.168.0.0/16` (`192.168.0.0 – 192.168.255.255`).
200. **Ring 0 / Ring 3 (CPU Privilege Rings)**: Hardware x86/x86_64 protection rings where **Ring 0** (Supervisor Mode) executes the OS kernel with unrestricted hardware access, **Ring 3** (User Mode) executes unprivileged applications, and **Ring -1** (`VMX root`) executes the Hypervisor (`VMM`).
201. **Rootkit**: Stealth software designed to conceal the presence of unauthorized processes, files, network sockets, or registry keys at the User Mode (`LD_PRELOAD`, IAT/inline API hooking), Kernel Mode (`DKOM`, `SSDT` hooks, `eBPF`), Hypervisor (`Blue Pill`), or Firmware (`UEFI`/`SPI flash`) layer.
202. **ROP (Return-Oriented Programming)**: An advanced memory exploitation technique that bypasses `DEP/NX` by chaining together short instruction sequences already present inside executable code pages (`libc` or the binary itself) ending in a `ret` (`0xC3`) instruction (**"gadgets"**), controlling execution purely by placing gadget addresses on the stack.
203. **RPKI (Resource Public Key Infrastructure)**: A cryptographic framework where Regional Internet Registries (`ARIN`, `RIPE`, `APNIC`) issue X.509 certificates binding IP prefixes to autonomous system numbers (`ASNs`) via signed **ROAs (Route Origin Authorizations)** so BGP routers can drop hijacked route announcements.
204. **RPO / RTO (Recovery Point Objective / Recovery Time Objective)**: Disaster recovery metrics where **RPO** defines the maximum acceptable age of data lost due to an incident (dictating backup frequency), and **RTO** defines the maximum acceptable downtime before critical business operations must be restored.

### S
205. **SAJE / SASE (Secure Access Service Edge)**: A cloud-delivered architecture converging SD-WAN networking with Zero-Trust Network Access (`ZTNA`), Secure Web Gateway (`SWG`), CASB, and Firewall-as-a-Service (`FWaaS`).
206. **Salt (Cryptographic Salt)**: A unique, cryptographically random byte string (`>= 128 bits`) generated per password and stored alongside the output hash to defeat precomputed **Rainbow Tables** and ensure two users with the same password produce completely different hashes.
207. **SAML 2.0 (Security Assertion Markup Language)**: An XML-based enterprise Single Sign-On (`SSO`) federation standard where an Identity Provider (`IdP`) issues a digitally signed XML `<Assertion>` to a Service Provider (`SP`); vulnerable to **XML Signature Wrapping (`XSW`)** and **XXE** if the SP parser is misconfigured.
208. **Same-Origin Policy (SOP)**: The foundational browser security boundary stating that scripts running in one origin (`scheme + hostname + port`, e.g., `https://app.example.com:443`) cannot read responses from a different origin unless explicitly permitted by **CORS** headers.
209. **SameSite Cookie Attribute (`Strict` / `Lax` / `None`)**: An HTTP `Set-Cookie` attribute controlling whether the browser attaches a cookie on cross-site requests; `SameSite=Strict` never sends the cookie on cross-site navigations, `SameSite=Lax` sends it only on top-level safe (`GET`) navigations, and `SameSite=None; Secure` sends it on all cross-site requests.
210. **SAST (Static Application Security Testing)**: White-box automated source code/bytecode analysis (`Semgrep`, `CodeQL`, `SonarQube`) that constructs Abstract Syntax Trees (`ASTs`) and Control/Data-Flow Graphs (`Taint Analysis` from `Sources` to `Sinks`) without executing the program.
211. **SBOM (Software Bill of Materials)**: A machine-readable inventory (`CycloneDX` or `SPDX` JSON format) listing every direct and transitive open-source library, version, cryptographic hash, and license inside a software artifact so teams can immediately query exposure to newly disclosed supply-chain CVEs (`Log4Shell`, `XZ Utils`).
212. **SCA (Software Composition Analysis)**: Automated scanning of package manifests (`package-lock.json`, `poetry.lock`, `go.sum`, `pom.xml`) and container layers against vulnerability databases (`OSV`, `NVD`, `GitHub Advisory Database`).
213. **Schannel (Secure Channel)**: Microsoft Windows' native Security Support Provider (`SSP`) implementing TLS, DTLS, and SSL protocols.
214. **Seccomp-BPF (Secure Computing Mode with Berkeley Packet Filter)**: A Linux kernel sandboxing facility (`prctl(PR_SET_SECCOMP)`) that filters which system calls (`syscall` numbers and register arguments) a thread is permitted to invoke, killing or returning `EPERM` on disallowed syscalls (Docker's default seccomp profile blocks ~44 dangerous syscalls such as `kexec_load`, `init_module`, `mount`, and `acct`).
215. **SeDebugPrivilege**: A powerful Windows token privilege (`MITRE T1134`) granted to local Administrators that allows a process to open handles (`PROCESS_ALL_ACCESS`) to any system process, including `lsass.exe` (unless `lsass.exe` runs as `Protected Process Light / PPL`).
216. **SeImpersonatePrivilege / SeAssignPrimaryTokenPrivilege**: Windows service account privileges granted to `LOCAL SERVICE`, `NETWORK SERVICE`, and IIS AppPools that allow token impersonation; abused by the **Potato exploit family (`JuicyPotato`, `PrintSpoofer`, `GodPotato`)** to coerce `NT AUTHORITY\SYSTEM` into authenticating to a local named pipe and escalate to `SYSTEM`.
217. **SELinux (Security-Enhanced Linux)**: A NSA-designed Linux Kernel Security Module (`LSM`) implementing Type Enforcement (`TE`), Multi-Level Security (`MLS`), and Multi-Category Security (`MCS`) Mandatory Access Control across every process (`user:role:type:level`) and file inode.
218. **Server-Side Template Injection (`SSTI`, `CWE-1336`)**: A critical vulnerability occurring when user input is concatenated directly into a server-side template string (`Jinja2`, `Twig`, `Freemarker`, `Velocity`, `Pug`) prior to rendering (e.g., `{{7*7}}` evaluating to `49`), allowing Python/Java sandbox escape via MRO object traversal (`__class__.__mro__[1].__subclasses__()`) to achieve RCE.
219. **Shadow Credentials (`msDS-KeyCredentialLink`, `MITRE T1098.005`)**: An Active Directory persistence and privilege escalation technique (`Whisker` / `PyWhisker`) where an attacker with `GenericWrite` over a user or computer object appends a rogue public key to its `msDS-KeyCredentialLink` attribute and authenticates via `PKINIT` Kerberos to extract the target's TGT and NTLM hash.
220. **Shadow Stack (`CET SHSTK`)**: A hardware-protected second stack maintained by the CPU that stores only function return addresses (`CALL` pushes to both the data stack and shadow stack; `RET` compares both and raises a `#CP` Control Protection fault on mismatch), defeating ROP stack-smashing attacks.
221. **Shimcache (AppCompatCache)**: A Windows registry structure in `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache` that tracks executable file paths and last-modified timestamps across reboots for forensic timeline reconstruction.
222. **Side-Channel Attack**: Extracting cryptographic secrets by observing physical or microarchitectural implementation artifacts rather than mathematical weaknesses, including **Timing Attacks**, **Cache-Timing (`Prime+Probe`, `Flush+Reload`)**, **Transient Execution (`Spectre`, `Meltdown`, `Downfall`)**, **Power Analysis (`SPA`/`DPA`)**, and **Electromagnetic (`TEMPEST`)** emanations.
223. **SIEM (Security Information and Event Management)**: A centralized security analytics platform (`Microsoft Sentinel`, `Splunk Enterprise Security`, `Elastic Security`, `Google SecOps`) that ingests, normalizes, correlates, and runs Sigma/KQL/SPL detections across multi-source enterprise telemetry.
224. **Sigma**: An open, vendor-neutral YAML signature format for describing log detection rules that compiles into SIEM-specific queries (`KQL`, `SPL`, `EQL`, `Lucene`).
225. **Silver Ticket (`MITRE T1558.002`)**: A forged Kerberos Service Ticket (`TGS`) encrypted using the stolen password hash of a specific service account (such as a computer account `SQLSRV01$` or `MSSQLSvc`), allowing an attacker to access that specific service as Admin without communicating with the Domain Controller (`KDC`).
226. **SLH-DSA (FIPS 205)**: NIST's stateless hash-based post-quantum digital signature standard (formerly **SPHINCS+**) whose security relies solely on the cryptographic properties of `SHA-2` or `SHAKE256`.
227. **SLSA (Supply-chain Levels for Software Artifacts)**: An OpenSSF security framework (`SLSA Levels 1–3`) specifying build provenance attestations, isolated ephemeral build environments, and cryptographic verification to prevent software supply-chain tampering (`SolarWinds`-style attacks).
228. **SMEP / SMAP (Supervisor Mode Execution / Access Prevention)**: Hardware CPU control-register bits (`CR4.SMEP`, `CR4.SMAP` on x86_64; `PXN`/`PAN` on ARM64) that trigger an immediate kernel page fault if Ring 0 kernel code attempts to execute (`SMEP`) or read/write (`SMAP`) user-space Ring 3 memory pages directly.
229. **Smurf / Fraggle / Amplification Attack**: Reflected volumetric DDoS attacks where an attacker sends small UDP requests with a **spoofed source IP** (the victim's IP) to open UDP services (`DNS`, `NTP monlist`, `Memcached UDP/11211`, `CLDAP`), which reply to the victim with up to $51,000\times$ bandwidth amplification; mitigated via **BCP 38 (Network Ingress Filtering)** and disabling UDP reflection services.
230. **SNI (Server Name Indication)**: A TLS ClientHello extension indicating the target hostname (`api.example.com`) so a single IP can serve multiple TLS certificates; transmitted in cleartext unless **TLS 1.3 Encrypted Client Hello (`ECH`)** is deployed.
231. **SOAR (Security Orchestration, Automation, and Response)**: Automated playbook execution platforms integrated with SIEM/EDR to enrich IoCs, quarantine compromised endpoints, revoke Entra ID refresh tokens, and block attacker IPs at the firewall within seconds.
232. **SPF (Sender Policy Framework)**: An email authentication standard (RFC 7208) publishing a DNS `TXT` record (`v=spf1 ip4:198.51.100.0/24 include:_spf.google.com -all`) specifying which mail server IP addresses are authorized to send email on behalf of the `RFC5321.MailFrom` (Return-Path) domain.
233. **SPIFFE / SPIRE**: The CNCF open standard (**Secure Production Identity Framework for Everyone**) that issues short-lived, automatically rotated cryptographic identities (`SVIDs`: X.509 certificates or JWTs identified by `spiffe://trust-domain/workload-id`) to microservices across heterogeneous cloud/Kubernetes environments without static secrets.
234. **SQL Injection (`SQLi`, `CWE-89`)**: An injection vulnerability where untrusted input alters the structure of a backend SQL query (`In-band UNION`, `Error-based`, `Blind Boolean`, `Blind Time-based`, or `Out-of-Band DNS/SMB`); completely prevented by **Parameterized Prepared Statements**.
235. **SRUM (System Resource Usage Monitor)**: A Windows diagnostic database (`C:\Windows\System32\sru\SRUDB.dat`) that records 30–60 days of per-process execution history, user SIDs, and exact network bytes sent and received—critical for proving data exfiltration volume in DFIR investigations.
236. **SSRF (Server-Side Request Forgery, `CWE-918`)**: A web vulnerability where an attacker induces the server-side application to make HTTP or TCP requests to an unintended internal destination (such as AWS/GCP/Azure Cloud Instance Metadata `169.254.169.254` or internal Redis/Kubernetes APIs).
237. **Sticky Bit (`01000` / `+t`)**: A POSIX permission bit on shared directories (`/tmp`, `drwxrwxrwt`) restricting file deletion or renaming inside that directory strictly to the file's owner, the directory's owner, or `root`.
238. **STIX / TAXII**: **STIX (Structured Threat Information Expression)** is a standardized JSON schema for representing cyber threat intelligence objects (Indicators, Malware, Threat Actors, Campaigns, TTPs), and **TAXII (Trusted Automated Exchange of Intelligence Information)** is the HTTPS transport protocol used to exchange STIX bundles.
239. **Subdomain Takeover**: A vulnerability occurring when a DNS record (`CNAME` or `A`) points to an external cloud resource (`S3 bucket`, `GitHub Pages`, `Azure App Service`) that has been deprovisioned by the organization, allowing an attacker to register that cloud resource name and serve malicious content under the organization's trusted subdomain.
240. **SUID / SGID (`Set Owner User ID` `04000` / `Set Group ID` `02000`)**: POSIX mode bits that cause an executable binary to run with the effective user ID (`euid`) or effective group ID (`egid`) of the file's owner rather than the user who launched it.
241. **Suricata**: A high-performance, multi-threaded open-source Network IDS, IPS, and Network Security Monitoring (`NSM`) engine that outputs unified JSON telemetry (`eve.json`) across L3–L7 protocols.
242. **Sysmon (System Monitor)**: A Windows Sysinternals system service and device driver (`Sysmon64.exe` / `SysmonDrv.sys`) that logs high-fidelity kernel telemetry (29 Event IDs including process hashes, parent command lines, process access, named pipes, and DNS queries) to the Windows Event Log.

### T
243. **Taint Analysis**: A static (`SAST`) or dynamic (`DAST`/`IAST`) program analysis method that marks all untrusted external inputs (**Sources**) as "tainted" and tracks data flow through variables and functions until it reaches a security-sensitive operation (**Sink**), alerting if no registered **Sanitizer** or **Validator** was applied along the path.
244. **Threat Hunting**: Proactive, hypothesis-driven iterative searching through enterprise telemetry (SIEM, EDR, NetFlow) to uncover stealthy adversaries who have evaded automated signature/rule detections.
245. **Threat Modeling (`STRIDE` / `PASTA` / `LINDDUN`)**: Structured architectural security analysis performed during system design; Microsoft's **STRIDE** categorizes threats into **S**poofing, **T**ampering, **R**epudiation, **I**nformation Disclosure, **D**enial of Service, and **E**levation of Privilege.
246. **Timestomping (`MITRE T1070.006`)**: Modifying a file's creation, modification, or access timestamps (`$STANDARD_INFORMATION` attribute in NTFS or `utimensat` in Linux) to blend in with legitimate OS binaries and frustrate forensic timeline analysis.
247. **TLS 1.3 (Transport Layer Security 1.3, `RFC 8446`)**: The modern cryptographic transport protocol that completes handshakes in **1-RTT**, mandates ephemeral Diffie-Hellman (`ECDHE` / `X25519` / `ML-KEM`) for **Perfect Forward Secrecy**, removes all legacy non-AEAD ciphers (`CBC`, `RC4`, static `RSA`), and encrypts all handshake messages after `ServerHello` (including server/client certificates).
248. **TOTP (Time-based One-Time Password, `RFC 6238`)**: An algorithm that computes a 6- or 8-digit OTP from a shared secret key and the current Unix timestamp divided into 30-second windows using `HMAC-SHA1`/`SHA256`; vulnerable to real-time **AiTM (`Evilginx2`)** phishing proxies unlike **FIDO2/WebAuthn**.
249. **TPM 2.0 (Trusted Platform Module)**: A dedicated hardware crypto-processor soldered onto the motherboard that performs Measured Boot (`PCR` hash extension of UEFI firmware, bootloader, and OS kernel) and seals full-disk encryption keys (`BitLocker`, `LUKS2 systemd-cryptenroll`).

### U
250. **UAC (User Account Control)**: A Windows security boundary mitigation that splits an administrator's logon session into a standard-user **Filtered Token** (`Medium Integrity`) and an elevated **Full Administrator Token** (`High Integrity`), requiring consent or credentials to cross from Medium to High Integrity.
251. **Unconstrained Delegation (Kerberos)**: A dangerous legacy Active Directory setting (`TRUSTED_FOR_DELEGATION` flag on a computer or service account) where any user connecting to that server has their full **TGT** forwarded and cached inside the server's `lsass.exe` memory; if an attacker compromises an Unconstrained Delegation server and coerces a Domain Controller to authenticate to it (`PetitPotam` / `PrinterBug`), they capture the DC's TGT and compromise the entire forest.
252. **Use-After-Free (`UAF`, `CWE-416`)**: A critical memory corruption vulnerability in C/C++ occurring when a program continues to use a heap pointer after the memory chunk it references has been deallocated (`free()`), allowing an attacker to reallocate controlled data into that exact heap slot and hijack control flow.
253. **USN Journal (`$UsnJrnl:$J`)**: The NTFS Update Sequence Number Change Journal that logs a chronological record of every metadata and data change made to files and directories on an NTFS volume.

### V
254. **VAD (Virtual Address Descriptor)**: A self-balancing binary tree maintained by the Windows kernel memory manager for each process describing the virtual address ranges, page protection permissions (`PAGE_EXECUTE_READWRITE`), and mapped backing files of every allocated memory segment; inspected by `volatility3 windows.malfind`.
255. **VBS / HVCI (Virtualization-Based Security / Hypervisor-Protected Code Integrity)**: Windows security architecture using the Hyper-V hypervisor (`Virtual Trust Level 1 / VTL1`) to isolate `Credential Guard` (`lsaiso.exe`) and enforce kernel driver code signing (`HVCI`) so even a Ring 0 kernel exploit cannot read LSASS secrets or allocate executable unsigned kernel memory.
256. **VLAN Hopping (`Switch Spoofing` & `Double Tagging`)**: Layer-2 network attacks where an attacker either negotiates an `802.1Q` trunk link via Cisco Dynamic Trunking Protocol (`DTP`) or transmits frames with two `802.1Q` tags across the native VLAN; mitigated by setting access ports explicitly (`switchport mode access`, `switchport nonegotiate`) and assigning the Native VLAN to an unused VLAN ID.
257. **Volatility 3**: The industry-standard open-source memory forensics framework written in Python for analyzing volatile RAM dumps across Windows, Linux, and macOS.

### W
258. **WAF (Web Application Firewall)**: A Layer-7 reverse proxy security control (`ModSecurity OWASP CRS`, `Cloudflare WAF`, `AWS WAF`) that inspects HTTP/HTTPS traffic for SQLi, XSS, LFI, and bot anomalies.
259. **W Digest (`WDigest.dll`)**: A legacy Windows authentication provider that cached cleartext passwords in `lsass.exe` memory; disabled by default since Windows 8.1 / Server 2012 R2, though attackers with admin access sometimes set `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential = 1` to harvest cleartext passwords on subsequent logons.
260. **W^X (Write XOR Execute)**: The fundamental memory protection principle stating that no virtual memory page should ever be simultaneously writable and executable (`PROT_WRITE | PROT_EXEC` or `PAGE_EXECUTE_READWRITE`).

### X, Y, Z
261. **XDR (Extended Detection and Response)**: A unified security detection and response architecture correlating telemetry across Endpoints (`EDR`), Network (`NDR`), Cloud (`CDR`), Identity (`ITDR`), and Email into single attack storylines.
262. **XXE (XML External Entity Injection, `CWE-611`)**: A vulnerability against XML parsers that evaluate external `<!ENTITY>` declarations in the `DOCTYPE` header, enabling local file read (`file:///etc/passwd`), SSRF, and Denial of Service (`Billion Laughs`).
263. **YARA**: The pattern-matching Swiss Army knife for malware researchers (`"Yet Another Recursive/Ridiculous Acronym"`), matching files and process memory against boolean expressions of hexadecimal byte sequences, ASCII/UTF-16 strings, regular expressions, and PE/ELF structural properties.
264. **Zero-Day (`0-day`) Vulnerability**: A hardware or software security vulnerability that is unknown to the vendor or has no official patch available at the time it is discovered or exploited.
265. **Zero-Trust Architecture (`ZTA`, `NIST SP 800-207`)**: A security paradigm centered on the tenet *"Never Trust, Always Verify"* that eliminates implicit trust based on network location (corporate LAN vs Internet), requiring continuous cryptographic authentication, device posture verification, microsegmentation, and least-privilege authorization for every single request.
