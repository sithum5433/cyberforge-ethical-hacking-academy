# PART V: EXTERNAL ATTACK SURFACE MANAGEMENT (EASM), ASSET INVENTORY & NETWORK AUDITING

---

# Chapter 20: External Attack Surface Management (EASM) & OSINT Architecture

## 20.1 Introduction to External Attack Surface Management (EASM)

Modern enterprise infrastructure is no longer confined to a single on-premises data center behind a static perimeter firewall. Organizations operate across hybrid multi-cloud environments (AWS, Microsoft Azure, Google Cloud Platform), Content Delivery Networks (CDNs), Software-as-a-Service (SaaS) platforms, third-party vendor integrations, and dynamically provisioned Kubernetes clusters. **External Attack Surface Management (EASM)** is the continuous security engineering discipline of discovering, classifying, inventorying, and monitoring all internet-facing assets associated with an organization from an external perspective.

### 20.1.1 The Defender's Asymmetry Problem

Security architecture teams face an inherent structural challenge: to secure an organization, defenders must maintain visibility over 100% of their external assets, whereas an adversary only needs to identify a single forgotten, unpatched, or misconfigured system (often referred to as **Shadow IT** or **Orphaned Infrastructure**). Common sources of untracked external assets include:

1. **Mergers and Acquisitions (M&A):** Subsidiary networks, legacy domains, and regional IT infrastructure acquired during corporate expansions that were never integrated into the parent company's Configuration Management Database (CMDB).
2. **Ephemeral Cloud Environments:** Developer-provisioned staging servers, test buckets, or proof-of-concept virtual machines deployed outside centralized Infrastructure-as-Code (IaC) pipelines (Terraform, OpenTofu, CloudFormation).
3. **Third-Party Marketing and Microsites:** Campaign domains registered by external marketing agencies that point directly to cloud instances or third-party hosting providers without corporate security oversight.
4. **Decommissioned Services with Residual DNS Records:** Cloud resources that have been terminated while their authoritative DNS records (`A`, `AAAA`, `CNAME`, or `NS`) remain active, creating dangling DNS conditions.

```
+-----------------------------------------------------------------------------------+
|                   CONTINUOUS EASM LIFECYCLE ARCHITECTURE                          |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|  +-----------------------+     +-----------------------+     +-----------------+  |
|  | 1. Asset Attribution  | --> | 2. DNS & Certificate  | --> | 3. Network &    |  |
|  |    & Seed Discovery   |     |    Inventory Mapping  |     |    Service      |  |
|  |  - Corporate Filings  |     |  - Authoritative DNS  |     |    Verification |  |
|  |  - ASN / BGP Prefixes |     |  - CT Logs (RFC 6962) |     |  - Port Audits  |  |
|  |  - WHOIS / RDAP       |     |  - Subdomain Catalog  |     |  - TLS Posture  |  |
|  +-----------------------+     +-----------------------+     +-----------------+  |
|              ^                                                        |           |
|              |                                                        v           |
|  +-----------------------+     +-----------------------+     +-----------------+  |
|  | 6. CMDB Reconciliation| <-- | 5. Risk Prioritization| <-- | 4. Application  |  |
|  |    & Continuous Alert |     |    & Remediation      |     |    Cataloging   |  |
|  |  - Drift Detection    |     |  - Misconfigurations  |     |  - Tech Stack   |  |
|  |  - Policy Enforcement |     |  - Expired Certs/DNS  |     |  - API Schemas  |  |
|  +-----------------------+     +-----------------------+     +-----------------+  |
|                                                                                   |
+-----------------------------------------------------------------------------------+
```

### 20.1.2 Scope Governance and Rules of Engagement (RoE)

Before conducting any external asset discovery or network auditing activity, security engineers and authorized auditors must establish formal **Rules of Engagement (RoE)** and verify legal authorization.

| Governance Parameter | Enterprise Internal Audit / EASM | Authorized Penetration Test | Public Vulnerability Disclosure Program (VDP) |
| :--- | :--- | :--- | :--- |
| **Legal Authorization** | Internal corporate charter & CISO sign-off | Master Services Agreement (MSA) & Statement of Work (SoW) | Published program policy & Safe Harbor terms |
| **Target Scope Definition** | All corporate ASNs, root domains, cloud accounts, and subsidiaries | Explicitly listed CIDR blocks, FQDNs, and applications | Designated wildcard (`*.example.com`) or specific endpoints |
| **Out-of-Scope Boundaries** | Shared multi-tenant SaaS infrastructure not owned by the enterprise | Production databases requiring high-availability exclusions, third-party providers | Non-listed domains, corporate physical offices, social engineering |
| **Rate-Limiting & Traffic Identification** | Dedicated scanner egress IPs whitelisted in SOC/SIEM | Custom HTTP headers (e.g., `X-Audit-ID`) and source IP coordination | Strict adherence to program rate limits (e.g., max 5-10 requests/second) |
| **Emergency Escalation** | Direct integration with internal Incident Response (IR) channels | Dedicated 24/7 point-of-contact (POC) for service degradation | Platform support channel or `security@` contact per RFC 9116 (`security.txt`) |

#### Implementing RFC 9116 (`security.txt`)

Organizations should publish a standardized `/.well-known/security.txt` file on all web properties so security researchers and automated EASM platforms know how to report findings and verify scope boundaries:

```text
# /.well-known/security.txt (RFC 9116 Compliant)
Contact: mailto:security-reports@example.com
Contact: https://security.example.com/report
Encryption: https://security.example.com/pgp-key.txt
Acknowledgments: https://security.example.com/hall-of-fame
Preferred-Languages: en
Canonical: https://www.example.com/.well-known/security.txt
Policy: https://security.example.com/vdp-policy
Expires: 2027-01-01T00:00:00.000Z
```

---

## 20.2 Corporate Attribution, ASN Architecture & BGP Routing

Large enterprises rarely operate under a single domain name. Building a complete seed inventory requires tracing organizational hierarchy, regional subsidiaries, and network-layer allocations managed by Regional Internet Registries (RIRs).

### 20.2.1 Organizational Hierarchy and Subsidiary Mapping

When establishing an EASM baseline for a multinational enterprise, security architects reconcile legal entities across public registries:

1. **Corporate Registries and Financial Disclosures:** Publicly traded organizations list wholly-owned subsidiaries in annual regulatory filings (such as SEC Form 10-K Exhibit 21 in the United States, Companies House in the UK, or the Department of the Registrar of Companies in Sri Lanka).
2. **Acquisition History:** Historical mergers and acquisitions introduce legacy domain namespaces and distinct cloud tenancies. Every acquired entity's primary domain (`acquired-brand.com`) and regional TLD variants (`.lk`, `.co.uk`, `.de`, `.sg`) must be ingested into the central asset inventory.
3. **Brand Protection and Typosquatting Monitoring:** Organizations track newly registered domains resembling corporate trademarks using Domain Name System Security Extensions (DNSSEC) and brand monitoring feeds to detect unauthorized phishing infrastructure early.

### 20.2.2 Autonomous System Numbers (ASNs) and Regional Internet Registries

At the network layer, the global Internet consists of interconnected **Autonomous Systems (AS)**—collections of IP routing prefixes under the control of a single administrative entity that presents a common routing policy to the Internet via the **Border Gateway Protocol (BGP)**.

Each Autonomous System is assigned a unique **Autonomous System Number (ASN)** (16-bit or 32-bit integer, such as `AS15169`) by one of the five Regional Internet Registries (RIRs):

| RIR | Geographic Region | WHOIS / RDAP Endpoint |
| :--- | :--- | :--- |
| **APNIC** | Asia-Pacific (including Sri Lanka, India, Australia, Japan) | `whois.apnic.net` / `rdap.apnic.net` |
| **ARIN** | North America (United States, Canada, parts of Caribbean) | `whois.arin.net` / `rdap.arin.net` |
| **RIPE NCC** | Europe, Middle East, and Central Asia | `whois.ripe.net` / `rdap.db.ripe.net` |
| **LACNIC** | Latin America and Caribbean | `whois.lacnic.net` / `rdap.lacnic.net` |
| **AFRINIC** | Africa | `whois.afrinic.net` / `rdap.afrinic.net` |

#### Querying ASN and Prefix Allocations via RDAP and BGP Looking Glasses

Modern security engineering pipelines prefer the **Registration Data Access Protocol (RDAP, RFC 7480–7484)** over legacy text-based WHOIS because RDAP returns structured JSON over HTTPS and supports standardized rate-limiting and internationalization.

Below is a defensive Python utility that queries public RDAP and BGP routing APIs (such as RIPEstat) to audit all IPv4 and IPv6 CIDR prefixes announced by an organization's ASN:

```python
#!/usr/bin/env python3
"""
asn_prefix_auditor.py
Defensive EASM utility to query RIPEstat public BGP routing data
and generate a structured inventory of announced IPv4/IPv6 CIDR blocks for an ASN.
"""

import ipaddress
import json
import sys
import urllib.request
from typing import Dict, List, Any


def fetch_announced_prefixes(asn: str) -> Dict[str, Any]:
    """
    Queries the public RIPEstat Data API for all currently announced BGP prefixes
    associated with a given Autonomous System Number (e.g., 'AS13335').
    """
    clean_asn = asn.upper().lstrip("AS")
    url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{clean_asn}"

    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Enterprise-EASM-Inventory-Auditor/1.0"}
    )

    with urllib.request.urlopen(req, timeout=15) as response:
        if response.status != 200:
            raise RuntimeError(f"HTTP error {response.status} querying RIPEstat API")
        payload = json.loads(response.read().decode("utf-8"))

    return payload.get("data", {})


def summarize_prefixes(asn: str) -> None:
    data = fetch_announced_prefixes(asn)
    prefixes: List[Dict[str, Any]] = data.get("prefixes", [])

    ipv4_networks: List[ipaddress.IPv4Network] = []
    ipv6_networks: List[ipaddress.IPv6Network] = []

    for item in prefixes:
        prefix_str = item.get("prefix")
        if not prefix_str:
            continue
        net = ipaddress.ip_network(prefix_str, strict=False)
        if isinstance(net, ipaddress.IPv4Network):
            ipv4_networks.append(net)
        else:
            ipv6_networks.append(net)

    total_ipv4_hosts = sum(net.num_addresses for net in ipv4_networks)

    print(f"=== ASN Inventory Report for {asn.upper()} ===")
    print(f"Total Announced IPv4 Prefixes : {len(ipv4_networks)}")
    print(f"Total Announced IPv6 Prefixes : {len(ipv6_networks)}")
    print(f"Total Routable IPv4 Addresses : {total_ipv4_hosts:,}\n")

    print("--- IPv4 CIDR Allocations ---")
    for net in sorted(ipv4_networks):
        print(f"  {str(net):<20} ({net.num_addresses:,} addresses)")

    print("\n--- IPv6 CIDR Allocations ---")
    for net in sorted(ipv6_networks):
        print(f"  {str(net):<32} (/{net.prefixlen})")


if __name__ == "__main__":
    target_asn = sys.argv[1] if len(sys.argv) > 1 else "AS13335"
    summarize_prefixes(target_asn)
```

### 20.2.3 Securing BGP Announcements with RPKI and ROAs

In addition to cataloging IP ranges, infrastructure security teams must protect their ASN prefixes against unauthorized BGP hijacking or route leaks by implementing **Resource Public Key Infrastructure (RPKI, RFC 6480)**:

1. **Route Origin Authorization (ROA):** A cryptographically signed object published in the RIR repository stating which ASN is authorized to originate a specific IP prefix (and the maximum prefix length permitted, e.g., `/24` for IPv4 or `/48` for IPv6).
2. **Route Origin Validation (ROV):** Transit providers and internet exchange points (IXPs) verify BGP route announcements against published RPKI ROAs and drop `Invalid` announcements.

---

## 20.3 Certificate Transparency (CT) Logs & Cryptographic Asset Monitoring

### 20.3.1 Architecture of Certificate Transparency (RFC 6962)

Historically, if a Certificate Authority (CA) mistakenly issued—or was compromised into issuing—a rogue TLS certificate for a domain, the domain owner had no way of knowing until the certificate was actively intercepted. **Certificate Transparency (CT)**, standardized in RFC 6962 (and updated in RFC 9162), solves this problem by requiring publicly trusted CAs to append every issued X.509 certificate to publicly auditable, append-only cryptographic **Merkle Tree logs** before web browsers (such as Chrome and Safari) will trust the certificate.

```
+--------------------+        1. Certificate Request         +-------------------------+
| Enterprise / Cloud | ------------------------------------> | Public Certificate      |
| Provisioning System|                                       | Authority (Let's Encrypt|
+--------------------+                                       | DigiCert, Sectigo, etc.)|
          ^                                                  +-------------------------+
          |                                                               |
          | 4. Issued Certificate                                         | 2. Submit Precertificate
          |    + Embedded SCTs                                            v
          |                                                  +-------------------------+
          +------------------------------------------------- | Append-Only Merkle Tree |
                                                             | Certificate Transparency|
                                                             | Logs (Google, Cloudflare|
                                                             +-------------------------+
                                                                          |
                                                                          | 3. Public Audit Feed
                                                                          v
                                                             +-------------------------+
                                                             | Enterprise EASM / SOC   |
                                                             | Certificate Monitor     |
                                                             | (crt.sh / CertSpotter)  |
                                                             +-------------------------+
```

Every certificate logged in CT contains two critical fields for asset inventory:
- **Common Name (CN):** The primary hostname encoded in the Subject field.
- **Subject Alternative Name (SAN, OID `2.5.29.17`):** An X.509v3 extension listing all additional DNS names, wildcard domains, or IP addresses covered by a single multi-domain (UCC/SAN) certificate.

### 20.3.2 Defensive Monitoring of CT Logs

For defenders and EASM engineers, Certificate Transparency logs serve two vital operational purposes:

1. **Automated Asset Discovery:** Whenever an internal engineering team spins up a new service and provisions a Let's Encrypt or AWS Certificate Manager (ACM) public certificate, that hostname appears immediately in public CT logs—even if the subdomain is non-obvious (e.g., `staging-k8s-ingress-04.corp.example.com`).
2. **Rogue Certificate Detection:** Monitoring CT logs in real time alerts the SOC if an unauthorized party or misconfigured internal system issues a certificate for the organization's domain.

#### Querying the `crt.sh` PostgreSQL Interface for Defensive Inventory

Sectigo operates `crt.sh`, which indexes global CT logs in a publicly accessible PostgreSQL database and JSON web interface. Security teams can query their own domains via JSON API or direct PostgreSQL connection to reconcile active certificates against internal PKI records:

```sql
-- Defensive SQL query against crt.sh PostgreSQL mirror (crt.sh:5432, user: guest, db: certwatch)
-- Retrieves distinct DNS identities and issuer details for a corporate domain over the past 90 days
SELECT DISTINCT
    ci.NAME_VALUE AS hostname,
    c. ID AS crt_sh_id,
    x509_issuerName(c.CERTIFICATE) AS issuer_dn,
    x509_notBefore(c.CERTIFICATE) AS valid_from,
    x509_notAfter(c.CERTIFICATE) AS valid_until
FROM
    certificate_and_identities ci
JOIN
    certificate c ON ci.CERTIFICATE_ID = c.ID
WHERE
    plainto_tsquery('certwatch', 'example.com') @@ identities(c.CERTIFICATE)
    AND ci.NAME_TYPE = 'dNSName'
    AND ci.NAME_VALUE ILIKE '%.example.com'
    AND x509_notAfter(c.CERTIFICATE) > NOW()
ORDER BY
    valid_from DESC
LIMIT 100;
```

### 20.3.3 Enforcing Certification Authority Authorization (CAA - RFC 8659)

To prevent unauthorized Certificate Authorities from issuing TLS certificates for corporate domains, organizations must configure **DNS Certification Authority Authorization (CAA)** resource records. Before issuing any certificate, a compliant CA checks the domain's DNS hierarchy for CAA records; if a CAA record is present and does not list that CA, issuance is strictly refused.

```dns
; Example Authoritative DNS Zone Configuration with RFC 8659 CAA Enforcement
example.com.    3600    IN  CAA 0 issue "letsencrypt.org"
example.com.    3600    IN  CAA 0 issue "amazon.com"
example.com.    3600    IN  CAA 0 issuewild ";"
example.com.    3600    IN  CAA 0 iodef "mailto:security-alerts@example.com"
```

* **`issue "letsencrypt.org"`**: Authorizes only Let's Encrypt (and Amazon ACM in the second record) to issue standard single-host certificates.
* **`issuewild ";"`**: Explicitly forbids *any* Certificate Authority from issuing wildcard (`*.example.com`) certificates, enforcing least-privilege per-host certificates.
* **`iodef "mailto:..."`**: Instructs CAs to send an Incident Object Description Exchange Format (IODEF) violation report to the security team if an unauthorized certificate request is blocked.

---

## 20.4 Internet-Wide Telemetry Indexing & Perimeter Exposure Auditing

Internet telemetry platforms continuously scan the public IPv4 space and sampled IPv6 ranges to index service banners, TLS certificates, HTTP headers, and protocol handshakes. Security operations teams use these telemetry indexes (such as **Shodan**, **Censys**, **FOFA**, **ZoomEye**, and **Netlas**) to audit their own perimeter for accidental exposures without generating direct scan traffic against production links.

### 20.4.1 Comparative Architecture of Internet Telemetry Platforms

| Telemetry Platform | Primary Indexing Focus | Key Query Syntax Structure | Defensive Use Case |
| :--- | :--- | :--- | :--- |
| **Shodan** | Service banners, IoT/OT protocols (Modbus, BACnet), TCP/UDP ports | `asn:AS12345 net:198.51.100.0/24 port:443` | Continuous alerts (`Shodan Monitor`) for newly exposed management ports on corporate CIDR blocks |
| **Censys** | Deep X.509 TLS parsing, JARM fingerprints, structured protocol handshakes | `autonomous_system.asn: 12345 and services.port: 22` | Identifying origin servers exposing corporate TLS certificates outside CDN proxy ranges |
| **FOFA / ZoomEye** | Web application framework fingerprinting, favicon hashes, HTTP headers | `domain="example.com" && cert.is_valid=true` | Auditing regional web assets and verifying web server header hardening |
| **Netlas** | Integrated passive DNS, WHOIS, and HTTP response bodies | `host:*.example.com AND http.status_code:200` | Historical tracking of changes in external service exposure over time |

### 20.4.2 Auditing Origin Server Exposure Behind Reverse Proxies and CDNs

A frequent architectural misconfiguration occurs when an enterprise places a web application behind a CDN or cloud DDoS protection layer (such as Cloudflare, Akamai, or AWS CloudFront) to enforce Web Application Firewall (WAF) policies, but leaves the backend **Origin Server** accessible to the entire public IPv4 Internet on ports `80/tcp` or `443/tcp`.

When the origin server responds to direct IP connections using the corporate TLS certificate (containing `Subject: CN=app.example.com`), internet-wide TLS scanners index that IP-to-certificate relationship immediately. If network-level access controls do not restrict incoming traffic exclusively to the CDN provider's IP ranges, any actor can connect directly to the origin IP, bypassing CDN edge controls entirely.

```
   VULNERABLE ORIGIN ARCHITECTURE                     HARDENED ORIGIN ARCHITECTURE
+------------------------------------+            +------------------------------------+
|       Public Internet Client       |            |       Public Internet Client       |
+------------------------------------+            +------------------------------------+
        |                    |                                    |
        | 1. Via DNS         | 2. Direct IP Connection            | 1. Via DNS Only
        v                    |    (Bypasses CDN/WAF!)             v
+---------------+            |                            +---------------+
| CDN / Edge WAF|            |                            | CDN / Edge WAF|
+---------------+            |                            +---------------+
        |                    |                                    |
        |                    v                                    | 2. mTLS (Authenticated
        +----------> +---------------+                            |    Origin Pull) + IP ACL
                     | Origin Server |                            v
                     | 0.0.0.0/0:443 |                    +---------------+
                     +---------------+                    | Origin Server |
                                                          | (Locked Down) |
                                                          +---------------+
```

#### Remediation: Securing Origin Servers

To eliminate direct-to-origin exposure, infrastructure engineers must enforce three defense-in-depth controls:

1. **Network-Layer IP Whitelisting (Security Groups / NACL):** Configure cloud security groups or host firewalls (`nftables` / `iptables`) to accept inbound traffic on ports `80` and `443` *strictly* from the upstream CDN's published IPv4/IPv6 CIDR blocks (or remove public IPs entirely by using an outbound-only encrypted tunnel such as Cloudflare Tunnel or AWS PrivateLink).
2. **Authenticated Origin Pulls (Mutual TLS / mTLS):** Configure the origin web server (Nginx, Apache, Envoy) to require a valid client certificate presented by the CDN edge proxy before completing the TLS handshake.
3. **Strict Default Virtual Host (`default_server`):** Configure the web server's default catch-all virtual host (for requests arriving via raw IP address or unrecognized `Host` headers) to present a dummy self-signed certificate or immediately terminate the connection (e.g., Nginx status `444`).

```nginx
# Hardened Nginx Configuration: Rejecting Unauthenticated or Direct-IP Connections
# 1. Catch-all block for direct IP access or unknown Host headers
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    listen 443 ssl default_server;
    listen [::]:443 ssl default_server;

    server_name _;

    # Reject TLS handshake immediately without revealing any corporate certificate SANs
    ssl_reject_handshake on;

    return 444;
}

# 2. Production Virtual Host with Mutual TLS (Authenticated Origin Pulls)
server {
    listen 443 ssl http2;
    server_name app.example.com;

    ssl_certificate     /etc/ssl/private/app.example.com.pem;
    ssl_certificate_key /etc/ssl/private/app.example.com.key;

    # Verify that the connecting proxy presents a valid CDN Client Certificate
    ssl_client_certificate /etc/ssl/certs/cdn-origin-pull-ca.pem;
    ssl_verify_client on;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

### 20.4.3 Common Telemetry Audit Categories for Enterprise SOCs

Security engineers regularly audit their ASN and domain namespaces against the following exposure categories to verify perimeter hygiene:

| Exposure Category | Default Port(s) | Root Cause of Exposure | Remediation Standard |
| :--- | :--- | :--- | :--- |
| **Container Orchestration & Docker Daemons** | `2375/tcp` (Docker HTTP), `6443/tcp` (K8s API), `10250/tcp` (Kubelet) | Binding daemon sockets to `0.0.0.0` without TLS client auth or private VPC isolation | Bind Docker to Unix socket only (`unix:///var/run/docker.sock`); place Kubernetes API servers behind private endpoints or VPNs with RBAC. |
| **In-Memory Caches & NoSQL Databases** | `6379/tcp` (Redis), `11211/tcp` (Memcached), `27017/tcp` (MongoDB), `9200/tcp` (Elasticsearch) | Default installations on cloud VMs lacking VPC firewall restrictions or authentication | Bind data stores strictly to private VPC subnets (`127.0.0.1` or internal interface), enable TLS and strong ACL authentication. |
| **CI/CD & Observability Dashboards** | `8080/tcp` (Jenkins), `3000/tcp` (Grafana), `9090/tcp` (Prometheus) | Internal engineering utilities deployed on public subnets for convenience | Place behind an Identity-Aware Proxy (IAP) / Zero-Trust Network Access (ZTNA) gateway with SSO/MFA enforcement. |
| **Application Diagnostic Endpoints** | `/actuator/env`, `/actuator/heapdump` (Spring Boot), `/metrics`, `/debug/pprof` (Go) | Production builds retaining development management endpoints on the primary HTTP listener | Bind management/actuator endpoints to an internal loopback/management port (`management.server.port=9001`) inaccessible from the public ingress. |

---

# Chapter 21: Search Engine Indexing Audits, Source Code Secret Scanning & Cloud Storage Auditing

## 21.1 Search Engine Indexing Audits & Preventing Unintended Information Disclosure

Public search engines (Google, Bing, DuckDuckGo) continuously crawl the web and index any resource that is publicly linked and not explicitly restricted by authentication or indexing directives. When sensitive administrative portals, directory listings, backup archives, or diagnostic logs are inadvertently placed in a public web root, search engine crawlers cache and index their contents.

### 21.1.1 Search Engine Indexing Mechanics and Audit Operators

Security auditors use advanced search operators to verify whether sensitive organizational files or internal portals have been indexed by public crawlers:

| Search Operator | Functional Behavior | Defensive Audit Objective |
| :--- | :--- | :--- |
| `site:example.com` | Restricts results strictly to the specified domain or subdomain hierarchy | Enumerating all publicly indexed subdomains and URL paths across an enterprise domain |
| `filetype:pdf` / `ext:env` | Filters indexed documents by file extension or MIME classification | Detecting accidentally published configuration files (`.env`, `.yaml`, `.bak`, `.sql`) or internal documents |
| `intitle:"index of"` | Matches strings inside the HTML `<title>` element | Identifying web servers with misconfigured directory auto-indexing (`Options +Indexes` in Apache or `autoindex on` in Nginx) |
| `inurl:/admin` or `inurl:/swagger` | Matches substrings within the indexed URL path | Auditing exposed administrative consoles, API documentation, or staging paths |
| `intext:"Index of /"` | Searches for exact phrases inside the body text of indexed pages | Locating stack traces, verbose database error messages, or leaked configuration blocks |

### 21.1.2 Why `robots.txt` Is Not an Access Control Mechanism

A common anti-pattern in web administration is attempting to hide sensitive directories (such as `/admin-portal/`, `/backups/`, or `/internal-api/`) by listing them under `Disallow:` in `/robots.txt`.

While well-behaved search engine crawlers honor the **Robots Exclusion Protocol (RFC 9309)** and refrain from indexing those paths, `/robots.txt` is itself a publicly readable file located at the root of the web server. Listing sensitive paths in `robots.txt` acts as a roadmap of unindexed directories.

#### Hardened Indexing & Directory Control

1. **Enforce Authentication and Network Access Controls:** Sensitive endpoints must require authentication (SSO/MFA) and network-level restrictions rather than relying on obscurity or `robots.txt`.
2. **Use HTTP `X-Robots-Tag` Response Headers:** To prevent legitimate crawlers from indexing authenticated or non-public pages without advertising the URL paths in a public `robots.txt` file, return the `X-Robots-Tag` HTTP header on those routes:
   ```http
   X-Robots-Tag: noindex, nofollow, noarchive, nosnippet
   ```
3. **Disable Directory Listing Server-Wide:** Ensure web servers never auto-generate HTML file listings when an index file is absent:
   ```nginx
   # Nginx: Explicitly disable directory listing globally
   http {
       autoindex off;
   }
   ```
   ```apache
   # Apache HTTP Server: Remove Indexes option across document root
   <Directory /var/www/html>
       Options -Indexes
   </Directory>
   ```

---

## 21.2 Source Code Secret Scanning & Git Repository Hygiene

Modern software engineering relies heavily on Distributed Version Control Systems (DVCS), primarily **Git** hosted on platforms such as GitHub, GitLab, and Bitbucket. One of the most pervasive causes of cloud and API breaches is **Secret Sprawl**—the accidental commit of hardcoded API keys, database connection strings, AWS IAM access keys, or private SSH/TLS keys into source code repositories.

### 21.2.1 Git Internal Architecture and Why Deleting a File Does Not Remove a Secret

A critical concept in source code auditing is understanding how Git stores data. Git is an immutable, content-addressable filesystem organized as a Directed Acyclic Graph (DAG) of objects inside the `.git/objects/` directory:

1. **Blob (Binary Large Object):** Stores the compressed raw contents of a file (identified by its SHA-1 or SHA-256 hash).
2. **Tree:** Maps file names and permissions to Blob hashes and subdirectories.
3. **Commit:** Points to a root Tree object, parent Commit hash(es), author metadata, and commit message.

```
+-------------------------------------------------------------------------+
|                    GIT COMMIT HISTORY & DANGLING BLOBS                  |
+-------------------------------------------------------------------------+
|                                                                         |
|  Commit A (c1a2b3)                  Commit B (d4e5f6) [HEAD]            |
|  "Initial API client"               "Remove hardcoded AWS key"          |
|         |                                  |                            |
|         v                                  v                            |
|     Tree (t1)                          Tree (t2)                        |
|         |                                  |                            |
|         +--> config.py (Blob b99f)         +--> config.py (Blob a11c)   |
|              [AWS_SECRET = "wJalrX..."]         [AWS_SECRET = os.env()] |
|                                                                         |
|  WARNING: Even though Commit B removed the secret from HEAD,            |
|           Blob b99f remains permanently accessible in Commit A!         |
+-------------------------------------------------------------------------+
```

When a developer commits a secret in `Commit A` and then immediately deletes the line and pushes `Commit B` ("Removed secret"), **the secret is still completely exposed in the repository's history**. Even if a branch is force-pushed or deleted, **dangling commits** (unreachable from any named branch or tag) can remain accessible via commit SHA URLs or `git reflog` until garbage collection (`git gc --prune=now`) is executed on the remote server.

#### Gold Standard Response to a Committed Secret

1. **Immediate Revocation and Rotation (Mandatory First Step):** Treat any secret that has touched a Git repository (even briefly in a private repository) as compromised. Immediately revoke the credential in the provider's IAM console and issue a new secret.
2. **History Sanitization:** Use `git-filter-repo` (the modern replacement for `git filter-branch`) or BFG Repo-Cleaner to purge the sensitive blob across all commits, tags, and branches, and coordinate with the repository hosting platform to clear cached objects and pull requests.

### 21.2.2 Preventing Exposed `.git/` Directories on Production Web Servers

If a deployment pipeline deploys an application to a web server by running `git clone` or `git pull` directly inside `/var/www/html/`, the hidden `/var/www/html/.git/` directory may become accessible over HTTP (`https://example.com/.git/HEAD`). Even when directory listing is disabled, deterministic files inside `.git/` (`.git/HEAD`, `.git/config`, `.git/index`, and `.git/logs/HEAD`) contain exact SHA-1 hashes of every tree and blob, allowing anyone to reconstruct the entire proprietary source code and commit history.

#### Remediation for Production Deployments

1. **Build Artifacts Outside the Web Root:** CI/CD pipelines should package only compiled artifacts or production assets into immutable container images ( using `.dockerignore` to exclude `.git`) or tarballs before deploying.
2. **Web Server Denial Rule:** Always block HTTP access to hidden dot-files and directories (except `/.well-known/` for ACME/RFC 9116):

```nginx
# Nginx: Deny access to .git, .env, .svn, and all hidden files (except .well-known)
location ~ /\.(?!well-known).* {
    deny all;
    access_log off;
    log_not_found off;
    return 404;
}
```

### 21.2.3 Automated Secret Detection Architecture: Entropy vs. Pattern Matching

Enterprise AppSec programs integrate automated secret scanners—such as **Gitleaks** and **TruffleHog**—at three enforcement points:
1. **Developer Workstation (Pre-Commit Hook):** Blocks the commit locally before it ever enters the local `.git` history.
2. **Server-Side Push Protection (Pre-Receive Hook):** Rejects `git push` operations containing high-confidence secret patterns on the Git server.
3. **CI/CD Pipeline & Historical Audit:** Scans full repository history (`--all` branches and commits) for historical leaks.

Secret scanners combine two detection engines:
* **Structured Regular Expressions (Regex) & Prefix Signatures:** Cloud providers increasingly design API tokens with deterministic prefixes (e.g., AWS Access Key IDs start with `AKIA` or `ASIA`; GitHub Personal Access Tokens start with `ghp_`, `gho_`, `ghu_`, `ghs_`, or `ghr_`; Slack tokens start with `xoxb-` or `xoxp-`) specifically to make automated detection accurate with near-zero false positives.
* **Shannon Entropy Calculation:** For unstructured secrets (such as custom HMAC keys or raw cryptographic keys), scanners compute the **Shannon Entropy** ($H$) of candidate strings to measure randomness:

$$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$

Where $P(x_i)$ is the frequency of character $x_i$ in the string. Natural language code identifiers typically have $H < 3.5$ bits per character, whereas base64-encoded or hexadecimal cryptographic keys typically exhibit $H > 4.5$ bits per character.

#### Example: Custom `.gitleaks.toml` Configuration & Pre-Commit Integration

```toml
# .gitleaks.toml - Enterprise Secret Scanning Configuration
title = "Enterprise Gitleaks Policy"

[extend]
useDefault = true

[[rules]]
id = "internal-jwt-signing-key"
description = "Detects hardcoded internal microservice HMAC/JWT signing keys"
regex = '''(?i)(?:jwt_secret|signing_key|hmac_secret)\s*[:=]\s*['"]([A-Za-z0-9_\-]{32,})['"]'''
secretGroup = 1
entropy = 4.2
keywords = ["jwt_secret", "signing_key", "hmac_secret"]

[allowlist]
description = "Global allowlist for unit test fixtures and mock keys"
paths = [
    '''(^|/)tests/fixtures/''',
    '''\.example$''',
    '''\.template$'''
]
```

To enforce scanning automatically on every developer workstation before a commit is created, configure `.pre-commit-config.yaml`:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.4
    hooks:
      - id: gitleaks
        name: "Block hardcoded secrets before commit"
        entry: gitleaks protect --verbose --redact --staged
        language: golang
```

---

## 21.3 Cloud Storage Access Control Auditing (AWS S3, Azure Blob, GCP Cloud Storage)

Cloud object storage services—**Amazon Simple Storage Service (AWS S3)**, **Microsoft Azure Blob Storage**, and **Google Cloud Storage (GCS)**—host petabytes of enterprise data. Misconfigured access control policies on storage buckets remain a top cause of sensitive data exposure.

### 21.3.1 Multi-Cloud Storage Architecture and Naming Conventions

Each major cloud provider exposes object storage over HTTPS endpoints using predictable DNS naming schemas:

| Cloud Provider | Service Name | Standard DNS Endpoint Structure | Access Control Mechanisms |
| :--- | :--- | :--- | :--- |
| **Amazon Web Services (AWS)** | Simple Storage Service (S3) | `https://<bucket>.s3.<region>.amazonaws.com` | IAM Policies, Bucket Policies (JSON), Access Control Lists (ACLs), S3 Block Public Access |
| **Microsoft Azure** | Azure Blob Storage | `https://<account>.blob.core.windows.net/<container>` | Azure RBAC (Entra ID), Shared Access Signatures (SAS), Container Public Access Level |
| **Google Cloud Platform (GCP)** | Google Cloud Storage (GCS) | `https://storage.googleapis.com/<bucket>` | IAM Roles (`allUsers`, `allAuthenticatedUsers`), Fine-Grained ACLs vs. Uniform Bucket-Level Access |

### 21.3.2 Common Cloud Storage Misconfigurations

1. **Unintended Public Read / List Permissions:**
   * In AWS S3, granting `s3:GetObject` to `Principal: "*"` allows anyone who knows an object key to download it. Worse, granting `s3:ListBucket` to `Principal: "*"` allows any unauthenticated user to retrieve an XML index of every file key inside the bucket.
2. **The `"AuthenticatedUsers"` Misconception (`AllAuthenticatedUsers` / `allAuthenticatedUsers`):**
   * Both AWS S3 legacy ACLs (`http://acs.amazonaws.com/groups/global/AuthenticatedUsers`) and GCP IAM (`allAuthenticatedUsers`) define "Authenticated Users" as **anyone signed into any account across the entire cloud provider globally**—*not* just users within the enterprise's own AWS Organization or GCP Workspace.
3. **Permissive Write / Upload Permissions (`s3:PutObject`, `s3:DeleteObject`):**
   * Allowing unauthenticated or broadly authenticated write access enables unauthorized actors to overwrite static web assets (e.g., poisoning JavaScript bundles hosted on S3) or delete critical backups.

### 21.3.3 Auditing and Remediating Cloud Storage Posture

#### Auditing AWS S3 with `aws-cli` and AWS Config

Security engineers audit their organization's S3 buckets by inspecting four settings on every bucket:
1. **Public Access Block Configuration**
2. **Bucket Policy Status**
3. **Bucket ACLs**
4. **Server-Side Encryption (SSE-S3 / SSE-KMS) & Object Versioning**

Below is a defensive Python script using `boto3` that audits all S3 buckets in an AWS account to verify that **S3 Block Public Access** is strictly enabled and that no bucket policies permit public access:

```python
#!/usr/bin/env python3
"""
s3_posture_auditor.py
Defensive Cloud Security Posture Management (CSPM) script to audit all S3 buckets
within an authorized AWS account for Public Access Block compliance and encryption.
"""

import boto3
from botocore.exceptions import ClientError


def audit_s3_buckets() -> None:
    s3 = boto3.client("s3")
    response = s3.list_buckets()
    buckets = response.get("Buckets", [])

    print(f"Auditing {len(buckets)} S3 buckets in AWS account...\n")
    print(f"{'Bucket Name':<40} | {'Public Block':<14} | {'Policy Public':<14} | {'SSE Enabled'}")
    print("-" * 88)

    for b in buckets:
        name = b["Name"]

        # 1. Check Public Access Block (All 4 flags must be True)
        pab_compliant = False
        try:
            pab = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            pab_compliant = all([
                pab.get("BlockPublicAcls", False),
                pab.get("IgnorePublicAcls", False),
                pab.get("BlockPublicPolicy", False),
                pab.get("RestrictPublicBuckets", False),
            ])
        except ClientError:
            pab_compliant = False

        # 2. Check Bucket Policy Public Status
        is_policy_public = False
        try:
            status = s3.get_bucket_policy_status(Bucket=name)
            is_policy_public = status.get("PolicyStatus", {}).get("IsPublic", False)
        except ClientError:
            is_policy_public = False

        # 3. Check Default Server-Side Encryption
        sse_enabled = False
        try:
            enc = s3.get_bucket_encryption(Bucket=name)
            rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
            sse_enabled = len(rules) > 0
        except ClientError:
            sse_enabled = False

        print(
            f"{name:<40} | "
            f"{'PASS' if pab_compliant else 'FAIL (OPEN)':<14} | "
            f"{'FAIL (PUBLIC)' if is_policy_public else 'PASS':<14} | "
            f"{'PASS' if sse_enabled else 'FAIL'}"
        )


if __name__ == "__main__":
    audit_s3_buckets()
```

#### Remediation: Enforcing Hardened Cloud Storage via Terraform (IaC)

To prevent accidental public bucket creation across an enterprise, cloud architects enforce account-wide **S3 Block Public Access**, disable legacy ACLs (`BucketOwnerEnforced`), and serve static web assets exclusively through a CDN using **Origin Access Control (OAC)** rather than making the S3 bucket public:

```hcl
# Hardened AWS S3 Bucket Configuration in Terraform
# 1. Account-Wide S3 Public Access Block (Prevents any public bucket in the AWS account)
resource "aws_s3_account_public_access_block" "enterprise_lockdown" {
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# 2. Private Application Storage Bucket
resource "aws_s3_bucket" "app_data" {
  bucket = "corp-prod-sensitive-records-2026"
}

# Disable legacy ACLs completely (BucketOwnerEnforced)
resource "aws_s3_bucket_ownership_controls" "app_data_ownership" {
  bucket = aws_s3_bucket.app_data.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

# Bucket-level Public Access Block
resource "aws_s3_bucket_public_access_block" "app_data_pab" {
  bucket                  = aws_s3_bucket.app_data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Enforce KMS Server-Side Encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "app_data_encryption" {
  bucket = aws_s3_bucket.app_data.id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.s3_key.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

# Enforce TLS-only (HTTPS) access via Bucket Policy
resource "aws_s3_bucket_policy" "enforce_tls" {
  bucket = aws_s3_bucket.app_data.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyNonTLSRequests"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.app_data.arn,
          "${aws_s3_bucket.app_data.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}
```


---

# Chapter 22: DNS Hierarchy, Subdomain Inventory & Preventing Dangling DNS Risks

## 22.1 The Domain Name System (DNS) Architecture & Resolution Mechanics

The **Domain Name System (DNS, RFC 1034 / RFC 1035)** is the hierarchical, distributed naming system that translates human-readable domain names into IP addresses and service routing metadata. Every External Attack Surface Management (EASM) program relies on a deep understanding of DNS architecture to maintain an accurate inventory of organizational hosts and to eliminate misconfigurations.

### 22.1.1 Hierarchical Resolution Path: Stub, Recursive, Root, TLD, and Authoritative Servers

When a client resolves a Fully Qualified Domain Name (FQDN) such as `api.payments.example.com.`, the query traverses four distinct tiers of DNS infrastructure:

```
+---------------+      1. Query: api.payments.example.com?      +-----------------------+
| Client System | --------------------------------------------> | Recursive Resolver    |
| (Stub)        | <-------------------------------------------- | (e.g., 1.1.1.1, 8.8.8.8|
+---------------+      8. Final Response: 198.51.100.42         |  or Internal Unbound) |
                                                                +-----------------------+
                                                                   |   ^    |   ^    |   ^
                   2. Query "."         3. Referral to ".com"      |   |    |   |    |   |
                   +-----------------------------------------------+   |    |   |    |   |
                   |  +------------------------------------------------+    |   |    |   |
                   v  |                                                     |   |    |   |
        +-----------------------+       4. Query ".com" / 5. NS Referral    |   |    |   |
        | Root Nameservers (.)  |      +------------------------------------+   |    |   |
        | (a.root-servers.net   |      |  +-------------------------------------+    |   |
        |  through m.root)      |      v  |                                          |   |
        +-----------------------+  +-----------------------+  6. Query Auth / 7. Ans |   |
                                   | TLD Nameservers (.com)|  +----------------------+   |
                                   | (gtld-servers.net)    |  |  +-----------------------+
                                   +-----------------------+  v  |
                                                         +-----------------------------+
                                                         | Authoritative Nameserver    |
                                                         | (ns1.example.com)           |
                                                         | Zone: example.com           |
                                                         +-----------------------------+
```

### 22.1.2 Core DNS Resource Record (RR) Types for Security Auditing

| Record Type | RFC Reference | Structure & Purpose | Security & EASM Relevance |
| :--- | :--- | :--- | :--- |
| **`SOA`** | RFC 1035 | Start of Authority: primary NS, administrator email, zone serial number, refresh/retry timers | Tracks zone serial changes to detect when DNS modifications occur |
| **`NS`** | RFC 1035 | Delegates a domain or subdomain zone to authoritative nameservers | Unmonitored `NS` delegations to expired domains allow full zone hijacking |
| **`A` / `AAAA`** | RFC 1035 / 3596 | Maps a hostname to an IPv4 (32-bit) or IPv6 (128-bit) address | Dangling `A` records pointing to released cloud Elastic IPs risk IP reuse takeover |
| **`CNAME`** | RFC 1035 | Canonical Name alias pointing one hostname to another target FQDN | Primary vector for Subdomain Takeover when the target SaaS/PaaS resource is deleted |
| **`MX`** | RFC 1035 | Mail Exchange servers responsible for accepting email for the domain | Must be paired with SPF, DKIM, and DMARC to prevent domain email spoofing |
| **`TXT`** | RFC 1035 | Arbitrary text strings; carries SPF (`v=spf1`), DKIM, DMARC, and vendor domain-verification tokens | Reveals third-party SaaS providers used by the enterprise (e.g., `atlassian-domain-verification=...`) |
| **`PTR`** | RFC 1035 | Reverse DNS record mapping an IP address (`in-addr.arpa` / `ip6.arpa`) back to a hostname | Used during CIDR block audits to identify server roles from IP ranges |
| **`SRV`** | RFC 2782 | Service location record (`_service._proto.name`) specifying port and target host | Exposes VoIP (`_sip._tls`), Active Directory (`_ldap._tcp`), and messaging services |
| **`CAA`** | RFC 8659 | Certification Authority Authorization restricting which CAs may issue TLS certificates | Prevents unauthorized CAs from issuing certificates for the domain |

---

## 22.2 Subdomain Inventory Management & Split-Horizon DNS Architecture

### 22.2.1 Reconciling Authoritative Zones vs. Passive DNS Telemetry

In a mature enterprise, the primary source of truth for subdomain inventory is the **Authoritative DNS Zone Export** (via cloud DNS APIs such as AWS Route53, Cloudflare DNS, or Azure DNS). However, security teams also cross-reference authoritative records with **Passive DNS (pDNS)** telemetry and Certificate Transparency logs for three reasons:

1. **Wildcard DNS Records (`*.example.com`):** An authoritative zone might contain a single `*.apps.example.com` record pointing to an ingress load balancer. The zone file itself does not list the hundreds of individual virtual hosts (`payroll.apps.example.com`, `grafana.apps.example.com`) routed by that ingress controller, whereas CT logs and passive DNS capture the actual FQDNs in use.
2. **Shadow Domains and Delegated Subzones:** A subzone (`dev.example.com`) may be delegated via `NS` records to a separate cloud account managed by an independent business unit.
3. **Historical DNS Drift:** Passive DNS repositories record historical `A` and `CNAME` mappings, allowing defenders to verify when an IP migration occurred or whether legacy servers remain online at old IP addresses.

### 22.2.2 Restricting Unauthorized Zone Transfers (AXFR / IXFR)

**DNS Zone Transfer (`AXFR`, RFC 5936, and Incremental Zone Transfer `IXFR`, RFC 1995)** is an operational mechanism used to replicate DNS zone databases from a primary authoritative nameserver to secondary nameservers.

If an authoritative nameserver is misconfigured to permit `AXFR` requests from arbitrary public IP addresses (`allow-transfer { any; };`), any external host can download the entire zone file in a single TCP query on port `53/tcp`, exposing every internal and external hostname registered in that zone.

#### Hardening BIND9 / Authoritative DNS Against Arbitrary Zone Transfers

Authoritative nameservers must restrict `AXFR`/`IXFR` strictly to the IP addresses of secondary nameservers AND require cryptographic authentication using **Transaction Signatures (TSIG, RFC 8945)**:

```named
// Hardened /etc/bind/named.conf.options and Zone Configuration
key "tsig-secondary-replication-key" {
    algorithm hmac-sha256;
    secret "8f9K2mP4qR7vX1zB5nL9wC3yT6hJ0dG2sF4aE8uI1oP=";
};

acl "authorized_secondaries" {
    198.51.100.53;    // Secondary NS 1
    203.0.113.53;     // Secondary NS 2
};

options {
    directory "/var/cache/bind";
    recursion no;                     // Authoritative servers must NEVER permit recursion
    allow-transfer { none; };         // Deny transfers globally by default
    version "Not Disclosed";          // Hide BIND version string
};

zone "example.com" {
    type master;
    file "/etc/bind/zones/db.example.com";
    // Require BOTH IP match AND valid HMAC-SHA256 TSIG key for zone transfer
    allow-transfer {
        key "tsig-secondary-replication-key";
    };
};
```

### 22.2.3 Split-Horizon DNS Architecture and Internal Namespace Isolation

A frequent architectural mistake is publishing RFC 1918 private IP addresses (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) inside public authoritative DNS zones (e.g., `prod-db-01.internal.example.com IN A 10.24.16.105`). While external clients cannot route directly to `10.24.16.105` over the public Internet, leaking internal hostnames and private IP topologies in public DNS provides a blueprint of internal subnet layouts and naming conventions.

#### Implementing Split-Horizon (Split-Brain) DNS

Organizations must separate internal and external DNS namespaces using **Split-Horizon DNS**:
- **External Public Zone (`example.com` on public Route53 / Cloudflare):** Contains *only* records intended to be reachable from the public Internet.
- **Internal Private Zone (`internal.example.com` or private Route53 Hosted Zone attached to VPC):** Resolves exclusively for workloads and VPN-authenticated clients inside the corporate network.
- **Zero-Trust Internal Certificates:** To avoid leaking internal hostnames in public Certificate Transparency logs while still enforcing HTTPS on internal services, issue certificates for internal services (`*.internal.example.com`) using an **Internal Private PKI** (such as HashiCorp Vault PKI, AWS Private CA, or Smallstep `step-ca`) rather than a public CA.

---

## 22.3 Dangling DNS & Subdomain Takeover Prevention

### 22.3.1 Mechanics of a Dangling DNS Condition

A **Dangling DNS Record** (which creates a **Subdomain Takeover** risk) occurs when an organization creates a DNS record (`CNAME`, `A`, or `NS`) pointing a corporate subdomain (e.g., `promo.example.com`) to an external multi-tenant cloud service, PaaS provider, or dynamic IP address, and later deletes or decommissions the target cloud resource **without removing the corresponding DNS record** from the authoritative zone.

```
+-----------------------------------------------------------------------------------+
|                        DANGLING DNS / SUBDOMAIN TAKEOVER                          |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|  1. Authoritative DNS Zone (example.com) retains stale record:                    |
|     promo.example.com.  300  IN  CNAME  example-promo-app.cloudprovider.net.      |
|                                                                                   |
|  2. Engineering team deletes "example-promo-app" in Cloud Provider console,       |
|     releasing the virtual host name back into the public multi-tenant pool.       |
|                                                                                   |
|  3. Unclaimed State:                                                              |
|     Querying https://promo.example.com returns provider error banner:             |
|     "404 - There isn't a site configured at this hostname / NoSuchBucket"         |
|                                                                                   |
|  4. Impact if Claimed by Unauthorized Party:                                      |
|     - Serves unauthorized content under legitimate corporate domain               |
|     - Obtains valid Let's Encrypt TLS certificate via HTTP-01 challenge           |
|     - Receives session cookies scoped to parent domain (.example.com)             |
|     - Bypasses CORS policies trusting *.example.com                               |
|                                                                                   |
+-----------------------------------------------------------------------------------+
```

### 22.3.2 Taxonomy of Dangling DNS Vectors

1. **Dangling `CNAME` to Multi-Tenant SaaS/PaaS Providers:**
   * Cloud storage buckets (AWS S3 website endpoints), static site hosts (GitHub Pages, Azure App Service, Azure Traffic Manager), or CDN distributions that do not require cryptographic TXT record ownership verification before claiming a custom domain.
2. **Dangling `A` / `AAAA` Records to Ephemeral Cloud IPs:**
   * When a cloud VM (EC2, DigitalOcean Droplet, Azure VM) using an ephemeral public IP is terminated, the IP address is returned to the cloud provider's public pool and rapidly reassigned to another customer. If `legacy.example.com` still points to that IP, traffic for `legacy.example.com` routes to the new tenant's VM.
3. **Dangling `NS` Delegation to Expired Domains or Unclaimed Cloud DNS Zones:**
   * If `sub.example.com` has `NS` records delegating authority to a managed DNS zone (e.g., `ns-123.awsdns-01.com`) that was deleted, or to a custom nameserver domain that has expired, an unauthorized party who recreates the matching hosted zone on those same nameservers gains complete DNS authority over `sub.example.com`.
4. **Dangling `MX` Records:**
   * Pointing `MX` records to an unclaimed domain or decommissioned mail server host allows unauthorized interception of inbound emails addressed to that subdomain.

### 22.3.3 Automated Dangling DNS Auditing Script (Defensive EASM)

Below is a defensive Python auditing script that parses an organization's DNS records, checks for `NXDOMAIN` responses on `CNAME` targets (a primary indicator of an unclaimed cloud resource), and inspects HTTP diagnostic banners on external `CNAME` targets so infrastructure teams can purge stale records immediately:

```python
#!/usr/bin/env python3
"""
dangling_dns_auditor.py
Defensive DNS hygiene utility that audits a list of corporate subdomains
for dangling CNAME records (NXDOMAIN targets or unprovisioned PaaS signatures).
Requires: pip install dnspython requests
"""

import sys
from typing import List, Dict, Optional
import dns.resolver
import requests

# Diagnostic fingerprints indicating an unprovisioned resource on a multi-tenant platform
UNPROVISIONED_SIGNATURES: Dict[str, str] = {
    "AWS S3 Bucket": "The specified bucket does not exist",
    "GitHub Pages": "There isn't a GitHub Pages site here.",
    "Azure App Service / Traffic Manager": "Error 404 - Web app not found",
    "Heroku": "No such app",
    "Fastly CDN": "Fastly error: unknown domain",
    "Shopify": "Sorry, this shop is currently unavailable.",
}


def check_subdomain_cname(fqdn: str) -> Optional[str]:
    """Resolves CNAME record for a given FQDN if present."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5.0
    resolver.lifetime = 5.0
    try:
        answers = resolver.resolve(fqdn, "CNAME")
        for rdata in answers:
            return str(rdata.target).rstrip(".")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
        return None
    return None


def target_resolves(target_fqdn: str) -> bool:
    """Checks whether the CNAME target itself resolves to an A or AAAA record."""
    resolver = dns.resolver.Resolver()
    for rtype in ("A", "AAAA"):
        try:
            resolver.resolve(target_fqdn, rtype)
            return True
        except Exception:
            continue
    return False


def audit_subdomains(subdomains: List[str]) -> None:
    print(f"{'Subdomain':<35} | {'CNAME Target':<40} | {'Status'}")
    print("-" * 105)

    for sub in subdomains:
        cname_target = check_subdomain_cname(sub)
        if not cname_target:
            continue

        # Check 1: Does the CNAME point to an NXDOMAIN target?
        if not target_resolves(cname_target):
            print(f"{sub:<35} | {cname_target:<40} | ALERT: CNAME target returns NXDOMAIN!")
            continue

        # Check 2: Does HTTP/HTTPS response match an unprovisioned PaaS banner?
        alert_found = False
        for scheme in ("http", "https"):
            try:
                resp = requests.get(f"{scheme}://{sub}", timeout=5, allow_redirects=True)
                for provider, signature in UNPROVISIONED_SIGNATURES.items():
                    if signature in resp.text:
                        print(
                            f"{sub:<35} | {cname_target:<40} | "
                            f"ALERT: Unclaimed {provider} resource!"
                        )
                        alert_found = True
                        break
                if alert_found:
                    break
            except requests.RequestException:
                continue

        if not alert_found:
            print(f"{sub:<35} | {cname_target:<40} | OK (Active)")


if __name__ == "__main__":
    sample_inventory = [
        "www.example.com",
        "docs.example.com",
        "status.example.com",
    ]
    if len(sys.argv) > 1:
        with open(sys.argv[1], "r", encoding="utf-8") as f:
            sample_inventory = [line.strip() for line in f if line.strip()]
    audit_subdomains(sample_inventory)
```

### 22.3.4 Lifecycle Governance: Eliminating Dangling DNS by Design

To permanently prevent subdomain takeovers across an enterprise:
1. **Strict Decommissioning Order of Operations (DNS First, Resource Second):** Always delete or update the DNS `CNAME`/`A`/`NS` record and wait for the record's TTL to expire *before* deleting the underlying cloud bucket, PaaS application, or Elastic IP.
2. **Manage DNS and Cloud Compute in the Same Terraform State:** When DNS records (`aws_route53_record`) and cloud resources (`aws_s3_bucket`, `aws_eip`) are managed together in Infrastructure-as-Code (IaC), destroying a module automatically removes the DNS record alongside the resource.
3. **Pre-Claim Defensive Placeholders:** When migrating away from a cloud resource, retain a minimal placeholder container or locked bucket until all DNS propagation has completely cleared.

---

# Chapter 23: Authorized Network Discovery, Port Auditing & Service Verification

## 23.1 TCP/IP Handshake Mechanics & Authorized Network Auditing

Network security engineers regularly perform authorized port and service audits across corporate CIDR blocks to verify that perimeter firewalls, cloud Security Groups, and host-based packet filters match approved network architecture diagrams.

### 23.1.1 TCP Header Control Flags and State Transitions (RFC 9293)

Understanding how network scanners determine port state (`open`, `closed`, or `filtered`) requires examining the 6 primary control bits (flags) in the TCP header and how a compliant TCP/IP stack responds according to **RFC 9293**:

| TCP Flag | Bit Meaning | Role in Connection & Auditing |
| :--- | :--- | :--- |
| **`SYN`** | Synchronize sequence numbers | Initiates a TCP connection handshake (`Client -> Server`) |
| **`ACK`** | Acknowledgment field significant | Confirms receipt of previous segment (`SYN/ACK`, `ACK`, `RST/ACK`) |
| **`RST`** | Reset the connection | Immediately aborts an invalid or refused connection (indicates a `closed` port) |
| **`FIN`** | No more data from sender | Gracefully terminates an established connection |
| **`PSH`** | Push function | Instructs receiver to pass buffered data immediately to the application layer |
| **`URG`** | Urgent pointer field significant | Marks out-of-band urgent data |

```
CASE 1: PORT IS OPEN (Service Listening)
Auditor                             Target Host (Port 443 Open)
   | -------- TCP SYN (Seq=x) ---------> |
   | <---- TCP SYN/ACK (Seq=y, Ack=x+1)- |  ==> Port Confirmed OPEN
   | -------- TCP RST (or ACK->RST) ---> |  (Connection torn down cleanly)

CASE 2: PORT IS CLOSED (No Service Listening, No Drop Firewall)
Auditor                             Target Host (Port 8443 Closed)
   | -------- TCP SYN (Seq=x) ---------> |
   | <------ TCP RST/ACK (Ack=x+1) ----- |  ==> Port Confirmed CLOSED

CASE 3: PORT IS FILTERED (Stateful Firewall Drops Packet or Sends ICMP Prohib)
Auditor                             Firewall / Target (Port 22 Filtered)
   | -------- TCP SYN (Seq=x) ---------> |  [Packet Silently Dropped]
   | -------- (Retransmit SYN) --------> |  [No Response / ICMP Type 3 Code 13]
                                            ==> Port Classified as FILTERED
```

---

## 23.2 Comprehensive `nmap` Reference for Enterprise Network Auditors

**Nmap (Network Mapper)** is the industry-standard network discovery and security auditing utility used by systems administrators and security engineers to verify firewall rule sets, inventory running services, and validate TLS/SSL configurations.

### 23.2.1 Host Discovery & Ping Sweep Verification

Before auditing ports across a large corporate subnet (e.g., a `/16` or `/24` VPC subnet), administrators run host discovery (`-sn`) to identify live IP addresses:

| Nmap Flag | Probe Protocol & Mechanism | Network Audit Context |
| :--- | :--- | :--- |
| `-sn` | Ping Scan only (disables port scanning after host discovery) | Rapidly inventories active hosts on an internal VLAN or management subnet |
| `-PE` / `-PP` / `-PM` | ICMP Echo Request (Type 8), Timestamp Request (Type 13), Netmask Request (Type 17) | Standard ICMP reachability verification across internal routers |
| `-PS<portlist>` | TCP `SYN` Ping to specified ports (default `80`) | Discovers hosts behind firewalls that block ICMP Echo (`ping`) but permit HTTP/HTTPS |
| `-PA<portlist>` | TCP `ACK` Ping to specified ports | Tests whether stateless vs. stateful packet filters exist along the network path |
| `-PU<portlist>` | UDP Ping to high port (default `40125`) | Triggers an ICMP Port Unreachable (Type 3, Code 3) response from live hosts |
| `-PR` | ARP Ping (default on local Ethernet LAN subnets) | Most reliable discovery method on a local Layer 2 broadcast domain |
| `-Pn` | Treat all specified hosts as online (skip discovery phase) | Essential when auditing cloud workloads (AWS EC2, Azure VMs) where Security Groups drop ICMP by default |

### 23.2.2 Port Scanning Techniques & Firewall Rule Verification

| Nmap Flag | Scan Technique | Packet Exchange & Audit Purpose |
| :--- | :--- | :--- |
| `-sS` | **TCP SYN Scan** (Default privileged) | Sends raw `SYN` packet; awaits `SYN/ACK` (`open`) or `RST` (`closed`) without completing full application handshake. Fast and minimal impact. |
| `-sT` | **TCP Connect Scan** (Default unprivileged) | Uses the OS `connect()` system call to complete the full 3-way handshake (`SYN` -> `SYN/ACK` -> `ACK`). Required when running without `CAP_NET_RAW` privileges or through SOCKS proxies. |
| `-sU` | **UDP Scan** | Sends protocol-specific UDP payloads (for DNS `53`, SNMP `161`, NTP `123`) or empty UDP datagrams. An `ICMP Port Unreachable` indicates `closed`; a valid UDP response indicates `open`. |
| `-sA` | **TCP ACK Scan** | Sends `ACK` probes to map firewall stateful inspection rules. Does *not* distinguish `open` vs `closed`, but accurately determines whether ports are `unfiltered` (returns `RST`) or `filtered` (dropped by stateful firewall). |
| `-sV` | **Service & Version Detection** | Connects to open ports and sends protocol-specific probes from `nmap-service-probes` to determine exact daemon name and version (e.g., `OpenSSH 9.6p1`, `nginx 1.26.1`). |
| `-O` | **OS TCP/IP Stack Fingerprinting** | Analyzes TCP Initial Window Size, IP TTL, DF bit, and TCP Option ordering against `nmap-os-db` to identify the host operating system family. |

### 23.2.3 Timing Templates, Bandwidth Control & Production Safety

When auditing production infrastructure, network engineers must tune packet rates carefully to avoid saturating WAN links, exhausting state tables on stateful firewalls (conntrack table exhaustion), or overwhelming legacy embedded/OT devices:

| Timing Template | Name | Max RTT Timeout | Parallelism & Delay Characteristics | Recommended Operational Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **`-T0` / `-T1`** | Paranoid / Sneaky | `5m` / `15s` | Serial execution (1 probe at a time) with long inter-probe delays | Diagnostic testing of fragile legacy/ICS/SCADA controllers |
| **`-T2`** | Polite | `10s` | Serializes probes with a `400ms` delay between packets | Auditing low-bandwidth remote branch office links |
| **`-T3`** | Normal | `1000ms` | Default adaptive parallelism based on network latency and packet loss | General internal corporate LAN auditing |
| **`-T4`** | Aggressive | `1250ms` (initial), `100ms` (min) | Caps TCP scan delay at `10ms`; requires reliable, modern network links | Standard authorized EASM and data center subnet audits |
| **`-T5`** | Insane | `300ms` (max), `50ms` (min) | Caps scan delay at `5ms`; sacrifices accuracy if packet loss occurs | High-speed local loopback or isolated lab benchmark environments only |

In addition to `-T` templates, enterprise auditors use explicit rate-bounding flags:
* `--max-rate <packets_per_second>`: Enforces a strict ceiling on outbound packet transmission (e.g., `--max-rate 200`) to guarantee compliance with Statement of Work (SoW) bandwidth limits.
* `--max-retries <num>`: Reduces retransmission attempts (e.g., `--max-retries 2`) when scanning heavily firewalled subnets that silently drop packets.

### 23.2.4 Nmap Scripting Engine (NSE) for Defensive Configuration Auditing

The **Nmap Scripting Engine (NSE)** executes Lua-based diagnostic scripts categorized by operational safety (`safe`, `default`, `discovery`, `version`, `auth`, `vuln`). Security engineers use `safe` and `discovery` scripts to audit cryptographic posture and protocol hardening:

```bash
# 1. Audit TLS Cipher Suites, Protocol Versions (TLS 1.0/1.1 deprecation), and Certificate Chain
nmap -Pn -p 443,8443 --script ssl-enum-ciphers,ssl-cert -oA tls_posture_audit 198.51.100.0/24

# 2. Audit SSH Server Cryptographic Algorithms (KEX, Ciphers, MACs, HostKey types)
nmap -Pn -p 22 --script ssh2-enum-algos,ssh-hostkey -oA ssh_crypto_audit 198.51.100.10

# 3. Verify HTTP Security Headers (HSTS, CSP, X-Frame-Options) and Allowed HTTP Methods
nmap -Pn -p 80,443 --script http-security-headers,http-methods -oA web_headers_audit app.example.com

# 4. Audit DNS Server for Open Recursion and Zone Transfer Exposure
nmap -Pn -sU -sT -p 53 --script dns-recursion,dns-nsid -oA dns_server_audit ns1.example.com
```

### 23.2.5 Parsing Nmap XML Output (`-oX` / `-oA`) for Automated CMDB Drift Detection

Always save audit results using `-oA <basename>`, which simultaneously produces three formats:
1. `.nmap` (Human-readable tabular summary)
2. `.gnmap` (Grepable line-oriented summary)
3. `.xml` (Structured XML conforming to `nmap.dtd` for programmatic ingestion)

Below is a production-grade Python script that parses Nmap XML audit logs and compares discovered open ports against an organization's approved baseline policy, flagging any unauthorized port drift:

```python
#!/usr/bin/env python3
"""
nmap_baseline_auditor.py
Parses Nmap XML (-oX) output and compares discovered open ports against
an approved YAML/dict security baseline to alert on perimeter configuration drift.
"""

import sys
import xml.etree.ElementTree as ET
from typing import Dict, Set, List

# Approved Perimeter Security Policy: Host IP -> Allowed TCP Ports
APPROVED_BASELINE: Dict[str, Set[int]] = {
    "198.51.100.10": {80, 443},          # Public Web Ingress
    "198.51.100.20": {25, 465, 587},     # Corporate Mail Gateway
    "198.51.100.53": {53},               # Authoritative DNS Server
}


def audit_nmap_xml(xml_path: str) -> int:
    tree = ET.parse(xml_path)
    root = tree.getroot()
    violations: List[str] = []

    print(f"{'Host IP':<18} | {'Port/Proto':<12} | {'Service Banner':<30} | {'Policy Status'}")
    print("-" * 85)

    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue

        address_elem = host.find("address[@addrtype='ipv4']")
        if address_elem is None:
            continue
        ip_addr = address_elem.get("addr", "unknown")

        allowed_ports = APPROVED_BASELINE.get(ip_addr, set())

        ports_elem = host.find("ports")
        if ports_elem is None:
            continue

        for port in ports_elem.findall("port"):
            state_elem = port.find("state")
            if state_elem is None or state_elem.get("state") != "open":
                continue

            port_id = int(port.get("portid", "0"))
            proto = port.get("protocol", "tcp")
            service_elem = port.find("service")
            service_desc = "unknown"
            if service_elem is not None:
                svc_name = service_elem.get("name", "")
                svc_prod = service_elem.get("product", "")
                svc_ver = service_elem.get("version", "")
                service_desc = f"{svc_name} ({svc_prod} {svc_ver})".strip()

            if port_id in allowed_ports:
                policy_status = "APPROVED"
            else:
                policy_status = "VIOLATION (UNAPPROVED OPEN PORT)"
                violations.append(f"{ip_addr}:{port_id}/{proto} ({service_desc})")

            print(f"{ip_addr:<18} | {f'{port_id}/{proto}':<12} | {service_desc[:30]:<30} | {policy_status}")

    print("\n" + "=" * 85)
    if violations:
        print(f"[!] AUDIT FAILED: {len(violations)} unapproved port exposure(s) detected:")
        for v in violations:
            print(f"    - {v}")
        return 1
    else:
        print("[+] AUDIT PASSED: All discovered open ports match the approved security baseline.")
        return 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <nmap_output.xml>")
        sys.exit(1)
    sys.exit(audit_nmap_xml(sys.argv[1]))
```

---

## 23.3 Web Service Probing, TLS Fingerprinting & Visual Inventory

Once network ports are inventoried across an enterprise's subdomains and IP ranges, EASM pipelines classify HTTP/HTTPS services to build a searchable catalog of web applications, technology stacks, and TLS configurations.

### 23.3.1 HTTP Telemetry Metadata Collection

During an authorized web inventory sweep (using tools such as `httpx` or custom Python `httpx`/`aiohttp` collectors), security teams record standardized telemetry fields for each web asset:

1. **HTTP Status Code Chain:** Tracks redirect chains (e.g., `http://example.com [301] -> https://www.example.com [200]`) to verify that HTTP-to-HTTPS redirection is enforced across all hosts.
2. **Response Headers & Security Posture:** Evaluates the presence and configuration of `Strict-Transport-Security` (HSTS), `Content-Security-Policy` (CSP), `X-Content-Type-Options: nosniff`, `Referrer-Policy`, and `Permissions-Policy`.
3. **Favicon MurmurHash3 (`mmh3`) Fingerprinting:** Many enterprise appliances (such as Citrix Gateway, Fortinet SSL-VPN, Palo Alto GlobalProtect, Jenkins, or Jira) serve a static default `/favicon.ico`. Computing the 32-bit **MurmurHash3** hash of the base64-encoded favicon allows EASM platforms to accurately identify the underlying appliance software even if the HTML title or login page banner has been customized.
4. **JARM and JA4+ TLS Fingerprinting:**
   * **JARM** actively sends 10 specially crafted TLS ClientHello packets with varying TLS versions, cipher suites, and extensions, and hashes the server's deterministic TLS ServerHello responses into a 62-character fingerprint. This enables defenders to group servers sharing identical TLS stack configurations (e.g., identifying all servers running an outdated OpenSSL version or a specific load balancer profile).

---

# Chapter 24: Web Asset Cataloging, OpenAPI Auditing & Continuous Security Monitoring Pipelines

## 24.1 Web Asset Cataloging & Historical Endpoint Inventory

Modern single-page applications (SPAs) built with React, Angular, or Vue.js communicate with backend microservices through hundreds of REST and GraphQL API routes. A comprehensive Application Security (AppSec) program maintains a complete **API and Endpoint Catalog** to ensure that deprecated API versions (such as `/api/v1/` when the frontend has migrated to `/api/v3/`) are properly decommissioned rather than left exposed as **Zombie APIs**.

### 24.1.1 Identifying Zombie APIs and Deprecated Endpoints

Engineering teams frequently update frontend JavaScript clients to use newer, hardened API routes while leaving older backend controller routes active for "backward compatibility." Security auditors catalog active vs. historical routes through three defensive data sources:

1. **Source Code Route Extraction:** Parsing framework routing tables directly from source repositories (e.g., FastAPI router decorators, Express.js `app.get()`/`app.post()`, Spring Boot `@RequestMapping`, or Django `urls.py`).
2. **API Gateway & Reverse Proxy Access Logs:** Aggregating distinct request paths (`request_uri`) from Nginx, Envoy, Kong, or AWS API Gateway logs in the SIEM to identify which API versions are still receiving production traffic.
3. **Public Web Archive Audits:** Checking the Internet Archive (`web.archive.org` CDX API) for historical URLs indexed under the corporate domain to confirm that retired promotional campaigns, legacy PHP endpoints, or old staging paths return `404 Not Found` or `410 Gone` and no longer expose legacy functionality.

---

## 24.2 Client-Side JavaScript Bundle Hygiene & Source Map Security

### 24.2.1 Why Source Maps (`.js.map`) Should Never Be Deployed to Public Production

When frontend build tools (Webpack, Vite, Rollup, Parcel, TypeScript `tsc`) minify and bundle application code for production, they can optionally generate **Source Map files** (`app.bundle.js.map`) referenced at the bottom of the minified JavaScript bundle via:

```javascript
//# sourceMappingURL=app.bundle.js.map
```

A `.js.map` JSON file contains a `sourcesContent` array holding the **entire original, unminified TypeScript/JSX source code**, developer comments, internal API route definitions, GraphQL schemas, and administrative UI components.

#### Remediation: Securing Frontend Build Pipelines

1. **Disable Public Source Maps in Production Builds:**
   In Webpack (`webpack.config.js`), set `devtool: false` or `devtool: 'hidden-source-map'`. In Next.js (`next.config.js`), ensure `productionBrowserSourceMaps: false` (the default). In Vite (`vite.config.ts`), set `build.sourcemap: false`.
2. **Upload Private Source Maps Directly to Error-Tracking Systems:**
   If engineering teams need stack-trace de-obfuscation in production observability platforms (such as Sentry, Datadog, or Rollbar), configure the CI/CD pipeline to upload `.js.map` files directly to the private observability API during the build step and **delete all `*.map` files** before uploading static assets to the public CDN or S3 bucket.
3. **Never Store Secrets in Frontend Environment Variables:**
   Frontend build frameworks automatically inline environment variables prefixed with `REACT_APP_`, `NEXT_PUBLIC_`, or `VITE_` directly into the public JavaScript bundle sent to every user's browser. Any variable embedded in client-side JavaScript is public by definition; sensitive API keys must remain strictly on backend servers.

---

## 24.3 OpenAPI / Swagger Documentation Auditing & Schema Governance

### 24.3.1 Controlling Exposure of Interactive API Documentation

Frameworks such as FastAPI, NestJS, Springdoc-OpenAPI (`swagger-ui`), and ASP.NET Core Swashbuckle automatically generate OpenAPI v3 specifications (`/openapi.json`, `/v3/api-docs`) and interactive Swagger UI consoles (`/swagger-ui/index.html`, `/docs`, `/redoc`).

While public developer APIs intentionally publish documentation, internal microservices and administrative backends frequently leave Swagger UI enabled in production by default because the environment flag was not toggled between `development` and `production`.

#### Side-by-Side Code Comparison: Securing OpenAPI Documentation in Production

**Vulnerable Configuration (FastAPI Leaving `/docs` and `/openapi.json` Public in Production):**
```python
# VULNERABLE: Exposes interactive Swagger UI (/docs), ReDoc (/redoc),
# and full OpenAPI schema (/openapi.json) unconditionally in production
from fastapi import FastAPI

app = FastAPI(
    title="Internal Financial Settlement Service",
    version="2.4.0"
)
```

**Remediated Configuration (Environment-Gated OpenAPI Schema in FastAPI):**
```python
# SECURE: Disables /docs, /redoc, and /openapi.json in production environments
import os
from fastapi import FastAPI

ENVIRONMENT = os.getenv("APP_ENV", "production").lower()
ENABLE_DOCS = ENVIRONMENT in ("development", "local")

app = FastAPI(
    title="Internal Financial Settlement Service",
    version="2.4.0",
    docs_url="/docs" if ENABLE_DOCS else None,
    redoc_url="/redoc" if ENABLE_DOCS else None,
    openapi_url="/openapi.json" if ENABLE_DOCS else None,
)
```

**Remediated Configuration (Spring Boot `application-prod.yml`):**
```yaml
# application-prod.yml - Explicitly disable Springdoc OpenAPI & Swagger UI in production
springdoc:
  api-docs:
    enabled: false
  swagger-ui:
    enabled: false

# Restrict Spring Boot Actuator strictly to internal loopback health checks
management:
  server:
    address: 127.0.0.1
    port: 9001
  endpoints:
    web:
      exposure:
        include: health,info
  endpoint:
    health:
      show-details: never
```

---

## 24.4 Continuous EASM & Security Monitoring Pipeline Architecture

Rather than treating asset discovery and configuration auditing as an annual point-in-time exercise, modern security engineering teams operate **Continuous EASM Pipelines** that run on a scheduled basis, compare current perimeter state against a version-controlled baseline, and alert the Security Operations Center (SOC) only when **drift** (new subdomains, new open ports, expiring TLS certificates, or missing security headers) occurs.

### 24.4.1 Architecture of an Event-Driven EASM Differential Pipeline

```
+-----------------------------------------------------------------------------------+
|               AUTOMATED DEFENSIVE EASM DIFFERENTIAL PIPELINE                      |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|  +-----------------------+     +-----------------------+     +-----------------+  |
|  | Scheduled Orchestrator| --> | 1. Inventory Sync     | --> | 2. Differential |  |
|  | (Cron / GitHub Actions|     |  - Route53 / Cloud DNS|     |    State Engine |  |
|  |  / Kubernetes CronJob)|     |  - CT Log Monitor     |     |  - Compare vs.  |  |
|  +-----------------------+     |  - Approved CIDRs     |     |    SQLite/Git   |  |
|                                +-----------------------+     |    Baseline DB  |  |
|                                                              +-----------------+  |
|                                                                       |           |
|                                        +------------------------------+           |
|                                        v                                          |
|  +-----------------------+     +-----------------------+                          |
|  | 4. SOC Alerting &     | <-- | 3. Posture Validation |                          |
|  |    Ticket Creation    |     |  - TLS Expiry Check   |                          |
|  |  - Webhook / SIEM     |     |  - Dangling DNS Check |                          |
|  |  - Jira / PagerDuty   |     |  - Security Headers   |                          |
|  +-----------------------+     +-----------------------+                          |
|                                                                                   |
+-----------------------------------------------------------------------------------+
```

### 24.4.2 Complete Defensive Continuous EASM & TLS/Header Posture Auditor (Python)

Below is a complete, self-contained Python continuous monitoring script designed to run as a scheduled job. It maintains a local SQLite state database of authorized corporate domains, verifies DNS resolution, checks TLS certificate expiration windows, audits mandatory HTTP security headers, detects perimeter state drift, and emits structured JSON alerts for SIEM/Webhook ingestion:

```python
#!/usr/bin/env python3
"""
continuous_easm_monitor.py
Enterprise External Attack Surface Management (EASM) Continuous Posture Monitor.
Tracks DNS resolution changes, TLS certificate expiration windows, and HTTP security
header compliance across an organization's domain inventory, storing state in SQLite
and alerting on configuration drift.
"""

import datetime
import json
import socket
import sqlite3
import ssl
import sys
import urllib.request
import urllib.error
from typing import Dict, Any, List, Optional

DB_PATH = "easm_inventory_state.db"
TLS_EXPIRY_WARNING_DAYS = 14

REQUIRED_SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
]


def init_db(conn: sqlite3.Connection) -> None:
    with conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS asset_state (
                hostname TEXT PRIMARY KEY,
                resolved_ips TEXT,
                tls_issuer TEXT,
                tls_expires_at TEXT,
                missing_headers TEXT,
                last_checked TEXT
            )
            """
        )


def resolve_host_ips(hostname: str) -> List[str]:
    try:
        infos = socket.getaddrinfo(hostname, 443, proto=socket.IPPROTO_TCP)
        ips = sorted({info[4][0] for info in infos})
        return ips
    except socket.gaierror:
        return []


def inspect_tls_certificate(hostname: str, timeout: int = 5) -> Dict[str, Optional[str]]:
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    return {"issuer": None, "notAfter": None}
                issuer_tuples = cert.get("issuer", ())
                issuer_cn = "Unknown"
                for rdn in issuer_tuples:
                    for key, val in rdn:
                        if key == "organizationName":
                            issuer_cn = val
                not_after_str = cert.get("notAfter")
                if not_after_str:
                    dt = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                    iso_expiry = dt.replace(tzinfo=datetime.timezone.utc).isoformat()
                else:
                    iso_expiry = None
                return {"issuer": issuer_cn, "notAfter": iso_expiry}
    except Exception as exc:
        return {"issuer": f"TLS_ERROR: {type(exc).__name__}", "notAfter": None}


def audit_http_headers(hostname: str, timeout: int = 5) -> List[str]:
    url = f"https://{hostname}/"
    req = urllib.request.Request(
        url,
        method="HEAD",
        headers={"User-Agent": "Enterprise-EASM-Posture-Monitor/2.0"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            present_headers = {k.lower() for k in resp.headers.keys()}
            missing = [
                h for h in REQUIRED_SECURITY_HEADERS
                if h.lower() not in present_headers
            ]
            return missing
    except urllib.error.HTTPError as e:
        present_headers = {k.lower() for k in e.headers.keys()}
        return [
            h for h in REQUIRED_SECURITY_HEADERS
            if h.lower() not in present_headers
        ]
    except Exception:
        return REQUIRED_SECURITY_HEADERS


def evaluate_host(conn: sqlite3.Connection, hostname: str) -> List[Dict[str, Any]]:
    alerts: List[Dict[str, Any]] = []
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

    ips = resolve_host_ips(hostname)
    ips_json = json.dumps(ips)

    if not ips:
        alerts.append({
            "severity": "HIGH",
            "hostname": hostname,
            "event": "DNS_RESOLUTION_FAILURE",
            "detail": "Hostname failed to resolve to any A/AAAA record (check for dangling DNS)."
        })
        return alerts

    tls_info = inspect_tls_certificate(hostname)
    missing_headers = audit_http_headers(hostname)
    missing_json = json.dumps(missing_headers)

    # Check TLS Expiration Window
    if tls_info["notAfter"]:
        expiry_dt = datetime.datetime.fromisoformat(tls_info["notAfter"])
        days_left = (expiry_dt - datetime.datetime.now(datetime.timezone.utc)).days
        if days_left <= TLS_EXPIRY_WARNING_DAYS:
            alerts.append({
                "severity": "HIGH" if days_left <= 3 else "MEDIUM",
                "hostname": hostname,
                "event": "TLS_CERTIFICATE_EXPIRING_SOON",
                "detail": f"Certificate expires in {days_left} days ({tls_info['notAfter']})."
            })
    else:
        alerts.append({
            "severity": "HIGH",
            "hostname": hostname,
            "event": "TLS_HANDSHAKE_ERROR",
            "detail": f"Could not validate TLS certificate: {tls_info['issuer']}"
        })

    # Compare against historical state in SQLite for Drift Detection
    cur = conn.cursor()
    cur.execute(
        "SELECT resolved_ips, missing_headers FROM asset_state WHERE hostname = ?",
        (hostname,)
    )
    row = cur.fetchone()

    if row is None:
        alerts.append({
            "severity": "INFO",
            "hostname": hostname,
            "event": "NEW_ASSET_BASELINED",
            "detail": f"Initial baseline recorded: IPs={ips}, MissingHeaders={missing_headers}"
        })
    else:
        prev_ips = json.loads(row[0])
        prev_missing = json.loads(row[1])

        if prev_ips != ips:
            alerts.append({
                "severity": "MEDIUM",
                "hostname": hostname,
                "event": "DNS_IP_DRIFT_DETECTED",
                "detail": f"Resolved IPs changed from {prev_ips} to {ips}."
            })

        newly_missing = sorted(set(missing_headers) - set(prev_missing))
        if newly_missing:
            alerts.append({
                "severity": "MEDIUM",
                "hostname": hostname,
                "event": "SECURITY_HEADER_REGRESSION",
                "detail": f"Security headers removed since last audit: {newly_missing}"
            })

    with conn:
        conn.execute(
            """
            INSERT INTO asset_state (
                hostname, resolved_ips, tls_issuer, tls_expires_at, missing_headers, last_checked
            ) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(hostname) DO UPDATE SET
                resolved_ips = excluded.resolved_ips,
                tls_issuer = excluded.tls_issuer,
                tls_expires_at = excluded.tls_expires_at,
                missing_headers = excluded.missing_headers,
                last_checked = excluded.last_checked
            """,
            (
                hostname,
                ips_json,
                tls_info["issuer"],
                tls_info["notAfter"],
                missing_json,
                now_iso,
            ),
        )

    return alerts


def main() -> None:
    monitored_domains = [
        "example.com",
        "www.example.com",
    ]
    if len(sys.argv) > 1:
        with open(sys.argv[1], "r", encoding="utf-8") as f:
            monitored_domains = [line.strip() for line in f if line.strip()]

    conn = sqlite3.connect(DB_PATH)
    init_db(conn)

    all_alerts: List[Dict[str, Any]] = []
    for domain in monitored_domains:
        host_alerts = evaluate_host(conn, domain)
        all_alerts.extend(host_alerts)

    print(json.dumps({"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(), "alerts": all_alerts}, indent=2))
    conn.close()


if __name__ == "__main__":
    main()
```

---

## Part V: Academic Review Exercises & Architecture Case Studies

### Exercise 20.1: Origin Server Hardening Architecture
An enterprise deploys a web application at `portal.corp-example.lk` behind a global CDN and Web Application Firewall. However, during an internal EASM audit using Censys, the security team discovers that the underlying AWS EC2 Elastic IP (`203.0.113.85`) responds directly to HTTPS requests on port `443/tcp` using the production `portal.corp-example.lk` TLS certificate.
1. Explain how internet-wide scanners correlated the raw IP address `203.0.113.85` with `portal.corp-example.lk`.
2. Design a three-layer remediation architecture covering (a) AWS Security Group rules, (b) Mutual TLS (Authenticated Origin Pulls), and (c) Nginx `default_server` configuration (`ssl_reject_handshake on`) to prevent direct-to-origin access.

### Exercise 21.1: Git Object Graph Remediation & Pre-Commit Enforcement
A junior developer accidentally commits an AWS IAM Access Key (`AKIA...`) inside `scripts/deploy.py` and pushes it to the shared corporate Git repository. Realizing the mistake five minutes later, the developer deletes the key, commits `"Remove key"`, and pushes again.
1. Explain using Git's internal Blob/Tree/Commit Directed Acyclic Graph (DAG) why the second commit does not remove the secret from the repository.
2. Outline the exact incident response and remediation procedure required, and write a `.gitleaks.toml` and `.pre-commit-config.yaml` policy to block future credential commits locally before they occur.

### Exercise 22.1: Eliminating Dangling DNS in Cloud Decommissioning Workflows
During a quarterly DNS hygiene review, you discover `events-2024.corp-example.lk IN CNAME corp-events-2024.azurewebsites.net`, and resolving `corp-events-2024.azurewebsites.net` returns `NXDOMAIN`.
1. Explain the security impact of leaving this `CNAME` record active in the authoritative zone, specifically addressing TLS certificate issuance (`HTTP-01` ACME validation), parent-scoped cookies (`Domain=.corp-example.lk`), and Cross-Origin Resource Sharing (CORS) trust.
2. Specify the mandatory order of operations when decommissioning cloud resources and how Infrastructure-as-Code (Terraform) prevents this class of misconfiguration.

### Exercise 23.1: Stateful Firewall Verification with Nmap
You are tasked with verifying a newly deployed perimeter firewall protecting an internal database subnet (`10.50.0.0/24`).
1. Explain the TCP packet exchange differences between running `nmap -sS`, `nmap -sT`, and `nmap -sA` against port `5432/tcp`.
2. How does Nmap differentiate between a port that is `closed` (host reachable, no daemon listening) versus a port that is `filtered` (dropped by a stateful firewall)?

### Exercise 24.1: Securing Production Frontend Builds and OpenAPI Schemas
An Application Security review of a React + FastAPI production application reveals that `https://app.corp-example.lk/static/js/main.chunk.js.map` and `https://api.corp-example.lk/openapi.json` are both publicly accessible without authentication.
1. What sensitive metadata is contained inside the `sourcesContent` field of a `.js.map` file?
2. Show the configuration changes required in both the frontend bundler and the FastAPI application initialization to disable public source maps and interactive OpenAPI schemas in production while preserving observability in development environments.


---

# Appendix V-A: Deep-Dive DNSSEC, Email Authentication & Multi-Cloud Storage Hardening

## A.1 Domain Name System Security Extensions (DNSSEC - RFC 4033–4035)

Standard UDP/TCP DNS (RFC 1035) includes no cryptographic integrity verification; if an on-path adversary or compromised recursive resolver spoofs a DNS response (DNS Cache Poisoning), clients unknowingly connect to an unauthorized IP address. **DNSSEC** remedies this by adding digital signatures to DNS resource record sets (**RRsets**) using public-key cryptography.

### A.1.1 DNSSEC Resource Records & Chain of Trust

| DNSSEC Record | Full Name | Cryptographic Function |
| :--- | :--- | :--- |
| **`DNSKEY`** | DNS Public Key Record | Holds the public keys used by the zone to verify signatures: the **Zone Signing Key (ZSK)** (signs individual RRsets in the zone) and the **Key Signing Key (KSK)** (signs the `DNSKEY` RRset itself). |
| **`RRSIG`** | Resource Record Digital Signature | Contains the cryptographic signature over a specific RRset (e.g., the `A` records for `www.example.com`), along with signature inception and expiration timestamps. |
| **`DS`** | Delegation Signer | Published in the **parent zone** (e.g., `.com` TLD zone); contains a cryptographic hash (SHA-256 or SHA-384) of the child zone's (`example.com`) public **KSK**, establishing the hierarchical chain of trust from the Root (`.`) down to the leaf domain. |
| **`NSEC` / `NSEC3`** | Next Secure Record (v1 / v3) | Provides **Authenticated Denial of Existence** (proving cryptographically that a requested subdomain does *not* exist without allowing an attacker to replay forged `NXDOMAIN` responses). |

```
+-----------------------------------------------------------------------------------+
|                     DNSSEC CRYPTOGRAPHIC CHAIN OF TRUST                           |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|  [Root Zone (.)]                                                                  |
|   - Root KSK (Anchored in Resolver Trust Store)                                   |
|   - Root ZSK signs DS Record for ".com"  ----------------------------------+      |
|                                                                            |      |
|  [TLD Zone (.com)] <-------------------------------------------------------+      |
|   - .com KSK (Matches Hash in Root DS Record)                                     |
|   - .com ZSK signs DS Record for "example.com"  ---------------------------+      |
|                                                                            |      |
|  [Authoritative Zone (example.com)] <--------------------------------------+      |
|   - example.com KSK (Matches Hash in .com DS Record; signs DNSKEY RRset)          |
|   - example.com ZSK (Signs A, AAAA, MX, TXT RRsets -> generates RRSIG records)    |
|                                                                                   |
+-----------------------------------------------------------------------------------+
```

### A.1.2 Architectural Considerations: `NSEC` vs. `NSEC3` (RFC 5155) and Zone Walking

In original DNSSEC (`NSEC`, RFC 4034), authenticated denial of existence worked by linking every existing hostname in canonical alphabetical order (`alpha.example.com -> beta.example.com -> prod.example.com`). While this proved that `gamma.example.com` did not exist between `beta` and `prod`, it inadvertently allowed anyone to enumerate the entire zone file record-by-record (known as **NSEC Zone Walking**).

**`NSEC3` (RFC 5155)** and **NSEC3 Opt-Out / White Lies (RFC 7129 / Cloudflare Black Lies)** mitigate zone walking:
- **`NSEC3`** replaces plaintext next-hostname links with iterated SHA-1 hashes of the hostnames.
- **RFC 4470 / White Lies (Compact Denial of Existence):** Dynamically synthesizes an `NSEC` record on the fly at the edge (e.g., claiming the next record after `query.example.com` is `\000.query.example.com`), providing full DNSSEC cryptographic validity without exposing any sibling subdomain names or hashes.

---

## A.2 Domain Email Security Architecture: SPF, DKIM, DMARC, MTA-STS & BIMI

Every domain inventoried during an EASM audit—including parked domains and non-mail-sending microservice domains—must enforce strict email authentication records in DNS to prevent unauthorized actors from spoofing emails appearing to originate from `@example.com`.

### A.2.1 The Three Pillars of Email Authentication

1. **Sender Policy Framework (SPF - RFC 7208):**
   * Published as a `TXT` record on the domain root (and any subdomain) specifying which IP addresses or CIDR ranges are authorized to transmit SMTP messages on behalf of the domain (`RFC5321.MailFrom` / Return-Path).
   * **Hardening Rule:** Always terminate SPF records with `-all` (Hard Fail) rather than `~all` (Soft Fail) or `?all` (Neutral), and keep total DNS-querying mechanisms (`include:`, `a`, `mx`, `ptr`, `exists`, `redirect`) at or below the strict **RFC 7208 limit of 10 DNS lookups** to prevent `PermError` validation failures.

2. **DomainKeys Identified Mail (DKIM - RFC 6376):**
   * Attaches a cryptographic digital signature (`DKIM-Signature` header) to outbound emails over selected headers (`From`, `To`, `Subject`, `Date`, `Message-ID`) and the body hash. Receiving mail servers verify the signature by querying the public RSA (2048-bit minimum) or Ed25519 key published at `<selector>._domainkey.example.com IN TXT`.

3. **Domain-based Message Authentication, Reporting, and Conformance (DMARC - RFC 7489):**
   * Published at `_dmarc.example.com IN TXT`. DMARC binds SPF and DKIM together by requiring **Identifier Alignment**: the domain in the user-visible `RFC5322.From` header must match the validated SPF domain and/or the validated DKIM `d=` domain.
   * Specifies the enforcement policy (`p=none` for monitoring only, `p=quarantine` to send failing messages to spam, or `p=reject` to block unauthorized messages outright) and where receivers should send aggregate XML (`rua=`) and forensic (`ruf=`) telemetry reports.

### A.2.2 Hardened DNS Email Configuration Templates

#### Template 1: Active Enterprise Mail-Sending Domain (`example.com`)
```dns
; 1. SPF Record (Strict -all enforcement, under 10 DNS lookups)
example.com.                    3600 IN TXT "v=spf1 ip4:198.51.100.20/32 include:_spf.google.com -all"

; 2. DKIM 2048-bit RSA Public Key Record
selector2026._domainkey.example.com. 3600 IN TXT (
    "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1b2c3d..."
)

; 3. DMARC Enforcement Policy (Strict alignment adkim=s, aspf=s, and p=reject on domain & subdomains)
_dmarc.example.com.             3600 IN TXT (
    "v=DMARC1; p=reject; sp=reject; pct=100; adkim=s; aspf=s; "
    "rua=mailto:dmarc-aggregate@example.com; ruf=mailto:dmarc-forensic@example.com; fo=1"
)

; 4. SMTP MTA Strict Transport Security (MTA-STS - RFC 8461) & TLS Reporting (RFC 8460)
_mta-sts.example.com.           3600 IN TXT "v=STSv1; id=2026110201;"
_smtp._tls.example.com.         3600 IN TXT "v=TLSRPTv1; rua=mailto:tls-reports@example.com"
```

#### Template 2: Non-Mail-Sending / Parked Corporate Domain (`example-cdn.net`)
Even if a domain never sends email, explicitly publish null SPF, null MX (RFC 7505), and `p=reject` DMARC records so the domain can never be spoofed in phishing campaigns:

```dns
; RFC 7505 Null MX Record (Explicitly declares domain accepts no mail)
example-cdn.net.                3600 IN MX  0 .

; Null SPF Record (Explicitly forbids all IP addresses from sending mail)
example-cdn.net.                3600 IN TXT "v=spf1 -all"

; Strict DMARC Reject Policy for Root and All Subdomains
_dmarc.example-cdn.net.         3600 IN TXT "v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s; rua=mailto:dmarc-aggregate@example.com"
```

### A.2.3 Automated Domain Email Posture Auditor (Python)

Below is a defensive Python auditing script that inspects any list of corporate domains for SPF (`-all` vs `~all`, lookup count check), Null MX, and DMARC (`p=reject` vs `p=none`) compliance:

```python
#!/usr/bin/env python3
"""
email_dns_posture_auditor.py
Audits corporate domains for SPF (-all enforcement & RFC 7208 10-lookup limit)
and DMARC (p=reject / sp=reject enforcement) compliance.
Requires: pip install dnspython
"""

import sys
from typing import List, Dict, Optional
import dns.resolver


def get_txt_records(fqdn: str) -> List[str]:
    resolver = dns.resolver.Resolver()
    resolver.timeout = 4.0
    resolver.lifetime = 4.0
    records: List[str] = []
    try:
        answers = resolver.resolve(fqdn, "TXT")
        for rdata in answers:
            txt_value = "".join(s.decode("utf-8", errors="ignore") for s in rdata.strings)
            records.append(txt_value)
    except Exception:
        pass
    return records


def audit_spf(domain: str) -> Dict[str, str]:
    txt_records = get_txt_records(domain)
    spf_records = [r for r in txt_records if r.lower().startswith("v=spf1")]

    if not spf_records:
        return {"status": "FAIL", "detail": "Missing SPF TXT record"}
    if len(spf_records) > 1:
        return {"status": "FAIL", "detail": "Multiple SPF records found (RFC 7208 violation)"}

    spf = spf_records[0]
    tokens = spf.split()

    # Count DNS-querying mechanisms (include, a, mx, ptr, exists, redirect)
    lookup_mechanisms = [
        t for t in tokens
        if any(t.lower().startswith(m) for m in ("include:", "a", "mx", "ptr", "exists:", "redirect="))
    ]
    lookup_count = len(lookup_mechanisms)

    if spf.endswith("-all"):
        policy = "PASS (-all HardFail)"
    elif spf.endswith("~all"):
        policy = "WARN (~all SoftFail)"
    elif spf.endswith("+all") or spf.endswith("?all"):
        policy = "CRITICAL (+all/?all Permits Spoofing)"
    else:
        policy = "WARN (No terminal all mechanism)"

    return {
        "status": policy,
        "detail": f"Direct lookup mechanisms={lookup_count} | Record='{spf}'"
    }


def audit_dmarc(domain: str) -> Dict[str, str]:
    dmarc_fqdn = f"_dmarc.{domain}"
    txt_records = get_txt_records(dmarc_fqdn)
    dmarc_records = [r for r in txt_records if r.upper().startswith("V=DMARC1")]

    if not dmarc_records:
        return {"status": "FAIL", "detail": "Missing _dmarc TXT record"}

    dmarc = dmarc_records[0]
    tags: Dict[str, str] = {}
    for part in dmarc.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip().lower()

    p_val = tags.get("p", "missing")
    sp_val = tags.get("sp", p_val)

    if p_val == "reject" and sp_val == "reject":
        status = "PASS (p=reject, sp=reject)"
    elif p_val == "quarantine":
        status = "WARN (p=quarantine)"
    elif p_val == "none":
        status = "FAIL (p=none Monitoring Only - No Enforcement)"
    else:
        status = f"FAIL (Invalid policy p={p_val})"

    return {"status": status, "detail": f"Record='{dmarc}'"}


def main() -> None:
    domains = ["example.com"]
    if len(sys.argv) > 1:
        with open(sys.argv[1], "r", encoding="utf-8") as f:
            domains = [line.strip() for line in f if line.strip()]

    print(f"{'Domain':<28} | {'SPF Posture':<28} | {'DMARC Posture'}")
    print("-" * 95)
    for d in domains:
        spf_res = audit_spf(d)
        dmarc_res = audit_dmarc(d)
        print(f"{d:<28} | {spf_res['status']:<28} | {dmarc_res['status']}")
        print(f"   -> SPF   : {spf_res['detail']}")
        print(f"   -> DMARC : {dmarc_res['detail']}\n")


if __name__ == "__main__":
    main()
```

---

## A.3 Multi-Cloud Object Storage Hardening: Azure Blob Storage & Google Cloud Storage

In Chapter 21, we examined AWS S3 posture auditing. Enterprise EASM and Cloud Security Posture Management (CSPM) programs must enforce equivalent zero-public-access controls across **Microsoft Azure Storage Accounts** and **Google Cloud Storage (GCS)**.

### A.3.1 Hardening Microsoft Azure Storage Accounts via Terraform

In Azure, anonymous public access to Blob containers is controlled at two levels:
1. **Storage Account Level (`allow_nested_items_to_be_public` / `allowBlobPublicAccess`):** When set to `false`, no container inside the storage account can ever be made public, overriding individual container ACLs.
2. **Container Access Type (`container_access_type`):** Must be set to `"private"` (never `"blob"` or `"container"`).

```hcl
# Hardened Microsoft Azure Storage Account Configuration (Terraform azurerm)
resource "azurerm_storage_account" "enterprise_secure_storage" {
  name                     = "corpprodsecurestore2026"
  resource_group_name      = azurerm_resource_group.core.name
  location                 = azurerm_resource_group.core.location
  account_tier             = "Standard"
  account_replication_type = "GRS"

  # 1. Strictly disable anonymous public access across the entire Storage Account
  allow_nested_items_to_be_public = false

  # 2. Disable legacy Shared Key authorization; enforce Azure Entra ID (RBAC) only
  shared_access_key_enabled = false

  # 3. Enforce HTTPS-only and minimum TLS 1.2
  https_traffic_only_enabled = true
  min_tls_version            = "TLS1_2"

  # 4. Restrict network access to private VNet subnets only
  public_network_access_enabled = false

  network_rules {
    default_action             = "Deny"
    bypass                     = ["AzureServices"]
    virtual_network_subnet_ids = [azurerm_subnet.private_app_subnet.id]
  }

  blob_properties {
    versioning_enabled = true
    delete_retention_policy {
      days = 30
    }
  }
}

resource "azurerm_storage_container" "sensitive_documents" {
  name                  = "customer-records"
  storage_account_name  = azurerm_storage_account.enterprise_secure_storage.name
  container_access_type = "private"
}
```

### A.3.2 Hardening Google Cloud Storage (GCS) via Terraform

In Google Cloud Platform, public access is prevented by enforcing:
1. **Public Access Prevention (`public_access_prevention = "enforced"`):** Blocks `allUsers` and `allAuthenticatedUsers` IAM bindings at the bucket or organization policy level (`constraints/storage.publicAccessPrevention`).
2. **Uniform Bucket-Level Access (`uniform_bucket_level_access = true`):** Disables legacy per-object Access Control Lists (ACLs) so access is governed exclusively by auditable Cloud IAM policies.

```hcl
# Hardened Google Cloud Storage (GCS) Bucket Configuration (Terraform google)
resource "google_storage_bucket" "enterprise_gcs_vault" {
  name          = "corp-prod-confidential-vault-2026"
  location      = "ASIA-SOUTH1"
  storage_class = "STANDARD"

  # 1. Strictly enforce Public Access Prevention (blocks allUsers / allAuthenticatedUsers)
  public_access_prevention = "enforced"

  # 2. Enforce Uniform Bucket-Level Access (disables legacy per-object ACLs)
  uniform_bucket_level_access = true

  # 3. Enable Object Versioning for ransomware/deletion recovery
  versioning {
    enabled = true
  }

  # 4. Customer-Managed Encryption Key (Cloud KMS)
  encryption {
    default_kms_key_name = google_kms_crypto_key.gcs_cmek.id
  }
}
```

---

## A.4 Mapping EASM & Reconnaissance Controls to OWASP WSTG v4.2

The **OWASP Web Security Testing Guide (WSTG v4.2)** Category `WSTG-INFO` defines the standardized methodology for Information Gathering during authorized security assessments. The table below maps each `WSTG-INFO` test ID to the architectural defenses covered in Part V:

| OWASP WSTG ID | Assessment Objective | Root Cause of Exposure | Architectural Defense & Remediation |
| :--- | :--- | :--- | :--- |
| **`WSTG-INFO-01`** | Conduct Search Engine Discovery Reconnaissance | Unauthenticated pages, directory listings (`autoindex on`), or backup files placed in public web root | Disable `autoindex`; enforce authentication; return `X-Robots-Tag: noindex, nofollow` on non-public routes |
| **`WSTG-INFO-02`** | Fingerprint Web Server | Verbose `Server:` and `X-Powered-By:` HTTP headers revealing exact software patch versions | Set `server_tokens off;` in Nginx; `ServerTokens Prod` and `ServerSignature Off` in Apache; remove `X-Powered-By` |
| **`WSTG-INFO-03`** | Review Webserver Metafiles for Information Leakage | Sensitive URL paths listed under `Disallow:` in `/robots.txt` or exposed in `sitemap.xml` | Never list unauthenticated sensitive paths in `/robots.txt`; protect internal endpoints with zero-trust authentication |
| **`WSTG-INFO-04`** | Enumerate Applications on Webserver | Forgotten virtual hosts, dangling DNS records, or origin servers exposed outside CDN proxy ranges | Enforce Authenticated Origin Pulls (mTLS), `ssl_reject_handshake on` on default vhost, and automated dangling DNS checks |
| **`WSTG-INFO-05`** | Review Webpage Content for Information Leakage | Production `.js.map` source maps, HTML developer comments, or `REACT_APP_*` secrets bundled into client code | Disable production source maps (`devtool: false`), strip comments in build pipelines, keep secrets strictly server-side |
| **`WSTG-INFO-06`** | Identify Application Entry Points | Undocumented or deprecated legacy API versions (`/api/v1/`) left active alongside current endpoints | Maintain an API Gateway catalog; disable public `/openapi.json` and `/swagger-ui` in production; retire zombie routes |
| **`WSTG-INFO-07`** | Map Execution Paths Through Application | Exposed `.git/` directories or backup source files (`.php.bak`, `.swp`) permitting source code reconstruction | Deploy immutable build artifacts (excluding `.git`); configure web server `location ~ /\.(?!well-known).* { deny all; }` |
| **`WSTG-INFO-08`** | Fingerprint Web Application Framework | Default framework error pages (Django `DEBUG=True`, Laravel Whoops, Spring Whitelabel Error Page) | Enforce `DEBUG=False` in production; return generic, structured RFC 9457 Problem Details JSON responses without stack traces |
| **`WSTG-INFO-09`** | Fingerprint Web Application | Default favicons, admin login portals, and uncustomized management consoles exposed on public interfaces | Place administrative consoles and observability dashboards (Grafana, Jenkins, K8s) behind internal VPN or ZTNA/IAP |
| **`WSTG-INFO-10`** | Map Application Architecture | Public DNS leaking RFC 1918 private IPs, unrestricted DNS `AXFR` zone transfers, or open actuator ports | Implement Split-Horizon DNS; restrict `AXFR` with HMAC-SHA256 TSIG keys; bind management actuators to `127.0.0.1` |

---

## A.5 Server Banner & Error Page Hardening Reference Configurations

To satisfy `WSTG-INFO-02` and `WSTG-INFO-08`, production web servers and application frameworks must suppress internal version strings and stack traces while logging detailed diagnostics internally to the SIEM.

### A.5.1 Nginx Production Hardening Snippet (`/etc/nginx/conf.d/security.conf`)

```nginx
# Suppress Nginx version number in HTTP Server header and default error pages
server_tokens off;

# Standard Enterprise HTTP Security Headers
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

# Strip upstream application framework version headers
proxy_hide_header X-Powered-By;
proxy_hide_header X-AspNet-Version;
proxy_hide_header X-AspNetMvc-Version;
proxy_hide_header X-Runtime;
```

### A.5.2 Apache HTTP Server Production Hardening Snippet (`/etc/apache2/conf-available/security.conf`)

```apache
# Emit only "Server: Apache" without OS type or module versions
ServerTokens Prod

# Disable server version footer on Apache-generated error documents
ServerSignature Off

# Disable directory auto-indexing and ETag inode disclosures
<Directory /var/www/html>
    Options -Indexes -Includes
    AllowOverride None
    Require all granted
</Directory>
FileETag MTime Size
```

### A.5.3 RFC 9457 Problem Details Standardized Error Handler (Python / FastAPI)

Instead of returning raw Python tracebacks or database driver exceptions to clients when an unhandled exception occurs, applications should log the full traceback internally with a correlation ID (`trace_id`) and return a sanitized **RFC 9457 (`application/problem+json`)** response to the client:

```python
import logging
import uuid
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

logger = logging.getLogger("enterprise.appsec")
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


@app.exception_handler(Exception)
async def global_rfc9457_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    trace_id = str(uuid.uuid4())

    # Log full exception and stack trace securely to internal SIEM/structured logs only
    logger.error(
        "Unhandled server exception [trace_id=%s path=%s]: %s",
        trace_id,
        request.url.path,
        exc,
        exc_info=True,
    )

    # Return sanitized RFC 9457 Problem Details response to external client
    return JSONResponse(
        status_code=500,
        media_type="application/problem+json",
        content={
            "type": "https://errors.example.com/internal-server-error",
            "title": "Internal Server Error",
            "status": 500,
            "detail": "An unexpected error occurred. Please provide the trace_id to support.",
            "instance": request.url.path,
            "trace_id": trace_id,
        },
    )
```
