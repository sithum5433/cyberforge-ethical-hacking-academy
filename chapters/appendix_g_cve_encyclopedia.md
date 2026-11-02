# APPENDIX G: LANDMARK CVE & VULNERABILITY ARCHITECTURE ENCYCLOPEDIA

## Architectural Post-Mortems, Root-Cause Code Analysis, Detection & Remediation

> [!IMPORTANT]
> **Why Elite Security Engineers Study Historical & Modern CVEs:** Every major vulnerability class in modern software is a recurring architectural anti-pattern. By studying the exact root-cause code, memory/protocol state transitions, and remediation patches of landmark CVEs, you develop the pattern-recognition instinct required for elite source-code auditing, bug bounty hunting, and secure systems design.

| CVE Identifier | Vulnerability Name | CVSS Score | CWE Classification | Primary Affected Subsystem |
|---|---|---|---|---|
| **CVE-2021-44228** | Log4Shell (Apache Log4j2 JNDI Lookup Injection) | 10.0 Critical | CWE-502 / CWE-917 | Apache Log4j 2.0-beta9 to 2.14.1 |
| **CVE-2014-0160** | Heartbleed (OpenSSL TLS Heartbeat Buffer Over-Read) | 7.5 High | CWE-125 (Out-of-Bounds Read) | OpenSSL 1.0.1 through 1.0.1f |
| **CVE-2014-6271** | Shellshock (GNU Bash Environment Variable Function Trailing Code) | 9.8 Critical | CWE-78 (OS Command Injection) | GNU Bash through 4.3 |
| **CVE-2017-0144** | EternalBlue (Microsoft Windows SMBv1 SrvOs2FeaListSizeToNt Buffer Overflow) | 8.8 High / 9.8 Critical | CWE-190 / CWE-122 | Windows XP through Windows Server 2016 (SMBv1 `srv.sys`) |
| **CVE-2020-1472** | Zerologon (Microsoft Netlogon AES-CFB8 Cryptographic Flaw) | 10.0 Critical | CWE-330 (Use of Insufficiently Random Values) | Windows Server 2008 R2 through Windows Server 2019 Domain Controllers |
| **CVE-2021-4034** | PwnKit (Polkit pkexec argc=0 Out-of-Bounds Memory Read/Write) | 7.8 High | CWE-125 / CWE-787 | Polkit `pkexec` (All versions from May 2009 to January 2022) |
| **CVE-2022-0847** | DirtyPipe (Linux Kernel Pipe Buffer Uninitialized Flags Overwrite) | 7.8 High | CWE-665 (Improper Initialization) | Linux Kernel 5.8 through 5.16.10, 5.15.24, 5.10.101 |
| **CVE-2021-3156** | Baron Samedit (Sudo Heap-Based Buffer Overflow in sudoedit) | 7.8 High | CWE-122 (Heap-Based Buffer Overflow) | Sudo 1.8.2 to 1.8.31p2 and 1.9.0 to 1.9.5p1 |
| **CVE-2023-4911** | Looney Tunables (GNU C Library glibc GLIBC_TUNABLES Buffer Overflow) | 7.8 High | CWE-122 | glibc 2.34 through 2.38 |
| **CVE-2024-6387** | regreSSHion (OpenSSH Server SIGALRM Asynchronous Signal Handler Race Condition) | 8.1 High | CWE-364 (Signal Handler Race Condition) | OpenSSH 8.5p1 to 9.7p1 on glibc-based Linux systems |
| **CVE-2024-3094** | XZ Utils Supply-Chain Backdoor (liblzma IFUNC Hook in sshd) | 10.0 Critical | CWE-506 (Embedded Malicious Code) | XZ Utils 5.6.0 and 5.6.1 |
| **CVE-2023-44487** | HTTP/2 Rapid Reset Attack (HEADERS + RST_STREAM Resource Exhaustion) | 7.5 High | CWE-400 (Uncontrolled Resource Consumption) | HTTP/2 Server Implementations (Nginx, Envoy, Apache, Go net/http, Node.js) |
| **CVE-2022-22965** | Spring4Shell (Spring Framework DataBinder ClassLoader Manipulation) | 9.8 Critical | CWE-94 | Spring Framework 5.3.0-5.3.17, 5.2.0-5.2.19 on JDK 9+ |
| **CVE-2019-11510** | Pulse Connect Secure Arbitrary File Read via Path Traversal | 10.0 Critical | CWE-22 (Path Traversal) | Pulse Connect Secure 8.2, 8.3, 9.0 |
| **CVE-2021-26855** | ProxyLogon (Microsoft Exchange Server SSRF in Front-End Proxy) | 9.8 Critical | CWE-918 (SSRF) | Microsoft Exchange Server 2013, 2016, 2019 |
| **CVE-2023-34362** | MOVEit Transfer SQL Injection to Deserialization Chain | 9.8 Critical | CWE-89 (SQL Injection) | Progress MOVEit Transfer before 2023.0.1 |
| **CVE-2021-34527** | PrintNightmare (Windows Print Spooler RpcAddPrinterDriverEx RCE/LPE) | 8.8 High | CWE-269 (Improper Privilege Management) | Windows Print Spooler (`spoolsv.exe`) |
| **CVE-2021-42278 & CVE-2021-42287** | sAMAccountName Spoofing & noPac (Active Directory KDC Impersonation) | 8.8 High | CWE-287 (Improper Authentication) | Active Directory Domain Services (KDC) |
| **CVE-2023-23397** | Microsoft Outlook Extended MAPI PidLidReminderFileParameter NTLM Leak | 9.8 Critical | CWE-294 | Microsoft Outlook for Windows |
| **CVE-2023-20198** | Cisco IOS XE Web UI Privilege Escalation & Implant Defense | 10.0 Critical | CWE-284 (Improper Access Control) | Cisco IOS XE Software with HTTP/HTTPS Server Feature Enabled |
| **CVE-2022-40684** | Fortinet FortiOS / FortiProxy Administrative Authentication Bypass | 9.8 Critical | CWE-288 (Authentication Bypass Using an Alternate Path or Channel) | FortiOS 7.0.0-7.0.6, 7.2.0-7.2.1 |
| **CVE-2023-38408** | OpenSSH ssh-agent PKCS#11 Remote Library Loading | 9.8 Critical | CWE-427 (Uncontrolled Search Path Element) | OpenSSH before 9.3p2 (when `ForwardAgent yes` is used) |

---
## G.1 CVE-2021-44228 — Log4Shell (Apache Log4j2 JNDI Lookup Injection)

- **Severity & Base Score:** `10.0 Critical`
- **CVSS v3.1 Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`
- **Weakness Classification:** `CWE-502 / CWE-917`
- **Affected Software / Component:** Apache Log4j 2.0-beta9 to 2.14.1

### 1. Architectural Root-Cause Analysis
Apache Log4j2 recursively parsed message lookup expressions `${...}` inside logged strings. When user-controlled HTTP headers (such as `User-Agent` or `X-Api-Version`) or form fields were written to application logs, Log4j evaluated Java Naming and Directory Interface (JNDI) lookups (`jndi:ldap://`, `jndi:rmi://`, `jndi:dns://`), causing the JVM to connect to an external directory server and deserialize or load untrusted Java class bytecode.

### 2. Vulnerable Pattern & Technical Mechanism
```c
// Vulnerable Java Pattern (Log4j 2.14.1 with default message lookups enabled)
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class AuthController {
    private static final Logger logger = LogManager.getLogger(AuthController.class);
    public void login(String username, String userAgent) {
        // If username or userAgent contains ${jndi:...}, Log4j2 evaluates it during logging!
        logger.info("Login attempt for user: " + username + " from UA: " + userAgent);
    }
}
```

### 3. Production Remediation & Patch Engineering
```bash
// Remediated Pattern (Upgrade to Log4j >= 2.17.1 + parameterized logging + JVM hardening)
// 1. In pom.xml: org.apache.logging.log4j:log4j-core:2.23.1
// 2. JVM Flag: -Dlog4j2.formatMsgNoLookups=true
// 3. Remove JndiLookup class if legacy jar cannot be replaced immediately:
//    zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class
logger.info("Login attempt for user: {} from UA: {}", username, userAgent);
```

### 4. Blue Team Detection, Telemetry & Audit Verification
Monitor outbound LDAP (389/636), RMI (1099), and DNS connections initiated directly by Java application server processes (`java`). Inspect web access logs and WAF telemetry for `${jndi:`, `${lower:`, `${upper:`, and nested lookup obfuscations.

---
## G.2 CVE-2014-0160 — Heartbleed (OpenSSL TLS Heartbeat Buffer Over-Read)

- **Severity & Base Score:** `7.5 High`
- **CVSS v3.1 Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
- **Weakness Classification:** `CWE-125 (Out-of-Bounds Read)`
- **Affected Software / Component:** OpenSSL 1.0.1 through 1.0.1f

### 1. Architectural Root-Cause Analysis
The TLS Heartbeat Extension (RFC 6520) allows a peer to send a payload along with a 16-bit integer specifying the payload length, expecting the server to allocate a response buffer and echo back that exact number of bytes. OpenSSL failed to validate that the user-supplied `payload_length` matched the actual length of the received TLS record. By sending a 1-byte payload while claiming a length of 65,535 bytes, an unauthenticated client caused `memcpy()` to read up to 64 KB of adjacent heap memory from the OpenSSL process—leaking TLS private keys, session cookies, and user passwords.

### 2. Vulnerable Pattern & Technical Mechanism
```c
/* Vulnerable C Pattern in OpenSSL t1_lib.c (simplified) */
int tls1_process_heartbeat(SSL *s) {
    unsigned char *p = &s->s3->rrec.data[0], *pl;
    unsigned int payload;
    hbtype = *p++;
    n2s(p, payload); /* Reads 16-bit length from network packet WITHOUT bounds check! */
    pl = p;
    unsigned char *buffer = OPENSSL_malloc(1 + 2 + payload + padding);
    unsigned char *bp = buffer;
    *bp++ = TLS1_HB_RESPONSE;
    s2n(payload, bp);
    memcpy(bp, pl, payload); /* OVER-READS up to 64KB of process heap memory! */
    return ssl3_write_bytes(s, TLS1_RT_HEARTBEAT, buffer, 3 + payload + padding);
}
```

### 3. Production Remediation & Patch Engineering
```bash
/* Remediated C Pattern (OpenSSL 1.0.1g+) */
int tls1_process_heartbeat(SSL *s) {
    unsigned char *p = &s->s3->rrec.data[0], *pl;
    unsigned int payload;
    if (1 + 2 + 16 > s->s3->rrec.length)
        return 0; /* Discard silently if record is smaller than minimum heartbeat */
    hbtype = *p++;
    n2s(p, payload);
    if (1 + 2 + payload + 16 > s->s3->rrec.length)
        return 0; /* CRITICAL BOUNDS CHECK: Reject if claimed length exceeds actual packet! */
    pl = p;
    /* Safe to allocate and copy */
}
```

### 4. Blue Team Detection, Telemetry & Audit Verification
Suricata/Snort IDS rules detecting TLS Heartbeat records where the TLS record length header is significantly smaller than the encapsulated Heartbeat `payload_length`. Remediation requires upgrading OpenSSL, revoking exposed X.509 certificates, and re-issuing new private keys.

---
## G.3 CVE-2014-6271 — Shellshock (GNU Bash Environment Variable Function Trailing Code)

- **Severity & Base Score:** `9.8 Critical`
- **CVSS v3.1 Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- **Weakness Classification:** `CWE-78 (OS Command Injection)`
- **Affected Software / Component:** GNU Bash through 4.3

### 1. Architectural Root-Cause Analysis
GNU Bash allowed exporting shell functions to child processes via environment variables whose values started with `() {`. When a new Bash subshell initialized, it parsed such environment variables by executing the function definition in the parser context. However, Bash did not stop parsing at the closing brace `}` of the function body—it executed any trailing commands appended after `() { :; };`. Network services such as Apache `mod_cgi` (which maps HTTP headers like `User-Agent` to `HTTP_USER_AGENT` environment variables before invoking CGI scripts) or DHCP clients became immediately vulnerable to remote command execution.

### 2. Vulnerable Pattern & Technical Mechanism
```c
# Vulnerable Mechanism in CGI / Bash Subshell Initialization
# When Apache mod_cgi processes an HTTP request, it sets environment variables:
export HTTP_USER_AGENT='() { :; }; /usr/bin/id'
# When mod_cgi spawns /bin/bash to run a CGI script, Bash parses HTTP_USER_AGENT
# as a function definition and executes trailing commands after the closing brace.
```

### 3. Production Remediation & Patch Engineering
```bash
# Remediated Mechanism in Patched GNU Bash (4.3 Patch 25+)
# 1. Function exports are namespaced with 'BASH_FUNC_name%%' prefix
# 2. The parser strictly validates that only a single function definition is parsed
#    from exported environment variables and rejects any trailing commands.
sudo apt-get update && sudo apt-get install --only-upgrade bash
# Verify patch status:
env x='() { :;}; echo VULNERABLE' bash -c "echo Safe"
```

### 4. Blue Team Detection, Telemetry & Audit Verification
WAF and web server access log rules matching the literal byte sequence `() {` inside HTTP headers, query strings, or cookies. Audit `auditd` process trees for `/bin/sh` or `/bin/bash` spawned as children of `apache2`, `httpd`, or `dhclient`.

---
## G.4 CVE-2017-0144 — EternalBlue (Microsoft Windows SMBv1 SrvOs2FeaListSizeToNt Buffer Overflow)

- **Severity & Base Score:** `8.8 High / 9.8 Critical`
- **CVSS v3.1 Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- **Weakness Classification:** `CWE-190 / CWE-122`
- **Affected Software / Component:** Windows XP through Windows Server 2016 (SMBv1 `srv.sys`)

### 1. Architectural Root-Cause Analysis
In Microsoft's SMBv1 driver (`srv.sys`), the function `SrvOs2FeaListSizeToNt()` converts an OS/2 File Extended Attribute (FEA) list into an NT FEA list. Due to an integer truncation bug where a 32-bit size field was cast/assigned into a 16-bit unsigned integer (`WORD`) after size validation, `srv.sys` allocated a smaller kernel pool buffer than required and subsequently copied a larger FEA list into the non-paged kernel pool, corrupting adjacent `SRVNET_BUFFER` structures in Ring 0.

### 2. Vulnerable Pattern & Technical Mechanism
```c
/* Conceptual Representation of the Integer Truncation in srv.sys */
/* 1. Size calculation computes required NT FEA buffer size in 32-bit int */
/* 2. Value is mistakenly written back via a 16-bit cast *(WORD *)pFeaList = ... */
/* 3. Subsequent kernel pool copy uses the larger un-truncated size */
/* Result: Out-of-bounds heap write in Windows Kernel Non-Paged Pool */
```

### 3. Production Remediation & Patch Engineering
```bash
# Complete Remediation on Windows Hosts & Active Directory GPO:
# 1. Apply Microsoft Security Bulletin MS17-010 immediately.
# 2. Permanently disable SMBv1 across all Windows endpoints and servers:
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
# 3. Enforce SMBv2/v3 Signing via Group Policy:
Set-SmbServerConfiguration -RequireSecuritySignature $true -EnableSecuritySignature $true -Force
# 4. Block TCP Ports 139 and 445 at perimeter and inter-VLAN firewalls.
```

### 4. Blue Team Detection, Telemetry & Audit Verification
Monitor SMB traffic for `SMB_COM_TRANSACTION2` requests targeting `IPC$` with abnormal `FEA_LIST` lengths and `SMB_COM_NT_TRANSACT` groom packets. Use `nmap --script smb-protocols -p 445 <target>` during internal audits to verify SMBv1 is completely disabled.

---
## G.5 CVE-2020-1472 — Zerologon (Microsoft Netlogon AES-CFB8 Cryptographic Flaw)

- **Severity & Base Score:** `10.0 Critical`
- **CVSS v3.1 Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`
- **Weakness Classification:** `CWE-330 (Use of Insufficiently Random Values)`
- **Affected Software / Component:** Windows Server 2008 R2 through Windows Server 2019 Domain Controllers

### 1. Architectural Root-Cause Analysis
The MS-NRPC (Netlogon Remote Protocol) `ComputeNetlogonCredential` function used AES-128 in CFB8 (8-bit Cipher Feedback) mode to encrypt an 8-byte client challenge using the Domain Controller's computer account session key. Instead of generating a cryptographically random 16-byte Initialization Vector (IV), the specification hardcoded an all-zero 16-byte IV (`0x00 * 16`). Because of how AES-CFB8 operates, for any random key there is a 1 in 256 probability that encrypting an 8-byte all-zero plaintext (`0x00 * 8`) with an all-zero IV produces an all-zero ciphertext (`0x00 * 8`). Within ~256 unauthenticated RPC attempts, an attacker could bypass authentication and invoke `NetrServerPasswordSet2` to reset the Domain Controller's machine account password in Active Directory.

### 2. Vulnerable Pattern & Technical Mechanism
```c
# Mathematical Probability of AES-CFB8 Zero-IV Collision:
# In AES-CFB8:
# Step 1: Block_0 = AES_Encrypt(Key, IV=0x00*16)
# Step 2: Ciphertext_Byte_0 = Plaintext_Byte_0 ^ MSB(Block_0)
# If Plaintext_Byte_0 == 0x00, then Ciphertext_Byte_0 == 0x00 whenever MSB(Block_0) == 0x00 (Probability: 1/256).
# Once Ciphertext_Byte_0 is 0x00, the shift register shift-in keeps the next 16-byte input to AES all-zeros!
# Thus ALL 8 bytes become 0x00 with probability exactly 1/256!
```

### 3. Production Remediation & Patch Engineering
```bash
# Remediation & Hardening on Domain Controllers:
# 1. Install August 2020 / February 2021 Windows Server Cumulative Updates (Enforcement Mode).
# 2. Enforce Secure RPC for Netlogon via Registry / Group Policy:
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "FullSecureChannelProtection" -Value 1 -Type DWord
# 3. Monitor Windows System Event IDs 5827, 5828, 5829, 5830, 5831 for non-compliant Netlogon clients.
```

### 4. Blue Team Detection, Telemetry & Audit Verification
Alert on Windows Security Event ID `4742` (A computer account was changed) where `Anonymous Logon` (`S-1-5-7`) modifies a Domain Controller computer object, combined with a burst of failed `NetrServerAuthenticate3` RPC calls over MS-NRPC.

---
## G.6 CVE-2021-4034 — PwnKit (Polkit pkexec argc=0 Out-of-Bounds Memory Read/Write)

- **Severity & Base Score:** `7.8 High`
- **CVSS v3.1 Vector:** `CVSS:3.1/AV:L/PR:L/AC:L/UI:N/S:U/C:H/I:H/A:H`
- **Weakness Classification:** `CWE-125 / CWE-787`
- **Affected Software / Component:** Polkit `pkexec` (All versions from May 2009 to January 2022)

### 1. Architectural Root-Cause Analysis
In POSIX operating systems, `execve(path, argv, envp)` permits passing an empty `argv` array (`argc == 0`, so `argv[0] == NULL`). In `pkexec`'s `main(int argc, char *argv[])` loop (`for (n = 1; n < (guint) argc; n++)`), when `argc` was `0`, the loop never ran and `n` remained `1`. Because `argv` and `envp` are laid out contiguously on the Linux process stack (`argv[0] == NULL`, followed immediately by `envp[0]`), reading `argv[1]` actually read `envp[0]`, and later writing back a resolved path to `argv[1]` overwrote `envp[0]`, allowing an unprivileged user to re-introduce dangerous environment variables (like `GCONV_PATH`) into a SUID-root binary after environment scrubbing.

### 2. Vulnerable Pattern & Technical Mechanism
```c
/* Vulnerable C Pattern in pkexec.c (2009 - 2022) */
int main(int argc, char *argv[]) {
    guint n;
    /* If argc == 0, this loop does not execute, leaving n = 1! */
    for (n = 1; n < (guint) argc; n++) {
        /* option parsing */
    }
    /* Out-of-bounds read: argv[1] is actually envp[0] on the stack! */
    path = g_strdup(argv[n]);
    if (path[0] != '/') {
        s = g_find_program_in_path(path);
        /* Out-of-bounds write: overwrites envp[0] with an unvalidated string! */
        argv[n] = path = s;
    }
}
```

### 3. Production Remediation & Patch Engineering
```bash
/* Remediated C Pattern in Polkit >= 0.120-r2 */
int main(int argc, char *argv[]) {
    /* Strictly enforce that argc >= 1 before indexing argv */
    if (argc < 1) {
        exit(127);
    }
    /* Additionally, Linux kernel 5.18+ patches do_execveat_common() to ensure
       argc is never 0 by inserting an empty string "" if argv is empty. */
}
```

### 4. Blue Team Detection, Telemetry & Audit Verification
Audit SUID binaries across Linux fleets (`find / -perm -4000 2>/dev/null`). Remove the SUID bit from `/usr/bin/pkexec` (`chmod 0755 /usr/bin/pkexec`) on headless servers that do not require graphical PolicyKit prompts, and monitor `auditd` for `execve` calls where `argc=0`.

---
## G.7 CVE-2022-0847 — DirtyPipe (Linux Kernel Pipe Buffer Uninitialized Flags Overwrite)

- **Severity & Base Score:** `7.8 High`
- **CVSS v3.1 Vector:** `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`
- **Weakness Classification:** `CWE-665 (Improper Initialization)`
- **Affected Software / Component:** Linux Kernel 5.8 through 5.16.10, 5.15.24, 5.10.101

### 1. Architectural Root-Cause Analysis
Linux 5.8 refactored anonymous pipe buffer handling and introduced the `PIPE_BUF_FLAG_CAN_MERGE` flag in `struct pipe_buffer`. When the `splice()` system call copied data from a read-only file's page cache into a pipe, it initialized a `pipe_buffer` pointing directly to the kernel's shared page cache for that file, but forgot to clear `buf->flags`. If an unprivileged user first wrote to and drained the pipe (setting `PIPE_BUF_FLAG_CAN_MERGE` on all ring entries), then called `splice()` on a read-only file (such as `/etc/passwd` or a SUID binary), subsequent `write()` calls to the pipe merged data directly into the kernel page cache of the read-only file, bypassing all VFS permission checks.

### 2. Vulnerable Pattern & Technical Mechanism
```c
/* Vulnerable Kernel Pattern in fs/splice.c (copy_page_to_iter_pipe) */
static size_t copy_page_to_iter_pipe(struct page *page, size_t offset, size_t bytes,
                                     struct iov_iter *i) {
    struct pipe_inode_info *pipe = i->pipe;
    struct pipe_buffer *buf = &pipe->bufs[idx];
    buf->ops = &page_cache_pipe_buf_ops;
    buf->page = page;
    buf->offset = offset;
    buf->len = bytes;
    /* BUG: buf->flags is NOT initialized to 0! Retains PIPE_BUF_FLAG_CAN_MERGE! */
}
```

### 3. Production Remediation & Patch Engineering
```bash
/* Remediated Kernel Pattern (Linux 5.16.11 / 5.15.25 / 5.10.102) */
    buf->ops = &page_cache_pipe_buf_ops;
    buf->page = page;
    buf->offset = offset;
    buf->len = bytes;
    buf->flags = 0; /* Explicitly clear PIPE_BUF_FLAG_CAN_MERGE on page-cache splice */
```

### 4. Blue Team Detection, Telemetry & Audit Verification
Verify kernel version via `uname -r`. Upgrade Linux kernels to patched stable branches (`>= 5.16.11`, `>= 5.15.25`, `>= 5.10.102`). Use File Integrity Monitoring (FIM) and `auditd` to alert on unexpected changes to `/etc/passwd`, `/etc/sudoers`, or system binaries.

---
## G.8 CVE-2021-3156 — Baron Samedit (Sudo Heap-Based Buffer Overflow in sudoedit)

- **Severity & Base Score:** `7.8 High`
- **CVSS v3.1 Vector:** `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`
- **Weakness Classification:** `CWE-122 (Heap-Based Buffer Overflow)`
- **Affected Software / Component:** Sudo 1.8.2 to 1.8.31p2 and 1.9.0 to 1.9.5p1

### 1. Architectural Root-Cause Analysis
When `sudo` was invoked in shell mode (`-s` or `-i`), `parse_args()` escaped special characters in command-line arguments with backslashes before concatenating them into a heap buffer. However, if `sudoedit -s` (which sets `MODE_EDIT` and `MODE_SHELL` simultaneously without setting `MODE_RUN`) was invoked, the pre-check loop that escaped backslashes was skipped, while the downstream loop in `set_cmnd()` still unescaped backslashes. When an argument ended with a single trailing backslash `\`, the unescaping loop read past the null terminator `\0` and continued copying data out-of-bounds on the heap.

### 2. Vulnerable Pattern & Technical Mechanism
```c
/* Vulnerable C Pattern in plugins/sudoers/sudoers.c (set_cmnd) */
if (sudo_mode & (MODE_RUN | MODE_EDIT | MODE_CHECK)) {
    if (ISSET(sudo_mode, MODE_RUN | MODE_CHECK)) { /* Skipped when MODE_EDIT! */
        /* Pre-escaping occurred in parse_args only for MODE_RUN */
    }
    /* Loop assumes backslashes are always followed by a valid character before NUL: */
    while (*from != '\0') {
        if (from[0] == '\\' && !isspace((unsigned char)from[1]))
            from++; /* If from[1] == '\0', increments past string terminator! */
        *to++ = *from++;
    }
}
```

### 3. Production Remediation & Patch Engineering
```bash
/* Remediated C Pattern in Sudo 1.9.5p2+ */
/* 1. Reject combining -s or -i flags with sudoedit (MODE_EDIT) in parse_args() */
/* 2. In set_cmnd(), verify from[1] != '\0' before advancing past a backslash: */
if (from[0] == '\\' && from[1] != '\0' && !isspace((unsigned char)from[1]))
    from++;
```

### 4. Blue Team Detection, Telemetry & Audit Verification
Verify sudo version with `sudo --version` (ensure `>= 1.9.5p2`). Audit `/var/log/auth.log` and `auditd` `execve` records for `sudoedit` invocations containing `-s` or `-i` flags.

---
## G.9 CVE-2023-4911 — Looney Tunables (GNU C Library glibc GLIBC_TUNABLES Buffer Overflow)

- **Severity & Base Score:** `7.8 High`
- **CVSS v3.1 Vector:** `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`
- **Weakness Classification:** `CWE-122`
- **Affected Software / Component:** glibc 2.34 through 2.38

### 1. Architectural Root-Cause Analysis
The GNU dynamic linker (`ld.so`) processes the `GLIBC_TUNABLES` environment variable before `main()` runs—even for SUID-root binaries—to allow performance tuning and sanitization of dangerous tunables. In `__tunables_init()`, when a malformed tunable string of the form `tunable1=tunable2=val` was supplied without a `:` delimiter, the string sanitization loop copied the second assignment past the bounds of the allocated buffer in `ld.so`'s private memory segment.

### 2. Vulnerable Pattern & Technical Mechanism
```c
# Diagnostic Verification of glibc Version
ldd --version
# Check if glibc is patched against CVE-2023-4911 across Debian/Ubuntu/RHEL
```

### 3. Production Remediation & Patch Engineering
```bash
# Remediation:
# 1. Update libc6 / glibc packages immediately:
sudo apt-get update && sudo apt-get install --only-upgrade libc6
# 2. Minimize SUID-root attack surface on production servers using mount options:
#    Mount /home, /tmp, /var/tmp, and /dev/shm with 'nosuid,nodev,noexec' in /etc/fstab.
```

### 4. Blue Team Detection, Telemetry & Audit Verification
Monitor `execve` system calls via `auditd` or eBPF (Falco/Tetragon) where an unprivileged UID invokes a SUID binary with an abnormally large `GLIBC_TUNABLES` environment variable.

---
## G.10 CVE-2024-6387 — regreSSHion (OpenSSH Server SIGALRM Asynchronous Signal Handler Race Condition)

- **Severity & Base Score:** `8.1 High`
- **CVSS v3.1 Vector:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H`
- **Weakness Classification:** `CWE-364 (Signal Handler Race Condition)`
- **Affected Software / Component:** OpenSSH 8.5p1 to 9.7p1 on glibc-based Linux systems

### 1. Architectural Root-Cause Analysis
When a client fails to authenticate within OpenSSH's `LoginGraceTime` (default 120 seconds), `sshd`'s `SIGALRM` handler (`grace_alarm_handler`) is invoked asynchronously. This signal handler called `syslog()`, which internally calls async-signal-unsafe functions (`malloc()`/`free()`) in `glibc`. If the `SIGALRM` signal interrupts the main `sshd` code while it is already inside `malloc()` or `free()` holding inconsistent heap metadata, heap corruption occurs.

### 2. Vulnerable Pattern & Technical Mechanism
```c
// Async-Signal-Unsafe Pattern in C Signal Handlers:
void sigalrm_handler(int sig) {
    // NEVER call syslog(), printf(), malloc(), or free() inside a POSIX signal handler!
    // Only async-signal-safe functions (see man 7 signal-safety, e.g., write(), _exit()) are safe.
    syslog(LOG_INFO, "Timeout expired"); // UNSAFE: invokes glibc heap allocator!
    _exit(1);
}
```

### 3. Production Remediation & Patch Engineering
```bash
# Remediation & Hardening in /etc/ssh/sshd_config:
# 1. Upgrade OpenSSH to >= 9.8p1.
# 2. If immediate patching is delayed, set LoginGraceTime to 0 (disables SIGALRM timeout,
#    combine with MaxStartups and firewall rate-limiting to prevent connection exhaustion):
LoginGraceTime 20
MaxStartups 10:30:60
# 3. Restrict SSH access via nftables/iptables or bastion VPNs.
```

### 4. Blue Team Detection, Telemetry & Audit Verification
Alert on high rates of SSH connection timeouts in `/var/log/auth.log` (`Timeout before authentication for...`) from a single source IP or subnet, which is a strong indicator of timing race probing.

---
## G.11 CVE-2024-3094 — XZ Utils Supply-Chain Backdoor (liblzma IFUNC Hook in sshd)

- **Severity & Base Score:** `10.0 Critical`
- **CVSS v3.1 Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`
- **Weakness Classification:** `CWE-506 (Embedded Malicious Code)`
- **Affected Software / Component:** XZ Utils 5.6.0 and 5.6.1

### 1. Architectural Root-Cause Analysis
A sophisticated multi-year supply-chain attack modified the release tarballs (`m4/build-to-host.m4` and test files `tests/files/bad-3-corrupt_lzma2.xz`) of `xz-utils` versions 5.6.0 and 5.6.1. During compilation on Debian/RPM x86_64 builds, the modified autotools script extracted an obfuscated object file and linked it into `liblzma.so`. Because Debian and Fedora patch OpenSSH (`sshd`) to link against `libsystemd.so`, which in turn links against `liblzma.so`, the malicious `liblzma` used a GNU Indirect Function (`IFUNC`) resolver during dynamic linking to hook `RSA_public_decrypt@GOT.plt` inside `sshd`, verifying an Ed448-signed payload in pre-authentication SSH certificates.

### 2. Vulnerable Pattern & Technical Mechanism
```c
# Auditing Shared Library Dependencies of sshd and xz Version:
xz --version
ldd $(which sshd) | grep -E "liblzma|libsystemd"
# Inspect ELF symbols and IFUNC relocations in liblzma:
readelf -r /lib/x86_64-linux-gnu/liblzma.so.5 | grep IRELATIVE
```

### 3. Production Remediation & Patch Engineering
```bash
# Supply-Chain Defense & Remediation:
# 1. Ensure xz-utils is on a verified clean version (e.g., 5.4.x or >= 5.6.2+ reverted).
# 2. Rebuild packages directly from audited git tag trees rather than maintainer-generated autotools tarballs.
# 3. Enable OpenSSH sshd dependency isolation (OpenSSH 9.8+ splits sshd into sshd and sshd-session,
#    moving libsystemd notification out of the network-listening binary).
```

### 4. Blue Team Detection, Telemetry & Audit Verification
Use Software Bill of Materials (SBOM) scanning (`syft`, `grype`, `trivy`) in CI/CD pipelines to detect vulnerable or revoked package versions across all container images and virtual machines.

---
## G.12 CVE-2023-44487 — HTTP/2 Rapid Reset Attack (HEADERS + RST_STREAM Resource Exhaustion)

- **Severity & Base Score:** `7.5 High`
- **CVSS v3.1 Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`
- **Weakness Classification:** `CWE-400 (Uncontrolled Resource Consumption)`
- **Affected Software / Component:** HTTP/2 Server Implementations (Nginx, Envoy, Apache, Go net/http, Node.js)

### 1. Architectural Root-Cause Analysis
In HTTP/2 (RFC 9113), a single TCP connection multiplexes multiple concurrent streams, bounded by `SETTINGS_MAX_CONCURRENCY_STREAMS` (commonly 100). However, when a client sends a `HEADERS` frame to open a stream and immediately sends an `RST_STREAM` frame in the same TCP packet to cancel it, the server considers the stream closed and decrements the active stream counter immediately—while the upstream application server or proxy worker still expends CPU and memory parsing the request headers and routing the cancelled request. This allowed opening and resetting hundreds of thousands of streams per second over a single TCP connection.

### 2. Vulnerable Pattern & Technical Mechanism
```c
# Nginx Hardened HTTP/2 Configuration (/etc/nginx/nginx.conf):
http {
    http2 on;
    # Limit concurrent streams per connection
    http2_max_concurrent_streams 128;
    # Limit total requests allowed on a single keepalive/HTTP2 connection
    keepalive_requests 1000;
    # Enforce per-IP request rate limiting
    limit_req_zone $binary_remote_addr zone=api_limit:10m rate=50r/s;
}
```

### 3. Production Remediation & Patch Engineering
```bash
// Go net/http & golang.org/x/net/http2 Remediation:
// Upgrade golang.org/x/net to >= v0.17.0 and Go standard library to >= 1.21.3 / 1.20.10,
// which enforces strict tracking of rapid stream resets and terminates abusive connections.
```

### 4. Blue Team Detection, Telemetry & Audit Verification
Monitor reverse proxy metrics (Nginx, Envoy, HAProxy, Cloudflare) for spikes in `RST_STREAM` frames per TCP connection and discrepancies between HTTP/2 stream creation rates and active stream counts.

---
## G.13 CVE-2022-22965 — Spring4Shell (Spring Framework DataBinder ClassLoader Manipulation)

- **Severity & Base Score:** `9.8 Critical`
- **CVSS v3.1 Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- **Weakness Classification:** `CWE-94`
- **Affected Software / Component:** Spring Framework 5.3.0-5.3.17, 5.2.0-5.2.19 on JDK 9+

### 1. Architectural Root-Cause Analysis
Spring MVC's `DataBinder` automatically binds HTTP query/form parameters to POJO properties via JavaBean getters and setters. On JDK 9+, `Object.getClass().getModule().getClassLoader()` exposed the Tomcat `ParallelWebappClassLoader`, allowing property traversal (`class.module.classLoader.resources.context.parent.pipeline.first.*`) to reconfigure Tomcat's `AccessLogValve` and write arbitrary log files into the web root.

### 2. Vulnerable Pattern & Technical Mechanism
```c
// Vulnerable Spring Controller binding directly to a broad POJO without @InitBinder allowlist:
@PostMapping("/register")
public String register(UserRegistrationDto userDto) {
    return "success";
}
```

### 3. Production Remediation & Patch Engineering
```bash
// Remediated Pattern (Upgrade to Spring >= 5.3.18 AND explicitly allowlist bindable fields):
@InitBinder
public void initBinder(WebDataBinder binder) {
    binder.setAllowedFields("username", "email", "displayName");
    binder.setDisallowedFields("class.*", "Class.*", "*.class.*", "*.Class.*");
}
```

### 4. Blue Team Detection, Telemetry & Audit Verification
Inspect web access logs for parameter names containing `class.module.classLoader`. Deploy Spring Boot applications as standalone executable JARs rather than traditional Tomcat WAR deployments where possible.

---
## G.14 CVE-2019-11510 — Pulse Connect Secure Arbitrary File Read via Path Traversal

- **Severity & Base Score:** `10.0 Critical`
- **CVSS v3.1 Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`
- **Weakness Classification:** `CWE-22 (Path Traversal)`
- **Affected Software / Component:** Pulse Connect Secure 8.2, 8.3, 9.0

### 1. Architectural Root-Cause Analysis
Unauthenticated URI normalization flaw in the SSL-VPN web interface allowed traversing outside the web root to read sensitive session cache databases and configuration files.

### 2. Vulnerable Pattern & Technical Mechanism
```c
# Vulnerable URI Routing without Canonical Path Verification:
# Web handler concatenated unvalidated path segments before resolving realpath().
```

### 3. Production Remediation & Patch Engineering
```bash
# Secure Path Canonicalization Pattern in Python/C/Go:
import os
def safe_resolve(base_dir: str, user_path: str) -> str:
    base_real = os.path.realpath(base_dir)
    target_real = os.path.realpath(os.path.join(base_real, user_path))
    if os.path.commonpath([base_real, target_real]) != base_real:
        raise PermissionError("Path traversal attempt blocked")
    return target_real
```

### 4. Blue Team Detection, Telemetry & Audit Verification
Enforce hardware/FIDO2 MFA on all VPN appliances, place VPN management interfaces on internal-only subnets, and monitor VPN web logs for `..` or `%2e%2e` sequences.

---
## G.15 CVE-2021-26855 — ProxyLogon (Microsoft Exchange Server SSRF in Front-End Proxy)

- **Severity & Base Score:** `9.8 Critical`
- **CVSS v3.1 Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- **Weakness Classification:** `CWE-918 (SSRF)`
- **Affected Software / Component:** Microsoft Exchange Server 2013, 2016, 2019

### 1. Architectural Root-Cause Analysis
Exchange's Client Access Service (CAS) front-end proxy trusted the `X-BEResource` cookie on unauthenticated static asset paths (`/owa/auth/x.js`) to determine which internal back-end server and Kerberos machine session to proxy the request to (`localhost~1942062522`), bypassing front-end authentication and reaching internal Exchange `ecp` endpoints.

### 2. Vulnerable Pattern & Technical Mechanism
```c
# Vulnerability Root Cause:
# Front-end reverse proxy trusted user-supplied routing cookies (X-BEResource)
# on unauthenticated static file routes and attached machine credentials when proxying.
```

### 3. Production Remediation & Patch Engineering
```bash
# Remediation:
# 1. Apply Exchange Cumulative Updates and Security Updates immediately.
# 2. Never trust client-supplied headers or cookies to determine internal proxy targets.
# 3. Restrict external access to /ecp and administrative endpoints at the reverse proxy layer.
```

### 4. Blue Team Detection, Telemetry & Audit Verification
Run Microsoft Exchange HealthChecker.ps1 regularly and monitor IIS logs under `C:\inetpub\logs\LogFiles\` for requests containing `X-BEResource` or `X-AnonResource-Backend` cookies.

---
## G.16 CVE-2023-34362 — MOVEit Transfer SQL Injection to Deserialization Chain

- **Severity & Base Score:** `9.8 Critical`
- **CVSS v3.1 Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- **Weakness Classification:** `CWE-89 (SQL Injection)`
- **Affected Software / Component:** Progress MOVEit Transfer before 2023.0.1

### 1. Architectural Root-Cause Analysis
Complex multi-stage parameter handling between IIS `.aspx` (`guestaccess.aspx`) and internal `.NET` handlers allowed an unauthenticated request to inject SQL statements into session state tables, which were subsequently deserialized by the application.

### 2. Vulnerable Pattern & Technical Mechanism
```c
// Vulnerable C# ADO.NET String Concatenation Pattern:
string sql = "SELECT * FROM Sessions WHERE SessionId = '" + headerValue + "'";
SqlCommand cmd = new SqlCommand(sql, conn);
```

### 3. Production Remediation & Patch Engineering
```bash
// Remediated C# Parameterized Query Pattern:
string sql = "SELECT * FROM Sessions WHERE SessionId = @SessionId";
using SqlCommand cmd = new SqlCommand(sql, conn);
cmd.Parameters.Add("@SessionId", SqlDbType.VarChar, 64).Value = headerValue;
```

### 4. Blue Team Detection, Telemetry & Audit Verification
Audit all `.NET` data access layers with SAST tools (Semgrep, CodeQL) to enforce strict `@Parameter` binding and prohibit dynamic string interpolation in SQL queries.

---
## G.17 CVE-2021-34527 — PrintNightmare (Windows Print Spooler RpcAddPrinterDriverEx RCE/LPE)

- **Severity & Base Score:** `8.8 High`
- **CVSS v3.1 Vector:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`
- **Weakness Classification:** `CWE-269 (Improper Privilege Management)`
- **Affected Software / Component:** Windows Print Spooler (`spoolsv.exe`)

### 1. Architectural Root-Cause Analysis
The Windows Print Spooler RPC function `RpcAddPrinterDriverEx()` permitted low-privileged authenticated users to pass the `APD_INSTALL_WARNED_DRIVER` (`0x8000`) flag, bypassing administrator privilege checks and causing `spoolsv.exe` (running as `NT AUTHORITY\SYSTEM`) to load an arbitrary driver DLL from a local path or remote UNC share.

### 2. Vulnerable Pattern & Technical Mechanism
```c
# Remediation via PowerShell & Group Policy:
# Disable Print Spooler service on all Domain Controllers and servers that do not print:
Stop-Service -Name Spooler -Force
Set-Service -Name Spooler -StartupType Disabled
```

### 3. Production Remediation & Patch Engineering
```bash
# Additionally, configure Point and Print Restrictions via GPO / Registry:
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" `
    -Name "RestrictDriverInstallationToAdministrators" -Value 1 -PropertyType DWord -Force
```

### 4. Blue Team Detection, Telemetry & Audit Verification
Monitor Windows Event Log `Microsoft-Windows-PrintService/Operational` Event ID `316` and Sysmon Event ID `7` (Image Loaded) for unsigned DLLs loaded by `C:\Windows\System32\spoolsv.exe`.

---
## G.18 CVE-2021-42278 & CVE-2021-42287 — sAMAccountName Spoofing & noPac (Active Directory KDC Impersonation)

- **Severity & Base Score:** `8.8 High`
- **CVSS v3.1 Vector:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`
- **Weakness Classification:** `CWE-287 (Improper Authentication)`
- **Affected Software / Component:** Active Directory Domain Services (KDC)

### 1. Architectural Root-Cause Analysis
By default in Active Directory (`ms-DS-MachineAccountQuota = 10`), any authenticated domain user could create up to 10 computer accounts. Due to missing validation on trailing `$` characters in `sAMAccountName` (CVE-2021-42278) combined with KDC fallback lookup behavior when an account was deleted after TGT issuance (`S4U2Self` in CVE-2021-42287), the KDC matched a renamed computer account (`DC01` without trailing `$`) to the real Domain Controller `DC01$` when issuing a service ticket.

### 2. Vulnerable Pattern & Technical Mechanism
```c
# Vulnerable Default Active Directory Configuration:
Get-ADObject -Identity ((Get-ADDomain).DistinguishedName) -Properties ms-DS-MachineAccountQuota
# Default returns: ms-DS-MachineAccountQuota : 10
```

### 3. Production Remediation & Patch Engineering
```bash
# Complete Active Directory Hardening:
# 1. Install November 2021 AD Domain Controller updates (KB5008380 / KB5008602).
# 2. Set ms-DS-MachineAccountQuota to 0 so standard users cannot join or create machine accounts:
Set-ADDomain -Identity (Get-ADDomain) -Replace @{"ms-DS-MachineAccountQuota"="0"}
```

### 4. Blue Team Detection, Telemetry & Audit Verification
Monitor Windows Security Event IDs `4741` (A computer account was created) and `4742` (A computer account was changed, especially where `sAMAccountName` changes to match a Domain Controller name), as well as new Kerberos validation Event IDs `35`, `36`, `37`, and `38`.

---
## G.19 CVE-2023-23397 — Microsoft Outlook Extended MAPI PidLidReminderFileParameter NTLM Leak

- **Severity & Base Score:** `9.8 Critical`
- **CVSS v3.1 Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- **Weakness Classification:** `CWE-294`
- **Affected Software / Component:** Microsoft Outlook for Windows

### 1. Architectural Root-Cause Analysis
When Microsoft Outlook processed an incoming calendar appointment or task containing a custom MAPI property `PidLidReminderFileParameter` set to a remote UNC path (`\\external-ip\share\sound.wav`), Windows automatically attempted SMB authentication to that UNC path when the reminder triggered—even before the user opened or previewed the email—leaking the user's NetNTLMv2 challenge-response hash over TCP port 445.

### 2. Vulnerable Pattern & Technical Mechanism
```c
# Network Perimeter & Endpoint Hardening Against Outbound NTLM Leakage:
# 1. Block outbound TCP 445 (SMB) and TCP/UDP 135-139 at the enterprise perimeter firewall.
# 2. Restrict Outbound NTLM Traffic via Windows Group Policy / Registry:
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
    -Name "RestrictSendingNTLMTraffic" -Value 2 -PropertyType DWord -Force
```

### 3. Production Remediation & Patch Engineering
```bash
# 3. Add privileged accounts to the Active Directory 'Protected Users' security group,
#    which completely disables NTLM authentication and enforces Kerberos AES:
Add-ADGroupMember -Identity "Protected Users" -Members "admin_user"
```

### 4. Blue Team Detection, Telemetry & Audit Verification
Monitor Windows Event ID `8004` under `Microsoft-Windows-NTLM/Operational` when auditing outbound NTLM traffic before switching to full block mode (`Value = 2`).

---
## G.20 CVE-2023-20198 — Cisco IOS XE Web UI Privilege Escalation & Implant Defense

- **Severity & Base Score:** `10.0 Critical`
- **CVSS v3.1 Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`
- **Weakness Classification:** `CWE-284 (Improper Access Control)`
- **Affected Software / Component:** Cisco IOS XE Software with HTTP/HTTPS Server Feature Enabled

### 1. Architectural Root-Cause Analysis
Improper access control in the Nginx reverse proxy configuration of the Cisco IOS XE Web UI (`webui_wsma_http`) allowed unauthenticated requests to reach internal WSMA management handlers and create a privilege level 15 administrative user.

### 2. Vulnerable Pattern & Technical Mechanism
```c
! Vulnerable Cisco IOS XE Configuration (HTTP Server Exposed to Untrusted Networks):
ip http server
ip http secure-server
! Without an access-class restriction or when Web UI is unnecessary
```

### 3. Production Remediation & Patch Engineering
```bash
! Hardened Cisco IOS XE Configuration:
! 1. Disable HTTP/HTTPS server entirely if CLI (SSH) is used for management:
no ip http server
no ip http secure-server
! 2. If Web UI is strictly required, bind it ONLY to an out-of-band management VRF and ACL:
ip access-list standard MGMT_ACL
 permit 10.250.0.0 0.0.0.255
 deny any log
ip http access-class ipv4 MGMT_ACL
ip http active-session-modules none
```

### 4. Blue Team Detection, Telemetry & Audit Verification
Audit all network switches and routers for unexpected privilege 15 local accounts (`show running-config | include username`) and verify that management planes (SSH, HTTPS, SNMP) are isolated to dedicated out-of-band management VLANs.

---
## G.21 CVE-2022-40684 — Fortinet FortiOS / FortiProxy Administrative Authentication Bypass

- **Severity & Base Score:** `9.8 Critical`
- **CVSS v3.1 Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- **Weakness Classification:** `CWE-288 (Authentication Bypass Using an Alternate Path or Channel)`
- **Affected Software / Component:** FortiOS 7.0.0-7.0.6, 7.2.0-7.2.1

### 1. Architectural Root-Cause Analysis
An internal inter-process communication trust flaw allowed external requests that set specific `Forwarded` headers and the internal `Node.js` report runner `User-Agent` to be treated as trusted localhost system requests by the HTTPS administrative API.

### 2. Vulnerable Pattern & Technical Mechanism
```c
# Vulnerable Reverse Proxy Pattern:
# Backend API trusted client-modifiable HTTP headers (Forwarded: for="127.0.0.1")
# to grant internal loopback administrative trust.
```

### 3. Production Remediation & Patch Engineering
```bash
# Hardened FortiOS Configuration (Local-In Policy to block WAN Admin Access):
config firewall local-in-policy
    edit 1
        set intf "wan1"
        set srcaddr "all"
        set dstaddr "all"
        set action deny
        set service "HTTPS" "SSH" "HTTP"
        set schedule "always"
    next
end
```

### 4. Blue Team Detection, Telemetry & Audit Verification
Never expose firewall administrative interfaces (`HTTPS`, `SSH`) on WAN interfaces. Enforce `local-in-policy` rules and monitor administrative audit logs for SSH keys or API tokens added by `Local_Process_Access`.

---
## G.22 CVE-2023-38408 — OpenSSH ssh-agent PKCS#11 Remote Library Loading

- **Severity & Base Score:** `9.8 Critical`
- **CVSS v3.1 Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- **Weakness Classification:** `CWE-427 (Uncontrolled Search Path Element)`
- **Affected Software / Component:** OpenSSH before 9.3p2 (when `ForwardAgent yes` is used)

### 1. Architectural Root-Cause Analysis
When a user connected to an untrusted remote server with SSH Agent Forwarding enabled (`ssh -A` or `ForwardAgent yes`), anyone with root access on that remote host could access the forwarded UNIX domain socket (`$SSH_AUTH_SOCK`) and send PKCS#11 provider loading requests back to the user's local `ssh-agent` workstation.

### 2. Vulnerable Pattern & Technical Mechanism
```c
# Dangerous SSH Client Configuration (~/.ssh/config):
Host *
    ForwardAgent yes  # NEVER enable ForwardAgent globally! Exposes local agent socket to remote root!
```

### 3. Production Remediation & Patch Engineering
```bash
# Safe SSH Bastion / Jump Host Pattern (~/.ssh/config):
# Always use ProxyJump (-J) instead of ForwardAgent (-A)!
# ProxyJump tunnels the end-to-end SSH handshake through the bastion WITHOUT exposing your keys or agent:
Host internal-prod-server
    HostName 10.20.30.40
    User secadmin
    ProxyJump bastion.corp.lk
    ForwardAgent no
```

### 4. Blue Team Detection, Telemetry & Audit Verification
Audit developer `~/.ssh/config` files to replace `ForwardAgent yes` with `ProxyJump` (`ssh -J`). Keep OpenSSH updated (`>= 9.3p2`), which restricts PKCS#11 modules to trusted paths and requires explicit user confirmation.

---
## G.21 Comparative Reference Matrix of 40 Additional High-Impact Enterprise CVEs

| CVE ID | Component | Vulnerability Class | Root Cause Summary | Defensive Control & Patch Verification |
|---|---|---|---|---|
| **CVE-2017-5638** | Apache Struts 2 | OGNL Expression Injection (CWE-917) | Jakarta Multipart parser included raw `Content-Type` header in localized error messages evaluated as OGNL expressions. | Upgrade Struts >= 2.5.10.1; validate `Content-Type` headers at edge WAF before reaching servlet container. |
| **CVE-2017-5753** | Modern CPUs (Spectre v1) | Bounds Check Bypass (CWE-1037) | Speculative execution past conditional branch bounds checks leaves secret data footprints in CPU L1 data cache timing. | Compiler `lfence` speculation barriers, array index masking, browser Site Isolation, and CPU microcode updates. |
| **CVE-2017-5754** | Intel/ARM CPUs (Meltdown) | Rogue Data Cache Load (CWE-1037) | Out-of-order execution reads kernel memory before privilege bit fault is raised, leaking data via cache side channel. | Kernel Page Table Isolation (KPTI / KAISER) unmapping kernel memory from user-space page tables. |
| **CVE-2016-5195** | Linux Kernel (DirtyCow) | Copy-on-Write Race Condition (CWE-362) | Race between `madvise(MADV_DONTNEED)` and `/proc/self/mem` writes tricked `get_user_pages` into writing to read-only mmap pages. | Kernel commit `19be0eaffa3ac7d8eb6784ad9bdbc7d67ed8e619` introducing `FOLL_COW` tracking flag. |
| **CVE-2018-1000001** | GNU libc realpath() | Buffer Underflow (CWE-124) | When current working directory resolved to `(unreachable)` in unprivileged mount namespace, `getcwd()` lacked leading `/`, causing underflow. | Upgrade `glibc >= 2.27`; restrict unprivileged user namespaces (`kernel.unprivileged_userns_clone = 0`). |
| **CVE-2019-5736** | Docker runc | Host Binary Overwrite via `/proc/self/exe` | Container process replaced `/bin/sh` with `#!/proc/self/exe`, allowing container to open host `runc` binary file descriptor for writing upon exit. | Upgrade `runc >= 1.0.0-rc6` (clones `runc` into an anonymous `memfd_create()` sealed memory buffer before entering container). |
| **CVE-2019-14287** | Sudo | UID -1 Integer Conversion Bypass | Specifying `sudo -u#-1` or `-u#4294967295` bypassed `ALL, !root` user checks while `setresuid(-1)` left UID as 0 (root). | Upgrade `sudo >= 1.8.28`; avoid negative/exclusion rules (`!root`) in `/etc/sudoers`. |
| **CVE-2019-19781** | Citrix ADC / NetScaler | Path Traversal in Perl Template Engine | Unauthenticated `/vpns/../` path traversal reached internal Perl `Template Toolkit` scripts, allowing arbitrary template writing. | Apply Citrix patches and block `..` path sequences in Responder policy rules. |
| **CVE-2020-0601** | Windows CryptoAPI (CurveBall) | Elliptic Curve Parameter Spoofing (CWE-295) | `crypt32.dll` failed to verify that an X.509 certificate's explicit ECC generator point `G` matched the standard NIST curve generator. | Install January 2020 Windows Security Update; enforce pinned root CA parameters for explicit ECC certificates. |
| **CVE-2020-0796** | Windows SMBv3 (SMBGhost) | Integer Overflow in LZNT1 Compression | `srv2.sys` `SmbCompressionDecompress()` summed `OriginalCompressedSegmentSize` and `OffsetOrLength` without integer overflow checking. | Apply KB4551762; disable SMBv3 compression if unpatched (`DisableCompression = 1`). |
| **CVE-2020-1350** | Windows DNS Server (SIGRed) | 16-Bit Integer Overflow in SIG Record Parsing | Large DNS `SIG` response records (>64 KB over TCP) overflowed a 16-bit allocation size calculation in `dns.exe`. | Apply July 2020 patch; set `TcpReceivePacketSize` registry cap to `0xFF00`. |
| **CVE-2020-5902** | F5 BIG-IP TMUI | Path Traversal in Apache/Tomcat Proxy (`;`)  | Discrepancy between Apache `/tmui/login.jsp/..;/tmui/` path normalization and Tomcat semicolon parameter handling bypassed auth. | Upgrade BIG-IP; never expose TMUI management port on self-IPs or untrusted VLANs. |
| **CVE-2021-21972** | VMware vCenter Server | Unauthenticated TAR Archive Path Traversal | vSphere Client `vropspluginui` endpoint extracted uploaded `.tar` archives without sanitizing `../../` file entry paths. | Upgrade vCenter Server; isolate ESXi and vCenter management interfaces on air-gapped Tier-0 VLANs. |
| **CVE-2021-22205** | GitLab CE/EE (ExifTool) | DjVu Annotation Metadata Parsing Flaw | Uploaded image files were passed to `ExifTool` prior to authentication, which evaluated unescaped tokens in DjVu `ANTa` chunks. | Upgrade GitLab and `ExifTool >= 12.24`. |
| **CVE-2021-26084** | Atlassian Confluence | OGNL Expression Injection in Webwork | Velocity template rendered `queryString` value directly into an OGNL evaluation attribute without quoting. | Upgrade Confluence; restrict public exposure of internal knowledge bases behind Zero Trust / VPN. |
| **CVE-2021-34473** | Microsoft Exchange (ProxyShell) | Autodiscover URL Normalization SSRF | `/autodiscover/autodiscover.json?@foo.com/mapi/nspi/` stripped the prefix during URL rewriting, reaching backend PowerShell remoting. | Apply April/May 2021 Exchange Security Updates; monitor IIS logs for `/autodiscover/autodiscover.json` requests. |
| **CVE-2021-41773** | Apache HTTP Server 2.4.49 | URL Normalization Path Traversal (`.%2e/`) | `ap_normalize_path()` decoded `%2e` single-byte sequences insufficiently, allowing `/cgi-bin/.%2e/.%2e/etc/passwd` traversal. | Upgrade immediately to Apache `>= 2.4.51`; enforce `Require all denied` on `<Directory />` root block. |
| **CVE-2022-0185** | Linux Kernel File System Context | Integer Underflow in `legacy_parse_param` | In `fs/fs_context.c`, the bounds check `size + len + 2 > PAGE_SIZE` used unsigned subtraction `len > PAGE_SIZE - 2 - size`, underflowing when `size > 4094`. | Upgrade Linux kernel `>= 5.16.2`; disable unprivileged user namespaces (`CAP_SYS_ADMIN` in userns) where not needed. |
| **CVE-2022-1388** | F5 BIG-IP iControl REST | Hop-by-Hop `Connection: X-F5-Auth-Token` Bypass | Apache front-end stripped `X-F5-Auth-Token` listed in `Connection` header after auth check, causing Jetty back-end to fall back to local admin trust. | Upgrade BIG-IP; configure front-end proxies to sanitize all headers named in client `Connection:` headers prior to authentication. |
| **CVE-2022-21449** | Oracle Java 15-18 (Psychic Signatures) | ECDSA Zero Signature (`r=0, s=0`) Verification Bug | Java rewrite of ECDSA verification failed to reject signatures where `r = 0` or `s = 0`, causing math equations `0 == 0` to always validate! | Upgrade JDK to April 2022 CPU (`17.0.3`, `18.0.1`); always enforce `0 < r < n` and `0 < s < n` in ECDSA implementations. |
| **CVE-2022-22947** | Spring Cloud Gateway | SpEL Injection in Actuator Route Creation | Exposed `/actuator/gateway/routes` endpoint evaluated Spring Expression Language (`#{...}`) inside filter definitions. | Disable unauthenticated management actuators (`management.endpoints.web.exposure.include=health,info`) and upgrade Spring Cloud Gateway. |
| **CVE-2022-26134** | Atlassian Confluence | Uncaught OGNL Namespace Lookup Evaluation | `ActionChainResult` translated URI namespace paths using `TextParseUtil.translateVariables()`, evaluating `${...}` OGNL expressions. | Upgrade Confluence; enforce WAF rules blocking `${` in request URIs. |
| **CVE-2022-30190** | Microsoft MSDT (Follina) | MSHTML `ms-msdt:` URI Handler Invocation | Word documents referencing an external HTML template triggered `ms-msdt:/id PCWDiagnostic` URI handler without macro execution. | Apply June 2022 Windows cumulative updates; unregister `ms-msdt` URL protocol if unused. |
| **CVE-2022-3602** | OpenSSL 3.0.0-3.0.6 (Punycode) | 4-Byte Stack Buffer Overflow in X.509 Name Constraints | `ossl_a2ulabel()` Punycode decoding wrote up to 4 bytes `0x2E` (`.`) past stack buffer during certificate verification. | Upgrade to OpenSSL `>= 3.0.7`. |
| **CVE-2023-22809** | Sudo (`sudoedit`) | Editor Argument Injection via `SUDO_EDITOR` | User-supplied `--` separator inside `EDITOR`/`SUDO_EDITOR` environment variable tricked `sudoedit` into opening unauthorized files. | Upgrade `sudo >= 1.9.12p2`; add `Defaults!SUDOEDIT env_delete+="SUDO_EDITOR VISUAL EDITOR"` to `/etc/sudoers`. |
| **CVE-2023-2640 & CVE-2023-32629** | Ubuntu Linux Kernel (GameOver(lay)) | OverlayFS SUID File Copy-Up Capability Bypass | Ubuntu-specific OverlayFS patches failed to strip security capabilities/SUID bits correctly during unprivileged userns copy-up. | Update Ubuntu kernel packages; set `kernel.unprivileged_userns_clone=0` on multi-tenant servers. |
| **CVE-2023-27350** | PaperCut MF/NG | SetupWizard Authentication Bypass | `SetupCompleted` session state tampering allowed unauthenticated users to re-enter the initial setup wizard and run print scripts. | Upgrade PaperCut `>= 22.0.9`; restrict port `9191/9192` to internal administration networks. |
| **CVE-2023-3519** | Citrix NetScaler ADC/Gateway | Unauthenticated Stack Buffer Overflow in SAML/AAA | SAML SP/IdP form parser copied oversized HTTP parameters into a fixed-size stack buffer without bounds checking. | Upgrade NetScaler firmware; enable stack protector compiler flags across all native network daemons. |
| **CVE-2023-36884** | Windows Search & Office | Remote Document Parsing Handling Flaw | Specially crafted Office documents invoked legacy Windows Search/IE rendering handlers. | Enable Attack Surface Reduction (ASR) rule `Block all Office applications from creating child processes`. |
| **CVE-2023-46604** | Apache ActiveMQ | OpenWire Protocol ClassInfo Deserialization | `BaseDataStreamMarshaller.createThrowable()` instantiated arbitrary classes present on the classpath (`ClassPathXmlApplicationContext`) with a string constructor. | Upgrade ActiveMQ `>= 5.18.3`; restrict class instantiation in custom marshallers to `Throwable` subclasses via `isAssignableFrom()`. |
| **CVE-2023-4863** | libwebp (Chrome, Firefox, Electron) | Huffman Lookup Table Heap Buffer Overflow | `BuildHuffmanTable()` allocated a fixed buffer for malformed WebP lossless Huffman trees, overflowing heap memory when rendering an image. | Update `libwebp >= 1.3.2`, browsers, Electron apps, and server-side image processors (`Pillow`, `sharp`). |
| **CVE-2023-4966** | Citrix NetScaler (Citrix Bleed) |  `snprintf` Return Value Out-of-Bounds Memory Read | `ns_aaa_oauthrp_send_openid_config()` used the return value of `snprintf()` (which returns how many bytes *would* have been written, not actual written bytes) to send HTTP response data, leaking session tokens from memory. | Upgrade NetScaler AND terminate all active ICA/PCoIP/AAA sessions (`kill icaconnection -all`). Never use `snprintf` return value as buffer length without clamping to `sizeof(buf) - 1`! |
| **CVE-2024-1709** | ConnectWise ScreenConnect | Path Normalization SetupWizard Re-Entry | Requesting `/SetupWizard.aspx/anything` caused ASP.NET sub-path routing to invoke `SetupWizard.aspx` while bypassing the URL authentication filter that only matched exact `/SetupWizard.aspx`. | Upgrade ScreenConnect `>= 23.9.8`; normalize paths before applying security middleware filters. |
| **CVE-2024-21626** | runc (Leaky Vessels) | Working Directory File Descriptor Leak (`chdir` to `/proc/self/fd/N`) | `runc` leaked an internal file descriptor pointing to the host's `/sys/fs/cgroup` into the container initialization step, allowing `WORKDIR /proc/self/fd/7/../../..` to escape to the host filesystem. | Upgrade `runc >= 1.1.12` (ensures `O_CLOEXEC` on all host directory descriptors and verifies `getcwd()` is inside container rootfs). |
| **CVE-2024-21762** | Fortinet FortiOS SSL-VPN | Out-of-Bounds Write in Chunked HTTP Transfer-Encoding Parser | `sslvpnd` failed to validate chunk length markers properly when parsing malformed HTTP chunked requests. | Upgrade FortiOS; disable SSL-VPN in favor of IPsec IKEv2 with certificate auth where possible. |
| **CVE-2024-23897** | Jenkins CLI (`args4j`) | `@filename` Argument Expansion Arbitrary File Read | `args4j` library used by Jenkins CLI replaced `@/path/to/file` arguments with the contents of that file on the Jenkins controller filesystem, leaking secrets in error messages. | Upgrade Jenkins `>= 2.442` / LTS `>= 2.426.3` or disable the CLI over HTTP/SSH via startup script. |
| **CVE-2024-24919** | Check Point Security Gateways | VPN Information Disclosure via Path Traversal | Unauthenticated path traversal on the Remote Access VPN portal allowed reading local files (`/etc/shadow`) when password-only legacy accounts existed. | Install Check Point May 2024 Hotfix and remove all local password-only VPN accounts. |
| **CVE-2024-27198** | JetBrains TeamCity | Alternative Path Authentication Bypass (`;/*.jsp`) | `res.sendRedirect` handling combined with `;` matrix parameter routing allowed hitting internal administrative controllers via `/hax?jsp=/app/rest/users;.jsp`. | Upgrade TeamCity `>= 2023.11.4`; block `;` in URL paths at reverse proxy. |
| **CVE-2024-3400** | Palo Alto Networks PAN-OS GlobalProtect | `SESSID` Cookie Path Traversal & Telemetry Command Injection | Session ID cookie value (`SESSID=/../../../var/appweb/sslvpndocs/...`) created arbitrary empty files whose filenames were later interpolated into a cron shell script. | Apply PAN-OS hotfixes; validate all session identifiers against a strict UUID/hex regex (`^[a-f0-9-]{36}$`) before filesystem operations. |
| **CVE-2024-38063** | Windows TCP/IP Stack (`tcpip.sys`) | IPv6 Packet Reassembly Integer Underflow | Processing specially crafted IPv6 packets with Destination Options and Fragment headers triggered an integer underflow in `Ipv6pProcessOptions()`. | Install August 2024 Windows Security Updates; disable IPv6 on network interfaces where IPv6 is not actively managed. |
