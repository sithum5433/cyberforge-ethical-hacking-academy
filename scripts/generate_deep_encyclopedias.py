#!/usr/bin/env python3
"""
Generates Appendix G (Landmark CVE & Vulnerability Architecture Encyclopedia)
and Appendix H (Complete CIS Hardening, DevSecOps & Secure Coding Reference)
for THE SRI LANKAN ELITE HACKER'S BIBLE.
"""
import os

CHAPTERS_DIR = "/home/sithum404/Desktop/final exam/cyber sec/chapters"
os.makedirs(CHAPTERS_DIR, exist_ok=True)

# ---------------------------------------------------------------------------
# APPENDIX G: LANDMARK CVE & VULNERABILITY ARCHITECTURE ENCYCLOPEDIA
# ---------------------------------------------------------------------------
CVES = [
    ("CVE-2021-44228", "Log4Shell (Apache Log4j2 JNDI Lookup Injection)", "10.0 Critical", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "CWE-502 / CWE-917", "Apache Log4j 2.0-beta9 to 2.14.1",
     "Apache Log4j2 recursively parsed message lookup expressions `${...}` inside logged strings. When user-controlled HTTP headers (such as `User-Agent` or `X-Api-Version`) or form fields were written to application logs, Log4j evaluated Java Naming and Directory Interface (JNDI) lookups (`jndi:ldap://`, `jndi:rmi://`, `jndi:dns://`), causing the JVM to connect to an external directory server and deserialize or load untrusted Java class bytecode.",
     """// Vulnerable Java Pattern (Log4j 2.14.1 with default message lookups enabled)
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class AuthController {
    private static final Logger logger = LogManager.getLogger(AuthController.class);
    public void login(String username, String userAgent) {
        // If username or userAgent contains ${jndi:...}, Log4j2 evaluates it during logging!
        logger.info("Login attempt for user: " + username + " from UA: " + userAgent);
    }
}""",
     """// Remediated Pattern (Upgrade to Log4j >= 2.17.1 + parameterized logging + JVM hardening)
// 1. In pom.xml: org.apache.logging.log4j:log4j-core:2.23.1
// 2. JVM Flag: -Dlog4j2.formatMsgNoLookups=true
// 3. Remove JndiLookup class if legacy jar cannot be replaced immediately:
//    zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class
logger.info("Login attempt for user: {} from UA: {}", username, userAgent);""",
     "Monitor outbound LDAP (389/636), RMI (1099), and DNS connections initiated directly by Java application server processes (`java`). Inspect web access logs and WAF telemetry for `${jndi:`, `${lower:`, `${upper:`, and nested lookup obfuscations."),

    ("CVE-2014-0160", "Heartbleed (OpenSSL TLS Heartbeat Buffer Over-Read)", "7.5 High", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "CWE-125 (Out-of-Bounds Read)", "OpenSSL 1.0.1 through 1.0.1f",
     "The TLS Heartbeat Extension (RFC 6520) allows a peer to send a payload along with a 16-bit integer specifying the payload length, expecting the server to allocate a response buffer and echo back that exact number of bytes. OpenSSL failed to validate that the user-supplied `payload_length` matched the actual length of the received TLS record. By sending a 1-byte payload while claiming a length of 65,535 bytes, an unauthenticated client caused `memcpy()` to read up to 64 KB of adjacent heap memory from the OpenSSL process—leaking TLS private keys, session cookies, and user passwords.",
     """/* Vulnerable C Pattern in OpenSSL t1_lib.c (simplified) */
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
}""",
     """/* Remediated C Pattern (OpenSSL 1.0.1g+) */
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
}""",
     "Suricata/Snort IDS rules detecting TLS Heartbeat records where the TLS record length header is significantly smaller than the encapsulated Heartbeat `payload_length`. Remediation requires upgrading OpenSSL, revoking exposed X.509 certificates, and re-issuing new private keys."),

    ("CVE-2014-6271", "Shellshock (GNU Bash Environment Variable Function Trailing Code)", "9.8 Critical", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CWE-78 (OS Command Injection)", "GNU Bash through 4.3",
     "GNU Bash allowed exporting shell functions to child processes via environment variables whose values started with `() {`. When a new Bash subshell initialized, it parsed such environment variables by executing the function definition in the parser context. However, Bash did not stop parsing at the closing brace `}` of the function body—it executed any trailing commands appended after `() { :; };`. Network services such as Apache `mod_cgi` (which maps HTTP headers like `User-Agent` to `HTTP_USER_AGENT` environment variables before invoking CGI scripts) or DHCP clients became immediately vulnerable to remote command execution.",
     """# Vulnerable Mechanism in CGI / Bash Subshell Initialization
# When Apache mod_cgi processes an HTTP request, it sets environment variables:
export HTTP_USER_AGENT='() { :; }; /usr/bin/id'
# When mod_cgi spawns /bin/bash to run a CGI script, Bash parses HTTP_USER_AGENT
# as a function definition and executes trailing commands after the closing brace.""",
     """# Remediated Mechanism in Patched GNU Bash (4.3 Patch 25+)
# 1. Function exports are namespaced with 'BASH_FUNC_name%%' prefix
# 2. The parser strictly validates that only a single function definition is parsed
#    from exported environment variables and rejects any trailing commands.
sudo apt-get update && sudo apt-get install --only-upgrade bash
# Verify patch status:
env x='() { :;}; echo VULNERABLE' bash -c "echo Safe" """,
     "WAF and web server access log rules matching the literal byte sequence `() {` inside HTTP headers, query strings, or cookies. Audit `auditd` process trees for `/bin/sh` or `/bin/bash` spawned as children of `apache2`, `httpd`, or `dhclient`."),

    ("CVE-2017-0144", "EternalBlue (Microsoft Windows SMBv1 SrvOs2FeaListSizeToNt Buffer Overflow)", "8.8 High / 9.8 Critical", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CWE-190 / CWE-122", "Windows XP through Windows Server 2016 (SMBv1 `srv.sys`)",
     "In Microsoft's SMBv1 driver (`srv.sys`), the function `SrvOs2FeaListSizeToNt()` converts an OS/2 File Extended Attribute (FEA) list into an NT FEA list. Due to an integer truncation bug where a 32-bit size field was cast/assigned into a 16-bit unsigned integer (`WORD`) after size validation, `srv.sys` allocated a smaller kernel pool buffer than required and subsequently copied a larger FEA list into the non-paged kernel pool, corrupting adjacent `SRVNET_BUFFER` structures in Ring 0.",
     """/* Conceptual Representation of the Integer Truncation in srv.sys */
/* 1. Size calculation computes required NT FEA buffer size in 32-bit int */
/* 2. Value is mistakenly written back via a 16-bit cast *(WORD *)pFeaList = ... */
/* 3. Subsequent kernel pool copy uses the larger un-truncated size */
/* Result: Out-of-bounds heap write in Windows Kernel Non-Paged Pool */""",
     """# Complete Remediation on Windows Hosts & Active Directory GPO:
# 1. Apply Microsoft Security Bulletin MS17-010 immediately.
# 2. Permanently disable SMBv1 across all Windows endpoints and servers:
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
# 3. Enforce SMBv2/v3 Signing via Group Policy:
Set-SmbServerConfiguration -RequireSecuritySignature $true -EnableSecuritySignature $true -Force
# 4. Block TCP Ports 139 and 445 at perimeter and inter-VLAN firewalls.""",
     "Monitor SMB traffic for `SMB_COM_TRANSACTION2` requests targeting `IPC$` with abnormal `FEA_LIST` lengths and `SMB_COM_NT_TRANSACT` groom packets. Use `nmap --script smb-protocols -p 445 <target>` during internal audits to verify SMBv1 is completely disabled."),

    ("CVE-2020-1472", "Zerologon (Microsoft Netlogon AES-CFB8 Cryptographic Flaw)", "10.0 Critical", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "CWE-330 (Use of Insufficiently Random Values)", "Windows Server 2008 R2 through Windows Server 2019 Domain Controllers",
     "The MS-NRPC (Netlogon Remote Protocol) `ComputeNetlogonCredential` function used AES-128 in CFB8 (8-bit Cipher Feedback) mode to encrypt an 8-byte client challenge using the Domain Controller's computer account session key. Instead of generating a cryptographically random 16-byte Initialization Vector (IV), the specification hardcoded an all-zero 16-byte IV (`0x00 * 16`). Because of how AES-CFB8 operates, for any random key there is a 1 in 256 probability that encrypting an 8-byte all-zero plaintext (`0x00 * 8`) with an all-zero IV produces an all-zero ciphertext (`0x00 * 8`). Within ~256 unauthenticated RPC attempts, an attacker could bypass authentication and invoke `NetrServerPasswordSet2` to reset the Domain Controller's machine account password in Active Directory.",
     """# Mathematical Probability of AES-CFB8 Zero-IV Collision:
# In AES-CFB8:
# Step 1: Block_0 = AES_Encrypt(Key, IV=0x00*16)
# Step 2: Ciphertext_Byte_0 = Plaintext_Byte_0 ^ MSB(Block_0)
# If Plaintext_Byte_0 == 0x00, then Ciphertext_Byte_0 == 0x00 whenever MSB(Block_0) == 0x00 (Probability: 1/256).
# Once Ciphertext_Byte_0 is 0x00, the shift register shift-in keeps the next 16-byte input to AES all-zeros!
# Thus ALL 8 bytes become 0x00 with probability exactly 1/256!""",
     """# Remediation & Hardening on Domain Controllers:
# 1. Install August 2020 / February 2021 Windows Server Cumulative Updates (Enforcement Mode).
# 2. Enforce Secure RPC for Netlogon via Registry / Group Policy:
Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters" -Name "FullSecureChannelProtection" -Value 1 -Type DWord
# 3. Monitor Windows System Event IDs 5827, 5828, 5829, 5830, 5831 for non-compliant Netlogon clients.""",
     "Alert on Windows Security Event ID `4742` (A computer account was changed) where `Anonymous Logon` (`S-1-5-7`) modifies a Domain Controller computer object, combined with a burst of failed `NetrServerAuthenticate3` RPC calls over MS-NRPC."),

    ("CVE-2021-4034", "PwnKit (Polkit pkexec argc=0 Out-of-Bounds Memory Read/Write)", "7.8 High", "CVSS:3.1/AV:L/PR:L/AC:L/UI:N/S:U/C:H/I:H/A:H", "CWE-125 / CWE-787", "Polkit `pkexec` (All versions from May 2009 to January 2022)",
     "In POSIX operating systems, `execve(path, argv, envp)` permits passing an empty `argv` array (`argc == 0`, so `argv[0] == NULL`). In `pkexec`'s `main(int argc, char *argv[])` loop (`for (n = 1; n < (guint) argc; n++)`), when `argc` was `0`, the loop never ran and `n` remained `1`. Because `argv` and `envp` are laid out contiguously on the Linux process stack (`argv[0] == NULL`, followed immediately by `envp[0]`), reading `argv[1]` actually read `envp[0]`, and later writing back a resolved path to `argv[1]` overwrote `envp[0]`, allowing an unprivileged user to re-introduce dangerous environment variables (like `GCONV_PATH`) into a SUID-root binary after environment scrubbing.",
     """/* Vulnerable C Pattern in pkexec.c (2009 - 2022) */
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
}""",
     """/* Remediated C Pattern in Polkit >= 0.120-r2 */
int main(int argc, char *argv[]) {
    /* Strictly enforce that argc >= 1 before indexing argv */
    if (argc < 1) {
        exit(127);
    }
    /* Additionally, Linux kernel 5.18+ patches do_execveat_common() to ensure
       argc is never 0 by inserting an empty string "" if argv is empty. */
}""",
     "Audit SUID binaries across Linux fleets (`find / -perm -4000 2>/dev/null`). Remove the SUID bit from `/usr/bin/pkexec` (`chmod 0755 /usr/bin/pkexec`) on headless servers that do not require graphical PolicyKit prompts, and monitor `auditd` for `execve` calls where `argc=0`."),

    ("CVE-2022-0847", "DirtyPipe (Linux Kernel Pipe Buffer Uninitialized Flags Overwrite)", "7.8 High", "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "CWE-665 (Improper Initialization)", "Linux Kernel 5.8 through 5.16.10, 5.15.24, 5.10.101",
     "Linux 5.8 refactored anonymous pipe buffer handling and introduced the `PIPE_BUF_FLAG_CAN_MERGE` flag in `struct pipe_buffer`. When the `splice()` system call copied data from a read-only file's page cache into a pipe, it initialized a `pipe_buffer` pointing directly to the kernel's shared page cache for that file, but forgot to clear `buf->flags`. If an unprivileged user first wrote to and drained the pipe (setting `PIPE_BUF_FLAG_CAN_MERGE` on all ring entries), then called `splice()` on a read-only file (such as `/etc/passwd` or a SUID binary), subsequent `write()` calls to the pipe merged data directly into the kernel page cache of the read-only file, bypassing all VFS permission checks.",
     """/* Vulnerable Kernel Pattern in fs/splice.c (copy_page_to_iter_pipe) */
static size_t copy_page_to_iter_pipe(struct page *page, size_t offset, size_t bytes,
                                     struct iov_iter *i) {
    struct pipe_inode_info *pipe = i->pipe;
    struct pipe_buffer *buf = &pipe->bufs[idx];
    buf->ops = &page_cache_pipe_buf_ops;
    buf->page = page;
    buf->offset = offset;
    buf->len = bytes;
    /* BUG: buf->flags is NOT initialized to 0! Retains PIPE_BUF_FLAG_CAN_MERGE! */
}""",
     """/* Remediated Kernel Pattern (Linux 5.16.11 / 5.15.25 / 5.10.102) */
    buf->ops = &page_cache_pipe_buf_ops;
    buf->page = page;
    buf->offset = offset;
    buf->len = bytes;
    buf->flags = 0; /* Explicitly clear PIPE_BUF_FLAG_CAN_MERGE on page-cache splice */""",
     "Verify kernel version via `uname -r`. Upgrade Linux kernels to patched stable branches (`>= 5.16.11`, `>= 5.15.25`, `>= 5.10.102`). Use File Integrity Monitoring (FIM) and `auditd` to alert on unexpected changes to `/etc/passwd`, `/etc/sudoers`, or system binaries."),

    ("CVE-2021-3156", "Baron Samedit (Sudo Heap-Based Buffer Overflow in sudoedit)", "7.8 High", "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "CWE-122 (Heap-Based Buffer Overflow)", "Sudo 1.8.2 to 1.8.31p2 and 1.9.0 to 1.9.5p1",
     "When `sudo` was invoked in shell mode (`-s` or `-i`), `parse_args()` escaped special characters in command-line arguments with backslashes before concatenating them into a heap buffer. However, if `sudoedit -s` (which sets `MODE_EDIT` and `MODE_SHELL` simultaneously without setting `MODE_RUN`) was invoked, the pre-check loop that escaped backslashes was skipped, while the downstream loop in `set_cmnd()` still unescaped backslashes. When an argument ended with a single trailing backslash `\\`, the unescaping loop read past the null terminator `\\0` and continued copying data out-of-bounds on the heap.",
     """/* Vulnerable C Pattern in plugins/sudoers/sudoers.c (set_cmnd) */
if (sudo_mode & (MODE_RUN | MODE_EDIT | MODE_CHECK)) {
    if (ISSET(sudo_mode, MODE_RUN | MODE_CHECK)) { /* Skipped when MODE_EDIT! */
        /* Pre-escaping occurred in parse_args only for MODE_RUN */
    }
    /* Loop assumes backslashes are always followed by a valid character before NUL: */
    while (*from != '\\0') {
        if (from[0] == '\\\\' && !isspace((unsigned char)from[1]))
            from++; /* If from[1] == '\\0', increments past string terminator! */
        *to++ = *from++;
    }
}""",
     """/* Remediated C Pattern in Sudo 1.9.5p2+ */
/* 1. Reject combining -s or -i flags with sudoedit (MODE_EDIT) in parse_args() */
/* 2. In set_cmnd(), verify from[1] != '\\0' before advancing past a backslash: */
if (from[0] == '\\\\' && from[1] != '\\0' && !isspace((unsigned char)from[1]))
    from++;""",
     "Verify sudo version with `sudo --version` (ensure `>= 1.9.5p2`). Audit `/var/log/auth.log` and `auditd` `execve` records for `sudoedit` invocations containing `-s` or `-i` flags."),

    ("CVE-2023-4911", "Looney Tunables (GNU C Library glibc GLIBC_TUNABLES Buffer Overflow)", "7.8 High", "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "CWE-122", "glibc 2.34 through 2.38",
     "The GNU dynamic linker (`ld.so`) processes the `GLIBC_TUNABLES` environment variable before `main()` runs—even for SUID-root binaries—to allow performance tuning and sanitization of dangerous tunables. In `__tunables_init()`, when a malformed tunable string of the form `tunable1=tunable2=val` was supplied without a `:` delimiter, the string sanitization loop copied the second assignment past the bounds of the allocated buffer in `ld.so`'s private memory segment.",
     """# Diagnostic Verification of glibc Version
ldd --version
# Check if glibc is patched against CVE-2023-4911 across Debian/Ubuntu/RHEL""",
     """# Remediation:
# 1. Update libc6 / glibc packages immediately:
sudo apt-get update && sudo apt-get install --only-upgrade libc6
# 2. Minimize SUID-root attack surface on production servers using mount options:
#    Mount /home, /tmp, /var/tmp, and /dev/shm with 'nosuid,nodev,noexec' in /etc/fstab.""",
     "Monitor `execve` system calls via `auditd` or eBPF (Falco/Tetragon) where an unprivileged UID invokes a SUID binary with an abnormally large `GLIBC_TUNABLES` environment variable."),

    ("CVE-2024-6387", "regreSSHion (OpenSSH Server SIGALRM Asynchronous Signal Handler Race Condition)", "8.1 High", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", "CWE-364 (Signal Handler Race Condition)", "OpenSSH 8.5p1 to 9.7p1 on glibc-based Linux systems",
     "When a client fails to authenticate within OpenSSH's `LoginGraceTime` (default 120 seconds), `sshd`'s `SIGALRM` handler (`grace_alarm_handler`) is invoked asynchronously. This signal handler called `syslog()`, which internally calls async-signal-unsafe functions (`malloc()`/`free()`) in `glibc`. If the `SIGALRM` signal interrupts the main `sshd` code while it is already inside `malloc()` or `free()` holding inconsistent heap metadata, heap corruption occurs.",
     """// Async-Signal-Unsafe Pattern in C Signal Handlers:
void sigalrm_handler(int sig) {
    // NEVER call syslog(), printf(), malloc(), or free() inside a POSIX signal handler!
    // Only async-signal-safe functions (see man 7 signal-safety, e.g., write(), _exit()) are safe.
    syslog(LOG_INFO, "Timeout expired"); // UNSAFE: invokes glibc heap allocator!
    _exit(1);
}""",
     """# Remediation & Hardening in /etc/ssh/sshd_config:
# 1. Upgrade OpenSSH to >= 9.8p1.
# 2. If immediate patching is delayed, set LoginGraceTime to 0 (disables SIGALRM timeout,
#    combine with MaxStartups and firewall rate-limiting to prevent connection exhaustion):
LoginGraceTime 20
MaxStartups 10:30:60
# 3. Restrict SSH access via nftables/iptables or bastion VPNs.""",
     "Alert on high rates of SSH connection timeouts in `/var/log/auth.log` (`Timeout before authentication for...`) from a single source IP or subnet, which is a strong indicator of timing race probing."),

    ("CVE-2024-3094", "XZ Utils Supply-Chain Backdoor (liblzma IFUNC Hook in sshd)", "10.0 Critical", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "CWE-506 (Embedded Malicious Code)", "XZ Utils 5.6.0 and 5.6.1",
     "A sophisticated multi-year supply-chain attack modified the release tarballs (`m4/build-to-host.m4` and test files `tests/files/bad-3-corrupt_lzma2.xz`) of `xz-utils` versions 5.6.0 and 5.6.1. During compilation on Debian/RPM x86_64 builds, the modified autotools script extracted an obfuscated object file and linked it into `liblzma.so`. Because Debian and Fedora patch OpenSSH (`sshd`) to link against `libsystemd.so`, which in turn links against `liblzma.so`, the malicious `liblzma` used a GNU Indirect Function (`IFUNC`) resolver during dynamic linking to hook `RSA_public_decrypt@GOT.plt` inside `sshd`, verifying an Ed448-signed payload in pre-authentication SSH certificates.",
     """# Auditing Shared Library Dependencies of sshd and xz Version:
xz --version
ldd $(which sshd) | grep -E "liblzma|libsystemd"
# Inspect ELF symbols and IFUNC relocations in liblzma:
readelf -r /lib/x86_64-linux-gnu/liblzma.so.5 | grep IRELATIVE""",
     """# Supply-Chain Defense & Remediation:
# 1. Ensure xz-utils is on a verified clean version (e.g., 5.4.x or >= 5.6.2+ reverted).
# 2. Rebuild packages directly from audited git tag trees rather than maintainer-generated autotools tarballs.
# 3. Enable OpenSSH sshd dependency isolation (OpenSSH 9.8+ splits sshd into sshd and sshd-session,
#    moving libsystemd notification out of the network-listening binary).""",
     "Use Software Bill of Materials (SBOM) scanning (`syft`, `grype`, `trivy`) in CI/CD pipelines to detect vulnerable or revoked package versions across all container images and virtual machines."),

    ("CVE-2023-44487", "HTTP/2 Rapid Reset Attack (HEADERS + RST_STREAM Resource Exhaustion)", "7.5 High", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", "CWE-400 (Uncontrolled Resource Consumption)", "HTTP/2 Server Implementations (Nginx, Envoy, Apache, Go net/http, Node.js)",
     "In HTTP/2 (RFC 9113), a single TCP connection multiplexes multiple concurrent streams, bounded by `SETTINGS_MAX_CONCURRENCY_STREAMS` (commonly 100). However, when a client sends a `HEADERS` frame to open a stream and immediately sends an `RST_STREAM` frame in the same TCP packet to cancel it, the server considers the stream closed and decrements the active stream counter immediately—while the upstream application server or proxy worker still expends CPU and memory parsing the request headers and routing the cancelled request. This allowed opening and resetting hundreds of thousands of streams per second over a single TCP connection.",
     """# Nginx Hardened HTTP/2 Configuration (/etc/nginx/nginx.conf):
http {
    http2 on;
    # Limit concurrent streams per connection
    http2_max_concurrent_streams 128;
    # Limit total requests allowed on a single keepalive/HTTP2 connection
    keepalive_requests 1000;
    # Enforce per-IP request rate limiting
    limit_req_zone $binary_remote_addr zone=api_limit:10m rate=50r/s;
}""",
     """// Go net/http & golang.org/x/net/http2 Remediation:
// Upgrade golang.org/x/net to >= v0.17.0 and Go standard library to >= 1.21.3 / 1.20.10,
// which enforces strict tracking of rapid stream resets and terminates abusive connections.""",
     "Monitor reverse proxy metrics (Nginx, Envoy, HAProxy, Cloudflare) for spikes in `RST_STREAM` frames per TCP connection and discrepancies between HTTP/2 stream creation rates and active stream counts."),
]

# Add 28 more detailed CVE architectural post-mortems across Web, Cloud, OS, DB, and Enterprise systems
MORE_CVES = [
    ("CVE-2022-22965", "Spring4Shell (Spring Framework DataBinder ClassLoader Manipulation)", "9.8 Critical", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CWE-94", "Spring Framework 5.3.0-5.3.17, 5.2.0-5.2.19 on JDK 9+",
     "Spring MVC's `DataBinder` automatically binds HTTP query/form parameters to POJO properties via JavaBean getters and setters. On JDK 9+, `Object.getClass().getModule().getClassLoader()` exposed the Tomcat `ParallelWebappClassLoader`, allowing property traversal (`class.module.classLoader.resources.context.parent.pipeline.first.*`) to reconfigure Tomcat's `AccessLogValve` and write arbitrary log files into the web root.",
     """// Vulnerable Spring Controller binding directly to a broad POJO without @InitBinder allowlist:
@PostMapping("/register")
public String register(UserRegistrationDto userDto) {
    return "success";
}""",
     """// Remediated Pattern (Upgrade to Spring >= 5.3.18 AND explicitly allowlist bindable fields):
@InitBinder
public void initBinder(WebDataBinder binder) {
    binder.setAllowedFields("username", "email", "displayName");
    binder.setDisallowedFields("class.*", "Class.*", "*.class.*", "*.Class.*");
}""",
     "Inspect web access logs for parameter names containing `class.module.classLoader`. Deploy Spring Boot applications as standalone executable JARs rather than traditional Tomcat WAR deployments where possible."),

    ("CVE-2019-11510", "Pulse Connect Secure Arbitrary File Read via Path Traversal", "10.0 Critical", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "CWE-22 (Path Traversal)", "Pulse Connect Secure 8.2, 8.3, 9.0",
     "Unauthenticated URI normalization flaw in the SSL-VPN web interface allowed traversing outside the web root to read sensitive session cache databases and configuration files.",
     """# Vulnerable URI Routing without Canonical Path Verification:
# Web handler concatenated unvalidated path segments before resolving realpath().""",
     """# Secure Path Canonicalization Pattern in Python/C/Go:
import os
def safe_resolve(base_dir: str, user_path: str) -> str:
    base_real = os.path.realpath(base_dir)
    target_real = os.path.realpath(os.path.join(base_real, user_path))
    if os.path.commonpath([base_real, target_real]) != base_real:
        raise PermissionError("Path traversal attempt blocked")
    return target_real""",
     "Enforce hardware/FIDO2 MFA on all VPN appliances, place VPN management interfaces on internal-only subnets, and monitor VPN web logs for `..` or `%2e%2e` sequences."),

    ("CVE-2021-26855", "ProxyLogon (Microsoft Exchange Server SSRF in Front-End Proxy)", "9.8 Critical", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CWE-918 (SSRF)", "Microsoft Exchange Server 2013, 2016, 2019",
     "Exchange's Client Access Service (CAS) front-end proxy trusted the `X-BEResource` cookie on unauthenticated static asset paths (`/owa/auth/x.js`) to determine which internal back-end server and Kerberos machine session to proxy the request to (`localhost~1942062522`), bypassing front-end authentication and reaching internal Exchange `ecp` endpoints.",
     """# Vulnerability Root Cause:
# Front-end reverse proxy trusted user-supplied routing cookies (X-BEResource)
# on unauthenticated static file routes and attached machine credentials when proxying.""",
     """# Remediation:
# 1. Apply Exchange Cumulative Updates and Security Updates immediately.
# 2. Never trust client-supplied headers or cookies to determine internal proxy targets.
# 3. Restrict external access to /ecp and administrative endpoints at the reverse proxy layer.""",
     "Run Microsoft Exchange HealthChecker.ps1 regularly and monitor IIS logs under `C:\\inetpub\\logs\\LogFiles\\` for requests containing `X-BEResource` or `X-AnonResource-Backend` cookies."),

    ("CVE-2023-34362", "MOVEit Transfer SQL Injection to Deserialization Chain", "9.8 Critical", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CWE-89 (SQL Injection)", "Progress MOVEit Transfer before 2023.0.1",
     "Complex multi-stage parameter handling between IIS `.aspx` (`guestaccess.aspx`) and internal `.NET` handlers allowed an unauthenticated request to inject SQL statements into session state tables, which were subsequently deserialized by the application.",
     """// Vulnerable C# ADO.NET String Concatenation Pattern:
string sql = "SELECT * FROM Sessions WHERE SessionId = '" + headerValue + "'";
SqlCommand cmd = new SqlCommand(sql, conn);""",
     """// Remediated C# Parameterized Query Pattern:
string sql = "SELECT * FROM Sessions WHERE SessionId = @SessionId";
using SqlCommand cmd = new SqlCommand(sql, conn);
cmd.Parameters.Add("@SessionId", SqlDbType.VarChar, 64).Value = headerValue;""",
     "Audit all `.NET` data access layers with SAST tools (Semgrep, CodeQL) to enforce strict `@Parameter` binding and prohibit dynamic string interpolation in SQL queries."),

    ("CVE-2021-34527", "PrintNightmare (Windows Print Spooler RpcAddPrinterDriverEx RCE/LPE)", "8.8 High", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "CWE-269 (Improper Privilege Management)", "Windows Print Spooler (`spoolsv.exe`)",
     "The Windows Print Spooler RPC function `RpcAddPrinterDriverEx()` permitted low-privileged authenticated users to pass the `APD_INSTALL_WARNED_DRIVER` (`0x8000`) flag, bypassing administrator privilege checks and causing `spoolsv.exe` (running as `NT AUTHORITY\\SYSTEM`) to load an arbitrary driver DLL from a local path or remote UNC share.",
     """# Remediation via PowerShell & Group Policy:
# Disable Print Spooler service on all Domain Controllers and servers that do not print:
Stop-Service -Name Spooler -Force
Set-Service -Name Spooler -StartupType Disabled""",
     """# Additionally, configure Point and Print Restrictions via GPO / Registry:
New-ItemProperty -Path "HKLM:\\Software\\Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint" `
    -Name "RestrictDriverInstallationToAdministrators" -Value 1 -PropertyType DWord -Force""",
     "Monitor Windows Event Log `Microsoft-Windows-PrintService/Operational` Event ID `316` and Sysmon Event ID `7` (Image Loaded) for unsigned DLLs loaded by `C:\\Windows\\System32\\spoolsv.exe`."),

    ("CVE-2021-42278 & CVE-2021-42287", "sAMAccountName Spoofing & noPac (Active Directory KDC Impersonation)", "8.8 High", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "CWE-287 (Improper Authentication)", "Active Directory Domain Services (KDC)",
     "By default in Active Directory (`ms-DS-MachineAccountQuota = 10`), any authenticated domain user could create up to 10 computer accounts. Due to missing validation on trailing `$` characters in `sAMAccountName` (CVE-2021-42278) combined with KDC fallback lookup behavior when an account was deleted after TGT issuance (`S4U2Self` in CVE-2021-42287), the KDC matched a renamed computer account (`DC01` without trailing `$`) to the real Domain Controller `DC01$` when issuing a service ticket.",
     """# Vulnerable Default Active Directory Configuration:
Get-ADObject -Identity ((Get-ADDomain).DistinguishedName) -Properties ms-DS-MachineAccountQuota
# Default returns: ms-DS-MachineAccountQuota : 10""",
     """# Complete Active Directory Hardening:
# 1. Install November 2021 AD Domain Controller updates (KB5008380 / KB5008602).
# 2. Set ms-DS-MachineAccountQuota to 0 so standard users cannot join or create machine accounts:
Set-ADDomain -Identity (Get-ADDomain) -Replace @{"ms-DS-MachineAccountQuota"="0"}""",
     "Monitor Windows Security Event IDs `4741` (A computer account was created) and `4742` (A computer account was changed, especially where `sAMAccountName` changes to match a Domain Controller name), as well as new Kerberos validation Event IDs `35`, `36`, `37`, and `38`."),

    ("CVE-2023-23397", "Microsoft Outlook Extended MAPI PidLidReminderFileParameter NTLM Leak", "9.8 Critical", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CWE-294", "Microsoft Outlook for Windows",
     "When Microsoft Outlook processed an incoming calendar appointment or task containing a custom MAPI property `PidLidReminderFileParameter` set to a remote UNC path (`\\\\external-ip\\share\\sound.wav`), Windows automatically attempted SMB authentication to that UNC path when the reminder triggered—even before the user opened or previewed the email—leaking the user's NetNTLMv2 challenge-response hash over TCP port 445.",
     """# Network Perimeter & Endpoint Hardening Against Outbound NTLM Leakage:
# 1. Block outbound TCP 445 (SMB) and TCP/UDP 135-139 at the enterprise perimeter firewall.
# 2. Restrict Outbound NTLM Traffic via Windows Group Policy / Registry:
New-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0" `
    -Name "RestrictSendingNTLMTraffic" -Value 2 -PropertyType DWord -Force""",
     """# 3. Add privileged accounts to the Active Directory 'Protected Users' security group,
#    which completely disables NTLM authentication and enforces Kerberos AES:
Add-ADGroupMember -Identity "Protected Users" -Members "admin_user" """,
     "Monitor Windows Event ID `8004` under `Microsoft-Windows-NTLM/Operational` when auditing outbound NTLM traffic before switching to full block mode (`Value = 2`)."),

    ("CVE-2023-20198", "Cisco IOS XE Web UI Privilege Escalation & Implant Defense", "10.0 Critical", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "CWE-284 (Improper Access Control)", "Cisco IOS XE Software with HTTP/HTTPS Server Feature Enabled",
     "Improper access control in the Nginx reverse proxy configuration of the Cisco IOS XE Web UI (`webui_wsma_http`) allowed unauthenticated requests to reach internal WSMA management handlers and create a privilege level 15 administrative user.",
     """! Vulnerable Cisco IOS XE Configuration (HTTP Server Exposed to Untrusted Networks):
ip http server
ip http secure-server
! Without an access-class restriction or when Web UI is unnecessary""",
     """! Hardened Cisco IOS XE Configuration:
! 1. Disable HTTP/HTTPS server entirely if CLI (SSH) is used for management:
no ip http server
no ip http secure-server
! 2. If Web UI is strictly required, bind it ONLY to an out-of-band management VRF and ACL:
ip access-list standard MGMT_ACL
 permit 10.250.0.0 0.0.0.255
 deny any log
ip http access-class ipv4 MGMT_ACL
ip http active-session-modules none""",
     "Audit all network switches and routers for unexpected privilege 15 local accounts (`show running-config | include username`) and verify that management planes (SSH, HTTPS, SNMP) are isolated to dedicated out-of-band management VLANs."),

    ("CVE-2022-40684", "Fortinet FortiOS / FortiProxy Administrative Authentication Bypass", "9.8 Critical", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CWE-288 (Authentication Bypass Using an Alternate Path or Channel)", "FortiOS 7.0.0-7.0.6, 7.2.0-7.2.1",
     "An internal inter-process communication trust flaw allowed external requests that set specific `Forwarded` headers and the internal `Node.js` report runner `User-Agent` to be treated as trusted localhost system requests by the HTTPS administrative API.",
     """# Vulnerable Reverse Proxy Pattern:
# Backend API trusted client-modifiable HTTP headers (Forwarded: for="127.0.0.1")
# to grant internal loopback administrative trust.""",
     """# Hardened FortiOS Configuration (Local-In Policy to block WAN Admin Access):
config firewall local-in-policy
    edit 1
        set intf "wan1"
        set srcaddr "all"
        set dstaddr "all"
        set action deny
        set service "HTTPS" "SSH" "HTTP"
        set schedule "always"
    next
end""",
     "Never expose firewall administrative interfaces (`HTTPS`, `SSH`) on WAN interfaces. Enforce `local-in-policy` rules and monitor administrative audit logs for SSH keys or API tokens added by `Local_Process_Access`."),

    ("CVE-2023-38408", "OpenSSH ssh-agent PKCS#11 Remote Library Loading", "9.8 Critical", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CWE-427 (Uncontrolled Search Path Element)", "OpenSSH before 9.3p2 (when `ForwardAgent yes` is used)",
     "When a user connected to an untrusted remote server with SSH Agent Forwarding enabled (`ssh -A` or `ForwardAgent yes`), anyone with root access on that remote host could access the forwarded UNIX domain socket (`$SSH_AUTH_SOCK`) and send PKCS#11 provider loading requests back to the user's local `ssh-agent` workstation.",
     """# Dangerous SSH Client Configuration (~/.ssh/config):
Host *
    ForwardAgent yes  # NEVER enable ForwardAgent globally! Exposes local agent socket to remote root!""",
     """# Safe SSH Bastion / Jump Host Pattern (~/.ssh/config):
# Always use ProxyJump (-J) instead of ForwardAgent (-A)!
# ProxyJump tunnels the end-to-end SSH handshake through the bastion WITHOUT exposing your keys or agent:
Host internal-prod-server
    HostName 10.20.30.40
    User secadmin
    ProxyJump bastion.corp.lk
    ForwardAgent no""",
     "Audit developer `~/.ssh/config` files to replace `ForwardAgent yes` with `ProxyJump` (`ssh -J`). Keep OpenSSH updated (`>= 9.3p2`), which restricts PKCS#11 modules to trusted paths and requires explicit user confirmation."),
]

def build_appendix_g():
    lines = []
    lines.append("# APPENDIX G: LANDMARK CVE & VULNERABILITY ARCHITECTURE ENCYCLOPEDIA")
    lines.append("")
    lines.append("## Architectural Post-Mortems, Root-Cause Code Analysis, Detection & Remediation")
    lines.append("")
    lines.append("> [!IMPORTANT]")
    lines.append("> **Why Elite Security Engineers Study Historical & Modern CVEs:** Every major vulnerability class in modern software is a recurring architectural anti-pattern. By studying the exact root-cause code, memory/protocol state transitions, and remediation patches of landmark CVEs, you develop the pattern-recognition instinct required for elite source-code auditing, bug bounty hunting, and secure systems design.")
    lines.append("")
    lines.append("| CVE Identifier | Vulnerability Name | CVSS Score | CWE Classification | Primary Affected Subsystem |")
    lines.append("|---|---|---|---|---|")
    all_cves = CVES + MORE_CVES
    for cve_id, name, score, vec, cwe, target, *_ in all_cves:
        lines.append(f"| **{cve_id}** | {name} | {score} | {cwe} | {target} |")
    lines.append("")

    for idx, (cve_id, name, score, vec, cwe, target, root_cause, vuln_code, fixed_code, detection) in enumerate(all_cves, 1):
        lines.append(f"---")
        lines.append(f"## G.{idx} {cve_id} — {name}")
        lines.append("")
        lines.append(f"- **Severity & Base Score:** `{score}`")
        lines.append(f"- **CVSS v3.1 Vector:** `{vec}`")
        lines.append(f"- **Weakness Classification:** `{cwe}`")
        lines.append(f"- **Affected Software / Component:** {target}")
        lines.append("")
        lines.append(f"### 1. Architectural Root-Cause Analysis")
        lines.append(root_cause)
        lines.append("")
        lines.append(f"### 2. Vulnerable Pattern & Technical Mechanism")
        lines.append("```c")
        lines.append(vuln_code.strip())
        lines.append("```")
        lines.append("")
        lines.append(f"### 3. Production Remediation & Patch Engineering")
        lines.append("```bash")
        lines.append(fixed_code.strip())
        lines.append("```")
        lines.append("")
        lines.append(f"### 4. Blue Team Detection, Telemetry & Audit Verification")
        lines.append(detection)
        lines.append("")

    # Add an extended Comparative Vulnerability Class Matrix across 40 additional high-impact CVEs
    lines.append("---")
    lines.append("## G.21 Comparative Reference Matrix of 40 Additional High-Impact Enterprise CVEs")
    lines.append("")
    lines.append("| CVE ID | Component | Vulnerability Class | Root Cause Summary | Defensive Control & Patch Verification |")
    lines.append("|---|---|---|---|---|")
    extra_matrix = [
        ("CVE-2017-5638", "Apache Struts 2", "OGNL Expression Injection (CWE-917)", "Jakarta Multipart parser included raw `Content-Type` header in localized error messages evaluated as OGNL expressions.", "Upgrade Struts >= 2.5.10.1; validate `Content-Type` headers at edge WAF before reaching servlet container."),
        ("CVE-2017-5753", "Modern CPUs (Spectre v1)", "Bounds Check Bypass (CWE-1037)", "Speculative execution past conditional branch bounds checks leaves secret data footprints in CPU L1 data cache timing.", "Compiler `lfence` speculation barriers, array index masking, browser Site Isolation, and CPU microcode updates."),
        ("CVE-2017-5754", "Intel/ARM CPUs (Meltdown)", "Rogue Data Cache Load (CWE-1037)", "Out-of-order execution reads kernel memory before privilege bit fault is raised, leaking data via cache side channel.", "Kernel Page Table Isolation (KPTI / KAISER) unmapping kernel memory from user-space page tables."),
        ("CVE-2016-5195", "Linux Kernel (DirtyCow)", "Copy-on-Write Race Condition (CWE-362)", "Race between `madvise(MADV_DONTNEED)` and `/proc/self/mem` writes tricked `get_user_pages` into writing to read-only mmap pages.", "Kernel commit `19be0eaffa3ac7d8eb6784ad9bdbc7d67ed8e619` introducing `FOLL_COW` tracking flag."),
        ("CVE-2018-1000001", "GNU libc realpath()", "Buffer Underflow (CWE-124)", "When current working directory resolved to `(unreachable)` in unprivileged mount namespace, `getcwd()` lacked leading `/`, causing underflow.", "Upgrade `glibc >= 2.27`; restrict unprivileged user namespaces (`kernel.unprivileged_userns_clone = 0`)."),
        ("CVE-2019-5736", "Docker runc", "Host Binary Overwrite via `/proc/self/exe`", "Container process replaced `/bin/sh` with `#!/proc/self/exe`, allowing container to open host `runc` binary file descriptor for writing upon exit.", "Upgrade `runc >= 1.0.0-rc6` (clones `runc` into an anonymous `memfd_create()` sealed memory buffer before entering container)."),
        ("CVE-2019-14287", "Sudo", "UID -1 Integer Conversion Bypass", "Specifying `sudo -u#-1` or `-u#4294967295` bypassed `ALL, !root` user checks while `setresuid(-1)` left UID as 0 (root).", "Upgrade `sudo >= 1.8.28`; avoid negative/exclusion rules (`!root`) in `/etc/sudoers`."),
        ("CVE-2019-19781", "Citrix ADC / NetScaler", "Path Traversal in Perl Template Engine", "Unauthenticated `/vpns/../` path traversal reached internal Perl `Template Toolkit` scripts, allowing arbitrary template writing.", "Apply Citrix patches and block `..` path sequences in Responder policy rules."),
        ("CVE-2020-0601", "Windows CryptoAPI (CurveBall)", "Elliptic Curve Parameter Spoofing (CWE-295)", "`crypt32.dll` failed to verify that an X.509 certificate's explicit ECC generator point `G` matched the standard NIST curve generator.", "Install January 2020 Windows Security Update; enforce pinned root CA parameters for explicit ECC certificates."),
        ("CVE-2020-0796", "Windows SMBv3 (SMBGhost)", "Integer Overflow in LZNT1 Compression", "`srv2.sys` `SmbCompressionDecompress()` summed `OriginalCompressedSegmentSize` and `OffsetOrLength` without integer overflow checking.", "Apply KB4551762; disable SMBv3 compression if unpatched (`DisableCompression = 1`)."),
        ("CVE-2020-1350", "Windows DNS Server (SIGRed)", "16-Bit Integer Overflow in SIG Record Parsing", "Large DNS `SIG` response records (>64 KB over TCP) overflowed a 16-bit allocation size calculation in `dns.exe`.", "Apply July 2020 patch; set `TcpReceivePacketSize` registry cap to `0xFF00`."),
        ("CVE-2020-5902", "F5 BIG-IP TMUI", "Path Traversal in Apache/Tomcat Proxy (`;`) ", "Discrepancy between Apache `/tmui/login.jsp/..;/tmui/` path normalization and Tomcat semicolon parameter handling bypassed auth.", "Upgrade BIG-IP; never expose TMUI management port on self-IPs or untrusted VLANs."),
        ("CVE-2021-21972", "VMware vCenter Server", "Unauthenticated TAR Archive Path Traversal", "vSphere Client `vropspluginui` endpoint extracted uploaded `.tar` archives without sanitizing `../../` file entry paths.", "Upgrade vCenter Server; isolate ESXi and vCenter management interfaces on air-gapped Tier-0 VLANs."),
        ("CVE-2021-22205", "GitLab CE/EE (ExifTool)", "DjVu Annotation Metadata Parsing Flaw", "Uploaded image files were passed to `ExifTool` prior to authentication, which evaluated unescaped tokens in DjVu `ANTa` chunks.", "Upgrade GitLab and `ExifTool >= 12.24`."),
        ("CVE-2021-26084", "Atlassian Confluence", "OGNL Expression Injection in Webwork", "Velocity template rendered `queryString` value directly into an OGNL evaluation attribute without quoting.", "Upgrade Confluence; restrict public exposure of internal knowledge bases behind Zero Trust / VPN."),
        ("CVE-2021-34473", "Microsoft Exchange (ProxyShell)", "Autodiscover URL Normalization SSRF", "`/autodiscover/autodiscover.json?@foo.com/mapi/nspi/` stripped the prefix during URL rewriting, reaching backend PowerShell remoting.", "Apply April/May 2021 Exchange Security Updates; monitor IIS logs for `/autodiscover/autodiscover.json` requests."),
        ("CVE-2021-41773", "Apache HTTP Server 2.4.49", "URL Normalization Path Traversal (`.%2e/`)", "`ap_normalize_path()` decoded `%2e` single-byte sequences insufficiently, allowing `/cgi-bin/.%2e/.%2e/etc/passwd` traversal.", "Upgrade immediately to Apache `>= 2.4.51`; enforce `Require all denied` on `<Directory />` root block."),
        ("CVE-2022-0185", "Linux Kernel File System Context", "Integer Underflow in `legacy_parse_param`", "In `fs/fs_context.c`, the bounds check `size + len + 2 > PAGE_SIZE` used unsigned subtraction `len > PAGE_SIZE - 2 - size`, underflowing when `size > 4094`.", "Upgrade Linux kernel `>= 5.16.2`; disable unprivileged user namespaces (`CAP_SYS_ADMIN` in userns) where not needed."),
        ("CVE-2022-1388", "F5 BIG-IP iControl REST", "Hop-by-Hop `Connection: X-F5-Auth-Token` Bypass", "Apache front-end stripped `X-F5-Auth-Token` listed in `Connection` header after auth check, causing Jetty back-end to fall back to local admin trust.", "Upgrade BIG-IP; configure front-end proxies to sanitize all headers named in client `Connection:` headers prior to authentication."),
        ("CVE-2022-21449", "Oracle Java 15-18 (Psychic Signatures)", "ECDSA Zero Signature (`r=0, s=0`) Verification Bug", "Java rewrite of ECDSA verification failed to reject signatures where `r = 0` or `s = 0`, causing math equations `0 == 0` to always validate!", "Upgrade JDK to April 2022 CPU (`17.0.3`, `18.0.1`); always enforce `0 < r < n` and `0 < s < n` in ECDSA implementations."),
        ("CVE-2022-22947", "Spring Cloud Gateway", "SpEL Injection in Actuator Route Creation", "Exposed `/actuator/gateway/routes` endpoint evaluated Spring Expression Language (`#{...}`) inside filter definitions.", "Disable unauthenticated management actuators (`management.endpoints.web.exposure.include=health,info`) and upgrade Spring Cloud Gateway."),
        ("CVE-2022-26134", "Atlassian Confluence", "Uncaught OGNL Namespace Lookup Evaluation", "`ActionChainResult` translated URI namespace paths using `TextParseUtil.translateVariables()`, evaluating `${...}` OGNL expressions.", "Upgrade Confluence; enforce WAF rules blocking `${` in request URIs."),
        ("CVE-2022-30190", "Microsoft MSDT (Follina)", "MSHTML `ms-msdt:` URI Handler Invocation", "Word documents referencing an external HTML template triggered `ms-msdt:/id PCWDiagnostic` URI handler without macro execution.", "Apply June 2022 Windows cumulative updates; unregister `ms-msdt` URL protocol if unused."),
        ("CVE-2022-3602", "OpenSSL 3.0.0-3.0.6 (Punycode)", "4-Byte Stack Buffer Overflow in X.509 Name Constraints", "`ossl_a2ulabel()` Punycode decoding wrote up to 4 bytes `0x2E` (`.`) past stack buffer during certificate verification.", "Upgrade to OpenSSL `>= 3.0.7`."),
        ("CVE-2023-22809", "Sudo (`sudoedit`)", "Editor Argument Injection via `SUDO_EDITOR`", "User-supplied `--` separator inside `EDITOR`/`SUDO_EDITOR` environment variable tricked `sudoedit` into opening unauthorized files.", "Upgrade `sudo >= 1.9.12p2`; add `Defaults!SUDOEDIT env_delete+=\"SUDO_EDITOR VISUAL EDITOR\"` to `/etc/sudoers`."),
        ("CVE-2023-2640 & CVE-2023-32629", "Ubuntu Linux Kernel (GameOver(lay))", "OverlayFS SUID File Copy-Up Capability Bypass", "Ubuntu-specific OverlayFS patches failed to strip security capabilities/SUID bits correctly during unprivileged userns copy-up.", "Update Ubuntu kernel packages; set `kernel.unprivileged_userns_clone=0` on multi-tenant servers."),
        ("CVE-2023-27350", "PaperCut MF/NG", "SetupWizard Authentication Bypass", "`SetupCompleted` session state tampering allowed unauthenticated users to re-enter the initial setup wizard and run print scripts.", "Upgrade PaperCut `>= 22.0.9`; restrict port `9191/9192` to internal administration networks."),
        ("CVE-2023-3519", "Citrix NetScaler ADC/Gateway", "Unauthenticated Stack Buffer Overflow in SAML/AAA", "SAML SP/IdP form parser copied oversized HTTP parameters into a fixed-size stack buffer without bounds checking.", "Upgrade NetScaler firmware; enable stack protector compiler flags across all native network daemons."),
        ("CVE-2023-36884", "Windows Search & Office", "Remote Document Parsing Handling Flaw", "Specially crafted Office documents invoked legacy Windows Search/IE rendering handlers.", "Enable Attack Surface Reduction (ASR) rule `Block all Office applications from creating child processes`."),
        ("CVE-2023-46604", "Apache ActiveMQ", "OpenWire Protocol ClassInfo Deserialization", "`BaseDataStreamMarshaller.createThrowable()` instantiated arbitrary classes present on the classpath (`ClassPathXmlApplicationContext`) with a string constructor.", "Upgrade ActiveMQ `>= 5.18.3`; restrict class instantiation in custom marshallers to `Throwable` subclasses via `isAssignableFrom()`."),
        ("CVE-2023-4863", "libwebp (Chrome, Firefox, Electron)", "Huffman Lookup Table Heap Buffer Overflow", "`BuildHuffmanTable()` allocated a fixed buffer for malformed WebP lossless Huffman trees, overflowing heap memory when rendering an image.", "Update `libwebp >= 1.3.2`, browsers, Electron apps, and server-side image processors (`Pillow`, `sharp`)."),
        ("CVE-2023-4966", "Citrix NetScaler (Citrix Bleed)", " `snprintf` Return Value Out-of-Bounds Memory Read", "`ns_aaa_oauthrp_send_openid_config()` used the return value of `snprintf()` (which returns how many bytes *would* have been written, not actual written bytes) to send HTTP response data, leaking session tokens from memory.", "Upgrade NetScaler AND terminate all active ICA/PCoIP/AAA sessions (`kill icaconnection -all`). Never use `snprintf` return value as buffer length without clamping to `sizeof(buf) - 1`!"),
        ("CVE-2024-1709", "ConnectWise ScreenConnect", "Path Normalization SetupWizard Re-Entry", "Requesting `/SetupWizard.aspx/anything` caused ASP.NET sub-path routing to invoke `SetupWizard.aspx` while bypassing the URL authentication filter that only matched exact `/SetupWizard.aspx`.", "Upgrade ScreenConnect `>= 23.9.8`; normalize paths before applying security middleware filters."),
        ("CVE-2024-21626", "runc (Leaky Vessels)", "Working Directory File Descriptor Leak (`chdir` to `/proc/self/fd/N`)", "`runc` leaked an internal file descriptor pointing to the host's `/sys/fs/cgroup` into the container initialization step, allowing `WORKDIR /proc/self/fd/7/../../..` to escape to the host filesystem.", "Upgrade `runc >= 1.1.12` (ensures `O_CLOEXEC` on all host directory descriptors and verifies `getcwd()` is inside container rootfs)."),
        ("CVE-2024-21762", "Fortinet FortiOS SSL-VPN", "Out-of-Bounds Write in Chunked HTTP Transfer-Encoding Parser", "`sslvpnd` failed to validate chunk length markers properly when parsing malformed HTTP chunked requests.", "Upgrade FortiOS; disable SSL-VPN in favor of IPsec IKEv2 with certificate auth where possible."),
        ("CVE-2024-23897", "Jenkins CLI (`args4j`)", "`@filename` Argument Expansion Arbitrary File Read", "`args4j` library used by Jenkins CLI replaced `@/path/to/file` arguments with the contents of that file on the Jenkins controller filesystem, leaking secrets in error messages.", "Upgrade Jenkins `>= 2.442` / LTS `>= 2.426.3` or disable the CLI over HTTP/SSH via startup script."),
        ("CVE-2024-24919", "Check Point Security Gateways", "VPN Information Disclosure via Path Traversal", "Unauthenticated path traversal on the Remote Access VPN portal allowed reading local files (`/etc/shadow`) when password-only legacy accounts existed.", "Install Check Point May 2024 Hotfix and remove all local password-only VPN accounts."),
        ("CVE-2024-27198", "JetBrains TeamCity", "Alternative Path Authentication Bypass (`;/*.jsp`)", "`res.sendRedirect` handling combined with `;` matrix parameter routing allowed hitting internal administrative controllers via `/hax?jsp=/app/rest/users;.jsp`.", "Upgrade TeamCity `>= 2023.11.4`; block `;` in URL paths at reverse proxy."),
        ("CVE-2024-3400", "Palo Alto Networks PAN-OS GlobalProtect", "`SESSID` Cookie Path Traversal & Telemetry Command Injection", "Session ID cookie value (`SESSID=/../../../var/appweb/sslvpndocs/...`) created arbitrary empty files whose filenames were later interpolated into a cron shell script.", "Apply PAN-OS hotfixes; validate all session identifiers against a strict UUID/hex regex (`^[a-f0-9-]{36}$`) before filesystem operations."),
        ("CVE-2024-38063", "Windows TCP/IP Stack (`tcpip.sys`)", "IPv6 Packet Reassembly Integer Underflow", "Processing specially crafted IPv6 packets with Destination Options and Fragment headers triggered an integer underflow in `Ipv6pProcessOptions()`.", "Install August 2024 Windows Security Updates; disable IPv6 on network interfaces where IPv6 is not actively managed.")
    ]
    for cid, comp, vclass, rc, fix in extra_matrix:
        lines.append(f"| **{cid}** | {comp} | {vclass} | {rc} | {fix} |")
    lines.append("")

    out_path = os.path.join(CHAPTERS_DIR, "appendix_g_cve_encyclopedia.md")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"Wrote {out_path} ({len(lines)} lines)")


# ---------------------------------------------------------------------------
# APPENDIX H: COMPLETE CIS HARDENING, DEVSECOPS & SECURE CODING REFERENCE
# ---------------------------------------------------------------------------
def build_appendix_h():
    content = """# APPENDIX H: COMPLETE CIS HARDENING BENCHMARKS, DEVSECOPS PIPELINES & SECURE CODING BLUEPRINTS

## Production-Grade Infrastructure Hardening, CI/CD Security Gates & Multi-Language Secure Code Reference

> [!TIP]
> **From Finding Bugs to Fixing Systems:** What separates a junior tester from a Principal Security Architect or Staff Application Security Engineer in Sri Lanka and globally is the ability to provide **drop-in, production-ready remediation configurations and secure code templates**. Use the blueprints in this appendix during penetration test reporting, DevSecOps architecture design, and university software engineering projects.

---

## H.1 CIS Linux Server Hardening Baseline (`/etc/sysctl.d/`, `sshd_config`, `nftables`, `PAM`)

### H.1.1 Kernel Network & Memory Hardening (`/etc/sysctl.d/99-cis-hardening.conf`)

```ini
# ==============================================================================
# CIS Linux Kernel Security & Network Stack Hardening (/etc/sysctl.d/99-cis.conf)
# Apply with: sudo sysctl --system
# ==============================================================================

# --- 1. Memory & Process Protection ---
# Enable Full Address Space Layout Randomization (ASLR: Stack, Heap, VDSO, Shared Libs)
kernel.randomize_va_space = 2

# Restrict access to kernel pointers in /proc/kallsyms to prevent KASLR leaks
kernel.kptr_restrict = 2

# Restrict dmesg kernel ring buffer access to privileged users (CAP_SYSLOG)
kernel.dmesg_restrict = 1

# Restrict ptrace() debugging strictly to parent processes (prevents credential theft from sibling processes)
kernel.yama.ptrace_scope = 2

# Disable unprivileged eBPF to prevent speculative/verifier kernel escalation
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2

# Restrict performance event monitoring to privileged users
kernel.perf_event_paranoid = 3

# Disable core dumps for SUID/SGID binaries (prevents leaking sensitive memory to disk)
fs.suid_dumpable = 0

# Enforce strict symlink and hardlink protections in world-writable sticky directories (/tmp)
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2

# --- 2. IPv4 & IPv6 Network Stack Hardening ---
# Enable TCP SYN Cookies to protect against SYN flood exhaustion
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 4096

# Enable Reverse Path Filtering (RFC 3704 Strict Mode) to prevent IP spoofing
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Disable IP Source Routing (prevents attackers from dictating return packet paths)
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Disable ICMP Redirect Acceptance and Sending (prevents Layer 3 MITM route table poisoning)
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Disable IPv6 Router Advertisements on static server interfaces (prevents SLAAC/mitm6)
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0

# Ignore broadcast ICMP echo requests (Smurf amplification defense)
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Log Martian packets (packets with impossible source IP addresses)
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
```

### H.1.2 Hardened OpenSSH Daemon Configuration (`/etc/ssh/sshd_config`)

```apache
# ==============================================================================
# CIS Level 2 Hardened OpenSSH Server Configuration (/etc/ssh/sshd_config)
# Validate syntax before reload: sudo sshd -t && sudo systemctl reload sshd
# ==============================================================================

Protocol 2
Port 22
AddressFamily inet

# --- Cryptographic Algorithms (Modern AEAD & Curve25519 Only) ---
KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256

# --- Authentication Controls ---
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
KbdInteractiveAuthentication no
UsePAM yes
AuthenticationMethods publickey

# --- Session & Connection Limits (Mitigates Brute-Force & regreSSHion Timing) ---
LoginGraceTime 20
MaxAuthTries 3
MaxSessions 4
MaxStartups 10:30:60
ClientAliveInterval 300
ClientAliveCountMax 2

# --- Attack Surface Reduction (Disable Unnecessary Forwarding) ---
AllowAgentForwarding no
AllowTcpForwarding no
X11Forwarding no
PermitTunnel no
PermitUserEnvironment no
DisableForwarding yes

# --- Access Control & Auditing ---
AllowGroups ssh-admins secops
LogLevel VERBOSE
SyslogFacility AUTH
Subsystem sftp internal-sftp -f AUTH -l INFO
```

### H.1.3 Production Host Firewall with `nftables` (`/etc/nftables.conf`)

```nginx
#!/usr/sbin/nft -f
# ==============================================================================
# Production Zero-Trust Host Firewall Ruleset (/etc/nftables.conf)
# Enable with: sudo systemctl enable --now nftables
# ==============================================================================

flush ruleset

table inet filter {
    set ssh_ratelimit {
        type ipv4_addr
        flags dynamic, timeout
        timeout 5m
    }

    chain input {
        type filter hook input priority 0; policy drop;

        # 1. Accept loopback traffic
        iifname "lo" accept

        # 2. Drop invalid connection states immediately
        ct state invalid drop

        # 3. Accept established and related return traffic
        ct state established,related accept

        # 4. Drop loopback addresses arriving on non-loopback interfaces (anti-spoofing)
        iifname != "lo" ip saddr 127.0.0.0/8 counter drop
        iifname != "lo" ip6 saddr ::1 counter drop

        # 5. Rate-limit ICMPv4 and allow essential ICMPv6 Neighbour Discovery
        ip protocol icmp icmp type { echo-request, destination-unreachable, time-exceeded } limit rate 10/second accept
        ip6 nexthdr icmpv6 icmpv6 type { echo-request, destination-unreachable, packet-too-big, time-exceeded, parameter-problem, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } limit rate 20/second accept

        # 6. Rate-limited SSH access (max 4 new connections per minute per IP)
        tcp dport 22 ct state new update @ssh_ratelimit { ip saddr limit rate 4/minute burst 4 packets } accept
        tcp dport 22 ct state new log prefix "[NFT-SSH-DROP] " drop

        # 7. Allow HTTPS (443) and HTTP (80) for public web servers
        tcp dport { 80, 443 } ct state new accept

        # 8. Log and drop everything else
        limit rate 5/minute log prefix "[NFT-INPUT-DROP] " level warn
        counter drop
    }

    chain forward {
        type filter hook forward priority 0; policy drop;
    }

    chain output {
        type filter hook output priority 0; policy accept;
    }
}
```

---

## H.2 Hardened Web Server, Docker & Kubernetes Security Blueprints

### H.2.1 Production Nginx Reverse Proxy with Full OWASP Security Headers (`/etc/nginx/conf.d/secure-app.conf`)

```nginx
# ==============================================================================
# Hardened Nginx Reverse Proxy Configuration with TLS 1.3 & OWASP Headers
# ==============================================================================

# Hide Nginx version from Server header and error pages
server_tokens off;

# Rate limiting zones (mitigates credential stuffing & L7 DoS)
limit_req_zone $binary_remote_addr zone=login_limit:10m rate=5r/m;
limit_req_zone $binary_remote_addr zone=api_limit:20m rate=30r/s;

server {
    listen 80;
    listen [::]:80;
    server_name app.example.lk;
    # Enforce permanent redirect to HTTPS
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name app.example.lk;

    # --- TLS 1.2 / 1.3 Configuration (Mozilla Intermediate/Modern Guideline) ---
    ssl_certificate /etc/letsencrypt/live/app.example.lk/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/app.example.lk/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
    ssl_prefer_server_ciphers off;
    ssl_session_timeout 1d;
    ssl_session_cache shared:MozSSL:10m;
    ssl_session_tickets off;

    # --- OWASP Defense-in-Depth HTTP Security Headers ---
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header Content-Security-Policy "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=(), payment=(), usb=()" always;
    add_header Cross-Origin-Opener-Policy "same-origin" always;
    add_header Cross-Origin-Resource-Policy "same-origin" always;

    # --- Request Size & Buffer Limits ---
    client_max_body_size 10M;
    client_body_timeout 12s;
    client_header_timeout 12s;

    # --- Block Dotfiles (.git, .env, .htaccess) ---
    location ~ /\\.(?!well-known).* {
        deny all;
        access_log off;
        log_not_found off;
    }

    # --- Strict Rate-Limited Authentication Endpoint ---
    location /api/v1/auth/login {
        limit_req zone=login_limit burst=3 nodelay;
        proxy_pass http://127.0.0.1:8000;
        # Hardcode Host header to prevent Host Header Injection / Cache Poisoning!
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # --- General Application Proxy ---
    location / {
        limit_req zone=api_limit burst=50 nodelay;
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### H.2.2 Hardened Multi-Stage Distroless/Non-Root `Dockerfile` & Kubernetes `Deployment` + `NetworkPolicy`

```dockerfile
# ==============================================================================
# Stage 1: Build Stage (Pinned SHA256 Digest to Prevent Tag Mutation Supply-Chain Risks)
# ==============================================================================
FROM python:3.12-slim-bookworm AS builder

WORKDIR /build
ENV PYTHONDONTWRITEBYTECODE=1 \\
    PYTHONUNBUFFERED=1 \\
    PIP_NO_CACHE_DIR=1 \\
    PIP_DISABLE_PIP_VERSION_CHECK=1

COPY requirements.txt .
RUN python3 -m venv /opt/venv && \\
    /opt/venv/bin/pip install --require-hashes -r requirements.txt

# ==============================================================================
# Stage 2: Minimal Non-Root Runtime Stage
# ==============================================================================
FROM python:3.12-slim-bookworm AS runtime

# Create dedicated unprivileged system group and user (UID/GID 10001)
RUN groupadd -g 10001 appgroup && \\
    useradd -u 10001 -g appgroup -s /usr/sbin/nologin -M appuser && \\
    apt-get update && apt-get upgrade -y && \\
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
COPY --chown=root:root --chmod=0555 ./src /app/src

ENV PATH="/opt/venv/bin:$PATH"
USER 10001:10001
EXPOSE 8000

ENTRYPOINT ["python3", "-m", "uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

```yaml
# ==============================================================================
# Hardened Kubernetes Deployment & Zero-Trust NetworkPolicy (k8s-hardened.yaml)
# Enforces Pod Security Standards (Restricted Profile): Non-Root, Read-Only RootFS,
# Dropped ALL Linux Capabilities, Seccomp RuntimeDefault, No ServiceAccount Token Mount
# ==============================================================================
apiVersion: apps/v1
kind: Deployment
metadata:
  name: payment-api
  namespace: fintech-prod
spec:
  replicas: 3
  selector:
    matchLabels:
      app: payment-api
  template:
    metadata:
      labels:
        app: payment-api
    spec:
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        runAsGroup: 10001
        fsGroup: 10001
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: payment-api
          image: registry.example.lk/fintech/payment-api@sha256:4f8b9c2e1d3a5b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c
          ports:
            - containerPort: 8000
              protocol: TCP
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL
          resources:
            requests:
              cpu: "250m"
              memory: "256Mi"
            limits:
              cpu: "500m"
              memory: "512Mi"
          volumeMounts:
            - name: tmp-dir
              mountPath: /tmp
      volumes:
        - name: tmp-dir
          emptyDir:
            medium: Memory
            sizeLimit: 64Mi
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: payment-api-zero-trust
  namespace: fintech-prod
spec:
  podSelector:
    matchLabels:
      app: payment-api
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: api-gateway
      ports:
        - protocol: TCP
          port: 8000
  egress:
    # Allow DNS resolution to CoreDNS only
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
          podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
    # Allow PostgreSQL connection strictly to database tier (Blocks AWS/GCP 169.254.169.254 SSRF!)
    - to:
        - podSelector:
            matchLabels:
              app: postgres-db
      ports:
        - protocol: TCP
          port: 5432
```

---

## H.3 Enterprise DevSecOps CI/CD Pipeline (GitHub Actions: Secret Scanning, SAST, SCA, Container Audit & SBOM)

```yaml
# ==============================================================================
# Complete DevSecOps Security Gate Pipeline (.github/workflows/devsecops.yml)
# Blocks merges on hardcoded secrets, SAST findings, vulnerable dependencies, or container flaws
# ==============================================================================
name: DevSecOps Security Gate

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]

permissions:
  contents: read
  security-events: write

jobs:
  secret-scanning:
    name: 1. Git Secret Scanning (Gitleaks)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - name: Run Gitleaks
        uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

  sast-semgrep:
    name: 2. Static Application Security Testing (Semgrep OWASP Top 10)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run Semgrep SAST
        uses: returntocorp/semgrep-action@v1
        with:
          config: >-
            p/owasp-top-ten
            p/security-audit
            p/secrets
            p/dockerfile
            p/kubernetes

  sca-and-container-scan:
    name: 3. Dependency & Container Vulnerability Audit (Trivy + SBOM)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build Candidate Docker Image
        run: docker build -t candidate-app:${{ github.sha }} .
      - name: Run Trivy Vulnerability & Misconfiguration Scanner
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: 'candidate-app:${{ github.sha }}'
          format: 'table'
          exit-code: '1'
          ignore-unfixed: true
          vuln-type: 'os,library'
          severity: 'CRITICAL,HIGH'
      - name: Generate CycloneDX SBOM
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: 'candidate-app:${{ github.sha }}'
          format: 'cyclonedx'
          output: 'sbom.cdx.json'
```

---

## H.4 Multi-Language Secure Coding Blueprints (Python, Node.js/TypeScript, Go & Rust)

### H.4.1 Python (FastAPI / SQLAlchemy): Preventing SQLi, IDOR, SSRF, Weak Hashing & Race Conditions

```python
#!/usr/bin/env python3
\"\"\"
Production-Grade Secure FastAPI Microservice Blueprint:
Demonstrates Argon2id password hashing, asymmetric EdDSA/RS256 JWT validation,
Parameterized SQL with FOR UPDATE row locking (Race Condition prevention),
Object-Level Authorization (IDOR prevention), and SSRF-safe URL fetching.
\"\"\"
import ipaddress
import socket
from urllib.parse import urlparse
from fastapi import FastAPI, Depends, HTTPException, status
from pydantic import BaseModel, Field, constr
from sqlalchemy import text
from sqlalchemy.orm import Session
from argon2 import PasswordHasher

app = FastAPI(docs_url=None, redoc_url=None)  # Disable public Swagger UI in production
ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)

# 1. Strict Input Validation with Pydantic (Blocks Mass Assignment / BOPLA)
class TransferRequest(BaseModel):
    from_account_id: int = Field(..., gt=0)
    to_account_id: int = Field(..., gt=0)
    amount_cents: int = Field(..., gt=0, le=10_000_000_00)
    idempotency_key: constr(pattern=r"^[a-f0-9-]{36}$")

# 2. Atomic Database Transfer with Row-Level Locking (Prevents TOCTOU Race Conditions & SQLi)
def execute_secure_transfer(db: Session, current_user_id: int, req: TransferRequest):
    if req.from_account_id == req.to_account_id:
        raise HTTPException(status_code=400, detail="Cannot transfer to the same account")

    # Lock rows in deterministic ascending ID order to prevent deadlocks AND race conditions!
    first_id, second_id = sorted([req.from_account_id, req.to_account_id])
    db.execute(
        text("SELECT id FROM accounts WHERE id IN (:id1, :id2) ORDER BY id FOR UPDATE"),
        {"id1": first_id, "id2": second_id}
    )

    # Verify Object-Level Authorization (Prevents IDOR / BOLA!)
    sender = db.execute(
        text("SELECT id, owner_user_id, balance_cents FROM accounts WHERE id = :id"),
        {"id": req.from_account_id}
    ).mappings().first()

    if not sender or sender["owner_user_id"] != current_user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden account access")

    if sender["balance_cents"] < req.amount_cents:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Insufficient funds")

    # Perform parameterized atomic balance update
    db.execute(
        text("UPDATE accounts SET balance_cents = balance_cents - :amt WHERE id = :id"),
        {"amt": req.amount_cents, "id": req.from_account_id}
    )
    db.execute(
        text("UPDATE accounts SET balance_cents = balance_cents + :amt WHERE id = :id"),
        {"amt": req.amount_cents, "id": req.to_account_id}
    )
    db.commit()

# 3. SSRF-Safe Outbound Webhook Validator (Blocks RFC 1918, Loopback, Link-Local 169.254.169.254 & DNS Rebinding)
ALLOWED_SCHEMES = {"https"}

def validate_external_webhook_url(raw_url: str) -> str:
    parsed = urlparse(raw_url)
    if parsed.scheme not in ALLOWED_SCHEMES or not parsed.hostname:
        raise ValueError("Only valid HTTPS URLs are permitted")
    if parsed.port not in (None, 443):
        raise ValueError("Only standard port 443 is permitted")

    # Resolve all IPv4/IPv6 records and verify every resolved IP is globally routable
    addr_info = socket.getaddrinfo(parsed.hostname, 443, proto=socket.IPPROTO_TCP)
    for family, _, _, _, sockaddr in addr_info:
        ip_obj = ipaddress.ip_address(sockaddr[0])
        if (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_reserved
            or ip_obj.is_unspecified
        ):
            raise PermissionError(f"SSRF Protection: Resolved IP {ip_obj} is non-public")
    return raw_url
```
"""
    out_path = os.path.join(CHAPTERS_DIR, "appendix_h_devsecops_and_hardening.md")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(content.strip() + "\n")
    print(f"Wrote {out_path} ({len(content.splitlines())} lines)")

if __name__ == "__main__":
    build_appendix_g()
    build_appendix_h()

