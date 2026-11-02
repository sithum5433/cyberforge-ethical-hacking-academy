# APPENDIX C: COMPLETE LINUX, WINDOWS, NETWORKING & SECURITY AUDITING CLI COMMAND ENCYCLOPEDIA

---

## Introduction & How to Use This Reference Encyclopedia

This appendix serves as a comprehensive desktop reference manual for systems administrators, DevSecOps engineers, security auditors, incident responders, and enterprise defenders. Over **70 essential command-line utilities** are organized into five operational domains:

1. **Section C.1: Linux System, File, Process & Kernel Auditing Utilities** (27 Tools)
2. **Section C.2: Network Diagnostics, Packet Analysis & Secure Transport Utilities** (12 Tools)
3. **Section C.3: DevSecOps, Static Analysis (SAST), Secret Scanning & Asset Inventory Tools** (13 Tools)
4. **Section C.4: ELF/PE Binary Inspection, Compiler Hardening & Firmware Analysis Tools** (9 Tools)
5. **Section C.5: Windows Administration, PowerShell Auditing, Container & Cloud Security CLIs** (14 Tools)

Every tool entry includes its architectural purpose, a structured flag reference table, practical defensive auditing invocations, and annotated sample output.

---
---

# Section C.1: Linux System, File, Process & Kernel Auditing Utilities

## C.1.1 `find` — Filesystem Hierarchy Permission & Anomaly Auditor

**Purpose**: Recursively traverses mounted directory trees to evaluate inode metadata (permissions, ownership, timestamps, extended attributes, and file types). Indispensable for locating unauthorized SUID/SGID binaries, world-writable configurations, and orphaned files.

| Flag / Predicate | Description |
| :--- | :--- |
| `-xdev` or `-mount` | Restricts traversal to the starting filesystem (prevents descending into `/proc`, `/sys`, or network mounts). |
| `-type <f\|d\|l\|s\|b\|c>` | Filters by inode type: `f` (regular file), `d` (directory), `l` (symlink), `s` (socket), `b` (block), `c` (char). |
| `-perm -<mode>` | Matches files where **all** of the specified octal permission bits are set (e.g., `-perm -4000` for SUID). |
| `-perm /<mode>` | Matches files where **any** of the specified octal permission bits are set (e.g., `-perm /6000` for SUID or SGID). |
| `-user <name\|uid>` | Matches files owned by a specific user or numeric UID. |
| `-nouser` / `-nogroup` | Matches orphaned files whose UID or GID does not exist in `/etc/passwd` or `/etc/group`. |
| `-mtime -<N>` / `-mmin -<N>` | Matches files whose data was modified within the last $N$ days (`-mtime`) or $N$ minutes (`-mmin`). |
| `-ctime -<N>` / `-cmin -<N>` | Matches files whose inode metadata (permissions, owner) changed within the last $N$ days or minutes. |
| `-printf "<fmt>"` | Formats output directly using inode fields (`%M` symbolic perms, `%u` owner, `%g` group, `%p` path). |

### Practical Auditing Examples:
```bash
# 1. Audit root filesystem for all SUID (04000) or SGID (02000) regular files with formatted metadata
find / -xdev -type f -perm /6000 -printf "%M %u:%g %TY-%Tm-%Td %p\n" 2>/dev/null

# 2. Identify world-writable directories that are missing the Sticky Bit (01000)
find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -ls 2>/dev/null

# 3. Locate orphaned files with unmapped UIDs or GIDs (CIS Linux Benchmark requirement)
find / -xdev \( -nouser -o -nogroup \) -printf "%u:%g %p\n" 2>/dev/null

# 4. Incident Response: List files in /etc modified in the last 60 minutes
find /etc -type f -mmin -60 -ls
```

---

## C.1.2 `grep` — Regular Expression Log & Configuration Pattern Scanner

**Purpose**: Searches input streams and file hierarchies using Basic Regular Expressions (BRE), Extended Regular Expressions (ERE), or Perl-Compatible Regular Expressions (PCRE).

| Flag | Description |
| :--- | :--- |
| `-E` (`--extended-regexp`) | Enables Extended Regular Expressions (`+`, `?`, `\|`, `()` without backslash escaping). |
| `-P` (`--perl-regexp`) | Enables Perl-Compatible Regular Expressions (supports lookaheads `(?=...)` and `\d`, `\s`). |
| `-r` / `-R` | Recursively searches directories (`-R` follows symbolic links; `-r` does not). |
| `-i` (`--ignore-case`) | Performs case-insensitive matching. |
| `-v` (`--invert-match`) | Selects lines that do **not** match the specified pattern (useful for stripping `#` comments). |
| `-n` (`--line-number`) | Prefixes each matching output line with its 1-based line number within the file. |
| `-H` / `-h` | Always print (`-H`) or suppress (`-h`) the filename prefix on output lines. |
| `-l` / `-L` | Prints only the names of files with matching lines (`-l`) or without matching lines (`-L`). |
| `-C <N>` / `-A <N>` / `-B <N>` | Prints $N$ lines of surrounding (`-C`), trailing (`-A`), or leading (`-B`) context. |

### Practical Auditing Examples:
```bash
# 1. Strip comments and blank lines from /etc/ssh/sshd_config to inspect active directives
grep -Ev '^\s*(#|$)' /etc/ssh/sshd_config

# 2. Search authentication logs for failed SSH logins and extract IPv4 addresses with line numbers
grep -En 'Failed password for .* from ([0-9]{1,3}\.){3}[0-9]{1,3}' /var/log/auth.log

# 3. Scan web application configuration directories for hardcoded AWS Access Key IDs
grep -rnE '(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}' /srv/webapp/
```

---

## C.1.3 `awk` (GNU `gawk`) — Structured Field & Log Aggregation Engine

**Purpose**: A pattern-scanning and Turing-complete data-processing language that splits each input record (line) into positional fields (`$1`, `$2`, ..., `$NF`) based on a configurable field separator (`FS`).

| Option / Built-in Variable | Description |
| :--- | :--- |
| `-F '<sep>'` | Sets the input Field Separator (`FS`), e.g., `-F:` for `/etc/passwd` or `-F','` for CSV files. |
| `NR` / `FNR` | Total number of input records read so far (`NR`), or record number in current file (`FNR`). |
| `NF` | Number of fields in the current record (`$NF` references the last column on the line). |
| `OFS` / `ORS` | Output Field Separator (default space) and Output Record Separator (default newline). |
| `BEGIN { ... }` | Code block executed once before reading any input lines. |
| `END { ... }` | Code block executed once after all input lines have been processed (used for summary tables). |

### Practical Auditing Examples:
```bash
# 1. Audit /etc/passwd for any account with UID 0 (Root equivalence check)
awk -F: '($3 == 0) { printf "UID 0 Account: %-15s Shell: %s\n", $1, $7 }' /etc/passwd

# 2. Identify system accounts (UID < 1000) that have an interactive login shell assigned
awk -F: '($3 > 0 && $3 < 1000 && $7 !~ /(nologin|false|sync|halt|shutdown)/) { print $1, $3, $7 }' /etc/passwd

# 3. Aggregate top 10 source IP addresses generating HTTP 401/403 status codes in Nginx access logs
awk '($9 == 401 || $9 == 403) { count[$1]++ } END { for (ip in count) print count[ip], ip }' /var/log/nginx/access.log | sort -rn | head -n 10
```

---

## C.1.4 `sed` — Stream Editor for Configuration Sanitization & Log Extraction

**Purpose**: Performs non-interactive text transformations on input streams or files in-place (`-i`), supporting regular expression substitutions, line range extraction, and deletion.

| Flag / Command | Description |
| :--- | :--- |
| `-n` (`--quiet`) | Suppresses automatic printing of pattern space (used with the `p` flag to print matched lines only). |
| `-E` (`--regexp-extended`) | Uses Extended Regular Expressions in pattern matching. |
| `-i[SUFFIX]` | Edits files in-place; if `SUFFIX` is supplied (e.g., `-i.bak`), creates a backup copy first. |
| `'s/regex/replacement/g'` | Substitutes all (`g`) occurrences of `regex` on each line with `replacement`. |
| `'/<start>/,/<end>/p'` | Prints all lines between two regular expression markers inclusive. |

### Practical Auditing Examples:
```bash
# 1. Redact Bearer JWT tokens from application logs before sharing with external vendors
sed -E 's/Authorization: Bearer [A-Za-z0-9._-]+/Authorization: Bearer [REDACTED]/g' app.log > app_sanitized.log

# 2. Hardening: Safely update PermitRootLogin to 'no' in /etc/ssh/sshd_config while creating a .bak backup
sudo sed -i.bak -E 's/^#?\s*PermitRootLogin\s+.*/PermitRootLogin no/' /etc/ssh/sshd_config
```

---

## C.1.5 `jq` — Command-Line JSON Processor for Cloud, Container & SIEM Logs

**Purpose**: Parses, filters, transforms, and formats structured JSON outputs emitted by `docker inspect`, `kubectl`, AWS CLI, Azure CLI, `nuclei`, `trivy`, and structured SIEM logs.

| Flag / Filter | Description |
| :--- | :--- |
| `-r` (`--raw-output`) | Outputs raw strings without enclosing JSON double quotes (essential for shell scripting loops). |
| `-c` (`--compact-output`) | Outputs each JSON object on a single compact line (JSONL format). |
| `.field` / `.[]` | Accesses object key `field` or iterates over all elements of an array. |
| `select(<expr>)` | Filters objects matching a boolean condition (e.g., `select(.Severity == "CRITICAL")`). |
| `@tsv` / `@csv` | Formats an array of values as tab-separated or comma-separated output. |

### Practical Auditing Examples:
```bash
# 1. Inspect running Docker containers and extract Container Name, Privileged status, and Mounts
docker inspect $(docker ps -q) | jq -r '.[] | "\(.Name) | Privileged=\(.HostConfig.Privileged) | CapAdd=\(.HostConfig.CapAdd)"'

# 2. Filter AWS CloudTrail JSON logs for failed ConsoleLogin events
jq -r '.Records[] | select(.eventName == "ConsoleLogin" and .responseElements.ConsoleLogin == "Failure") | [.eventTime, .sourceIPAddress, .userIdentity.userName] | @tsv' cloudtrail.json
```

---

## C.1.6 `xargs` — Parallelized Argument Pipeline Builder

**Purpose**: Reads items from standard input and executes a specified command with controlled batching and parallel worker processes, safely handling filenames containing whitespace or special characters via null delimiters (`-0`).

| Flag | Description |
| :--- | :--- |
| `-0` (`--null`) | Expects input items to be terminated by a null byte (`\0`) rather than whitespace (pairs with `find -print0`). |
| `-n <max-args>` | Passes at most `<max-args>` positional arguments per command invocation. |
| `-I {}` | Replaces occurrences of placeholder `{}` in the command template with the input line. |
| `-P <max-procs>` | Runs up to `<max-procs>` parallel child processes simultaneously. |
| `-r` (`--no-run-if-empty`) | Does not execute the command if standard input is empty. |

### Practical Auditing Examples:
```bash
# 1. Compute SHA-256 integrity hashes of all binaries in /usr/sbin using 4 parallel worker processes
find /usr/sbin -type f -print0 | xargs -0 -r -n 20 -P 4 sha256sum > /var/backups/usr_sbin_sha256.manifest
```

---

## C.1.7 `tar` — Tape Archive Utility & Secure Backup Verification

**Purpose**: Creates, inspects, and extracts POSIX `.tar` archives with optional compression (`gzip`, `zstd`, `xz`, `bzip2`) while preserving extended attributes (`xattrs`), SELinux contexts, and POSIX ACLs.

| Flag | Description |
| :--- | :--- |
| `-c` / `-t` / `-x` | Create archive (`-c`), list archive contents without extracting (`-t`), or extract (`-x`). |
| `-f <file>` | Specifies the archive filename. |
| `-z` / `-J` / `--zstd` | Filters archive through `gzip` (`-z`), `xz` (`-J`), or `zstd` (`--zstd`). |
| `--acls` / `--xattrs` / `--selinux` | Preserves POSIX ACLs, extended attributes (`security.capability`), and SELinux contexts. |
| `--no-same-owner` / `--no-same-permissions` | Prevents extracting files with arbitrary owner UIDs or SUID bits when untarring untrusted archives as root. |
| `--` | End-of-options delimiter; prevents filenames starting with `-` from being interpreted as flags. |

### Practical Auditing Examples:
```bash
# 1. Inspect an untrusted archive for path traversal ('../') or SUID bits BEFORE extracting
tar -ztvf untrusted_bundle.tar.gz | grep -E '(\.\./|^-[rwx-]{2}s)'

# 2. Create a forensic backup of /etc preserving all ACLs, capabilities, and SELinux labels
sudo tar --zstd --acls --xattrs --selinux -cvf /var/backups/etc_forensic.tar.zst -C / etc
```

---

## C.1.8 `openssl` — Cryptographic Toolkit & X.509 / TLS Configuration Auditor

**Purpose**: Provides command-line access to OpenSSL cryptographic primitives, X.509 certificate inspection, Certificate Signing Request (CSR) verification, password hashing, and remote TLS cipher/protocol testing.

| Subcommand | Key Flags | Description |
| :--- | :--- | :--- |
| `s_client` | `-connect <host:port> -servername <sni> -tls1_2 / -tls1_3 -showcerts` | Connects to a remote TLS server (HTTPS, LDAPS,STARTTLS) and dumps certificate chains and negotiated cipher suites. |
| `x509` | `-in <cert.pem> -noout -text -dates -ext subjectAltName,extendedKeyUsage` | Parses an X.509 certificate and displays validity dates, Subject, Issuer, SANs, and EKUs. |
| `req` | `-in <csr.pem> -noout -text -verify` | Inspects and verifies the cryptographic signature on a PKCS#10 Certificate Signing Request. |
| `passwd` | `-6 -salt <salt>` | Generates a salted SHA-512 (`$6$`) `crypt(3)` password hash compatible with `/etc/shadow`. |
| `dgst` | `-sha256 -verify <pub.pem> -signature <sig.bin> <file>` | Computes message digests or verifies digital signatures. |

### Practical Auditing Examples:
```bash
# 1. Inspect a Domain Controller's LDAPS (TCP 636) certificate expiration and Subject Alternative Names
echo | openssl s_client -connect dc01.corp.example.lk:636 2>/dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName

# 2. Verify whether a web server still permits deprecated TLSv1.0 or TLSv1.1 connections
openssl s_client -connect webapp.corp.example.lk:443 -tls1_1
```

---

## C.1.9 `strace` — System Call and Signal Tracer

**Purpose**: Intercepts and records all system calls invoked by a process (`openat`, `execve`, `connect`, `mmap`, `setresuid`) and signals received by the process via the kernel `ptrace(2)` API. Essential for diagnosing missing shared libraries, file access checks, and anomalous daemon behavior.

| Flag | Description |
| :--- | :--- |
| `-f` | Traces child processes created by `fork(2)`, `vfork(2)`, and `clone(2)`. |
| `-e trace=<set>` | Filters traced system calls (e.g., `-e trace=file`, `-e trace=network`, `-e trace=process`, or `-e trace=openat,execve`). |
| `-p <pid>` | Attaches to an already-running process ID. |
| `-s <strsize>` | Maximum string length to print for buffer arguments (default is `32`; use `-s 256` for full paths/commands). |
| `-c` | Counts time, calls, and errors for each system call and prints a summary table upon exit. |
| `-o <filename>` | Writes trace output to `<filename>` rather than `stderr`. |

### Practical Auditing Examples:
```bash
# 1. Audit all configuration files and shared libraries a binary attempts to open (identifying missing files / ENOENT)
strace -f -e trace=open,openat,access -s 256 /usr/local/bin/custom_service 2>&1 | grep -E '(ENOENT|\.so|\.conf)'
```

---

## C.1.10 `ltrace` — Dynamic Library Call Tracer

**Purpose**: Intercepts and records calls made by an dynamically linked ELF executable to shared library functions inside the Procedure Linkage Table (`PLT`, e.g., `strcmp`, `getenv`, `system`, `SSL_write`).

| Flag | Description |
| :--- | :--- |
| `-f` | Traces child processes across `fork()` / `clone()`. |
| `-e <filter>` | Filters which library calls are traced (e.g., `-e getenv+system+popen`). |
| `-S` | Displays both library calls and raw kernel system calls. |
| `-s <strsize>` | Sets maximum printed string length. |

### Practical Auditing Examples:
```bash
# 1. Inspect which environment variables an unknown binary queries via getenv() at startup
ltrace -e getenv /opt/vendor/bin/agent
```

---

## C.1.11 `lsof` — List Open Files, Network Sockets, and Deleted Inodes

**Purpose**: Queries `/proc/<pid>/fd` and kernel socket tables to list all files, directories, block devices, shared libraries, UNIX domain sockets, and IPv4/IPv6 network connections held open by running processes.

| Flag | Description |
| :--- | :--- |
| `-i [4\|6][protocol][@host][:port]` | Lists open network sockets matching family, protocol, address, or port (e.g., `-i TCP:443`). |
| `-n` / `-P` | Inhibits DNS hostname resolution (`-n`) and port service name lookup (`-P`) for rapid execution. |
| `-p <pid>` | Lists only files opened by the specified Process ID. |
| `-u <user>` | Lists only files opened by the specified user (`^root` excludes root). |
| `+L1` | Lists open files that have a link count less than 1 (files deleted from disk but still held open in RAM!). |

### Practical Auditing Examples:
```bash
# 1. Identify unlinked (deleted) executables or log files still held open by running processes
sudo lsof +L1

# 2. List all active listening TCP sockets with owning PID and user without DNS/port lookup delays
sudo lsof -nP -iTCP -sTCP:LISTEN
```

---

## C.1.12 `ps` — Process Table & Security Context Inspector

**Purpose**: Captures a snapshot of active processes from `/proc`, supporting custom formatting of Real/Effective UIDs, process hierarchy trees, command arguments, and SELinux/AppArmor security contexts.

| Flag / Format Specifier | Description |
| :--- | :--- |
| `-ef` or `aux` | Displays all running processes across all terminals with full command lines. |
| `--forest` or `f` | Renders parent-child process relationships as an ASCII tree hierarchy. |
| `-Z` | Includes Mandatory Access Control (SELinux Type / AppArmor Profile) security context column. |
| `-o <format>` | User-defined output columns: `pid,ppid,ruid,euid,ruser,euser,capeff,label,args`. |

### Practical Auditing Examples:
```bash
# 1. Detect processes where Effective UID (euid) differs from Real UID (ruid) (active SUID execution)
ps -eo pid,ppid,ruid,euid,ruser,euser,args | awk 'NR==1 || $3 != $4'

# 2. Display full process tree with SELinux security contexts
ps -efZ --forest
```

---

## C.1.13 `ss` — Socket Statistics & Kernel Network Connection Auditor

**Purpose**: Modern replacement for `netstat` that queries the Linux kernel's `tcp_diag` / `inet_diag` Netlink interface directly to inspect TCP, UDP, RAW, and UNIX domain sockets with minimal overhead.

| Flag | Description |
| :--- | :--- |
| `-t` / `-u` / `-x` / `-w` | Filters by socket type: TCP (`-t`), UDP (`-u`), UNIX domain sockets (`-x`), RAW (`-w`). |
| `-l` / `-a` | Shows only listening sockets (`-l`) or all listening and established sockets (`-a`). |
| `-n` | Numeric output (does not resolve IP addresses or `/etc/services` port names). |
| `-p` | Displays the process name, PID, and file descriptor holding the socket (requires `root`). |
| `-e` / `-o` | Shows extended socket details (UID, inode, cgroup) and TCP timer information. |
| `state <state>` | Filters by TCP state (`established`, `listening`, `syn-sent`, `time-wait`). |

### Practical Auditing Examples:
```bash
# 1. Audit all listening TCP and UDP ports with owning process PIDs and extended UID/inode metadata
sudo ss -tulnpe

# 2. Filter established outbound connections to port 443 or 8443
sudo ss -tnp state established '( dport = :443 or dport = :8443 )'
```

---

## C.1.14 `ip` (`iproute2`) — Network Interface, Routing, Neighbor & Namespace Manager

**Purpose**: Configures and audits Linux network interfaces, IPv4/IPv6 addresses, routing tables, policy routing rules, ARP/NDP neighbor caches, and network namespaces (`netns`).

| Object / Subcommand | Description |
| :--- | :--- |
| `ip -br addr show` | Displays a concise, brief summary table of interfaces, operational state, and IP addresses. |
| `ip -d link show` | Displays detailed Layer-2 interface attributes (MAC address, VLAN tags, `veth` peer, `promisc` mode). |
| `ip route show table all` | Displays all kernel routing tables (including `local`, `main`, and custom policy routing tables). |
| `ip neigh show` | Displays the ARP (IPv4) and NDISC (IPv6) neighbor cache (detects ARP spoofing / `REACHABLE` states). |
| `ip netns list` / `exec` | Lists isolated network namespaces in `/var/run/netns` or executes a command inside a namespace. |

### Practical Auditing Examples:
```bash
# 1. Check if any network interface has PROMISC (promiscuous packet capture mode) enabled
ip -d link show | grep -B 1 'PROMISC'

# 2. Audit listening sockets inside an isolated container or VPN network namespace
sudo ip netns exec vpn_ns ss -tulnp
```

---

## C.1.15 `iptables` & `nftables` (`nft`) — Linux Kernel Netfilter Firewall Auditors

**Purpose**: Inspects and manages packet filtering, Network Address Translation (NAT), and connection tracking rules enforced by the Linux kernel's Netfilter hooks (`NF_INET_PRE_ROUTING`, `INPUT`, `FORWARD`, `OUTPUT`, `POST_ROUTING`).

| Command / Flag | Description |
| :--- | :--- |
| `iptables -L -n -v --line-numbers` | Lists all rules in the `filter` table with numeric IPs/ports, packet/byte counters, and rule numbers. |
| `iptables -t nat -L -n -v` | Inspects `PREROUTING`, `OUTPUT`, and `POSTROUTING` NAT / port-forwarding rules. |
| `iptables-save` | Dumps the complete active `iptables` ruleset across all tables in atomic configuration format. |
| `nft list ruleset` | Dumps the complete active `nftables` tables, chains, sets, and rules (modern default on Debian/RHEL/Ubuntu). |

### Practical Auditing Examples:
```bash
# 1. Inspect the complete active nftables firewall policy (including Docker/firewalld chains)
sudo nft list ruleset

# 2. Audit legacy iptables filter and nat tables with packet hit counters
sudo iptables -L -n -v --line-numbers && sudo iptables -t nat -L -n -v
```

---

## C.1.16 `systemctl` & `systemd-analyze` — Systemd Service & Sandboxing Manager

**Purpose**: Introspects and controls the `systemd` init system (PID 1), manages `.service`, `.timer`, and `.socket` units, and evaluates unit sandboxing exposure scores.

| Subcommand | Description |
| :--- | :--- |
| `list-units --type=service --state=running` | Lists all currently active service daemons. |
| `list-timers --all` | Lists all scheduled `systemd.timer` units with next/last execution timestamps. |
| `cat <unit>` | Prints the full unit file and any `/etc/systemd/system/<unit>.d/*.conf` drop-in overrides. |
| `show <unit>` | Dumps all effective properties (including `User=`, `CapabilityBoundingSet=`, `ExecStart=`). |
| `systemd-analyze security [<unit>]` | Calculates a numerical privilege exposure rating (`0.0 SAFE` to `10.0 UNSAFE`) for running services. |

### Practical Auditing Examples:
```bash
# 1. Audit all active systemd timers and the services they trigger
systemctl list-timers --all

# 2. Evaluate the sandboxing posture of sshd.service and nginx.service
systemd-analyze security sshd.service nginx.service
```

---

## C.1.17 `journalctl` — Systemd Binary Journal Query & Forensic Log Analyzer

**Purpose**: Queries the structured, indexed binary logs managed by `systemd-journald` (`/var/log/journal/`), filtering by unit, UID, binary path, syslog priority, boot session, and time window.

| Flag | Description |
| :--- | :--- |
| `-u <unit>` | Filters log entries belonging to a specific `systemd` unit (e.g., `-u ssh.service`). |
| `-b [<N>]` | Shows logs from a specific boot (`-b 0` current boot, `-b -1` previous boot before a crash/reboot). |
| `-p <priority>` | Filters by syslog severity level (`emerg` [0], `alert` [1], `crit` [2], `err` [3], `warning` [4]). |
| `--since` / `--until` | Filters by timestamp (`"2026-11-01 08:00:00"`, `"1 hour ago"`, `"today"`). |
| `_UID=<uid>` / `_COMM=<bin>` | Filters by trusted kernel-supplied journal fields (`_UID=0`, `_COMM=sudo`, `_TRANSPORT=audit`). |
| `-o json-pretty` | Outputs full structured metadata fields (including `_PID`, `_CMDLINE`, `_SELINUX_CONTEXT`) as JSON. |

### Practical Auditing Examples:
```bash
# 1. Inspect all sudo and pkexec invocations across the last 24 hours with full JSON metadata
sudo journalctl _COMM=sudo + _COMM=pkexec --since "24 hours ago" -o short-precise

# 2. Verify cryptographic Forward Secure Sealing (FSS) integrity of tamper-evident journal files
sudo journalctl --verify
```

---

## C.1.18 `auditctl` & `ausearch` — Linux Kernel Audit Framework (`auditd`) CLI

**Purpose**: `auditctl` configures real-time kernel audit rules (filesystem watches `-w` and system call rules `-a`) and inspects audit subsystem status; `ausearch` queries `/var/log/audit/audit.log` by event key, syscall, UID, or Mandatory Access Control (AVC) denial.

| Utility & Flag | Description |
| :--- | :--- |
| `auditctl -s` | Displays kernel audit subsystem status (`enabled`, `locked`, `pid`, `backlog`, `lost` events). |
| `auditctl -l` | Lists all active filesystem watch and syscall audit rules loaded in the kernel. |
| `auditctl -w <path> -p <rwxa> -k <key>` | Adds a watch on `<path>` for Read (`r`), Write (`w`), Execute (`x`), or Attribute change (`a`). |
| `ausearch -k <key> -i` | Searches audit logs by rule key (`-k`) and interprets numeric UIDs/syscalls into human names (`-i`). |
| `ausearch -m AVC,USER_AVC -ts recent` | Searches for SELinux/AppArmor Mandatory Access Control denial events. |
| `aureport --auth --summary` | Generates summary statistical reports of authentication failures, anomalies, and executable runs. |

### Practical Auditing Examples:
```bash
# 1. List all active kernel audit rules and verify whether the configuration is locked (enabled=2)
sudo auditctl -s && sudo auditctl -l

# 2. Search audit logs for any modifications to /etc/passwd or /etc/sudoers with interpreted usernames
sudo ausearch -k identity_tampering -i
```

---

## C.1.19 `getcap` & `setcap` — POSIX File Capabilities Auditors

**Purpose**: Inspects (`getcap`) and modifies (`setcap`) the `security.capability` extended attribute on executables, controlling which discrete POSIX capabilities are granted upon `execve()`.

| Command / Syntax | Description |
| :--- | :--- |
| `getcap -r <dir>` | Recursively scans `<dir>` and outputs all files carrying POSIX file capabilities. |
| `setcap <caps>=<flags> <file>` | Assigns Permitted (`p`), Effective (`e`), and/or Inheritable (`i`) capabilities to `<file>`. |
| `setcap -r <file>` | Completely removes all extended file capabilities from `<file>`. |

### Practical Auditing Examples:
```bash
# 1. Scan the entire filesystem for binaries carrying POSIX capabilities
getcap -r / 2>/dev/null

# 2. Remediation: Remove unintended capabilities from a scripting interpreter
sudo setcap -r /usr/bin/python3.11
```

---

## C.1.20 `getfacl` & `setfacl` — POSIX Extended Access Control List Utilities

**Purpose**: Views (`getfacl`) and configures (`setfacl`) fine-grained POSIX Extended ACLs (`system.posix_acl_access` and `system.posix_acl_default`), which grant permissions to additional individual users or groups beyond the single owning UID/GID shown by `ls -l` (indicated by a trailing `+` in `ls -l` mode output, e.g., `-rw-rwxr--+`).

| Command / Flag | Description |
| :--- | :--- |
| `getfacl -R -s <dir>` | Recursively lists extended ACLs in `<dir>`, skipping (`-s`) files that only have base `rwx` mode bits! |
| `setfacl -m u:<user>:<rwx> <file>` | Modifies/adds an extended ACL entry for a specific user on `<file>`. |
| `setfacl -x u:<user> <file>` | Removes a specific user's extended ACL entry from `<file>`. |
| `setfacl -b <file>` | Strips **all** extended ACL entries from `<file>`, reverting strictly to standard POSIX owner/group/other bits. |

### Practical Auditing Examples:
```bash
# 1. Audit /etc and /usr/local/bin for any files possessing hidden Extended POSIX ACLs (-s skips base-only files)
getfacl -R -s /etc /usr/local/bin 2>/dev/null

# 2. Strip an unauthorized extended ACL from a sensitive configuration file
sudo setfacl -b /etc/shadow
```

---

## C.1.21 `chmod`, `chown` & `chattr` / `lsattr` — Inode Mode, Ownership & Immutable Attributes

**Purpose**: Manages POSIX file mode bits (`chmod`), UID/GID ownership (`chown`), and Linux Second Extended Filesystem (`ext2/ext3/ext4`, `xfs`, `btrfs`) inode flags (`lsattr` / `chattr`).

| Utility & Flag | Description |
| :--- | :--- |
| `chmod u-s,g-s <file>` | Strips the Set-UID (`u-s`) and Set-GID (`g-s`) bits from a binary. |
| `chown -h root:root <file>` | Sets owner and group to `root:root` (`-h` changes ownership of a symlink itself rather than dereferencing its target, preventing symlink race attacks!). |
| `lsattr -a <dir>` | Lists extended filesystem inode attributes (such as `i` immutable and `a` append-only). |
| `chattr +i <file>` | Marks `<file>` **immutable** (`EXT4_IMMUTABLE_FL`): even `root` cannot modify, rename, hardlink, or delete the file until `chattr -i` is run (requires `CAP_LINUX_IMMUTABLE`). |
| `chattr +a <logfile>` | Marks `<logfile>` **append-only**: processes may open the file in append mode to write new log lines, but cannot truncate or overwrite existing log lines. |

### Practical Auditing Examples:
```bash
# 1. Protect critical configuration files from accidental or unauthorized modification with the immutable flag
sudo chattr +i /etc/passwd /etc/shadow /etc/sudoers
lsattr /etc/passwd /etc/shadow /etc/sudoers
```

---
---

# Section C.2: Network Diagnostics, Packet Analysis & Secure Transport Utilities

## C.2.1 `nmap` — Network Mapper & Service / TLS / Script Security Auditor

**Purpose**: Industry-standard network discovery, port state auditing, service version fingerprinting, and NSE (Nmap Scripting Engine) configuration compliance scanner.

| Flag | Category | Description |
| :--- | :--- | :--- |
| `-sn` | Host Discovery | Ping scan only (ARP on local LAN, ICMP Echo/Timestamp + TCP SYN 443/ACK 80); disables port scanning. |
| `-Pn` | Host Discovery | Treats all targets as online (skips host discovery phase when ICMP is filtered by firewalls). |
| `-sS` | Port Scan Technique | TCP SYN (Half-Open) scan; default when run with `root` / `cap_net_raw`. |
| `-sT` | Port Scan Technique | Full TCP `connect()` system call scan (used when running without raw socket privileges). |
| `-sU` | Port Scan Technique | UDP port scan (e.g., auditing DNS `53`, SNMP `161`, NTP `123`, NetBIOS `137`). |
| `-p <range>` / `-p-` | Port Specification | Scans specified ports (`-p 22,80,443,445,3389`) or all 65,535 ports (`-p-`). |
| `-sV` | Service Detection | Probes open ports to determine service protocol, application name, and version number. |
| `-sC` / `--script=<nse>` | NSE Auditing | Runs default safe NSE scripts (`-sC`) or specific compliance/audit scripts (e.g., `ssl-enum-ciphers`, `smb2-security-mode`). |
| `-T<0-5>` / `--min-rate` | Timing & Performance | Timing template (`-T3` normal, `-T4` aggressive); `--min-rate <N>` enforces packet transmission rate. |
| `-oA <basename>` | Output Formatting | Saves scan results simultaneously in Normal (`.nmap`), XML (`.xml`), and Grepable (`.gnmap`) formats. |

### Practical Defensive Auditing Examples:
```bash
# 1. Audit an Active Directory subnet for hosts where SMB Signing is not required (Relay risk audit)
nmap -Pn -n -p 445 --script smb2-security-mode 10.10.20.0/24 -oA smb_signing_audit

# 2. Audit TLS cipher suites and certificate strength on enterprise HTTPS / LDAPS endpoints
nmap -Pn -p 443,636,8443 --script ssl-enum-ciphers,ssl-cert 10.10.20.10-50
```

Sample annotated output:
```text
PORT    STATE SERVICE
445/tcp open  microsoft-ds
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
```

---

## C.2.2 `tcpdump` — Command-Line BPF Packet Capture & Wire Analyzer

**Purpose**: Captures and inspects network packets on an interface using kernel **Berkeley Packet Filter (BPF)** expressions, writing raw `.pcap` files for forensic analysis or decoding headers inline.

| Flag | Description |
| :--- | :--- |
| `-i <interface>` / `-i any` | Specifies the capture interface (`eth0`, `wlan0`, or `any` for all interfaces). |
| `-n` / `-nn` | Does not resolve hostnames (`-n`) or both hostnames and port names (`-nn`). |
| `-v` / `-vv` / `-vvv` | Increases protocol decoding verbosity (TTL, IP ID, TCP options, SMB/DNS payloads). |
| `-X` / `-A` | Prints each packet's payload in simultaneous Hex and ASCII (`-X`) or ASCII only (`-A`). |
| `-s <snaplen>` (`-s 0`) | Sets snapshot length in bytes (`-s 0` captures the full packet frame up to 262,144 bytes). |
| `-w <file.pcap>` / `-r <file.pcap>` | Writes raw packets to `<file.pcap>` (`-w`) or reads packets from an existing capture file (`-r`). |
| `-c <count>` | Exits after capturing `<count>` packets. |

### Practical Auditing Examples:
```bash
# 1. Detect unauthenticated LLMNR (UDP 5355), NBT-NS (UDP 137), and mDNS (UDP 5353) broadcast traffic on the LAN
sudo tcpdump -i eth0 -nn -v 'udp port 5355 or udp port 137 or udp port 5353'

# 2. Capture TCP SYN packets without ACK (new connection attempts) excluding SSH management traffic
sudo tcpdump -i eth0 -nn 'tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn and not port 22'
```

---

## C.2.3 `tshark` — Terminal Wireshark Deep Packet Inspection Engine

**Purpose**: Command-line counterpart to Wireshark that applies full Layer-7 **Display Filters** (`-Y`) and extracts specific protocol fields (`-T fields -e <field>`) from live interfaces or forensic `.pcapng` captures.

| Flag | Description |
| :--- | :--- |
| `-r <infile.pcap>` | Reads packets from an existing capture file. |
| `-Y "<display_filter>"` | Applies a Wireshark Display Filter (`http.request`, `tls.handshake.type == 1`, `kerberos`, `ntlmssp`). |
| `-T fields -e <field>` | Extracts only specific protocol dissector fields as tab-separated columns (e.g., `-e ip.src -e dns.qry.name`). |
| `-T json` | Exports full dissected protocol trees in structured JSON format. |
| `-z <statistics>` | Generates protocol hierarchy (`-z io,phs`), conversation tables (`-z conv,tcp`), or HTTP stats (`-z http,tree`). |

### Practical Auditing Examples:
```bash
# 1. Extract TLS ClientHello Server Name Indication (SNI) hostnames and source IPs from a PCAP
tshark -r capture.pcap -Y "tls.handshake.type == 1" -T fields -e ip.src -e ip.dst -e tls.handshake.extensions_server_name

# 2. Audit a PCAP for legacy NTLMSSP authentication events and extract Domain and Username fields
tshark -r capture.pcap -Y "ntlmssp.messagetype == 0x00000003" -T fields -e ip.src -e ip.dst -e ntlmssp.auth.domain -e ntlmssp.auth.username
```

---

## C.2.4 `dig` & `whois` — DNS Resolution, Zone Transfer & Domain Registration Auditors

**Purpose**: `dig` (Domain Information Groper) queries authoritative and recursive DNS servers to inspect resource records (`A`, `AAAA`, `MX`, `TXT`, `SRV`, `CAA`, `DNSKEY`), DNSSEC validation chains (`+dnssec`), and Zone Transfer (`AXFR`) restrictions. `whois` queries regional internet registries (RIRs) and domain registrars for ASN, CIDR ownership, and Abuse contact records.

| Flag / Argument (`dig`) | Description |
| :--- | :--- |
| `@<dns-server>` | Sends the DNS query directly to the specified resolver or authoritative nameserver IP. |
| `<qtype>` | Resource record type (`A`, `AAAA`, `CNAME`, `MX`, `NS`, `TXT`, `SRV`, `SOA`, `CAA`, `ANY`, `AXFR`). |
| `+short` | Outputs only the raw answer data without header/authority boilerplate. |
| `+trace` | Traces delegation path iteratively starting from the internet root hints (`.`). |
| `+dnssec` | Requests DNSSEC `RRSIG` cryptographic signature records. |
| `-x <ip-address>` | Performs a reverse DNS (`PTR` in `in-addr.arpa` / `ip6.arpa`) lookup on an IP address. |

### Practical Auditing Examples:
```bash
# 1. Query Active Directory DNS SRV records to enumerate all Domain Controllers and Kerberos KDCs
dig @10.10.20.10 _ldap._tcp.dc._msdcs.corp.example.lk SRV +short
dig @10.10.20.10 _kerberos._tcp.corp.example.lk SRV +short

# 2. Audit email authentication posture (SPF, DMARC, and CAA records) for an enterprise domain
dig corp.example.lk TXT +short
dig _dmarc.corp.example.lk TXT +short
dig corp.example.lk CAA +short

# 3. Verify that authoritative nameservers properly refuse unauthorized Zone Transfers (AXFR)
dig @ns1.corp.example.lk corp.example.lk AXFR
```

---

## C.2.5 `curl` — HTTP/HTTPS Client & Web API Security Header Auditor

**Purpose**: Transfers data across HTTP/1.1, HTTP/2, HTTP/3, FTP, and LDAP endpoints with granular control over request methods, headers, cookies, TLS client certificates, and proxy routing.

| Flag | Description |
| :--- | :--- |
| `-I` (`--head`) / `-i` | Fetches HTTP response headers only (`-I`) or includes response headers above the body (`-i`). |
| `-v` / `-s` / `-S` | Verbose TLS/HTTP handshake debugging (`-v`), silent mode (`-s`), show errors (`-S`). |
| `-L` (`--location`) | Follows `301`/`302`/`307`/`308` HTTP `Location:` redirects automatically. |
| `-X <METHOD>` | Specifies the HTTP request method (`GET`, `POST`, `PUT`, `DELETE`, `OPTIONS`, `PATCH`). |
| `-H "Header: Value"` | Adds or overrides an HTTP request header (e.g., `-H "Host: internal.corp.lk"`). |
| `--resolve <host:port:ip>` | Pins hostname resolution to a specific IP address (vital for testing SNI / VirtualHosts before DNS cutover). |
| `--cert <cert>` / `--key <key>` | Authenticates using a Mutual TLS (mTLS) client certificate and private key. |
| `-w "<format>"` | Outputs timing and status metrics (`%{http_code}`, `%{time_total}`, `%{ssl_verify_result}`). |

### Practical Auditing Examples:
```bash
# 1. Audit HTTP Security Response Headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options)
curl -sI https://portal.corp.example.lk | grep -iE '^(strict-transport-security|content-security-policy|x-frame-options|x-content-type-options|referrer-policy|permissions-policy):'
```

---

## C.2.6 `ssh`, `scp` & `rsync` — OpenSSH Administration, Tunneling & File Synchronization

**Purpose**: Provides encrypted remote administration (`ssh`), authenticated file transfer (`scp` / `sftp`), and delta-transfer synchronization (`rsync`).

| Utility & Flag | Description |
| :--- | :--- |
| `ssh -i <id_ed25519>` | Authenticates using a specific Ed25519 or ECDSA private key file. |
| `ssh -J <jump_user@bastion>` | Connects to an isolated internal host through an intermediate SSH Bastion (`ProxyJump`). |
| `ssh -L 127.0.0.1:<lport>:<rhost>:<rport>` | **Local Port Forwarding**: Binds `127.0.0.1:<lport>` locally and tunnels traffic over SSH to `<rhost>:<rport>` (e.g., securely accessing an internal database management port bound to `127.0.0.1`). |
| `ssh -Q cipher` / `ssh -Q kex` | Queries supported ciphers, MACs, and key exchange algorithms on the client. |
| `sshd -T` | Parses `/etc/ssh/sshd_config` (including `Match` blocks) and outputs the complete effective daemon configuration! |
| `rsync -avzP --delete -e ssh` | Synchronizes directories preserving archive permissions (`-a`), compressing in transit (`-z`), showing progress (`-P`), over SSH. |

### Practical Auditing Examples:
```bash
# 1. Audit the running OpenSSH daemon's effective security configuration (PermitRootLogin, PasswordAuthentication, AllowGroups)
sudo sshd -T | grep -E '^(permitrootlogin|passwordauthentication|pubkeyauthentication|kbdinteractiveauthentication|maxauthtries|allowgroups|ciphers|kexalgorithms)'
```

---

## C.2.7 `nc` (Netcat / `ncat`) & `socat` — Socket Diagnostic & TLS Relay Utilities

**Purpose**: Reads and writes data across TCP, UDP, UNIX domain, and SCTP sockets for firewall reachability testing, banner verification, and TLS-wrapped socket proxying.

| Command / Syntax | Description |
| :--- | :--- |
| `nc -zv -w 3 <host> <port>` | Zero-I/O mode (`-z`) TCP reachability check with a 3-second timeout (`-w 3`) and verbose output (`-v`). |
| `ncat --ssl -v <host> <port>` | Connects to a TLS-encrypted TCP service and displays certificate details (`nmap-ncat`). |
| `socat - UNIX-CONNECT:<path>` | Connects standard input/output interactively to a local UNIX domain socket (`<path>`). |
| `socat TCP-LISTEN:8443,fork,reuseaddr OPENSSL:127.0.0.1:8080,verify=1` | Wraps or proxies a local service socket with OpenSSL TLS verification. |

---
---

# Section C.3: DevSecOps, Static Analysis (SAST), Secret Scanning & Asset Inventory Tools

## C.3.1 `subfinder` & `amass` — External Attack Surface Management (EASM) Subdomain Inventory

**Purpose**: Discovers organization-owned subdomains using passive Certificate Transparency (`crt.sh`) logs, ASN/BGP routing data, WHOIS records, and DNS datasets so security teams can maintain an accurate external asset inventory and detect "Shadow IT" deployments.

| Tool & Flag | Description |
| :--- | :--- |
| `subfinder -d <domain> -all -silent` | Queries all configured passive OSINT and Certificate Transparency sources for `<domain>`. |
| `subfinder -dL <domains.txt> -o <out.txt>` | Enumerates subdomains for a list of root domains and writes deduplicated output to `<out.txt>`. |
| `amass enum -passive -d <domain>` | Performs strictly passive subdomain discovery without sending active traffic to target infrastructure. |
| `amass intel -asn <ASN>` | Discovers root domains and netblocks registered to a specific Autonomous System Number (ASN). |

### Practical Auditing Examples:
```bash
# 1. Build a passive external subdomain inventory for an organization's root domain
subfinder -d corp.example.lk -all -silent -o external_subdomains.txt
```

---

## C.3.2 `dnsx` & `naabu` — Mass DNS Resolution & SYN Port Inventory Verifiers

**Purpose**: `dnsx` resolves discovered hostnames against trusted DNS resolvers to filter out dead records and detect dangling `CNAME` records (Subdomain Takeover auditing); `naabu` performs fast TCP SYN port verification across inventoried hosts.

| Tool & Flag | Description |
| :--- | :--- |
| `dnsx -l <hosts.txt> -a -aaaa -cname -resp` | Resolves `A`, `AAAA`, and `CNAME` records for a list of hostnames and prints the record values (`-resp`). |
| `dnsx -l <hosts.txt> -cdn -asn` | Identifies which hosts sit behind CDN providers (Cloudflare, Akamai, Fastly, CloudFront) and prints ASN metadata. |
| `naabu -list <hosts.txt> -top-ports 100` | Audits the top 100 TCP ports across inventoried hosts to identify exposed management services. |

### Practical Auditing Examples:
```bash
# 1. Audit all organizational subdomains for CNAME records pointing to deprovisioned cloud storage/PaaS buckets
dnsx -l external_subdomains.txt -cname -resp -silent | tee cname_inventory.txt
```

---

## C.3.3 `httpx` & `katana` — HTTP Tech Stack Fingerprinting & Web Application Crawlers

**Purpose**: `httpx` probes web servers across an asset list to catalog HTTP status codes, TLS certificates, server headers, Wappalyzer technology stacks, and response hashes; `katana` crawls authorized web applications to inventory API endpoints and JavaScript bundles.

| Tool & Flag | Description |
| :--- | :--- |
| `httpx -l <hosts.txt> -sc -title -tech-detect -tls-grab -json` | Probes hosts and outputs HTTP status code (`-sc`), HTML `<title>`, detected web frameworks (`-tech-detect`), and TLS metadata as JSON. |
| `katana -u <https://app.corp.lk> -jc -d 3` | Crawls an authorized web application up to depth 3 (`-d 3`) and parses JavaScript files (`-jc`) to catalog all API routes. |

### Practical Auditing Examples:
```bash
# 1. Inventory all web assets, extract TLS expiration dates and tech stacks, and flag outdated web servers
httpx -l external_subdomains.txt -sc -title -server -tech-detect -tls-grab -json -o web_asset_inventory.json
```

---

## C.3.4 `ffuf` — Fast Web Fuzzer for API Route & VirtualHost Discovery Audits

**Purpose**: High-performance Go-based HTTP testing tool used during authorized application security assessments to verify whether unlinked backup files (`.git/config`, `.env`, `.bak`), undocumented API endpoints, or internal VirtualHosts are exposed on production web servers.

| Flag | Description |
| :--- | :--- |
| `-u <URL>` | Target URL containing the `FUZZ` keyword placeholder (`https://app.corp.lk/FUZZ`). |
| `-w <wordlist:KEYWORD>` | Path to wordlist dictionary mapped to `FUZZ` (default). |
| `-mc <codes>` / `-fc <codes>` | Match (`-mc 200,204,301,302,401,403`) or Filter out (`-fc 404`) specific HTTP status codes. |
| `-fs <size>` / `-fw <words>` / `-fl <lines>` | Filters out custom soft-404 responses by byte size (`-fs`), word count (`-fw`), or line count (`-fl`). |
| `-rate <N>` / `-p <sec>` | Limits request rate (`-rate 20` req/sec) to prevent degrading target service availability. |
| `-ac` | Automatically calibrates response filtering baselines before testing. |

### Practical Auditing Examples:
```bash
# 1. Rate-limited DevSecOps QA check verifying no sensitive dotfiles (.env, .git/HEAD, backup archives) are exposed
ffuf -u https://staging.corp.example.lk/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200,403 -ac -rate 25 -o staging_exposure_audit.json -of json
```

---

## C.3.5 `nuclei` — Template-Based Vulnerability & Misconfiguration Compliance Scanner

**Purpose**: Executes declarative YAML templates against web applications, cloud configurations, DNS records, and network services to verify CVE patch compliance, missing security headers, and exposed administrative panels with near-zero false positives.

| Flag | Description |
| :--- | :--- |
| `-u <target>` / `-l <targets.txt>` | Specifies a single target URL/host or a file containing a list of targets. |
| `-t <template-path>` | Specifies template directories or individual `.yaml` templates to execute (e.g., `-t http/misconfiguration/`). |
| `-tags <tags>` | Filters templates by tag (`-tags config,exposure,tls,ssl`). |
| `-s <severity>` | Filters templates by severity (`info`, `low`, `medium`, `high`, `critical`). |
| `-rl <N>` / `-c <N>` | Enforces a global rate limit (`-rl 50` requests/sec) and template concurrency (`-c 10`). |
| `-jsonl -o <out.jsonl>` | Writes structured findings with full matched request/response evidence in JSON Lines format. |

### Practical Auditing Examples:
```bash
# 1. Run safe configuration, TLS, and exposure compliance checks against staging web servers
nuclei -l staging_urls.txt -tags misconfig,exposure,ssl -s low,medium,high,critical -rl 30 -jsonl -o nuclei_compliance.jsonl
```

---

## C.3.6 `trufflehog` & `gitleaks` — Git Repository Secret & Credential Scanners

**Purpose**: Scans Git commit histories, filesystem directories, Docker images, S3 buckets, and CI/CD logs using Shannon entropy analysis and 700+ regular expression detectors to identify accidentally committed API keys, private keys, database connection strings, and cloud tokens.

| Tool & Command | Description |
| :--- | :--- |
| `trufflehog git file://<repo_path> --only-verified --json` | Scans full Git commit history across all branches and filters for active credentials (`--only-verified`). |
| `trufflehog filesystem <dir> --no-verification` | Offline static scan of a local directory without making external network verification calls. |
| `gitleaks detect --source <repo_path> -v --report-path <out.json>` | Scans full Git repository history using fast regex/entropy rules and outputs a structured JSON report. |
| `gitleaks protect --staged -v` | Pre-commit hook mode: scans only `git diff --staged` changes to block developers from committing secrets before `git commit` completes! |

### Practical Auditing Examples:
```bash
# 1. Audit an entire Git repository history offline for leaked secrets and export a SARIF/JSON report
gitleaks detect --source /srv/repos/payment-service --report-format json --report-path gitleaks_audit.json -v

# 2. Enforce pre-commit secret blocking in a local Git workflow
gitleaks protect --staged --verbose
```

---

## C.3.7 `semgrep` & `bandit` — Static Application Security Testing (SAST) Code Auditors

**Purpose**: `semgrep` is a polyglot Abstract Syntax Tree (AST)-aware static analysis engine supporting 30+ languages (Python, Go, Java, TypeScript, C/C++, Terraform, Dockerfile) to detect SQL injection, XSS, insecure deserialization, and framework anti-patterns; `bandit` is the PyCQA specialized AST security linter for Python codebases.

| Tool & Command | Description |
| :--- | :--- |
| `semgrep scan --config=p/default` | Scans codebase using the curated Semgrep Registry security ruleset (`p/ci`, `p/owasp-top-ten`, `p/dockerfile`). |
| `semgrep scan --config=<custom.yaml> --sarif -o out.sarif` | Runs custom organizational AST rules and outputs results in GitHub/GitLab SARIF format. |
| `bandit -r <src_dir> -ll -ii -f json -o bandit.json` | Recursively scans Python files in `<src_dir>`, filtering for Medium/High severity (`-ll`) and Medium/High confidence (`-ii`). |

### Practical Auditing Examples:
```bash
# 1. Run OWASP Top 10 and Secrets AST static analysis across a microservice repository
semgrep scan --config p/owasp-top-ten --config p/secrets /srv/repos/api-gateway

# 2. Audit a Python application for medium- and high-severity security anti-patterns (subprocess shell=True, pickle, weak crypto)
bandit -r ./app -ll -ii
```

---

## C.3.8 `trivy` — Container Image, SBOM, Filesystem & Kubernetes Security Scanner

**Purpose**: Comprehensive open-source vulnerability and misconfiguration scanner built by Aqua Security that audits OS packages (`dpkg`, `rpm`, `apk`), language dependencies (`package-lock.json`, `requirements.txt`, `go.mod`, `pom.xml`), Infrastructure-as-Code (`Dockerfile`, Terraform, Kubernetes manifests), and generates CycloneDX / SPDX **Software Bills of Materials (SBOMs)**.

| Subcommand & Flag | Description |
| :--- | :--- |
| `trivy image --severity HIGH,CRITICAL <image:tag>` | Scans a container image's OS layers and application dependencies for High and Critical CVEs. |
| `trivy image --ignore-unfixed <image:tag>` | Shows only vulnerabilities for which an upstream vendor patch already exists. |
| `trivy fs --scanners vuln,secret,misconfig <dir>` | Scans a local source directory for vulnerable dependencies, hardcoded secrets, and IaC misconfigurations. |
| `trivy config <k8s_manifests_dir>` | Audits Kubernetes YAML, Helm charts, Terraform (`.tf`), and `Dockerfile` files against CIS security benchmarks. |
| `trivy image --format cyclonedx --output sbom.cdx.json <image>` | Generates a standardized CycloneDX SBOM for supply-chain compliance. |

### Practical Auditing Examples:
```bash
# 1. Audit a production container image for patchable High/Critical CVEs and exposed secrets
trivy image --scanners vuln,secret --severity HIGH,CRITICAL --ignore-unfixed nginx:1.25-alpine

# 2. Scan Kubernetes deployment manifests for privileged containers, hostPID, and missing securityContexts
trivy config ./k8s/manifests/
```


---
---

# Section C.4: ELF/PE Binary Inspection, Compiler Hardening & Firmware Analysis Tools

## C.4.1 `file` & `strings` — Magic-Byte File Identification & Static String Extraction

**Purpose**: `file` inspects file headers (magic bytes in `/usr/share/misc/magic.mgc`), ELF architecture headers, linking mode (static vs. dynamic), symbol stripping state, and GNU `BuildID` hashes regardless of filename extension; `strings` extracts contiguous printable ASCII, UTF-8, or UTF-16LE/BE character sequences from binary files.

| Utility & Flag | Description |
| :--- | :--- |
| `file -b -k <binary>` | Brief output (`-b`, omits filename prefix) and keeps matching (`-k`) beyond the first magic rule. |
| `file --mime-type <file>` | Outputs standardized MIME type (`application/x-pie-executable`, `application/x-dosexec`). |
| `strings -a -n <len> <file>` | Scans the entire file (`-a`, not just initialized data sections) for strings of at least `<len>` characters. |
| `strings -t x <file>` | Prints the hexadecimal byte offset (`-t x`) within the file before each extracted string. |
| `strings -e <encoding> <file>` | Specifies character encoding: `s` (7-bit ASCII), `S` (8-bit ISO-8859-1), `l` (16-bit little-endian UTF-16LE, standard in Windows PE binaries!), `b` (16-bit big-endian). |

### Practical Auditing Examples:
```bash
# 1. Verify ELF architecture, PIE compilation, dynamic linker path, and BuildID of a system binary
file /usr/sbin/sshd

# 2. Extract both ASCII and 16-bit UTF-16LE strings with hex offsets from a Windows PE binary or memory dump
strings -a -t x -n 8 sample.exe > ascii_strings.txt
strings -a -t x -e l -n 8 sample.exe > utf16le_strings.txt
```

Sample output of `file /usr/sbin/sshd`:
```text
/usr/sbin/sshd: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=a3c9e4..., for GNU/Linux 3.2.0, stripped
```

---

## C.4.2 `checksec` — Binary Compiler Mitigation & Exploit Hardening Verifier

**Purpose**: Audits ELF binaries, running processes, and kernel configurations to verify whether modern compiler-enforced memory corruption mitigations (**RELRO**, **Stack Canary**, **NX / W^X**, **PIE**, **RPATH/RUNPATH**, **FORTIFY_SOURCE**, and **CFI / Shadow Stack**) are enabled.

| Mitigation Field | Architectural Security Meaning & Compiler Flag |
| :--- | :--- |
| **RELRO** (*Relocation Read-Only*) | - `Partial RELRO` (`-Wl,-z,relro`): Places `.got` before `.bss` and marks internal ELF data sections read-only.<br>- **`Full RELRO`** (`-Wl,-z,relro,-z,now`): Resolves all dynamic symbols at startup before `main()` and marks the entire Global Offset Table (`.got` and `.got.plt`) strictly **Read-Only** (`mprotect(PROT_READ)`), preventing GOT overwrite attacks! |
| **Stack Canary** | - **`Canary found`** (`-fstack-protector-strong` or `-fstack-protector-all`): Places a random 64-bit value from `fs:0x28` between stack buffers and the saved frame pointer/return address (`RIP`), calling `__stack_chk_fail()` if overwritten. |
| **NX** (*No-eXecute / DEP*) | - **`NX enabled`** (`-z noexecstack`): Marks the stack and heap pages non-executable (`PT_GNU_STACK` lacks `PF_X`) via the CPU page table XD/NX bit. |
| **PIE** (*Position-Independent Executable*) | - **`PIE enabled`** (`-fPIE -pie`): Compiles the executable with relative addressing (`ET_DYN` ELF type) so the kernel randomizes the base address of the `.text`, `.data`, and `.bss` segments under ASLR. |
| **RPATH / RUNPATH** | - **`No RPATH` / `No RUNPATH`**: Confirms the binary does not hardcode potentially insecure custom shared library search paths. |
| **FORTIFY** | -Replaces unbounded glibc calls (`memcpy`, `strcpy`, `sprintf`) with bounds-checked variants (`__memcpy_chk`) when `-D_FORTIFY_SOURCE=2` or `3` is used at `-O2`. |

### Practical Auditing Examples:
```bash
# 1. Audit all binaries inside /usr/local/bin to verify compliance with corporate secure build flags
checksec --dir=/usr/local/bin --output=json | jq .

# 2. Audit all currently running daemons on the host for missing PIE or Stack Canaries
sudo checksec --proc-all
```

Sample output:
```text
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY  Fortified  Fortifiable  FILE
Full RELRO      Canary found      NX enabled    PIE enabled     No RPATH   No RUNPATH   No Symbols      Yes      14         28           /usr/sbin/sshd
```

---

## C.4.3 `readelf` — ELF Header, Section, Segment & Dynamic Tag Inspector

**Purpose**: Parses the structural headers of Executable and Linkable Format (ELF) binaries directly without relying on the `BFD` library (`libbfd`), making it resilient against malformed or obfuscated section headers when inspecting unknown binaries.

| Flag | Description |
| :--- | :--- |
| `-h` (`--file-header`) | Displays the ELF File Header (Magic bytes `7f 45 4c 46`, Class 32/64-bit, Endianness, `Type` `EXEC`/`DYN`, Entry point address). |
| `-l` (`--program-headers`) | Displays Program Headers (Segments mapped into memory at runtime, including `PT_LOAD`, `PT_INTERP`, `PT_GNU_STACK`, `PT_GNU_RELRO`). |
| `-S` (`--section-headers`) | Displays Section Headers (`.text`, `.rodata`, `.data`, `.bss`, `.got.plt`, `.dynsym`). |
| `-d` (`--dynamic`) | Displays the `.dynamic` section: lists all required shared libraries (`DT_NEEDED`), `DT_RPATH`, `DT_RUNPATH`, and `BIND_NOW` (Full RELRO). |
| `-s` (`--syms`) | Displays entries in the `.dynsym` (dynamic symbol table) and `.symtab` (if unstripped). |
| `-n` (`--notes`) | Displays ELF notes (`NT_GNU_BUILD_ID` SHA-1 hash and minimum ABI kernel version). |

### Practical Auditing Examples:
```bash
# 1. Inspect dynamic linker tags of a SUID binary for DT_NEEDED dependencies, RPATH/RUNPATH, and BIND_NOW
readelf -d /usr/bin/sudo | grep -E '(NEEDED|RPATH|RUNPATH|BIND_NOW|FLAGS)'

# 2. Check segment permissions in Program Headers to verify no segment has simultaneous Write + Execute (W E) flags
readelf -lW /usr/local/bin/service_bin
```

---

## C.4.4 `nm` — Symbol Table Inspector for Object Files, Archives & Executables

**Purpose**: Lists symbols imported and exported by `.o` object files, `.a` static archives, `.so` shared libraries, and ELF binaries.

| Flag / Symbol Type Code | Description |
| :--- | :--- |
| `-D` (`--dynamic`) | Displays dynamic symbols (`.dynsym`) rather than static `.symtab` symbols (required for stripped production binaries). |
| `-C` (`--demangle`) | Decodes (demangles) low-level C++ / Rust mangled symbol names into human-readable function signatures. |
| `-u` (`--undefined-only`) | Lists only undefined symbols (external functions imported from shared libraries, e.g., `system@GLIBC_2.2.5`). |
| `T` / `t` | Symbol resides in the `.text` (executable code) section (Uppercase = Global/Exported; Lowercase = Local/Static). |
| `D` / `d` / `B` / `b` | Symbol resides in initialized data (`.data`: `D`/`d`) or uninitialized BSS (`.bss`: `B`/`b`). |
| `U` | Symbol is undefined in this file and resolved by the dynamic linker at runtime. |

### Practical Auditing Examples:
```bash
# 1. Check whether a binary imports high-risk C library execution or memory functions (system, popen, execve, gets, strcpy)
nm -Du /usr/local/bin/custom_helper | grep -E '\b(system|popen|execve|execl|execlp|gets|strcpy|sprintf)\b'
```

---

## C.4.5 `objdump` — Binary Disassembler & Section Dump Utility

**Purpose**: Displays information about object files and disassembles machine instructions inside executable sections (`.init`, `.plt`, `.text`, `.fini`) in Intel or AT&T assembly syntax.

| Flag | Description |
| :--- | :--- |
| `-d` (`--disassemble`) | Disassembles only sections expected to contain executable machine instructions. |
| `-M intel` | Renders x86/x86-64 disassembly using clean **Intel syntax** (`mov rax, rdi`) instead of default AT&T syntax (`movq %rdi, %rax`). |
| `-C` (`--demangle`) | Demangles C++ and Rust symbol names in disassembly output. |
| `-R` (`--dynamic-reloc`) | Prints the dynamic relocation entries (`.rela.plt` / `.rela.dyn` mapping GOT slots to imported functions). |
| `-s -j <section>` | Dumps the full hexadecimal and ASCII contents of a specific section (e.g., `-s -j .rodata` or `-s -j .comment`). |

### Practical Auditing Examples:
```bash
# 1. Disassemble the main() function of an unstripped binary in Intel syntax
objdump -d -M intel --disassemble=main /usr/local/bin/validator

# 2. Inspect compiler version metadata stored inside the ELF .comment section
objdump -s -j .comment /usr/local/bin/validator
```

---

## C.4.6 `gdb` — The GNU Project Debugger (Dynamic Binary & Crash Analysis)

**Purpose**: Inspects program execution state, CPU registers, call stacks (backtraces), memory mappings, and thread states either live or post-mortem via core dumps (`core`).

| Command / Flag | Description |
| :--- | :--- |
| `gdb -q --args <bin> <arg1>` | Launches GDB quietly (`-q`) and passes `<arg1>` to the target program. |
| `gdb <bin> <corefile>` | Loads an executable alongside a post-mortem crash `core` dump for root-cause analysis. |
| `set disassembly-flavor intel` | Configures GDB to display x86/x86-64 instructions in Intel syntax. |
| `info proc mappings` | Displays the complete virtual memory address space map (`/proc/<pid>/maps`) with page permissions (`r-xp`, `rw-p`). |
| `info functions` / `info registers` | Lists all defined functions or prints current CPU general-purpose register values (`rax`, `rdi`, `rsi`, `rsp`, `rip`). |
| `bt full` (`backtrace full`) | Prints the complete call stack trace along with local variable values for every stack frame. |
| `x/<N><f><u> <addr>` | Examines memory at `<addr>`: `<N>` count, `<f>` format (`x` hex, `s` string, `i` instruction), `<u>` unit size (`b` byte, `w` 4-byte word, `g` 8-byte giant quadword). |

### Practical Auditing Examples:
```bash
# 1. Non-interactive batch analysis of a crash core dump to extract register state and full stack backtrace
gdb -q -batch -ex "set disassembly-flavor intel" -ex "info registers" -ex "bt full" -ex "x/8i \$pc" /usr/sbin/custom_daemon /var/crash/core.custom_daemon.1234
```

---

## C.4.7 `radare2` (`r2`) & `rabin2` — Command-Line Reverse Engineering & Binary Analysis Suite

**Purpose**: Full-featured hexadecimal editor, multi-architecture disassembler (`x86`, `ARM64`, `MIPS`, `RISC-V`, `JVM`, `WASM`), control-flow graph (`agf`) generator, and binary metadata inspector (`rabin2`).

| Tool / Command | Description |
| :--- | :--- |
| `rabin2 -I <bin>` | Prints comprehensive binary summary (architecture, bits, endianness, canary, NX, PIC/PIE, relocs, stripped status, compiler). |
| `rabin2 -i <bin>` / `-E <bin>` | Lists all imported functions (`-i`) or exported symbols (`-E`). |
| `rabin2 -z <bin>` | Extracts strings strictly from initialized data sections (`.rodata` / `.data`), avoiding false positives in code. |
| `r2 -A <bin>` | Opens `<bin>` in `radare2` and runs automated recursive function and cross-reference analysis (`aaa`). |
| `afl` / `s <sym>` / `pdf` | Inside `r2`: Lists all analyzed functions (`afl`), seeks to a symbol/address (`s main`), and prints disassembled function (`pdf`). |
| `axt @ <addr>` | Inside `r2`: Finds all code/data cross-references (**XREFs** To) referencing `<addr>`. |

### Practical Auditing Examples:
```bash
# 1. Use rabin2 to output a JSON summary of binary security flags and imported functions
rabin2 -Ij /usr/local/bin/iot_daemon | jq .
rabin2 -ij /usr/local/bin/iot_daemon | jq '.imports[].name'
```

---

## C.4.8 `binwalk` — Firmware Image & Embedded Filesystem Extractor

**Purpose**: Scans embedded device firmware images (`.bin`, `.img`, router/IoT updates) for magic byte signatures of bootloaders (`U-Boot`), compressed kernels (`LZMA`, `gzip`, `xz`, `zstd`), device trees (`DTB`), and embedded filesystems (`SquashFS`, `JFFS2`, `UBIFS`, `CPIO`, `ext4`).

| Flag | Description |
| :--- | :--- |
| `<firmware.bin>` | Scans the image and prints a table of hexadecimal offsets and identified embedded file/filesystem signatures. |
| `-e` (`--extract`) | Automatically extracts known archive and filesystem types found inside the firmware image into `_${filename}.extracted/`. |
| `-M` (`--matryoshka`) | Recursively scans and extracts nested archives/filesystems (up to 8 layers deep). |
| `-E` (`--entropy`) | Calculates Shannon entropy across blocks of the firmware file (entropy near `1.0` indicates encryption or high-ratio compression). |
| `--run-as=nobody` | Drops privileges when invoking third-party extraction utilities (`unsquashfs`, `cpio`) for safety. |

### Practical Auditing Examples:
```bash
# 1. Inspect an IoT router firmware image for embedded SquashFS filesystems and U-Boot environment tables
binwalk router_v2.1.4.bin

# 2. Extract embedded filesystems safely to audit hardcoded /etc/shadow hashes and startup scripts
binwalk -eM --run-as=USER router_v2.1.4.bin
```

---
---

# Section C.5: Windows Administration, PowerShell Auditing, Container & Cloud Security CLIs

## C.5.1 `whoami.exe` — Windows Access Token, SID, Group & Privilege Inspector

**Purpose**: Queries the calling process's kernel **Primary Access Token** via `GetTokenInformation()` and displays the user's SID, domain/local group memberships (including Mandatory Integrity Level SIDs), logon ID, and token privileges.

| Flag | Description |
| :--- | :--- |
| `/user` | Displays the current user principal name (`DOMAIN\User`) and Security Identifier (`S-1-5-21-...`). |
| `/groups` | Lists all group memberships, SID attributes (`Mandatory group`, `Enabled`, `Group used for deny only`), and the **Mandatory Label** Integrity Level (`Low`, `Medium`, `High`, `System`). |
| `/priv` | Lists all security privileges held in the Access Token (`SeImpersonatePrivilege`, `SeDebugPrivilege`, etc.) and whether each is currently `Enabled` or `Disabled`. |
| `/all` | Displays user SID, all group SIDs, logon ID, and all token privileges in a single comprehensive report. |
| `/fo <TABLE\|LIST\|CSV>` | Formats output as a table, vertical list, or machine-parseable CSV (`whoami /priv /fo csv \| ConvertFrom-Csv`). |

### Practical Auditing Examples:
```cmd
:: Inspect complete access token state including Mandatory Integrity Level and Privileges
whoami.exe /all
```

Sample annotated output excerpt:
```text
GROUP INFORMATION
-----------------
Group Name                                 Type             SID          Attributes
========================================== ================ ============ ==================================================
BUILTIN\Administrators                     Alias            S-1-5-32-544 Group used for deny only
Mandatory Label\Medium Mandatory Level     Label            S-1-16-8192

PRIVILEGES INFORMATION
----------------------
Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
```

---

## C.5.2 `icacls.exe` — Windows NTFS Discretionary Access Control List (DACL) Utility

**Purpose**: Displays, modifies, backs up, and restores NTFS file and directory Discretionary Access Control Lists (DACLs), ownership, and Mandatory Integrity Labels.

| Flag / Permission Token | Description |
| :--- | :--- |
| `<path>` (No flags) | Displays the current DACL of the specified file or directory. |
| `/save <aclfile> /t` | Backs up DACLs of all matching files and subdirectories (`/t`) to `<aclfile>` before making permission changes. |
| `/inheritance:<e\|d\|r>` | Controls ACL inheritance from parent folder: `e` (enable), `d` (disable and copy inherited ACEs), `r` (remove all inherited ACEs). |
| `/grant:r <SID\|User>:<Perms>` | Grants specified permissions, replacing (`:r`) any previously granted explicit permissions for that trustee. |
| `/remove[:g\|:d] <SID\|User>` | Removes all explicit Allow (`:g`) or Deny (`:d`) ACEs for the specified user or SID. |
| `(OI)` / `(CI)` / `(IO)` / `(NP)` | Inheritance flags: `(OI)` Object Inherit (files), `(CI)` Container Inherit (subfolders), `(IO)` Inherit Only, `(NP)` Do Not Propagate. |
| `F` / `M` / `RX` / `R` / `W` | Basic permission masks: `F` (Full access), `M` (Modify), `RX` (Read & Execute), `R` (Read-only), `W` (Write-only). |

### Practical Auditing Examples:
```cmd
:: 1. Inspect NTFS permissions on a custom service binary and its parent folder
icacls.exe "C:\VendorApp\Service"
icacls.exe "C:\VendorApp\Service\daemon.exe"

:: 2. Hardening: Strip inherited Users write permissions and grant Users strictly Read & Execute (RX)
icacls.exe "C:\VendorApp" /inheritance:r /grant:r "NT AUTHORITY\SYSTEM:(OI)(CI)F" /grant:r "BUILTIN\Administrators:(OI)(CI)F" /grant:r "BUILTIN\Users:(OI)(CI)RX"
```

---

## C.5.3 `sc.exe` — Windows Service Control Manager (SCM) Command-Line Interface

**Purpose**: Communicates with the Service Control Manager (`services.exe`) via RPC to query, configure, start, stop, and inspect the SDDL Security Descriptors of Windows Services and Kernel Drivers.
*(Note: In PowerShell, always type `sc.exe` with the `.exe` extension because `sc` without an extension is a built-in PowerShell alias for `Set-Content`!)*

| Subcommand | Description |
| :--- | :--- |
| `sc.exe query state= all` | Lists the runtime state (`RUNNING`, `STOPPED`) of all registered Windows services. |
| `sc.exe qc <ServiceName>` | Queries the persistent configuration of a service (`BINARY_PATH_NAME`, `START_TYPE`, `SERVICE_START_NAME`). |
| `sc.exe qsidtype <ServiceName>` | Queries the service's Virtual Service Account SID type (`UNRESTRICTED`, `RESTRICTED`, or `NONE`). |
| `sc.exe qprivs <ServiceName>` | Queries the list of required Token Privileges configured for a specific service (`RequiredPrivileges`). |
| `sc.exe sdshow <ServiceName>` | Outputs the service object's DACL and SACL in **Security Descriptor Definition Language (SDDL)** format. |
| `sc.exe config <Svc> binPath= "..."` | Updates a service's executable path (e.g., adding quotes to remediate an unquoted service path). |

### Understanding SDDL (Security Descriptor Definition Language) Output from `sc.exe sdshow`:
An SDDL string takes the form `D:(AceType;AceFlags;Rights;ObjectGuid;InheritObjectGuid;AccountSid)`:
- `A` = Access Allowed; `D` = Access Denied.
- Service Rights: `CC` (Query Config), `LC` (Query Status), `RP` (Start), `WP` (Stop), **`DC` (`SERVICE_CHANGE_CONFIG` — dangerous!)**, **`WD` (`WRITE_DAC` — dangerous!)**, **`WO` (`WRITE_OWNER` — dangerous!)**, **`GA` (`GENERIC_ALL`)**.
- Trustee Shorthands: `SY` (`SYSTEM`), `BA` (`BUILTIN\Administrators`), `IU` (`INTERACTIVE`), `AU` (`Authenticated Users`), `BU` (`BUILTIN\Users`), `WD` (`Everyone`).

```cmd
:: Query configuration, required privileges, and SDDL security descriptor of a service
sc.exe qc Spooler
sc.exe qprivs Spooler
sc.exe sdshow Spooler
```

---

## C.5.4 `schtasks.exe` — Windows Task Scheduler CLI Auditor

**Purpose**: Queries, creates, modifies, and deletes scheduled tasks managed by the Windows Task Scheduler service (`Schedule`).

| Flag | Description |
| :--- | :--- |
| `/query /fo <LIST\|CSV\|TABLE> /v` | Queries all scheduled tasks with verbose details (`Task To Run`, `Run As User`, `Schedule Type`, `Last Result`). |
| `/query /tn "<TaskPath>" /xml` | Exports the raw XML definition of a specific task (including hidden `Actions` and `Principals` blocks). |
| `/change /tn "<TaskPath>" /disable` | Disables a scheduled task without deleting its forensic definition. |

### Practical Auditing Examples:
```powershell
# Parse schtasks CSV output in PowerShell to list non-Microsoft tasks running as SYSTEM
schtasks.exe /query /fo CSV /v | ConvertFrom-Csv |
    Where-Object { $_.'Author' -notmatch 'Microsoft' -and $_.'Run As User' -match 'SYSTEM' } |
    Select-Object 'TaskName', 'Task To Run', 'Run As User', 'Schedule Type' | Format-Table -AutoSize
```

---

## C.5.5 `netsh.exe` — Windows Network Shell, Firewall, Portproxy & Packet Capture CLI

**Purpose**: Audits and manages Windows Defender Firewall rules, IPsec policies, WLAN profiles, HTTP.sys URL ACLs, native packet captures (`netsh trace`), and IPv4/IPv6 TCP port-forwarding rules (`portproxy`).

| Context & Subcommand | Description |
| :--- | :--- |
| `netsh advfirewall show allprofiles` | Displays the operational state (`ON`/`OFF`) and default inbound/outbound action for Domain, Private, and Public firewall profiles. |
| `netsh advfirewall firewall show rule name=all dir=in status=enabled` | Lists all enabled inbound firewall rules with ports, programs, and allowed remote IP scopes. |
| `netsh interface portproxy show all` | **Critical Audit Check**: Displays all kernel-mode (`iphlpsvc`) TCP port-forwarding rules configured on the host (`v4tov4`, `v4tov6`). Adversaries frequently abuse `portproxy` for internal lateral pivoting! |
| `netsh http show urlacl` / `show sslcert` | Lists HTTP.sys reserved URL namespaces (and their SDDL ACLs) and TLS certificate bindings. |
| `netsh trace start capture=yes tracefile=C:\temp\net.etl` | Captures a native NDIS packet trace into an `.etl` file without installing third-party drivers (`WinPcap`/`Npcap`). Stop with `netsh trace stop`. |

### Practical Auditing Examples:
```cmd
:: 1. Audit host for any persistent kernel TCP port-forwarding rules (MITRE ATT&CK T1090)
netsh.exe interface portproxy show all

:: 2. Verify Windows Defender Firewall state across Domain, Private, and Public profiles
netsh.exe advfirewall show allprofiles
```

---

## C.5.6 `wevtutil.exe` & `Get-WinEvent` — Windows Event Log & XPath Query Engines

**Purpose**: `wevtutil.exe` manages Event Log channels (sizing, retention, exporting `.evtx` files) and executes native CLI queries; `Get-WinEvent` is the high-performance PowerShell cmdlet supporting server-side `-FilterHashtable` and `-FilterXPath` queries across Security, System, Sysmon, and PowerShell Operational logs.

| Command / Parameter | Description |
| :--- | :--- |
| `wevtutil el` / `wevtutil gl <LogName>` | Lists all registered Event Log channels (`el`) or displays channel configuration, file path, and maximum size (`gl`). |
| `wevtutil sl Security /ms:1073741824` | Sets the maximum size of the Security event log to 1 GB (`1073741824` bytes) to prevent rapid log rollover. |
| `wevtutil epl <LogName> <Out.evtx>` | Exports a live Event Log channel (or filtered subset `/q:`) to a portable forensic `.evtx` file. |
| `Get-WinEvent -FilterHashtable @{...}` | Filters events inside the native Windows Eventing engine before marshaling objects into PowerShell (10x faster than `Where-Object`). |
| `Get-WinEvent -FilterXPath "<XPath>"` | Queries deeply nested `<EventData><Data Name='...'>` XML elements directly. |

### Practical Auditing Examples:
```powershell
# 1. Query Security Event ID 4625 (Failed Logons) over the last 24 hours and group by TargetUserName and IpAddress
$startTime = (Get-Date).AddHours(-24)
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625; StartTime = $startTime } | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $data = @{}
    foreach ($d in $xml.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }
    [PSCustomObject]@{
        TimeCreated    = $_.TimeCreated
        TargetUserName = $data['TargetUserName']
        LogonType      = $data['LogonType']
        IpAddress      = $data['IpAddress']
        SubStatus      = $data['SubStatus']
    }
} | Format-Table -AutoSize

# 2. Query PowerShell Operational Log (Event ID 4104 - Script Block Logging) for high-severity script blocks
Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-PowerShell/Operational'; Id = 4104; Level = 3 } -MaxEvents 20 |
    Select-Object TimeCreated, Message
```

---

## C.5.7 `certutil.exe` — Windows PKI, Certificate Store & File Hash Inspector

**Purpose**: Built-in Windows tool for inspecting local/domain Certificate Stores, verifying Active Directory Certificate Services (ADCS) CA configurations, checking Certificate Revocation Lists (CRLs), and computing cryptographic file hashes (`SHA256`, `SHA512`).

| Flag / Argument | Description |
| :--- | :--- |
| `-hashfile <file> SHA256` | Computes the cryptographic SHA-256 hash of `<file>` (native equivalent to PowerShell `Get-FileHash`). |
| `-store My` / `-store -user My` | Displays certificates in the Local Machine (`My`) or Current User (`-user My`) Personal certificate store. |
| `-viewstore -enterprise NTAuth` | Inspects the Active Directory Forest's `NTAuthCertificates` store (lists all CAs trusted to issue smart card / PKINIT logon certificates!). |
| `-TCAInfo` | Displays Enterprise CA configuration and published Certificate Templates in Active Directory. |
| `-getreg policy\EditFlags` | Queries the CA's active `EditFlags` bitmask (used on a CA server to verify `EDITF_ATTRIBUTESUBJECTALTNAME2` is disabled). |

### Practical Auditing Examples:
```cmd
:: 1. Audit all Certification Authorities trusted in the Forest NTAuthCertificates store for Kerberos PKINIT
certutil.exe -enterprise -store NTAuth

:: 2. On an Enterprise CA server, verify whether EDITF_ATTRIBUTESUBJECTALTNAME2 (ESC6) is enabled
certutil.exe -getreg policy\EditFlags
```

---

## C.5.8 `Get-Acl` & `Set-Acl` — PowerShell Security Descriptor Auditing Cmdlets

**Purpose**: Retrieves and modifies .NET `ObjectSecurity` descriptors across all PowerShell drive providers—including the NTFS Filesystem (`C:\`), Windows Registry (`HKLM:\`, `HKCU:\`), and Active Directory (`AD:\DC=corp,...`).

| Parameter / Property | Description |
| :--- | :--- |
| `(Get-Acl <Path>).Owner` | Returns the Owner principal of the file, registry key, or Active Directory object. |
| `(Get-Acl <Path>).Access` | Returns the collection of Discretionary Access Control Entries (`ACEs`) with `IdentityReference`, `AccessControlType`, `IsInherited`, and rights bitmasks. |
| `(Get-Acl <Path>).Sddl` | Returns the raw SDDL string representation of the Security Descriptor. |
| `-Audit` | Includes the System Access Control List (**SACL**) audit entries alongside the DACL. |

### Practical Auditing Examples:
```powershell
# 1. Inspect explicit (non-inherited) DACL entries on an Active Directory Organizational Unit
Import-Module ActiveDirectory
(Get-Acl -Path "AD:\OU=Workstations,DC=corp,DC=example,DC=lk").Access |
    Where-Object { -not $_.IsInherited } |
    Select-Object IdentityReference, ActiveDirectoryRights, AccessControlType, ObjectType |
    Format-Table -AutoSize
```

---

## C.5.9 `docker` — Container Runtime Security & Isolation Auditor

**Purpose**: Manages and inspects OCI containers, images, volumes, networks, and daemon configurations via the Docker Engine CLI.

| Subcommand & Flag | Description |
| :--- | :--- |
| `docker info --format '{{json .SecurityOptions}}'` | Outputs the active host kernel security modules enforced by `dockerd` (`apparmor`, `seccomp`, `selinux`, `rootless`, `userns`). |
| `docker ps --no-trunc` | Lists all running containers with full, untruncated command lines and container IDs. |
| `docker inspect <container>` | Outputs complete low-level JSON metadata (`HostConfig.Privileged`, `CapAdd`, `CapDrop`, `PidMode`, `NetworkMode`, `Mounts`). |
| `docker history --no-trunc <image>` | Displays the complete Dockerfile build history of every image layer (used to audit whether secrets were baked into earlier layers!). |
| `docker diff <container>` | Lists all files Added (`A`), Changed (`C`), or Deleted (`D`) inside a running container's writable overlay layer compared to its base image! |

### Practical Auditing Examples:
```bash
# 1. Forensic Incident Response: Inspect which files have been modified or dropped inside a running container's filesystem
docker diff webapp_prod_1

# 2. Audit all running containers for dangerous host namespace sharing or privileged flags
docker inspect $(docker ps -q) | jq '.[] | {Name: .Name, User: .Config.User, Privileged: .HostConfig.Privileged, PidMode: .HostConfig.PidMode, NetworkMode: .HostConfig.NetworkMode, CapAdd: .HostConfig.CapAdd, Mounts: [.Mounts[].Source]}'
```

---

## C.5.10 `kubectl` — Kubernetes Cluster RBAC & Pod Security Posture Auditor

**Purpose**: Communicates with the Kubernetes API Server (`kube-apiserver`) to inspect workloads, namespaces, Secrets, NetworkPolicies, and Role-Based Access Control (`ClusterRole`, `ClusterRoleBinding`, `Role`, `RoleBinding`) permissions.

| Subcommand & Flag | Description |
| :--- | :--- |
| `kubectl auth can-i --list [-n <ns>]` | Lists all API verbs and resources the current user or ServiceAccount is authorized to access. |
| `kubectl auth can-i <verb> <resource> --as=<user\|sa>` | Impersonation audit check: tests whether a specific ServiceAccount or user can perform `<verb>` on `<resource>`. |
| `kubectl get pods -A -o json` | Exports all Pod specifications across all namespaces (`-A`) in JSON format for `jq` security auditing. |
| `kubectl get clusterrolebindings -o wide` | Lists cluster-wide RBAC bindings (e.g., auditing who is bound to `cluster-admin`). |
| `kubectl get networkpolicies -A` | Audits whether namespaces enforce default-deny ingress/egress `NetworkPolicy` segmentation. |

### Practical Auditing Examples:
```bash
# 1. Audit all Pods across the cluster for containers running as privileged, hostPID, hostNetwork, or root (runAsNonRoot != true)
kubectl get pods -A -o json | jq -r '.items[] | select(.spec.hostPID == true or .spec.hostNetwork == true or .spec.containers[].securityContext.privileged == true) | "\(.metadata.namespace)/\(.metadata.name)"'

# 2. Audit all ClusterRoleBindings bound to the superuser 'cluster-admin' ClusterRole
kubectl get clusterrolebindings -o json | jq -r '.items[] | select(.roleRef.name == "cluster-admin") | "\(.metadata.name) -> \(.subjects)"'
```

---

## C.5.11 `aws` — Amazon Web Services Cloud Security Auditing CLI

**Purpose**: Official AWS command-line interface for auditing Identity and Access Management (IAM), S3 bucket policies, EC2 Security Groups, KMS keys, GuardDuty findings, and CloudTrail telemetry.

| Service & Command | Description |
| :--- | :--- |
| `aws sts get-caller-identity` | Returns the AWS Account ID, IAM UserId, and ARN of the active credential profile (safe `whoami` equivalent). |
| `aws iam get-account-authorization-details` | Downloads a complete JSON snapshot of **all** IAM Users, Groups, Roles, and Managed/Inline Policies in the AWS account for offline graph auditing! |
| `aws iam generate-credential-report` / `get-credential-report` | Generates and retrieves the account-wide CSV report showing MFA status, password age, and Access Key rotation dates for all IAM users (including the `root` account). |
| `aws s3api get-public-access-block --bucket <name>` | Verifies that all four S3 `PublicAccessBlock` controls (`BlockPublicAcls`, `IgnorePublicAcls`, `BlockPublicPolicy`, `RestrictPublicBuckets`) are enabled. |
| `aws ec2 describe-security-groups` | Audits VPC Security Groups for overly permissive `0.0.0.0/0` or `::/0` ingress rules on management ports (`22`, `3389`). |

### Practical Auditing Examples:
```bash
# 1. Audit EC2 Security Groups for any inbound rule allowing unrestricted 0.0.0.0/0 access to SSH (22) or RDP (3389)
aws ec2 describe-security-groups --query "SecurityGroups[?IpPermissions[?contains(IpRanges[].CidrIp, '0.0.0.0/0') && (FromPort==\`22\` || FromPort==\`3389\`)]].{GroupId:GroupId,GroupName:GroupName}" --output table

# 2. Export complete IAM authorization posture for offline privilege-escalation path analysis
aws iam get-account-authorization-details --output json > aws_iam_posture_snapshot.json
```

---

## C.5.12 `az` & `gcloud` — Microsoft Azure / Entra ID & Google Cloud Security Auditing CLIs

**Purpose**: Official command-line interfaces for auditing **Microsoft Azure** subscriptions / **Microsoft Entra ID** tenants (`az`) and **Google Cloud Platform** organizations/projects (`gcloud`).

| CLI & Command | Description |
| :--- | :--- |
| `az account show` | Displays the currently authenticated Azure Tenant ID, Subscription ID, and user/service principal identity. |
| `az role assignment list --all --include-inherited` | Lists all Azure RBAC role assignments (`Owner`, `Contributor`, `User Access Administrator`) across the subscription. |
| `az ad user list` / `az ad sp list --all` | Audits Microsoft Entra ID user accounts and Enterprise Application Service Principals. |
| `az network nsg rule list -g <rg> --nsg-name <nsg>` | Audits Azure Network Security Group (NSG) inbound/outbound rules. |
| `gcloud auth list` / `gcloud config list` | Displays active GCP authenticated accounts and project configuration. |
| `gcloud projects get-iam-policy <project-id> --format=json` | Exports the complete GCP Project IAM policy bindings (`roles/owner`, `roles/editor`, `roles/iam.serviceAccountTokenCreator`). |
| `gcloud compute firewall-rules list` | Lists all VPC firewall rules across the GCP project with source ranges and target tags. |

### Practical Auditing Examples:
```bash
# 1. Azure: List all principals assigned the 'Owner' or 'User Access Administrator' role at the Subscription scope
az role assignment list --all --query "[?roleDefinitionName=='Owner' || roleDefinitionName=='User Access Administrator'].{Principal:principalName, Type:principalType, Role:roleDefinitionName, Scope:scope}" -o table

# 2. Google Cloud: Audit a GCP Project IAM policy for external 'allUsers' or 'allAuthenticatedUsers' bindings
gcloud projects get-iam-policy my-production-project --format=json | jq '.bindings[] | select(.members[] | test("^(allUsers|allAuthenticatedUsers)$"))'
```

---
---

# Section C.6: Master Rapid-Response Auditing Task Index

Use the quick-reference index below to select the exact command for common high-priority security auditing tasks:

| Security Auditing Objective | Operating System / Platform | Authoritative CLI Command |
| :--- | :--- | :--- |
| **Find all SUID/SGID binaries on local disk** | Linux | `find / -xdev -type f -perm /6000 -ls 2>/dev/null` |
| **Find all files with POSIX Capabilities** | Linux | `getcap -r / 2>/dev/null` |
| **Find files with hidden Extended POSIX ACLs** | Linux | `getfacl -R -s /etc /usr/local/bin 2>/dev/null` |
| **Verify compiler hardening (PIE/RELRO/Canary/NX)** | Linux (ELF) | `checksec --file=/path/to/binary` |
| **Inspect ELF `RPATH` / `RUNPATH` tags** | Linux (ELF) | `readelf -d /path/to/binary \| grep -E '(RPATH\|RUNPATH)'` |
| **Evaluate `systemd` unit sandboxing posture** | Linux | `systemd-analyze security <service.service>` |
| **Audit effective `sshd` daemon configuration** | Linux | `sudo sshd -T` |
| **List listening sockets with PID & security context** | Linux | `sudo ss -tulnpeZ` |
| **Inspect current Windows Access Token & Privileges** | Windows | `whoami.exe /all` |
| **Inspect Windows Service DACL in SDDL format** | Windows | `sc.exe sdshow <ServiceName>` |
| **Detect kernel TCP port-forwarding (`portproxy`)** | Windows | `netsh.exe interface portproxy show all` |
| **Audit Forest CAs trusted for Kerberos PKINIT** | Windows / AD | `certutil.exe -enterprise -store NTAuth` |
| **Detect unauthenticated LLMNR/NBT-NS on LAN** | Network | `sudo tcpdump -i eth0 -nn 'udp port 5355 or udp port 137'` |
| **Verify SMB Signing enforcement across subnet** | Network / AD | `nmap -Pn -n -p 445 --script smb2-security-mode <CIDR>` |
| **Scan Git repository history for leaked secrets** | DevSecOps | `gitleaks detect --source . --verbose` |
| **Scan container image for High/Critical CVEs** | Containers | `trivy image --severity HIGH,CRITICAL <image:tag>` |
| **Detect privileged Pods across Kubernetes** | Kubernetes | `kubectl get pods -A -o json \| jq '.items[] \| select(.spec.containers[].securityContext.privileged==true)'` |
| **Export full AWS IAM authorization graph** | AWS Cloud | `aws iam get-account-authorization-details > iam.json` |
