# PART IX: OPERATING SYSTEMS ACCESS CONTROL, PRIVILEGE ARCHITECTURE & ENDPOINT HARDENING

---

# Chapter 40: Linux Access Control, Privilege Management & Hardening Auditing

## 40.1 Introduction to Linux Privilege Architecture

Modern Unix-like operating systems, and specifically the Linux kernel, enforce multi-user isolation through a layered access control architecture. Understanding how privilege boundaries are defined, inherited, transitioned, and enforced inside the kernel is essential for both systems engineers designing resilient infrastructure and security auditors evaluating host posture.

At the core of the Linux security model lies the distinction between **unprivileged user space processes** and **privileged execution contexts**. Historically, traditional Unix systems divided all execution contexts into two coarse categories:
1. **Superuser (`root`, UID `0`)**: Bypassed nearly all kernel permission checks, allowing unrestricted access to filesystems, raw network sockets, process memory spaces, and kernel modules.
2. **Non-root users (UID `> 0`)**: Restricted by Discretionary Access Control (DAC) checks based on ownership and file mode bits.

Over the past two decades, the Linux kernel has evolved beyond this binary model into a defense-in-depth framework composed of five primary enforcement layers:

```
+-------------------------------------------------------------------------+
|                   USER-SPACE PROCESS INVOCATION                         |
|           (execve() system call / fork() / clone() / setuid())          |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
| Layer 1: Discretionary Access Control (DAC)                             |
| - Real, Effective, Saved, and Filesystem UIDs/GIDs                      |
| - POSIX Mode Bits (rwx) & Special Bits (SUID, SGID, Sticky)             |
| - POSIX Access Control Lists (Extended ACLs: getfacl / setfacl)         |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
| Layer 2: POSIX Capabilities (capabilities(7))                           |
| - Partitioning of root privileges into 41+ discrete capability bits     |
| - Thread Capability Sets: Permitted, Effective, Inheritable, Bounding,  |
|   and Ambient capabilities                                              |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
| Layer 3: Linux Security Modules (LSM) / Mandatory Access Control (MAC)  |
| - SELinux (Type Enforcement, Multi-Level Security, Multi-Category)      |
| - AppArmor (Path-based Mandatory Access Profiles)                       |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
| Layer 4: System Call Filtering (Seccomp-BPF)                            |
| - Berkeley Packet Filter programs attached to task_struct               |
| - Restricting syscall surface area (e.g., blocking kexec_load, ptrace)  |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
| Layer 5: Kernel Namespaces & Control Groups (cgroups v1/v2)             |
| - Isolation of Mount, PID, Network, IPC, UTS, User, Cgroup, and Time    |
| - Resource accounting and device access controllers                     |
+-------------------------------------------------------------------------+
```

A privilege escalation condition exists whenever a flaw in configuration, software implementation, or kernel logic permits a principal operating in a lower-trust security domain to cross one or more of these boundaries without authorization. In this chapter, we examine the internal mechanics of each layer, analyze how misconfigurations introduce privilege boundary violations, and build comprehensive auditing and hardening workflows aligned with the **CIS Distribution Independent Linux Benchmark** and **NIST SP 800-53**.

---

## 40.2 Kernel Credential Structures: UID, GID, and Effective Identity

Every process (and thread) running on a Linux system is represented inside the kernel by a `struct task_struct` defined in `<linux/sched.h>`. Attached to each `task_struct` is an immutable pointer to a `struct cred` (defined in `<linux/cred.h>`), which holds the security context of that task.

### 40.2.1 The Four Identity Identifiers

Within `struct cred`, the kernel tracks four distinct User ID (UID) and Group ID (GID) pairs, alongside supplementary group memberships:

```c
/* Simplified excerpt from include/linux/cred.h */
struct cred {
    atomic_t    usage;
    kuid_t      uid;        /* Real UID of the task */
    kgid_t      gid;        /* Real GID of the task */
    kuid_t      suid;       /* Saved UID of the task */
    kgid_t      sgid;       /* Saved GID of the task */
    kuid_t      euid;       /* Effective UID of the task */
    kgid_t      egid;       /* Effective GID of the task */
    kuid_t      fsuid;      /* UID for VFS ops */
    kgid_t      fsgid;      /* GID for VFS ops */
    unsigned    securebits; /* SUID-less security management */
    kernel_cap_t cap_inheritable; /* Capabilities inheritable by child */
    kernel_cap_t cap_permitted;   /* Capabilities task is permitted to use */
    kernel_cap_t cap_effective;   /* Capabilities currently active */
    kernel_cap_t cap_bset;        /* Capability bounding set */
    kernel_cap_t cap_ambient;     /* Ambient capabilities */
    struct group_info *group_info; /* Supplementary groups */
    struct user_namespace *user_ns; /* User namespace reference */
};
```

Each of the four identifiers serves a distinct architectural role:

| Identifier | Kernel Field | Purpose and Security Role |
| :--- | :--- | :--- |
| **Real UID / GID** (`RUID` / `RGID`) | `cred->uid`, `cred->gid` | Identifies the actual user who launched the process. Used primarily for accounting and determining permissions to send signals (`kill(2)`) between processes. |
| **Effective UID / GID** (`EUID` / `EGID`) | `cred->euid`, `cred->egid` | Determines the active privilege level of the process for most kernel checks (shared memory, IPC, network port binding, and initial capability assignment). |
| **Saved Set-UID / Set-GID** (`SUID` / `SGID`) | `cred->suid`, `cred->sgid` | Stores the previous `EUID` when a privileged process temporarily drops privileges using `seteuid()`, allowing it to restore privileges later if required, or permanently drop them via `setresuid()`. |
| **Filesystem UID / GID** (`FSUID` / `FSGID`) | `cred->fsuid`, `cred->fsgid` | Used specifically by the Virtual File System (VFS) layer to verify permissions when opening, reading, writing, or unlinking files. Normally mirrors `EUID`/`EGID` unless explicitly changed by `setfsuid(2)` (historically used by user-space NFS daemons). |

### 40.2.2 Inspecting Process Credentials in `/proc`

Administrators and security auditors can inspect the live `struct cred` values of any running process through the `/proc/<pid>/status` pseudo-file. The `Uid:` and `Gid:` lines output four tab-separated integers corresponding to **Real**, **Effective**, **Saved Set**, and **Filesystem** IDs respectively:

```bash
# Inspecting the credential state of the current shell and a privileged daemon
grep -E '^(Name|Uid|Gid|Groups|Cap|NoNewPrivs|Seccomp)' /proc/self/status
```

Example output from `/proc/self/status` for a standard user (`UID 1001`):

```text
Name:   bash
Uid:    1001    1001    1001    1001
Gid:    1001    1001    1001    1001
Groups: 27 1001
CapInh: 0000000000000000
CapPrm: 0000000000000000
CapEff: 0000000000000000
CapBnd: 000001ffffffffff
CapAmb: 0000000000000000
NoNewPrivs:     0
Seccomp:        0
```

### 40.2.3 Identity Databases: `/etc/passwd`, `/etc/shadow`, and `/etc/group`

User-space utilities translate numerical UIDs and GIDs to human-readable names via the Name Service Switch (`/etc/nsswitch.conf`), which typically queries local flat files first:

1. **`/etc/passwd`**: World-readable (`0644`, owned by `root:root`) mapping username to UID, primary GID, GECOS comment, home directory, and login shell.
   - Format: `username:password_placeholder:UID:GID:GECOS:home_dir:shell`
   - Architectural Hazard: Historically, the second field stored the DES-hashed password. Modern systems place an `x` in the second field and store password hashes in `/etc/shadow`. However, for backward compatibility inside glibc's `pam_unix` module, if the second field of `/etc/passwd` contains a valid `crypt(3)` hash (or is empty), PAM may evaluate it directly or permit passwordless authentication if `/etc/passwd` is modified. Therefore, write permissions on `/etc/passwd` by any non-root user or group represent an immediate root compromise risk.
2. **`/etc/shadow`**: Restricted exclusively to privileged readers (`0640` owned by `root:shadow` on Debian/Ubuntu, or `0000` owned by `root:root` on RHEL/Fedora).
   - Format: `username:$id$salt$hash:lastchanged:min:max:warn:inactive:expire:reserved`
   - Hash identifiers (`$id$`):
     - `$1$`: MD5 (Cryptographically broken; legacy)
     - `$5$`: SHA-256 (`rounds=N` configurable)
     - `$6$`: SHA-512 (`rounds=5000` default)
     - `$y$`: yescrypt (Memory-hard KDF; default on modern Debian 11+/Ubuntu 22.04+/Fedora 35+)
     - `$2b$` / `$2y$`: bcrypt
3. **`/etc/group` and `/etc/gshadow`**: Define supplementary groups. Membership in certain system groups grants implicit root-equivalent capabilities (e.g., `sudo`, `wheel`, `admin`, `disk`, `adm`, `shadow`, `docker`, `lxd`, `libvirt`).

---

## 40.3 Delegated Administration: `sudo` Architecture and Policy Auditing

The `sudo` (superuser do) utility allows system administrators to delegate granular command execution privileges to specific users or groups without sharing the root password. It operates as a Set-UID root binary (`/usr/bin/sudo`, mode `4755`, owned by `root:root`) that consults `/etc/sudoers` and files within `/etc/sudoers.d/`.

### 40.3.1 Extended Backus-Naur Form (EBNF) Structure of `sudoers` Rules

A standard `sudoers` user specification follows the syntax:

```text
User_List Host_List = [(Runas_User_List : Runas_Group_List)] [Tag_Spec] Command_List
```

For example:
```sudoers
%sysadmins ALL = (root:root) NOPASSWD: NOEXEC: /usr/bin/systemctl status nginx, /usr/bin/journalctl -u nginx
```

Key architectural components of this rule include:
- **`User_List`**: Can be a username, `#uid`, `%group`, `%#gid`, or a `User_Alias`.
- **`Host_List`**: Hostnames, IP addresses, CIDR blocks, or `ALL`.
- **`Runas_Spec`**: Specifies the target user and/or group the command may run as. If omitted, defaults to `(root)`.
- **`Tag_Spec`**: Modifiers controlling execution behavior:
  - `PASSWD:` / `NOPASSWD:`: Whether PAM authentication is required before invocation.
  - `EXEC:` / `NOEXEC:`: Controls whether the invoked binary is permitted to spawn child processes via `execve(2)` using `sudo_noexec.so` preload or seccomp filtering.
  - `SETENV:` / `NOSETENV:`: Controls whether the caller can pass arbitrary environment variables via `sudo -E`.

### 40.3.2 Interactive Binary Subshell Escapes (The GTFOBins Architectural Problem)

A pervasive misconception in Linux administration is that granting `sudo` rights to a single diagnostic, file-viewing, or archiving utility restricts the user solely to that utility's intended purpose. In Unix design philosophy, many interactive utilities include built-in features to invoke subshells, execute external filters, load custom configuration files, or interpret scripts. When such a utility runs with `EUID 0` via `sudo`, any child process it spawns via `fork()` and `execve()` inherits `EUID 0` and `RUID 0`.

Below is a comprehensive architectural taxonomy of why common system utilities break privilege boundaries when granted unrestricted `sudo` permissions:

| Utility Category | Examples | Architectural Mechanism Permitting Arbitrary Execution | Hardening / Mitigation Alternative |
| :--- | :--- | :--- | :--- |
| **Pagers & Text Viewers** | `less`, `more`, `man`, `journalctl`, `systemctl` (when paging output) | Pagers invoke `/bin/sh -c` when the user triggers shell escape commands (such as `!command`) or invokes an external editor (`v`). Utilities like `journalctl` and `systemctl` automatically pipe output to `less` if stdout is a TTY and `SYSTEMD_LESS` is not restricted. | Set `Defaults noexec` on the rule; pass `--no-pager` in explicit command arguments; set `SYSTEMD_PAGER=""` inside `sudoers` environment defaults. |
| **Text Editors** | `vim`, `vi`, `nano`, `emacs`, `ed`, `pico` | Editors inherently allow reading and writing arbitrary files on the filesystem (including `/etc/sudoers` and `/etc/passwd`) and provide direct shell execution (`:!/bin/sh` in `vi`, spellcheck filter execution in `nano`). | Never grant `sudo /usr/bin/vim`. Use `sudoedit` (`sudo -e`) paired with exact file paths and a patched `sudo` version (`>= 1.9.12p2`), which edits a temporary copy as the unprivileged user. |
| **File Search & Manipulation** | `find`, `awk`, `gawk`, `sed` (GNU) | `find` implements the `-exec` and `-execdir` predicates to invoke external binaries on matched nodes. `awk` implements the `system()` function and piped I/O. GNU `sed` supports the `e` modifier on substitution commands (`s/.../.../e`), passing pattern space to `/bin/sh`. | Wrap required queries inside a root-owned (`0700`) read-only wrapper script that takes no untrusted flags or sanitizes inputs strictly. |
| **Archive & Backup Tools** | `tar`, `zip`, `rsync`, `cpio` | GNU `tar` supports `--checkpoint` and `--checkpoint-action=exec=...` hooks intended for tape-drive rotation scripts, as well as `--to-command` and `-I` (`--use-compress-program`). `zip` supports `-T --unzip-command`. `rsync` supports `-e` to specify a custom remote shell transport. | Enforce `NOEXEC` where supported, or execute backups from a root-owned `systemd` timer rather than interactive `sudo`. |
| **Interpreters & Runtimes** | `python`, `perl`, `ruby`, `node`, `php`, `lua`, `bash`, `sh` | Language runtimes by definition execute arbitrary Turing-complete code and expose OS system call wrappers (`os.system`, `exec`, `syscall`). | Never grant interactive interpreter access via `sudo`. Only authorize specific, immutable (`root:root`, `0750`) scripts with full path and fixed arguments (`sudo /usr/local/sbin/task.py ""`). |
| **Network & Diagnostic Tools** | `nmap`, `tcpdump`, `strace`, `ltrace`, `gdb` | Legacy `nmap` had `--interactive`; modern `nmap` includes the Nmap Scripting Engine (NSE, `--script`), which executes arbitrary Lua scripts with OS library access. `tcpdump` supports `-z postrotate-command` to execute a binary after rotating capture files. Debuggers (`gdb`, `strace`) attach to or spawn processes directly. | Grant network tools narrow POSIX capabilities (`cap_net_raw,cap_net_admin+eip`) scoped to a dedicated administrative group rather than full `sudo` root execution. |

### 40.3.3 Environment Variable Inheritance Hazards in `sudo`

When `sudo` initializes a privileged process, the dynamic linker (`ld-linux.so`) and the invoked binary inspect process environment variables. If `Defaults env_reset` is disabled in `/etc/sudoers`, or if dangerous variables are explicitly preserved in `Defaults env_keep`, an unprivileged caller can hijack the execution flow of the privileged binary before `main()` is even reached:

1. **`LD_PRELOAD` and `LD_LIBRARY_PATH`**:
   - Normally, when `ld.so` executes a **Set-UID** binary where `RUID != EUID`, the kernel sets the `AT_SECURE` flag in the ELF auxiliary vector (`auxv`), causing `ld.so` to ignore `LD_PRELOAD` and `LD_LIBRARY_PATH`.
   - **Crucial Architectural Nuance**: When `sudo` executes a target command, `sudo` calls `setresuid(0, 0, 0)` (or `setuid(0)`) *before* calling `execve()` on the target binary. Consequently, when the target binary starts, `RUID == 0` and `EUID == 0`. Because `RUID == EUID`, the kernel sets `AT_SECURE = 0`!
   - Therefore, `sudo` itself must strip `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`, `PYTHONINSPECT`, `PYTHONPATH`, `PERL5LIB`, `RUBYLIB`, and `BASH_ENV` from the environment prior to calling `execve()`. If an administrator misconfigures `Defaults env_keep += "LD_PRELOAD"` or `Defaults env_keep += "LD_LIBRARY_PATH"`, any user permitted to run *any* dynamically linked binary via `sudo` can supply custom shared object code that runs as `root`.
2. **`PATH` and `secure_path`**:
   - If `Defaults secure_path` is omitted from `/etc/sudoers` and a `sudoers` rule or root-owned script invokes utilities by relative name rather than absolute path, a caller can prepend a user-writable directory to `$PATH`.

### 40.3.4 Historical `sudo` Vulnerabilities and Parser Edge Cases

Even when `sudoers` policies are carefully written, parser logic flaws in older versions of `sudo` have historically permitted privilege boundary bypasses. Auditors must verify both policy syntax and package patch levels:

- **CVE-2019-14287 (UID `-1` / `4294967295` Integer Underflow)**:
  - Affected `sudo` versions prior to `1.8.28`.
  - When a `sudoers` rule included the keyword `ALL` in the `Runas` specification with an exclusion such as `alice ALL=(ALL, !root) /usr/bin/id`, `sudo` checked that the requested target UID was not `0`.
  - However, the POSIX `setresuid(2)` and `setreuid(2)` system calls treat a UID argument of `-1` (or unsigned `4294967295`) as a sentinel meaning "do not change this UID field." Because `sudo` already ran with `EUID 0` (due to its SUID-root bit) and did not exist in `/etc/passwd` as UID `-1`, passing `-u#-1` bypassed the `!root` policy check while causing `setresuid()` to leave the process UID at `0`.
- **CVE-2021-3156 ("Baron Samedit" Heap-Based Buffer Overflow)**:
  - Affected `sudo` versions `1.8.2` through `1.8.31p2` and `1.9.0` through `1.9.5p1`.
  - Caused by a mismatch between command-line argument escaping in `sudoedit -s` mode and unescaping in `sudoers` policy evaluation (`set_cmnd()`). When trailing backslashes were passed in specific argument combinations, the unescaping loop wrote past the end of a heap-allocated buffer regardless of whether the invoking user was listed in `/etc/sudoers`.
- **CVE-2023-22809 (`sudoedit` Arbitrary File Write via Editor Argument Injection)**:
  - Affected `sudo` versions `1.8.0` through `1.9.12p1`.
  - In `sudoedit`, `sudo` determines which editor to launch by reading `SUDO_EDITOR`, `VISUAL`, or `EDITOR` from the user's environment, and appends `--` before the list of authorized files to edit. However, if the user-supplied `EDITOR` variable itself contained `--` followed by an unauthorized file path (e.g., `/etc/sudoers`), the internal argument parser split the list on the first `--` token and treated the injected path as an authorized target file to copy back with root privileges.

---

## 40.4 SUID/SGID Binaries and Dynamic Linker (`ld.so`) Security

### 40.4.1 Mechanics of the Set-UID (`04000`) and Set-GID (`02000`) Mode Bits

In POSIX filesystems, every inode stores a 16-bit `i_mode` field:
- Bits `0-8` (`0777`): Standard Owner, Group, and Other read/write/execute permissions.
- Bit `9` (`01000`, `S_ISVTX`): Sticky bit (on directories like `/tmp`, prevents users from deleting or renaming files owned by other users).
- Bit `10` (`02000`, `S_ISGID`): Set-GID bit (on executables, sets `EGID` to the file's group owner; on directories, forces newly created files inside to inherit the directory's group).
- Bit `11` (`04000`, `S_ISUID`): Set-UID bit (on executables, sets `EUID` and `FSUID` of the calling task to the file's owner UID upon `execve()`).

Wait—why does Linux ignore the Set-UID bit on interpreted shell scripts (`#!/bin/bash` or `#!/usr/bin/python3`)?
When the kernel executes a script with a `#!` (shebang) header, the kernel opens the script, reads the interpreter path, and invokes the interpreter binary passing the script's filename as `argv[1]`. Between the time the kernel checks permissions on the script path and the time the interpreter calls `open(argv[1])`, an unprivileged user could replace a symbolic link pointing to the script (a classic **Time-of-Check to Time-of-Use / TOCTOU** race condition). Consequently, the Linux kernel (`fs/binfmt_script.c`) explicitly strips SUID/SGID elevation on scripts unless implemented via secure binary wrappers or capability-aware mechanisms.

### 40.4.2 How Custom SUID Binaries Fail Security Audits

When developers or system administrators compile custom C/C++ helper binaries and mark them `chmod 4755` owned by `root`, four primary classes of vulnerabilities frequently arise:

#### 1. Unqualified Command Execution via `system()` or `popen()`
Unlike `execve()`, which executes a binary directly at an explicit path without invoking a shell, the C standard library functions `system(const char *command)` and `popen(const char *command, const char *type)` execute `/bin/sh -c <command>`.
- If the string passed to `system()` uses a relative binary name (e.g., `system("service apache2 status")`) instead of an absolute path (`/usr/sbin/service`), `/bin/sh` resolves the binary by searching directories listed in the user-controlled `$PATH` environment variable.
- Furthermore, while modern GNU `bash` drops privileges (`EUID` reset to `RUID`) when invoked as `/bin/sh` unless the `-p` (privileged) flag is passed, other `/bin/sh` implementations (such as `dash` prior to privilege-drop patches or BusyBox `ash` depending on build flags) or explicit `setuid(0)` calls inside the C binary prior to `system()` preserve `EUID 0` across the subshell.

Consider the comparison between a vulnerable custom SUID C implementation and a hardened implementation:

```c
/* ============================================================================
 * ANTI-PATTERN (VULNERABLE DESIGN - DO NOT DEPLOY)
 * Flaws:
 * 1. Calls setuid(0) and setgid(0), erasing the RUID/EUID distinction so
 *    subshells and ld.so treat the context as native root.
 * 2. Invokes system() with a relative command name ("systemctl"), allowing
 *    $PATH manipulation and shell metacharacter parsing.
 * 3. Does not sanitize the environment (envp).
 * ============================================================================ */
// setuid(0);
// system("systemctl status nginx");
```

```c
/* ============================================================================
 * HARDENED DESIGN: Safe Privileged Helper Pattern
 * Security Controls:
 * 1. Never call setuid(0) unnecessarily; drop privileges permanently once done.
 * 2. Avoid system() and popen() entirely; use execve() with an explicit
 *    read-only argument array and a sanitized, minimal environment array.
 * 3. Verify absolute path integrity before invocation.
 * ============================================================================ */
#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    /* 1. Define strict, sanitized environment (no user PATH, LD_*, or IFS) */
    char *const clean_env[] = {
        "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG=C.UTF-8",
        NULL
    };

    /* 2. Define immutable argument vector using absolute path */
    char *const args[] = {
        "/usr/bin/systemctl",
        "status",
        "--no-pager",
        "nginx.service",
        NULL
    };

    /* 3. Execute directly via execve() without invoking /bin/sh */
    execve(args[0], args, clean_env);

    /* If execve returns, an error occurred */
    perror("execve failed");
    return EXIT_FAILURE;
}
```

#### 2. Dynamic Linker (`ld.so`) Search Order and `RPATH` / `RUNPATH` Flaws
When an ELF binary is dynamically linked, the kernel maps `/lib64/ld-linux-x86-64.so.2` into memory to resolve shared library dependencies (`DT_NEEDED` entries in the `.dynamic` section). The dynamic linker searches for shared objects (`.so` files) in the following strict order:

1. **`DT_RPATH`** (compiled into the binary's ELF header, unless `DT_RUNPATH` is also present). Crucially, `DT_RPATH` is evaluated even when `AT_SECURE=1` (SUID execution), provided it does not contain `$ORIGIN` tokens pointing to untrusted directories!
2. **`LD_LIBRARY_PATH`** (Ignored when `AT_SECURE=1`, i.e., when `RUID != EUID`).
3. **`DT_RUNPATH`** (compiled into the binary's ELF header via `-Wl,-rpath,...` on modern linkers).
4. **`/etc/ld.so.cache`** (generated by `ldconfig` from paths defined in `/etc/ld.so.conf` and `/etc/ld.so.conf.d/*.conf`).
5. **Default system library directories** (`/lib`, `/lib64`, `/usr/lib`, `/usr/lib64`).

If a developer compiles a SUID binary with a development flag such as `gcc -Wl,-rpath,/home/dev/build/lib:/opt/custom/lib ...` and either `/home/dev/build/lib` or `/opt/custom/lib` is writable by a non-root user (or missing inside a writable parent directory), any shared object placed in that directory will be loaded into the SUID root process address space and its `__attribute__((constructor))` functions will execute with `EUID 0`.

Auditors can inspect any SUID binary for dangerous `RPATH` or `RUNPATH` entries and unresolved libraries using `readelf` and `ldd`:

```bash
# Inspect DT_RPATH, DT_RUNPATH, and DT_NEEDED entries of a SUID binary safely
readelf -d /usr/local/bin/custom_suid_helper | grep -E '(RPATH|RUNPATH|NEEDED)'
```

---

## 40.5 POSIX Capabilities (`capabilities(7)`) Internals and Auditing

Introduced in Linux 2.2 and expanded significantly with file capabilities (`xattr` `security.capability`) in Linux 2.6.24 and Ambient capabilities in Linux 4.3, **POSIX Capabilities** divide the monolithic privileges of `root` into over 40 discrete units.

### 40.5.1 Thread vs. File Capability Sets and Transformation Rules

Capabilities exist on both **files** (stored in the `security.capability` extended attribute on the inode) and **threads** (stored in `struct cred`).

- **File Capability Sets**:
  - `Permitted` (formerly "Forced"): Capabilities automatically granted to the thread's Permitted set upon execution, regardless of the caller's privileges.
  - `Inheritable`: Capabilities ANDed with the calling thread's Inheritable set to determine which capabilities survive across `execve()`.
  - `Effective` (a single boolean flag on files): If set (`+e`), any capability placed into the new thread's Permitted set during `execve()` is also automatically copied into its Effective set.
- **Thread Capability Sets**:
  - $P(\text{permitted})$: The superset of capabilities that the thread may activate in its Effective set.
  - $P(\text{effective})$: The capabilities currently checked by the kernel during system calls.
  - $P(\text{inheritable})$: Capabilities preserved across an `execve()` call when matched with file inheritable bits.
  - $P(\text{bounding})$ (`cap_bset`): A ceiling mask; cannot grant capabilities on its own, but blocks file `Permitted` capabilities not present in `cap_bset`.
  - $P(\text{ambient})$: Capabilities that are automatically preserved across `execve()` of non-SUID, capability-unaware binaries (must be a subset of both $P(\text{permitted})$ and $P(\text{inheritable})$).

During an `execve()` system call, the kernel calculates the new thread capability sets ($P'$) from the old thread capability sets ($P$) and the file capability sets ($F$) according to these exact mathematical equations:

$$P'(\text{ambient}) = \text{file is privileged} \ ? \ 0 : P(\text{ambient})$$

$$P'(\text{permitted}) = (P(\text{inheritable}) \cap F(\text{inheritable})) \cup (F(\text{permitted}) \cap P(\text{bounding})) \cup P'(\text{ambient})$$

$$P'(\text{effective}) = F(\text{effective}) \ ? \ P'(\text{permitted}) : P'(\text{ambient})$$

$$P'(\text{inheritable}) = P(\text{inheritable})$$

$$P'(\text{bounding}) = P(\text{bounding})$$

### 40.5.2 High-Risk Capabilities Equivalent to Root (`UID 0`)

While capabilities are intended to reduce attack surface (for instance, granting `/usr/bin/ping` only `cap_net_raw+ep` instead of making it SUID root), assigning certain capabilities to general-purpose binaries, scripting runtimes, or file tools is functionally equivalent to granting full root access:

| Capability | Intended Kernel Purpose | Why Over-Assignment Leads to Root Equivalence |
| :--- | :--- | :--- |
| **`CAP_SETUID`** | Allows a process to make arbitrary manipulations of process UIDs (`setuid(2)`, `setreuid(2)`, `setresuid(2)`) and forge UID credentials on UNIX domain sockets. | If granted to an interpreter (`python3`, `perl`, `node`, `php`) or archive tool, the process can invoke `setuid(0)` to transition its `RUID`, `EUID`, and `SUID` directly to `0` (root). |
| **`CAP_SETGID`** | Allows arbitrary manipulation of process GIDs and supplementary group lists (`setgid(2)`, `setgroups(2)`). | Allows a process to join privileged system groups such as `shadow` (reading `/etc/shadow`), `disk` (raw block device read/write on `/dev/sda`), or `docker`. |
| **`CAP_DAC_OVERRIDE`** | Bypasses all file Read, Write, and Execute Discretionary Access Control (DAC) permission checks. | Allows overwriting `/etc/passwd`, `/etc/sudoers`, `/etc/shadow`, or `/etc/crontab` regardless of file ownership or `0000`/`0400` mode bits. |
| **`CAP_DAC_READ_SEARCH`** | Bypasses file Read permission checks and directory Read/Execute (search) permission checks; also permits invoking `open_by_handle_at(2)`. | Allows reading any sensitive file on the host (`/etc/shadow`, `/root/.ssh/id_ed25519`, TLS private keys) and traversing restricted directories; in containers, permits host filesystem traversal via `open_by_handle_at()`. |
| **`CAP_CHOWN`** | Allows arbitrary changes to file UIDs and GIDs (`chown(2)`). | Allows taking ownership of `/etc/passwd` or `/etc/sudoers`, modifying permissions, and restoring ownership. |
| **`CAP_FOWNER`** | Bypasses permission checks on operations that normally require the filesystem UID of the process to match the UID of the file (e.g., `chmod(2)`, `utime(2)`). | Allows changing `/etc/shadow` or `/etc/sudoers` mode bits to `0666` (world-writable), modifying the file, and restoring mode bits. |
| **`CAP_SYS_ADMIN`** | The kernel's "catch-all" administrative capability: allows `mount(2)`, `umount(2)`, `swapon(2)`, `setns(2)`, `ioctl` operations, and quota/filesystem controls. | Allows mounting a user-controlled filesystem or bind-mounting over `/etc/passwd` or `/etc/sudoers` to inject privileged configurations. |
| **`CAP_SYS_MODULE`** | Allows loading and unloading Linux kernel modules (`init_module(2)`, `finit_module(2)`, `delete_module(2)`). | Allows inserting code directly into Ring 0 (kernel space), bypassing all user-space and LSM security controls. |
| **`CAP_SYS_PTRACE`** | Allows tracing arbitrary processes using `ptrace(2)`, `process_vm_readv(2)`, and `process_vm_writev(2)`. | Allows attaching to an existing root-owned daemon or SSH session to read credentials or modify execution state in memory. |
| **`CAP_BPF` & `CAP_PERFMON`** | Allows loading eBPF programs and attaching performance monitors. | Can be abused to read arbitrary kernel memory (`bpf_probe_read_kernel`) including sensitive credentials and keys passing through VFS or TTY buffers. |

### 40.5.3 Auditing File Capabilities Safely

Security engineers should periodically enumerate all files on mounted filesystems that possess extended capability attributes using `getcap`:

```bash
# Enumerate all file capabilities across local filesystems
getcap -r / 2>/dev/null
```

To restrict capability use to a specific group rather than all users on the system, administrators should:
1. Change the binary's group ownership to a dedicated group (e.g., `chgrp netdiag /usr/bin/tcpdump`).
2. Remove world-execute permissions (`chmod 0750 /usr/bin/tcpdump`).
3. Apply only the minimum required capabilities (`setcap cap_net_raw,cap_net_admin=eip /usr/bin/tcpdump`).

---

## 40.6 Scheduled Execution: `cron`, `anacron`, and `systemd` Timers

Background task schedulers execute maintenance scripts automatically under specified user contexts (frequently `root`). If the configuration files, execution paths, or invoked scripts are improperly secured, an unprivileged local user can alter what the scheduler executes.

### 40.6.1 The `cron` Architecture and Inspection Locations

The cron daemon (`cron` or `crond`) inspects several configuration sources every minute:
- `/etc/crontab`: System-wide crontab file (includes an explicit `user` column before the command).
- `/etc/cron.d/*`: Drop-in system cron jobs (also include the `user` column).
- `/etc/cron.hourly/`, `/etc/cron.daily/`, `/etc/cron.weekly/`, `/etc/cron.monthly/`: Directories executed via `run-parts`.
- `/var/spool/cron/crontabs/*` (Debian/Ubuntu) or `/var/spool/cron/*` (RHEL/Rocky): Per-user crontabs managed via `crontab -e`.
- `/etc/anacrontab`: Schedules periodic jobs on systems that are not powered on 24/7.

### 40.6.2 Three Common Cron Security Flaws

#### 1. Loose File or Directory Permissions on Scheduled Scripts
If a root cron job executes `/usr/local/bin/cleanup.sh`, and either `/usr/local/bin/cleanup.sh` is writable by a non-root user/group (`0775` or `0777`), or the parent directory `/usr/local/bin` is writable by a non-root user (allowing the file to be unlinked and replaced), any modification to that script will run as `root` on the next scheduled tick.

#### 2. Custom `PATH` Directives in `/etc/crontab`
By default, `/etc/crontab` defines a `PATH=` environment variable at the top of the file:
```crontab
SHELL=/bin/sh
PATH=/home/admin/bin:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

* * * * * root backup.sh
```
Notice two compounding errors in the snippet above:
1. `PATH` includes `/home/admin/bin` ahead of `/usr/local/sbin`.
2. The cron job invokes `backup.sh` using a relative name rather than `/usr/local/sbin/backup.sh`.
If `/home/admin/bin` is writable by a lower-privileged account (such as `admin`), placing an executable named `backup.sh` inside `/home/admin/bin` causes `cron` to execute it as `root` instead of `/usr/local/sbin/backup.sh`.

#### 3. Shell Globbing (Wildcard Expansion) in Scheduled Commands
When a cron script executes a command containing an unquoted asterisk (`*`), the shell (`/bin/sh` or `/bin/bash`) expands the `*` into a sorted list of all filenames in the current working directory *before* invoking the target binary. Importantly, the target binary cannot distinguish between a command-line flag typed by the script author and a filename in the directory that begins with a hyphen (`-` or `--`)!

For example, consider a scheduled root script that runs:
```bash
cd /var/backups/staging && tar -czf /var/backups/archive.tar.gz *
```
If `/var/backups/staging` is world-writable, any user can create files inside `/var/backups/staging` whose names begin with `--` (such as `--checkpoint=1`). When the shell expands `*`, `tar` receives those filenames as `argv[]` option flags rather than positional file arguments. The same architectural flaw affects `chown -R user:group *`, `chmod -R 0644 *`, and `rsync -a * /dest`.

**Hardening Rule for Shell Globbing**:
Always prefix wildcard globs with `./` (so expanded filenames start with `./-` rather than `-`) or use the POSIX `--` end-of-options delimiter:
```bash
# Hardened wildcard usage in cron scripts:
cd /var/backups/staging && tar -czf /var/backups/archive.tar.gz -- *
# Or even better, archive the directory itself without shell expansion:
tar -czf /var/backups/archive.tar.gz -C /var/backups staging
```

### 40.6.3 `systemd` Units and Timers

Modern Linux distributions increasingly replace `cron` jobs with `systemd.timer` units paired with `systemd.service` units. Systemd searches unit files in order of precedence:
1. `/etc/systemd/system/` (Local administrator overrides)
2. `/run/systemd/system/` (Runtime units)
3. `/lib/systemd/system/` or `/usr/lib/systemd/system/` (Vendor package units)

An auditor must check that:
- No `.service`, `.timer`, `.socket`, or `.path` unit file (or symlink target) is writable by non-root users.
- None of the binaries or `EnvironmentFile=` paths referenced in `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`, `ExecReload=`, or `ExecStop=` are writable by non-root users.
- Unprivileged processes cannot monitor sensitive command-line arguments passed via `execve()`. Note that by default on Linux, `/proc` allows any local user to view `/proc/<pid>/cmdline` of all processes running on the system, which means tools that poll `/proc` (or Netlink `proc_connector` events) can observe short-lived root cron processes and read any secrets (such as database passwords or API tokens) passed directly on the command line.
  - **Hardening Control**: Mount `/proc` with the `hidepid=invisible` (or `hidepid=2`) option in `/etc/fstab` so unprivileged users can only see their own processes in `/proc`:
    ```fstab
    proc /proc proc defaults,nosuid,nodev,noexec,relatime,hidepid=2 0 0
    ```
    And never pass secrets as CLI arguments; pass them via restricted `LoadCredential=` directives in `systemd` or `0400` configuration files.

---

## 40.7 Network File System (NFS), Kernel Surface, and Container Isolation

### 40.7.1 NFS Root Squashing (`root_squash` vs. `no_root_squash`)

Network File System (NFSv3 and NFSv4 with `AUTH_SYS` authentication) trusts the client kernel to assert the numeric `UID` and `GID` of the user making file requests over the network.
- To prevent a user with root access on an untrusted client workstation from modifying root-owned files on the NFS server, the NFS server enforces **`root_squash`** by default: any request arriving with `UID 0` is mapped ("squashed") to the unprivileged `nobody` / `nfsnobody` UID (`65534`).
- If an administrator exports a share in `/etc/exports` with the **`no_root_squash`** flag:
  ```text
  # INSECURE /etc/exports CONFIGURATION
  /srv/shared 10.10.20.0/24(rw,sync,no_root_squash,no_subtree_check)
  ```
  Then any client within `10.10.20.0/24` where an attacker or user has local root (or can craft raw NFS RPC packets from a privileged port) can mount `/srv/shared`, create root-owned files (including SUID binaries or modified configuration files) on the share, and if the NFS server also mounts or executes binaries from `/srv/shared` without `nosuid,noexec`, compromise the server itself.

**Hardening Remediation for NFS**:
1. Never use `no_root_squash` in `/etc/exports`; explicitly enforce `root_squash` or `all_squash`.
2. Enforce Kerberos authentication (`sec=krb5p`) on NFSv4 exports rather than trusting client-asserted `AUTH_SYS` UIDs.
3. On all NFS clients, mount remote shares with `nosuid,nodev,noexec` in `/etc/fstab`.

### 40.7.2 Linux Kernel Attack Surface and Historical CVEs

Even when user-space DAC, `sudo`, capabilities, and scheduled tasks are hardened, all user-space processes interact with the Linux kernel directly via system calls (`syscall` instruction), virtual filesystems (`/proc`, `/sys`), ioctls, network sockets, and user namespaces. A flaw in kernel memory management or privilege-checking logic can allow a local task to overwrite its own `struct cred` in kernel RAM (setting `uid = euid = 0`) or overwrite read-only files in the page cache.

Understanding the root causes of landmark Linux privilege escalation CVEs informs kernel hardening strategies:

| CVE Identifier | Common Name & Component | Architectural Root Cause | Hardening / Mitigation Control |
| :--- | :--- | :--- | :--- |
| **CVE-2016-5195** | **Dirty COW** (`mm/gup.c` Copy-on-Write race condition) | A race condition between `get_user_pages()` handling a fault on a read-only memory mapping and `madvise(MADV_DONTNEED)` discarding the page allowed an unprivileged process to write directly to the underlying read-only page cache of files it only had read permissions for (e.g., `/etc/passwd` or SUID binaries). | Kernel patching; livepatch (`kpatch` / `canonical-livepatch`). |
| **CVE-2021-4034** | **PwnKit** (Polkit `pkexec` out-of-bounds `argv` processing) | `pkexec` (a SUID-root binary installed by default on major distros) iterated over command-line arguments starting at `n = 1`. When invoked with `argc == 0` (`execve("/usr/bin/pkexec", {NULL}, envp)`), the loop read and wrote out-of-bounds to `argv[1]`, which in the contiguous stack layout pointed directly to `envp[0]`. This allowed injecting insecure environment variables (`GCONV_PATH`) after `ld.so` had already cleared the environment. | Kernel patch enforcing `argc >= 1` in `do_execveat_common()` (added in Linux 5.18+); patching `polkit` and removing the SUID bit from `/usr/bin/pkexec` (`chmod 0755 /usr/bin/pkexec`) if GUI Polkit elevation is unused on servers. |
| **CVE-2022-0847** | **Dirty Pipe** (Linux `5.8` – `5.16.10` pipe buffer flag initialization flaw) | When `splice(2)` moved a page cache reference from a read-only file into a pipe buffer (`struct pipe_buffer`), the kernel failed to clear the `PIPE_BUF_FLAG_CAN_MERGE` flag left over from previous pipe writes. Subsequent writes to the pipe overwrote the backing page cache directly, bypassing all VFS read-only file checks. | Kernel upgrade to `>= 5.16.11`, `5.15.25`, or `5.10.102`. |
| **CVE-2023-2640 & CVE-2023-32629** | **GameOver(lay)** (Ubuntu OverlayFS + Unprivileged User Namespaces) | Ubuntu kernels carried custom patches allowing unprivileged user namespaces to mount `OverlayFS` filesystems and copy files with extended attributes (`security.capability`) across layers without scoping them to the user namespace, creating scoped SUID/capability binaries usable in the initial namespace. | Disable unprivileged user namespaces on servers that do not require rootless containers (`sysctl kernel.apparmor_restrict_unprivileged_userns=1` or `user.max_user_namespaces=0`). |
| **CVE-2023-4911** | **Looney Tunables** (glibc `ld.so` `GLIBC_TUNABLES` buffer overflow) | A buffer overflow in the GNU C Library dynamic loader's parsing of the `GLIBC_TUNABLES` environment variable occurred during early process startup before `main()`, affecting SUID binaries across major distributions. | Patch `glibc` and remove unneeded SUID bits across the filesystem using `chmod u-s`. |

### 40.7.3 Container Architecture and Isolation Boundaries (Docker & LXC/LXD)

Containers are **not** virtual machines; all containers on a Linux host share the single underlying host kernel. Container isolation relies on combining:
1. **Kernel Namespaces** (`pid`, `net`, `mnt`, `ipc`, `uts`, `user`, `cgroup`, `time`) — controlling what a process can *see*.
2. **Control Groups (`cgroups`)** — controlling how much CPU, memory, and I/O a process can *consume* and which device nodes (`devices` cgroup) it may open.
3. **Reduced Capability Bounding Set** — Docker drops most capabilities by default, retaining only 14 capabilities (such as `CAP_CHOWN`, `CAP_NET_BIND_SERVICE`, `CAP_SETUID`, `CAP_SETGID`).
4. **Seccomp Profile & AppArmor/SELinux** — blocking ~44 dangerous syscalls (`mount`, `kexec_load`, `init_module`, `open_by_handle_at`, `bpf`) even for UID 0 inside the container.

#### Architectural Flaws that Collapse Container Isolation

```
+-----------------------------------------------------------------------------+
|                        CONTAINER ISOLATION BOUNDARY                         |
|                                                                             |
|  1. Docker Socket Exposure (/var/run/docker.sock or docker group)           |
|     -> Unauthenticated root-level REST API to the host Docker daemon.       |
|                                                                             |
|  2. Privileged Mode (--privileged)                                          |
|     -> Grants ALL capabilities (CapEff: 000001ffffffffff), disables         |
|        AppArmor/SELinux & Seccomp, and exposes all host /dev/* block nodes. |
|                                                                             |
|  3. Host Namespace Sharing (--pid=host, --net=host, --ipc=host)             |
|     -> Exposes host processes in /proc and host abstract UNIX sockets.      |
|                                                                             |
|  4. Host Filesystem Bind Mounts (-v /:/host or -v /etc:/etc)                |
|     -> Direct read/write access to host /etc/shadow, /etc/crontab, etc.     |
+-----------------------------------------------------------------------------+
```

1. **Membership in the `docker`, `lxd`, or `incus` Group**:
   - The Docker daemon (`dockerd`) runs as `root` on the host and listens on the UNIX domain socket `/var/run/docker.sock` (owned by `root:docker`, mode `0660`).
   - Any user who is a member of the `docker` group (or any container into which `/var/run/docker.sock` is bind-mounted) can send HTTP API requests to `dockerd` instructing it to create a new container with the host's root filesystem (`/`) bind-mounted inside, running as `UID 0`. Therefore, **`docker` group membership is strictly equivalent to passwordless `sudo` root access on the host**.
   - Similarly, membership in the `lxd` group allows communicating with the LXD daemon socket (`/var/snap/lxd/common/lxd/unix.socket`) to initialize a container with `security.privileged=true` and mount the host `/` disk device.
2. **Running Containers with `--privileged` or `--cap-add=SYS_ADMIN`**:
   - Starting a container with `--privileged` disables `seccomp`, disables AppArmor/SELinux profiles, populates `/dev` with all host block devices (`/dev/sda`, `/dev/nvme0n1`), and enables the full capability bounding set (`CapEff: 000001ffffffffff`). A process running as root inside a `--privileged` container can directly mount the host's root block device or register a `cgroup` v1 `release_agent` handler (which the kernel executes in the host root namespace whenever the cgroup empties).

---

## 40.8 Comprehensive Linux Security Auditing Script (Read-Only)

Below is a production-grade, non-destructive Bash auditing script designed for Linux systems administrators and security auditors. It systematically inspects credential files, `sudo` configurations, SUID/SGID binaries, POSIX capabilities, scheduled tasks, NFS exports, sysctl kernel hardening parameters, and container boundaries.

```bash
#!/usr/bin/env bash
# ==============================================================================
# linux_privilege_audit.sh
# Read-Only Operating System Privilege Boundary & Hardening Auditor
# Standards Alignment: CIS Distribution Independent Linux Benchmark v2.0 / NIST
# ==============================================================================

set -uo pipefail

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

banner() {
    printf "\n${BLUE}==============================================================================${NC}\n"
    printf "${BLUE}[*] %s${NC}\n" "$1"
    printf "${BLUE}==============================================================================${NC}\n"
}

pass() { printf "${GREEN}[PASS]${NC} %s\n" "$1"; }
warn() { printf "${YELLOW}[WARN]${NC} %s\n" "$1"; }
crit() { printf "${RED}[CRIT]${NC} %s\n" "$1"; }

banner "1. SYSTEM & KERNEL BASELINE CONTEXT"
printf "Hostname        : %s\n" "$(hostname -f 2>/dev/null || hostname)"
printf "Kernel Version  : %s\n" "$(uname -srmo)"
printf "Current Context : %s\n" "$(id)"
if [ -f /etc/os-release ]; then
    grep -E '^(PRETTY_NAME|VERSION)=' /etc/os-release
fi

banner "2. IDENTITY DATABASE & CRITICAL FILE PERMISSIONS AUDIT"
check_file_perms() {
    local file="$1"
    local max_perm="$2"
    local expected_owner="$3"
    if [ ! -e "$file" ]; then
        return
    fi
    local actual_perm actual_owner
    actual_perm=$(stat -c "%a" "$file")
    actual_owner=$(stat -c "%U:%G" "$file")

    if [ -w "$file" ] && [ "$(id -u)" -ne 0 ]; then
        crit "$file is WRITABLE by current non-root user! (Mode: $actual_perm, Owner: $actual_owner)"
    else
        pass "$file Mode: $actual_perm | Owner: $actual_owner (Expected max mode: $max_perm, Owner: $expected_owner)"
    fi
}

check_file_perms "/etc/passwd" "644" "root:root"
check_file_perms "/etc/shadow" "640" "root:shadow"
check_file_perms "/etc/group"  "644" "root:root"
check_file_perms "/etc/gshadow" "640" "root:shadow"
check_file_perms "/etc/sudoers" "440" "root:root"
check_file_perms "/etc/crontab" "600" "root:root"

# Check for multiple UID 0 accounts in /etc/passwd
uid0_accounts=$(awk -F: '($3 == 0) {print $1}' /etc/passwd)
if [ "$uid0_accounts" != "root" ]; then
    crit "Non-root accounts with UID 0 detected: $(echo "$uid0_accounts" | tr '\n' ' ')"
else
    pass "Only 'root' possesses UID 0 in /etc/passwd."
fi

# Check for accounts with empty password field in /etc/passwd
empty_pw=$(awk -F: '($2 == "") {print $1}' /etc/passwd)
if [ -n "$empty_pw" ]; then
    crit "Accounts with empty password field in /etc/passwd: $empty_pw"
else
    pass "All accounts in /etc/passwd enforce shadow password lookup ('x')."
fi

# Check privileged group memberships
printf "\n--- Privileged System Group Memberships ---\n"
grep -E '^(sudo|wheel|admin|docker|lxd|incus|disk|shadow|adm|libvirt):' /etc/group || true

banner "3. SUID & SGID BINARY INVENTORY AND ANOMALY AUDIT"
# Known standard SUID binaries on typical Linux servers
STANDARD_SUID="(/usr/bin/sudo|/usr/bin/passwd|/usr/bin/chsh|/usr/bin/chfn|/usr/bin/gpasswd|/usr/bin/newgrp|/usr/bin/su|/bin/su|/usr/bin/mount|/usr/bin/umount|/usr/lib/openssh/ssh-keysign|/usr/libexec/openssh/ssh-keysign|/usr/lib/dbus-1.0/dbus-daemon-launch-helper)"

printf "Scanning local filesystems for SUID (04000) and SGID (02000) binaries...\n"
mapfile -t suid_files < <(find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null)

for bin in "${suid_files[@]}"; do
    if [[ ! "$bin" =~ ^$STANDARD_SUID$ ]]; then
        warn "Non-standard or reviewable SUID/SGID binary: $(stat -c '%A %U:%G %n' "$bin")"
        # Check for dangerous RPATH / RUNPATH on non-standard SUID binaries
        if command -v readelf >/dev/null 2>&1; then
            rpath_out=$(readelf -d "$bin" 2>/dev/null | grep -E '(RPATH|RUNPATH)' || true)
            if [ -n "$rpath_out" ]; then
                crit "  -> Binary $bin contains custom RPATH/RUNPATH: $rpath_out"
            fi
        fi
    fi
done

banner "4. POSIX FILE CAPABILITIES AUDIT (capabilities(7))"
if command -v getcap >/dev/null 2>&1; then
    cap_output=$(getcap -r / 2>/dev/null || true)
    if [ -n "$cap_output" ]; then
        printf "%s\n" "$cap_output"
        if echo "$cap_output" | grep -Eq 'cap_(setuid|setgid|dac_override|dac_read_search|sys_admin|sys_ptrace|sys_module|chown|fowner)'; then
            crit "High-risk root-equivalent file capabilities detected above!"
        fi
    else
        pass "No extended file capabilities found on filesystem."
    fi
else
    warn "getcap utility not installed; skipping capability scan."
fi

banner "5. SCHEDULED TASKS (CRON & SYSTEMD TIMERS) WRITABILITY AUDIT"
cron_paths=(
    "/etc/crontab"
    "/etc/anacrontab"
    "/etc/cron.d"
    "/etc/cron.hourly"
    "/etc/cron.daily"
    "/etc/cron.weekly"
    "/etc/cron.monthly"
    "/var/spool/cron"
)

for cp in "${cron_paths[@]}"; do
    if [ -e "$cp" ]; then
        writable_cron=$(find "$cp" -perm -0002 -o \( ! -user root -a -type f \) 2>/dev/null || true)
        if [ -n "$writable_cron" ]; then
            crit "World-writable or non-root-owned cron file detected in $cp: $writable_cron"
        else
            pass "Cron path $cp permissions verified (root-owned, not world-writable)."
        fi
    fi
done

printf "\n--- Checking Systemd Service Units for World-Writable Files ---\n"
writable_units=$(find /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system -perm -0002 2>/dev/null || true)
if [ -n "$writable_units" ]; then
    crit "World-writable systemd unit files detected:\n$writable_units"
else
    pass "No world-writable systemd unit files found."
fi

banner "6. NFS EXPORTS & MOUNT OPTIONS AUDIT"
if [ -f /etc/exports ]; then
    if grep -v '^[[:space:]]*#' /etc/exports | grep -q 'no_root_squash'; then
        crit "/etc/exports contains 'no_root_squash'! Remote root users can act as local root."
        grep -v '^[[:space:]]*#' /etc/exports | grep 'no_root_squash'
    else
        pass "/etc/exports does not contain 'no_root_squash'."
    fi
fi

# Verify /tmp, /var/tmp, /dev/shm mount flags
for mp in /tmp /var/tmp /dev/shm; do
    mount_line=$(findmnt -n "$mp" 2>/dev/null || true)
    if [ -n "$mount_line" ]; then
        if [[ "$mount_line" != *"nosuid"* ]] || [[ "$mount_line" != *"noexec"* ]] || [[ "$mount_line" != *"nodev"* ]]; then
            warn "Mountpoint $mp is missing one or more hardening flags (nosuid,nodev,noexec): $mount_line"
        else
            pass "Mountpoint $mp enforces nosuid, nodev, and noexec."
        fi
    else
        warn "Directory $mp is not on a separate mountpoint."
    fi
done

banner "7. KERNEL SYSCTL & LSM HARDENING PARAMETERS AUDIT"
check_sysctl() {
    local key="$1"
    local expected="$2"
    local current
    current=$(sysctl -n "$key" 2>/dev/null || echo "N/A")
    if [ "$current" = "$expected" ]; then
        pass "$key = $current"
    else
        warn "$key = $current (Recommended hardening value: $expected)"
    fi
}

check_sysctl "kernel.randomize_va_space" "2"
check_sysctl "kernel.kptr_restrict" "2"
check_sysctl "kernel.dmesg_restrict" "1"
check_sysctl "kernel.yama.ptrace_scope" "2"
check_sysctl "kernel.unprivileged_bpf_disabled" "1"
check_sysctl "fs.protected_hardlinks" "1"
check_sysctl "fs.protected_symlinks" "1"
check_sysctl "fs.protected_fifos" "2"
check_sysctl "fs.protected_regular" "2"
check_sysctl "fs.suid_dumpable" "0"

banner "8. CONTAINER & RUNTIME CONTEXT AUDIT"
if [ -f /.dockerenv ] || grep -Eq '(docker|lxc|kubepods|containerd)' /proc/1/cgroup 2>/dev/null; then
    warn "System appears to be running inside a container environment."
    grep -E '^(CapEff|NoNewPrivs|Seccomp)' /proc/self/status
else
    pass "System is running on bare-metal or full hypervisor VM."
fi

if [ -S /var/run/docker.sock ]; then
    sock_perms=$(stat -c "%a %U:%G" /var/run/docker.sock)
    warn "Docker UNIX socket present at /var/run/docker.sock ($sock_perms)"
fi
```

---

## 40.9 CIS Linux Hardening & Defense-in-Depth Remediation

### 40.9.1 Hardening `/etc/sudoers` Configuration

Every production `/etc/sudoers` file should enforce the following baseline directives to prevent environment injection, subshell escapes, TTY hijacking (`TIOCSTI` ioctl injection), and unaudited command execution:

```sudoers
# ==============================================================================
# HARDENED /etc/sudoers BASELINE CONFIGURATION
# ==============================================================================

# 1. Reset environment variables and enforce a known-good PATH
Defaults    env_reset
Defaults    secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# 2. Allocate a dedicated pseudo-terminal (PTY) for sudo processes to prevent
#    background process hijacking via TIOCSTI ioctl on the caller's TTY
Defaults    use_pty

# 3. Log all sudo invocations and full I/O streams for forensic auditing
Defaults    logfile="/var/log/sudo.log"
Defaults    log_input, log_output
Defaults    iolog_dir="/var/log/sudo-io/%{user}"

# 4. Require authentication every time or set short credential caching timeout
Defaults    timestamp_timeout=5
Defaults    passwd_tries=3

# 5. Prevent subshell escapes on read-only diagnostic commands using NOEXEC
Cmnd_Alias  DIAG_CMDS = /usr/bin/journalctl --no-pager -u nginx.service, \
                        /usr/bin/systemctl status --no-pager nginx.service

%webops     ALL = (root:root) NOEXEC: DIAG_CMDS
```

### 40.9.2 Kernel Hardening via `/etc/sysctl.d/99-cis-hardening.conf`

Applying kernel-level restrictions blocks whole classes of local privilege escalation techniques (including symlink/hardlink races in `/tmp`, unprivileged `ptrace` inspection, kernel address leaks in `/proc/kallsyms`, and unprivileged eBPF):

```ini
# /etc/sysctl.d/99-cis-hardening.conf
# Apply with: sudo sysctl --system

# Enable full Address Space Layout Randomization (ASLR)
kernel.randomize_va_space = 2

# Hide kernel symbol addresses in /proc/kallsyms and /proc/modules from all users
kernel.kptr_restrict = 2

# Restrict dmesg kernel ring buffer viewing to root / CAP_SYSLOG
kernel.dmesg_restrict = 1

# Restrict ptrace(2) to processes with CAP_SYS_PTRACE only (blocks user-to-user ptrace)
kernel.yama.ptrace_scope = 2

# Disable unprivileged eBPF and restrict performance event monitoring
kernel.unprivileged_bpf_disabled = 1
kernel.perf_event_paranoid = 3

# Disable kexec_load syscall to prevent loading an unsigned replacement kernel
kernel.kexec_load_disabled = 1

# Restrict unprivileged user namespaces (Ubuntu 23.10+ / AppArmor control)
kernel.apparmor_restrict_unprivileged_userns = 1

# Protect against TOCTOU symlink, hardlink, FIFO, and regular file races in world-writable sticky dirs (/tmp)
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2

# Never generate core dumps from SUID/SGID binaries (prevents credential leakage & cron dir core files)
fs.suid_dumpable = 0
```

### 40.9.3 `systemd` Service Sandboxing (Zero-Trust Service Units)

Modern `systemd` allows administrators to wrap any service daemon in its own isolated container-like sandbox using declarative directives inside the `[Service]` block. Even if an application vulnerability yields remote code execution inside the service, the process cannot escalate privileges on the host:

```ini
# /etc/systemd/system/webapp.service
[Unit]
Description=Hardened Production Web Application Service
After=network.target

[Service]
Type=simple
User=webapp
Group=webapp
WorkingDirectory=/srv/webapp
ExecStart=/usr/bin/python3 /srv/webapp/app.py

# --- Privilege & Capability Sandboxing ---
# Blocks SUID/SGID binaries and file capabilities from granting new privileges on execve()
NoNewPrivileges=yes
# Drops all POSIX capabilities from the Capability Bounding Set
CapabilityBoundingSet=
AmbientCapabilities=

# --- Filesystem Namespace Sandboxing ---
# Mounts /usr, /boot, and /etc read-only inside the service's mount namespace
ProtectSystem=strict
# Makes /home, /root, and /run/user inaccessible (empty read-only directories)
ProtectHome=yes
# Allocates private /tmp and /var/tmp disconnected from the host /tmp
PrivateTmp=yes
# Mounts a private /dev with only pseudo-devices (/dev/null, /dev/zero, /dev/random)
PrivateDevices=yes
# Only allow writing to the application's specific state directory
ReadWritePaths=/var/lib/webapp

# --- Kernel & System Call Sandboxing ---
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectProc=invisible
ProcSubset=pid
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictNamespaces=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources @mount @obsolete @debug

[Install]
WantedBy=multi-user.target
```

You can verify the hardening score of all running `systemd` units at any time using:
```bash
systemd-analyze security
systemd-analyze security webapp.service
```

---
---
### 40.9.4 Mandatory Access Control (MAC): SELinux and AppArmor

Even when a process runs with `EUID 0` and full POSIX capabilities, **Mandatory Access Control (MAC)** implemented via the **Linux Security Modules (LSM)** framework enforces centrally defined security policies in the kernel before any VFS, socket, or IPC operation completes.

#### 1. SELinux (Security-Enhanced Linux — RHEL, Fedora, Rocky, AlmaLinux)
SELinux implements **Type Enforcement (TE)**, **Role-Based Access Control (RBAC)**, and optional **Multi-Level Security (MLS)**. Every subject (process) and every object (file, directory, port, socket) carries an extended attribute (`security.selinux`) formatted as a four-part security context:

```text
user : role : type : level (sensitivity:category)
system_u:system_r:httpd_t:s0
system_u:object_r:httpd_sys_content_t:s0
```

In SELinux Type Enforcement:
- A web server process running in the **`httpd_t`** domain is only permitted to read files labeled **`httpd_sys_content_t`** and write to **`httpd_sys_rw_content_t`**.
- Even if a flaw in the web server allows it to execute commands as `UID 0`, the kernel blocks `httpd_t` from reading `/etc/shadow` (which is labeled `shadow_t`) because no `allow httpd_t shadow_t:file read;` rule exists in the loaded SELinux policy!

Essential SELinux Administration & Auditing Commands:
```bash
# Check SELinux operational mode (Must be 'Enforcing' in production)
getenforce
sestatus

# Inspect SELinux security contexts on processes (-Z) and files (-Z)
ps -eZ | grep httpd
ls -laZ /etc/shadow /var/www/html

# Audit SELinux Access Vector Cache (AVC) denials in /var/log/audit/audit.log
ausearch -m AVC,USER_AVC -ts recent

# Restore default file security contexts defined by system policy
restorecon -Rv /var/www/html
```

#### 2. AppArmor (Application Armor — Debian, Ubuntu, SUSE)
AppArmor uses **path-based** Mandatory Access Control profiles stored in `/etc/apparmor.d/`. Profiles specify which file paths, capabilities, and network families a specific executable binary may access:

```text
# Example excerpt: /etc/apparmor.d/usr.sbin.nginx
#include <tunables/global>

/usr/sbin/nginx flags=(attach_disconnected) {
  #include <abstractions/base>
  #include <abstractions/nameservice>

  capability dac_override,
  capability net_bind_service,
  capability setgid,
  capability setuid,

  network inet tcp,
  network inet6 tcp,

  /etc/nginx/**                r,
  /usr/sbin/nginx              mr,
  /var/log/nginx/*.log         w,
  /var/www/html/**             r,
  /run/nginx.pid               rw,

  # Explicitly deny access to sensitive credential stores even if running as root
  deny /etc/shadow             rwx,
  deny /etc/sudoers            rwx,
  deny /etc/sudoers.d/**       rwx,
  deny /root/**                rwx,
}
```

Essential AppArmor Administration & Auditing Commands:
```bash
# Inspect loaded AppArmor profiles (Enforce vs Complain mode)
sudo aa-status

# Place a profile into strict Enforce mode
sudo aa-enforce /etc/apparmor.d/usr.sbin.nginx
```

### 40.9.5 Linux Kernel Audit Subsystem (`auditd`) Monitoring Rules

To detect unauthorized privilege changes or modifications to identity databases in real time, configure `/etc/audit/rules.d/privilege-monitoring.rules`:

```text
# /etc/audit/rules.d/privilege-monitoring.rules
# Reload with: sudo augenrules --load

# 1. Monitor modifications to identity and privilege configuration files
-w /etc/passwd -p wa -k identity_tampering
-w /etc/shadow -p wa -k identity_tampering
-w /etc/group -p wa -k identity_tampering
-w /etc/gshadow -p wa -k identity_tampering
-w /etc/security/opasswd -p wa -k identity_tampering
-w /etc/sudoers -p wa -k sudoers_modification
-w /etc/sudoers.d/ -p wa -k sudoers_modification

# 2. Monitor scheduled task directories
-w /etc/crontab -p wa -k cron_modification
-w /etc/cron.d/ -p wa -k cron_modification
-w /etc/cron.daily/ -p wa -k cron_modification
-w /etc/cron.hourly/ -p wa -k cron_modification
-w /var/spool/cron/ -p wa -k cron_modification
-w /etc/systemd/system/ -p wa -k systemd_unit_modification

# 3. Monitor execution of privilege elevation syscalls where RUID != 0 transitions to EUID == 0
-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k setuid_execution
-a always,exit -F arch=b64 -S setresuid,setreuid,setuid -F a0=0 -F exe!=/usr/bin/sudo -F exe!=/usr/sbin/sshd -k root_uid_transition

# 4. Monitor file capability and permission changes (chmod SUID/SGID, setcap)
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F a1&04000 -k suid_bit_set
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F a1&02000 -k sgid_bit_set
-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr -F A0=security.capability -k capability_modification

# 5. Monitor Kernel Module loading/unloading
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k kernel_module_activity

# Make audit configuration immutable until next reboot
-e 2
```

---

## 40.10 Chapter 40 Review Questions & Lab Exercises

1. **Kernel Credential Architecture**: Explain the difference between `RUID`, `EUID`, `SUID`, and `FSUID` inside the Linux kernel's `struct cred`. Why does `sudo` executing a binary result in `AT_SECURE = 0` whereas a Set-UID root binary executed directly by a standard user results in `AT_SECURE = 1`?
2. **`sudoers` Policy Analysis**: A system administrator grants a junior operator the rule `operator ALL=(root) NOPASSWD: /usr/bin/less /var/log/syslog`. Explain the exact architectural mechanism by which `less` permits the user to break out of the intended read-only log-viewing restriction, and write the hardened `sudoers` configuration and wrapper alternative that eliminates this risk.
3. **POSIX Capabilities**: Calculate the resulting thread capability sets $P'(\text{permitted})$ and $P'(\text{effective})$ when an unprivileged user ($P(\text{inheritable}) = 0$, $P(\text{ambient}) = 0$) executes `/usr/bin/python3` after an administrator mistakenly runs `setcap cap_setuid+ep /usr/bin/python3`. Why is `cap_dac_read_search` nearly as dangerous as `cap_dac_override`?
4. **Systemd Sandboxing Lab**: Take an existing `systemd` service unit on a test Linux VM, run `systemd-analyze security <unit>`, and iteratively add `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, `PrivateDevices=yes`, and `CapabilityBoundingSet=` until the exposure rating drops below `2.0 SAFE`.

---
---

# Chapter 41: Windows OS Security Architecture, Access Tokens & Endpoint Hardening

## 41.1 Introduction to the Windows NT Security Architecture

The Microsoft Windows NT kernel (`ntoskrnl.exe`) implements a centralized, object-based **Reference Monitor** architecture designed to meet the C2/EAL4+ security evaluation criteria. Unlike Unix systems—where everything is represented as a file descriptor and permissions were historically governed by 9 mode bits (`rwx`)—Windows represents every system resource (processes, threads, files, registry keys, named pipes, services, sections of shared memory, and window stations) as a typed **Executive Object** managed by the **Object Manager**.

Every access request to a securable object in Windows passes through the **Security Reference Monitor (SRM)** inside the Executive layer of `ntoskrnl.exe`:

```
+-----------------------------------------------------------------------------+
|                        USER MODE (Ring 3)                                   |
|                                                                             |
|  +-----------------------+              +--------------------------------+  |
|  |   Winlogon.exe /      |              |    User Process (Subject)      |  |
|  |   CredUI              |              |    Holds Primary Access Token  |  |
|  +-----------+-----------+              +---------------+----------------+  |
|              |                                          |                   |
|              v                                          | Win32 API /       |
|  +-----------------------+                              | Native API        |
|  |   LSASS.exe           |                              | (NtOpenFile,      |
|  | - Local Security Auth |                              |  NtOpenProcess)   |
|  | - Kerberos / NTLM     |                              |                   |
|  | - SAM / LSA Policy    |                              |                   |
|  +-----------+-----------+                              |                   |
+--------------|------------------------------------------|-------------------+
               | Creates Token via                        | Syscall
               | NtCreateToken()                          v
+--------------|--------------------------------------------------------------+
|              |         KERNEL MODE (Ring 0 - ntoskrnl.exe)                  |
|              v                                                              |
|  +-----------------------------------------------------------------------+  |
|  |                Security Reference Monitor (SRM - SeAccessCheck)       |  |
|  |                                                                       |  |
|  |  Compares:                                                            |  |
|  |  1. Subject's ACCESS TOKEN (User SID, Group SIDs, Privileges,         |  |
|  |     Mandatory Integrity Level)                                        |  |
|  |  2. Object's SECURITY DESCRIPTOR (Owner SID, DACL [ACEs], SACL,       |  |
|  |     Mandatory Integrity Label)                                        |  |
|  +-----------------------------------------------------------------------+  |
+-----------------------------------------------------------------------------+
```

To audit Windows systems effectively and engineer resilient endpoint configurations, a security practitioner must understand four foundational pillars:
1. **Security Identifiers (SIDs)** and how Windows uniquely identifies principals.
2. **Access Tokens** (Primary vs. Impersonation tokens, Token Privileges, and Mandatory Integrity Control).
3. **Security Descriptors (SDs)**, Discretionary Access Control Lists (**DACLs**), and Access Control Entries (**ACEs**).
4. **The Service Control Manager (SCM)**, Registry hierarchy, Dynamic-Link Library (DLL) loader mechanics, Data Protection API (**DPAPI**), and User Account Control (**UAC**).

---

## 41.2 Security Identifiers (SIDs) and Well-Known Principals

Windows never uses human-readable account names (such as `Administrator` or `SYSTEM`) internally inside access control lists. Instead, every user, group, computer account, and service is assigned a variable-length binary structure called a **Security Identifier (SID)**, formatted in string notation as:

$$\text{S}-R-I-S_1-S_2-\dots-S_n-\text{RID}$$

Where:
- $\text{S}$: Literal prefix indicating a SID.
- $R$: Revision level (always `1`).
- $I$: 48-bit Identifier Authority value (`5` = `SECURITY_NT_AUTHORITY`, `16` = `SECURITY_MANDATORY_LABEL_AUTHORITY`).
- $S_1 \dots S_n$: Subauthority values identifying the local machine or domain (`21-xxxxxxxxxx-yyyyyyyyyy-zzzzzzzzzz`).
- $\text{RID}$: **Relative Identifier** uniquely identifying the principal within that authority or domain.

### 41.2.1 Critical Well-Known SIDs and Service Accounts

| SID String | Principal Name | Architectural Privileges & Characteristics |
| :--- | :--- | :--- |
| **`S-1-5-18`** | `NT AUTHORITY\SYSTEM` (`LocalSystem`) | The highest-privilege built-in account on a Windows host. Used by the OS kernel and core Windows services. Presents the computer's machine account (`<HOSTNAME>$`) when accessing network resources over SMB/Kerberos. |
| **`S-1-5-19`** | `NT AUTHORITY\LOCAL SERVICE` | A reduced-privilege built-in service account with the same local permissions as standard `Users` (`S-1-5-32-545`). Accesses the network anonymously (null session). |
| **`S-1-5-20`** | `NT AUTHORITY\NETWORK SERVICE` | A reduced-privilege built-in service account with standard local permissions, but like `SYSTEM`, it authenticates to remote network servers using the computer's Active Directory machine account (`<HOSTNAME>$`). |
| **`S-1-5-32-544`** | `BUILTIN\Administrators` | Local Administrators group. Possesses full administrative control over the local OS. |
| **`S-1-5-32-545`** | `BUILTIN\Users` | Standard local users group (Includes `Authenticated Users` and `INTERACTIVE` by default). |
| **`S-1-5-11`** | `NT AUTHORITY\Authenticated Users` | Any user or computer principal that has authenticated to the local system or Active Directory domain (excludes Anonymous logon `S-1-5-7`). **Audit note**: Permissions granted to `Authenticated Users` apply to all standard domain users! |
| **`S-1-5-80-...`** | `NT SERVICE\<ServiceName>` | Virtual Service Accounts introduced in Windows Server 2008 R2 / Windows 7. Each service gets its own isolated SID (`NT SERVICE\mssqlserver`), allowing file and registry ACLs to be scoped to a single service without granting access to other services. |
| **`S-1-16-4096`** | `Mandatory Label\Low Integrity` | Used by sandboxed processes (e.g., Protected Mode / AppContainer renderers). |
| **`S-1-16-8192`** | `Mandatory Label\Medium Integrity` | Default integrity level for standard users and filtered UAC tokens for administrators. |
| **`S-1-16-12288`** | `Mandatory Label\High Integrity` | Integrity level for elevated administrative processes. |
| **`S-1-16-16384`** | `Mandatory Label\System Integrity` | Integrity level reserved for `SYSTEM` and protected OS services. |

---

## 41.3 Windows Access Tokens and Token Privileges (`whoami /priv`)

When a user authenticates via `Winlogon.exe`, `sshd`, `WinRM`, or `SMB`, the Local Security Authority Subsystem Service (`lsass.exe`) verifies their credentials and constructs an executive kernel object of type `TOKEN` (`_TOKEN` structure in `ntoskrnl.exe`).

### 41.3.1 Primary Tokens vs. Impersonation Tokens and Named Pipe Mechanics

Every Windows process has a **Primary Token** that describes the default security context inherited by all threads created inside that process. However, Windows is built around a client-server architecture (using RPC, ALPC, DCOM, HTTP, and Named Pipes) where a high-privilege system service (running as `SYSTEM`, `NETWORK SERVICE`, or `LOCAL SERVICE`) frequently handles requests on behalf of an unprivileged client user.

To ensure that a `SYSTEM` service does not accidentally open a file on behalf of `Alice` that `Alice` herself is forbidden from reading, Windows provides **Thread Impersonation**:
1. When a client connects to a Named Pipe (`\\.\pipe\<pipename>`) or RPC endpoint exposed by a server process, the server thread can call Win32 APIs such as `ImpersonateNamedPipeClient()`, `RpcImpersonateClient()`, or `SetThreadToken()`.
2. The kernel attaches an **Impersonation Token** representing the client's identity directly to that specific server thread while leaving the process's Primary Token untouched.
3. Every Impersonation Token is created at one of four **Security Impersonation Levels** (`SECURITY_IMPERSONATION_LEVEL` enum):
   - **`SecurityAnonymous`**: The server cannot obtain identification information about the client and cannot impersonate the client.
   - **`SecurityIdentification`**: The server can inspect the client's SIDs and privileges (e.g., to perform custom ACL checks), but **cannot** impersonate the client to open local or network objects.
   - **`SecurityImpersonation`**: The server can impersonate the client's security context on the **local** system (and can duplicate the token into a Primary Token to spawn a new process via `CreateProcessWithTokenW` or `CreateProcessAsUserW` if the calling process holds `SeImpersonatePrivilege` or `SeAssignPrimaryTokenPrivilege`).
   - **`SecurityDelegation`**: The server can impersonate the client on both local and remote network systems.

### 41.3.2 Architectural Analysis of High-Risk Token Privileges

In Windows, **Privileges** are distinct from Object Access Rights:
- **Access Rights** are stored on the *object* (inside its DACL) and control who can open a specific file, registry key, or service.
- **Privileges** are stored inside the *subject's Access Token* and authorize the holder to perform system-wide operations that override normal DACL checks or modify kernel state.

A token stores an array of privileges (`_SEP_TOKEN_PRIVILEGES`), each with a flag indicating whether it is currently **Disabled** or **Enabled**. Importantly, a privilege that is listed as `Disabled` in `whoami /priv` is **not** blocked—it is merely inactive by default to prevent accidental errors, and any code running inside that process can immediately enable it by invoking the Win32 API `AdjustTokenPrivileges()`. Only privileges completely removed from the token cannot be enabled.

Below is the architectural breakdown of the seven most critical Windows Token Privileges that grant `SYSTEM`-equivalent control over the operating system:

| Token Privilege Name | Intended OS Purpose | Why Holding This Privilege Is Equivalent to `SYSTEM` | Hardening & Mitigation Strategy |
| :--- | :--- | :--- | :--- |
| **`SeImpersonatePrivilege`** (*Impersonate a client after authentication*) | Assigned by default to `LOCAL SERVICE`, `NETWORK SERVICE`, IIS Application Pool identities (`IIS_IUSRS`), SQL Server service accounts, and local `Administrators` so service threads can drop *down* to impersonate connecting clients. | The kernel check inside `CreateProcessWithTokenW()` verifies whether the caller holds `SeImpersonatePrivilege`, **not** whether the impersonated token is lower-privileged than the caller! If a service account holding `SeImpersonatePrivilege` receives an inbound local RPC, DCOM, or Named Pipe connection from a `SYSTEM` service (such as the Print Spooler, RPC Endpoint Mapper, or BITS), it acquires a `SecurityImpersonation` token for `NT AUTHORITY\SYSTEM` and can launch a process as `SYSTEM`. | Minimize services granted `SeImpersonatePrivilege` via Local Security Policy (`secpol.msc` -> *User Rights Assignment*); disable unnecessary `SYSTEM` services (such as `Spooler` on servers); enforce Windows Server 2022/Windows 11 DCOM/RPC authentication hardening; isolate web/DB services in Group Managed Service Accounts (gMSAs) with restricted User Rights. |
| **`SeAssignPrimaryTokenPrivilege`** (*Replace a process-level token*) | Allows a parent service (like Task Scheduler or `Winlogon`) to start a new process using a primary token via `CreateProcessAsUser()`. | Identical impact to `SeImpersonatePrivilege`: any `SecurityImpersonation` token obtained for `SYSTEM` can be duplicated via `DuplicateTokenEx(..., TokenPrimary, ...)` and assigned to a newly spawned process. | Restrict *Replace a process level token* strictly to `LOCAL SERVICE` and `NETWORK SERVICE` where required by the OS; never assign to custom user accounts. |
| **`SeBackupPrivilege`** (*Back up files and directories*) | Allows backup agents to read any file on the NTFS volume regardless of the file's DACL when `CreateFile()` is invoked with the `FILE_FLAG_BACKUP_SEMANTICS` flag. | Bypasses all NTFS read ACLs across the entire filesystem, allowing the holder to read the Registry hives (`HKLM\SAM`, `HKLM\SYSTEM`, `HKLM\SECURITY`), Volume Shadow Copies, or Active Directory's `C:\Windows\NTDS\ntds.dit` on a Domain Controller. | Never grant `Backup Operators` (`S-1-5-32-551`) membership to interactive user accounts; use dedicated, non-interactive tiered service accounts with strict logon restrictions (`SeDenyInteractiveLogonRight`, `SeDenyRemoteInteractiveLogonRight`). |
| **`SeRestorePrivilege`** (*Restore files and directories*) | Allows backup agents to write to any file or registry key and set any valid SID as the file's owner when opening with `FILE_FLAG_BACKUP_SEMANTICS`. | Bypasses all NTFS and Registry write ACLs, allowing modification of `SYSTEM`-owned service binaries in `C:\Windows\System32`, DLLs, or `HKLM\SYSTEM\CurrentControlSet\Services` configurations. | Same as `SeBackupPrivilege`; audit membership of `Backup Operators` and `Server Operators` continuously. |
| **`SeDebugPrivilege`** (*Debug programs*) | Allows a debugger to call `OpenProcess(PROCESS_ALL_ACCESS, ...)` on any process, ignoring the target process's DACL (except Protected Process Light `PPL` processes). | Allows opening a handle to `SYSTEM`-owned processes (such as `winlogon.exe` or `services.exe`) to duplicate their `SYSTEM` token or spawn a child process inheriting the `SYSTEM` parent handle (`PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`), and on systems without LSA Protection (`RunAsPPL`), allows reading `lsass.exe` memory. | Remove all accounts (including `Administrators` where feasible on hardened production servers) from the *Debug programs* User Rights Assignment GPO, and enable **LSA Protection (`RunAsPPL`)** + **Credential Guard**. |
| **`SeTakeOwnershipPrivilege`** (*Take ownership of files or other objects*) | Allows a user to invoke `SetNamedSecurityInfo()` (`WRITE_OWNER`) on any securable object to set themselves as the object's Owner, ignoring the existing DACL. | Because the **Owner** of an object in Windows always possesses the implicit `WRITE_DAC` right, taking ownership of a `SYSTEM` service registry key or executable allows immediately granting oneself `FullControl` (`GENERIC_ALL`). | Restrict *Take ownership of files or other objects* strictly to `BUILTIN\Administrators`. |
| **`SeLoadDriverPrivilege`** (*Load and unload device drivers*) | Allows calling `NtLoadDriver()` to load a kernel-mode device driver (`.sys`) specified under `HKCU` or `HKLM` into Ring 0. | Even with Driver Signature Enforcement (DSE), a principal with `SeLoadDriverPrivilege` can load a legitimately Microsoft-signed third-party hardware diagnostic driver that contains a known arbitrary kernel read/write IOCTL flaw (known as **Bring Your Own Vulnerable Driver / BYOVD**). | Remove `Print Operators` and non-Tier-0 accounts from *Load and unload device drivers*; enforce **Hypervisor-Protected Code Integrity (HVCI)** and the **Microsoft Vulnerable Driver Blocklist**. |

---

## 41.4 Windows Services Architecture and Common Misconfigurations

Windows Services are background daemons managed by the **Service Control Manager (SCM)** (`services.exe`, running as `NT AUTHORITY\SYSTEM`). Every registered service has a persistent configuration key in the Windows Registry at:

```text
HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>
```

Key registry values inside each service key include:
- **`ImagePath`** (`REG_EXPAND_SZ`): The command line of the executable binary (or `svchost.exe -k <GroupName>`).
- **`ObjectName`** (`REG_SZ`): The security principal under which the service runs (`LocalSystem`, `NT AUTHORITY\LocalService`, `NT AUTHORITY\NetworkService`, or a domain/gMSA account).
- **`Start`** (`REG_DWORD`): Startup type (`0` = Boot, `1` = System, `2` = Automatic, `3` = Manual/Demand, `4` = Disabled).
- **`Security` (`SD` subkey)**: The binary Security Descriptor governing which users/groups are permitted to query, start, stop, or reconfigure the service via the SCM API.

When a service runs as `LocalSystem` (`SYSTEM`), four distinct misconfigurations in how the service is installed or permissioned allow a standard local user (`BUILTIN\Users` or `NT AUTHORITY\Authenticated Users`) to execute code as `SYSTEM`:

### 41.4.1 Weak Permissions on the Service Binary or Parent Directory

When a third-party vendor installs software into a custom directory (such as `C:\VendorApp\Service\daemon.exe`) rather than `C:\Program Files\`, the directory inherits the root drive `C:\` default NTFS DACL. On standard Windows installations, the root drive `C:\` grants `BUILTIN\Users` permission to create subdirectories (`FILE_ADD_SUBDIRECTORY`) and append data, and poorly authored MSI installers frequently grant `BUILTIN\Users` or `Everyone` **Modify (`M`)** or **FullControl (`F`)** rights on the application folder and its `.exe` binary.

If `daemon.exe` runs as `LocalSystem` and a non-administrative user has `FILE_WRITE_DATA` (`W`), `Modify` (`M`), or `FullControl` (`F`) on `daemon.exe` (or `FILE_DELETE_CHILD` + `FILE_ADD_FILE` on its parent directory), the user can replace the binary on disk and wait for the service (or the machine) to restart.

### 41.4.2 Unquoted Service Paths Containing Spaces

When the Service Control Manager starts a service whose `ImagePath` contains spaces **and is not enclosed in double quotes**, the Windows `CreateProcessW()` API must resolve the ambiguity between where the executable path ends and where command-line arguments begin.

Suppose a service running as `LocalSystem` has the unquoted `ImagePath`:
```text
C:\Program Files\Acme Corp\Cloud Sync\Agent Service\SyncAgent.exe -service -silent
```

Because `CreateProcessW()` parses spaces from left to right when quotes are absent, it attempts to execute the following file paths in exact sequential order until one succeeds:

```
Attempt 1: C:\Program.exe
Attempt 2: C:\Program Files\Acme.exe
Attempt 3: C:\Program Files\Acme Corp\Cloud.exe
Attempt 4: C:\Program Files\Acme Corp\Cloud Sync\Agent.exe
Attempt 5: C:\Program Files\Acme Corp\Cloud Sync\Agent Service\SyncAgent.exe
```

If a non-administrative user has write permissions (`FILE_ADD_FILE` / `W`) in any of the intermediate directories—for instance, `C:\Program Files\Acme Corp\`—and places an executable named `Cloud.exe` there, SCM will execute `C:\Program Files\Acme Corp\Cloud.exe` as `NT AUTHORITY\SYSTEM` instead of reaching `SyncAgent.exe`.

**Hardening Fix**: Always enclose any service `ImagePath` containing spaces in explicit double quotes:
```text
"C:\Program Files\Acme Corp\Cloud Sync\Agent Service\SyncAgent.exe" -service -silent
```

### 41.4.3 Weak Service Object DACLs in the Service Control Manager (SCM)

Independently of the NTFS permissions on the `.exe` file, every service object inside SCM has its own Security Descriptor (viewable via `sc.exe sdshow <ServiceName>` in Security Descriptor Definition Language / **SDDL** format, or via PowerShell / Sysinternals `AccessChk`).

Key SCM Service Access Rights include:
- `SERVICE_QUERY_CONFIG` (`CC`) & `SERVICE_QUERY_STATUS` (`LC`): Safe read-only rights.
- `SERVICE_START` (`RP`) & `SERVICE_STOP` (`WP`): Allows starting and stopping the service.
- **`SERVICE_CHANGE_CONFIG` (`DC`)**: Allows calling `ChangeServiceConfigW()` (`sc.exe config`) to modify the service's `ImagePath` (`binPath=`) and `ObjectName` (`obj= LocalSystem`).
- **`WRITE_DAC` (`WD`)**: Allows overwriting the service's DACL to grant `SERVICE_CHANGE_CONFIG`.
- **`WRITE_OWNER` (`WO`)**: Allows taking ownership of the service object.
- **`GENERIC_ALL` (`GA`) / `SERVICE_ALL_ACCESS` (`FA`)**: Grants all of the above.

If `BUILTIN\Users` (`BU`), `Authenticated Users` (`AU`), or `INTERACTIVE` (`IU`) is granted `DC`, `WD`, `WO`, or `GA` on a service in SCM, any standard user can reconfigure the service's `ImagePath` to run arbitrary commands as `LocalSystem`.

### 41.4.4 Weak Registry Key Permissions on `HKLM\SYSTEM\CurrentControlSet\Services\<Svc>`

Even if the SCM Service DACL is locked down, SCM reads the service configuration from `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>` upon system boot or service reload. If the Registry key's DACL grants `KEY_SET_VALUE`, `WriteKey`, or `FullControl` to a non-administrative user or group, that user can directly modify the `ImagePath` registry value (or the `Performance` / `Parameters\ServiceDll` subkey for `svchost`-hosted services) so that the modified binary path executes as `SYSTEM` on the next service start or reboot.

### 41.4.5 Dynamic-Link Library (DLL) Search Order Mechanics

When a Windows process loads a Dynamic-Link Library via `LoadLibrary("version.dll")` without specifying a fully qualified path (`C:\Windows\System32\version.dll`), the Windows Loader (`ntdll.dll!LdrLoadDll`) resolves the library name using a deterministic search order.

With **SafeDllSearchMode** enabled (the default since Windows XP SP2 / Windows Server 2003), the standard desktop application DLL search order is:

```
+-------------------------------------------------------------------------+
|                    WINDOWS DLL LOADER RESOLUTION ORDER                  |
|                                                                         |
|  Pre-Check A: Is the DLL already loaded in memory?                      |
|  Pre-Check B: Is the DLL on the KnownDLLs list?                         |
|               (HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\   |
|                KnownDLLs -> loaded directly from \KnownDlls\ System32)  |
|                                                                         |
|  If not in memory and not in KnownDLLs, search disk in this order:      |
|  1. The directory from which the application (.exe) was loaded.         |
|  2. The System directory (C:\Windows\System32 via GetSystemDirectory).  |
|  3. The 16-bit System directory (C:\Windows\System).                    |
|  4. The Windows directory (C:\Windows via GetWindowsDirectory).         |
|  5. The current working directory (CWD).                                |
|  6. The directories listed in the system and user %PATH% environment    |
|     variable (in order from left to right).                             |
+-------------------------------------------------------------------------+
```

Two common architectural flaws create privilege escalation risks via the DLL loader:
1. **Writable Application Directory (Step 1)**: If a privileged service runs from `C:\VendorApp\daemon.exe` and imports a non-`KnownDLL` library (such as `wtsapi32.dll`, `userenv.dll`, `version.dll`, or a vendor plugin DLL), the loader checks `C:\VendorApp\` **before** `C:\Windows\System32\`. If `C:\VendorApp\` is writable by standard users, placing a DLL of that name in `C:\VendorApp\` causes the privileged process to load it instead of the real `System32` copy.
2. **Missing DLLs with a Writable Directory in System `%PATH%` (Step 6)**: If a privileged service attempts to load an optional plugin DLL that does not exist in Steps 1–5 (observable as `NAME NOT FOUND` in Sysinternals Process Monitor), the loader iterates through every directory in the system `%PATH%`. If an administrator has installed third-party developer tools (such as Python, Ruby, Perl, or custom scripts) into a folder like `C:\Python311\` or `C:\Tools\` that is added to the system `%PATH%` and retains default `BUILTIN\Users:(OI)(CI)(M)` write permissions, any standard user can place the missing DLL into that `%PATH%` folder.

**Hardening Remediations for DLL Loading**:
- Developers must call `LoadLibraryExW()` with `LOAD_LIBRARY_SEARCH_SYSTEM32` or call `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32)` at the beginning of `main()` / `ServiceMain()`.
- Administrators must audit every directory in the Machine `%PATH%` (`HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment\Path`) to ensure no non-administrative user has Write/Modify permissions.

---

## 41.5 Registry Policies, Scheduled Tasks, DPAPI, and Credential Storage

### 41.5.1 The `AlwaysInstallElevated` Group Policy Anti-Pattern

Windows Installer (`msiexec.exe`) installs `.msi` packages using a twin-process architecture: a client process running in the user's context communicates with the `msiserver` Windows service running as `NT AUTHORITY\SYSTEM`. Normally, `msiserver` impersonates the calling user when installing software unless the user is a member of `BUILTIN\Administrators`.

However, Group Policy includes a legacy policy setting named **Always install with elevated privileges** (`AlwaysInstallElevated`), designed in the Windows 2000 era to let non-administrative users install software packages without IT assistance. When enabled, it sets `AlwaysInstallElevated = 1` (`REG_DWORD`) in **both** of the following Registry keys:
1. `HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer`
2. `HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer`

**Why This Policy Is Fatal to Endpoint Security**:
An `.msi` file is a relational database containing a `CustomAction` table that allows the package author to execute arbitrary VBScript, JScript, or native executables during installation. When `AlwaysInstallElevated` is enabled in both `HKLM` and `HKCU`, Windows Installer executes *any* user-supplied `.msi` package—including its custom actions—directly as `NT AUTHORITY\SYSTEM`. Therefore, enabling `AlwaysInstallElevated` grants every standard user on the workstation full `SYSTEM` privileges. It must **always** be set to `Disabled` (`0` or absent) in enterprise Group Policy.

### 41.5.2 Autoruns, Logon Scripts, and Scheduled Tasks

Similar to `cron` and `systemd` on Linux, Windows provides multiple auto-start extensibility points (ASEPs):
- **Registry Run Keys**:
  - `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
  - `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`
  - `HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`
  Executables listed under `HKLM\...\Run` execute inside the security context of *every* user who logs into the machine interactively (including Domain Administrators or Local Administrators). If the binary referenced by an `HKLM\...\Run` value is writable by a standard user, any higher-privileged user who logs on interactively will execute the modified binary.
- **Scheduled Tasks (`Task Scheduler`)**:
  Stored as XML definitions in `C:\Windows\System32\Tasks\` and registered under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\`. Auditors must verify that neither the task XML files nor any executable or PowerShell/Batch script invoked by a `SYSTEM` or privileged user task has write permissions for standard users.

### 41.5.3 Windows Credential Architecture: SAM, LSA Secrets, DPAPI, and History Files

Understanding where Windows caches or stores authentication secrets allows security engineers to eliminate plaintext exposures and configure hardware-backed credential isolation:

```
+-----------------------------------------------------------------------------+
|                    WINDOWS CREDENTIAL STORAGE ARCHITECTURE                  |
+-----------------------------------------------------------------------------+
| 1. Security Accounts Manager (SAM - C:\Windows\System32\config\SAM)         |
|    - Stores local user accounts (e.g., local Administrator).                |
|    - Hashes passwords as 16-byte MD4(UTF-16LE(password)) [NT Hash],         |
|      encrypted at rest with the SYSKEY BootKey stored in HKLM\SYSTEM.       |
|                                                                             |
| 2. Local Security Authority (LSA) Secrets (C:\Windows\System32\config\SECURITY)
|    - Stored under HKLM\SECURITY\Policy\Secrets.                             |
|    - Contains: Domain Cached Credentials (DCC2 / MSCacheV2 PBKDF2 hashes),  |
|      Active Directory Machine Account password ($MACHINE.ACC), DPAPI        |
|      System Master Key, and non-gMSA Windows Service account passwords!     |
|                                                                             |
| 3. Data Protection API (DPAPI)                                              |
|    - User Master Keys stored in %APPDATA%\Microsoft\Protect\<User-SID>\     |
|    - Encrypted with a key derived from the user's SHA-1/NT password hash    |
|      and (for domain users) backed up with the Domain Controller's DPAPI    |
|      Domain Backup Key.                                                     |
|    - Protects: Windows Credential Manager (Vault / cmdkey), Chrome/Edge     |
|      Browser encryption keys, EFS keys, and Wi-Fi WPA2 profiles.            |
+-----------------------------------------------------------------------------+
```

#### Common Cleartext and Weakly Protected Credential Artifacts Audited on Endpoints
1. **Unattended Windows Deployment Files**:
   Enterprise imaging systems (MDT, SCCM/MECM, WDS) use answer files to configure Windows during automated installation. If cleanup scripts fail to scrub these files after deployment, local Administrator or domain-join service account passwords may remain on disk in cleartext or Base64 encoding inside:
   - `C:\Windows\Panther\Unattend.xml`
   - `C:\Windows\Panther\Unattend\Unattend.xml`
   - `C:\Windows\System32\Sysprep\unattend.xml`
   - `C:\Windows\System32\Sysprep\sysprep.inf`
2. **PowerShell `PSReadLine` Command History**:
   Starting in Windows 10 / Windows Server 2016 (PowerShell 5.0+), the `PSReadLine` module automatically persists the last 4,096 commands typed in every interactive PowerShell session to a plain text file at:
   ```text
   %APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
   ```
   If an administrator types `ConvertTo-SecureString "MySecretPass!" -AsPlainText -Force` or passes credentials inline, those credentials remain on disk in plaintext until purged.
3. **Legacy Group Policy Preferences (GPP `cpassword` — MS14-025)**:
   Prior to Microsoft patch MS14-025 (KB2962486), Group Policy Preferences allowed administrators to push local user password updates via XML files (`Groups.xml`, `Services.xml`, `Scheduledtasks.xml`, `DataSources.xml`) stored in the domain's world-readable `\\<DOMAIN>\SYSVOL\<DOMAIN>\Policies\` share. Microsoft encrypted the `cpassword` attribute using a static, publicly documented 32-byte AES key published in the MSDN protocol specifications. Although KB2962486 blocked the GPO editor from creating *new* GPP password policies, historical `Groups.xml` files frequently remain lingering in `SYSVOL` until manually audited and deleted.
4. **Windows Credential Manager (`cmdkey /list`)**:
   Users or administrators who store persistent network or `runas /savecred` credentials in the Windows Vault allow any code running inside their user session to invoke stored credentials without re-entering the password.

---

## 41.6 User Account Control (UAC) Architecture and Enforcement Boundaries

Introduced in Windows Vista / Windows Server 2008, **User Account Control (UAC)** implements the **Admin Approval Mode (AAM)** architecture so that members of `BUILTIN\Administrators` do not run day-to-day applications (such as web browsers, email clients, and document viewers) with full administrative privileges.

### 41.6.1 How UAC Split-Token Architecture Works

When a user who is a member of `BUILTIN\Administrators` logs into Windows interactively, `lsass.exe` generates **two linked Access Tokens**:

```
+-----------------------------------------------------------------------------+
|            ADMIN APPROVAL MODE (UAC SPLIT-TOKEN ARCHITECTURE)               |
+-----------------------------------------------------------------------------+
|                                                                             |
|  +----------------------------------+   +--------------------------------+  |
|  |     FILTERED ACCESS TOKEN        |   |      FULL ACCESS TOKEN         |  |
|  |   (Default for Explorer.exe)     |   |   (Linked via TokenLinkedToken)|  |
|  +----------------------------------+   +--------------------------------+  |
|  | Integrity Level: Medium (0x2000) |   | Integrity Level: High (0x3000) |  |
|  |                                  |   |                                |  |
|  | Group SIDs:                      |   | Group SIDs:                    |  |
|  | - BUILTIN\Users (Enabled)        |   | - BUILTIN\Users (Enabled)      |  |
|  | - BUILTIN\Administrators         |   | - BUILTIN\Administrators       |  |
|  |   [SE_GROUP_USE_FOR_DENY_ONLY!]  |   |   [SE_GROUP_ENABLED!]          |  |
|  |                                  |   |                                |  |
|  | Privileges:                      |   | Privileges:                    |  |
|  | - SeChangeNotifyPrivilege        |   | - SeDebugPrivilege             |  |
|  | - SeShutdownPrivilege            |   | - SeTakeOwnershipPrivilege     |  |
|  | - SeUndockPrivilege              |   | - SeBackupPrivilege            |  |
|  | (All admin privileges STRIPPED)  |   | - SeRestorePrivilege           |  |
|  |                                  |   | - SeImpersonatePrivilege (etc) |  |
|  +----------------------------------+   +--------------------------------+  |
+-----------------------------------------------------------------------------+
```

When a Medium-integrity process requests elevation (`ShellExecuteEx` with the `"runas"` verb, or launching a binary whose application manifest declares `<requestedExecutionLevel level="requireAdministrator" />`):
1. The request is sent over ALPC to the **Application Information Service (`AppInfo` / `svchost.exe`)** running as `NT AUTHORITY\SYSTEM`.
2. Depending on the UAC Group Policy level, `AppInfo` switches the display to the isolated **Secure Desktop** (`Winlogon` desktop, inaccessible to Medium-integrity user processes) and launches `consent.exe` to prompt the user for confirmation or credentials.
3. Once approved, `AppInfo` retrieves the user's linked **Full (High-Integrity) Token** and spawns the new process.

### 41.6.2 Why Default UAC ("Elevate without prompting for Windows binaries") Has Auto-Elevation Gaps

By default on Windows client installations, UAC is configured to level 3 of 4: **"Notify me only when apps try to make changes to my computer (do not dim my desktop)"** (`ConsentPromptBehaviorAdmin = 5`, `EnableLUA = 1`, `PromptOnSecureDesktop = 1`).

Under `ConsentPromptBehaviorAdmin = 5`, Microsoft wanted built-in Windows management applets (such as `fodhelper.exe`, `computerdefaults.exe`, `eventvwr.exe`, `sdclt.exe`, and `CompMgmtLauncher.exe`) to open smoothly without annoying the administrator with a UAC popup every time they open Event Viewer or Settings. Therefore, `AppInfo` automatically elevates any executable that meets **three criteria** without showing a `consent.exe` prompt:
1. The executable is digitally signed by the Microsoft Windows Publisher certificate.
2. The executable resides in a trusted system directory (`C:\Windows\System32\` or `C:\Windows\SysWOW64\`).
3. The executable's embedded XML manifest specifies `<autoElevate>true</autoElevate>`.

**The Architectural Flaw of Auto-Elevating Binaries**:
Although an auto-elevating binary runs at **High Integrity**, it still runs inside the **same user account session** (`HKCU` Registry hive and user environment variables) as the unprivileged **Medium Integrity** processes of that user! Because `HKCU` (`HKEY_CURRENT_USER`) is writable by Medium-integrity processes, if an `<autoElevate>true</autoElevate>` binary queries `HKCU\Software\Classes\...` (the per-user COM class or file association registry hive, which takes precedence over `HKLM\Software\Classes\` inside the Merged `HKEY_CLASSES_ROOT` view) to look up a shell command or COM Server DLL to invoke, any Medium-integrity process can write a handler into `HKCU\Software\Classes\` that the High-integrity auto-elevated binary will subsequently execute at High Integrity.

This is why Microsoft officially states that **UAC is a convenience feature to encourage least-privilege software design, not a formal security boundary between Medium and High integrity within the same administrative user account**, unless configured to its maximum enforcement level.

### 41.6.3 Hardening UAC to Eliminate Silent Auto-Elevation

To prevent silent auto-elevation (`<autoElevate>true</autoElevate>`), enterprise security teams should configure two primary controls:
1. **Principle of Least Privilege (Account Separation)**: Never use an account that is a member of `BUILTIN\Administrators` for daily interactive work, web browsing, or email. Standard users (`ConsentPromptBehaviorUser`) cannot use `<autoElevate>true</autoElevate>` at all; they must enter separate administrative credentials ("Over-the-Shoulder" elevation).
2. **Enforce `Always Notify` on Secure Desktop (`ConsentPromptBehaviorAdmin = 2` or `1`)**:
   Configure Group Policy under `Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Local Policies -> Security Options`:
   - **User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode** = `Prompt for consent on the secure desktop` (`ConsentPromptBehaviorAdmin = 2`) or `Prompt for credentials on the secure desktop` (`ConsentPromptBehaviorAdmin = 1`).
   When set to `2` or `1`, Windows disables silent `<autoElevate>true</autoElevate>` completely—every elevation request requires human interaction on the isolated Secure Desktop.

---

## 41.7 Comprehensive Windows Endpoint Security Auditing Script (PowerShell)

Below is a comprehensive, read-only PowerShell security auditing script (`Invoke-WindowsPrivilegeAudit.ps1`) designed for systems engineers and security auditors. It systematically inspects token privileges, unquoted service paths, weak service binary and directory ACLs, weak SCM service DACLs, Machine `%PATH%` ACLs, `AlwaysInstallElevated`, UAC posture, LSA Protection (`RunAsPPL`), and leftover unattended installation files.

```powershell
<#
.SYNOPSIS
    Invoke-WindowsPrivilegeAudit.ps1
    Read-Only Windows Endpoint Privilege Boundary & Hardening Auditor
.DESCRIPTION
    Audits a Windows workstation or server for local privilege escalation
    misconfigurations and verifies CIS / Microsoft Security Baseline controls.
    Performs strictly read-only WMI/CIM, Registry, and ACL inspections.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'SilentlyContinue'

function Write-AuditSection {
    param([string]$Title)
    Write-Host "`n==============================================================================" -ForegroundColor Cyan
    Write-Host "[*] $Title" -ForegroundColor Cyan
    Write-Host "==============================================================================" -ForegroundColor Cyan
}

function Write-Pass { param([string]$Msg) Write-Host "[PASS] $Msg" -ForegroundColor Green }
function Write-Warn { param([string]$Msg) Write-Host "[WARN] $Msg" -ForegroundColor Yellow }
function Write-Crit { param([string]$Msg) Write-Host "[CRIT] $Msg" -ForegroundColor Red }

# Low-privileged identity patterns to flag when granted write/modify rights on SYSTEM resources
$LowPrivIdentities = @(
    'Everyone',
    'BUILTIN\Users',
    'NT AUTHORITY\Authenticated Users',
    'NT AUTHORITY\INTERACTIVE',
    'BUILTIN\Guests'
)

$WriteRightsMask = [System.Security.AccessControl.FileSystemRights]::Write -bor `
                   [System.Security.AccessControl.FileSystemRights]::Modify -bor `
                   [System.Security.AccessControl.FileSystemRights]::FullControl -bor `
                   [System.Security.AccessControl.FileSystemRights]::WriteData -bor `
                   [System.Security.AccessControl.FileSystemRights]::CreateFiles -bor `
                   [System.Security.AccessControl.FileSystemRights]::TakeOwnership -bor `
                   [System.Security.AccessControl.FileSystemRights]::ChangePermissions

# ------------------------------------------------------------------------------
Write-AuditSection "1. SYSTEM BASELINE & CURRENT ACCESS TOKEN CONTEXT"
# ------------------------------------------------------------------------------
$os = Get-CimInstance -ClassName Win32_OperatingSystem
Write-Host ("Hostname        : {0}" -f $env:COMPUTERNAME)
Write-Host ("OS Caption      : {0} ({1})" -f $os.Caption, $os.OSArchitecture)
Write-Host ("OS Version/Build: {0} (Build {1})" -f $os.Version, $os.BuildNumber)
Write-Host ("Current User    : {0}" -f [System.Security.Principal.WindowsIdentity]::GetCurrent().Name)

Write-Host "`n--- Checking Current Token Privileges (whoami /priv) ---"
$HighRiskPrivs = @(
    'SeImpersonatePrivilege',
    'SeAssignPrimaryTokenPrivilege',
    'SeBackupPrivilege',
    'SeRestorePrivilege',
    'SeDebugPrivilege',
    'SeTakeOwnershipPrivilege',
    'SeLoadDriverPrivilege',
    'SeTcbPrivilege',
    'SeCreateTokenPrivilege'
)

$privOutput = whoami.exe /priv /fo csv | ConvertFrom-Csv
foreach ($priv in $privOutput) {
    if ($HighRiskPrivs -contains $priv.'Privilege Name') {
        Write-Warn ("High-impact privilege present in current token: {0} ({1})" -f $priv.'Privilege Name', $priv.State)
    }
}

# ------------------------------------------------------------------------------
Write-AuditSection "2. UNQUOTED SERVICE PATHS AUDIT"
# ------------------------------------------------------------------------------
$services = Get-CimInstance -ClassName Win32_Service | Where-Object { $_.PathName -ne $null }
$unquotedCount = 0

foreach ($svc in $services) {
    $path = $svc.PathName.Trim()
    # Ignore paths starting with a quote or paths residing inside C:\Windows\System32\svchost.exe without spaces in the executable portion
    if ($path -notmatch '^"' -and $path -notmatch '^\\?\??\\') {
        # Extract executable portion before any command-line flag (- or /)
        if ($path -match '^(?<exe>.+?\.exe)\b') {
            $exePath = $Matches['exe']
            if ($exePath -match '\s') {
                $unquotedCount++
                Write-Crit ("Unquoted Service Path: [{0}] (StartMode: {1}, RunAs: {2}) -> {3}" -f $svc.Name, $svc.StartMode, $svc.StartName, $svc.PathName)
            }
        }
    }
}
if ($unquotedCount -eq 0) {
    Write-Pass "No services with unquoted spaces in their executable path were found."
}

# ------------------------------------------------------------------------------
Write-AuditSection "3. SERVICE BINARY & DIRECTORY NTFS PERMISSIONS AUDIT"
# ------------------------------------------------------------------------------
$weakBinCount = 0
foreach ($svc in $services) {
    $rawPath = $svc.PathName.Trim().Trim('"')
    if ($rawPath -match '^(?<exe>[a-zA-Z]:\\.+?\.exe)\b') {
        $exeFile = $Matches['exe']
        if ($exeFile -notlike "$env:SystemRoot\*" -and (Test-Path -LiteralPath $exeFile)) {
            $acl = Get-Acl -LiteralPath $exeFile
            foreach ($ace in $acl.Access) {
                if ($ace.AccessControlType -eq 'Allow' -and ($LowPrivIdentities -contains $ace.IdentityReference.Value)) {
                    if (($ace.FileSystemRights -band $WriteRightsMask) -ne 0) {
                        $weakBinCount++
                        Write-Crit ("Service Binary Writable by [{0}]: Service '{1}' ({2}) -> {3} [{4}]" -f $ace.IdentityReference, $svc.Name, $svc.StartName, $exeFile, $ace.FileSystemRights)
                    }
                }
            }
        }
    }
}
if ($weakBinCount -eq 0) {
    Write-Pass "All non-Windows service binaries have restricted NTFS write permissions."
}

# ------------------------------------------------------------------------------
Write-AuditSection "4. SERVICE REGISTRY KEY PERMISSIONS AUDIT"
# ------------------------------------------------------------------------------
$weakSvcRegCount = 0
$svcRegRoot = "HKLM:\SYSTEM\CurrentControlSet\Services"
Get-ChildItem -Path $svcRegRoot | ForEach-Object {
    $regKey = $_
    $acl = Get-Acl -LiteralPath $regKey.PSPath
    foreach ($ace in $acl.Access) {
        if ($ace.AccessControlType -eq 'Allow' -and ($LowPrivIdentities -contains $ace.IdentityReference.Value)) {
            $regWriteMask = [System.Security.AccessControl.RegistryRights]::SetValue -bor `
                            [System.Security.AccessControl.RegistryRights]::CreateSubKey -bor `
                            [System.Security.AccessControl.RegistryRights]::WriteKey -bor `
                            [System.Security.AccessControl.RegistryRights]::FullControl -bor `
                            [System.Security.AccessControl.RegistryRights]::ChangePermissions -bor `
                            [System.Security.AccessControl.RegistryRights]::TakeOwnership
            if (($ace.RegistryRights -band $regWriteMask) -ne 0) {
                $weakSvcRegCount++
                Write-Crit ("Writable Service Registry Key: {0} writable by [{1}] ({2})" -f $regKey.Name, $ace.IdentityReference, $ace.RegistryRights)
            }
        }
    }
}
if ($weakSvcRegCount -eq 0) {
    Write-Pass "All HKLM\SYSTEM\CurrentControlSet\Services keys are protected against non-admin writes."
}

# ------------------------------------------------------------------------------
Write-AuditSection "5. SYSTEM %PATH% DIRECTORY ACL AUDIT (DLL SEARCH ORDER HYGIENE)"
# ------------------------------------------------------------------------------
$machinePath = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name Path).Path
$pathDirs = $machinePath -split ';' | Where-Object { $_ -ne '' }
$writablePathCount = 0

foreach ($dir in $pathDirs) {
    if (Test-Path -LiteralPath $dir) {
        $acl = Get-Acl -LiteralPath $dir
        foreach ($ace in $acl.Access) {
            if ($ace.AccessControlType -eq 'Allow' -and ($LowPrivIdentities -contains $ace.IdentityReference.Value)) {
                if (($ace.FileSystemRights -band $WriteRightsMask) -ne 0) {
                    $writablePathCount++
                    Write-Crit ("Machine %PATH% Directory Writable by [{0}]: {1} ({2})" -f $ace.IdentityReference, $dir, $ace.FileSystemRights)
                }
            }
        }
    }
}
if ($writablePathCount -eq 0) {
    Write-Pass "All directories in the Machine %PATH% have strict read-only permissions for standard users."
}

# ------------------------------------------------------------------------------
Write-AuditSection "6. MSI ALWAYSINSTALLELEVATED POLICY AUDIT"
# ------------------------------------------------------------------------------
$hklmMsi = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated).AlwaysInstallElevated
$hkcuMsi = (Get-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated).AlwaysInstallElevated

if ($hklmMsi -eq 1 -or $hkcuMsi -eq 1) {
    Write-Crit ("AlwaysInstallElevated is enabled! (HKLM={0}, HKCU={1}). Any user can run MSI packages as SYSTEM." -f $hklmMsi, $hkcuMsi)
} else {
    Write-Pass "AlwaysInstallElevated is disabled (HKLM and HKCU)."
}

# ------------------------------------------------------------------------------
Write-AuditSection "7. UAC, LSA PROTECTION (RunAsPPL), AND CREDENTIAL HYGIENE AUDIT"
# ------------------------------------------------------------------------------
$uacKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$enableLua = (Get-ItemProperty -Path $uacKey -Name EnableLUA).EnableLUA
$consentAdmin = (Get-ItemProperty -Path $uacKey -Name ConsentPromptBehaviorAdmin).ConsentPromptBehaviorAdmin
$secureDesktop = (Get-ItemProperty -Path $uacKey -Name PromptOnSecureDesktop).PromptOnSecureDesktop

if ($enableLua -ne 1) {
    Write-Crit "UAC (EnableLUA) is DISABLED!"
} elseif ($consentAdmin -eq 5) {
    Write-Warn "UAC ConsentPromptBehaviorAdmin = 5 (Default: silent auto-elevation enabled for Windows binaries). Recommend value 2 or 1."
} elseif ($consentAdmin -in @(1, 2) -and $secureDesktop -eq 1) {
    Write-Pass ("UAC hardened (EnableLUA=1, ConsentPromptBehaviorAdmin={0}, PromptOnSecureDesktop=1)." -f $consentAdmin)
}

# Check LSA Protection (RunAsPPL)
$lsaKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$runAsPpl = (Get-ItemProperty -Path $lsaKey -Name RunAsPPL).RunAsPPL
if ($runAsPpl -in @(1, 2)) {
    Write-Pass ("LSA Protection (RunAsPPL = {0}) is enabled, protecting lsass.exe as a Protected Process Light (PPL)." -f $runAsPpl)
} else {
    Write-Warn "LSA Protection (RunAsPPL) is not enabled under HKLM\SYSTEM\CurrentControlSet\Control\Lsa."
}

# Check WDigest cleartext credential caching
$wdigest = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name UseLogonCredential).UseLogonCredential
if ($wdigest -eq 1) {
    Write-Crit "WDigest UseLogonCredential = 1! Plaintext passwords are being cached in LSASS memory."
} else {
    Write-Pass "WDigest cleartext password caching is disabled."
}

# Check for leftover Unattend installation files
$unattendLocations = @(
    "$env:SystemRoot\Panther\Unattend.xml",
    "$env:SystemRoot\Panther\Unattend\Unattend.xml",
    "$env:SystemRoot\System32\Sysprep\unattend.xml",
    "$env:SystemRoot\System32\Sysprep\sysprep.inf"
)
foreach ($file in $unattendLocations) {
    if (Test-Path -LiteralPath $file) {
        Write-Warn "Unattended installation file present on disk (verify no credentials remain): $file"
    }
}
```

---

## 41.8 Windows Endpoint Hardening & Remediation Guide

### 41.8.1 Automated PowerShell Remediation for Unquoted Service Paths and Weak ACLs

When an audit reveals unquoted service paths or overly permissive directory ACLs, administrators can remediate them systematically using PowerShell:

```powershell
# ==============================================================================
# 1. Remediating Unquoted Service Paths Safely
# ==============================================================================
Get-CimInstance -ClassName Win32_Service | Where-Object {
    $_.PathName -ne $null -and $_.PathName.Trim() -notmatch '^"' -and $_.PathName -match '^(?<exe>[a-zA-Z]:\\.+?\.exe)\b'
} | ForEach-Object {
    $exePath = $Matches['exe']
    if ($exePath -match '\s') {
        $newPath = $PSItem.PathName -replace [regex]::Escape($exePath), "`"$exePath`""
        Write-Host "[*] Quoting service [$($PSItem.Name)]: $newPath" -ForegroundColor Green
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$($PSItem.Name)" -Name "ImagePath" -Value $newPath
    }
}

# ==============================================================================
# 2. Removing Non-Admin Write Access from Custom Application Directories
# ==============================================================================
# Example: Hardening C:\VendorApp so BUILTIN\Users only has ReadAndExecute
icacls.exe "C:\VendorApp" /inheritance:r /grant:r "NT AUTHORITY\SYSTEM:(OI)(CI)F" /grant:r "BUILTIN\Administrators:(OI)(CI)F" /grant:r "BUILTIN\Users:(OI)(CI)RX"
```

### 41.8.2 Hardening LSASS, Credential Caching, and UAC via Registry / GPO

Applying the following baseline controls aligns Windows endpoints with the **Microsoft Windows Security Baseline** and **CIS Microsoft Windows Benchmark**:

```powershell
# ==============================================================================
# WINDOWS CREDENTIAL & PRIVILEGE BOUNDARY HARDENING SCRIPT (Run Elevated)
# ==============================================================================

# 1. Enable LSA Protection (RunAsPPL) with UEFI Lock (1 = Enabled with UEFI variable, 2 = Enabled without UEFI lock)
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1 -PropertyType DWord -Force

# 2. Disable WDigest Cleartext Password Caching in LSASS
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Value 0 -PropertyType DWord -Force

# 3. Restrict Cached Domain Logons to 0 (on servers) or 2 (on mobile laptops)
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "CachedLogonsCount" -Value "0" -PropertyType String -Force

# 4. Enforce Strict UAC (Disable silent auto-elevation; prompt on Secure Desktop)
$uacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
New-ItemProperty -Path $uacPath -Name "EnableLUA" -Value 1 -PropertyType DWord -Force
New-ItemProperty -Path $uacPath -Name "ConsentPromptBehaviorAdmin" -Value 2 -PropertyType DWord -Force
New-ItemProperty -Path $uacPath -Name "ConsentPromptBehaviorUser" -Value 0 -PropertyType DWord -Force
New-ItemProperty -Path $uacPath -Name "PromptOnSecureDesktop" -Value 1 -PropertyType DWord -Force
New-ItemProperty -Path $uacPath -Name "FilterAdministratorToken" -Value 1 -PropertyType DWord -Force

# 5. Explicitly Disable MSI AlwaysInstallElevated
$msiPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"
if (-not (Test-Path $msiPolicyPath)) { New-Item -Path $msiPolicyPath -Force | Out-Null }
New-ItemProperty -Path $msiPolicyPath -Name "AlwaysInstallElevated" -Value 0 -PropertyType DWord -Force
```

### 41.8.3 Windows Event Log & Sysmon Telemetry for Local Privilege Escalation

Security Operations Centers (SOCs) should collect the following Windows Security Event IDs and Sysmon events to detect anomalous local privilege transitions:

| Event Source | Event ID | Telemetry Description & Detection Logic |
| :--- | :--- | :--- |
| **Security** | **4672** | *Special privileges assigned to new logon*. Triggered whenever a token is created with administrative/system privileges (`SeDebugPrivilege`, `SeImpersonatePrivilege`, `SeBackupPrivilege`, `SeTakeOwnershipPrivilege`, `SeLoadDriverPrivilege`). Filter out expected service accounts to detect unexpected privilege assignments. |
| **Security** | **4673** / **4674** | *A privileged service was called* / *An operation was attempted on a privileged object*. Logs usage of sensitive privileges such as `SeDebugPrivilege` or `SeTakeOwnershipPrivilege`. |
| **Security** | **4688** | *A new process has been created* (Enable *Include command line in process creation events* via GPO). Alert when a child process running as `NT AUTHORITY\SYSTEM` (`S-1-5-18`) is spawned by a non-SYSTEM parent process or web/database service account (`w3wp.exe`, `sqlservr.exe`). |
| **Security** | **4697** / **System 7045** | *A service was installed in the system*. Inspect Service Name, Service File Name (`ImagePath`), Service Type, and Service Account (`LocalSystem`). |
| **System** | **7040** | *The start type of a service was changed* or service configuration modified via SCM. |
| **Sysmon** | **Event ID 10** | *ProcessAccess*. Detects non-standard processes opening handles to `C:\Windows\System32\lsass.exe` or `winlogon.exe` with `GrantedAccess` masks such as `0x1010` (`PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION`) or `0x1F0FFF` (`PROCESS_ALL_ACCESS`). |
| **Sysmon** | **Event ID 6** | *DriverLoaded*. Detects any kernel driver (`.sys`) loaded into Ring 0; cross-reference SHA-256 hashes against the Microsoft Vulnerable Driver Blocklist. |
| **Sysmon** | **Event ID 17 & 18** | *PipeCreated* and *PipeConnected*. Monitors creation and client connections to Named Pipes (`\Device\NamedPipe\*`) to detect anomalous RPC/Named Pipe impersonation activity. |

---

## 41.9 Chapter 41 Review Questions & Lab Exercises

1. **Access Tokens & Impersonation**: Explain the difference between a Windows Primary Token and an Impersonation Token, and describe the four `SECURITY_IMPERSONATION_LEVEL` values. Why does holding `SeImpersonatePrivilege` allow a lower-privileged service account (`LOCAL SERVICE` or `IIS APPPOOL`) to spawn a process as `NT AUTHORITY\SYSTEM` if a `SYSTEM` thread connects to its Named Pipe?
2. **Service Control Manager (SCM) & `CreateProcessW` Parsing**: A vendor installs a service running as `LocalSystem` with the registry value `ImagePath = C:\Program Files\Enterprise Monitoring\Endpoint Agent\bin\MonitorSvc.exe -daemon`. List the exact sequence of file paths that `CreateProcessW` attempts to execute when starting this service, and explain what permission condition is required for a standard user to hijack execution.
3. **DLL Search Order Hygiene**: Contrast how the Windows loader resolves a DLL listed in `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` versus a DLL not listed in `KnownDLLs`. Why is having a world-writable or user-writable directory (such as `C:\Tools` or `C:\Python311`) inside the Machine `%PATH%` environment variable a critical privilege boundary risk?
4. **UAC Internals**: Explain how Admin Approval Mode (AAM) constructs the split token pair (`Medium` vs. `High` integrity) when a member of `BUILTIN\Administrators` logs in, why the `BUILTIN\Administrators` SID in the filtered token is marked `SE_GROUP_USE_FOR_DENY_ONLY`, and why setting `ConsentPromptBehaviorAdmin = 2` eliminates silent `<autoElevate>true</autoElevate>` abuses.
