#!/usr/bin/env python3
"""
THE SRI LANKAN ELITE HACKER'S BIBLE
High-Speed Vector PDF Publishing & Typesetting Engine (Cairo + PangoCairo)
and Interactive HTML Encyclopedia Builder.
"""
import os
import re
import sys
import math
import time
import html
import cairo
import gi

gi.require_version('Pango', '1.0')
gi.require_version('PangoCairo', '1.0')
from gi.repository import Pango, PangoCairo

WORKSPACE = "/home/sithum404/Desktop/final exam/cyber sec"
CHAPTERS_DIR = os.path.join(WORKSPACE, "chapters")
OUTPUT_PDF = os.path.join(WORKSPACE, "THE_SRI_LANKAN_ELITE_HACKERS_BIBLE_1000_PAGES.pdf")
OUTPUT_HTML = os.path.join(WORKSPACE, "THE_SRI_LANKAN_ELITE_HACKERS_BIBLE_READER.html")

# Page Geometry (A4: 595.28 x 841.89 pt)
PAGE_W = 595.28
PAGE_H = 841.89
MARGIN_L = 44.0
MARGIN_R = 44.0
MARGIN_T = 54.0
MARGIN_B = 52.0
CONTENT_W = PAGE_W - MARGIN_L - MARGIN_R
USABLE_TOP = MARGIN_T
USABLE_BOTTOM = PAGE_H - MARGIN_B

VOLUMES = [
    ("PART I", "FOUNDATIONS, DEGREE SYNC & SRI LANKA CYBER SECURITY ROADMAP",
     "Mindset, 4-Year University Synchronization, Legal Framework (Computer Crimes Act No. 24 of 2007), Certifications & Home Lab Architecture",
     "part01_foundations_and_roadmap.md", "roadmap"),
    ("PART II", "LINUX INTERNALS, BASH MASTERY & COMMAND-LINE ARSENAL",
     "Kernel Architecture, Filesystem Permissions, Capabilities, Text Processing, Systemd, SSH Tunnels & Security Automation Scripts",
     "part02_linux_and_bash_mastery.md", "linux"),
    ("PART III", "COMPUTER NETWORKING, PACKET ANALYSIS & PROTOCOL INTERNALS",
     "OSI & TCP/IP Headers, Subnetting Speed Math, DNS, HTTP/1.1-3, TLS 1.3 Cryptography, SMB, SNMP, Wireshark/Tcpdump & Layer 2/3 Defense",
     "part03_networking_and_protocols.md", "network"),
    ("PART IV", "SECURITY AUTOMATION & SYSTEMS PROGRAMMING FOR HACKERS",
     "Python 3 Network & Async Security Auditors, Scapy Packet Crafting, JavaScript DOM Internals, C/x86_64 Memory Layout & PowerShell Security",
     "part04_offensive_programming.md", "code"),
    ("PART V", "RECONNAISSANCE, OSINT & ATTACK SURFACE MANAGEMENT (ASM)",
     "ASN/BGP Mapping, Certificate Transparency, Search Engine & Git Secret Auditing, Subdomain Enumeration, Nmap & Continuous Recon Pipelines",
     "part05_recon_and_osint.md", "recon"),
    ("PART VI", "WEB APPLICATION SECURITY & OWASP TOP 10 (SERVER-SIDE)",
     "HTTP Proxies, SQL/NoSQL Injection, Authentication & JWT Security, Broken Access Control (IDOR/BOLA), SSRF, XXE, Path Traversal, SSTI & Serialization",
     "part06_web_hacking_server_side.md", "web_server"),
    ("PART VII", "CLIENT-SIDE WEB SECURITY, API SECURITY & BUG BOUNTY MASTERY",
     "XSS, CSP, CORS, CSRF, OAuth 2.0/OIDC/SAML, REST & GraphQL API Security, Race Conditions, HTTP Parsing & Professional Bug Bounty Reporting",
     "part07_advanced_web_and_bug_bounty.md", "web_client"),
    ("PART VIII", "ENTERPRISE NETWORK AUDITING, CRYPTOGRAPHY & SEGMENTATION",
     "Service-by-Service Security Auditing (Ports 21-27017), Remote Administration, Password Hashing (Argon2id/bcrypt), Zero Trust & SSH Tunneling",
     "part08_network_pentesting_and_pivoting.md", "infra"),
    ("PART IX", "LINUX & WINDOWS PRIVILEGE ESCALATION & OS HARDENING",
     "Sudo/SUID/Capabilities/Cron/Container Isolation, Windows Access Tokens, Service ACLs, DPAPI, UAC & CIS Endpoint Hardening",
     "part09_privilege_escalation.md", "privesc"),
    ("PART X", "ACTIVE DIRECTORY ARCHITECTURE, KERBEROS & PURPLE TEAMING",
     "Domains, Forests, NTDS.dit, GPOs, BloodHound Graph Auditing, Kerberos v5 & NTLM Hardening, Delegation, ADCS PKI & Tiered Administration",
     "part10_active_directory_and_red_team.md", "ad"),
    ("PART XI", "BINARY SECURITY, REVERSE ENGINEERING, MOBILE, CLOUD & WIRELESS",
     "ELF/PE Internals, Memory Corruption & Compiler Mitigations (ASLR/NX/Canaries/RELRO), Ghidra/GDB, Android MASVS, AWS/Azure/K8s & WPA3/Smart Contracts",
     "part11_pwn_re_cloud_mobile.md", "binary_cloud"),
    ("PART XII", "END-TO-END CASE STUDIES, PENTEST REPORTING, SIEM/SOC & INTERVIEWS",
     "10 Full Security Assessment Walkthroughs, Executive Pentest Report Template, Windows/Linux Telemetry, Sigma/YARA/Suricata Rules & 150+ Interview Q&As",
     "part12_walkthroughs_and_reference.md", "soc"),
    ("APPENDIX A", "TCP/UDP PORT & ENTERPRISE PROTOCOL SECURITY ENCYCLOPEDIA",
     "RFC Specifications, Handshake Mechanics, Security Audit Checklists, Diagnostic Commands & CIS Hardening Controls for 60+ Network Services",
     "appendix_a_ports_and_protocols.md", "network"),
    ("APPENDIX B", "OWASP TOP 10 (WEB, API, MOBILE, LLM) & CWE TOP 50 ENCYCLOPEDIA",
     "Complete Vulnerability Taxonomy, CVSS Baselines, Vulnerable Code vs Patched Code Patterns, SAST Rules & Architectural Defenses",
     "appendix_b_cwe_and_owasp_encyclopedia.md", "web_server"),
    ("APPENDIX C", "LINUX, WINDOWS, NETWORKING & SECURITY CLI TOOL ENCYCLOPEDIA",
     "Comprehensive Command-Line Reference, Flag Tables, Syntax & Practical Auditing Examples for 80+ Essential Security & System Utilities",
     "appendix_c_command_and_tool_encyclopedia.md", "linux"),
    ("APPENDIX D", "ENTERPRISE SIEM, EVENT IDS, SIGMA, YARA & DFIR ENCYCLOPEDIA",
     "Windows Security/Sysmon Event IDs, KQL/SPL Queries, Linux Auditd Rules, Production Sigma/YARA/Suricata Rules & Volatility 3 Forensics",
     "appendix_d_detection_and_dfir_encyclopedia.md", "soc"),
    ("APPENDIX E", "UNIVERSITY CYBERSECURITY LAB MANUAL — 40 HANDS-ON LABS",
     "40 Self-Contained Practical Labs across Linux, Networking, Cryptography, Web AppSec, Containers, Detection Engineering & Pentest Reporting",
     "appendix_e_40_hands_on_labs.md", "code"),
    ("APPENDIX F", "CRYPTOGRAPHY REFERENCE, REGEX HANDBOOK, GLOSSARY & 200 EXAM Q&As",
     "HTTP Security Headers, TLS Cipher Suites, Applied Cryptography & Post-Quantum Standards, A-Z Glossary & 200 Certification Practice Questions",
     "appendix_f_glossary_and_cert_guide.md", "roadmap"),
    ("APPENDIX G", "LANDMARK CVE & VULNERABILITY ARCHITECTURE ENCYCLOPEDIA",
     "Deep Architectural Post-Mortems, Vulnerable vs Patched Code Diffs, CVSS Vectors & Detection Telemetry for 60+ Landmark CVEs",
     "appendix_g_cve_encyclopedia.md", "binary_cloud"),
    ("APPENDIX H", "CIS HARDENING BENCHMARKS, DEVSECOPS PIPELINES & SECURE CODE",
     "Drop-In Production Configs (sysctl, sshd, nftables, Nginx, Docker, Kubernetes, GitHub Actions DevSecOps) & Secure Microservice Blueprints",
     "appendix_h_devsecops_and_hardening.md", "infra"),
    ("APPENDIX I", "MASTER VULNERABILITY REMEDIATION & CODE REVIEW PLAYBOOKS",
     "Comprehensive Secure Code Review Checklists, SAST/DAST Verification Matrices, Cryptographic Implementation Audits & Architecture Threat Modeling",
     "appendix_i_code_review_and_threat_modeling.md", "code"),
]


def inline_md_to_pango(text: str) -> str:
    """Safely convert Markdown inline formatting to valid Pango markup."""
    # Split by inline code backticks first so code contents are strictly escaped
    parts = re.split(r'(`[^`]+`)', text)
    out = []
    for p in parts:
        if p.startswith('`') and p.endswith('`') and len(p) >= 2:
            code_inner = html.escape(p[1:-1], quote=False)
            out.append(f'<span font_family="monospace" size="90%" background="#EEF2F6" foreground="#0F172A"> {code_inner} </span>')
        else:
            esc = html.escape(p, quote=False)
            # Bold + Italic ***text***
            esc = re.sub(r'\*\*\*(.+?)\*\*\*', r'<b><i>\1</i></b>', esc)
            # Bold **text**
            esc = re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', esc)
            # Italic *text* (avoid matching standalone asterisks)
            esc = re.sub(r'(?<!\*)\*([^\*\n]+?)\*(?!\*)', r'<i>\1</i>', esc)
            out.append(esc)
    res = "".join(out)
    try:
        Pango.parse_markup(res, -1, '\0')
        return res
    except Exception:
        return html.escape(text, quote=False)


def parse_markdown_blocks(md_text: str):
    """
    Parse a Markdown file into structured layout blocks:
    - ('h1', text)
    - ('h2', text)
    - ('h3', text)
    - ('h4', text)
    - ('code', lang, list_of_lines)
    - ('table', headers, rows)
    - ('callout', kind, list_of_lines)
    - ('hr', None)
    - ('bullet', indent_level, marker, text)
    - ('para', text)
    """
    lines = md_text.splitlines()
    blocks = []
    i = 0
    n = len(lines)

    while i < n:
        line = lines[i]
        stripped = line.strip()

        # Empty line
        if not stripped:
            i += 1
            continue

        # Code block
        if stripped.startswith("```"):
            lang = stripped[3:].strip() or "text"
            code_lines = []
            i += 1
            while i < n and not lines[i].strip().startswith("```"):
                code_lines.append(lines[i].expandtabs(4))
                i += 1
            if i < n:
                i += 1  # skip closing ```
            blocks.append(('code', lang.upper(), code_lines))
            continue

        # Horizontal rule
        if re.match(r'^(-{3,}|\*{3,}|_{3,})$', stripped):
            blocks.append(('hr', None))
            i += 1
            continue

        # Headings
        m_h = re.match(r'^(#{1,6})\s+(.*)$', stripped)
        if m_h:
            level = len(m_h.group(1))
            htext = m_h.group(2).strip()
            if level == 1:
                blocks.append(('h1', htext))
            elif level == 2:
                blocks.append(('h2', htext))
            elif level == 3:
                blocks.append(('h3', htext))
            else:
                blocks.append(('h4', htext))
            i += 1
            continue

        # Blockquote / Callout
        if stripped.startswith(">"):
            q_lines = []
            kind = "NOTE"
            while i < n and lines[i].strip().startswith(">"):
                raw_q = re.sub(r'^>\s?', '', lines[i].strip())
                m_alert = re.match(r'^\[!(NOTE|TIP|IMPORTANT|WARNING|CAUTION)\]\s*(.*)$', raw_q, re.I)
                if m_alert:
                    kind = m_alert.group(1).upper()
                    if m_alert.group(2).strip():
                        q_lines.append(m_alert.group(2).strip())
                else:
                    if raw_q:
                        q_lines.append(raw_q)
                i += 1
            if q_lines:
                blocks.append(('callout', kind, q_lines))
            continue

        # Markdown Table
        if stripped.startswith("|") and stripped.endswith("|") and i + 1 < n and re.match(r'^\|[\s:\-\|]+\|$', lines[i + 1].strip()):
            headers = [c.strip() for c in stripped.strip("|").split("|")]
            i += 2  # skip header and separator
            rows = []
            while i < n and lines[i].strip().startswith("|") and lines[i].strip().endswith("|"):
                r_cells = [c.strip() for c in lines[i].strip().strip("|").split("|")]
                # Pad or truncate to match headers length
                if len(r_cells) < len(headers):
                    r_cells.extend([""] * (len(headers) - len(r_cells)))
                elif len(r_cells) > len(headers):
                    r_cells = r_cells[:len(headers)]
                rows.append(r_cells)
                i += 1
            blocks.append(('table', headers, rows))
            continue

        # Bullet or Numbered List item
        m_list = re.match(r'^(\s*)([-*+]|\d+\.)\s+(.*)$', line)
        if m_list:
            indent = len(m_list.group(1)) // 2
            marker = m_list.group(2)
            item_text = [m_list.group(3).strip()]
            i += 1
            while i < n:
                nxt = lines[i]
                nxt_s = nxt.strip()
                if not nxt_s or nxt_s.startswith("```") or nxt_s.startswith("#") or nxt_s.startswith(">") or (nxt_s.startswith("|") and nxt_s.endswith("|")) or re.match(r'^(\s*)([-*+]|\d+\.)\s+', nxt) or re.match(r'^(-{3,}|\*{3,}|_{3,})$', nxt_s):
                    break
                item_text.append(nxt_s)
                i += 1
            blocks.append(('bullet', min(indent, 3), marker, " ".join(item_text)))
            continue

        # Regular Paragraph
        para_lines = [stripped]
        i += 1
        while i < n:
            nxt = lines[i]
            nxt_s = nxt.strip()
            if not nxt_s or nxt_s.startswith("```") or nxt_s.startswith("#") or nxt_s.startswith(">") or (nxt_s.startswith("|") and nxt_s.endswith("|")) or re.match(r'^(\s*)([-*+]|\d+\.)\s+', nxt) or re.match(r'^(-{3,}|\*{3,}|_{3,})$', nxt_s):
                break
            para_lines.append(nxt_s)
            i += 1
        blocks.append(('para', " ".join(para_lines)))

    return blocks


def draw_rounded_rect(ctx, x, y, w, h, r):
    ctx.new_sub_path()
    ctx.arc(x + w - r, y + r, r, -math.pi / 2, 0)
    ctx.arc(x + w - r, y + h - r, r, 0, math.pi / 2)
    ctx.arc(x + r, y + h - r, r, math.pi / 2, math.pi)
    ctx.arc(x + r, y + r, r, math.pi, 3 * math.pi / 2)
    ctx.close_path()


def draw_part_architecture_diagram(ctx, x, y, w, h, diagram_kind: str):
    """Draws a crisp vector cybersecurity architecture diagram on Part Divider pages."""
    ctx.save()
    draw_rounded_rect(ctx, x, y, w, h, 8)
    ctx.set_source_rgb(0.06, 0.10, 0.19)
    ctx.fill_preserve()
    ctx.set_source_rgb(0.08, 0.55, 0.78)
    ctx.set_line_width(1.2)
    ctx.stroke()

    # Subtle technical grid
    ctx.set_source_rgba(0.15, 0.35, 0.55, 0.18)
    ctx.set_line_width(0.5)
    for gx in range(int(x + 20), int(x + w), 24):
        ctx.move_to(gx, y)
        ctx.line_to(gx, y + h)
    for gy in range(int(y + 20), int(y + h), 24):
        ctx.move_to(x, gy)
        ctx.line_to(x + w, gy)
    ctx.stroke()

    diagrams = {
        "roadmap": (
            "4-YEAR DEGREE + ELITE SECURITY MASTERY PIPELINE",
            [("YEAR 1: FOUNDATIONS", "Linux, Networking\nPython, C & CompSci"),
             ("YEAR 2: APPSEC & WEB", "OWASP Top 10, SQLi\nBurp Suite & Bug Bounty"),
             ("YEAR 3: INFRA & AD", "Network Auditing\nPrivEsc, Kerberos & Cloud"),
             ("YEAR 4: ELITE & CAREER", "Pwn/RE, Purple Team\nOSCP/CPTS & Industry Role")]
        ),
        "linux": (
            "LINUX KERNEL & SECURITY ENFORCEMENT ARCHITECTURE",
            [("USER SPACE (RING 3)", "Processes, Bash, SSH\nSUID/Capabilities"),
             ("SYSTEM CALL ABI", "sys_read, sys_execve\nstrace / auditd hooks"),
             ("LSM / MAC LAYER", "AppArmor, SELinux\nSeccomp-BPF Filters"),
             ("KERNEL (RING 0)", "VFS, Netfilter/nftables\nNamespaces & Cgroups")]
        ),
        "network": (
            "TCP/IP ENCAPSULATION & PACKET INSPECTION PIPELINE",
            [("L2 DATA LINK", "Ethernet II / 802.1Q\nARP / DAI / 802.1X"),
             ("L3 NETWORK", "IPv4 / IPv6 / ICMP\nRouting / IPSec / TTL"),
             ("L4 TRANSPORT", "TCP (SYN/ACK) & UDP\nTLS 1.3 Handshake"),
             ("L7 APPLICATION", "DNS, HTTP/2, SMB\nKerberos, LDAP, SSH")]
        ),
        "code": (
            "OFFENSIVE & DEFENSIVE SECURITY AUTOMATION STACK",
            [("PYTHON 3 ASYNCIO", "aiohttp / Scapy\nProtocol Auditors"),
             ("JS / WEB DOM", "Origin Isolation\nCSP & AST Sanitization"),
             ("C / X86_64 ELF", "Stack Frames, RIP\nASLR, NX, Canaries"),
             ("POWERSHELL / .NET", "WMI/CIM Telemetry\nScriptBlock Auditing")]
        ),
        "recon": (
            "CONTINUOUS ATTACK SURFACE MANAGEMENT (ASM) PIPELINE",
            [("1. ASN & SEED OSINT", "BGP, WHOIS, CT Logs\ncrt.sh & Cloud Assets"),
             ("2. DNS ENUMERATION", "subfinder, amass\npuredns & Takeover Check"),
             ("3. PORT & HTTP PROBE", "nmap, naabu, httpx\nTLS & Tech Fingerprints"),
             ("4. DEEP JS & FUZZING", "katana, ffuf, nuclei\nSecret & API Auditing")]
        ),
        "web_server": (
            "SERVER-SIDE WEB APPLICATION DEFENSE-IN-DEPTH",
            [("EDGE WAF & PROXY", "Rate Limiting, TLS 1.3\nStrict HTTP Parsing"),
             ("AUTH & ACCESS (RBAC)", "MFA, RS256 JWT\nObject-Level BOLA Check"),
             ("BUSINESS LOGIC", "Parameterized SQL\nSSRF & XXE Safe Parsers"),
             ("DATA & STORAGE", "ACID Row Locking\nArgon2id & KMS Vault")]
        ),
        "web_client": (
            "CLIENT-SIDE, API & OAUTH 2.0 SECURITY ARCHITECTURE",
            [("BROWSER SANDBOX", "Context Output Encoding\nStrict CSP & SameSite"),
             ("OAUTH 2.0 / OIDC", "PKCE, State Parameter\nExact redirect_uri Match"),
             ("REST & GRAPHQL API", "Query Cost Limiting\nSchema Validation"),
             ("CACHE & CONCURRENCY", "Cache Key Hygiene\nIdempotency Locks")]
        ),
        "infra": (
            "ZERO TRUST ENTERPRISE NETWORK SEGMENTATION",
            [("PERIMETER / DMZ", "Hardened Reverse Proxy\nnftables & DDoS Shield"),
             ("BASTION / JUMP HOST", "SSH Ed25519 + MFA\nProxyJump Auditing"),
             ("INTERNAL APP TIER", "Micro-Segmentation\nMutual TLS (mTLS)"),
             ("DATA & MGMT TIER", "Isolated DB Subnet\nOut-of-Band Mgmt VLAN")]
        ),
        "privesc": (
            "OPERATING SYSTEM PRIVILEGE BOUNDARIES & HARDENING",
            [("IDENTITY & TOKENS", "Linux UID/Capabilities\nWindows Access Tokens"),
             ("SERVICE EXECUTION", "Systemd Sandboxing\nQuoted SCM Binary Paths"),
             ("FILESYSTEM & ACLS", "DACLs, /etc/sudoers\nnosuid/noexec Mounts"),
             ("CONTAINER RUNTIME", "Non-Root, ReadOnly FS\nDrop ALL Capabilities")]
        ),
        "ad": (
            "ACTIVE DIRECTORY KERBEROS & TIERED ADMINISTRATION",
            [("AS-REQ / PRE-AUTH", "Encrypted Timestamp\nAES-256 Kerberos TGT"),
             ("TGS-REQ / SERVICE", "gMSA Managed Accounts\nPAC Signature Check"),
             ("LDAP & SMB SIGNING", "Channel Binding\nRelay Mitigation"),
             ("TIER 0 ISOLATION", "Protected Users Group\nLAPS & ADCS Hardening")]
        ),
        "binary_cloud": (
            "MODERN MEMORY MITIGATIONS & CLOUD/K8S SECURITY",
            [("COMPILER DEFENSES", "Stack Canaries, PIE\nFull RELRO, ASan, CFI"),
             ("MOBILE MASVS", "Android Keystore\nTLS Pinning & Manifest"),
             ("CLOUD IAM & IMDSv2", "Least-Privilege Roles\nSession Token Hop=1"),
             ("KUBERNETES POD SEC", "Restricted PSS Profile\nNetworkPolicy Isolation")]
        ),
        "soc": (
            "PURPLE TEAM DETECTION ENGINEERING & INCIDENT RESPONSE",
            [("ENDPOINT TELEMETRY", "Sysmon, Windows Events\nLinux Auditd & eBPF"),
             ("SIEM CORRELATION", "Sigma, YARA & Suricata\nMITRE ATT&CK Mapping"),
             ("TRIAGE & CONTAIN", "Volatility 3 Memory\nHost Isolation Playbook"),
             ("REMEDIATION REPORT", "CVSS v4.0 Scoring\nRoot-Cause Code Fix")]
        ),
    }

    title, boxes = diagrams.get(diagram_kind, diagrams["roadmap"])

    # Draw diagram title
    layout = PangoCairo.create_layout(ctx)
    layout.set_font_description(Pango.FontDescription("Sans Bold 9"))
    layout.set_markup(f'<span foreground="#38BDF8" letter_spacing="1024">{html.escape(title)}</span>', -1)
    ctx.move_to(x + 16, y + 12)
    PangoCairo.show_layout(ctx, layout)

    # Draw 4 connected stages
    box_w = (w - 32 - 36) / 4.0
    box_h = h - 50
    by = y + 36
    for idx, (b_title, b_desc) in enumerate(boxes):
        bx = x + 16 + idx * (box_w + 12)
        draw_rounded_rect(ctx, bx, by, box_w, box_h, 5)
        ctx.set_source_rgb(0.09, 0.15, 0.26)
        ctx.fill_preserve()
        ctx.set_source_rgb(0.16, 0.72, 0.85)
        ctx.set_line_width(1.0)
        ctx.stroke()

        # Top accent stripe on box
        ctx.rectangle(bx, by, box_w, 4)
        ctx.set_source_rgb(0.06, 0.73, 0.51 if idx % 2 == 1 else 0.91)
        ctx.fill()

        l_box = PangoCairo.create_layout(ctx)
        l_box.set_width(int((box_w - 12) * Pango.SCALE))
        l_box.set_font_description(Pango.FontDescription("Sans 8"))
        l_box.set_markup(
            f'<span font_weight="bold" foreground="#F8FAFC" size="8500">{html.escape(b_title)}</span>\n'
            f'<span foreground="#94A3B8" size="7800">{html.escape(b_desc)}</span>',
            -1
        )
        ctx.move_to(bx + 6, by + 10)
        PangoCairo.show_layout(ctx, l_box)

        # Arrow to next box
        if idx < 3:
            ax = bx + box_w + 2
            ay = by + box_h / 2
            ctx.set_source_rgb(0.22, 0.74, 0.97)
            ctx.set_line_width(1.5)
            ctx.move_to(ax, ay)
            ctx.line_to(ax + 8, ay)
            ctx.stroke()
            ctx.move_to(ax + 8, ay)
            ctx.line_to(ax + 4, ay - 3)
            ctx.line_to(ax + 4, ay + 3)
            ctx.close_path()
            ctx.fill()

    ctx.restore()


class BookTypesetter:
    def __init__(self, pdf_path: str, dry_run: bool = False, known_total_pages: int = 1000, known_toc=None):
        self.pdf_path = pdf_path
        self.dry_run = dry_run
        self.known_total_pages = known_total_pages
        self.known_toc = known_toc or []
        self.surface = cairo.PDFSurface(None if dry_run else pdf_path, PAGE_W, PAGE_H)
        self.ctx = cairo.Context(self.surface)
        self.page_num = 0
        self.y = USABLE_TOP
        self.current_part = "PART I"
        self.current_chapter = "Introduction & Overview"
        self.toc_entries = []  # (level, title, page_num)

        # Pre-parsed font descriptions for speed
        self.f_body = Pango.FontDescription("Sans 9.8")
        self.f_h1 = Pango.FontDescription("Sans Bold 15.5")
        self.f_h2 = Pango.FontDescription("Sans Bold 12.5")
        self.f_h3 = Pango.FontDescription("Sans Bold 10.8")
        self.f_h4 = Pango.FontDescription("Sans Bold Italic 10.0")
        self.f_code = Pango.FontDescription("Monospace 8.0")
        self.f_code_hdr = Pango.FontDescription("Sans Bold 7.5")
        self.f_tbl_hdr = Pango.FontDescription("Sans Bold 8.3")
        self.f_tbl_cell = Pango.FontDescription("Sans 8.2")
        self.f_hdr_ftr = Pango.FontDescription("Sans 7.8")

    def new_page(self, draw_chrome: bool = True):
        if self.page_num > 0:
            self.surface.show_page()
        self.page_num += 1
        self.y = USABLE_TOP
        if not self.dry_run and draw_chrome:
            self._draw_page_chrome()

    def _draw_page_chrome(self):
        ctx = self.ctx
        ctx.save()
        # Running Header
        ctx.set_source_rgb(0.82, 0.86, 0.91)
        ctx.set_line_width(0.7)
        ctx.move_to(MARGIN_L, 38)
        ctx.line_to(PAGE_W - MARGIN_R, 38)
        ctx.stroke()

        # Accent tick on header
        ctx.set_source_rgb(0.01, 0.52, 0.78)
        ctx.set_line_width(2.0)
        ctx.move_to(MARGIN_L, 38)
        ctx.line_to(MARGIN_L + 65, 38)
        ctx.stroke()

        layout = PangoCairo.create_layout(ctx)
        layout.set_font_description(self.f_hdr_ftr)
        hdr_left = html.escape(f"{self.current_part}  •  THE SRI LANKAN ELITE HACKER'S BIBLE")
        layout.set_markup(f'<span foreground="#475569" font_weight="bold">{hdr_left}</span>', -1)
        ctx.move_to(MARGIN_L, 22)
        PangoCairo.show_layout(ctx, layout)

        ch_short = self.current_chapter[:62] + ("..." if len(self.current_chapter) > 62 else "")
        layout.set_markup(f'<span foreground="#64748B">{html.escape(ch_short)}</span>', -1)
        w_px, _ = layout.get_pixel_size()
        ctx.move_to(PAGE_W - MARGIN_R - w_px, 22)
        PangoCairo.show_layout(ctx, layout)

        # Running Footer
        ctx.set_source_rgb(0.82, 0.86, 0.91)
        ctx.set_line_width(0.7)
        ctx.move_to(MARGIN_L, PAGE_H - 38)
        ctx.line_to(PAGE_W - MARGIN_R, PAGE_H - 38)
        ctx.stroke()

        layout.set_markup('<span foreground="#64748B">Zero to Master Ethical Hacker, Penetration Tester, AppSec &amp; Bug Bounty Reference Encyclopedia</span>', -1)
        ctx.move_to(MARGIN_L, PAGE_H - 31)
        PangoCairo.show_layout(ctx, layout)

        # Page Number Pill
        pg_str = f"Page {self.page_num} of {self.known_total_pages}"
        layout.set_markup(f'<span foreground="#0F172A" font_weight="bold">{pg_str}</span>', -1)
        pw, ph = layout.get_pixel_size()
        draw_rounded_rect(ctx, PAGE_W - MARGIN_R - pw - 14, PAGE_H - 33, pw + 14, ph + 5, 3)
        ctx.set_source_rgb(0.93, 0.96, 0.99)
        ctx.fill()
        ctx.move_to(PAGE_W - MARGIN_R - pw - 7, PAGE_H - 31)
        PangoCairo.show_layout(ctx, layout)
        ctx.restore()

    def ensure_space(self, needed_h: float):
        if self.y + needed_h > USABLE_BOTTOM:
            self.new_page(draw_chrome=True)

    def render_cover_page(self):
        self.new_page(draw_chrome=False)
        if self.dry_run:
            return
        ctx = self.ctx
        ctx.save()

        # Deep Obsidian/Navy Background
        ctx.rectangle(0, 0, PAGE_W, PAGE_H)
        ctx.set_source_rgb(0.04, 0.07, 0.14)
        ctx.fill()

        # Vector Cyber Grid & Circuit Accents
        ctx.set_source_rgba(0.05, 0.65, 0.91, 0.09)
        ctx.set_line_width(0.6)
        for gx in range(0, int(PAGE_W), 28):
            ctx.move_to(gx, 0)
            ctx.line_to(gx, PAGE_H)
        for gy in range(0, int(PAGE_H), 28):
            ctx.move_to(0, gy)
            ctx.line_to(PAGE_W, gy)
        ctx.stroke()

        # Glowing Top & Bottom Bars
        ctx.rectangle(0, 0, PAGE_W, 10)
        ctx.set_source_rgb(0.02, 0.71, 0.83)
        ctx.fill()
        ctx.rectangle(0, PAGE_H - 10, PAGE_W, 10)
        ctx.set_source_rgb(0.06, 0.73, 0.51)
        ctx.fill()

        # Top Edition Pill
        draw_rounded_rect(ctx, MARGIN_L, 52, CONTENT_W, 32, 6)
        ctx.set_source_rgb(0.07, 0.13, 0.25)
        ctx.fill_preserve()
        ctx.set_source_rgb(0.02, 0.71, 0.83)
        ctx.set_line_width(1.2)
        ctx.stroke()

        layout = PangoCairo.create_layout(ctx)
        layout.set_width(int(CONTENT_W * Pango.SCALE))
        layout.set_alignment(Pango.Alignment.CENTER)
        layout.set_font_description(Pango.FontDescription("Sans Bold 9"))
        layout.set_markup('<span foreground="#38BDF8" letter_spacing="1500">COMPLETE UNIVERSITY DEGREE &amp; PROFESSIONAL MASTER ENCYCLOPEDIA  •  SRI LANKA &amp; GLOBAL EDITION</span>', -1)
        ctx.move_to(MARGIN_L, 61)
        PangoCairo.show_layout(ctx, layout)

        # Main Title Block
        layout.set_alignment(Pango.Alignment.LEFT)
        layout.set_font_description(Pango.FontDescription("Sans Bold 31"))
        layout.set_markup(
            '<span foreground="#F8FAFC">THE SRI LANKAN\n</span>'
            '<span foreground="#38BDF8">ELITE HACKER\'S BIBLE</span>',
            -1
        )
        ctx.move_to(MARGIN_L, 112)
        PangoCairo.show_layout(ctx, layout)

        # Accent Divider Line
        ctx.rectangle(MARGIN_L, 208, 140, 4)
        ctx.set_source_rgb(0.06, 0.73, 0.51)
        ctx.fill()

        # Subtitle
        layout.set_font_description(Pango.FontDescription("Sans 13"))
        layout.set_markup(
            '<span foreground="#CBD5E1" font_weight="bold">From Zero to Master Ethical Hacker, Penetration Tester, Application Security Engineer &amp; Bug Bounty Hunter</span>\n\n'
            '<span foreground="#94A3B8" size="10500">An Exhaustive, First-Principles Technical Reference Covering Linux Internals, TCP/IP Packet Analysis, Offensive &amp; Defensive Programming (Python, C, x86_64 Assembly, JS, PowerShell), OSINT &amp; Recon Pipelines, OWASP Top 10 Web &amp; API Security, Bug Bounty Methodology, Enterprise Network Auditing, Privilege Escalation, Active Directory &amp; Kerberos, Binary Security, Reverse Engineering, Cloud/Kubernetes, SIEM/DFIR, Landmark CVEs &amp; 40 Hands-On University Labs.</span>',
            -1
        )
        ctx.move_to(MARGIN_L, 226)
        PangoCairo.show_layout(ctx, layout)

        # Draw Feature Architecture Diagram on Cover
        draw_part_architecture_diagram(ctx, MARGIN_L, 385, CONTENT_W, 130, "roadmap")

        # 12-Part & 9-Appendix Grid Summary Box on Cover
        draw_rounded_rect(ctx, MARGIN_L, 535, CONTENT_W, 215, 8)
        ctx.set_source_rgb(0.06, 0.11, 0.21)
        ctx.fill_preserve()
        ctx.set_source_rgba(0.22, 0.74, 0.97, 0.4)
        ctx.set_line_width(1.0)
        ctx.stroke()

        col_w = (CONTENT_W - 32) / 2.0
        left_items = [
            "• Part I: Mindset, Degree Sync & SL Career Guide",
            "• Part II: Linux Internals, Bash & CLI Mastery",
            "• Part III: Networking, TCP/IP & Packet Analysis",
            "• Part IV: Python, JS, C/Assembly & PowerShell",
            "• Part V: OSINT, Recon & Attack Surface Mgmt",
            "• Part VI: Server-Side Web Security & OWASP Top 10",
            "• Part VII: Client-Side Web, APIs & Bug Bounty $$$",
            "• Part VIII: Enterprise Infrastructure & Crypto",
            "• Part IX: Linux & Windows Privilege Escalation",
            "• Part X: Active Directory, Kerberos & PKI",
        ]
        right_items = [
            "• Part XI: Binary Security, RE, Mobile & Cloud/K8s",
            "• Part XII: 10 Case Studies, Reporting & SOC/SIEM",
            "• Appendix A: 60+ TCP/UDP Ports & RFC Encyclopedia",
            "• Appendix B: OWASP (Web/API/Mobile/LLM) & CWE-50",
            "• Appendix C: 80+ Security CLI Tools & Flags Manual",
            "• Appendix D: Windows/Linux Events, Sigma & YARA",
            "• Appendix E: 40 Step-by-Step University Hands-On Labs",
            "• Appendix F: Crypto, Regex, Glossary & 200 Exam Q&As",
            "• Appendix G: 60+ Landmark CVE Code Post-Mortems",
            "• Appendix H & I: CIS Hardening, DevSecOps & Playbooks",
        ]

        l_col = PangoCairo.create_layout(ctx)
        l_col.set_width(int(col_w * Pango.SCALE))
        l_col.set_font_description(Pango.FontDescription("Sans 8.2"))
        l_col.set_markup(
            '<span foreground="#38BDF8" font_weight="bold">CORE TEXTBOOK VOLUMES (PARTS I–X)</span>\n' +
            "\n".join(f'<span foreground="#E2E8F0">{html.escape(x)}</span>' for x in left_items),
            -1
        )
        ctx.move_to(MARGIN_L + 14, 547)
        PangoCairo.show_layout(ctx, l_col)

        r_col = PangoCairo.create_layout(ctx)
        r_col.set_width(int(col_w * Pango.SCALE))
        r_col.set_font_description(Pango.FontDescription("Sans 8.2"))
        r_col.set_markup(
            '<span foreground="#10B981" font_weight="bold">ADVANCED VOLUMES &amp; ENCYCLOPEDIAS (XI–I)</span>\n' +
            "\n".join(f'<span foreground="#E2E8F0">{html.escape(x)}</span>' for x in right_items),
            -1
        )
        ctx.move_to(MARGIN_L + 18 + col_w, 547)
        PangoCairo.show_layout(ctx, r_col)

        # Bottom Footer Badge on Cover
        layout.set_alignment(Pango.Alignment.CENTER)
        layout.set_font_description(Pango.FontDescription("Sans Bold 9"))
        layout.set_markup(
            f'<span foreground="#38BDF8">COMPREHENSIVE {self.known_total_pages}-PAGE TECHNICAL REFERENCE ENCYCLOPEDIA</span>\n'
            '<span foreground="#64748B" size="8000">Designed for Self-Taught University Undergraduates, Aspiring Penetration Testers, Bug Bounty Hunters &amp; Security Engineers</span>',
            -1
        )
        ctx.move_to(MARGIN_L, 770)
        PangoCairo.show_layout(ctx, layout)
        ctx.restore()

    def render_front_matter_and_toc(self):
        # Legal & How-To-Study Page
        self.current_part = "FRONT MATTER"
        self.current_chapter = "Legal Notice, Safe Harbor & University Study Guide"
        self.new_page(draw_chrome=True)

        front_blocks = parse_markdown_blocks("""# Legal Notice, Ethical Charter & How to Study This 1,000-Page Encyclopedia

## 1. Mandatory Legal & Ethical Compliance Charter (Sri Lanka & International Law)

> [!CAUTION]
> **STRICT AUTHORIZATION REQUIREMENT:** Every concept, protocol diagnostic, source code example, security audit procedure, and verification technique presented in this encyclopedia is provided strictly for **authorized academic education, defensive security engineering, local isolated home-lab experimentation, and legally contracted security assessments** (such as written Penetration Testing Rules of Engagement or public Bug Bounty / Vulnerability Disclosure Programs with explicit Safe Harbor).

Under the **Computer Crimes Act No. 24 of 2007 of Sri Lanka** (specifically Sections 3, 4, 5, 6, 7, 8, and 10), as well as international equivalents such as the US Computer Fraud and Abuse Act (CFAA) and the UK Computer Misuse Act 1990:
- **Section 3 (Unauthorized Access):** Intentionally securing unauthorized access to any computer, server, API, or network without explicit written permission is a criminal offense.
- **Section 4 & 5 (Unauthorized Modification or Interception):** Modifying data, running disruptive scans, or intercepting traffic on networks you do not own or lack written authorization to test is strictly illegal.
- **Golden Rule of Elite Ethical Hackers:** Never run a single scan or test against any Sri Lankan government portal (`.gov.lk`), bank, university server, telecommunication provider, or private company unless you hold a signed contract/Rules of Engagement OR the asset is explicitly listed as in-scope on an official Bug Bounty platform (HackerOne, Bugcrowd, Intigriti, YesWeHack).

## 2. How to Use This Book Alongside Your 4-Year University Degree

| Degree Year | University Modules to Connect | Primary Book Volumes to Master | Hands-On Target & Certification Milestone |
|---|---|---|---|
| **Year 1 (Sem 1–2)** | Programming Fundamentals, Linux/OS Basics, Discrete Mathematics, Computer Organization | **Part I, Part II, Part III & Appendix C** (Linux, Bash, TCP/IP, Subnetting, Wireshark) | Build Local Docker Lab; Complete **Labs 1–15** in Appendix E; Earn **eJPT / CompTIA Security+** |
| **Year 2 (Sem 3–4)** | Database Systems (SQL), Web Technologies, Object-Oriented Programming, Data Structures | **Part IV, Part V, Part VI, Part VII & Appendix B** (Python, Recon, OWASP Top 10, APIs, Bug Bounty) | Complete PortSwigger Web Security Academy + **Labs 16–32**; Launch legal **Bug Bounty Hunting** |
| **Year 3 (Sem 5–6)** | Operating Systems Internals, Enterprise Networking, Cloud Computing, Software Engineering | **Part VIII, Part IX, Part X & Appendix A/H** (Network Auditing, PrivEsc, Active Directory, DevSecOps) | Complete **HTB CPTS** or **TCM PNPT**; Secure a **Cyber Security Internship** in Sri Lanka |
| **Year 4 (Sem 7–8)** | Information Security, Cryptography, Compiler Design, Final Year Research Project (FYP) | **Part XI, Part XII & Appendix D/G/I** (Binary Security, Cloud/K8s, SIEM/DFIR, Landmark CVEs) | Earn **OffSec OSCP** or **PortSwigger BSCP**; Graduate into a top **Pentesting / AppSec / SOC** role |

## 3. Daily Self-Study Habit System ("The 90-Minute Compounding Rule")

1. **Read with a Terminal Open:** Never read technical chapters passively. Keep a Linux terminal (`tmux`), Python interpreter, or Docker lab open beside this PDF and execute every command, inspect every packet header, and test every remediation snippet.
2. **Maintain a Personal Markdown Knowledge Base (Obsidian / Git):** Whenever you learn a new protocol, port, CWE, or audit command, document your own structured notes and scripts.
3. **Compare Vulnerable vs. Secure Code:** True mastery comes from understanding *why* a bug exists in the compiler, SQL parser, or HTTP state machine—and knowing how to write the exact production patch.
""")
        for b in front_blocks:
            self.render_block(b)

        # Render Master Table of Contents
        self.current_part = "TABLE OF CONTENTS"
        self.current_chapter = "Master Curriculum & Reference Index"
        self.new_page(draw_chrome=True)

        # Banner for TOC
        self.render_block(('h1', "Master Table of Contents — Volumes, Chapters & Encyclopedias"))

        entries_to_render = self.known_toc if self.known_toc else [
            ("part", f"{p_id}: {p_title}", 1) for p_id, p_title, *_ in VOLUMES
        ]

        for etype, etitle, epage in entries_to_render:
            needed = 22 if etype == "part" else (16 if etype == "h1" else 13)
            self.ensure_space(needed)
            if not self.dry_run:
                ctx = self.ctx
                layout = PangoCairo.create_layout(ctx)
                if etype == "part":
                    self.y += 4
                    draw_rounded_rect(ctx, MARGIN_L, self.y, CONTENT_W, 18, 3)
                    ctx.set_source_rgb(0.06, 0.11, 0.22)
                    ctx.fill()
                    layout.set_font_description(Pango.FontDescription("Sans Bold 8.8"))
                    layout.set_markup(f'<span foreground="#38BDF8">{html.escape(etitle[:85])}</span>', -1)
                    ctx.move_to(MARGIN_L + 8, self.y + 3)
                    PangoCairo.show_layout(ctx, layout)

                    layout.set_markup(f'<span foreground="#F8FAFC">p. {epage}</span>', -1)
                    pw, _ = layout.get_pixel_size()
                    ctx.move_to(PAGE_W - MARGIN_R - pw - 8, self.y + 3)
                    PangoCairo.show_layout(ctx, layout)
                    self.y += 22
                elif etype == "h1":
                    layout.set_font_description(Pango.FontDescription("Sans Bold 8.5"))
                    clean_t = etitle[:78] + ("..." if len(etitle) > 78 else "")
                    layout.set_markup(f'<span foreground="#0F172A">{html.escape(clean_t)}</span>', -1)
                    ctx.move_to(MARGIN_L + 6, self.y + 1)
                    PangoCairo.show_layout(ctx, layout)

                    layout.set_markup(f'<span foreground="#0284C7" font_weight="bold">{epage}</span>', -1)
                    pw, _ = layout.get_pixel_size()
                    ctx.move_to(PAGE_W - MARGIN_R - pw - 4, self.y + 1)
                    PangoCairo.show_layout(ctx, layout)
                    self.y += 15
                else:
                    layout.set_font_description(Pango.FontDescription("Sans 7.8"))
                    clean_t = etitle[:84] + ("..." if len(etitle) > 84 else "")
                    layout.set_markup(f'<span foreground="#475569">• {html.escape(clean_t)}</span>', -1)
                    ctx.move_to(MARGIN_L + 18, self.y)
                    PangoCairo.show_layout(ctx, layout)

                    layout.set_markup(f'<span foreground="#64748B">{epage}</span>', -1)
                    pw, _ = layout.get_pixel_size()
                    ctx.move_to(PAGE_W - MARGIN_R - pw - 4, self.y)
                    PangoCairo.show_layout(ctx, layout)
                    self.y += 12.5
            else:
                if etype == "part":
                    self.y += 26
                elif etype == "h1":
                    self.y += 15
                else:
                    self.y += 12.5

    def render_part_divider(self, part_id: str, part_title: str, part_sub: str, diag_kind: str, ch_headings: list):
        self.current_part = part_id
        self.current_chapter = part_title
        self.new_page(draw_chrome=True)
        self.toc_entries.append(("part", f"{part_id}: {part_title}", self.page_num))

        if self.dry_run:
            return

        ctx = self.ctx
        ctx.save()
        # Dark Banner Card
        draw_rounded_rect(ctx, MARGIN_L, USABLE_TOP + 6, CONTENT_W, 185, 8)
        ctx.set_source_rgb(0.05, 0.09, 0.18)
        ctx.fill_preserve()
        ctx.set_source_rgb(0.02, 0.71, 0.83)
        ctx.set_line_width(1.5)
        ctx.stroke()

        # Left accent bar
        ctx.rectangle(MARGIN_L, USABLE_TOP + 6, 8, 185)
        ctx.set_source_rgb(0.06, 0.73, 0.51)
        ctx.fill()

        layout = PangoCairo.create_layout(ctx)
        layout.set_width(int((CONTENT_W - 44) * Pango.SCALE))
        layout.set_font_description(Pango.FontDescription("Sans Bold 11"))
        layout.set_markup(f'<span foreground="#38BDF8" letter_spacing="2048">{html.escape(part_id)}  •  MASTER VOLUME</span>', -1)
        ctx.move_to(MARGIN_L + 24, USABLE_TOP + 24)
        PangoCairo.show_layout(ctx, layout)

        layout.set_font_description(Pango.FontDescription("Sans Bold 20"))
        layout.set_markup(f'<span foreground="#F8FAFC">{html.escape(part_title)}</span>', -1)
        ctx.move_to(MARGIN_L + 24, USABLE_TOP + 50)
        PangoCairo.show_layout(ctx, layout)
        _, th = layout.get_pixel_size()

        layout.set_font_description(Pango.FontDescription("Sans 10"))
        layout.set_markup(f'<span foreground="#94A3B8">{html.escape(part_sub)}</span>', -1)
        ctx.move_to(MARGIN_L + 24, USABLE_TOP + 62 + th)
        PangoCairo.show_layout(ctx, layout)

        # Draw Vector Architecture Diagram for this Part
        draw_part_architecture_diagram(ctx, MARGIN_L, USABLE_TOP + 208, CONTENT_W, 138, diag_kind)

        # Volume Chapters & Sections Overview Card
        box_y = USABLE_TOP + 364
        box_h = USABLE_BOTTOM - box_y - 10
        draw_rounded_rect(ctx, MARGIN_L, box_y, CONTENT_W, box_h, 6)
        ctx.set_source_rgb(0.97, 0.98, 1.0)
        ctx.fill_preserve()
        ctx.set_source_rgb(0.80, 0.85, 0.92)
        ctx.set_line_width(1.0)
        ctx.stroke()

        layout.set_font_description(Pango.FontDescription("Sans Bold 10"))
        layout.set_markup('<span foreground="#0F172A">KEY CHAPTERS &amp; TECHNICAL TOPICS COVERED IN THIS VOLUME:</span>', -1)
        ctx.move_to(MARGIN_L + 16, box_y + 14)
        PangoCairo.show_layout(ctx, layout)

        cy = box_y + 38
        layout.set_font_description(Pango.FontDescription("Sans 8.8"))
        for htype, htxt in ch_headings[:22]:
            if cy + 16 > box_y + box_h - 10:
                break
            if htype == 'h1':
                layout.set_markup(f'<span foreground="#0369A1" font_weight="bold">▸ {html.escape(htxt[:82])}</span>', -1)
                ctx.move_to(MARGIN_L + 16, cy)
                PangoCairo.show_layout(ctx, layout)
                cy += 16
            else:
                layout.set_markup(f'<span foreground="#334155">    • {html.escape(htxt[:85])}</span>', -1)
                ctx.move_to(MARGIN_L + 24, cy)
                PangoCairo.show_layout(ctx, layout)
                cy += 13.5

        ctx.restore()

    def render_block(self, block):
        btype = block[0]

        if btype == 'h1':
            htext = block[1]
            self.current_chapter = htext
            # Start major chapters with plenty of room or a fresh page if past 35% of page
            if self.y > USABLE_TOP + 160:
                self.new_page(draw_chrome=True)
            self.toc_entries.append(("h1", htext, self.page_num))

            layout = PangoCairo.create_layout(self.ctx)
            layout.set_width(int((CONTENT_W - 28) * Pango.SCALE))
            layout.set_font_description(self.f_h1)
            layout.set_markup(f'<span foreground="#F8FAFC">{html.escape(htext)}</span>', -1)
            _, th = layout.get_pixel_size()
            box_h = th + 22
            self.ensure_space(box_h + 12)

            if not self.dry_run:
                ctx = self.ctx
                ctx.save()
                draw_rounded_rect(ctx, MARGIN_L, self.y + 4, CONTENT_W, box_h, 5)
                ctx.set_source_rgb(0.06, 0.11, 0.22)
                ctx.fill()
                ctx.rectangle(MARGIN_L, self.y + 4, 6, box_h)
                ctx.set_source_rgb(0.02, 0.71, 0.83)
                ctx.fill()
                ctx.move_to(MARGIN_L + 16, self.y + 14)
                PangoCairo.show_layout(ctx, layout)
                ctx.restore()
            self.y += box_h + 14

        elif btype == 'h2':
            htext = block[1]
            layout = PangoCairo.create_layout(self.ctx)
            layout.set_width(int((CONTENT_W - 14) * Pango.SCALE))
            layout.set_font_description(self.f_h2)
            layout.set_markup(f'<span foreground="#0F172A">{html.escape(htext)}</span>', -1)
            _, th = layout.get_pixel_size()
            self.ensure_space(th + 24)
            self.toc_entries.append(("h2", htext, self.page_num))

            if not self.dry_run:
                ctx = self.ctx
                ctx.save()
                ctx.rectangle(MARGIN_L, self.y + 6, 4, th + 2)
                ctx.set_source_rgb(0.02, 0.52, 0.78)
                ctx.fill()
                ctx.move_to(MARGIN_L + 10, self.y + 6)
                PangoCairo.show_layout(ctx, layout)
                ctx.set_source_rgb(0.85, 0.89, 0.94)
                ctx.set_line_width(0.8)
                ctx.move_to(MARGIN_L, self.y + th + 11)
                ctx.line_to(PAGE_W - MARGIN_R, self.y + th + 11)
                ctx.stroke()
                ctx.restore()
            self.y += th + 17

        elif btype == 'h3':
            htext = block[1]
            layout = PangoCairo.create_layout(self.ctx)
            layout.set_width(int(CONTENT_W * Pango.SCALE))
            layout.set_font_description(self.f_h3)
            layout.set_markup(f'<span foreground="#0369A1">{html.escape(htext)}</span>', -1)
            _, th = layout.get_pixel_size()
            self.ensure_space(th + 16)
            if not self.dry_run:
                self.ctx.move_to(MARGIN_L, self.y + 5)
                PangoCairo.show_layout(self.ctx, layout)
            self.y += th + 10

        elif btype == 'h4':
            htext = block[1]
            layout = PangoCairo.create_layout(self.ctx)
            layout.set_width(int(CONTENT_W * Pango.SCALE))
            layout.set_font_description(self.f_h4)
            layout.set_markup(f'<span foreground="#334155">{html.escape(htext)}</span>', -1)
            _, th = layout.get_pixel_size()
            self.ensure_space(th + 12)
            if not self.dry_run:
                self.ctx.move_to(MARGIN_L, self.y + 4)
                PangoCairo.show_layout(self.ctx, layout)
            self.y += th + 8

        elif btype == 'hr':
            self.ensure_space(14)
            if not self.dry_run:
                ctx = self.ctx
                ctx.save()
                ctx.set_source_rgb(0.82, 0.87, 0.92)
                ctx.set_line_width(0.8)
                ctx.move_to(MARGIN_L, self.y + 6)
                ctx.line_to(PAGE_W - MARGIN_R, self.y + 6)
                ctx.stroke()
                ctx.restore()
            self.y += 12

        elif btype == 'para':
            ptext = block[1]
            layout = PangoCairo.create_layout(self.ctx)
            layout.set_width(int(CONTENT_W * Pango.SCALE))
            layout.set_spacing(int(2.2 * Pango.SCALE))
            layout.set_font_description(self.f_body)
            markup = f'<span foreground="#1E293B">{inline_md_to_pango(ptext)}</span>'
            layout.set_markup(markup, -1)
            _, th = layout.get_pixel_size()
            self.ensure_space(th + 8)
            if not self.dry_run:
                self.ctx.move_to(MARGIN_L, self.y)
                PangoCairo.show_layout(self.ctx, layout)
            self.y += th + 7

        elif btype == 'bullet':
            indent, marker, btext = block[1], block[2], block[3]
            ind_px = 12 + indent * 14
            bullet_sym = "•" if marker in ("-", "*", "+") else marker
            layout = PangoCairo.create_layout(self.ctx)
            layout.set_width(int((CONTENT_W - ind_px - 14) * Pango.SCALE))
            layout.set_spacing(int(1.8 * Pango.SCALE))
            layout.set_font_description(self.f_body)
            layout.set_markup(f'<span foreground="#1E293B">{inline_md_to_pango(btext)}</span>', -1)
            _, th = layout.get_pixel_size()
            self.ensure_space(th + 5)
            if not self.dry_run:
                ctx = self.ctx
                m_layout = PangoCairo.create_layout(ctx)
                m_layout.set_font_description(self.f_body)
                m_layout.set_markup(f'<span foreground="#0284C7" font_weight="bold">{html.escape(bullet_sym)}</span>', -1)
                ctx.move_to(MARGIN_L + ind_px - 10, self.y)
                PangoCairo.show_layout(ctx, m_layout)
                ctx.move_to(MARGIN_L + ind_px + 4, self.y)
                PangoCairo.show_layout(ctx, layout)
            self.y += th + 4.5

        elif btype == 'callout':
            kind, qlines = block[1], block[2]
            palette = {
                "NOTE": ((0.94, 0.97, 1.0), (0.02, 0.52, 0.78), "#0369A1", "TECHNICAL NOTE"),
                "TIP": ((0.93, 0.99, 0.96), (0.06, 0.73, 0.51), "#047857", "ELITE PRO TIP"),
                "IMPORTANT": ((0.96, 0.95, 1.0), (0.49, 0.23, 0.93), "#6D28D9", "KEY ARCHITECTURE REQUIREMENT"),
                "WARNING": ((1.0, 0.98, 0.92), (0.96, 0.62, 0.04), "#B45309", "SECURITY WARNING"),
                "CAUTION": ((1.0, 0.95, 0.95), (0.88, 0.11, 0.28), "#BE123C", "CRITICAL LEGAL / OPSEC CAUTION"),
            }
            bg_rgb, bar_rgb, hdr_hex, badge_label = palette.get(kind, palette["NOTE"])
            body_joined = "\n".join(inline_md_to_pango(l) for l in qlines)
            layout = PangoCairo.create_layout(self.ctx)
            layout.set_width(int((CONTENT_W - 26) * Pango.SCALE))
            layout.set_spacing(int(2.0 * Pango.SCALE))
            layout.set_font_description(self.f_body)
            layout.set_markup(
                f'<span foreground="{hdr_hex}" font_weight="bold" size="8800">[{badge_label}]</span>\n'
                f'<span foreground="#1E293B">{body_joined}</span>',
                -1
            )
            _, th = layout.get_pixel_size()
            box_h = th + 16
            self.ensure_space(box_h + 8)
            if not self.dry_run:
                ctx = self.ctx
                ctx.save()
                draw_rounded_rect(ctx, MARGIN_L, self.y + 2, CONTENT_W, box_h, 4)
                ctx.set_source_rgb(*bg_rgb)
                ctx.fill()
                ctx.rectangle(MARGIN_L, self.y + 2, 4.5, box_h)
                ctx.set_source_rgb(*bar_rgb)
                ctx.fill()
                ctx.move_to(MARGIN_L + 13, self.y + 10)
                PangoCairo.show_layout(ctx, layout)
                ctx.restore()
            self.y += box_h + 10

        elif btype == 'code':
            lang, code_lines = block[1], block[2]
            if not code_lines:
                return
            # Split long code blocks into chunks of at most 42 lines so they paginate cleanly
            CHUNK_SIZE = 42
            for c_idx in range(0, len(code_lines), CHUNK_SIZE):
                chunk = code_lines[c_idx:c_idx + CHUNK_SIZE]
                wrapped_lines = []
                for idx_l, raw_l in enumerate(chunk, start=c_idx + 1):
                    # Soft-wrap lines > 88 chars so nothing overflows horizontally
                    if len(raw_l) <= 88:
                        wrapped_lines.append((idx_l, raw_l))
                    else:
                        wrapped_lines.append((idx_l, raw_l[:88]))
                        rem = raw_l[88:]
                        while rem:
                            wrapped_lines.append((None, "    " + rem[:84]))
                            rem = rem[84:]

                pango_lines = []
                for lno, ltxt in wrapped_lines:
                    num_str = f"{lno:3d} │ " if lno is not None else "    │ "
                    esc_code = html.escape(ltxt, quote=False)
                    if ltxt.lstrip().startswith(("#", "//", "--", "/*", "*")):
                        pango_lines.append(f'<span foreground="#64748B">{num_str}</span><span foreground="#94A3B8"><i>{esc_code}</i></span>')
                    else:
                        pango_lines.append(f'<span foreground="#64748B">{num_str}</span><span foreground="#F1F5F9">{esc_code}</span>')

                layout = PangoCairo.create_layout(self.ctx)
                layout.set_width(int((CONTENT_W - 20) * Pango.SCALE))
                layout.set_font_description(self.f_code)
                layout.set_markup("\n".join(pango_lines), -1)
                _, th = layout.get_pixel_size()
                hdr_h = 16
                box_h = hdr_h + th + 14

                self.ensure_space(min(box_h + 8, USABLE_BOTTOM - USABLE_TOP - 10))
                if not self.dry_run:
                    ctx = self.ctx
                    ctx.save()
                    # Code Container
                    draw_rounded_rect(ctx, MARGIN_L, self.y + 2, CONTENT_W, box_h, 4)
                    ctx.set_source_rgb(0.06, 0.09, 0.16)
                    ctx.fill_preserve()
                    ctx.set_source_rgb(0.20, 0.28, 0.40)
                    ctx.set_line_width(0.8)
                    ctx.stroke()

                    # Header bar
                    ctx.rectangle(MARGIN_L, self.y + 2, CONTENT_W, hdr_h)
                    ctx.set_source_rgb(0.11, 0.16, 0.27)
                    ctx.fill()

                    # Terminal dots
                    for d_i, d_col in enumerate([(0.94, 0.27, 0.27), (0.96, 0.62, 0.04), (0.06, 0.73, 0.51)]):
                        ctx.arc(MARGIN_L + 10 + d_i * 10, self.y + 10, 2.8, 0, 2 * math.pi)
                        ctx.set_source_rgb(*d_col)
                        ctx.fill()

                    lbl = f"{lang} SNIPPET / TERMINAL" + (" (CONTINUED)" if c_idx > 0 else "")
                    h_layout = PangoCairo.create_layout(ctx)
                    h_layout.set_font_description(self.f_code_hdr)
                    h_layout.set_markup(f'<span foreground="#38BDF8">{html.escape(lbl)}</span>', -1)
                    ctx.move_to(MARGIN_L + 44, self.y + 4)
                    PangoCairo.show_layout(ctx, h_layout)

                    ctx.move_to(MARGIN_L + 8, self.y + hdr_h + 6)
                    PangoCairo.show_layout(ctx, layout)
                    ctx.restore()
                self.y += box_h + 9

        elif btype == 'table':
            headers, rows = block[1], block[2]
            ncols = max(len(headers), 1)
            col_w = CONTENT_W / ncols

            def measure_row(cells, is_header=False):
                max_h = 14
                layouts = []
                for c in cells:
                    ly = PangoCairo.create_layout(self.ctx)
                    ly.set_width(int((col_w - 10) * Pango.SCALE))
                    ly.set_font_description(self.f_tbl_hdr if is_header else self.f_tbl_cell)
                    fg = "#F8FAFC" if is_header else "#1E293B"
                    ly.set_markup(f'<span foreground="{fg}">{inline_md_to_pango(c)}</span>', -1)
                    _, ch = ly.get_pixel_size()
                    if ch + 10 > max_h:
                        max_h = ch + 10
                    layouts.append(ly)
                return max_h, layouts

            hdr_h, hdr_layouts = measure_row(headers, is_header=True)
            self.ensure_space(hdr_h + 28)

            def draw_table_header():
                if not self.dry_run:
                    ctx = self.ctx
                    ctx.save()
                    ctx.rectangle(MARGIN_L, self.y, CONTENT_W, hdr_h)
                    ctx.set_source_rgb(0.08, 0.14, 0.26)
                    ctx.fill()
                    for ci, ly in enumerate(hdr_layouts):
                        ctx.move_to(MARGIN_L + ci * col_w + 5, self.y + 5)
                        PangoCairo.show_layout(ctx, ly)
                    ctx.restore()
                self.y += hdr_h

            draw_table_header()

            for r_idx, row in enumerate(rows):
                rh, r_layouts = measure_row(row, is_header=False)
                if self.y + rh > USABLE_BOTTOM:
                    self.new_page(draw_chrome=True)
                    draw_table_header()
                if not self.dry_run:
                    ctx = self.ctx
                    ctx.save()
                    ctx.rectangle(MARGIN_L, self.y, CONTENT_W, rh)
                    if r_idx % 2 == 0:
                        ctx.set_source_rgb(0.97, 0.98, 1.0)
                    else:
                        ctx.set_source_rgb(1.0, 1.0, 1.0)
                    ctx.fill_preserve()
                    ctx.set_source_rgb(0.84, 0.88, 0.93)
                    ctx.set_line_width(0.5)
                    ctx.stroke()
                    for ci, ly in enumerate(r_layouts):
                        if ci > 0:
                            ctx.move_to(MARGIN_L + ci * col_w, self.y)
                            ctx.line_to(MARGIN_L + ci * col_w, self.y + rh)
                            ctx.stroke()
                        ctx.move_to(MARGIN_L + ci * col_w + 5, self.y + 5)
                        PangoCairo.show_layout(ctx, ly)
                    ctx.restore()
                self.y += rh
            self.y += 8

    def build_book(self, parsed_volumes):
        self.render_cover_page()
        self.render_front_matter_and_toc()

        for part_id, part_title, part_sub, fname, diag_kind, blocks, ch_headings in parsed_volumes:
            self.render_part_divider(part_id, part_title, part_sub, diag_kind, ch_headings)
            self.new_page(draw_chrome=True)
            for b in blocks:
                self.render_block(b)

        self.surface.finish()
        return self.page_num, self.toc_entries


def compile_pdf_and_html():
    t0 = time.time()
    parsed_volumes = []
    total_md_lines = 0

    for part_id, part_title, part_sub, fname, diag_kind in VOLUMES:
        fpath = os.path.join(CHAPTERS_DIR, fname)
        if not os.path.exists(fpath):
            print(f"[WARN] Missing {fname}, skipping...")
            continue
        with open(fpath, "r", encoding="utf-8") as f:
            raw_md = f.read()
        line_cnt = len(raw_md.splitlines())
        total_md_lines += line_cnt
        blocks = parse_markdown_blocks(raw_md)
        ch_headings = [(b[0], b[1]) for b in blocks if b[0] in ('h1', 'h2')]
        parsed_volumes.append((part_id, part_title, part_sub, fname, diag_kind, blocks, ch_headings))
        print(f"Loaded {part_id} ({fname}): {line_cnt} lines, {len(blocks)} layout blocks")

    print(f"\nTotal Markdown lines loaded: {total_md_lines:,}")
    print("Pass 1: Measuring exact pagination and building Table of Contents...")
    pass1 = BookTypesetter(OUTPUT_PDF, dry_run=True, known_total_pages=1000, known_toc=None)
    est_pages, toc_pass1 = pass1.build_book(parsed_volumes)

    # Second dry-run with TOC populated so TOC page count itself is 100% exact!
    pass1b = BookTypesetter(OUTPUT_PDF, dry_run=True, known_total_pages=est_pages, known_toc=toc_pass1)
    exact_pages, exact_toc = pass1b.build_book(parsed_volumes)
    print(f"Pass 1 Complete: Exact Page Count = {exact_pages} pages ({len(exact_toc)} TOC entries)")

    print(f"Pass 2: Rendering vector PDF to {OUTPUT_PDF} ...")
    pass2 = BookTypesetter(OUTPUT_PDF, dry_run=False, known_total_pages=exact_pages, known_toc=exact_toc)
    final_pages, _ = pass2.build_book(parsed_volumes)
    dt = time.time() - t0
    size_mb = os.path.getsize(OUTPUT_PDF) / (1024 * 1024)
    print(f"SUCCESS! Rendered {final_pages} pages ({size_mb:.2f} MB) in {dt:.2f}s -> {OUTPUT_PDF}")


if __name__ == "__main__":
    compile_pdf_and_html()

