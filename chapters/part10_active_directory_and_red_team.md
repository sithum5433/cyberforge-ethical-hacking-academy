# PART X: ENTERPRISE ACTIVE DIRECTORY ARCHITECTURE, IDENTITY PROTOCOLS & DEFENSIVE POSTURE MANAGEMENT

---

# Chapter 42: Active Directory Architecture & Identity Security Auditing

## 42.1 Introduction to Enterprise Directory Services

Since its introduction in Windows 2000 Server, **Microsoft Active Directory Domain Services (AD DS)** has served as the foundational identity, authentication, authorization, and policy management plane for the vast majority of Fortune 500 enterprises, government agencies, and financial institutions worldwide. In hybrid architectures, on-premises AD DS commonly synchronizes identities with **Microsoft Entra ID** (formerly Azure AD) via Entra Connect or Cloud Sync, making the security posture of Active Directory critical to both on-premises and cloud infrastructure.

From an architectural perspective, Active Directory combines five core network standards into a unified directory service:
1. **LDAP (Lightweight Directory Access Protocol — RFC 4511, TCP/UDP 389 & LDAPS TCP 636)**: The wire protocol used to query and modify objects in the directory database.
2. **Kerberos v5 (RFC 4120, TCP/UDP 88)**: The cryptographic ticket-based authentication protocol used to verify user and computer identities across the domain.
3. **DNS (Domain Name System — TCP/UDP 53)**: The naming and service location backbone (via SRV records such as `_ldap._tcp.dc._msdcs.<Domain>`) that enables clients to locate Domain Controllers and Global Catalog servers.
4. **SMB / CIFS (Server Message Block — TCP 445) & MSRPC (TCP 135 + Dynamic Ports)**: The transport mechanisms used to distribute Group Policy files (`SYSVOL`), replicate directory changes (`DRS` / `MS-DRSR`), and manage domain hosts.
5. **X.500 Directory Information Tree (DIT) & Extensible Storage Engine (ESE)**: The hierarchical data model and transactional database (`ntds.dit`) stored on every Domain Controller.

```
+-----------------------------------------------------------------------------+
|                ACTIVE DIRECTORY LOGICAL & PHYSICAL HIERARCHY                |
+-----------------------------------------------------------------------------+
|                                                                             |
|  FOREST (Outer Security Boundary — Shared Schema & Configuration NCs)       |
|  +-----------------------------------------------------------------------+  |
|  |                                                                       |  |
|  |   TREE 1: corp.example.lk                TREE 2: subsidiary.lk        |  |
|  |   +---------------------------+          +-------------------------+  |  |
|  |   | Root Domain:              | <======> | Root Domain:            |  |  |
|  |   | corp.example.lk           | Two-Way  | subsidiary.lk           |  |  |
|  |   +-------------+-------------+ Transitive                         |  |  |
|  |                 |               Trust                              |  |  |
|  |                 v                                                  |  |  |
|  |   +---------------------------+                                    |  |  |
|  |   | Child Domain:             |                                    |  |  |
|  |   | fin.corp.example.lk       |                                    |  |  |
|  |   | - OU=Tier0_Admins         |                                    |  |  |
|  |   | - OU=Servers              |                                    |  |  |
|  |   | - OU=Workstations         |                                    |  |  |
|  |   +---------------------------+                                    |  |  |
|  +-----------------------------------------------------------------------+  |
+-----------------------------------------------------------------------------+
```

---

## 42.2 Core Logical and Physical Components of Active Directory

### 42.2.1 Forests, Trees, Domains, and Trust Boundaries

A frequent misconception in enterprise architecture is treating the **Domain** as the ultimate security boundary in Active Directory. Microsoft's official architectural documentation explicitly defines the **Forest**—not the individual Domain—as the true security boundary:

1. **Domain**: A logical administrative partition that shares a single Domain Naming Context (`DC=corp,DC=example,DC=lk`), a single password and account lockout policy (unless Fine-Grained Password Policies / PSOs are deployed), and a single `krbtgt` key distribution center account.
2. **Domain Tree**: A hierarchical collection of one or more domains that share a contiguous DNS namespace (for example, `corp.example.lk` and `fin.corp.example.lk`) connected by automatic two-way transitive parent-child Kerberos trusts.
3. **Forest**: A collection of one or more Domain Trees that share a **single Schema Naming Context** (`CN=Schema,CN=Configuration,DC=...`), a **single Configuration Naming Context** (`CN=Configuration,DC=...`), and a **Global Catalog**.
   - Why is the **Forest** (and not the Domain) the security boundary? Because every Domain Controller inside a forest replicates the shared `Configuration` and `Schema` partitions, and built-in forest-wide administrative groups (`Enterprise Admins`, RID `519`; `Schema Admins`, RID `518`) have implicit administrative rights across every domain in the forest. A compromise of a single Domain Controller in a child domain allows altering replicated forest-wide metadata or constructing cross-domain trust tickets unless strict forest isolation controls are enforced.

### 42.2.2 Domain Controllers, Naming Contexts, and `NTDS.dit`

A **Domain Controller (DC)** is a Windows Server instance running the Active Directory Domain Services (`NTDS`) role. Every writable Domain Controller holds a physical database file located by default at:

```text
C:\Windows\NTDS\ntds.dit
```

Managed by the **Extensible Storage Engine (`esent.dll` / Jet Blue)**, `ntds.dit` is divided into three primary internal tables:
- **`datatable`**: Stores the actual rows representing every directory object (users, computers, groups, OUs, GPO containers) and their attributes, including password hashes (`unicodePwd` / `dBCSPwd`, encrypted with the two-layer `PEK` Password Encryption Key, which is in turn encrypted with the DC's `SYSKEY` BootKey stored in `HKLM\SYSTEM`).
- **`link_table`**: Stores linked multi-valued attributes such as group memberships (`member` / `memberOf`) and manager relationships.
- **`sd_table` (Single-Instance Security Descriptor Table)**: Stores the binary Security Descriptors (`nTSecurityDescriptor`, containing Owner, Group, DACL, and SACL) for every object in the directory.

Logically, the directory database is partitioned into **Naming Contexts (Directory Partitions)**:

| Naming Context (Partition) | Distinguished Name (DN) Pattern | Replication Scope | Contents |
| :--- | :--- | :--- | :--- |
| **Schema Partition** | `CN=Schema,CN=Configuration,DC=<ForestRoot>` | Forest-wide (All DCs in Forest) | Definitions of every `classSchema` (object class) and `attributeSchema` (attribute type) permitted in the forest. |
| **Configuration Partition** | `CN=Configuration,DC=<ForestRoot>` | Forest-wide (All DCs in Forest) | Forest topology, Sites, Subnets, Replication links, Services (`CN=Public Key Services` for ADCS PKI), and Display Specifiers. |
| **Domain Partition** | `DC=corp,DC=example,DC=lk` | Domain-wide (All DCs in that Domain + Partial subset to Global Catalogs) | Users, Computers, Groups, Organizational Units (OUs), and Group Policy Containers within that domain. |
| **Application Partitions** | `DC=DomainDnsZones,...` and `DC=ForestDnsZones,...` | Configurable (Domain or Forest DNS Servers) | Active Directory-Integrated DNS zone records (`dnsNode` objects). |

### 42.2.3 The Five FSMO (Flexible Single Master Operations) Roles

While Active Directory uses **multi-master replication** for routine object updates (any writable DC can create a user or reset a password), five critical operations require a **single authoritative master** to prevent split-brain conflicts:

| FSMO Role | Scope | Count | Architectural Responsibility |
| :--- | :--- | :--- | :--- |
| **Schema Master** | Forest | 1 per Forest | The only DC permitted to write modifications to the `CN=Schema` partition (e.g., `adprep /forestprep` during Exchange or OS upgrades). |
| **Domain Naming Master** | Forest | 1 per Forest | Controls adding or removing domains and application directory partitions within the forest (`CN=Partitions,CN=Configuration`). |
| **PDC Emulator (Primary Domain Controller Emulator)** | Domain | 1 per Domain | 1) Authoritative NTP time source for the domain (critical for Kerberos 5-minute clock skew enforcement); 2) Processes urgent password changes and account lockouts immediately; 3) Default target DC for Group Policy (`gpmc.msc`) edits. |
| **RID Master (Relative ID Master)** | Domain | 1 per Domain | Allocates pools of 500 contiguous Relative IDs (RIDs) to each writable DC in the domain so that DCs never assign duplicate SIDs when creating new security principals. |
| **Infrastructure Master** | Domain | 1 per Domain | Updates cross-domain object references (phantom objects) when a principal from another domain is renamed or moved. |

### 42.2.4 `SYSVOL`, Organizational Units (OUs), and Group Policy Objects (GPOs)

**Group Policy Objects (GPOs)** allow centralized configuration of registry settings, security baselines, audit policies, software deployment, and startup/logon scripts across domain-joined computers.

Architecturally, a single GPO consists of **two halves** that must remain synchronized:
1. **Group Policy Container (GPC)**: An LDAP object stored inside `ntds.dit` at:
   ```text
   CN={<GPO-GUID>},CN=Policies,CN=System,DC=corp,DC=example,DC=lk
   ```
   Stores metadata including `displayName`, `versionNumber`, status flags, and `gPCFileSysPath`.
2. **Group Policy Template (GPT)**: A folder hierarchy stored on the filesystem of every Domain Controller inside the **`SYSVOL`** SMB share (`C:\Windows\SYSVOL\sysvol\<domain>\Policies\{<GPO-GUID>}\`), replicated across DCs via **DFS-R (Distributed File System Replication)**:
   ```text
   \\corp.example.lk\SYSVOL\corp.example.lk\Policies\{<GPO-GUID>}\
   ├── GPT.INI
   ├── Machine\
   │   ├── Registry.pol              (Administrative Templates registry settings)
   │   ├── Microsoft\Windows NT\SecEdit\GptTmpl.inf  (Security Options, User Rights, Restricted Groups)
   │   ├── Scripts\Startup\
   │   └── Preferences\              (ScheduledTasks, Services, Groups, Registry XMLs)
   └── User\
       ├── Registry.pol
       ├── Scripts\Logon\
       └── Preferences\
   ```

GPOs are linked to **Sites**, **Domains**, or **Organizational Units (OUs)** via the `gPLink` attribute on the target container, and evaluated by client workstations in the classic **LSDOU** order:
1. **L**ocal Group Policy (`C:\Windows\System32\GroupPolicy`)
2. **S**ite-linked GPOs
3. **D**omain-linked GPOs
4. **O**rganizational **U**nit-linked GPOs (from parent OU down to child OU; the closest OU wins in case of conflicting settings unless a parent GPO link has the **Enforced** flag set, or a child OU has **Block Inheritance** enabled).

---

## 42.3 Active Directory Access Control Model: DACLs, ACEs, and Graph Theory

Every object inside `ntds.dit`—whether a User, Computer, Group, OU, GPO, Domain root, or Certificate Template—possesses an `nTSecurityDescriptor` attribute containing a **Discretionary Access Control List (DACL)** and a **System Access Control List (SACL)**.

### 42.3.1 Anatomy of an Active Directory Access Control Entry (ACE)

An Active Directory ACE (`ADS_ACCESS_CONTROL_ENTRY`) is significantly more expressive than a filesystem ACE because it supports object-specific and property-specific GUIDs:

```
+-----------------------------------------------------------------------------+
|                    ACTIVE DIRECTORY ACE STRUCTURE                           |
+-----------------------------------------------------------------------------+
| 1. AceType          : ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE,      |
|                       ACCESS_ALLOWED_OBJECT_ACE_TYPE (GUID-scoped)          |
| 2. AceFlags         : ContainerInherit (CI), InheritOnly (IO),              |
|                       NoPropagateInherit (NP), Inherited (ID)               |
| 3. AccessMask       : 32-bit bitmask of ActiveDirectoryRights               |
|                       (GenericAll, GenericWrite, WriteDacl, WriteOwner,     |
|                        WriteProperty, Self, ExtendedRight, CreateChild...)  |
| 4. ObjectType GUID  : Identifies the specific Attribute, Property Set, or   |
|                       Extended Right (`controlAccessRight`) this ACE        |
|                       applies to (`00000000-0000-0000-0000-000000000000`    |
|                       means ALL attributes/extended rights).                |
| 5. InheritedObjectType GUID : Restricts which child object classes          |
|                       (e.g., `user`, `group`, `computer`) inherit this ACE. |
| 6. Trustee (SID)    : The Security Identifier granted or denied the right.  |
+-----------------------------------------------------------------------------+
```

### 42.3.2 Security-Critical Active Directory Rights and Extended Rights GUIDs

When auditing Active Directory DACLs, security engineers look for non-Tier-0 principals (such as Helpdesk groups, server administrators, or standard users) that have been granted control rights over higher-privileged users, groups, computers, OUs, or GPOs:

| AD Right (`ActiveDirectoryRights`) | `ObjectType` GUID | Effective Security Meaning & Impact |
| :--- | :--- | :--- |
| **`GenericAll`** | All (`00000000-...`) | Full control over the target object: reset password, modify group memberships, edit attributes, modify DACL, or delete the object. |
| **`GenericWrite`** | All (`00000000-...`) | Grants write access to all non-protected properties on the object (including `servicePrincipalName`, `scriptPath`, and `msDS-KeyCredentialLink`). |
| **`WriteOwner`** | All (`00000000-...`) | Allows changing the Owner SID of the AD object. Because the Owner implicitly receives `WriteDacl`, `WriteOwner` is functionally equivalent to `GenericAll`. |
| **`WriteDacl`** | All (`00000000-...`) | Allows modifying the object's `nTSecurityDescriptor` DACL to grant `GenericAll` or any Extended Right. |
| **`ExtendedRight`** (`User-Force-Change-Password`) | `00299570-246d-11d0-a768-00aa006e0529` | Allows resetting a user or computer account's password (`Set-ADAccountPassword`) without knowing the current password. |
| **`WriteProperty`** / **`Self`** (`Member`) | `bf9679c0-0de6-11d0-a285-00aa003049e2` | Allows adding or removing principals in a Security Group's `member` attribute. |
| **`WriteProperty`** (`msDS-KeyCredentialLink`) | `5b47d60f-6090-40b2-9f37-2a4de88f3063` | Allows registering a Windows Hello for Business (WHfB) X.509 public key on a user or computer object, permitting PKINIT authentication as that object. |
| **`WriteProperty`** (`gPLink` / `gPOptions`) | `f30e3bbe-9ff0-11d1-b603-0000f80367c1` | On a Domain, Site, or OU, allows linking an arbitrary GPO to apply configurations to all users and computers inside that scope. |
| **`ExtendedRight`** (`DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All`) | `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` & `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` | On the Domain Root (`DC=corp,...`), authorizes the holder to invoke the MS-DRSR Directory Replication Service API (normally reserved exclusively for Domain Controllers) to replicate password hashes from `ntds.dit`. |

### 42.3.3 Graph-Based Attack Path Management (Defensive BloodHound Auditing)

In a large enterprise directory containing 50,000 users, 30,000 workstations, 5,000 servers, and 15,000 nested security groups accumulated over 20 years, evaluating risk using flat spreadsheets (`lists`) fails—**defenders think in lists, while complex access paths form directed graphs**.

Graph-based posture management tools (such as **BloodHound Enterprise / BloodHound CE** and **ADalanche**) model Active Directory as a directed mathematical graph $G = (V, E)$:
- **Vertices / Nodes ($V$)**: `User`, `Group`, `Computer`, `OU`, `GPO`, `Domain`, `Container`, `CertTemplate`, `EnterpriseCA`.
- **Directed Edges ($E$)**: Relationships where Node $A$ has control or authentication traverse capability over Node $B$:
  - *Group Membership Edges*: `(User)-[:MemberOf]->(Group)`
  - *ACL Control Edges*: `(Group)-[:GenericAll|GenericWrite|WriteDacl|WriteOwner|ForceChangePassword|AddMember]->(User|Group|Computer|GPO|OU)`
  - *GPO Containment Edges*: `(GPO)-[:GpLink]->(OU)-[:Contains]->(Computer)`
  - *Session & Local Admin Edges*: `(Computer)-[:HasSession]->(User)` and `(Group)-[:AdminTo]->(Computer)`

```
+-----------------------------------------------------------------------------+
|            GRAPH-BASED TRANSITIVE PRIVILEGE CHAIN EXAMPLE                   |
+-----------------------------------------------------------------------------+
|                                                                             |
|  (Standard User: Alice)                                                     |
|         |                                                                   |
|         | [:MemberOf]                                                       |
|         v                                                                   |
|  (Group: IT_Helpdesk_L1)                                                    |
|         |                                                                   |
|         | [:GenericWrite]  (Legacy ACL left over from 2018 migration)       |
|         v                                                                   |
|  (Group: Server_Backup_Operators)                                           |
|         |                                                                   |
|         | [:MemberOf]                                                       |
|         v                                                                   |
|  (Group: Tier0_PKI_Admins)                                                  |
|         |                                                                   |
|         | [:AdminTo]                                                        |
|         v                                                                   |
|  (Computer: SUBCA01.corp.example.lk)  ===> Full Enterprise PKI Control      |
+-----------------------------------------------------------------------------+
```

#### Essential Defensive Neo4j Cypher Queries for Active Directory Auditors

When security engineers load an Active Directory LDAP/ACL snapshot into a Neo4j graph database for defensive posture auditing, the following read-only **Cypher** queries immediately surface transitive privilege chains and Tier-0 boundary violations:

```cypher
// 1. Identify any non-Domain-Admin principal with DS-Replication-Get-Changes-All (Replication rights) on the Domain Root
MATCH p=(n)-[:GetChanges|GetChangesAll*1..]->(d:Domain)
WHERE NOT n.objectid ENDS WITH '-512' // Exclude Domain Admins
  AND NOT n.objectid ENDS WITH '-516' // Exclude Domain Controllers
  AND NOT n.objectid ENDS WITH '-519' // Exclude Enterprise Admins
  AND NOT n.objectid ENDS WITH '-498' // Exclude Enterprise Read-Only DCs
RETURN p;

// 2. Find shortest transitive ACL paths from "Domain Users" (-513) or "Authenticated Users" to "Domain Admins" (-512)
MATCH (start:Group), (end:Group)
WHERE (start.objectid ENDS WITH '-513' OR start.objectid ENDS WITH '-S-1-5-11')
  AND end.objectid ENDS WITH '-512'
MATCH p=shortestPath((start)-[r:MemberOf|GenericAll|GenericWrite|WriteDacl|WriteOwner|ForceChangePassword|AddMember|AllExtendedRights|GpLink|Contains*1..]->(end))
RETURN p;

// 3. Audit all GPOs linked to the Domain Controllers OU where non-Tier-0 users have Write/Edit permissions
MATCH (ou:OU {name: 'DOMAIN CONTROLLERS@CORP.EXAMPLE.LK'})
MATCH p=(n)-[:GenericAll|GenericWrite|WriteDacl|WriteOwner]->(gpo:GPO)-[:GpLink]->(ou)
RETURN p;

// 4. Identify Tier-0 Admins whose accounts have active interactive sessions on lower-tier workstations (Tier Violation)
MATCH (c:Computer)-[:HasSession]->(u:User)-[:MemberOf*1..]->(g:Group)
WHERE g.objectid ENDS WITH '-512'
  AND NOT (c)-[:MemberOf*1..]->(:Group {objectid: replace(g.objectid, '-512', '-516')})
RETURN c.name AS NonTier0Host, u.name AS ExposedDomainAdmin;
```

---

## 42.4 Active Directory `AdminSDHolder` and `SDProp` Architecture

To protect built-in privileged groups and their members from accidental (or malicious) DACL modifications by delegated OU administrators, Active Directory implements an automated background protection mechanism composed of two parts:
1. **The `AdminSDHolder` Container Object**:
   Located at `CN=AdminSDHolder,CN=System,DC=corp,DC=example,DC=lk`. This single object holds a master template `nTSecurityDescriptor` (DACL).
2. **The `SDProp` (Security Descriptor Propagator) Background Thread**:
   Runs every **60 minutes** on the domain's **PDC Emulator** FSMO role holder (configurable via `HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\AdminSDProtectFrequency`).

### 42.4.1 How `SDProp` Enforces Security on Protected Accounts

Every 60 minutes, `SDProp` enumerates all users and groups that are direct or transitive members of Active Directory's **Protected Groups**, which include:
- `Enterprise Admins` (`-519`), `Schema Admins` (`-518`), `Domain Admins` (`-512`), `Administrators` (`S-1-5-32-544`)
- `Account Operators` (`S-1-5-32-548`), `Server Operators` (`S-1-5-32-549`), `Print Operators` (`S-1-5-32-550`), `Backup Operators` (`S-1-5-32-551`)
- `Domain Controllers` (`-516`), `Read-Only Domain Controllers` (`-498`), `Cert Publishers` (`-517`), `Key Admins` (`-526`), `Enterprise Key Admins` (`-527`), and `krbtgt`.

For every object in this protected set, `SDProp`:
1. Sets the object's **`adminCount`** attribute to `1`.
2. **Disables DACL Inheritance** (`SE_DACL_PROTECTED`) on the object so that permissions granted on the parent OU no longer flow down to the privileged user or group.
3. **Overwrites the object's entire DACL** with an exact copy of the DACL on `CN=AdminSDHolder,CN=System,DC=...`.

### 42.4.2 Two Critical Auditing Pitfalls of `AdminSDHolder` / `SDProp`

1. **"Orphaned" `adminCount=1` Accounts**:
   When a user is later *removed* from `Domain Admins`, Active Directory **does not** reset `adminCount` to `0` and **does not** re-enable DACL inheritance! The user remains permanently with `adminCount=1` and broken OU inheritance (meaning Helpdesk cannot reset their password) until an administrator manually clears `adminCount` and re-enables DACL inheritance.
2. **Unauthorized ACEs Added to `CN=AdminSDHolder`**:
   Conversely, if an attacker or misconfigured installation script (such as legacy Exchange split-permissions setups) adds an ACE granting a lower-privileged principal `GenericAll` or `WriteDacl` directly on the `CN=AdminSDHolder` object itself, `SDProp` will faithfully propagate that ACE onto **every Domain Admin and Protected Group in the entire domain every 60 minutes**. Therefore, `CN=AdminSDHolder`'s DACL must be continuously monitored via SIEM (Event ID `5136`) and PowerShell auditing.

---

## 42.5 Comprehensive Active Directory Posture Auditing Script (PowerShell)

Below is a read-only PowerShell auditing script (`Invoke-ADSecurityPostureAudit.ps1`) using the official `ActiveDirectory` RSAT module to audit Domain Controllers, FSMO roles, password policies, `AdminSDHolder` DACLs, orphaned `adminCount=1` accounts, dangerous Replication/ACL delegations, and MachineAccountQuota settings.

```powershell
<#
.SYNOPSIS
    Invoke-ADSecurityPostureAudit.ps1
    Read-Only Active Directory Architecture & Access Control Auditor
.DESCRIPTION
    Performs non-destructive LDAP and DACL inspections across the current
    Active Directory domain to identify privilege boundary risks and verify
    Microsoft Tier-0 hardening controls.
#>

[CmdletBinding()]
param()

Import-Module ActiveDirectory -ErrorAction Stop

function Write-Section {
    param([string]$Title)
    Write-Host "`n==============================================================================" -ForegroundColor Cyan
    Write-Host "[*] $Title" -ForegroundColor Cyan
    Write-Host "==============================================================================" -ForegroundColor Cyan
}

$domain = Get-ADDomain
$forest = Get-ADForest
$domainDN = $domain.DistinguishedName

# ------------------------------------------------------------------------------
Write-Section "1. FOREST, DOMAIN & FSMO ROLE TOPOLOGY"
# ------------------------------------------------------------------------------
Write-Host ("Forest Name           : {0} (Mode: {1})" -f $forest.Name, $forest.ForestMode)
Write-Host ("Domain Name           : {0} (Mode: {1})" -f $domain.DNSRoot, $domain.DomainMode)
Write-Host ("Schema Master         : {0}" -f $forest.SchemaMaster)
Write-Host ("Domain Naming Master  : {0}" -f $forest.DomainNamingMaster)
Write-Host ("PDC Emulator          : {0}" -f $domain.PDCEmulator)
Write-Host ("RID Master            : {0}" -f $domain.RIDMaster)
Write-Host ("Infrastructure Master : {0}" -f $domain.InfrastructureMaster)

# ------------------------------------------------------------------------------
Write-Section "2. MACHINEACCOUNTQUOTA & DEFAULT DOMAIN PASSWORD POLICY"
# ------------------------------------------------------------------------------
# ms-DS-MachineAccountQuota controls how many computer accounts any standard user can join to the domain (Default = 10; Hardened = 0)
$maq = (Get-ADObject -Identity $domainDN -Properties "ms-DS-MachineAccountQuota")."ms-DS-MachineAccountQuota"
if ($maq -gt 0) {
    Write-Host "[WARN] ms-DS-MachineAccountQuota = $maq (Standard users can create up to $maq computer objects in AD! Recommended: 0)" -ForegroundColor Yellow
} else {
    Write-Host "[PASS] ms-DS-MachineAccountQuota = 0 (Standard users cannot create arbitrary computer accounts)." -ForegroundColor Green
}

$pwdPolicy = Get-ADDefaultDomainPasswordPolicy
Write-Host ("Minimum Password Length : {0} (Recommended >= 14)" -f $pwdPolicy.MinPasswordLength)
Write-Host ("Lockout Threshold       : {0}" -f $pwdPolicy.LockoutThreshold)
Write-Host ("Reversible Encryption   : {0} (Must be False)" -f $pwdPolicy.ReversibleEncryptionEnabled)
if ($pwdPolicy.ReversibleEncryptionEnabled) {
    Write-Host "[CRIT] Reversible password encryption is enabled at the Domain level!" -ForegroundColor Red
}

# ------------------------------------------------------------------------------
Write-Section "3. ADMINSDHOLDER & ORPHANED ADMINCOUNT=1 AUDIT"
# ------------------------------------------------------------------------------
$adminSDHolderDN = "CN=AdminSDHolder,CN=System,$domainDN"
$sdHolderAcl = Get-Acl -Path "AD:\$adminSDHolderDN"

$ExpectedTier0Principals = @(
    'NT AUTHORITY\SYSTEM',
    'BUILTIN\Administrators',
    "$($domain.NetBIOSName)\Domain Admins",
    "$($domain.NetBIOSName)\Enterprise Admins"
)

$WriteADMask = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll -bor `
               [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite -bor `
               [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl -bor `
               [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner -bor `
               [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty -bor `
               [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight

foreach ($ace in $sdHolderAcl.Access) {
    if ($ace.AccessControlType -eq 'Allow' -and (($ace.ActiveDirectoryRights -band $WriteADMask) -ne 0)) {
        if ($ExpectedTier0Principals -notcontains $ace.IdentityReference.Value) {
            Write-Host ("[WARN] Non-default principal with Write/Control ACE on AdminSDHolder: {0} -> {1}" -f $ace.IdentityReference, $ace.ActiveDirectoryRights) -ForegroundColor Yellow
        }
    }
}

# Enumerate users with adminCount=1 and check if they are disabled or have PasswordNeverExpires
$adminCountUsers = Get-ADUser -Filter 'adminCount -eq 1' -Properties adminCount, Enabled, PasswordNeverExpires, PasswordLastSet
Write-Host ("Total User Accounts with adminCount=1 : {0}" -f $adminCountUsers.Count)
foreach ($u in $adminCountUsers) {
    if ($u.PasswordNeverExpires -and $u.Name -ne 'krbtgt') {
        Write-Host ("[WARN] Privileged user (adminCount=1) has PasswordNeverExpires=True: {0}" -f $u.SamAccountName) -ForegroundColor Yellow
    }
}

# ------------------------------------------------------------------------------
Write-Section "4. DOMAIN ROOT REPLICATION RIGHTS (DS-REPLICATION-GET-CHANGES-ALL) AUDIT"
# ------------------------------------------------------------------------------
$domainRootAcl = Get-Acl -Path "AD:\$domainDN"
$ReplGetChangesAllGuid = [Guid]"1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"

foreach ($ace in $domainRootAcl.Access) {
    if ($ace.AccessControlType -eq 'Allow') {
        $hasGenericAll = ($ace.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericAll) -ne 0
        $hasReplAll = (($ace.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) -ne 0) -and `
                      ($ace.ObjectType -eq $ReplGetChangesAllGuid -or $ace.ObjectType -eq [Guid]::Empty)
        if ($hasGenericAll -or $hasReplAll) {
            Write-Host ("Principal authorized for Directory Secret Replication: {0} ({1})" -f $ace.IdentityReference, $ace.ActiveDirectoryRights)
        }
    }
}

# ------------------------------------------------------------------------------
Write-Section "5. LEGACY GROUP POLICY PREFERENCES (SYSVOL cpassword) AUDIT"
# ------------------------------------------------------------------------------
$sysvolPolicies = "\\$($domain.DNSRoot)\SYSVOL\$($domain.DNSRoot)\Policies"
if (Test-Path $sysvolPolicies) {
    $gppXmls = Get-ChildItem -Path $sysvolPolicies -Recurse -Include "Groups.xml","Services.xml","Scheduledtasks.xml","DataSources.xml","Drives.xml" -ErrorAction SilentlyContinue
    $cpasswordFound = 0
    foreach ($xmlFile in $gppXmls) {
        if (Select-String -Path $xmlFile.FullName -Pattern 'cpassword="[A-Za-z0-9+/=]+"' -Quiet) {
            $cpasswordFound++
            Write-Host ("[CRIT] Legacy GPP cpassword attribute found in SYSVOL XML: {0}" -f $xmlFile.FullName) -ForegroundColor Red
        }
    }
    if ($cpasswordFound -eq 0) {
        Write-Host "[PASS] No legacy GPP cpassword attributes found in SYSVOL." -ForegroundColor Green
    }
}
```

---

## 42.6 Chapter 42 Review Questions

1. **Forest vs. Domain Security Boundary**: Explain why Microsoft defines the Active Directory **Forest** rather than the **Domain** as the true security boundary. Which Naming Contexts are replicated across all Domain Controllers in the forest regardless of domain boundaries?
2. **`AdminSDHolder` and `SDProp`**: Describe the role of the `SDProp` background thread on the PDC Emulator. What happens to a user object's DACL inheritance when the user is added to `Domain Admins`, and what remains unchanged if the user is later removed from `Domain Admins`?
3. **Graph-Based Posture Auditing**: Why does `ms-DS-MachineAccountQuota = 10` (the default Active Directory setting) create significant risk in an enterprise domain, and how should it be remediated?

---
---

# Chapter 43: Kerberos v5 & NTLM Protocol Internals and Hardening

## 43.1 Enterprise Authentication Protocols Overview

Active Directory supports two primary network authentication protocols:
1. **Kerberos Version 5 (RFC 4120 & MS-KILE)**: The default, modern, cryptographic ticket-based mutual authentication protocol introduced in Windows 2000.
2. **NT LAN Manager (NTLM — MS-NLMP)**: A legacy challenge-response authentication protocol retained for backward compatibility when authenticating to systems by raw IP address (rather than DNS hostname), workgroup hosts, or legacy applications that do not support Kerberos Service Principal Names (SPNs).

Understanding the cryptographic message exchanges of both Kerberos and NTLM explains why certain protocol configurations expose credential material or permit man-in-the-middle relays, and how security architects configure protocol-level hardening to eliminate those risks.

---

## 43.2 Kerberos v5 Protocol Architecture and Message Exchange

Kerberos is based on the Needham-Schroeder symmetric key distribution protocol and relies on a trusted third-party **Key Distribution Center (KDC)**—which in Active Directory runs on every Domain Controller (`kdcsvc.dll` inside `lsass.exe`, TCP/UDP port 88). Rather than sending passwords across the network or requiring application servers to contact the Domain Controller on every client request, Kerberos issues time-bounded, cryptographically encrypted **Tickets**.

### 43.2.1 The Three Sub-Protocols of Kerberos Authentication

A complete Kerberos authentication workflow consists of three distinct two-message exchanges (6 messages total):

```
+-----------------------------------------------------------------------------+
|                KERBEROS V5 AUTHENTICATION EXCHANGE (RFC 4120)               |
+-----------------------------------------------------------------------------+
|                                                                             |
|  +---------------+                                     +-----------------+  |
|  |               |  1. AS-REQ (Pre-Auth Timestamp      |                 |  |
|  |               |     encrypted with User Long-Term   |                 |  |
|  |               |     Key K_User)                     |                 |  |
|  |               | ----------------------------------> |   DOMAIN        |  |
|  |               |                                     |   CONTROLLER    |  |
|  |               |  2. AS-REP (Logon Session Key       |   (KDC - Port   |  |
|  |               |     [Encrypted w/ K_User] +         |    88)          |  |
|  |               |     TGT [Encrypted w/ K_krbtgt])    |                 |  |
|  |               | <---------------------------------- |   Holds:        |  |
|  |               |                                     |   - K_User      |  |
|  |    CLIENT     |  3. TGS-REQ (TGT + Target SPN       |   - K_krbtgt    |  |
|  |  WORKSTATION  |     e.g. MSSQLSvc/db01.corp.lk +    |   - K_Service   |  |
|  |               |     Authenticator [K_LogonSession]) |                 |  |
|  |               | ----------------------------------> |                 |  |
|  |               |                                     |                 |  |
|  |               |  4. TGS-REP (Service Session Key    |                 |  |
|  |               |     [Encrypted w/ K_LogonSession] + |                 |  |
|  |               |     Service Ticket [Encrypted w/    |                 |  |
|  |               |     Target Service Key K_Service])  |                 |  |
|  |               | <---------------------------------- +-----------------+  |
|  |               |                                                          |
|  |               |  5. AP-REQ (Service Ticket + Authenticator encrypted     |
|  |               |     with Service Session Key K_SvcSession)               |
|  |               | ----------------------------------> +-----------------+  |
|  |               |                                     |   APPLICATION   |  |
|  |               |  6. AP-REP (Optional Mutual Auth    |   SERVER        |  |
|  |               |     confirmation from Server)       |   (Holds only   |  |
|  |               | <---------------------------------- |    K_Service)   |  |
|  +---------------+                                     +-----------------+  |
+-----------------------------------------------------------------------------+
```

Let us examine each step and its exact cryptographic transformations in detail:

#### Phase 1: Authentication Service Exchange (`KRB_AS_REQ` & `KRB_AS_REP`)
1. **Key Derivation on the Client**:
   When a user enters their username and password on a workstation, the client's Kerberos SSP (`kerberos.dll`) derives the user's symmetric secret key $K_{\text{User}}$ from their password:
   - If using **AES-256-CTS-HMAC-SHA1-96** (etype `18`, default in modern AD): $K_{\text{User}} = \text{PBKDF2-HMAC-SHA1}(\text{Password}, \text{Salt}=\text{REALM}+\text{username}, \text{Iterations}=4096)$.
   - If using legacy **RC4-HMAC** (etype `23`): $K_{\text{User}} = \text{MD4}(\text{UTF-16LE}(\text{Password}))$ (the raw NT Hash, with no salt!).
2. **Step 1 (`KRB_AS_REQ`)**:
   To prove possession of $K_{\text{User}}$ without sending the password over the wire, the client takes its current UTC timestamp (`PA-ENC-TIMESTAMP`) and encrypts it with $K_{\text{User}}$. It sends the `AS-REQ` containing the client's principal name, requested encryption types, and encrypted timestamp to the KDC.
3. **Step 2 (`KRB_AS_REP`)**:
   The KDC looks up the user's $K_{\text{User}}$ in `ntds.dit` and decrypts the timestamp. If the decrypted timestamp is within **5 minutes** of the KDC's clock (preventing replay attacks), pre-authentication succeeds. The KDC then returns `AS-REP`, which contains two separate encrypted structures:
   - **Outer Client Portion** (encrypted with $K_{\text{User}}$): Contains the newly generated random **Logon Session Key** ($K_{\text{LogonSession}}$) and ticket validity times.
   - **The Ticket Granting Ticket (TGT)** (encrypted with the secret key of the KDC's own **`krbtgt`** account, $K_{\text{krbtgt}}$): Contains the user's identity, a copy of $K_{\text{LogonSession}}$, and the **Privilege Attribute Certificate (PAC)**.
   - **Crucial Architectural Fact**: The client **cannot decrypt or read its own TGT**, because only the KDC knows $K_{\text{krbtgt}}$! The client simply caches the opaque TGT in LSASS memory alongside $K_{\text{LogonSession}}$.

#### Phase 2: Ticket-Granting Service Exchange (`KRB_TGS_REQ` & `KRB_TGS_REP`)
When the user wants to connect to a network resource—such as a SQL database or an SMB file share on `filesrv01.corp.example.lk`—the client requests a **Service Ticket** (`TGS`) for that specific **Service Principal Name (SPN)** (e.g., `cifs/filesrv01.corp.example.lk`):
1. **Step 3 (`KRB_TGS_REQ`)**:
   The client sends its cached **TGT**, the target **SPN**, and an **Authenticator** (client identity + current timestamp encrypted with $K_{\text{LogonSession}}$) to the KDC.
2. **Step 4 (`KRB_TGS_REP`)**:
   - The KDC decrypts the TGT using its own $K_{\text{krbtgt}}$ key, extracts $K_{\text{LogonSession}}$ from inside the TGT, and uses $K_{\text{LogonSession}}$ to decrypt the client's Authenticator. Notice that the KDC did not even need to query `ntds.dit` for the user's password hash during this step—the TGT itself is stateless proof of identity!
   - The KDC looks up the target service account that owns the requested SPN (e.g., `FILESRV01$` or a SQL service account) in `ntds.dit` to retrieve that service's long-term secret key ($K_{\text{Service}}$).
   - The KDC generates a fresh **Service Session Key** ($K_{\text{SvcSession}}$) and returns `TGS-REP`, containing:
     - **Outer Client Portion** (encrypted with $K_{\text{LogonSession}}$): Contains $K_{\text{SvcSession}}$.
     - **The Service Ticket** (encrypted with the target service's long-term key, **$K_{\text{Service}}$**): Contains the user's PAC, username, and a copy of $K_{\text{SvcSession}}$.

#### Phase 3: Client/Server Authentication Exchange (`KRB_AP_REQ` & `KRB_AP_REP`)
1. **Step 5 (`KRB_AP_REQ`)**:
   The client connects directly to the application server (e.g., over SMB port 445) and presents the **Service Ticket** plus a new **Authenticator** encrypted with $K_{\text{SvcSession}}$.
2. **Step 6 (`KRB_AP_REP`)**:
   The application server decrypts the Service Ticket using its own local secret key ($K_{\text{Service}}$), extracts $K_{\text{SvcSession}}$, verifies the Authenticator, and reads the user's SIDs and group memberships directly from the **PAC** inside the ticket to construct the user's Windows Access Token—**without contacting the Domain Controller** (unless PAC validation over Netlogon is explicitly required).

### 43.2.2 Anatomy of the Microsoft Privilege Attribute Certificate (PAC — MS-PAC)

Standard MIT Kerberos v5 (RFC 4120) only authenticates *who* the principal is (`alice@CORP.EXAMPLE.LK`), leaving authorization lookups to the target server. Microsoft extended Kerberos (in specification **MS-KILE** and **MS-PAC**) by embedding the **Privilege Attribute Certificate (PAC)** inside the `AuthorizationData` field of every TGT and Service Ticket.

The PAC contains:
- **`KERB_VALIDATION_INFO` (`LogonInfo`)**: The user's `UserId` (RID), `PrimaryGroupId`, array of domain `GroupIds`, `ExtraSids` (for Universal Groups and SID History), and `UserAccountControl` flags.
- **Two Cryptographic Checksums (Signatures)** to prevent tampering:
  1. **`ServerSignature` (`PAC_SERVER_CHECKSUM`)**: Keyed hash of the PAC contents signed using the target service's key ($K_{\text{Service}}$).
  2. **`KDC Signature` (`PAC_PRIVSVR_CHECKSUM`)**: Keyed hash of the `ServerSignature` signed using the Domain Controller's **`krbtgt`** key ($K_{\text{krbtgt}}$)—preventing a compromised application server from forging a PAC with `Domain Admins` RIDs for a service ticket it decrypts!
  3. **`TicketChecksum` & `PAC_ATTRIBUTES_INFO` / `PAC_REQUESTOR_SID`** (added in KB5008380 / CVE-2021-42287 patches): Binds the PAC cryptographically to the outer Kerberos ticket and explicitly records the requesting user's exact ObjectSID.

---

## 43.3 Kerberos Configuration Weaknesses and Architectural Remediations

Because the `AS-REP` and `TGS-REP` messages contain ciphertext encrypted with long-term account keys ($K_{\text{User}}$ and $K_{\text{Service}}$), specific account misconfigurations expose those ciphertexts to offline brute-force dictionary analysis if weak passwords or legacy encryption algorithms are used.

### 43.3.1 Pre-Authentication Disabled (`UF_DONT_REQUIRE_PREAUTH`)

In Phase 1 (`AS-REQ`), standard Kerberos requires the client to prove knowledge of $K_{\text{User}}$ *before* the KDC will issue an `AS-REP`. However, Active Directory user objects support a legacy `userAccountControl` bitflag (`0x400000`, `UF_DONT_REQUIRE_PREAUTH` — checkbox **"Do not require Kerberos preauthentication"** in ADUC), originally intended for compatibility with non-Windows RFC 1510 Kerberos v4/early v5 implementations.

**Architectural Consequence**:
If `DoesNotRequirePreAuth = True` is set on a user account, the KDC will respond to an unauthenticated `AS-REQ` for that username (from *any* host that can reach port 88) with a valid `AS-REP`. While the TGT portion of the `AS-REP` is encrypted with $K_{\text{krbtgt}}$, the outer `enc-part` containing the Logon Session Key has a known ASN.1 structure encrypted directly with the user's password-derived key $K_{\text{User}}$. Anyone who receives that `AS-REP` can test password guesses offline against the `enc-part` without triggering any Active Directory account lockout telemetry.

**Remediation**:
No modern application requires disabling Kerberos Pre-Authentication. Security teams must audit all accounts in Active Directory and clear the `0x400000` flag immediately.

### 43.3.2 Service Principal Names (SPNs) on User Accounts with Weak Passwords & RC4

In Phase 2 (`TGS-REQ`), any authenticated domain user with a valid TGT is permitted by the Kerberos protocol specification to request a Service Ticket (`TGS-REP`) for **any** Service Principal Name (SPN) registered in the domain, because the KDC delegates access control decisions (`SeAccessCheck`) to the target application server itself.

**Architectural Consequence**:
As shown in Phase 2 Step 4, the Service Ticket returned inside `TGS-REP` is encrypted with the long-term secret key ($K_{\text{Service}}$) of the account that owns the target `servicePrincipalName` attribute:
- When an SPN is registered on a **Computer Account** (`FILESRV01$`) or a **Group Managed Service Account (`gMSA`)**, Active Directory automatically generates a cryptographically random 120-character UTF-16 password rotated every 30 days, and supports **AES-256** (`etype 18`). Offline dictionary guessing against a 120-character random password is computationally infeasible ($2^{256}$ keyspace).
- However, when an administrator manually creates a **standard User Account** (e.g., `svc_mssql`), assigns a human-chosen password (such as `SqlServer2024!`) set to `PasswordNeverExpires = True`, registers an SPN (`setspn -S MSSQLSvc/db01.corp.lk:1433 svc_mssql`), and leaves **RC4-HMAC (`etype 23`)** enabled, any domain user who requests a service ticket for that SPN receives ciphertext encrypted with the account's password key. Furthermore, if a lower-privileged principal holds `GenericWrite` or `WriteProperty(servicePrincipalName)` over a privileged user account, they could register a temporary SPN on that user account if ACLs are not hardened.

**Four-Step Architectural Remediation for Service Accounts**:
1. **Migrate all service accounts with SPNs to Group Managed Service Accounts (`gMSA` — `msDS-GroupManagedServiceAccount`)**: gMSAs use 240-byte (120 UTF-16 character) random keys managed and rotated automatically by the KDC every 30 days.
2. **For legacy services that cannot use gMSAs**: Enforce a minimum 25+ character randomly generated password stored in an Enterprise Vault, rotated regularly.
3. **Disable RC4-HMAC (`etype 23`) and Enforce AES-128 / AES-256 (`msDS-SupportedEncryptionTypes = 24` [`0x18`])**:
   AES-256 uses PBKDF2-HMAC-SHA1 with 4,096 iterations and a realm+username salt, slowing offline key derivation by orders of magnitude compared to unsalted single-round MD4 (RC4-HMAC), and preventing encryption-downgrade requests in `TGS-REQ`.
4. **Never place Service Principal Names on human interactive admin accounts (`adminCount=1`)**.

---

## 43.4 NTLM Challenge-Response, Name Resolution Poisoning & Relay Mechanics

### 43.4.1 How NTLM Challenge-Response Works (Net-NTLMv2)

Unlike Kerberos, NTLM does not use tickets or a centralized KDC during connection establishment. Instead, it uses a three-message challenge-response handshake embedded directly inside the application protocol (such as SMB, HTTP `Authorization: NTLM`, LDAP, MSSQL, or MSRPC) via the **Security Support Provider Interface (SSPI)**:

```
+-----------------------------------------------------------------------------+
|                    NTLMv2 CHALLENGE-RESPONSE HANDSHAKE                      |
+-----------------------------------------------------------------------------+
|                                                                             |
|  +--------------+             +--------------+             +-------------+  |
|  |              | 1. NEGOTIATE_MESSAGE (Type 1)            |             |  |
|  |              | ----------> |              |             |             |  |
|  |              |             |              |             |             |  |
|  |              | 2. CHALLENGE_MESSAGE (Type 2: 8-byte     |             |  |
|  |    CLIENT    |    Server Challenge Nonce) |             |   DOMAIN    |  |
|  |              | <---------- |  APP SERVER  |             |  CONTROLLER |  |
|  |              |             |              |             |  (Netlogon) |  |
|  |              | 3. AUTHENTICATE_MESSAGE (Type 3:         |             |  |
|  |              |    Net-NTLMv2 HMAC-MD5 Response)         |             |  |
|  |              | ----------> |              | 4. Verify   |             |  |
|  |              |             |              | ----------> |             |  |
+-----------------------------------------------------------------------------+
```

1. **Key Derivation**:
   - $\text{NT Hash} = \text{MD4}(\text{UTF-16LE}(\text{Password}))$
   - $\text{NTLMv2 Hash} = \text{HMAC-MD5}(\text{Key} = \text{NT Hash}, \text{Data} = \text{UTF-16LE}(\text{UPPERCASE}(\text{Username}) + \text{Domain}))$
2. **Response Calculation**:
   When the server sends the 8-byte random `ServerChallenge` in the Type 2 message, the client constructs a client blob (`temp`, containing timestamp, client 8-byte challenge, and TargetInfo AV_PAIRs) and computes:
   $$\text{NTProofStr} = \text{HMAC-MD5}(\text{Key} = \text{NTLMv2 Hash}, \text{Data} = \text{ServerChallenge} \parallel \text{ClientBlob})$$

### 43.4.2 Why Broadcast Name Resolution (LLMNR, NBT-NS, mDNS) Is an Architectural Hazard

When a Windows client attempts to resolve a hostname (for example, when a user mistypes a file share path as `\\filesvr01\share` instead of `\\filesrv01\share`, or when WPAD proxy auto-discovery queries `http://wpad/wpad.dat`), Windows queries DNS first.

If the DNS server responds with `NXDOMAIN` (Name Error), legacy Windows configurations fall back to **unauthenticated local subnet multicast/broadcast name resolution**:
1. **LLMNR (Link-Local Multicast Name Resolution)**: Sends UDP multicast queries to `224.0.0.252` (`FF02::1:3` on IPv6) on **UDP port 5355**.
2. **NBT-NS (NetBIOS Name Service)**: Sends UDP broadcast queries to the local subnet broadcast address on **UDP port 137**.
3. **mDNS (Multicast DNS)**: Sends queries to `224.0.0.251` on **UDP port 5353**.

Because LLMNR and NBT-NS have no cryptographic authentication, any host on the local Layer-2 broadcast domain can reply claiming to be `filesvr01`, causing the client workstation to initiate an SMB or HTTP connection and send a Net-NTLMv2 `AUTHENTICATE_MESSAGE` (Type 3).

### 43.4.3 Architectural Mechanics of NTLM Relaying & Why Signing + Channel Binding Stop It

Even more critically than offline password guessing against captured Net-NTLMv2 challenges, the classic NTLM protocol **lacks mutual authentication and does not bind the NTLM authentication handshake to the underlying transport session or application payload** unless **Signing** and **Channel Binding** are enforced:

1. **Protocol-Level Relay Vulnerability**:
   If a client connects to an untrusted host over SMB or HTTP using NTLM, that intermediate host can forward the client's Type 1 `NEGOTIATE_MESSAGE` to a target server (such as another SMB server, an LDAPS server on a Domain Controller, or an Active Directory Certificate Services HTTP Web Enrollment endpoint `/certsrv/`), return the target server's Type 2 `CHALLENGE_MESSAGE` back to the client, and forward the client's Type 3 `AUTHENTICATE_MESSAGE` to the target server.
2. **How Cryptographic Signing (SMB Signing / LDAP Signing) Prevents Relaying**:
   When **SMB Signing** (`RequireSecuritySignature = 1`) or **LDAP Signing** (`LDAPServerIntegrity = 2`) is enforced, every packet transmitted *after* the Type 3 `AUTHENTICATE_MESSAGE` must carry a cryptographic Message Integrity Code (MIC / HMAC signature) computed using the **Session Key** ($K_{\text{ExchangeKey}}$).
   - Crucially, the **Session Key** is never transmitted across the network during the NTLM handshake—it is derived independently by the real client (using its NTLMv2 Hash) and by the Domain Controller (via Netlogon pass-through validation).
   - Therefore, an intermediary sitting in the middle of an NTLM handshake **never learns the Session Key** and cannot compute a valid cryptographic signature on subsequent SMB or LDAP packets!
3. **How Extended Protection for Authentication (EPA / Channel Binding Tokens — RFC 5929) Protects TLS Endpoints (LDAPS & HTTPS)**:
   What if the target server uses TLS (such as **LDAPS on TCP 636** or **HTTPS ADCS Web Enrollment on TCP 443**), where application-layer packet signing is handled by TLS instead of SMB/LDAP signing?
   - Without Channel Binding, the outer TLS session terminates at the intermediary (between intermediary and Server, with certificate $C_{\text{Server}}$) separately from the TLS session between Client and intermediary ($C_{\text{Intermediary}}$).
   - When **Channel Binding (EPA)** is enforced (`LdapEnforceChannelBinding = 2` on Domain Controllers and Extended Protection = `Required` in IIS), the client computes a SHA-256 hash of the target server's TLS certificate (`tls-server-end-point` Channel Binding Token / CBT) and embeds it inside the signed `AV_PAIR` (`MsvAvChannelBindings`) of the NTLMv2 Type 3 message.
   - When the target LDAPS or HTTPS server verifies the NTLMv2 Type 3 message, it checks that the embedded CBT matches its own TLS certificate. If the handshake was relayed across two separate TLS connections, the certificates do not match and the server immediately drops the connection!

---

## 43.5 Protocol Hardening & Remediation Guide (PowerShell & GPO)

### 43.5.1 Disabling LLMNR, NBT-NS, and WPAD Across the Enterprise

1. **Disable LLMNR via Group Policy**:
   - Path: `Computer Configuration -> Administrative Templates -> Network -> DNS Client`
   - Policy: **Turn off multicast name resolution** = `Enabled`
   - Registry Equivalent:
     ```powershell
     New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DnsClient" -Force | Out-Null
     New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DnsClient" -Name "EnableMulticast" -Value 0 -PropertyType DWord -Force
     ```
2. **Disable NetBIOS over TCP/IP (NBT-NS)**:
   - On DHCP Scopes: Configure Microsoft Vendor Option `001` (*Microsoft Disable Netbios Option*) = `0x2`.
   - Via PowerShell Startup Script across all network adapters:
     ```powershell
     # Set TcpipNetbiosOptions = 2 (Disable NetBIOS over TCP/IP) on all adapters
     Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled=TRUE" |
         Invoke-CimMethod -MethodName SetTcpipNetbios -Arguments @{ TcpipNetbiosOptions = [uint32]2 }
     ```
3. **Disable WPAD (Web Proxy Auto-Discovery) Broadcast Fallback**:
   Create an explicit static `A` record for `wpad` in internal DNS pointing to `127.0.0.1` (or remove `wpad` from the DNS Global Query Block List and point it to a sinkhole), and disable the `WinHttpAutoProxySvc` service via GPO if WPAD is unused:
   ```powershell
   New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc" -Name "Start" -Value 4 -PropertyType DWord -Force
   ```

### 43.5.2 Enforcing SMB Signing, LDAP Signing, and LDAP Channel Binding

Deploy the following Group Policy settings to both the **Default Domain Controllers Policy** and the **Default Domain Policy**:

| Security Control | GPO Policy Name | Registry Key & Value | Hardened Setting |
| :--- | :--- | :--- | :--- |
| **SMB Server Signing** | *Microsoft network server: Digitally sign communications (always)* | `HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature` | `1` (Enabled on all DCs, Servers, and Workstations) |
| **SMB Client Signing** | *Microsoft network client: Digitally sign communications (always)* | `HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature` | `1` (Enabled on all DCs, Servers, and Workstations) |
| **LDAP Server Signing** | *Domain controller: LDAP server signing requirements* | `HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity` | `2` (`Require signing`) |
| **LDAP Client Signing** | *Network security: LDAP client signing requirements* | `HKLM\SYSTEM\CurrentControlSet\Services\ldap\LDAPClientIntegrity` | `2` (`Require signing`) |
| **LDAP Channel Binding (CBT)** | *Domain controller: LDAP server channel binding token requirements* | `HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\LdapEnforceChannelBinding` | `2` (`Always`) |
| **LAN Manager Auth Level** | *Network security: LAN Manager authentication level* | `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LmCompatibilityLevel` | `5` (*Send NTLMv2 response only. Refuse LM & NTLM*) |

### 43.5.3 Auditing and Remediating Kerberos Pre-Auth, SPNs, and Encryption Types

Below is an enterprise PowerShell audit and remediation script (`Invoke-KerberosProtocolAudit.ps1`) that identifies accounts with Pre-Authentication disabled, user accounts carrying SPNs, and accounts allowing legacy RC4/DES encryption, followed by safe remediation commands including deploying Group Managed Service Accounts (gMSAs):

```powershell
<#
.SYNOPSIS
    Invoke-KerberosProtocolAudit.ps1
    Audits Active Directory for Kerberos Pre-Auth gaps, User SPNs, and RC4 exposure.
#>

Import-Module ActiveDirectory -ErrorAction Stop

Write-Host "=== 1. AUDITING ACCOUNTS WITH KERBEROS PRE-AUTHENTICATION DISABLED ===" -ForegroundColor Cyan
$noPreAuthUsers = Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $true' -Properties DoesNotRequirePreAuth, Enabled, AdminCount
if ($noPreAuthUsers) {
    foreach ($u in $noPreAuthUsers) {
        Write-Host ("[CRIT] Pre-Auth Disabled on User: {0} (Enabled: {1}, AdminCount: {2})" -f $u.SamAccountName, $u.Enabled, $u.AdminCount) -ForegroundColor Red
        # Remediation command (uncomment after verification):
        # Set-ADAccountControl -Identity $u.DistinguishedName -DoesNotRequirePreAuth $false
    }
} else {
    Write-Host "[PASS] All domain user accounts require Kerberos Pre-Authentication." -ForegroundColor Green
}

Write-Host "`n=== 2. AUDITING USER ACCOUNTS WITH SERVICE PRINCIPAL NAMES (SPNs) ===" -ForegroundColor Cyan
$spnUsers = Get-ADUser -Filter 'ServicePrincipalName -like "*"' -Properties ServicePrincipalName, PasswordLastSet, PasswordNeverExpires, msDS-SupportedEncryptionTypes, AdminCount |
    Where-Object { $_.SamAccountName -ne 'krbtgt' }

foreach ($su in $spnUsers) {
    $encType = $su.'msDS-SupportedEncryptionTypes'
    $aesOnly = ($encType -eq 16 -or $encType -eq 24)
    Write-Host ("[WARN] User Account with SPN: {0} | AdminCount={1} | PwdLastSet={2} | AES-Only={3}" -f $su.SamAccountName, $su.AdminCount, $su.PasswordLastSet, $aesOnly) -ForegroundColor Yellow
    foreach ($spn in $su.ServicePrincipalName) {
        Write-Host ("       -> SPN: {0}" -f $spn)
    }
    if ($su.AdminCount -eq 1) {
        Write-Host ("       [CRIT] Privileged Admin account ({0}) has an SPN attached! Remove SPN immediately." -f $su.SamAccountName) -ForegroundColor Red
    }
    if (-not $aesOnly) {
        Write-Host ("       [WARN] Account {0} permits RC4-HMAC encryption (msDS-SupportedEncryptionTypes={1}). Recommend setting to 24 (AES128+AES256)." -f $su.SamAccountName, $encType) -ForegroundColor Yellow
    }
}

Write-Host "`n=== 3. EXAMPLE: REPLACING LEGACY USER SERVICE ACCOUNT WITH A HARDENED gMSA ===" -ForegroundColor Cyan
<#
    Step A (Once per Forest): Create the KDS Root Key on a Domain Controller:
        Add-KdsRootKey -EffectiveImmediately

    Step B: Create the Group Managed Service Account (gMSA) scoped to authorized server hosts:
        New-ADServiceAccount -Name "gmsa_sqlprod" `
                             -DNSHostName "gmsa_sqlprod.corp.example.lk" `
                             -PrincipalsAllowedToRetrieveManagedPassword "SG_SQL_Servers" `
                             -KerberosEncryptionType AES128, AES256 `
                             -ServicePrincipalNames "MSSQLSvc/db01.corp.example.lk:1433"
#>
```

---

## 43.6 Chapter 43 Review Questions

1. **Kerberos Protocol Mechanics**: Trace the six messages of a full Kerberos authentication exchange (`AS-REQ`, `AS-REP`, `TGS-REQ`, `TGS-REP`, `AP-REQ`, `AP-REP`). Specify which exact symmetric key encrypts the Ticket Granting Ticket (TGT), which key encrypts the Service Ticket, and why a client workstation cannot decrypt its own TGT.
2. **PAC Dual Signatures**: Why does the Privilege Attribute Certificate (PAC) inside a Kerberos ticket contain **two** cryptographic signatures (`ServerSignature` signed with $K_{\text{Service}}$ and `KDC Signature` signed with $K_{\text{krbtgt}}$)? What security failure would occur if only `ServerSignature` existed?
3. **NTLM Relaying vs. Signing & Channel Binding**: Explain the cryptographic difference between **SMB/LDAP Signing** (which relies on the NTLM Session Key) and **LDAP/HTTPS Channel Binding Tokens (EPA)** (which bind the NTLM Type 3 `AV_PAIR` to the outer TLS server certificate). Why are *both* required to protect a Domain Controller?


---
---

# Chapter 44: Active Directory Delegation, ADCS (PKI) Security & Access Control Hygiene

## 44.1 The Multi-Tier Application Problem and Kerberos Delegation

In enterprise distributed systems, users rarely connect directly to back-end databases or mainframe storage systems. Instead, a client authenticates to a **Front-End Web or Middleware Server** (Tier A, e.g., an IIS web application `webapp.corp.example.lk`), and that front-end server must query a **Back-End Database or File Server** (Tier B, e.g., `sql01.corp.example.lk`) **on behalf of the connecting user** so that the back-end server can enforce per-user row-level security and audit logging.

This is known as the **Kerberos Double-Hop Problem**:
- When `Alice` authenticates to `webapp.corp.example.lk` using a standard Kerberos Service Ticket (`HTTP/webapp.corp.example.lk`), `webapp` can verify that `Alice` is connecting, but `webapp` cannot simply forward its `HTTP/webapp` Service Ticket to `sql01`—because `sql01` only accepts tickets encrypted with `sql01`'s key (`MSSQLSvc/sql01.corp.example.lk`)!

To solve the Double-Hop Problem across different eras of Windows Server, Microsoft engineered three successive generations of **Kerberos Delegation**. Each generation carries vastly different architectural security properties:

```
+-----------------------------------------------------------------------------+
|            EVOLUTION OF KERBEROS DELEGATION IN ACTIVE DIRECTORY             |
+-----------------------------------------------------------------------------+
|                                                                             |
|  1. UNCONSTRAINED DELEGATION (Windows 2000)                                 |
|     - Flag: TRUSTED_FOR_DELEGATION (0x80000)                                |
|     - Mechanism: Client places a full copy of its TGT inside the            |
|       AP-REQ sent to the Front-End server!                                  |
|     - Risk: Front-End server caches EVERY connecting user's TGT in LSASS    |
|       and can impersonate them to ANY service in the entire domain.         |
|                                                                             |
|  2. CONSTRAINED DELEGATION (KCD — Windows Server 2003)                      |
|     - Attribute: msDS-AllowedToDelegateTo (on Front-End Server)             |
|     - Mechanism: Front-End server never receives the client's TGT. Instead, |
|       it uses S4U2self and S4U2proxy extensions to request tickets ONLY     |
|       for the explicitly whitelisted target SPNs in msDS-AllowedToDelegateTo|
|     - Risk: If Protocol Transition (TRUSTED_TO_AUTH_FOR_DELEGATION) is      |
|       enabled, a compromised Front-End server can forge S4U2self tickets    |
|       for any non-protected user to the whitelisted back-end service.       |
|                                                                             |
|  3. RESOURCE-BASED CONSTRAINED DELEGATION (RBCD — Windows Server 2012)      |
|     - Attribute: msDS-AllowedToActOnBehalfOfOtherIdentity (on Back-End!)    |
|     - Mechanism: The Back-End resource owner controls a Security Descriptor |
|       listing which Front-End accounts are trusted to delegate to it.       |
|     - Risk: Any principal with GenericWrite/WriteProperty on a Computer     |
|       object can populate msDS-AllowedToActOnBehalfOfOtherIdentity.         |
+-----------------------------------------------------------------------------+
```

---

## 44.2 Deep-Dive into the Three Kerberos Delegation Models

### 44.2.1 Unconstrained Delegation (`UF_TRUSTED_FOR_DELEGATION`)

When an administrator checks **"Trust this computer for delegation to any service (Kerberos only)"** on a computer or service account in Active Directory, AD sets the `0x80000` (`UF_TRUSTED_FOR_DELEGATION`) bit in the object's `userAccountControl` attribute.

#### Architectural Mechanics:
1. When a client requests a Service Ticket (`TGS-REQ`) for a server that has `UF_TRUSTED_FOR_DELEGATION` set, the KDC sets the `OK-AS-DELEGATE` flag inside the returned Service Ticket (`TGS-REP`).
2. Seeing this flag, the client requests a **Forwarded TGT** from the KDC and embeds that full TGT (along with its session key) inside the `KRB_CRED` structure of the `AP-REQ` sent to the Unconstrained Delegation server.
3. Upon decrypting the `AP-REQ`, the server's `lsass.exe` extracts the user's Forwarded TGT and places it into local LSASS ticket memory, allowing the server to request Service Tickets as that user for **any SPN on any host in the domain**.

#### Why Non-DC Unconstrained Delegation Is an Critical Enterprise Risk:
If a non-Domain-Controller server (such as an IIS web server or print server) is configured with Unconstrained Delegation and becomes compromised, any privileged administrator who connects to that server (or any Domain Controller machine account coerced via RPC protocols like `MS-RPRN` / `MS-EFSRPC` to authenticate to that server) deposits an active TGT into the server's memory. Note that by default, **Domain Controllers** themselves require `UF_TRUSTED_FOR_DELEGATION`, which is normal; however, **zero member servers or user accounts** should ever have Unconstrained Delegation enabled.

### 44.2.2 Traditional Constrained Delegation (KCD: `S4U2self` & `S4U2proxy`)

Introduced in Windows Server 2003, **Kerberos Constrained Delegation (KCD)** eliminates the need to send client TGTs to front-end servers by introducing two Microsoft Kerberos extensions (specification **MS-SFU** — Service for User):

1. **`S4U2proxy` (Service-for-User-to-Proxy — Kerberos Only)**:
   - Suppose `Alice` authenticates to `webapp` using Kerberos, sending her normal Service Ticket (`HTTP/webapp`).
   - `webapp` sends a `TGS-REQ` to the KDC containing its own TGT, `Alice`'s `HTTP/webapp` Service Ticket as evidence in the `additional-tickets` field (`cname-in-addl-tkt`), and the target back-end SPN (`MSSQLSvc/sql01`).
   - The KDC checks the **`msDS-AllowedToDelegateTo`** attribute on `webapp`'s AD object. If `MSSQLSvc/sql01` is listed in `msDS-AllowedToDelegateTo`, the KDC issues a Service Ticket for `Alice` to `MSSQLSvc/sql01`.
2. **`S4U2self` (Service-for-User-to-Self — Protocol Transition)**:
   - What if `Alice` authenticated to `webapp` using a **non-Kerberos protocol** (such as NTLM, SAML, TLS Client Certificate, or OAuthForms), meaning `webapp` does not have an incoming Kerberos Service Ticket from `Alice` to pass to `S4U2proxy`?
   - If the administrator selects **"Trust this computer for delegation to specified services only -> Use any authentication protocol"**, Active Directory sets the `0x1000000` (`UF_TRUSTED_TO_AUTH_FOR_DELEGATION`) flag in `userAccountControl`.
   - With `UF_TRUSTED_TO_AUTH_FOR_DELEGATION` enabled, `webapp` can send an `S4U2self` request to the KDC asking for a forwardable Service Ticket to *itself* (`HTTP/webapp`) on behalf of **any arbitrary username** (`Alice`, or even a `Domain Admin`), without providing any cryptographic proof that `Alice` actually connected! `webapp` can then immediately pass that `S4U2self` ticket into `S4U2proxy` to impersonate that user to any service listed in `msDS-AllowedToDelegateTo`.
   - Furthermore, note that the **service class** prefix of an SPN (e.g., `cifs/sql01` vs. `ldap/sql01` vs. `host/sql01`) is **not** encrypted inside the Service Ticket; the ticket is encrypted solely with the target host `sql01$`'s machine key, which is shared across all host services running as `SYSTEM`/`NETWORK SERVICE` on `sql01`.

### 44.2.3 Resource-Based Constrained Delegation (RBCD)

Introduced in Windows Server 2012, **Resource-Based Constrained Delegation (RBCD)** flips the trust direction:
- In classic KCD, modifying `msDS-AllowedToDelegateTo` on a front-end server required **`SeEnableDelegationPrivilege`** (a Tier-0 Domain Admin privilege), because it allowed the front-end server to specify which back-end servers it wanted to impersonate users to.
- In **RBCD**, the delegation configuration is stored on the **Back-End Resource Computer Object** inside the attribute **`msDS-AllowedToActOnBehalfOfOtherIdentity`**.
- This attribute holds a binary Security Descriptor (`nTSecurityDescriptor`) listing the SIDs of front-end accounts that the back-end server trusts to perform `S4U2self` + `S4U2proxy` delegation to it.

**Why RBCD Audited Permissions Matter**:
Because `msDS-AllowedToActOnBehalfOfOtherIdentity` is stored on the back-end computer object itself, modifying it **does not require `SeEnableDelegationPrivilege`**. Any principal that holds `GenericAll`, `GenericWrite`, or `WriteProperty` over a Computer object in Active Directory (such as the creator/owner of the computer object or a delegated server administrator) can write a Security Descriptor into `msDS-AllowedToActOnBehalfOfOtherIdentity` authorizing another SPN-bearing account (such as a newly created computer account when `ms-DS-MachineAccountQuota > 0`) to delegate to that computer as an arbitrary non-protected administrator!

### 44.2.4 Defending Against Delegation Risks: `Protected Users` & `Account is sensitive`

Microsoft provides two built-in controls that completely block **all** forms of Kerberos Delegation (`Unconstrained`, `KCD`, and `RBCD`) from impersonating privileged accounts:

1. **The `Protected Users` Security Group (`S-1-5-21-<domain>-525`)**:
   Introduced in Windows Server 2012 R2. Adding all Tier-0 and Tier-1 administrative accounts to `Protected Users` enforces five non-overridable protections at the KDC and client workstation level:
   - **Blocks all Kerberos Delegation**: The KDC refuses to issue Forwardable (`FORWARDABLE`) or Proxiable (`PROXIABLE`) tickets for members of `Protected Users`. Neither Unconstrained Delegation, KCD (`S4U2self`/`S4U2proxy`), nor RBCD can impersonate a member of `Protected Users`!
   - **Blocks NTLM Authentication**: Members of `Protected Users` cannot authenticate using NTLM (protecting them from NTLM relaying and Net-NTLMv2 capture).
   - **Blocks DES and RC4 Kerberos Encryption**: Enforces AES-only encryption for TGTs.
   - **Blocks Credential Caching on Endpoints**: Neither WDigest nor DCC2 (`MSCacheV2`) hashes are cached when a `Protected Users` member logs off.
   - **Shortens TGT Lifetime to 4 Hours**: Reduces TGT lifetime from the default 10 hours to 4 hours (`240` minutes).
2. **Account Flag: "Account is sensitive and cannot be delegated" (`UF_NOT_DELEGATED`, `0x100000`)**:
   For legacy administrative or service accounts that cannot yet be added to `Protected Users` (for example, if they require NTLM to manage a legacy appliance), setting `AccountNotDelegated = $true` (`0x100000` in `userAccountControl`) instructs the KDC to strip the `FORWARDABLE` flag from their tickets, making them immune to Unconstrained, Constrained, and RBCD delegation.

---

## 44.3 Tiered Administration Model (Enterprise Access Model) and Windows LAPS

### 44.3.1 Preventing Credential Lateral Movement via Administrative Tiering

Historically, enterprise IT departments used a single `Domain Admin` account to manage Domain Controllers, reboot application servers, and troubleshoot end-user laptops. Whenever a `Domain Admin` logs onto a Tier-2 workstation via RDP (`mstsc.exe`) or interactive logon, their Kerberos TGT and credentials are placed into that workstation's `lsass.exe` memory. If that workstation was previously compromised by phishing malware running as `SYSTEM`, the workstation's attacker immediately harvests the `Domain Admin` TGT and compromises the entire forest.

To sever this escalation path, Microsoft designed the **Active Directory Administrative Tier Model** (evolved into the **Enterprise Access Model**):

```
+-----------------------------------------------------------------------------+
|                ENTERPRISE ADMINISTRATIVE TIERING ARCHITECTURE               |
+-----------------------------------------------------------------------------+
|                                                                             |
|  TIER 0: IDENTITY & FOREST CONTROL PLANE                                    |
|  - Assets: Domain Controllers, ADCS PKI CAs, Entra Connect Sync Servers,    |
|    AD FS, Key Vaults, Tier-0 Privileged Access Workstations (PAWs).         |
|  - Accounts: Dedicated Tier-0 Admin Accounts (Added to Protected Users).    |
|  - Rule: Tier-0 accounts are BLOCKED via GPO Deny Logon Rights from EVER    |
|    logging onto Tier-1 Servers or Tier-2 Workstations!                      |
|                                                                             |
|  -------------------------------------------------------------------------  |
|  TIER 1: ENTERPRISE SERVERS & APPLICATIONS                                  |
|  - Assets: ERP, Database Servers, Web/App Servers, File Servers.            |
|  - Accounts: Dedicated Tier-1 Server Admin Accounts.                        |
|  - Rule: Tier-1 accounts are BLOCKED via GPO Deny Logon Rights from         |
|    logging onto Tier-0 assets or Tier-2 Workstations!                       |
|                                                                             |
|  -------------------------------------------------------------------------  |
|  TIER 2: USER WORKSTATIONS & ENDPOINT DEVICES                               |
|  - Assets: Laptops, Desktops, VDI, Printers, Kiosks.                        |
|  - Accounts: Dedicated Tier-2 Helpdesk / Workstation Admin Accounts +       |
|    Standard Domain Users.                                                   |
|  - Rule: Tier-2 Admin accounts cannot log onto Tier-1 or Tier-0 systems.    |
+-----------------------------------------------------------------------------+
```

#### Enforcing Tier Isolation via Group Policy User Rights Assignment
Tier separation is not merely a policy on paper—it must be cryptographically and OS-enforced using **Deny Logon Rights** in Group Policy (`Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment`) linked to Tier-1 Server OUs and Tier-2 Workstation OUs:
- **`SeDenyInteractiveLogonRight`** (*Deny log on locally*) -> `SG_Tier0_Admins`
- **`SeDenyRemoteInteractiveLogonRight`** (*Deny log on through Remote Desktop Services*) -> `SG_Tier0_Admins`
- **`SeDenyBatchLogonRight`** (*Deny log on as a batch job* — blocks Scheduled Tasks) -> `SG_Tier0_Admins`
- **`SeDenyServiceLogonRight`** (*Deny log on as a service* — blocks Windows Services) -> `SG_Tier0_Admins`
- **`SeDenyNetworkLogonRight`** (*Deny access to this computer from the network* — applied on Tier-2 Workstations for Tier-0 and Tier-1 Admins).

### 44.3.2 Windows LAPS (Local Administrator Password Solution)

A second major lateral movement vector on Tier-2 workstations and Tier-1 member servers occurs when IT departments deploy golden OS images sharing the **same local `Administrator` (`RID 500`) password** across thousands of machines. If one workstation is compromised and its local SAM hive is dumped, an identical local Administrator NT hash allows authenticating to every other workstation over SMB/WinRM.

**Windows LAPS** (natively built into Windows 11, Windows 10, and Windows Server 2019/2022+ following the April 2023 OS updates, superseding Legacy Microsoft LAPS `AdmPwd.dll`) solves this by:
1. Generating a unique, cryptographically random password for the local Administrator account on every individual computer.
2. Rotating the password automatically on a configurable schedule (e.g., every 14 or 30 days) and **automatically rotating it immediately after the password is used or retrieved (`PostAuthenticationActions`)**.
3. **Encrypting the password in Active Directory (`msLAPS-EncryptedPassword`)**: Unlike Legacy LAPS (which stored the password in cleartext inside the `ms-Mcs-AdmPwd` LDAP attribute protected only by DACLs), modern **Windows LAPS** encrypts the password using the Microsoft Cloud/AD KDS Root Key (`CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,CN=Configuration`) so that only the specific security group specified in the GPO is cryptographically capable of decrypting it.

**Auditing Note for LAPS**:
Auditors must still inspect DACLs on Workstation and Server OUs to ensure that only authorized Tier-2/Tier-1 administrative groups hold `ExtendedRight` (`AllExtendedRights`) or `ReadProperty` on `ms-Mcs-AdmPwd` (Legacy LAPS) or are authorized decryptors for `msLAPS-EncryptedPassword`.

---

## 44.4 Active Directory Certificate Services (ADCS / Enterprise PKI) Security Architecture

**Active Directory Certificate Services (ADCS)** is Microsoft's Enterprise Public Key Infrastructure (PKI) implementation. ADCS enables Enterprise Certification Authorities (CAs) to issue X.509 digital certificates automatically to users, computers, domain controllers, smart cards, VPN clients, and Wi-Fi 802.1X endpoints based on **Certificate Templates** stored in the Forest Configuration Naming Context (`CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=...`).

### 44.4.1 How PKINIT (Certificate Authentication in Kerberos — RFC 4556) Works

When a certificate is issued with the **Client Authentication** (`1.3.6.1.5.5.7.3.2`), **PKINIT Client Authentication** (`1.3.6.1.5.2.3.4`), **Smart Card Logon** (`1.3.6.1.4.1.311.20.2.2`), or **Any Purpose** (`2.5.29.37.0`) Enhanced Key Usage (EKU), a client can use that X.509 certificate and its corresponding private key to request a **Kerberos TGT (`AS-REQ`)** from the Domain Controller via the **PKINIT** extension (RFC 4556):
1. Instead of encrypting the `AS-REQ` pre-authentication timestamp with a password-derived symmetric key ($K_{\text{User}}$), the client signs the pre-authentication data (`PA-PK-AS-REQ`) using its **RSA/ECDSA Private Key** and attaches the X.509 Certificate signed by an Enterprise CA listed in the Forest's **`NTAuthCertificates`** store (`CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=...`).
2. The KDC verifies the CA signature chain up to a Root CA in `CN=Certification Authorities` and verifies that the issuing CA resides in `NTAuthCertificates`.
3. The KDC then maps the certificate to an Active Directory user or computer account by inspecting the certificate's **Subject Alternative Name (SAN — `userPrincipalName` / `dNSHostName`)** or **`szOID_NTDS_CA_SECURITY_EXT` (`1.3.6.1.4.1.311.25.2` ObjectSID extension)** (enforced by the KB5014754 Strong Certificate Mapping patch).
4. Finally, the KDC returns an `AS-REP` containing a valid **TGT** for that account (plus the account's NT Hash inside the `PAC_CREDENTIAL_INFO` structure so that the user can still perform NTLM authentication to legacy servers!).

### 44.4.2 Architectural Taxonomy of ADCS Misconfigurations (ESC1 – ESC8)

In 2021, researchers Will Schroeder and Lee Christensen published *"Certified Pre-Owned"*, codifying a taxonomy of Active Directory Certificate Services misconfigurations (**ESC1 through ESC8**, later expanded to ESC15). Because an Enterprise CA in `NTAuthCertificates` is trusted to assert the identity of *any* user in the entire forest (including `Domain Admins` and `Enterprise Admins`), a single misconfigured Certificate Template or CA ACL compromises the entire forest.

Below is the comprehensive architectural breakdown and remediation matrix for ADCS ESC1–ESC8:

| Misconfiguration Code | Architectural Root Cause | Specific LDAP Attributes / Flags Involved | Definitive Hardening & Remediation |
| :--- | :--- | :--- | :--- |
| **ESC1** (*Enrollee Supplies Subject + Client Auth EKU*) | A Certificate Template grants low-privileged users (`Domain Users` / `Authenticated Users`) **Enroll** permission, permits **Client Authentication** EKU, requires no Manager Approval, and sets the `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` flag—allowing the requester to specify an arbitrary `SubjectAltName` (UPN/SID of a `Domain Admin`) in the CSR! | - `mspki-certificate-name-flag` contains `0x00000001` (`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`)<br>- `pKIExtendedKeyUsage` contains Client Auth / Smart Card Logon / Any Purpose (or is empty)<br>- `mspki-enrollment-flag` lacks `0x00000002` (`CT_FLAG_PEND_ALL_REQUESTS`) | 1. Never combine `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` with Client Authentication EKUs for non-Tier-0 enrollees.<br>2. If custom SANs are required for web server TLS certificates, change the EKU strictly to **Server Authentication** (`1.3.6.1.5.5.7.3.1`) only, require **CA Certificate Manager Approval** (`CT_FLAG_PEND_ALL_REQUESTS`), and scope **Enroll** ACLs strictly to the specific web server computer group. |
| **ESC2** (*Any Purpose EKU or SubCA Template*) | A Certificate Template grants low-privileged principals **Enroll** rights and either specifies the **Any Purpose** EKU (`2.5.29.37.0`) or specifies **no EKUs at all** (which X.509 treats as valid for all purposes, including Client Authentication and Subordinate CA signing). | - `pKIExtendedKeyUsage` is empty or contains `2.5.29.37.0` | Remove Any Purpose / empty EKUs from all templates; unpublish unused default templates (`SubCA`); restrict enrollment to Tier-0 PKI Admins with Manager Approval. |
| **ESC3** (*Enrollment Agent Template Abuse*) | A Certificate Template grants low-privileged users **Enroll** for the **Certificate Request Agent** EKU (`1.3.6.1.4.1.311.20.2.1`), which allows signing CSRs *on behalf of other users* against a second schema v1 or v2 template that accepts Enrollment Agent signatures for Client Auth. | - Template 1 has EKU `1.3.6.1.4.1.311.20.2.1`<br>- Template 2 has `msPKI-RA-Application-Policies` accepting Request Agent | Unpublish or tightly restrict all templates containing the `Certificate Request Agent` EKU; configure **Restrict Enrollment Agents** inside the CA properties (`certsrv.msc` -> Properties -> Enrollment Agents tab). |
| **ESC4** (*Vulnerable Certificate Template DACL*) | A Certificate Template object in `CN=Certificate Templates,...` grants `GenericAll`, `GenericWrite`, `WriteDacl`, `WriteOwner`, or `WriteProperty` to a non-Tier-0 user or group, allowing them to modify the template's LDAP attributes into an ESC1 state. | - Overly permissive ACEs in `nTSecurityDescriptor` of the `pKICertificateTemplate` object | Audit DACLs on all objects in `CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=...`; remove all Write/Modify ACEs for non-Tier-0 principals. |
| **ESC5** (*Vulnerable PKI Object / CA Server ACLs*) | Overly permissive ACLs on the CA server itself (local admin rights on the CA host, CA private key file ACLs, or ACLs on `CN=Public Key Services`, `CN=NTAuthCertificates`, or `CN=Enrollment Services`). | - Host ACLs or `CN=Public Key Services` container DACLs | Treat all Enterprise CA servers and the `CN=Public Key Services` AD container strictly as **Tier-0** assets with Tier-0 PAW administration only. |
| **ESC6** (*CA Flag `EDITF_ATTRIBUTESUBJECTALTNAME2` Enabled*) | An administrator runs `certutil -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2` on the Enterprise CA. This forces the CA to accept a user-supplied Subject Alternative Name (SAN) in the request attributes of **any** published template—even templates where `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` is disabled (such as the default `User` template)! | - CA Registry value `HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CAName>\PolicyModules\...\EditFlags` bit `0x00040000` (`EDITF_ATTRIBUTESUBJECTALTNAME2`) | Immediately disable this flag on all Enterprise CAs:<br>`certutil.exe -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2`<br>`Restart-Service CertSvc` |
| **ESC7** (*Vulnerable Enterprise CA Officer / Manager ACLs*) | A non-Tier-0 principal is granted **ManageCA** (*CA Administrator*, `0x1`) or **ManageCertificates** (*Certificate Manager / Officer*, `0x2`) rights on the Certification Authority's Security tab. `ManageCA` allows enabling `EDITF_ATTRIBUTESUBJECTALTNAME2`; `ManageCertificates` allows approving pending CSRs (`CT_FLAG_PEND_ALL_REQUESTS`), bypassing Manager Approval protections on ESC1/ESC2 templates. | - CA Security Descriptor (`HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CAName>\Security`) | Restrict `ManageCA` and `ManageCertificates` strictly to dedicated Tier-0 PKI Administrators; enable CA Role Separation if required by compliance standards. |
| **ESC8** (*NTLM Relay to ADCS HTTP Web Enrollment*) | The legacy **Certification Authority Web Enrollment** (`http://<ca-server>/certsrv/`) or **CES/CEP** IIS roles are installed with plain HTTP (or HTTPS without Extended Protection for Authentication / Channel Binding) and accept **NTLM authentication**. If a Domain Controller or user is coerced or tricked into authenticating over NTLM, the handshake can be relayed to `/certsrv/certfnsh.asp` to enroll a Client Authentication certificate (`DomainController` or `User` template). | - IIS `/certsrv` virtual directory enabled over HTTP or accepting NTLM without EPA (Channel Binding) | 1. **Best Practice**: Uninstall the legacy `ADCS-Web-Enrollment` (`/certsrv`) Windows Server feature completely and use RPC/DCOM auto-enrollment with `IF_ENFORCEENCRYPTICERTREQUEST`.<br>2. If Web Enrollment must remain installed: Disable HTTP (enforce HTTPS only), disable NTLM authentication in IIS (enforce `Negotiate:Kerberos` only), and set **Extended Protection (EPA) = Required** in IIS Authentication Advanced Settings. |

---

## 44.5 Comprehensive Delegation, LAPS & ADCS Security Auditing Script (PowerShell)

Below is a read-only PowerShell script (`Invoke-ADDelegationAndPKIAudit.ps1`) that audits the Active Directory Forest for Unconstrained Delegation, Constrained Delegation, Resource-Based Constrained Delegation (RBCD), `Protected Users` membership hygiene, and Active Directory Certificate Services (ESC1, ESC2, ESC3, ESC4, ESC6, ESC8) misconfigurations.

```powershell
<#
.SYNOPSIS
    Invoke-ADDelegationAndPKIAudit.ps1
    Read-Only Auditor for Kerberos Delegation, Protected Users, and ADCS PKI Templates
.DESCRIPTION
    Performs non-destructive LDAP queries across Domain and Configuration Naming
    Contexts to detect Delegation risks and ADCS Certificate Template flaws.
#>

[CmdletBinding()]
param()

Import-Module ActiveDirectory -ErrorAction Stop

$domain = Get-ADDomain
$forest = Get-ADForest
$configNC = (Get-ADRootDSE).configurationNamingContext

function Write-Section {
    param([string]$Title)
    Write-Host "`n==============================================================================" -ForegroundColor Cyan
    Write-Host "[*] $Title" -ForegroundColor Cyan
    Write-Host "==============================================================================" -ForegroundColor Cyan
}

# ------------------------------------------------------------------------------
Write-Section "1. UNCONSTRAINED KERBEROS DELEGATION AUDIT (Excluding Domain Controllers)"
# ------------------------------------------------------------------------------
# TrustedForDelegation = True, excluding primaryGroupID 516 (Domain Controllers) and 521 (RODCs)
$unconstrained = Get-ADObject -LDAPFilter "(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(primaryGroupID=516))(!(primaryGroupID=521)))" `
    -Properties samAccountName, objectClass, dNSHostName, servicePrincipalName

if ($unconstrained) {
    foreach ($obj in $unconstrained) {
        Write-Host ("[CRIT] Non-DC Object with Unconstrained Delegation: {0} ({1})" -f $obj.samAccountName, $obj.objectClass) -ForegroundColor Red
    }
} else {
    Write-Host "[PASS] No non-Domain-Controller objects have Unconstrained Delegation enabled." -ForegroundColor Green
}

# ------------------------------------------------------------------------------
Write-Section "2. CONSTRAINED DELEGATION (KCD & PROTOCOL TRANSITION) AUDIT"
# ------------------------------------------------------------------------------
$constrained = Get-ADObject -LDAPFilter "(msDS-AllowedToDelegateTo=*)" `
    -Properties samAccountName, userAccountControl, msDS-AllowedToDelegateTo

foreach ($obj in $constrained) {
    # 0x1000000 (16777216) = TRUSTED_TO_AUTH_FOR_DELEGATION (Protocol Transition / S4U2self enabled)
    $protoTransition = ($obj.userAccountControl -band 0x1000000) -ne 0
    $targets = ($obj.'msDS-AllowedToDelegateTo') -join ', '
    if ($protoTransition) {
        Write-Host ("[WARN] KCD with Protocol Transition (S4U2self): {0} -> Targets: [{1}]" -f $obj.samAccountName, $targets) -ForegroundColor Yellow
    } else {
        Write-Host ("[INFO] KCD (Kerberos-Only S4U2proxy): {0} -> Targets: [{1}]" -f $obj.samAccountName, $targets) -ForegroundColor Gray
    }
}

# ------------------------------------------------------------------------------
Write-Section "3. RESOURCE-BASED CONSTRAINED DELEGATION (RBCD) AUDIT"
# ------------------------------------------------------------------------------
$rbcdObjects = Get-ADObject -LDAPFilter "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)" `
    -Properties samAccountName, msDS-AllowedToActOnBehalfOfOtherIdentity

foreach ($obj in $rbcdObjects) {
    $sdBytes = $obj.'msDS-AllowedToActOnBehalfOfOtherIdentity'
    $rawSd = New-Object System.Security.AccessControl.RawSecurityDescriptor($sdBytes, 0)
    foreach ($ace in $rawSd.DiscretionaryAcl) {
        Write-Host ("[WARN] RBCD Configured on Resource [{0}] trusting SID: {1}" -f $obj.samAccountName, $ace.SecurityIdentifier.Value) -ForegroundColor Yellow
    }
}

# ------------------------------------------------------------------------------
Write-Section "4. PROTECTED USERS GROUP & ADMIN SENSITIVITY HYGIENE"
# ------------------------------------------------------------------------------
$protectedUsers = Get-ADGroupMember -Identity "Protected Users" -Recursive | Select-Object -ExpandProperty DistinguishedName
$domainAdmins = Get-ADGroupMember -Identity "Domain Admins" -Recursive | Where-Object { $_.objectClass -eq 'user' }

foreach ($da in $domainAdmins) {
    $u = Get-ADUser -Identity $da.DistinguishedName -Properties AccountNotDelegated
    if ($protectedUsers -notcontains $da.DistinguishedName -and (-not $u.AccountNotDelegated)) {
        Write-Host ("[CRIT] Domain Admin [{0}] is NOT in 'Protected Users' and does NOT have 'AccountNotDelegated' set!" -f $u.SamAccountName) -ForegroundColor Red
    } else {
        Write-Host ("[PASS] Domain Admin [{0}] is protected against delegation." -f $u.SamAccountName) -ForegroundColor Green
    }
}

# ------------------------------------------------------------------------------
Write-Section "5. ACTIVE DIRECTORY CERTIFICATE SERVICES (ADCS) TEMPLATE AUDIT (ESC1/ESC2/ESC3/ESC4)"
# ------------------------------------------------------------------------------
$templatesDN = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"
$enrollmentDN = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$configNC"

if (Test-Path "AD:\$templatesDN") {
    # Enumerate published templates across all Enterprise CAs
    $cas = Get-ADObject -SearchBase $enrollmentDN -LDAPFilter "(objectClass=pKIEnrollmentService)" -Properties name, dNSHostName, certificateTemplates
    $publishedTemplates = @()
    foreach ($ca in $cas) {
        Write-Host ("Enterprise CA Found: {0} (Host: {1})" -f $ca.name, $ca.dNSHostName)
        $publishedTemplates += $ca.certificateTemplates
    }
    $publishedTemplates = $publishedTemplates | Select-Object -Unique

    $ClientAuthEKUs = @(
        '1.3.6.1.5.5.7.3.2',       # Client Authentication
        '1.3.6.1.5.2.3.4',         # PKINIT Client Authentication
        '1.3.6.1.4.1.311.20.2.2',  # Smart Card Logon
        '2.5.29.37.0'              # Any Purpose
    )

    $templates = Get-ADObject -SearchBase $templatesDN -LDAPFilter "(objectClass=pKICertificateTemplate)" `
        -Properties cn, displayName, mspki-certificate-name-flag, mspki-enrollment-flag, pKIExtendedKeyUsage, mspki-ra-signature, nTSecurityDescriptor

    foreach ($tmpl in $templates) {
        if ($publishedTemplates -notcontains $tmpl.cn) { continue }

        # Flag 0x1 = CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
        $enrolleeSuppliesSubject = ($tmpl.'mspki-certificate-name-flag' -band 0x1) -ne 0
        # Flag 0x2 = CT_FLAG_PEND_ALL_REQUESTS (Manager Approval required)
        $pendAllRequests = ($tmpl.'mspki-enrollment-flag' -band 0x2) -ne 0
        $raSignaturesRequired = [int]$tmpl.'mspki-ra-signature'

        $ekus = $tmpl.pKIExtendedKeyUsage
        $hasClientAuthEku = ($ekus.Count -eq 0) -or (($ekus | Where-Object { $ClientAuthEKUs -contains $_ }).Count -gt 0)
        $hasAgentEku = ($ekus -contains '1.3.6.1.4.1.311.20.2.1')

        if ($enrolleeSuppliesSubject -and $hasClientAuthEku -and (-not $pendAllRequests) -and ($raSignaturesRequired -eq 0)) {
            Write-Host ("[CRIT] Potential ESC1 Template Published: [{0}] (EnrolleeSuppliesSubject=True, ClientAuthEKU=True, ManagerApproval=False)" -f $tmpl.cn) -ForegroundColor Red
        }
        if (($ekus.Count -eq 0 -or ($ekus -contains '2.5.29.37.0')) -and (-not $pendAllRequests)) {
            Write-Host ("[WARN] Potential ESC2 Template Published: [{0}] (Any Purpose or Empty EKU without Manager Approval)" -f $tmpl.cn) -ForegroundColor Yellow
        }
        if ($hasAgentEku -and (-not $pendAllRequests)) {
            Write-Host ("[WARN] Potential ESC3 Template Published: [{0}] (Certificate Request Agent EKU)" -f $tmpl.cn) -ForegroundColor Yellow
        }
    }
}
```

---

## 44.6 Chapter 44 Review Questions

1. **Kerberos Delegation Comparison**: Compare Unconstrained Delegation, Traditional Constrained Delegation (`S4U2self` + `S4U2proxy`), and Resource-Based Constrained Delegation (RBCD). Why does RBCD store its authorization descriptor (`msDS-AllowedToActOnBehalfOfOtherIdentity`) on the back-end resource computer rather than the front-end service, and why does setting `ms-DS-MachineAccountQuota = 0` mitigate unauthorized RBCD configuration by standard users?
2. **`Protected Users` Security Group**: List the five cryptographic and protocol restrictions enforced when an administrative account is added to the `Protected Users` security group.
3. **ADCS PKI Security (ESC1 – ESC8)**: Explain the exact combination of Certificate Template flags (`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`, `pKIExtendedKeyUsage`, `CT_FLAG_PEND_ALL_REQUESTS`, and Enrollment ACLs) that causes an **ESC1** condition, and explain why enabling `EDITF_ATTRIBUTESUBJECTALTNAME2` on an Enterprise CA (**ESC6**) turns even the default `User` template into an ESC1-equivalent risk.

---
---

# Chapter 45: Enterprise Identity Monitoring, Domain Trust Security & Adversary Emulation Frameworks

## 45.1 Active Directory Long-Term Cryptographic Keys & Persistence Hygiene

Protecting an Active Directory forest requires not only preventing initial unauthorized elevation, but also ensuring that long-term cryptographic keys, directory service recovery accounts, and cross-domain trust boundaries are continuously audited and rotated.

### 45.1.1 The `krbtgt` Account Architecture and Double-Rotation Procedure

Every Active Directory domain possesses a built-in disabled user account named **`krbtgt`** (`RID 502`). As established in Chapter 43, the secret keys derived from the `krbtgt` account's password ($K_{\text{krbtgt}}$: AES-256, AES-128, and NT/RC4) are used by the Key Distribution Center (KDC) on every Domain Controller to encrypt and sign all **Ticket Granting Tickets (TGTs)** (`KRB_AS_REP`) and to compute the **KDC Signature** inside every Privilege Attribute Certificate (`PAC_PRIVSVR_CHECKSUM`).

#### Why `krbtgt` Key Hygiene Is Paramount:
1. Because the KDC validates a TGT simply by decrypting it with $K_{\text{krbtgt}}$ (without checking `ntds.dit` on every `TGS-REQ` unless the ticket is older than 20 minutes or validated across a trust), anyone who possesses a copy of the domain's $K_{\text{krbtgt}}$ key material can forge arbitrary TGTs offline with customized PACs.
2. **Active Directory Retains Two `krbtgt` Keys in History (`N` and `N-1`)**:
   To ensure that existing user sessions do not break immediately when `krbtgt`'s password is changed during normal maintenance, Active Directory stores both the **current `krbtgt` password (`kvno N`)** and the **immediately preceding `krbtgt` password (`kvno N-1`)** inside `ntds.dit` and honors tickets encrypted with *either* key!
3. **The Mandatory Double-Rotation Rule**:
   - **Proactive Routine Hygiene**: Microsoft recommends rotating the `krbtgt` password once every **180 days** (waiting at least 10 hours—the maximum TGT lifetime—between rotations).
   - **Incident Response / Suspected Tier-0 Compromise**: After evicting an unauthorized actor from the domain, administrators must rotate the `krbtgt` password **twice** (waiting until AD replication completes across all DCs between the first and second reset) to purge both key `N` and key `N-1`, immediately invalidating any ticket forged with the old key!

### 45.1.2 Service Account Ticket Forgery vs. PAC Validation (`ValidateKdcPacSignature`)

Whereas $K_{\text{krbtgt}}$ encrypts TGTs, individual **Service Tickets (`TGS`)** are encrypted with the target service or computer account's key ($K_{\text{Service}}$, e.g., `FILESRV01$`).
- By default, when an application server receives an `AP-REQ` containing a Service Ticket, the server decrypts the ticket using its own local $K_{\text{Service}}$ and verifies the `ServerSignature` on the PAC, **without** sending the PAC over the Netlogon secure channel to a Domain Controller to verify the `KDC Signature` (`PAC_PRIVSVR_CHECKSUM` signed with $K_{\text{krbtgt}}$).
- Consequently, if the long-term password hash of a computer account (`FILESRV01$`) or service account is compromised (or is not rotated), someone holding $K_{\text{Service}}$ can construct a forged Service Ticket valid solely on that specific server.
- **Hardening Controls**:
  1. Ensure **Machine Account Password Rotation** (`DisablePasswordChange = 0` under `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters`) is enabled on all domain computers so computer passwords rotate automatically every 30 days.
  2. For high-security services, enable **KDC PAC Signature Validation** (`ValidateKdcPacSignature = 1` under `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters`), which forces the server to verify the `KDC Signature` with a Domain Controller over the Netlogon RPC channel.

### 45.1.3 Directory Services Restore Mode (DSRM) Account Hardening

Every Domain Controller maintains a local SAM database (`C:\Windows\System32\config\SAM`) containing a local `Administrator` (`RID 500`) account known as the **Directory Services Restore Mode (DSRM)** account. Originally intended only for offline recovery when `ntds.dit` fails to mount during safe-mode boot, a registry key on the Domain Controller (`DsrmAdminLogonBehavior` under `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`) controls when the DSRM password can be used:

| `DsrmAdminLogonBehavior` Value | Operational Behavior & Risk Profile |
| :--- | :--- |
| **`0` (Default & Required Hardened Setting)** | The DSRM Administrator account can **only** log on when the Domain Controller is booted physically/console into offline **Directory Services Restore Mode**. Network logons using the DSRM hash are completely blocked while AD DS is running. |
| **`1`** | The DSRM account can log on when the `NTDS` (Active Directory Domain Services) service is stopped. |
| **`2` (Critical Misconfiguration / Persistence Vector)** | The DSRM local Administrator account is permitted to log onto the Domain Controller **at any time over the network** (via WinRM, SMB, or RDP) while the Domain Controller is running normally, granting full Tier-0 DC control using a local SAM hash that does not appear in Active Directory LDAP queries! |

**Hardening Requirement**: Continuously monitor `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\DsrmAdminLogonBehavior` across all Domain Controllers (must be `0` or absent) and periodically synchronize or rotate DSRM passwords using `ntdsutil.exe -> set dsrm password`.

---

## 45.2 Domain & Forest Trust Architecture, `SIDHistory`, and Trust Boundary Hardening

When enterprises merge, acquire subsidiaries, or operate multi-domain forests, they link domains using **Active Directory Trusts** represented by `trustedDomain` objects (`CN=<TrustedDomain>,CN=System,DC=...`). Each trust direction maintains a shared cryptographic secret (Trust Key / Inter-Realm `krbtgt` key) used by the trusting and trusted KDCs to issue **Inter-Realm Referral TGTs**.

### 45.2.1 `SIDHistory` and How SID Filtering Works Across Trust Boundaries

During a domain migration, when user `Alice` is migrated from `DomainA` to `DomainB`, her account receives a new primary `objectSid` in `DomainB`. So that `Alice` does not lose access to file shares in `DomainA` before all NTFS ACLs are re-permissioned, Active Directory provides the **`sIDHistory`** multi-valued attribute on `Alice`'s user object in `DomainB`, which stores her old SIDs from `DomainA`. When the KDC constructs `Alice`'s Kerberos PAC (`KERB_VALIDATION_INFO`), it copies every SID in `Alice`'s `sIDHistory` into the PAC's **`ExtraSids`** array.

#### The Architectural Dilemma of `ExtraSids` Across Parent-Child vs. External/Forest Trusts:
What happens if a KDC in `DomainA` (for example, a compromised child domain `child.corp.example.lk`) inserts an arbitrary privileged SID belonging to `DomainB` (such as the Forest Root's `Enterprise Admins` SID: `S-1-5-21-<RootDomain>-519`) into the `ExtraSids` field of an Inter-Realm Referral TGT presented to the Root Domain Controller?

To prevent an untrusted or semi-trusted domain from asserting SIDs that do not belong to it, Windows implements **SID Filtering** inside the Security Reference Monitor / Netlogon / KDC boundary when evaluating incoming cross-domain tickets:

```
+-----------------------------------------------------------------------------+
|            KERBEROS INTER-REALM TRUST & SID FILTERING BOUNDARY              |
+-----------------------------------------------------------------------------+
|                                                                             |
|  1. EXTERNAL TRUSTS & FOREST TRUSTS (Separate Forests)                      |
|     - SID Filtering is ENABLED by default.                                  |
|     - Rule: Any SID in ExtraSids that does NOT begin with the Trusted       |
|       Domain's own Domain SID prefix (plus ALL RID < 1000 built-in admin    |
|       SIDs except Domain Users -513) is STRIPPED at the trust boundary!     |
|                                                                             |
|  2. INTRA-FOREST TRUSTS (Parent-Child & Tree-Root Trusts in Same Forest)    |
|     - Remember: The FOREST (not the Domain) is the security boundary!       |
|     - Inside the same forest, SID Filtering does NOT strip Enterprise       |
|       Admins (S-1-5-21-<ForestRoot>-519) or Schema Admins (-518) by         |
|       default, because Universal Groups reside across the forest.           |
|     - Note: Microsoft patch KB5008380 / Forest Quarantine (`netdom trust    |
|       /quarantine:yes`) restricts RIDs < 1000 across explicit quarantined   |
|       trusts, reinforcing why every DC in every child domain must be        |
|       protected at the exact same Tier-0 standard as the Forest Root DC!    |
+-----------------------------------------------------------------------------+
```

### 45.2.2 Hardening Domain and Forest Trusts (`netdom trust`)

When an enterprise must maintain a trust with an external partner, vendor, or newly acquired company forest, security architects must apply three mandatory trust hardening controls:

1. **Enforce SID Filtering (Quarantine)**:
   Verify that SID Filtering (`TRUST_ATTRIBUTE_QUARANTINED_DOMAIN`, `0x4`) is active so the external domain can never assert SIDs outside its own domain namespace:
   ```cmd
   netdom trust corp.example.lk /domain:partner.example.com /quarantine:yes
   ```
2. **Disable TGT Delegation Across the Trust (`EnableTGTDelegation:No`)**:
   By default on Forest Trusts prior to recent Windows Server updates, an unconstrained delegation server in the partner forest could receive forwarded TGTs when users from your forest connected to it. Explicitly block TGT forwarding across the trust:
   ```cmd
   netdom trust corp.example.lk /domain:partner.example.com /EnableTGTDelegation:No
   ```
3. **Enable Selective Authentication (`TRUST_ATTRIBUTE_CROSS_ORGANIZATION`, `0x10`)**:
   By default (**Forest-Wide / Domain-Wide Authentication**), establishing a trust automatically adds every user in the external forest into the `Authenticated Users` (`S-1-5-11`) SID on every computer in your forest!
   Enabling **Selective Authentication** prevents external users from authenticating to *any* server or workstation in your domain unless that specific user/group is explicitly granted the **`Allowed to Authenticate`** Extended Right on the target computer object's DACL in Active Directory:
   ```cmd
   netdom trust corp.example.lk /domain:partner.example.com /SelectiveAuth:yes
   ```

---

## 45.3 Enterprise Active Directory Telemetry & SIEM Detection Matrix

A resilient Active Directory architecture pairs proactive hardening with real-time **Advanced Audit Policy Configuration** (`Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> Policies -> Audit Policies`) on all Domain Controllers and Tier-0 servers.

Below is the authoritative Windows Security Event ID engineering reference for detecting identity, protocol, delegation, ADCS, and directory replication anomalies in a Security Information and Event Management (SIEM) platform:

| Event ID | Log Channel & Audit Subcategory | Event Description | High-Fidelity SIEM Detection Logic & Key XML Fields |
| :--- | :--- | :--- | :--- |
| **4624** & **4625** | Security (*Audit Logon*) | Successful (`4624`) and Failed (`4625`) account logons. | - Alert on **Logon Type 3** (Network) or **Logon Type 9** (`NewCredentials`) where `AuthenticationPackageName = NTLM` and `WorkstationName` is unexpected.<br>- Alert on any Tier-0 account (`Domain Admins`) logging onto a Tier-1 or Tier-2 host (**Logon Type 2** Interactive or **Logon Type 10** RemoteInteractive/RDP).<br>- Detect password spraying via high-volume `4625` (`SubStatus = 0xC000006A` bad password) across distinct `TargetUserName` values from a single IP. |
| **4768** | Security (*Audit Kerberos Authentication Service*) | A Kerberos authentication ticket (**TGT**) was requested (`AS-REQ` / `AS-REP`). | - **Pre-Auth Disabled Detection**: Alert when `PreAuthType = 0` (No pre-authentication).<br>- **Encryption Downgrade Detection**: Alert when `TicketEncryptionType = 0x17` (`23`, RC4-HMAC) instead of `0x12` (`18`, AES-256).<br>- **PKINIT Certificate Auth Monitoring**: Monitor `PreAuthType = 15` or `16` (Certificate logon) and correlate `CertIssuerName` / `CertSerialNumber` against recent `4886`/`4887` CA issuance events. |
| **4769** | Security (*Audit Kerberos Service Ticket Operations*) | A Kerberos service ticket (**TGS**) was requested (`TGS-REQ` / `TGS-REP`). | - **Anomalous SPN Enumeration / RC4 Ticket Detection**: Alert when a single client requests multiple `4769` tickets for User SPNs within a short window, or whenever `TicketEncryptionType = 0x17` (`RC4-HMAC`) is requested (`TicketOptions = 0x40810010`) from a modern Windows host (which normally requests `0x12` AES-256). |
| **4771** | Security (*Audit Kerberos Authentication Service*) | Kerberos pre-authentication failed. | - `FailureCode = 0x18` (`KRB5KDC_ERR_PREAUTH_FAILED` — wrong password) or `0x12` (`KRB5KDC_ERR_CLIENT_REVOKED` — disabled/locked account). High-velocity `4771` across multiple accounts indicates Kerberos password spraying. |
| **4662** | Security (*Audit Directory Service Access*) | An operation was performed on an Active Directory object (Requires configuring a **SACL** on the Domain Root object for `Everyone`). | - **Unauthorized Directory Replication (DCSync) Detection**: Alert immediately whenever `Properties` contains `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` (`DS-Replication-Get-Changes`), `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` (`DS-Replication-Get-Changes-All`), or `89e95b76-444d-4c62-991a-0facbeda640c` (`DS-Replication-Get-Changes-In-Filtered-Set`) **AND** `SubjectUserName` does **not** end with `$` (a legitimate Domain Controller machine account) and is not the authorized Entra Connect account! |
| **5136** | Security (*Audit Directory Service Changes*) | A directory service object was modified (Logs Both Old and New LDAP Attribute Values!). | - Alert on modifications to:<br>  1. `msDS-AllowedToActOnBehalfOfOtherIdentity` (`AttributeLDAPDisplayName` — RBCD modification).<br>  2. `msDS-KeyCredentialLink` (Shadow Credentials / WHfB key registration).<br>  3. `servicePrincipalName` on any `user` object.<br>  4. `nTSecurityDescriptor` on `CN=AdminSDHolder`, the Domain Root (`DC=...`), or any GPO / Certificate Template.<br>  5. `gPLink` on any OU or Domain container.<br>  6. `sIDHistory` attribute additions (`4765` / `4766`). |
| **4720**, **4728**, **4732**, **4756** | Security (*Audit User / Security Group Management*) | User account created (`4720`) or member added to Global (`4728`), Local (`4732`), or Universal (`4756`) security group. | - Alert immediately on any membership addition to Tier-0 groups (`Domain Admins`, `Enterprise Admins`, `Schema Admins`, `Administrators`, `Backup Operators`, `Server Operators`, `Print Operators`, `DnsAdmins`). |
| **4741** | Security (*Audit Computer Account Management*) | A computer account was created in Active Directory. | - Alert when `SubjectUserName` is a standard user account rather than an authorized domain-join provisioning account. |
| **4886** & **4887** | Security (*Audit Certification Services*) | Certificate Services received a certificate request (`4886`) and approved/issued a certificate (`4887`). | - Enable *Include SubjectAltName in audit logs* on the CA (`certutil -setreg policy\EditFlags +EDITF_AUDITCERTTEMPLATELOAD`). Alert whenever an issued certificate (`4887`) contains a `SubjectAltName` (`UPN` or `DNS`) that does not match the `RequesterName` in `4886`! |

---

## 45.4 Adversary Emulation Frameworks & Purple Team Methodology (MITRE ATT&CK)

### 45.4.1 Distinguishing Penetration Testing, Red Teaming, and Purple Team Adversary Emulation

In mature enterprise security programs, organizations move beyond point-in-time vulnerability scanning into structured validation of their people, processes, and detection engineering:

| Assessment Discipline | Primary Objective | Operational Model & Output |
| :--- | :--- | :--- |
| **Compliance Auditing / Posture Assessment** | Identify configuration drift, missing patches, and overly permissive ACLs across 100% of in-scope assets. | Full-visibility read-only scripts (`Invoke-ADSecurityPostureAudit.ps1`, BloodHound Enterprise, PingCastle, CIS-CAT) producing prioritized remediation roadmaps. |
| **Penetration Testing** | Validate whether identified vulnerabilities or misconfigurations can be chained to cross defined trust boundaries within a time-boxed engagement. | Scoped testing resulting in a technical findings and remediation report. |
| **Red Team Operations** | Test the Blue Team's (SOC's) end-to-end detection, triage, escalation, and incident response capabilities under realistic, unannounced operational conditions. | Objective-driven simulation modeled on specific threat actor TTPs (Tactics, Techniques, and Procedures), measuring **Mean Time to Detect (MTTD)** and **Mean Time to Respond (MTTR)**. |
| **Purple Team Adversary Emulation** | Collaborative, side-by-side engineering exercises where offensive operators and defensive detection engineers execute specific atomic techniques, inspect raw telemetry (`Sysmon`, `ETW`, Windows Event Logs, EDR), and tune SIEM/SOAR rules in real time. | Repeatable **Detection-as-Code** rules (Sigma, YARA, KQL, Splunk SPL) mapped directly to the **MITRE ATT&CK® Enterprise Matrix**. |

### 45.4.2 Mapping OS & Active Directory Hardening to the MITRE ATT&CK® Framework

When designing a Purple Team exercise for Linux, Windows, and Active Directory infrastructure, security engineers map each architectural control and telemetry source to its corresponding **MITRE ATT&CK Technique ID** and **MITRE D3FEND™ Countermeasure**:

| MITRE ATT&CK Tactic | Technique ID & Name | Architectural Mechanism Audited | Preventive Hardening Control (D3FEND) | Primary Detection Telemetry |
| :--- | :--- | :--- | :--- | :--- |
| **Privilege Escalation** | **T1548.001** (*Abuse Elevation Control Mechanism: Setuid and Setgid*) | Unintended SUID/SGID mode bits or `RPATH` flaws on Linux binaries. | Remove unneeded SUID bits (`chmod u-s`); mount `/tmp`, `/home`, `/var/tmp` with `nosuid,nodev,noexec`; enforce `NoNewPrivileges=yes` in `systemd`. | `auditd` syscall rule on `execve` with `uid!=euid -F euid=0` and `chmod` `04000`/`02000`. |
| **Privilege Escalation** | **T1548.002** (*Bypass User Account Control*) | Auto-elevating `<autoElevate>true` Windows binaries reading `HKCU\Software\Classes`. | Enforce `ConsentPromptBehaviorAdmin = 2` (Always Notify on Secure Desktop); remove local Admin rights from daily accounts. | Sysmon Event ID 1 (`ProcessCreate` with `IntegrityLevel: High` spawned by `Medium` parent) & Event ID 13 (`RegistryEvent` on `HKCU\Software\Classes`). |
| **Privilege Escalation** | **T1548.003** (*Sudo and Sudo Caching*) | Overly permissive `sudoers` rules (`NOPASSWD`, subshell-capable binaries, `env_keep+=LD_PRELOAD`). | Enforce `Defaults env_reset`, `Defaults use_pty`, `NOEXEC:` tag, and minimal root-owned wrapper scripts. | `/var/log/sudo.log`, `sudo-io` session recording, and `auditd` watch on `/etc/sudoers`. |
| **Privilege Escalation / Persistence** | **T1574.001 / .009** (*Hijack Execution Flow: DLL Search Order Hijacking & Path Interception by Unquoted Path*) | Unquoted `ImagePath` strings with spaces or writable directories in Machine `%PATH%`. | Enclose all service `ImagePath` values in quotes; restrict NTFS Write/Modify ACLs on application folders and `%PATH%` directories to `SYSTEM` and `Administrators`. | Windows Event ID `7045` / `4697` and Sysmon Event ID 7 (`ImageLoaded` from non-System32 paths into `SYSTEM` processes). |
| **Privilege Escalation** | **T1134.001** (*Access Token Manipulation: Token Impersonation/Theft*) | Service accounts holding `SeImpersonatePrivilege` or `SeDebugPrivilege`. | Scope services to gMSAs with minimal User Rights Assignments; enable LSA Protection (`RunAsPPL = 1`). | Windows Event ID `4672`, `4673`, and Sysmon Event ID 10 (`ProcessAccess` on `lsass.exe` / `winlogon.exe`). |
| **Credential Access** | **T1558.003** (*Steal or Forge Kerberos Tickets: Kerberoasting*) | User accounts registered with SPNs using weak passwords and RC4-HMAC encryption. | Migrate all SPNs to Group Managed Service Accounts (gMSAs) with 120-char auto-rotating keys; enforce AES-256 (`msDS-SupportedEncryptionTypes = 24`). | Windows Event ID `4769` where `ServiceName` != `krbtgt` and `TicketEncryptionType = 0x17` (RC4). |
| **Credential Access** | **T1558.004** (*Steal or Forge Kerberos Tickets: AS-REP Roasting*) | User accounts configured with `UF_DONT_REQUIRE_PREAUTH` (`0x400000`). | Clear `DoesNotRequirePreAuth` across all AD user objects (`Set-ADAccountControl -DoesNotRequirePreAuth $false`). | Windows Event ID `4768` where `PreAuthType = 0` and Event ID `5136` modifying `userAccountControl`. |
| **Credential Access** | **T1557.001** (*Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay*) | Fallback broadcast name resolution and unsigned SMB/LDAP/HTTP NTLM sessions. | Disable LLMNR and NetBIOS; enforce SMB Signing, LDAP Signing (`2`), and LDAP/HTTPS Channel Binding (`EPA`). | Network sensor monitoring UDP `5355`/`137` responses and DC Event ID `2889` (unsigned LDAP bind attempts). |
| **Credential Access / Escalation** | **T1649** (*Steal or Forge Authentication Certificates*) | ADCS ESC1–ESC8 template, CA flag, or Web Enrollment misconfigurations. | Remove `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` from Client Auth templates; disable `EDITF_ATTRIBUTESUBJECTALTNAME2`; uninstall `/certsrv` HTTP Web Enrollment; apply KB5014754 Strong Certificate Mapping. | Windows Event IDs `4886`, `4887`, `4898`, and `4768` (`PreAuthType = 15/16`). |
| **Credential Access** | **T1003.006** (*OS Credential Dumping: DCSync*) | Non-DC principals holding `DS-Replication-Get-Changes-All` on the Domain Root. | Remove replication extended rights from all non-DC principals; enforce Tier-0 PAW isolation. | Windows Event ID `4662` on the Domain Root matching replication GUID `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`. |

### 45.4.3 Translating Telemetry into Portable Sigma Detection Rules

To ensure that detections engineered during Purple Team exercises remain vendor-agnostic across Splunk, Microsoft Sentinel (KQL), Elastic Security, and QRadar, detection engineers author rules in the open **Sigma** YAML format. Below are two production-grade Sigma rules for Active Directory defense:

#### Sigma Rule 1: Detecting Unauthorized Directory Replication (`DCSync` — Event ID `4662`)
```yaml
title: Active Directory Replication Request from Non-Domain-Controller Principal
id: 619c8e18-4f32-4a91-9b8e-7c02a5d11e01
status: stable
description: >
    Detects a security principal requesting directory replication changes
    (DS-Replication-Get-Changes-All or DS-Replication-Get-Changes-In-Filtered-Set)
    where the subject account is not a Domain Controller machine account ($).
references:
    - https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4662
author: Enterprise Purple Team Engineering
date: 2026/11/02
tags:
    - attack.credential_access
    - attack.t1003.006
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4662
        ObjectServer: 'DS'
        AccessMask: '0x100' # ADS_RIGHT_DS_CONTROL_ACCESS (Extended Right)
        Properties|contains:
            - '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' # DS-Replication-Get-Changes-All
            - '89e95b76-444d-4c62-991a-0facbeda640c' # DS-Replication-Get-Changes-In-Filtered-Set
            - 'Replicating Directory Changes All'
    filter_dc_machine_accounts:
        SubjectUserName|endswith: '$'
    filter_system:
        SubjectUserSid: 'S-1-5-18'
    condition: selection and not 1 of filter_*
falsepositives:
    - Authorized Microsoft Entra Connect (Azure AD Connect) synchronization service accounts (add explicit SubjectUserName exclusion).
level: critical
```

#### Sigma Rule 2: Detecting Modification of RBCD or Shadow Credentials Attributes (`Event ID 5136`)
```yaml
title: Suspicious Modification of RBCD or KeyCredentialLink LDAP Attributes
id: 94f02d11-8c3b-4d04-a9e1-3b77c8910e44
status: stable
description: >
    Detects LDAP directory modifications to msDS-AllowedToActOnBehalfOfOtherIdentity
    (Resource-Based Constrained Delegation) or msDS-KeyCredentialLink (Windows Hello
    for Business / PKINIT Key Credentials) via Windows Security Event ID 5136.
author: Enterprise Purple Team Engineering
date: 2026/11/02
tags:
    - attack.persistence
    - attack.privilege_escalation
    - attack.t1098
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 5136
        AttributeLDAPDisplayName:
            - 'msDS-AllowedToActOnBehalfOfOtherIdentity'
            - 'msDS-KeyCredentialLink'
    condition: selection
falsepositives:
    - Legitimate Windows Hello for Business device registration or planned Hyper-V/Failover Cluster RBCD administration.
level: high
```

---

## 45.5 Comprehensive Trust, `krbtgt`, DSRM & Audit Policy Verification Script (PowerShell)

Below is a read-only PowerShell verification script (`Invoke-ADTrustAndMonitoringAudit.ps1`) that audits `krbtgt` password age, Domain Trust boundaries (SID Filtering, Selective Auth, TGT Delegation), Domain Controller DSRM registry settings, LDAP Signing / Channel Binding status, and Advanced Audit Policy readiness on Domain Controllers.

```powershell
<#
.SYNOPSIS
    Invoke-ADTrustAndMonitoringAudit.ps1
    Read-Only Auditor for krbtgt Hygiene, Domain Trusts, DSRM, and DC Audit Telemetry
#>

[CmdletBinding()]
param()

Import-Module ActiveDirectory -ErrorAction Stop

function Write-Section {
    param([string]$Title)
    Write-Host "`n==============================================================================" -ForegroundColor Cyan
    Write-Host "[*] $Title" -ForegroundColor Cyan
    Write-Host "==============================================================================" -ForegroundColor Cyan
}

# ------------------------------------------------------------------------------
Write-Section "1. KRBTGT ACCOUNT KEY AGE AUDIT"
# ------------------------------------------------------------------------------
$krbtgt = Get-ADUser -Identity "krbtgt" -Properties PasswordLastSet, msDS-KeyVersionNumber
$daysSinceReset = ((Get-Date) - $krbtgt.PasswordLastSet).Days
Write-Host ("krbtgt PasswordLastSet      : {0} ({1} days ago)" -f $krbtgt.PasswordLastSet, $daysSinceReset)
Write-Host ("krbtgt KeyVersionNumber     : {0}" -f $krbtgt.'msDS-KeyVersionNumber')

if ($daysSinceReset -gt 180) {
    Write-Host "[WARN] krbtgt password has not been rotated in $daysSinceReset days (Recommended <= 180 days)." -ForegroundColor Yellow
} else {
    Write-Host "[PASS] krbtgt password rotation age is within the 180-day threshold." -ForegroundColor Green
}

# ------------------------------------------------------------------------------
Write-Section "2. DOMAIN & FOREST TRUST BOUNDARY SECURITY AUDIT"
# ------------------------------------------------------------------------------
$trusts = Get-ADTrust -Filter * -Properties TrustAttributes, TrustDirection, TrustType, SelectiveAuthentication, SIDFilteringQuarantined, TGTDelegation

if ($trusts) {
    foreach ($t in $trusts) {
        Write-Host ("`nTrust Partner              : {0}" -f $t.Target) -ForegroundColor White
        Write-Host ("  Direction / Type         : {0} / {1}" -f $t.TrustDirection, $t.TrustType)
        Write-Host ("  SID Filtering Quarantined: {0}" -f $t.SIDFilteringQuarantined)
        Write-Host ("  Selective Authentication : {0}" -f $t.SelectiveAuthentication)
        Write-Host ("  TGT Delegation Enabled   : {0}" -f $t.TGTDelegation)

        if (-not $t.SIDFilteringQuarantined) {
            Write-Host "  [WARN] SID Filtering (Quarantine) is NOT enabled on this trust!" -ForegroundColor Yellow
        }
        if ($t.TGTDelegation) {
            Write-Host "  [CRIT] TGT Delegation is ENABLED across trust $($t.Target)! Run: netdom trust ... /EnableTGTDelegation:No" -ForegroundColor Red
        }
    }
} else {
    Write-Host "[INFO] No external or inter-domain trusts configured on this domain." -ForegroundColor Green
}

# ------------------------------------------------------------------------------
Write-Section "3. LOCAL DOMAIN CONTROLLER DSRM, LDAP SIGNING & CHANNEL BINDING AUDIT"
# ------------------------------------------------------------------------------
# Verify if running on a Domain Controller
$osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
if ($osInfo.ProductType -eq 2) {
    # Check DsrmAdminLogonBehavior
    $dsrmBehavior = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name DsrmAdminLogonBehavior -ErrorAction SilentlyContinue).DsrmAdminLogonBehavior
    if ($dsrmBehavior -in @(1, 2)) {
        Write-Host ("[CRIT] DsrmAdminLogonBehavior = {0} on DC! DSRM local admin can log on over the network!" -f $dsrmBehavior) -ForegroundColor Red
    } else {
        Write-Host "[PASS] DsrmAdminLogonBehavior is 0/Default (DSRM restricted to physical safe-mode recovery console)." -ForegroundColor Green
    }

    # Check LDAP Server Signing & Channel Binding
    $ntdsParams = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
    $ldapSign = (Get-ItemProperty -Path $ntdsParams -Name LDAPServerIntegrity -ErrorAction SilentlyContinue).LDAPServerIntegrity
    $ldapCbt  = (Get-ItemProperty -Path $ntdsParams -Name LdapEnforceChannelBinding -ErrorAction SilentlyContinue).LdapEnforceChannelBinding

    if ($ldapSign -eq 2) {
        Write-Host "[PASS] LDAPServerIntegrity = 2 (LDAP Signing Required)." -ForegroundColor Green
    } else {
        Write-Host ("[WARN] LDAPServerIntegrity = {0} (Recommended: 2 - Require Signing)." -f $ldapSign) -ForegroundColor Yellow
    }

    if ($ldapCbt -eq 2) {
        Write-Host "[PASS] LdapEnforceChannelBinding = 2 (LDAP Channel Binding Tokens Always Required)." -ForegroundColor Green
    } else {
        Write-Host ("[WARN] LdapEnforceChannelBinding = {0} (Recommended: 2 - Always)." -f $ldapCbt) -ForegroundColor Yellow
    }
} else {
    Write-Host "[INFO] Current host is not a Domain Controller; skipping local NTDS registry checks." -ForegroundColor Gray
}

# ------------------------------------------------------------------------------
Write-Section "4. ADVANCED AUDIT POLICY TELEMETRY VERIFICATION (auditpol.exe)"
# ------------------------------------------------------------------------------
$RequiredSubcategories = @(
    'Kerberos Authentication Service',
    'Kerberos Service Ticket Operations',
    'Directory Service Access',
    'Directory Service Changes',
    'Security Group Management',
    'User Account Management',
    'Computer Account Management',
    'Process Creation'
)

$auditCsv = auditpol.exe /get /category:* /r | ConvertFrom-Csv
foreach ($sub in $RequiredSubcategories) {
    $entry = $auditCsv | Where-Object { $_.'Subcategory' -eq $sub }
    if ($entry) {
        if ($entry.'Inclusion Setting' -match 'Success') {
            Write-Host ("[PASS] Audit Subcategory '{0}' = {1}" -f $sub, $entry.'Inclusion Setting') -ForegroundColor Green
        } else {
            Write-Host ("[WARN] Audit Subcategory '{0}' is set to [{1}] (Recommend: Success and Failure)" -f $sub, $entry.'Inclusion Setting') -ForegroundColor Yellow
        }
    }
}
```

---

## 45.6 Chapter 45 Review Questions & Comprehensive Case Study

1. **`krbtgt` Double-Rotation**: Why does rotating the `krbtgt` account password only **once** fail to invalidate existing forged Ticket Granting Tickets (`TGTs`), and why must administrators wait for Active Directory replication across all Domain Controllers before executing the second password reset?
2. **Trust Boundaries & `SIDHistory`**: Explain how the `sIDHistory` attribute is populated into the `ExtraSids` array of a Kerberos PAC during authentication. Why does SID Filtering (`netdom trust /quarantine:yes`) strip privileged RIDs (`< 1000`) across an External or Forest Trust, and why does `Selective Authentication` prevent external forest users from automatically matching `NT AUTHORITY\Authenticated Users` ACLs inside your forest?
3. **SIEM Telemetry Engineering**: A SOC engineer wants to detect unauthorized Active Directory replication (`DCSync`) and unauthorized modification of Resource-Based Constrained Delegation (`RBCD`) with near-zero false positives. Specify the exact Windows Security Event IDs, Audit Policy subcategories, and XML attribute filters (`Properties` GUIDs and `AttributeLDAPDisplayName` values) required to detect both events.
4. **Capstone Enterprise Architecture Exercise**: You are appointed Lead Security Architect for a financial institution running a multi-domain Active Directory forest (`bank.lk` and `retail.bank.lk`) with 15,000 endpoints and an Enterprise ADCS PKI. Design a 30-60-90 day hardening roadmap addressing:
   - Administrative Tiering (Tier 0 / Tier 1 / Tier 2) and `Protected Users` onboarding;
   - Elimination of NTLM broadcast poisoning (LLMNR/NBT-NS) and enforcement of SMB/LDAP Signing + Channel Binding;
   - Migration of legacy user SPN service accounts to AES-only Group Managed Service Accounts (`gMSAs`);
   - Remediation of ADCS ESC1–ESC8 risks and deployment of Windows LAPS across all workstations and member servers.


---

## 45.7 Privileged Access Workstations (PAWs), Hybrid Identity Sync & Application Control

### 45.7.1 Privileged Access Workstation (PAW) Architecture

Even when an Active Directory domain enforces Administrative Tiering, `Protected Users`, and Windows LAPS, a fundamental endpoint truth remains: **an administrative session is only as trustworthy as the physical keyboard and operating system from which it originates**. If a Tier-0 Domain Admin initiates an RDP or PowerShell Remoting session from a standard corporate laptop that also runs email clients, web browsers, PDF readers, and third-party collaboration software, any user-mode keylogger or browser exploit on that laptop compromises the Tier-0 administrative session before the credentials even enter the Kerberos protocol.

To eliminate this source-host risk, Microsoft's **Privileged Access Strategy** mandates dedicated **Privileged Access Workstations (PAWs)** for all Tier-0 (and ideally Tier-1) administrators:

```
+-----------------------------------------------------------------------------+
|            PRIVILEGED ACCESS WORKSTATION (PAW) ARCHITECTURE                 |
+-----------------------------------------------------------------------------+
|                                                                             |
|  Physical / Hardware Layer:                                                 |
|  - Dedicated physical hardware with TPM 2.0 + BitLocker Pre-Boot PIN        |
|  - UEFI Secure Boot + Hypervisor-Protected Code Integrity (HVCI)            |
|  - Windows Defender Credential Guard (Virtualization-Based Security / VBS)  |
|                                                                             |
|  Network & Identity Isolation Layer:                                        |
|  - Outbound Internet access BLOCKED completely (no email, no web browsing)  |
|  - Inbound SMB (445), WinRM (5985/5986), and RDP (3389) BLOCKED via         |
|    Windows Defender Firewall with Advanced Security                         |
|  - Authenticates to Tier-0 Domain Controllers exclusively via IPSec /       |
|    Kerberos Authentication Firewall Rules + Smart Card / FIDO2 WHfB         |
|                                                                             |
|  Application Control Layer:                                                 |
|  - Windows Defender Application Control (WDAC) / AppLocker enforcing        |
|    strict Microsoft + Enterprise CA code signing allowlists                 |
|  - PowerShell Constrained Language Mode (CLM) + Script Block Logging (4104) |
+-----------------------------------------------------------------------------+
```

### 45.7.2 Hybrid Identity Security: Hardening Microsoft Entra Connect (`Azure AD Connect`)

In modern hybrid enterprises, on-premises Active Directory synchronizes users, groups, and optionally password hashes (`Password Hash Synchronization / PHS`) or Pass-Through Authentication (`PTA`) with **Microsoft Entra ID** via the **Microsoft Entra Connect** server.

#### Architectural Why Entra Connect Is Strictly a Tier-0 Asset:
1. **On-Premises Directory Permissions (`MSOL_<hex>` Account)**:
   When Password Hash Synchronization (PHS) is configured, the on-premises AD Connector account (`MSOL_<hex>`) is granted `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All` on the Active Directory Domain Root so it can synchronize password hashes to the cloud.
2. **Cloud Directory Permissions**:
   In Microsoft Entra ID, the synchronization service holds the privileges to synchronize user attributes, reset passwords (if Password Writeback is enabled), and manage federated/synchronized objects.
3. **Database Storage**:
   Entra Connect stores synchronization configuration and encrypted connector credentials inside a local Microsoft SQL Server (`ADSync` database), with the symmetric encryption key protected by DPAPI and the local machine/service context.

#### Mandatory Hardening Controls for Microsoft Entra Connect Servers:
- **Classify and Isolate as Tier 0**: Place the Entra Connect server computer object inside the Tier-0 Organizational Unit alongside Domain Controllers and Enterprise CAs; restrict local `Administrators` on the Entra Connect server exclusively to Tier-0 PAW accounts.
- **Prevent Cloud-to-On-Premises and On-Premises-to-Cloud Escalation**:
  - Never synchronize Tier-0 on-premises administrative accounts (`Domain Admins`, `Enterprise Admins`) to Microsoft Entra ID. Keep cloud `Global Administrators` as dedicated cloud-only accounts protected by phishing-resistant FIDO2 hardware security keys and Entra Privileged Identity Management (PIM).
  - Restrict the `MSOL_<hex>` account using GPO (`SeDenyInteractiveLogonRight`, `SeDenyNetworkLogonRight`) so it can only authenticate from the specific IP/Computer SID of the Entra Connect server.
  - Enable **Single Object Sync** auditing and monitor Event ID `4662` (`DS-Replication-Get-Changes-All`) to ensure the `MSOL_<hex>` account never initiates replication from any host other than the designated Entra Connect server IP.

### 45.7.3 Application Control (`WDAC` / `AppLocker`) and PowerShell Hardening

To prevent unauthorized binaries, unsigned scripts, or user-writable DLLs from executing on Domain Controllers, PAWs, and member servers, enterprise defense-in-depth combines **Application Control** with **PowerShell Security Telemetry**:

1. **Windows Defender Application Control (WDAC) & AppLocker**:
   - **Default AppLocker Rule Fallacy**: If an administrator enables AppLocker with only the "Default Rules" (which blindly allow anything inside `C:\Windows\*` and `C:\Program Files\*`), standard users can still copy executables or DLLs into legacy user-writable subdirectories inside `C:\Windows\` (such as `C:\Windows\Tasks`, `C:\Windows\Temp`, `C:\Windows\tracing`, or `C:\Windows\System32\spool\drivers\color`) and execute them!
   - **Hardened Rule Design**: Always pair path rules with explicit **Path Exceptions** blocking known user-writable subdirectories under `C:\Windows\`, enforce **DLL Rules** (`AppLocker -> DLL Rules`) so user-writable DLLs cannot be loaded into signed processes, or prefer **WDAC (Code Integrity Policies)** enforced at the kernel level (`ci.dll`) with Publisher/WHQL signature enforcement.
2. **PowerShell Security Baseline (PowerShell v5.1 / PowerShell 7+)**:
   - **Uninstall PowerShell v2.0 Engine**: PowerShell 2.0 lacks Script Block Logging, Module Logging, AMSI integration, and Constrained Language Mode. Remove it across all hosts to prevent version-downgrade (`powershell.exe -Version 2`) bypasses:
     ```powershell
     Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart
     ```
   - **Enable PowerShell Script Block Logging (`Event ID 4104`), Module Logging (`Event ID 4103`), and Transcription**:
     Records the full, de-obfuscated content of every PowerShell code block compiled by the engine into the `Microsoft-Windows-PowerShell/Operational` event log:
     ```powershell
     $psLogPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"
     New-Item -Path "$psLogPath\ScriptBlockLogging" -Force | Out-Null
     New-ItemProperty -Path "$psLogPath\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1 -PropertyType DWord -Force

     New-Item -Path "$psLogPath\ModuleLogging" -Force | Out-Null
     New-ItemProperty -Path "$psLogPath\ModuleLogging" -Name "EnableModuleLogging" -Value 1 -PropertyType DWord -Force

     New-Item -Path "$psLogPath\Transcription" -Force | Out-Null
     New-ItemProperty -Path "$psLogPath\Transcription" -Name "EnableTranscripting" -Value 1 -PropertyType DWord -Force
     New-ItemProperty -Path "$psLogPath\Transcription" -Name "OutputDirectory" -Value "\\logcollector.corp.example.lk\PSTranscripts$" -PropertyType String -Force
     New-ItemProperty -Path "$psLogPath\Transcription" -Name "EnableInvocationHeader" -Value 1 -PropertyType DWord -Force
     ```
   - **Enforce Just Enough Administration (JEA) for Delegated PowerShell Remoting**:
     Instead of granting Tier-1 or Tier-2 administrators full interactive local Administrator rights on servers via WinRM, configure **PowerShell Just Enough Administration (JEA)** role capability files (`.psrc`) and session configurations (`.pssc` running under a virtual transformation account `RunAsVirtualAccount = $true`). JEA restricts connecting administrators to a specific allowlist of cmdlets and parameters with `LanguageMode = 'NoLanguage'`, completely eliminating arbitrary command execution while still permitting operational administration.
