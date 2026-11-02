# Appendix D: Enterprise SIEM, Windows Event IDs, Linux Auditd, Sigma, YARA & Suricata Detection Encyclopedia

> **Academic & Operational Reference Scope**: This appendix provides an exhaustive engineering reference for Security Operations Center (SOC) analysts, Detection Engineers, Threat Hunters, and Digital Forensics and Incident Response (DFIR) practitioners. Every telemetry event, detection rule, and forensic artifact path documented herein follows enterprise production standards mapped to the MITRE ATT&CK v15 framework.

---

## Section 1: Complete Windows Security Event ID & Sysmon Event ID Reference

Windows enterprise telemetry relies on two complementary event architectures:
1. **Native Windows Security Auditing (`Microsoft-Windows-Security-Auditing`)**: Recorded in `%SystemRoot%\System32\Winevt\Logs\Security.evtx`, supplemented by PowerShell, WMI, Task Scheduler, and Active Directory Directory Service logs.
2. **System Monitor (`Microsoft-Windows-Sysmon/Operational`)**: Recorded in `%SystemRoot%\System32\Winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx`, providing kernel-level telemetry including cryptographic process hashes (SHA-256, IMPHASH), parent-child command lines, process hollowing/injection, DNS queries, and raw disk access.

### 1.1 Master Telemetry Matrix (65 Essential Windows & Sysmon Event IDs)

| Category | Event ID | Log Channel / Provider | Event Summary | Key XML `EventData` Fields | MITRE ATT&CK Mapping |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Authentication** | `4624` | `Security` | An account was successfully logged on | `TargetUserName`, `TargetDomainName`, `LogonType`, `IpAddress`, `WorkstationName`, `AuthenticationPackageName`, `LogonProcessName`, `ElevatedToken` | T1078, T1021 |
| **Authentication** | `4625` | `Security` | An account failed to log on | `TargetUserName`, `Status`, `SubStatus`, `LogonType`, `IpAddress`, `WorkstationName`, `FailureReason` | T1110.001, T1110.003 |
| **Authentication** | `4634` | `Security` | An account was logged off | `TargetUserName`, `TargetLogonId`, `LogonType` | T1078 |
| **Authentication** | `4647` | `Security` | User initiated logoff | `TargetUserName`, `TargetDomainName`, `TargetLogonId` | T1078 |
| **Authentication** | `4648` | `Security` | A logon was attempted using explicit credentials (`runas` / lateral movement) | `SubjectUserName`, `TargetUserName`, `TargetServerName`, `IpAddress`, `ProcessName` | T1021, T1134.001 |
| **Authentication** | `4672` | `Security` | Special privileges assigned to new logon (Admin equivalent) | `SubjectUserName`, `SubjectDomainName`, `PrivilegeList` (`SeDebugPrivilege`, `SeTcbPrivilege`, `SeBackupPrivilege`) | T1078.002, T1134 |
| **Authentication** | `4776` | `Security` | Domain Controller attempted to validate credentials for an account (NTLM) | `PackageName`, `TargetUserName`, `Workstation`, `ErrorCode` | T1550.002, T1110 |
| **Authentication** | `4778` | `Security` | A session was reconnected to a Window Station (RDP session resume) | `AccountName`, `SessionName`, `ClientName`, `ClientAddress` | T1021.001 |
| **Authentication** | `4779` | `Security` | A session was disconnected from a Window Station | `AccountName`, `SessionName`, `ClientName`, `ClientAddress` | T1021.001 |
| **Authentication** | `4800` | `Security` | The workstation was locked | `TargetUserName`, `TargetLogonId`, `SessionId` | T1078 |
| **Authentication** | `4801` | `Security` | The workstation was unlocked | `TargetUserName`, `TargetLogonId`, `SessionId` | T1078 |
| **Kerberos** | `4768` | `Security` | A Kerberos authentication ticket (TGT) was requested | `TargetUserName`, `ServiceName` (`krbtgt`), `TicketEncryptionType`, `PreAuthType`, `IpAddress`, `Status` | T1558.001, T1558.004 |
| **Kerberos** | `4769` | `Security` | A Kerberos service ticket (TGS) was requested | `TargetUserName`, `ServiceName`, `TicketEncryptionType` (`0x17` = RC4), `TicketOptions`, `IpAddress`, `Status` | T1558.003, T1550.003 |
| **Kerberos** | `4770` | `Security` | A Kerberos service ticket was renewed | `TargetUserName`, `ServiceName`, `IpAddress`, `TicketEncryptionType` | T1558 |
| **Kerberos** | `4771` | `Security` | Kerberos pre-authentication failed | `TargetUserName`, `FailureCode` (`0x18` = Bad Password, `0x12` = Account Disabled/Revoked), `PreAuthType`, `IpAddress` | T1110.003 |
| **Account Mgmt** | `4720` | `Security` | A user account was created | `TargetUserName`, `SubjectUserName`, `SamAccountName`, `UserPrincipalName`, `HomeDirectory` | T1136.001, T1136.002 |
| **Account Mgmt** | `4722` | `Security` | A user account was enabled | `TargetUserName`, `SubjectUserName`, `TargetSid` | T1098 |
| **Account Mgmt** | `4723` | `Security` | An attempt was made to change an account's password | `TargetUserName`, `SubjectUserName`, `PrivilegeList` | T1098 |
| **Account Mgmt** | `4724` | `Security` | An attempt was made to reset an account's password | `TargetUserName`, `SubjectUserName` | T1098 |
| **Account Mgmt** | `4725` | `Security` | A user account was disabled | `TargetUserName`, `SubjectUserName` | T1531 |
| **Account Mgmt** | `4726` | `Security` | A user account was deleted | `TargetUserName`, `SubjectUserName` | T1531 |
| **Account Mgmt** | `4728` | `Security` | A member was added to a security-enabled global group | `MemberName`, `MemberSid`, `TargetUserName` (Group Name), `SubjectUserName` | T1098 |
| **Account Mgmt** | `4732` | `Security` | A member was added to a security-enabled local group (`Administrators`) | `MemberName`, `MemberSid`, `TargetUserName`, `SubjectUserName` | T1098 |
| **Account Mgmt** | `4738` | `Security` | A user account was changed (UAC flags, SPN, Password Never Expires) | `TargetUserName`, `UserAccountControl`, `ServicePrincipalNames`, `SidHistory` | T1098, T1558.004 |
| **Account Mgmt** | `4740` | `Security` | A user account was locked out | `TargetUserName`, `TargetDomainName` (Caller Computer Name), `SubjectUserName` | T1110 |
| **Account Mgmt** | `4741` | `Security` | A computer account was created (`MachineAccountQuota` abuse) | `TargetUserName`, `SubjectUserName`, `DnsHostName`, `ServicePrincipalNames` | T1136.002 |
| **Account Mgmt** | `4756` | `Security` | A member was added to a security-enabled universal group (`Enterprise Admins`) | `MemberName`, `TargetUserName`, `SubjectUserName` | T1098 |
| **Process / Exec** | `4688` | `Security` | A new process has been created | `NewProcessName`, `CommandLine`, `CreatorProcessName`, `TokenElevationType`, `SubjectUserName` | T1059 |
| **Process / Exec** | `4689` | `Security` | A process has exited | `ProcessName`, `ProcessId`, `Status` | T1059 |
| **Services / Tasks** | `4697` | `Security` | A service was installed in the system | `ServiceName`, `ServiceFileName`, `ServiceType`, `ServiceStartType`, `ServiceAccount` | T1543.003, T1569.002 |
| **Services / Tasks** | `7045` | `System` | A service was installed in the system (Service Control Manager) | `ServiceName`, `ImagePath`, `ServiceType`, `StartType`, `AccountName` | T1543.003 |
| **Services / Tasks** | `4698` | `Security` | A scheduled task was created | `TaskName`, `TaskContent` (XML payload), `SubjectUserName` | T1053.005 |
| **Services / Tasks** | `4699` | `Security` | A scheduled task was deleted | `TaskName`, `SubjectUserName` | T1070 |
| **Services / Tasks** | `4702` | `Security` | A scheduled task was updated | `TaskName`, `TaskContent`, `SubjectUserName` | T1053.005 |
| **Shares / Files** | `5140` | `Security` | A network share object was accessed | `ShareName` (`\\*\IPC$`, `\\*\ADMIN$`, `\\*\C$`), `IpAddress`, `SubjectUserName`, `AccessMask` | T1021.002 |
| **Shares / Files** | `5145` | `Security` | A network share object was checked for access permissions | `ShareName`, `RelativeTargetName` (`samr`, `lsarpc`, `srvsvc`, `atsvc`), `IpAddress`, `AccessList` | T1021.002, T1003.006 |
| **Registry / Audit** | `4657` | `Security` | A registry value was modified | `ObjectName`, `ObjectValueName`, `OldValue`, `NewValue`, `ProcessName` | T1112, T1547.001 |
| **Registry / Audit** | `1102` | `Security` | The audit log was cleared (`wevtutil cl Security`) | `SubjectUserName`, `SubjectDomainName`, `SubjectLogonId` | T1070.001 |
| **Registry / Audit** | `4719` | `Security` | System audit policy was changed (`auditpol`) | `SubjectUserName`, `CategoryId`, `SubcategoryGuid`, `AuditPolicyChanges` | T1562.002 |
| **Firewall** | `5156` | `Security` | Windows Filtering Platform (WFP) permitted a connection | `Application`, `Direction`, `SourceAddress`, `SourcePort`, `DestAddress`, `DestPort`, `Protocol` | T1071 |
| **Firewall** | `4946` | `Security` | A change has been made to Windows Firewall exception list (Rule Added) | `ProfileChanged`, `RuleId`, `RuleName` | T1562.004 |
| **AD Directory** | `4662` | `Security` | An operation was performed on an Active Directory object (DCSync) | `ObjectName`, `Properties` (`1131f6aa-...`, `1131f6ad-...` = Replicating Directory Changes), `SubjectUserName` | T1003.006 |
| **AD Directory** | `5136` | `Security` | A directory service object was modified (ACL, GPO, RBCD, Shadow Creds) | `ObjectDN`, `ObjectClass`, `AttributeLDAPDisplayName` (`ntSecurityDescriptor`, `msDS-AllowedToActOnBehalfOfOtherIdentity`, `msDS-KeyCredentialLink`), `AttributeValue` | T1484, T1098.005 |
| **PowerShell** | `4103` | `Microsoft-Windows-PowerShell/Operational` | Module Logging (Pipeline execution & cmdlet parameter bindings) | `ContextInfo`, `Payload` (`CommandInvocation`, `ParameterBinding`) | T1059.001 |
| **PowerShell** | `4104` | `Microsoft-Windows-PowerShell/Operational` | Script Block Logging (Full de-obfuscated PowerShell script block content) | `ScriptBlockText`, `ScriptBlockId`, `MessageNumber`, `MessageTotal`, `Path` | T1059.001 |
| **WMI** | `5861` | `Microsoft-Windows-WMI-Activity/Operational` | Permanent WMI Event Subscription (`__FilterToConsumerBinding`) | `Namespace`, `ESS`, `CONSUMER` (`CommandLineEventConsumer`, `ActiveScriptEventConsumer`), `PossibleCause` | T1546.003 |
| **Sysmon** | `1` | `Microsoft-Windows-Sysmon/Operational` | Process Creation | `Image`, `CommandLine`, `ParentImage`, `ParentCommandLine`, `Hashes` (`SHA256`, `IMPHASH`), `OriginalFileName`, `User`, `IntegrityLevel` | T1059, T1036 |
| **Sysmon** | `2` | `Microsoft-Windows-Sysmon/Operational` | A process changed a file creation time (Timestomping) | `Image`, `TargetFilename`, `CreationUtcTime`, `PreviousCreationUtcTime` | T1070.006 |
| **Sysmon** | `3` | `Microsoft-Windows-Sysmon/Operational` | Network connection detected | `Image`, `User`, `Protocol`, `Initiated`, `SourceIp`, `DestinationIp`, `DestinationHostname`, `DestinationPort` | T1071, T1041 |
| **Sysmon** | `5` | `Microsoft-Windows-Sysmon/Operational` | Process terminated | `Image`, `ProcessGuid`, `ProcessId`, `User` | T1059 |
| **Sysmon** | `6` | `Microsoft-Windows-Sysmon/Operational` | Driver loaded into kernel (`BYOVD` - Bring Your Own Vulnerable Driver) | `ImageLoaded`, `Hashes`, `Signed`, `Signature`, `SignatureStatus` | T1068, T1547.006 |
| **Sysmon** | `7` | `Microsoft-Windows-Sysmon/Operational` | Image loaded (DLL sideloading / Reflective DLL injection) | `Image`, `ImageLoaded`, `Signed`, `Signature`, `OriginalFileName`, `Hashes` | T1574.002, T1055.001 |
| **Sysmon** | `8` | `Microsoft-Windows-Sysmon/Operational` | `CreateRemoteThread` detected (Process Injection) | `SourceImage`, `TargetImage` (`lsass.exe`, `svchost.exe`), `StartAddress`, `StartModule`, `StartFunction` | T1055 |
| **Sysmon** | `9` | `Microsoft-Windows-Sysmon/Operational` | RawAccessRead detected (Direct volume read of `\\.\C:` to copy `NTDS.dit`/`SAM`) | `Image`, `Device` | T1003.002, T1003.003 |
| **Sysmon** | `10` | `Microsoft-Windows-Sysmon/Operational` | ProcessAccess detected (Memory read of `lsass.exe`) | `SourceImage`, `TargetImage`, `GrantedAccess` (`0x1010`, `0x1410`, `0x1fffff`), `CallTrace` | T1003.001 |
| **Sysmon** | `11` | `Microsoft-Windows-Sysmon/Operational` | FileCreate (Dropper creation, startup folder persistence) | `Image`, `TargetFilename`, `CreationUtcTime`, `User` | T1105, T1547.001 |
| **Sysmon** | `12` | `Microsoft-Windows-Sysmon/Operational` | RegistryEvent (Object create and delete) | `EventType`, `Image`, `TargetObject`, `User` | T1112, T1547.001 |
| **Sysmon** | `13` | `Microsoft-Windows-Sysmon/Operational` | RegistryEvent (Value Set) | `EventType` (`SetValue`), `Image`, `TargetObject`, `Details` | T1547.001, T1112 |
| **Sysmon** | `15` | `Microsoft-Windows-Sysmon/Operational` | FileCreateStreamHash (Zone.Identifier Mark-of-the-Web & ADS payloads) | `Image`, `TargetFilename`, `Hash`, `Contents` (`ZoneId=3`, `HostUrl`) | T1564.004, T1553.005 |
| **Sysmon** | `17` | `Microsoft-Windows-Sysmon/Operational` | PipeEvent (Named Pipe Created — Cobalt Strike / PsExec / Potato exploits) | `EventType` (`CreatePipe`), `Image`, `PipeName` (`\msagent_*`, `\postex_*`, `\PSEXESVC`) | T1570, T1055 |
| **Sysmon** | `18` | `Microsoft-Windows-Sysmon/Operational` | PipeEvent (Named Pipe Connected) | `EventType` (`ConnectPipe`), `Image`, `PipeName` | T1021.002 |
| **Sysmon** | `22` | `Microsoft-Windows-Sysmon/Operational` | DNSEvent (DNS query initiated by process) | `Image`, `QueryName`, `QueryStatus`, `QueryResults` | T1071.004 |
| **Sysmon** | `23` | `Microsoft-Windows-Sysmon/Operational` | FileDelete (File Delete archived by Sysmon) | `Image`, `TargetFilename`, `Hashes`, `IsExecutable`, `Archived` | T1070.004 |
| **Sysmon** | `25` | `Microsoft-Windows-Sysmon/Operational` | ProcessTampering (Process Herpaderping / Process Hollowing / Ghosting) | `Image`, `Type` (`Image is replaced`, `Image is locked for access`), `User` | T1055.012, T1055.013 |
| **Sysmon** | `26` | `Microsoft-Windows-Sysmon/Operational` | FileDeleteDetected (Logs file deletion without archiving binary) | `Image`, `TargetFilename`, `Hashes`, `IsExecutable` | T1070.004 |

---

### 1.2 Reference Sub-Tables: Logon Types, Failure Codes & LSASS Access Masks

#### Windows Event 4624/4625 `LogonType` Reference
| LogonType | Name | Operational Meaning & Threat Hunting Context |
| :--- | :--- | :--- |
| `2` | **Interactive** | Physical console login, KVM, or RDP when RestrictedAdmin/Remote Guard is not used in specific configurations. |
| `3` | **Network** | SMB, RPC, WinRM (`Enter-PSSession`), PsExec network auth, Pass-the-Hash (`sekurlsa::pth`). No cached credentials stored. |
| `4` | **Batch** | Scheduled Task execution running under stored user credentials. |
| `5` | **Service** | Windows Service startup under a configured service account. |
| `7` | **Unlock** | Console unlock of a locked workstation session. |
| `8` | **NetworkCleartext** | Network logon where cleartext password was passed (IIS Basic Auth, WinRM Basic Auth). |
| `9` | **NewCredentials** | `runas /netonly` or `sekurlsa::pth` (Overpass-the-Hash / Pass-the-Hash spawning local token with alternate network credentials). **Critical hunting target**: `LogonType=9` with `LogonProcessName="seclogo"`. |
| `10` | **RemoteInteractive** | Standard Terminal Services / Remote Desktop Protocol (RDP) graphical session. |
| `11` | **CachedInteractive** | Logon using locally cached domain credentials (`DCC2` / MSCash2) when Domain Controller is unreachable. |

#### Windows Event 4625 `Status` & `SubStatus` Hex Codes
| Hex Code | Meaning | Threat Implication |
| :--- | :--- | :--- |
| `0xC0000064` | User name does not exist | Username enumeration / spraying against non-existent accounts. |
| `0xC000006A` | User name is correct but the password is wrong | Password spraying / brute-force against valid accounts. |
| `0xC0000234` | User is currently locked out | Account lockout triggered by brute-force threshold. |
| `0xC0000072` | Account is currently disabled | Attempted use of decommissioned or Honeytoken account. |
| `0xC0000193` | Account has expired | Attempted use of expired contractor/vendor account. |
| `0xC000015B` | The user has not been granted the requested logon type | Lateral movement blocked by GPO (`SeDenyNetworkLogonRight` / `SeDenyRemoteInteractiveLogonRight`). |

---

### 1.3 Deep XML Schema Inspection & Dual KQL / SPL Investigation Queries

#### Case Study 1: Kerberoasting Detection (`EventID 4769` with RC4 Downgrade)
When an adversary executes `Rubeus.exe kerberoast` or Impacket's `GetUserSPNs.py`, they request Kerberos Service Tickets (TGS) for accounts with registered Service Principal Names (`SPNs`), requesting `RC4_HMAC_MD5` (`0x17`) encryption for offline GPU cracking.

**Raw XML Event Structure (`EventID 4769`)**:
```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" />
    <EventID>4769</EventID>
    <Channel>Security</Channel>
    <Computer>DC01.corp.local</Computer>
  </System>
  <EventData>
    <Data Name="TargetUserName">jdoe@CORP.LOCAL</Data>
    <Data Name="TargetDomainName">CORP.LOCAL</Data>
    <Data Name="ServiceName">svc_mssql</Data>
    <Data Name="ServiceSid">S-1-5-21-3842939050-189203910-291048291-1109</Data>
    <Data Name="TicketOptions">0x40810000</Data>
    <Data Name="TicketEncryptionType">0x17</Data>
    <Data Name="IpAddress">::ffff:10.20.30.115</Data>
    <Data Name="IpPort">59412</Data>
    <Data Name="Status">0x0</Data>
  </EventData>
</Event>
```

**Microsoft Sentinel (KQL)**:
```kql
SecurityEvent
| where EventID == 4769
| parse EventData with * 'TicketEncryptionType">' TicketEncryptionType "<" *
| parse EventData with * 'ServiceName">' ServiceName "<" *
| parse EventData with * 'Status">' Status "<" *
| where Status == "0x0"
| where TicketEncryptionType in ("0x17", "0x18")
| where ServiceName !endswith "$" and ServiceName != "krbtgt"
| where TargetUserName !endswith "$"
| summarize RequestedSPNs = make_set(ServiceName), TicketCount = count() by TargetUserName, IpAddress, bin(TimeGenerated, 5m)
| where TicketCount >= 1
| project TimeGenerated, TargetUserName, IpAddress, TicketCount, RequestedSPNs
```

**Splunk Enterprise (SPL)**:
```spl
index=wineventlog source="WinEventLog:Security" EventCode=4769 Status="0x0"
  (Ticket_Encryption_Type="0x17" OR Ticket_Encryption_Type="0x18")
  NOT Service_Name="*$" NOT Service_Name="krbtgt" NOT Account_Name="*$"
| bucket _time span=5m
| stats dc(Service_Name) as UniqueSPNs, values(Service_Name) as RequestedSPNs, count by _time, Account_Name, Client_Address
| where UniqueSPNs >= 1
| table _time, Account_Name, Client_Address, UniqueSPNs, RequestedSPNs
```

---

#### Case Study 2: Active Directory DCSync Replication Attack (`EventID 4662`)
When an attacker uses `lsadump::dcsync` in Mimikatz or Impacket's `secretsdump.py` over the MS-DRSR (`drsuapi`) RPC interface, the Domain Controller logs `EventID 4662` with the DS-Replication-Get-Changes (`1131f6aa-9c07-11d1-f79f-00c04fc2dcd2`), DS-Replication-Get-Changes-All (`1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`), or DS-Replication-Get-Changes-In-Filtered-Set (`89e95b76-444d-4c62-991a-0facbeda640c`) extended rights GUIDs.

**Microsoft Sentinel (KQL)**:
```kql
SecurityEvent
| where EventID == 4662
| where AccessMask == "0x100" // Control Access (Extended Right)
| where Properties has_any (
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",
    "89e95b76-444d-4c62-991a-0facbeda640c",
    "Replicating Directory Changes All"
)
| where SubjectUserName !endswith "$" and not(SubjectUserName startswith "MSOL_")
| project TimeGenerated, Computer, SubjectDomainName, SubjectUserName, SubjectUserSid, ObjectName, Properties
```

**Splunk Enterprise (SPL)**:
```spl
index=wineventlog source="WinEventLog:Security" EventCode=4662 Access_Mask="0x100"
  (Properties="*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*" OR
   Properties="*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*" OR
   Properties="*89e95b76-444d-4c62-991a-0facbeda640c*")
  NOT SubjectUserName="*$" NOT SubjectUserName="MSOL_*"
| table _time, host, SubjectDomainName, SubjectUserName, ObjectName, Properties
```

---

#### Case Study 3: LSASS Memory Credential Dumping (`Sysmon EventID 10`)
Tools such as Mimikatz (`sekurlsa::logonpasswords`), `nanodump`, `pypykatz`, and `comsvcs.dll` (`MiniDump`) open a handle to `C:\Windows\System32\lsass.exe` requesting `PROCESS_VM_READ` (`0x0010`) combined with `PROCESS_QUERY_INFORMATION` (`0x0400`) or `PROCESS_QUERY_LIMITED_INFORMATION` (`0x1000`), producing `GrantedAccess` masks such as `0x1010`, `0x1410`, `0x1438`, `0x143a`, or `0x1fffff`.

**Microsoft Sentinel (KQL)**:
```kql
Event
| where Source == "Microsoft-Windows-Sysmon" and EventID == 10
| extend EvData = parse_xml(EventData)
| extend SourceImage = tostring(EvData.DataItem.EventData.Data[4].["#text"]),
         TargetImage = tostring(EvData.DataItem.EventData.Data[8].["#text"]),
         GrantedAccess = tostring(EvData.DataItem.EventData.Data[9].["#text"]),
         CallTrace = tostring(EvData.DataItem.EventData.Data[10].["#text"])
| where TargetImage endswith "\\lsass.exe"
| where GrantedAccess in ("0x1010", "0x1410", "0x1438", "0x143a", "0x1fffff", "0x0010")
| where not(SourceImage in~ (
    "C:\\Program Files\\Windows Defender\\MsMpEng.exe",
    "C:\\Windows\\System32\\wbem\\wmiprvse.exe",
    "C:\\Windows\\System32\\svchost.exe"
)) or CallTrace has "comsvcs.dll" or CallTrace has "dbghelp.dll" or CallTrace has "dbgcore.dll" or CallTrace has "UNKNOWN"
| project TimeGenerated, Computer, SourceImage, TargetImage, GrantedAccess, CallTrace
```

**Splunk Enterprise (SPL)**:
```spl
index=sysmon EventCode=10 TargetImage="*\\lsass.exe"
  GrantedAccess IN ("0x1010", "0x1410", "0x1438", "0x143a", "0x1fffff", "0x1f0fff", "0x0010")
| where NOT (like(SourceImage, "%\\MsMpEng.exe") AND NOT like(CallTrace, "%UNKNOWN%"))
| eval SuspiciousTrace=if(match(CallTrace, "(?i)(dbgcore\.dll|dbghelp\.dll|comsvcs\.dll|UNKNOWN)"), "HIGH", "MEDIUM")
| table _time, host, User, SourceImage, TargetImage, GrantedAccess, SuspiciousTrace, CallTrace
```

---

#### Case Study 4: Resource-Based Constrained Delegation (RBCD) & Shadow Credentials (`EventID 5136`)
When an attacker modifies `msDS-AllowedToActOnBehalfOfOtherIdentity` (RBCD) or `msDS-KeyCredentialLink` (Whisker / Shadow Credentials) on a computer or user object in Active Directory, Event `5136` records the LDAP attribute modification.

**Microsoft Sentinel (KQL)**:
```kql
SecurityEvent
| where EventID == 5136
| parse EventData with * 'ObjectDN">' ObjectDN "<" *
| parse EventData with * 'AttributeLDAPDisplayName">' AttributeLDAPDisplayName "<" *
| parse EventData with * 'AttributeValue">' AttributeValue "<" *
| parse EventData with * 'OperationType">' OperationType "<" *
| where AttributeLDAPDisplayName in~ (
    "msDS-AllowedToActOnBehalfOfOtherIdentity",
    "msDS-KeyCredentialLink",
    "ntSecurityDescriptor",
    "scriptPath",
    "gPCFileSysPath"
)
| project TimeGenerated, Computer, SubjectUserName, OperationType, ObjectDN, AttributeLDAPDisplayName, AttributeValue
```

**Splunk Enterprise (SPL)**:
```spl
index=wineventlog source="WinEventLog:Security" EventCode=5136
  AttributeLDAPDisplayName IN ("msDS-AllowedToActOnBehalfOfOtherIdentity", "msDS-KeyCredentialLink", "ntSecurityDescriptor", "gPCFileSysPath")
| table _time, host, SubjectUserName, OperationType, ObjectDN, AttributeLDAPDisplayName, AttributeValue
```

---

#### Case Study 5: Malicious PowerShell ScriptBlock Logging (`EventID 4104`)
PowerShell Script Block Logging (`EventID 4104`) captures the full de-obfuscated code block executed by the PowerShell engine at runtime, even if the initial command line was Base64-encoded (`-EncodedCommand`) or compressed.

**Microsoft Sentinel (KQL)**:
```kql
Event
| where Source == "Microsoft-Windows-PowerShell" and EventID == 4104
| extend ScriptBlockText = tostring(parse_xml(EventData).DataItem.EventData.Data[2].["#text"])
| where ScriptBlockText has_any (
    "AmsiUtils", "amsiInitFailed", "System.Reflection.Assembly",
    "Invoke-Mimikatz", "FromBase64String", "Net.WebClient",
    "DownloadString", "VirtualAlloc", "CreateThread", "MiniDumpWriteDump"
)
| project TimeGenerated, Computer, UserName, ScriptBlockText
```

**Splunk Enterprise (SPL)**:
```spl
index=wineventlog source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104
| where match(ScriptBlockText, "(?i)(AmsiUtils|amsiInitFailed|Invoke-Mimikatz|VirtualAlloc|MiniDumpWriteDump|DownloadString|Reflection\.Assembly)")
| table _time, host, UserID, Path, ScriptBlockId, ScriptBlockText
```

---

## Section 2: Linux `auditd` & Syslog Telemetry Reference

The Linux Audit Subsystem (`kauditd` in kernel space and `auditd` in user space) intercepts system calls (`syscalls`) at the VFS and kernel entry/exit boundary, logging structured key-value telemetry to `/var/log/audit/audit.log`.

### 2.1 Linux `auditd` Record Types
Every `auditd` event shares a unique timestamp and serial number (`msg=audit(1730541200.412:8942):`) that groups multiple record lines into a single atomic event:
- **`type=SYSCALL`**: Captures the syscall number (`syscall=59` for `execve` on `x86_64`), return value (`exit=0`), success status (`success=yes`), Real User ID (`uid`), Effective User ID (`euid`), Audit User ID (`auid` / loginuid — immutable across `sudo`/`su` transitions!), Process ID (`pid`), Parent PID (`ppid`), executable path (`exe="/usr/bin/bash"`), and audit rule key (`key="priv_esc"`).
- **`type=EXECVE`**: Captures full command-line argument count (`argc`) and individual arguments (`a0`, `a1`, `a2`, ...; hex-encoded if containing spaces or control characters).
- **`type=CWD`**: Captures the current working directory (`cwd="/tmp"`) at the time of syscall invocation.
- **`type=PATH`**: Captures file system inode metadata, permissions (`mode=0100755`), owner (`ouid`), and path name (`nametype=NORMAL`, `CREATE`, `DELETE`).
- **`type=SOCKADDR`**: Captures raw socket address structures (`saddr=0200115C0A000001...` where `0200` = `AF_INET`, `115C` = port `4444`, `0A000001` = IP `10.0.0.1`).
- **`type=PROCTITLE`**: Hex-encoded full process title as visible in `/proc/<pid>/cmdline`.

### 2.2 Production `/etc/audit/rules.d/99-enterprise-hardening.rules` Configuration

```ini
## ============================================================================
## ENTERPRISE LINUX AUDITD CONFIGURATION (/etc/audit/rules.d/99-hardening.rules)
## Architecture: x86_64 (b64) & i386/32-bit compatibility (b32)
## ============================================================================

# 1. Remove any existing rules and configure kernel buffer & failure parameters
-D
# Set kernel backlog buffer to 16384 messages to prevent drop during burst activity
-b 16384
# Failure mode: 1 = printk to dmesg/syslog, 2 = kernel panic (high-security environments)
-f 1
# Ignore current working directory records if excessive, or keep for forensics
--backlog_wait_time 60000

## ----------------------------------------------------------------------------
## IDENTITY, AUTHENTICATION & PRIVILEGE CONFIGURATION MONITORING (MITRE T1098/T1136)
## ----------------------------------------------------------------------------
-w /etc/passwd -p wa -k identity_modification
-w /etc/shadow -p wa -k shadow_credential_access
-w /etc/group -p wa -k group_modification
-w /etc/gshadow -p wa -k gshadow_modification
-w /etc/security/opasswd -p wa -k password_history_mod

# Monitor sudoers configuration and drop-in privilege rules (MITRE T1548.003)
-w /etc/sudoers -p wa -k sudoers_modification
-w /etc/sudoers.d/ -p wa -k sudoers_modification

# Monitor PAM configuration and NSSwitch (MITRE T1556.003)
-w /etc/pam.d/ -p wa -k pam_configuration
-w /etc/nsswitch.conf -p wa -k nsswitch_modification

# Monitor SSH daemon configuration and root authorized_keys (MITRE T1098.004)
-w /etc/ssh/sshd_config -p wa -k sshd_config_modification
-w /etc/ssh/sshd_config.d/ -p wa -k sshd_config_modification
-w /root/.ssh/ -p wa -k root_ssh_keys

## ----------------------------------------------------------------------------
## PERSISTENCE MECHANISMS: CRON, SYSTEMD, INIT, LD.SO.PRELOAD (MITRE T1053/T1543/T1574)
## ----------------------------------------------------------------------------
-w /etc/crontab -p wa -k cron_persistence
-w /etc/cron.allow -p wa -k cron_persistence
-w /etc/cron.deny -p wa -k cron_persistence
-w /etc/cron.d/ -p wa -k cron_persistence
-w /etc/cron.daily/ -p wa -k cron_persistence
-w /etc/cron.hourly/ -p wa -k cron_persistence
-w /etc/cron.monthly/ -p wa -k cron_persistence
-w /etc/cron.weekly/ -p wa -k cron_persistence
-w /var/spool/cron/ -p wa -k cron_persistence

# Systemd Services, Generators, and Timers (MITRE T1543.002)
-w /etc/systemd/system/ -p wa -k systemd_persistence
-w /usr/lib/systemd/system/ -p wa -k systemd_persistence
-w /run/systemd/system/ -p wa -k systemd_persistence
-w /etc/systemd/system-generators/ -p wa -k systemd_generator_persistence

# Dynamic Linker Hijacking / Userland Rootkits (MITRE T1574.006)
-w /etc/ld.so.preload -p wa -k ld_so_preload_rootkit
-w /etc/ld.so.conf -p wa -k ld_so_conf_modification
-w /etc/ld.so.conf.d/ -p wa -k ld_so_conf_modification

# Shell Profiles & RC Persistence (MITRE T1546.004)
-w /etc/profile -p wa -k shell_profile_mod
-w /etc/profile.d/ -p wa -k shell_profile_mod
-w /etc/bash.bashrc -p wa -k shell_profile_mod
-w /etc/zsh/ -p wa -k shell_profile_mod

## ----------------------------------------------------------------------------
## PRIVILEGE ESCALATION, SUID/SGID & CAPABILITIES (MITRE T1548.001)
## ----------------------------------------------------------------------------
# Audit all executions where Effective UID (euid=0) differs from real UID (SUID root execution)
-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k suid_root_exec
-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -k suid_root_exec

# Audit all executions where Effective GID differs from real GID (SGID execution)
-a always,exit -F arch=b64 -S execve -C gid!=egid -k sgid_exec
-a always,exit -F arch=b32 -S execve -C gid!=egid -k sgid_exec

# Audit chmod/fchmod/fchmodat setting SUID/SGID bits and extended file attributes (POSIX capabilities)
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -k capabilities_mod

## ----------------------------------------------------------------------------
## KERNEL MODULE LOADING & EBPF / KEXEC TAMPERING (MITRE T1547.006 / T1014)
## ----------------------------------------------------------------------------
-w /sbin/insmod -p x -k kernel_module_tools
-w /sbin/rmmod -p x -k kernel_module_tools
-w /sbin/modprobe -p x -k kernel_module_tools
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module,create_module -k kernel_module_syscall
-a always,exit -F arch=b64 -S kexec_load,kexec_file_load -k kexec_syscall
-a always,exit -F arch=b64 -S bpf -F auid>=1000 -F auid!=unset -k ebpf_program_load

## ----------------------------------------------------------------------------
## PROCESS INJECTION & MEMORY EXECUTION (MITRE T1055.008 / T1620)
## ----------------------------------------------------------------------------
# Detect ptrace process injection / debugging of other processes
-a always,exit -F arch=b64 -S ptrace -F a0=0x4 -k ptrace_poke_text
-a always,exit -F arch=b64 -S ptrace -F a0=0x5 -k ptrace_poke_data
-a always,exit -F arch=b64 -S ptrace -F a0=0x6 -k ptrace_poke_user
-a always,exit -F arch=b64 -S ptrace -k ptrace_activity

# Detect fileless execution via memfd_create (in-memory anonymous ELF execution)
-a always,exit -F arch=b64 -S memfd_create -k fileless_memfd_exec

## ----------------------------------------------------------------------------
## NETWORK SOCKET CONNECTIONS & PACKET CAPTURE (MITRE T1071 / T1049)
## ----------------------------------------------------------------------------
# Audit outbound IPv4 (a0=2 / AF_INET) and IPv6 (a0=10 / AF_INET6) socket connections
-a always,exit -F arch=b64 -S connect -F a0=2 -k network_connect_ipv4
-a always,exit -F arch=b64 -S connect -F a0=10 -k network_connect_ipv6
-a always,exit -F arch=b64 -S accept,accept4,bind,listen -F auid>=1000 -F auid!=unset -k network_listen_socket

## ----------------------------------------------------------------------------
## LOG TAMPERING & AUDIT IMMUTABILITY (MITRE T1070.002)
## ----------------------------------------------------------------------------
-w /var/log/audit/ -p wa -k audit_log_tampering
-w /etc/audit/ -p wa -k audit_config_tampering
-w /var/log/wtmp -p wa -k session_log_tampering
-w /var/log/btmp -p wa -k session_log_tampering
-w /var/log/lastlog -p wa -k session_log_tampering

# Lock audit configuration in kernel until next system reboot (2 = immutable)
-e 2
```

### 2.3 `ausearch` & `aureport` Investigation Reference
- **Search by Audit Key and decode hex strings (`-i`)**:
  ```bash
  ausearch -k suid_root_exec -i
  ausearch -k fileless_memfd_exec -i
  ausearch -k network_connect_ipv4 -i --start today
  ```
- **Trace a compromised user across `sudo` transitions using `auid` (Audit Login UID)**:
  Even after an attacker runs `sudo su -` (changing `uid=0` and `euid=0`), their `auid` remains their initial SSH login UID (e.g., `auid=1001`):
  ```bash
  ausearch -ua 1001 -i
  ```
- **Generate Summary Reports of Anomalies, Failed Syscalls, and Executables**:
  ```bash
  aureport --summary
  aureport -x --summary      # Summary of all executed binaries
  aureport -au --failed      # Summary of failed authentication attempts
  aureport -k --summary      # Summary of triggered audit keys
  ```

---

## Section 3: 25 Production-Ready Sigma Rules Mapped to MITRE ATT&CK

Sigma is an open, vendor-agnostic generic signature format for SIEM systems (`sigmac` / `sigma-cli` compiles Sigma YAML into KQL, Splunk SPL, Elastic EQL/Lucene, and QRadar AQL). Below are 25 production-grade Sigma rules spanning Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Command & Control, and Impact.

### Sigma Rule 01: Suspicious Office Macro Spawning Shell or Scripting Interpreter
```yaml
title: Microsoft Office Product Spawning Suspicious Child Process
id: 438025f9-5856-4663-83f7-52f878a70a50
status: production
description: Detects a Microsoft Office application (Word, Excel, PowerPoint, Publisher, Visio) spawning a command interpreter, scripting engine, or LOLBin indicative of malicious VBA macro, XLM 4.0 macro, or DDE exploitation.
author: Sri Lankan Elite Hacker's Bible Detection Engineering Team
date: 2026/11/02
tags:
  - attack.initial_access
  - attack.execution
  - attack.t1566.001
  - attack.t1204.002
  - attack.t1059
logsource:
  category: process_creation
  product: windows
detection:
  selection_parent:
    ParentImage|endswith:
      - '\WINWORD.EXE'
      - '\EXCEL.EXE'
      - '\POWERPNT.EXE'
      - '\MSPUB.EXE'
      - '\VISIO.EXE'
      - '\MSACCESS.EXE'
  selection_child_img:
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\pwsh.exe'
      - '\wscript.exe'
      - '\cscript.exe'
      - '\mshta.exe'
      - '\regsvr32.exe'
      - '\rundll32.exe'
      - '\certutil.exe'
      - '\bitsadmin.exe'
      - '\schtasks.exe'
      - '\wmic.exe'
  selection_child_orig:
    OriginalFileName:
      - 'Cmd.Exe'
      - 'PowerShell.EXE'
      - 'pwsh.dll'
      - 'wscript.exe'
      - 'cscript.exe'
      - 'mshta.exe'
      - 'REGSVR32.EXE'
      - 'RUNDLL32.EXE'
  condition: selection_parent and (selection_child_img or selection_child_orig)
falsepositives:
  - Legacy enterprise ERP add-ins invoking batch scripts from Excel
level: high
```

### Sigma Rule 02: Encoded or Download-Cradle PowerShell Execution
```yaml
title: Suspicious Encoded or Web Download Cradle PowerShell Command Line
id: b7a94c12-1e2f-49d0-9b14-31a82e9f0002
status: production
description: Detects PowerShell execution combining hidden windows, execution policy bypass, encoded commands, or in-memory web download cradles (IEX, DownloadString, Invoke-WebRequest).
author: Sri Lankan Elite Hacker's Bible Detection Engineering Team
date: 2026/11/02
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  category: process_creation
  product: windows
detection:
  selection_img:
    - Image|endswith:
        - '\powershell.exe'
        - '\pwsh.exe'
    - OriginalFileName:
        - 'PowerShell.EXE'
        - 'pwsh.dll'
  selection_encoded:
    CommandLine|contains:
      - ' -e '
      - ' -en '
      - ' -enc '
      - ' -enco '
      - ' -encodedcommand '
      - 'FromBase64String'
  selection_cradle:
    CommandLine|contains:
      - 'Net.WebClient'
      - 'DownloadString'
      - 'DownloadData'
      - 'DownloadFile'
      - 'Invoke-Expression'
      - 'IEX('
      - 'IEX '
      - 'AMSIUtils'
      - 'Reflection.Assembly]::Load'
  condition: selection_img and (selection_encoded or selection_cradle)
falsepositives:
  - Administrative SCCM/Intune deployment scripts using encoded blocks
level: high
```

### Sigma Rule 03: Certutil Used for Remote File Download or Base64 Decoding
```yaml
title: Certutil LOLBin Malicious Download or Decode Execution
id: 6d4e21a8-9f11-48c2-822e-7b9310f40003
status: production
description: Detects abuse of Windows certutil.exe utility to download remote payloads (-urlcache, -verifyctl) or decode Base64/Hex staged payloads (-decode, -decodehex).
author: Sri Lankan Elite Hacker's Bible Detection Engineering Team
date: 2026/11/02
tags:
  - attack.defense_evasion
  - attack.command_and_control
  - attack.t1105
  - attack.t1140
logsource:
  category: process_creation
  product: windows
detection:
  selection_img:
    - Image|endswith: '\certutil.exe'
    - OriginalFileName: 'CertUtil.exe'
  selection_cli:
    CommandLine|contains:
      - 'urlcache'
      - 'verifyctl'
      - '-decode'
      - '/decode'
      - '-decodehex'
      - '/decodehex'
  condition: selection_img and selection_cli
falsepositives:
  - Legitimate PKI certificate troubleshooting by domain administrators
level: high
```

### Sigma Rule 04: Regsvr32 Squiblydoo AppLocker Bypass & Remote Scriptlet Execution
```yaml
title: Regsvr32 Squiblydoo COM Scriptlet Execution
id: 9012b4f3-5c21-4e78-b910-81d3c4e20004
status: production
description: Detects regsvr32.exe loading remote or local COM scriptlets via scrobj.dll (/i:http or scrobj.dll) to bypass application allowlisting.
author: Sri Lankan Elite Hacker's Bible Detection Engineering Team
date: 2026/11/02
tags:
  - attack.defense_evasion
  - attack.t1218.010
logsource:
  category: process_creation
  product: windows
detection:
  selection_img:
    - Image|endswith: '\regsvr32.exe'
    - OriginalFileName: 'REGSVR32.EXE'
  selection_flags:
    CommandLine|contains:
      - 'scrobj'
      - '/i:http'
      - '/i:ftp'
      - '-i:http'
      - '/u /n /s /i:'
  condition: selection_img and selection_flags
falsepositives:
  - Unlikely in modern production environments
level: critical
```

### Sigma Rule 05: Mshta Executing Inline VBScript/JScript or Remote HTA
```yaml
title: Mshta Executing Inline Script or Remote HTA Payload
id: 3a41d8c2-7f90-41e2-991a-54c2e8a10005
status: production
description: Detects mshta.exe executing inline javascript:, vbscript:, about: protocols or fetching remote HTA payloads over HTTP/HTTPS.
author: Sri Lankan Elite Hacker's Bible Detection Engineering Team
date: 2026/11/02
tags:
  - attack.defense_evasion
  - attack.t1218.005
logsource:
  category: process_creation
  product: windows
detection:
  selection_img:
    - Image|endswith: '\mshta.exe'
    - OriginalFileName: 'MSHTA.EXE'
  selection_cli:
    CommandLine|contains:
      - 'vbscript:'
      - 'javascript:'
      - 'about:'
      - 'http://'
      - 'https://'
      - 'Execute('
      - 'CreateObject'
  condition: selection_img and selection_cli
falsepositives:
  - Legacy internal intranet HTA tools
level: high
```

### Sigma Rule 06: Rundll32 Comsvcs.dll MiniDump LSASS Memory Dump
```yaml
title: LSASS Memory Dump via Rundll32 and Comsvcs.dll MiniDump
id: 1f8c39a2-64b1-4821-88c3-73f9a10b0006
status: production
description: Detects adversaries dumping LSASS process memory using the native comsvcs.dll MiniDump export via rundll32.exe.
author: Sri Lankan Elite Hacker's Bible Detection Engineering Team
date: 2026/11/02
tags:
  - attack.credential_access
  - attack.t1003.001
logsource:
  category: process_creation
  product: windows
detection:
  selection_comsvcs:
    CommandLine|contains|all:
      - 'comsvcs'
      - 'full'
  selection_minidump:
    CommandLine|contains:
      - 'MiniDump'
      - '#24'
      - '#+24'
  condition: selection_comsvcs and selection_minidump
falsepositives:
  - None expected
level: critical
```

### Sigma Rule 07: Direct LSASS Process Memory Access by Non-System Binary
```yaml
title: Suspicious Process Access to LSASS Memory
id: 7c29e104-8b42-4c19-930a-64e8b2100007
status: production
description: Detects Sysmon EventID 10 ProcessAccess targeting lsass.exe with PROCESS_VM_READ permissions and suspicious call traces indicative of Mimikatz, Nanodump, or Pypykatz.
author: Sri Lankan Elite Hacker's Bible Detection Engineering Team
date: 2026/11/02
tags:
  - attack.credential_access
  - attack.t1003.001
logsource:
  category: process_access
  product: windows
detection:
  selection:
    TargetImage|endswith: '\lsass.exe'
    GrantedAccess|contains:
      - '0x1010'
      - '0x1410'
      - '0x1438'
      - '0x143a'
      - '0x1fffff'
      - '0x1f0fff'
  filter_legit:
    SourceImage:
      - 'C:\Program Files\Windows Defender\MsMpEng.exe'
      - 'C:\Windows\System32\svchost.exe'
      - 'C:\Windows\System32\wbem\wmiprvse.exe'
  filter_calltrace:
    CallTrace|contains:
      - 'UNKNOWN'
      - 'dbgcore.dll'
      - 'dbghelp.dll'
      - 'comsvcs.dll'
  condition: selection and (not filter_legit or filter_calltrace)
falsepositives:
  - Third-party EDR agents not excluded in filter_legit
level: critical
```

### Sigma Rule 08: Registry Hive Credential Extraction (`SAM`, `SYSTEM`, `SECURITY`)
```yaml
title: Credential Hive Extraction via Reg.exe Save or Export
id: 5e91a402-3d18-4f29-a812-90c4b1200008
status: production
description: Detects dumping of SAM, SYSTEM, or SECURITY registry hives using reg.exe save/export to extract local NTLM hashes, LSA secrets, and cached domain credentials.
author: Sri Lankan Elite Hacker's Bible Detection Engineering Team
date: 2026/11/02
tags:
  - attack.credential_access
  - attack.t1003.002
logsource:
  category: process_creation
  product: windows
detection:
  selection_reg:
    - Image|endswith: '\reg.exe'
    - OriginalFileName: 'reg.exe'
  selection_action:
    CommandLine|contains:
      - ' save '
      - ' export '
  selection_hive:
    CommandLine|contains:
      - 'hklm\sam'
      - 'hklm\system'
      - 'hklm\security'
      - 'HKEY_LOCAL_MACHINE\SAM'
      - 'HKEY_LOCAL_MACHINE\SYSTEM'
      - 'HKEY_LOCAL_MACHINE\SECURITY'
  condition: selection_reg and selection_action and selection_hive
falsepositives:
  - Rare manual registry backup of SYSTEM hive by administrators
level: critical
```

### Sigma Rule 09: Volume Shadow Copy Deletion for Ransomware Pre-Impact
```yaml
title: Volume Shadow Copy Deletion via Vssadmin, WMIC, or PowerShell
id: 2b84c910-5a12-4d39-911f-44e2a8900009
status: production
description: Detects deletion or resizing of Volume Shadow Copies using vssadmin, wmic, wbadmin, or PowerShell WMI classes prior to ransomware encryption.
author: Sri Lankan Elite Hacker's Bible Detection Engineering Team
date: 2026/11/02
tags:
  - attack.impact
  - attack.t1490
logsource:
  category: process_creation
  product: windows
detection:
  selection_vssadmin:
    CommandLine|contains|all:
      - 'vssadmin'
      - 'delete'
      - 'shadows'
  selection_vss_resize:
    CommandLine|contains|all:
      - 'vssadmin'
      - 'resize'
      - 'shadowstorage'
  selection_wmic:
    CommandLine|contains|all:
      - 'shadowcopy'
      - 'delete'
  selection_wbadmin:
    CommandLine|contains|all:
      - 'wbadmin'
      - 'delete'
      - 'catalog'
  selection_bcdedit:
    CommandLine|contains|all:
      - 'bcdedit'
      - 'recoveryenabled'
      - 'no'
  condition: 1 of selection_*
falsepositives:
  - Backup software managing shadow storage quotas
level: critical
```

### Sigma Rule 10: NTDS.dit Active Directory Database Extraction via Ntdsutil
```yaml
title: Active Directory NTDS.dit Extraction via Ntdsutil IFM
id: 8d12f4a9-7c31-4092-b12e-65a9c3100010
status: production
description: Detects invocation of ntdsutil.exe with "ac i ntds" and "create full" (Install From Media) to dump the Domain Controller NTDS.dit database and SYSTEM hive.
author: Sri Lankan Elite Hacker's Bible Detection Engineering Team
date: 2026/11/02
tags:
  - attack.credential_access
  - attack.t1003.003
logsource:
  category: process_creation
  product: windows
detection:
  selection_img:
    - Image|endswith: '\ntdsutil.exe'
    - OriginalFileName: 'ntdsutil.exe'
  selection_cli:
    CommandLine|contains:
      - 'ifm'
      - 'create full'
      - 'ac i ntds'
      - 'activate instance ntds'
  condition: selection_img and selection_cli
falsepositives:
  - Planned Domain Controller promotion using Install From Media (IFM)
level: critical
```

### Sigma Rule 11: Active Directory DCSync Replication Attack by Non-DC Account
```yaml
title: Active Directory DCSync Replication Rights Abuse
id: 3f90c218-4b11-48e2-901a-77d4e1200011
status: production
description: Detects EventID 4662 where an account other than a legitimate Domain Controller machine account exercises DS-Replication-Get-Changes-All extended rights.
author: Sri Lankan Elite Hacker's Bible Detection Engineering Team
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
    AccessMask: '0x100'
    Properties|contains:
      - '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
      - '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
      - '89e95b76-444d-4c62-991a-0facbeda640c'
  filter_machine_and_sync:
    - SubjectUserName|endswith: '$'
    - SubjectUserName|startswith: 'MSOL_'
  condition: selection and not filter_machine_and_sync
falsepositives:
  - Misconfigured Azure AD Connect running under a non-standard user account
level: critical
```

### Sigma Rule 12: Kerberoasting RC4 Service Ticket Request Anomaly
```yaml
title: Kerberoasting RC4-HMAC Service Ticket Request
id: 9a41b820-6c19-4f02-881c-52e9d3400012
status: production
description: Detects Kerberos TGS requests (EventID 4769) requesting weak RC4_HMAC (0x17) encryption for non-machine SPNs, indicative of Rubeus or Impacket GetUserSPNs.
author: Sri Lankan Elite Hacker's Bible Detection Engineering Team
date: 2026/11/02
tags:
  - attack.credential_access
  - attack.t1558.003
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4769
    Status: '0x0'
    TicketEncryptionType:
      - '0x17'
      - '0x18'
  filter_legit:
    - ServiceName|endswith: '$'
    - ServiceName: 'krbtgt'
    - TargetUserName|endswith: '$'
  condition: selection and not filter_legit
falsepositives:
  - Legacy service accounts explicitly configured without AES128/AES256 support
level: high
```

### Sigma Rule 13: AS-REP Roasting Pre-Authentication Disabled Ticket Request
```yaml
title: AS-REP Roasting TGT Request Without Pre-Authentication
id: 4c82e109-2d31-49a0-912b-83f1c2500013
status: production
description: Detects Kerberos TGT requests (EventID 4768) with PreAuthType 0 and RC4 encryption (0x17), indicative of AS-REP Roasting against accounts with DONT_REQ_PREAUTH set.
author: Sri Lankan Elite Hacker's Bible Detection Engineering Team
date: 2026/11/02
tags:
  - attack.credential_access
  - attack.t1558.004
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4768
    Status: '0x0'
    PreAuthType: '0'
    TicketEncryptionType: '0x17'
  filter_machine:
    TargetUserName|endswith: '$'
  condition: selection and not filter_machine
falsepositives:
  - None in properly hardened Active Directory domains
level: high
```

### Sigma Rule 14: Pass-the-Hash / Overpass-the-Hash via Sekurlsa (`LogonType 9`)
```yaml
title: Suspicious NewCredentials Logon via Seclogo (Pass-the-Hash)
id: 6f19a304-8e21-47c0-b412-19d8e4600014
status: production
description: Detects EventID 4624 with LogonType 9 (NewCredentials), AuthenticationPackageName Negotiate, and LogonProcessName seclogo, generated by Mimikatz sekurlsa::pth or Rubeus createnetonly.
author: Sri Lankan Elite Hacker's Bible Detection Engineering Team
date: 2026/11/02
tags:
  - attack.lateral_movement
  - attack.defense_evasion
  - attack.t1550.002
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4624
    LogonType: 9
    LogonProcessName: 'seclogo'
    AuthenticationPackageName: 'Negotiate'
  condition: selection
falsepositives:
  - Legitimate administrative use of runas.exe /netonly
level: high
```

### Sigma Rule 15: PsExec or SMBExec Service Installation Persistence & Lateral Movement
```yaml
title: PsExec or Impacket SMBExec Service Installation
id: 7b30d912-1a49-4e82-891f-20c4a8700015
status: production
description: Detects installation of remote execution services (PSEXESVC, BTOBTO, execute.bat via %COMSPEC%) logged in System EventID 7045 or Security EventID 4697.
author: Sri Lankan Elite Hacker's Bible Detection Engineering Team
date: 2026/11/02
tags:
  - attack.execution
  - attack.lateral_movement
  - attack.t1569.002
  - attack.t1021.002
logsource:
  product: windows
  service: system
detection:
  selection_event:
    EventID: 7045
  selection_Indicators:
    - ServiceName|contains:
        - 'PSEXESVC'
        - 'BTOBTO'
    - ImagePath|contains:
        - 'PSEXESVC'
        - '%COMSPEC%'
        - 'cmd.exe /c'
        - 'powershell.exe'
        - '\\127.0.0.1\'
  condition: selection_event and selection_Indicators
falsepositives:
  - Authorized sysadmin usage of Sysinternals PsExec
level: high
```

### Sigma Rule 16: WMI Lateral Movement Spawning Process Under `WmiPrvSE.exe`
```yaml
title: WMI Lateral Movement Process Execution via WmiPrvSE
id: 1e49c820-3f12-4a91-902c-38b4d1800016
status: production
description: Detects WmiPrvSE.exe spawning command interpreters or PowerShell, indicative of remote WMI execution (wmic /node: process call create or Impacket wmiexec.py).
author: Sri Lankan Elite Hacker's Bible Detection Engineering Team
date: 2026/11/02
tags:
  - attack.execution
  - attack.t1047
logsource:
  category: process_creation
  product: windows
detection:
  selection_parent:
    ParentImage|endswith: '\wmiprvse.exe'
  selection_child:
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\pwsh.exe'
      - '\rundll32.exe'
      - '\mshta.exe'
  condition: selection_parent and selection_child
falsepositives:
  - Agentless monitoring software executing WMI inventory scripts
level: high
```

### Sigma Rule 17: Scheduled Task Created Executing from Suspicious Path or Script
```yaml
title: Suspicious Scheduled Task Creation via Schtasks or XML
id: 5a20e914-9b31-4d82-810e-49c3f2900017
status: production
description: Detects creation of scheduled tasks executing payloads from public/temp directories or invoking scripting engines directly.
author: Sri Lankan Elite Hacker's Bible Detection Engineering Team
date: 2026/11/02
tags:
  - attack.persistence
  - attack.privilege_escalation
  - attack.t1053.005
logsource:
  category: process_creation
  product: windows
detection:
  selection_img:
    Image|endswith: '\schtasks.exe'
    CommandLine|contains: '/create'
  selection_suspicious:
    CommandLine|contains:
      - '\Users\Public\'
      - '\AppData\Local\Temp\'
      - '\Windows\Temp\'
      - '\ProgramData\'
      - 'powershell'
      - 'cmd /c'
      - 'mshta'
      - 'regsvr32'
      - 'rundll32'
  condition: selection_img and selection_suspicious
falsepositives:
  - Custom third-party updaters staging in ProgramData
level: high
```

### Sigma Rule 18: Windows Registry Run/RunOnce Key Persistence Modification
```yaml
title: Suspicious Registry Run or RunOnce Key Persistence
id: 8c19f302-4d28-4e19-923a-50d4e3000018
status: production
description: Detects registry modifications under CurrentVersion\Run or RunOnce pointing to suspicious user-writable directories or LOLBins.
author: Sri Lankan Elite Hacker's Bible Detection Engineering Team
date: 2026/11/02
tags:
  - attack.persistence
  - attack.t1547.001
logsource:
  category: registry_set
  product: windows
detection:
  selection_key:
    TargetObject|contains:
      - '\Software\Microsoft\Windows\CurrentVersion\Run\'
      - '\Software\Microsoft\Windows\CurrentVersion\RunOnce\'
      - '\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run\'
  selection_details:
    Details|contains:
      - '\Users\Public\'
      - '\AppData\Local\Temp\'
      - '\ProgramData\'
      - 'powershell'
      - 'mshta'
      - 'rundll32'
      - 'regsvr32'
      - 'wscript'
  condition: selection_key and selection_details
falsepositives:
  - User-scope application installers running from AppData\Local\Temp
level: high
```

### Sigma Rule 19: Windows Event Log Clearing via `Wevtutil` or PowerShell
```yaml
title: Windows Event Log Cleared via Wevtutil or Clear-EventLog
id: 2d49a810-7c12-4f39-801b-61e5f4100019
status: production
description: Detects clearing of Security, System, PowerShell, or Sysmon event logs using wevtutil.exe cl or PowerShell Clear-EventLog cmdlets.
author: Sri Lankan Elite Hacker's Bible Detection Engineering Team
date: 2026/11/02
tags:
  - attack.defense_evasion
  - attack.t1070.001
logsource:
  category: process_creation
  product: windows
detection:
  selection_wevtutil:
    Image|endswith: '\wevtutil.exe'
    CommandLine|contains:
      - ' cl '
      - ' clear-log '
  selection_ps:
    CommandLine|contains:
      - 'Clear-EventLog'
      - 'Remove-EventLog'
      - 'ClearLog('
  condition: selection_wevtutil or selection_ps
falsepositives:
  - Golden VM image preparation prior to sysprep
level: critical
```

### Sigma Rule 20: Microsoft Defender Tampering via `Set-MpPreference`
```yaml
title: Microsoft Defender Real-Time Monitoring Disabled or Exclusion Added
id: 9e30b712-5a41-4c28-912d-72f6a5200020
status: production
description: Detects PowerShell commands disabling Microsoft Defender real-time protection, IOAV protection, script scanning, or adding broad path/extension exclusions.
author: Sri Lankan Elite Hacker's Bible Detection Engineering Team
date: 2026/11/02
tags:
  - attack.defense_evasion
  - attack.t1562.001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains:
      - 'DisableRealtimeMonitoring $true'
      - 'DisableIOAVProtection $true'
      - 'DisableBehaviorMonitoring $true'
      - 'DisableScriptScanning $true'
      - 'DisableIntrusionPreventionSystem $true'
      - 'Add-MpPreference -ExclusionPath'
      - 'Add-MpPreference -ExclusionExtension'
      - 'Add-MpPreference -ExclusionProcess'
  condition: selection
falsepositives:
  - Authorized build server exclusions managed by configuration management
level: critical
```

### Sigma Rule 21: Cobalt Strike Default & Malleable Named Pipe Creation
```yaml
title: Cobalt Strike Post-Exploitation Named Pipe Created
id: 4f18c920-6b29-4d10-823e-83a7b6300021
status: production
description: Detects Sysmon EventID 17/18 named pipe patterns associated with Cobalt Strike Beacon SMB C2 and post-exploitation jobs (keylogger, screenshot, hashdump,Mimikatz).
author: Sri Lankan Elite Hacker's Bible Detection Engineering Team
date: 2026/11/02
tags:
  - attack.execution
  - attack.lateral_movement
  - attack.t1055
  - attack.t1570
logsource:
  category: pipe_created
  product: windows
detection:
  selection:
    PipeName|startswith:
      - '\msagent_'
      - '\postex_'
      - '\postex_ssh_'
      - '\status_'
      - '\MSSE-'
      - '\win_svc'
      - '\ntsvcs_'
      - '\scerpc_'
  condition: selection
falsepositives:
  - None expected for default Cobalt Strike prefixes
level: critical
```

### Sigma Rule 22: Linux Interactive Reverse Shell Execution (`auditd` / EDR)
```yaml
title: Linux Reverse Shell Execution via Bash, Netcat, Socat, or Python
id: 7a29d810-3c41-4e19-934f-94b8c7400022
status: production
description: Detects Linux command lines indicative of interactive reverse shells over /dev/tcp, netcat (-e /bin/sh), mkfifo named pipes, socat, or Python pty.spawn.
author: Sri Lankan Elite Hacker's Bible Detection Engineering Team
date: 2026/11/02
tags:
  - attack.execution
  - attack.t1059.004
  - attack.t1059.006
logsource:
  category: process_creation
  product: linux
detection:
  selection_cli:
    CommandLine|contains:
      - '/dev/tcp/'
      - '/dev/udp/'
      - 'nc -e /bin/'
      - 'ncat -e /bin/'
      - 'mkfifo /tmp/'
      - 'pty.spawn('
      - 'socat exec:'
      - 'socket.socket(socket.AF_INET'
  condition: selection_cli
falsepositives:
  - Authorized red team exercises
level: critical
```

### Sigma Rule 23: Linux Dynamic Linker Rootkit Hijacking via `/etc/ld.so.preload`
```yaml
title: Linux Userland Rootkit Persistence via /etc/ld.so.preload
id: 3b40e912-8d19-4f20-845a-05c9d8500023
status: production
description: Detects creation or modification of /etc/ld.so.preload or LD_PRELOAD environment variable injection used by Linux userland rootkits to hook libc functions (readdir, accept, open).
author: Sri Lankan Elite Hacker's Bible Detection Engineering Team
date: 2026/11/02
tags:
  - attack.persistence
  - attack.defense_evasion
  - attack.t1574.006
logsource:
  product: linux
  service: auditd
detection:
  selection_audit:
    type: 'PATH'
    name: '/etc/ld.so.preload'
    nametype:
      - 'CREATE'
      - 'NORMAL'
  condition: selection_audit
falsepositives:
  - Specialized HPC profiling libraries explicitly preloaded by system administrators
level: critical
```

### Sigma Rule 24: Linux SUID Bit Assigned to Shell or GTFOBin Binary
```yaml
title: Linux SUID Bit Assigned to Shell or System Utility
id: 6c51f024-9e28-4a31-956b-16dae9600024
status: production
description: Detects chmod execution setting the SUID bit (+s, 4755, 4777, u+s) on shells or GTFOBins (bash, sh, dash, python, find, vim, nmap, cp).
author: Sri Lankan Elite Hacker's Bible Detection Engineering Team
date: 2026/11/02
tags:
  - attack.persistence
  - attack.privilege_escalation
  - attack.t1548.001
logsource:
  category: process_creation
  product: linux
detection:
  selection_img:
    Image|endswith: '/chmod'
  selection_mode:
    CommandLine|contains:
      - '+s'
      - '4755'
      - '4777'
      - '6755'
      - '6777'
  selection_target:
    CommandLine|contains:
      - '/bash'
      - '/sh'
      - '/dash'
      - '/zsh'
      - '/python'
      - '/perl'
      - '/find'
      - '/vim'
      - '/nmap'
  condition: selection_img and selection_mode and selection_target
falsepositives:
  - None in production systems
level: critical
```

### Sigma Rule 25: Linux Fileless Memory Execution via `memfd_create` (`auditd`)
```yaml
title: Linux Fileless ELF Execution from Anonymous Memory (memfd_create)
id: 9d62a135-1f39-4b42-867c-27ebf0700025
status: production
description: Detects execution of an anonymous in-memory ELF binary created via the memfd_create syscall (visible as /proc/self/fd/<N> or memfd:), a hallmark of modern Linux fileless malware and DDexec.
author: Sri Lankan Elite Hacker's Bible Detection Engineering Team
date: 2026/11/02
tags:
  - attack.defense_evasion
  - attack.t1620
logsource:
  product: linux
  service: auditd
detection:
  selection_exec:
    type: 'SYSCALL'
    syscall: 'execve'
    exe|startswith: '/memfd:'
  selection_proc_fd:
    type: 'SYSCALL'
    syscall: 'execve'
    exe|contains: '/proc/self/fd/'
  condition: selection_exec or selection_proc_fd
falsepositives:
  - Specific container runtimes (runc CVE-2019-5736 mitigation clones runc into memfd)
level: high
```

---

## Section 4: 15 Production-Ready YARA Rules for Malware & Webshell Classification

YARA rules scan files on disk, unpacked sections, and live process memory dumps (`volatility3 windows.vadyarascan` / `yara -r`). Below are 15 production-ready YARA rules incorporating `pe` and `math` modules, header magic checks (`uint16(0) == 0x5A4D` for PE, `uint32(0) == 0x464C457F` for ELF), byte-sequence wildcards, and entropy thresholds.

```yara
import "pe"
import "math"
import "elf"

/* ==========================================================================
   YARA RULE 01: PHP Obfuscated & Command-Execution Webshell
   ========================================================================== */
rule WEBSHELL_PHP_Obfuscated_And_Exec {
    meta:
        description = "Detects PHP webshells combining superglobal input with dynamic execution or obfuscation"
        author = "Sri Lankan Elite Hacker's Bible DFIR Team"
        severity = "Critical"
        mitre_attack = "T1505.003"
        date = "2026-11-02"
    strings:
        $php_tag1 = "<?php" ascii nocase
        $php_tag2 = "<?=" ascii
        $inp1 = "$_POST[" ascii nocase
        $inp2 = "$_GET[" ascii nocase
        $inp3 = "$_REQUEST[" ascii nocase
        $inp4 = "$_COOKIE[" ascii nocase
        $inp5 = "php://input" ascii nocase
        $exec1 = "eval(" ascii nocase
        $exec2 = "assert(" ascii nocase
        $exec3 = "system(" ascii nocase
        $exec4 = "passthru(" ascii nocase
        $exec5 = "shell_exec(" ascii nocase
        $exec6 = "popen(" ascii nocase
        $exec7 = "proc_open(" ascii nocase
        $obf1 = "base64_decode(" ascii nocase
        $obf2 = "gzinflate(" ascii nocase
        $obf3 = "gzuncompress(" ascii nocase
        $obf4 = "str_rot13(" ascii nocase
        $obf5 = /preg_replace\s*\(\s*['"]\/.*\/e['"]/ ascii nocase
    condition:
        filesize < 500KB and
        any of ($php_tag*) and
        any of ($inp*) and
        (any of ($exec*) or 2 of ($obf*))
}

/* ==========================================================================
   YARA RULE 02: ASPX / .NET ChinaChopper & Godzilla Webshell Family
   ========================================================================== */
rule WEBSHELL_ASPX_Godzilla_And_ChinaChopper {
    meta:
        description = "Detects ASPX/C# memory-compiled webshells including Godzilla, Behinder, and ChinaChopper"
        author = "Sri Lankan Elite Hacker's Bible DFIR Team"
        severity = "Critical"
        mitre_attack = "T1505.003"
    strings:
        $aspx = "<%@ Page" ascii nocase
        $chopper = /eval\s*\(\s*Request\.Item\[/ ascii nocase
        $behinder1 = "System.Reflection.Assembly.Load" ascii
        $behinder2 = "CreateInstance" ascii
        $behinder3 = "RijndaelManaged" ascii
        $behinder4 = "CreateDecryptor" ascii
        $proc1 = "Diagnostics.ProcessStartInfo" ascii
        $proc2 = "cmd.exe" ascii nocase
        $proc3 = "UseShellExecute = false" ascii nocase
    condition:
        filesize < 250KB and
        ($chopper or ($aspx and 3 of ($behinder*)) or ($aspx and all of ($proc*)))
}

/* ==========================================================================
   YARA RULE 03: JSP Runtime.getRuntime().exec & ProcessBuilder Webshell
   ========================================================================== */
rule WEBSHELL_JSP_Command_Execution {
    meta:
        description = "Detects Java Server Pages (JSP) and WAR webshells invoking OS commands or classloader reflection"
        author = "Sri Lankan Elite Hacker's Bible DFIR Team"
        severity = "Critical"
        mitre_attack = "T1505.003"
    strings:
        $jsp1 = "request.getParameter(" ascii
        $jsp2 = "request.getInputStream(" ascii
        $jsp3 = "request.getReader(" ascii
        $exec1 = "Runtime.getRuntime().exec(" ascii
        $exec2 = "java.lang.ProcessBuilder" ascii
        $exec3 = "defineClass(" ascii
        $exec4 = "javax.crypto.Cipher" ascii
    condition:
        filesize < 1MB and any of ($jsp*) and any of ($exec*)
}

/* ==========================================================================
   YARA RULE 04: Mimikatz Credential Dumper (Binary & In-Memory Artifacts)
   ========================================================================== */
rule HACKTOOL_Win_Mimikatz_Memory_And_Disk {
    meta:
        description = "Detects Mimikatz PE binaries, reflective DLLs, and in-memory strings"
        author = "Sri Lankan Elite Hacker's Bible DFIR Team"
        severity = "Critical"
        mitre_attack = "T1003.001"
    strings:
        $s1 = "sekurlsa::logonpasswords" wide ascii nocase
        $s2 = "lsadump::dcsync" wide ascii nocase
        $s3 = "kerberos::golden" wide ascii nocase
        $s4 = "privilege::debug" wide ascii nocase
        $s5 = "gentilkiwi" wide ascii nocase
        $s6 = "benjamin@gentilkiwi.com" wide ascii
        $b_wdigest = { 48 3b d9 74 ?? 48 8b 4b ?? 48 39 48 }
        $b_lsasrv = { 33 ff 41 89 37 4c 8b f3 45 85 c0 74 }
    condition:
        2 of ($s*) or all of ($b_*)
}

/* ==========================================================================
   YARA RULE 05: Cobalt Strike Beacon Payload (Sleep Mask & Config Stub)
   ========================================================================== */
rule MALWARE_Win_CobaltStrike_Beacon {
    meta:
        description = "Detects Cobalt Strike Beacon reflective DLLs, XOR configuration blocks, and named pipe templates"
        author = "Sri Lankan Elite Hacker's Bible DFIR Team"
        severity = "Critical"
        mitre_attack = "T1071.001"
    strings:
        $cfg_xor2e = { 2e 2f 2e 2e 2e 2c 2e 2e 2e 2f 2e 2e }
        $cfg_xor69 = { 69 68 69 69 69 6b 69 69 69 68 69 69 }
        $sleepmask_x64 = { 4c 8b 53 08 45 8b 0a 45 8b 5a 04 4d 8d 52 08 45 85 c9 75 05 45 85 db 74 33 }
        $pipe1 = "\\\\%s\\pipe\\msagent_%x" ascii
        $pipe2 = "\\\\.\\pipe\\MSSE-%d-server" ascii
        $refl = "ReflectiveLoader" ascii
    condition:
        any of ($cfg_*) or $sleepmask_x64 or any of ($pipe*) or (uint16(0) == 0x5A4D and $refl and pe.exports("ReflectiveLoader"))
}

/* ==========================================================================
   YARA RULE 06: Metasploit Meterpreter Stager & Reflective DLL
   ========================================================================== */
rule MALWARE_Win_Metasploit_Meterpreter {
    meta:
        description = "Detects Metasploit Meterpreter reverse_tcp/reverse_https stagers and metsrv DLLs"
        author = "Sri Lankan Elite Hacker's Bible DFIR Team"
        severity = "Critical"
        mitre_attack = "T1059"
    strings:
        $s1 = "metsrv.dll" ascii nocase
        $s2 = "stdapi_" ascii
        $s3 = "core_channel_open" ascii
        $s4 = "ext_server_" ascii
        $block_api = { fc 48 83 e4 f0 e8 c0 00 00 00 41 51 41 50 52 51 56 48 31 d2 65 48 8b 52 60 }
        $block_api_x86 = { fc e8 82 00 00 00 60 89 e5 31 c0 64 8b 50 30 8b 52 0c 8b 52 14 }
    condition:
        2 of ($s*) or $block_api or $block_api_x86
}

/* ==========================================================================
   YARA RULE 07: Sliver C2 Implant (Go Binary Metadata & Protobuf Strings)
   ========================================================================== */
rule MALWARE_Multi_Sliver_C2_Implant {
    meta:
        description = "Detects BishopFox Sliver C2 compiled Go implants across Windows, Linux, and macOS"
        author = "Sri Lankan Elite Hacker's Bible DFIR Team"
        severity = "Critical"
        mitre_attack = "T1071"
    strings:
        $go_hdr = "Go build ID:" ascii
        $s1 = "github.com/bishopfox/sliver/protobuf/sliverpb" ascii
        $s2 = "github.com/bishopfox/sliver/implant/sliver" ascii
        $s3 = "Sliverpb" ascii
        $s4 = "RegisterExtension" ascii
        $s5 = "PivotListeners" ascii
        $s6 = "StartServiceReq" ascii
    condition:
        $go_hdr and 2 of ($s*)
}

/* ==========================================================================
   YARA RULE 08: Rubeus Kerberos Attack Toolkit (.NET Assembly)
   ========================================================================== */
rule HACKTOOL_DotNet_Rubeus {
    meta:
        description = "Detects Rubeus C# Kerberos exploitation toolkit on disk or in CLR memory"
        author = "Sri Lankan Elite Hacker's Bible DFIR Team"
        severity = "Critical"
        mitre_attack = "T1558.003"
    strings:
        $s1 = "Rubeus.Program" ascii wide
        $s2 = "kerberoast" ascii wide nocase
        $s3 = "asreproast" ascii wide nocase
        $s4 = "s4u /user:" ascii wide nocase
        $s5 = "tgtdeleg" ascii wide nocase
        $s6 = "kirbi" ascii wide nocase
        $s7 = "LsaRegisterLogonProcess" ascii wide
    condition:
        uint16(0) == 0x5A4D and 4 of ($s*)
}

/* ==========================================================================
   YARA RULE 09: BloodHound SharpHound Active Directory Collector
   ========================================================================== */
rule HACKTOOL_DotNet_SharpHound_Collector {
    meta:
        description = "Detects SharpHound C# ingestor used for BloodHound Active Directory attack path mapping"
        author = "Sri Lankan Elite Hacker's Bible DFIR Team"
        severity = "High"
        mitre_attack = "T1087.002"
    strings:
        $s1 = "SharpHound" ascii wide
        $s2 = "SpecterOps" ascii wide
        $s3 = "CollectionMethod" ascii wide
        $s4 = "GPOLocalGroup" ascii wide
        $s5 = "NetSessionEnum" ascii wide
        $s6 = "BloodHound.zip" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and 3 of ($s*)
}

/* ==========================================================================
   YARA RULE 10: Chisel Fast TCP/UDP Tunneling over HTTP/WebSockets
   ========================================================================== */
rule HACKTOOL_Go_Chisel_SOCKS_Tunnel {
    meta:
        description = "Detects Chisel Go binary used for reverse SOCKS5 proxy tunneling over SSH-inside-HTTP"
        author = "Sri Lankan Elite Hacker's Bible DFIR Team"
        severity = "High"
        mitre_attack = "T1572"
    strings:
        $s1 = "github.com/jpillora/chisel" ascii
        $s2 = "chisel-v" ascii
        $s3 = "chisel/share/tunnel" ascii
        $s4 = "chisel/client" ascii
        $s5 = "chisel/server" ascii
    condition:
        (uint16(0) == 0x5A4D or uint32(0) == 0x464C457F) and 2 of ($s*)
}

/* ==========================================================================
   YARA RULE 11: Windows Process Hollowing & Reflective Injection Capabilities
   ========================================================================== */
rule MALWARE_Win_Process_Hollowing_APIs {
    meta:
        description = "Detects PE binaries importing classic Process Hollowing (RunPE) API sequence"
        author = "Sri Lankan Elite Hacker's Bible DFIR Team"
        severity = "High"
        mitre_attack = "T1055.012"
    strings:
        $a1 = "CreateProcessA" ascii
        $a2 = "CreateProcessW" ascii
        $b1 = "NtUnmapViewOfSection" ascii
        $b2 = "ZwUnmapViewOfSection" ascii
        $c1 = "VirtualAllocEx" ascii
        $d1 = "WriteProcessMemory" ascii
        $e1 = "SetThreadContext" ascii
        $e2 = "Wow64SetThreadContext" ascii
        $f1 = "ResumeThread" ascii
    condition:
        uint16(0) == 0x5A4D and
        any of ($a*) and any of ($b*) and $c1 and $d1 and any of ($e*) and $f1
}

/* ==========================================================================
   YARA RULE 12: High-Entropy Packed or Encrypted PE Section Anomaly
   ========================================================================== */
rule SUSPICIOUS_PE_High_Entropy_Packed_Section {
    meta:
        description = "Detects PE executables with high section entropy (>7.3) and sparse import table typical of custom crypters/packers"
        author = "Sri Lankan Elite Hacker's Bible DFIR Team"
        severity = "Medium"
        mitre_attack = "T1027.002"
    condition:
        uint16(0) == 0x5A4D and
        pe.number_of_imports < 3 and
        for any i in (0..pe.number_of_sections - 1): (
            pe.sections[i].raw_data_size > 16384 and
            (pe.sections[i].characteristics & pe.SECTION_MEM_EXECUTE) != 0 and
            math.entropy(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) > 7.35
        )
}

/* ==========================================================================
   YARA RULE 13: Ransomware Pre-Encryption Shadow Copy & Boot Config Wiper
   ========================================================================== */
rule MALWARE_Win_Ransomware_ShadowCopy_Wiper {
    meta:
        description = "Detects binaries embedding shadow copy deletion, boot recovery disabling, and cryptographic file locking strings"
        author = "Sri Lankan Elite Hacker's Bible DFIR Team"
        severity = "Critical"
        mitre_attack = "T1486"
    strings:
        $vss1 = "vssadmin.exe delete shadows /all /quiet" ascii wide nocase
        $vss2 = "wmic.exe shadowcopy delete" ascii wide nocase
        $bcd1 = "bcdedit /set {default} recoveryenabled No" ascii wide nocase
        $bcd2 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" ascii wide nocase
        $wb1 = "wbadmin DELETE SYSTEMSTATEBACKUP" ascii wide nocase
        $api1 = "CryptAcquireContext" ascii wide
        $api2 = "BCryptEncrypt" ascii wide
        $note1 = "YOUR FILES HAVE BEEN ENCRYPTED" ascii wide nocase
        $note2 = "README_FOR_DECRYPT" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and
        (2 of ($vss*, $bcd*, $wb*)) and
        (any of ($api*) or any of ($note*))
}

/* ==========================================================================
   YARA RULE 14: Linux LD_PRELOAD Userland Rootkit Shared Object
   ========================================================================== */
rule MALWARE_Linux_LD_PRELOAD_Userland_Rootkit {
    meta:
        description = "Detects Linux ELF shared objects (.so) hooking readdir, open, stat, and accept via dlsym(RTLD_NEXT) to hide files, PIDs, and sockets"
        author = "Sri Lankan Elite Hacker's Bible DFIR Team"
        severity = "Critical"
        mitre_attack = "T1014"
    strings:
        $dlsym = "dlsym" ascii
        $h1 = "readdir" ascii
        $h2 = "readdir64" ascii
        $h3 = "fopen" ascii
        $h4 = "unlink" ascii
        $h5 = "accept" ascii
        $p1 = "/proc/net/tcp" ascii
        $p2 = "ld.so.preload" ascii
        $p3 = "/proc/%d/stat" ascii
    condition:
        uint32(0) == 0x464C457F and
        elf.type == elf.ET_DYN and
        $dlsym and 3 of ($h*) and any of ($p*)
}

/* ==========================================================================
   YARA RULE 15: Linux XMRig Cryptocurrency Miner & Stratum Protocol
   ========================================================================== */
rule MALWARE_Linux_XMRig_Cryptominer {
    meta:
        description = "Detects ELF or PE binaries containing Monero RandomX / Stratum mining pool protocol artifacts"
        author = "Sri Lankan Elite Hacker's Bible DFIR Team"
        severity = "High"
        mitre_attack = "T1496"
    strings:
        $s1 = "stratum+tcp://" ascii
        $s2 = "stratum+ssl://" ascii
        $s3 = "donate-level" ascii
        $s4 = "randomx" ascii nocase
        $s5 = "xmrig" ascii nocase
        $s6 = "\"algo\":" ascii
        $s7 = "nicehash" ascii nocase
    condition:
        (uint16(0) == 0x5A4D or uint32(0) == 0x464C457F) and 3 of ($s*)
}
```

---

## Section 5: 20 Production-Ready Suricata / Snort Network IDS Rules

Suricata inspects live network traffic at Layer 3–7 using protocol-aware sticky buffers (`http.uri`, `http.user_agent`, `http.request_body`, `tls.sni`, `ja3.hash`, `dns.query`). Below are 20 production-grade Suricata rules (`sid:1000001` through `sid:1000020`).

```suricata
# ============================================================================
# SURICATA PRODUCTION RULE SET (SIDs 1000001 - 1000020)
# ============================================================================

# Rule 01: Log4Shell JNDI Lookup Injection in HTTP Headers or URI (CVE-2021-44228)
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET EXPLOIT Apache Log4j RCE JNDI Injection Attempt (CVE-2021-44228)"; flow:established,to_server; content:"${"; pcre:"/\$\{(?:jndi|lower|upper|env|sys|date|base64)[^}]{0,100}:(?:ldap|ldaps|rmi|dns|iiop|corba|nis|nds):/i"; classtype:attempted-admin; sid:1000001; rev:2;)

# Rule 02: SQL Injection UNION SELECT / Information_Schema Probing in HTTP URI
alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"SLHB WEB_SERVER SQL Injection UNION SELECT or Schema Enumeration"; flow:established,to_server; http.uri; content:"select"; nocase; pcre:"/(?:union[\s\/\*]+(?:all[\s\/\*]+)?select|information_schema\.(?:tables|columns)|waitfor\s+delay\s+'0:0:|pg_sleep\s*\()/i"; classtype:web-application-attack; sid:1000002; rev:1;)

# Rule 03: Directory Traversal / Local File Inclusion (/etc/passwd or win.ini)
alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"SLHB WEB_SERVER Local File Inclusion Path Traversal Attempt"; flow:established,to_server; http.uri.raw; pcre:"/(?:(?:\.|%2e){2}(?:\/|%2f|\\|%5c)){2,}(?:etc\/passwd|etc\/shadow|proc\/self\/environ|windows\/win\.ini|boot\.ini)/i"; classtype:web-application-attack; sid:1000003; rev:1;)

# Rule 04: Shellshock Bash Environment Variable RCE (CVE-2014-6271)
alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"SLHB EXPLOIT GNU Bash Shellshock Environment Variable Injection"; flow:established,to_server; content:"() {"; fast_pattern; pcre:"/\(\)\s*\{[^}]*\}\s*;/"; classtype:attempted-admin; sid:1000004; rev:1;)

# Rule 05: AWS / Cloud Instance Metadata SSRF Exploitation (169.254.169.254)
alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"SLHB CLOUD SSRF Attempt Targeting Cloud Instance Metadata Service (IMDS)"; flow:established,to_server; content:"169.254.169.254"; nocase; pcre:"/169\.254\.169\.254\/(?:latest\/meta-data|computeMetadata\/v1|metadata\/instance)/i"; classtype:web-application-attack; sid:1000005; rev:1;)

# Rule 06: XML External Entity (XXE) SYSTEM / ENTITY Declaration in HTTP POST Body
alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"SLHB WEB_SERVER XML External Entity (XXE) Injection Attempt"; flow:established,to_server; http.request_body; content:"<!ENTITY"; nocase; pcre:"/<!ENTITY\s+[%\w\s]+(?:SYSTEM|PUBLIC)\s+['\"](?:file|http|https|ftp|php|expect|gopher):/i"; classtype:web-application-attack; sid:1000006; rev:1;)

# Rule 07: Linux Interactive Shell Command Output over Cleartext TCP (`uid=0(root)`)
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"SLHB COMPROMISE Linux id Command Output Returning uid=0(root) Over Network"; flow:established; content:"uid="; content:"gid="; distance:0; within:30; pcre:"/uid=\d+\([a-z0-9_-]+\)\s+gid=\d+\([a-z0-9_-]+\)/"; classtype:trojan-activity; sid:1000007; rev:1;)

# Rule 08: Windows cmd.exe Interactive Banner Over Raw TCP Reverse Shell
alert tcp $HOME_NET any -> $EXTERNAL_NET !$HTTP_PORTS (msg:"SLHB COMPROMISE Microsoft Windows cmd.exe Interactive Reverse Shell Banner"; flow:established; content:"Microsoft Windows [Version "; depth:40; content:"(c) Microsoft Corporation"; distance:0; within:80; classtype:trojan-activity; sid:1000008; rev:1;)

# Rule 09: Cobalt Strike Default HTTP C2 Check-in Cookie Base64 Metadata Pattern
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"SLHB C2 Cobalt Strike Beacon Default HTTP GET Metadata Cookie"; flow:established,to_server; http.method; content:"GET"; http.cookie; pcre:"/^[A-Za-z0-9+\/]{171}=$/"; classtype:trojan-activity; sid:1000009; rev:1;)

# Rule 10: Cobalt Strike Default Self-Signed TLS Certificate Serial Number
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"SLHB C2 Cobalt Strike Default TeamServer TLS Certificate Serial 146473198"; flow:established,to_client; tls.cert_serial; content:"08:bb:00:ee"; classtype:trojan-activity; sid:1000010; rev:1;)

# Rule 11: Metasploit Meterpreter Reverse HTTPS Default User-Agent / TLS Subject
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"SLHB C2 Metasploit Meterpreter Default TLS Certificate Subject Pattern"; flow:established,to_client; tls.cert_subject; content:"CN=localhost"; tls.cert_issuer; content:"CN=localhost"; classtype:trojan-activity; sid:1000011; rev:1;)

# Rule 12: SMBv1 EternalBlue MS17-010 Multiplex ID (`MID=65`) Exploit Attempt
alert smb any any -> $HOME_NET 445 (msg:"SLHB EXPLOIT MS17-010 EternalBlue SMBv1 Trans2 Heap Overflow Attempt"; flow:established,to_server; content:"|ff|SMB|32 00 00 00 00 18 07 c0|"; offset:4; depth:12; content:"|00 00 00 00 00 00 00 00 00 00 00 08 ff fe 00 08 41 00|"; distance:2; within:18; classtype:attempted-admin; sid:1000012; rev:1;)

# Rule 13: Impacket SecretsDump / Remote Registry Winreg Named Pipe Access Over SMB
alert smb any any -> $HOME_NET 445 (msg:"SLHB LATERAL_MOVEMENT Impacket SecretsDump Remote Registry Pipe (winreg) Access"; flow:established,to_server; content:"|5c 00|w|00|i|00|n|00|r|00|e|00|g|00|"; nocase; threshold:type limit, track by_src, count 1, seconds 60; classtype:credential-theft; sid:1000013; rev:1;)

# Rule 14: PsExec Remote Service Control & Named Pipe (`PSEXESVC`) Over SMB
alert smb any any -> $HOME_NET 445 (msg:"SLHB LATERAL_MOVEMENT Sysinternals PsExec Service Binary Upload Over ADMIN$ Share"; flow:established,to_server; content:"P|00|S|00|E|00|X|00|E|00|S|00|V|00|C|00|"; nocase; classtype:policy-violation; sid:1000014; rev:1;)

# Rule 15: High-Entropy / High-Length DNS Tunneling Subdomain Query (`iodine` / `dnscat2`)
alert dns $HOME_NET any -> any 53 (msg:"SLHB EXFILTRATION Suspicious Long Subdomain DNS Tunneling Query (>55 chars)"; dns.query; content:"."; pcre:"/^[a-zA-Z0-9\-_]{55,250}\.[a-zA-Z0-9\-]+\.[a-zA-Z]{2,10}$/"; threshold:type both, track by_src, count 10, seconds 60; classtype:bad-unknown; sid:1000015; rev:1;)

# Rule 16: ICMP Large Payload Tunneling (`ptunnel` / `icmpsh` > 128 Bytes)
alert icmp $HOME_NET any -> $EXTERNAL_NET any (msg:"SLHB EXFILTRATION Anomalous Large ICMP Echo Request Payload (>128 Bytes)"; itype:8; dsize:>128; threshold:type both, track by_src, count 20, seconds 30; classtype:bad-unknown; sid:1000016; rev:1;)

# Rule 17: Cryptocurrency Mining Stratum Protocol JSON-RPC Login Over TCP
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"SLHB MALWARE Cryptocurrency Miner Stratum Pool JSON-RPC Subscription"; flow:established,to_server; content:"\"method\""; content:"\"mining.subscribe\""; distance:0; within:50; classtype:trojan-activity; sid:1000017; rev:1;)

# Rule 18: Offensive Security Scanner User-Agent Detection (`sqlmap`, `nikto`, `nuclei`, `gobuster`)
alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"SLHB SCAN Offensive Vulnerability Scanner HTTP User-Agent Detected"; flow:established,to_server; http.user_agent; pcre:"/(?:sqlmap|nikto|nuclei|gobuster|ffuf|feroxbuster|dirbuster|wpscan|masscan|zgrab)/i"; threshold:type limit, track by_src, count 1, seconds 120; classtype:web-application-attack; sid:1000018; rev:1;)

# Rule 19: Nmap TCP SYN Stealth Scan Flood Detection
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"SLHB SCAN Aggressive TCP SYN Port Scan Detected"; flags:S,12; window:1024; threshold:type both, track by_src, count 40, seconds 10; classtype:attempted-recon; sid:1000019; rev:1;)

# Rule 20: Cleartext Windows PE Executable Downloaded Over Unencrypted HTTP
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"SLHB POLICY Windows PE Binary Downloaded Over Unencrypted HTTP"; flow:established,to_client; http.stat_code; content:"200"; file.data; content:"MZ"; depth:2; content:"This program cannot be run in DOS mode"; distance:30; within:100; classtype:policy-violation; sid:1000020; rev:1;)
```

---

## Section 6: Digital Forensics & Incident Response (DFIR) Playbooks

### 6.1 Order of Volatility (RFC 3227)
During live incident triage, forensic responders must collect evidence strictly from most volatile to least volatile:
1. **CPU Registers, L1/L2/L3 Cache & TLB Entries** (Nanoseconds)
2. **System RAM / Physical Memory (`LiME`, `WinPmem`, `DumpIt`, `AVML`)** (Milliseconds to Seconds)
3. **Active Network Connections, ARP Cache, Kernel Routing Tables & Open Sockets**
4. **Running Processes, Open File Descriptors (`/proc/<pid>/fd`) & Loaded Kernel Modules**
5. **Local Disk / NVMe / SSD Non-Volatile Storage & Volume Shadow Copies**
6. **Centralized SIEM Logs, NetFlow Records, and Off-Host Backups**

---

### 6.2 Memory Forensics Reference: `Volatility 3` Complete Plugin Playbook

Assume a physical RAM image `memory_dump.raw` has been captured from a compromised host using `WinPmem` or `AVML` (Linux).

| Investigation Objective | `Volatility 3` Plugin Command | Forensic Analysis & Malware Indicators |
| :--- | :--- | :--- |
| **OS Fingerprint & Kernel DTB** | `vol -f memory_dump.raw windows.info` | Identifies exact NT kernel build, PDB symbols (`ntkrnlmp.pdb`), system time, and Directory Table Base (`DTB`). |
| **Active Process Listing (`EPROCESS` Doubly-Linked List)** | `vol -f memory_dump.raw windows.pslist` | Walks `PsActiveProcessHead` doubly-linked list (`ActiveProcessLinks`). Inspect abnormal parent-child relationships (e.g., `services.exe` -> `cmd.exe`, or `svchost.exe` without `-k` parented by `explorer.exe`). |
| **Process Tree Hierarchy** | `vol -f memory_dump.raw windows.pstree` | Visualizes hierarchical parent-child chains (`PPID` -> `PID`). Verify `lsass.exe` (single instance, parent `wininit.exe`) and `smss.exe` (parent `System` PID 4). |
| **Hidden / Unlinked Process Scan (DKOM Detection)** | `vol -f memory_dump.raw windows.psscan` | Scans physical memory pool tags for `_EPROCESS` structures even if unlinked by a Direct Kernel Object Manipulation (DKOM) rootkit. Compare `psscan` vs `pslist`! |
| **Command Line Arguments (`PEB`)** | `vol -f memory_dump.raw windows.cmdline` | Extracts `CommandLine` from `_RTL_USER_PROCESS_PARAMETERS` inside Process Environment Block (`PEB`). |
| **Loaded DLLs & Path Verification** | `vol -f memory_dump.raw windows.dlllist --pid 4120` | Lists loaded modules from PEB `InLoadOrderModuleList`. Detects DLL sideloading from `C:\Users\Public\`. |
| **Unlinked / Reflective DLL Scan** | `vol -f memory_dump.raw windows.ldrmodules --pid 4120` | Cross-references PEB Ldr lists (`InLoad`, `InInit`, `InMem`) against Virtual Address Descriptors (`VAD`). If a mapped PE region is `False` in all three PEB lists, it was reflectively injected! |
| **Process Injection & RWX Memory (`VAD` Inspection)** | `vol -f memory_dump.raw windows.malfind --dump` | Scans VAD nodes for private memory regions marked `PAGE_EXECUTE_READWRITE` (`RWX`) containing `MZ` headers or shellcode prologues (`48 83 ec`, `fc e8`). Dumps injected regions to disk. |
| **Process Hollowing Detection** | `vol -f memory_dump.raw windows.hollowprocesses` | Compares `_EPROCESS.ImageFilePointer` against VAD section object paths and PEB base addresses to detect Process Hollowing / Herpaderping. |
| **Active & Closed Network Sockets** | `vol -f memory_dump.raw windows.netscan` | Scans `TcpE`, `UdpA` pool structures for TCP/UDP endpoints, listening ports, remote C2 IPs, and owning PIDs. |
| **Open File Handles, Mutexes & Named Pipes** | `vol -f memory_dump.raw windows.handles --pid 4120` | Enumerates object table handles (`File`, `Key`, `Mutant` / Mutexes, `Process`, `Thread`). Search for known malware mutexes or Cobalt Strike named pipes. |
| **Kernel System Call Table (`SSDT`) Hooks** | `vol -f memory_dump.raw windows.ssdt` | Inspects System Service Descriptor Table pointers to ensure all syscalls point inside `ntoskrnl.exe` or `win32k.sys`. |
| **Loaded Kernel Drivers (`BYOVD` Detection)** | `vol -f memory_dump.raw windows.driverscan` | Scans `_DRIVER_OBJECT` structures in kernel pool memory to detect malicious or vulnerable signed drivers (`RTCore64.sys`, `mhyprot2.sys`). |
| **In-Memory Registry Hive Listing** | `vol -f memory_dump.raw windows.registry.hivelist` | Locates cached virtual addresses of `SAM`, `SYSTEM`, `SECURITY`, `SOFTWARE`, and `NTUSER.DAT` hives in kernel memory. |
| **Extract Cached Password Hashes (`SAM` + `SYSTEM`)** | `vol -f memory_dump.raw windows.hashdump` | Extracts local account NTLM hashes directly from in-memory `SAM` and `SYSTEM` registry hives. |
| **Extract LSA Secrets & Cached Domain Creds** | `vol -f memory_dump.raw windows.lsadump` / `windows.cachedump` | Extracts plaintext service account passwords, DPAPI master keys, and `DCC2` cached domain hashes from `SECURITY` hive. |
| **Scan Process Memory with YARA Rules** | `vol -f memory_dump.raw windows.vadyarascan --yara-file rules.yar` | Runs YARA signatures across all process Virtual Address Descriptor memory segments. |
| **Dump Specific Process Executable from RAM** | `vol -f memory_dump.raw windows.pslist --pid 4120 --dump` | Reconstructs the PE binary from process memory onto disk for static analysis in Ghidra/IDA. |

---

### 6.3 Linux Live Response & Forensic Triage Checklist

When responding to a potentially compromised Linux server *before* rebooting, execute the following read-only forensic inspection commands (ideally from a statically compiled, trusted binary toolkit mounted read-only):

```bash
# 1. Capture Volatile System Metadata & Active Logged-In Sessions
uname -a && date -u && uptime
w && who -a && last -Faiwx -n 50
lastb -Faiwx -n 50   # Failed login attempts from /var/log/btmp

# 2. Hunt for Deleted Binaries Still Running in Memory (/proc/<pid>/exe -> "(deleted)")
ls -la /proc/*/exe 2>/dev/null | grep '(deleted)'
# Recovery Tip: Copy the deleted binary directly out of /proc/<pid>/exe before killing the process!
# cp /proc/<PID>/exe /tmp/recovered_malware.elf

# 3. Hunt for Fileless Execution via memfd_create (/memfd:...)
ls -la /proc/*/exe 2>/dev/null | grep 'memfd:'
ls -la /proc/*/fd/* 2>/dev/null | grep 'memfd:'

# 4. Inspect Process Environment Variables for LD_PRELOAD, SSH Client IPs, or Hidden Keys
for pid in /proc/[0-9]*; do
    echo "=== $pid ($(cat $pid/comm 2>/dev/null)) ==="
    tr '\0' '\n' < "$pid/environ" 2>/dev/null | grep -E 'LD_PRELOAD|LD_LIBRARY_PATH|SSH_|HISTFILE|PATH'
done

# 5. Inspect Process Current Working Directories Running Out of /tmp, /dev/shm, or /var/tmp
ls -l /proc/*/cwd 2>/dev/null | grep -E '/tmp|/dev/shm|/var/tmp|/run/user'

# 6. Enumerate All Listening & Established Network Sockets with Owning PIDs and Inodes
ss -tulpan
lsof -i -n -P

# 7. Check for Promiscuous Mode Network Interfaces (Packet Sniffers / Passive Backdoors)
ip link | grep -i promisc
# Also inspect raw packet sockets opened by processes:
cat /proc/net/packet

# 8. Audit Userland Dynamic Linker Rootkits & PAM Backdoors
cat /etc/ld.so.preload 2>/dev/null
ldd /usr/bin/ssh /usr/sbin/sshd /bin/ls /bin/ps
rpm -Va 2>/dev/null || debsums -c 2>/dev/null   # Verify package binary SHA256 hashes against dpkg/rpm DB

# 9. Audit All Persistence Vectors (Cron, Systemd Timers, Generators, RC Scripts, SSH Keys)
for user in $(cut -f1 -d: /etc/passwd); do crontab -u "$user" -l 2>/dev/null; done
ls -la /etc/cron* /var/spool/cron/crontabs/
systemctl list-timers --all
find /etc/systemd/system /usr/lib/systemd/system -type f -mtime -14 -ls
find / -name "authorized_keys" -exec ls -la {} + -exec cat {} + 2>/dev/null

# 10. Hunt for Anomalous SUID/SGID Binaries and Extended File Capabilities
find / -perm -4000 -o -perm -2000 -type f 2>/dev/null | xargs ls -la
getcap -r / 2>/dev/null
```

---

### 6.4 Windows Disk Triage Artifact Encyclopedia

When performing dead-box disk forensics or KAPE (Kroll Artifact Parser and Extractor) triage collection on a Windows NTFS volume, the following forensic artifacts reconstruct program execution, file access, user activity, and persistence with sub-second precision:

| Artifact Name | Exact Disk Path / Registry Key | Forensic Proof Provided | Primary Analysis Tool |
| :--- | :--- | :--- | :--- |
| **Prefetch (`*.pf`)** | `C:\Windows\Prefetch\<EXECNAME>-<8_CHAR_HASH>.pf` | Proves **Program Execution**: Records binary name, path hash, run count, last **8 execution timestamps**, volume serial number, and every file/DLL loaded during the first 10 seconds of execution (even if the binary was subsequently deleted!). | Eric Zimmerman's `PECmd.exe` |
| **Amcache (`Amcache.hve`)** | `C:\Windows\AppCompat\Programs\Amcache.hve` (`InventoryApplicationFile` subkey) | Proves **Binary Presence & First Execution**: Records full path, file size, PE Linker compile timestamp, publisher metadata, and **SHA-1 hash** of executed binaries. | `AmcacheParser.exe` |
| **Shimcache (AppCompatCache)** | `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache` | Proves **File Presence / Execution Lookups**: Kernel tracks executables inspected by the Application Compatibility engine and flushes to `SYSTEM` hive on shutdown. Records full path and Last Modified timestamp (`$STANDARD_INFORMATION`). | `AppCompatCacheParser.exe` |
| **BAM / DAM (Background Activity Moderator)** | `HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\<SID>` | Proves **Program Execution per User SID**: Records full NT device path (`\Device\HarddiskVolume3\...`) and exact execution timestamp of binaries run by each user SID. | `Registry Explorer` / `RECmd.exe` |
| **SRUM (System Resource Usage Monitor)** | `C:\Windows\System32\sru\SRUDB.dat` (ESE Database) + `SOFTWARE` hive | Proves **30–60 Days of Process Execution & Network Bytes Transferred**: Tracks exact application path, user SID, CPU cycle consumption, and exact **Bytes Sent / Bytes Received** per process per interface (invaluable for quantifying data exfiltration volume!). | `SrumECmd.exe` |
| **NTFS Master File Table (`$MFT`)** | `C:\$MFT` (Root of NTFS Volume) | Proves **File Existence & Timestomping**: Every file/directory has two timestamp pairs containing 4 timestamps (MACB: Modified, Accessed, MFT Entry Modified, Created/Born): `$STANDARD_INFORMATION` (`0x10`, user-modifiable via API) and `$FILE_NAME` (`0x30`, modified only by the NTFS kernel driver). **Timestomping Detection**: If `$STANDARD_INFORMATION` Created timestamp is *earlier* than `$FILE_NAME` Created timestamp, or has zeroed nanoseconds (`.0000000`), timestomping (`Sysmon EventID 2`) occurred! | `MFTECmd.exe` |
| **USN Change Journal (`$UsnJrnl:$J`)** | `C:\$Extend\$UsnJrnl:$J` | Proves **Chronological File System Operations**: Transactional log of every file creation (`FILE_CREATE`), rename (`RENAME_OLD_NAME`/`RENAME_NEW_NAME`), data overwrite, and deletion (`FILE_DELETE`), proving staging and self-deletion of malware droppers. | `MFTECmd.exe` |
| **Volume Shadow Copies (`VSS`)** | `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy<N>\` | Provides historical point-in-time snapshots of `$MFT`, Registry Hives, and `.evtx` logs before attacker cleanup. | `vssadmin` / `ShadowExplorer` |
| **UserAssist** | `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count` | Proves **GUI Program Execution by User**: Registry values are **ROT13-encoded** paths (e.g., `HRZR_EHACNGU` = `UEME_RUNPATH`), storing run count, focus time, and last execution timestamp. | `RECmd.exe` / `Registry Explorer` |
| **Shellbags** | `USRCLASS.DAT` (`Local Settings\Software\Microsoft\Windows\Shell\BagMRU` & `Bags`) | Proves **Directory Browsing & Deleted/Removable Folder Access**: Persists folder hierarchy, window coordinates, and MFT entry numbers of every directory opened in Windows Explorer, including USB drives and network shares long after disconnection. | `SBECmd.exe` |
| **Windows LNK Shortcut Files & JumpLists** | `%APPDATA%\Microsoft\Windows\Recent\*.lnk` & `AutomaticDestinations\*.automaticDestinations-ms` | Proves **File Opening & External Volume Metadata**: Stores original target file path, MACB timestamps, target Volume Serial Number, NetBIOS machine name, and MAC address (within TrackerDataBlock Droid Birth ID). | `LECmd.exe` / `JLECmd.exe` |
| **PowerShell ConsoleHost_history** | `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` | Captures up to **4,096 lines of interactive PowerShell commands** typed by the user, persisted across reboots even if Event Logs (`4104`) were cleared! | Text / `grep` |
| **BITS Jobs Database (`qmgr.db`)** | `C:\ProgramData\Microsoft\Network\Downloader\qmgr.db` | Proves **Background Intelligent Transfer Service (BITS)** persistence jobs, remote C2 URLs, local destination paths, and owner SIDs. | `BitsParser` |
| **Windows Event Logs (`*.evtx`)** | `C:\Windows\System32\Winevt\Logs\*.evtx` | Stores over 300 operational event channels (`Security.evtx`, `System.evtx`, `TerminalServices-LocalSessionManager%4Operational.evtx`, `TaskScheduler%4Operational.evtx`, `Bits-Client%4Operational.evtx`). | `EvtxECmd.exe` / `Chainsaw` / `Hayabusa` |

### 6.5 Rapid Triage Execution with `EvtxECmd` and `MFTECmd`
```powershell
# 1. Parse all Windows Event Logs into a unified forensic timeline CSV using Eric Zimmerman's EvtxECmd:
.\EvtxECmd.exe -d "C:\Triage\Windows\System32\Winevt\Logs" --csv "C:\ForensicOutput\Evtx" --csvf "AllEvents_Timeline.csv"

# 2. Parse $MFT and $UsnJrnl:$J to detect timestomped droppers and deleted staging archives:
.\MFTECmd.exe -f "C:\Triage\$MFT" --csv "C:\ForensicOutput\MFT" --csvf "MFT_Parsed.csv"
.\MFTECmd.exe -f "C:\Triage\$Extend\$UsnJrnl_$J" -m "C:\Triage\$MFT" --csv "C:\ForensicOutput\USN" --csvf "USN_Journal.csv"

# 3. Parse Prefetch, Amcache, and SRUM to reconstruct binary execution and exfiltration byte counts:
.\PECmd.exe -d "C:\Triage\Windows\Prefetch" --csv "C:\ForensicOutput\Prefetch"
.\AmcacheParser.exe -f "C:\Triage\Windows\AppCompat\Programs\Amcache.hve" --csv "C:\ForensicOutput\Amcache"
.\SrumECmd.exe -f "C:\Triage\Windows\System32\sru\SRUDB.dat" -r "C:\Triage\Windows\System32\config\SOFTWARE" --csv "C:\ForensicOutput\SRUM"
```
