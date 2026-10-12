# Cloud Incident Response & Threat Hunting: Triaging Account Takeover (ATO) with KQL

![Domain](https://img.shields.io/badge/Domain-Cloud%20DFIR%20%26%20Threat%20Hunting-blue)
![Query Language](https://img.shields.io/badge/Query-KQL-0078D4?logo=microsoftazure&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Microsoft%20Entra%20ID%20%2F%20Azure-informational)
![MITRE](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-red)

---

## Executive Summary

This project demonstrates an end-to-end Security Operations Center (SOC) triage, behavioral profiling, and threat-hunting investigation using **Kusto Query Language (KQL)** within **Azure Data Explorer (ADX)**.

The investigation analyzes a cloud identity intrusion against an executive identity (`adele.vance@targetcorp.com`), reconstructing the attacker's trajectory from initial access reconnaissance (low-and-slow password spraying), through behavioral deviation from legitimate baselines, to post-exploitation persistence mechanisms (rogue MFA addition and mailbox exfiltration rules).

---

## MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name |
| :--- | :--- | :--- |
| Initial Access | `T1110.003` | Password Spraying |
| Initial Access | `T1078.004` | Valid Accounts: Cloud Accounts |
| Defense Evasion | `T1556` | Modify Authentication Process (Rogue MFA Registration) |
| Collection / Exfiltration | `T1114.001` | Email Collection: Local Email Collection (Inbox Forwarding Rules) |

---

## Technical Investigation & Evidence

### 1. Reverse Threat Hunting: Correlating Initial Access

Following an initial anomaly alert, the investigation traced authentication activity backwards across previous days to identify precursor events. A distributed password spray campaign was detected originating from a Tor exit node (`185.220.101.45`), targeting multiple user principals with authentication error `50126` (Invalid Credentials) before achieving a single successful logon (`ResultType == 0`) on Adele Vance's account.

```kql
let SprayIP = "185.220.101.45";
SigninLogs
| where IPAddress == SprayIP
| project TimeGenerated, UserPrincipalName, IPAddress, ResultType,
          Status = iff(ResultType == 0, "SUCCESSFUL ENTRY POINT", "FAILED SPRAY ATTEMPT"),
          Location
| order by TimeGenerated asc
```

---

### 2. Behavioral Profiling & Anomaly Detection

To eliminate potential false positives (such as approved executive international travel), a behavioral baseline was calculated over the target identity's historical authentication telemetry.

Adele's historical baselines established consistent operational hours (`08:00–17:00 UTC+1`) and an origin of `Lagos, NG` (`102.89.34.12`). The compromised session was isolated immediately as anomalous across three parameters:

- **Timestamp:** `03:00:12 AM` (off-hours / night)
- **Origin Geolocation:** Romania / Tor exit node
- **Infrastructure:** Public anonymization network

```kql
let TargetUser = "adele.vance@targetcorp.com";
SigninLogs
| where UserPrincipalName == TargetUser and ResultType == 0
| extend
    HourOfDay = datetime_part("hour", TimeGenerated),
    IsAnomalousTime = iff(datetime_part("hour", TimeGenerated) between (0 .. 6), "YES - Off Hours (Night)", "NO - Business Hours"),
    IsKnownLocation = iff(Location has "Lagos", "Known Origin", "UNUSUAL / ANOMALOUS ORIGIN")
| project TimeGenerated, UserPrincipalName, Location, IsKnownLocation, HourOfDay, IsAnomalousTime, IPAddress
| order by TimeGenerated asc
```

---

### 3. Post-Compromise Persistence & Exfiltration Audit

Standard containment mandates evaluating post-authentication telemetry rather than stopping at password resets. Microsoft Entra ID and Exchange `AuditLogs` were queried to identify unauthorized changes executed within minutes of initial breach.

The query identified two critical persistence artifacts established via the same Tor exit node (`185.220.101.45`):

1. **Rogue MFA Enrollment (`03:04:15 AM`)** — Attacker registered an unauthorized mobile number (`+44 7700 900123`) to maintain authentication access regardless of password resets.
2. **Mailbox Tampering (`03:08:40 AM`)** — Attacker created a hidden inbox rule (`New-InboxRule`) designed to auto-forward emails containing "invoice" or "wire" to an external address (`dropbox-exfil@external-evil.com`) and purge them from the inbox.

```kql
AuditLogs
| where ActivityDisplayName in ("User registered security info", "New-InboxRule", "Set-Mailbox", "Add member to role")
| project
    TimeGenerated,
    Actor = InitiatedBy,
    Source_IP = IPAddress,
    Persistence_Technique = ActivityDisplayName,
    Details = AdditionalDetails
| order by TimeGenerated asc
```

---

## Containment & Remediation Plan

| Priority | Action Item | Technical Execution |
| :--- | :--- | :--- |
| **P0 – Critical** | Session Revocation | Revoke all active tokens: `Revoke-AzureADUserAllRefreshToken -ObjectId <Adele_GUID>` |
| **P0 – Critical** | Purge Rogue Factors | Remove unauthorized phone factor (`+44 7700 900123`) from the user's Entra ID Authentication Methods blade |
| **P1 – High** | Remove Mailbox Rules | `Remove-InboxRule -Mailbox "adele.vance" -Identity "<Rule_ID>"` via Exchange Online PowerShell |
| **P1 – High** | Credential Reset | Force an out-of-band password reset with a temporary access pass |
| **P2 – Medium** | Perimeter Hardening | Block malicious Tor exit IP `185.220.101.45` and enforce Conditional Access policies blocking anonymous IP tiers |

---

## Key Takeaways

- **Password spraying vs. brute force:** Attackers use multi-day, distributed login attempts across diverse user accounts to circumvent legacy lockout thresholds.
- **Deep scope of compromise:** Incident containment must audit identity provider logs and mailbox configurations to neutralize backdoors before closing a ticket.
