# 🛡️ SOC Investigations & DFIR Labs

![Cybersecurity](https://img.shields.io/badge/Cybersecurity-Blue%20Team-blue)
![SOC](https://img.shields.io/badge/SOC-Investigations-2D9CDB)
![DFIR](https://img.shields.io/badge/DFIR-Incident%20Response-56C7E8)
![HackTheBox](https://img.shields.io/badge/Hack%20The%20Box-Sherlocks-9FEF00)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)

Hands-on **SOC, DFIR and Threat Hunting investigations** based primarily on Hack The Box Sherlocks and controlled lab scenarios.

The purpose of this repository is not simply to complete challenges, but to approach each case as a real security investigation:

> **Alert → Triage → Evidence → Timeline → Root Cause → MITRE ATT&CK → Detection → Response**

---

## 🎯 Objectives

This repository documents my practical development in areas such as:

- Security Operations Center (SOC) investigations
- Incident triage and response
- Windows Event Log analysis
- Sysmon telemetry analysis
- Active Directory attack detection
- Network forensics
- Threat hunting
- Digital forensics
- Indicator of Compromise (IoC) extraction
- MITRE ATT&CK mapping
- Detection engineering
- KQL and Sigma rule development
- Investigation reporting

Each investigation will focus not only on finding the answer, but also on understanding **what happened, how it happened, what evidence proves it, and how the activity could be detected in a real environment**.

---

# 🧭 Sherlock Roadmap

## 🟢 Phase 1 — SOC & Log Analysis Fundamentals

These Sherlocks are intended to build a solid foundation in log analysis, timeline reconstruction and basic incident investigation.

| Status | Sherlock | Focus |
|:---:|---|---|
| ⬜ | **Brutus** | Investigating SSH brute-force activity, authentication logs, suspicious logins and attacker IP identification. |
| ⬜ | **Unit42** | Investigating malicious activity through Sysmon telemetry, process execution, network connections and file activity. |
| ⬜ | **BFT** | Introduction to Windows forensic artifacts, NTFS metadata and timeline reconstruction. |
| ⬜ | **LogJammer** | Investigation using Windows Event Logs, including Security, Defender, Firewall and PowerShell events. |

---

## 🔵 Phase 2 — Active Directory Attack Detection

This phase focuses on understanding common Active Directory attacks from the defender's perspective.

The goal is to connect offensive techniques with the telemetry they generate inside a Windows domain.

| Status | Sherlock | Focus |
|:---:|---|---|
| ⬜ | **Campfire-1** | Detection and investigation of **Kerberoasting** activity using Domain Controller logs and endpoint artifacts. |
| ⬜ | **Campfire-2** | Investigation of **AS-REP Roasting** and suspicious Kerberos authentication activity. |
| ⬜ | **Noxious** | Detection of **LLMNR/NBT-NS poisoning**, NTLM authentication and rogue systems inside the network. |
| ⬜ | **Reaper** | Investigation of **NTLM Relay** activity using network captures and Windows authentication logs. |
| ⬜ | **CrownJewel-1** | Detection of attempts to obtain **NTDS.dit** using Volume Shadow Copy techniques. |
| ⬜ | **CrownJewel-2** | Investigation of NTDS database extraction using tools such as `ntdsutil`. |

### Key concepts

- Kerberos authentication
- NTLM authentication
- Windows Security Events
- Credential Access
- Active Directory attacks
- Lateral Movement
- Domain Controller telemetry

---

## 🌐 Phase 3 — Network Forensics

These investigations focus on reconstructing attacks using packet captures and network telemetry.

| Status | Sherlock | Focus |
|:---:|---|---|
| ⬜ | **Meerkat** | SOC-style investigation combining IDS alerts, network traffic and HTTP activity. |
| ⬜ | **Litter** | Network forensic investigation involving suspicious protocols, data transfer and possible exfiltration. |
| ⬜ | **Knock Knock** | Investigation of unusual network behavior, port knocking, FTP activity and attacker communication. |
| ⬜ | **Origins** | Investigation of brute-force activity and suspicious network communication through packet analysis. |

### Tools

- Wireshark
- tshark
- Zeek
- Suricata
- CyberChef
- Network protocol analysis

---

## 🟣 Phase 4 — Endpoint & Digital Forensics

This phase moves deeper into host-based investigations and reconstruction of attacker activity.

| Status | Sherlock | Focus |
|:---:|---|---|
| ⬜ | **Bumblebee** | Multi-source forensic investigation involving web activity, databases and malicious artifacts. |
| ⬜ | **Einladen** | Endpoint compromise investigation using forensic evidence and timeline reconstruction. |
| ⬜ | **Jingle Bell** | Windows digital forensics and filesystem artifact investigation. |
| ⬜ | **Event Horizon** | Reconstruction of malicious activity using multiple Windows forensic artifacts. |
| ⬜ | **RogueOne** | Broader DFIR investigation involving correlation of multiple sources of evidence. |

### Areas of analysis

- NTFS artifacts
- `$MFT`
- Prefetch
- Registry artifacts
- Event Logs
- Browser artifacts
- File creation/modification
- Process execution
- Timeline reconstruction

---

## 🔴 Phase 5 — Advanced Incident Response

These Sherlocks combine several sources of evidence and require a more complete SOC investigation methodology.

| Status | Sherlock | Focus |
|:---:|---|---|
| ⬜ | **Tracer** | Investigation of lateral movement and remote execution, including techniques such as PsExec. |
| ⬜ | **GroundStorm** | Ransomware-related investigation using SIEM data and Windows telemetry. |
| ⬜ | **PunkStar** | End-to-end attack investigation using SIEM, Sysmon, PowerShell and Windows Security logs. |

---

# 🔍 Investigation Methodology

For every Sherlock, I will follow approximately the same investigation process.

### 1. Initial triage

Identify:

- What triggered the investigation?
- Which systems are affected?
- Which users are involved?
- When did the suspicious activity begin?
- What data sources are available?

---

### 2. Evidence collection

Relevant evidence may include:

- Windows Event Logs
- Sysmon logs
- PowerShell logs
- Authentication logs
- Packet captures
- Web server logs
- File system artifacts
- Registry artifacts
- SIEM alerts
- Endpoint telemetry

---

### 3. Timeline reconstruction

Build a chronological view of the incident.

Example:

| Time | Host | User | Event |
|---|---|---|---|
| 10:14:21 | WS01 | user01 | Suspicious PowerShell execution |
| 10:14:24 | WS01 | user01 | External network connection |
| 10:14:28 | WS01 | user01 | Payload downloaded |
| 10:15:03 | DC01 | user01 | Suspicious Kerberos activity |

The objective is to understand the sequence of attacker actions rather than analyzing isolated events.

---

### 4. Pivoting

Investigation follows relationships between artifacts:

```text
Suspicious Process
        │
        ▼
Parent Process
        │
        ▼
User Account
        │
        ▼
Network Connection
        │
        ▼
Remote IP / Domain
        │
        ▼
Downloaded File
        │
        ▼
File Hash
        │
        ▼
Persistence / Lateral Movement