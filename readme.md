# Privileged Identity Misuse Detection — SIEM Project

**Purpose:** Splunk-based detection system in a virtual environment, ingesting logs from AD/LDAP to monitor for privileged identity misuse

## Table of Contents

1. [🚀 Introduction](#-introduction)
2. [📚 Recommended Reading Flow To Quick Start](#-recommended-reading-flow-to-quick-start)
3. [🧠 Key Features](#-key-features)
4. [⚙️ Installation Pre-requisites & Setup](#️-installation-pre-requisites--setup)
5. [🔍 Detection Logic](#-detection-logic)
6. [🧪 Testing & Validation](#-testing--validation)
7. [🔒 Security Hardening](#-security-hardening)
8. [🧩 Future Scope](#-future-scope)
9. [📚 References](#-references)


## 🚀 Introduction

The **Privileged Identity Misuse Detection System** is a SIEM-driven project designed to detect, analyze, and visualize abuse of **privileged credentials** across Windows and Linux systems.

It simulates **real-world attacks** such as Pass-the-Hash, Kerberoasting, privilege escalation, unauthorized admin logins, and lateral movement, while leveraging Splunk or ELK Stack as the central log correlation and detection engine.

Built to showcase real-world **SOC detection engineering** and **incident response capabilities.**


## 📚 Recommended Reading Flow To Quick Start
1. [Overview](docs/01_overview.md)
1. [Architecture](docs/02_architecture.md)
2. [Environment](docs/03_environment.md)
4. [Detection Validation Playbook - Kerberoasting](playbooks/kerberoasting.md)
5. [Detection Validation Playbook - Pass-The-Hash](playbooks/pass_the_hash.md)
6. [Installation Files](installation)


## 🧠 Key Features

🕵️ Privileged Identity Monitoring – Detects suspicious admin logins, privilege escalations, and AD account abuses.

⚙️ Cross-Platform Visibility – Integrates Windows Sysmon and Linux Auditd logs into Splunk/ELK.

📡 MITRE ATT&CK Mapping – Detection rules aligned to ATT&CK framework.

📊 Custom Dashboards – Visualize user access anomalies and privilege activities.

🧪 Red Team Simulation – Executes real attacks using Kali Linux for validation.

🧾 Detection as Code – SPL / Sigma rules for reproducible detection pipelines.


## ⚙️ Installation Pre-requisites & Setup

### Pre-requisites
- Virtualization: VirtualBox / VMware / Proxmox
- OS: Ubuntu (SIEM), Windows Server, Windows Client, Kali Linux
- Minimum specs: 4GB RAM (each), 40GB disk
- Static IP assignment for all VMs

**Setup:** Refer [Installation](installation/)


## 🔍 Detection Logic

Each detection rule is implemented in Splunk SPL format

Example for Kerberoasting:
```bash
index=wineventlog sourcetype="XmlWinEventLog:Security" 
| spath 
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>" 
| search EventID=4769
| rex field=_raw "<Data Name='TargetUserName'>(?<AccountName>[^<]+)</Data>"
| rex field=_raw "<Data Name='ServiceName'>(?<ServiceName>[^<]+)</Data>"
| bucket _time span=1m
| stats count as ServiceTicketCount, dc(ServiceName) as UniqueSPNCount, values(ServiceName) as TargetedSPNs by AccountName, ServiceName _time
| where ServiceTicketCount > 5
| sort _time desc
```
Example for Pass-The-Hash (PTH):
```bash
index=wineventlog 
| spath 
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| rex field=_raw "<Data Name='LogonType'>(?<LogonType>[^<]+)</Data>"
| rex field=_raw "<Data Name='LogonId'>(?<LogonId>[^<]+)</Data>"
| rex field=_raw "<Data Name='LogonType'>(?<LogonType>[^<]+)</Data>"
| rex field=_raw "<Data Name='TargetUserName'>(?<TargetUserName>[^<]+)</Data>"
| rex field=_raw "<Data Name='TargetDomainName'>(?<TargetDomainName>[^<]+)</Data>"
| rex field=_raw "<Data Name='ParentProcessName'>(?<ParentProcessName>[^<]+)</Data>"
| rex field=_raw "<Data Name='IpAddress'>(?<IpAddress>[^<]+)</Data>"
| where EventID=1
| where LogonId="0x26bb03"
```

**For full logic detections and analysis refer** [playbooks](playbooks/)


## 🧪 Testing & Validation

### Validating Splunk UF Service in Windows PowerShell

```bash
# Check Splunk UF service status
sc query splunkforwarder

# OR using PowerShell
Get-Service splunkforwarder

# Restart service if needed
Restart-Service splunkforwarder
```
**Note:** Splunk UF service needs to be restarted whenever there is a change in inputs.conf

### Validate Sysmon Service

```bash
# Check Sysmon service status
sc query sysmon64

# OR
Get-Service sysmon64

# Restart Sysmon if stopped
Restart-Service sysmon64
```

### Validate Data Ingestion in Splunk

```bash
#All Windows logs
index=wineventlog | stats count by host, sourcetype

#security events
index=wineventlog sourcetype="WinEventLog:Security" | stats count by host

#sysmon logs
index=sysmon | stats count by Image, ParentImage
```


## 🔒 Security Hardening

- Enforce least-privilege access in Splunk/ELK.
- Use TLS for log forwarding.
- Implement role-based dashboard access.
- Regular rotation of SIEM credentials.


## 🧩 Future Scope

- SOAR Integration: Optional XSOAR / Shuffle / TheHive for automated alert response.
- Email Alerts: Configured via Splunk alert actions.
- API Hooks: REST API endpoints for future enrichment modules.


## 📚 References

- [MITRE ATT&CK](https://attack.mitre.org/)
- [Splunk](https://www.splunk.com/)
- [Sysmon Config by SwiftOnSecurity](https://github.com/SwiftOnSecurity/sysmon-config)