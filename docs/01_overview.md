### 01_overview.md

**Purpose**: Detect, investigate, and respond to privileged identity misuse within a lab AD environment using a SIEM-based approach (Splunk indexer on Ubuntu), Windows clients and domain controllers, Sysmon, and Splunk Universal Forwarders.

**Goals**:
- Implement audit policy and GPOs to collect the required Windows security telemetry.
- Forward Windows Event Logs (including Sysmon) to Splunk with `renderXml = true` to preserve fields.
- Create deterministic detections for: unusual admin logins, Kerberoasting behavior (4769 spikes), privilege escalation attempts, suspicious service account modifications, and object access of critical assets.
- Provide playbooks for response and a runbook demonstrating each detection.

**Scope**:
- Lab-only: Windows Server (DC), Windows Client(s), Ubuntu (Splunk indexer), Kali (attacker). Not production.

**Expected outcomes**:
- Working detections with test cases, documented runbook steps, and reproducible artifacts (sample logs, saved searches).