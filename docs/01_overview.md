### 01_overview.md

**Purpose**: Simulate a domain with regular users, analysts, admins. Detect, investigate, and respond to privileged identity misuse within a lab AD environment using a SIEM-based approach (Splunk indexer on Ubuntu), Windows clients and domain controllers, Sysmon, and Splunk Universal Forwarders.

**Goals**:
- Implement audit policy and GPOs to collect the required Windows security telemetry.
- Forward Windows Event Logs (including Sysmon) to Splunk which acts as the SIEM using Splunk UF with `renderXml = true` to preserve fields.
- Create deterministic detections for: 
    - unusual admin logins
    - Kerberoasting behavior (4769 spikes)
    - privilege escalation attempts
    - Pass The Hash (PTH)
- Provide playbooks for response and a runbook demonstrating each detection.

**Scope**:
- Lab-only: Windows Server (DC), Windows Client(s), Ubuntu (SIEM , Splunk indexer), Kali (attacker). Not production.

**Expected outcomes**:
- Working detections with test cases, documented runbook steps, and reproducible artifacts (sample logs, saved searches).

<br>
<div style="display: flex; justify-content: space-between;">
  <a href="README.md">⬅️ Previous: Introduction</a>
  <a href="02_architecture.md">Next: Architecture ➡️</a>
</div>