### 02_architecture.md

This section describes how the system is strcutured - the overall design, data flow, components and connections.

**High level diagram**: include `diagrams/network-arch.drawio` and exported PNG.

**Components**:
- Windows Server (Domain Controller - AD) — runs AD DS, Security Event Logs, KDC; event source for 4720/4728/4769/etc.
- Windows Client(s) — user activity, Sysmon, PowerShell, process execution.
- Ubuntu (SIEM) — Splunk Enterprise (Indexer + Search Head in lab), listening on port 9997 for Universal Forwarder traffic.
- Kali Linux — attacker VM to run Rubeus, PowerView, and other offensive tooling.

**Log flow and ports**:
- Windows UF -> Splunk indexer (TCP 9997)
- Splunk web/UI -> 8000 (default) on Ubuntu
- Note: `sudo /opt/splunk/bin/splunk enable listen 9997` must be run on the SIEM indexer.

**Data sources collected**:
- Windows Security, System, Application, Windows PowerShell, Microsoft-Windows-Sysmon/Operational
- (Optional) Forwarded audit logs from `auditd` on Linux hosts

**Known blockers**:
- Sysmon logs not forwarded if inputs.conf doesn't define `Microsoft-Windows-Sysmon/Operational` or if UF permissions block access to the Sysmon channel. Documented in `99_appendix.md`.