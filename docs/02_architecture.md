## 02_Architecture

This section describes how the system is strcutured - the overall design, data flow, components and connections.

**High level diagram**: include `diagrams/network-arch.drawio` and exported PNG.

**Components**:
- Windows Server (Domain Controller - AD) — runs AD DS, Security Event Logs, KDC; event source for 4720/4728/4769/etc.
- Windows Client(s) — User activity, Sysmon, PowerShell, process execution. Consists of different roles in OU: Member/Admin/Analyst
- Ubuntu (SIEM) — Splunk Enterprise (Indexer, acts as SIEM), listening on port 9997 for Universal Forwarder traffic.
- Kali Linux — attacker VM to run Rubeus, PowerView, and other offensive tooling.

**Log flow and ports**:
1. Windows Domain Controller (DC)
    - **Flow:** Windows Event Logs (Security, System, Directory Services) and Sysmon -> Splunk Universal Forwarder (UF) -> Splunk Indexer (Ubuntu SIEM)
    - Protocol / Port: TCP 9997 (Splunk receiver).

    - The Splunk UF is configured with inputs.conf (refer config/inputs.conf) to forward Security and Sysmon events. Used "renderXml = true" for Windows Event XML preservation.

2. Windows Client (domain-joined)
    - **Flow:** Windows Event Logs (Security, Application), Sysmon, PowerShell logging → Splunk UF → Splunk Indexer (Ubuntu).

    - **Protocol / Port:** TCP 9997.

    - In a similar way, the Splunk UF is also installed and configured in Windows Client VM as like in Windows DC. Installed Sysmon and properly tuned config to capture process/create, network connect, and logon events. Use inputs.conf on UF to set correct sourcetype (e.g., XmlWinEventLog:Microsoft-Windows-Sysmon/Operational or XmlWinEventLog:Security).

3. Ubuntu (SIEM/Splunk Indexer)
    - **Flow:** Receives forwarded Windows UF traffic from multiple hosts; Also, the log flows could include collecting local logs (Auditd, Syslog, Splunk internal logs) which I considered it as optional.

    - **Protocol / Port:** TCP 9997 (UFs → indexer), HTTP(S) 8000 (Splunk Web UI)

    - Enable the 9997 receiver. Use index naming conventions if you want. To double check incoming host use search like index=* | stats count by host

4. Kali (Attacker VM)
    - **Flow:**: Attack simulation traffic could be forwarded optionally by installing forwarder like Auditd to send logs to splunk. There is no point in forwarding logs from attacker VM since it doesn't align with reality. So, I just skipped it.

5. Splunk Web Access
    - **Protocol / Port:** HTTP or HTTPS 8000 (default)

    - For lab use HTTP is fine; in production use HTTPS and restrict access. If Splunk Web is on a different host, open port 8000 appropriately.

### Data sources collected
- Windows Security, System, Application, Windows PowerShell, Microsoft-Windows-Sysmon/Operational
- (Optional) Forwarded audit logs from `auditd` on Linux hosts


### General Troubleshooting / verification notes
- On SIEM (i.e. Ubuntu VM), confirm the listener `sudo /opt/splunk/bin/splunk show listen` or if not listening run `sudo /opt/splunk/bin/splunk enable listen 9997` then you will see "Listening for Splunk Universal Forwarders on port 9997"

- On both Windows Client and Windows DC, to confirm the Splunk UF status run `splunk list forward-server` and you should see something like "<SIEM-IP>:9997 Active" status.

- In Splunk search: run `index=* | stats count by host, sourcetype` to confirm which hosts/sourcetypes are sending events.

**Notes:** You should see more configuration details related to this in `/config` folder

<br>
<div style="display: flex; justify-content: space-between;">
  <a href="01_overview.md">⬅️ Previous: Overview</a>
  <a href="03_environment.md">Next: Environment ➡️</a>
</div>
