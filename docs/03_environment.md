### Pre-requisites and setup

This section gives you the details regarding environment set-up and its pre-requisites

**1. System Requirements**
- Host Machine: Capable of running multiple VMs simultaneously.
    - Minimum: 16GB, 150GB free disk space

- Virtualization Software: Oracle VirtualBox (just my preference)


**2. Operating System ISOs**
- Windows Server 2019 or 2022 ISO – for Domain Controller (Active Directory) and 

- Windows 10 ISO - for Client VM.

- Ubuntu Server 22.04 LTS ISO – for SIEM server (Splunk or ELK stack).

- Kali Linux ISO – for attacker simulation and lateral movement testing.


**3. Networking Setup**
- Virtual Network:
    - Something need to filled here

- Static IP Assignment
    - Each VM must have a static IP within the same subnet for consistent log forwarding. The below table gives you detailed network setup details:

| Role | Hostname | IP Address | Default Gateway | DNS | OS Version | Description |
|------|-----------|-------------|--------------|-------------|------------|-------|
| Domain Controller | WIN-QNNQGH26EP1 | 192.168.56.10 | 192.168.56.1 | 192.168.56.10 | Windows Server 2019 | AD DS, KDC, main event source |
| Client | win-client01 | 192.168.56.21 | 192.168.56.1 |  192.168.56.10 | Windows 10 Pro | Domain-joined workstation, victim machine |
| SIEM | splunk-siem | 192.168.56.30 | 192.168.56.1 |  192.168.56.10 | Ubuntu 22.04 | Splunk Enterprise, SIEM |
| Attacker | kali-attacker | 192.168.56.40 | 192.168.56.1 |  192.168.56.10 | Kali Linux 2024 | Offensive simulation tools (Rubeus, PowerView) |

(should check the exact host name for documentation purpose)

**4. Software and Tools**
- Splunk Enterprise - Installed on Ubuntu SIEM
- Splunk Universal Forwarder - installed on Windows DC and Client
- Sysmon (System Monitor by Microsoft)

**5. Organizational Unit (OU) Setup and Account Matrix**

The domain name: lab.local

| OU Name | domain | Privilege Level | User Component |
|-----------|------|-----------------|--------------|
| Domain Controller | lab.local | Domain Admin | LAB\Administrator |
| Admin | lab.local | Local Admin | admin01@lab.local |
| Analyst | lab.local | Analyst| analyst01@lab.local |
| Service Account | lab.local | Service Account | SPN mapped service account: service_account |

**6. Network Time Protocol (NTP)**

- Seems simple but important part of setup. Sync all VMs to the same time source so that you don't find any confusion during log correlation

---


(This should be added in the configuration part)
### GPO / Local Policy baseline
- Local Policies -> Audit Policy: enable audit account logon events, account management, logon events, privilege use, object access (File Share, Registry if needed)
- Advanced GPO audit categories: Account Logon (Credential Validation), Account Management, Logon/Logoff (Logon, Logoff, Special Logon), Object Access (File Share), Privilege Use (SeDebugPrivilege, SeTcbPrivilege)


**Notes on testing**:
- After changing GPOs, run `gpupdate /force` and confirm events like 4720 (user created), 4769 (TGS request), 4624 (successful logon) appear in the Security log.

