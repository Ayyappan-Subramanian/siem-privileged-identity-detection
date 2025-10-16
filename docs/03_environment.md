### Lab Inventory

| Role | Hostname | OS Version | Description |
|------|-----------|-------------|--------------|
| Domain Controller | win-dc.lab.local | Windows Server 2019 | AD DS, KDC, main event source |
| Client | win-client01 | Windows 10 Pro | Domain-joined workstation |
| SIEM | splunk-siem | Ubuntu 22.04 | Splunk Enterprise (Indexer + Search Head) |
| Attacker | kali-attacker | Kali Linux 2024 | Offensive simulation tools (Rubeus, PowerView) |

### Account Matrix

| Username | Role | Privilege Level | Description |
|-----------|------|-----------------|--------------|
| Administrator | Built-in | Domain Admin | Default domain administrator |
| admin01 | Admin | Elevated | Test admin account for privileged actions |
| analyst01 | Analyst | Standard | SOC analyst account (no admin rights) |
| service_account | Service | Limited | Has SPN mapped; used for Kerberoast testing |


### GPO / Local Policy baseline
- Local Policies -> Audit Policy: enable audit account logon events, account management, logon events, privilege use, object access (File Share, Registry if needed)
- Advanced GPO audit categories: Account Logon (Credential Validation), Account Management, Logon/Logoff (Logon, Logoff, Special Logon), Object Access (File Share), Privilege Use (SeDebugPrivilege, SeTcbPrivilege)


**Notes on testing**:
- After changing GPOs, run `gpupdate /force` and confirm events like 4720 (user created), 4769 (TGS request), 4624 (successful logon) appear in the Security log.

