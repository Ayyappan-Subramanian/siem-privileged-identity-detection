## Sysmon Installation and Configuration

1. Download sysmon from Microsoft Sysinternals

2. Download a sysmon configuration file
```bash
curl -L -o sysmonconfig.xml https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml
```
This downloads a community maintained Sysmon configuration file (SwiftOnSecurity) that defines which events sysmon logs.

3. Install sysmon with the config
```bash
cd "C:\Tools\Sysmon"
.\Sysmon64.exe -accepteula -i sysmonconfig.xml
```
4. To verify installation, run
```bash
.\Sysmon64.exe -c
```


If in case of update/reload sysmon config, run
```bash
.\Sysmon64.exe -c sysmonconfig.xml
```

**To confirm logging check:** Event Viewer → Applications and Services Logs → Microsoft → Windows → Sysmon → Operational