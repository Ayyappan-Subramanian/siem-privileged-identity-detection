## Splunk Installation on Ubuntu SIEM

1. Firstly, download the Splunk.deb package to the system.

2. Install, the downloaded debian package
```bash
sudo dpkg -i splunk-9.2.0-amd64.deb
```

3. Start and Enable Splunk
```bash
sudo /opt/splunk/bin/splunk start --accept-license
sudo /opt/splunk/bin/splunk enable boot-start
```
Now to access Splunk go to `http://<Ubuntu_IP>:8000`

## Splunk UF installation

**Prerequisite:** Before configuring forwarder, we should enable splunk to receive forwarded data on Ubuntu SIEM. 

To receive logs from Windows (or other endpoints), Splunk must open a network port (default 9997) and listen for incoming data on that port. This allows the Splunk Universal Forwarders (installed on Windows machines) to send logs over the network to your Ubuntu Splunk. 

If Splunk is not listening on port 9997, Windows forwarders cannot send their logs.

```bash
sudo /opt/splunk/bin/splunk enable listen 9997
```
This tells Splunk to open port 9997 and wait for incoming logs.



1. Go to Splunk UF download page and download Splunk UF

2. Set the forwarder server
```bash
cd "C:\Program Files\SplunkUniversalForwarder\bin"
.\splunk add forward-server <Ubuntu_IP>:9997 -auth admin:<password>
```
3. Create the inputs.conf file

inputs.conf file defines which log sources (files, event logs, directories, or scripts) the Splunk Universal Forwarder should monitor and forward to the indexer.

Refer [input config file](../config/splunk_uf/inputs.conf) to see what log sources are added

4. Restart the forwarder
```bash
.\splunk restart

#or

net stop splunkforwarder
net start splunkforwarder

# Note: Restart splunk, whenever you make changes in input.conf
```

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


(Note: This guides gives you a summarized instruction of installation. However, it has more configuration details to deal with during installation which could be complex to discuss everything in the text)
