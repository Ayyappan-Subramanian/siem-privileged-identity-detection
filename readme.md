# Privileged Identity Misuse Detection — SIEM Project

**Purpose:** Simulate and detect privileged identity abuse in an Active Directory environment using Splunk/ELK.

## 📚 Recommended reading flow
1. [Overview](docs/01_overview.md)
1. [Architecture](docs/architecture.md)
2. [Environment](docs/environment.md)  
3. [Detection logic & rules](docs/detections.md)  
4. [Incident playbooks](docs/playbooks.md)  
5. [Runbook/demo steps](docs/runbook.md)  
6. [Tests & sample logs](tests/test_cases.md)

## ⚡ Quick demo (5 min)
1. Boot VMs (Domain Controller, Client, SIEM, Attacker)  
2. Trigger attack (see `playbooks/playbook_kerberoast.md`)  
3. Open Splunk/ELK and view dashboards (see `splunk/dashboards/` or `elk/dashboards/`)

## Repo layout
See the `docs/` folder for narrative and `splunk/`, `configs/`, `playbooks/` for artifacts.