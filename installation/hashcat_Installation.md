Bypass PowerShell execution policy:
```bash
Set-ExecutionPolicy Bypass -Scope Process -Force
```

Install Chocolatey:
```bash
iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
```

Install Hashcat via Chocolatey:
```bash
choco install hashcat -y
```


To verify installation:
```bash
hashcat --version
```