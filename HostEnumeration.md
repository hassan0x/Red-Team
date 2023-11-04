### Info commands
```shell
getuid
pwd
ls
ps
run systeminfo
```

### Cobalt net command
```shell
net domain
net domain_controllers
net computers
net user
net user \\hydra-dc
net localgroup
net group \\hydra-dc
net logons
net logons \\hydra-dc
net share
net share \\hydra-dc
```

### Native net command
```shell
shell net user
shell net user /domain
shell net localgroup
shell net group /domain
shell net share
shell net view \\localhost /all
shell net view \\hydra-dc /all
```

### Seatbelt (https://github.com/GhostPack/Seatbelt)
```shell
execute-assembly /root/Seatbelt.exe AntiVirus
execute-assembly /root/Seatbelt.exe -group=all
execute-assembly /root/Seatbelt.exe -group=system
execute-assembly /root/Seatbelt.exe -group=user
```
