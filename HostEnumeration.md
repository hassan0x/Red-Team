getuid<br>
pwd<br>
ls<br>
ps<br>
run systeminfo<br>
<br>
net domain<br>
net domain_controllers<br>
net computers<br>
net user<br>
net user \\hydra-dc<br>
net localgroup<br>
net group \\hydra-dc<br>
net logons<br>
net logons \\hydra-dc<br>
net share<br>
net share \\hydra-dc<br>
<br>
shell net user<br>
shell net user /domain<br>
shell net localgroup<br>
shell net group /domain<br>
shell net share<br>
shell net view \\localhost /all<br>
shell net view \\hydra-dc /all<br>
<br>
### Seatbelt (https://github.com/GhostPack/Seatbelt)<br>
execute-assembly /root/Seatbelt.exe AntiVirus<br>
execute-assembly /root/Seatbelt.exe -group=all<br>
execute-assembly /root/Seatbelt.exe -group=system<br>
execute-assembly /root/Seatbelt.exe -group=user<br>
<br>
