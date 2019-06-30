# RedGhost
Linux post exploitation framework designed to assist red teams in persistence, reconnaissance, privilege escalation and leaving no trace. 
![RG](https://user-images.githubusercontent.com/44454186/60386498-f5b2b100-9a84-11e9-92f7-e05ed9021065.PNG)
- Payloads
Function to generate various encoded reverse shells in
netcat, bash, python, php, ruby, perl
- lsWrapper 
Function to wrap the "ls" command with payload to run payload everytime "ls" is run for persistence 
- Crontab
Function to create cron job that downloads and runs payload every minute for persistence
- GetRoot
Function to try various methods to escalate privileges
- Clearlogs
Function to clear logs and make investigation with forensics difficult
- MassInfoGrab
Function to grab mass information on system
- BanIp
Function to BanIp

- Prerequisites

  dialog, gcc, iptables

- Installation

one liner to install RedGhost:

  wget https://raw.githubusercontent.com/d4rk007/RedGhost/master/redghost.sh


One liner to install reqrequisites and RedGhost:

  wget https://raw.githubusercontent.com/d4rk007/RedGhost/master/redghost.sh; apt-get install dialog; apt-get install gcc; apt-get install iptables; ./redghost.sh
