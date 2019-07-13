# RedGhost
Linux post exploitation framework designed to assist red teams in persistence, reconnaissance, privilege escalation and leaving no trace. 
![RG](https://user-images.githubusercontent.com/44454186/61165432-0ac12280-a510-11e9-8a44-191c36d49fe5.PNG)
- Payloads

  Function to generate various encoded reverse shells in
  netcat, bash, python, php, ruby, perl

- SudoWrapper

Function to inject sudo command with wrapper function to run a reverse root shell everytime "sudo" is run for privilege     escalataion

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


## Installation

one liner to install RedGhost:
```
wget https://raw.githubusercontent.com/d4rk007/RedGhost/master/redghost.sh; chmod +x redghost.sh; ./redghost.sh
```

One liner to install prerequisites and RedGhost:
```
wget https://raw.githubusercontent.com/d4rk007/RedGhost/master/redghost.sh; chmod +x redghost.sh; apt-get install dialog; apt-get install gcc; apt-get install iptables; ./redghost.sh
```

### Prerequisites

dialog, gcc, iptables
