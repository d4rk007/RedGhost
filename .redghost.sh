#!/bin/bash
#This script is intended to be run as root
function blueghost() {
	INPUT=/tmp/menu.sh.$$
	OUTPUT=/tmp/output.sh.$$
	trap "rm $OUTPUT; rm $INPUT; exit" SIGHUP SIGINT SIGTERM

	function display_output(){
			local h=${1-10}
			local w=${2-41}
			local t=${3-Output} 
			dialog --backtitle "Ghost Network Tools" --title "${t}" --clear --msgbox "$(<$OUTPUT)" ${h} ${w}
	}

	function scanip(){
			sleep 1
			echo -e '\nConnected IP Addresses:'
			netstat -anpt | grep ESTABLISHED | awk '{ print $5 }' | cut -d: -f1 | sort -u
			echo -e '\nIP Addresses connected via SSH:'
			netstat -tnpa | grep 'ESTABLISHED.*sshd' | awk '{ print $5 }' | cut -d: -f1 | sort -u
			echo -e '\nCurrent activity on this system:'
			w
			echo -e '\n'
			read -r -p 'Enter Address to gather reconnaissance on, press enter to skip: ' lookup
			clear
			sleep .5
			echo -e '\nScanning IP address: '$lookup'...\n'
			echo -e 'Open ports and whois data:'
			nmap $lookup | grep open
			whois $lookup | grep 'Country:\|OrgName:\|StateProv:\|City:\|OrgTechName:\|NetRange:\|Organization:'
			echo -e '\nIP address abuse report from abuseipdb.com:'
			curl -v --silent https://www.abuseipdb.com/check/$lookup 2>&1 | grep "This IP" | sed 's/<\/*[^>]*>//g'
	}

	function banip(){
			scanip
			echo -e '\nDo you want to ban a IP address or scan another IP address?'
			read -p 'enter (b/s) or press enter to return to menu: ' bs	
				case $bs in
				[Bb]* ) read -r -p  'Enter IP to be banned: ' address; iptables -A INPUT -s $address -j DROP;;
				[Ss]* ) scanip
						read -r -p "Press Enter to continue";;
			esac
	}
	
	function Unban(){
			read -r -p 'Would you like to unban a IP address? (Press enter to continue or ctrl + c to exit): '
			echo -e '\n'
			read -r -p 'Enter IP address to be unbanned: ' address
	
			iptables -D INPUT -p all -s $address -j DROP
			iptables -D OUTPUT -p all -s $address -j DROP
	}

	function ListAllBanned(){
			iptables -L -n --line | more
			read -r -p "Press Enter to continue"
			clear
	}
	
	function tracert(){
			clear
			sleep .5
			echo 'Connected IP addresses:'
			netstat -anpt | grep ESTABLISHED | awk '{ print $5 }' | cut -d: -f1 | sort -u
			echo -e '\n'
			read -r -p 'Enter address to be tracerouted: ' address
			traceroute $address
	
	}
	
	function schjobs(){
			 clear
			 crontab -l 
			 ls -alh /var/spool/cron
			 ls -al /etc/ | grep cron
			 ls -al /etc/cron*
			 cat /etc/cron*
			 cat /etc/at.allow
			 cat /etc/at.deny
			 cat /etc/cron.allow
			 cat /etc/cron.deny

			 read -p "Press enter to continue "
	
	}

	function installed(){
			clear
			ls -alh /usr/bin/
			ls -alh /sbin/
			dpkg -l
			read -p "Press enter to continue "

	}

	while true
	do

	dialog --clear --nocancel --backtitle "Coded by d4rkst4t1c.." \
	--title "[ B L U E G H O S T - N E T W O R K - T O O L ]" \
	--menu "This tool is designed to help administrators prevent/ban connected attackers on linux servers." 15 60 7 \
	Scan/Ban "Scan & Ban unwanted IPs" \
	UnbanAnAddress "Unban a banned IP" \
	ListAllBanned "List all banned IPs" \
	TraceRoute "TraceRoute a IP address" \
	ScheduledJobs "View all scheduled jobs" \
	Apps "View installed applications" \
	Exit "" 2>"${INPUT}"

	menuitem=$(<"${INPUT}")

	case $menuitem in
		Scan/Ban) banip;;
		UnbanAnAddress) Unban;;
		ListAllBanned) ListAllBanned;;
		TraceRoute) tracert;;
		ScheduledJobs) schjobs;;
		Apps) installed;;
		Exit) clear; break;;
	esac

	done

	[ -f $OUTPUT ] && rm $OUTPUT
	[ -f $INPUT ] && rm $INPUT
}
