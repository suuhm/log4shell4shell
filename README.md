# log4shell4shell
Log4j - Multitool. Find &amp; fix possible CVE-2021-44228 vulneraries - provides a complete LOG4SHELL test/attack environment

![Thumb](/logo_banner.png )

# Features

- check your System for CVE-2021-44228 vulneraries
- fix yout system by deleting log4j java class
- you can run a dummy spring boot server for testing the exploit by yourself (https://github.com/christophetd/log4shell-vulnerable-app)
- you can run a attack against a wished IP-Port and include a Base64 Command / Or A simple Reverse Shell
- full ip-range scanning by https://github.com/fullhunt/log4j-scan

### This script is easy to run on your linux distribution by:

```bash
wget https://raw.githubusercontent.com/suuhm/log4shell4shell/main/log4shell4shell.sh -qO- | bash -s -- --check-system
```

#### Run a sample attack against IP: 10.4.4.20 Port 8080 and additionally a Reverse Proxy Shell :

```bash
./l4s4s.sh --run-attack 10.4.4.20:8080 -e
```

#### Run a full scan  IP: 10.4.4.20 Port 8080 and additionally a try all tests :

```bash
./l4s4s.sh --python-scan "-u 10.4.4.20:8080 --run-all-tests"
```


### Options

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

### This script is alpha! So please let me know if you have some issues

### Legal Disclaimer

The project log4shell4shell is made for educational and ethical testing purposes only. Usage of log4j-scan for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program.
