![Wifiknockd](/images/wifiknockd.png?raw=true&s=100)
# 802.11 Wi-Fi Knockd service #

*Copyright (c) 2018, by Yago Hansen - Twitter:@yadox*

## About:
Some day I was configuring the practical knock daemon in Linux used to protect you against
network attacks to exposed open ports and services, and noticed that it could be a good
option to create a secret Wi-Fi knockd service that monitors for a specific forged packet
that triggers any services on or off, runs commands, etc. The architecture of this tool is
client/server. The server should be Linux based and the client can also be any Smartphone,
Tablet, Windows, etc. At the end we are using a covert channel communication type to get
actions executed by the server.

In order to use this kind of service,  it will be necessary to have a "monitor mode" Wi-Fi 
interface sniffing for a specific kind of 802.11 packet. To avoid complicated configurations, 
the expected packet will be a 802.11 Probe Request frame, direct probing for a wifi network 
with a specific forged SSID. The frame SSID field will contain the command requesting to execute, 
but for security reasons it will be encrypted by AES-CBC 128  and it will use a unique sequence 
number to avoid replay attacks also. 

When receiving a valid forged probe request frame, the server will (if configured by parameter) 
respond with a directed probe response with an ACK value, confirming requested execution. If you
specify in the configuration files the ports to be handled, when entering the script, all these
ports will be automatically blocked for every connection. When exiting the script, the closed 
ports will be opened automatically, the switched on GPIOs will be switched off, and the created 
AP will be automatically switched off.


## WiFiknockd service
* Author:		Yago [@yadox](https://twitter.com/yadox) Hansen - 2018.
* Language:  		Python 2.7.
* Format:    		Script as system daemon.
* Libraries: 		Look at requirements.txt file.
			[pip install -r requirements.txt]
* DST Hardware:  	Raspberry Pi, Gl.inet AR300M, PC.
* Requirements:		Linux OS, Python 2.7, Scapy 2.3.
			WiFi interface that supports  monitor mode.
			Internal Wi-Fi interface for AP.
			hostapd, dnsmasq, iptables.

* Packet type:  	Actions by Probe request frame
* Security:     	ACK by Probe response frame.
			Specific BSSID MAC to monitor actions.
	      		MAC whitelist specified.
	      		Payload encripted by AES-CBC 128 (simmetric key+IV).
			Replay protection by pkt seq in encrypted msg.


## Functions:
- Start AP with requested config: [ap1\~ssid,wpa,key,channel,hidden\~timeout]
- Kill AP: [ap0]
- Open requested TCP/UDP ports by firewall: [pr1\~22,80,443,67U\~timeout]
- Block requested TCP/UDP ports by firewall:  [pr0\~22,80,443,67U]
- Switch circuit on:  [sw1\~logical_number\~timeout]
- Switch circuit off:  [sw0\~logical_number]
- Execute command: [exe\~command with arguments\~timeout]

After executing any action, if configured in configuration file, an ACK is
sent to the client using a probe response frame with SSID field encrypted,
including action sequence number and return code. 

There are two modes for learrning or debugging purposes: 

* debug mode:  can be activated inside both .py scripts with var "debug = True"
* verbose mode: can be activated inside wifiknockd.conf configuration file with "verbose = True"

> Debug mode is more verbose than verbose mode, showing packet dissections in 
and discarded packets in screen. Verbose mode shows more info in screen than
standard mode, and also saves packets in standard pcap format, readable by
Wireshark to /tmp/wifiknockd.cap and /tmp/wifiknockd_client.cap


## Installation
The installer script will copy /etc/init.d/wifiknockd.sh and activate the 
service in order to start it automatically during Linux boot. It will also
copy configuration files and python scripts to the /bin/ directory.Run:

```
$ sudo apt-get update && sudo apt-get install python python-pip -y

$ git clone https://github.com/yadox666/wifiknockd/

$ cd wifiknockd/

$ chmod 755 ./install.sh

$ ./install.sh
```

## Sample configuration file (/etc/wifiknock.conf)
Edit /etc/wifiknockd.conf to change settings. Use the included example as template
and do not use quotes or single quotes. All the comments have to be preceded by 
semicolon sign. Do not move options between sections or delete [default] section.
```
[default]
verbose = True  ;; verbosity level (0-3)
use_ack = True  ;; respond to rx probe sending ack probes
use_encryption = True  ;; encrypt probe payload
encryption_key = matrix  ;; probe payload encryption key

listen_iface = wlan1 ;; interface to listen for probes
ap_iface = wlan5  ;; interface to create AP
ap_gateway = eth0  ;; gateway interface to internet for AP

listen_channel = 3  ;; Channel to listen to
listen_bssid = 00:40:96:01:02:03 ;; destination BSSID MAC Address
mac_whitelist = aa:06:12:a5:95:33  ;; mac address list separated by commas
ports_blocked = 80,443,22,67U  ;; default ports to block when entering
```
You must specify both wireless monitor mode interface (listen_iface, ex: wlan1) and
AP capable interface (ap_iface, ex: wlan0). Monitor mode interface for client and 
server scripts will be initialized automatically when entering scripts. 

## WiFiknockd Python client:
I developed another python script "wifiknockd_client.py", that is also included
and installed inside /bin/ directory. This script can be used to test wifiknockd
in the same computer or in another computer with a monitor mode WiFi card and also
running it as root user.

Both scripts share the same configuration file: /etc/wifiknockd.conf when installed
in the same computer or board.

```
usage: wifiknockd_client.py [-h] [-a APMODE] [-g GPIOLIST] [-p PORTLIST]
                            [-e EXECUTE] [-1] [-0] [-d] [-q]
-----------------------------------------------------------------------------------
optional arguments:
  -h, --help            show this help message and exit
  -a APMODE, --apmode APMODE
                        Enter Access Point mode: ssid,[wpa,open],key,channel,hidden[1/0]
  -g GPIOLIST, --gpiolist GPIOLIST
                        Enter a GPIO port number or a list separated by commas
  -p PORTLIST, --portlist PORTLIST
                        Enter a TCP port number or a list separated by commas  [UDP ports must include U after port]
  -e EXECUTE, --execute EXECUTE
                        Enter a command to execute
  -t TIMEOUT, --timeout TIMEOUT
                        Timeout for the required action (Stop action after n secs)
  -1, --on              Switch ON requested action (selected by default)
  -0, --off             Switch OFF requested mode
  -i, --reqinitmon      Start monitor mode VAP
  -d, --debug           If debug is passed, more verbose messages will be
                        shown
  -q, --quiet           If quiet is passed, verbose messages wont be shown
```

## Examples:
```
python wifiknockd_client.py -1 -p80,22,443,67U
python wifiknockd_client.py -1 -a "rogueAP,wpa,password,13,0"
python wifiknockd_client.py -e "service apache2 stop"
```

## TO-DO:
[TO-DO thoughts](/TODO) 

## Further reading:
[PoC presented in Mundo Hacker Day 2018 - Madrid](http://mundohackerday.com/)


