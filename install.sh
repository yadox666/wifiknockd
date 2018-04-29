#!/bin/bash
# WiFiknockd install Script
# by @yadox (2018)

function checkmac(){
	local inmac=$1
	result=$(echo $inmac | sed -n "/^\([0-9A-Fa-f][0-9A-Fa-f]:\)\{5\}[0-9A-Fa-f][0-9A-Fa-f]$/p")
	if [ "$result" ] ; then
		return 0
	fi
	return 1
}

function checkport(){
	local port_num=$1
	if [[ "$port_num" =~ ^([uU]) ]] ; then
		return 1
	fi
	port_num="${1//[!0-9]/}"
	if (( $port_num < 1 || $port_num > 65535 )) ; then
		return 1
	fi
	return 0
}

echo " _       _ _       ____  _                           "
echo "| |     / (_)     / __/ (_)  _   _   _   _   _   _  "
echo "| | /| / / / __  / /_  / /  / \ / \ / \ / \ / \ / \ "
echo "| |/ |/ / / /_/ / __/ / /  ( k | n | o | c | k | d )"
echo "|__/|__/_/     /_/   /_/    \_/ \_/ \_/ \_/ \_/ \_/ "
echo "===================================================="
echo "  WiFi(802.11) Knockd installer script, by @yadox"
echo "===================================================="
echo ""

if ping -W1 -w1 -c1 google.com >/dev/null 2>&1  ; then
	echo "Installing required Python libraries..."
	pip install -r ./requirements.txt
	echo ""
else
	echo "Error. No internet connection!"
	echo "Cannot install required Python libraries. Exiting now!"
	echo ""
	exit 2
fi

echo "Creating wifiknockd.conf configuration file in /etc/..."
echo '[default]' >/etc/wifiknockd.conf
echo "verbose = False  ;; verbosity level (True,False)" >>/etc/wifiknockd.conf

read -N1 -p "Is this wifiknockd server system [Y,n]? " is_server
[ "$is_server" == "Nn" ] && is_server=0 || is_server=1
echo ""

if [ $is_server == 1 ] ; then
	read -r -N1 -p "Do you want to send Action ACK (recommended) [Y,n]? " use_ack
	[[ "$use_ack" =~ ^([yY][eE][sS]|[yY])+$ ]] && use_ack='True' || use_ack='False'
	echo "use_ack = $use_ack  ;; respond to rx probe sending ack probes" >>/etc/wifiknockd.conf
	echo ""

	read -N1 -p "Do you want to cipher packets (recommended) [Y,n]? " use_encryption
	[[ "$use_encryption" =~ ^([yY][eE][sS]|[yY])+$ ]] && use_encryption='True' || use_encryption='False'
	echo "use_encryption = $use_encryption  ;; encrypt probe payload" >>/etc/wifiknockd.conf
	echo ""
	read -p "Enter master encryption key [min 8 char]: " encryption_key
	if [ ${#encryption_key} -lt 8 ] ; then
		echo "Encryption key is to short ($encryption_key). Minimun length 8 chars!"
		exit 6
	fi
	echo "encryption_key = $encryption_key  ;; probe payload encryption key" >>/etc/wifiknockd.conf
	echo "" >>/etc/wifiknockd.conf

	# Ask for interface and Check if it's present
	read -p "Enter monitor mode WLAN card parent [ex: wlan1]: " listen_iface
	if [ ! -d "/sys/class/net/$listen_iface" ] ; then
		echo "Specified interface ($listen_iface) is NOT present. Exiting!"
		exit 1
	fi
	echo "listen_iface = $listen_iface ;; interface to listen for probes" >>/etc/wifiknockd.conf

	read -p "Enter channel to listen in [1-13]: " listen_channel
	if (( $listen_channel < 1 || $listen_channel > 120 )) ; then
		echo "Wrong channel specified ($listen_channel). Exiting!"
		exit 4
	else
		echo "listen_channel = $listen_channel  ;; Channel to listen to" >>/etc/wifiknockd.conf
	fi

	read -p "Enter any valid MAC address to listen frames [ex: 00:40:96:01:02:03]: " listen_bssid
	if checkmac "$listen_bssid" ; then
		echo "listen_bssid = $listen_bssid ;; destination BSSID MAC Address" >>/etc/wifiknockd.conf
	else
		echo "Wrong MAC format specified ($listen_bssid). Exiting!"
		exit 4
	fi

	read -p "Enter authorized MACs separated by commas as source for frames [ex: AA:06:12:A5:95:33]: " mac_whitelist
	IFS=','
	for mac in $mac_whitelist ; do
		if ! checkmac "$mac" ; then
			echo "Wrong MAC format specified ($mac). Exiting!"
			IFS=' '
			exit 4
		fi
	done
	IFS=' '
	echo "mac_whitelist = $mac_whitelist  ;; mac address list separated by commas" >>/etc/wifiknockd.conf

	# Ask for interface and Check if it's present
	read -p "Enter AP mode WLAN card parent [ex:wlan0]: " ap_iface
	if [ ! -d "/sys/class/net/$ap_iface" ] ; then
		echo "Specified interface ($ap_iface) is NOT present. Exiting!"
		exit 1
	fi
	echo "ap_iface = $ap_iface  ;; interface to create AP" >>/etc/wifiknockd.conf

	# Ask for interface and Check if it's present
	read -p "Enter Internet gateway interface [ex: eth0]: " ap_gateway
	if [ ! -d "/sys/class/net/$ap_gateway" ] ; then
		echo "Specified interface ($ap_gateway) is NOT present. Exiting!"
		exit 1
	fi
	echo "ap_gateway = $ap_gateway  ;; gateway interface to internet for AP" >>/etc/wifiknockd.conf
	echo "" >>/etc/wifiknockd.conf

	read -p "Enter default TCP,UDP port list to be blocked [ex: 80,443,22,67U]: " ports_blocked
	IFS=','
	for port in $ports_blocked ; do
		if ! checkport "$port" ; then
			echo "Wrong Port specified ($port). Exiting!"
			IFS=' '
			exit 4
		fi
	done
	echo "ports_blocked = $ports_blocked  ;; default ports to block when entering" >>/etc/wifiknockd.conf
	IFS=' '

	echo "Installing python scripts..."
	chmod 755 ./wifiknockd.py
	cp ./wifiknockd.py /sbin/

	chmod 755 ./wifiknockd_client.py
	cp ./wifiknockd_client.py /sbin/

	echo "Installing wifiknockd.sh boot daemon..."
	chmod 755 ./wifiknockd.sh
	cp ./wifiknockd.sh /etc/init.d/
	sudo update-rc.d -f wifiknockd.sh defaults
else
	read -N1 -p "Do you want to cipher packets (recommended) [Y,n]? " use_encryption
	[ "$use_encryption" == "Nn" ] && use_encryption = 'False' || use_encryption = 'True'
	echo "use_encryption = $use_encryption  ;; encrypt probe payload" >>/etc/wifiknockd.conf
	echo ""
	read -p "Enter master encryption key [min 8 char]: " encryption_key
	echo "encryption_key = $encryption_key  ;; probe payload encryption key" >>/etc/wifiknockd.conf
	echo "" >>/etc/wifiknockd.conf

	read -p "Enter monitor mode WLAN card parent [ex: wlan1]: " listen_iface
	if [ ! -d "/sys/class/net/$listen_iface" ] ; then
		echo "Specified interface ($listen_iface) is NOT present. Exiting!"
		exit 1
	fi
	echo "listen_iface = $listen_iface ;; interface to listen for probes" >>/etc/wifiknockd.conf

	read -p "Enter channel to send frames [1-13]: " listen_channel
	echo "listen_channel = $listen_channel  ;; Channel to listen to" >>/etc/wifiknockd.conf
	read -p "Enter wifiknockd server\'s destination MAC address [ex: 00:40:96:01:02:03]: " listen_bssid
	echo "listen_bssid = $listen_bssid ;; destination BSSID MAC Address" >>/etc/wifiknockd.conf
	read -p "Enter any valid MAC address as source for frames [ex: AA:06:12:A5:95:33]: " mac_whitelist
	echo "mac_whitelist = $mac_whitelist  ;; mac address list separated by commas" >>/etc/wifiknockd.conf

	echo "ap_iface = $ap_iface  ;; interface to create AP" >>/etc/wifiknockd.conf
	echo "ap_gateway = $ap_gateway  ;; gateway interface to internet for AP" >>/etc/wifiknockd.conf
	echo "" >>/etc/wifiknockd.conf
	echo "ports_blocked = $ports_blocked  ;; default ports to block when entering" >>/etc/wifiknockd.conf

	echo "Installing python scripts..."
	chmod 755 ./wifiknockd_client.py
	cp ./wifiknockd_client.py /sbin/
fi
