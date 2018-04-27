#!/bin/bash
# WiFiknockd install Script
# by @yadox (2018)

echo " _       _ _       ____  _                           "
echo "| |     / (_)     / __/ (_)  _   _   _   _   _   _  "
echo "| | /| / / / __  / /_  / /  / \ / \ / \ / \ / \ / \ "
echo "| |/ |/ / / /_/ / __/ / /  ( k | n | o | c | k | d )"
echo "|__/|__/_/     /_/   /_/    \_/ \_/ \_/ \_/ \_/ \_/ "
echo "===================================================="
echo "  WiFi(802.11) Knockd installer script, by @yadox"
echo "===================================================="
echo ""
echo "Installing Python required libraries..."
pip install -r ./requirements.txt

echo "Installing python scripts..."
chmod 755 ./wifiknockd.py
cp ./wifiknockd.py /sbin/

chmod 755 ./wifiknockd_client.py
cp ./wifiknockd_client.py /sbin/

echo "Copying configuration file to /etc/..."
cp ./wifiknockd.conf /etc/

echo "Installing wifiknockd.sh boot daemon..."
chmod 755 ./wifiknockd.sh
cp ./wifiknockd.sh /etc/init.d/
sudo update-rc.d -f wifiknockd.sh defaults
