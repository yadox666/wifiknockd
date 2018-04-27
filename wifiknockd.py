#!/usr/bin/env python
# -*- coding: utf-8 -*-​
__version__ = '0.5'

try:
    import fcntl
    import sys, os, time
    from random import randint
    from platform import system
    import logging.handlers
    from threading import Thread
    from threading import Timer
    from subprocess import Popen, PIPE
    from signal import SIGINT,signal
    import ConfigParser
    import binascii
    from Crypto import Random
    from Crypto.Cipher import AES
    import base64
    # from gpiozero import LED,Button,OutputDevice

    # Configure syslog environment
    logging.basicConfig(level=logging.INFO)
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    from scapy.all import *
    dlogger = logging.getLogger('WifiKnockD')
    dlogger.setLevel(logging.DEBUG)
    handler = logging.handlers.SysLogHandler(address = '/dev/log')
    dlogger.addHandler(handler)

except Exception as e:
    print "Cannot import required library! (pip install -r requirements.txt)! %s"  %e.message
    exit()

# Default system variables
ap_channel = 9
ap_essid = "RogueAP"
ap_security = "WPA"
ap_key = "matrixman"
ap_hidden = False
verbose = False
debug = False
gpiobase = '/sys/class/gpio'
capfile = '/tmp/wifiknockd.cap' ## directory and file name to save captured packets
conffile='/etc/wifiknockd.conf'
count = 20  ## Default number of packets to send
seq = randint(1, 4096)
seqlist = []
portlist = []
gpiolist = []
payload = ''
payload_ie = 221
frequency = ''
DN = open(os.devnull, 'w')
closing = 0
intfmon=''
ap_on = 0
action_timeout = 0
msg_timeout = ""

# Broadcast, broadcast, IPv6mcast, spanning tree, spanning tree, multicast, broadcast
broadcast = 'FF:FF:FF:FF:FF:FF'  ## Destination address for beacons and probes
ignore = [broadcast, '00:00:00:00:00:00', '33:33:00:', '33:33:FF:', '01:80:C2:00:00:00', '01:00:5E:']


def PacketHandler(pkt):
    global seqlist, seq, mac_whitelist, msg_timeout

    # Filter broadcast and multicast
    bssid = pkt.addr3.upper()
    if bssid in ignore:
        if debug: dlogger.debug('MAC adress filtered by ignored list (%s)!' %bssid)
	return

    # Check for whitelist MACs
    sta = pkt.addr2.upper()
    if len(mac_whitelist) > 1:
	if sta not in mac_whitelist:
	    if debug: dlogger.debug('MAC Whitelist active, will not accept packet (%s)!' %sta)
	    return 

    # Check if probe request is directed to us
    if bssid != listen_bssid:
	if debug: dlogger.debug('Wrong destination BSSID (%s), will only accept: %s' %(bssid,listen_bssid))
	return

    # Check if packet is repeated or replayed
    seq = pkt.SC
    if seq in seqlist:
        if debug: dlogger.debug("Repeated or replayed packet from %s." %sta)
	return
    seqlist.append(seq)

    dlogger.info("RX Probe Request from STA %s." %sta)

    # Check if encryption is enabled
    # typical data: ap1~0545~rogueap,wpa,matrixman,4,0
    ssid = pkt.info
    if use_encryption: 
	if debug: dlogger.debug("Encrypted payload: %s" %ssid)
        ssid = cipher.decrypt(ssid)
	if debug: dlogger.debug("Decrypted payload: %s" %ssid)

    command = ssid[:3]
    value = []

    # Security check if same SC is inside payload
    seqck = ssid.split("~")[1]
    rc = ""
    if seqck != str(seq):
    	if verbose: dlogger.info('Wrong forged packet detected! (%s,%s)' %(seq, seqck))
        return

    # Max action timeout received?
    if len(ssid.split("~")) > 3:
        req_timeout = ssid.split("~")[3]
        if len(req_timeout) > 0:
            try:
                if float(req_timeout).is_integer():
                    action_timeout = int(req_timeout)
                    msg_timeout = "for %d secs" %(action_timeout)
            except:
                pass

    # Check for known commands inside payload
    if command == "ap1":
        value = ssid.split("~")[2].split(",")
        StartAp(value,action_timeout)
    elif command == "ap0":
	StopAp()
    elif command == "exe":
        value = ssid.split("~")[2].split(" ")
        rc = ExecProc(value,action_timeout)
    elif command == "pr1":
        value = ssid.split("~")[2].split(",")
        OpenPorts(value,action_timeout)
    elif command == "pr0":
        value = ssid.split("~")[2].split(",")
        ClosePorts(value)
    elif command == "sw1":
        value = ssid.split("~")[2].split(",")
        GpioOn(value,action_timeout)
    elif command == "sw0":
        value = ssid.split("~")[2].split(",")
        GpioOff(value)
    else:
        if verbose: logging.error('Wrong command: %s' %ssid)
        return

    if use_ack:
        time.sleep(count*0.1)
        apssid = 'ACK~'+ seqck + '~' + str(rc) + '~' + str(action_timeout)
        if use_encryption:   # Cipher and encode ssid
            padd = len(apssid) % 16
            if padd > 0: apssid = apssid + (' ' * (16 - padd))
            apssid = base64.b64encode(cipher.encrypt(apssid))
        dlogger.info('Sendig ACK in %d probe responses to MAC:%s' %(count, sta))
        sdot11.proberesp(sta, count, apssid, listen_bssid, payload)

    dlogger.info('Waiting for new actions...')
    if verbose: wrpcap(capfile, pkt, append=True)


def GpioOn(value,timeout):
    global gpiolist, msg_timeout
    gpiolist.extend(value)
    for gpio in value:
        try:
            gpio = Button(value)
            gpio.on()
            dlogger.info('Setting GPIO %s ON %s' %(gpio,msg_timeout))
        except:
            dlogger.info('Cannot set GPIO %s ON!' %gpio)
    msg_timeout = ""
    if timeout > 0:
        t = threading.Timer(timeout, GpioOff, [value])
        t.start()


def GpioOff(value):
    global gpiolist
    gpiolist=[x for x in gpiolist if x not in value]
    for gpio in value:
        try:
            gpio = Button(value)
            gpio.off()
            dlogger.info('Setting GPIO %s OFF!' %gpio)
        except:
            dlogger.info('Cannot set GPIO %s OFF!' %gpio)


def OpenPorts(value,timeout):
    global portlist, msg_timeout
    # Remove closed ports from global list
    portlist=[x for x in portlist if x not in value]
    for port in value:
	try:
	    if "U" in port.upper():
		port = ''.join(filter(str.isdigit, port))
                proc = Popen(['iptables','-DINPUT','-pudp','--dport', port,'-jDROP'], shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
                dlogger.info('Requested to open UDP port %s %s' %(port, msg_timeout))
	    else:
                proc = Popen(['iptables','-DINPUT','-ptcp','--dport', port,'-jDROP'], shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
                dlogger.info('Requested to open TCP port %s %s' %(port, msg_timeout))
        except OSError as e:
            dlogger.info('Could not open port: %s!' %port)
            os.kill(os.getpid(), SIGINT)
    msg_timeout = ""
    if timeout > 0:
        t = threading.Timer(timeout, ClosePorts, [value])
	t.start()

def ClosePorts(value):
    global portlist
    for port in value:
        if not port in portlist:
	    portlist.append(port) 
	    try:
		if "U" in port.upper():
		    port = ''.join(filter(str.isdigit, port))
                    proc = Popen(['iptables','-AINPUT','-pudp','--dport', str(port),'-jDROP'], shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
                    dlogger.info('Closing UDP port %s' %port)
		else:
                    proc = Popen(['iptables','-AINPUT','-ptcp','--dport', port,'-jDROP'], shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
                    dlogger.info('Closing TCP port %s' %port)
            except OSError as e:
                dlogger.info('Could not close port %s!' %port)
                os.kill(os.getpid(), SIGINT)


def ExecProc(value,timeout):
    global msg_timeout
    try:
        proc = Popen(value, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
        time.sleep(1)
	rc = proc.poll()
        dlogger.info('Executing command %s: %s(return code:%s)' %(msg_timeout,' '.join(value), str(rc)))
        msg_timeout = ""
	return int(rc)
    except OSError as e:
        dlogger.info('Could not execute: %s!' %value)
        os.kill(os.getpid(), SIGINT)
        msg_timeout = ""
        return -1


def StartAp(value,timeout):
    global ap_on, msg_timeout
    hostapdconf = '/tmp/hostapd.conf'
    if debug: dlogger.debug("Updating hostapd config file: %s" %hostapdconf)
    config=[]
    config.append('interface='+ap_iface+'\n')
    config.append('driver=nl80211'+'\n')
    config.append('hw_mode=g'+'\n')
    config.append('auth_algs=3'+'\n')
    config.append('ctrl_interface=/var/run/hostapd'+'\n')
    if len(value) > 3: 
        dlogger.info("Requested to switch AP ON %s: %s" %(msg_timeout,value))
        config.append('ssid='+value[0]+'\n')
        config.append('channel='+value[3]+'\n')
        if value[1][:3].upper() == "WPA":
            config.append('wpa=2'+'\n')
            config.append('wpa_key_mgmt=WPA-PSK'+'\n')
            config.append('rsn_pairwise=CCMP TKIP'+'\n')
            config.append('wpa_passphrase='+value[2]+'\n')
        if value[4] == "1":  ## request for hidden ssid
            config.apppend('ignore_broadcast_ssid=1'+'\n')
    else:
        dlogger.info("Requested to switch default AP ON %s:%s,%s,%s,%s,%s" %(msg_timeout,ap_essid,ap_security,ap_key,ap_channel,ap_hidden))
        config.append('ssid='+ap_essid+'\n')
        config.append('channel='+ap_channel+'\n')
        if ap_security.upper() == "WPA":
            config.append('wpa=2'+'\n')
            config.append('wpa_key_mgmt=WPA-PSK'+'\n')
            config.append('rsn_pairwise=CCMP TKIP'+'\n')
            config.append('wpa_passphrase='+ap_key+'\n')
        if ap_hidden == "1":  ## request for hidden ssid
            config.apppend('ignore_broadcast_ssid=1'+'\n')

    f = open(hostapdconf,'w')
    f.writelines(config)
    f.close()
    msg_timeout = ""

    try:
        proc = Popen(['/usr/bin/killall','hostapd'], shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
        proc = Popen(['service','dnsmasq','stop'], shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
        proc = Popen(['ifconfig',ap_iface,'10.0.1.1','netmask','255.255.255.0','up'], shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
        proc1 = Popen(['/usr/sbin/hostapd','-B',hostapdconf], shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        proc2 = Popen(['service','dnsmasq','restart'], shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        proc = Popen(['sysctl','-w','net.ipv4.ip_forward=1'], shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
        proc = Popen(['iptables','-t nat','-A POSTROUTING','-o',ap_gateway,'-j MASQUERADE'], shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
        proc = Popen(['iptables','-F FORWARD'], shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
        proc = Popen(['iptables','-F FORWARD','-j ACCEPT'], shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	if verbose: dlogger.info("Starting AP hostapd")
        ap_on = 1      
    except OSError as e:
        dlogger.info('Could not execute: %s!' %value)
        os.kill(os.getpid(), SIGINT)
        return False

    if timeout > 0:
        t = threading.Timer(timeout, StopAp)
        t.start()


def StopAp():
    global ap_on
    if ap_on: 
        dlogger.info("Requested to stop AP.")
    else:
        dlogger.info("AP not running. Nothing to do!")
	return
    try:
        proc = Popen(['/usr/bin/killall','hostapd'], shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
        proc = Popen(['service','dnsmasq','stop'], shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
        proc = Popen(['ifconfig',ap_iface,'10.0.1.1','netmask','255.255.255.0','down'], shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
        proc = Popen(['iptables','-t nat','--flush'], shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
        proc = Popen(['iptables','-D FORWARD'], shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
        if verbose: dlogger.info("Stopping AP and hostapd daemon")
        ap_on = 0
    except OSError as e:
        dlogger.info('Could not execute: %s!' %value)
        os.kill(os.getpid(), SIGINT)
        return False


class Sniffer(Thread):  # Scapy sniffer thread
    def __init__(self):
        Thread.__init__(self)
        Thread.daemon = True

    def run(self):
        try:
            sniff(iface=intfmon, prn=PacketHandler, lfilter=lambda p:(Dot11ProbeReq in p), store=0)
            dlogger.info("Start sniffing data with interface %s" % intfmon)
        except Exception as e:
            logging.error("Cannot start sniffer thread with interface %s! %s" %(intfmon,e.message))
            closeall(0,0)


def closeall(signal,frame):
    global closing
    StopAp()
    OpenPorts(portlist,0)
    GpioOff(gpiolist)
    closing = 1
    dlogger.info('Ending wifiknockd execution!')
    exit()


def oscheck():
    osversion = system()
    if debug: dlogger.debug("Operating System: %s" % osversion)
    if osversion != 'Linux':
        dlogger.info("This script only works on Linux OS! Exitting!")
        exit(1)


def GetMAC(iface):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', iface[:15]))
    mac = ''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1]
    return mac


def initmon(intfparent):
    global intfmon, ignore
    dlogger.info("Using WiFi interface to monitor packets: %s" %intfparent)
    if not os.path.isdir("/sys/class/net/" + intfparent):
        dlogger.info("WiFi parent interface %s does not exist! Cannot continue!" % intfparent)
        exit(1)
    else:
        intfmon = 'mon' + intfparent[-1]
        if os.path.isdir("/sys/class/net/" + intfmon):
            if debug: dlogger.debug("WiFi interface %s exists! Deleting it!" % (intfmon))
            try:
                # create monitor interface using iw
                os.system("iw dev %s del" % intfmon)
                time.sleep(0.5)
            except OSError as oserr:
                if debug: dlogger.debug("Could not delete monitor interface %s. %s" % (intfmon, oserr.message))
                os.kill(os.getpid(), SIGINT)
                sys.exit(1)
        try:
            # create monitor interface using iw
	    os.system('rfkill unblock wlan')
            time.sleep(0.3)
            os.system("ifconfig %s down" % intfparent)
            time.sleep(0.3)
            os.system("iwconfig %s mode monitor" % intfparent)
            time.sleep(0.3)
            os.system("iw dev %s interface add %s type monitor" % (intfparent, intfmon))
            time.sleep(0.3)
            os.system("ifconfig %s up" % intfmon)
            if verbose: dlogger.info("Creating monitor VAP %s for parent %s..." % (intfmon, intfparent))
        except OSError as oserr:
            dlogger.info("Could not create monitor %s. %s" % (intfmon, oserr.message))
            os.kill(os.getpid(), SIGINT)
            sys.exit(1)

        # Get actual MAC addresses
        macaddr1 = GetMAC(intfmon).upper()
        ignore.append(macaddr1)
        dlogger.info("Actual %s MAC Address: %s" % (intfparent, macaddr1))
        macaddr = GetMAC(intfmon).upper()
        if macaddr1 != macaddr:
            ignore.append(macaddr);
            if verbose: dlogger.info("Actual %s MAC Address: %s" % (intfmon, macaddr))


def calc_freq(channel):
    global frequency
    if channel in range(1, 14):
        if channel == 14:
            frequency = "2484"
        else:
            frequency = str(2407 + (channel * 5))
        return frequency
    else:
        return "n/a"


class Dot11EltRates(Packet):
    name = "802.11 Rates Information Element"
    # Our Test STA supports the rates 6, 9, 12, 18, 24, 36, 48 and 54 Mbps
    supported_rates = [0x0c, 0x12, 0x18, 0x24, 0x30, 0x48, 0x60, 0x6c]
    fields_desc = [ByteField("ID", 1), ByteField("len", len(supported_rates))]
    for index, rate in enumerate(supported_rates):
        fields_desc.append(ByteField("supported_rate{0}".format(index + 1), rate))


def next_seq():  # type: () -> object
    global seq
    seq = (seq + 1) % 4096
    temp = seq * 16   # Fragment number -> right 4 bits
    return temp


class Scapy80211():
    def __init__(self, intfparent='wlan1', intfmon='mon1'):
        self.intfparent = intfparent
        self.intfmon = intfmon
        conf.iface = self.intfmon

    def proberesp(self, src, count, ssid, bssid, payload):
	global verbose
        param = Dot11ProbeResp(beacon_interval=0x0064, cap=0x2104)
        essid = Dot11Elt(ID='SSID', info=ssid, len=len(ssid))
        dsset = Dot11Elt(ID='DSset', info=chr(listen_channel))
	# eltpayload = Dot11Elt(ID=payload_ie,len=len(payload),info=payload) ## vendorWPS
        pkt = RadioTap() / Dot11(subtype=5, addr1=src, addr2=bssid, addr3=bssid, SC=next_seq()) / param / essid / Dot11EltRates() / dsset
        try:
            if debug: pkt.show()
            sendp(pkt, iface=intfmon, count=count, inter=0.1, verbose=0)
            if verbose: wrpcap(capfile, pkt, append=True)
        except Exception as e:
	    logging.error('Cannot send packets. %s' %e.message)

    def setchannel(self, chan):
        global channel,frequency
        channel = int(chan)
        frequency = calc_freq(channel)
        try:
            proc = Popen(['iw', 'dev', self.intfmon, 'set', 'channel', str(channel)], shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
            dlogger.info("Setting %s to channel: %s (%s MHz)" % (self.intfmon, channel, frequency))
        except OSError as e:
            dlogger.info('Could not execute iw!')
            os.kill(os.getpid(), SIGINT)
            return False
        for line in proc.communicate()[1].split('\n'):
            if len(line) > 2:  # iw dev shouldnt display output unless there's an error
                dlogger.info("Error setting channel %s for %s" % (channel, self.intfmon))
                return False


class AESCipher(object):
    def __init__(self, key):
        self.key = key
        self.key = (self.key * ((16/len(key))+1))[:16]
        self.pad = lambda s: s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)
        self.unpad = lambda s: s[:-ord(s[len(s) - 1:])]
    def encrypt(self, raw):
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return binascii.b2a_hex(iv + cipher.encrypt(self.pad(raw)))
    def decrypt(self, enc):
        enc = binascii.a2b_hex(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self.unpad(cipher.decrypt(enc[AES.block_size:]))


# main routine
if __name__ == "__main__":

    # Check if OS is linux:
    oscheck()

    # Check for root privileges
    if os.geteuid() != 0:
        dlogger.info("You need to be root to run this script!")
        exit()
    else:
        if debug: dlogger.debug("You are running this script as root!")

    # parse configuration file
    try:
	rconfig = ConfigParser.SafeConfigParser(allow_no_value=True)
	rconfig.read(conffile)
    except:
        dlogger.info("Could not open /etc/wifiknockd.conf file!")
        exit()

    # user defined variables
    try:
        verbose = rconfig.getboolean('default','verbose')
        if verbose or debug:
	    print "\n _       _ _       ____  _                           "
	    print "| |     / (_)     / __/ (_)  _   _   _   _   _   _  "
	    print "| | /| / / / __  / /_  / /  / \ / \ / \ / \ / \ / \ "
	    print "| |/ |/ / / /_/ / __/ / /  ( k | n | o | c | k | d )"
	    print "|__/|__/_/     /_/   /_/    \_/ \_/ \_/ \_/ \_/ \_/ "
	    print ""
            print "===================================================="
            print " WiFi (802.11) Knockd Server script, by @yadox"
            print "====================================================\n"

            if debug:
		dlogger.info('Debug mode configured (inside this .py file)')
		verbose = True
            dlogger.info('Parsing configuration file! (%s)' %conffile)

        use_ack = rconfig.getboolean('default','use_ack')
        use_encryption = rconfig.getboolean('default','use_encryption')
        encryption_key = rconfig.get('default','encryption_key')
        listen_iface = rconfig.get('default','listen_iface')
        listen_channel = rconfig.getint('default','listen_channel')

        listen_bssid = rconfig.get('default','listen_bssid').upper()
        dlogger.info('Authorized RX from BSSID: %s' %listen_bssid)

        mac_whitelist = rconfig.get('default','mac_whitelist').upper().split(",")
        dlogger.info('Authorized MACs: %s (%d)' %(mac_whitelist, len(mac_whitelist)))

        ap_iface = rconfig.get('default','ap_iface')
        ap_gateway = rconfig.get('default','ap_gateway')
        dlogger.info('Using WiFi interface for new AP: %s' %ap_iface)

	ports_blocked = rconfig.get('default','ports_blocked').split(",")

    except Exception as e:
	logging.error('Cannot find necessary options in wifiknockd.conf: %s, exiting!' %e)
        exit()

    # Start encryption if requested
    if use_encryption:
	if debug: dlogger.debug('Using encryption with key! (%s)' %encryption_key)
	cipher = AESCipher("matrixman")

    # Delete capfile before starting
    try:
        if verbose: os.remove(capfile)
    except OSError:
        pass

    # Check if monitor device exists
    initmon(listen_iface)

    # Interrupt handler to exit
    signal(SIGINT, closeall)

    # Start injection class
    sdot11 = Scapy80211(listen_iface,intfmon)
    sdot11.setchannel(listen_channel)

    # Block ports if requested
    if len(ports_blocked) > 1:
        dlogger.info('Default ports to block: %s' %', '.join(ports_blocked))
        ClosePorts(ports_blocked)

    # Start sniffer
    Sniffer().start()
    if verbose: dlogger.info('Press Ctrl+C to end execution!')
    dlogger.info('Waiting for new actions...')

    # Main loop
    try:
        while not closing:
	    time.sleep(1)
    except KeyboardInterrupt:
	closeall(0,0)
