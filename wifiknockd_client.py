#!/usr/bin/python
# -*- coding: utf-8 -*-​
import sys,logging, fcntl
import binascii
from Crypto import Random
from Crypto.Cipher import AES
import ConfigParser
import argparse
from random import randint
from signal import SIGINT,signal
from subprocess import Popen, PIPE
from threading import Thread
import logging.handlers
logging.basicConfig(level=logging.INFO)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

# Configure syslog
dlogger = logging.getLogger('WiFiknockd_Client')
dlogger.setLevel(logging.DEBUG)
handler = logging.handlers.SysLogHandler(address = '/dev/log')
dlogger.addHandler(handler)

# Broadcast, broadcast, IPv6mcast, spanning tree, spanning tree, multicast, broadcast
broadcast = 'FF:FF:FF:FF:FF:FF'  ## Destination address for beacons and probes
ignore = [broadcast, '00:00:00:00:00:00', '33:33:00:', '33:33:ff:', '01:80:c2:00:00:00', '01:00:5e:']

salt="mysaltiv"
conffile='/etc/wifiknockd.conf'
capfile = '/tmp/wifiknockd_client.cap' ## directory and file name to save captured packets
count = 20  ## Default number of packets to send
timeout = 10 ## Timeout to listen for responses
seq = randint(1, 4095)
seqlist = []
verbose = False
debug = False
closing = 0
reqinitmon = False
intfmon = "mon1"
DN = open(os.devnull, 'w')
action_timeout = '0'


class Sniffer(Thread):  # Scapy sniffer thread
    def __init__(self):
        Thread.__init__(self)
        Thread.daemon = True

    def run(self):
        try:
            dlogger.info("Start sniffing data with interface %s" % intfmon)
            sniff(iface=intfmon, prn=PacketHandler, lfilter=lambda p:(Dot11ProbeResp in p), store=0)
        except Exception as e:
            logging.error("Cannot start sniffer thread with interface %s! %s" %(intfmon,e.message))


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


def next_seq():  # type: () -> object
    global seq
    seq = (seq + 1) % 4096
    temp = seq * 16 # Fragment number -> right 4 bits
    return temp


def setchannel(chan):
    global channel,frequency
    channel = int(chan)
    frequency = calc_freq(channel)
    try:
        proc = Popen(['iw', 'dev', intfmon, 'set', 'channel', str(channel)], stdout=DN, stderr=PIPE)
        if verbose: dlogger.info("Setting %s to channel: %s (%s MHz)" % (intfmon, channel, frequency))
    except OSError as e:
        dlogger.info('Could not execute iw!')
        os.kill(os.getpid(), SIGINT)
        return False
    for line in proc.communicate()[1].split('\n'):
        if len(line) > 2:  # iw dev shouldnt display output unless there's an error
            print line
            dlogger.info("Error setting channel %s for %s" % (channel, intfmon))
            return False


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


def GetMAC(iface):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', iface[:15]))
    mac = ''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1]
    return mac


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


def closeall(signal,frame):
    global closing
    closing = 1
    dlogger.info('Ending execution!')
    exit()


def PacketHandler(pkt):
    global seqlist,seq,mac_whitelist

    # Filter repeated or replayed packets
    seq = pkt.SC
    if seq in seqlist:
	if debug: dlogger.debug('Repeated or replayed packet received!')
	return
    seqlist.append(seq)

    # Filter broadcast and multicast
    bssid = pkt.addr3.upper()
    if bssid in ignore:
	if debug: dlogger.debug('MAC adress filtered by ignored list (%s)!' %bssid)
        return

    # Check if packet comes from BSSID
    if bssid != listen_bssid:
	if debug: dlogger.debug('Wrong destination BSSID (%s), will only accept: %s' %(bssid,listen_bssid))
	return

    # Check if packet is directed to us
    dst = pkt.addr1.upper()
    if dst != src.upper():
	if debug: dlogger.debug('Packet is not directed to our MAC (%s)!' %dst)
        return

    ssid = pkt.info
    if use_encryption:
        if debug: dlogger.debug("Encrypted payload: %s" %ssid)
        ssid = cipher.decrypt(base64.b64decode(ssid)).strip()
        if debug: dlogger.debug("Decrypted payload: %s" %ssid)

    dlogger.info("RX directed Probe Response from %s" %dst)

    command = ssid[:3]
    value = []
    seqck = ssid.split("~")[1]
    rc = ssid.split("~")[2]
    if command == 'ACK':
	if int(seqck) in seqlist:
            dlogger.info("ACK received to message: %s with result: %s" %(seqck, rc))
	    if verbose: wrpcap(capfile, pkt, append=True)
            closeall(0,0)


# Main loop
# parse configuration file
try:
    if verbose: dlogger.info('Parsing configuration file! (%s)' %conffile)
    rconfig = ConfigParser.SafeConfigParser()
    rconfig.read(conffile)

    # user defined variables
    verbose = rconfig.getboolean('default','verbose')
    if verbose or debug:
        print "\n _       _ _       ____  _                           "
        print "| |     / (_)     / __/ (_)  _   _   _   _   _   _  "
        print "| | /| / / / __  / /_  / /  / \ / \ / \ / \ / \ / \ "
        print "| |/ |/ / / /_/ / __/ / /  ( k | n | o | c | k | d )"
        print "|__/|__/_/     /_/   /_/    \_/ \_/ \_/ \_/ \_/ \_/ "
        print ""
        print "===================================================="
        print "   WiFi (802.11) Knockd client script, by @yadox"
        print "====================================================\n"

    listen_iface = rconfig.get('default','listen_iface')
    listen_channel = rconfig.getint('default','listen_channel')
    listen_bssid = rconfig.get('default','listen_bssid').upper()

    use_ack = rconfig.getboolean('default','use_ack')
    use_encryption = rconfig.getboolean('default','use_encryption')
    encryption_key = rconfig.get('default','encryption_key')

    # Decide which MAC to use as src of packets
    mac_whitelist = rconfig.get('default','mac_whitelist').upper().split(",")
    if len(mac_whitelist) > 1:
        src = mac_whitelist[0]
        dlogger.info("Using MAC address from Whitelist: %s" %src)
    else:
        src = "AA:06:12:A5:95:33"
        dlogger.info("Using default MAC address: %s" %src)
except IOError:
    dlogger.error('Cannot open configuration file: %s, exiting!' %conffile)
    exit()

# Generate sequence number for next packet
seq=next_seq()
seqlist.append(seq)
apssid = 'ap1~' + str(seq) + '~' + 'rogueap,wpa,matrixman,8'

# Define arguments for the script
parser = argparse.ArgumentParser()
parser.add_argument("-a","--apmode", type=str, help="Enter Access Point mode: ssid,[wpa,open],key,channel,hidden[1/0]")
parser.add_argument("-g","--gpiolist", type=str, help="Enter a GPIO port number or a list separated by commas")
parser.add_argument("-p","--portlist", type=str, help="Enter a TCP port number or a list separated by commas [UDP ports must include U after port]")
parser.add_argument("-e","--execute", type=str, help="Enter a command to execute (use quotes to delimite)")
parser.add_argument("-t","--timeout", type=int, help="Timeout for the required action (Stop action after n secs)")
parser.add_argument("-1","--on", action="store_true", help="Switch ON requested action (selected by default)")
parser.add_argument("-0","--off", action="store_true", help="Switch OFF requested mode")
parser.add_argument("-i","--reqinitmon", action="store_true", help="Start monitor mode VAP")
parser.add_argument("-d","--debug", action="store_true", help="If debug is passed, more verbose messages will be shown")
parser.add_argument("-q","--quiet", action="store_true", help="If quiet is passed, verbose messages wont be shown")
args = parser.parse_args()

# If no arguments are passed, show usage and exit
if len(sys.argv) == 1:
    parser.print_help()
    sys.exit()

if args.reqinitmon:
    # If requested to init monitor interface
    reqinitmon = True 
    dlogger.info('Requested to init monitor mode vap!')
    initmon(listen_iface)
    setchannel(listen_channel)
else:
    intfmon = 'mon' + listen_iface[-1]

# Start sniffer
if use_ack: Sniffer().start()

# If requested max execution time
if args.timeout:
    action_timeout = str(args.timeout)  ## not need int var in client
    dlogger.info('Action max execution time (timeout): %s' %args.timeout)

if args.debug: 
    dlogger.info('Debug mode configured (inside this .py file)')
    debug = True
    verbose = True
elif args.quiet: 
    debug = False
    verbose = False
if args.apmode:
    if args.off:
        dlogger.info('Requesting to switch AP off!')
        apssid = 'ap0~' + str(seq) + '~'
    else:
        dlogger.info('Requesting to switch AP on! (%s)' %args.apmode)
        apssid = 'ap1~' + str(seq) + '~' + args.apmode + '~' + action_timeout
elif args.portlist:
    if args.off:
        dlogger.info('Requesting to close port/s %s!' %args.portlist)
        apssid = 'pr0~' + str(seq) + '~' + args.portlist
    else:
        dlogger.info('Requesting to open port/s %s!' %args.portlist)
        apssid = 'pr1~' + str(seq) + '~' + args.portlist + '~' + action_timeout
elif args.gpiolist:
    if args.off:
        dlogger.info('Requesting to switch GPIO/s $s off!' %args.gpiolist)
        apssid = 'gp0~' + str(seq) + '~' + args.gpiolist + '~' + action_timeout
    else:
        dlogger.info('Requesting to switch GPIO/s $s on!' %args.gpiolist)
        apssid = 'gp1~' + str(seq) + '~' + args.gpiolist + '~' + action_timeout
elif args.execute:
    dlogger.info('Requesting to execute: %s!' %args.execute)
    apssid = 'exe~' + str(seq) + '~' + args.execute + '~' + action_timeout


# Interrupt handler to exit
signal(SIGINT, closeall)

# Start encryption if requested
if use_encryption:
    if debug: dlogger.debug('Using encryption with key: %s' %encryption_key)
    cipher = cipher = AESCipher("matrixman")

    # Cipher and encode ssid
    if verbose: dlogger.info("Cleartext payload: %s" %apssid)
    apssid = cipher.encrypt(apssid)
    if verbose: dlogger.info("Encrypted payload: %s..." %apssid[:28])

# Standard 802.11 Probe Request frame to use as base packet
essid = Dot11Elt(ID=0,info=apssid, len=len(apssid))
channel = Dot11Elt(ID=3, len=1, info="\x01")  ## IE channel 1
dsset = Dot11Elt(ID='DSset',info='\x01')
basepkt =  RadioTap()
basepkt /= Dot11(type=0,subtype=4,addr1=listen_bssid,addr2=src,addr3=listen_bssid,FCfield=0,SC=seq,ID=0)
basepkt /= Dot11ProbeReq()/essid/channel/dsset

if debug: basepkt.show()

# Send a packet every 1/10th of a second, 20 times
dlogger.info("Sending %d Probe Request frames to %s" %(count,listen_bssid))
sendp(basepkt, iface=intfmon, count=count, inter=0.100, verbose=0)
if verbose: 
    wrpcap(capfile, basepkt, append=True)
    dlogger.info('Waiting %d secs to receive ACK packet...' %timeout)

# Listen until timeout
t = 0
while not closing and t <= timeout:
    time.sleep(1)
    t += 1
    
