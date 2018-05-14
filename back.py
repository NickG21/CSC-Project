#!/usr/bin/python2.7

import sys
import time
from scapy.all import *

filename = open('mac-vendor.txt', 'r')
vendors = filename.read()
filename.close()
del filename
vendors = eval(vendors)

def macSplit(mac):
    return ''.join(mac.split(':')[0:3])
    

class Host(object):

    def __init__(self, mac):
        self.mac = mac

class AccessPoint(Host):

    def __init__(self, mac, density):
        self.mac = mac
        self.density = density
        self.distances = []
        self.name = ''
        self.channel = ''
        self.enc = ''
        self.vendor = 'Unknown'

    def __str__(self):
        return '{} ({}:{}) - enc:{} chan:{} dist:{}'.format(self.name,
                                                            self.mac,
                                                            self.vendor,
                                                            self.enc,
                                                            self.channel,
                                                            str(sum(self.distances)/self.density))

class Probe(Host):

    def __init__(self, mac, density):
        self.mac = mac
        self.density = density
        self.distances = []
        self.parent = 'none'
        self.vendor = 'Unknown'

    def __str__(self):
        return '{} - {}; (parent:{}); dist:{}'.format(self.mac,
                                                      self.vendor,
                                                      self.parent,
                                                      str(sum(self.distances)/self.density))

'''FUNCTIONS'''
# Converts hexadecimal dBm to Decimal for easier understanding
def dBmConverter(dBm):
    # Possible hex characters 
    digits='0123456789abcdef'
    x = []
    # Make sure the input is 2 digits long
    if (len(dBm)==2):
        for i in dBm:
            # Check if input matches with hex characters
            for digit in digits:
                if i==digit:
                    x.append(digits.index(i))
        # Convert to decimal
        a = x[0]*16
        a = a + x[1]
    # If the input is not 2 digits long, return 0
    else:
        a = 255
    return a-255

aps = dict()
probes = dict()

# Packet handler (all your packets are belong to us)
def classifier(pkt):

    # packet is from an AP that is not in the list
    if pkt.haslayer(Dot11Beacon):
        if not aps.has_key(pkt.addr2):
            # grab the mac
            mac = pkt.addr2
            # add the AP to the list
            aps[mac] = AccessPoint(mac, 1)
            # get the distance
            dBm = pkt.notdecoded
            dBm = dBm[6]
            dBm = dBm.encode('hex')
            dBm = dBmConverter(dBm)
            aps[mac].distances.append(dBm)
            # get the ssid
            aps[mac].name = pkt.info
            # if the ssid is blank, call it <unknown>
            if aps[mac].name == "":
                aps[mac].name = "<Hidden>"
            # get the channel
            aps[mac].channel = str(ord(pkt[Dot11Elt:3].info))
            # cycle to test if it has WPA2 Encryption
            while True:
                try:
                    if pkt.ID == 48:
                        aps[mac].enc = "Locked"
                    pkt = pkt.payload
                except:
                    break
            # if WPA2 is not found, assume it is Open
            if not aps[mac].enc:
                aps[mac].enc = "Open"
            # add vendor if vendor exists
            if vendors.has_key(macSplit(mac)):
                aps[mac].vendor = vendors[macSplit(mac)]

    # packet is from a Probe that is not in the list
    elif pkt.haslayer(Dot11ProbeReq):
        if not probes.has_key(pkt.addr2):
            # grab the mac
            mac = pkt.addr2
            # add the Probe to the list
            probes[mac] = Probe(pkt.addr2, 1)
            # get the distance
            dBm = pkt.notdecoded
            dBm = dBm[6]
            dBm = dBm.encode('hex')
            dBm = dBmConverter(dBm)
            probes[mac].distances.append(dBm)
            # add vendor if vendor exists
            if vendors.has_key(macSplit(mac)):
                probes[mac].vendor = vendors[macSplit(mac)]

    # packet is from a Probe that is in the list
    elif probes.has_key(pkt.addr2):
        # increase the density
        probes[pkt.addr2].density += 1
        # get the distance
        dBm = pkt.notdecoded
        dBm = dBm[6]
        dBm = dBm.encode('hex')
        dBm = dBmConverter(dBm)
        probes[pkt.addr2].distances.append(dBm)
        # Check if the Probe has a parent
        if ((pkt.addr1 != 'ff:ff:ff:ff:ff:ff') and (pkt.addr1 and pkt.addr2)):
            probes[pkt.addr2].parent = pkt.addr1

    # packet is from anAP that is in the list
    elif aps.has_key(pkt.addr2):
        # increase the density
        aps[pkt.addr2].density += 1
        # get the distance
        dBm = pkt.notdecoded
        dBm = dBm[6]
        dBm = dBm.encode('hex')
        dBm = dBmConverter(dBm)
        aps[pkt.addr2].distances.append(dBm)

# sniff for packets
a = sniff(iface = 'wlan0mon', timeout=20, prn=classifier)
