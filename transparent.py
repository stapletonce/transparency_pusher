from scapy.all import *
from socket import *
import sys

# https://stackoverflow.com/questions/10033285/how-to-change-a-packet-data-with-scapy


def chgSend(x):
    if x.haslayer(IP):
        if x[IP].dst == '10.0.0.12':            # send honeypot traffic to camera
            x[IP].dst = '10.0.0.2'              # make sure packet has original internet source IP
            x[Ether].dst = 'e8:ab:fa:58:b2:de'
            x[IP].src = '10.0.0.12'
            x[Ether].src = '3c:15:c2:e7:67:e4'
            print("changed dst")
                    #else:                                  # packets go back to internet
                    #x[IP].src = '10.0.0.12'              # make sure source IP is the same as dest IP from first packet
            try:
                print(x.show())
            except:
                print("would not print")
            sendp(x)

while 1:
    # s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sniff(prn=chgSend)

