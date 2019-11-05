from scapy.all import *

# https://stackoverflow.com/questions/10033285/how-to-change-a-packet-data-with-scapy

def chgSend(x):
    if x[IP].dst == 'honeypot destination'      # send honeypot traffic to camera
        x[IP].dst = 'x.x.x.x'                   # make sure packet has original internet source IP
    else if x[IP].dst != 'honeypot IP'          # packets go back to internet
        x[IP].src = 'honeypot IP'               # make sure source IP is the same as dest IP from first packet
    send(x)

while 1:
    sniff(pckt=chgSend)
