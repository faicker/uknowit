#!/usr/bin/env python

import socket
import logging
import sys

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *


def ackattack(host):
    port = RandNum(1024, 65535)
    # build a simple ACK packet, using a range (1,31) for the ttl creates 255 packets
    ack = IP(dst=host, ttl=(1, 31))/TCP(sport=port, dport=80, flags="A")
    # send packets and collect answers
    ans, unans = sr(ack, timeout=4, verbose=1)

    iplist = []
    retdata = ""
    for snd, rcv in ans:
        print rcv.summary()
        endpoint = isinstance(rcv.payload, TCP)
        retdata += "%s %s %s\n" % (snd.ttl, rcv.src, endpoint)
        #retdata += "%s\n" % (rcv.src)
        iplist.append(rcv.src)
        if endpoint:
            break
    return retdata, iplist


def connect(host):
    try:
        ipaddr = socket.gethostbyname(host)
    except socket.gaierror:
        print "Could not resolve " + host
        return
    port = RandNum(1024, 65535)
    ip = IP(dst=ipaddr)
    syn = ip / TCP(sport=port, dport=80, flags='S', seq=38)
    syn_ack = sr1(syn)

    tcp = TCP(sport=syn_ack.dport, dport=80, flags="A", seq=syn_ack.ack, ack=syn_ack.seq + 1)
    ack = ip / tcp
    send(ack)
    return ack


def http_trace(host, url):
    ack = connect(host)
    getStr = "GET %s HTTP/1.1\r\nHost: %s\r\n\r\n" % (url, host)
    request = ack / getStr
    iplist = []
    retdata = ""
    for i in range(1, 31):
        request.ttl = i
        ans, unans = sr(request, timeout=1, verbose=1, multi=1)
        for snd, rcv in ans:
            #print rcv.summary()
            middlepoint = isinstance(rcv.payload, ICMP)
            # ICMP time exceeded
            if (middlepoint):
                if (rcv.src not in iplist):
                    iplist.append(rcv.src)
                    retdata += "TTL:%s SRC:%s ICMP:%s\n" % (request.ttl, rcv.src, middlepoint)
            # GFW reset
            elif (isinstance(rcv.payload, TCP) and (rcv.payload.flags & 0x4)):
                retdata += "TTL:%s SRC:%s ICMP:%s\n" % (request.ttl, rcv.src, middlepoint)
                return retdata, iplist
    return retdata, iplist

if __name__ == "__main__":
    #NONFWPrint, NONFWList = ackattack('106.187.42.42')
    if(len(sys.argv) < 2):
        print "Usage:", sys.argv[0], "www.freebuf.com"
        sys.exit(1)
    print 'begin stimulus'
    FWPrint, FWList = http_trace(sys.argv[1], '/tibetalk')
    print '---fwprint---'
    print FWPrint
    #print '---fwlist---'
    #print FWList
    print "We find it. %s" % (FWList[-1])
