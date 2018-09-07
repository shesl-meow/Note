#!/usr/bin/env python
# -*- coding: cp936 -*-
import socket
socket.setdefaulttimeout(3)
def socktest(domain):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    testip, testport = domain.split(':')
    sock.connect((testip, int(testport)))
    data = """
     05 01 00 01 CA 6C 23 E2 00 50
    """
    data_s = ''
    for _ in data.split():
        data_s += chr(int(_, 16))
    sock.send(data_s)
    try:
        ret = sock.recv(1024)
        print len(ret)
    except Exception, e:
        pass
    sock.close()

socktest('122.114.136.108:2345')