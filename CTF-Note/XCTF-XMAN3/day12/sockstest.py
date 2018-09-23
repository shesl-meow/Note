#!/usr/bin/env python
# -*- coding: cp936 -*-
import socks,socket,requests
socket.setdefaulttimeout(3)
def SocketTest(ip,port):
    socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, ip, port)
    socket.socket = socks.socksocket
    r=requests.get("http://px1624.sinaapp.com",timeout=3)
    print r.text

SocketTest("122.114.136.108",2345)