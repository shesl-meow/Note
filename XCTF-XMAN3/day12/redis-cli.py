#!/usr/bin/env python
# -*- coding: cp936 -*-
import redis
def redisTester(host,port):
    client =  redis.StrictRedis(host=host, port=port)
    return client.info()

print redisTester("122.114.136.108",6379)
