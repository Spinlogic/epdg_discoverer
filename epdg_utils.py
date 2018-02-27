# -*- coding: utf-8 -*-
"""
Set of helper functions.
"""

import random, socket

def RandHexString(length = 16):
    '''Generates a random hex string of any legth (16 characters by default)'''
    valid_letters='0123456789abcdef'
    return ''.join((random.choice(valid_letters) for i in range(length)))



def GetIp():
    '''Gets the IP address of the interface for default route.'''
    # Code borrowed from https://stackoverflow.com/questions/166506/finding-local-ip-addresses-using-pythons-stdlib
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't even have to be reachable
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP