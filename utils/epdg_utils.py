# -*- coding: utf-8 -*-
"""
Set of helper functions.
"""

import random, socket

def RandHexString(length = 16):
    '''Generates a random hex string of any legth (16 characters by default)
    :param length: number of hex digits
    :type integer
    :rtype: string
    '''
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

def GenerateRandomIMSI(mcc='',mnc=''):
    '''Generates a ransom IMSI with the passed mcc and mnc.

    :param mcc: Mobile Country Code
    :type string
    :param mnc: Mobile Network Code
    :type string
    :rtype: string
    '''
    valid_letters='0123456789'
    imsi = mcc + mnc
    return imsi.join((random.choice(valid_letters) for i in range(12 - len(imsi))))
    