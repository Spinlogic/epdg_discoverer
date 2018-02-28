# -*- coding: utf-8 -*-
"""
This class handles IKEv2 state machine for interactions with ePDGs.
Only IPv4 at this time.
"""

import binascii, hashlib, socket
import logging
from dh.diffiehellman import DiffieHellman
from .exceptions import PRFError
import epdg_utils as eutils
logging.getLogger("scapy3k.runtime").setLevel(logging.ERROR)
from scapy3k.all import *
load_contrib('ikev2')


class epdg_ikev2(object):
    
    def __init__(self, ip_dst, sport, dport):
        self.prf = 'sha1'
        self.i_spi = binascii.unhexlify(eutils.RandHexString(16))
        self.r_spi = binascii.unhexlify('0' * 16)
        self.dst_addr = ip_dst
        self.dst_port = dport
        self.src_addr = eutils.GetIp()
        self.src_port = sport
        self.transform_set = {'encrypt': 12, 'prf': 2, 'integr': 2, 'group': 2}
        self.dh = DiffieHellman(group = 2, key_length = 128)
        self.dh.generate_public_key()
        self.i_n = binascii.unhexlify(eutils.RandHexString(32))


    def sa_init(self, analyse_response = False):
        '''Attempts to set up SA to peer. 
        
        :param analyse_response: Analyse the response from server
        :type bool
        :return: length of the response from peer
        :rtype: int'''
         ## calculate nat_detection_source_ip and nat_detection_destination_ip
        ip_src = socket.inet_aton(self.src_addr)
        ip_dst = socket.inet_aton(self.dst_addr)
        src_port = binascii.unhexlify(format(self.src_port, '04x'))
        dst_port = binascii.unhexlify(format(self.dst_port, '04x'))
        nat_det_src = binascii.unhexlify(hashlib.sha1(self.i_spi + self.r_spi + ip_src + src_port).hexdigest())
        nat_det_dst = binascii.unhexlify(hashlib.sha1(self.i_spi + self.r_spi + ip_dst + dst_port).hexdigest())
        transform_1 = IKEv2_payload_Transform(next_payload = 'Transform', transform_type = 'Encryption', transform_id = 12, length = 12, key_length = 128) 
        transform_2 = IKEv2_payload_Transform(next_payload = 'Transform', transform_type = 'PRF', transform_id = 2)
        transform_3 = IKEv2_payload_Transform(next_payload = 'Transform', transform_type = 'Integrity', transform_id = 2)
        transform_4 = IKEv2_payload_Transform(next_payload = 'last', transform_type = 'GroupDesc', transform_id = 2)
        packet = IP(dst = self.dst_addr, proto = 'udp') /\
            UDP(sport = self.src_port, dport = self.dst_port) /\
            IKEv2(init_SPI = self.i_spi, next_payload = 'SA', exch_type = 'IKE_SA_INIT', flags='Initiator') /\
            IKEv2_payload_SA(next_payload = 'KE', prop = IKEv2_payload_Proposal(trans_nb = 4, trans = transform_1 / transform_2 / transform_3 / transform_4, )) /\
            IKEv2_payload_KE(next_payload = 'Nonce', group = '1024MODPgr', load = binascii.unhexlify(format(self.dh.public_key, '0256x'))) /\
            IKEv2_payload_Nonce(next_payload = 'Notify', load = self.i_n) /\
            IKEv2_payload_Notify(next_payload = 'Notify', type = 16388, load = nat_det_src) /\
            IKEv2_payload_Notify(next_payload = 'None', type = 16389, load = nat_det_dst)
        ans = sr1(packet, timeout = 3, verbose = 0)
        if ans == None:
            return 0
        else:
            if(analyse_response):
                self.__analyseSAInitResponse(IKEv2(ans[UDP].load))
            return len(ans)
            

    def __analyseSAInitResponse(self, ans):
        assert ans.init_SPI == self.i_spi
        self.r_spi = ans.resp_SPI
        try:
            r_ke = int.from_bytes(ans[IKEv2_payload_KE].load, byteorder='big')
            self.r_n = ans[IKEv2_payload_Nonce].load
            self.__generateKeys(r_ke)
        except:
            print('Proposal not supported by peer.')


    def __generateKeys(self, key):
        self.dh.generate_shared_secret(key)
        salt = self.dh.shared_secret_bytes
        if(len(salt) < self.dh.prime.bit_length() // 8):
            salt = salt.ljust(self.dh.prime.bit_length() // 8, b"\x00")
        nonce = self.i_n + self.r_n #DEBUG
        SKEYSEED = hashlib.pbkdf2_hmac(self.prf, self.i_n + self.r_n, salt, 1)
        S = self.i_n + self.r_n + self.i_spi + self.r_spi
        K = b''
        T = b''
        for n in range(10):
            T = hashlib.pbkdf2_hmac(self.prf, SKEYSEED, T + S + n.to_bytes(1, byteorder='big'), 1)
            K += T
        self.SK_d = K[0:20]
        self.SK_ai = K[20:40]
        self.SK_ar = K[40:60]
        self.SK_ei = K[60:76]
        self.SK_er = K[76:92]
        self.SK_pi = K[92:112]
        self.SK_pr = K[112:132]
        return None

    