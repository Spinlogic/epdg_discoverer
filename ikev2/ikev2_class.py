# -*- coding: utf-8 -*-
"""
This class handles IKEv2 state machine for interactions with ePDGs.
Only IPv4 at this time.
"""

import binascii, hashlib, socket
import logging
from dh.diffiehellman import DiffieHellman
from .exceptions import PRFError
from cipher.AES_CBC import AES_CBC_Cipher
import Cryptodome.Hash as cryp
import epdg_utils as eutils
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
load_contrib('ikev2')


class epdg_ikev2(object):
    
    def __init__(self, ip_dst):
        self.prf = 'SHA1'
        self.i_spi = binascii.unhexlify(eutils.RandHexString(16))
        self.r_spi = binascii.unhexlify('0' * 16)
        self.dst_addr = ip_dst
        self.src_addr = eutils.GetIp()
        self.transform_set = {'encrypt': 12, 'prf': 2, 'integr': 2, 'group': 2}
        self.dh = DiffieHellman(group = 2, key_length = 128)
        self.dh.generate_public_key()
        self.i_n = binascii.unhexlify(eutils.RandHexString(32))


    def sa_init(self, sport, dport, analyse_response = False):
        '''Attempts to set up SA to peer. 
        
        :param analyse_response: Analyse the response from server
        :type bool
        :return: length of the response from peer
        :rtype: int'''
         ## calculate nat_detection_source_ip and nat_detection_destination_ip
        ip_src = socket.inet_aton(self.src_addr)
        ip_dst = socket.inet_aton(self.dst_addr)
        src_port = binascii.unhexlify(format(sport, '04x'))
        dst_port = binascii.unhexlify(format(dport, '04x'))
        nat_det_src = binascii.unhexlify(hashlib.sha1(self.i_spi + self.r_spi + ip_src + src_port).hexdigest())
        nat_det_dst = binascii.unhexlify(hashlib.sha1(self.i_spi + self.r_spi + ip_dst + dst_port).hexdigest())
        transform_1 = IKEv2_payload_Transform(next_payload = 'Transform', transform_type = 'Encryption', transform_id = 12, length = 12, key_length = 128) 
        transform_2 = IKEv2_payload_Transform(next_payload = 'Transform', transform_type = 'PRF', transform_id = 2)
        transform_3 = IKEv2_payload_Transform(next_payload = 'Transform', transform_type = 'Integrity', transform_id = 2)
        transform_4 = IKEv2_payload_Transform(next_payload = 'last', transform_type = 'GroupDesc', transform_id = 2)
        packet = IP(dst = self.dst_addr, proto = 'udp') /\
            UDP(sport = sport, dport = dport) /\
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

    def sa_auth(self, sport, dport, imsi, mcc = '', mnc = ''):
        '''Sends encrypted IKE_AUTH with content 
        mcc and mnc only need to be provided when mcc is not equal to the first three digits of the IMSI or the mnc is not equal the 4th and 5th digit of the IMSI.  
        :param imsi: user IMSI
        :type string
        :param mcc: mobile country code
        :return: length of the response from peer
        :rtype: int'''
        self.__buildIdentity(imsi, mcc, mnc)
        ip_src = socket.inet_aton(self.src_addr)
        ip_dst = socket.inet_aton(self.dst_addr)
        packet_to_encrypt = self.__buildInnerPacket()
        #print('Payload to encrypt: {}'.format(packet_to_encrypt[0].show()))
        payload_to_encrypt = raw(packet_to_encrypt[0])
        #print('Raw payload to encrypt: {}'.format(payload_to_encrypt))
        cipher = AES_CBC_Cipher(self.SK_ei)
        encrypted_payload = cipher.encrypt(payload_to_encrypt)
        print('Encrypted payload: {}'.format(encrypted_payload))
        packet = IP(dst = self.dst_addr, proto = 'udp') /\
            UDP(sport = sport, dport = dport) /\
            binascii.unhexlify('00000000') /\
            IKEv2(init_SPI = self.i_spi, resp_SPI = self.r_spi, next_payload = 'Encrypted', exch_type = 'IKE_AUTH', flags='Initiator', id = 1) /\
            IKEv2_payload_Encrypted(next_payload = 'IDi', load = encrypted_payload)
        checksum = self.__calcIntegrity(packet[UDP].load)
        print('Checksum: {}'.format(checksum))
        packet = packet / checksum
        ans = sr1(packet, timeout = 3, verbose = 0)
        if ans == None:
            return 0
        else:
            return len(ans)

    def __buildInnerPacket(self):
        transform_1 = IKEv2_payload_Transform(next_payload = 'Transform', transform_type = 'Encryption', transform_id = 12, length = 12, key_length = 128) 
        transform_2 = IKEv2_payload_Transform(next_payload = 'Transform', transform_type = 'Integrity', transform_id = 2)
        transform_3 = IKEv2_payload_Transform(next_payload = 'last', transform_type = 'Extended Sequence Number', transform_id = 0)
        cp_attrib_1 = CP_Attribute(attr_type = 'INTERNAL_IP4_ADDRESS', value = binascii.unhexlify('00000000'))
        cp_attrib_2 = CP_Attribute(attr_type = 'INTERNAL_IP4_NETMASK', value = binascii.unhexlify('00000000'))
        cp_attrib_3 = CP_Attribute(attr_type = 'INTERNAL_IP4_DNS', value = binascii.unhexlify('00000000'))
        cp_attrib_4 = CP_Attribute(attr_type = 'INTERNAL_IP4_DNS', value = binascii.unhexlify('00000000'))
        cp_attrib_5 = CP_Attribute(attr_type = 'P_CSCF_IP4_ADDRESS_ALT', value = binascii.unhexlify('00000000'))
        payload =  IKEv2_payload_IDi(next_payload = 'IDr', IDtype = 'Email_addr', load = self.i_ID) /\
            IKEv2_payload_IDr(next_payload = 'SA', IDtype = 'Key', load = "ims") /\
            IKEv2_payload_SA(next_payload = 'TSi', prop = IKEv2_payload_Proposal(trans_nb = 3, trans = transform_1 / transform_2 / transform_3, )) /\
            IKEv2_payload_TSi(next_payload = 'TSr', number_of_TSs = 1, traffic_selector = IPv4TrafficSelector()) /\
            IKEv2_payload_TSr(next_payload = 'CP', number_of_TSs = 1, traffic_selector = IPv4TrafficSelector()) /\
            IKEv2_payload_CP(next_payload = 'Notify', cfg_type = 'CFG_REQUEST', attribs = cp_attrib_1 / cp_attrib_2 / cp_attrib_3 / cp_attrib_4 / cp_attrib_5) /\
            IKEv2_payload_Notify(next_payload = 'Notify', type = 16384) /\
            IKEv2_payload_Notify(next_payload = 'Notify', type = 16394) /\
            IKEv2_payload_Notify(next_payload = 'Notify', type = 16395) /\
            IKEv2_payload_Notify(next_payload = 'None', type = 16417)
        return payload

    def __calcIntegrity(self, raw):
        isha1 = hashlib.sha1(raw)
        return binascii.unhexlify(isha1.hexdigest())

    def __analyseSAInitResponse(self, ans):
        assert ans.init_SPI == self.i_spi
        self.r_spi = ans.resp_SPI
        try:
            r_ke = int.from_bytes(ans[IKEv2_payload_KE].load, byteorder='big')
            self.r_n = ans[IKEv2_payload_Nonce].load
            try:
                self.__generateKeys(r_ke)
            except:
                print('Error generating keys.')
        except:
            print('Proposal not supported by peer.')


    def __generateKeys(self, key):
        self.dh.generate_shared_secret(key)
        shared_secret = self.dh.shared_secret_bytes
        if(len(shared_secret) < self.dh.prime.bit_length() // 8):
            shared_secret = shared_secret.ljust(self.dh.prime.bit_length() // 8, b"\x00")
        mMac = cryp.HMAC.new(key = self.i_n + self.r_n, msg = shared_secret, digestmod = cryp.SHA1)
        SKEYSEED = binascii.unhexlify(mMac.hexdigest())
        S = self.i_n + self.r_n + self.i_spi + self.r_spi
        K = b''
        T = b''
        for n in range(1, 15):
            hmac = cryp.HMAC.new(SKEYSEED, digestmod = cryp.SHA1)
            hmac.update(T + S + n.to_bytes(1, byteorder='big'))
            T = binascii.unhexlify(hmac.hexdigest())
            K += T
            del(hmac)
        self.SK_d = K[0:64]
        self.SK_ai = K[64:84]
        self.SK_ar = K[84:104]
        self.SK_ei = K[104:120]
        self.SK_er = K[120:136]
        self.SK_pi = K[136:200]
        self.SK_pr = K[200:264]
        return None


    def __buildIdentity(self, pimsi, pmcc, pmnc):
        '''Builds the NAI identity for the user as specified in 3GPP TS23.003 
        
        :param imsi: user IMSI
        :type string
        :rtype: void'''
        if(len(pmcc) == 0):
            mcc = pimsi[0:3]
        else:
            mcc = pmcc
        if(len(pmnc) == 0):
            mnc = pimsi[len(mcc):len(mcc) + 2]
        else:
            mnc = pmnc
        if(len(mnc) < 3):
            mnc += '0' * (3 - len(mnc))
        nai_id = '0{}@nai.epc.mnc{}.mcc{}.3gppnetwork.org'.format(pimsi, mnc, mcc)
        self.i_ID = nai_id
        