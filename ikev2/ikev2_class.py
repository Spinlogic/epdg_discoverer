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
import utils.epdg_utils as eutils
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
load_contrib('ikev2')


class epdg_ikev2(object):
    
    def __init__(self, ip_dst):
        self.prf = 'SHA1'
        self.i_spi = binascii.unhexlify(eutils.RandHexString(16))
        self.r_spi = binascii.unhexlify('0' * 16)
        self.i_spi_esp = binascii.unhexlify(eutils.RandHexString(8))
        self.dst_addr = ip_dst
        self.src_addr = eutils.GetIp()
        self.transform_set = {'encrypt': 12, 'prf': 2, 'integr': 2, 'group': 2}
        self.dh = DiffieHellman(group = 2, key_length = 256)
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
            IKEv2_payload_KE(next_payload = 'Nonce', group = '1024MODPgr', load = self.dh.public_key_bytes) /\
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
        cipher = AES_CBC_Cipher(self.SK_ei)
        encrypted_payload = cipher.encrypt(raw(packet_to_encrypt[0])) + (b'\x00' * 12)  # add 12 bytes of checsum
        packet = IP(dst = self.dst_addr, proto = 'udp') /\
            UDP(sport = sport, dport = dport) /\
            (b'\x00' * 4) /\
            IKEv2(init_SPI = self.i_spi, resp_SPI = self.r_spi, next_payload = 'Encrypted', exch_type = 'IKE_AUTH', flags='Initiator', id = 1) /\
            IKEv2_payload_Encrypted(next_payload = 'IDi', load = encrypted_payload)  # Void checksum for length calculation
        checksum = self.__calcIntegrity(raw(packet[IKEv2]))
        packet2send = IP(raw(packet)[:-12] + checksum)      # replace with correct checksum
        resp = sr1(packet2send, timeout = 3, verbose = 0)
        if resp == None:
            return 0
        else:
            resp.show()
            self.__analyseSAAuthResponse(resp[ESP])
            return len(resp)

    def __buildInnerPacket(self):
        transform_1 = IKEv2_payload_Transform(next_payload = 'Transform', transform_type = 'Encryption', transform_id = 12, length = 12, key_length = 128) 
        transform_2 = IKEv2_payload_Transform(next_payload = 'Transform', transform_type = 'Integrity', transform_id = 2)
        transform_3 = IKEv2_payload_Transform(next_payload = 'last', transform_type = 'Extended Sequence Number', transform_id = 0)
        cp_attrib_1 = CP_Attribute(attr_type = 'INTERNAL_IP4_ADDRESS')
        cp_attrib_2 = CP_Attribute(attr_type = 'INTERNAL_IP4_NETMASK')
        cp_attrib_3 = CP_Attribute(attr_type = 'INTERNAL_IP4_DNS')
        cp_attrib_4 = CP_Attribute(attr_type = 'INTERNAL_IP4_DNS')
        cp_attrib_5 = CP_Attribute(attr_type = 'P_CSCF_IP4_ADDRESS_ALT')
        payload =  IKEv2_payload_IDi(next_payload = 'IDr', IDtype = 'Email_addr', load = self.i_ID) /\
            IKEv2_payload_IDr(next_payload = 'SA', IDtype = 'Key', load = "ims") /\
            IKEv2_payload_SA(next_payload = 'TSi', prop = IKEv2_payload_Proposal(proto = 'ESP', trans_nb = 3, SPI = self.i_spi_esp, SPIsize = 4, trans = transform_1 / transform_2 / transform_3)) /\
            IKEv2_payload_TSi(next_payload = 'TSr', number_of_TSs = 1, traffic_selector = IPv4TrafficSelector(starting_address_v4='0.0.0.0',ending_address_v4='255.255.255.255')) /\
            IKEv2_payload_TSr(next_payload = 'CP', number_of_TSs = 1, traffic_selector = IPv4TrafficSelector(starting_address_v4='0.0.0.0',ending_address_v4='255.255.255.255')) /\
            IKEv2_payload_CP(next_payload = 'Notify', cfg_type = 'CFG_REQUEST', attribs = cp_attrib_1 / cp_attrib_2 / cp_attrib_3 / cp_attrib_4 / cp_attrib_5) /\
            IKEv2_payload_Notify(next_payload = 'Notify', type = 16384) /\
            IKEv2_payload_Notify(next_payload = 'Notify', type = 16394) /\
            IKEv2_payload_Notify(next_payload = 'Notify', type = 16395) /\
            IKEv2_payload_Notify(next_payload = 'None', type = 16417)
        return payload

    def __calcIntegrity(self, raw):
        payload = raw[0:-12]
        mMac = cryp.HMAC.new(self.SK_ai, msg = payload, digestmod = cryp.SHA1)
        # The actual integrity alg is SHA1-96 NOT SHA1
        return mMac.digest()[0:12]

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

    def __analyseSAAuthResponse(self, ans):
        print('Raw response: {}'.format(raw(ans)))
        ike = IKEv2(raw(ans)[4:])
        assert ike.init_SPI == self.i_spi
        assert ike.resp_SPI == self.r_spi
        # try:
        #     encr_payload = ans[IKEv2_payload_Encrypted].load
        #     cipher = AES_CBC_Cipher(self.SK_er)
        #     dcrt_payload = cipher.encrypt(encr_payload[0:12])
        #     dcrt_payload.show()
        # except:
        #     print('Decrypt error.')

    def __generateKeys(self, key):
        self.dh.generate_shared_secret(key)        
        mMac = cryp.HMAC.new(key = self.i_n + self.r_n, msg = self.dh.shared_secret_bytes, digestmod = cryp.SHA1)
        SKEYSEED = mMac.digest()
        S = self.i_n + self.r_n + self.i_spi + self.r_spi
        K = b''
        T = b''
        for n in range(1, 10):
            hmac = cryp.HMAC.new(SKEYSEED, digestmod = cryp.SHA1)
            hmac.update(T + S + n.to_bytes(1, byteorder='big'))
            T = hmac.digest()
            K += T
            del(hmac)
        # KEY lengths in bytes
        prf_len = 20 # RFC7296 -> key length for SK_d, SK_pi and SK_py must be the length of the output of the underlying hash function (SHA1 = 20 bytes)
        integrity_len = 20  # SHA1-96 key length as per RFC2404
        encrypt_len = 16    # AES (128 bit keys are negotiated)
        index = 0
        self.SK_d = K[index:prf_len]
        index += prf_len
        self.SK_ai = K[index:index + integrity_len]
        index += integrity_len
        self.SK_ar = K[index:index + integrity_len]
        index += integrity_len
        self.SK_ei = K[index:index + encrypt_len]
        index += encrypt_len
        self.SK_er = K[index:index + encrypt_len]
        index += encrypt_len
        self.SK_pi = K[index:index + prf_len]
        index += prf_len
        self.SK_pr = K[index:index + prf_len]
        
        print_keys = True
        if(print_keys):
            #DEBUG Prints
            print('\n\n-------------------------- BEGIN KEY GENERATION MATERIAL ---------------------------\n')
            print('KE_i: {}\nbytes: {}\n'.format(self.dh.public_key, self.dh.public_key_bytes))
            print('KE_r: {}\nbytes: {}\n'.format(key, key.to_bytes(128, byteorder='big')))
            print('Shared_secret: {}\nbytes: {}\n'.format(self.dh.shared_secret, self.dh.shared_secret_bytes))
            print('DH Modulus: {}\nbytes: {}\n'.format(self.dh.prime, self.dh.prime.to_bytes(self.dh.prime.bit_length() // 8, byteorder='big')))
            print('Ni: {}\n'.format(self.i_n))
            print('Nr: {}\n'.format(self.r_n))
            print('SPIi: {}\n'.format(self.i_spi))
            print('SPIr: {}\n'.format(self.r_spi))
            print('SKEYSEED: {}\n'.format(SKEYSEED))
            print('Keys string: {}\n'.format(K))
            print('SK_d =  {}\n'.format(self.SK_d))
            print('SK_ai = {}\n'.format(self.SK_ai))
            print('SK_ar = {}\n'.format(self.SK_ar))
            print('SK_ei = {}\n'.format(self.SK_ei))
            print('SK_er = {}\n'.format(self.SK_er))
            print('SK_pi = {}\n'.format(self.SK_pi))
            print('SK_pr = {}\n'.format(self.SK_pr))
            print('--------------------------- END KEY GENERATION MATERIAL ----------------------------\n\n')
        return None

    def __buildIdentity(self, pimsi, pmcc = '', pmnc = ''):
        '''Builds the NAI identity for the user as specified in 3GPP TS23.003 
        
        :param imsi: user IMSI
        :type string
        :param pmcc: Mobile Country Code
        :type string
        :param pmnc: Mobile Network Code
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
            mnc = '0' * (3 - len(mnc)) + mnc
        nai_id = '0{}@nai.epc.mnc{}.mcc{}.3gppnetwork.org'.format(pimsi, mnc, mcc)
        self.i_ID = nai_id
        