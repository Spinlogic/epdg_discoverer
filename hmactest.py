import binascii, hashlib, socket
import logging
from dh.diffiehellman import DiffieHellman
from cipher.AES_CBC import AES_CBC_Cipher
import Cryptodome.Hash as crypto
import epdg_utils as eutils
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
load_contrib('ikev2')

Ni = b'\xb2Cm\x9c\xd0@\x97\xe5,0(\xde\x17\xed\xb7\x9b\x98\xc6f\xa1D\xa5\xa7\x19LN\x183\xdd\xa7m\x04'
Nr = b'\xd5\x7fM\xe6\xd9{ \x0fUR\xe7\x9b8\xe0WX'
h = crypto.HMAC.new(Ni + Nr, digestmod=crypto.SHA1)
h.update("abc".encode())
h.hexdigest()
h.update("def".encode())
res = h.hexdigest()
print('Result 1: {}'.format(res))

hmac = crypto.HMAC.new(Ni + Nr, digestmod=crypto.SHA1)
hmac.update("abcdef".encode())
res1 = hmac.hexdigest()
print('Result 2: {}'.format(res1))
