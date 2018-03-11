'''
Script to decode packets in pcap file.
Use it as a guidance. You will need to modify it to suit your needs.
In my case, I use it to decode IKEv2_AUTH request and respond messages when I need to debug the scripts.
'''

from scapy.all import *
load_contrib('ikev2')
from cipher.AES_CBC import AES_CBC_Cipher

SK_ei = b'\xc2\x12\xdb\x0c\xa7tj7\xaf;\r>\xf1{C\xf1'
SK_er = b'\x17m\xb3\xd8\xc5\x10\x80\xb8 ~\xdcr\xbf8\xd5x'

packet = rdpcap('ikev2_auth.pcap')
ike_req = IKEv2(raw(packet[2][ESP])[4:])
ike_res = IKEv2(raw(packet[3][ESP])[4:])

ike_req.show()
ike_encrypted = ike_req[IKEv2_payload_Encrypted]
mCipher = AES_CBC_Cipher(SK_ei)
decrypted = mCipher.decrypt(ike_encrypted.load[:-12])

#IDi
len = int.from_bytes(decrypted[2:4], byteorder='big')
print("Raw: {}".format(decrypted[:len]))
IDi = IKEv2_payload_IDi(decrypted[:len])
IDi.show()
decrypted = decrypted[len:]

#IDr
len = int.from_bytes(decrypted[2:4], byteorder='big')
print("Raw: {}".format(decrypted[:len]))
IDr = IKEv2_payload_IDr(decrypted[:len])
IDr.show()
decrypted = decrypted[len:]

#SA
len = int.from_bytes(decrypted[2:4], byteorder='big')
print("Raw: {}".format(decrypted[:len]))
SA = IKEv2_payload_SA(decrypted[:len])
SA.show()
decrypted = decrypted[len:]

#TSi
len = int.from_bytes(decrypted[2:4], byteorder='big')
print("Raw: {}".format(decrypted[:len]))
TSi = IKEv2_payload_TSi(decrypted[:len])
TSi.show()
decrypted = decrypted[len:]

#TSr
len = int.from_bytes(decrypted[2:4], byteorder='big')
print("Raw: {}".format(decrypted[:len]))
TSr = IKEv2_payload_TSr(decrypted[:len])
TSr.show()
decrypted = decrypted[len:]

#CP
len = int.from_bytes(decrypted[2:4], byteorder='big')
print("Raw: {}".format(decrypted[:len]))
CP = IKEv2_payload_CP(decrypted[:len])
CP.show()
decrypted = decrypted[len:]

#Notify
len = int.from_bytes(decrypted[2:4], byteorder='big')
print("Raw: {}".format(decrypted[:len]))
not1 = IKEv2_payload_Notify(decrypted[:len])
not1.show()
decrypted = decrypted[len:]

#Notify
len = int.from_bytes(decrypted[2:4], byteorder='big')
print("Raw: {}".format(decrypted[:len]))
not2 = IKEv2_payload_Notify(decrypted[:len])
not2.show()
decrypted = decrypted[len:]

#Notify
len = int.from_bytes(decrypted[2:4], byteorder='big')
print("Raw: {}".format(decrypted[:len]))
not3 = IKEv2_payload_Notify(decrypted[:len])
not3.show()
decrypted = decrypted[len:]

#Notify
len = int.from_bytes(decrypted[2:4], byteorder='big')
print("Raw: {}".format(decrypted[:len]))
not4 = IKEv2_payload_Notify(decrypted[:len])
not4.show()
decrypted = decrypted[len:]

print('\n-----------------------------------------------------------------------------\n')

ike_res.show()
ike_encrypted = ike_res[IKEv2_payload_Encrypted]
mCipher = AES_CBC_Cipher(SK_er)
decrypted = mCipher.decrypt(ike_encrypted.load[:-12])

response = IKEv2_payload(decrypted)
response.show()
