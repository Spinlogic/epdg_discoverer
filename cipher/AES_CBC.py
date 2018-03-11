import base64, binascii
from Cryptodome import Random
from Cryptodome.Cipher import AES

class AES_CBC_Cipher(object):

    def __init__(self, key):
        self.key = key

    def encrypt(self, raw):
        to_encrypt = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(to_encrypt)

    def decrypt(self, enc):
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:]))

    def _pad(self, s):
        pad_len = (AES.block_size - len(s) % AES.block_size) - 1
        padding = format(pad_len, '02x') * (pad_len + 1)
        return s + binascii.unhexlify(padding)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]