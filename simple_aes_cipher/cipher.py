# -*- coding: utf-8 -*-

import base64
from Crypto import Random
from Crypto.Cipher import AES


class AESCipher(object):
    def __init__(self, key, block_size=128):
        if len(key) >= len(str(block_size)):
            self.key = key[:block_size]
        else:
            self.key = self._pad(key, block_size)

    def encrypt(self, raw, mode=AES.MODE_CBC):
        raw = self._pad(raw, AES.block_size)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, mode, iv)
        return iv + cipher.encrypt(raw)

    def decrypt(self, enc, mode=AES.MODE_CBC):
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, mode, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:]))

    def _pad(self, s, bs):
        return s + (bs - len(s) % bs) * chr(bs - len(s) % bs)

    def _unpad(self, s):
        return s[:-ord(s[len(s)-1:])]
