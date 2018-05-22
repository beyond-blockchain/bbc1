import os
import binascii
from ctypes import *


class PyBBcSigSecp256k1(object):

    def __init__(self):
        """
        """
        if os.name == "nt":
            self.lib = windll.LoadLibrary("libbbcsig.dll")
        else:
            self.lib = cdll.LoadLibrary("libbbcsig.so")

    def generate_keypair(self, pubkey_type):
        """
        """
        privkey_len = c_int32(32)
        privkey     = (c_byte * privkey_len.value)()
        pubkey_len  = c_int32(65)
        pubkey      = (c_byte * pubkey_len.value)()

        ret = self.lib.generate_keypair(pubkey_type, byref(pubkey_len), pubkey, byref(privkey_len), privkey)
        if ret:
            return ( bytes(bytearray(pubkey)[:pubkey_len.value]), bytes(bytearray(privkey)[:privkey_len.value]) )
        else:
            return (None, None)

    def sign(self, privkey, digest):
        """
        """
        signature = (c_byte * 64)()

        ret = self.lib.sign(len(privkey), privkey, 32, digest, signature)
        if ret:
            return bytes(signature)
        else:
            return None

    def output_der(self, privkey):
        """
        """
        der_data = (c_byte * 512)()

        der_len = self.lib.output_der(len(privkey), privkey, byref(der_data))
        # print("der_len = {}".format(der_len))
        if der_len > 0:
            return bytes(bytearray(der_data)[:der_len])
        else:
            return None

    def convert_from_der(self, der_data, pubkey_type):
        """
        """
        privkey_len = c_int32(32)
        privkey     = (c_byte * privkey_len.value)()
        pubkey_len  = c_int32(65)
        pubkey      = (c_byte * pubkey_len.value)()

        ret = self.lib.convert_from_der(len(der_data), der_data, pubkey_type, byref(pubkey_len), pubkey, byref(privkey_len), privkey)
        if ret:
            return ( bytes(bytearray(pubkey)[:pubkey_len.value]), bytes(bytearray(privkey)[:privkey_len.value]) )
        else:
            return (None, None)

    def get_public_key_compressed(self, privkey):
        """
        """
        pubkey_len  = c_int32(65)
        pubkey      = (c_byte * pubkey_len.value)()

        ret = self.lib.get_public_key_compressed(len(privkey), privkey, byref(pubkey_len), pubkey)
        if ret:
            return bytes(bytearray(pubkey)[:pubkey_len.value])
        else:
            return None

    def get_public_key_uncompressed(self, privkey):
        """
        """
        pubkey_len  = c_int32(65)
        pubkey      = (c_byte * pubkey_len.value)()

        ret = self.lib.get_public_key_uncompressed(len(privkey), privkey, byref(pubkey_len), pubkey)
        if ret:
            return bytes(bytearray(pubkey)[:pubkey_len.value])
        else:
            return None

    def verify(self, pubkey, digest, signature):
        """
        """
        ret = self.lib.verify(len(pubkey), pubkey, 32, digest, 64, signature)
        return ret

    def output_pem(self, privkey):
        """
        """
        pem_data = (c_byte * 512)()

        pem_len = self.lib.output_pem(len(privkey), privkey, byref(pem_data))
        # print("pem_len = {}".format(pem_len))
        if pem_len > 0:
            array = bytearray(pem_data)[:(pem_len + 1)]
            array[pem_len] = 0
            return bytes(array)
        else:
            return None

    def convert_from_pem(self, pem_data, pubkey_type):
        """
        """
        privkey_len = c_int32(32)
        privkey     = (c_byte * privkey_len.value)()
        pubkey_len  = c_int32(65)
        pubkey      = (c_byte * pubkey_len.value)()

        ret = self.lib.convert_from_pem(pem_data, pubkey_type, byref(pubkey_len), pubkey, byref(privkey_len), privkey)
        if ret:
            return ( bytes(bytearray(pubkey)[:pubkey_len.value]), bytes(bytearray(privkey)[:privkey_len.value]) )
        else:
            return None

