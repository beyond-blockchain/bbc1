# -*- coding: utf-8 -*-
"""
Copyright (c) 2018 beyond-blockchain.org.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
import sys
import os
import platform
import binascii

current_dir = os.path.abspath(os.path.dirname(__file__))
sys.path.append(os.path.join(current_dir, "../../.."))

directory, filename = os.path.split(os.path.realpath(__file__))
from ctypes import *

if platform.system() == "Windows":
    libbbcsig = windll.LoadLibrary(os.path.join(directory, "libbbcsig.dll"))
elif platform.system() == "Darwin":
    libbbcsig = cdll.LoadLibrary(os.path.join(directory, "libbbcsig.dylib"))
else:
    libbbcsig = cdll.LoadLibrary(os.path.join(directory, "libbbcsig.so"))


class KeyType:
    NOT_INITIALIZED = 0
    ECDSA_SECP256k1 = 1
    ECDSA_P256v1 = 2


class KeyPair:
    POINT_CONVERSION_COMPRESSED = 2     # same as enum point_conversion_form_t in openssl/crypto/ec.h
    POINT_CONVERSION_UNCOMPRESSED = 4   # same as enum point_conversion_form_t in openssl/crypto/ec.h

    """Key pair container"""
    def __init__(self, curvetype=KeyType.ECDSA_P256v1, compression=False, privkey=None, pubkey=None):
        self.curvetype = curvetype
        self.private_key_len = c_int32(32)
        self.private_key = (c_byte * self.private_key_len.value)()
        if compression:
            self.public_key_len = c_int32(33)
            self.key_compression = KeyPair.POINT_CONVERSION_COMPRESSED
        else:
            self.public_key_len = c_int32(65)
            self.key_compression = KeyPair.POINT_CONVERSION_UNCOMPRESSED
        self.public_key = (c_byte * self.public_key_len.value)()
        if privkey is not None:
            memmove(self.private_key, bytes(privkey), sizeof(self.private_key))
        if pubkey is not None:
            self.public_key_len = c_int32(len(pubkey))
            memmove(self.public_key, bytes(pubkey), self.public_key_len.value)

    def generate(self):
        """Generate a new key pair"""
        libbbcsig.generate_keypair(self.curvetype, self.key_compression, byref(self.public_key_len), self.public_key,
                                   byref(self.private_key_len), self.private_key)

    def mk_keyobj_from_private_key(self):
        """Make a keypair object from the binary data of private key"""
        if self.private_key is None:
            return
        libbbcsig.get_public_key_uncompressed(self.curvetype, self.private_key_len, self.private_key,
                                              byref(self.public_key_len), self.public_key)

    def mk_keyobj_from_private_key_der(self, derdat):
        """Make a keypair object from the private key in DER format"""
        der_len = len(derdat)
        der_data = (c_byte * der_len)()
        memmove(der_data, bytes(derdat), der_len)
        libbbcsig.convert_from_der(der_len, byref(der_data), self.key_compression,
                                   byref(self.public_key_len), self.public_key,
                                   byref(self.private_key_len), self.private_key)

    def mk_keyobj_from_private_key_pem(self, pemdat_string):
        """Make a keypair object from the private key in PEM format"""
        libbbcsig.convert_from_pem(create_string_buffer(pemdat_string.encode()), self.key_compression,
                                   byref(self.public_key_len), self.public_key,
                                   byref(self.private_key_len), self.private_key)

    def import_publickey_cert_pem(self, cert_pemstring, privkey_pemstring=None):
        """Verify and import X509 public key certificate in pem format"""
        if privkey_pemstring is not None:
            ret = libbbcsig.verify_x509(create_string_buffer(cert_pemstring.encode()),
                                        create_string_buffer(privkey_pemstring.encode()))
        else:
            ret = libbbcsig.verify_x509(create_string_buffer(cert_pemstring.encode()), None)
        if ret != 1:
            return False

        if privkey_pemstring is not None:
            self.mk_keyobj_from_private_key_pem(privkey_pemstring)
        else:
            ret = libbbcsig.read_x509(create_string_buffer(cert_pemstring.encode()), self.key_compression, byref(self.public_key_len), self.public_key)
            if ret != 1:
                return False
        return True

    def to_binary(self, dat):
        byteval = bytearray()
        if self.public_key_len > 0:
            for i in range(self.public_key_len):
                byteval.append(dat % 256)
                dat = dat // 256
        else:
            while True:
                byteval.append(dat % 256)
                dat = dat // 256
                if dat == 0:
                    break
        return byteval

    def get_private_key_in_der(self):
        """Return private key in DER format"""
        der_data = (c_byte * 512)()     # 256 -> 512
        der_len = libbbcsig.output_der(self.curvetype, self.private_key_len, self.private_key, byref(der_data))
        return bytes(bytearray(der_data)[:der_len])

    def get_private_key_in_pem(self):
        """Return private key in PEM format"""
        pem_data = (c_char * 512)()     # 256 -> 512
        pem_len = libbbcsig.output_pem(self.curvetype, self.private_key_len, self.private_key, byref(pem_data))
        return pem_data.value

    def get_public_key_in_pem(self):
        """Return public key in PEM format"""
        pem_data = (c_char * 512)()     # 256 -> 512
        pem_len = libbbcsig.output_public_key_pem(self.curvetype, self.public_key_len, self.public_key, byref(pem_data))
        return pem_data.value

    def sign(self, digest):
        """Sign to the given value

        Args:
            digest (bytes): given value
        Returns:
            bytes: signature
        """
        sig_r = (c_byte * 32)()
        sig_s = (c_byte * 32)()
        sig_r_len = (c_byte * 4)()  # Adjust size according to the expected size of sig_r and sig_s. Default:uint32.
        sig_s_len = (c_byte * 4)()
        libbbcsig.sign(self.curvetype, self.private_key_len, self.private_key, len(digest), digest,
                       sig_r, sig_s, sig_r_len, sig_s_len)
        sig_r_len = int.from_bytes(bytes(sig_r_len), "little")
        sig_s_len = int.from_bytes(bytes(sig_s_len), "little")
        sig_r = binascii.a2b_hex("00"*(32-sig_r_len) + bytes(sig_r)[:sig_r_len].hex())
        sig_s = binascii.a2b_hex("00"*(32-sig_s_len) + bytes(sig_s)[:sig_s_len].hex())
        return bytes(bytearray(sig_r)+bytearray(sig_s))

    def verify(self, digest, sig):
        """Verify the digest and the signature using the rivate key in this object"""
        return libbbcsig.verify(self.curvetype, self.public_key_len, self.public_key, len(digest), digest, len(sig), sig)

