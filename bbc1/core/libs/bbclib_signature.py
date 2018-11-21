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
import os
import sys
import binascii
import traceback

current_dir = os.path.abspath(os.path.dirname(__file__))
sys.path.append(os.path.join(current_dir, "../../.."))

from bbc1.core import bbclib
from bbc1.core.libs.bbclib_config import DEFAULT_CURVETYPE
from bbc1.core import bbc_error
from bbc1.core.libs import bbclib_utils
from bbc1.core.libs.bbclib_keypair import KeyPair, KeyType


class BBcSignature:
    """Signature part in a transaction"""
    def __init__(self, key_type=DEFAULT_CURVETYPE, unpack=None):
        self.key_type = key_type
        self.signature = None
        self.pubkey = None
        self.keypair = None
        self.not_initialized = True
        if unpack is not None:
            self.not_initialized = False
            self.unpack(unpack)

    def add(self, signature=None, pubkey=None):
        """Add signature and public key"""
        if signature is not None:
            self.not_initialized = False
            self.signature = signature
        if pubkey is not None:
            self.pubkey = pubkey
            self.keypair = KeyPair(curvetype=self.key_type, pubkey=pubkey)
        return True

    def __str__(self):
        if self.not_initialized:
            return "  Not initialized\n"
        ret =  "  key_type: %d\n" % self.key_type
        ret += "  signature: %s\n" % binascii.b2a_hex(self.signature)
        ret += "  pubkey: %s\n" % binascii.b2a_hex(self.pubkey)
        return ret

    def pack(self):
        """Pack this object"""
        if self.not_initialized:
            dat = bytearray(bbclib_utils.to_4byte(KeyType.NOT_INITIALIZED))
            return bytes(dat)
        dat = bytearray(bbclib_utils.to_4byte(self.key_type))
        pubkey_len_bit = len(self.pubkey) * 8
        dat.extend(bbclib_utils.to_4byte(pubkey_len_bit))
        dat.extend(self.pubkey)
        sig_len_bit = len(self.signature) * 8
        dat.extend(bbclib_utils.to_4byte(sig_len_bit))
        dat.extend(self.signature)
        return bytes(dat)

    def unpack(self, data):
        """Unpack into this object

        Args:
            data (bytes): packed binary data
        Returns:
            bool: True if successful
        """
        ptr = 0
        try:
            ptr, self.key_type = bbclib_utils.get_n_byte_int(ptr, 4, data)
            if self.key_type == KeyType.NOT_INITIALIZED:
                return True
            ptr, pubkey_len_bit = bbclib_utils.get_n_byte_int(ptr, 4, data)
            pubkey_len = int(pubkey_len_bit/8)
            ptr, pubkey = bbclib_utils.get_n_bytes(ptr, pubkey_len, data)
            ptr, sig_len_bit = bbclib_utils.get_n_byte_int(ptr, 4, data)
            sig_len = int(sig_len_bit/8)
            ptr, signature = bbclib_utils.get_n_bytes(ptr, sig_len, data)
            self.add(signature=signature, pubkey=pubkey)
        except:
            return False
        return True

    def verify(self, digest):
        """Verify digest using pubkey in signature

        Args:
            digest (bytes): digest to verify
        Returns:
            int: 0:invalid, 1:valid
        """
        bbclib._reset_error()
        if self.keypair is None:
            bbclib._set_error(code=bbc_error.EBADKEYPAIR, txt="Bad private_key/public_key")
            return False
        try:
            flag = self.keypair.verify(digest, self.signature)
        except:
            traceback.print_exc()
            return False
        return flag
