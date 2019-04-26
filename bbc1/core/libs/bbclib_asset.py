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

import hashlib
import msgpack
import traceback

current_dir = os.path.abspath(os.path.dirname(__file__))
sys.path.append(os.path.join(current_dir, "../../.."))

from bbc1.core.libs import bbclib_utils
from bbc1.core.libs.bbclib_config import DEFAULT_ID_LEN


class BBcAsset:
    """Asset part in a transaction"""
    def __init__(self, user_id=None, asset_file=None, asset_body=None, id_length=DEFAULT_ID_LEN, version=2):
        self.id_length = id_length
        self.version = version
        self.asset_id = None
        if user_id is not None and id_length < 32:
            self.user_id = user_id[:id_length]
        else:
            self.user_id = user_id
        self.nonce = bbclib_utils.get_random_value()
        self.asset_file_size = 0
        self.asset_file = None
        self.asset_file_digest = None
        self.asset_body_size = 0
        self.asset_body = None
        if user_id is not None:
            self.add(user_id, asset_file, asset_body)

    def __str__(self):
        ret =  "  Asset:\n"
        ret += "     asset_id: %s\n" % bbclib_utils.str_binary(self.asset_id)
        ret += "     user_id: %s\n" % bbclib_utils.str_binary(self.user_id)
        ret += "     nonce: %s\n" % bbclib_utils.str_binary(self.nonce)
        ret += "     file_size: %d\n" % self.asset_file_size
        ret += "     file_digest: %s\n" % bbclib_utils.str_binary(self.asset_file_digest)
        ret += "     body_size: %d\n" % self.asset_body_size
        ret += "     body: %s\n" % self.asset_body
        return ret

    def add(self, user_id=None, asset_file=None, asset_body=None):
        """Add parts in this object"""
        if user_id is not None:
            self.user_id = user_id[:self.id_length]
        if asset_file is not None:
            self.asset_file = asset_file
            self.asset_file_size = len(asset_file)
            self.asset_file_digest = hashlib.sha256(bytes(asset_file)).digest()
        if asset_body is not None:
            self.asset_body = asset_body
            if isinstance(asset_body, str):
                self.asset_body = asset_body.encode()
            self.asset_body_size = len(asset_body)
        self.digest()

    def digest(self):
        """Calculate the digest

        The digest corresponds to the asset_id of this object

        Returns:
            bytes: asset_id (or digest)
        """
        target = self.pack(for_digest_calculation=True)
        self.asset_id = hashlib.sha256(target).digest()[:self.id_length]
        return self.asset_id

    def get_asset_file(self):
        """Get asset file content and its digest

        Returns:
            bytes: digest of the file content
            bytes: the file content
        """
        if self.asset_file is None:
            return None, None
        return self.asset_file_digest, self.asset_file

    def recover_asset_file(self, asset_file):
        """Recover asset file info from the given raw content"""
        digest = hashlib.sha256(asset_file).digest()
        if digest == self.asset_file_digest:
            self.asset_file = asset_file
            return True
        else:
            return False

    def pack(self, for_digest_calculation=False):
        """Pack this object

        Args:
            for_digest_calculation (bool): True if digest calculation
        Returns:
            bytes: packed binary data
        """
        dat = bytearray()
        if not for_digest_calculation:
            dat.extend(bbclib_utils.to_bigint(self.asset_id, size=self.id_length))
        dat.extend(bbclib_utils.to_bigint(self.user_id, size=self.id_length))
        dat.extend(bbclib_utils.to_2byte(len(self.nonce)))
        dat.extend(self.nonce)
        dat.extend(bbclib_utils.to_4byte(self.asset_file_size))
        if self.asset_file_size > 0:
            dat.extend(bbclib_utils.to_bigint(self.asset_file_digest))
        if isinstance(self.asset_body, dict):
            dat.extend(bbclib_utils.to_2byte(1))
            astbdy = msgpack.dumps(self.asset_body)
            dat.extend(bbclib_utils.to_2byte(len(astbdy)))
            dat.extend(astbdy)
        else:
            dat.extend(bbclib_utils.to_2byte(0))
            dat.extend(bbclib_utils.to_2byte(self.asset_body_size))
            if self.asset_body_size > 0:
                dat.extend(self.asset_body)
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
            ptr, self.asset_id = bbclib_utils.get_bigint(ptr, data)
            ptr, self.user_id = bbclib_utils.get_bigint(ptr, data)
            ptr, noncelen = bbclib_utils.get_n_byte_int(ptr, 2, data)
            ptr, self.nonce = bbclib_utils.get_n_bytes(ptr, noncelen, data)
            ptr, self.asset_file_size = bbclib_utils.get_n_byte_int(ptr, 4, data)
            if self.asset_file_size > 0:
                ptr, self.asset_file_digest = bbclib_utils.get_bigint(ptr, data)
            else:
                self.asset_file_digest = None
            ptr, dict_flag = bbclib_utils.get_n_byte_int(ptr, 2, data)
            if dict_flag != 1:
                ptr, self.asset_body_size = bbclib_utils.get_n_byte_int(ptr, 2, data)
                if self.asset_body_size > 0:
                    ptr, self.asset_body = bbclib_utils.get_n_bytes(ptr, self.asset_body_size, data)
            else:
                ptr, sz = bbclib_utils.get_n_byte_int(ptr, 2, data)
                ptr, astbdy = bbclib_utils.get_n_bytes(ptr, sz, data)
                self.asset_body = msgpack.loads(astbdy)
                self.asset_body_size = len(self.asset_body)

        except:
            traceback.print_exc()
            return False
        return True
