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
import traceback

current_dir = os.path.abspath(os.path.dirname(__file__))
sys.path.append(os.path.join(current_dir, "../.."))
from bbc1.core.libs.bbclib_config import DEFAULT_ID_LEN
from bbc1.core.libs import bbclib_utils
from bbc1.core.libs.bbclib_pointer import BBcPointer
from bbc1.core.libs.bbclib_asset import BBcAsset



class BBcRelation:
    """Relation part in a transaction"""
    def __init__(self, asset_group_id=None, id_length=DEFAULT_ID_LEN):
        self.id_length = id_length
        if asset_group_id is not None and id_length < 32:
            self.asset_group_id = asset_group_id[:id_length]
        else:
            self.asset_group_id = asset_group_id
        self.pointers = list()
        self.asset = None

    def __str__(self):
        ret =  "  asset_group_id: %s\n" % bbclib_utils.str_binary(self.asset_group_id)
        if len(self.pointers) > 0:
            ret += "  Pointers[]: %d\n" % len(self.pointers)
            for i, pt in enumerate(self.pointers):
                ret += "   [%d]\n" % i
                ret += str(pt)
        ret += str(self.asset)
        return ret

    def add(self, asset_group_id=None, asset=None, pointer=None):
        """Add parts"""
        if asset_group_id is not None:
            self.asset_group_id = asset_group_id[:self.id_length]
        if pointer is not None:
            if isinstance(pointer, list):
                self.pointers.extend(pointer)
            else:
                self.pointers.append(pointer)
        if asset is not None:
            self.asset = asset
        return True

    def pack(self):
        """Pack this object

        Returns:
            bytes: packed binary data
        """
        dat = bytearray(bbclib_utils.to_bigint(self.asset_group_id, size=self.id_length))
        dat.extend(bbclib_utils.to_2byte(len(self.pointers)))
        for i in range(len(self.pointers)):
            pt = self.pointers[i].pack()
            dat.extend(bbclib_utils.to_2byte(len(pt)))
            dat.extend(pt)
        if self.asset is not None:
            ast = self.asset.pack()
            dat.extend(bbclib_utils.to_4byte(len(ast)))
            dat.extend(ast)
        else:
            dat.extend(bbclib_utils.to_4byte(0))
        return bytes(dat)

    def unpack(self, data):
        """Unpack data into transaction object

        Args:
            data (bytes): packed binary data
        Returns:
            bool: True if successful
        """
        ptr = 0
        data_size = len(data)
        try:
            ptr, self.asset_group_id = bbclib_utils.get_bigint(ptr, data)
            ptr, pt_num = bbclib_utils.get_n_byte_int(ptr, 2, data)
            self.pointers = list()
            for i in range(pt_num):
                ptr, size = bbclib_utils.get_n_byte_int(ptr, 2, data)
                ptr, ptdata = bbclib_utils.get_n_bytes(ptr, size, data)
                if ptr >= data_size:
                    return False
                pt = BBcPointer()
                if not pt.unpack(ptdata):
                    return False
                self.pointers.append(pt)
            self.asset = None
            ptr, astsize = bbclib_utils.get_n_byte_int(ptr, 4, data)
            if astsize > 0:
                self.asset = BBcAsset(id_length=self.id_length)
                ptr, astdata = bbclib_utils.get_n_bytes(ptr, astsize, data)
                if not self.asset.unpack(astdata):
                    return False
        except:
            return False
        return True
