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
import zlib


class BBcFormat:
    FORMAT_PLAIN = 0
    # ---- obsoleted
    #FORMAT_BSON = 1
    #FORMAT_BSON_COMPRESS_BZ2 = 2
    #FORMAT_BSON_COMPRESS_ZLIB = 3
    #FORMAT_MSGPACK = 4
    #FORMAT_MSGPACK_COMPRESS_BZ2 = 5
    #FORMAT_MSGPACK_COMPRESS_ZLIB = 6
    # ----
    FORMAT_ZLIB = 0x0010

    @classmethod
    def generate(cls, txobj, format_type=FORMAT_PLAIN):
        """
        Transform transaction object in wire format

        :param txobj: BBcTransaction object
        :param format_type: 2-byte value of BBcFormat type
        :return: binary data
        """
        if txobj.WITH_WIRE:
            raise Exception("Fallback")
        hdr = format_type.to_bytes(2, 'little')
        if format_type == BBcFormat.FORMAT_PLAIN:
            return bytes(hdr + txobj.pack())
        elif format_type == BBcFormat.FORMAT_ZLIB:
            return bytes(hdr + zlib.compress(txobj.pack()))
        else:
            return None

    @classmethod
    def strip(cls, data):
        """
        Strip 2-byte wire header and recover plain binary

        :param data: binary data with wire header
        :return: plain binary data without the header
        """
        hdr = int.from_bytes(data[0:2], 'little')
        if hdr == BBcFormat.FORMAT_PLAIN:
            return data[2:], hdr
        elif hdr == BBcFormat.FORMAT_ZLIB:
            return zlib.decompress(data[2:]), hdr
        else:
            raise Exception("Fallback")
