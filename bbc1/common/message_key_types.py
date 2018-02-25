# -*- coding: utf-8 -*-
"""
Copyright (c) 2017 beyond-blockchain.org.

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
import msgpack
import struct


def to_4byte(val, offset=0):
    return (val+offset).to_bytes(4, 'big')   # network byte order


def to_2byte(val, offset=0):
    return (val+offset).to_bytes(2, 'big')   # network byte order


def make_message(payload_type, msg, payload_version=0):
    if payload_type == PayloadType.Type_msgpack:
        dat = msgpack.packb(msg)
    elif payload_type == PayloadType.Type_binary:
        dat = make_TLV_formatted_message(msg)
    else:
        return None
    msg = bytearray()
    msg.extend(struct.pack(">HHI", payload_type, payload_version, len(dat)))
    msg.extend(dat)
    return msg


def deserialize_data(payload_type, dat):
    if payload_type == PayloadType.Type_msgpack:
        return msgpack.unpackb(dat)
    elif payload_type == PayloadType.Type_binary:
        return make_dictionary_from_TLV_format(dat)
    return None


def make_TLV_formatted_message(msg):
    dat = bytearray()
    for k, v in msg.itmes():
        dat.extend(k)
        length = len(v).to_bytes(4, 'little')
        dat.extend(length)
        if isinstance(v, list):
            dat.extend(make_TLV_formatted_message(v))
    return bytes(dat)


def make_dictionary_from_TLV_format(dat):
    msg = dict()
    ptr = 0
    while ptr < len(dat):
        T, L = struct.unpack("II")
    return


class PayloadType:
    Type_binary = 0
    Type_msgpack = 1


class Message:
    HEADER_LEN = 8  # Type, length of data_body, data_body

    def __init__(self):
        self.pending_buf = bytearray()
        self.is_new_chunk = True
        self.msg_body = None
        self.payload_type = 0
        self.format_version = 0
        self.msg_len = 0

    def recv(self, dat):
        self.pending_buf.extend(dat)

    def parse(self):
        #print(" > pending_buf=%d,%d"%(len(self.pending_buf), Message.HEADER_LEN))
        if self.is_new_chunk:
            if len(self.pending_buf) < Message.HEADER_LEN:
                return None
            self.payload_type, self.format_version, self.msg_len = struct.unpack(">HHI",
                                                                                 self.pending_buf[:Message.HEADER_LEN])
            self.is_new_chunk = False
            self.msg_body = None
            #print("  >> msg_len=%d"%(self.msg_len))

        if self.msg_len == 0:
            self.is_new_chunk = True
            self.msg_body = []
            self.pending_buf = self.pending_buf[Message.HEADER_LEN:]
            #print("  --self.msg_len == Message.HEADER_LEN -->true")
            return None

        if self.msg_len > 0 and len(self.pending_buf) >= self.msg_len+Message.HEADER_LEN:
            self.is_new_chunk = True
            self.msg_body = self.pending_buf[Message.HEADER_LEN:(self.msg_len+Message.HEADER_LEN)]
            self.pending_buf = self.pending_buf[(self.msg_len+Message.HEADER_LEN):]
            #print("  --self.msg_len > Message.HEADER_LEN -->true")
            return deserialize_data(self.payload_type, self.msg_body)
        #print(" --->>> false")
        return None


class KeyType:
    status = to_4byte(0)    # status code in bbc_error
    reason = to_4byte(1)    # text
    result = to_4byte(2)    # True/False

    command = to_4byte(8)   # command type
    message = to_4byte(9)
    domain_ping = to_4byte(10)   # send directly to bbc_network without node_id in the domain
    p2p_msg_type = to_4byte(11)  # message type in p2p network
    query_id = to_4byte(12)      # query_id from bbc_app
    nonce = to_4byte(13)
    count = to_4byte(14)
    stats = to_4byte(15)

    ledger_subsys_manip = to_4byte(0, 0x20)     # enable/disable ledger_subsystem
    ledger_subsys_register = to_4byte(1, 0x20)
    ledger_subsys_verify = to_4byte(2, 0x20)
    merkle_tree = to_4byte(3, 0x20)

    network_module = to_4byte(0, 0x30)
    storage_type = to_4byte(1, 0x30)
    storage_path = to_4byte(2, 0x30)
    peer_info = to_4byte(3, 0x30)
    peer_list = to_4byte(4, 0x30)
    domain_list = to_4byte(7, 0x30)
    bbc_configuration = to_4byte(8, 0x30)
    ipv4_address = to_4byte(9, 0x30)
    ipv6_address = to_4byte(10, 0x30)
    port_number = to_4byte(11, 0x30)
    external_ip4addr = to_4byte(12, 0x30)
    external_ip6addr = to_4byte(13, 0x30)

    resource_id = to_4byte(0, 0x40)
    resource_type = to_4byte(1, 0x40)
    resource = to_4byte(2, 0x40)

    user_id = to_4byte(0, 0x50)
    source_user_id = to_4byte(1, 0x50)
    destination_user_id = to_4byte(2, 0x50)
    destination_user_ids = to_4byte(3, 0x50)
    node_id = to_4byte(4, 0x50)
    source_node_id = to_4byte(5, 0x50)
    destination_node_id = to_4byte(6, 0x50)

    domain_id = to_4byte(0, 0x60)
    asset_group_id = to_4byte(1, 0x60)
    transaction_id = to_4byte(2, 0x60)
    asset_id = to_4byte(3, 0x60)

    transaction_data = to_4byte(0, 0x70)
    transactions = to_4byte(1, 0x70)
    ref_index = to_4byte(2, 0x70)
    asset_file = to_4byte(3, 0x70)
    all_asset_files = to_4byte(4, 0x70)
    signature = to_4byte(5, 0x70)
    cross_refs = to_4byte(6, 0x70)


