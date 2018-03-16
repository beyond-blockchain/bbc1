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
import os
import msgpack
import struct
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

encryptors = dict()
decryptors = dict()


def to_4byte(val, offset=0):
    return (val+offset).to_bytes(4, 'big')   # network byte order


def to_2byte(val, offset=0):
    return (val+offset).to_bytes(2, 'big')   # network byte order


def make_message(payload_type, msg, payload_version=0, key_name=None):
    if payload_type == PayloadType.Type_msgpack:
        dat = msgpack.packb(msg)
    elif payload_type == PayloadType.Type_binary:
        dat = make_TLV_formatted_message(msg)
    elif payload_type == PayloadType.Type_encrypted_msgpack:
        if key_name not in encryptors or encryptors[key_name] is None:
            return None
        dat = bytearray()
        dat.extend(encryptors[key_name][1])  # add hint to the counter entity
        dat += encryptors[key_name][0].update(msgpack.packb(msg))
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
    elif payload_type == PayloadType.Type_encrypted_msgpack:
        name = bytes(dat[:4])
        try:
            msg = decryptors[name].update(bytes(dat[4:]))
        except:
            import traceback
            traceback.print_exc()
        return msgpack.unpackb(msg)
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
    while ptr < len(dat)-1:
        T, L = struct.unpack("II")
        ptr += 8
        msg[T] = dat[ptr:ptr+L]
        ptr += L
    return msg


def get_ECDH_parameters():
    global encryptors, decryptors
    private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
    serialized_pubkey = private_key.public_key().public_numbers().encode_point()
    key_name = None
    while key_name is None:
        key_name = os.urandom(4)
        if key_name in encryptors:
            key_name = None
    encryptors[key_name] = None
    decryptors[key_name] = None
    return private_key, serialized_pubkey, key_name


def derive_shared_key(private_key, serialized_pubkey, shared_info):
    deserialized_public_numbers = ec.EllipticCurvePublicNumbers.from_encoded_point(ec.SECP384R1(), serialized_pubkey)
    deserialized_pubkey = deserialized_public_numbers.public_key(default_backend())
    shared_key = private_key.exchange(ec.ECDH(), deserialized_pubkey)
    derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                       info=shared_info, backend=default_backend()).derive(shared_key)
    return derived_key


def set_cipher(shared_key, nonce, key_name, hint):
    global encryptors, decryptors
    cipher = Cipher(algorithms.AES(bytes(shared_key)), modes.CTR(nonce), backend=default_backend())
    encryptors[key_name] = [cipher.encryptor(), hint]
    decryptors[key_name] = cipher.decryptor()


def unset_cipher(key_name):
    if key_name in encryptors:
        del encryptors[key_name]
        del decryptors[key_name]


class PayloadType:
    Type_binary = 0
    Type_any = 1
    Type_msgpack = 2
    Type_encrypted_msgpack = 3


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

    infra_msg_type = to_4byte(8)  # message type in p2p network
    command = to_4byte(9)   # command type
    infra_command = to_4byte(10)
    domain_ping = to_4byte(11)   # send directly to bbc_network without node_id in the domain
    query_id = to_4byte(12)      # query_id from bbc_app
    message = to_4byte(13)
    nonce = to_4byte(14)
    count = to_4byte(15)
    stats = to_4byte(16)
    hint = to_4byte(17)
    ecdh = to_4byte(18)     # peer_public_key value for ECDH
    random = to_4byte(19)
    retry_tiemr = to_4byte(20)

    network_module = to_4byte(0, 0x30)
    storage_type = to_4byte(1, 0x30)
    storage_path = to_4byte(2, 0x30)
    node_info = to_4byte(3, 0x30)
    peer_list = to_4byte(4, 0x30)   # TODO: will obsoleted in v0.10
    domain_list = to_4byte(5, 0x30)
    forwarding_list = to_4byte(6, 0x30)
    user_list = to_4byte(7, 0x30)
    bbc_configuration = to_4byte(8, 0x30)
    ipv4_address = to_4byte(9, 0x30)
    ipv6_address = to_4byte(10, 0x30)
    port_number = to_4byte(11, 0x30)
    external_ip4addr = to_4byte(12, 0x30)
    external_ip6addr = to_4byte(13, 0x30)
    static_entry = to_4byte(14, 0x30)
    neighbor_list = to_4byte(15, 0x30)
    notification_list = to_4byte(16, 0x30)

    resource_id = to_4byte(0, 0x50)
    resource_type = to_4byte(1, 0x50)
    resource = to_4byte(2, 0x50)
    sql = to_4byte(3, 0x50)

    user_id = to_4byte(0, 0x60)
    source_user_id = to_4byte(1, 0x60)
    destination_user_id = to_4byte(2, 0x60)
    destination_user_ids = to_4byte(3, 0x60)
    node_id = to_4byte(4, 0x60)
    source_node_id = to_4byte(5, 0x60)
    destination_node_id = to_4byte(6, 0x60)

    domain_id = to_4byte(0, 0x70)
    transaction_id = to_4byte(1, 0x70)
    asset_group_id = to_4byte(2, 0x70)
    asset_group_ids = to_4byte(3, 0x70)
    asset_id = to_4byte(4, 0x70)

    transaction_data = to_4byte(0, 0x80)
    transactions = to_4byte(1, 0x80)
    ref_index = to_4byte(2, 0x80)
    asset_file = to_4byte(3, 0x80)
    all_asset_files = to_4byte(4, 0x80)
    signature = to_4byte(5, 0x80)
    cross_refs = to_4byte(6, 0x80)

    ledger_subsys_manip = to_4byte(0, 0xA0)     # enable/disable ledger_subsystem
    ledger_subsys_register = to_4byte(1, 0xA0)
    ledger_subsys_verify = to_4byte(2, 0xA0)
    merkle_tree = to_4byte(3, 0xA0)


