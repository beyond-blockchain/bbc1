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
import hashlib
import random
import time
from collections import Mapping

current_dir = os.path.abspath(os.path.dirname(__file__))
sys.path.append(os.path.join(current_dir, "../../.."))

from bbc1.core.libs.bbclib_config import DEFAULT_ID_LEN

from bbc1.core.libs.bbclib_transaction import BBcTransaction
from bbc1.core.libs.bbclib_signature import BBcSignature
from bbc1.core.libs.bbclib_asset import BBcAsset
from bbc1.core.libs.bbclib_relation import BBcRelation
from bbc1.core.libs.bbclib_reference import BBcReference
from bbc1.core.libs.bbclib_event import BBcEvent
from bbc1.core.libs.bbclib_pointer import BBcPointer
from bbc1.core.libs.bbclib_witness import BBcWitness
from bbc1.core.libs.bbclib_crossref import BBcCrossRef


def str_binary(dat):
    if dat is None:
        return "None"
    else:
        return binascii.b2a_hex(dat)


def get_new_id(seed_str=None, include_timestamp=True):
    """Return 256-bit binary data

    Args:
          seed_str (str): seed string that is hashed by SHA256
          include_timestamp (bool): if True, timestamp (current time) is appended to the seed string
    Returns:
          bytes: 256-bit binary
    """
    if seed_str is None:
        return get_random_id()
    if include_timestamp:
        seed_str += "%f" % time.time()
    return hashlib.sha256(bytes(seed_str.encode())).digest()


def get_random_id():
    """Return 256-bit binary data

    Returns:
          bytes: 256-bit random binary
    """
    source_str = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
    output = "".join([random.choice(source_str) for x in range(16)])
    return hashlib.sha256(bytes(output.encode())).digest()


def get_random_value(length=DEFAULT_ID_LEN):
    """Return 1-byte random value"""
    val = bytearray()
    for i in range(length):
        val.append(random.randint(0,255))
    return bytes(val)


def convert_id_to_string(data, bytelen=DEFAULT_ID_LEN):
    """Convert binary data to hex string"""
    res = binascii.b2a_hex(data)
    if len(res) < bytelen*2:
        res += "0"*(bytelen*2-len(res)) + res
    return res.decode()


def convert_idstring_to_bytes(datastr, bytelen=DEFAULT_ID_LEN):
    """Convert hex string to binary data"""
    res = bytearray(binascii.a2b_hex(datastr))
    if len(res) < bytelen:
        res = bytearray([0]*(bytelen-len(res)))+res
    return bytes(res)


def deep_copy_with_key_stringify(u, d=None):
    """Utility for updating nested dictionary"""
    if d is None:
        d = dict()
    for k, v in u.items():
        if isinstance(k, bytes):
            k_str = k.decode()
        else:
            k_str = k
        # this condition handles the problem
        if not isinstance(d, Mapping):
            d = u
        elif isinstance(v, Mapping):
            r = deep_copy_with_key_stringify(v, d.get(k, {}))
            d[k_str] = r
        else:
            d[k_str] = u[k]
    return d


def make_transaction(event_num=0, relation_num=0, witness=False, id_length=DEFAULT_ID_LEN):
    """Utility to make transaction object

    Args:
        event_num (int): the number of BBcEvent object to include in the transaction
        relation_num (int): the number of BBcRelation object to include in the transaction
        witness (bool): If true, BBcWitness object is included in the transaction
        id_length (int): If <32, IDs will be truncated
    Returns:
        BBcTransaction:
    """
    transaction = BBcTransaction(id_length=id_length)
    if event_num > 0:
        for i in range(event_num):
            evt = BBcEvent(id_length=id_length)
            ast = BBcAsset(id_length=id_length)
            evt.add(asset=ast)
            transaction.add(event=evt)
    if relation_num > 0:
        for i in range(relation_num):
            transaction.add(relation=BBcRelation(id_length=id_length))
    if witness:
        transaction.add(witness=BBcWitness(id_length=id_length))
    return transaction


def add_relation_asset(transaction, relation_idx, asset_group_id, user_id, asset_body=None, asset_file=None):
    """Utility to add BBcRelation object with BBcAsset in the transaction"""
    ast = BBcAsset(user_id=user_id, asset_file=asset_file, asset_body=asset_body, id_length=transaction.id_length)
    transaction.relations[relation_idx].add(asset_group_id=asset_group_id, asset=ast)


def add_relation_pointer(transaction, relation_idx, ref_transaction_id=None, ref_asset_id=None):
    """Utility to add BBcRelation object with BBcPointer in the transaction"""
    pointer = BBcPointer(transaction_id=ref_transaction_id, asset_id=ref_asset_id, id_length=transaction.id_length)
    transaction.relations[relation_idx].add(pointer=pointer)


def add_reference_to_transaction(transaction, asset_group_id, ref_transaction_obj, event_index_in_ref):
    """Utility to add BBcReference object in the transaction

    Returns:
        BBcReference:
    """
    ref = BBcReference(asset_group_id=asset_group_id, transaction=transaction,
                       ref_transaction=ref_transaction_obj, event_index_in_ref=event_index_in_ref, id_length=transaction.id_length)
    if ref.transaction_id is None:
        return None
    transaction.add(reference=ref)
    return ref


def add_event_asset(transaction, event_idx, asset_group_id, user_id, asset_body=None, asset_file=None):
    """Utility to add BBcEvent object with BBcAsset in the transaction"""
    ast = BBcAsset(user_id=user_id, asset_file=asset_file, asset_body=asset_body, id_length=transaction.id_length)
    transaction.events[event_idx].add(asset_group_id=asset_group_id, asset=ast)


def make_relation_with_asset(asset_group_id, user_id, asset_body=None, asset_file=None, id_length=DEFAULT_ID_LEN):
    """Utility to make BBcRelation object"""
    relation = BBcRelation(id_length=id_length)
    ast = BBcAsset(user_id=user_id, asset_file=asset_file, asset_body=asset_body, id_length=id_length)
    relation.add(asset_group_id=asset_group_id, asset=ast)
    return relation


def add_pointer_in_relation(relation, ref_transaction_id=None, ref_asset_id=None):
    """Utility to add BBcRelation object with BBcPointer in the BBcRelation object"""
    pointer = BBcPointer(transaction_id=ref_transaction_id, asset_id=ref_asset_id, id_length=relation.id_length)
    relation.add(pointer=pointer)


def recover_signature_object(data):
    """Unpack signature data"""
    sig = BBcSignature()
    sig.unpack(data)
    return sig


def to_bigint(val, size=32):
    dat = bytearray(to_2byte(size))
    dat.extend(val)
    return dat


def to_8byte(val):
    return val.to_bytes(8, 'little')


def to_4byte(val):
    return val.to_bytes(4, 'little')


def to_2byte(val):
    return val.to_bytes(2, 'little')


def to_1byte(val):
    return val.to_bytes(1, 'little')


def get_n_bytes(ptr, n, dat):
    return ptr+n, dat[ptr:ptr+n]


def get_n_byte_int(ptr, n, dat):
    return ptr+n, int.from_bytes(dat[ptr:ptr+n], 'little')


def get_bigint(ptr, dat):
    size = int.from_bytes(dat[ptr:ptr+2], 'little')
    return ptr+2+size, dat[ptr+2:ptr+2+size]


def bin2str_base64(dat):
    import binascii
    return binascii.b2a_base64(dat, newline=False).decode("utf-8")


def bin2str_base64(dat):
    import binascii
    return binascii.b2a_base64(dat, newline=False).decode("utf-8")


def validate_transaction_object(txobj, asset_files=None):
    """Validate transaction and its asset

    Args:
        txobj (BBcTransaction): target transaction object
        asset_files (dict): dictionary containing the asset file contents
    Returns:
        bool: True if valid
        tuple: list of valid assets
        tuple: list of invalid assets
    """
    digest = txobj.digest()
    for i, sig in enumerate(txobj.signatures):
        try:
            if not sig.verify(digest):
                return False, (), ()
        except:
            return False, (), ()

    if asset_files is None:
        return True, (), ()

    # -- if asset_files is given, check them.
    valid_asset = list()
    invalid_asset = list()
    for idx, evt in enumerate(txobj.events):
        if evt.asset is None:
            continue
        asid = evt.asset.asset_id
        asset_group_id = evt.asset_group_id
        if asid in asset_files:
            if asset_files[asid] is None:
                continue
            if evt.asset.asset_file_digest != hashlib.sha256(bytes(asset_files[asid])).digest():
                invalid_asset.append((asset_group_id, asid))
            else:
                valid_asset.append((asset_group_id, asid))
    for idx, rtn in enumerate(txobj.relations):
        if rtn.asset is None:
            continue
        asid = rtn.asset.asset_id
        asset_group_id = rtn.asset_group_id
        if asid in asset_files:
            if asset_files[asid] is None:
                continue
            if rtn.asset.asset_file_digest != hashlib.sha256(bytes(asset_files[asid])).digest():
                invalid_asset.append((asset_group_id, asid))
            else:
                valid_asset.append((asset_group_id, asid))
    return True, valid_asset, invalid_asset


def verify_using_cross_ref(domain_id, transaction_id, transaction_base_digest, cross_ref_data, sigdata):
    """Confirm the existence of the transaction using cross_ref

    Args:
        domain_id (bytes): target domain_id
        transaction_id (bytes): target transaction_id of which existence you want to confirm
        transaction_base_digest (bytes): digest obtained from the outer domain
        cross_ref_data (bytes): packed BBcCrossRef object
        sigdata (bytes): packed signature
    Returns:
        bool: True if valid
    """
    cross = BBcCrossRef(unpack=cross_ref_data)
    if cross.domain_id != domain_id or cross.transaction_id != transaction_id:
        return False
    dat = bytearray(transaction_base_digest)
    dat.extend(to_2byte(1))
    dat.extend(to_4byte(len(cross_ref_data)))
    dat.extend(cross.pack())
    digest = hashlib.sha256(bytes(dat)).digest()
    sig = BBcSignature(unpack=sigdata)
    return sig.verify(digest) == 1
