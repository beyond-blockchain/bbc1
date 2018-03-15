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
import sys
import os
import binascii
import hashlib
import random
import socket
import time
import traceback

current_dir = os.path.abspath(os.path.dirname(__file__))
sys.path.append(os.path.join(current_dir, "../.."))
from bbc1.common.bbc_error import *

directory, filename = os.path.split(os.path.realpath(__file__))
from ctypes import *

if os.name == "nt":
    libbbcsig = CDLL("%s/libbbcsig.dll" % directory)
else:
    libbbcsig = CDLL("%s/libbbcsig.so" % directory)


domain_global_0 = binascii.a2b_hex("0000000000000000000000000000000000000000000000000000000000000000")

error_code = -1
error_text = ""


def set_error(code=-1, txt=""):
    global error_code
    global error_text
    error_code = code
    error_text = txt


def reset_error():
    global error_code
    global error_text
    error_code = ESUCCESS
    error_text = ""


def get_new_id(seed_str=None, include_timestamp=True):
    if seed_str is None:
        return get_random_id()
    if include_timestamp:
        seed_str += "%f" % time.time()
    return hashlib.sha256(bytes(seed_str.encode())).digest()


def get_random_id():
    source_str = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
    output = "".join([random.choice(source_str) for x in range(16)])
    return hashlib.sha256(bytes(output.encode())).digest()


def get_random_value(length=8):
    val = bytearray()
    for i in range(length):
        val.append(random.randint(0,255))
    return bytes(val)


def convert_id_to_string(data, bytelen=32):
    res = binascii.b2a_hex(data)
    if len(res) < bytelen*2:
        res += "0"*(bytelen*2-len(res)) + res
    return res.decode()


def convert_idstring_to_bytes(datastr, bytelen=32):
    res = bytearray(binascii.a2b_hex(datastr))
    if len(res) < bytelen:
        res = bytearray([0]*(bytelen-len(res)))+res
    return bytes(res)


def make_transaction_for_base_asset(asset_group_id=None, event_num=1, witness=False):
    transaction = BBcTransaction()
    for i in range(event_num):
        evt = BBcEvent(asset_group_id=asset_group_id)
        ast = BBcAsset()
        evt.add(asset=ast)
        transaction.add(event=evt)
    if witness:
        transaction.add(witness=BBcWitness())
    return transaction


def add_reference_to_transaction(asset_group_id, transaction, ref_transaction_obj, event_index_in_ref):
    ref = BBcReference(asset_group_id=asset_group_id,
                       transaction=transaction, ref_transaction=ref_transaction_obj, event_index_in_ref=event_index_in_ref)
    if ref.transaction_id is None:
        return None
    transaction.add(reference=ref)
    return ref


def make_transaction_with_relation(asset_group_id=None, asset=None, base_transaction=None):
    if base_transaction is None:
        base_transaction = BBcTransaction()
    rtn = BBcRelation(asset_group_id=asset_group_id)
    if asset is None:
        asset = BBcAsset()
    rtn.add(asset=asset)
    base_transaction.add(relation=rtn)
    return base_transaction


def add_relation_pointer(relation, transaction_id, asset_id):
    pointer = BBcPointer(transaction_id=transaction_id, asset_id=asset_id)
    relation.add(pointer=pointer)


def get_relation_with_asset_group_id(txobj, asset_group_id):
    ret = list()
    for r in txobj.relations:
        if r.asset_group_id == asset_group_id:
            ret.append(r)
    return ret


def get_relation_with_asset_id(txobj, asset_id):
    ret = list()
    for r in txobj.relations:
        if r.asset is not None and r.asset.asset_id == asset_id:
            ret.append(r)
    return ret


def make_transaction_with_witness(base_transaction=None):
    if base_transaction is None:
        base_transaction = BBcTransaction()
    wit = BBcWitness()
    base_transaction.add(witness=wit)
    return base_transaction


def recover_transaction_object_from_rawdata(data):
    transaction = BBcTransaction()
    transaction.deserialize(data)
    return transaction


def recover_signature_object(data):
    sig = BBcSignature()
    sig.deserialize(data)
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


def get_n_bytes(ptr, n, dat):
    return ptr+n, dat[ptr:ptr+n]


def get_n_byte_int(ptr, n, dat):
    return ptr+n, int.from_bytes(dat[ptr:ptr+n], 'little')


def get_bigint(ptr, dat):
    size = int.from_bytes(dat[ptr:ptr+2], 'little')
    return ptr+2+size, dat[ptr+2:ptr+2+size]


class KeyType:
    ECDSA_SECP256k1 = 1


class KeyPair:
    def __init__(self, type=KeyType.ECDSA_SECP256k1, privkey=None, pubkey=None):
        self.type = type
        self.private_key_len = c_int32(32)
        self.private_key = (c_byte * self.private_key_len.value)()
        self.public_key_len = c_int32(65)
        self.public_key = (c_byte * self.public_key_len.value)()
        if privkey is not None:
            memmove(self.private_key, bytes(privkey), sizeof(self.private_key))
        if pubkey is not None:
            self.public_key_len = c_int32(len(pubkey))
            memmove(self.public_key, bytes(pubkey), self.public_key_len.value)

        if privkey is None and pubkey is None:
            self.generate()

    def generate(self):
        if self.type == KeyType.ECDSA_SECP256k1:
            libbbcsig.generate_keypair(0, byref(self.public_key_len), self.public_key,
                                       byref(self.private_key_len), self.private_key)

    def mk_keyobj_from_private_key(self):
        if self.private_key is None:
            return
        if self.type != KeyType.ECDSA_SECP256k1:
            return
        libbbcsig.get_public_key_uncompressed(self.private_key_len, self.private_key,
                                              byref(self.public_key_len), self.public_key)

    def mk_keyobj_from_private_key_der(self, derdat):
        der_len = len(derdat)
        der_data = (c_byte * der_len)()
        memmove(der_data, bytes(derdat), der_len)
        libbbcsig.convert_from_der(der_len, byref(der_data), 0,
                                   byref(self.public_key_len), self.public_key,
                                   byref(self.private_key_len), self.private_key)

    def mk_keyobj_from_private_key_pem(self, pemdat_string):
        libbbcsig.convert_from_pem(create_string_buffer(pemdat_string.encode()), 0,
                                   byref(self.public_key_len), self.public_key,
                                   byref(self.private_key_len), self.private_key)

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

    def to_bigint(self, dat):
        intval = 0
        for i in range(len(dat)):
            intval += int(dat[i])*(256**i)
        return intval

    def get_private_key_in_der(self):
        der_data = (c_byte * 512)()     # 256 -> 512
        der_len = libbbcsig.output_der(self.private_key_len, self.private_key, byref(der_data))
        return bytes(bytearray(der_data)[:der_len])

    def get_private_key_in_pem(self):
        pem_data = (c_char * 512)()     # 256 -> 512
        pem_len = libbbcsig.output_pem(self.private_key_len, self.private_key, byref(pem_data))
        return pem_data.value

    def sign(self, digest):
        if self.type == KeyType.ECDSA_SECP256k1:
            sig_r = (c_byte * 32)()
            sig_s = (c_byte * 32)()
            sig_r_len = (c_byte * 4)()  # Adjust size according to the expected size of sig_r and sig_s. Default:uint32.
            sig_s_len = (c_byte * 4)()
            libbbcsig.sign(self.private_key_len, self.private_key, 32, digest, sig_r, sig_s, sig_r_len, sig_s_len)
            sig_r_len = int.from_bytes(bytes(sig_r_len), "little")
            sig_s_len = int.from_bytes(bytes(sig_s_len), "little")
            sig_r = binascii.a2b_hex("00"*(32-sig_r_len) + bytes(sig_r)[:sig_r_len].hex())
            sig_s = binascii.a2b_hex("00"*(32-sig_s_len) + bytes(sig_s)[:sig_s_len].hex())
            return bytes(bytearray(sig_r)+bytearray(sig_s))
        else:
            set_error(code=EOTHER, txt="sig_type %d is not supported" % self.type)
            return None

    def verify(self, digest, sig):
        return libbbcsig.verify(self.public_key_len, self.public_key, len(digest), digest, len(sig), sig)


class BBcSignature:
    def __init__(self, key_type=KeyType.ECDSA_SECP256k1):
        self.type = key_type
        self.signature = None
        self.pubkey = None
        self.keypair = None

    def add(self, signature=None, pubkey=None):
        if signature is not None:
            self.signature = signature
        if pubkey is not None:
            self.pubkey = pubkey
            self.keypair = KeyPair(type=self.type, pubkey=pubkey)
        return True

    def serialize(self):
        dat = bytearray(to_4byte(self.type))
        pubkey_len_bit = len(self.pubkey) * 8
        dat.extend(to_4byte(pubkey_len_bit))
        dat.extend(self.pubkey)
        sig_len_bit = len(self.signature) * 8
        dat.extend(to_4byte(sig_len_bit))
        dat.extend(self.signature)
        return bytes(dat)

    def deserialize(self, data):
        ptr = 0
        try:
            ptr, self.type = get_n_byte_int(ptr, 4, data)
            ptr, pubkey_len_bit = get_n_byte_int(ptr, 4, data)
            pubkey_len = int(pubkey_len_bit/8)
            ptr, pubkey = get_n_bytes(ptr, pubkey_len, data)
            ptr, sig_len_bit = get_n_byte_int(ptr, 4, data)
            sig_len = int(sig_len_bit/8)
            ptr, signature = get_n_bytes(ptr, sig_len, data)
            self.add(signature=signature, pubkey=pubkey)
        except:
            return False
        return True

    def verify(self, digest):
        reset_error()
        if self.keypair is None:
            set_error(code=EBADKEYPAIR, txt="Bad private_key/public_key")
            return False
        try:
            flag = self.keypair.verify(digest, self.signature)
        except:
            traceback.print_exc()
            return False
        return flag


class BBcTransaction:
    def __init__(self, version=0, deserialize=None):
        self.version = version
        self.timestamp = int(time.time())
        self.events = []
        self.references = []
        self.relations = []
        self.witness = None
        self.cross_refs = []
        self.signatures = []
        self.userid_sigidx_mapping = dict()
        self.transaction_id = None
        self.transaction_base_digest = None
        self.transaction_data = None
        if deserialize is not None:
            self.deserialize(deserialize)

    def add(self, event=None, reference=None, relation=None, witness=None, cross_ref=None):
        if event is not None:
            if isinstance(event, list):
                self.events.extend(event)
            else:
                self.events.append(event)
        if reference is not None:
            if isinstance(reference, list):
                self.references.extend(reference)
            else:
                self.references.append(reference)
        if relation is not None:
            if isinstance(relation, list):
                self.relations.extend(relation)
            else:
                self.relations.append(relation)
        if witness is not None:
            witness.transaction = self
            self.witness = witness
        if cross_ref is not None:
            if isinstance(cross_ref, list):
                self.cross_refs.extend(cross_ref)
            else:
                self.cross_refs.append(cross_ref)
        return True

    def get_sig_index(self, user_id):
        if user_id not in self.userid_sigidx_mapping:
            self.userid_sigidx_mapping[user_id] = len(self.userid_sigidx_mapping)
            self.signatures.append(None)
        return self.userid_sigidx_mapping[user_id]

    def add_signature(self, user_id=None, signature=None):
        if user_id not in self.userid_sigidx_mapping:
            return False
        idx = self.userid_sigidx_mapping[user_id]
        self.signatures[idx] = signature
        return True

    def digest(self):
        target = self.serialize(for_id=True)
        d = hashlib.sha256(target).digest()
        self.transaction_id = d
        return d

    def serialize(self, for_id=False):
        dat = bytearray(to_4byte(self.version))
        dat.extend(to_8byte(self.timestamp))
        dat.extend(to_2byte(len(self.events)))
        for i in range(len(self.events)):
            evt = self.events[i].serialize()
            dat.extend(to_4byte(len(evt)))
            dat.extend(evt)
        dat.extend(to_2byte(len(self.references)))
        for i in range(len(self.references)):
            refe = self.references[i].serialize()
            dat.extend(to_4byte(len(refe)))
            dat.extend(refe)
        dat.extend(to_2byte(len(self.relations)))
        for i in range(len(self.relations)):
            rtn = self.relations[i].serialize()
            dat.extend(to_4byte(len(rtn)))
            dat.extend(rtn)
        if self.witness is not None:
            dat.extend(to_2byte(1))
            witness = self.witness.serialize()
            dat.extend(to_4byte(len(witness)))
            dat.extend(witness)
        else:
            dat.extend(to_2byte(0))
        if for_id:
            self.transaction_base_digest = hashlib.sha256(dat).digest()

        dat_cross = bytearray(to_2byte(len(self.cross_refs)))
        for i in range(len(self.cross_refs)):
            cross = self.cross_refs[i].serialize()
            dat_cross.extend(to_4byte(len(cross)))
            dat_cross.extend(cross)

        if for_id:
            dat2 = bytearray(self.transaction_base_digest)
            dat2.extend(dat_cross)
            return bytes(dat2)

        dat.extend(dat_cross)

        real_signum = 0
        for sig in self.signatures:
            if sig is not None:
                real_signum += 1
        dat.extend(to_2byte(real_signum))
        for i in range(real_signum):
            sig = self.signatures[i].serialize()
            dat.extend(to_4byte(len(sig)))
            dat.extend(sig)
        return bytes(dat)

    def deserialize(self, data):
        ptr = 0
        try:
            ptr, self.version = get_n_byte_int(ptr, 4, data)
            ptr, self.timestamp = get_n_byte_int(ptr, 8, data)
            ptr, evt_num = get_n_byte_int(ptr, 2, data)
            self.events = []
            for i in range(evt_num):
                ptr, size = get_n_byte_int(ptr, 4, data)
                ptr, evtdata = get_n_bytes(ptr, size, data)
                evt = BBcEvent()
                evt.deserialize(evtdata)
                self.events.append(evt)

            ptr, ref_num = get_n_byte_int(ptr, 2, data)
            self.references = []
            for i in range(ref_num):
                ptr, size = get_n_byte_int(ptr, 4, data)
                ptr, refdata = get_n_bytes(ptr, size, data)
                refe = BBcReference(None, None)
                refe.deserialize(refdata)
                self.references.append(refe)

            ptr, rtn_num = get_n_byte_int(ptr, 2, data)
            self.relations = []
            for i in range(rtn_num):
                ptr, size = get_n_byte_int(ptr, 4, data)
                ptr, rtndata = get_n_bytes(ptr, size, data)
                rtn = BBcRelation()
                rtn.deserialize(rtndata)
                self.relations.append(rtn)

            ptr, witness_num = get_n_byte_int(ptr, 2, data)
            if witness_num == 0:
                self.witness = None
            else:
                ptr, size = get_n_byte_int(ptr, 4, data)
                ptr, witnessdata = get_n_bytes(ptr, size, data)
                self.witness = BBcWitness()
                self.witness.deserialize(witnessdata)
                self.witness.transaction = self

            ptr, cross_num = get_n_byte_int(ptr, 2, data)
            self.cross_refs = []
            for i in range(cross_num):
                ptr, size = get_n_byte_int(ptr, 4, data)
                ptr, crossdata = get_n_bytes(ptr, size, data)
                cross = BBcCrossRef()
                cross.deserialize(crossdata)
                self.cross_refs.append(cross)

            ptr, sig_num = get_n_byte_int(ptr, 2, data)
            self.signatures = []
            for i in range(sig_num):
                ptr, size = get_n_byte_int(ptr, 4, data)
                ptr, sigdata = get_n_bytes(ptr, size, data)
                sig = BBcSignature()
                sig.deserialize(sigdata)
                self.signatures.append(sig)
            self.digest()
            self.transaction_data = data
        except Exception as e:
            print("Transaction data deserialize: %s" % e)
            print(traceback.format_exc())
            return False
        return True

    def sign(self, key_type=KeyType.ECDSA_SECP256k1, private_key=None, public_key=None, keypair=None):
        """
        Sign transaction
        :param key_type: KeyType.ECDSA_SECP256k1
        :param private_key: bytes format
        :param public_key: bytes format
        :return: BBcSignature object
        """
        reset_error()
        if key_type != KeyType.ECDSA_SECP256k1:
            set_error(code=EBADKEYPAIR, txt="Not support other than ECDSA_SECP256k1")
            return None
        if keypair is None:
            if len(private_key) != 32 or len(public_key) <= 32:
                set_error(code=EBADKEYPAIR, txt="Bad private_key/public_key (must be in bytes format)")
                return None
            keypair = KeyPair(type=key_type, privkey=private_key, pubkey=public_key)
            if keypair is None:
                set_error(code=EBADKEYPAIR, txt="Bad private_key/public_key")
                return None

        sig = BBcSignature(key_type=keypair.type)
        s = keypair.sign(self.digest())
        if s is None:
            set_error(code=EOTHER, txt="sig_type %d is not supported" % keypair.type)
            return None
        sig.add(signature=s, pubkey=keypair.public_key)
        return sig

    def dump(self):
        import binascii
        print("------- Dump of the transaction data ------")
        if self.transaction_id is not None:
            print("transaction_id:", binascii.b2a_hex(self.transaction_id))
        else:
            print("transaction_id: None")
        print("version:", self.version)
        print("timestamp:", self.timestamp)
        print("Event[]:", len(self.events))
        if len(self.events) > 0:
            for i, evt in enumerate(self.events):
                print("[%d]" % i)
                print("  asset_group_id:", binascii.b2a_hex(evt.asset_group_id))
                print("  reference_indices:", evt.reference_indices)
                print("  mandatory_approvers:")
                if len(evt.mandatory_approvers) > 0:
                    for user in evt.mandatory_approvers:
                        print("    - ", binascii.b2a_hex(user))
                else:
                    print("    - NONE")
                print("  option_approvers:")
                if len(evt.option_approvers) > 0:
                    for user in evt.option_approvers:
                        print("    - ", binascii.b2a_hex(user))
                else:
                    print("    - NONE")
                print("  option_approver_num_numerator:", evt.option_approver_num_numerator)
                print("  option_approver_num_denominator:", evt.option_approver_num_denominator)
                print("  Asset:")
                print("     asset_id:", binascii.b2a_hex(evt.asset.asset_id))
                if evt.asset.user_id is not None:
                    print("     user_id:", binascii.b2a_hex(evt.asset.user_id))
                else:
                    print("     user_id: NONE")
                print("     nonce:", binascii.b2a_hex(evt.asset.nonce))
                print("     file_size:", evt.asset.asset_file_size)
                if evt.asset.asset_file_digest is not None:
                    print("     file_digest:", binascii.b2a_hex(evt.asset.asset_file_digest))
                print("     body_size:", evt.asset.asset_body_size)
                print("     body:", evt.asset.asset_body)
        else:
            print("  None")
        print("Reference[]:",len(self.references))
        if len(self.references) > 0:
            for i, refe in enumerate(self.references):
                if refe.asset_group_id is not None and refe.transaction_id is not None:
                    print("  asset_group_id:", binascii.b2a_hex(refe.asset_group_id))
                    print("  transaction_id:", binascii.b2a_hex(refe.transaction_id))
                    print("  event_index_in_ref:", refe.event_index_in_ref)
                    print("  sig_index:", refe.sig_indices)
                else:
                    print("  -- None (invalid)")
        else:
            print("  None")
        print("Relation[]:", len(self.relations))
        if len(self.relations) > 0:
            for i, rtn in enumerate(self.relations):
                print("[%d]" % i)
                print("  asset_group_id:", binascii.b2a_hex(rtn.asset_group_id))
                print("  Pointers[]:", len(rtn.pointers))
                if len(rtn.pointers) > 0:
                    for pt in rtn.pointers:
                        if pt.transaction_id is not None:
                            print("     transaction_id:", binascii.b2a_hex(pt.transaction_id))
                        else:
                            print("     transaction_id: NONE")
                        if pt.asset_id is not None:
                            print("     asset_id:", binascii.b2a_hex(pt.asset_id))
                        else:
                            print("     asset_id: NONE")
                else:
                    print("     NONE")
                print("  Asset:")
                if rtn.asset is not None:
                    print("     asset_id:", binascii.b2a_hex(rtn.asset.asset_id))
                    if rtn.asset.user_id is not None:
                        print("     user_id:", binascii.b2a_hex(rtn.asset.user_id))
                    else:
                        print("     user_id: NONE")
                    print("     nonce:", binascii.b2a_hex(rtn.asset.nonce))
                    print("     file_size:", rtn.asset.asset_file_size)
                    if rtn.asset.asset_file_digest is not None:
                        print("     file_digest:", binascii.b2a_hex(rtn.asset.asset_file_digest))
                    print("     body_size:", rtn.asset.asset_body_size)
                    print("     body:", rtn.asset.asset_body)
                else:
                    print("    NONE")
        else:
            print("  None")
        print("Witness:")
        if self.witness is not None:
            for i in range(len(self.witness.sig_indices)):
                print("[%d]" % i)
                if self.witness.user_ids[i] is not None:
                    print("  user_id:", binascii.b2a_hex(self.witness.user_ids[i]))
                    print("  sig_index:", self.witness.sig_indices[i])
                else:
                    print("  -- None (invalid)")
        else:
            print("  None")
        print("Cross_Ref[]:",len(self.cross_refs))
        if len(self.cross_refs) > 0:
            for i, cross in enumerate(self.cross_refs):
                print("[%d]" % i)
                if cross is not None:
                    print("  domain_id:", binascii.b2a_hex(cross.domain_id))
                    print("  transaction_id:", binascii.b2a_hex(cross.transaction_id))
                else:
                    print("  -- None (invalid)")
        else:
            print("  None")
        print("Signature[]:", len(self.signatures))
        if len(self.signatures) > 0:
            for i, sig in enumerate(self.signatures):
                print("[%d]" % i)
                if sig is None:
                    print("  *RESERVED*")
                    continue
                print("  type:", sig.type)
                print("  signature:", binascii.b2a_hex(sig.signature))
                print("  pubkey:", binascii.b2a_hex(sig.pubkey))
        else:
            print("  None")


class BBcEvent:
    def __init__(self, asset_group_id=None):
        self.asset_group_id = asset_group_id
        self.reference_indices = []
        self.mandatory_approvers = []
        self.option_approver_num_numerator = 0
        self.option_approver_num_denominator = 0
        self.option_approvers = []
        self.asset = None

    def add(self, asset_group_id=None, reference_index=None, mandatory_approver=None,
            option_approver_num_numerator=0, option_approver_num_denominator=0,
            option_approver=None, asset=None):
        if asset_group_id is not None:
            self.asset_group_id = asset_group_id
        if reference_index is not None:
            self.reference_indices.append(reference_index)
        if mandatory_approver is not None:
            self.mandatory_approvers.append(mandatory_approver)
        if option_approver_num_numerator > 0:
            self.option_approver_num_numerator = option_approver_num_numerator
        if option_approver_num_denominator > 0:
            self.option_approver_num_denominator = option_approver_num_denominator
        if option_approver is not None:
            self.option_approvers.append(option_approver)
        if asset is not None:
            self.asset = asset
        return True

    def serialize(self):
        dat = bytearray(to_bigint(self.asset_group_id))
        dat.extend(to_2byte(len(self.reference_indices)))
        for i in range(len(self.reference_indices)):
            dat.extend(to_2byte(self.reference_indices[i]))
        dat.extend(to_2byte(len(self.mandatory_approvers)))
        for i in range(len(self.mandatory_approvers)):
            dat.extend(to_bigint(self.mandatory_approvers[i]))
        dat.extend(to_2byte(self.option_approver_num_numerator))
        dat.extend(to_2byte(self.option_approver_num_denominator))
        for i in range(self.option_approver_num_denominator):
            dat.extend(to_bigint(self.option_approvers[i]))
        ast = self.asset.serialize()
        dat.extend(to_4byte(len(ast)))
        dat.extend(ast)
        return bytes(dat)

    def deserialize(self, data):
        ptr = 0
        try:
            ptr, self.asset_group_id = get_bigint(ptr, data)
            ptr, ref_num = get_n_byte_int(ptr, 2, data)
            self.reference_indices = []
            for i in range(ref_num):
                ptr, idx = get_n_byte_int(ptr, 2, data)
                self.reference_indices.append(idx)
            ptr, appr_num = get_n_byte_int(ptr, 2, data)
            self.mandatory_approvers = []
            for i in range(appr_num):
                ptr, appr = get_bigint(ptr, data)
                self.mandatory_approvers.append(appr)
            ptr, self.option_approver_num_numerator = get_n_byte_int(ptr, 2, data)
            ptr, self.option_approver_num_denominator = get_n_byte_int(ptr, 2, data)
            self.option_approvers = []
            for i in range(self.option_approver_num_denominator):
                ptr, appr = get_bigint(ptr, data)
                self.option_approvers.append(appr)
            ptr, astsize = get_n_byte_int(ptr, 4, data)
            ptr, astdata = get_n_bytes(ptr, astsize, data)
            self.asset = BBcAsset()
            self.asset.deserialize(astdata)
        except:
            return False
        return True


class BBcReference:
    def __init__(self, asset_group_id, transaction, ref_transaction=None, event_index_in_ref=0):
        self.asset_group_id = asset_group_id
        self.transaction_id = None
        self.transaction = transaction
        self.ref_transaction = ref_transaction
        self.event_index_in_ref = event_index_in_ref
        self.sig_indices = []
        self.mandatory_approvers = None
        self.option_approvers = None
        self.option_sig_ids = []
        if ref_transaction is None:
            return
        self.prepare_reference(ref_transaction=ref_transaction)

    def prepare_reference(self, ref_transaction):
        self.ref_transaction = ref_transaction
        try:
            evt = ref_transaction.events[self.event_index_in_ref]
            for user in evt.mandatory_approvers:
                self.sig_indices.append(self.transaction.get_sig_index(user))
            for i in range(evt.option_approver_num_numerator):
                dummy_id = get_random_value(4)
                self.option_sig_ids.append(dummy_id)
                self.sig_indices.append(self.transaction.get_sig_index(dummy_id))
            self.mandatory_approvers = evt.mandatory_approvers
            self.option_approvers = evt.option_approvers
            self.transaction_id = ref_transaction.digest()
        except Exception as e:
            print(traceback.format_exc())

    def add_signature(self, user_id=None, signature=None):
        if user_id in self.option_approvers:
            if len(self.option_sig_ids) == 0:
                return
            user_id = self.option_sig_ids.pop(0)
        self.transaction.add_signature(user_id=user_id, signature=signature)

    def get_referred_transaction(self):
        return {self.ref_transaction.transaction_id: self.ref_transaction.serialize()}

    def get_destinations(self):
        return self.mandatory_approvers+self.option_approvers

    def serialize(self):
        dat = bytearray(to_bigint(self.asset_group_id))
        dat.extend(to_bigint(self.transaction_id))
        dat.extend(to_2byte(self.event_index_in_ref))
        dat.extend(to_2byte(len(self.sig_indices)))
        for i in range(len(self.sig_indices)):
            dat.extend(to_2byte(self.sig_indices[i]))
        return bytes(dat)

    def deserialize(self, data):
        ptr = 0
        try:
            ptr, self.asset_group_id = get_bigint(ptr, data)
            ptr, self.transaction_id = get_bigint(ptr, data)
            ptr, self.event_index_in_ref = get_n_byte_int(ptr, 2, data)
            ptr, signum = get_n_byte_int(ptr, 2, data)
            self.sig_indices = []
            for i in range(signum):
                ptr, idx = get_n_byte_int(ptr, 2, data)
                self.sig_indices.append(idx)
        except:
            return False
        return True


class BBcRelation:
    def __init__(self, asset_group_id=None):
        self.asset_group_id = asset_group_id
        self.pointers = list()
        self.asset = None

    def add(self, asset_group_id=None, asset=None, pointer=None):
        if asset_group_id is not None:
            self.asset_group_id = asset_group_id
        if pointer is not None:
            if isinstance(pointer, list):
                self.pointers.extend(pointer)
            else:
                self.pointers.append(pointer)
        if asset is not None:
            self.asset = asset
        return True

    def serialize(self):
        dat = bytearray(to_bigint(self.asset_group_id))
        dat.extend(to_2byte(len(self.pointers)))
        for i in range(len(self.pointers)):
            pt = self.pointers[i].serialize()
            dat.extend(to_2byte(len(pt)))
            dat.extend(pt)
        if self.asset is not None:
            ast = self.asset.serialize()
            dat.extend(to_4byte(len(ast)))
            dat.extend(ast)
        else:
            dat.extend(to_4byte(0))
        return bytes(dat)

    def deserialize(self, data):
        ptr = 0
        try:
            ptr, self.asset_group_id = get_bigint(ptr, data)
            ptr, pt_num = get_n_byte_int(ptr, 2, data)
            self.pointers = list()
            for i in range(pt_num):
                ptr, size = get_n_byte_int(ptr, 2, data)
                ptr, ptdata = get_n_bytes(ptr, size, data)
                pt = BBcPointer()
                pt.deserialize(ptdata)
                self.pointers.append(pt)
            self.asset = None
            ptr, astsize = get_n_byte_int(ptr, 4, data)
            if astsize > 0:
                self.asset = BBcAsset()
                ptr, astdata = get_n_bytes(ptr, astsize, data)
                self.asset.deserialize(astdata)
        except:
            return False
        return True


class BBcPointer:
    def __init__(self, transaction_id=None, asset_id=None):
        self.transaction_id = transaction_id
        self.asset_id = asset_id

    def add(self, transaction_id=None, asset_id=None):
        if transaction_id is not None:
            self.transaction_id = transaction_id
        if asset_id is not None:
            self.asset_id = asset_id

    def serialize(self):
        dat = bytearray(to_bigint(self.transaction_id))
        if self.asset_id is None:
            dat.extend(to_2byte(0))
        else:
            dat.extend(to_2byte(1))
            dat.extend(to_bigint(self.asset_id))
        return bytes(dat)

    def deserialize(self, data):
        ptr = 0
        try:
            ptr, self.transaction_id = get_bigint(ptr, data)
            ptr, num = get_n_byte_int(ptr, 2, data)
            if num == 1:
                ptr, self.asset_id = get_bigint(ptr, data)
            else:
                self.asset_id = None
        except:
            return False
        return True


class BBcWitness:
    def __init__(self):
        self.transaction = None
        self.user_ids = list()
        self.sig_indices = list()

    def add_witness(self, user_id):
        self.user_ids.append(user_id)
        self.sig_indices.append(self.transaction.get_sig_index(user_id))

    def add_signature(self, user_id=None, signature=None):
        self.transaction.add_signature(user_id=user_id, signature=signature)

    def serialize(self):
        dat = bytearray(to_2byte(len(self.sig_indices)))
        for i in range(len(self.sig_indices)):
            dat.extend(to_bigint(self.user_ids[i]))
            dat.extend(to_2byte(self.sig_indices[i]))
        return bytes(dat)

    def deserialize(self, data):
        ptr = 0
        try:
            ptr, signum = get_n_byte_int(ptr, 2, data)
            self.user_ids = list()
            self.sig_indices = list()
            for i in range(signum):
                ptr, uid = get_bigint(ptr, data)
                self.user_ids.append(uid)
                ptr, idx = get_n_byte_int(ptr, 2, data)
                self.sig_indices.append(idx)
        except:
            return False
        return True


class BBcAsset:
    def __init__(self):
        self.asset_id = None
        self.user_id = None
        self.nonce = get_random_value()
        self.asset_file_size = 0
        self.asset_file = None
        self.asset_file_digest = None
        self.asset_body_size = 0
        self.asset_body = []

    def add(self, user_id=None, asset_file=None, asset_body=None):
        if user_id is not None:
            self.user_id = user_id
        if asset_file is not None:
            self.asset_file = asset_file
            self.asset_file_size = len(asset_file)
            self.asset_file_digest = hashlib.sha256(asset_file).digest()
        if asset_body is not None:
            self.asset_body = asset_body
            if isinstance(asset_body, str):
                self.asset_body = asset_body.encode()
            self.asset_body_size = len(asset_body)
        self.digest()

    def digest(self):
        target = self.serialize(for_digest_calculation=True)
        self.asset_id = hashlib.sha256(target).digest()
        return self.asset_id

    def get_asset_file(self):
        if self.asset_file is None:
            return None, None
        return self.asset_file_digest, self.asset_file

    def recover_asset_file(self, asset_file):
        digest = hashlib.sha256(asset_file).digest()
        if digest == self.asset_file_digest:
            self.asset_file = asset_file
            return True
        else:
            return False

    def serialize(self, for_digest_calculation=False):
        if for_digest_calculation:
            dat = bytearray(to_bigint(self.user_id))
            dat.extend(to_2byte(len(self.nonce)))
            dat.extend(self.nonce)
            dat.extend(to_4byte(self.asset_file_size))
            if self.asset_file_size > 0:
                dat.extend(self.asset_file_digest)
            dat.extend(to_2byte(self.asset_body_size))
            if self.asset_body_size > 0:
                dat.extend(self.asset_body)
            return bytes(dat)
        else:
            dat = bytearray(to_bigint(self.asset_id))
            dat.extend(to_bigint(self.user_id))
            dat.extend(to_2byte(len(self.nonce)))
            dat.extend(self.nonce)
            dat.extend(to_4byte(self.asset_file_size))
            if self.asset_file_size > 0:
                dat.extend(to_bigint(self.asset_file_digest))
            dat.extend(to_2byte(self.asset_body_size))
            if self.asset_body_size > 0:
                dat.extend(self.asset_body)
            return bytes(dat)

    def deserialize(self, data):
        ptr = 0
        try:
            ptr, self.asset_id = get_bigint(ptr, data)
            ptr, self.user_id = get_bigint(ptr, data)
            ptr, noncelen = get_n_byte_int(ptr, 2, data)
            ptr, self.nonce = get_n_bytes(ptr, noncelen, data)
            ptr, self.asset_file_size = get_n_byte_int(ptr, 4, data)
            if self.asset_file_size > 0:
                ptr, self.asset_file_digest = get_bigint(ptr, data)
            ptr, self.asset_body_size = get_n_byte_int(ptr, 2, data)
            if self.asset_body_size > 0:
                ptr, self.asset_body = get_n_bytes(ptr, self.asset_body_size, data)
        except:
            traceback.print_exc()
            return False
        return True


class BBcCrossRef:
    def __init__(self, domain_id=None, transaction_id=None):
        self.domain_id = domain_id
        self.transaction_id = transaction_id

    def serialize(self):
        dat = bytearray(to_bigint(self.domain_id))
        dat.extend(to_bigint(self.transaction_id))
        return bytes(dat)

    def deserialize(self, data):
        ptr = 0
        try:
            ptr, self.domain_id = get_bigint(ptr, data)
            ptr, self.transaction_id = get_bigint(ptr, data)
        except:
            return False
        return True


class MsgType:
    REQUEST_SETUP_DOMAIN = 0
    RESPONSE_SETUP_DOMAIN = 1
    REQUEST_GET_PEERLIST = 2        # TODO: will obsolete in v0.10
    RESPONSE_GET_PEERLIST = 3       # TODO: will obsolete in v0.10
    REQUEST_SET_STATIC_NODE = 4
    RESPONSE_SET_STATIC_NODE = 5
    REQUEST_GET_CONFIG = 8
    RESPONSE_GET_CONFIG = 9
    REQUEST_MANIP_LEDGER_SUBSYS = 10
    RESPONSE_MANIP_LEDGER_SUBSYS = 11
    DOMAIN_PING = 12
    REQUEST_GET_DOMAINLIST = 13
    RESPONSE_GET_DOMAINLIST = 14
    REQUEST_INSERT_NOTIFICATION = 15
    CANCEL_INSERT_NOTIFICATION = 16
    REQUEST_GET_STATS = 17
    RESPONSE_GET_STATS = 18
    REQUEST_GET_NEIGHBORLIST = 21
    RESPONSE_GET_NEIGHBORLIST = 22
    REQUEST_GET_USERS = 23
    RESPONSE_GET_USERS = 24
    REQUEST_GET_FORWARDING_LIST = 25
    RESPONSE_GET_FORWARDING_LIST = 26
    REQUEST_GET_NODEID = 27
    RESPONSE_GET_NODEID = 28
    REQUEST_GET_NOTIFICATION_LIST = 29
    RESPONSE_GET_NOTIFICATION_LIST = 30
    REQUEST_CLOSE_DOMAIN = 31
    RESPONSE_CLOSE_DOMAIN = 32
    REQUEST_ECDH_KEY_EXCHANGE = 33
    RESPONSE_ECDH_KEY_EXCHANGE = 34

    REGISTER = 64
    UNREGISTER = 65
    MESSAGE = 66

    REQUEST_GATHER_SIGNATURE = 67
    RESPONSE_GATHER_SIGNATURE = 68
    REQUEST_SIGNATURE = 69
    RESPONSE_SIGNATURE = 70
    REQUEST_INSERT = 71
    RESPONSE_INSERT = 72
    NOTIFY_INSERTED = 73

    REQUEST_SEARCH_ASSET = 80
    RESPONSE_SEARCH_ASSET = 81
    REQUEST_SEARCH_TRANSACTION = 82
    RESPONSE_SEARCH_TRANSACTION = 83
    REQUEST_SEARCH_USERID = 84
    RESPONSE_SEARCH_USERID = 85
    REQUEST_SEARCH_WITH_CONDITIONS = 86
    RESPONSE_SEARCH_WITH_CONDITIONS = 87
    REQUEST_CROSS_REF = 88
    RESPONSE_CROSS_REF = 89

    REQUEST_REGISTER_HASH_IN_SUBSYS = 128
    RESPONSE_REGISTER_HASH_IN_SUBSYS = 129
    REQUEST_VERIFY_HASH_IN_SUBSYS = 130
    RESPONSE_VERIFY_HASH_IN_SUBSYS = 131


class StorageType:  # TODO: will be obsoleted in v0.10
    NONE = 0
    FILESYSTEM = 1
    #HTTP_PUT = 2
    #HTTP_POST = 3

