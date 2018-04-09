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


def str_binary(dat):
    if dat is None:
        return "None"
    else:
        return binascii.b2a_hex(dat)


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


def validate_transaction_object(txobj, asset_files=None):
    txid = txobj.transaction_id
    for i, sig in enumerate(txobj.signatures):
        try:
            if not sig.verify(txid):
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
        if asid in asset_files.keys():
            if evt.asset.asset_file_digest != hashlib.sha256(asset_files[asid]).digest():
                invalid_asset.append(asid)
            else:
                valid_asset.append(asid)
    for idx, rtn in enumerate(txobj.relations):
        if rtn.asset is None:
            continue
        asid = rtn.asset.asset_id
        if asid in asset_files.keys():
            if rtn.asset.asset_file_digest != hashlib.sha256(asset_files[asid]).digest():
                invalid_asset.append(asid)
            else:
                valid_asset.append(asid)
    return True, valid_asset, invalid_asset


def verify_using_cross_ref(domain_id, transaction_id, transaction_base_digest, cross_ref_data, sigdata):
    cross = BBcCrossRef(deserialize=cross_ref_data)
    if cross.domain_id != domain_id or cross.transaction_id != transaction_id:
        return False
    sig = BBcSignature(deserialize=sigdata)
    dat = bytearray(transaction_base_digest)
    dat.extend(to_2byte(1))
    dat.extend(to_4byte(len(cross_ref_data)))
    dat.extend(cross_ref_data)
    digest = hashlib.sha256(bytes(dat)).digest()
    return sig.verify(digest) == 1


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
    def __init__(self, key_type=KeyType.ECDSA_SECP256k1, deserialize=None):
        self.type = key_type
        self.signature = None
        self.pubkey = None
        self.keypair = None
        if deserialize is not None:
            self.deserialize(deserialize)

    def add(self, signature=None, pubkey=None):
        if signature is not None:
            self.signature = signature
        if pubkey is not None:
            self.pubkey = pubkey
            self.keypair = KeyPair(type=self.type, pubkey=pubkey)
        return True

    def __str__(self):
        ret =  "  type: %d\n" % self.type
        ret += "  signature: %s\n" % binascii.b2a_hex(self.signature)
        ret += "  pubkey: %s\n" % binascii.b2a_hex(self.pubkey)
        return ret

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
        """
        Verify digest using pubkey in signature
        :param digest:
        :return: 0:invalid, 1:valid
        """
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
    def __init__(self, version=0, deserialize=None, jsonload=None):
        self.version = version
        self.timestamp = int(time.time())
        self.events = []
        self.references = []
        self.relations = []
        self.witness = None
        self.cross_ref = None
        self.signatures = []
        self.userid_sigidx_mapping = dict()
        self.transaction_id = None
        self.transaction_base_digest = None
        self.transaction_data = None
        if deserialize is not None:
            self.deserialize(deserialize)
        if jsonload is not None:
            self.jsonload(jsonload)

    def __str__(self):
        ret =  "------- Dump of the transaction data ------\n"
        ret += "* transaction_id: %s\n" % str_binary(self.transaction_id)
        ret += "version: %d\n" % self.version
        ret += "timestamp: %d\n" % self.timestamp
        ret += "Event[]: %d\n" % len(self.events)
        for i, evt in enumerate(self.events):
            ret += " [%d]\n" % i
            ret += str(evt)
        ret += "Reference[]: %d\n" % len(self.references)
        for i, refe in enumerate(self.references):
            ret += " [%d]\n" % i
            ret += str(refe)
        ret += "Relation[]: %d\n" % len(self.relations)
        for i, rtn in enumerate(self.relations):
            ret += " [%d]\n" % i
            ret += str(rtn)
        ret += str(self.witness)
        ret += str(self.cross_ref)
        ret += "Signature[]: %d\n" % len(self.signatures)
        for i, sig in enumerate(self.signatures):
            ret += " [%d]\n" % i
            ret += str(sig)
        return ret

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
            self.cross_ref = cross_ref
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
        self.transaction_base_digest = hashlib.sha256(dat).digest()

        dat_cross = bytearray()
        if self.cross_ref is not None:
            cross = self.cross_ref.serialize()
            dat_cross.extend(to_2byte(1))
            dat_cross.extend(to_4byte(len(cross)))
            dat_cross.extend(cross)
        else:
            dat_cross.extend(to_2byte(0))

        if for_id:
            dat2 = bytearray(self.transaction_base_digest)
            dat2.extend(dat_cross)
            return bytes(dat2)

        dat.extend(dat_cross)

        if None in self.signatures:
            dat.extend(to_2byte(0))
        else:
            dat.extend(to_2byte(len(self.signatures)))
            for signature in self.signatures:
                sig = signature.serialize()
                dat.extend(to_4byte(len(sig)))
                dat.extend(sig)
        self.transaction_data = bytes(dat)
        return self.transaction_data

    def deserialize(self, data):
        self.transaction_data = data[:]
        ptr = 0
        data_size = len(data)
        try:
            ptr, self.version = get_n_byte_int(ptr, 4, data)
            ptr, self.timestamp = get_n_byte_int(ptr, 8, data)
            ptr, evt_num = get_n_byte_int(ptr, 2, data)
            self.events = []
            for i in range(evt_num):
                ptr, size = get_n_byte_int(ptr, 4, data)
                ptr, evtdata = get_n_bytes(ptr, size, data)
                evt = BBcEvent()
                if not evt.deserialize(evtdata):
                    return False
                self.events.append(evt)
                if ptr >= data_size:
                    return False

            ptr, ref_num = get_n_byte_int(ptr, 2, data)
            self.references = []
            for i in range(ref_num):
                ptr, size = get_n_byte_int(ptr, 4, data)
                ptr, refdata = get_n_bytes(ptr, size, data)
                refe = BBcReference(None, None)
                if not refe.deserialize(refdata):
                    return False
                self.references.append(refe)
                if ptr >= data_size:
                    return False

            ptr, rtn_num = get_n_byte_int(ptr, 2, data)
            self.relations = []
            for i in range(rtn_num):
                ptr, size = get_n_byte_int(ptr, 4, data)
                ptr, rtndata = get_n_bytes(ptr, size, data)
                rtn = BBcRelation()
                if not rtn.deserialize(rtndata):
                    return False
                self.relations.append(rtn)
                if ptr >= data_size:
                    return False

            ptr, witness_num = get_n_byte_int(ptr, 2, data)
            if witness_num == 0:
                self.witness = None
            else:
                ptr, size = get_n_byte_int(ptr, 4, data)
                ptr, witnessdata = get_n_bytes(ptr, size, data)
                self.witness = BBcWitness()
                if not self.witness.deserialize(witnessdata):
                    return False
                self.witness.transaction = self

            ptr, cross_num = get_n_byte_int(ptr, 2, data)
            if cross_num == 0:
                self.cross_ref = None
            else:
                ptr, size = get_n_byte_int(ptr, 4, data)
                ptr, crossdata = get_n_bytes(ptr, size, data)
                self.cross_ref = BBcCrossRef()
                if not self.cross_ref.deserialize(crossdata):
                    return False

            ptr, sig_num = get_n_byte_int(ptr, 2, data)
            self.signatures = []
            for i in range(sig_num):
                ptr, size = get_n_byte_int(ptr, 4, data)
                ptr, sigdata = get_n_bytes(ptr, size, data)
                sig = BBcSignature()
                if not sig.deserialize(sigdata):
                    return False
                self.signatures.append(sig)
                if ptr > data_size:
                    return False
            self.digest()
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

    def jsondump(self):
        jsontx = {}
        if self.transaction_id is not None:
            jsontx["transaction_id"] = bin2str_base64(self.transaction_id)
        else:
            jsontx["transaction_id"] = None
        jsontx["version"] = self.version
        jsontx["timestamp"] = self.timestamp
        jsontx["Event"] = []
        if len(self.events) > 0:
            for i, evt in enumerate(self.events):
                event = {}
                event["asset_group_id"] =  bin2str_base64(evt.asset_group_id)
                event["reference_indices"] = evt.reference_indices
                event["mandatory_approvers"] = []
                if len(evt.mandatory_approvers) > 0:
                    for user in evt.mandatory_approvers:
                        event["mandatory_approvers"].append(bin2str_base64(user))
                event["option_approvers"] = []
                if len(evt.option_approvers) > 0:
                    for user in evt.option_approvers:
                        event["option_approvers"].append(bin2str_base64(user))
                event["option_approver_num_numerator"] = evt.option_approver_num_numerator
                event["option_approver_num_denominator"] = evt.option_approver_num_denominator
                event["Asset"] = {}
                event["Asset"]["asset_id"] = bin2str_base64(evt.asset.asset_id)
                if evt.asset.user_id is not None:
                    event["Asset"]["user_id"] = bin2str_base64(evt.asset.user_id)
                else:
                    event["Asset"]["user_id"] = None
                event["Asset"]["nonce"] = bin2str_base64(evt.asset.nonce)
                event["Asset"]["file_size"] = evt.asset.asset_file_size
                if evt.asset.asset_file_digest is not None:
                    event["Asset"]["file_digest"] = bin2str_base64(evt.asset.asset_file_digest)
                event["Asset"]["body_size"] = evt.asset.asset_body_size
                event["Asset"]["body"] = evt.asset.asset_body.decode("utf-8")
                jsontx["Event"].append(event)
        jsontx["Reference"] = []
        if len(self.references) > 0:
            for i, refe in enumerate(self.references):
                reference = {}
                if refe.asset_group_id is not None and refe.transaction_id is not None:
                    reference["asset_group_id"] = bin2str_base64(refe.asset_group_id)
                    reference["transaction_id"] = bin2str_base64(refe.transaction_id)
                    reference["event_index_in_ref"] = refe.event_index_in_ref
                    reference["sig_index"] = refe.sig_indices
                jsontx["Reference"].append(reference)
        jsontx["Relation"] = []
        if len(self.relations) > 0:
            for i, rtn in enumerate(self.relations):
                relation = {}
                relation["asset_group_id"] = bin2str_base64(rtn.asset_group_id)
                relation["Pointers"] = []
                if len(rtn.pointers) > 0:
                    for pt in rtn.pointers:
                        pointer = {}
                        if pt.transaction_id is not None:
                            pointer["transaction_id"] = bin2str_base64(pt.transaction_id)
                        else:
                            pointer["transaction_id"] = None
                        if pt.asset_id is not None:
                            pointer["asset_id"] = bin2str_base64(pt.asset_id)
                        else:
                            pointer["asset_id"] = None
                    relation["Pointers"].append(pointer)
                relation["Asset"] = {}
                if rtn.asset is not None:
                    relation["Asset"]["asset_id"] = bin2str_base64(rtn.asset.asset_id)
                    if rtn.asset.user_id is not None:
                        relation["Asset"]["user_id"] = bin2str_base64(rtn.asset.user_id)
                    else:
                        relation["Asset"]["user_id"] = None
                    relation["Asset"]["nonce"] = bin2str_base64(rtn.asset.nonce)
                    relation["Asset"]["file_size"] = rtn.asset.asset_file_size
                    if rtn.asset.asset_file_digest is not None:
                        relation["Asset"]["file_digest"] = bin2str_base64(rtn.asset.asset_file_digest)
                    relation["Asset"]["body_size"] = rtn.asset.asset_body_size
                    relation["Asset"]["body"] = rtn.asset.asset_body.decode("utf-8")
                jsontx["Relation"].append(relation)
        jsontx["Witness"] = []
        if self.witness is not None:
            for i in range(len(self.witness.sig_indices)):
                witt = {}
                if self.witness.user_ids[i] is not None:
                    witt["user_id"] = bin2str_base64(self.witness.user_ids[i])
                    witt["sig_index"] = self.witness.sig_indices[i]
                jsontx["Witness"].append(witt)
        jsontx["Cross_Ref"] = []
        if self.cross_ref is not None:
            xref = {}
            xref["domain_id"] = bin2str_base64(self.cross_ref.domain_id)
            xref["transaction_id"] = bin2str_base64(self.cross_ref.transaction_id)
            jsontx["Cross_Ref"].append(xref)
        jsontx["Signature"] = []
        if len(self.signatures) > 0:
            for i, sig in enumerate(self.signatures):
                signature = {}
                if sig is None:
                    signature = "*RESERVED*"
                    continue
                signature["type"] = sig.type
                signature["signature"] = bin2str_base64(sig.signature)
                signature["pubkey"] = bin2str_base64(sig.pubkey)
                jsontx["Signature"].append(signature)
        import json
        return json.dumps(jsontx)

    def jsonload(self, jsontx):
        import json
        jsontx = json.loads(jsontx)
        import binascii
        if jsontx["transaction_id"] is not None:
            self.transaction_id = binascii.a2b_base64(jsontx["transaction_id"])
        else:
            self.transaction_id = None
        self.version = jsontx["version"]
        self.timestamp = jsontx["timestamp"]
        if len(jsontx["Event"]) > 0:
            for i, event in enumerate(jsontx["Event"]):
                evt = BBcEvent()
                evt.asset_group_id =  binascii.a2b_base64(event["asset_group_id"])
                evt.reference_indices = event["reference_indices"]
                if len(event["mandatory_approvers"]) > 0:
                    for user in event["mandatory_approvers"]:
                        evt.mandatory_approvers.append(binascii.a2b_base64(user))
                if len(event["option_approvers"]) > 0:
                    for user in event["option_approvers"]:
                        evt.option_approvers.append(binascii.a2b_base64(user))
                evt.option_approver_num_numerator = event["option_approver_num_numerator"]
                evt.option_approver_num_denominator = event["option_approver_num_denominator"]
                evt.asset = BBcAsset()
                evt.asset.asset_id = binascii.a2b_base64(event["Asset"]["asset_id"])
                if event["Asset"]["user_id"] is not None:
                    evt.asset.user_id = binascii.a2b_base64(event["Asset"]["user_id"])
                else:
                    evt.asset.user_id = None
                evt.asset.nonce = binascii.a2b_base64(event["Asset"]["nonce"])
                evt.asset.asset_file_size = event["Asset"]["file_size"]
                if "file_digest" in event["Asset"].keys():
                    evt.asset.asset_file_digest = binascii.a2b_base64(event["Asset"]["file_digest"])
                evt.asset.asset_body_size = event["Asset"]["body_size"]
                evt.asset.asset_body = event["Asset"]["body"].encode("utf-8")
                self.add(event=evt)
        if len(jsontx["Reference"]) > 0:
            for i, reference in enumerate(jsontx["Reference"]):
                refe = BBcReference(None, None)
                if reference["asset_group_id"] is not None and reference["transaction_id"] is not None:
                    refe.asset_group_id = binascii.a2b_base64(reference["asset_group_id"])
                    refe.transaction_id = binascii.a2b_base64(reference["transaction_id"])
                    refe.event_index_in_ref = reference["event_index_in_ref"]
                    refe.sig_indices = reference["sig_index"]
                self.add(reference=refe)
        if len(jsontx["Relation"]) > 0:
            for i, relation in enumerate(jsontx["Relation"]):
                rtn = BBcRelation()
                rtn.asset_group_id = binascii.a2b_base64(relation["asset_group_id"])
                if len(relation["Pointers"]) > 0:
                    for pointer in relation["Pointers"]:
                        pt = BBcPointer()
                        if pointer["transaction_id"] is not None:
                            pt.transaction_id = binascii.a2b_base64(pointer["transaction_id"])
                        else:
                            pt.transaction_id = None
                        if pointer["asset_id"] is not None:
                            pt.asset_id = binascii.a2b_base64(pointer["asset_id"])
                        else:
                            pt.asset_id = None
                    rtn.pointers.append(pt)
                rtn.asset = BBcAsset()
                if relation["Asset"] is not None:
                    rtn.asset.asset_id = binascii.a2b_base64(relation["Asset"]["asset_id"])
                    if relation["Asset"]["user_id"] is not None:
                        rtn.asset.user_id = binascii.a2b_base64(relation["Asset"]["user_id"])
                    else:
                        rtn.asset.user_id = None
                    rtn.asset.nonce = binascii.a2b_base64(relation["Asset"]["nonce"])
                    rtn.asset.asset_file_size = relation["Asset"]["file_size"]
                    if "file_digest" in relation["Asset"].keys():
                        rtn.asset.asset_file_digest = binascii.a2b_base64(relation["Asset"]["file_digest"])
                    rtn.asset.asset_body_size = relation["Asset"]["body_size"]
                    rtn.asset.asset_body = relation["Asset"]["body"].encode("utf-8")
                self.add(relation=rtn)
        if jsontx["Witness"] is not None:
            witness = BBcWitness()
            for witt in jsontx["Witness"]:
                if witt["user_id"] is not None:
                    witness.user_ids.append(binascii.a2b_base64(witt["user_id"]))
                    witness.sig_indices.append(witt["sig_index"])
            self.add(witness=witness)
        if jsontx["Cross_Ref"] is not None:
            xref = jsontx["Cross_Ref"]
            cross = BBcCrossRef(domain_id=binascii.a2b_base64(xref["domain_id"]),
                                transaction_id=binascii.a2b_base64(xref["transaction_id"]))
            self.add(cross_ref=cross)
        if len(jsontx["Signature"]) > 0:
            for i, signature in enumerate(self.signatures):
                sig = BBcSignature()
                if signature is not "*RESERVED*":
                    sig.type = signature["type"]
                    sig.signature = binascii.a2b_base64(signature["signature"])
                    sig.pubkey = binascii.a2b_base64(signature["pubkey"])
                self.signatures.append(sig)
        return True


class BBcEvent:
    def __init__(self, asset_group_id=None):
        self.asset_group_id = asset_group_id
        self.reference_indices = []
        self.mandatory_approvers = []
        self.option_approver_num_numerator = 0
        self.option_approver_num_denominator = 0
        self.option_approvers = []
        self.asset = None

    def __str__(self):
        ret =  "  asset_group_id: %s\n" % str_binary(self.asset_group_id)
        ret += "  reference_indices: %s\n" % self.reference_indices
        ret += "  mandatory_approvers:\n"
        if len(self.mandatory_approvers) > 0:
            for user in self.mandatory_approvers:
                ret += "    - %s\n" % str_binary(user)
        else:
            ret += "    - None\n"
        ret += "  option_approvers:\n"
        if len(self.option_approvers) > 0:
            for user in self.option_approvers:
                ret += "    - %s\n" % str_binary(user)
        else:
            ret += "    - None\n"
        ret += "  option_approver_num_numerator: %d\n" % self.option_approver_num_numerator
        ret += "  option_approver_num_denominator: %d\n" % self.option_approver_num_denominator
        ret += str(self.asset)
        return ret

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
        data_size = len(data)
        try:
            ptr, self.asset_group_id = get_bigint(ptr, data)
            ptr, ref_num = get_n_byte_int(ptr, 2, data)
            self.reference_indices = []
            for i in range(ref_num):
                ptr, idx = get_n_byte_int(ptr, 2, data)
                self.reference_indices.append(idx)
                if ptr >= data_size:
                    return False
            ptr, appr_num = get_n_byte_int(ptr, 2, data)
            self.mandatory_approvers = []
            for i in range(appr_num):
                ptr, appr = get_bigint(ptr, data)
                self.mandatory_approvers.append(appr)
                if ptr >= data_size:
                    return False
            ptr, self.option_approver_num_numerator = get_n_byte_int(ptr, 2, data)
            ptr, self.option_approver_num_denominator = get_n_byte_int(ptr, 2, data)
            self.option_approvers = []
            for i in range(self.option_approver_num_denominator):
                ptr, appr = get_bigint(ptr, data)
                self.option_approvers.append(appr)
                if ptr >= data_size:
                    return False
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

    def __str__(self):
        ret =  "  asset_group_id: %s\n" % str_binary(self.asset_group_id)
        ret += "  transaction_id: %s\n" % str_binary(self.transaction_id)
        ret += "  event_index_in_ref: %d\n" % self.event_index_in_ref
        ret += "  sig_indices: %s\n" % self.sig_indices
        return ret

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
        data_size = len(data)
        try:
            ptr, self.asset_group_id = get_bigint(ptr, data)
            ptr, self.transaction_id = get_bigint(ptr, data)
            ptr, self.event_index_in_ref = get_n_byte_int(ptr, 2, data)
            ptr, signum = get_n_byte_int(ptr, 2, data)
            self.sig_indices = []
            for i in range(signum):
                ptr, idx = get_n_byte_int(ptr, 2, data)
                self.sig_indices.append(idx)
                if ptr > data_size:
                    return False
        except:
            return False
        return True


class BBcRelation:
    def __init__(self, asset_group_id=None):
        self.asset_group_id = asset_group_id
        self.pointers = list()
        self.asset = None

    def __str__(self):
        ret =  "  asset_group_id: %s\n" % str_binary(self.asset_group_id)
        if len(self.pointers) > 0:
            ret += "  Pointers[]: %d\n" % len(self.pointers)
            for i, pt in enumerate(self.pointers):
                ret += "   [%d]\n" % i
                ret += str(pt)
        ret += str(self.asset)
        return ret

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
        data_size = len(data)
        try:
            ptr, self.asset_group_id = get_bigint(ptr, data)
            ptr, pt_num = get_n_byte_int(ptr, 2, data)
            self.pointers = list()
            for i in range(pt_num):
                ptr, size = get_n_byte_int(ptr, 2, data)
                ptr, ptdata = get_n_bytes(ptr, size, data)
                if ptr >= data_size:
                    return False
                pt = BBcPointer()
                if not pt.deserialize(ptdata):
                    return False
                self.pointers.append(pt)
            self.asset = None
            ptr, astsize = get_n_byte_int(ptr, 4, data)
            if astsize > 0:
                self.asset = BBcAsset()
                ptr, astdata = get_n_bytes(ptr, astsize, data)
                if not self.asset.deserialize(astdata):
                    return False
        except:
            return False
        return True


class BBcPointer:
    def __init__(self, transaction_id=None, asset_id=None):
        self.transaction_id = transaction_id
        self.asset_id = asset_id

    def __str__(self):
        ret =  "     transaction_id: %s\n" % str_binary(self.transaction_id)
        ret += "     asset_id: %s\n" % str_binary(self.asset_id)
        return ret

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

    def __str__(self):
        ret = "Witness:\n"
        for i in range(len(self.sig_indices)):
            ret += " [%d]\n" % i
            if self.user_ids[i] is not None:
                ret += "  user_id: %s\n" % str_binary(self.user_ids[i])
                ret += "  sig_index: %d\n" % self.sig_indices[i]
            else:
                ret += "  None (invalid)\n"
        return ret

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
        data_size = len(data)
        try:
            ptr, signum = get_n_byte_int(ptr, 2, data)
            self.user_ids = list()
            self.sig_indices = list()
            for i in range(signum):
                ptr, uid = get_bigint(ptr, data)
                self.user_ids.append(uid)
                ptr, idx = get_n_byte_int(ptr, 2, data)
                self.sig_indices.append(idx)
                if ptr > data_size:
                    return False
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

    def __str__(self):
        ret =  "  Asset:\n"
        ret += "     asset_id: %s\n" % str_binary(self.asset_id)
        ret += "     user_id: %s\n" % str_binary(self.user_id)
        ret += "     nonce: %s\n" % str_binary(self.nonce)
        ret += "     file_size: %d\n" % self.asset_file_size
        ret += "     file_digest: %s\n" % str_binary(self.asset_file_digest)
        ret += "     body_size: %d\n" % self.asset_body_size
        ret += "     body: %s\n" % self.asset_body
        return ret

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
            else:
                self.asset_file_digest = None
            ptr, self.asset_body_size = get_n_byte_int(ptr, 2, data)
            if self.asset_body_size > 0:
                ptr, self.asset_body = get_n_bytes(ptr, self.asset_body_size, data)
        except:
            traceback.print_exc()
            return False
        return True


class BBcCrossRef:
    def __init__(self, domain_id=None, transaction_id=None, deserialize=None):
        self.domain_id = domain_id
        self.transaction_id = transaction_id
        if deserialize is not None:
            self.deserialize(deserialize)

    def __str__(self):
        ret  = "Cross_Ref:\n"
        ret += "  domain_id: %s\n" % str_binary(self.domain_id)
        ret += "  transaction_id: %s\n" % str_binary(self.transaction_id)
        return ret

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
    NOTIFY_CROSS_REF = 74

    REQUEST_SEARCH_TRANSACTION = 82
    RESPONSE_SEARCH_TRANSACTION = 83
    REQUEST_SEARCH_WITH_CONDITIONS = 86
    RESPONSE_SEARCH_WITH_CONDITIONS = 87
    REQUEST_TRAVERSE_TRANSACTIONS = 88
    RESPONSE_TRAVERSE_TRANSACTIONS = 89
    REQUEST_CROSS_REF_VERIFY = 90
    RESPONSE_CROSS_REF_VERIFY = 91
    REQUEST_CROSS_REF_LIST = 92
    RESPONSE_CROSS_REF_LIST = 93
    REQUEST_REPAIR = 94
    RESPONSE_REPAIR = 95

    REQUEST_REGISTER_HASH_IN_SUBSYS = 128
    RESPONSE_REGISTER_HASH_IN_SUBSYS = 129
    REQUEST_VERIFY_HASH_IN_SUBSYS = 130
    RESPONSE_VERIFY_HASH_IN_SUBSYS = 131
