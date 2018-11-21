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
import platform
import binascii
import hashlib
import msgpack
import bson
import bz2
import zlib
import random
import time
import traceback
from collections import Mapping

current_dir = os.path.abspath(os.path.dirname(__file__))
sys.path.append(os.path.join(current_dir, "../.."))
import bbc1.core.bbc_error as bbc_error

directory, filename = os.path.split(os.path.realpath(__file__))
from ctypes import *

if platform.system() == "Windows":
    libbbcsig = windll.LoadLibrary(os.path.join(directory, "../libs/", "libbbcsig.dll"))
elif platform.system() == "Darwin":
    libbbcsig = cdll.LoadLibrary(os.path.join(directory, "../libs/", "libbbcsig.dylib"))
else:
    libbbcsig = cdll.LoadLibrary(os.path.join(directory, "../libs/", "libbbcsig.so"))


domain_global_0 = binascii.a2b_hex("0000000000000000000000000000000000000000000000000000000000000000")

error_code = -1
error_text = ""

DEFAULT_ID_LEN = 32


class BBcFormat:
    FORMAT_BINARY = 0
    FORMAT_BSON = 1
    FORMAT_BSON_COMPRESS_BZ2 = 2
    FORMAT_BSON_COMPRESS_ZLIB = 3
    FORMAT_MSGPACK = 4
    FORMAT_MSGPACK_COMPRESS_BZ2 = 5
    FORMAT_MSGPACK_COMPRESS_ZLIB = 6


def set_error(code=-1, txt=""):
    global error_code
    global error_text
    error_code = code
    error_text = txt


def reset_error():
    global error_code
    global error_text
    error_code = bbc_error.ESUCCESS
    error_text = ""


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


def make_transaction(event_num=0, relation_num=0, witness=False, format_type=BBcFormat.FORMAT_BINARY, id_length=DEFAULT_ID_LEN):
    """Utility to make transaction object

    Args:
        event_num (int): the number of BBcEvent object to include in the transaction
        relation_num (int): the number of BBcRelation object to include in the transaction
        witness (bool): If true, BBcWitness object is included in the transaction
        format_type (int): Data format defined in BBcFormat class
        id_length (int): If <32, IDs will be truncated
    Returns:
        BBcTransaction:
    """
    transaction = BBcTransaction(format_type=format_type, id_length=id_length)
    if event_num > 0:
        for i in range(event_num):
            evt = BBcEvent(format_type=format_type, id_length=id_length)
            ast = BBcAsset(format_type=format_type, id_length=id_length)
            evt.add(asset=ast)
            transaction.add(event=evt)
    if relation_num > 0:
        for i in range(relation_num):
            transaction.add(relation=BBcRelation(format_type=format_type, id_length=id_length))
    if witness:
        transaction.add(witness=BBcWitness(format_type=format_type, id_length=id_length))
    return transaction


def add_relation_asset(transaction, relation_idx, asset_group_id, user_id, asset_body=None, asset_file=None):
    """Utility to add BBcRelation object with BBcAsset in the transaction"""
    ast = BBcAsset(user_id=user_id, asset_file=asset_file, asset_body=asset_body,
                   format_type=transaction.format_type, id_length=transaction.id_length)
    transaction.relations[relation_idx].add(asset_group_id=asset_group_id, asset=ast)


def add_relation_pointer(transaction, relation_idx, ref_transaction_id=None, ref_asset_id=None):
    """Utility to add BBcRelation object with BBcPointer in the transaction"""
    pointer = BBcPointer(transaction_id=ref_transaction_id, asset_id=ref_asset_id,
                         format_type=transaction.format_type, id_length=transaction.id_length)
    transaction.relations[relation_idx].add(pointer=pointer)


def add_reference_to_transaction(transaction, asset_group_id, ref_transaction_obj, event_index_in_ref):
    """Utility to add BBcReference object in the transaction

    Returns:
        BBcReference:
    """
    ref = BBcReference(asset_group_id=asset_group_id, transaction=transaction,
                       ref_transaction=ref_transaction_obj, event_index_in_ref=event_index_in_ref,
                       format_type=transaction.format_type, id_length=transaction.id_length)
    if ref.transaction_id is None:
        return None
    transaction.add(reference=ref)
    return ref


def add_event_asset(transaction, event_idx, asset_group_id, user_id, asset_body=None, asset_file=None):
    """Utility to add BBcEvent object with BBcAsset in the transaction"""
    ast = BBcAsset(user_id=user_id, asset_file=asset_file, asset_body=asset_body,
                   format_type=transaction.format_type, id_length=transaction.id_length)
    transaction.events[event_idx].add(asset_group_id=asset_group_id, asset=ast)


def make_relation_with_asset(asset_group_id, user_id, asset_body=None, asset_file=None,
                             format_type=BBcFormat.FORMAT_BINARY, id_length=DEFAULT_ID_LEN):
    """Utility to make BBcRelation object"""
    relation = BBcRelation(format_type=format_type, id_length=id_length)
    ast = BBcAsset(user_id=user_id, asset_file=asset_file, asset_body=asset_body,
                   format_type=format_type, id_length=id_length)
    relation.add(asset_group_id=asset_group_id, asset=ast)
    return relation


def add_pointer_in_relation(relation, ref_transaction_id=None, ref_asset_id=None):
    """Utility to add BBcRelation object with BBcPointer in the BBcRelation object"""
    pointer = BBcPointer(transaction_id=ref_transaction_id, asset_id=ref_asset_id,
                         format_type=relation.format_type, id_length=relation.id_length)
    relation.add(pointer=pointer)


def recover_signature_object(data, format_type=BBcFormat.FORMAT_BINARY):
    """Deserialize signature data"""
    sig = BBcSignature(format_type=format_type)
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


def verify_using_cross_ref(domain_id, transaction_id, transaction_base_digest, cross_ref_data, sigdata,
                           format_type=BBcFormat.FORMAT_BINARY):
    """Confirm the existence of the transaction using cross_ref

    Args:
        domain_id (bytes): target domain_id
        transaction_id (bytes): target transaction_id of which existence you want to confirm
        transaction_base_digest (bytes): digest obtained from the outer domain
        cross_ref_data (bytes): serialized BBcCrossRef object
        sigdata (bytes): serialized signature
        format_type (int): Data format type when calculating the digest (transaction_id)
    Returns:
        bool: True if valid
    """
    cross = BBcCrossRef(deserialize=cross_ref_data, format_type=BBcFormat.FORMAT_BINARY)
    cross.format_type = format_type
    if cross.domain_id != domain_id or cross.transaction_id != transaction_id:
        return False
    if format_type in [BBcFormat.FORMAT_BSON, BBcFormat.FORMAT_BSON_COMPRESS_BZ2, BBcFormat.FORMAT_BSON_COMPRESS_ZLIB]:
        dat = bson.dumps({
            "tx_base": transaction_base_digest,
            "cross_ref": cross.serialize(),
        })
    elif format_type in [BBcFormat.FORMAT_MSGPACK, BBcFormat.FORMAT_MSGPACK_COMPRESS_BZ2, BBcFormat.FORMAT_MSGPACK_COMPRESS_ZLIB]:
        dat = msgpack.dumps({
            "tx_base": transaction_base_digest,
            "cross_ref": cross.serialize(),
        })
    else:
        dat = bytearray(transaction_base_digest)
        dat.extend(to_2byte(1))
        dat.extend(to_4byte(len(cross_ref_data)))
        dat.extend(cross.serialize())
    digest = hashlib.sha256(bytes(dat)).digest()
    sig = BBcSignature(deserialize=sigdata)
    return sig.verify(digest) == 1


class KeyType:
    NOT_INITIALIZED = 0
    ECDSA_SECP256k1 = 1
    ECDSA_P256v1 = 2


DEFAULT_CURVETYPE = KeyType.ECDSA_P256v1


class KeyPair:
    POINT_CONVERSION_COMPRESSED = 2     # same as enum point_conversion_form_t in openssl/crypto/ec.h
    POINT_CONVERSION_UNCOMPRESSED = 4   # same as enum point_conversion_form_t in openssl/crypto/ec.h

    """Key pair container"""
    def __init__(self, curvetype=DEFAULT_CURVETYPE, compression=False, privkey=None, pubkey=None):
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


class BBcSignature:
    """Signature part in a transaction"""
    def __init__(self, key_type=DEFAULT_CURVETYPE, deserialize=None, format_type=BBcFormat.FORMAT_BINARY):
        self.format_type = format_type
        self.key_type = key_type
        self.signature = None
        self.pubkey = None
        self.keypair = None
        self.not_initialized = True
        if deserialize is not None:
            self.not_initialized = False
            self.deserialize(deserialize)

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

    def serialize(self):
        """Serialize this object"""
        if self.format_type != BBcFormat.FORMAT_BINARY:
            return self.get_dict()
        if self.not_initialized:
            dat = bytearray(to_4byte(KeyType.NOT_INITIALIZED))
            return bytes(dat)
        dat = bytearray(to_4byte(self.key_type))
        pubkey_len_bit = len(self.pubkey) * 8
        dat.extend(to_4byte(pubkey_len_bit))
        dat.extend(self.pubkey)
        sig_len_bit = len(self.signature) * 8
        dat.extend(to_4byte(sig_len_bit))
        dat.extend(self.signature)
        return bytes(dat)

    def deserialize(self, data):
        """Deserialize into this object

        Args:
            data (bytes): serialized binary data
        Returns:
            bool: True if successful
        """
        if self.format_type != BBcFormat.FORMAT_BINARY:
            return self.deserialize_obj(data)
        ptr = 0
        try:
            ptr, self.key_type = get_n_byte_int(ptr, 4, data)
            if self.key_type == KeyType.NOT_INITIALIZED:
                return True
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

    def get_dict(self):
        """Serialize this object"""
        if self.not_initialized:
            return {'key_type': 0}
        pubkey_len_bit = len(self.pubkey) * 8
        sig_len_bit = len(self.signature) * 8
        return {
            'key_type': self.key_type,
            'pubkey_len': pubkey_len_bit,
            'pubkey': bytes(self.pubkey),
            'signature_len': sig_len_bit,
            'signature': self.signature,
        }

    def deserialize_obj(self, obj):
        """Deserialize bson/msgpack data into this object

        Args:
            obj (bytes): object data
        Returns:
            bool: True if successful
        """
        try:
            if self.key_type == KeyType.NOT_INITIALIZED:
                return True
            if self.format_type in [BBcFormat.FORMAT_MSGPACK, BBcFormat.FORMAT_MSGPACK_COMPRESS_BZ2,
                                    BBcFormat.FORMAT_MSGPACK_COMPRESS_ZLIB]:
                dat = deep_copy_with_key_stringify(obj)
            else:
                dat = obj
            self.key_type = dat['key_type']
            pubkey = dat['pubkey']
            signature = dat['signature']
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
        reset_error()
        if self.keypair is None:
            set_error(code=bbc_error.EBADKEYPAIR, txt="Bad private_key/public_key")
            return False
        try:
            flag = self.keypair.verify(digest, self.signature)
        except:
            traceback.print_exc()
            return False
        return flag


class BBcTransaction:
    """Transaction object"""
    WITH_WIRE = True

    def __init__(self, version=1, deserialize=None,
                 format_type=BBcFormat.FORMAT_BINARY, id_length=DEFAULT_ID_LEN):
        self.format_type = format_type
        self.id_length = id_length
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
        self.asset_group_ids = dict()
        if deserialize is not None:
            self.deserialize(deserialize)

    def __str__(self):
        ret =  "------- Dump of the transaction data ------\n"
        ret += "* transaction_id: %s\n" % str_binary(self.transaction_id)
        ret += "version: %d\n" % self.version
        ret += "timestamp: %d\n" % self.timestamp
        if self.version != 0:
            ret += "id_length: %d\n" % self.id_length
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
        if self.witness is None:
            ret += "Witness: None\n"
        else:
            ret += str(self.witness)
        if self.cross_ref is None:
            ret += "Cross_Ref: None\n"
        else:
            ret += str(self.cross_ref)
        ret += "Signature[]: %d\n" % len(self.signatures)
        for i, sig in enumerate(self.signatures):
            ret += " [%d]\n" % i
            ret += str(sig)
        return ret

    def set_format_type(self, format_type):
        self.format_type = format_type
        if len(self.events) > 0:
            for evt in self.events:
                evt.format_type = format_type
        if len(self.references) > 0:
            for refe in self.references:
                refe.format_type = format_type
        if len(self.relations) > 0:
            for rtn in self.relations:
                rtn.format_type = format_type
                if len(rtn.pointers) > 0:
                    for ptr in rtn.pointers:
                        ptr.format_type = format_type
        if self.witness is not None:
            self.witness.format_type = format_type
        if len(self.signatures) > 0:
            for sig in self.signatures:
                sig.format_type = format_type

    def add(self, event=None, reference=None, relation=None, witness=None, cross_ref=None):
        """Add parts"""
        if event is not None:
            if isinstance(event, list):
                self.events.extend(event)
            else:
                self.events.append(event)
            for evt in self.events:
                evt.format_type = self.format_type
                if evt.asset is not None:
                    evt.asset.format_type = self.format_type
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
            for rtn in self.relations:
                rtn.format_type = self.format_type
                for ptr in rtn.pointers:
                    ptr.format_type = self.format_type
                if rtn.asset is not None:
                    rtn.asset.format_type = self.format_type
        if witness is not None:
            witness.transaction = self
            self.witness = witness
        if cross_ref is not None:
            self.cross_ref = cross_ref
        return True

    def get_sig_index(self, user_id):
        """Reserve a space for signature for the specified user_id

        Args:
            user_id (bytes): user_id whose signature will be added to the signature part
        Returns:
            int: position (index) in the signature part
        """
        if user_id not in self.userid_sigidx_mapping:
            self.userid_sigidx_mapping[user_id] = len(self.userid_sigidx_mapping)
            self.signatures.append(BBcSignature(format_type=self.format_type))
        return self.userid_sigidx_mapping[user_id]

    def add_signature(self, user_id=None, signature=None):
        """Add signature in the reserved space

        Args:
            user_id (bytes): user_id of the signature owner
            signature (BBcSignature): signature
        Returns:
            bool: True if successful
        """
        if user_id not in self.userid_sigidx_mapping:
            return False
        idx = self.userid_sigidx_mapping[user_id]
        self.signatures[idx] = signature
        return True

    def digest(self):
        """Calculate the digest

        The digest corresponds to the transaction_id of this object

        Returns:
            bytes: transaction_id (or digest)
        """
        target = self.serialize(for_id=True)
        d = hashlib.sha256(target).digest()
        self.transaction_id = d[:self.id_length]
        return d

    def serialize(self, for_id=False):
        """Serialize the whole parts"""
        if self.format_type != BBcFormat.FORMAT_BINARY:
            return self.serialize_obj(for_id)
        dat = bytearray(to_4byte(self.version))
        dat.extend(to_8byte(self.timestamp))
        if self.version != 0:
            dat.extend(to_2byte(self.id_length))
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
            dat_for_id = bytearray(self.transaction_base_digest)
            dat_for_id.extend(dat_cross)
            return bytes(dat_for_id)

        dat.extend(dat_cross)

        dat.extend(to_2byte(len(self.signatures)))
        for signature in self.signatures:
            sig = signature.serialize()
            dat.extend(to_4byte(len(sig)))
            dat.extend(sig)
        self.transaction_data = bytes(to_2byte(self.format_type)+dat)
        return self.transaction_data

    def deserialize(self, data):
        """Deserialize into this object

        Args:
            data (bytes): serialized binary data
        Returns:
            bool: True if successful
        """
        self.transaction_data = data[:]
        ptr = 0
        ptr, self.format_type = get_n_byte_int(ptr, 2, data)
        if self.format_type != BBcFormat.FORMAT_BINARY:
            return self.deserialize_obj(data[2:])
        data_size = len(data)
        try:
            ptr, self.version = get_n_byte_int(ptr, 4, data)
            ptr, self.timestamp = get_n_byte_int(ptr, 8, data)
            if self.version != 0:
                ptr, self.id_length = get_n_byte_int(ptr, 2, data)
            ptr, evt_num = get_n_byte_int(ptr, 2, data)
            self.events = []
            for i in range(evt_num):
                ptr, size = get_n_byte_int(ptr, 4, data)
                ptr, evtdata = get_n_bytes(ptr, size, data)
                evt = BBcEvent(id_length=self.id_length)
                if not evt.deserialize(evtdata):
                    return False
                self.events.append(evt)
                if ptr >= data_size:
                    return False
                self.asset_group_ids[evt.asset.asset_id] = evt.asset_group_id

            ptr, ref_num = get_n_byte_int(ptr, 2, data)
            self.references = []
            for i in range(ref_num):
                ptr, size = get_n_byte_int(ptr, 4, data)
                ptr, refdata = get_n_bytes(ptr, size, data)
                refe = BBcReference(None, None, id_length=self.id_length)
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
                rtn = BBcRelation(id_length=self.id_length)
                if not rtn.deserialize(rtndata):
                    return False
                self.relations.append(rtn)
                if ptr >= data_size:
                    return False
                self.asset_group_ids[rtn.asset.asset_id] = rtn.asset_group_id

            ptr, witness_num = get_n_byte_int(ptr, 2, data)
            if witness_num == 0:
                self.witness = None
            else:
                ptr, size = get_n_byte_int(ptr, 4, data)
                ptr, witnessdata = get_n_bytes(ptr, size, data)
                self.witness = BBcWitness(id_length=self.id_length)
                self.witness.transaction = self
                if not self.witness.deserialize(witnessdata):
                    return False

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
                sig = BBcSignature()
                if size > 4:
                    ptr, sigdata = get_n_bytes(ptr, size, data)
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

    def serialize_obj(self, for_id=False, no_header=False):
        """Serialize the whole parts"""
        if self.witness is not None:
            witness = self.witness.get_dict()
        else:
            witness = None
        if self.cross_ref is not None:
            tx_crossref = self.cross_ref.get_dict()
        else:
            tx_crossref = None

        tx_base = {
            "header": {
                "version": self.version,
                "timestamp": self.timestamp,
                "id_length": self.id_length
            },
            "events": [evt.serialize() for evt in self.events],
            "references": [refe.serialize() for refe in self.references],
            "relations": [rtn.serialize() for rtn in self.relations],
            "witness": witness,
        }
        if self.format_type in [BBcFormat.FORMAT_MSGPACK, BBcFormat.FORMAT_MSGPACK_COMPRESS_BZ2,
                                BBcFormat.FORMAT_MSGPACK_COMPRESS_ZLIB]:
            self.transaction_base_digest = hashlib.sha256(msgpack.dumps(tx_base)).digest()
        else:
            self.transaction_base_digest = hashlib.sha256(bson.dumps(tx_base)).digest()
        if for_id:
            if self.format_type in [BBcFormat.FORMAT_MSGPACK, BBcFormat.FORMAT_MSGPACK_COMPRESS_BZ2,
                                    BBcFormat.FORMAT_MSGPACK_COMPRESS_ZLIB]:
                return msgpack.dumps({
                    "tx_base": self.transaction_base_digest,
                    "cross_ref": tx_crossref,
                })
            else:
                return bson.dumps({
                    "tx_base": self.transaction_base_digest,
                    "cross_ref": tx_crossref,
                })
        if self.version == 0:
            tx_base.update({"cross_ref": tx_crossref})

        if self.format_type in [BBcFormat.FORMAT_MSGPACK, BBcFormat.FORMAT_MSGPACK_COMPRESS_BZ2,
                                BBcFormat.FORMAT_MSGPACK_COMPRESS_ZLIB]:
            if self.version == 0:
                dat = msgpack.dumps({
                    "transaction_base": tx_base,
                    "signatures": [sig.serialize() for sig in self.signatures],
                })
            else:
                dat = msgpack.dumps({
                    "transaction_base": tx_base,
                    "cross_ref": tx_crossref,
                    "signatures": [sig.serialize() for sig in self.signatures],
                })
        else:
            if self.version == 0:
                dat = bson.dumps({
                    "transaction_base": tx_base,
                    "signatures": [sig.serialize() for sig in self.signatures],
                })
            else:
                dat = bson.dumps({
                    "transaction_base": tx_base,
                    "cross_ref": tx_crossref,
                    "signatures": [sig.serialize() for sig in self.signatures],
                })
        if self.format_type in [BBcFormat.FORMAT_MSGPACK_COMPRESS_BZ2, BBcFormat.FORMAT_BSON_COMPRESS_BZ2]:
            dat = bz2.compress(dat, compresslevel=1)
        elif self.format_type in [BBcFormat.FORMAT_BSON_COMPRESS_ZLIB, BBcFormat.FORMAT_MSGPACK_COMPRESS_ZLIB]:
            dat = zlib.compress(dat)
        if no_header:
            return dat
        self.transaction_data = bytes(to_2byte(self.format_type) + dat)
        return self.transaction_data

    def deserialize_obj(self, data):
        """Deserialize bson/msgpack data into this object

        Args:
            data (bytes): object data
        Returns:
            bool: True if successful
        """
        if self.format_type in [BBcFormat.FORMAT_BSON_COMPRESS_BZ2, BBcFormat.FORMAT_MSGPACK_COMPRESS_BZ2]:
            data = bz2.decompress(data)
        elif self.format_type in [BBcFormat.FORMAT_BSON_COMPRESS_ZLIB, BBcFormat.FORMAT_MSGPACK_COMPRESS_ZLIB]:
            data = zlib.decompress(data)

        if self.format_type in [BBcFormat.FORMAT_MSGPACK, BBcFormat.FORMAT_MSGPACK_COMPRESS_BZ2,
                                BBcFormat.FORMAT_MSGPACK_COMPRESS_ZLIB]:
            datobj = deep_copy_with_key_stringify(msgpack.loads(data))
        else:
            datobj = bson.loads(data)
        tx_base = datobj["transaction_base"]
        self.version = tx_base["header"]["version"]
        self.timestamp = tx_base["header"]["timestamp"]
        self.id_length = tx_base["header"]["id_length"]
        self.events = []
        for evt_bson in tx_base["events"]:
            evt = BBcEvent(format_type=self.format_type, id_length=self.id_length)
            evt.deserialize(evt_bson)
            self.events.append(evt)
        self.references = []
        for refe_bson in tx_base["references"]:
            refe = BBcReference(None, None, format_type=self.format_type, id_length=self.id_length)
            refe.deserialize(refe_bson)
            self.references.append(refe)
        self.relations = []
        for rtn_bson in tx_base["relations"]:
            rtn = BBcRelation(format_type=self.format_type, id_length=self.id_length)
            rtn.deserialize(rtn_bson)
            self.relations.append(rtn)
        wit = tx_base.get("witness", None)
        if wit is None:
            self.witness = None
        else:
            self.witness = BBcWitness(format_type=self.format_type, id_length=self.id_length)
            self.witness.transaction = self
            self.witness.deserialize(wit)
        if self.version == 0:
            cross_ref = tx_base.get("cross_ref", None)
        else:
            cross_ref = datobj.get("cross_ref", None)
        if cross_ref is None:
            self.cross_ref = None
        else:
            self.cross_ref = BBcCrossRef(format_type=self.format_type)
            self.cross_ref.deserialize(cross_ref)

        self.signatures = []
        if "signatures" in datobj:
            for sigobj in datobj["signatures"]:
                sig = BBcSignature(format_type=self.format_type)
                sig.deserialize(sigobj)
                self.signatures.append(sig)
        self.digest()
        return True

    def sign(self, key_type=DEFAULT_CURVETYPE, private_key=None, public_key=None, keypair=None):
        """Sign the transaction

        Args:
            key_type (int): Type of encryption key's curve
            private_key (bytes):
            public_key (bytes):
            keypair (KeyPair): keypair or set of private_key and public_key needs to be given
        Returns:
            BBcSignature:
        """
        reset_error()
        if keypair is None:
            if len(private_key) != 32 or len(public_key) <= 32:
                set_error(code=bbc_error.EBADKEYPAIR, txt="Bad private_key/public_key (must be in bytes format)")
                return None
            keypair = KeyPair(curvetype=key_type, privkey=private_key, pubkey=public_key)
            if keypair is None:
                set_error(code=bbc_error.EBADKEYPAIR, txt="Bad private_key/public_key")
                return None

        sig = BBcSignature(key_type=keypair.curvetype, format_type=self.format_type)
        s = keypair.sign(self.digest())
        if s is None:
            set_error(code=bbc_error.EOTHER, txt="sig_type %d is not supported" % keypair.curvetype)
            return None
        sig.add(signature=s, pubkey=keypair.public_key)
        return sig


class BBcEvent:
    """Event part in a transaction"""
    def __init__(self, asset_group_id=None, format_type=BBcFormat.FORMAT_BINARY, id_length=DEFAULT_ID_LEN):
        self.format_type = format_type
        self.id_length = id_length
        if asset_group_id is not None and id_length < 32:
            self.asset_group_id = asset_group_id[:id_length]
        else:
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
            option_approver_num_numerator=0, option_approver_num_denominator=0, option_approver=None, asset=None):
        """Add parts"""
        if asset_group_id is not None:
            self.asset_group_id = asset_group_id[:self.id_length]
        if reference_index is not None:
            self.reference_indices.append(reference_index)
        if mandatory_approver is not None:
            self.mandatory_approvers.append(mandatory_approver[:self.id_length])
        if option_approver_num_numerator > 0:
            self.option_approver_num_numerator = option_approver_num_numerator
        if option_approver_num_denominator > 0:
            self.option_approver_num_denominator = option_approver_num_denominator
        if option_approver is not None:
            self.option_approvers.append(option_approver[:self.id_length])
        if asset is not None:
            self.asset = asset
        return True

    def serialize(self):
        """Serialize this object

        Returns:
            bytes: serialized binary data
        """
        if self.format_type != BBcFormat.FORMAT_BINARY:
            return self.get_dict()
        dat = bytearray(to_bigint(self.asset_group_id, size=self.id_length))
        dat.extend(to_2byte(len(self.reference_indices)))
        for i in range(len(self.reference_indices)):
            dat.extend(to_2byte(self.reference_indices[i]))
        dat.extend(to_2byte(len(self.mandatory_approvers)))
        for i in range(len(self.mandatory_approvers)):
            dat.extend(to_bigint(self.mandatory_approvers[i], size=self.id_length))
        dat.extend(to_2byte(self.option_approver_num_numerator))
        dat.extend(to_2byte(self.option_approver_num_denominator))
        for i in range(self.option_approver_num_denominator):
            dat.extend(to_bigint(self.option_approvers[i], size=self.id_length))
        ast = self.asset.serialize()
        dat.extend(to_4byte(len(ast)))
        dat.extend(ast)
        return bytes(dat)

    def deserialize(self, data):
        """Deserialize into this object

        Args:
            data (bytes): serialized binary data
        Returns:
            bool: True if successful
        """
        if self.format_type != BBcFormat.FORMAT_BINARY:
            return self.deserialize_obj(data)
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
            self.asset = BBcAsset(id_length=self.id_length)
            self.asset.deserialize(astdata)
        except:
            return False
        return True

    def get_dict(self):
        """Serialize this object"""
        if self.asset is None:
            asset = None
        else:
            asset = self.asset.get_dict()
        return {
            'asset_group_id': self.asset_group_id,
            'reference_indices': self.reference_indices,
            'mandatory_approvers': self.mandatory_approvers,
            'option_approver_num_numerator': self.option_approver_num_numerator,
            'option_approver_num_denominator': self.option_approver_num_denominator,
            'option_approvers': self.option_approvers,
            'asset': asset,
        }

    def deserialize_obj(self, obj):
        """Deserialize bson/msgpack data into this object

        Args:
            obj (bytes): object data
        Returns:
            bool: True if successful
        """
        if self.format_type in [BBcFormat.FORMAT_MSGPACK, BBcFormat.FORMAT_MSGPACK_COMPRESS_BZ2,
                                BBcFormat.FORMAT_MSGPACK_COMPRESS_ZLIB]:
            data = deep_copy_with_key_stringify(obj)
        else:
            data = obj

        self.asset_group_id = data.get('asset_group_id', None)
        self.reference_indices = data.get('reference_indices', [])
        self.mandatory_approvers = data.get('mandatory_approvers', [])
        self.option_approver_num_numerator = data.get('option_approver_num_numerator', 0)
        self.option_approver_num_denominator = data.get('option_approver_num_denominator', 0)
        self.option_approvers = data.get('option_approvers', [])
        asset = data.get('asset', None)
        if asset is None:
            self.asset = None
        else:
            self.asset = BBcAsset(format_type=self.format_type)
            self.asset.deserialize_obj(asset)
        return True


class BBcReference:
    """Reference part in a transaction"""
    def __init__(self, asset_group_id, transaction, ref_transaction=None, event_index_in_ref=0,
                 format_type=BBcFormat.FORMAT_BINARY, id_length=DEFAULT_ID_LEN):
        self.format_type = format_type
        self.id_length = id_length
        if asset_group_id is not None:
            self.asset_group_id = asset_group_id[:self.id_length]
        else:
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
        """Read the previous referencing transaction"""
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
            ref_transaction.digest()
            self.transaction_id = ref_transaction.transaction_id
        except Exception as e:
            print(traceback.format_exc())

    def add_signature(self, user_id=None, signature=None):
        """Add signature in the reserved space

        Args:
            user_id (bytes): user_id of the signature owner
            signature (BBcSignature): signature
        """
        if user_id in self.option_approvers:
            if len(self.option_sig_ids) == 0:
                return
            user_id = self.option_sig_ids.pop(0)
        signature.format_type = self.transaction.format_type
        self.transaction.add_signature(user_id=user_id, signature=signature)

    def get_referred_transaction(self):
        """Return referred transaction in serialized format"""
        return {self.ref_transaction.transaction_id: self.ref_transaction.serialize()}

    def get_destinations(self):
        """Return the list of approvers in the referred transaction"""
        return self.mandatory_approvers+self.option_approvers

    def serialize(self):
        """Serialize this object

        Returns:
            bytes: serialized binary data
        """
        if self.format_type != BBcFormat.FORMAT_BINARY:
            return self.get_dict()
        dat = bytearray(to_bigint(self.asset_group_id, size=self.id_length))
        dat.extend(to_bigint(self.transaction_id, size=self.id_length))
        dat.extend(to_2byte(self.event_index_in_ref))
        dat.extend(to_2byte(len(self.sig_indices)))
        for i in range(len(self.sig_indices)):
            dat.extend(to_2byte(self.sig_indices[i]))
        return bytes(dat)

    def deserialize(self, data):
        """Deserialize into this object

        Args:
            data (bytes): serialized binary data
        Returns:
            bool: True if successful
        """
        if self.format_type != BBcFormat.FORMAT_BINARY:
            return self.deserialize_obj(data)
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

    def get_dict(self):
        """Serialize this object"""
        return {
            'asset_group_id': self.asset_group_id,
            'transaction_id': self.transaction_id,
            'event_index_in_ref': self.event_index_in_ref,
            'sig_indices': self.sig_indices,
        }

    def deserialize_obj(self, obj):
        """Deserialize bson/msgpack data into this object

        Args:
            obj (bytes): object data
        Returns:
            bool: True if successful
        """
        if self.format_type in [BBcFormat.FORMAT_MSGPACK, BBcFormat.FORMAT_MSGPACK_COMPRESS_BZ2,
                                BBcFormat.FORMAT_MSGPACK_COMPRESS_ZLIB]:
            data = deep_copy_with_key_stringify(obj)
        else:
            data = obj

        self.asset_group_id = data.get('asset_group_id', None)
        self.transaction_id = data.get('transaction_id', None)
        self.event_index_in_ref = data.get('event_index_in_ref', 0)
        self.sig_indices = data.get('sig_indices', [])
        return True


class BBcRelation:
    """Relation part in a transaction"""
    def __init__(self, asset_group_id=None, format_type=BBcFormat.FORMAT_BINARY, id_length=DEFAULT_ID_LEN):
        self.format_type = format_type
        self.id_length = id_length
        if asset_group_id is not None and id_length < 32:
            self.asset_group_id = asset_group_id[:id_length]
        else:
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

    def serialize(self):
        """Serialize this object

        Returns:
            bytes: serialized binary data
        """
        if self.format_type != BBcFormat.FORMAT_BINARY:
            return self.get_dict()
        dat = bytearray(to_bigint(self.asset_group_id, size=self.id_length))
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
        """Deserialize bson data into this object

        Args:
            data (dict): bson data
        Returns:
            bool: True if successful
        """
        if self.format_type != BBcFormat.FORMAT_BINARY:
            return self.deserialize_obj(data)
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
                self.asset = BBcAsset(id_length=self.id_length)
                ptr, astdata = get_n_bytes(ptr, astsize, data)
                if not self.asset.deserialize(astdata):
                    return False
        except:
            return False
        return True

    def get_dict(self):
        """Serialize this object"""
        if self.asset is None:
            asset = None
        else:
            asset = self.asset.get_dict()
        return {
            'asset_group_id': self.asset_group_id,
            'pointers': [ptr.serialize() for ptr in self.pointers],
            'asset': asset
        }

    def deserialize_obj(self, obj):
        """Deserialize bson/msgpack data into this object

        Args:
            data (bytes): object data
        Returns:
            bool: True if successful
        """
        if self.format_type in [BBcFormat.FORMAT_MSGPACK, BBcFormat.FORMAT_MSGPACK_COMPRESS_BZ2,
                                BBcFormat.FORMAT_MSGPACK_COMPRESS_ZLIB]:
            data = deep_copy_with_key_stringify(obj)
        else:
            data = obj

        self.asset_group_id = data.get('asset_group_id', None)
        for ptrdat in data.get('pointers', []):
            ptr = BBcPointer(format_type=self.format_type, id_length=self.id_length)
            ptr.deserialize(ptrdat)
            self.pointers.append(ptr)
        asset = data.get('asset', None)
        if asset is None:
            self.asset = None
        else:
            self.asset = BBcAsset(format_type=self.format_type, id_length=self.id_length)
            self.asset.deserialize_obj(asset)
        return True


class BBcPointer:
    """Pointer part in a transaction"""
    def __init__(self, transaction_id=None, asset_id=None, format_type=BBcFormat.FORMAT_BINARY, id_length=DEFAULT_ID_LEN):
        self.format_type = format_type
        self.id_length = id_length
        if transaction_id is not None and id_length < 32:
            self.transaction_id = transaction_id[:id_length]
        else:
            self.transaction_id = transaction_id
        if asset_id is not None and id_length < 32:
            self.asset_id = asset_id[:id_length]
        else:
            self.asset_id = asset_id

    def __str__(self):
        ret =  "     transaction_id: %s\n" % str_binary(self.transaction_id)
        ret += "     asset_id: %s\n" % str_binary(self.asset_id)
        return ret

    def add(self, transaction_id=None, asset_id=None):
        """Add parts"""
        if transaction_id is not None:
            self.transaction_id = transaction_id[:self.id_length]
        if asset_id is not None:
            self.asset_id = asset_id[:self.id_length]

    def serialize(self):
        """Serialize this object

        Returns:
            bytes: serialized binary data
        """
        if self.format_type != BBcFormat.FORMAT_BINARY:
            return self.get_dict()
        dat = bytearray(to_bigint(self.transaction_id, size=self.id_length))
        if self.asset_id is None:
            dat.extend(to_2byte(0))
        else:
            dat.extend(to_2byte(1))
            dat.extend(to_bigint(self.asset_id, size=self.id_length))
        return bytes(dat)

    def deserialize(self, data):
        """Deserialize into this object

        Args:
            data (bytes): serialized binary data
        Returns:
            bool: True if successful
        """
        if self.format_type != BBcFormat.FORMAT_BINARY:
            return self.deserialize_obj(data)
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

    def get_dict(self):
        """Serialize this object"""
        return {
            'transaction_id': self.transaction_id,
            'asset_id': self.asset_id,
        }

    def deserialize_obj(self, obj):
        """Deserialize bson/msgpack data into this object

        Args:
            obj (bytes): object data
        Returns:
            bool: True if successful
        """
        if self.format_type in [BBcFormat.FORMAT_MSGPACK, BBcFormat.FORMAT_MSGPACK_COMPRESS_BZ2,
                                BBcFormat.FORMAT_MSGPACK_COMPRESS_ZLIB]:
            data = deep_copy_with_key_stringify(obj)
        else:
            data = obj

        self.transaction_id = data.get('transaction_id', None)
        self.asset_id = data.get('asset_id', None)
        return True


class BBcWitness:
    """Witness part in a transaction"""
    def __init__(self, format_type=BBcFormat.FORMAT_BINARY, id_length=DEFAULT_ID_LEN):
        self.format_type = format_type
        self.id_length = id_length
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
        """Register user_id in the list"""
        if user_id not in self.user_ids:
            self.user_ids.append(user_id[:self.id_length])
            self.sig_indices.append(self.transaction.get_sig_index(user_id[:self.id_length]))

    def add_signature(self, user_id=None, signature=None):
        """Add signature in the reserved space for the user_id that was registered before

        Args:
            user_id (bytes): user_id of the signature owner
            signature (bytes): signature
        """
        signature.format_type = self.transaction.format_type
        self.transaction.add_signature(user_id=user_id[:self.id_length], signature=signature)

    def serialize(self):
        """Serialize this object

        Returns:
            bytes: serialized binary data
        """
        if self.format_type != BBcFormat.FORMAT_BINARY:
            return self.get_dict()
        dat = bytearray(to_2byte(len(self.sig_indices)))
        for i in range(len(self.sig_indices)):
            dat.extend(to_bigint(self.user_ids[i], size=self.id_length))
            dat.extend(to_2byte(self.sig_indices[i]))
        return bytes(dat)

    def deserialize(self, data):
        """Deserialize into this object

        Args:
            data (bytes): serialized binary data
        Returns:
            bool: True if successful
        """
        if self.format_type != BBcFormat.FORMAT_BINARY:
            return self.deserialize_obj(data)
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
                self.transaction.get_sig_index(uid[:self.id_length])
        except:
            return False
        return True

    def get_dict(self):
        """Serialize this object"""
        return {
            'user_ids': self.user_ids,
            'sig_indices': self.sig_indices,
        }

    def deserialize_obj(self, obj):
        """Deserialize bson/msgpack data into this object

        Args:
            obj (bytes): object data
        Returns:
            bool: True if successful
        """
        if self.format_type in [BBcFormat.FORMAT_MSGPACK, BBcFormat.FORMAT_MSGPACK_COMPRESS_BZ2,
                                BBcFormat.FORMAT_MSGPACK_COMPRESS_ZLIB]:
            data = deep_copy_with_key_stringify(obj)
        else:
            data = obj

        self.user_ids = data.get('user_ids', [])
        self.sig_indices = data.get('sig_indices', [])
        for i, user_id in enumerate(self.user_ids):
            self.transaction.get_sig_index(user_id[:self.id_length])
        return True


class BBcAsset:
    """Asset part in a transaction"""
    def __init__(self, user_id=None, asset_file=None, asset_body=None,
                 format_type=BBcFormat.FORMAT_BINARY, id_length=DEFAULT_ID_LEN):
        self.id_length = id_length
        self.format_type = format_type
        self.asset_id = None
        if user_id is not None and id_length < 32:
            self.user_id = user_id[:id_length]
        else:
            self.user_id = user_id
        self.nonce = get_random_value()
        self.asset_file_size = 0
        self.asset_file = None
        self.asset_file_digest = None
        self.asset_body_size = 0
        self.asset_body = None
        if user_id is not None:
            self.add(user_id, asset_file, asset_body)

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
        """Add parts in this object"""
        if user_id is not None:
            self.user_id = user_id[:self.id_length]
        if asset_file is not None:
            self.asset_file = asset_file
            self.asset_file_size = len(asset_file)
            self.asset_file_digest = hashlib.sha256(bytes(asset_file)).digest()[:self.id_length]
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
        target = self.serialize(for_digest_calculation=True)
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

    def recover_asset_file(self, asset_file, id_length=DEFAULT_ID_LEN):
        """Recover asset file info from the given raw content"""
        digest = hashlib.sha256(asset_file).digest()[:id_length]
        if digest == self.asset_file_digest:
            self.asset_file = asset_file
            return True
        else:
            return False

    def serialize(self, for_digest_calculation=False):
        """Serialize this object

        Args:
            for_digest_calculation (bool): True if digest calculation
        Returns:
            bytes: serialized binary data
        """
        if self.format_type != BBcFormat.FORMAT_BINARY:
            return self.get_dict(for_digest_calculation=for_digest_calculation)
        if for_digest_calculation:
            dat = bytearray(to_bigint(self.user_id, size=self.id_length))
            dat.extend(to_2byte(len(self.nonce)))
            dat.extend(self.nonce)
            dat.extend(to_4byte(self.asset_file_size))
            if self.asset_file_size > 0:
                dat.extend(self.asset_file_digest)
            if isinstance(self.asset_body, dict):
                dat.extend(to_2byte(1))
                astbdy = bson.dumps(self.asset_body)
                dat.extend(to_2byte(len(astbdy)))
                dat.extend(astbdy)
            else:
                dat.extend(to_2byte(0))
                dat.extend(to_2byte(self.asset_body_size))
                if self.asset_body_size > 0:
                    dat.extend(self.asset_body)
            return bytes(dat)
        else:
            dat = bytearray(to_bigint(self.asset_id, size=self.id_length))
            dat.extend(to_bigint(self.user_id, size=self.id_length))
            dat.extend(to_2byte(len(self.nonce)))
            dat.extend(self.nonce)
            dat.extend(to_4byte(self.asset_file_size))
            if self.asset_file_size > 0:
                dat.extend(to_bigint(self.asset_file_digest, size=self.id_length))
            if isinstance(self.asset_body, dict):
                dat.extend(to_2byte(1))
                astbdy = bson.dumps(self.asset_body)
                dat.extend(to_2byte(len(astbdy)))
                dat.extend(astbdy)
            else:
                dat.extend(to_2byte(0))
                dat.extend(to_2byte(self.asset_body_size))
                if self.asset_body_size > 0:
                    dat.extend(self.asset_body)
            return bytes(dat)

    def deserialize(self, data):
        """Deserialize into this object

        Args:
            data (bytes): serialized binary data
        Returns:
            bool: True if successful
        """
        if self.format_type != BBcFormat.FORMAT_BINARY:
            return self.deserialize_obj(data)
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
            ptr, dict_flag = get_n_byte_int(ptr, 2, data)
            if dict_flag != 1:
                ptr, self.asset_body_size = get_n_byte_int(ptr, 2, data)
                if self.asset_body_size > 0:
                    ptr, self.asset_body = get_n_bytes(ptr, self.asset_body_size, data)
            else:
                ptr, sz = get_n_byte_int(ptr, 2, data)
                ptr, astbdy = get_n_bytes(ptr, sz, data)
                self.asset_body = bson.loads(astbdy)
                self.asset_body_size = len(self.asset_body)

        except:
            traceback.print_exc()
            return False
        return True

    def get_dict(self, for_digest_calculation=False):
        """Serialize this object"""
        if for_digest_calculation:
            return bson.dumps({
                'user_id': self.user_id,
                'nonce': self.nonce,
                'asset_file_size': self.asset_file_size,
                'asset_file_digest': self.asset_file_digest,
                'asset_body_size': self.asset_body_size,
                'asset_body': self.asset_body,
            })
        else:
            return {
                'asset_id': self.asset_id,
                'user_id': self.user_id,
                'nonce': self.nonce,
                'asset_file_size': self.asset_file_size,
                'asset_file_digest': self.asset_file_digest,
                'asset_body_size': self.asset_body_size,
                'asset_body': self.asset_body,
            }

    def deserialize_obj(self, obj):
        """Deserialize bson/msgpack data into this object

        Args:
            obj (bytes): object data
        Returns:
            bool: True if successful
        """
        if self.format_type in [BBcFormat.FORMAT_MSGPACK, BBcFormat.FORMAT_MSGPACK_COMPRESS_BZ2,
                                BBcFormat.FORMAT_MSGPACK_COMPRESS_ZLIB]:
            data = deep_copy_with_key_stringify(obj)
        else:
            data = obj

        self.asset_id = data.get('asset_id', None)
        self.user_id = data.get('user_id', None)
        self.nonce = data.get('nonce', None)
        self.asset_file_size = data.get('asset_file_size', 0)
        self.asset_file_digest = data.get('asset_file_digest', None)
        self.asset_body_size = data.get('asset_body_size', 0)
        self.asset_body = data.get('asset_body', None)
        return True


class BBcCrossRef:
    """CrossRef part in a transaction"""
    def __init__(self, domain_id=None, transaction_id=None, deserialize=None, format_type=BBcFormat.FORMAT_BINARY):
        self.format_type = format_type
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
        """Serialize this object

        Returns:
            bytes: serialized binary data
        """
        if self.format_type != BBcFormat.FORMAT_BINARY:
            return self.get_dict()
        dat = bytearray(to_bigint(self.domain_id))
        dat.extend(to_bigint(self.transaction_id))
        return bytes(dat)

    def deserialize(self, data):
        """Deserialize into this object

        Args:
            data (bytes): serialized binary data
        Returns:
            bool: True if successful
        """
        if self.format_type != BBcFormat.FORMAT_BINARY:
            return self.deserialize_obj(data)
        ptr = 0
        try:
            ptr, self.domain_id = get_bigint(ptr, data)
            ptr, self.transaction_id = get_bigint(ptr, data)
        except:
            return False
        return True

    def get_dict(self):
        """Serialize this object into bson format"""
        return {
            'domain_id': self.domain_id,
            'transaction_id': self.transaction_id,
        }

    def deserialize_obj(self, obj):
        """Deserialize bson/msgpack data into this object

        Args:
            obj (bytes): object data
        Returns:
            bool: True if successful
        """
        if self.format_type in [BBcFormat.FORMAT_MSGPACK, BBcFormat.FORMAT_MSGPACK_COMPRESS_BZ2,
                                BBcFormat.FORMAT_MSGPACK_COMPRESS_ZLIB]:
            data = deep_copy_with_key_stringify(obj)
        else:
            data = obj

        self.domain_id = data.get('domain_id', None)
        self.transaction_id = data.get('transaction_id', None)
        return True


class MsgType:
    """Message types for between core node and client"""
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
    NOTIFY_DOMAIN_KEY_UPDATE = 19
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
    REQUEST_COUNT_TRANSACTIONS = 95
    RESPONSE_COUNT_TRANSACTIONS = 95

    REQUEST_REGISTER_HASH_IN_SUBSYS = 128
    RESPONSE_REGISTER_HASH_IN_SUBSYS = 129
    REQUEST_VERIFY_HASH_IN_SUBSYS = 130
    RESPONSE_VERIFY_HASH_IN_SUBSYS = 131
