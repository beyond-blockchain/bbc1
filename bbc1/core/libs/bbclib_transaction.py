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
import random
import time
import traceback
from collections import Mapping

current_dir = os.path.abspath(os.path.dirname(__file__))
sys.path.append(os.path.join(current_dir, "../../.."))

from bbc1.core.libs import bbclib_utils
from bbc1.core import bbc_error
from bbc1.core.libs.bbclib_config import DEFAULT_ID_LEN, DEFAULT_CURVETYPE
from bbc1.core.libs.bbclib_keypair import KeyPair
from bbc1.core.libs.bbclib_signature import BBcSignature
from bbc1.core.libs.bbclib_relation import BBcRelation
from bbc1.core.libs.bbclib_reference import BBcReference
from bbc1.core.libs.bbclib_event import BBcEvent
from bbc1.core.libs.bbclib_witness import BBcWitness
from bbc1.core.libs.bbclib_crossref import BBcCrossRef
from bbc1.core import bbclib


class BBcTransaction:
    """Transaction object"""
    WITH_WIRE = False  # for backward compatibility

    def __init__(self, version=1, unpack=None, id_length=DEFAULT_ID_LEN):
        self.id_length = id_length
        self.version = version
        self.timestamp = int(time.time() * 1000)  # milliseconds
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
        if unpack is not None:
            self.unpack(unpack)

    def __str__(self):
        ret =  "------- Dump of the transaction data ------\n"
        ret += "* transaction_id: %s\n" % bbclib_utils.str_binary(self.transaction_id)
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

    def add(self, event=None, reference=None, relation=None, witness=None, cross_ref=None):
        """Add parts"""
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
        """Reserve a space for signature for the specified user_id

        Args:
            user_id (bytes): user_id whose signature will be added to the signature part
        Returns:
            int: position (index) in the signature part
        """
        if user_id not in self.userid_sigidx_mapping:
            self.userid_sigidx_mapping[user_id] = len(self.userid_sigidx_mapping)
            self.signatures.append(BBcSignature())
        return self.userid_sigidx_mapping[user_id]

    def set_sig_index(self, user_id, idx):
        """Map a user_id with the index of signature list

        Args:
            user_id (bytes): user_id whose signature will be added to the signature part
            idx (int): index number
        """
        if user_id in self.userid_sigidx_mapping:
            return
        self.userid_sigidx_mapping[user_id] = idx

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
        signature.not_initialized = False
        self.signatures[idx] = signature
        return True

    def digest(self):
        """Calculate the digest

        The digest corresponds to the transaction_id of this object

        Returns:
            bytes: transaction_id (or digest)
        """
        target = self.pack(for_id=True)
        d = hashlib.sha256(target).digest()
        self.transaction_id = d[:self.id_length]
        return d

    def pack(self, for_id=False):
        """Pack the whole parts"""
        dat = bytearray(bbclib_utils.to_4byte(self.version))
        dat.extend(bbclib_utils.to_8byte(self.timestamp))
        if self.version != 0:
            dat.extend(bbclib_utils.to_2byte(self.id_length))
        dat.extend(bbclib_utils.to_2byte(len(self.events)))
        for i in range(len(self.events)):
            evt = self.events[i].pack()
            dat.extend(bbclib_utils.to_4byte(len(evt)))
            dat.extend(evt)
        dat.extend(bbclib_utils.to_2byte(len(self.references)))
        for i in range(len(self.references)):
            refe = self.references[i].pack()
            dat.extend(bbclib_utils.to_4byte(len(refe)))
            dat.extend(refe)
        dat.extend(bbclib_utils.to_2byte(len(self.relations)))
        for i in range(len(self.relations)):
            rtn = self.relations[i].pack()
            dat.extend(bbclib_utils.to_4byte(len(rtn)))
            dat.extend(rtn)
        if self.witness is not None:
            dat.extend(bbclib_utils.to_2byte(1))
            witness = self.witness.pack()
            dat.extend(bbclib_utils.to_4byte(len(witness)))
            dat.extend(witness)
        else:
            dat.extend(bbclib_utils.to_2byte(0))
        self.transaction_base_digest = hashlib.sha256(dat).digest()

        dat_cross = bytearray()
        if self.cross_ref is not None:
            cross = self.cross_ref.pack()
            dat_cross.extend(bbclib_utils.to_2byte(1))
            dat_cross.extend(bbclib_utils.to_4byte(len(cross)))
            dat_cross.extend(cross)
        else:
            dat_cross.extend(bbclib_utils.to_2byte(0))

        if for_id:
            dat_for_id = bytearray(self.transaction_base_digest)
            dat_for_id.extend(dat_cross)
            return bytes(dat_for_id)

        dat.extend(dat_cross)

        dat.extend(bbclib_utils.to_2byte(len(self.signatures)))
        for signature in self.signatures:
            sig = signature.pack()
            dat.extend(bbclib_utils.to_4byte(len(sig)))
            dat.extend(sig)
        self.transaction_data = bytes(dat)
        return self.transaction_data

    def unpack(self, data):
        """Unpack into this object

        Args:
            data (bytes): packed binary data
        Returns:
            bool: True if successful
        """
        self.transaction_data = data[:]
        ptr = 0
        data_size = len(data)
        try:
            ptr, self.version = bbclib_utils.get_n_byte_int(ptr, 4, data)
            ptr, self.timestamp = bbclib_utils.get_n_byte_int(ptr, 8, data)
            if self.version != 0:
                ptr, self.id_length = bbclib_utils.get_n_byte_int(ptr, 2, data)
            ptr, evt_num = bbclib_utils.get_n_byte_int(ptr, 2, data)
            self.events = []
            for i in range(evt_num):
                ptr, size = bbclib_utils.get_n_byte_int(ptr, 4, data)
                ptr, evtdata = bbclib_utils.get_n_bytes(ptr, size, data)
                evt = BBcEvent(id_length=self.id_length)
                if not evt.unpack(evtdata):
                    return False
                self.events.append(evt)
                if ptr >= data_size:
                    return False
                self.asset_group_ids[evt.asset.asset_id] = evt.asset_group_id

            ptr, ref_num = bbclib_utils.get_n_byte_int(ptr, 2, data)
            self.references = []
            for i in range(ref_num):
                ptr, size = bbclib_utils.get_n_byte_int(ptr, 4, data)
                ptr, refdata = bbclib_utils.get_n_bytes(ptr, size, data)
                refe = BBcReference(None, self, id_length=self.id_length)
                if not refe.unpack(refdata):
                    return False
                self.references.append(refe)
                if ptr >= data_size:
                    return False

            ptr, rtn_num = bbclib_utils.get_n_byte_int(ptr, 2, data)
            self.relations = []
            for i in range(rtn_num):
                ptr, size = bbclib_utils.get_n_byte_int(ptr, 4, data)
                ptr, rtndata = bbclib_utils.get_n_bytes(ptr, size, data)
                rtn = BBcRelation(id_length=self.id_length)
                if not rtn.unpack(rtndata):
                    return False
                self.relations.append(rtn)
                if ptr >= data_size:
                    return False
                self.asset_group_ids[rtn.asset.asset_id] = rtn.asset_group_id

            ptr, witness_num = bbclib_utils.get_n_byte_int(ptr, 2, data)
            if witness_num == 0:
                self.witness = None
            else:
                ptr, size = bbclib_utils.get_n_byte_int(ptr, 4, data)
                ptr, witnessdata = bbclib_utils.get_n_bytes(ptr, size, data)
                self.witness = BBcWitness(id_length=self.id_length)
                self.witness.transaction = self
                if not self.witness.unpack(witnessdata):
                    return False

            ptr, cross_num = bbclib_utils.get_n_byte_int(ptr, 2, data)
            if cross_num == 0:
                self.cross_ref = None
            else:
                ptr, size = bbclib_utils.get_n_byte_int(ptr, 4, data)
                ptr, crossdata = bbclib_utils.get_n_bytes(ptr, size, data)
                self.cross_ref = BBcCrossRef()
                if not self.cross_ref.unpack(crossdata):
                    return False

            ptr, sig_num = bbclib_utils.get_n_byte_int(ptr, 2, data)
            self.signatures = []
            for i in range(sig_num):
                ptr, size = bbclib_utils.get_n_byte_int(ptr, 4, data)
                sig = BBcSignature()
                if size > 4:
                    ptr, sigdata = bbclib_utils.get_n_bytes(ptr, size, data)
                    if not sig.unpack(sigdata):
                        return False
                self.signatures.append(sig)
                if ptr > data_size:
                    return False
            self.digest()
        except Exception as e:
            print("Transaction data unpack: %s" % e)
            print(traceback.format_exc())
            return False
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
        bbclib._reset_error()
        if keypair is None:
            if len(private_key) != 32 or len(public_key) <= 32:
                bbclib._set_error(code=bbc_error.EBADKEYPAIR, txt="Bad private_key/public_key (must be in bytes format)")
                return None
            keypair = KeyPair(curvetype=key_type, privkey=private_key, pubkey=public_key)
            if keypair is None:
                bbclib._set_error(code=bbc_error.EBADKEYPAIR, txt="Bad private_key/public_key")
                return None

        sig = BBcSignature(key_type=keypair.curvetype)
        s = keypair.sign(self.digest())
        if s is None:
            bbclib._set_error(code=bbc_error.EOTHER, txt="sig_type %d is not supported" % keypair.curvetype)
            return None
        sig.add(signature=s, pubkey=keypair.public_key)
        return sig
