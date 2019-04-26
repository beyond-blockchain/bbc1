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
sys.path.append(os.path.join(current_dir, "../../.."))
from bbc1.core.libs.bbclib_config import DEFAULT_ID_LEN
from bbc1.core.libs import bbclib_utils


class BBcReference:
    """Reference part in a transaction"""
    def __init__(self, asset_group_id, transaction, ref_transaction=None, event_index_in_ref=0, id_length=DEFAULT_ID_LEN):
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
        ret =  "  asset_group_id: %s\n" % bbclib_utils.str_binary(self.asset_group_id)
        ret += "  transaction_id: %s\n" % bbclib_utils.str_binary(self.transaction_id)
        ret += "  event_index_in_ref: %d\n" % self.event_index_in_ref
        ret += "  sig_indices: %s\n" % self.sig_indices
        return ret

    def prepare_reference(self, ref_transaction):
        """Read the previous referencing transaction"""
        self.ref_transaction = ref_transaction
        try:
            evt = ref_transaction.events[self.event_index_in_ref]
            if len(self.sig_indices) == 0:
                for user in evt.mandatory_approvers:
                    self.sig_indices.append(self.transaction.get_sig_index(user))
                for i in range(evt.option_approver_num_numerator):
                    dummy_id = bbclib_utils.get_random_value(4)
                    self.option_sig_ids.append(dummy_id)
                    self.sig_indices.append(self.transaction.get_sig_index(dummy_id))
            else:
                i = 0
                for user in evt.mandatory_approvers:
                    self.transaction.set_sig_index(user, self.sig_indices[i])
                    i += 1
                for i in range(evt.option_approver_num_numerator):
                    dummy_id = bbclib_utils.get_random_value(4)
                    self.option_sig_ids.append(dummy_id)
                    self.transaction.set_sig_index(dummy_id, self.sig_indices[i])
                    i += 1
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
        elif user_id not in self.mandatory_approvers:
            return
        self.transaction.add_signature(user_id=user_id, signature=signature)

    def get_destinations(self):
        """Return the list of approvers in the referred transaction"""
        return self.mandatory_approvers+self.option_approvers

    def pack(self):
        """Pack this object

        Returns:
            bytes: packed binary data
        """
        dat = bytearray(bbclib_utils.to_bigint(self.asset_group_id, size=self.id_length))
        dat.extend(bbclib_utils.to_bigint(self.transaction_id, size=self.id_length))
        dat.extend(bbclib_utils.to_2byte(self.event_index_in_ref))
        dat.extend(bbclib_utils.to_2byte(len(self.sig_indices)))
        for i in range(len(self.sig_indices)):
            dat.extend(bbclib_utils.to_2byte(self.sig_indices[i]))
        return bytes(dat)

    def unpack(self, data):
        """unpack into this object

        Args:
            data (bytes): packed binary data
        Returns:
            bool: True if successful
        """
        ptr = 0
        data_size = len(data)
        try:
            ptr, self.asset_group_id = bbclib_utils.get_bigint(ptr, data)
            ptr, self.transaction_id = bbclib_utils.get_bigint(ptr, data)
            ptr, self.event_index_in_ref = bbclib_utils.get_n_byte_int(ptr, 2, data)
            ptr, signum = bbclib_utils.get_n_byte_int(ptr, 2, data)
            self.sig_indices = []
            for i in range(signum):
                ptr, idx = bbclib_utils.get_n_byte_int(ptr, 2, data)
                self.sig_indices.append(idx)
                if ptr > data_size:
                    return False
        except:
            return False
        return True
