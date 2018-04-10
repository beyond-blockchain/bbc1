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
import binascii
import hashlib
import sys
import time

sys.path.append("../../")

from bbc1.app import bbc_app, app_support_lib
from bbc1.common import bbclib, logger
from bbc1.common.bbc_error import *
from bbc1.common.message_key_types import KeyType
from bbc1.core.bbc_config import DEFAULT_CORE_PORT


NAME_OF_DB = 'id_db'


id_pubkey_table_definition = [
    ["user_id", "BLOB"],
    ["public_key", "BLOB"],
    ["tx_id_added", "BLOB"],
    ["tx_id_removed", "BLOB"],
]


IDX_USER_ID       = 0
IDX_PUBLIC_KEY    = 1
IDX_TX_ID_ADDED   = 2
IDX_TX_ID_REMOVED = 3


default_namespace_id = bbclib.get_new_id(".default_namespace",
                                            include_timestamp=False)
id_publickey_map_user_id = bbclib.get_new_id(".id_publickey_map",
                                            include_timestamp=False)


class Directive:

    CMD_NONE    = 0
    CMD_ADD     = 1
    CMD_REMOVE  = 2
    CMD_REPLACE = 3


    def __init__(self, command, public_keys):
        self.command = command
        self.public_keys = public_keys


    @staticmethod
    def from_serialized_data(ptr, data):
        if ptr >= len(data):
            return ptr, None
        try:
            ptr, command = bbclib.get_n_byte_int(ptr, 1, data)
            ptr, num_pubkeys = bbclib.get_n_byte_int(ptr, 2, data)
            public_keys = []
            for i in range(num_pubkeys):
                ptr, size = bbclib.get_n_byte_int(ptr, 2, data)
                ptr, pubkey = bbclib.get_n_bytes(ptr, size, data)
                public_keys.append(bytes(pubkey))
        except:
            raise
        return ptr, Directive(command, public_keys)


    def serialize(self):
        dat = bytearray(bbclib.to_1byte(self.command))
        dat.extend(bbclib.to_2byte(len(self.public_keys)))
        for i in range(len(self.public_keys)):
            dat.extend(bbclib.to_2byte(len(self.public_keys[i])))
            dat.extend(self.public_keys[i])
        return bytes(dat)


class BBcIdPublickeyMap:

    """
    Domain must have been registered to the core prior to creating this object.
    """
    def __init__(self, domain_id, namespace_id=default_namespace_id,
            port=DEFAULT_CORE_PORT, logname="-", loglevel="none"):
        self.logger = logger.get_logger(key="id_lib", level=loglevel,
                logname=logname) # FIXME: use the logger
        self.domain_id = domain_id
        self.namespace_id = namespace_id
        self.__app = bbc_app.BBcAppClient(port=DEFAULT_CORE_PORT,
                loglevel=loglevel)
        self.__app.set_user_id(id_publickey_map_user_id)
        self.__app.set_domain_id(domain_id)
        self.__app.set_callback(bbc_app.Callback())
        ret = self.__app.register_to_core()
        assert ret
        self.__db = app_support_lib.Database()
        self.__db.setup_db(domain_id, NAME_OF_DB)
        self.__db.create_table_in_db(domain_id, NAME_OF_DB,
                'id_pubkey_table',
                id_pubkey_table_definition,
                indices=[0, 1])


    def create_user_id(self, num_pubkeys=1, public_keys=None):

        keypair = bbclib.KeyPair()
        user_id = hashlib.sha256(bytes(keypair.public_key)).digest()
        # FIXME: detect collision

        initial_keypairs = []
        if public_keys is None:
            public_keys = []
            for i in range(num_pubkeys):
                new_keypair = bbclib.KeyPair()
                initial_keypairs.append(new_keypair)
                public_keys.append(new_keypair.public_key)

        directive = Directive(Directive.CMD_REPLACE, public_keys)

        tx = bbclib.make_transaction_for_base_asset(
                asset_group_id=self.namespace_id, event_num=1)

        tx.events[0].asset.add(user_id=user_id,
                asset_body=directive.serialize())
        tx.events[0].add(mandatory_approver=user_id)
        tx.add(witness=bbclib.BBcWitness())
        tx.witness.add_witness(user_id)
        self.sign_and_insert(tx, user_id, keypair)
        return (user_id, initial_keypairs)


    def get_mapped_public_keys(self, user_id, eval_time=None):
        tx = self.__update_local_database(user_id)
        ret = self.__read_maps_by_user_id(user_id)
        public_keys = []
        for r in ret:
            public_keys.append(r[IDX_PUBLIC_KEY])

        if eval_time is None:
            eval_time = int(time.time())

        while tx.timestamp > eval_time:
            self.__undo_public_keys(public_keys, tx.transaction_id, user_id)
            tx = self.__get_referred_transaction(tx)
            if tx is None:
                break

        return public_keys


    def is_mapped(self, user_id, public_key, eval_time=None):
        tx = self.__update_local_database(user_id)
        ret = self.__read_maps_by_public_key(public_key)
        user_ids = []
        for r in ret:
            user_ids.append(r[IDX_USER_ID])

        if eval_time is None:
            eval_time = int(time.time())

        while tx.timestamp > eval_time:
            self.__undo_user_ids(user_ids, tx.transaction_id, user_id,
                    public_key)
            tx = self.__get_referred_transaction(tx)
            if tx is None:
                break

        return user_id in user_ids


    def sign(self, transaction, user_id, keypair):
        sig = transaction.sign(key_type=bbclib.KeyType.ECDSA_SECP256k1,
                private_key=keypair.private_key,
                public_key=keypair.public_key)
        transaction.add_signature(user_id=user_id, signature=sig)


    def sign_and_insert(self, transaction, user_id, keypair):
        self.sign(transaction, user_id, keypair)
        transaction.digest()

        if self.verify_signers(transaction, self.namespace_id, user_id,
                id_mapping=True) == False:
            raise RuntimeError('signers not verified')

        ret = self.__app.insert_transaction(transaction)
        assert ret
        res = self.__app.callback.sync_by_queryid(ret)
        if res[KeyType.status] < ESUCCESS:
            raise RuntimeError(res[KeyType.reason].decode())

        event = self.__get_event(transaction, user_id)
        ptr = 0
        while True:
            ptr, directive = Directive.from_serialized_data(ptr,
                    event.asset.asset_body)
            if directive is None:
                break
            self.__apply(transaction.transaction_id, user_id, directive)


    def update(self, user_id, public_keys_to_add=None,
            public_keys_to_remove=None, public_keys_to_replace=None,
            keypair=None):
        reftx = self.__update_local_database(user_id)

        dat = bytearray(b'')
        if public_keys_to_add is not None:
            dat.extend(Directive(Directive.CMD_ADD,
                    public_keys_to_add).serialize())
        if public_keys_to_remove is not None:
            dat.extend(Directive(Directive.CMD_REMOVE,
                    public_keys_to_remove).serialize())
        if public_keys_to_replace is not None:
            dat.extend(Directive(Directive.CMD_REPLACE,
                    public_keys_to_replace).serialize())

        tx = bbclib.make_transaction_for_base_asset(
                asset_group_id=self.namespace_id, event_num=1)
        tx.events[0].asset.add(user_id=user_id, asset_body=dat)
        tx.events[0].add(mandatory_approver=user_id)
        bbclib.add_reference_to_transaction(self.namespace_id, tx, reftx, 0)

        if keypair is None:
            return tx

        return self.sign_and_insert(tx, user_id, keypair)


    def verify_signers(self, transaction, asset_group_id, user_id=None,
            id_mapping=False):
        if len(transaction.references) <= 0:
            try:
                idx = transaction.witness.user_ids.index(user_id)
                idx = transaction.witness.sig_indices[idx]
                if id_mapping:
                    if user_id == hashlib.sha256(
                        bytes(transaction.signatures[idx].pubkey)
                    ).digest():
                        return True
                else:
                    if self.is_mapped(user_id,
                            transaction.signatures[idx].pubkey,
                            transaction.timestamp):
                        return True
            except:
                return False
            return False

        else:
            for ref in transaction.references:
                reftx = self.__get_transaction(ref.transaction_id)
                event = reftx.events[ref.event_index_in_ref]
                if event.asset_group_id != asset_group_id:
                    continue
                for approver in event.mandatory_approvers:
                    signed = False
                    for i in ref.sig_indices:
                        if self.is_mapped(approver,
                                transaction.signatures[i].pubkey,
                                transaction.timestamp):
                            signed = True
                            break
                    if signed == False:
                        return False
                count = 0
                for approver in event.option_approvers:
                    for i in ref.sig_indices:
                        if self.is_mapped(approver,
                                transaction.signatures[i].pubkey,
                                transaction.timestamp):
                            count += 1
                            break
                if count < event.option_approver_num_numerator:
                    return False
            return True


    def __apply(self, tx_id, user_id, directive):
        if directive.command == Directive.CMD_ADD:
            self.__write_maps(tx_id, user_id, directive.public_keys)
        elif directive.command == Directive.CMD_REMOVE:
            self.__delete_maps(tx_id, user_id, directive.public_keys)
        elif directive.command == Directive.CMD_REPLACE:
            self.__delete_maps(tx_id, user_id)
            self.__write_maps(tx_id, user_id, directive.public_keys)


    '''
    This private method is for testing purposes only.
    '''
    def __clear_local_database(self, user_id):
        return self.__db.exec_sql(
            self.domain_id,
            NAME_OF_DB,
            'delete from id_pubkey_table where user_id=?',
            user_id
        )


    def __delete_maps(self, tx_id, user_id, public_keys=None):
        if public_keys is None:
            self.__db.exec_sql(
                self.domain_id,
                NAME_OF_DB,
                ('update id_pubkey_table set tx_id_removed=? where '
                 'user_id=? and tx_id_removed is NULL'),
                tx_id,
                user_id
            )
        else:
            for pubkey in public_keys:
                self.__db.exec_sql(
                    self.domain_id,
                    NAME_OF_DB,
                    ('update id_pubkey_table set tx_id_removed=? where '
                     'user_id=? and public_key=? and tx_id_removed is NULL'),
                    tx_id,
                    user_id,
                    pubkey
                )


    def __get_event(self, transaction, user_id):
        for event in transaction.events:
            if event.asset_group_id == self.namespace_id and \
                    event.asset is not None and event.asset.user_id == user_id:
                return event
        return None


    def __get_referred_transaction(self, tx):
        if len(tx.references) <= 0:
            return None
        return self.__get_transaction(tx.references[0].transaction_id)


    def __get_transaction(self, tx_id):
        ret = self.__app.search_transaction(tx_id)
        res = self.__app.callback.sync_by_queryid(ret)
        if res[KeyType.status] < ESUCCESS:
            raise RuntimeError(res[KeyType.reason].decode())
        return bbclib.recover_transaction_object_from_rawdata(
                res[KeyType.transaction_data])


    def __read_maps_by_public_key(self, public_key):
        return self.__db.exec_sql(
            self.domain_id,
            NAME_OF_DB,
            ('select * from id_pubkey_table where public_key=? and '
             'tx_id_removed is NULL'),
            public_key
        )


    def __read_maps_by_user_id(self, user_id):
        return self.__db.exec_sql(
            self.domain_id,
            NAME_OF_DB,
            ('select * from id_pubkey_table where user_id=? and '
             'tx_id_removed is NULL'),
            user_id
        )


    def __undo_public_keys(self, public_keys, tx_id, user_id):
        ret = self.__db.exec_sql(
            self.domain_id,
            NAME_OF_DB,
            ('select public_key from id_pubkey_table where '
             'user_id=? and tx_id_added=?'),
            user_id,
            tx_id
        )
        for r in ret:
            public_keys.remove(r[0])
        ret = self.__db.exec_sql(
            self.domain_id,
            NAME_OF_DB,
            ('select public_key from id_pubkey_table where '
             'user_id=? and tx_id_removed=?'),
            user_id,
            tx_id
        )
        for r in ret:
            public_keys.append(r[0])


    def __undo_user_ids(self, user_ids, tx_id, user_id, public_key):
        ret = self.__db.exec_sql(
            self.domain_id,
            NAME_OF_DB,
            ('select user_id from id_pubkey_table where '
             'public_key=? and tx_id_added=?'),
            public_key,
            tx_id
        )
        for r in ret:
            user_ids.remove(r[0])
        ret = self.__db.exec_sql(
            self.domain_id,
            NAME_OF_DB,
            ('select user_id from id_pubkey_table where '
             'public_key=? and tx_id_removed=?'),
            public_key,
            tx_id
        )
        for r in ret:
            user_ids.append(r[0])


    def __update_local_database(self, user_id):
        ret = self.__app.search_transaction_with_condition(
                asset_group_id=self.namespace_id, user_id=user_id)
        res = self.__app.callback.sync_by_queryid(ret, 2) # FIXME: slow when not found
        if res is None or res[KeyType.status] < ESUCCESS:
            raise ValueError('not found')
        tx = bbclib.BBcTransaction(deserialize=res[KeyType.transactions][0])
        tx_last = tx
        tx_directives = []
        while True:
            ret = self.__db.exec_sql_fetchone(
                self.domain_id,
                NAME_OF_DB,
                ('select * from id_pubkey_table where '
                 'tx_id_added=? or tx_id_removed=?'),
                tx.transaction_id,
                tx.transaction_id
            )
            if ret is not None:
                break
            directives = []
            event = self.__get_event(tx, user_id)
            ptr = 0
            while True:
                ptr, directive = Directive.from_serialized_data(ptr,
                        event.asset.asset_body)
                if directive is None:
                    break
                directives.append(directive)
            tx_directives.append((tx.transaction_id, directives))
            tx = self.__get_referred_transaction(tx)
            if tx is None:
                break

        for (tx_id, directives) in reversed(tx_directives):
            for directive in directives:
                self.__apply(tx_id, user_id, directive)

        return tx_last


    def __write_maps(self, tx_id, user_id, public_keys):
        for pubkey in public_keys:
            self.__db.exec_sql(
                self.domain_id,
                NAME_OF_DB,
                'insert into id_pubkey_table values (?, ?, ?, ?)',
                user_id,
                pubkey,
                tx_id,
                None
            )


# end of id_lib.py
