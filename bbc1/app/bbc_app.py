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
import gevent
from gevent import monkey
monkey.patch_all()
from gevent import socket
import json
import traceback
import queue
import binascii
import hashlib
import os

import sys
sys.path.append("../../")

from bbc1.common import bbclib, message_key_types
from bbc1.common.bbclib import MsgType, StorageType
from bbc1.common.message_key_types import KeyType, PayloadType
from bbc1.common.bbc_error import *
from bbc1.common import logger

DEFAULT_CORE_PORT = 9000
DEFAULT_P2P_PORT = 6641
MAPPING_FILE = ".bbc_id_mappings"

MESSAGE_WITH_NO_RESPONSE = (MsgType.MESSAGE, MsgType.REGISTER, MsgType.UNREGISTER, MsgType.DOMAIN_PING,
                            MsgType.REQUEST_INSERT_NOTIFICATION, MsgType.CANCEL_INSERT_NOTIFICATION)


def store_id_mappings(name, asset_group_id, transaction_id=None, asset_ids=None):
    if transaction_id is None and asset_ids is None:
        return
    mapping = dict()
    asset_group_id_str = binascii.b2a_hex(asset_group_id).decode()
    if os.path.exists(MAPPING_FILE):
        with open(MAPPING_FILE, "r") as f:
            mapping = json.load(f)

    mapping.setdefault(asset_group_id_str, dict()).setdefault(name, dict())
    if transaction_id is not None:
        mapping[asset_group_id_str][name]['transaction_id'] = binascii.b2a_hex(transaction_id).decode()
    if asset_ids is not None:
        if isinstance(asset_ids, list):
            entry = []
            for ast in asset_ids:
                entry.append(binascii.b2a_hex(ast))
            mapping[asset_group_id_str][name]['asset_id'] = entry
        else:
            mapping[asset_group_id_str][name]['asset_id'] = binascii.b2a_hex(asset_ids).decode()

    with open(MAPPING_FILE, "w") as f:
        json.dump(mapping, f, indent=4)


def remove_id_mappings(name, asset_group_id):
    mapping = dict()
    asset_group_id_str = binascii.b2a_hex(asset_group_id).decode()
    if os.path.exists(MAPPING_FILE):
        with open(MAPPING_FILE, "r") as f:
            mapping = json.load(f)
    if asset_group_id_str in mapping:
        mapping[asset_group_id_str].pop(name, None)
        if len(mapping[asset_group_id_str].keys()) == 0:
            del mapping[asset_group_id_str]

    with open(MAPPING_FILE, "w") as f:
        json.dump(mapping, f, indent=4)


def get_id_from_mappings(name, asset_group_id):
    if not os.path.exists(MAPPING_FILE):
        return None
    asset_group_id_str = binascii.b2a_hex(asset_group_id).decode()
    with open(MAPPING_FILE, "r") as f:
        mapping = json.load(f)
    if mapping is None:
        return None
    if asset_group_id_str in mapping and name in mapping[asset_group_id_str]:
        result = dict()
        if 'transaction_id' in mapping[asset_group_id_str][name]:
            result['transaction_id'] = binascii.a2b_hex(mapping[asset_group_id_str][name]['transaction_id'])
        if 'asset_id' in mapping[asset_group_id_str][name]:
            if isinstance(mapping[asset_group_id_str][name]['asset_id'], list):
                entry = []
                for ast in mapping[asset_group_id_str][name]['asset_id']:
                    entry.append(binascii.a2b_hex(ast))
                result['asset_id'] = entry
            else:
                result['asset_id'] = binascii.a2b_hex(mapping[asset_group_id_str][name]['asset_id'])
        return result
    return None


def get_list_from_mappings(asset_group_id):
    if not os.path.exists(MAPPING_FILE):
        return None
    asset_group_id_str = binascii.b2a_hex(asset_group_id).decode()
    with open(MAPPING_FILE, "r") as f:
        mapping = json.load(f)
    if mapping is None:
        return None
    if asset_group_id_str in mapping:
        result  = []
        for name in mapping[asset_group_id_str]:
            result.append(name)
        return result
    return None


def parse_one_level_list(dat):
    results = []
    count = int.from_bytes(dat[:2], 'big')
    for i in range(count):
        base = 2 + 32 * i
        results.append(dat[base:base + 32])
    return results


def parse_two_level_dict(dat):
    results = dict()
    count = int.from_bytes(dat[:2], 'big')
    ptr = 2
    for i in range(count):
        first_id = dat[ptr:ptr+32]
        ptr += 32
        results[first_id] = list()
        count2 = int.from_bytes(dat[ptr:ptr+2], 'big')
        ptr += 2
        for j in range(count2):
            second_id = dat[ptr:ptr+32]
            ptr += 32
            results[first_id].append(second_id)
    return results


class BBcAppClient:
    def __init__(self, host='127.0.0.1', port=DEFAULT_CORE_PORT, logname="-", loglevel="none"):
        self.logger = logger.get_logger(key="bbc_app", level=loglevel, logname=logname)
        self.connection = socket.create_connection((host, port))
        self.callback = Callback(log=self.logger)
        self.set_client = self
        self.domain_keypair = None
        self.default_node_keypair = None
        self.use_query_id_based_message_wait = False
        self.user_id = None
        self.domain_id = None
        self.query_id = (0).to_bytes(2, 'little')
        self.privatekey_for_ecdh = None
        self.aes_key_name = None
        self.is_secure_connection = False
        self.start_receiver_loop()

    def set_callback(self, callback_obj):
        """
        Set callback object that implements message processing functions

        :param callback_obj:
        :return:
        """
        self.callback = callback_obj
        self.callback.set_logger(self.logger)

    def set_domain_id(self, domain_id):
        """
        set domain_id to this client to include it in all messages

        :param domain_id:
        :return:
        """
        self.domain_id = domain_id

    def set_user_id(self, identifier):
        """
        Set user_id of the object

        :param identifier:
        :return:
        """
        self.user_id = identifier

    def set_node_key(self, pem_file=None):
        """
        Set node_key to this client
        :param pem_file:
        :return:
        """
        if pem_file is None:
            self.default_node_keypair = None
        try:
            self.default_node_keypair = bbclib.KeyPair()
            with open(pem_file, "r") as f:
                self.default_node_keypair.mk_keyobj_from_private_key_pem(f.read())
        except:
            return

    def set_domain_key(self, pem_file=None):
        """
        Set domain_auth_key to this client
        :param pem_file:
        :return:
        """
        if pem_file is None:
            self.domain_keypair = None
        try:
            self.domain_keypair = bbclib.KeyPair()
            with open(pem_file, "r") as f:
                self.domain_keypair.mk_keyobj_from_private_key_pem(f.read())
        except:
            return

    def include_admin_info(self, dat, admin_info, keypair):
        if keypair is not None:
            dat[KeyType.domain_admin_info] = message_key_types.make_TLV_formatted_message(admin_info)
            digest = hashlib.sha256(dat[KeyType.domain_admin_info]).digest()
            dat[KeyType.domain_signature] = keypair.sign(digest)
        else:
            dat.update(admin_info)

    def make_message_structure(self, cmd):
        """
        (internal use) make a base message structure for sending to the core node

        :param cmd:
        :return:
        """
        self.query_id = ((int.from_bytes(self.query_id, 'little') + 1) % 65536).to_bytes(2, 'little')
        if cmd not in MESSAGE_WITH_NO_RESPONSE:
            if self.use_query_id_based_message_wait:
                if self.query_id not in self.callback.query_queue:
                    self.callback.create_queue(self.query_id)
        msg = {
            KeyType.command: cmd,
            KeyType.domain_id: self.domain_id,
            KeyType.source_user_id: self.user_id,
            KeyType.query_id: self.query_id,
            KeyType.status: ESUCCESS,
        }
        return msg

    def send_msg(self, dat):
        """
        (internal use) send the message to the core node

        :param dat:
        :return query_id or None:
        """
        if KeyType.domain_id not in dat or KeyType.source_user_id not in dat:
            self.logger.warn("Message must include domain_id and source_id")
            print(">>>>>1")
            return None
        try:
            if self.is_secure_connection:
                msg = message_key_types.make_message(PayloadType.Type_encrypted_msgpack, dat, key_name=self.aes_key_name)
            else:
                msg = message_key_types.make_message(PayloadType.Type_msgpack, dat)
            self.connection.sendall(msg)
        except Exception as e:
            self.logger.error(traceback.format_exc())
            print(">>>>>2",traceback.format_exc())
            return None
        return self.query_id

    def exchange_key(self):
        """
        Perform ECDH (key exchange algorithm)
        :return:
        """
        if self.domain_id is None:
            self.logger.error("Need to set domain first!")
            return None
        dat = self.make_message_structure(MsgType.REQUEST_ECDH_KEY_EXCHANGE)
        self.privatekey_for_ecdh, dat[KeyType.ecdh], self.aes_key_name = message_key_types.get_ECDH_parameters()
        dat[KeyType.nonce] = os.urandom(16)
        dat[KeyType.hint] = self.aes_key_name
        dat[KeyType.random] = os.urandom(8)
        return self.send_msg(dat)

    def domain_setup(self, domain_id, config=None):
        """
        Set up domain with the specified network module and storage (maybe used by a system administrator)

        :param domain_id:
        :param config:       in json format
        :return:
        """
        dat = self.make_message_structure(MsgType.REQUEST_SETUP_DOMAIN)
        admin_info = {
            KeyType.domain_id: domain_id,
            KeyType.random: bbclib.get_random_value(32)
        }
        if config is not None:
            admin_info[KeyType.bbc_configuration] = config
        self.include_admin_info(dat, admin_info, self.default_node_keypair)
        return self.send_msg(dat)

    def domain_close(self):
        """
        Close domain leading to remove_domain in the core
        :return:
        """
        dat = self.make_message_structure(MsgType.REQUEST_CLOSE_DOMAIN)
        admin_info = {
            KeyType.random: bbclib.get_random_value(32)
        }
        self.include_admin_info(dat, admin_info, self.domain_keypair)
        return self.send_msg(dat)

    def get_node_id(self):
        """
        Get node_id of the connecting core node

        :param domain_id:
        :return:
        """
        dat = self.make_message_structure(MsgType.REQUEST_GET_NODEID)
        return self.send_msg(dat)

    def get_domain_neighborlist(self, domain_id):
        """
        Get peer list of the domain from the core node (maybe used by a system administrator)

        :param domain_id:
        :return:
        """
        dat = self.make_message_structure(MsgType.REQUEST_GET_NEIGHBORLIST)
        dat[KeyType.domain_id] = domain_id
        admin_info = {
            KeyType.random: bbclib.get_random_value(32)
        }
        self.include_admin_info(dat, admin_info, self.domain_keypair)
        return self.send_msg(dat)

    def get_domain_peerlist(self, domain_id):
        """
        TODO: will be obsoleted in v0.10
        Get peer list of the domain from the core node (maybe used by a system administrator)

        :param domain_id:
        :return:
        """
        dat = self.make_message_structure(MsgType.REQUEST_GET_PEERLIST)
        dat[KeyType.domain_id] = domain_id
        return self.send_msg(dat)

    def set_domain_static_node(self, domain_id, node_id, ipv4, ipv6, port):
        """
        Set static node to the core node (maybe used by a system administrator)

        :param domain_id:
        :param node_id:
        :param ipv4:
        :param ipv6:
        :param port:
        :return:
        """
        dat = self.make_message_structure(MsgType.REQUEST_SET_STATIC_NODE)
        dat[KeyType.domain_id] = domain_id
        admin_info = {
            KeyType.node_info: [node_id, ipv4, ipv6, port]
        }
        self.include_admin_info(dat, admin_info, self.domain_keypair)
        return self.send_msg(dat)

    def send_domain_ping(self, domain_id, ipv4=None, ipv6=None, port=DEFAULT_P2P_PORT):
        """
        Send domain ping to notify the existence of the node (maybe used by a system administrator)

        :param domain_id:
        :param ipv4:
        :param ipv6:
        :param port:
        :return:
        """
        if ipv4 is None and ipv6 is None:
            return
        dat = self.make_message_structure(MsgType.DOMAIN_PING)
        dat[KeyType.domain_id] = domain_id
        admin_info = dict()
        if ipv4 is not None and ipv4 != "0.0.0.0":
            admin_info[KeyType.ipv4_address] = ipv4
        if ipv6 is not None and ipv6 != "::":
            admin_info[KeyType.ipv6_address] = ipv6
        admin_info[KeyType.port_number] = port
        admin_info[KeyType.static_entry] = True
        self.include_admin_info(dat, admin_info, self.domain_keypair)
        return self.send_msg(dat)

    def get_bbc_config(self):
        """
        Get config file of bbc_core (maybe used by a system administrator)

        :return:
        """
        dat = self.make_message_structure(MsgType.REQUEST_GET_CONFIG)
        admin_info = {
            KeyType.random: bbclib.get_random_value(32)
        }
        self.include_admin_info(dat, admin_info, self.default_node_keypair)
        return self.send_msg(dat)

    def get_domain_list(self):
        """
        Get domain_id list in bbc_core (maybe used by a system administrator)

        :return:
        """
        dat = self.make_message_structure(MsgType.REQUEST_GET_DOMAINLIST)
        admin_info = {
            KeyType.random: bbclib.get_random_value(32)
        }
        self.include_admin_info(dat, admin_info, self.default_node_keypair)
        return self.send_msg(dat)

    def get_user_list(self):
        """
        Get user_ids in the domain that are connecting to the core node

        :return:
        """
        dat = self.make_message_structure(MsgType.REQUEST_GET_USERS)
        admin_info = {
            KeyType.random: bbclib.get_random_value(32)
        }
        self.include_admin_info(dat, admin_info, self.domain_keypair)
        return self.send_msg(dat)

    def get_forwarding_list(self):
        """
        Get forwarding_list of the domain in the core node

        :return:
        """
        dat = self.make_message_structure(MsgType.REQUEST_GET_FORWARDING_LIST)
        admin_info = {
            KeyType.random: bbclib.get_random_value(32)
        }
        self.include_admin_info(dat, admin_info, self.domain_keypair)
        return self.send_msg(dat)

    def get_notification_list(self):
        """
        Get notification_list of the core node

        :return:
        """
        dat = self.make_message_structure(MsgType.REQUEST_GET_NOTIFICATION_LIST)
        admin_info = {
            KeyType.random: bbclib.get_random_value(32)
        }
        self.include_admin_info(dat, admin_info, self.domain_keypair)
        return self.send_msg(dat)

    def manipulate_ledger_subsystem(self, enable=False, domain_id=None):
        """
        start/stop ledger_subsystem on the bbc_core (maybe used by a system administrator)

        :param enable: True->start, False->stop
        :param domain_id: 
        :return:
        """
        dat = self.make_message_structure(MsgType.REQUEST_MANIP_LEDGER_SUBSYS)
        dat[KeyType.domain_id] = domain_id
        admin_info = {
            KeyType.ledger_subsys_manip: enable,
            KeyType.random: bbclib.get_random_value(32)
        }
        self.include_admin_info(dat, admin_info, self.domain_keypair)
        return self.send_msg(dat)

    def register_to_core(self):
        """
        Register the client (user_id) to the core node. After that, the client can communicate with the core node

        :return:
        """
        dat = self.make_message_structure(MsgType.REGISTER)
        self.send_msg(dat)
        return True

    def unregister_from_core(self):
        """
        Unregister and disconnect from the core node

        :return:
        """
        dat = self.make_message_structure(MsgType.UNREGISTER)
        self.send_msg(dat)
        if self.aes_key_name is not None:
            message_key_types.unset_cipher(self.aes_key_name)
            self.privatekey_for_ecdh = None
            self.aes_key_name = None
            self.is_secure_connection = False
        return True

    def request_insert_completion_notification(self, asset_group_id):
        """
        Request notification when a transaction has been inserted (as a copy of transaction)
        :param asset_group_id:
        :return:
        """
        dat = self.make_message_structure(MsgType.REQUEST_INSERT_NOTIFICATION)
        dat[KeyType.asset_group_id] = asset_group_id
        return self.send_msg(dat)

    def cancel_insert_completion_notification(self, asset_group_id):
        """
        Cancel notification when a transaction has been inserted (as a copy of transaction)
        :param asset_group_id:
        :return:
        """
        dat = self.make_message_structure(MsgType.CANCEL_INSERT_NOTIFICATION)
        dat[KeyType.asset_group_id] = asset_group_id
        return self.send_msg(dat)

    def get_cross_refs(self, asset_group_id=None, number=1):
        """
        Get cross_refs

        :param asset_group_id:  TODO: will be obsoleted in v0.10
        :param number:
        :return:
        """
        dat = self.make_message_structure(MsgType.REQUEST_CROSS_REF)
        dat[KeyType.count] = number
        return self.send_msg(dat)

    def gather_signatures(self, tx_obj, reference_obj=None, destinations=None, asset_files=None):
        """
        Request to gather signatures from the specified user_ids

        :param tx_obj:
        :param reference_obj: BBcReference object
        :param destinations: list of destination user_ids
        :param asset_files: dictionary of {asset_id: file_content}
        :return:
        """
        if reference_obj is None and destinations is None:
            return False
        dat = self.make_message_structure(MsgType.REQUEST_GATHER_SIGNATURE)
        dat[KeyType.transaction_data] = tx_obj.serialize()
        if reference_obj is not None:
            dat[KeyType.destination_user_ids] = reference_obj.get_destinations()
            referred_transactions = dict()
            referred_transactions.update(reference_obj.get_referred_transaction())
            if len(referred_transactions) > 0:
                dat[KeyType.transactions] = referred_transactions
        elif destinations is not None:
            dat[KeyType.destination_user_ids] = destinations
        if isinstance(asset_files, dict):
            dat[KeyType.all_asset_files] = asset_files
        return self.send_msg(dat)

    def sendback_signature(self, dst, ref_index, sig, query_id=None):
        """
        Send back the signed transaction to the source

        :param dst:
        :param ref_index: Which reference in transaction the signature is for
        :param sig:
        :param query_id:
        :return:
        """
        dat = self.make_message_structure(MsgType.RESPONSE_SIGNATURE)
        dat[KeyType.destination_user_id] = dst
        dat[KeyType.ref_index] = ref_index
        dat[KeyType.signature] = sig.serialize()
        if query_id is not None:
            dat[KeyType.query_id] = query_id
        return self.send_msg(dat)

    def sendback_denial_of_sign(self, dst, reason_text, query_id=None):
        """
        Send back the denial of sign the transaction

        :param dst:
        :param reason_text:
        :param query_id:
        :return:
        """
        dat = self.make_message_structure(MsgType.RESPONSE_SIGNATURE)
        dat[KeyType.destination_user_id] = dst
        dat[KeyType.status] = EOTHER
        dat[KeyType.reason] = reason_text
        if query_id is not None:
            dat[KeyType.query_id] = query_id
        return self.send_msg(dat)

    def insert_transaction(self, tx_obj):
        """
        Request to insert a legitimate transaction

        :param asset_group_id:
        :param tx_obj: Transaction object (not deserialized one)
        :return:
        """
        if tx_obj.transaction_id is None:
            tx_obj.digest()
        dat = self.make_message_structure(MsgType.REQUEST_INSERT)
        dat[KeyType.transaction_data] = tx_obj.serialize()
        ast = dict()
        for evt in tx_obj.events:
            if evt.asset is None:
                continue
            asset_digest, content = evt.asset.get_asset_file()
            if content is not None:
                ast[evt.asset.asset_id] = content
        dat[KeyType.all_asset_files] = ast
        return self.send_msg(dat)

    def search_transaction_with_condition(self, asset_group_id=None, asset_id=None, user_id=None, count=1):
        """
        Search transaction data by asset_group_id/asset_id/user_id
        :param asset_group_id:
        :param asset_id:
        :param user_id:
        :param count:
        :return:
        """
        dat = self.make_message_structure(MsgType.REQUEST_SEARCH_WITH_CONDITIONS)
        if asset_group_id is not None:
            dat[KeyType.asset_group_id] = asset_group_id
        if asset_id is not None:
            dat[KeyType.asset_id] = asset_id
        if user_id is not None:
            dat[KeyType.user_id] = user_id
        dat[KeyType.count] = count
        return self.send_msg(dat)

    def search_asset(self, asset_group_id, asset_id):
        """
        TODO: will be obsoleted in v0.10
        Search request for the specified asset. This would return transaction_data (and asset_file file content)

        :param asset_group_id:
        :param asset_id:
        :return:
        """
        dat = self.make_message_structure(MsgType.REQUEST_SEARCH_WITH_CONDITIONS)
        dat[KeyType.asset_group_id] = asset_group_id
        dat[KeyType.asset_id] = asset_id
        return self.send_msg(dat)

    def search_transaction(self, transaction_id):
        """
        Search request for transaction_data

        :param transaction_id:
        :return:
        """
        dat = self.make_message_structure(MsgType.REQUEST_SEARCH_TRANSACTION)
        dat[KeyType.transaction_id] = transaction_id
        return self.send_msg(dat)

    def search_transaction_by_userid(self, asset_group_id, user_id):
        """
        Search request for transaction_data by user_id
        TODO: will be obsoleted in v0.10
        :param asset_group_id:
        :param user_id: user_id of the asset owner
        :return: The transaction_data that includes asset with the specified user_id
        """
        dat = self.make_message_structure(MsgType.REQUEST_SEARCH_WITH_CONDITIONS)
        dat[KeyType.asset_group_id] = asset_group_id
        dat[KeyType.user_id] = user_id
        return self.send_msg(dat)

    def request_to_repair_transaction(self, transaction_id):
        """
        Request to repair compromised transaction data
        :param transaction_id:
        :return:
        """
        dat = self.make_message_structure(MsgType.REQUEST_REPAIR)
        dat[KeyType.transaction_id] = transaction_id
        return self.send_msg(dat)

    def register_in_ledger_subsystem(self, asset_group_id, transaction_id):
        """
        Register transaction_id in the ledger_subsystem

        :param asset_group_id:
        :param transaction_id:
        :return:
        """
        dat = self.make_message_structure(MsgType.REQUEST_REGISTER_HASH_IN_SUBSYS)
        dat[KeyType.transaction_id] = transaction_id
        dat[KeyType.asset_group_id] = asset_group_id
        return self.send_msg(dat)

    def verify_in_ledger_subsystem(self, asset_group_id, transaction_id):
        """
        Verify transaction_id in the ledger_subsystem

        :param asset_group_id:
        :param transaction_id:
        :return:
        """
        dat = self.make_message_structure(MsgType.REQUEST_VERIFY_HASH_IN_SUBSYS)
        dat[KeyType.transaction_id] = transaction_id
        dat[KeyType.asset_group_id] = asset_group_id
        return self.send_msg(dat)

    def get_stats(self):
        """
        Get statistics of bbc_core
        :return:
        """
        dat = self.make_message_structure(MsgType.REQUEST_GET_STATS)
        admin_info = {
            KeyType.random: bbclib.get_random_value(32)
        }
        self.include_admin_info(dat, admin_info, self.default_node_keypair)
        return self.send_msg(dat)

    def send_message(self, msg, dst_user_id):
        """
        Send peer-to-peer message to the specified user_id

        :param msg:
        :param dst_user_id:
        :return:
        """
        dat = self.make_message_structure(MsgType.MESSAGE)
        dat[KeyType.destination_user_id] = dst_user_id
        dat[KeyType.message] = msg
        return self.send_msg(dat)

    def start_receiver_loop(self):
        jobs = [gevent.spawn(self.receiver_loop)]
        #gevent.joinall(jobs)

    def receiver_loop(self):
        msg_parser = message_key_types.Message()
        try:
            while True:
                buf = self.connection.recv(8192)
                if len(buf) == 0:
                    break
                msg_parser.recv(buf)
                while True:
                    msg = msg_parser.parse()
                    if msg is None:
                        break
                    self.callback.dispatch(msg, msg_parser.payload_type)
        except Exception as e:
            self.logger.info("TCP disconnect: %s" % e)
            print(traceback.format_exc())
        self.connection.close()


class Callback:
    """
    Set of callback functions for processing received message
    """
    def __init__(self, log=None):
        self.logger = log
        self.client = None
        self.queue = queue.Queue()
        self.query_queue = dict()

    def set_logger(self, log):
        self.logger = log

    def set_client(self, client):
        self.client = client

    def create_queue(self, query_id):
        self.query_queue.setdefault(query_id, queue.Queue())

    def destroy_queue(self, query_id):
        self.query_queue.pop(query_id, None)

    def dispatch(self, dat, payload_type):
        #self.logger.debug("Received: %s" % dat)
        if KeyType.command not in dat:
            self.logger.warn("No command exists")
            return
        if KeyType.query_id in dat and dat[KeyType.query_id] in self.query_queue:
            self.query_queue[dat[KeyType.query_id]].put(dat)
            return

        if dat[KeyType.command] == MsgType.RESPONSE_SEARCH_TRANSACTION:
            self.proc_resp_search_transaction(dat)
        elif dat[KeyType.command] == MsgType.RESPONSE_SEARCH_WITH_CONDITIONS:
            self.proc_resp_search_with_condition(dat)
        elif dat[KeyType.command] == MsgType.RESPONSE_SEARCH_ASSET:  # TODO: will be obsoleted in v0.10
            self.proc_resp_search_with_condition(dat)
        elif dat[KeyType.command] == MsgType.RESPONSE_SEARCH_USERID: # TODO: will be obsoleted in v0.10
            self.proc_resp_search_with_condition(dat)
        elif dat[KeyType.command] == MsgType.RESPONSE_GATHER_SIGNATURE:
            self.proc_resp_gather_signature(dat)
        elif dat[KeyType.command] == MsgType.REQUEST_SIGNATURE:
            self.proc_cmd_sign_request(dat)
        elif dat[KeyType.command] == MsgType.RESPONSE_SIGNATURE:
            self.proc_resp_sign_request(dat)
        elif dat[KeyType.command] == MsgType.RESPONSE_INSERT:
            self.proc_resp_insert(dat)
        elif dat[KeyType.command] == MsgType.NOTIFY_INSERTED:
            self.proc_notify_inserted(dat)
        elif dat[KeyType.command] == MsgType.RESPONSE_CROSS_REF:
            self.proc_resp_cross_ref(dat)
        elif dat[KeyType.command] == MsgType.MESSAGE:
            self.proc_user_message(dat)
        elif dat[KeyType.command] == MsgType.RESPONSE_REGISTER_HASH_IN_SUBSYS:
            self.proc_resp_register_hash(dat)
        elif dat[KeyType.command] == MsgType.RESPONSE_VERIFY_HASH_IN_SUBSYS:
            self.proc_resp_verify_hash(dat)
        elif dat[KeyType.command] == MsgType.RESPONSE_GET_STATS:
            self.proc_resp_get_stats(dat)
        elif dat[KeyType.command] == MsgType.RESPONSE_GET_PEERLIST: # TODO: will be obsoleted in v0.10
            self.proc_resp_get_neighborlist(dat)
        elif dat[KeyType.command] == MsgType.RESPONSE_GET_NEIGHBORLIST:
            self.proc_resp_get_neighborlist(dat)
        elif dat[KeyType.command] == MsgType.RESPONSE_GET_DOMAINLIST:
            self.proc_resp_get_domainlist(dat)
        elif dat[KeyType.command] == MsgType.RESPONSE_GET_USERS:
            self.proc_resp_get_userlist(dat)
        elif dat[KeyType.command] == MsgType.RESPONSE_GET_FORWARDING_LIST:
            self.proc_resp_get_forwardinglist(dat)
        elif dat[KeyType.command] == MsgType.RESPONSE_GET_NOTIFICATION_LIST:
            self.proc_resp_get_notificationlist(dat)
        elif dat[KeyType.command] == MsgType.RESPONSE_GET_NODEID:
            self.proc_resp_get_node_id(dat)
        elif dat[KeyType.command] == MsgType.RESPONSE_GET_CONFIG:
            self.proc_resp_get_config(dat)
        elif dat[KeyType.command] == MsgType.RESPONSE_MANIP_LEDGER_SUBSYS:
            self.proc_resp_ledger_subsystem(dat)
        elif dat[KeyType.command] == MsgType.RESPONSE_SETUP_DOMAIN:
            self.proc_resp_domain_setup(dat)
        elif dat[KeyType.command] == MsgType.RESPONSE_SET_STATIC_NODE:
            self.proc_resp_set_neighbor(dat)
        elif dat[KeyType.command] == MsgType.RESPONSE_CLOSE_DOMAIN:
            self.proc_resp_domain_close(dat)
        elif dat[KeyType.command] == MsgType.RESPONSE_ECDH_KEY_EXCHANGE:
            self.proc_resp_ecdh_key_exchange(dat)
        elif dat[KeyType.command] == MsgType.RESPONSE_REPAIR:
            self.proc_resp_repair(dat)
        else:
            self.logger.warn("No method to process for command=%d" % dat[KeyType.command])

    def synchronize(self, timeout=None):
        """
        Wait for receiving message

        :param timeout: timeout second for waiting
        :return:
        """
        try:
            return self.queue.get(timeout=timeout)
        except:
            return None

    def sync_by_queryid(self, query_id, timeout=None):
        """
        Wait for message with specified query_id

        :param query_id:
        :param timeout: timeout second for waiting
        :return:
        """
        try:
            if query_id not in self.query_queue:
                self.create_queue(query_id)
            return self.query_queue[query_id].get(timeout=timeout)
        except:
            return None

    def proc_resp_cross_ref(self, dat):
        cross_refs = []
        for cross_ref in dat[KeyType.cross_refs]:
            cross = bbclib.BBcCrossRef(cross_ref[0], cross_ref[1])
            cross_refs.append(cross)
        self.queue.put(cross_refs)

    def proc_cmd_sign_request(self, dat):
        self.queue.put(dat)

    def proc_resp_sign_request(self, dat):
        self.queue.put(dat)

    def proc_resp_gather_signature(self, dat):
        if KeyType.status not in dat or dat[KeyType.status] < ESUCCESS:
            self.queue.put(dat)
            return
        sig = bbclib.recover_signature_object(dat[KeyType.signature])
        self.queue.put({KeyType.status: ESUCCESS, KeyType.result: (dat[KeyType.ref_index], dat[KeyType.source_user_id], sig)})

    def proc_resp_insert(self, dat):
        self.queue.put(dat)

    def proc_notify_inserted(self, dat):
        self.queue.put(dat)

    def proc_resp_search_with_condition(self, dat):
        self.queue.put(dat)

    def proc_resp_search_transaction(self, dat):
        self.queue.put(dat)

    def proc_user_message(self, dat):
        self.queue.put(dat)

    def proc_resp_ledger_subsystem(self, dat):
        self.queue.put(dat)

    def proc_resp_register_hash(self, dat):
        self.queue.put(dat)

    def proc_resp_verify_hash(self, dat):
        self.queue.put(dat)

    def proc_resp_domain_setup(self, dat):
        self.queue.put(dat)

    def proc_resp_domain_close(self, dat):
        self.queue.put(dat)

    def proc_resp_set_neighbor(self, dat):
        self.queue.put(dat)

    def proc_resp_get_config(self, dat):
        self.queue.put(dat)

    def proc_resp_get_neighborlist(self, dat):
        """
        Return node info

        :param dat:
        :return: list of node info (the first one is that of the connecting core)
        """
        if KeyType.neighbor_list not in dat:
            self.queue.put(None)
            return
        neighbor_list = dat[KeyType.neighbor_list]
        results = []
        count = int.from_bytes(neighbor_list[:4], 'big')
        for i in range(count):
            base = 4 + i*(32+4+16+2+8)
            node_id = neighbor_list[base:base+32]
            ipv4 = socket.inet_ntop(socket.AF_INET, neighbor_list[base + 32:base + 36])
            ipv6 = socket.inet_ntop(socket.AF_INET6, neighbor_list[base + 36:base + 52])
            port = socket.ntohs(int.from_bytes(neighbor_list[base + 52:base + 54], 'big'))
            updated_at = neighbor_list[base+54:base+62]
            results.append([node_id, ipv4, ipv6, port])
        self.queue.put(results)

    def proc_resp_get_domainlist(self, dat):
        """
        Return domain_ids

        :param dat:
        :return: list of domain_id
        """
        if KeyType.domain_list not in dat:
            self.queue.put(None)
            return
        self.queue.put(parse_one_level_list(dat[KeyType.domain_list]))

    def proc_resp_get_userlist(self, dat):
        """
        Return list of user_ids
        :param dat:
        :return:
        """
        if KeyType.user_list not in dat:
            self.queue.put(None)
            return
        self.queue.put(parse_one_level_list(dat[KeyType.user_list]))

    def proc_resp_get_forwardinglist(self, dat):
        if KeyType.forwarding_list not in dat:
            self.queue.put(None)
            return
        self.queue.put(parse_two_level_dict(dat[KeyType.forwarding_list]))

    def proc_resp_get_notificationlist(self, dat):
        if KeyType.notification_list not in dat:
            self.queue.put(None)
            return
        self.queue.put(parse_two_level_dict(dat[KeyType.notification_list]))

    def proc_resp_get_node_id(self, dat):
        if KeyType.node_id not in dat:
            self.queue.put(None)
            return
        self.queue.put(dat[KeyType.node_id])

    def proc_resp_get_stats(self, dat):
        self.queue.put(dat)

    def proc_resp_ecdh_key_exchange(self, dat):
        shared_key = message_key_types.derive_shared_key(self.client.privatekey_for_ecdh,
                                                         dat[KeyType.ecdh], dat[KeyType.random])
        message_key_types.set_cipher(shared_key, dat[KeyType.nonce], self.client.aes_key_name, dat[KeyType.hint])
        self.client.is_secure_connection = False
        self.queue.put(True)

    def proc_resp_repair(self, dat):
        self.queue.put(True)
