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
import traceback
import queue
import hashlib
import os

import sys
sys.path.append("../../")

from bbc1.core import bbclib
from bbc1.core import message_key_types, logger
from bbc1.core.bbclib import MsgType
from bbc1.core.message_key_types import KeyType, PayloadType
from bbc1.core.bbc_error import *

DEFAULT_CORE_PORT = 9000
DEFAULT_P2P_PORT = 6641

MESSAGE_WITH_NO_RESPONSE = (MsgType.MESSAGE, MsgType.REGISTER, MsgType.UNREGISTER, MsgType.DOMAIN_PING,
                            MsgType.REQUEST_INSERT_NOTIFICATION, MsgType.CANCEL_INSERT_NOTIFICATION,
                            MsgType.REQUEST_REPAIR)


def _parse_one_level_list(dat):
    results = []
    count = int.from_bytes(dat[:2], 'big')
    for i in range(count):
        base = 2 + 32 * i
        results.append(dat[base:base + 32])
    return results


def _parse_two_level_dict(dat):
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
    def __init__(self, host='127.0.0.1', port=DEFAULT_CORE_PORT, multiq=True, logname="-", loglevel="none"):
        self.logger = logger.get_logger(key="bbc_app", level=loglevel, logname=logname)
        self.connection = socket.create_connection((host, port))
        self.callback = Callback(log=self.logger)
        self.callback.set_client(self)
        self.keypair = None
        self.node_keypair = None
        self.use_query_id_based_message_wait = multiq
        self.user_id = None
        self.domain_id = None
        self.query_id = (0).to_bytes(2, 'little')
        self.privatekey_for_ecdh = None
        self.aes_key_name = None
        self.is_secure_connection = False
        self.cross_ref_list = list()
        self.start_receiver_loop()

    def set_callback(self, callback_obj):
        """
        Set callback object that implements message processing functions
        :param callback_obj:
        :return:
        """
        self.callback = callback_obj
        self.callback.set_logger(self.logger)
        self.callback.set_client(self)

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

    def set_keypair(self, keypair):
        """
        Set keypair for the user
        :param keypair:
        :return:
        """
        self.keypair = keypair

    def set_node_key(self, pem_file=None):
        """
        Set node_key to this client
        :param pem_file:
        :return:
        """
        if pem_file is None:
            self.node_keypair = None
        try:
            self.node_keypair = bbclib.KeyPair()
            with open(pem_file, "r") as f:
                self.node_keypair.mk_keyobj_from_private_key_pem(f.read())
        except:
            return

    def include_admin_info(self, dat, admin_info, keypair):
        if keypair is not None:
            dat[KeyType.admin_info] = message_key_types.make_TLV_formatted_message(admin_info)
            digest = hashlib.sha256(dat[KeyType.admin_info]).digest()
            dat[KeyType.nodekey_signature] = keypair.sign(digest)
        else:
            dat.update(admin_info)

    def _make_message_structure(self, cmd):
        """
        Make a base message structure for sending to the core node
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

    def _send_msg(self, dat):
        """
        send the message to the core node
        :param dat:
        :return query_id or None:
        """
        if KeyType.domain_id not in dat or KeyType.source_user_id not in dat:
            self.logger.warn("Message must include domain_id and source_id")
            return None
        try:
            if self.is_secure_connection:
                msg = message_key_types.make_message(PayloadType.Type_encrypted_msgpack, dat, key_name=self.aes_key_name)
            else:
                msg = message_key_types.make_message(PayloadType.Type_msgpack, dat)
            self.connection.sendall(msg)
        except Exception as e:
            self.logger.error(traceback.format_exc())
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
        dat = self._make_message_structure(MsgType.REQUEST_ECDH_KEY_EXCHANGE)
        self.privatekey_for_ecdh, dat[KeyType.ecdh], self.aes_key_name = message_key_types.get_ECDH_parameters()
        dat[KeyType.nonce] = os.urandom(16)
        dat[KeyType.hint] = self.aes_key_name
        dat[KeyType.random] = os.urandom(8)
        return self._send_msg(dat)

    def domain_setup(self, domain_id, config=None):
        """
        Set up domain with the specified network module and storage (maybe used by a system administrator)
        :param domain_id:
        :param config:       in json format
        :return:
        """
        dat = self._make_message_structure(MsgType.REQUEST_SETUP_DOMAIN)
        admin_info = {
            KeyType.domain_id: domain_id,
            KeyType.random: bbclib.get_random_value(32)
        }
        if config is not None:
            admin_info[KeyType.bbc_configuration] = config
        self.include_admin_info(dat, admin_info, self.node_keypair)
        return self._send_msg(dat)

    def domain_close(self, domain_id=None):
        """
        Close domain leading to remove_domain in the core
        :param domain_id: if None, use self.domain_id
        :return:
        """
        if domain_id is None and self.domain_id is not None:
            domain_id = self.domain_id
        if domain_id is None:
            return None
        dat = self._make_message_structure(MsgType.REQUEST_CLOSE_DOMAIN)
        admin_info = {
            KeyType.domain_id: domain_id,
            KeyType.random: bbclib.get_random_value(32)
        }
        self.include_admin_info(dat, admin_info, self.node_keypair)
        return self._send_msg(dat)

    def get_node_id(self):
        """
        Get node_id of the connecting core node
        :param domain_id:
        :return:
        """
        dat = self._make_message_structure(MsgType.REQUEST_GET_NODEID)
        return self._send_msg(dat)

    def get_domain_neighborlist(self, domain_id):
        """
        Get peer list of the domain from the core node (maybe used by a system administrator)
        :param domain_id:
        :return:
        """
        dat = self._make_message_structure(MsgType.REQUEST_GET_NEIGHBORLIST)
        dat[KeyType.domain_id] = domain_id
        admin_info = {
            KeyType.random: bbclib.get_random_value(32)
        }
        self.include_admin_info(dat, admin_info, self.node_keypair)
        return self._send_msg(dat)

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
        dat = self._make_message_structure(MsgType.REQUEST_SET_STATIC_NODE)
        dat[KeyType.domain_id] = domain_id
        admin_info = {
            KeyType.node_info: [node_id, ipv4, ipv6, port]
        }
        self.include_admin_info(dat, admin_info, self.node_keypair)
        return self._send_msg(dat)

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
        dat = self._make_message_structure(MsgType.DOMAIN_PING)
        dat[KeyType.domain_id] = domain_id
        admin_info = dict()
        if ipv4 is not None and ipv4 != "0.0.0.0":
            admin_info[KeyType.ipv4_address] = ipv4
        if ipv6 is not None and ipv6 != "::":
            admin_info[KeyType.ipv6_address] = ipv6
        admin_info[KeyType.port_number] = port
        admin_info[KeyType.static_entry] = True
        self.include_admin_info(dat, admin_info, self.node_keypair)
        return self._send_msg(dat)

    def get_bbc_config(self):
        """
        Get config file of bbc_core (maybe used by a system administrator)
        :return:
        """
        dat = self._make_message_structure(MsgType.REQUEST_GET_CONFIG)
        admin_info = {
            KeyType.random: bbclib.get_random_value(32)
        }
        self.include_admin_info(dat, admin_info, self.node_keypair)
        return self._send_msg(dat)

    def notify_domain_key_update(self):
        """
        Notify update of bbc_core
        :return:
        """
        dat = self._make_message_structure(MsgType.NOTIFY_DOMAIN_KEY_UPDATE)
        admin_info = {
            KeyType.random: bbclib.get_random_value(32)
        }
        self.include_admin_info(dat, admin_info, self.node_keypair)
        return self._send_msg(dat)

    def get_domain_list(self):
        """
        Get domain_id list in bbc_core (maybe used by a system administrator)
        :return:
        """
        dat = self._make_message_structure(MsgType.REQUEST_GET_DOMAINLIST)
        admin_info = {
            KeyType.random: bbclib.get_random_value(32)
        }
        self.include_admin_info(dat, admin_info, self.node_keypair)
        return self._send_msg(dat)

    def get_user_list(self):
        """
        Get user_ids in the domain that are connecting to the core node
        :return:
        """
        dat = self._make_message_structure(MsgType.REQUEST_GET_USERS)
        admin_info = {
            KeyType.random: bbclib.get_random_value(32)
        }
        self.include_admin_info(dat, admin_info, self.node_keypair)
        return self._send_msg(dat)

    def get_forwarding_list(self):
        """
        Get forwarding_list of the domain in the core node
        :return:
        """
        dat = self._make_message_structure(MsgType.REQUEST_GET_FORWARDING_LIST)
        admin_info = {
            KeyType.random: bbclib.get_random_value(32)
        }
        self.include_admin_info(dat, admin_info, self.node_keypair)
        return self._send_msg(dat)

    def get_notification_list(self):
        """
        Get notification_list of the core node
        :return:
        """
        dat = self._make_message_structure(MsgType.REQUEST_GET_NOTIFICATION_LIST)
        admin_info = {
            KeyType.random: bbclib.get_random_value(32)
        }
        self.include_admin_info(dat, admin_info, self.node_keypair)
        return self._send_msg(dat)

    def manipulate_ledger_subsystem(self, enable=False, domain_id=None):
        """
        start/stop ledger_subsystem on the bbc_core (maybe used by a system administrator)
        :param enable: True->start, False->stop
        :param domain_id:
        :return:
        """
        dat = self._make_message_structure(MsgType.REQUEST_MANIP_LEDGER_SUBSYS)
        dat[KeyType.domain_id] = domain_id
        admin_info = {
            KeyType.ledger_subsys_manip: enable,
            KeyType.random: bbclib.get_random_value(32)
        }
        self.include_admin_info(dat, admin_info, self.node_keypair)
        return self._send_msg(dat)

    def register_to_core(self, on_multiple_nodes=False):
        """
        Register the client (user_id) to the core node. After that, the client can communicate with the core node
        :param on_multiple_nodes: True if this user_id is for multicast address
        :return:
        """
        dat = self._make_message_structure(MsgType.REGISTER)
        if on_multiple_nodes:
            dat[KeyType.on_multinodes] = True
        self._send_msg(dat)
        return True

    def unregister_from_core(self):
        """
        Unregister and disconnect from the core node
        :return:
        """
        dat = self._make_message_structure(MsgType.UNREGISTER)
        self._send_msg(dat)
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
        dat = self._make_message_structure(MsgType.REQUEST_INSERT_NOTIFICATION)
        dat[KeyType.asset_group_id] = asset_group_id
        return self._send_msg(dat)

    def cancel_insert_completion_notification(self, asset_group_id):
        """
        Cancel notification when a transaction has been inserted (as a copy of transaction)
        :param asset_group_id:
        :return:
        """
        dat = self._make_message_structure(MsgType.CANCEL_INSERT_NOTIFICATION)
        dat[KeyType.asset_group_id] = asset_group_id
        return self._send_msg(dat)

    def gather_signatures(self, tx_obj, reference_obj=None, asset_files=None, destinations=None, anycast=False):
        """
        Request to gather signatures from the specified user_ids
        :param tx_obj:
        :param reference_obj: BBcReference object
        :param asset_files: dictionary of {asset_id: file_content}
        :param destinations: list of destination user_ids
        :param anycast: True if this message is for anycasting
        :return:
        """
        if reference_obj is None and destinations is None:
            return False
        dat = self._make_message_structure(MsgType.REQUEST_GATHER_SIGNATURE)
        dat[KeyType.transaction_data] = tx_obj.serialize()
        dat[KeyType.transaction_id] = tx_obj.transaction_id
        if anycast:
            dat[KeyType.is_anycast] = True
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
        return self._send_msg(dat)

    def sendback_signature(self, dest_user_id=None, transaction_id=None, ref_index=-1, signature=None, query_id=None):
        """
        Send back the signed transaction to the source
        :param dest_user_id:
        :param transaction_id:
        :param ref_index: Which reference in transaction the signature is for
        :param signature: BBcSignature object
        :param query_id:
        :return:
        """
        dat = self._make_message_structure(MsgType.RESPONSE_SIGNATURE)
        dat[KeyType.destination_user_id] = dest_user_id
        dat[KeyType.transaction_id] = transaction_id
        dat[KeyType.ref_index] = ref_index
        dat[KeyType.signature] = signature.serialize()
        if query_id is not None:
            dat[KeyType.query_id] = query_id
        return self._send_msg(dat)

    def sendback_denial_of_sign(self, dest_user_id=None, transaction_id=None, reason_text=None, query_id=None):
        """
        Send back the denial of sign the transaction
        :param dest_user_id:
        :param transaction_id:
        :param reason_text:
        :param query_id:
        :return:
        """
        dat = self._make_message_structure(MsgType.RESPONSE_SIGNATURE)
        dat[KeyType.destination_user_id] = dest_user_id
        dat[KeyType.transaction_id] = transaction_id
        dat[KeyType.status] = EOTHER
        dat[KeyType.reason] = reason_text
        if query_id is not None:
            dat[KeyType.query_id] = query_id
        return self._send_msg(dat)

    def insert_transaction(self, tx_obj):
        """
        Request to insert a legitimate transaction
        :param tx_obj: Transaction object (not deserialized one)
        :return:
        """
        if tx_obj.transaction_id is None:
            tx_obj.digest()
        dat = self._make_message_structure(MsgType.REQUEST_INSERT)
        dat[KeyType.transaction_data] = tx_obj.serialize()
        ast = dict()
        for evt in tx_obj.events:
            if evt.asset is None:
                continue
            asset_digest, content = evt.asset.get_asset_file()
            if content is not None:
                ast[evt.asset.asset_id] = content
        for rtn in tx_obj.relations:
            if rtn.asset is None:
                continue
            asset_digest, content = rtn.asset.get_asset_file()
            if content is not None:
                ast[rtn.asset.asset_id] = content
        dat[KeyType.all_asset_files] = ast
        return self._send_msg(dat)

    def search_transaction_with_condition(self, asset_group_id=None, asset_id=None, user_id=None, count=1):
        """
        Search transaction data by asset_group_id/asset_id/user_id
        :param asset_group_id:
        :param asset_id:
        :param user_id:
        :param count:
        :return:
        """
        dat = self._make_message_structure(MsgType.REQUEST_SEARCH_WITH_CONDITIONS)
        if asset_group_id is not None:
            dat[KeyType.asset_group_id] = asset_group_id
        if asset_id is not None:
            dat[KeyType.asset_id] = asset_id
        if user_id is not None:
            dat[KeyType.user_id] = user_id
        dat[KeyType.count] = count
        return self._send_msg(dat)

    def search_transaction(self, transaction_id):
        """
        Search request for transaction_data

        :param transaction_id:
        :return:
        """
        dat = self._make_message_structure(MsgType.REQUEST_SEARCH_TRANSACTION)
        dat[KeyType.transaction_id] = transaction_id
        return self._send_msg(dat)

    def traverse_transactions(self, transaction_id, direction=1, hop_count=3):
        """
        Search request for transaction_data

        :param transaction_id:
        :param direction: 1:backforward, non-1:forward
        :param hop_count:
        :return:
        """
        dat = self._make_message_structure(MsgType.REQUEST_TRAVERSE_TRANSACTIONS)
        dat[KeyType.transaction_id] = transaction_id
        dat[KeyType.direction] = direction
        dat[KeyType.hop_count] = hop_count
        return self._send_msg(dat)

    def request_to_repair_transaction(self, transaction_id):
        """
        Request to repair compromised transaction data
        :param transaction_id:
        :return:
        """
        dat = self._make_message_structure(MsgType.REQUEST_REPAIR)
        dat[KeyType.transaction_id] = transaction_id
        return self._send_msg(dat)

    def request_to_repair_asset(self, asset_group_id, asset_id):
        """
        Request to repair compromised asset file
        :param asset_group_id:
        :param asset_id:
        :return:
        """
        dat = self._make_message_structure(MsgType.REQUEST_REPAIR)
        dat[KeyType.asset_group_id] = asset_group_id
        dat[KeyType.asset_id] = asset_id
        return self._send_msg(dat)

    def request_verify_by_cross_ref(self, transaction_id):
        """
        Request to verify the transaction by Cross_ref in transaction of outer domain
        :param transaction_id:
        :return:
        """
        dat = self._make_message_structure(MsgType.REQUEST_CROSS_REF_VERIFY)
        dat[KeyType.transaction_id] = transaction_id
        return self._send_msg(dat)

    def request_cross_ref_holders_list(self):
        """
        Request the list of transaction_ids that are registered as cross_ref in outer domains
        :return:
        """
        dat = self._make_message_structure(MsgType.REQUEST_CROSS_REF_LIST)
        # TODO: need to limit the number of entries??
        return self._send_msg(dat)

    def register_in_ledger_subsystem(self, asset_group_id, transaction_id):
        """
        Register transaction_id in the ledger_subsystem
        :param asset_group_id:
        :param transaction_id:
        :return:
        """
        dat = self._make_message_structure(MsgType.REQUEST_REGISTER_HASH_IN_SUBSYS)
        dat[KeyType.transaction_id] = transaction_id
        dat[KeyType.asset_group_id] = asset_group_id
        return self._send_msg(dat)

    def verify_in_ledger_subsystem(self, asset_group_id, transaction_id):
        """
        Verify transaction_id in the ledger_subsystem
        :param asset_group_id:
        :param transaction_id:
        :return:
        """
        dat = self._make_message_structure(MsgType.REQUEST_VERIFY_HASH_IN_SUBSYS)
        dat[KeyType.transaction_id] = transaction_id
        dat[KeyType.asset_group_id] = asset_group_id
        return self._send_msg(dat)

    def get_stats(self):
        """
        Get statistics of bbc_core
        :return:
        """
        dat = self._make_message_structure(MsgType.REQUEST_GET_STATS)
        admin_info = {
            KeyType.random: bbclib.get_random_value(32)
        }
        self.include_admin_info(dat, admin_info, self.node_keypair)
        return self._send_msg(dat)

    def send_message(self, msg, dst_user_id, is_anycast=False):
        """
        Send peer-to-peer message to the specified user_id
        :param msg:
        :param dst_user_id:
        :param is_anycast:
        :return:
        """
        dat = self._make_message_structure(MsgType.MESSAGE)
        dat[KeyType.destination_user_id] = dst_user_id
        dat[KeyType.message] = msg
        if is_anycast:
            dat[KeyType.is_anycast] = True
        return self._send_msg(dat)

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

    def include_cross_ref(self, txobj):
        """
        Include BBcCrossRef if cross_ref has been assigned to the client from other domains
        :param txobj:
        :return:
        """
        if len(self.cross_ref_list) > 0:
            txobj.add(cross_ref=self.cross_ref_list.pop(0))


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

    def get_from_queue(self, query_id, timeout=None, no_delete=False):
        msg = self.query_queue[query_id].get(timeout=timeout)
        if not no_delete:
            del self.query_queue[query_id]
        return msg

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
        elif dat[KeyType.command] == MsgType.RESPONSE_TRAVERSE_TRANSACTIONS:
            self.proc_resp_travarse_transactions(dat)
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
        elif dat[KeyType.command] == MsgType.NOTIFY_CROSS_REF:
            self.proc_notify_cross_ref(dat)
        elif dat[KeyType.command] == MsgType.MESSAGE:
            self.proc_user_message(dat)
        elif dat[KeyType.command] == MsgType.RESPONSE_CROSS_REF_VERIFY:
            self.proc_resp_verify_cross_ref(dat)
        elif dat[KeyType.command] == MsgType.RESPONSE_CROSS_REF_LIST:
            self.proc_resp_cross_ref_list(dat)
        elif dat[KeyType.command] == MsgType.RESPONSE_REGISTER_HASH_IN_SUBSYS:
            self.proc_resp_register_hash(dat)
        elif dat[KeyType.command] == MsgType.RESPONSE_VERIFY_HASH_IN_SUBSYS:
            self.proc_resp_verify_hash(dat)
        elif dat[KeyType.command] == MsgType.RESPONSE_GET_STATS:
            self.proc_resp_get_stats(dat)
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

    def sync_by_queryid(self, query_id, timeout=None, no_delete_q=False):
        """
        Wait for message with specified query_id
        :param query_id:
        :param timeout: timeout second for waiting
        :param no_delete_q: if true, queue for the query_id remains after popping a message
        :return:
        """
        try:
            if query_id not in self.query_queue:
                self.create_queue(query_id)
            return self.get_from_queue(query_id, timeout=timeout)
        except:
            return None

    def proc_notify_cross_ref(self, dat):
        cross_ref = bbclib.BBcCrossRef(dat[KeyType.cross_ref][0], dat[KeyType.cross_ref][1])
        self.client.cross_ref_list.append(cross_ref)

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

    def proc_resp_travarse_transactions(self, dat):
        self.queue.put(dat)

    def proc_user_message(self, dat):
        self.queue.put(dat)

    def proc_resp_verify_cross_ref(self, dat):
        self.queue.put(dat)

    def proc_resp_cross_ref_list(self, dat):
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
            base = 4 + i*(32+4+16+2+1+8)
            node_id = neighbor_list[base:base+32]
            ipv4 = socket.inet_ntop(socket.AF_INET, neighbor_list[base + 32:base + 36])
            ipv6 = socket.inet_ntop(socket.AF_INET6, neighbor_list[base + 36:base + 52])
            port = socket.ntohs(int.from_bytes(neighbor_list[base + 52:base + 54], 'big'))
            domain0 = True if neighbor_list[base + 54] == 0x01 else False
            updated_at = neighbor_list[base+55:base+63]
            results.append([node_id, ipv4, ipv6, port, domain0])
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
        self.queue.put(_parse_one_level_list(dat[KeyType.domain_list]))

    def proc_resp_get_userlist(self, dat):
        """
        Return list of user_ids
        :param dat:
        :return:
        """
        if KeyType.user_list not in dat:
            self.queue.put(None)
            return
        self.queue.put(_parse_one_level_list(dat[KeyType.user_list]))

    def proc_resp_get_forwardinglist(self, dat):
        if KeyType.forwarding_list not in dat:
            self.queue.put(None)
            return
        self.queue.put(_parse_two_level_dict(dat[KeyType.forwarding_list]))

    def proc_resp_get_notificationlist(self, dat):
        if KeyType.notification_list not in dat:
            self.queue.put(None)
            return
        self.queue.put(_parse_two_level_dict(dat[KeyType.notification_list]))

    def proc_resp_get_node_id(self, dat):
        if KeyType.node_id not in dat:
            self.queue.put(dat)
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
