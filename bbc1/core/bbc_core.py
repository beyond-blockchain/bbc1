#!/bin/sh
""":" .

exec python "$0" "$@"
"""
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
from gevent import monkey
monkey.patch_all()
from gevent.pool import Pool
from gevent.server import StreamServer
import socket as py_socket
from gevent.socket import wait_read
import gevent
import os
import signal
import hashlib
import binascii
import traceback
import json
import copy

import sys
sys.path.extend(["../../"])
from bbc1.core import bbclib
from bbc1.core.message_key_types import KeyType, to_2byte
from bbc1.core.bbclib import BBcTransaction, MsgType
from bbc1.core import bbc_network, user_message_routing, data_handler, repair_manager, message_key_types, logger
from bbc1.core import domain0_manager, query_management, bbc_stats
from bbc1.core.bbc_config import BBcConfig
from bbc1.core.data_handler import InfraMessageCategory
from bbc1.core import command
from bbc1.core.bbc_error import *

VERSION = "core version 1.0"

PID_FILE = "/tmp/bbc1.pid"
POOL_SIZE = 1000
DURATION_GIVEUP_GET = 10
GET_RETRY_COUNT = 3
INTERVAL_RETRY = 3
DEFAULT_ANYCAST_TTL = 5

ticker = query_management.get_ticker()
core_service = None
ledger_subsystem_module = None

admin_message_commands = (
    MsgType.REQUEST_GET_STATS, MsgType.REQUEST_GET_NEIGHBORLIST,
    MsgType.REQUEST_GET_CONFIG, MsgType.REQUEST_GET_DOMAINLIST,
    MsgType.REQUEST_GET_FORWARDING_LIST, MsgType.REQUEST_GET_USERS,
    MsgType.REQUEST_GET_NODEID, MsgType.REQUEST_GET_NOTIFICATION_LIST,
    MsgType.REQUEST_SETUP_DOMAIN, MsgType.REQUEST_CLOSE_DOMAIN,
    MsgType.NOTIFY_DOMAIN_KEY_UPDATE,
    MsgType.DOMAIN_PING, MsgType.REQUEST_SET_STATIC_NODE,
    MsgType.REQUEST_MANIP_LEDGER_SUBSYS
)


def activate_ledgersubsystem():
    """Load module of ledger_subsystem if installed"""
    global ledger_subsystem_module
    if ledger_subsystem_module is None:
        try:
            ledger_subsystem_module = __import__("ledger_subsystem")
        except:
            ledger_subsystem_module = None


def _make_message_structure(domain_id, cmd, dstid, qid):
    """Create a base structure of message

    Args:
        domain_id (bytes): the target domain_id
        cmd (bytes): command type in message_key_types.KeyType
        dstid (bytes): destination user_id
        qid (bytes): query_id to include in the message
    Returns:
        dict: message
    """
    return {
        KeyType.domain_id: domain_id,
        KeyType.command: cmd,
        KeyType.destination_user_id: dstid,
        KeyType.query_id: qid,
        KeyType.status: ESUCCESS,
    }


def _create_search_result(txobj_dict, asset_files_dict):
    """Create transaction search result"""
    response_info = dict()
    for txid, txobj in txobj_dict.items():
        if txid != txobj.transaction_id:
            response_info.setdefault(KeyType.compromised_transactions, list()).append(txobj.transaction_data)
            response_info.setdefault(KeyType.compromised_transaction_ids, list()).append(txid)
            continue
        txobj_is_valid, valid_assets, invalid_assets = bbclib.validate_transaction_object(txobj, asset_files_dict)
        if txobj_is_valid:
            response_info.setdefault(KeyType.transactions, list()).append(txobj.transaction_data)
        else:
            response_info.setdefault(KeyType.compromised_transactions, list()).append(txobj.transaction_data)
            response_info.setdefault(KeyType.compromised_transaction_ids, list()).append(txid)
            
        if len(valid_assets) > 0:
            response_info.setdefault(KeyType.all_asset_files, dict())
            for asgid, asid in valid_assets:
                response_info[KeyType.all_asset_files][asid] = asset_files_dict[asid]
        if len(invalid_assets) > 0:
            response_info.setdefault(KeyType.compromised_asset_files, dict())
            for asgid, asid in invalid_assets:
                response_info[KeyType.compromised_asset_files][asid] = asset_files_dict[asid]
    return response_info


class BBcCoreService:
    """Base service object of BBc-1"""
    def __init__(self, p2p_port=None, core_port=None, use_domain0=False, ip4addr=None, ip6addr=None,
                 workingdir=".bbc1", configfile=None, use_nodekey=None, use_ledger_subsystem=False,
                 default_conffile=None, loglevel="all", logname="-", server_start=True):
        self.logger = logger.get_logger(key="core", level=loglevel, logname=logname)
        self.stats = bbc_stats.BBcStats()
        self.config = BBcConfig(workingdir, configfile, default_conffile)
        conf = self.config.get_config()
        if p2p_port is not None:
            conf['client']['port'] = core_port
        else:
            core_port = conf['client']['port']
        self.node_key = None
        if use_nodekey is not None:
            if use_nodekey:
                conf['client']['use_node_key'] = True
            elif not use_nodekey:
                conf['client']['use_node_key'] = False
        if 'use_node_key' in conf['client'] and conf['client']['use_node_key']:
            self._get_node_key()
        self.logger.debug("config = %s" % conf)
        self.search_max_count = conf['search_config']['max_count']
        self.traverse_max_count = conf['search_config']['max_traverse']
        self.test_tx_obj = BBcTransaction()
        self.insert_notification_user_list = dict()
        self.networking = bbc_network.BBcNetwork(self.config, core=self, p2p_port=p2p_port,
                                                 external_ip4addr=ip4addr, external_ip6addr=ip6addr,
                                                 loglevel=loglevel, logname=logname)
        self.ledger_subsystems = dict()
        for domain_id_str in conf['domains'].keys():
            domain_id = bbclib.convert_idstring_to_bytes(domain_id_str)
            if not use_domain0 and domain_id == bbclib.domain_global_0:
                continue
            c = self.config.get_domain_config(domain_id)
            self.networking.create_domain(domain_id=domain_id, config=c)
            for nd, info in c['static_nodes'].items():
                node_id, ipv4, ipv6, port = bbclib.convert_idstring_to_bytes(nd), info[0], info[1], info[2]
                self.networking.add_neighbor(domain_id, node_id, ipv4, ipv6, port, is_static=True)
            if ('use_ledger_subsystem' in c and c['use_ledger_subsystem']) or use_ledger_subsystem:
                activate_ledgersubsystem()
                if ledger_subsystem_module is not None:
                    self.ledger_subsystems[domain_id] = ledger_subsystem_module.LedgerSubsystem(self.config,
                                                                                                networking=self.networking,
                                                                                                domain_id=domain_id,
                                                                                                loglevel=loglevel,
                                                                                                logname=logname)
                else:
                    self.logger.info("Failed to load ledger_subsystem module")

        gevent.signal(signal.SIGINT, self.quit_program)
        if server_start:
            self._start_server(core_port)

    def quit_program(self):
        """Processes when quiting program"""
        self.networking.save_all_static_node_list()
        self.config.update_config()
        os._exit(0)

    def _start_server(self, port):
        """Start TCP(v4 or v6) server"""
        pool = Pool(POOL_SIZE)
        if self.networking.ip6_address == "::":
            server = StreamServer(("0.0.0.0", port), self._handler, spawn=pool)
        else:
            server = StreamServer(("::", port), self._handler, spawn=pool)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass

    def _error_reply(self, msg=None, err_code=EINVALID_COMMAND, txt=""):
        """Create and send error reply message

        Args:
            msg (dict): message to send
            err_code (int): error code defined in bbc_error.py
            txt (str): error message
        Returns:
            bool:
        """
        msg[KeyType.status] = err_code
        msg[KeyType.reason] = txt
        domain_id = msg[KeyType.domain_id]
        if domain_id in self.networking.domains:
            self.networking.domains[domain_id]['user'].send_message_to_user(msg)
            return True
        else:
            return False

    def _handler(self, socket, address):
        """Message wait loop for a client"""
        # self.logger.debug("New connection")
        self.stats.update_stats_increment("client", "total_num", 1)
        user_info = None
        msg_parser = message_key_types.Message()
        try:
            while True:
                wait_read(socket.fileno())
                buf = socket.recv(8192)
                if len(buf) == 0:
                    break
                msg_parser.recv(buf)
                while True:
                    msg = msg_parser.parse()
                    if msg is None:
                        break
                    disconnection, new_info = self._process(socket, msg, msg_parser.payload_type)
                    if disconnection:
                        break
                    if new_info is not None:
                        user_info = new_info
        except Exception as e:
            self.logger.info("TCP disconnect: %s" % e)
            traceback.print_exc()
        self.logger.debug("closing socket")
        if user_info is not None:
            self.networking.domains[user_info[0]]['user'].unregister_user(user_info[1], socket)
        try:
            socket.shutdown(py_socket.SHUT_RDWR)
            socket.close()
        except:
            pass
        self.logger.debug("connection closed")
        self.stats.update_stats_decrement("client", "total_num", 1)

    def _get_node_key(self):
        """Get or create node key for creating a domain by bbc_app"""
        self.logger.info("The core use node_key to check signature on admin command message")
        keypath = os.path.join(self.config.working_dir, "node_key.pem")

        self.node_key = bbclib.KeyPair()
        if os.path.exists(keypath):
            try:
                with open(keypath, "r") as f:
                    self.node_key.mk_keyobj_from_private_key_pem(f.read())
                return
            except:
                pass
        self.node_key.generate()
        with open(keypath, "wb") as f:
            f.write(self.node_key.get_private_key_in_pem())
        return

    def _check_signature_by_nodekey(self, dat):
        """Verify signature in the message

        Args:
            dat (dict): received message that includes KeyType.admin command
        Returns:
            bool: True if check is successful
        """
        if self.node_key is None:
            return True
        if KeyType.admin_info not in dat:
            return False
        digest = hashlib.sha256(dat[KeyType.admin_info]).digest()
        if not self.node_key.verify(digest, dat[KeyType.nodekey_signature]):
            return False
        admin_info = message_key_types.make_dictionary_from_TLV_format(dat[KeyType.admin_info])
        dat.update(admin_info)
        return True

    def _param_check(self, param, dat):
        """Check if the param is included

        Args:
            param (bytes|list): Commands that must be included in the message
            dat (dict): received message
        Returns:
            bool: True if check is successful
        """
        if isinstance(param, list):
            for p in param:
                if p not in dat:
                    self._error_reply(msg=dat, err_code=EINVALID_COMMAND, txt="lack of mandatory params")
                    return False
        else:
            if param not in dat:
                self._error_reply(msg=dat, err_code=EINVALID_COMMAND, txt="lack of mandatory params")
                return False
        return True

    def _process(self, socket, dat, payload_type):
        """Process received message

        Args:
            socket (Socket): server socket
            dat (dict): received message
            payload_type (bytes): PayloadType value of msg
        Returns:
            bool: True if disconnection is detected
            list: return user info (domain_id, user_id) when a new user_id is coming
        """
        self.stats.update_stats_increment("client", "num_message_receive", 1)
        #self.logger.debug("process message from %s: %s" % (binascii.b2a_hex(dat[KeyType.source_user_id]), dat))
        if not self._param_check([KeyType.command, KeyType.source_user_id], dat):
            self.logger.debug("message has bad format")
            return False, None
        if dat[KeyType.command] in admin_message_commands:
            if self.node_key is None and KeyType.admin_info in dat:
                admin_info = message_key_types.make_dictionary_from_TLV_format(dat[KeyType.admin_info])
                dat.update(admin_info)
            else:
                if not self._check_signature_by_nodekey(dat):
                    self.logger.error("Illegal access to core node")
                    return False, None

        domain_id = dat.get(KeyType.domain_id, None)
        umr = None
        if domain_id is not None:
            if domain_id in self.networking.domains:
                umr = self.networking.domains[domain_id]['user']
            else:
                umr = user_message_routing.UserMessageRoutingDummy(networking=self.networking, domain_id=domain_id)

        cmd = dat[KeyType.command]
        if cmd == MsgType.REQUEST_SEARCH_TRANSACTION:
            if not self._param_check([KeyType.domain_id, KeyType.transaction_id], dat):
                self.logger.debug("REQUEST_SEARCH_TRANSACTION: bad format")
                return False, None
            retmsg = _make_message_structure(domain_id, MsgType.RESPONSE_SEARCH_TRANSACTION,
                                            dat[KeyType.source_user_id], dat[KeyType.query_id])
            txinfo = self._search_transaction_by_txid(domain_id, dat[KeyType.transaction_id])
            if txinfo is None:
                if not self._error_reply(msg=retmsg, err_code=ENOTRANSACTION, txt="Cannot find transaction"):
                    user_message_routing.direct_send_to_user(socket, retmsg)
                return False, None
            if KeyType.compromised_transaction_data in txinfo or KeyType.compromised_asset_files in txinfo:
                retmsg[KeyType.status] = EBADTRANSACTION
            retmsg.update(txinfo)
            umr.send_message_to_user(retmsg)

        elif cmd == MsgType.REQUEST_SEARCH_WITH_CONDITIONS:
            if not self._param_check([KeyType.domain_id], dat):
                self.logger.debug("REQUEST_SEARCH_WITH_CONDITIONS: bad format")
                return False, None
            retmsg = _make_message_structure(domain_id, MsgType.RESPONSE_SEARCH_WITH_CONDITIONS,
                                            dat[KeyType.source_user_id], dat[KeyType.query_id])
            txinfo = self.search_transaction_with_condition(domain_id,
                                                            asset_group_id=dat.get(KeyType.asset_group_id, None),
                                                            asset_id=dat.get(KeyType.asset_id, None),
                                                            user_id=dat.get(KeyType.user_id, None),
                                                            direction=dat.get(KeyType.direction, 0),
                                                            count=dat.get(KeyType.count, 1))
            if txinfo is None or KeyType.transactions not in txinfo:
                if not self._error_reply(msg=retmsg, err_code=ENOTRANSACTION, txt="Cannot find transaction"):
                    user_message_routing.direct_send_to_user(socket, retmsg)
            else:
                retmsg.update(txinfo)
                umr.send_message_to_user(retmsg)

        elif cmd == MsgType.REQUEST_COUNT_TRANSACTIONS:
            if not self._param_check([KeyType.domain_id], dat):
                self.logger.debug("REQUEST_COUNT_TRANSACTIONS: bad format")
                return False, None
            retmsg = _make_message_structure(domain_id, MsgType.RESPONSE_COUNT_TRANSACTIONS,
                                             dat[KeyType.source_user_id], dat[KeyType.query_id])
            count = self.count_transactions(domain_id, asset_group_id=dat.get(KeyType.asset_group_id, None),
                                            asset_id=dat.get(KeyType.asset_id, None),
                                            user_id=dat.get(KeyType.user_id, None))
            retmsg[KeyType.count] = count
            umr.send_message_to_user(retmsg)

        elif cmd == MsgType.REQUEST_TRAVERSE_TRANSACTIONS:
            if not self._param_check([KeyType.domain_id, KeyType.transaction_id,
                                     KeyType.direction, KeyType.hop_count], dat):
                self.logger.debug("REQUEST_TRAVERSE_TRANSACTIONS: bad format")
                return False, None
            retmsg = _make_message_structure(domain_id, MsgType.RESPONSE_TRAVERSE_TRANSACTIONS,
                                            dat[KeyType.source_user_id], dat[KeyType.query_id])
            retmsg[KeyType.transaction_id] = dat[KeyType.transaction_id]
            asset_group_id = dat.get(KeyType.asset_group_id, None)
            user_id = dat.get(KeyType.user_id, None)
            all_included, txtree, asset_files = self._traverse_transactions(domain_id, dat[KeyType.transaction_id],
                                                                            asset_group_id=asset_group_id,
                                                                            user_id=user_id,
                                                                            direction=dat[KeyType.direction],
                                                                            hop_count=dat[KeyType.hop_count])
            if txtree is None or len(txtree) == 0:
                if not self._error_reply(msg=retmsg, err_code=ENOTRANSACTION, txt="Cannot find transaction"):
                    user_message_routing.direct_send_to_user(socket, retmsg)
            else:
                retmsg[KeyType.transaction_tree] = txtree
                retmsg[KeyType.all_included] = all_included
                if len(asset_files) > 0:
                    retmsg[KeyType.all_asset_files] = asset_files
                umr.send_message_to_user(retmsg)

        elif cmd == MsgType.REQUEST_GATHER_SIGNATURE:
            if not self._param_check([KeyType.domain_id, KeyType.transaction_data], dat):
                self.logger.debug("REQUEST_GATHER_SIGNATURE: bad format")
                return False, None
            if not self._distribute_transaction_to_gather_signatures(dat[KeyType.domain_id], dat):
                retmsg = _make_message_structure(domain_id, MsgType.RESPONSE_GATHER_SIGNATURE,
                                                dat[KeyType.source_user_id], dat[KeyType.query_id])
                if not self._error_reply(msg=retmsg, err_code=EINVALID_COMMAND, txt="Fail to forward transaction"):
                    user_message_routing.direct_send_to_user(socket, retmsg)

        elif cmd == MsgType.REQUEST_INSERT:
            if not self._param_check([KeyType.domain_id, KeyType.transaction_data, KeyType.all_asset_files], dat):
                self.logger.debug("REQUEST_INSERT: bad format")
                return False, None
            transaction_data = dat[KeyType.transaction_data]
            asset_files = dat[KeyType.all_asset_files]
            retmsg = _make_message_structure(domain_id, MsgType.RESPONSE_INSERT,
                                            dat[KeyType.source_user_id], dat[KeyType.query_id])
            ret = self.insert_transaction(dat[KeyType.domain_id], transaction_data, asset_files)
            if isinstance(ret, str):
                if not self._error_reply(msg=retmsg, err_code=EINVALID_COMMAND, txt=ret):
                    user_message_routing.direct_send_to_user(socket, retmsg)
            else:
                retmsg.update(ret)
                umr.send_message_to_user(retmsg)

        elif cmd == MsgType.RESPONSE_SIGNATURE:
            if not self._param_check([KeyType.domain_id, KeyType.destination_user_id, KeyType.source_user_id], dat):
                self.logger.debug("RESPONSE_SIGNATURE: bad format")
                return False, None
            retmsg = _make_message_structure(domain_id, MsgType.RESPONSE_GATHER_SIGNATURE,
                                             dat[KeyType.destination_user_id], dat[KeyType.query_id])
            if KeyType.signature in dat:
                retmsg[KeyType.transaction_data_format] = dat[KeyType.transaction_data_format]
                retmsg[KeyType.signature] = dat[KeyType.signature]
                retmsg[KeyType.ref_index] = dat[KeyType.ref_index]
            elif KeyType.status not in dat:
                retmsg[KeyType.status] = EOTHER
                retmsg[KeyType.reason] = dat[KeyType.reason]
            elif dat[KeyType.status] < ESUCCESS:
                retmsg[KeyType.status] = dat[KeyType.status]
                retmsg[KeyType.reason] = dat[KeyType.reason]
            retmsg[KeyType.source_user_id] = dat[KeyType.source_user_id]
            umr.send_message_to_user(retmsg)

        elif cmd == MsgType.MESSAGE:
            if not self._param_check([KeyType.domain_id, KeyType.source_user_id, KeyType.destination_user_id], dat):
                self.logger.debug("MESSAGE: bad format")
                return False, None
            if KeyType.is_anycast in dat:
                dat[KeyType.anycast_ttl] = DEFAULT_ANYCAST_TTL
            umr.send_message_to_user(dat)

        elif cmd == MsgType.REQUEST_CROSS_REF_VERIFY:
            if not self._param_check([KeyType.domain_id, KeyType.source_user_id, KeyType.transaction_id], dat):
                self.logger.debug("REQUEST_CROSS_REF_VERIFY: bad format")
                return False, None
            dat[KeyType.command] = domain0_manager.Domain0Manager.REQUEST_VERIFY
            self.networking.send_message_to_a_domain0_manager(domain_id, dat)

        elif cmd == MsgType.REQUEST_CROSS_REF_LIST:
            if not self._param_check([KeyType.domain_id, KeyType.source_user_id], dat):
                self.logger.debug("REQUEST_CROSS_REF_LIST: bad format")
                return False, None
            retmsg = _make_message_structure(domain_id, MsgType.RESPONSE_CROSS_REF_LIST,
                                            dat[KeyType.source_user_id], dat[KeyType.query_id])
            domain_list = self.networking.domains[domain_id]['data'].search_domain_having_cross_ref()
            # domain_list = list of ["id", "transaction_id", "outer_domain_id", "txid_having_cross_ref"]
            retmsg[KeyType.transaction_id_list] = [row[1] for row in domain_list]
            umr.send_message_to_user(retmsg)

        elif cmd == MsgType.REQUEST_REGISTER_HASH_IN_SUBSYS:
            if not self._param_check([KeyType.transaction_id], dat):
                self.logger.debug("REQUEST_REGISTER_HASH_IN_SUBSYS: bad format")
                return False, None
            retmsg = _make_message_structure(domain_id, MsgType.RESPONSE_REGISTER_HASH_IN_SUBSYS,
                                             dat[KeyType.source_user_id], dat[KeyType.query_id])
            if domain_id in self.ledger_subsystems:
                transaction_id = dat[KeyType.transaction_id]
                self.ledger_subsystems[domain_id].register_transaction(transaction_id=transaction_id)
                umr.send_message_to_user(retmsg)
            else:
                self._error_reply(msg=retmsg, err_code=ENOSUBSYSTEM, txt="Ledger_subsystem is not activated")

        elif cmd == MsgType.REQUEST_VERIFY_HASH_IN_SUBSYS:
            if not self._param_check([KeyType.transaction_id], dat):
                self.logger.debug("REQUEST_REGISTER_HASH_IN_SUBSYS: bad format")
                return False, None
            retmsg = _make_message_structure(domain_id, MsgType.RESPONSE_VERIFY_HASH_IN_SUBSYS,
                                             dat[KeyType.source_user_id], dat[KeyType.query_id])
            if domain_id in self.ledger_subsystems:
                transaction_id = dat[KeyType.transaction_id]
                result = self.ledger_subsystems[domain_id].verify_transaction(transaction_id=transaction_id)
                retmsg[KeyType.merkle_tree] = result
                umr.send_message_to_user(retmsg)
            else:
                self._error_reply(msg=retmsg, err_code=ENOSUBSYSTEM, txt="Ledger_subsystem is not activated")

        elif cmd == MsgType.REGISTER:
            if domain_id is None:
                return False, None
            if not self._param_check([KeyType.domain_id, KeyType.source_user_id], dat):
                self.logger.debug("REGISTER: bad format")
                return False, None
            user_id = dat[KeyType.source_user_id]
            self.logger.debug("[%s] register_user: %s" % (binascii.b2a_hex(domain_id[:2]),
                                                          binascii.b2a_hex(user_id[:4])))
            umr.register_user(user_id, socket, on_multiple_nodes=dat.get(KeyType.on_multinodes, False))
            return False, (domain_id, user_id)

        elif cmd == MsgType.UNREGISTER:
            if umr is not None:
                umr.unregister_user(dat[KeyType.source_user_id], socket)
            return True, None

        elif cmd == MsgType.REQUEST_INSERT_NOTIFICATION:
            self._register_to_notification_list(domain_id, dat[KeyType.asset_group_id], dat[KeyType.source_user_id])

        elif cmd == MsgType.CANCEL_INSERT_NOTIFICATION:
            self.remove_from_notification_list(domain_id, dat[KeyType.asset_group_id], dat[KeyType.source_user_id])

        elif cmd == MsgType.REQUEST_GET_STATS:
            retmsg = _make_message_structure(domain_id, MsgType.RESPONSE_GET_STATS,
                                             dat[KeyType.source_user_id], dat[KeyType.query_id])
            retmsg[KeyType.stats] = copy.deepcopy(self.stats.get_stats())
            user_message_routing.direct_send_to_user(socket, retmsg)

        elif cmd == MsgType.NOTIFY_DOMAIN_KEY_UPDATE:
            if domain_id is not None:
                self.networking.get_domain_keypair(domain_id)

        elif cmd == MsgType.REQUEST_REPAIR:
            if KeyType.transaction_id in dat:
                dat[KeyType.command] = repair_manager.RepairManager.REQUEST_REPAIR_TRANSACTION
                self.networking.domains[domain_id]['repair'].put_message(dat)
            elif KeyType.asset_group_id in dat and KeyType.asset_id in dat:
                dat[KeyType.command] = repair_manager.RepairManager.REQUEST_REPAIR_ASSET_FILE
                self.networking.domains[domain_id]['repair'].put_message(dat)
            else:
                self.logger.debug("REQUEST_REPAIR: bad format")
            return False, None

        elif cmd == MsgType.REQUEST_GET_NEIGHBORLIST:
            retmsg = _make_message_structure(domain_id, MsgType.RESPONSE_GET_NEIGHBORLIST,
                                             dat[KeyType.source_user_id], dat[KeyType.query_id])
            if domain_id in self.networking.domains:
                retmsg[KeyType.domain_id] = domain_id
                retmsg[KeyType.neighbor_list] = self.networking.domains[domain_id]['topology'].make_neighbor_list()
            else:
                retmsg[KeyType.status] = False
                retmsg[KeyType.reason] = "No such domain"
            user_message_routing.direct_send_to_user(socket, retmsg)

        elif cmd == MsgType.REQUEST_GET_CONFIG:
            retmsg = _make_message_structure(domain_id, MsgType.RESPONSE_GET_CONFIG,
                                             dat[KeyType.source_user_id], dat[KeyType.query_id])
            jsondat = self.config.get_json_config()
            retmsg[KeyType.bbc_configuration] = jsondat
            user_message_routing.direct_send_to_user(socket, retmsg)

        elif cmd == MsgType.REQUEST_GET_DOMAINLIST:
            retmsg = _make_message_structure(domain_id, MsgType.RESPONSE_GET_DOMAINLIST,
                                             dat[KeyType.source_user_id], dat[KeyType.query_id])
            data = bytearray()
            data.extend(to_2byte(len(self.networking.domains)))
            for domain_id in self.networking.domains:
                data.extend(domain_id)
            retmsg[KeyType.domain_list] = bytes(data)
            user_message_routing.direct_send_to_user(socket, retmsg)

        elif cmd == MsgType.REQUEST_GET_FORWARDING_LIST:
            retmsg = _make_message_structure(domain_id, MsgType.RESPONSE_GET_FORWARDING_LIST,
                                             dat[KeyType.source_user_id], dat[KeyType.query_id])
            data = bytearray()
            data.extend(to_2byte(len(umr.forwarding_entries)))
            for user_id in umr.forwarding_entries:
                data.extend(user_id)
                data.extend(to_2byte(len(umr.forwarding_entries[user_id]['nodes'])))
                for node_id in umr.forwarding_entries[user_id]['nodes']:
                    data.extend(node_id)
            retmsg[KeyType.forwarding_list] = bytes(data)
            user_message_routing.direct_send_to_user(socket, retmsg)

        elif cmd == MsgType.REQUEST_GET_USERS:
            retmsg = _make_message_structure(domain_id, MsgType.RESPONSE_GET_USERS,
                                             dat[KeyType.source_user_id], dat[KeyType.query_id])
            data = bytearray()
            data.extend(to_2byte(len(umr.registered_users)))
            for user_id in umr.registered_users.keys():
                data.extend(user_id)
            retmsg[KeyType.user_list] = bytes(data)
            user_message_routing.direct_send_to_user(socket, retmsg)

        elif cmd == MsgType.REQUEST_GET_NODEID:
            retmsg = _make_message_structure(domain_id, MsgType.RESPONSE_GET_NODEID,
                                             dat[KeyType.source_user_id], dat[KeyType.query_id])
            data = bytearray()
            data.extend(self.networking.domains[domain_id]['topology'].my_node_id)
            retmsg[KeyType.node_id] = bytes(data)
            user_message_routing.direct_send_to_user(socket, retmsg)

        elif cmd == MsgType.REQUEST_GET_NOTIFICATION_LIST:
            retmsg = _make_message_structure(domain_id, MsgType.RESPONSE_GET_NOTIFICATION_LIST,
                                             dat[KeyType.source_user_id], dat[KeyType.query_id])
            data = bytearray()
            data.extend(to_2byte(len(self.insert_notification_user_list[domain_id])))
            for asset_group_id in self.insert_notification_user_list[domain_id].keys():
                data.extend(asset_group_id)
                data.extend(to_2byte(len(self.insert_notification_user_list[domain_id][asset_group_id])))
                for user_id in self.insert_notification_user_list[domain_id][asset_group_id]:
                    data.extend(user_id)
            retmsg[KeyType.notification_list] = bytes(data)
            user_message_routing.direct_send_to_user(socket, retmsg)

        elif cmd == MsgType.REQUEST_SETUP_DOMAIN:
            if not self._param_check([KeyType.domain_id], dat):
                self.logger.debug("REQUEST_SETUP_DOMAIN: bad format")
                return False, None
            conf = None
            if KeyType.bbc_configuration in dat:
                conf = json.loads(dat[KeyType.bbc_configuration])
            retmsg = _make_message_structure(None, MsgType.RESPONSE_SETUP_DOMAIN,
                                             dat[KeyType.source_user_id], dat[KeyType.query_id])
            retmsg[KeyType.result] = self.networking.create_domain(domain_id=domain_id, config=conf)
            if not retmsg[KeyType.result]:
                retmsg[KeyType.reason] = "Already exists"
            retmsg[KeyType.domain_id] = domain_id
            self.config.update_config()
            user_message_routing.direct_send_to_user(socket, retmsg)

        elif cmd == MsgType.REQUEST_CLOSE_DOMAIN:
            retmsg = _make_message_structure(None, MsgType.RESPONSE_CLOSE_DOMAIN,
                                             dat[KeyType.source_user_id], dat[KeyType.query_id])
            retmsg[KeyType.result] = self.networking.remove_domain(domain_id)
            if not retmsg[KeyType.result]:
                retmsg[KeyType.reason] = "No such domain"
            user_message_routing.direct_send_to_user(socket, retmsg)

        elif cmd == MsgType.REQUEST_ECDH_KEY_EXCHANGE:
            retmsg = _make_message_structure(None, MsgType.RESPONSE_ECDH_KEY_EXCHANGE,
                                            dat[KeyType.source_user_id], dat[KeyType.query_id])
            privatekey_for_ecdh, peer_pub_key_to_send, my_keyname = message_key_types.get_ECDH_parameters()
            if privatekey_for_ecdh is None:
                return False, None
            nonce = dat[KeyType.nonce]
            rand = dat[KeyType.random]
            shared_key = message_key_types.derive_shared_key(privatekey_for_ecdh, dat[KeyType.ecdh], rand)
            retmsg[KeyType.ecdh] = peer_pub_key_to_send
            retmsg[KeyType.nonce] = nonce
            retmsg[KeyType.random] = rand
            retmsg[KeyType.hint] = my_keyname
            user_message_routing.direct_send_to_user(socket, retmsg)
            message_key_types.set_cipher(shared_key, nonce, my_keyname, dat[KeyType.hint])
            umr.set_aes_name(socket, my_keyname)

        elif cmd == MsgType.DOMAIN_PING:
            if not self._param_check([KeyType.domain_id, KeyType.source_user_id, KeyType.port_number], dat):
                return False, None
            ipv4 = dat.get(KeyType.ipv4_address, None)
            ipv6 = dat.get(KeyType.ipv6_address, None)
            if ipv4 is None and ipv6 is None:
                return False, None
            port = dat[KeyType.port_number]
            self.networking.send_domain_ping(domain_id, ipv4, ipv6, port)

        elif cmd == MsgType.REQUEST_SET_STATIC_NODE:
            retmsg = _make_message_structure(domain_id, MsgType.RESPONSE_SET_STATIC_NODE,
                                             dat[KeyType.source_user_id], dat[KeyType.query_id])
            retmsg[KeyType.domain_id] = domain_id
            node_info = dat.get(KeyType.node_info, None)
            if node_info is None:
                retmsg[KeyType.result] = False
            else:
                self.networking.add_neighbor(domain_id, *node_info, is_static=True)
                self.config.update_config()
                retmsg[KeyType.result] = True
            user_message_routing.direct_send_to_user(socket, retmsg)

        elif cmd == MsgType.REQUEST_MANIP_LEDGER_SUBSYS:
            retmsg = _make_message_structure(domain_id, MsgType.RESPONSE_MANIP_LEDGER_SUBSYS,
                                             dat[KeyType.source_user_id], dat[KeyType.query_id])
            if self.ledger_subsystems[domain_id] is not None:
                if dat[KeyType.ledger_subsys_manip]:
                    self.ledger_subsystems[domain_id].enable()
                else:
                    self.ledger_subsystems[domain_id].disable()
                user_message_routing.direct_send_to_user(socket, retmsg)
            else:
                self._error_reply(msg=retmsg, err_code=ENOSUBSYSTEM, txt="Ledger_subsystem is not installed")

        else:
            self.logger.error("Bad command/response: %s" % cmd)
        return False, None

    def _register_to_notification_list(self, domain_id, asset_group_id, user_id):
        """Register user_id in insert completion notification list

        Args:
            domain_id (bytes): target domain_id
            asset_group_id (bytes): target asset_group_id of which you want to get notification about the insertion
            user_id (bytes): user_id that registers in the list
        """
        self.insert_notification_user_list.setdefault(domain_id, dict())
        self.insert_notification_user_list[domain_id].setdefault(asset_group_id, set())
        self.insert_notification_user_list[domain_id][asset_group_id].add(user_id)
        umr = self.networking.domains[domain_id]['user']
        umr.send_multicast_join(asset_group_id, permanent=True)

    def remove_from_notification_list(self, domain_id, asset_group_id, user_id):
        """Remove entry from insert completion notification list

        This method checks validation only.

        Args:
            domain_id (bytes): target domain_id
            asset_group_id (bytes): target asset_group_id of which you want to get notification about the insertion
            user_id (bytes): user_id that registers in the list
        """
        if domain_id not in self.insert_notification_user_list:
            return
        if asset_group_id is not None:
            if asset_group_id in self.insert_notification_user_list[domain_id]:
                self._remove_notification_entry(domain_id, asset_group_id, user_id)
        else:
            for asset_group_id in list(self.insert_notification_user_list[domain_id]):
                self._remove_notification_entry(domain_id, asset_group_id, user_id)

    def _remove_notification_entry(self, domain_id, asset_group_id, user_id):
        """Remove entry from insert completion notification list

        Args:
            domain_id (bytes): target domain_id
            asset_group_id (bytes): target asset_group_id of which you want to get notification about the insertion
            user_id (bytes): user_id that registers in the list
        """
        self.insert_notification_user_list[domain_id][asset_group_id].remove(user_id)
        if len(self.insert_notification_user_list[domain_id][asset_group_id]) == 0:
            self.insert_notification_user_list[domain_id].pop(asset_group_id, None)
            umr = self.networking.domains[domain_id]['user']
            umr.send_multicast_leave(asset_group_id)
        if len(self.insert_notification_user_list[domain_id]) == 0:
            self.insert_notification_user_list.pop(domain_id, None)

    def validate_transaction(self, txdata, asset_files=None):
        """Validate transaction by verifying signature

        Args:
            txdata (bytes): serialized transaction data
            asset_files (dict): dictionary of {asset_id: content} for the transaction
        Returns:
            BBcTransaction: if validation fails, None returns.
        """
        txobj = BBcTransaction()
        if not txobj.deserialize(txdata):
            self.stats.update_stats_increment("transaction", "invalid", 1)
            self.logger.error("Fail to deserialize transaction data")
            return None
        txobj.digest()

        txobj_is_valid, valid_assets, invalid_assets = bbclib.validate_transaction_object(txobj, asset_files)
        if not txobj_is_valid:
            self.stats.update_stats_increment("transaction", "invalid", 1)
        if len(invalid_assets) > 0:
            self.stats.update_stats_increment("asset_file", "invalid", 1)

        if txobj_is_valid and len(invalid_assets) == 0:
            return txobj
        else:
            return None

    def insert_transaction(self, domain_id, txdata, asset_files):
        """Insert transaction into ledger

        Args:
            domain_id (bytes): target domain_id
            txdata (bytes): serialized transaction data
            asset_files (dict): dictionary of {asset_id: content} for the transaction
        Returns:
            dict|str: inserted transaction_id or error message
        """
        self.stats.update_stats_increment("transaction", "insert_count", 1)
        if domain_id is None:
            self.stats.update_stats_increment("transaction", "insert_fail_count", 1)
            self.logger.error("No such domain")
            return "Set up the domain, first!"
        if domain_id == bbclib.domain_global_0:
            self.stats.update_stats_increment("transaction", "insert_fail_count", 1)
            self.logger.error("Insert is not allowed in domain_global_0")
            return "Insert is not allowed in domain_global_0"
        txobj = self.validate_transaction(txdata, asset_files)
        if txobj is None:
            self.stats.update_stats_increment("transaction", "insert_fail_count", 1)
            self.logger.error("Bad transaction format")
            return "Bad transaction format"
        self.logger.debug("[node:%s] insert_transaction %s" %
                          (self.networking.domains[domain_id]['name'], binascii.b2a_hex(txobj.transaction_id[:4])))

        asset_group_ids = self.networking.domains[domain_id]['data'].insert_transaction(txdata, txobj=txobj,
                                                                                        asset_files=asset_files)
        if asset_group_ids is None:
            self.stats.update_stats_increment("transaction", "insert_fail_count", 1)
            self.logger.error("[%s] Fail to insert a transaction into the ledger" % self.networking.domains[domain_id]['name'])
            return "Failed to insert a transaction into the ledger"

        self.send_inserted_notification(domain_id, asset_group_ids, txobj.transaction_id)

        return {KeyType.transaction_id: txobj.transaction_id}

    def send_inserted_notification(self, domain_id, asset_group_ids, transaction_id, only_registered_user=False):
        """Broadcast NOTIFY_INSERTED

        Args:
            domain_id (bytes): target domain_id
            asset_group_ids (list): list of asset_group_ids
            transaction_id (bytes): transaction_id that has just inserted
            only_registered_user (bool): If True, notification is not sent to other nodes
        """
        umr = self.networking.domains[domain_id]['user']
        destination_users = set()
        destination_nodes = set()
        for asset_group_id in asset_group_ids:
            if domain_id in self.insert_notification_user_list:
                if asset_group_id in self.insert_notification_user_list[domain_id]:
                    for user_id in self.insert_notification_user_list[domain_id][asset_group_id]:
                        destination_users.add(user_id)
            if not only_registered_user:
                if asset_group_id in umr.forwarding_entries:
                    for node_id in umr.forwarding_entries[asset_group_id]['nodes']:
                        destination_nodes.add(node_id)

        if len(destination_users) == 0 and len(destination_nodes) == 0:
            return
        msg = {
            KeyType.domain_id: domain_id,
            KeyType.infra_command: data_handler.DataHandler.NOTIFY_INSERTED,
            KeyType.command: MsgType.NOTIFY_INSERTED,
            KeyType.transaction_id: transaction_id,
            KeyType.asset_group_ids: list(asset_group_ids),
        }
        for user_id in destination_users:
            msg[KeyType.destination_user_id] = user_id
            if not umr.send_message_to_user(msg=msg, direct_only=True):
                self.remove_from_notification_list(domain_id, None, user_id)

        msg[KeyType.infra_msg_type] = InfraMessageCategory.CATEGORY_DATA
        for node_id in destination_nodes:   # TODO: need test (multiple asset_groups are bundled)
            msg[KeyType.destination_node_id] = node_id
            self.networking.send_message_in_network(domain_id=domain_id, msg=msg)

    def _distribute_transaction_to_gather_signatures(self, domain_id, dat):
        """Request to distribute sign_request to users

        Args:
            domain_id (bytes): target domain_id
            dat (dict): message to send
        Returns:
            bool: True
        """
        destinations = dat[KeyType.destination_user_ids]
        msg = _make_message_structure(domain_id, MsgType.REQUEST_SIGNATURE, None, dat[KeyType.query_id])
        msg[KeyType.source_user_id] = dat[KeyType.source_user_id]
        umr = self.networking.domains[domain_id]['user']
        for dst in destinations:
            if dst == dat[KeyType.source_user_id]:
                continue
            msg[KeyType.destination_user_id] = dst
            if KeyType.hint in dat:
                msg[KeyType.hint] = dat[KeyType.hint]
            msg[KeyType.transaction_data] = dat[KeyType.transaction_data]
            if KeyType.transactions in dat:
                msg[KeyType.transactions] = dat[KeyType.transactions]
            if KeyType.all_asset_files in dat:
                msg[KeyType.all_asset_files] = dat[KeyType.all_asset_files]
            umr.send_message_to_user(msg)
        return True

    def _search_transaction_by_txid(self, domain_id, transaction_id):
        """Search transaction_data by transaction_id

        Args:
            domain_id (bytes): target domain_id
            transaction_id (bytes): transaction_id to search
        Returns:
            dict: dictionary having transaction_id, serialized transaction data, asset files
        """
        self.stats.update_stats_increment("transaction", "search_count", 1)
        if domain_id is None:
            self.logger.error("No such domain")
            return None
        if transaction_id is None:
            self.logger.error("Transaction_id must not be None")
            return None

        dh = self.networking.domains[domain_id]['data']
        ret_txobj, ret_asset_files = dh.search_transaction(transaction_id=transaction_id)
        if ret_txobj is None or len(ret_txobj) == 0:
            return None

        response_info = _create_search_result(ret_txobj, ret_asset_files)
        response_info[KeyType.transaction_id] = transaction_id
        if KeyType.transactions in response_info:
            response_info[KeyType.transaction_data] = response_info[KeyType.transactions][0]
            del response_info[KeyType.transactions]
        elif KeyType.compromised_transactions in response_info:
            response_info[KeyType.compromised_transaction_data] = response_info[KeyType.compromised_transactions][0]
            del response_info[KeyType.compromised_transactions]
        return response_info

    def search_transaction_with_condition(self, domain_id, asset_group_id=None, asset_id=None, user_id=None,
                                          direction=0, count=1):
        """Search transactions that match given conditions

        When Multiple conditions are given, they are considered as AND condition.

        Args:
            domain_id (bytes): target domain_id
            asset_group_id (bytes): asset_group_id that target transactions should have
            asset_id (bytes): asset_id that target transactions should have
            user_id (bytes): user_id that target transactions should have
            direction (int): 0: descend, 1: ascend
            count (int): The maximum number of transactions to retrieve (self.search_max_count is the upper bound)
        Returns:
            dict: dictionary having transaction_id, serialized transaction data, asset files
        """
        if domain_id is None:
            self.logger.error("No such domain")
            return None

        if self.search_max_count < count:
            count = self.search_max_count

        dh = self.networking.domains[domain_id]['data']
        ret_txobj, ret_asset_files = dh.search_transaction(asset_group_id=asset_group_id, asset_id=asset_id,
                                                           user_id=user_id, direction=direction, count=count)
        if ret_txobj is None or len(ret_txobj) == 0:
            return None

        return _create_search_result(ret_txobj, ret_asset_files)

    def count_transactions(self, domain_id, asset_group_id=None, asset_id=None, user_id=None):
        """Count transactions that match given conditions

        When Multiple conditions are given, they are considered as AND condition.

        Args:
            domain_id (bytes): target domain_id
            asset_group_id (bytes): asset_group_id that target transactions should have
            asset_id (bytes): asset_id that target transactions should have
            user_id (bytes): user_id that target transactions should have
        Returns:
            int: the number of transactions
        """
        if domain_id is None:
            self.logger.error("No such domain")
            return None

        dh = self.networking.domains[domain_id]['data']
        return dh.count_transactions(asset_group_id=asset_group_id, asset_id=asset_id, user_id=user_id)

    def _traverse_transactions(self, domain_id, transaction_id, asset_group_id=None, user_id=None, direction=1, hop_count=3):
        """Get transaction tree from the specified transaction_id with given condition

        If both asset_group_id and user_id are specified, they are treated as AND condition.
        Transaction tree in the return values are in the following format:
        [ [list of serialized transactions in 1-hop from the base], [list of serialized transactions in 2-hop from the base],,,,

        Args:
            domain_id (bytes): target domain_id
            transaction_id (bytes): the base transaction_id from which traverse starts
            asset_group_id (bytes): asset_group_id that target transactions should have
            user_id (bytes): user_id that target transactions should have
            direction (int): 1:backward, non-1:forward
            hop_count (bytes): hop count to traverse (self.traverse_max_count is the upper bound)
        Returns:
            list: list of [include_all_flag, transaction tree, asset_files]
        """
        self.stats.update_stats_increment("transaction", "search_count", 1)
        if domain_id is None:
            self.logger.error("No such domain")
            return None
        if transaction_id is None:
            self.logger.error("Transaction_id must not be None")
            return None

        dh = self.networking.domains[domain_id]['data']
        txtree = list()
        asset_files = dict()

        traverse_to_past = True if direction == 1 else False
        tx_count = 0
        txids = dict()
        current_txids = [transaction_id]
        include_all_flag = True
        if hop_count > self.traverse_max_count * 2:
            hop_count = self.traverse_max_count * 2
        for i in range(hop_count):
            tx_brothers = list()
            next_txids = list()
            #print("### txcount=%d, len(current_txids)=%d" % (tx_count, len(current_txids)))
            if tx_count + len(current_txids) > self.traverse_max_count:
                include_all_flag = False
                break
            #print("[%d] current_txids:%s" % (i, [d.hex() for d in current_txids]))
            for txid in current_txids:
                if txid in txids:
                    continue
                tx_count += 1
                txids[txid] = True
                ret_txobj, ret_asset_files = dh.search_transaction(transaction_id=txid)
                if ret_txobj is None or len(ret_txobj) == 0:
                    continue
                if asset_group_id is not None or user_id is not None:
                    flag = False
                    for asgid, asset_id, uid, fileflag, filedigest in dh.get_asset_info(ret_txobj[txid]):
                        flag = True
                        if asset_group_id is not None and asgid != asset_group_id:
                            flag = False
                        if user_id is not None and uid != user_id:
                            flag = False
                        if flag:
                            break
                    if not flag:
                        continue
                tx_brothers.append(ret_txobj[txid].transaction_data)
                if len(ret_asset_files) > 0:
                    asset_files.update(ret_asset_files)

                ret = dh.search_transaction_topology(transaction_id=txid, traverse_to_past=traverse_to_past)
                #print("txid=%s: (%d) ret=%s" % (txid.hex(), len(ret), ret))
                if ret is not None:
                    for topology in ret:
                        if traverse_to_past:
                            next_txid = topology[2]
                        else:
                            next_txid = topology[1]
                        if next_txid not in txids:
                            next_txids.append(next_txid)
            if len(tx_brothers) > 0:
                txtree.append(tx_brothers)
            current_txids = next_txids

        return include_all_flag, txtree, asset_files


def daemonize(pidfile=PID_FILE):
    """Run in background"""
    pid = os.fork()
    if pid > 0:
        os._exit(0)
    os.setsid()
    pid = os.fork()
    if pid > 0:
        f2 = open(pidfile, 'w')
        f2.write(str(pid)+"\n")
        f2.close()
        os._exit(0)
    os.umask(0)


if __name__ == '__main__':
    argresult = command.parser()
    if argresult.kill:
        import subprocess
        import sys
        subprocess.call("kill `cat " + PID_FILE + "`", shell=True)
        subprocess.call("rm -f " + PID_FILE, shell=True)
        sys.exit(0)
    if argresult.daemon:
        daemonize()
    use_nodekey = None
    if argresult.no_nodekey:
        use_nodekey = False
    elif argresult.nodekey:
        use_nodekey = True
    BBcCoreService(
        p2p_port=argresult.p2pport,
        core_port=argresult.coreport,
        workingdir=argresult.workingdir,
        configfile=argresult.config,
        use_nodekey=use_nodekey,
        use_domain0=argresult.domain0,
        use_ledger_subsystem=argresult.ledgersubsystem,
        ip4addr=argresult.ip4addr,
        ip6addr=argresult.ip6addr,
        default_conffile=argresult.default_config,
        logname=argresult.log,
        loglevel=argresult.verbose_level,
    )
