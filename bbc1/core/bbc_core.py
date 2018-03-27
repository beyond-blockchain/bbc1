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

import sys
sys.path.extend(["../../"])
from bbc1.common import bbclib, message_key_types, logger
from bbc1.common.message_key_types import KeyType, to_2byte
from bbc1.common.bbclib import BBcTransaction, MsgType
from bbc1.core import bbc_network, user_message_routing, data_handler, repair_manager, query_management, bbc_stats
from bbc1.core.bbc_config import BBcConfig
from bbc1.core.data_handler import InfraMessageCategory
from bbc1.core import command
from bbc1.common.bbc_error import *

VERSION = "core version 0.9"

PID_FILE = "/tmp/bbc1.pid"
POOL_SIZE = 1000
DURATION_GIVEUP_GET = 10
GET_RETRY_COUNT = 3
INTERVAL_RETRY = 3

ticker = query_management.get_ticker()
core_service = None


def make_message_structure(domain_id, cmd, dstid, qid):
    """
    (internal use) Create a base structure of message

    :param cmd:
    :param dstid: destination_user_id
    :param qid:   query_id
    :return:
    """
    return {
        KeyType.domain_id: domain_id,
        KeyType.command: cmd,
        KeyType.destination_user_id: dstid,
        KeyType.query_id: qid,
        KeyType.status: ESUCCESS,
    }


def check_transaction_if_having_asset_file(txdata, asid):
    tx_obj = BBcTransaction()
    tx_obj.deserialize(txdata)
    for evt in tx_obj.events:
        if evt.asset.asset_id != asid:
            continue
        if evt.asset.asset_file_size > 0:
            return True
    return False


def create_search_result(txobj_dict, asset_files_dict):
    response_info = dict()
    for txid, txobj in txobj_dict.items():
        if txid != txobj.transaction_id:
            response_info.setdefault(KeyType.compromised_transactions, list()).append(txobj.transaction_data)
            continue
        txobj_is_valid, valid_assets, invalid_assets = bbclib.validate_transaction_object(txobj, asset_files_dict)
        if txobj_is_valid:
            response_info.setdefault(KeyType.transactions, list()).append(txobj.transaction_data)
        else:
            response_info.setdefault(KeyType.compromised_transactions, list()).append(txobj.transaction_data)

        if len(valid_assets) > 0:
            response_info.setdefault(KeyType.all_asset_files, dict())
            for asid in valid_assets:
                response_info[KeyType.all_asset_files][asid] = asset_files_dict[asid]
        if len(invalid_assets) > 0:
            response_info.setdefault(KeyType.compromised_asset_files, dict())
            for asid in invalid_assets:
                response_info[KeyType.compromised_asset_files][asid] = asset_files_dict[asid]
    return response_info


class BBcCoreService:
    def __init__(self, p2p_port=None, core_port=None, use_domain0=False, ip4addr=None, ip6addr=None,
                 workingdir=".bbc1", configfile=None, use_nodekey=False, use_ledger_subsystem=False,
                 loglevel="all", logname="-", server_start=True):
        self.logger = logger.get_logger(key="core", level=loglevel, logname=logname)
        self.stats = bbc_stats.BBcStats()
        self.config = BBcConfig(workingdir, configfile)
        conf = self.config.get_config()
        if p2p_port is not None:
            conf['client']['port'] = core_port
        else:
            core_port = conf['client']['port']
        self.default_node_key = None
        if use_nodekey:
            self.get_default_node_key()
        self.logger.debug("config = %s" % conf)
        self.test_tx_obj = BBcTransaction()
        self.insert_notification_user_list = dict()
        self.cross_ref_list = []
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
            if ('use_ledger_subsystem' in conf and conf['use_ledger_subsystem']) or use_ledger_subsystem:
                from bbc1.core import ledger_subsystem
                self.ledger_subsystems[domain_id] = ledger_subsystem.LedgerSubsystem(self.config,
                                                                                     networking=self.networking,
                                                                                     domain_id=domain_id,
                                                                                     loglevel=loglevel, logname=logname)
        gevent.signal(signal.SIGINT, self.quit_program)
        if server_start:
            self.start_server(core_port)

    def quit_program(self):
        self.networking.save_all_static_node_list()
        self.config.update_config()
        os._exit(0)

    def start_server(self, port):
        pool = Pool(POOL_SIZE)
        if self.networking.ip6_address == "::":
            server = StreamServer(("0.0.0.0", port), self.handler, spawn=pool)
        else:
            server = StreamServer(("::", port), self.handler, spawn=pool)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass

    def error_reply(self, msg=None, err_code=EINVALID_COMMAND, txt=""):
        msg[KeyType.status] = err_code
        msg[KeyType.reason] = txt
        domain_id = msg[KeyType.domain_id]
        if domain_id in self.networking.domains:
            self.networking.domains[domain_id][InfraMessageCategory.CATEGORY_USER].send_message_to_user(msg)
            return True
        else:
            return False

    def handler(self, socket, address):
        """
        Message wait loop

        :param socket:
        :param address:
        :return:
        """
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
                    disconnection, new_info = self.process(socket, msg, msg_parser.payload_type)
                    if disconnection:
                        break
                    if new_info is not None:
                        user_info = new_info
        except Exception as e:
            self.logger.info("TCP disconnect: %s" % e)
            traceback.print_exc()
        self.logger.debug("closing socket")
        if user_info is not None:
            self.networking.domains[user_info[0]][InfraMessageCategory.CATEGORY_USER].unregister_user(user_info[1],
                                                                                                      socket)
        try:
            socket.shutdown(py_socket.SHUT_RDWR)
            socket.close()
        except:
            pass
        self.logger.debug("connection closed")
        self.stats.update_stats_decrement("client", "total_num", 1)

    def get_default_node_key(self):
        """
        Get or create default node key for creating a domain by bbc_app
        :return:
        """
        keyconfig = self.config.get_config().get('domain_auth_key', None)
        if keyconfig is None or 'directory' not in keyconfig:
            return
        if not os.path.exists(keyconfig['directory']):
            os.makedirs(os.path.exists(keyconfig['directory']), exist_ok=True)
        keypath = os.path.join(keyconfig['directory'], "default_node_key.pem")

        self.default_node_key = bbclib.KeyPair()
        if os.path.exists(keypath):
            try:
                with open(keypath, "r") as f:
                    self.default_node_key.mk_keyobj_from_private_key_pem(f.read())
                return
            except:
                pass
        self.default_node_key.generate()
        with open(keypath, "wb") as f:
            f.write(self.default_node_key.get_private_key_in_pem())
        return

    def check_signature_by_nodekey(self, dat):
        """
        Verify signature in the message
        :param dat:
        :return:
        """
        if self.default_node_key is None:
            return True
        if KeyType.domain_admin_info not in dat:
            return False
        digest = hashlib.sha256(dat[KeyType.domain_admin_info]).digest()
        if not self.default_node_key.verify(digest, dat[KeyType.domain_signature]):
            return False
        admin_info = message_key_types.make_dictionary_from_TLV_format(dat[KeyType.domain_admin_info])
        dat.update(admin_info)
        return True

    def param_check(self, param, dat):
        """
        Check if the param is included

        :param param: string or list of strings
        :param dat:
        :return:
        """
        if isinstance(param, list):
            for p in param:
                if p not in dat:
                    self.error_reply(msg=dat, err_code=EINVALID_COMMAND, txt="lack of mandatory params")
                    return False
        else:
            if param not in dat:
                self.error_reply(msg=dat, err_code=EINVALID_COMMAND, txt="lack of mandatory params")
                return False
        return True

    def process(self, socket, dat, payload_type):
        """
        Process received message

        :param socket:
        :param dat:
        :param payload_type: PayloadType value of msg
        :return:
        """
        self.stats.update_stats_increment("client", "num_message_receive", 1)
        #self.logger.debug("process message from %s: %s" % (binascii.b2a_hex(dat[KeyType.source_user_id]), dat))
        if not self.param_check([KeyType.command, KeyType.source_user_id], dat):
            self.logger.debug("message has bad format")
            return False, None
        domain_id = dat.get(KeyType.domain_id, None)
        umr = None
        if domain_id is not None:
            if domain_id in self.networking.domains:
                umr = self.networking.domains[domain_id][InfraMessageCategory.CATEGORY_USER]
            else:
                umr = user_message_routing.UserMessageRoutingDummy(network=self.networking, domain_id=domain_id)

        cmd = dat[KeyType.command]
        if cmd == MsgType.REQUEST_SEARCH_TRANSACTION:
            if not self.param_check([KeyType.domain_id, KeyType.transaction_id], dat):
                self.logger.debug("REQUEST_SEARCH_TRANSACTION: bad format")
                return False, None
            retmsg = make_message_structure(domain_id, MsgType.RESPONSE_SEARCH_TRANSACTION,
                                            dat[KeyType.source_user_id], dat[KeyType.query_id])
            txinfo = self.search_transaction_by_txid(domain_id, dat[KeyType.transaction_id])
            if txinfo is None:
                if not self.error_reply(msg=retmsg, err_code=ENOTRANSACTION, txt="Cannot find transaction"):
                    user_message_routing.direct_send_to_user(socket, retmsg)
                return False, None
            if KeyType.compromised_transaction_data in txinfo or KeyType.compromised_asset_files in txinfo:
                retmsg[KeyType.status] = EBADTRANSACTION
            retmsg.update(txinfo)
            umr.send_message_to_user(retmsg)

        elif cmd == MsgType.REQUEST_SEARCH_WITH_CONDITIONS:
            if not self.param_check([KeyType.domain_id], dat):
                self.logger.debug("REQUEST_SEARCH_WITH_CONDITIONS: bad format")
                return False, None
            retmsg = make_message_structure(domain_id, MsgType.RESPONSE_SEARCH_WITH_CONDITIONS,
                                            dat[KeyType.source_user_id], dat[KeyType.query_id])
            txinfo = self.search_transaction_with_condition(domain_id,
                                                            asset_group_id=dat.get(KeyType.asset_group_id, None),
                                                            asset_id=dat.get(KeyType.asset_id, None),
                                                            user_id=dat.get(KeyType.user_id, None),
                                                            count=dat.get(KeyType.count, 1))
            if txinfo is None or KeyType.transactions not in txinfo:
                if not self.error_reply(msg=retmsg, err_code=ENOTRANSACTION, txt="Cannot find transaction"):
                    user_message_routing.direct_send_to_user(socket, retmsg)
            else:
                retmsg.update(txinfo)
                umr.send_message_to_user(retmsg)

        # --- TODO: will be obsoleted in v0.10
        elif cmd == MsgType.REQUEST_SEARCH_USERID:
            if not self.param_check([KeyType.domain_id, KeyType.asset_group_id, KeyType.user_id], dat):
                self.logger.debug("REQUEST_SEARCH_USERID: bad format")
                return False, None
            retmsg = make_message_structure(domain_id, MsgType.RESPONSE_SEARCH_USERID,
                                            dat[KeyType.source_user_id], dat[KeyType.query_id])
            txinfo = self.search_transaction_with_condition(domain_id, asset_group_id=dat[KeyType.asset_group_id],
                                                            user_id=dat[KeyType.user_id])
            if txinfo is None:
                if not self.error_reply(msg=retmsg, err_code=ENOTRANSACTION, txt="Cannot find transaction"):
                    user_message_routing.direct_send_to_user(socket, retmsg)
            else:
                retmsg.update(txinfo)
                umr.send_message_to_user(retmsg)

        # --- TODO: will be obsoleted in v0.10
        elif cmd == MsgType.REQUEST_SEARCH_ASSET:
            if not self.param_check([KeyType.domain_id, KeyType.asset_group_id, KeyType.asset_id], dat):
                self.logger.debug("REQUEST_SEARCH_ASSET: bad format")
                return False, None
            retmsg = make_message_structure(domain_id, MsgType.RESPONSE_SEARCH_ASSET,
                                            dat[KeyType.source_user_id], dat[KeyType.query_id])
            retmsg[KeyType.asset_group_id] = dat[KeyType.asset_group_id]
            txinfo = self.search_transaction_with_condition(domain_id, asset_group_id=dat[KeyType.asset_group_id],
                                                            asset_id=dat[KeyType.asset_id])
            if txinfo is None:
                if not self.error_reply(msg=retmsg, err_code=ENOTRANSACTION, txt="Cannot find transaction"):
                    user_message_routing.direct_send_to_user(socket, retmsg)
            else:
                retmsg.update(txinfo)
                umr.send_message_to_user(retmsg)

        elif cmd == MsgType.REQUEST_GATHER_SIGNATURE:
            if not self.param_check([KeyType.domain_id, KeyType.transaction_data], dat):
                self.logger.debug("REQUEST_GATHER_SIGNATURE: bad format")
                return False, None
            if not self.distribute_transaction_to_gather_signatures(dat[KeyType.domain_id], dat):
                retmsg = make_message_structure(domain_id, MsgType.RESPONSE_GATHER_SIGNATURE,
                                                dat[KeyType.source_user_id], dat[KeyType.query_id])
                if not self.error_reply(msg=retmsg, err_code=EINVALID_COMMAND, txt="Fail to forward transaction"):
                    user_message_routing.direct_send_to_user(socket, retmsg)

        elif cmd == MsgType.REQUEST_INSERT:
            if not self.param_check([KeyType.domain_id, KeyType.transaction_data, KeyType.all_asset_files], dat):
                self.logger.debug("REQUEST_INSERT: bad format")
                return False, None
            transaction_data = dat[KeyType.transaction_data]
            asset_files = dat[KeyType.all_asset_files]
            retmsg = make_message_structure(domain_id, MsgType.RESPONSE_INSERT,
                                            dat[KeyType.source_user_id], dat[KeyType.query_id])
            ret = self.insert_transaction(dat[KeyType.domain_id], transaction_data, asset_files)
            if isinstance(ret, str):
                if not self.error_reply(msg=retmsg, err_code=EINVALID_COMMAND, txt=ret):
                    user_message_routing.direct_send_to_user(socket, retmsg)
            else:
                retmsg.update(ret)
                umr.send_message_to_user(retmsg)

        elif cmd == MsgType.RESPONSE_SIGNATURE:
            if not self.param_check([KeyType.domain_id, KeyType.destination_user_id, KeyType.source_user_id], dat):
                self.logger.debug("RESPONSE_SIGNATURE: bad format")
                return False, None
            retmsg = make_message_structure(domain_id, MsgType.RESPONSE_GATHER_SIGNATURE,
                                            dat[KeyType.destination_user_id], dat[KeyType.query_id])
            if KeyType.signature in dat:
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

        elif cmd == MsgType.REQUEST_CROSS_REF:
            if KeyType.count in dat:
                num = dat[KeyType.count]
            else:
                num = 1
            retmsg = make_message_structure(domain_id, MsgType.RESPONSE_CROSS_REF,
                                            dat[KeyType.source_user_id], dat[KeyType.query_id])
            retmsg[KeyType.cross_refs] = self.pop_cross_refs(num=num)
            umr.send_message_to_user(retmsg)

        elif cmd == MsgType.MESSAGE:
            if not self.param_check([KeyType.domain_id, KeyType.source_user_id,
                                     KeyType.destination_user_id], dat):
                self.logger.debug("MESSAGE: bad format")
                return False, None
            umr.send_message_to_user(dat)

        elif cmd == MsgType.REQUEST_REGISTER_HASH_IN_SUBSYS:
            if not self.param_check([KeyType.transaction_id], dat):
                self.logger.debug("REQUEST_REGISTER_HASH_IN_SUBSYS: bad format")
                return False, None
            if domain_id in self.ledger_subsystems:
                transaction_id = dat[KeyType.transaction_id]
                self.ledger_subsystems[domain_id].register_transaction(transaction_id=transaction_id)
                retmsg = make_message_structure(domain_id, MsgType.RESPONSE_REGISTER_HASH_IN_SUBSYS,
                                                dat[KeyType.source_user_id], dat[KeyType.query_id])
                umr.send_message_to_user(retmsg)

        elif cmd == MsgType.REQUEST_VERIFY_HASH_IN_SUBSYS:
            if not self.param_check([KeyType.transaction_id], dat):
                self.logger.debug("REQUEST_REGISTER_HASH_IN_SUBSYS: bad format")
                return False, None
            if domain_id in self.ledger_subsystems:
                transaction_id = dat[KeyType.transaction_id]
                retmsg = make_message_structure(domain_id, MsgType.RESPONSE_VERIFY_HASH_IN_SUBSYS,
                                                dat[KeyType.source_user_id], dat[KeyType.query_id])
                result = self.ledger_subsystems[domain_id].verify_transaction(transaction_id=transaction_id)
                retmsg[KeyType.merkle_tree] = result
                umr.send_message_to_user(retmsg)

        elif cmd == MsgType.REGISTER:
            if domain_id is None:
                return False, None
            if not self.param_check([KeyType.domain_id, KeyType.source_user_id], dat):
                self.logger.debug("REGISTER: bad format")
                return False, None
            user_id = dat[KeyType.source_user_id]
            self.logger.debug("[%s] register_user: %s" % (binascii.b2a_hex(domain_id[:2]),
                                                          binascii.b2a_hex(user_id[:4])))
            umr.register_user(user_id, socket)
            return False, (domain_id, user_id)

        elif cmd == MsgType.UNREGISTER:
            if umr is not None:
                umr.unregister_user(dat[KeyType.source_user_id], socket)
            return True, None

        elif cmd == MsgType.REQUEST_INSERT_NOTIFICATION:
            self.register_to_notification_list(domain_id, dat[KeyType.asset_group_id], dat[KeyType.source_user_id])

        elif cmd == MsgType.CANCEL_INSERT_NOTIFICATION:
            self.remove_from_notification_list(domain_id, dat[KeyType.asset_group_id], dat[KeyType.source_user_id])

        elif cmd == MsgType.REQUEST_GET_STATS:
            if not self.check_signature_by_nodekey(dat):
                self.logger.error("Illegal access without node_key")
                return False, None
            retmsg = make_message_structure(domain_id, MsgType.RESPONSE_GET_STATS,
                                            dat[KeyType.source_user_id], dat[KeyType.query_id])
            retmsg[KeyType.stats] = self.stats.get_stats()
            user_message_routing.direct_send_to_user(socket, retmsg)

        elif cmd == MsgType.REQUEST_REPAIR:
            if not self.param_check([KeyType.transaction_id], dat):
                self.logger.debug("REQUEST_REPAIR: bad format")
                return False, None
            dat[KeyType.command] = repair_manager.RepairManager.REQUEST_REPAIR_TRANSACTION
            self.networking.domains[domain_id]['repair'].put_message(dat)
            return False, None

        # --- TODO: REQUEST_GET_PEERLIST will be obsoleted in v0.10
        elif cmd == MsgType.REQUEST_GET_NEIGHBORLIST or cmd == MsgType.REQUEST_GET_PEERLIST:
            if not self.networking.check_admin_signature(domain_id, dat):
                self.logger.error("Illegal access to domain %s" % domain_id.hex())
                return False, None
            domain_id = dat[KeyType.domain_id]
            retmsg = make_message_structure(domain_id, MsgType.RESPONSE_GET_NEIGHBORLIST,
                                            dat[KeyType.source_user_id], dat[KeyType.query_id])
            if domain_id in self.networking.domains:
                retmsg[KeyType.domain_id] = domain_id
                retmsg[KeyType.neighbor_list] = self.networking.domains[domain_id][InfraMessageCategory.CATEGORY_TOPOLOGY].make_neighbor_list()
            else:
                retmsg[KeyType.status] = False
                retmsg[KeyType.reason] = "No such domain"
            user_message_routing.direct_send_to_user(socket, retmsg)

        elif cmd == MsgType.REQUEST_GET_CONFIG:
            if not self.check_signature_by_nodekey(dat):
                self.logger.error("Illegal access without node_kdy")
                return False, None
            retmsg = make_message_structure(domain_id, MsgType.RESPONSE_GET_CONFIG,
                                            dat[KeyType.source_user_id], dat[KeyType.query_id])
            jsondat = self.config.get_json_config()
            retmsg[KeyType.bbc_configuration] = jsondat
            user_message_routing.direct_send_to_user(socket, retmsg)

        elif cmd == MsgType.REQUEST_GET_DOMAINLIST:
            if not self.check_signature_by_nodekey(dat):
                self.logger.error("Illegal access without node_kdy")
                return False, None
            retmsg = make_message_structure(domain_id, MsgType.RESPONSE_GET_DOMAINLIST,
                                            dat[KeyType.source_user_id], dat[KeyType.query_id])
            data = bytearray()
            data.extend(to_2byte(len(self.networking.domains)))
            for domain_id in self.networking.domains:
                data.extend(domain_id)
            retmsg[KeyType.domain_list] = bytes(data)
            user_message_routing.direct_send_to_user(socket, retmsg)

        elif cmd == MsgType.REQUEST_GET_FORWARDING_LIST:
            if not self.networking.check_admin_signature(domain_id, dat):
                self.logger.error("Illegal access to domain %s" % domain_id.hex())
                return False, None
            retmsg = make_message_structure(domain_id, MsgType.RESPONSE_GET_FORWARDING_LIST,
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
            if not self.networking.check_admin_signature(domain_id, dat):
                self.logger.error("Illegal access to domain %s" % domain_id.hex())
                return False, None
            retmsg = make_message_structure(domain_id, MsgType.RESPONSE_GET_USERS,
                                            dat[KeyType.source_user_id], dat[KeyType.query_id])
            data = bytearray()
            data.extend(to_2byte(len(umr.registered_users)))
            for user_id in umr.registered_users.keys():
                data.extend(user_id)
            retmsg[KeyType.user_list] = bytes(data)
            user_message_routing.direct_send_to_user(socket, retmsg)

        elif cmd == MsgType.REQUEST_GET_NODEID:
            if not self.networking.check_admin_signature(domain_id, dat):
                self.logger.error("Illegal access to domain %s" % domain_id.hex())
                return False, None
            retmsg = make_message_structure(domain_id, MsgType.RESPONSE_GET_NODEID,
                                            dat[KeyType.source_user_id], dat[KeyType.query_id])
            data = bytearray()
            data.extend(self.networking.domains[domain_id][InfraMessageCategory.CATEGORY_TOPOLOGY].my_node_id)
            retmsg[KeyType.node_id] = bytes(data)
            user_message_routing.direct_send_to_user(socket, retmsg)

        elif cmd == MsgType.REQUEST_GET_NOTIFICATION_LIST:
            if not self.networking.check_admin_signature(domain_id, dat):
                self.logger.error("Illegal access to domain %s" % domain_id.hex())
                return False, None
            retmsg = make_message_structure(domain_id, MsgType.RESPONSE_GET_NOTIFICATION_LIST,
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
            if not self.check_signature_by_nodekey(dat):
                self.logger.error("Illegal access without node_kdy")
                return False, None
            retmsg = make_message_structure(None, MsgType.RESPONSE_SETUP_DOMAIN,
                                            dat[KeyType.source_user_id], dat[KeyType.query_id])
            if domain_id is None:
                retmsg[KeyType.result] = False
            else:
                config = None
                if KeyType.bbc_configuration in dat:
                    try:
                        config = json.loads(dat[KeyType.bbc_configuration])
                    except:
                        config = None
                self.networking.create_domain(domain_id=domain_id, config=config)
                retmsg[KeyType.result] = True
                retmsg[KeyType.domain_id] = domain_id
            user_message_routing.direct_send_to_user(socket, retmsg)

        elif cmd == MsgType.REQUEST_CLOSE_DOMAIN:
            if not self.networking.check_admin_signature(domain_id, dat):
                self.logger.error("Illegal access to domain %s" % domain_id.hex())
                return False, None
            retmsg = make_message_structure(None, MsgType.RESPONSE_CLOSE_DOMAIN,
                                            dat[KeyType.source_user_id], dat[KeyType.query_id])
            retmsg[KeyType.result] = self.networking.remove_domain(domain_id)
            user_message_routing.direct_send_to_user(socket, retmsg)

        elif cmd == MsgType.REQUEST_ECDH_KEY_EXCHANGE:
            retmsg = make_message_structure(None, MsgType.RESPONSE_ECDH_KEY_EXCHANGE,
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
            if not self.networking.check_admin_signature(domain_id, dat):
                self.logger.error("Illegal access to domain %s" % domain_id.hex())
                return False, None
            if not self.param_check([KeyType.domain_id, KeyType.source_user_id, KeyType.port_number], dat):
                return False, None
            ipv4 = dat.get(KeyType.ipv4_address, None)
            ipv6 = dat.get(KeyType.ipv6_address, None)
            if ipv4 is None and ipv6 is None:
                return False, None
            port = dat[KeyType.port_number]
            self.networking.send_domain_ping(domain_id, ipv4, ipv6, port)

        elif cmd == MsgType.REQUEST_SET_STATIC_NODE:
            if not self.networking.check_admin_signature(domain_id, dat):
                self.logger.error("Illegal access to domain %s" % domain_id.hex())
                return False, None
            retmsg = make_message_structure(domain_id, MsgType.RESPONSE_SET_STATIC_NODE,
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
            if not self.networking.check_admin_signature(domain_id, dat):
                self.logger.error("Illegal access to domain %s" % domain_id.hex())
                return False, None
            retmsg = make_message_structure(domain_id, MsgType.RESPONSE_MANIP_LEDGER_SUBSYS,
                                            dat[KeyType.source_user_id], dat[KeyType.query_id])
            if self.ledger_subsystems[domain_id] is not None:
                if dat[KeyType.ledger_subsys_manip]:
                    self.ledger_subsystems[domain_id].enable()
                else:
                    self.ledger_subsystems[domain_id].disable()
                user_message_routing.direct_send_to_user(socket, retmsg)

        else:
            self.logger.error("Bad command/response: %s" % cmd)
        return False, None

    def register_to_notification_list(self, domain_id, asset_group_id, user_id):
        """
        Register user_id in notification_list
        :param domain_id:
        :param asset_group_id:
        :param user_id:
        :return:
        """
        self.insert_notification_user_list.setdefault(domain_id, dict())
        self.insert_notification_user_list[domain_id].setdefault(asset_group_id, set())
        self.insert_notification_user_list[domain_id][asset_group_id].add(user_id)
        umr = self.networking.domains[domain_id][InfraMessageCategory.CATEGORY_USER]
        umr.send_multicast_join(asset_group_id, permanent=True)

    def remove_from_notification_list(self, domain_id, asset_group_id, user_id):
        """
        Remove entry from insert completion notification list
        :param domain_id:
        :param asset_group_id:
        :param user_id:
        :return:
        """
        if domain_id not in self.insert_notification_user_list:
            return
        if asset_group_id is not None:
            if asset_group_id in self.insert_notification_user_list[domain_id]:
                self.remove_notification_entry(domain_id, asset_group_id, user_id)
        else:
            for asset_group_id in list(self.insert_notification_user_list[domain_id]):
                self.remove_notification_entry(domain_id, asset_group_id, user_id)

    def remove_notification_entry(self, domain_id, asset_group_id, user_id):
        self.insert_notification_user_list[domain_id][asset_group_id].remove(user_id)
        if len(self.insert_notification_user_list[domain_id][asset_group_id]) == 0:
            self.insert_notification_user_list[domain_id].pop(asset_group_id, None)
            umr = self.networking.domains[domain_id][InfraMessageCategory.CATEGORY_USER]
            umr.send_multicast_leave(asset_group_id)
        if len(self.insert_notification_user_list[domain_id]) == 0:
            self.insert_notification_user_list.pop(domain_id, None)

    def validate_transaction(self, txdata, asset_files=None):
        """
        Validate transaction by verifying signature

        :param txid:          transaction_id
        :param txdata:        BBcTransaction data
        :param asset_files:   dictionary of { asid=>asset_content,,, }
        :rtype: BBcTransaction or None
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
        """
        Insert transaction into ledger

        :param domain_id:     domain_id where the transaction is inserted
        :param txdata:        BBcTransaction data
        :param asset_files:   dictionary of { asid=>asset_content,,, }
        :rtype: **result or str
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

        asset_group_ids = self.networking.domains[domain_id][InfraMessageCategory.CATEGORY_DATA].insert_transaction(
                                txdata, txobj=txobj, asset_files=asset_files)
        if asset_group_ids is None:
            self.stats.update_stats_increment("transaction", "insert_fail_count", 1)
            self.logger.error("[%s] Fail to insert a transaction into the ledger" % self.networking.domains[domain_id]['name'])
            return "Failed to insert a transaction into the ledger"

        self.send_inserted_notification(domain_id, asset_group_ids, txobj.transaction_id)

        return {KeyType.transaction_id: txobj.transaction_id}

    def send_inserted_notification(self, domain_id, asset_group_ids, transaction_id, only_registered_user=False):
        """
        broadcast NOTIFY_INSERTED
        :param domain_id:
        :param asset_group_ids:
        :param transaction_id:
        :param only_registered_user:  If True, notification is not sent to other nodes
        :return:
        """
        umr = self.networking.domains[domain_id][InfraMessageCategory.CATEGORY_USER]
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

    def distribute_transaction_to_gather_signatures(self, domain_id, dat):
        """
        Request to distribute sign_request to users

        :param domain_id:
        :param dat:
        :rtype: bool
        :return:
        """
        destinations = dat[KeyType.destination_user_ids]
        msg = make_message_structure(domain_id, MsgType.REQUEST_SIGNATURE, None, dat[KeyType.query_id])
        msg[KeyType.source_user_id] = dat[KeyType.source_user_id]
        umr = self.networking.domains[domain_id][InfraMessageCategory.CATEGORY_USER]
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

    def search_transaction_by_txid(self, domain_id, txid):
        """
        Search transaction_data by transaction_id

        :param domain_id:        domain_id where the transaction is inserted
        :param txid:  transaction_id
        :rtype: **response_info
        :return: {transaction_id, transaction_data, asset_files}
        """
        self.stats.update_stats_increment("transaction", "search_count", 1)
        if domain_id is None:
            self.logger.error("No such domain")
            return None
        if txid is None:
            self.logger.error("Transaction_id must not be None")
            return None

        dh = self.networking.domains[domain_id][InfraMessageCategory.CATEGORY_DATA]
        ret_txobj, ret_asset_files = dh.search_transaction(transaction_id=txid)
        if ret_txobj is None or len(ret_txobj) == 0:
            return None

        response_info = create_search_result(ret_txobj, ret_asset_files)
        response_info[KeyType.transaction_id] = txid
        if KeyType.transactions in response_info:
            response_info[KeyType.transaction_data] = response_info[KeyType.transactions][0]
            del response_info[KeyType.transactions]
        elif KeyType.compromised_transactions in response_info:
            response_info[KeyType.compromised_transaction_data] = response_info[KeyType.compromised_transactions][0]
            del response_info[KeyType.compromised_transactions]
        return response_info

    def search_transaction_with_condition(self, domain_id, asset_group_id=None, asset_id=None, user_id=None, count=1):
        """
        Search transactions that match given conditions
        :param domain_id:
        :param asset_group_id:
        :param asset_group_id:
        :param user_id:
        :rtype: **response_info
        :return: {transactions, all_asset_files, compromised_transactions, compromised_asset, compromised_asset_files}
        """
        if domain_id is None:
            self.logger.error("No such domain")
            return None

        dh = self.networking.domains[domain_id][InfraMessageCategory.CATEGORY_DATA]
        ret_txobj, ret_asset_files = dh.search_transaction(asset_group_id=asset_group_id,
                                                           asset_id=asset_id, user_id=user_id, count=count)
        if ret_txobj is None or len(ret_txobj) == 0:
            return None

        return create_search_result(ret_txobj, ret_asset_files)

    def add_cross_ref_into_list(self, domain_id, txid):
        """
        (internal use) register cross_ref info in the list

        :param domain_id:
        :param txid:
        :return:
        """
        self.stats.update_stats_increment("cross_ref", "total_num", 1)
        self.cross_ref_list.append([domain_id, txid])

    def pop_cross_refs(self, num=1):
        """
        Return TxIDs for cross_refs

        :param num: The number of set of (txid, domain_id) to return
        :return:
        """
        refs = []
        for i in range(num):
            if len(self.cross_ref_list) > 0:
                refs.append(self.cross_ref_list.pop(0))
                self.stats.update_stats_decrement("cross_ref", "total_num", 1)
            else:
                break
        return refs


def daemonize(pidfile=PID_FILE):
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
    BBcCoreService(
        p2p_port=argresult.p2pport,
        core_port=argresult.coreport,
        workingdir=argresult.workingdir,
        configfile=argresult.config,
        use_nodekey=argresult.nodekey,
        use_domain0=argresult.domain0,
        use_ledger_subsystem=argresult.ledgersubsystem,
        ip4addr=argresult.ip4addr,
        ip6addr=argresult.ip6addr,
        logname=argresult.log,
        loglevel=argresult.verbose_level,
    )
