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

import sys
sys.path.extend(["../../"])
from bbc1.common import bbclib, message_key_types, logger
from bbc1.common.message_key_types import KeyType, PayloadType, to_2byte
from bbc1.common.bbclib import BBcTransaction, ServiceMessageType as MsgType, StorageType
from bbc1.core import bbc_network, user_message_routing, data_handler, query_management, bbc_stats
from bbc1.core.bbc_config import BBcConfig
from bbc1.core.bbc_types import ResourceType
from bbc1.core.bbc_ledger import BBcLedger
from bbc1.core.user_message_routing import UserMessageRouting
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


def make_message_structure(cmd, dstid, qid):
    """
    (internal use) Create a base structure of message

    :param cmd:
    :param dstid: destination_user_id
    :param qid:   query_id
    :return:
    """
    return {
        KeyType.command: cmd,
        KeyType.destination_user_id: dstid,
        KeyType.query_id: qid,
        KeyType.status: ESUCCESS,
    }


def error_response(err_code=EOTHER, txt=""):
    """
    (internal use) Create error response with reason text

    :param err_code: error code (defined in bbc_error.py)
    :param txt:  reason text
    :return:     dictionary type data
    """
    return {
        KeyType.status: err_code,
        KeyType.reason: txt
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


class BBcCoreService:
    def __init__(self, p2p_port=None, core_port=None, use_global=False, ip4addr=None, ip6addr=None,
                 workingdir=".bbc1", configfile=None, use_ledger_subsystem=False,
                 loglevel="all", logname="-", server_start=True):
        self.logger = logger.get_logger(key="core", level=loglevel, logname=logname)
        self.stats = bbc_stats.BBcStats()
        self.config = BBcConfig(workingdir, configfile)
        conf = self.config.get_config()
        if p2p_port is not None:
            conf['client']['port'] = core_port
        else:
            core_port = conf['client']['port']
        self.logger.debug("config = %s" % conf)
        self.test_tx_obj = BBcTransaction()
        self.need_insert_completion_notification = dict()
        self.cross_ref_list = []
        self.networking = bbc_network.BBcNetwork(self.config, core=self, p2p_port=p2p_port, use_global=use_global,
                                                 external_ip4addr=ip4addr, external_ip6addr=ip6addr,
                                                 loglevel=loglevel, logname=logname)
        self.ledger_subsystem = None
        if conf['use_ledger_subsystem'] or use_ledger_subsystem:
            from bbc1.core import ledger_subsystem
            self.ledger_subsystem = ledger_subsystem.LedgerSubsystem(self.config, core=self,
                                                                     loglevel=loglevel, logname=logname)

        for domain_id_str in conf['domains'].keys():
            domain_id = bbclib.convert_idstring_to_bytes(domain_id_str)
            c = self.config.get_domain_config(domain_id)



            """
            nw_module = c.get('module', 'simple_cluster')
            default_type = StorageType.FILESYSTEM
            if domain_id == bbclib.domain_global_0:
                default_type = StorageType.NONE
            storage_type = c.pop('storage_type', default_type)
            storage_path = c.pop('storage_path', None)
            self.configure_domain(domain_id, nw_module, storage_type, storage_path)

            for nd, info in c['static_nodes'].items():
                node_id, ipv4, ipv6, port = bbclib.convert_idstring_to_bytes(nd), info[0], info[1], info[2]
                self.networking.add_static_node_to_domain(domain_id, node_id, ipv4, ipv6, port)
            for nd, info in c['peer_list'].items():
                node_id, ipv4, ipv6, port = bbclib.convert_idstring_to_bytes(nd), info[0], info[1], info[2]
                self.networking.domains[domain_id].add_peer_node_ip46(node_id, ipv4, ipv6, port, need_ping=True)
            """
        gevent.signal(signal.SIGINT, self.quit_program)
        if server_start:
            self.start_server(core_port)

    def configure_domain(self, domain_id, nw_module='simple_cluster', storage_type=StorageType.NONE, storage_path=None):
        self.networking.create_domain(domain_id=domain_id, network_module=nw_module)
        if domain_id != bbclib.domain_global_0:
            self.ledger_manager.add_domain(domain_id)
            self.storage_manager.set_storage_path(domain_id, storage_type=storage_type, storage_path=storage_path)

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

    def send_to_other_user(self, domain_id, dst_user_id, src_user_id, msg):
        if dst_user_id in self.user_id_sock_mapping:
            return self.user_message_routing.send_message_to_user(msg)
        return self.networking.route_message(domain_id, dst_user_id, src_user_id, msg)

    def error_reply(self, msg=None, err_code=EINVALID_COMMAND, txt=""):
        msg[KeyType.status] = err_code
        msg[KeyType.reason] = txt
        self.user_message_routing.send_message_to_user(msg)

    def handler(self, socket, address):
        """
        Message wait loop

        :param socket:
        :param address:
        :return:
        """
        #self.logger.debug("New connection")
        self.stats.update_stats_increment("client", "total_num", 1)
        mappings = []
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
                        mappings.append(new_info)
        except Exception as e:
            self.logger.info("TCP disconnect: %s" % e)
            traceback.print_exc()
        self.logger.debug("closing socket")
        try:
            for uid in mappings:
                self.user_id_sock_mapping.pop(uid, None)
                if len(self.user_id_sock_mapping) == 0:
                    self.user_id_sock_mapping.pop(uid, None)
                self.networking.remove_user_id(uid)
            socket.shutdown(py_socket.SHUT_RDWR)
            socket.close()
        except:
            pass
        self.logger.debug("connection closed")
        self.stats.update_stats_decrement("client", "total_num", 1)

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
        if KeyType.domain_id in dat:
            domain_id = dat[KeyType.domain_id]
            umr = self.networking.domains[domain_id]

        cmd = dat[KeyType.command]
        if cmd == MsgType.REQUEST_SEARCH_TRANSACTION:
            if not self.param_check([KeyType.domain_id, KeyType.transaction_id], dat):
                self.logger.debug("REQUEST_SEARCH_TRANSACTION: bad format")
                return False, None
            retmsg = make_message_structure(MsgType.RESPONSE_SEARCH_TRANSACTION,
                                            dat[KeyType.source_user_id], dat[KeyType.query_id])
            txinfo = self.search_transaction_by_txid(domain_id, dat[KeyType.transaction_id])
            if txinfo is None:
                self.error_reply(msg=retmsg, err_code=ENOTRANSACTION, txt="Cannot find transaction")
            else:
                retmsg.update(txinfo)
                umr.send_message_to_user(retmsg)

        elif cmd == MsgType.REQUEST_SEARCH_WITH_CONDITIONS:
            if not self.param_check([KeyType.domain_id], dat):
                self.logger.debug("REQUEST_SEARCH_WITH_CONDITIONS: bad format")
                return False, None
            retmsg = make_message_structure(MsgType.RESPONSE_SEARCH_WITH_CONDITIONS,
                                            dat[KeyType.source_user_id], dat[KeyType.query_id])
            txinfo = self.search_transaction_with_condition(domain_id,
                                                            asset_group_id=dat.get(KeyType.asset_group_id, None),
                                                            asset_id=dat.get(KeyType.asset_id, None),
                                                            user_id=dat.get(KeyType.user_id, None),
                                                            count=dat.get(KeyType.count, None))
            if txinfo is None:
                self.error_reply(msg=retmsg, err_code=ENOTRANSACTION, txt="Cannot find transaction")
            else:
                retmsg.update(txinfo)
                umr.send_message_to_user(retmsg)

        # --- TODO: will be obsoleted in v0.10
        elif cmd == MsgType.REQUEST_SEARCH_USERID:
            if not self.param_check([KeyType.domain_id, KeyType.asset_group_id, KeyType.user_id], dat):
                self.logger.debug("REQUEST_SEARCH_USERID: bad format")
                return False, None
            retmsg = make_message_structure(MsgType.RESPONSE_SEARCH_USERID,
                                            dat[KeyType.source_user_id], dat[KeyType.query_id])
            txinfo = self.search_transaction_with_condition(domain_id, asset_group_id=dat[KeyType.asset_group_id],
                                                            user_id=dat[KeyType.user_id])
            if txinfo is None:
                self.error_reply(msg=retmsg, err_code=ENOTRANSACTION, txt="Cannot find transaction")
            else:
                retmsg.update(txinfo)
                umr.send_message_to_user(retmsg)

        # --- TODO: will be obsoleted in v0.10
        elif cmd == MsgType.REQUEST_SEARCH_ASSET:
            if not self.param_check([KeyType.domain_id, KeyType.asset_group_id, KeyType.asset_id], dat):
                self.logger.debug("REQUEST_SEARCH_ASSET: bad format")
                return False, None
            retmsg = make_message_structure(MsgType.RESPONSE_SEARCH_ASSET,
                                            dat[KeyType.source_user_id], dat[KeyType.query_id])
            retmsg[KeyType.asset_group_id] = dat[KeyType.asset_group_id]
            txinfo = self.search_transaction_with_condition(domain_id, asset_group_id=dat[KeyType.asset_group_id],
                                                            asset_id=dat[KeyType.asset_id])
            if txinfo is None:
                self.error_reply(msg=retmsg, err_code=ENOTRANSACTION, txt="Cannot find transaction")
            else:
                retmsg.update(txinfo)
                umr.send_message_to_user(retmsg)

        elif cmd == MsgType.REQUEST_GATHER_SIGNATURE:
            if not self.param_check([KeyType.domain_id, KeyType.transaction_data], dat):
                self.logger.debug("REQUEST_GATHER_SIGNATURE: bad format")
                return False, None
            if not self.distribute_transaction_to_gather_signatures(dat[KeyType.domain_id], dat):
                retmsg = make_message_structure(MsgType.RESPONSE_GATHER_SIGNATURE,
                                                dat[KeyType.source_user_id], dat[KeyType.query_id])
                self.error_reply(msg=retmsg, err_code=EINVALID_COMMAND, txt="Fail to forward transaction")

        elif cmd == MsgType.REQUEST_INSERT:
            if not self.param_check([KeyType.domain_id, KeyType.transaction_data, KeyType.all_asset_files], dat):
                self.logger.debug("REQUEST_INSERT: bad format")
                return False, None
            transaction_data = dat[KeyType.transaction_data]
            asset_files = dat[KeyType.all_asset_files]
            retmsg = make_message_structure(MsgType.RESPONSE_INSERT,
                                            dat[KeyType.source_user_id], dat[KeyType.query_id])
            ret = self.insert_transaction(dat[KeyType.domain_id], transaction_data, asset_files)
            if isinstance(ret, str):
                self.error_reply(msg=retmsg, err_code=EINVALID_COMMAND, txt=ret)
            else:
                retmsg.update(ret)
                self.user_message_routing.send_message_to_user(retmsg)

        elif cmd == MsgType.RESPONSE_SIGNATURE:
            if not self.param_check([KeyType.domain_id, KeyType.destination_user_id, KeyType.source_user_id], dat):
                self.logger.debug("RESPONSE_SIGNATURE: bad format")
                return False, None
            retmsg = make_message_structure(MsgType.RESPONSE_GATHER_SIGNATURE,
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
            self.send_to_other_user(dat[KeyType.domain_id], dat[KeyType.destination_user_id],
                                    dat[KeyType.source_user_id], retmsg)

        elif cmd == MsgType.REQUEST_CROSS_REF:
            if KeyType.count in dat:
                num = dat[KeyType.count]
            else:
                num = 1
            retmsg = make_message_structure(MsgType.RESPONSE_CROSS_REF,
                                            dat[KeyType.source_user_id], dat[KeyType.query_id])
            retmsg[KeyType.cross_refs] = self.pop_cross_refs(num=num)
            self.user_message_routing.send_message_to_user(retmsg)

        elif cmd == MsgType.MESSAGE:
            if not self.param_check([KeyType.domain_id, KeyType.source_user_id,
                                     KeyType.destination_user_id], dat):
                self.logger.debug("MESSAGE: bad format")
                return False, None
            self.networking.route_message(dat[KeyType.domain_id], dat[KeyType.destination_user_id],
                                          dat[KeyType.source_user_id], dat)

        elif cmd == MsgType.REQUEST_REGISTER_HASH_IN_SUBSYS:
            if not self.param_check([KeyType.asset_group_id, KeyType.transaction_id], dat):
                self.logger.debug("REQUEST_REGISTER_HASH_IN_SUBSYS: bad format")
                return False, None
            if self.ledger_subsystem is not None:
                asset_group_id = dat[KeyType.asset_group_id]
                transaction_id = dat[KeyType.transaction_id]
                self.ledger_subsystem.register_transaction(asset_group_id=asset_group_id, transaction_id=transaction_id)
                retmsg = make_message_structure(MsgType.RESPONSE_REGISTER_HASH_IN_SUBSYS,
                                                dat[KeyType.source_user_id], dat[KeyType.query_id])
                retmsg[KeyType.asset_group_id] = dat[KeyType.asset_group_id]
                self.user_message_routing.send_message_to_user(retmsg)

        elif cmd == MsgType.REQUEST_VERIFY_HASH_IN_SUBSYS:
            if not self.param_check([KeyType.asset_group_id, KeyType.transaction_id], dat):
                self.logger.debug("REQUEST_REGISTER_HASH_IN_SUBSYS: bad format")
                return False, None
            if self.ledger_subsystem is not None:
                asset_group_id = dat[KeyType.asset_group_id]
                transaction_id = dat[KeyType.transaction_id]
                retmsg = make_message_structure(MsgType.RESPONSE_VERIFY_HASH_IN_SUBSYS,
                                                dat[KeyType.source_user_id], dat[KeyType.query_id])
                retmsg[KeyType.asset_group_id] = dat[KeyType.asset_group_id]
                result = self.ledger_subsystem.verify_transaction(asset_group_id=asset_group_id,
                                                                  transaction_id=transaction_id)
                retmsg[KeyType.merkle_tree] = result
                self.user_message_routing.send_message_to_user(retmsg)

        elif cmd == MsgType.REQUEST_GET_STATS:
            retmsg = make_message_structure(MsgType.RESPONSE_GET_STATS,
                                            dat[KeyType.source_user_id], dat[KeyType.query_id])
            retmsg[KeyType.stats] = self.stats.get_stats()
            self.user_message_routing.send_message_to_user(retmsg, sock=socket)

        elif cmd == MsgType.REGISTER:
            if not self.param_check([KeyType.domain_id, KeyType.source_user_id], dat):
                self.logger.debug("REGISTER: bad format")
                return False, None
            user_id = dat[KeyType.source_user_id]
            domain_id = dat[KeyType.domain_id]
            self.logger.debug("[%s] register_user: %s" % (binascii.b2a_hex(domain_id[:2]),
                                                          binascii.b2a_hex(user_id[:4])))
            self.user_message_routing.register_user(domain_id, user_id, socket)
            return False, user_id

        elif cmd == MsgType.UNREGISTER:
            user_id = dat[KeyType.source_user_id]
            domain_id = dat[KeyType.domain_id]
            self.user_message_routing.unregister_user(domain_id, user_id, socket)
            return True, None

        elif cmd == MsgType.REQUEST_SETUP_DOMAIN:
            retmsg = make_message_structure(MsgType.RESPONSE_SETUP_DOMAIN,
                                            dat[KeyType.source_user_id], dat[KeyType.query_id])
            domain_id = dat.get(KeyType.domain_id, None)
            if domain_id is None:
                retmsg[KeyType.result] = False
            else:
                self.configure_domain(domain_id, nw_module=dat.get(KeyType.network_module, "simple_cluster"),
                                      storage_type=dat.get(KeyType.storage_type, StorageType.FILESYSTEM),
                                      storage_path=dat.get(KeyType.storage_path, None))
            self.user_message_routing.send_message_to_user(retmsg, sock=socket)

        elif cmd == MsgType.REQUEST_GET_PEERLIST:
            domain_id = dat[KeyType.domain_id]
            retmsg = make_message_structure(MsgType.RESPONSE_GET_PEERLIST,
                                            dat[KeyType.source_user_id], dat[KeyType.query_id])
            if domain_id in self.networking.domains:
                retmsg[KeyType.domain_id] = domain_id
                retmsg[KeyType.peer_list] = self.networking.domains[domain_id].make_peer_list()
            self.user_message_routing.send_message_to_user(retmsg, sock=socket)

        elif cmd == MsgType.REQUEST_SET_STATIC_NODE:
            retmsg = make_message_structure(MsgType.RESPONSE_SET_STATIC_NODE,
                                            dat[KeyType.source_user_id], dat[KeyType.query_id])
            domain_id = dat[KeyType.domain_id]
            node_info = dat.get(KeyType.peer_info, None)
            if node_info is None:
                retmsg[KeyType.domain_id] = domain_id
                retmsg[KeyType.result] = False
            else:
                self.networking.add_static_node_to_domain(domain_id, *node_info)
                self.config.update_config()
                retmsg[KeyType.domain_id] = domain_id
                retmsg[KeyType.result] = True
            self.user_message_routing.send_message_to_user(retmsg, sock=socket)

        elif cmd == MsgType.REQUEST_GET_CONFIG:
            retmsg = make_message_structure(MsgType.RESPONSE_GET_CONFIG,
                                            dat[KeyType.source_user_id], dat[KeyType.query_id])
            jsondat = self.config.get_json_config()
            retmsg[KeyType.bbc_configuration] = jsondat
            self.user_message_routing.send_message_to_user(retmsg, sock=socket)

        elif cmd == MsgType.REQUEST_GET_DOMAINLIST:
            retmsg = make_message_structure(MsgType.RESPONSE_GET_DOMAINLIST,
                                            dat[KeyType.source_user_id], dat[KeyType.query_id])
            data = bytearray()
            data.extend(to_2byte(len(self.networking.domains)))
            for domain_id in self.networking.domains:
                data.extend(domain_id)
            retmsg[KeyType.domain_list] = bytes(data)
            self.user_message_routing.send_message_to_user(retmsg, sock=socket)

        elif cmd == MsgType.DOMAIN_PING:
            if not self.param_check([KeyType.domain_id, KeyType.source_user_id, KeyType.port_number], dat):
                return False, None
            ipv4 = dat.get(KeyType.ipv4_address, None)
            ipv6 = dat.get(KeyType.ipv6_address, None)
            if ipv4 is None and ipv6 is None:
                return False, None
            domain_id = dat[KeyType.domain_id]
            port = dat[KeyType.port_number]
            self.networking.send_domain_ping(domain_id, ipv4, ipv6, port)

        elif cmd == MsgType.REQUEST_PING_TO_ALL:
            domain_id = dat[KeyType.domain_id]
            if domain_id in self.networking.domains:
                self.networking.domains[domain_id].ping_to_all_neighbors()

        elif cmd == MsgType.REQUEST_ALIVE_CHECK:
            domain_id = dat[KeyType.domain_id]
            if domain_id in self.networking.domains:
                self.networking.domains[domain_id].send_peerlist(None)

        elif cmd == MsgType.REQUEST_MANIP_LEDGER_SUBSYS:
            retmsg = make_message_structure(MsgType.RESPONSE_MANIP_LEDGER_SUBSYS,
                                            dat[KeyType.source_user_id], dat[KeyType.query_id])
            if self.ledger_subsystem is not None:
                if dat[KeyType.ledger_subsys_manip]:
                    self.ledger_subsystem.enable()
                else:
                    self.ledger_subsystem.disable()
                self.ledger_subsystem.set_domain(dat[KeyType.domain_id])
                self.user_message_routing.send_message_to_user(retmsg, sock=socket)

        elif cmd == MsgType.REQUEST_INSERT_NOTIFICATION:
            domain_id = dat[KeyType.domain_id]
            asset_group_id = dat[KeyType.asset_group_id]
            self.need_insert_completion_notification.setdefault(domain_id, dict())
            self.need_insert_completion_notification[domain_id].setdefault(asset_group_id, set())
            self.need_insert_completion_notification[domain_id][asset_group_id].add(dat[KeyType.source_user_id])

        elif cmd == MsgType.CANCEL_INSERT_NOTIFICATION:
            self.remove_from_notification_list(dat[KeyType.domain_id], dat[KeyType.asset_group_id],
                                               dat[KeyType.source_user_id])

        else:
            self.logger.error("Bad command/response: %s" % cmd)
        return False, None

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

    def remove_from_notification_list(self, domain_id, asset_group_id, user_id):
        """
        Remove entry from insert completion notification list
        :param domain_id:
        :param asset_group_id:
        :param user_id:
        :return:
        """
        if domain_id in self.need_insert_completion_notification:
            if asset_group_id in self.need_insert_completion_notification[domain_id]:
                self.need_insert_completion_notification[domain_id][asset_group_id].remove(user_id)
                if len(self.need_insert_completion_notification[domain_id][asset_group_id]) == 0:
                    self.need_insert_completion_notification[domain_id].pop(asset_group_id, None)
                if len(self.need_insert_completion_notification[domain_id]) == 0:
                    self.need_insert_completion_notification.pop(domain_id, None)

    def validate_transaction(self, txdata, asset_files=None):
        """
        Validate transaction by verifying signature

        :param txid:          transaction_id
        :param txdata:        BBcTransaction data
        :param asset_files:   dictionary of { asid=>asset_content,,, }
        """
        txobj = BBcTransaction()
        if not txobj.deserialize(txdata):
            self.stats.update_stats_increment("transaction", "invalid", 1)
            self.logger.error("Fail to deserialize transaction data")
            return None
        digest = txobj.digest()

        for i, sig in enumerate(txobj.signatures):
            try:
                if not sig.verify(digest):
                    self.stats.update_stats_increment("transaction", "invalid", 1)
                    self.logger.error("Bad signature [%i]" % i)
                    return None
            except:
                self.stats.update_stats_increment("transaction", "invalid", 1)
                self.logger.error("Bad signature [%i]" % i)
                return None
        if asset_files is None:
            return txobj

        for idx, evt in enumerate(txobj.events):
            if evt.asset is None:
                continue
            asid = evt.asset.asset_id
            if asid in asset_files.keys():
                if evt.asset.asset_file_digest != hashlib.sha256(asset_files[asid]).digest():
                    self.stats.update_stats_increment("transaction", "invalid", 1)
                    self.logger.error("Bad asset_id for event[%d]" % idx)
                    return None
        for idx, rtn in enumerate(txobj.relations):
            if rtn.asset is None:
                continue
            asid = rtn.asset.asset_id
            if asid in asset_files.keys():
                if rtn.asset.asset_file_digest != hashlib.sha256(asset_files[asid]).digest():
                    self.stats.update_stats_increment("transaction", "invalid", 1)
                    self.logger.error("Bad asset_id for event[%d]" % idx)
                    return None
        return txobj

    def validate_asset_file(self, txobj, asid, asset_file):
        """
        Validate asset in storage by verifying SHA256 digest

        :param txobj:
        :param asset_file:
        :return:
        """
        for idx, evt in enumerate(txobj.events):
            if evt.asset is None:
                continue
            if asid == evt.asset.asset_id:
                if evt.asset.asset_file_digest == hashlib.sha256(asset_file).digest():
                    return True
                else:
                    self.stats.update_stats_increment("asset", "invalid", 1)
                    self.logger.error("Bad asset_id for event[%d]" % idx)
                    return False
        for idx, rtn in enumerate(txobj.relations):
            if rtn.asset is None:
                continue
            if asid == rtn.asset.asset_id:
                if rtn.asset.asset_file_digest == hashlib.sha256(asset_file).digest():
                    return True
                else:
                    self.stats.update_stats_increment("asset", "invalid", 1)
                    self.logger.error("Bad asset_id for event[%d]" % idx)
                    return False
        self.stats.update_stats_increment("asset", "invalid", 1)
        return False

    def insert_transaction(self, domain_id, txdata, asset_files):
        """
        Insert transaction into ledger

        :param domain_id:     domain_id where the transaction is inserted
        :param txdata:        BBcTransaction data
        :param asset_files:   dictionary of { asid=>asset_content,,, }
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

        ret = self.networking.domains[domain_id][InfraMessageCategory.CATEGORY_DATA].insert_transaction(
            txdata, txobj=txobj, asset_files=asset_files)
        if not ret:
            self.stats.update_stats_increment("transaction", "insert_fail_count", 1)
            self.logger.error("[%s] Fail to insert a transaction into the ledger" % self.networking.domains[domain_id]['name'])
            return "Failed to insert a transaction into the ledger"
        return {KeyType.transaction_id: txobj.transaction_id}

    def distribute_transaction_to_gather_signatures(self, domain_id, dat):
        """
        Request to distribute sign_request to users

        :param domain_id:
        :param dat:
        :return:
        """
        destinations = dat[KeyType.destination_user_ids]
        msg = make_message_structure(MsgType.REQUEST_SIGNATURE, None, dat[KeyType.query_id])
        msg[KeyType.source_user_id] = dat[KeyType.source_user_id]
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
            if not self.networking.domains[domain_id].user_message_routing.send_message_to_user(msg):
                return False
        return True

    def search_transaction_by_txid(self, domain_id, txid):
        """
        Search transaction_data by transaction_id

        :param domain_id:        domain_id where the transaction is inserted
        :param txid:  transaction_id
        :return: transaction_data and asset_files
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

        response_info = dict()
        response_info[KeyType.transaction_data] = ret_txobj[0].transaction_data
        response_info[KeyType.transaction_id] = txid
        if len(ret_asset_files) > 0:
            response_info[KeyType.all_asset_files] = ret_asset_files
        return response_info

    def search_transaction_with_condition(self, domain_id, asset_group_id=None, asset_id=None, user_id=None, count=1):
        """
        Search transactions that match given conditions
        :param domain_id:
        :param asset_group_id:
        :param asset_group_id:
        :param user_id:
        :return: response data including transaction_data, if a transaction is not found in the local DB, None is returned.
        """
        if domain_id is None:
            self.logger.error("No such domain")
            return None

        dh = self.networking.domains[domain_id][InfraMessageCategory.CATEGORY_DATA]
        ret_txobj, ret_asset_files = dh.search_transaction(asset_group_id=asset_group_id, asset_id=asset_id,
                                                           user_id=user_id, count=count)
        if ret_txobj is None or len(ret_txobj) == 0:
            return None

        response_info = dict()
        response_info[KeyType.transactions] = ret_txobj
        if len(ret_asset_files) > 0:
            response_info[KeyType.all_asset_files] = ret_asset_files
        return response_info

    def add_cross_ref_into_list(self, domain_id, txid):
        """
        (internal use) register cross_ref info in the list

        :param domain_id:
        :param txid:
        :return:
        """
        self.stats.update_stats_increment("cross_ref", "total_num", 1)
        self.cross_ref_list.append([domain_id, txid])

    def send_response(self, response_info, dat):
        """
        (internal use) send response message

        :param response_info:
        :param dat:
        :return:
        """
        response_info.update(dat)
        self.user_message_routing.send_message_to_user(response_info)

    def send_error_response(self, response_info):
        """
        (internal use) send error response

        :param response_info:
        :return:
        """
        if response_info[b'cmd'] == MsgType.RESPONSE_SEARCH_TRANSACTION:
            self.error_reply(msg=response_info, err_code=ENOTRANSACTION, txt="Cannot find transaction data")
        elif response_info[b'cmd'] == MsgType.RESPONSE_SEARCH_ASSET:
            self.error_reply(msg=response_info, err_code=ENOASSET, txt="Cannot find asset")


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
        use_global=argresult.globaldomain,
        use_ledger_subsystem=argresult.ledgersubsystem,
        ip4addr=argresult.ip4addr,
        ip6addr=argresult.ip6addr,
        logname=argresult.log,
        loglevel=argresult.verbose_level,
    )
