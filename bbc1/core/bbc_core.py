#!/usr/bin/env python
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
from bbc1.core import bbc_network, bbc_storage, query_management
from bbc1.core.bbc_config import BBcConfig
from bbc1.core.bbc_ledger import BBcLedger, ResourceType
from bbc1.core import ledger_subsystem
from bbc1.core import command
from bbc1.common.bbc_error import *

VERSION = "core version 0.1.0"

PID_FILE = "/tmp/bbc1.pid"
POOL_SIZE = 1000
DURATION_GIVEUP_GET = 10
GET_RETRY_COUNT = 3
INTERVAL_RETRY = 3

ticker = query_management.get_ticker()
core_service = None


def make_message_structure(cmd, asgid, dstid, qid):
    """
    (internal use) Create a base structure of message

    :param cmd:
    :param asgid: asset_group_id
    :param dstid: destination_user_id
    :param qid:   query_id
    :return:
    """
    if asgid is None:
        return {
            KeyType.command: cmd,
            KeyType.destination_user_id: dstid,
            KeyType.query_id: qid,
            KeyType.status: ESUCCESS,
        }
    return {
        KeyType.command: cmd,
        KeyType.asset_group_id: asgid,
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
    def __init__(self, ipv6=None, p2p_port=None, core_port=None, use_global=False,
                 workingdir=".bbc1", configfile=None,
                 loglevel="all", logname="-", server_start=True):
        self.logger = logger.get_logger(key="core", level=loglevel, logname=logname)
        self.config = BBcConfig(workingdir, configfile)
        conf = self.config.get_config()
        if ipv6 is not None:
            conf['client']['ipv6'] = ipv6
        else:
            ipv6 = conf['client']['ipv6']
        if p2p_port is not None:
            conf['client']['port'] = core_port
        else:
            core_port = conf['client']['port']
        self.logger.debug("config = %s" % conf)
        self.test_tx_obj = BBcTransaction()
        self.user_id_sock_mapping = dict()
        self.asset_group_domain_mapping = dict()
        self.cross_ref_list = []
        self.ledger_manager = BBcLedger(self.config)
        self.storage_manager = bbc_storage.BBcStorage(self.config)
        self.networking = bbc_network.BBcNetwork(self.config, core=self, p2p_port=p2p_port, use_global=use_global,
                                                 loglevel=loglevel, logname=logname)
        self.ledger_subsystem = ledger_subsystem.LedgerSubsystem(self.config, core=self, loglevel=loglevel, logname=logname)

        gevent.signal(signal.SIGINT, self.quit_program)
        if server_start:
            self.start_server(core_port, ipv6=ipv6)

    def quit_program(self):
        self.networking.save_all_peer_lists()
        self.config.update_config()
        os._exit(0)

    def start_server(self, port, ipv6=False):
        pool = Pool(POOL_SIZE)
        if ipv6:
            server = StreamServer(("::", port), self.handler, spawn=pool)
        else:
            server = StreamServer(("0.0.0.0", port), self.handler, spawn=pool)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass

    def send_message(self, dat):
        """
        Send message to bbc_app (TCP client)
        :param dat:
        :return:
        """
        if KeyType.asset_group_id not in dat or KeyType.destination_user_id not in dat:
            self.logger.warn("invalid message")
            return
        self.logger.debug("[port:%d] send_message to %s" % (self.networking.port,
                                                            binascii.b2a_hex(dat[KeyType.destination_user_id][:4])))
        try:
            asset_group_id = dat[KeyType.asset_group_id]
            user_id = dat[KeyType.destination_user_id]
            sock = self.user_id_sock_mapping[asset_group_id][user_id]
            sock.sendall(message_key_types.make_message(PayloadType.Type_msgpack, dat))
        except Exception as e:
            self.logger.error("send error: %s" % dat)
            self.user_id_sock_mapping[asset_group_id].pop(user_id, None)
            return False
        return True

    def send_raw_message(self, socket, dat):
        try:
            socket.sendall(message_key_types.make_message(PayloadType.Type_msgpack, dat))
        except Exception as e:
            self.logger.error("send error: %s" % e)
        return True

    def send_to_other_user(self, asset_group_id, dst_user_id, src_user_id, msg):
        if dst_user_id in self.user_id_sock_mapping[asset_group_id]:
            return self.send_message(msg)
        domain_id = self.asset_group_domain_mapping[asset_group_id]
        return self.networking.route_message(domain_id, asset_group_id, dst_user_id, src_user_id, msg)

    def error_reply(self, msg=None, err_code=EINVALID_COMMAND, txt=""):
        msg[KeyType.status] = err_code
        msg[KeyType.reason] = txt
        self.send_message(msg)

    def handler(self, socket, address):
        """
        Message wait loop

        :param socket:
        :param address:
        :return:
        """
        #self.logger.debug("New connection")
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
            for info in mappings:
                self.user_id_sock_mapping[info[0]].pop(info[1], None)
                if len(self.user_id_sock_mapping[info[0]]) == 0:
                    self.user_id_sock_mapping[info[0]].pop(info[1], None)
                self.networking.remove_user_id(info[0], info[1])
            socket.shutdown(py_socket.SHUT_RDWR)
            socket.close()
        except:
            pass
        self.logger.debug("connection closed")

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
        #self.logger.debug("process message from %s: %s" % (binascii.b2a_hex(dat[KeyType.source_user_id]), dat))
        if not self.param_check([KeyType.command, KeyType.source_user_id], dat):
            self.logger.debug("message has bad format")
            return False, None
        cmd = dat[KeyType.command]
        if cmd == MsgType.REQUEST_SEARCH_TRANSACTION:
            if not self.param_check([KeyType.asset_group_id, KeyType.transaction_id], dat):
                self.logger.debug("REQUEST_SEARCH_TRANSACTION: bad format")
                return False, None
            result = self.search_transaction_by_txid(dat[KeyType.asset_group_id], dat[KeyType.transaction_id],
                                                     dat[KeyType.source_user_id], dat[KeyType.query_id])
            if result is not None:
                self.send_message(result)

        elif cmd == MsgType.REQUEST_SEARCH_ASSET:
            if not self.param_check([KeyType.asset_group_id, KeyType.asset_id], dat):
                self.logger.debug("REQUEST_SEARCH_ASSET: bad format")
                return False, None
            retmsg = make_message_structure(MsgType.RESPONSE_SEARCH_ASSET,
                                            dat[KeyType.asset_group_id],
                                            dat[KeyType.source_user_id], dat[KeyType.query_id])
            result = self.search_asset_by_asid(dat[KeyType.asset_group_id], dat[KeyType.asset_id], dat[KeyType.source_user_id], dat[KeyType.query_id])
            if isinstance(result, dict):
                retmsg.update(result)
                self.send_message(retmsg)

        elif cmd == MsgType.REQUEST_GATHER_SIGNATURE:
            if not self.param_check([KeyType.asset_group_id, KeyType.transaction_data], dat):
                self.logger.debug("REQUEST_GATHER_SIGNATURE: bad format")
                return False, None
            if not self.distribute_transaction_to_gather_signatures(dat[KeyType.asset_group_id], dat):
                retmsg = make_message_structure(MsgType.RESPONSE_GATHER_SIGNATURE,
                                                dat[KeyType.asset_group_id], dat[KeyType.source_user_id], dat[KeyType.query_id])
                self.error_reply(msg=retmsg, err_code=EINVALID_COMMAND, txt="Fail to forward transaction")

        elif cmd == MsgType.REQUEST_INSERT:
            if not self.param_check([KeyType.asset_group_id, KeyType.transaction_data,
                                     KeyType.all_asset_files], dat):
                self.logger.debug("REQUEST_INSERT: bad format")
                return False, None
            transaction_data = dat[KeyType.transaction_data]
            asset_files = dat[KeyType.all_asset_files]
            retmsg = make_message_structure(MsgType.RESPONSE_INSERT,
                                            dat[KeyType.asset_group_id], dat[KeyType.source_user_id], dat[KeyType.query_id])
            ret = self.insert_transaction(dat[KeyType.asset_group_id], transaction_data, asset_files)
            if isinstance(ret, str):
                self.error_reply(msg=retmsg, err_code=EINVALID_COMMAND, txt=ret)
            else:
                retmsg.update(ret)
                self.send_message(retmsg)

        elif cmd == MsgType.RESPONSE_SIGNATURE:
            if not self.param_check([KeyType.asset_group_id, KeyType.destination_user_id, KeyType.source_user_id], dat):
                self.logger.debug("RESPONSE_SIGNATURE: bad format")
                return False, None
            retmsg = make_message_structure(MsgType.RESPONSE_GATHER_SIGNATURE,
                                            dat[KeyType.asset_group_id], dat[KeyType.destination_user_id], dat[KeyType.query_id])
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
            self.send_to_other_user(dat[KeyType.asset_group_id],
                                    dat[KeyType.destination_user_id],
                                    dat[KeyType.source_user_id],
                                    retmsg)

        elif cmd == MsgType.REQUEST_CROSS_REF:
            if KeyType.count in dat:
                num = dat[KeyType.count]
            else:
                num = 1
            retmsg = make_message_structure(MsgType.RESPONSE_CROSS_REF,
                                            dat[KeyType.asset_group_id], dat[KeyType.source_user_id], dat[KeyType.query_id])
            retmsg[KeyType.cross_refs] = self.pop_cross_refs(num=num)
            self.send_message(retmsg)

        elif cmd == MsgType.MESSAGE:
            if not self.param_check([KeyType.asset_group_id, KeyType.source_user_id, KeyType.destination_user_id], dat):
                self.logger.debug("MESSAGE: bad format")
                return False, None
            domain_id = self.asset_group_domain_mapping[dat[KeyType.asset_group_id]]
            self.networking.route_message(domain_id, dat[KeyType.asset_group_id],
                                          dat[KeyType.destination_user_id],
                                          dat[KeyType.source_user_id], dat)

        elif cmd == MsgType.REQUEST_REGISTER_HASH_IN_SUBSYS:
            if not self.param_check([KeyType.asset_group_id, KeyType.transaction_id], dat):
                self.logger.debug("REQUEST_REGISTER_HASH_IN_SUBSYS: bad format")
                return False, None
            asset_group_id = dat[KeyType.asset_group_id]
            transaction_id = dat[KeyType.transaction_id]
            self.ledger_subsystem.register_transaction(asset_group_id=asset_group_id, transaction_id=transaction_id)
            retmsg = make_message_structure(MsgType.RESPONSE_REGISTER_HASH_IN_SUBSYS,
                                            dat[KeyType.asset_group_id], dat[KeyType.source_user_id], dat[KeyType.query_id])
            self.send_message(retmsg)

        elif cmd == MsgType.REQUEST_VERIFY_HASH_IN_SUBSYS:
            if not self.param_check([KeyType.asset_group_id, KeyType.transaction_id], dat):
                self.logger.debug("REQUEST_REGISTER_HASH_IN_SUBSYS: bad format")
                return False, None
            asset_group_id = dat[KeyType.asset_group_id]
            transaction_id = dat[KeyType.transaction_id]
            retmsg = make_message_structure(MsgType.RESPONSE_VERIFY_HASH_IN_SUBSYS,
                                            dat[KeyType.asset_group_id], dat[KeyType.source_user_id], dat[KeyType.query_id])
            result = self.ledger_subsystem.verify_transaction(asset_group_id=asset_group_id,
                                                              transaction_id=transaction_id)
            retmsg[KeyType.merkle_tree] = result
            self.send_message(retmsg)

        elif cmd == MsgType.REGISTER:
            if not self.param_check([KeyType.asset_group_id, KeyType.source_user_id], dat):
                self.logger.debug("REGISTER: bad format")
                return False, None
            user_id = dat[KeyType.source_user_id]
            asset_group_id = dat[KeyType.asset_group_id]
            if asset_group_id in self.asset_group_domain_mapping:
                domain_id = self.asset_group_domain_mapping[asset_group_id]
                self.logger.debug("[%s] register_user: %s" % (binascii.b2a_hex(domain_id[:2]),
                                                              binascii.b2a_hex(user_id[:4])))
                self.networking.register_user_id(domain_id, asset_group_id, user_id)
                self.user_id_sock_mapping.setdefault(asset_group_id, {})[user_id] = socket
                return False, (asset_group_id, user_id)
            return False, None

        elif cmd == MsgType.UNREGISTER:
            return True, None

        elif cmd == MsgType.REQUEST_SETUP_ASSET_GROUP:
            domain_id = dat.get(KeyType.domain_id, None)
            asset_group_id = dat.get(KeyType.asset_group_id, None)
            if domain_id is None or asset_group_id is None:
                return False, None
            if domain_id not in self.networking.domains:
                return False, None
            self.asset_group_setup(domain_id, asset_group_id, dat.get(KeyType.storage_type, StorageType.FILESYSTEM),
                                   dat.get(KeyType.storage_path,None), dat.get(KeyType.advertise_in_domain0, False),
                                   config_update=True)
            retmsg = make_message_structure(MsgType.RESPONSE_SETUP_ASSET_GROUP,
                                            dat[KeyType.asset_group_id], dat[KeyType.source_user_id], dat[KeyType.query_id])
            self.send_raw_message(socket, retmsg)

        elif cmd == MsgType.REQUEST_SETUP_DOMAIN:
            retmsg = make_message_structure(MsgType.RESPONSE_SETUP_DOMAIN,
                                            None, dat[KeyType.source_user_id], dat[KeyType.query_id])
            domain_id = dat.get(KeyType.domain_id, None)
            if domain_id is None:
                retmsg[KeyType.result] = False
            else:
                self.networking.create_domain(domain_id=domain_id,
                                              network_module=dat.get(KeyType.network_module, "simple_cluster"))
                retmsg[KeyType.domain_id] = domain_id
                retmsg[KeyType.result] = True
                retmsg[KeyType.network_module] = self.networking.domains[domain_id].module_name
            self.send_raw_message(socket, retmsg)

        elif cmd == MsgType.REQUEST_GET_PEERLIST:
            domain_id = dat[KeyType.domain_id]
            retmsg = make_message_structure(MsgType.RESPONSE_GET_PEERLIST,
                                            None, dat[KeyType.source_user_id], dat[KeyType.query_id])
            if domain_id in self.networking.domains:
                retmsg[KeyType.domain_id] = domain_id
                retmsg[KeyType.peer_list] = self.networking.domains[domain_id].make_peer_list()
            self.send_raw_message(socket, retmsg)

        elif cmd == MsgType.REQUEST_SET_STATIC_NODE:
            retmsg = make_message_structure(MsgType.RESPONSE_SET_STATIC_NODE,
                                            None, dat[KeyType.source_user_id], dat[KeyType.query_id])
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
            self.send_raw_message(socket, retmsg)

        elif cmd == MsgType.REQUEST_GET_CONFIG:
            retmsg = make_message_structure(MsgType.RESPONSE_GET_CONFIG,
                                            None, dat[KeyType.source_user_id], dat[KeyType.query_id])
            jsondat = self.config.get_json_config()
            retmsg[KeyType.bbc_configuration] = jsondat
            self.send_raw_message(socket, retmsg)

        elif cmd == MsgType.REQUEST_GET_PEERLIST:
            domain_id = dat[KeyType.domain_id]
            retmsg = make_message_structure(MsgType.RESPONSE_GET_PEERLIST,
                                            None, dat[KeyType.source_user_id], dat[KeyType.query_id])
            if domain_id in self.networking.domains:
                retmsg[KeyType.domain_id] = domain_id
                retmsg[KeyType.peer_list] = self.networking.domains[domain_id].make_peer_list()
            self.send_raw_message(socket, retmsg)

        elif cmd == MsgType.REQUEST_GET_DOMAINLIST:
            retmsg = make_message_structure(MsgType.RESPONSE_GET_DOMAINLIST,
                                            None, dat[KeyType.source_user_id], dat[KeyType.query_id])
            data = bytearray()
            data.extend(to_2byte(len(self.networking.domains)))
            for domain_id in self.networking.domains:
                data.extend(domain_id)
            retmsg[KeyType.domain_list] = bytes(data)
            self.send_raw_message(socket, retmsg)

        elif cmd == MsgType.DOMAIN_PING:
            if not self.param_check([KeyType.domain_id, KeyType.source_user_id, KeyType.ipv4_address,
                                     KeyType.ipv6_address, KeyType.port_number], dat):
                return False, None
            domain_id = dat[KeyType.domain_id]
            ipv4 = dat[KeyType.ipv4_address]
            ipv6 = dat[KeyType.ipv6_address]
            port = dat[KeyType.port_number]
            self.networking.send_raw_message(domain_id, ipv4, ipv6, port)

        elif cmd == MsgType.REQUEST_MANIP_LEDGER_SUBSYS:
            retmsg = make_message_structure(MsgType.RESPONSE_MANIP_LEDGER_SUBSYS,
                                            None, dat[KeyType.source_user_id], dat[KeyType.query_id])
            if dat[KeyType.ledger_subsys_manip]:
                self.ledger_subsystem.enable()
            else:
                self.ledger_subsystem.disable()
            self.ledger_subsystem.set_domain(dat[KeyType.domain_id])
            self.send_raw_message(socket, retmsg)

        else:
            self.logger.error("Bad command/response: %s" % cmd)
        return False, None

    def asset_group_setup(self, domain_id, asset_group_id, storage_type=StorageType.FILESYSTEM,
                          storage_path=None, advertise_in_domain0=False, config_update=False):
        """
        Setup asset_group in a specified domain

        :param domain_id:
        :param asset_group_id:
        :param storage_type:
        :param storage_path:
        :param advertise_in_domain0:
        :param config_update:
        :return:
        """
        if config_update:
            conf = self.config.get_asset_group_config(domain_id, asset_group_id, create_if_new=True)
            conf['storage_type'] = storage_type
            conf['storage_path'] = storage_path
            conf['advertise_in_domain0'] = advertise_in_domain0
            self.config.update_config()
        self.storage_manager.set_storage_path(domain_id, asset_group_id, from_config=True)
        self.asset_group_domain_mapping[asset_group_id] = domain_id
        if advertise_in_domain0:
            self.networking.asset_groups_to_advertise.add(asset_group_id)

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
            else:
                break
        return refs

    def validate_transaction(self, txid, txdata, asset_files):
        """
        Validate transaction by verifying signature

        :param txid:                transaction_id
        :param txdata:              BBcTransaction data
        :param asset_files:   dictionary of { asid=>asset_content,,, }
        """
        txobj = BBcTransaction()
        if not txobj.deserialize(txdata):
            self.logger.error("Fail to deserialize transaction data")
            return None
        digest = txobj.digest()
        if txid is not None and txid != digest:
            self.logger.error("Bad transaction_id")
            return None

        for i, sig in enumerate(txobj.signatures):
            try:
                if not sig.verify(digest):
                    self.logger.error("Bad signature [%i]" % i)
                    return None
            except:
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
                    self.logger.error("Bad asset_id for event[%d]" % idx)
                    return False
        return False

    def insert_transaction(self, asset_group_id, txdata, asset_files, no_network_put=False):
        """
        Insert transaction into ledger subsystem

        :param asset_group_id:      asset_group_id to insert into
        :param txdata:              BBcTransaction data
        :param asset_files:   dictionary of { asid=>asset_content,,, }
        :param no_network_put:      If false, skip networking.put()
        """
        domain_id = self.asset_group_domain_mapping.get(asset_group_id, None)
        if domain_id is None:
            self.logger.error("No such asset_group_id is set up in any domain")
            return "Set up the asset_group_id in a domain"
        if domain_id == bbclib.domain_global_0:
            self.logger.error("Insert is not allowed in domain_global_0")
            return "Insert is not allowed in domain_global_0"
        txobj = self.validate_transaction(None, txdata, asset_files)
        if txobj is None:
            self.logger.error("Bad transaction format")
            return "Bad transaction format"
        self.logger.debug("[node:%s] insert_transaction %s" %
                          (binascii.b2a_hex(self.networking.domains[domain_id].node_id[:4]),
                           binascii.b2a_hex(txobj.transaction_id[:4])))

        ret = self.ledger_manager.insert_locally(domain_id, asset_group_id, txobj.transaction_id,
                                                 ResourceType.Transaction_data, txdata)
        if not ret:
            self.logger.error("[%s] Fail to insert a transaction into the ledger"%
                              binascii.b2a_hex(self.networking.domains[domain_id].node_id[:4]))
            return "Failed to insert a transaction into the ledger"

        rollback_flag = False
        registered_asset_ids = []
        registered_asset_ids_in_storage = []
        for idx, evt in enumerate(txobj.events):
            if evt.asset is None:
                continue
            asid = evt.asset.asset_id
            if asset_files is not None and asid in asset_files.keys():
                if not self.storage_manager.store_locally(domain_id, asset_group_id, asid, asset_files[asid]):
                    rollback_flag = True
                    break
                registered_asset_ids_in_storage.append(asid)
            if not self.ledger_manager.insert_locally(domain_id, asset_group_id, asid,
                                                      ResourceType.Asset_ID, txobj.transaction_id):
                rollback_flag = True
                break
            user_id = evt.asset.user_id
            if not self.ledger_manager.insert_locally(domain_id, asset_group_id, user_id,
                                                      ResourceType.Owner_asset, asid,
                                                      require_uniqueness=False):
                rollback_flag = True
                break
            registered_asset_ids.append(asid)

        for reference in txobj.references:
            self.ledger_manager.insert_locally(domain_id, asset_group_id, txobj.transaction_id,
                                               ResourceType.Edge_outgoing, reference.transaction_id)
            self.ledger_manager.insert_locally(domain_id, asset_group_id, reference.transaction_id,
                                               ResourceType.Edge_incoming, txobj.transaction_id)

        if rollback_flag:
            self.ledger_manager.remove(domain_id, asset_group_id, txobj.transaction_id)
            for asid in registered_asset_ids:
                self.ledger_manager.remove(domain_id, asset_group_id, asid)
            for asid in registered_asset_ids_in_storage:
                self.storage_manager.remove(domain_id, asset_group_id, asid)
            return "Failed to register asset"

        if no_network_put:
            return None

        if len(txobj.cross_refs) > 0 or len(self.cross_ref_list) < 3:
            self.networking.disseminate_cross_ref(asset_group_id, txobj.transaction_id)

        self.networking.put(domain_id=domain_id, asset_group_id=asset_group_id, resource_id=txobj.transaction_id,
                            resource_type=ResourceType.Transaction_data, resource=txdata)
        if self.storage_manager.get_storage_type(domain_id, asset_group_id) != "NONE":
            for asid in registered_asset_ids_in_storage:
                self.networking.put(domain_id=domain_id, asset_group_id=asset_group_id, resource_id=asid,
                                    resource_type=ResourceType.Asset_file, resource=asset_files[asid])
        return {KeyType.transaction_id: txobj.transaction_id}

    def distribute_transaction_to_gather_signatures(self, asset_group_id, dat):
        """
        Request to distribute sign_request to users

        :param asset_group_id:
        :param dat:
        :return:
        """
        destinations = dat[KeyType.destination_user_ids]
        for dst in destinations:
            if dst == dat[KeyType.source_user_id]:
                continue
            msg = make_message_structure(MsgType.REQUEST_SIGNATURE, asset_group_id, dst, dat[KeyType.query_id])
            msg[KeyType.source_user_id] = dat[KeyType.source_user_id]
            msg[KeyType.transaction_data] = dat[KeyType.transaction_data]
            if KeyType.transactions in dat:
                msg[KeyType.transactions] = dat[KeyType.transactions]
            if KeyType.all_asset_files in dat:
                msg[KeyType.all_asset_files] = dat[KeyType.all_asset_files]
            if not self.send_to_other_user(asset_group_id, dst, dat[KeyType.source_user_id], msg):
                return False
        return True

    def search_asset_by_asid(self, asset_group_id, asid, source_id, query_id):
        """
        Search asset in the storage by asset_id. If not found, search it in the network

        :param asset_group_id:   asset_group_id to search in
        :param asid:        asset_id in byte format
        :param source_id: the user_id of the sender
        :param query_id:
        :return: dictionary data of transaction_data, asset_file (if exists)
        """
        response_info = make_message_structure(MsgType.RESPONSE_SEARCH_ASSET,
                                               asset_group_id, source_id, query_id)
        domain_id = self.asset_group_domain_mapping.get(asset_group_id, None)
        if domain_id is None:
            self.logger.error("No such asset_group_id is set up in any domain")
            return None
        response_info[KeyType.asset_id] = asid

        txid = self.ledger_manager.find_locally(domain_id, asset_group_id, asid, ResourceType.Asset_ID)
        if txid is None:
            query_entry = query_management.QueryEntry(expire_after=DURATION_GIVEUP_GET,
                                                      callback_expire=self.failure_response,
                                                      data={'response_info': response_info,
                                                            KeyType.domain_id: domain_id,
                                                            KeyType.asset_group_id: asset_group_id,
                                                            KeyType.asset_id: asid,
                                                            KeyType.resource_id: asid,
                                                            KeyType.resource_type: ResourceType.Asset_ID},
                                                      retry_count=GET_RETRY_COUNT)
            query_entry.update(fire_after=INTERVAL_RETRY, callback=self.search_transaction_for_asset)
            self.networking.get(query_entry)
            return None

        txdata = self.ledger_manager.find_locally(domain_id, asset_group_id, txid, ResourceType.Transaction_data)
        if txdata is not None:
            txobj = self.validate_transaction(txid, txdata, None)
            if txobj is None:
                txdata = None
                self.ledger_manager.remove(domain_id, asset_group_id, txid)

        if txdata is None:
            query_entry = query_management.QueryEntry(expire_after=DURATION_GIVEUP_GET,
                                                      callback_expire=self.failure_response,
                                                      data={'response_info': response_info,
                                                            KeyType.domain_id: domain_id,
                                                            KeyType.asset_group_id: asset_group_id,
                                                            KeyType.asset_id: asid,
                                                            KeyType.resource_id: txid,
                                                            KeyType.resource_type: ResourceType.Transaction_data},
                                                      retry_count=GET_RETRY_COUNT)
            query_entry.update(fire_after=INTERVAL_RETRY, callback=self.check_asset_in_response)
            self.networking.get(query_entry)
            return None

        response_info[KeyType.transaction_data] = txdata
        if check_transaction_if_having_asset_file(txdata, asid):
            asset_file = self.storage_manager.get_locally(domain_id, asset_group_id, asid)  # FIXME: to support storage_type=NONE
            if asset_file is not None:
                if not self.validate_asset_file(txobj, asid, asset_file):
                    asset_file = None
                    self.storage_manager.remove(domain_id, asset_group_id, asid)
            if asset_file is None:
                query_entry = query_management.QueryEntry(expire_after=DURATION_GIVEUP_GET,
                                                          callback_expire=self.failure_response,
                                                          data={'response_info': response_info,
                                                                KeyType.domain_id: domain_id,
                                                                KeyType.asset_group_id: asset_group_id,
                                                                KeyType.asset_id: asid,
                                                                KeyType.resource_id: asid,
                                                                KeyType.resource_type: ResourceType.Asset_file},
                                                          retry_count=GET_RETRY_COUNT)
                query_entry.update(fire_after=INTERVAL_RETRY, callback=self.check_asset_in_response)
                self.networking.get(query_entry)
                return None
            response_info[KeyType.asset_file] = asset_file
        return response_info

    def search_transaction_for_asset(self, query_entry):
        """
        (internal use) Search transaction that includes the specified asset_id

        :param query_entry:
        :return:
        """
        domain_id = query_entry.data[KeyType.domain_id]
        asset_group_id = query_entry.data[KeyType.asset_group_id]
        if query_entry.data[KeyType.resource_type] == ResourceType.Asset_ID:  # resource is txid that includes the asset
            txid = query_entry.data[KeyType.resource]
            txdata = self.ledger_manager.find_locally(domain_id, asset_group_id, txid, ResourceType.Transaction_data)
        else:
            txid = query_entry.data[KeyType.resource_id]
            txdata = query_entry.data[KeyType.resource]

        if txdata is not None:
            txobj = self.validate_transaction(txid, txdata, None)
            if txobj is None:
                txdata = None
                self.ledger_manager.remove(domain_id, asset_group_id, txid)
        if txdata is None:
            del query_entry.data[KeyType.resource]
            query_entry.data.update({KeyType.resource_id: txid, KeyType.resource_type: ResourceType.Transaction_data})
            query_entry.retry_count = GET_RETRY_COUNT
            query_entry.update(fire_after=INTERVAL_RETRY, callback=self.check_asset_in_response)
            self.networking.get(query_entry)
            return

        query_entry.data['response_info'][KeyType.transaction_data] = txdata
        asid = query_entry.data[KeyType.asset_id]
        if check_transaction_if_having_asset_file(txdata, asid):
            asset_file = self.storage_manager.get_locally(domain_id, asset_group_id, asid)  # FIXME: to support storage_type=NONE
            if asset_file is not None:
                if not self.validate_asset_file(txobj, asid, asset_file):
                    asset_file = None
                    self.storage_manager.remove(domain_id, asset_group_id, asid)
            if asset_file is None:
                del query_entry.data[KeyType.resource]
                query_entry.data.update({KeyType.resource_id: asid, KeyType.resource_type: ResourceType.Asset_file})
                query_entry.retry_count = GET_RETRY_COUNT
                query_entry.update(fire_after=INTERVAL_RETRY, callback=self.check_asset_in_response)
                self.networking.get(query_entry)
                return None
            query_entry.data['response_info'][KeyType.asset_file] = asset_file
        self.send_message(query_entry.data['response_info'])

    def check_asset_in_response(self, query_entry):
        """
        (internal use) Check asset in the transaction

        :param query_entry:
        :return:
        """
        domain_id = query_entry.data[KeyType.domain_id]
        asset_group_id = query_entry.data[KeyType.asset_group_id]
        if query_entry.data[KeyType.resource_type] == ResourceType.Transaction_data:
            # FIXME: too redundant with the latter half of search_transaction_for_asset()
            txdata = query_entry.data[KeyType.resource]
            query_entry.data['response_info'][KeyType.transaction_data] = txdata
            asid = query_entry.data[KeyType.asset_id]
            if check_transaction_if_having_asset_file(txdata, asid):
                asset_file = self.storage_manager.get_locally(domain_id, asset_group_id, asid)  # FIXME: to support storage_type=NONE
                txobj = BBcTransaction()
                txobj.deserialize(txdata)
                if asset_file is not None:
                    if not self.validate_asset_file(txobj, asid, asset_file):
                        asset_file = None
                        self.storage_manager.remove(domain_id, asset_group_id, asid)
                if asset_file is None:
                    del query_entry.data[KeyType.resource]
                    query_entry.data.update({KeyType.resource_id: asid, KeyType.resource_type: ResourceType.Asset_file})
                    query_entry.retry_count = GET_RETRY_COUNT
                    query_entry.update(fire_after=INTERVAL_RETRY, callback=self.check_asset_in_response)
                    self.networking.get(query_entry)
                    return None
                query_entry.data['response_info'][KeyType.asset_file] = asset_file
                self.storage_manager.store_locally(domain_id, asset_group_id, asid, asset_file)
        else:
            query_entry.data['response_info'][KeyType.asset_file] = query_entry.data[KeyType.resource]
            self.storage_manager.store_locally(domain_id, asset_group_id, query_entry.data[KeyType.asset_id],
                                               query_entry.data[KeyType.resource])
        self.send_message(query_entry.data['response_info'])

    def search_transaction_by_txid(self, asset_group_id, txid, source_id, query_id):
        """
        Search transaction_data by transaction_id

        :param asset_group_id:   asset_group_id to search in
        :param txid:  transaction_id
        :param source_id: the user_id of the sender
        :param query_id:
        :return: dictionary data of transaction_data
        """
        domain_id = self.asset_group_domain_mapping.get(asset_group_id, None)
        if domain_id is None:
            self.logger.error("No such asset_group_id is set up in any domain")
            return None

        txdata = self.ledger_manager.find_locally(domain_id, asset_group_id, txid, ResourceType.Transaction_data)
        if txdata is not None and self.validate_transaction(txid, txdata, None) is None:
            txdata = None
            self.ledger_manager.remove(domain_id, asset_group_id, txid)
        response_info = make_message_structure(MsgType.RESPONSE_SEARCH_TRANSACTION,
                                               asset_group_id, source_id, query_id)
        if txdata is None:
            query_entry = query_management.QueryEntry(expire_after=DURATION_GIVEUP_GET,
                                                      callback_expire=self.failure_response,
                                                      data={'response_info': response_info,
                                                            KeyType.domain_id: domain_id,
                                                            KeyType.asset_group_id: asset_group_id,
                                                            KeyType.resource_id: txid,
                                                            KeyType.resource_type: ResourceType.Transaction_data},
                                                      retry_count=GET_RETRY_COUNT)
            query_entry.update(fire_after=INTERVAL_RETRY, callback=self.succeed_to_find_transaction)
            self.networking.get(query_entry)
            return None
        response_info[KeyType.transaction_data] = txdata
        return response_info

    def add_cross_ref_into_list(self, asset_group_id, txid):
        """
        (internal use) register cross_ref info in the list

        :param asset_group_id:
        :param txid:
        :return:
        """
        self.cross_ref_list.append([asset_group_id, txid])

    def send_response(self, response_info, dat):
        """
        (internal use) send response message

        :param response_info:
        :param dat:
        :return:
        """
        response_info.update(dat)
        self.send_message(response_info)

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

    def succeed_to_find_transaction(self, query_entry):
        """
        (internal use) Called when transaction search is successful

        :param query_entry:
        :return:
        """
        self.ledger_manager.insert_locally(query_entry.data[KeyType.domain_id], query_entry.data[KeyType.asset_group_id],
                                           query_entry.data[KeyType.resource_id],
                                           ResourceType.Transaction_data, query_entry.data[KeyType.resource])
        response_info = query_entry.data['response_info']
        response_info[KeyType.transaction_data] = query_entry.data[KeyType.resource]
        self.send_message(response_info)

    def failure_response(self, query_entry):
        """
        (internal use) Called when transaction search fails

        :param query_entry:
        :return:
        """
        response_info = query_entry.data['response_info']
        if query_entry.data[KeyType.resource_type] == ResourceType.Transaction_data:
            self.error_reply(msg=response_info, err_code=ENOTRANSACTION, txt="Cannot find transaction")
        elif query_entry.data[KeyType.resource_type] == ResourceType.Asset_ID:
            self.error_reply(msg=response_info, err_code=ENOASSET, txt="Cannot find asset")
        elif query_entry.data[KeyType.resource_type] == ResourceType.Asset_file:
            self.error_reply(msg=response_info, err_code=ENOTINSTORAGE, txt="Cannot find asset file")


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
        ipv6=argresult.ipv6,
        p2p_port=argresult.p2pport,
        core_port=argresult.coreport,
        workingdir=argresult.workingdir,
        configfile=argresult.config,
        use_global=argresult.globaldomain,
        logname=argresult.log,
        loglevel=argresult.verbose_level,
    )
