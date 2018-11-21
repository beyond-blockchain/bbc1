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

import json
import hashlib
import time
import threading
import queue
import os
import sys
sys.path.extend(["../../", os.path.abspath(os.path.dirname(__file__))])
from bbc1.core.data_handler import DataHandler
from bbc1.core.bbc_stats import BBcStats
from bbc1.core import bbclib
from bbc1.core.message_key_types import PayloadType, KeyType, InfraMessageCategory
from bbc1.core import logger


class RepairManager:
    """Data repair manager for forged transaction/asset"""
    REQUEST_REPAIR_TRANSACTION = 0
    REQUEST_REPAIR_ASSET_FILE = 1
    REQUEST_TO_SEND_TRANSACTION_DATA = 2
    RESPONSE_TRANSACTION_DATA = 3
    REQUEST_TO_SEND_ASSET_FILE = 4
    RESPONSE_ASSET_FILE = 5

    def __init__(self, network=None, domain_id=None, workingdir=".", loglevel="all", logname=None):
        if network is not None:
            self.network = network
            self.core = network.core
            self.stats = network.core.stats
            self.data_handler = network.domains[domain_id]['data']
        else:
            self.stats = BBcStats()
        self.repair_log = os.path.join(workingdir, domain_id.hex(), "repair_log.json")
        self.logger = logger.get_logger(key="repair_manager", level=loglevel, logname=logname)
        self.domain_id = domain_id
        self.queue = queue.Queue()
        self.requesting_list = dict()
        self.loop_flag = True
        th_nw_loop = threading.Thread(target=self._manager_loop)
        th_nw_loop.setDaemon(True)
        th_nw_loop.start()

    def _output_log(self, repair_info):
        """Output log in json format"""
        with open(self.repair_log, "a") as f:
            f.write(json.dumps(repair_info)+"\n")

    def exit_loop(self):
        """Exit the manager loop"""
        self.loop_flag = False
        self.put_message()

    def _manager_loop(self):
        """Main loop"""
        while self.loop_flag:
            msg = self.queue.get()
            if msg is None:
                continue
            if msg[KeyType.command] == RepairManager.REQUEST_REPAIR_TRANSACTION:
                self._repair_transaction_data(msg[KeyType.transaction_id])
            elif msg[KeyType.command] == RepairManager.REQUEST_REPAIR_ASSET_FILE:
                self._repair_asset_file(msg[KeyType.asset_group_id], msg[KeyType.asset_id])
            elif msg[KeyType.command] == RepairManager.REQUEST_TO_SEND_TRANSACTION_DATA:
                self._send_transaction_data(msg)
            elif msg[KeyType.command] == RepairManager.RESPONSE_TRANSACTION_DATA:
                self._receive_transaction_data_from_others(msg)
            elif msg[KeyType.command] == RepairManager.REQUEST_TO_SEND_ASSET_FILE:
                self._send_asset_file(msg)
            elif msg[KeyType.command] == RepairManager.RESPONSE_ASSET_FILE:
                self._receive_asset_file_from_others(msg)

    def put_message(self, msg=None):
        """append a message to the queue"""
        self.queue.put(msg)

    def _repair_transaction_data(self, transaction_id):
        """Repair forged transaction_data or asset_file by getting legitimate one from other nodes

        Args:
            transaction_id (bytes): target transaction_id
        """
        #print("_repair_transaction_data:")
        self.stats.update_stats_increment("transaction", "repair_request", 1)
        forged_asset_files = set()
        if len(self.data_handler.db_adaptors) > 1:
            valid_txobj = None
            db_nums_with_invalid_data = list()
            for idx in range(1, len(self.data_handler.db_adaptors)):
                result_txobj, result_asset_files = self.data_handler.search_transaction(transaction_id=transaction_id, db_num=idx)
                txobj_is_valid, valid_assets, invalid_assets = bbclib.validate_transaction_object(result_txobj[0],
                                                                                                       result_asset_files)
                if txobj_is_valid and valid_txobj is None:
                    valid_txobj = result_txobj[0]
                if not txobj_is_valid:
                    db_nums_with_invalid_data.append(idx)
                if len(invalid_assets) > 0:
                    for ent in invalid_assets:
                        forged_asset_files.add(ent)
            if valid_txobj is None:
                self.stats.update_stats_increment("transaction", "fail_to_repair_in_local", 1)
                self.logger.fatal("Failed to repair transaction locally (transaction_id=%s in domain=%s)" %
                                  (transaction_id.hex(), self.domain_id.hex()))
            else:
                for i in db_nums_with_invalid_data:
                    self.data_handler.restore_transaction_data(db_num=i, transaction_id=transaction_id, txobj=valid_txobj)
                self.stats.update_stats_increment("transaction", "success_repair", 1)
            self._output_log({"transaction_id": transaction_id.hex(), "request_at": int(time.time()),
                             "repaired_by": "locally", "repaired_at": int(time.time())})

        if len(forged_asset_files) > 0:
            for asgid, ast in forged_asset_files:
                self._repair_asset_file(asset_group_id=asgid, asset_id=ast, need_check=False)

        if self.data_handler.replication_strategy == DataHandler.REPLICATION_EXT:
            return

        random_nonce = bbclib.get_random_value(4)
        while random_nonce in self.requesting_list:
            random_nonce = bbclib.get_random_value(4)
        self.requesting_list[random_nonce] = {
            "transaction_id": transaction_id.hex(),
            "request_at": int(time.time())
        }
        msg = {
            KeyType.domain_id: self.domain_id,
            KeyType.infra_msg_type: InfraMessageCategory.CATEGORY_DATA,
            KeyType.infra_command: DataHandler.REPAIR_TRANSACTION_DATA,
            KeyType.command: RepairManager.REQUEST_TO_SEND_TRANSACTION_DATA,
            KeyType.transaction_id: transaction_id,
            KeyType.nonce: random_nonce,
        }
        self.network.broadcast_message_in_network(domain_id=self.domain_id,
                                                  payload_type=PayloadType.Type_any, msg=msg)
        return

    def _repair_asset_file(self, asset_group_id, asset_id, need_check=True):
        """Repair forged asset_file by getting legitimate one from other nodes

        Args:
            asset_group_id (bytes): asset_group_id of the asset
            asset_id (bytes): asset_id of the asset
            need_check (bool): If True, check the digest of the asset file
        """
        #print("_repair_asset_file:")
        if self.data_handler.use_external_storage:
            return
        if need_check:
            asset_file = self.data_handler.get_in_storage(asset_group_id, asset_id)
            if asset_file is not None and asset_id == hashlib.sha256(asset_file).digest():
                return

        random_nonce = bbclib.get_random_value(4)
        while random_nonce in self.requesting_list:
            random_nonce = bbclib.get_random_value(4)
        self.requesting_list[random_nonce] = {
            "asset_group_id": asset_group_id.hex(),
            "asset_id": asset_id.hex(),
            "request_at": int(time.time())
        }
        msg = {
            KeyType.domain_id: self.domain_id,
            KeyType.infra_msg_type: InfraMessageCategory.CATEGORY_DATA,
            KeyType.infra_command: DataHandler.REPAIR_TRANSACTION_DATA,
            KeyType.command: RepairManager.REQUEST_TO_SEND_ASSET_FILE,
            KeyType.asset_group_id: asset_group_id,
            KeyType.asset_id: asset_id,
            KeyType.nonce: random_nonce,
        }
        self.network.broadcast_message_in_network(domain_id=self.domain_id,
                                                  payload_type=PayloadType.Type_any, msg=msg)

    def _send_transaction_data(self, dat):
        """Send transaction data if having valid one"""
        #print("_send_transaction_data::")
        transaction_id = dat[KeyType.transaction_id]
        for idx in range(len(self.data_handler.db_adaptors)):
            result_txobj, result_asset_files = self.data_handler.search_transaction(transaction_id=transaction_id, db_num=idx)
            txobj_is_valid, valid_assets, invalid_assets = bbclib.validate_transaction_object(result_txobj[transaction_id])
            if txobj_is_valid:
                dat[KeyType.command] = RepairManager.RESPONSE_TRANSACTION_DATA
                dat[KeyType.transaction_data] = bbclib.serialize(result_txobj[transaction_id])
                dat[KeyType.destination_node_id] = dat[KeyType.source_node_id]
                self.network.send_message_in_network(None, domain_id=self.domain_id, msg=dat)
                return

    def _receive_transaction_data_from_others(self, dat):
        """Receive transaction data from other core_nodes and check its validity

        Args:
            dat (dict): received message
        """
        #print("_receive_transaction_data_from_others:")
        if KeyType.transaction_data not in dat or KeyType.transaction_id not in dat or KeyType.nonce not in dat:
            return
        if dat[KeyType.nonce] not in self.requesting_list:
            return
        asset_files = dict()
        if KeyType.all_asset_files in dat:
            asset_files = dat[KeyType.all_asset_files]
        txobj, fmt_type = bbclib.deserialize(dat[KeyType.transaction_data])
        if txobj.transaction_data is None:
            return

        txobj_is_valid, valid_assets, invalid_assets = bbclib.validate_transaction_object(txobj, asset_files)
        if txobj_is_valid:
            self.stats.update_stats_increment("transaction", "success_repair", 1)
            for idx in range(len(self.data_handler.db_adaptors)):
                self.data_handler.restore_transaction_data(db_num=idx, transaction_id=txobj.transaction_id, txobj=txobj)
            add_info = {
                "repaired_by": dat[KeyType.source_node_id].hex(),
                "repaired_at": int(time.time())
            }
            self.requesting_list[dat[KeyType.nonce]].update(add_info)
            self._output_log(self.requesting_list[dat[KeyType.nonce]])
            del self.requesting_list[dat[KeyType.nonce]]

    def _send_asset_file(self, dat):
        """Send the asset file if having valid one

        Args:
            dat (dict): received message
        """
        #print("_send_asset_file::")
        asset_group_id = dat[KeyType.asset_group_id]
        asset_id = dat[KeyType.asset_id]
        asset_file = self.data_handler.get_in_storage(asset_group_id, asset_id)
        if asset_file is None:
            return
        result_txobj, result_asset_files = self.data_handler.search_transaction(asset_group_id=asset_group_id,
                                                                                asset_id=asset_id)
        txobj = next(iter(result_txobj.values()))
        txobj_is_valid, valid_assets, invalid_assets = bbclib.validate_transaction_object(txobj, result_asset_files)

        if (asset_group_id, asset_id) in valid_assets:
            dat[KeyType.command] = RepairManager.RESPONSE_ASSET_FILE
            dat[KeyType.asset_group_id] = asset_group_id
            dat[KeyType.asset_id] = asset_id
            dat[KeyType.asset_file] = asset_file
            dat[KeyType.destination_node_id] = dat[KeyType.source_node_id]
            self.network.send_message_in_network(None, domain_id=self.domain_id, msg=dat)

    def _receive_asset_file_from_others(self, dat):
        """Receive asset file from other core_nodes and check its validity

        Args:
            dat (dict): received message
        """
        #print("_receive_asset_file_from_others:")
        if KeyType.nonce not in dat or dat[KeyType.nonce] not in self.requesting_list:
            return
        if KeyType.asset_group_id not in dat or KeyType.asset_id not in dat or KeyType.asset_file not in dat:
            return

        asset_group_id = dat[KeyType.asset_group_id]
        asset_id = dat[KeyType.asset_id]
        asset_file = dat[KeyType.asset_file]
        if asset_file is None:
            return
        asset_files = {asset_id: asset_file}
        result_txobj, result_asset_files = self.data_handler.search_transaction(asset_group_id=asset_group_id,
                                                                                asset_id=asset_id)
        txobj = next(iter(result_txobj.values()))

        txobj_is_valid, valid_assets, invalid_assets = bbclib.validate_transaction_object(txobj, asset_files)

        if (asset_group_id, asset_id) in valid_assets:

            self.data_handler.store_in_storage(asset_group_id, asset_id, asset_file, do_overwrite=True)
            add_info = {
                "repaired_by": dat[KeyType.source_node_id].hex(),
                "repaired_at": int(time.time())
            }
            self.requesting_list[dat[KeyType.nonce]].update(add_info)
            self._output_log(self.requesting_list[dat[KeyType.nonce]])
            del self.requesting_list[dat[KeyType.nonce]]
