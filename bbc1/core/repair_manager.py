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
import time
import threading
import queue
import os
import sys
sys.path.extend(["../../", os.path.abspath(os.path.dirname(__file__))])
from bbc1.core.bbc_types import InfraMessageCategory
from bbc1.core.data_handler import DataHandler
from bbc1.core.bbc_stats import BBcStats
from bbc1.core import bbclib
from bbc1.core.message_key_types import PayloadType, KeyType
from bbc1.core import logger


class RepairManager:
    """
    Data repair messager for forged transaction/asset
    """
    REQUEST_REPAIR_TRANSACTION = 0
    REQUEST_TO_SEND_TRANSACTION_DATA = 1
    RESPONSE_TRANSACTION_DATA = 2

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
        th_nw_loop = threading.Thread(target=self.manager_loop)
        th_nw_loop.setDaemon(True)
        th_nw_loop.start()

    def output_log(self, repair_info):
        with open(self.repair_log, "a") as f:
            f.write(json.dumps(repair_info)+"\n")

    def exit_loop(self):
        self.loop_flag = False
        self.put_message()

    def manager_loop(self):
        while self.loop_flag:
            msg = self.queue.get()
            if msg is None:
                continue
            if msg[KeyType.command] == RepairManager.REQUEST_REPAIR_TRANSACTION:
                self.repair_transaction_data(msg[KeyType.transaction_id])
            elif msg[KeyType.command] == RepairManager.REQUEST_TO_SEND_TRANSACTION_DATA:
                self.send_transaction_data(msg)
            elif msg[KeyType.command] == RepairManager.RESPONSE_TRANSACTION_DATA:
                self.receive_transaction_data_from_others(msg)

    def put_message(self, msg=None):
        self.queue.put(msg)

    def repair_transaction_data(self, transaction_id):
        """
        Repair forged transaction_data or asset_file by getting legitimate one from other nodes
        :param domain_id:
        :param transaction_id:
        :return:
        """
        #print("repair_transaction_data:")
        self.stats.update_stats_increment("transaction", "repair_request", 1)
        if len(self.data_handler.db_adaptors) > 1:
            valid_txobj = None
            valid_asset_files = dict()
            db_nums_with_invalid_data = list()
            for idx in range(1, len(self.data_handler.db_adaptors)):
                result_txobj, result_asset_files = self.data_handler.search_transaction(transaction_id=transaction_id, db_num=idx)
                txobj_is_valid, valid_assets, invalid_assets = bbclib.validate_transaction_object(result_txobj[0],
                                                                                                  result_asset_files)
                if txobj_is_valid and valid_txobj is None:
                    valid_txobj = result_txobj[0]
                if not txobj_is_valid:
                    db_nums_with_invalid_data.append(idx)
                for ast, file in valid_assets.items():
                    valid_asset_files[ast] = file
            if valid_txobj is None:
                self.stats.update_stats_increment("transaction", "fail_to_repair_in_local", 1)
                self.logger.fatal("Failed to repair transaction locally (transaction_id=%s in domain=%s)" % (transaction_id.hex(),
                                                                                                   self.domain_id.hex()))
            else:
                for i in db_nums_with_invalid_data:
                    self.data_handler.restore_data(db_num=i, transaction_id=transaction_id, txobj=valid_txobj, asset_files=valid_assets)
                self.stats.update_stats_increment("transaction", "success_repair", 1)
            self.output_log({"transaction_id": transaction_id.hex(), "request_at": int(time.time()),
                             "repaired_by": "locally", "repaired_at": int(time.time())})

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

    def send_transaction_data(self, dat):
        """
        Send transaction data if having valid one
        :param dat:
        :return:
        """
        #print("send_transaction_data::")
        transaction_id = dat[KeyType.transaction_id]
        for idx in range(len(self.data_handler.db_adaptors)):
            result_txobj, result_asset_files = self.data_handler.search_transaction(transaction_id=transaction_id, db_num=idx)
            txobj_is_valid, valid_assets, invalid_assets = bbclib.validate_transaction_object(result_txobj[transaction_id],
                                                                                              result_asset_files)
            if txobj_is_valid and len(invalid_assets) == 0:
                dat[KeyType.command] = RepairManager.RESPONSE_TRANSACTION_DATA
                dat[KeyType.transaction_data] = result_txobj[transaction_id].transaction_data
                if len(valid_assets) > 0:
                    dat[KeyType.all_asset_files] = valid_assets
                else:
                    if KeyType.all_asset_files in dat:
                        del dat[KeyType.all_asset_files]
                dat[KeyType.destination_node_id] = dat[KeyType.source_node_id]
                self.network.send_message_in_network(None, domain_id=self.domain_id, msg=dat)
                return

    def receive_transaction_data_from_others(self, dat):
        """
        Receive transaction data from other core_nodes and check its validity
        :param dat:
        :return:
        """
        #print("receive_transaction_data_from_others:")
        if KeyType.transaction_data not in dat or KeyType.transaction_id not in dat or KeyType.nonce not in dat:
            return
        if dat[KeyType.nonce] not in self.requesting_list:
            return
        asset_files = dict()
        if KeyType.all_asset_files in dat:
            asset_files = dat[KeyType.all_asset_files]
        txobj = bbclib.BBcTransaction(deserialize=dat[KeyType.transaction_data])
        if txobj.transaction_data is None:
            return
        txobj_is_valid, valid_assets, invalid_assets = bbclib.validate_transaction_object(txobj, asset_files)
        if txobj_is_valid and len(invalid_assets) == 0:
            self.stats.update_stats_increment("transaction", "success_repair", 1)
            for idx in range(len(self.data_handler.db_adaptors)):
                self.data_handler.restore_data(db_num=idx, transaction_id=txobj.transaction_id,
                                               txobj=txobj, asset_files=valid_assets)
            add_info = {
                "repaired_by": dat[KeyType.source_node_id].hex(),
                "repaired_at": int(time.time())
            }
            self.requesting_list[dat[KeyType.nonce]].update(add_info)
            self.output_log(self.requesting_list[dat[KeyType.nonce]])
            del self.requesting_list[dat[KeyType.nonce]]

