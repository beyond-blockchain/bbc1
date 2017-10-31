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
import binascii
import time
import random
import struct

import sys
sys.path.extend(["../../"])
from bbc1.common.message_key_types import to_2byte, PayloadType, KeyType
from bbc1.core.bbc_network import InfraMessageTypeBase
from bbc1.core import query_management, simple_cluster


INTERVAL_RETRY = 3
FORWARD_CACHE_SIZE = 1000
ZEROS = bytes([0] * 32)

ASSET_GROUP_INFO_LIFETIME = 1800

ticker = query_management.get_ticker()


class AssetGroupInfo:
    def __init__(self, asset_group_id, del_func):
        self.asset_group_id = asset_group_id
        self.asset_groups = dict()
        self.del_func = del_func

    def get_nodes(self):
        return self.asset_groups.keys()

    def add_node(self, node_id):
        if node_id not in self.asset_groups:
            self.asset_groups[node_id] = query_management.QueryEntry(expire_after=ASSET_GROUP_INFO_LIFETIME,
                                                                     callback_expire=self.remove_entry,
                                                                     data={KeyType.node_id: node_id},
                                                                     retry_count=0)
        else:
            self.asset_groups[node_id].update_expiration_time(ASSET_GROUP_INFO_LIFETIME)

    def remove_entry(self, query_entry):
        self.asset_groups.pop(query_entry.data[KeyType.node_id], None)
        self.del_func(self.asset_group_id)


class NetworkDomain(simple_cluster.NetworkDomain):
    """
    Compose a simple core node cluster
    """
    def __init__(self, network=None, config=None, domain_id=None, node_id=None, loglevel="all", logname=None):
        super(NetworkDomain, self).__init__(network, config, domain_id, node_id, loglevel, logname)
        self.module_name = "simple_cluster"  # TODO: this is temporary module
        self.asset_group_list = dict()
        self.periodic_advertising_asset_group_info()

    def domain_manager_loop(self):
        """
        (internal use) maintain domain (e.g., updating peer list and topology)

        :return:
        """
        pass

    def periodic_advertising_asset_group_info(self, query_entry=None):
        self.advertise_asset_group_info()
        query_management.exec_func_after(self.periodic_advertising_asset_group_info,
                                         random.randint(int(ASSET_GROUP_INFO_LIFETIME * 0.4),
                                                        int(ASSET_GROUP_INFO_LIFETIME * 0.6)))

    def advertise_asset_group_info(self):
        """
        Advertise domain information in domain_global_0

        :return:
        """
        data = bytearray()
        count = len(self.network.asset_groups_to_advertise)
        data.extend(to_2byte(count))
        for asset_group_id in self.network.asset_groups_to_advertise:
            data.extend(asset_group_id)

        msg = self.make_message(dst_node_id=None, msg_type=InfraMessageTypeBase.ADVERTISE_ASSET_GROUP)
        msg[KeyType.asset_group_list] = bytes(data)
        for nd in self.id_ip_mapping.keys():
            msg[KeyType.destination_node_id] = nd
            self.send_message_to_peer(msg)

    def update_asset_group_info(self, source_node_id, asset_group_id):
        """
        (internal use) update asset_group info (self.asset_group_list)

        :param source_node_id:
        :param asset_group_id:
        :return:
        """
        if asset_group_id not in self.asset_group_list:
            self.asset_group_list[asset_group_id] = AssetGroupInfo(asset_group_id, self.delete_asset_group_from_info)
        self.asset_group_list[asset_group_id].add_node(source_node_id)

    def delete_asset_group_from_info(self, asset_group_id):
        """
        (internal use) delete asset_group_id

        :param asset_group_id:
        :return:
        """
        if len(self.asset_group_list[asset_group_id].get_nodes()) == 0:
            self.asset_group_list.pop(asset_group_id, None)

    def print_asset_group_info(self):
        if self.asset_group_list is None:
            self.logger.info("** No asset_group_id..")
        self.logger.info("========================")
        for asset_group_id in self.asset_group_list.keys():
            self.logger.info("AssetGroup: %s" % binascii.b2a_hex(asset_group_id[:4]))
            for nd in self.asset_group_list[asset_group_id].get_nodes():
                self.logger.info("  * node_id: %s" % binascii.b2a_hex(nd[:4]))
        self.logger.info("========================")

    def process_message(self, ip4, from_addr, msg):
        """
        process received message

        :param ip4:       True (from IPv4) / False (from IPv6)
        :param from_addr: sender address and port (None if TCP)
        :param msg:       the message body (already deserialized)
        :return:
        """
        super(NetworkDomain, self).process_message(ip4, from_addr, msg)

        if msg[KeyType.p2p_msg_type] == InfraMessageTypeBase.ADVERTISE_ASSET_GROUP:
            if KeyType.asset_group_list not in msg or KeyType.source_node_id not in msg:
                return
            self.add_peer_node(msg[KeyType.source_node_id], ip4, from_addr)
            self.process_ADVERTISE_ASSET_GROUP(msg)

    def process_ADVERTISE_ASSET_GROUP(self, msg):
        source_node_id = msg[KeyType.source_node_id]
        data = msg[KeyType.asset_group_list]
        count = struct.unpack(">H", data[:2])[0]
        ptr = 2
        for i in range(count):
            asset_group_id = data[ptr:ptr+32]
            self.update_asset_group_info(source_node_id, asset_group_id)
