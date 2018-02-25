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
import random
import struct

import sys
sys.path.extend(["../../"])
from bbc1.common import bbclib
from bbc1.common.message_key_types import to_2byte, PayloadType, KeyType
from bbc1.core.bbc_types import InfraMessageTypeBase
from bbc1.core import query_management, simple_cluster


INTERVAL_RETRY = 3
FORWARD_CACHE_SIZE = 1000
ZEROS = bytes([0] * 32)

DOMAIN_INFO_LIFETIME = 1800

ticker = query_management.get_ticker()


class DomainInfo:
    def __init__(self, domain_id, del_func):
        self.domain_id = domain_id
        self.domains = dict()
        self.del_func = del_func

    def get_nodes(self):
        return self.domains.keys()

    def add_node(self, node_id):
        if node_id not in self.domains:
            self.domains[node_id] = query_management.QueryEntry(expire_after=DOMAIN_INFO_LIFETIME,
                                                                callback_expire=self.remove_entry,
                                                                data={KeyType.node_id: node_id},
                                                                retry_count=0)
        else:
            self.domains[node_id].update_expiration_time(DOMAIN_INFO_LIFETIME)

    def remove_entry(self, query_entry):
        self.domains.pop(query_entry.data[KeyType.node_id], None)
        self.del_func(self.domains)


class NetworkDomain(simple_cluster.NetworkDomain):
    """
    Compose a simple core node cluster
    """
    def __init__(self, network=None, config=None, domain_id=None, node_id=None, loglevel="all", logname=None):
        super(NetworkDomain, self).__init__(network, config, domain_id, node_id, loglevel, logname)
        self.module_name = "simple_cluster"  # TODO: this is temporary module
        self.domain_list = dict()
        self.periodic_advertising_domain_info()

    def domain_manager_loop(self):
        """
        (internal use) maintain domain (e.g., updating peer list and topology)

        :return:
        """
        pass

    def periodic_advertising_domain_info(self, query_entry=None):
        self.advertise_domain_info()
        query_management.exec_func_after(self.periodic_advertising_domain_info,
                                         random.randint(int(DOMAIN_INFO_LIFETIME * 0.4),
                                                        int(DOMAIN_INFO_LIFETIME * 0.6)))

    def advertise_domain_info(self):
        """
        Advertise domain information in domain_global_0

        :return:
        """
        data = bytearray()
        count = len(self.network.domains)
        data.extend(to_2byte(count))
        for domain_id in self.network.domains:
            if domain_id != bbclib.domain_global_0:
                data[0:2] = to_2byte(count-1)
                data.extend(domain_id)

        msg = self.make_message(dst_node_id=None, msg_type=InfraMessageTypeBase.ADVERTISE_DOMAIN_INFO)
        msg[KeyType.domain_list] = bytes(data)
        for nd in self.id_ip_mapping.keys():
            msg[KeyType.destination_node_id] = nd
            self.send_message_to_peer(msg)

    def update_domain_info(self, source_node_id, domain_id):
        """
        (internal use) update asset_group info (self.domain_list)

        :param source_node_id:
        :param domain_id:
        :return:
        """
        if domain_id not in self.domain_list:
            self.domain_list[domain_id] = DomainInfo(domain_id, self.delete_domain_from_info)
        self.domain_list[domain_id].add_node(source_node_id)

    def delete_domain_from_info(self, domain_id):
        """
        (internal use) delete asset_group_id

        :param domain_id:
        :return:
        """
        if len(self.domain_list[domain_id].get_nodes()) == 0:
            self.domain_list.pop(domain_id, None)

    def print_domain_info(self):
        if self.domain_list is None:
            self.logger.info("** No domain_id..")
        self.logger.info("========================")
        for domain_id in self.domain_list.keys():
            self.logger.info("Domain: %s" % binascii.b2a_hex(domain_id[:4]))
            for nd in self.domain_list[domain_id].get_nodes():
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

        if msg[KeyType.p2p_msg_type] == InfraMessageTypeBase.ADVERTISE_DOMAIN_INFO:
            if KeyType.domain_list not in msg or KeyType.source_node_id not in msg:
                return
            self.add_peer_node(msg[KeyType.source_node_id], ip4, from_addr)
            self.process_ADVERTISE_DOMAIN_INFO(msg)

    def process_ADVERTISE_DOMAIN_INFO(self, msg):
        source_node_id = msg[KeyType.source_node_id]
        data = msg[KeyType.domain_list]
        count = struct.unpack(">H", data[:2])[0]
        ptr = 2
        for i in range(count):
            domain_id = data[ptr:ptr+32]
            self.update_domain_info(source_node_id, domain_id)
