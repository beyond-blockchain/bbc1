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

import socket
import random
import binascii

import os
import sys
sys.path.extend(["../../", os.path.abspath(os.path.dirname(__file__))])
from bbc1.core.bbc_types import InfraMessageCategory
from bbc1.core import query_management
from bbc1.common.message_key_types import to_2byte, PayloadType, KeyType
from bbc1.common import logger


ticker = query_management.get_ticker()


class TopologyManagerBase:
    """
    Network topology management for a domain

    This class defines how to create topology, meaning that who should be neighbors and provides very simple topology
    management, that is full mesh topology. If P2P routing algorithm is needed, you should override this class
    to upgrade functions.
    This class does not manage the neighbor list itself (It's in BBcNetwork)
    """

    NOTIFY_NEIGHBOR_LIST = to_2byte(0)
    NEIGHBOR_LIST_REFRESH_INTERVAL = 300

    def __init__(self, network=None, config=None, domain_id=None, node_id=None, loglevel="all", logname=None):
        self.network = network
        self.stats = network.core.stats
        self.neighbors = network.domains[domain_id]['neighbor']
        self.config = config
        self.domain_id = domain_id
        self.logger = logger.get_logger(key="topology_manager:%s" % binascii.b2a_hex(domain_id[:4]).decode(),
                                        level=loglevel, logname=logname)
        self.my_node_id = node_id
        self.advertise_wait_entry = None
        self.neighbor_refresh_timer_entry = None
        self.update_refresh_timer_entry()

    def stop_all_timers(self):
        """
        Invalidate all running timers
        :return:
        """
        if self.advertise_wait_entry is not None:
            self.advertise_wait_entry.deactivate()
        if self.neighbor_refresh_timer_entry is not None:
            self.neighbor_refresh_timer_entry.deactivate()

    def resolve_next_hop(self, destination_id):
        """
        Determine next hop node to forward message
        :param destination_id:
        :return:
        """
        if destination_id in self.neighbors.nodeinfo_list:
            return destination_id
        else:
            return None
        pass

    def notify_neighbor_update(self, node_id, is_new=True):
        """
        Notified when neighbor node info is updated
        :param node_id:
        :param is_new:
        :return:
        """
        if node_id is not None:
            self.logger.debug("[%s] notify_neighbor_update: node_id=%s, is_new=%s" % (self.my_node_id.hex()[:4],
                                                                                      node_id.hex()[:4], is_new))
        else:
            self.logger.debug("[%s] notify_neighbor_update" % self.my_node_id.hex()[:4])

        rand_time = random.uniform(0.5, 1) * 5 / (len(self.neighbors.nodeinfo_list) + 1)
        if self.advertise_wait_entry is None:
            self.advertise_wait_entry = query_management.QueryEntry(expire_after=rand_time,
                                                                    callback_expire=self.advertise_neighbor_info,
                                                                    retry_count=0)
        else:
            self.advertise_wait_entry.update_expiration_time(rand_time)

    def update_refresh_timer_entry(self, new_entry=True):
        rand_interval = random.randint(int(TopologyManagerBase.NEIGHBOR_LIST_REFRESH_INTERVAL * 2 / 3),
                                       int(TopologyManagerBase.NEIGHBOR_LIST_REFRESH_INTERVAL * 4 / 3))
        self.logger.debug("update_refresh_timer_entry: %d" % rand_interval)
        if new_entry:
            self.neighbor_refresh_timer_entry = query_management.QueryEntry(
                expire_after=rand_interval, data={"is_refresh": True},
                callback_expire=self.advertise_neighbor_info, retry_count=0)
        else:
            self.neighbor_refresh_timer_entry.update_expiration_time(rand_interval)

    def advertise_neighbor_info(self, query_entry):
        """
        Broadcast nodeinfo list
        :return:
        """
        #print("[%s]: advertise_neighbor_info" % self.my_node_id.hex()[:4])
        self.advertise_wait_entry = None
        msg = {
            KeyType.infra_msg_type: InfraMessageCategory.CATEGORY_TOPOLOGY,
            KeyType.domain_id: self.domain_id,
            KeyType.command: TopologyManagerBase.NOTIFY_NEIGHBOR_LIST,
            KeyType.neighbor_list: self.make_neighbor_list(),
        }
        self.network.broadcast_message_in_network(domain_id=self.domain_id,
                                                  payload_type=PayloadType.Type_msgpack, msg=msg)
        if "is_refresh" in query_entry.data:
            self.update_refresh_timer_entry()

    def make_neighbor_list(self):
        """
        make nodelist binary for advertising
        :return:
        """
        nodeinfo = bytearray()

        # the node itself
        nodeinfo.extend(self.my_node_id)
        for item in self.neighbors.my_socket_info:
            nodeinfo.extend(item)
        count = 1

        # neighboring node
        for nd in self.neighbors.nodeinfo_list.keys():
            if self.neighbors.nodeinfo_list[nd].is_alive:
                count += 1
                for item in self.neighbors.nodeinfo_list[nd].get_nodeinfo():
                    nodeinfo.extend(item)

        nodes = bytearray(count.to_bytes(4, 'big'))
        nodes.extend(nodeinfo)
        return bytes(nodes)

    def update_neighbor_list(self, binary_data):
        """
        Parse binary data and update neighbors
        :param binary_data:
        :return: True/False:  True if the received nodeinfo and that the node has is different
        """
        count_originally = len(list(filter(lambda nd: nd.is_alive, self.neighbors.nodeinfo_list.values())))
        count_unchanged = 0
        count = int.from_bytes(binary_data[:4], 'big')
        for i in range(count):
            base = 4 + i * (32 + 4 + 16 + 2 + 8)
            node_id = binary_data[base:base + 32]
            if node_id == self.my_node_id:
                continue
            ipv4 = socket.inet_ntop(socket.AF_INET, binary_data[base + 32:base + 36])
            ipv6 = socket.inet_ntop(socket.AF_INET6, binary_data[base + 36:base + 52])
            port = socket.ntohs(int.from_bytes(binary_data[base + 52:base + 54], 'big'))
            updated_at = int.from_bytes(binary_data[base + 54:base + 62], 'big')
            if not self.neighbors.add(node_id, ipv4, ipv6, port):
                count_unchanged += 1
        self.logger.debug("[%s] update_neighbor_list: orig=%d, unchanged=%d, recv=%d, need_advertise=%s" %
              (self.my_node_id.hex()[:4], count_originally, count_unchanged, count, count_originally != count_unchanged))
        if count_originally == count_unchanged:
            return False
        else:
            return True

    def process_message(self, ipv4, ipv6, port, msg):
        """
        (internal use) process received message
        :param ipv4:      sender ipv4 address
        :param ipv6:      sender ipv6 address
        :param port:      sender address and port (None if TCP)
        :param msg:
        :return:
        """
        if KeyType.destination_node_id not in msg or KeyType.command not in msg:
            return
        if msg[KeyType.command] == TopologyManagerBase.NOTIFY_NEIGHBOR_LIST:
            self.stats.update_stats_increment("topology_manager", "NOTIFY_NEIGHBOR_LIST", 1)
            self.update_refresh_timer_entry(new_entry=False)
            diff_flag = self.update_neighbor_list(msg[KeyType.neighbor_list])
            if diff_flag:
                if self.advertise_wait_entry is None:
                    self.notify_neighbor_update(None)
            else:
                if self.advertise_wait_entry is not None:
                    self.advertise_wait_entry.deactivate()
                    self.advertise_wait_entry = None

