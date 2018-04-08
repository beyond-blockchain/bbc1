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

import time
import random
import binascii
import threading

import os
import sys
sys.path.extend(["../../", os.path.abspath(os.path.dirname(__file__))])
from bbc1.core.bbc_types import InfraMessageCategory
from bbc1.core import query_management
from bbc1.common.message_key_types import to_2byte, PayloadType, KeyType
from bbc1.common import logger


ticker = query_management.get_ticker()

domain_global_0 = binascii.a2b_hex("0000000000000000000000000000000000000000000000000000000000000000")


class Domain0Manager:
    """
    Management for inter-domain collaboration over domain_0
    """
    DOMAIN_INFO_ADVERTISE_INTERVAL = 1800
    DOMAIN_INFO_LIFETIME = 3600
    INITIAL_ACCEPT_LIMIT = 10
    ADV_DOMAIN_LIST = to_2byte(0)
    NOTIFY_CROSS_REF = to_2byte(1)
    REQUEST_VERIFY = to_2byte(2)
    RESPONSE_VERIFY = to_2byte(3)

    def __init__(self, network=None, node_id=None, loglevel="all", logname=None):
        self.network = network
        self.stats = network.core.stats
        self.my_node_id = node_id
        self.logger = logger.get_logger(key="domain0", level=loglevel, logname=logname)
        self.domains_belong_to = set()
        self.domain_list = dict()        # {domain_id: set(node_id,,,)}
        self.node_domain_list = dict()   # {node_id: {domain_id: expiration_time}}
        self.remove_lock = threading.Lock()
        self.cross_ref_accept_limit = dict()
        self.advertise_timer_entry = None
        self.update_advertise_timer_entry()

    def stop_all_timers(self):
        """
        Invalidate all running timers
        :return:
        """
        if self.advertise_timer_entry is not None:
            self.advertise_timer_entry.deactivate()

    def register_node(self, domain_id, node_id):
        self.domain_list.setdefault(domain_id, set()).add(node_id)
        self.node_domain_list.setdefault(node_id, dict())[domain_id] = int(time.time())

    def remove_node(self, domain_id, node_id):
        """
        Remove node from the lists
        :param domain_id:
        :param node_id:
        :return:
        """
        #print("*** remove_node at %s:" % self.my_node_id.hex(), node_id.hex(), "in domain", domain_id.hex())
        #print(" ==> before: len(node_domain_list)=%d" % len(self.node_domain_list.keys()))
        self.remove_lock.acquire()
        if domain_id in self.domain_list:
            if node_id in self.domain_list[domain_id]:
                self.domain_list[domain_id].remove(node_id)
                if len(self.domain_list[domain_id]) == 0:
                    self.domain_list.pop(domain_id, None)

        if node_id in self.node_domain_list:
            if domain_id in self.node_domain_list[node_id]:
                self.node_domain_list[node_id].pop(domain_id, None)
                if len(self.node_domain_list[node_id]) == 0:
                    self.node_domain_list.pop(node_id, None)
        self.remove_lock.release()
        #print(" ==> after: len(node_domain_list)=%d" % len(self.node_domain_list.keys()))

    def update_domain_belong_to(self):
        """
        Update the list domain_belong_to
        :return:
        """
        self.domains_belong_to = set(self.network.domains.keys())

    def update_advertise_timer_entry(self):
        rand_interval = random.randint(int(Domain0Manager.DOMAIN_INFO_ADVERTISE_INTERVAL * 5 / 6),
                                       int(Domain0Manager.DOMAIN_INFO_ADVERTISE_INTERVAL * 7 / 6))
        self.logger.debug("update_advertise_timer_entry: %d" % rand_interval)
        self.advertise_timer_entry = query_management.QueryEntry(
                expire_after=rand_interval, callback_expire=self.advertise_domain_info, retry_count=0)

    def eliminate_obsoleted_entries(self):
        """
        Check expiration of the node_domain_list
        :return:
        """
        #print("eliminate_obsoleted_entries at %s: len(node_domain_list)=%d" % (self.my_node_id.hex(),
        #                                                                       len(self.node_domain_list.keys())))
        for node_id in list(self.node_domain_list.keys()):
            for domain_id in list(self.node_domain_list[node_id].keys()):
                prev_time = self.node_domain_list[node_id][domain_id]
                if int(time.time()) - prev_time > Domain0Manager.DOMAIN_INFO_LIFETIME:
                    #print(" --> expire node_id=%s in domain %s" % (node_id.hex(), domain_id.hex()))
                    self.remove_node(domain_id, node_id)

    def advertise_domain_info(self, query_entry):
        """
        Advertise domain list in the domain 0 network
        :return:
        """
        #print("[%s]: advertise_domain_info" % self.my_node_id.hex()[:4])
        self.eliminate_obsoleted_entries()
        domain_list = list(filter(lambda d: d != domain_global_0, self.network.domains.keys()))
        if len(domain_list) > 0:
            msg = {
                KeyType.infra_msg_type: InfraMessageCategory.CATEGORY_DOMAIN0,
                KeyType.domain_id: domain_global_0,
                KeyType.command: Domain0Manager.ADV_DOMAIN_LIST,
                KeyType.domain_list: domain_list,
            }
            # TODO: need modify below in the case of using Kademlia (or DHT algorithm)
            self.network.broadcast_message_in_network(domain_id=domain_global_0,
                                                      payload_type=PayloadType.Type_msgpack, msg=msg)
            self.stats.update_stats_increment("domain0", "send_advertisement", 1)
        self.update_advertise_timer_entry()

    def update_domain_list(self, msg):
        """
        Parse binary data and update domain_list
        :param msg:
        :return: True/False:  True if the received nodeinfo and that the node has is different
        """
        src_node_id = msg[KeyType.source_node_id]
        new_domains = set(filter(lambda d: d not in self.domains_belong_to, msg[KeyType.domain_list]))
        #print("newdomain:", [dm.hex() for dm in new_domains])

        if src_node_id in self.node_domain_list:
            self.remove_lock.acquire()
            deleted = set(self.node_domain_list[src_node_id].keys()) - new_domains
            self.remove_lock.release()
            #print("deleted:", [dm.hex() for dm in deleted])
            for dm in deleted:
                self.remove_node(dm, src_node_id)
        for dm in new_domains:
            #print("NEW:", dm.hex())
            self.register_node(dm, src_node_id)

    def process_message(self, msg):
        """
        (internal use) process received message
        :param msg:
        :return:
        """
        if KeyType.command not in msg:
            return

        if msg[KeyType.command] == Domain0Manager.ADV_DOMAIN_LIST:
            if KeyType.domain_list in msg:
                #print("RECV domain_list at %s from %s" % (self.my_node_id.hex(), msg[KeyType.source_node_id].hex()))
                self.stats.update_stats_increment("domain0", "ADV_DOMAIN_LIST", 1)
                self.update_domain_list(msg)

        elif msg[KeyType.command] == Domain0Manager.NOTIFY_CROSS_REF:
            if KeyType.domain_id not in msg or KeyType.transaction_id not in msg:
                return
            self.stats.update_stats_increment("domain0", "NOTIFY_CROSS_REF", 1)
            domain_id = msg[KeyType.domain_id]
            if domain_id not in self.cross_ref_accept_limit:
                self.cross_ref_accept_limit[domain_id] = Domain0Manager.INITIAL_ACCEPT_LIMIT
            if self.cross_ref_accept_limit[domain_id] > 0:
                self.core.add_cross_ref_into_list(domain_id, msg[KeyType.transaction_id])
                self.cross_ref_accept_limit[domain_id] -= 1

        elif msg[KeyType.command] == Domain0Manager.REQUEST_VERIFY:
            self.stats.update_stats_increment("domain0", "REQUEST_VERIFY", 1)
            domain_id = msg[KeyType.domain_id]
            transaction_id = msg[KeyType.transaction_id]

