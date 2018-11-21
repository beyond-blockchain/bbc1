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
import threading
import bson
import msgpack

import os
import sys
sys.path.extend(["../../", os.path.abspath(os.path.dirname(__file__))])
from bbc1.core import query_management, user_message_routing, repair_manager, logger
from bbc1.core import bbclib
from bbc1.core.bbclib import MsgType
from bbc1.core.message_key_types import to_2byte, PayloadType, KeyType, InfraMessageCategory


ticker = query_management.get_ticker()

domain_global_0 = bytes([0] * 32)


class Domain0Manager:
    """Management for inter-domain collaboration over domain_global_0"""
    DOMAIN_INFO_ADVERTISE_INTERVAL = 1800  # seconds
    DOMAIN_INFO_LIFETIME = 3600
    INITIAL_ACCEPT_LIMIT = 10
    DOMAIN_ACCEPTANCE_RECOVER_INTERVAL = 600  # seconds
    CROSS_REF_PROBABILITY = 0.1
    NUM_OF_COPIES = 3

    ADV_DOMAIN_LIST = to_2byte(0)
    DISTRIBUTE_CROSS_REF = to_2byte(1)
    NOTIFY_CROSS_REF_REGISTERED = to_2byte(2)
    REQUEST_VERIFY = to_2byte(4)
    REQUEST_VERIFY_FROM_OUTER_DOMAIN = to_2byte(5)
    RESPONSE_VERIFY_FROM_OUTER_DOMAIN = to_2byte(6)

    def __init__(self, networking=None, node_id=None, loglevel="all", logname=None):
        self.networking = networking
        self.stats = networking.core.stats
        self.my_node_id = node_id
        self.logger = logger.get_logger(key="domain0", level=loglevel, logname=logname)
        self.domains_belong_to = set()
        self.domain_list = dict()        # {domain_id: list(node_id,,,)}
        self.node_domain_list = dict()   # {node_id: {domain_id: expiration_time}}
        self.domain_accept_margin = dict()
        self.requested_cross_refs = dict()
        self.remove_lock = threading.Lock()
        self.advertise_timer_entry = None
        self._update_advertise_timer_entry()
        self.cross_ref_timer_entry = None
        self._update_cross_ref_timer_entry()

    def stop_all_timers(self):
        """Invalidate all running timers"""
        if self.advertise_timer_entry is not None:
            self.advertise_timer_entry.deactivate()
        if self.cross_ref_timer_entry is not None:
            self.cross_ref_timer_entry.deactivate()

    def _register_node(self, domain_id, node_id):
        """Register node of other domain

        Args:
            domain_id (bytes): target domain_id
            node_id (bytes): target node_id
        """
        self.domain_list.setdefault(domain_id, list())
        if node_id not in self.domain_list[domain_id]:
            self.domain_list[domain_id].append(node_id)
        self.node_domain_list.setdefault(node_id, dict())[domain_id] = int(time.time())

    def _remove_node(self, domain_id, node_id):
        """Remove node from the lists

        Args:
            domain_id (bytes): target domain_id
            node_id (bytes): target node_id
        """
        #print("*** _remove_node at %s:" % self.my_node_id.hex(), node_id.hex(), "in domain", domain_id.hex())
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
        """Update the list domain_belong_to

        domain_belong_to holds all domain_ids that this node belongs to
        """
        self.domains_belong_to = set(self.networking.domains.keys())

    def _update_advertise_timer_entry(self):
        """Update advertisement timer"""
        rand_interval = random.randint(int(Domain0Manager.DOMAIN_INFO_ADVERTISE_INTERVAL * 5 / 6),
                                       int(Domain0Manager.DOMAIN_INFO_ADVERTISE_INTERVAL * 7 / 6))
        self.logger.debug("_update_advertise_timer_entry: %d" % rand_interval)
        self.advertise_timer_entry = query_management.QueryEntry(
                expire_after=rand_interval, callback_expire=self._advertise_domain_info, retry_count=0)

    def _update_cross_ref_timer_entry(self):
        """Update cross_ref timer"""
        rand_interval = random.randint(int(Domain0Manager.DOMAIN_ACCEPTANCE_RECOVER_INTERVAL * 5 / 6),
                                       int(Domain0Manager.DOMAIN_ACCEPTANCE_RECOVER_INTERVAL * 7 / 6))
        self.logger.debug("update_cross_ref_timer_entry: %d" % rand_interval)
        self.cross_ref_timer_entry = query_management.QueryEntry(
                expire_after=rand_interval, callback_expire=self._purge_left_cross_ref, retry_count=0)

    def _eliminate_obsoleted_entries(self):
        """Check expiration of the node_domain_list"""
        #print("_eliminate_obsoleted_entries at %s: len(node_domain_list)=%d" % (self.my_node_id.hex(),
        #                                                                       len(self.node_domain_list.keys())))
        for node_id in list(self.node_domain_list.keys()):
            for domain_id in list(self.node_domain_list[node_id].keys()):
                prev_time = self.node_domain_list[node_id][domain_id]
                if int(time.time()) - prev_time > Domain0Manager.DOMAIN_INFO_LIFETIME:
                    #print(" --> expire node_id=%s in domain %s" % (node_id.hex(), domain_id.hex()))
                    self._remove_node(domain_id, node_id)

    def _advertise_domain_info(self, query_entry):
        """Advertise domain list in the domain_global_0 network"""
        #print("[%s]: _advertise_domain_info" % self.my_node_id.hex()[:4])
        self._eliminate_obsoleted_entries()
        domain_list = list(filter(lambda d: d != domain_global_0, self.networking.domains.keys()))
        if len(domain_list) > 0:
            msg = {
                KeyType.infra_msg_type: InfraMessageCategory.CATEGORY_DOMAIN0,
                KeyType.domain_id: domain_global_0,
                KeyType.command: Domain0Manager.ADV_DOMAIN_LIST,
                KeyType.domain_list: domain_list,
            }
            # TODO: need modify below in the case of using Kademlia (or DHT algorithm)
            self.networking.broadcast_message_in_network(domain_id=domain_global_0,
                                                         payload_type=PayloadType.Type_msgpack, msg=msg)
            self.stats.update_stats_increment("domain0", "send_advertisement", 1)
        self._update_advertise_timer_entry()

    def _update_domain_list(self, msg):
        """Parse binary data and update domain_list

        Args:
            msg (dict): received message
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
                self._remove_node(dm, src_node_id)
        for dm in new_domains:
            #print("NEW:", dm.hex())
            self._register_node(dm, src_node_id)

    def distribute_cross_ref_in_domain0(self, domain_id, transaction_id):
        """Determine if the node distributes the cross_ref (into domain_global_0)

        Args:
            domain_id (bytes): target domain_id
            transaction_id (bytes): target transaction_id
        """
        # TODO: probability calculation needs to be modified
        if random.random() > Domain0Manager.CROSS_REF_PROBABILITY:
            return

        self.stats.update_stats_increment("domain0", "distribute_cross_ref_in_domain0", 1)
        num_copies = Domain0Manager.NUM_OF_COPIES
        if len(self.domain_list) <= Domain0Manager.NUM_OF_COPIES:
            num_copies = len(self.domain_list)
        target_domains = random.sample(tuple(self.domain_list.keys()), num_copies)
        msg = {
            KeyType.infra_msg_type: InfraMessageCategory.CATEGORY_DOMAIN0,
            KeyType.command: Domain0Manager.DISTRIBUTE_CROSS_REF,
            KeyType.domain_id: domain_global_0,
            KeyType.cross_ref: (domain_id, transaction_id),
        }
        for dm in target_domains:
            if len(self.domain_list[dm]) == 0:
                continue
            dst_node_id = random.choice(self.domain_list[dm])
            msg[KeyType.destination_node_id] = dst_node_id
            self.networking.send_message_in_network(nodeinfo=None, payload_type=PayloadType.Type_any,
                                                    domain_id=domain_global_0, msg=msg)

    def _assign_cross_ref(self, cross_ref):
        """Assign cross_ref to core nodes in domains this node belongs to"""
        now = int(time.time())
        if cross_ref[0] not in self.domain_accept_margin:
            count = self._get_acceptance_margin(cross_ref[0])
            self.domain_accept_margin[cross_ref[0]] = [now, count]  # last accepting time, margin
        elif self.domain_accept_margin[cross_ref[0]][1] > 0:
            self.domain_accept_margin[cross_ref[0]][1] -= 1
        else:
            if now - self.domain_accept_margin[cross_ref[0]][0] > Domain0Manager.DOMAIN_ACCEPTANCE_RECOVER_INTERVAL:
                count = self._get_acceptance_margin(cross_ref[0])
                self.domain_accept_margin[cross_ref[0]] = [now, count]
            else:
                self.stats.update_stats_increment("domain0", "drop_cross_ref_because_exceed_margin", 1)
                return
        self.requested_cross_refs.setdefault(cross_ref[0], dict()).setdefault(cross_ref[1], now)

        msg = {
            KeyType.infra_msg_type: InfraMessageCategory.CATEGORY_USER,
            KeyType.infra_command: user_message_routing.UserMessageRouting.CROSS_REF_ASSIGNMENT,
            KeyType.cross_ref: cross_ref,
        }

        i = len(self.networking.domains)
        if domain_global_0 in self.networking.domains:
            i -= 1
        if i <= 0:
            return
        if i > Domain0Manager.NUM_OF_COPIES:
            i = Domain0Manager.NUM_OF_COPIES
        dup_check = set()
        while i > 0:
            target_domain = random.choice(tuple(self.networking.domains.keys()))
            if target_domain == domain_global_0:
                continue
            if len(self.networking.domains[target_domain]['neighbor'].nodeinfo_list) > 0:
                dst_node_id = random.choice(tuple(self.networking.domains[target_domain]['neighbor'].nodeinfo_list.keys()))
                if (target_domain, dst_node_id) in dup_check:
                    continue
                msg[KeyType.domain_id] = target_domain
                msg[KeyType.destination_node_id] = dst_node_id
                self.networking.send_message_in_network(nodeinfo=None, payload_type=PayloadType.Type_any,
                                                        domain_id=target_domain, msg=msg)
                dup_check.add((target_domain, dst_node_id))
                self.stats.update_stats_increment("domain0", "assign_cross_ref_to_nodes", 1)
            i -= 1

    def _get_acceptance_margin(self, domain_id):
        """Check how many cross ref will be accepted

        Args:
            domain_id (bytes): target domain_id
        """
        if domain_id not in self.networking.domains:
            return 1
        ret = self.networking.domains[domain_id]['data'].count_domain_in_cross_ref(domain_id)
        if ret is None:
            ret = 0
        # TODO: need implementation
        return ret+1

    def _purge_left_cross_ref(self, query_entry):
        """Purge expired cross_ref entries of requested_cross_refs"""
        now = int(time.time())
        for dm in tuple(self.requested_cross_refs.keys()):
            for txid in tuple(self.requested_cross_refs[dm].keys()):
                if now - self.requested_cross_refs[dm][txid] > Domain0Manager.DOMAIN_ACCEPTANCE_RECOVER_INTERVAL:
                    del self.requested_cross_refs[dm][txid]

    def cross_ref_registered(self, domain_id, transaction_id, cross_ref):
        """Notify cross_ref inclusion in a transaction of the outer domain and insert the info into DB

        Args:
            domain_id (bytes): domain_id where the cross_ref is from
            transaction_id (bytes): transaction_id that the cross_ref proves
            cross_ref (bytes): the registered cross_ref in other domain
        """
        cross_ref_domain_id = cross_ref[0]
        cross_ref_txid = cross_ref[1]
        if cross_ref_domain_id not in self.requested_cross_refs or cross_ref_txid not in self.requested_cross_refs[cross_ref_domain_id]:
            return
        del self.requested_cross_refs[cross_ref_domain_id][cross_ref_txid]
        self.stats.update_stats_increment("domain0", "cross_ref_registered", 1)
        if len(self.domain_list[cross_ref_domain_id]) == 0:
            return
        try:
            msg = {
                KeyType.infra_msg_type: InfraMessageCategory.CATEGORY_DOMAIN0,
                KeyType.command: Domain0Manager.NOTIFY_CROSS_REF_REGISTERED,
                KeyType.domain_id: domain_global_0,
                KeyType.destination_node_id: random.choice(self.domain_list[cross_ref_domain_id]),
                KeyType.outer_domain_id: domain_id,
                KeyType.txid_having_cross_ref: transaction_id,
                KeyType.cross_ref: cross_ref,
            }
            self.networking.send_message_in_network(nodeinfo=None, payload_type=PayloadType.Type_any,
                                                    domain_id=domain_global_0, msg=msg)
        except:
            return

    def _get_transaction_data_for_verification(self, domain_id, transaction_id):
        """Get transaction object and verify it"""
        txobjs, asts = self.networking.domains[domain_id]['data'].search_transaction(transaction_id=transaction_id)
        if transaction_id not in txobjs:
            return None
        txobj = txobjs[transaction_id]
        if txobj.WITH_WIRE:
            self.logger.info("To use cross_reference the transaction object must not be in bson/msgpack format")
            return None
        txobj_is_valid, valid_assets, invalid_assets = bbclib.validate_transaction_object(txobj, asts)
        if not txobj_is_valid:
            msg = {
                KeyType.command: repair_manager.RepairManager.REQUEST_REPAIR_TRANSACTION,
                KeyType.transaction_id: transaction_id,
            }
            self.networking.domains[domain_id]['repair'].put_message(msg)
            return None
        txobj.digest()
        cross_ref_dat = txobj.cross_ref.pack()
        sigdata = txobj.signatures[0].pack()
        return txobj.transaction_base_digest, cross_ref_dat, sigdata

    def process_message(self, msg):
        """Process received message

        Args:
            msg (dict): received message
        """
        if KeyType.command not in msg:
            return

        if msg[KeyType.command] == Domain0Manager.ADV_DOMAIN_LIST:
            if KeyType.domain_list in msg:
                #print("RECV domain_list at %s from %s" % (self.my_node_id.hex(), msg[KeyType.source_node_id].hex()))
                self.stats.update_stats_increment("domain0", "ADV_DOMAIN_LIST", 1)
                self._update_domain_list(msg)

        elif msg[KeyType.command] == Domain0Manager.DISTRIBUTE_CROSS_REF:
            if KeyType.cross_ref not in msg:
                return
            self.stats.update_stats_increment("domain0", "GET_CROSS_REF_DISTRIBUTION", 1)
            self._assign_cross_ref(msg[KeyType.cross_ref])

        elif msg[KeyType.command] == Domain0Manager.NOTIFY_CROSS_REF_REGISTERED:
            if KeyType.domain_id not in msg or KeyType.txid_having_cross_ref not in msg:
                return
            outer_domain_id = msg[KeyType.outer_domain_id]
            txid_having_cross_ref = msg[KeyType.txid_having_cross_ref]
            domain_id = msg[KeyType.cross_ref][0]
            transaction_id = msg[KeyType.cross_ref][1]
            self.networking.domains[domain_id]['data'].insert_cross_ref(transaction_id, outer_domain_id,
                                                                        txid_having_cross_ref)

        elif msg[KeyType.command] == Domain0Manager.REQUEST_VERIFY:
            self.stats.update_stats_increment("domain0", "REQUEST_VERIFY", 1)
            domain_id = msg[KeyType.domain_id]
            transaction_id = msg[KeyType.transaction_id]
            domain_list = self.networking.domains[domain_id]['data'].search_domain_having_cross_ref(transaction_id)
            if domain_list is None or len(domain_list) == 0:
                return
            dm = random.choice(domain_list)  # "id", "transaction_id", "outer_domain_id", "txid_having_cross_ref"
            if dm[2] not in self.domain_list or len(self.domain_list[dm[2]]) == 0:
                return
            dst_node_id = random.choice(self.domain_list[dm[2]])
            msg2 = {
                KeyType.infra_msg_type: InfraMessageCategory.CATEGORY_DOMAIN0,
                KeyType.command: Domain0Manager.REQUEST_VERIFY_FROM_OUTER_DOMAIN,
                KeyType.domain_id: domain_global_0,
                KeyType.destination_node_id: dst_node_id,
                KeyType.source_user_id: msg[KeyType.source_user_id],
                KeyType.transaction_id: transaction_id,
                KeyType.source_domain_id: domain_id,
                KeyType.outer_domain_id: dm[2],
                KeyType.txid_having_cross_ref: dm[3],
            }
            self.networking.send_message_in_network(nodeinfo=None, payload_type=PayloadType.Type_any,
                                                    domain_id=domain_global_0, msg=msg2)

        elif msg[KeyType.command] == Domain0Manager.REQUEST_VERIFY_FROM_OUTER_DOMAIN:
            if KeyType.outer_domain_id not in msg or KeyType.txid_having_cross_ref not in msg:
                return
            domain_id = msg.pop(KeyType.outer_domain_id, None)
            if domain_id not in self.networking.domains:
                return
            transaction_id = msg.pop(KeyType.txid_having_cross_ref, None)
            if transaction_id is None:
                return
            ret = self._get_transaction_data_for_verification(domain_id, transaction_id)
            if ret is None:
                return
            msg[KeyType.cross_ref_verification_info] = ret
            msg[KeyType.command] = Domain0Manager.RESPONSE_VERIFY_FROM_OUTER_DOMAIN
            msg[KeyType.destination_node_id] = msg[KeyType.source_node_id]
            self.networking.send_message_in_network(nodeinfo=None, payload_type=PayloadType.Type_any,
                                                    domain_id=domain_global_0, msg=msg)

        elif msg[KeyType.command] == Domain0Manager.RESPONSE_VERIFY_FROM_OUTER_DOMAIN:
            domain_id = msg[KeyType.source_domain_id]
            msg2 = {
                KeyType.infra_msg_type: InfraMessageCategory.CATEGORY_USER,
                KeyType.command: MsgType.RESPONSE_CROSS_REF_VERIFY,
                KeyType.domain_id: domain_id,
                KeyType.destination_user_id: msg[KeyType.source_user_id],
                KeyType.source_user_id: msg[KeyType.source_user_id],
                KeyType.transaction_id: msg[KeyType.transaction_id],
                KeyType.cross_ref_verification_info: msg[KeyType.cross_ref_verification_info],
            }
            self.networking.domains[domain_id]['user'].send_message_to_user(msg2)
