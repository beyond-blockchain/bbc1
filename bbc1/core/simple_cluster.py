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

import sys
sys.path.extend(["../../"])
from bbc1.common.message_key_types import KeyType, PayloadType
from bbc1.core.bbc_types import ResourceType
from bbc1.core.bbc_network import DomainBase
from bbc1.core.bbc_types import InfraMessageTypeBase
from bbc1.core import query_management


INTERVAL_RETRY = 3
FORWARD_CACHE_SIZE = 1000
ZEROS = bytes([0] * 32)

ticker = query_management.get_ticker()


class NetworkDomain(DomainBase):
    """
    Compose a simple core node cluster
    """
    def __init__(self, network=None, config=None, domain_id=None, node_id=None, loglevel="all", logname=None):
        super(NetworkDomain, self).__init__(network, config, domain_id, node_id, loglevel, logname)
        self.start_domain_manager()
        self.node_pointer_index = 0
        self.module_name = "simple_cluster"
        self.default_payload_type = PayloadType.Type_msgpack
        self.in_alive_checking = False

    def domain_manager_loop(self):
        """
        maintain domain (e.g., updating peer list and topology)

        :return:
        """
        time.sleep(3)
        while True:
            time.sleep(30)

    def alive_check(self):
        if self.in_alive_checking:
            return
        self.in_alive_checking = True
        query_entry = query_management.QueryEntry(expire_after=15,
                                                  callback_expire=self.send_peerlist,
                                                  retry_count=0)
        self.ping_to_all_neighbors()

    def add_peer_node(self, node_id, ip4, addr_info):
        """
        (internal use) add node as a peer node

        :param node_id:
        :param ip4:
        :param addr_info:
        :return:
        """
        if super(NetworkDomain, self).add_peer_node(node_id, ip4, addr_info):
            self.node_pointer_index = 0

    def print_peerlist(self):
        """
        Print peer list

        :return:
        """
        self.logger.info("================ peer list [%s] ===============" % self.shortname)
        print("================ peer list [%s] ===============" % self.shortname)
        for nd in self.id_ip_mapping.keys():
            self.logger.info("%s: (%s, %s, %d)" % (binascii.b2a_hex(nd[:4]), self.id_ip_mapping[nd].ipv4,
                                                   self.id_ip_mapping[nd].ipv6, self.id_ip_mapping[nd].port))
            print("%s: (%s, %s, %d)" % (binascii.b2a_hex(nd[:4]), self.id_ip_mapping[nd].ipv4,
                                        self.id_ip_mapping[nd].ipv6, self.id_ip_mapping[nd].port))
        self.logger.info("-----------------------------------------------")
        print("-----------------------------------------------")

    def advertise_domain_info(self):
        pass

    def get_neighbor_nodes(self):
        """
        Return neighbor nodes (for broadcasting message)

        :return:
        """
        return self.id_ip_mapping.keys()

    def process_message(self, ip4, from_addr, msg):
        """
        process received message

        :param ip4:       True (from IPv4) / False (from IPv6)
        :param from_addr: sender address and port (None if TCP)
        :param msg:       the message body (already deserialized)
        :return:
        """
        if msg[KeyType.p2p_msg_type] == InfraMessageTypeBase.REQUEST_STORE:
            if KeyType.resource_id not in msg or KeyType.resource not in msg:
                return
            self.add_peer_node(msg[KeyType.source_node_id], ip4, from_addr)
            self.process_REQUEST_STORE(msg)

        elif msg[KeyType.p2p_msg_type] == InfraMessageTypeBase.REQUEST_FIND_VALUE:
            if KeyType.resource_id not in msg or KeyType.resource_type not in msg:
                return
            self.add_peer_node(msg[KeyType.source_node_id], ip4, from_addr)
            self.process_REQUEST_FIND_VALUE(msg)

        elif msg[KeyType.p2p_msg_type] == InfraMessageTypeBase.RESPONSE_FIND_VALUE:
            if KeyType.resource_id not in msg or KeyType.resource_type not in msg:
                return
            self.add_peer_node(msg[KeyType.source_node_id], ip4, from_addr)
            self.process_RESPONSE_FIND_VALUE(msg)

        elif msg[KeyType.p2p_msg_type] == InfraMessageTypeBase.REQUEST_FIND_USER:
            if KeyType.resource_id not in msg or KeyType.asset_group_id not in msg:
                return
            asset_group_id = msg[KeyType.asset_group_id]
            user_id = msg[KeyType.resource_id]
            if user_id in self.registered_user_id:
                target_id = msg[KeyType.source_node_id]
                nonce = msg[KeyType.nonce]
                resource_id = msg[KeyType.resource_id]
                self.respond_find_node(target_id, nonce, asset_group_id, resource_id)

        elif msg[KeyType.p2p_msg_type] == InfraMessageTypeBase.RESPONSE_FIND_USER:
            self.add_peer_node(msg[KeyType.source_node_id], ip4, from_addr)
            if KeyType.resource_id not in msg:
                return
            self.user_id_forward_cache[msg[KeyType.resource_id]] = [time.time(), msg[KeyType.source_node_id]]
            if len(self.user_id_forward_cache) > FORWARD_CACHE_SIZE:
                self.purge_by_LRU()
            query_entry = ticker.get_entry(msg[KeyType.nonce])
            query_entry.data[KeyType.peer_info] = self.id_ip_mapping[msg[KeyType.source_node_id]]
            query_entry.callback()

    def process_REQUEST_STORE(self, msg):
        domain_id = msg[KeyType.domain_id]
        asset_group_id = msg[KeyType.asset_group_id]
        resource_type = msg[KeyType.resource_type]
        resource_id = msg[KeyType.resource_id]
        resource = msg[KeyType.resource]
        if resource_type == ResourceType.Transaction_data:
            self.network.core.insert_transaction(domain_id, asset_group_id, resource, None, no_network_put=True)
        elif resource_type == ResourceType.Asset_file:
            # TODO: need to check validity of the file
            self.network.core.storage_manager.store_locally(self.domain_id, asset_group_id, resource_id, resource)
        self.respond_store(msg[KeyType.source_node_id], msg[KeyType.nonce])

    def process_REQUEST_FIND_VALUE(self, msg):
        domain_id = msg[KeyType.domain_id]
        asset_group_id = msg[KeyType.asset_group_id]
        resource_id = msg[KeyType.resource_id]
        resource_type = msg[KeyType.resource_type]
        result = None
        self.logger.debug("[%s] REQUEST_FIND_VALUE: type:%d, resource_id=%s" %
                          (self.shortname, resource_type, binascii.b2a_hex(resource_id[:4])))
        if resource_type == ResourceType.Asset_file:
            # resource_id is asset_id
            result = self.network.core.storage_manager.get_locally(domain_id, asset_group_id, resource_id)
        elif resource_type == ResourceType.Transaction_data:
            # resource_id is txid
            result = self.network.core.ledger_manager.find_locally(domain_id, asset_group_id,
                                                                   resource_id, resource_type)
        elif resource_type == ResourceType.Asset_ID:
            # resource_id at this point is asset_id
            res = self.network.core.ledger_manager.find_locally(domain_id, asset_group_id,
                                                                resource_id, resource_type)  # res=txid
            if res is None:
                result = None
            else:
                resource_id = res
                resource_type = ResourceType.Transaction_data
                result = self.network.core.ledger_manager.find_locally(domain_id, asset_group_id,
                                                                       resource_id, resource_type)

        self.respond_find_value(msg[KeyType.source_node_id], msg[KeyType.nonce],
                                resource_id=resource_id, resource=result, resource_type=resource_type)

    def process_RESPONSE_FIND_VALUE(self, msg):
        query_entry = ticker.get_entry(msg[KeyType.nonce])
        if KeyType.resource in msg:
            self.logger.debug("[%s] RESPONSE_FIND_VALUE: %s" %
                              (self.shortname, binascii.b2a_hex(msg[KeyType.resource][:4])))
            query_entry.data.update({KeyType.resource_type: msg[KeyType.resource_type], KeyType.resource: msg[KeyType.resource],
                                     KeyType.resource_id: msg[KeyType.resource_id]})
            query_entry.callback()
        else:
            query_entry.callback_error()

    def send_find_value(self, target_id, nonce, asset_group_id, resource_id, resource_type):
        self.logger.debug("[%s] send_find_value to %s about %s" % (self.shortname,
                                                                   binascii.b2a_hex(target_id[:4]),
                                                                   binascii.b2a_hex(resource_id[:4])))
        msg = self.make_message(dst_node_id=target_id, nonce=nonce, msg_type=InfraMessageTypeBase.REQUEST_FIND_VALUE)
        msg[KeyType.asset_group_id] = asset_group_id
        msg[KeyType.resource_id] = resource_id
        msg[KeyType.resource_type] = resource_type
        return self.send_message_to_peer(msg, self.default_payload_type)

    def respond_find_value(self, target_id, nonce, asset_group_id=None,
                           resource_id=None, resource=None, resource_type=None):
        msg = self.make_message(dst_node_id=target_id, nonce=nonce, msg_type=InfraMessageTypeBase.RESPONSE_FIND_VALUE)
        msg[KeyType.asset_group_id] = asset_group_id
        msg[KeyType.resource_id] = resource_id
        msg[KeyType.resource_type] = resource_type
        if resource is not None:
            msg[KeyType.resource] = resource
            self.logger.debug("[%s] respond_find_value (resource=%s)" %
                              (self.shortname, binascii.b2a_hex(resource[:4])))
        return self.send_message_to_peer(msg, self.default_payload_type)

    def respond_find_node(self, target_id, nonce, asset_group_id=None, resource_id=None):
        msg = self.make_message(dst_node_id=target_id, nonce=nonce, msg_type=InfraMessageTypeBase.RESPONSE_FIND_USER)
        msg[KeyType.asset_group_id] = asset_group_id
        msg[KeyType.resource_id] = resource_id
        return self.send_message_to_peer(msg, self.default_payload_type)

    def send_peerlist(self, query_entry):
        msg = self.make_message(dst_node_id=ZEROS, nonce=None, msg_type=InfraMessageTypeBase.NOTIFY_PEERLIST)
        msg[KeyType.peer_list] = self.make_peer_list()
        for nd in self.get_neighbor_nodes():
            msg[KeyType.destination_node_id] = nd
            self.send_message_to_peer(msg, self.default_payload_type)
        self.in_alive_checking = False

    def get_resource(self, query_entry):
        if len(self.get_neighbor_nodes()) == 0:
            query_entry.force_expire()
            return
        neighbor_list = list(self.get_neighbor_nodes())
        asset_group_id = query_entry.data[KeyType.asset_group_id]
        resource_id = query_entry.data[KeyType.resource_id]
        resource_type = query_entry.data[KeyType.resource_type]
        target_id = neighbor_list[self.node_pointer_index]
        self.node_pointer_index = (self.node_pointer_index+1) % len(neighbor_list)
        query_entry.update(fire_after=INTERVAL_RETRY, callback_error=self.get_resource)
        self.send_find_value(target_id, query_entry.nonce, asset_group_id, resource_id, resource_type)

    def put_resource(self, asset_group_id, resource_id, resource_type, resource):
        for nd in self.get_neighbor_nodes():
            entry = query_management.QueryEntry(expire_after=30,
                                                callback_expire=None,
                                                callback_error=self.resend_resource,
                                                data={'target_id': nd,
                                                      KeyType.asset_group_id: asset_group_id,
                                                      KeyType.resource_id: resource_id,
                                                      KeyType.resource: resource,
                                                      KeyType.resource_type: resource_type},
                                                retry_count=2)
            entry.update(INTERVAL_RETRY)
            self.send_store(nd, entry.nonce, asset_group_id, resource_id, resource, resource_type)

    def resend_resource(self, query_entry):
        target_id = query_entry.data['target_id']
        asset_group_id = query_entry.data[KeyType.asset_group_id]
        resource_id = query_entry.data[KeyType.resource_id]
        resource = query_entry.data[KeyType.resource]
        resource_type = query_entry.data[KeyType.resource_type]
        query_entry.update(INTERVAL_RETRY)
        self.send_store(target_id, query_entry.nonce, asset_group_id, resource_id, resource, resource_type)

    def send_p2p_message(self, query_entry):
        """
        Send a message to another node

        :param query_entry:
        :return:
        """
        asset_group_id = query_entry.data[KeyType.asset_group_id]
        user_id = query_entry.data[KeyType.resource_id]
        if user_id in self.registered_user_id:
            # TODO: can remove this condition
            query_entry.callback()
        elif user_id in self.user_id_forward_cache:
            target_id = self.user_id_forward_cache[user_id][1]
            self.user_id_forward_cache[user_id][0] = time.time()
            query_entry.data[KeyType.peer_info] = self.id_ip_mapping[target_id]
            query_entry.callback()
        else:
            query_entry.update(INTERVAL_RETRY)
            self.resolve_accommodating_core_node(query_entry)

    def resolve_accommodating_core_node(self, query_entry):
        """
        Resolve which node the user connects to

        :param query_entry:
        :return:
        """
        user_id = query_entry.data[KeyType.resource_id]
        asset_group_id = query_entry.data[KeyType.asset_group_id]
        nonce = query_entry.nonce
        msg = self.make_message(dst_node_id=ZEROS, nonce=nonce, msg_type=InfraMessageTypeBase.REQUEST_FIND_USER)
        msg[KeyType.resource_id] = user_id
        msg[KeyType.asset_group_id] = asset_group_id
        for nd in self.get_neighbor_nodes():
            if nd == self.node_id:
                continue
            self.logger.debug("[%s] resolve_accommodating_core_node: send to %s" % (self.shortname,
                                                                                    binascii.b2a_hex(nd[:2])))
            msg[KeyType.destination_node_id] = nd
            self.send_message_to_peer(msg, self.default_payload_type)

    def purge_by_LRU(self):
        """
        (internal use) purge cache entry by Least Recently Used algorithm

        :return:
        """
        user_ids = sorted(self.user_id_forward_cache.keys(), key=lambda ent: ent[0])
        delflag = False
        for id in user_ids:
            if self.user_id_forward_cache[id][0] + 86400 < time.time():
                del self.user_id_forward_cache[id]
                delflag = True
        if not delflag:
            del self.user_id_forward_cache[user_ids[0]]

    def random_send(self, msg, count):
        """
        (internal use) send data to randomly selected nodes

        :param msg:
        :param count: number of nodes to send
        :return:
        """
        dstlist = random.sample(self.id_ip_mapping.keys(), min(count+1, len(self.id_ip_mapping)))
        sent_count = 0
        for dst in dstlist:
            if sent_count == count:
                break
            if dst == self.node_id:
                continue
            msg[KeyType.destination_node_id] = dst
            self.send_message_to_peer(msg, self.default_payload_type)
            sent_count += 1
