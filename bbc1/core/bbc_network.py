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
import gevent
import socket
import select

import threading
import random
import binascii
import hashlib
import time

import os
import sys
sys.path.extend(["../../", os.path.abspath(os.path.dirname(__file__))])
from bbc1.core.bbc_config import DEFAULT_P2P_PORT
from bbc1.core.key_exchange_manager import KeyExchangeManager
from bbc1.core.topology_manager import TopologyManagerBase
from bbc1.core.user_message_routing import UserMessageRouting
from bbc1.core.data_handler import DataHandler, DataHandlerDomain0
from bbc1.core.repair_manager import RepairManager
from bbc1.core.domain0_manager import Domain0Manager
from bbc1.core import query_management, message_key_types, logger
from bbc1.core import bbclib
from bbc1.core.message_key_types import to_2byte, PayloadType, KeyType, InfraMessageCategory
from bbc1.core.bbc_error import *

TCP_THRESHOLD_SIZE = 1300
ZEROS = bytes([0] * 32)
NUM_CROSS_REF_COPY = 2

DURATION_GIVEUP_PUT = 30
INTERVAL_RETRY = 3
GET_RETRY_COUNT = 5
ROUTE_RETRY_COUNT = 1
REFRESH_INTERVAL = 1800  # not sure whether it's appropriate
ALIVE_CHECK_PING_WAIT = 2

ticker = query_management.get_ticker()


def _check_my_IPaddresses(target4='8.8.8.8', target6='2001:4860:4860::8888', port=80):
    """Check IP address by sending DNS query"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((target4, port))
        ip4 = s.getsockname()[0]
        s.close()
    except OSError:
        ip4 = "127.0.0.1"
    if socket.has_ipv6:
        try:
            s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            s.connect((target6, port))
            ip6 = s.getsockname()[0]
            s.close()
        except OSError:
            ip6 = None
    return ip4, ip6


def _send_data_by_tcp(ipv4=None, ipv6=None, port=DEFAULT_P2P_PORT, msg=None):
    """Establish TCP connection and send data"""
    def worker():
        if ipv6 is not None and ipv6 != "::":
            conn = socket.create_connection((ipv6, port))
        elif ipv4 is not None and ipv4 != "0.0.0.0":
            conn = socket.create_connection((ipv4, port))
        else:
            return
        conn.sendall(msg)
        conn.close()
    gevent.spawn(worker)


def _convert_to_string(array):
    """Data convert utility"""
    for i in range(len(array)):
        if isinstance(array[i], bytes):
            array[i] = array[i].decode()
    return array


def is_less_than(val_a, val_b):
    """Return True if val_a is less than val_b (evaluate as integer)"""
    size = len(val_a)
    if size != len(val_b):
        return False
    for i in reversed(range(size)):
        if val_a[i] < val_b[i]:
            return True
        elif val_a[i] > val_b[i]:
            return False
    return False


class BBcNetwork:
    """Socket and thread management for infrastructure layers"""
    NOTIFY_LEAVE = to_2byte(0)
    REQUEST_KEY_EXCHANGE = to_2byte(1)
    RESPONSE_KEY_EXCHANGE = to_2byte(2)
    CONFIRM_KEY_EXCHANGE = to_2byte(3)

    def __init__(self, config, core=None, p2p_port=None, external_ip4addr=None, external_ip6addr=None,
                 loglevel="all", logname=None):
        self.core = core
        self.stats = core.stats
        self.logger = logger.get_logger(key="bbc_network", level=loglevel, logname=logname)
        self.logname = logname
        self.loglevel = loglevel
        self.config = config
        self.domain0manager = None
        conf = self.config.get_config()
        self.domains = dict()
        self.ip_address, self.ip6_address = _check_my_IPaddresses()
        if external_ip4addr is not None:
            self.external_ip4addr = external_ip4addr
        else:
            self.external_ip4addr = self.ip_address
        if external_ip6addr is not None:
            self.external_ip6addr = external_ip6addr
        else:
            self.external_ip6addr = self.ip6_address
        if p2p_port is not None:
            conf['network']['p2p_port'] = p2p_port
            self.config.update_config()
        self.port = conf['network']['p2p_port']
        self.socket_udp = None
        self.socket_udp6 = None
        if not self.setup_udp_socket():
            self.logger.error("** Fail to setup UDP socket **")
            return
        self.listen_socket = None
        self.listen_socket6 = None
        self.max_connections = conf['network']['max_connections']
        if not self.setup_tcp_server():
            self.logger.error("** Fail to setup TCP server **")
            return

    def _get_my_nodeinfo(self, node_id):
        """Return NodeInfo

        Args:
            node_id (bytes): my node_id
        Returns:
            NodeInfo: my NodeInfo
        """
        ipv4 = self.ip_address
        if self.external_ip4addr is not None:
            ipv4 = self.external_ip4addr
        if ipv4 is None or len(ipv4) == 0:
            ipv4 = "0.0.0.0"
        ipv6 = self.ip6_address
        if self.external_ip6addr is not None:
            ipv6 = self.external_ip6addr
        if ipv6 is None or len(ipv6) == 0:
            ipv6 = "::"
        domain0 = True if self.domain0manager is not None else False
        return NodeInfo(node_id=node_id, ipv4=ipv4, ipv6=ipv6, port=self.port, domain0=domain0)

    def include_admin_info_into_message_if_needed(self, domain_id, msg, admin_info):
        """Serialize admin info into one binary object and add signature"""
        admin_info[KeyType.message_seq] = self.domains[domain_id]["neighbor"].admin_sequence_number + 1
        self.domains[domain_id]["neighbor"].admin_sequence_number += 1
        if "keypair" in self.domains[domain_id] and self.domains[domain_id]["keypair"] is not None:
            msg[KeyType.admin_info] = message_key_types.make_TLV_formatted_message(admin_info)
            digest = hashlib.sha256(msg[KeyType.admin_info]).digest()
            msg[KeyType.nodekey_signature] = self.domains[domain_id]["keypair"]['keys'][0].sign(digest)
        else:
            msg.update(admin_info)

    def send_key_exchange_message(self, domain_id, node_id, command, pubkey, nonce, random_val, key_name):
        """Send ECDH key exchange message"""
        if command == "request":
            command = BBcNetwork.REQUEST_KEY_EXCHANGE
        elif command == "response":
            command = BBcNetwork.RESPONSE_KEY_EXCHANGE
        else:
            command = BBcNetwork.CONFIRM_KEY_EXCHANGE
        msg = {
            KeyType.infra_msg_type: InfraMessageCategory.CATEGORY_NETWORK,
            KeyType.domain_id: domain_id,
            KeyType.destination_node_id: node_id,
        }
        admin_info = {
            KeyType.destination_node_id: node_id,  # To defend from replay attack
            KeyType.command: command,
            KeyType.ecdh: pubkey,
            KeyType.nonce: nonce,
            KeyType.random: random_val,
            KeyType.hint: key_name,
        }
        self.include_admin_info_into_message_if_needed(domain_id, msg, admin_info)
        return self.send_message_in_network(None, PayloadType.Type_msgpack, domain_id, msg)

    def create_domain(self, domain_id=ZEROS, config=None):
        """Create domain and register user in the domain

        Args:
            domain_id (bytes): target domain_id to create
            config (dict): configuration for the domain
        Returns:
            bool:
        """
        if domain_id in self.domains:
            return False

        conf = self.config.get_domain_config(domain_id, create_if_new=True)
        if config is not None:
            conf.update(config)
        if 'node_id' not in conf or conf['node_id'] == "":
            node_id = bbclib.get_random_id()
            conf['node_id'] = bbclib.convert_id_to_string(node_id)
            self.config.update_config()
        else:
            node_id = bbclib.convert_idstring_to_bytes(conf.get('node_id'))

        self.domains[domain_id] = dict()
        self.domains[domain_id]['node_id'] = node_id
        self.domains[domain_id]['name'] = node_id.hex()[:4]
        self.domains[domain_id]['neighbor'] = NeighborInfo(network=self, domain_id=domain_id, node_id=node_id,
                                                           my_info=self._get_my_nodeinfo(node_id))
        self.domains[domain_id]['topology'] = TopologyManagerBase(network=self, domain_id=domain_id, node_id=node_id,
                                                                  logname=self.logname, loglevel=self.loglevel)
        self.domains[domain_id]['user'] = UserMessageRouting(self, domain_id, logname=self.logname,
                                                             loglevel=self.loglevel)
        self.get_domain_keypair(domain_id)

        workingdir = self.config.get_config()['workingdir']
        if domain_id == ZEROS:
            self.domains[domain_id]['data'] = DataHandlerDomain0(self, domain_id=domain_id, logname=self.logname,
                                                                 loglevel=self.loglevel)
            self.domain0manager = Domain0Manager(self, node_id=node_id, logname=self.logname, loglevel=self.loglevel)
        else:
            self.domains[domain_id]['data'] = DataHandler(self, config=conf, workingdir=workingdir,
                                                          domain_id=domain_id, logname=self.logname,
                                                          loglevel=self.loglevel)

        self.domains[domain_id]['repair'] = RepairManager(self, domain_id, workingdir=workingdir,
                                                          logname=self.logname, loglevel=self.loglevel)

        if self.domain0manager is not None:
            self.domain0manager.update_domain_belong_to()
            for dm in self.domains.keys():
                if dm != ZEROS:
                    self.domains[dm]['neighbor'].my_info.update(domain0=True)
            self.domains[domain_id]['topology'].update_refresh_timer_entry(1)
        self.stats.update_stats_increment("network", "num_domains", 1)
        self.logger.info("Domain %s is created" % (domain_id.hex()))
        return True

    def remove_domain(self, domain_id=ZEROS):
        """Leave the domain and remove it

        Args:
            domain_id (bytes): target domain_id to remove
        Returns:
            bool: True if successful
        """
        if domain_id not in self.domains:
            return False
        self.domains[domain_id]['topology'].stop_all_timers()
        self.domains[domain_id]['user'].stop_all_timers()
        self.domains[domain_id]['repair'].exit_loop()
        for nd in self.domains[domain_id]["neighbor"].nodeinfo_list.values():
            nd.key_manager.stop_all_timers()

        msg = {
            KeyType.infra_msg_type: InfraMessageCategory.CATEGORY_NETWORK,
            KeyType.domain_id: domain_id,
            KeyType.command: BBcNetwork.NOTIFY_LEAVE,
        }
        admin_info = {
            KeyType.source_node_id: self.domains[domain_id]["neighbor"].my_node_id,
            KeyType.nonce: bbclib.get_random_value(32)   # just for randomization
        }
        self.include_admin_info_into_message_if_needed(domain_id, msg, admin_info)
        self.broadcast_message_in_network(domain_id=domain_id, msg=msg)

        if domain_id == ZEROS:
            self.domain0manager.stop_all_timers()
            for dm in self.domains.keys():
                if dm != ZEROS:
                    self.domains[dm]['neighbor'].my_info.update(domain0=False)
                    self.domains[dm]['topology'].update_refresh_timer_entry(1)
        del self.domains[domain_id]
        if self.domain0manager is not None:
            self.domain0manager.update_domain_belong_to()
        self.config.remove_domain_config(domain_id)
        self.stats.update_stats_decrement("network", "num_domains", 1)
        self.logger.info("Domain %s is removed" % (domain_id.hex()))
        return True

    def save_all_static_node_list(self):
        """Save all static nodes in the config file"""
        self.logger.info("Saving the neighbor list")
        for domain_id in self.domains.keys():
            conf = self.config.get_domain_config(domain_id)
            conf['static_node'] = dict()
            for node_id, nodeinfo in self.domains[domain_id]['neighbor'].nodeinfo_list.items():
                if nodeinfo.is_static:
                    nid = bbclib.convert_id_to_string(node_id)
                    info = _convert_to_string([nodeinfo.ipv4, nodeinfo.ipv6, nodeinfo.port])
                    conf['static_node'][nid] = info
        self.config.update_config()
        self.logger.info("Done...")

    def send_message_to_a_domain0_manager(self, domain_id, msg):
        """Choose one of domain0_managers and send msg to it

        Args:
            domain_id (bytes): target domain_id
            msg (bytes): message to send
        """
        if domain_id not in self.domains:
            return
        managers = tuple(filter(lambda nd: nd.is_domain0_node,
                                self.domains[domain_id]['neighbor'].nodeinfo_list.values()))
        if len(managers) == 0:
            return
        dst_manager = random.choice(managers)
        msg[KeyType.destination_node_id] = dst_manager.node_id
        msg[KeyType.infra_msg_type] = InfraMessageCategory.CATEGORY_DOMAIN0
        self.send_message_in_network(dst_manager, PayloadType.Type_msgpack, domain_id, msg)

    def get_domain_keypair(self, domain_id):
        """Get domain_keys (private key and public key)

        Args:
            domain_id (bytes): target domain_id
        """
        keyconfig = self.config.get_config().get('domain_key', None)
        if keyconfig is None:
            self.domains[domain_id]['keypair'] = None
            return
        if 'use' not in keyconfig or not keyconfig['use']:
            return
        if 'directory' not in keyconfig or not os.path.exists(keyconfig['directory']):
            self.domains[domain_id]['keypair'] = None
            return
        domain_id_str = domain_id.hex()
        keypair = bbclib.KeyPair()
        try:
            with open(os.path.join(keyconfig['directory'], domain_id_str+".pem"), "r") as f:
                keypair.mk_keyobj_from_private_key_pem(f.read())
        except:
            self.domains[domain_id]['keypair'] = None
            return
        self.domains[domain_id].setdefault('keypair', dict())
        self.domains[domain_id]['keypair'].setdefault('keys', list())
        self.domains[domain_id]['keypair']['keys'].insert(0, keypair)
        timer = self.domains[domain_id]['keypair'].setdefault('timer', None)
        if timer is None or not timer.active:
            self.domains[domain_id]['keypair']['timer'] = query_management.QueryEntry(
                expire_after=keyconfig['obsolete_timeout'],
                data={KeyType.domain_id: domain_id}, callback_expire=self._delete_obsoleted_domain_keys)
        else:
            timer.update_expiration_time(keyconfig['obsolete_timeout'])
        self.domains[domain_id]['keypair']['keys'].insert(0, keypair)

    def _delete_obsoleted_domain_keys(self, query_entry):
        domain_id = query_entry.data[KeyType.domain_id]
        if self.domains[domain_id]['keypair'] is not None and len(self.domains[domain_id]['keypair']['keys']) > 1:
            del self.domains[domain_id]['keypair']['keys'][1:]

    def send_domain_ping(self, domain_id, ipv4, ipv6, port, is_static=False):
        """Send domain ping to the specified node

        Args:
            domain_id (bytes): target domain_id
            ipv4 (str): IPv4 address of the node
            ipv6 (str): IPv6 address of the node
            port (int): Port number
            is_static (bool): If true, the entry is treated as static one and will be saved in config.json
        Returns:
            bool: True if successful
        """
        if domain_id not in self.domains:
            return False
        if ipv4 is None and ipv6 is None:
            return False
        node_id = self.domains[domain_id]['neighbor'].my_node_id
        nodeinfo = NodeInfo(ipv4=ipv4, ipv6=ipv6, port=port, is_static=is_static)
        query_entry = query_management.QueryEntry(expire_after=10,
                                                  callback_error=self._domain_ping,
                                                  callback_expire=self._invalidate_neighbor,
                                                  data={KeyType.domain_id: domain_id,
                                                        KeyType.node_id: node_id,
                                                        KeyType.node_info: nodeinfo},
                                                  retry_count=3)
        self._domain_ping(query_entry)
        return True

    def _domain_ping(self, query_entry):
        """Send domain ping"""
        domain_id = query_entry.data[KeyType.domain_id]
        msg = {
            KeyType.infra_msg_type: InfraMessageCategory.CATEGORY_NETWORK,
            KeyType.domain_id: domain_id,
        }
        admin_info = {
            KeyType.node_id: query_entry.data[KeyType.node_id],
            KeyType.domain_ping: 0,
            KeyType.nonce: query_entry.nonce,
            KeyType.static_entry: query_entry.data[KeyType.node_info].is_static,
        }
        if self.external_ip4addr is not None:
            admin_info[KeyType.external_ip4addr] = self.external_ip4addr
        else:
            admin_info[KeyType.external_ip4addr] = self.ip_address
        if self.external_ip6addr is not None:
            admin_info[KeyType.external_ip6addr] = self.external_ip6addr
        else:
            admin_info[KeyType.external_ip6addr] = self.ip6_address
        if query_entry.data[KeyType.node_info].ipv6 is not None:
            self.logger.debug("Send domain_ping to %s:%d" % (query_entry.data[KeyType.node_info].ipv6,
                                                             query_entry.data[KeyType.node_info].port))
        else:
            self.logger.debug("Send domain_ping to %s:%d" % (query_entry.data[KeyType.node_info].ipv4,
                                                             query_entry.data[KeyType.node_info].port))
        query_entry.update(fire_after=1)
        self.stats.update_stats_increment("network", "domain_ping_send", 1)

        self.include_admin_info_into_message_if_needed(domain_id, msg, admin_info)
        self.send_message_in_network(query_entry.data[KeyType.node_info], PayloadType.Type_msgpack, domain_id, msg)

    def _receive_domain_ping(self, domain_id, port, msg):
        """Process received domain_ping.

        If KeyType.domain_ping value is 1, the sender of the ping is registered as static

        Args:
            domain_id (bytes): target domain_id
            port (int): Port number
            msg (dict): received message
        """
        if KeyType.node_id not in msg:
            return
        self.stats.update_stats_increment("network", "domain_ping_receive", 1)
        node_id = msg[KeyType.node_id]
        ipv4 = msg.get(KeyType.external_ip4addr, None)
        ipv6 = msg.get(KeyType.external_ip6addr, None)
        is_static = msg.get(KeyType.static_entry, False)

        self.logger.debug("Receive domain_ping for domain %s from %s" % (binascii.b2a_hex(domain_id[:4]), (ipv4, ipv6)))
        self.logger.debug(msg)
        if domain_id not in self.domains:
            self.logger.debug("no domain_id")
            return
        if self.domains[domain_id]['neighbor'].my_node_id == node_id:
            self.logger.debug("no other node_id")
            return

        self.add_neighbor(domain_id=domain_id, node_id=node_id, ipv4=ipv4, ipv6=ipv6, port=port, is_static=is_static)
        self.stats.update_stats_increment("network", "domain_ping_received", 1)

        if msg[KeyType.domain_ping] == 1:
            query_entry = ticker.get_entry(msg[KeyType.nonce])
            query_entry.deactivate()
        else:
            nonce = msg[KeyType.nonce]
            msg = {
                KeyType.infra_msg_type: InfraMessageCategory.CATEGORY_NETWORK,
                KeyType.domain_id: domain_id,
            }
            admin_info = {
                KeyType.node_id: self.domains[domain_id]['neighbor'].my_node_id,
                KeyType.domain_ping: 1,
                KeyType.nonce: nonce,
                KeyType.static_entry: is_static,
            }
            if self.external_ip4addr is not None:
                admin_info[KeyType.external_ip4addr] = self.external_ip4addr
            else:
                admin_info[KeyType.external_ip4addr] = self.ip_address
            if self.external_ip6addr is not None:
                admin_info[KeyType.external_ip6addr] = self.external_ip6addr
            else:
                admin_info[KeyType.external_ip6addr] = self.ip6_address
            self.include_admin_info_into_message_if_needed(domain_id, msg, admin_info)
            nodeinfo = NodeInfo(ipv4=ipv4, ipv6=ipv6, port=port)
            self.send_message_in_network(nodeinfo, PayloadType.Type_msgpack, domain_id, msg)

    def _invalidate_neighbor(self, query_entry):
        """Set the flag of the nodeinfo false"""
        domain_id = query_entry.data[KeyType.domain_id]
        node_id = query_entry.data[KeyType.node_id]
        try:
            self.domains[domain_id]['neighbor'].nodelist[node_id].is_alive = False
        except:
            pass

    def send_message_in_network(self, nodeinfo=None, payload_type=PayloadType.Type_any, domain_id=None, msg=None):
        """Send message over a domain network

        Args:
            nodeinfo (NodeInfo): NodeInfo object of the destination
            payload_type (bytes): message format type
            domain_id (bytes): target domain_id
            msg (dict): message to send
        Returns:
            bool: True if successful
        """
        if nodeinfo is None:
            if domain_id not in self.domains:
                return False
            if msg[KeyType.destination_node_id] not in self.domains[domain_id]['neighbor'].nodeinfo_list:
                return False
            nodeinfo = self.domains[domain_id]['neighbor'].nodeinfo_list[msg[KeyType.destination_node_id]]
        msg[KeyType.source_node_id] = self.domains[domain_id]['neighbor'].my_node_id

        if payload_type == PayloadType.Type_any:
            if nodeinfo.key_manager is not None and nodeinfo.key_manager.key_name is not None and \
                    nodeinfo.key_manager.key_name in message_key_types.encryptors:
                payload_type = PayloadType.Type_encrypted_msgpack
            else:
                payload_type = PayloadType.Type_msgpack

        if payload_type in [PayloadType.Type_msgpack, PayloadType.Type_binary]:
            data_to_send = message_key_types.make_message(payload_type, msg)
        elif payload_type == PayloadType.Type_encrypted_msgpack:
            payload_type = PayloadType.Type_encrypted_msgpack
            data_to_send = message_key_types.make_message(payload_type, msg, key_name=nodeinfo.key_manager.key_name)
            if data_to_send is None:
                self.logger.error("Fail to encrypt message")
                return False
        else:
            return False

        if len(data_to_send) > TCP_THRESHOLD_SIZE:
            _send_data_by_tcp(ipv4=nodeinfo.ipv4, ipv6=nodeinfo.ipv6, port=nodeinfo.port, msg=data_to_send)
            self.stats.update_stats_increment("network", "send_msg_by_tcp", 1)
            self.stats.update_stats_increment("network", "sent_data_size", len(data_to_send))
            return True
        if nodeinfo.ipv6 is not None and self.socket_udp6 is not None:
            self.socket_udp6.sendto(data_to_send, (nodeinfo.ipv6, nodeinfo.port))
            self.stats.update_stats_increment("network", "send_msg_by_udp6", 1)
            self.stats.update_stats_increment("network", "sent_data_size", len(data_to_send))
            return True
        if nodeinfo.ipv4 is not None and self.socket_udp is not None:
            self.socket_udp.sendto(data_to_send, (nodeinfo.ipv4, nodeinfo.port))
            self.stats.update_stats_increment("network", "send_msg_by_udp4", 1)
            self.stats.update_stats_increment("network", "sent_data_size", len(data_to_send))
            return True

    def broadcast_message_in_network(self, domain_id, payload_type=PayloadType.Type_any, msg=None):
        """Send message to all neighbor nodes

        Args:
            payload_type (bytes): message format type
            domain_id (bytes): target domain_id
            msg (dict): message to send
        Returns:
            bool: True if successful
        """
        if domain_id not in self.domains:
            return
        for node_id, nodeinfo in self.domains[domain_id]['neighbor'].nodeinfo_list.items():
            msg[KeyType.destination_node_id] = node_id
            #print("broadcast:", node_id.hex(), node_id)
            self.send_message_in_network(nodeinfo, payload_type, domain_id, msg)

    def add_neighbor(self, domain_id, node_id, ipv4=None, ipv6=None, port=None, is_static=False):
        """Add node in the neighbor list

        Args:
            domain_id (bytes): target domain_id
            node_id (bytes): target node_id
            ipv4 (str): IPv4 address of the node
            ipv6 (str): IPv6 address of the node
            port (int): Port number that the node is waiting at
            is_static (bool): If true, the entry is treated as static one and will be saved in config.json
        Returns:
            bool: True if it is a new entry, None if error.
        """
        if domain_id not in self.domains or self.domains[domain_id]['neighbor'].my_node_id == node_id or port is None:
            return None

        is_new = self.domains[domain_id]['neighbor'].add(node_id=node_id, ipv4=ipv4, ipv6=ipv6, port=port, is_static=is_static)
        if is_new is not None and is_new:
            nodelist = self.domains[domain_id]['neighbor'].nodeinfo_list
            self.domains[domain_id]['topology'].notify_neighbor_update(node_id, is_new=True)
            self.stats.update_stats("network", "neighbor_nodes", len(nodelist))
        return is_new

    def check_admin_signature(self, domain_id, msg):
        """Check admin signature in the message

        Args:
            domain_id (bytes): target domain_id
            msg (dict): received message
        Returns:
            bool: True if valid
        """
        if domain_id not in self.domains:
            return False
        if "keypair" not in self.domains[domain_id] or self.domains[domain_id]["keypair"] is None:
            return True
        if KeyType.nodekey_signature not in msg or KeyType.admin_info not in msg:
            return False
        digest = hashlib.sha256(msg[KeyType.admin_info]).digest()
        flag = False
        for key in self.domains[domain_id]["keypair"]['keys']:
            if key.verify(digest, msg[KeyType.nodekey_signature]):
                flag = True
                break
        if not flag:
            return False
        admin_info = message_key_types.make_dictionary_from_TLV_format(msg[KeyType.admin_info])
        msg.update(admin_info)
        return True

    def _process_message_base(self, domain_id, ipv4, ipv6, port, msg):
        """Process received message (common process for any kind of network module)

        Args:
            domain_id (bytes): target domain_id
            ipv4 (str): IPv4 address of the sender node
            ipv6 (str): IPv6 address of the sender node
            port (int): Port number of the sender
            msg (dict): received message
        """
        if KeyType.infra_msg_type not in msg:
            return
        self.logger.debug("[%s] process_message(type=%d)" % (self.domains[domain_id]['name'],
                                                             int.from_bytes(msg[KeyType.infra_msg_type], 'big')))

        if msg[KeyType.infra_msg_type] == InfraMessageCategory.CATEGORY_NETWORK:
            self._process_message(domain_id, ipv4, ipv6, port, msg)

        elif msg[KeyType.infra_msg_type] == InfraMessageCategory.CATEGORY_USER:
            self.add_neighbor(domain_id, msg[KeyType.source_node_id], ipv4, ipv6, port)
            self.domains[domain_id]['user'].process_message(msg)
        elif msg[KeyType.infra_msg_type] == InfraMessageCategory.CATEGORY_DATA:
            self.add_neighbor(domain_id, msg[KeyType.source_node_id], ipv4, ipv6, port)
            self.domains[domain_id]['data'].process_message(msg)
        elif msg[KeyType.infra_msg_type] == InfraMessageCategory.CATEGORY_TOPOLOGY:
            self.add_neighbor(domain_id, msg[KeyType.source_node_id], ipv4, ipv6, port)
            self.domains[domain_id]['topology'].process_message(msg)
        elif msg[KeyType.infra_msg_type] == InfraMessageCategory.CATEGORY_DOMAIN0:
            self.add_neighbor(domain_id, msg[KeyType.source_node_id], ipv4, ipv6, port)
            self.domain0manager.process_message(msg)

    def _process_message(self, domain_id, ipv4, ipv6, port, msg):
        """Process received message

        Args:
            domain_id (bytes): target domain_id
            ipv4 (str): IPv4 address of the sender node
            ipv6 (str): IPv6 address of the sender node
            port (int): Port number of the sender
            msg (dict): received message
        """
        if not self.check_admin_signature(domain_id, msg):
            self.logger.error("Illegal access to domain %s" % domain_id.hex())
            return

        source_node_id = msg[KeyType.source_node_id]
        if source_node_id in self.domains[domain_id]["neighbor"].nodeinfo_list:
            admin_msg_seq = msg[KeyType.message_seq]
            if self.domains[domain_id]["neighbor"].nodeinfo_list[source_node_id].admin_sequence_number >= admin_msg_seq:
                return
            self.domains[domain_id]["neighbor"].nodeinfo_list[source_node_id].admin_sequence_number = admin_msg_seq

        if KeyType.domain_ping in msg and port is not None:
            self._receive_domain_ping(domain_id, port, msg)

        elif msg[KeyType.command] == BBcNetwork.REQUEST_KEY_EXCHANGE:
            if KeyType.ecdh in msg and KeyType.hint in msg and KeyType.nonce in msg and KeyType.random in msg:
                if source_node_id not in self.domains[domain_id]['neighbor'].nodeinfo_list:
                    self.add_neighbor(domain_id, source_node_id, ipv4, ipv6, port)
                nodeinfo = self.domains[domain_id]['neighbor'].nodeinfo_list[source_node_id]
                if nodeinfo.key_manager is None:
                    nodeinfo.key_manager = KeyExchangeManager(self, domain_id, source_node_id)
                nodeinfo.key_manager.receive_exchange_request(msg[KeyType.ecdh], msg[KeyType.nonce],
                                                              msg[KeyType.random], msg[KeyType.hint])

        elif msg[KeyType.command] == BBcNetwork.RESPONSE_KEY_EXCHANGE:
            if KeyType.ecdh in msg and KeyType.hint in msg and KeyType.nonce in msg and KeyType.random in msg:
                nodeinfo = self.domains[domain_id]['neighbor'].nodeinfo_list[source_node_id]
                nodeinfo.key_manager.receive_exchange_response(msg[KeyType.ecdh], msg[KeyType.random], msg[KeyType.hint])

        elif msg[KeyType.command] == BBcNetwork.CONFIRM_KEY_EXCHANGE:
            nodeinfo = self.domains[domain_id]['neighbor'].nodeinfo_list[source_node_id]
            nodeinfo.key_manager.receive_confirmation()

        elif msg[KeyType.command] == BBcNetwork.NOTIFY_LEAVE:
            if KeyType.source_node_id in msg:
                self.domains[domain_id]['topology'].notify_neighbor_update(source_node_id, is_new=False)
                self.domains[domain_id]['neighbor'].remove(source_node_id)

    def setup_udp_socket(self):
        """Setup UDP socket"""
        try:
            self.socket_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket_udp.bind(("0.0.0.0", self.port))
        except OSError:
            self.socket_udp = None
            self.logger.error("UDP Socket error for IPv4")
        if self.ip6_address is not None:
            try:
                self.socket_udp6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
                self.socket_udp6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                self.socket_udp6.bind(("::", self.port))
            except OSError:
                self.socket_udp6 = None
                self.logger.error("UDP Socket error for IPv6")
        if self.socket_udp is None and self.socket_udp6 is None:
            return False
        th_nw_loop = threading.Thread(target=self.udp_message_loop)
        th_nw_loop.setDaemon(True)
        th_nw_loop.start()
        return True

    def udp_message_loop(self):
        """Message loop for UDP socket"""
        self.logger.debug("Start udp_message_loop")
        msg_parser = message_key_types.Message()
        # readfds = set([self.socket_udp, self.socket_udp6])
        readfds = set()
        if self.socket_udp:
            readfds.add(self.socket_udp)
        if self.socket_udp6:
            readfds.add(self.socket_udp6)
        try:
            while True:
                rready, wready, xready = select.select(readfds, [], [])
                for sock in rready:
                    data = None
                    ipv4 = None
                    ipv6 = None
                    if sock is self.socket_udp:
                        data, (ipv4, port) = self.socket_udp.recvfrom(1500)
                    elif sock is self.socket_udp6:
                        data, (ipv6, port) = self.socket_udp6.recvfrom(1500)
                    if data is not None:
                        self.stats.update_stats_increment("network", "packets_received_by_udp", 1)
                        msg_parser.recv(data)
                        msg = msg_parser.parse()
                        #self.logger.debug("Recv_UDP from %s: data=%s" % (addr, msg))
                        if KeyType.domain_id not in msg:
                            continue
                        if msg[KeyType.domain_id] in self.domains:
                            self._process_message_base(msg[KeyType.domain_id], ipv4, ipv6, port, msg)
        finally:
            for sock in readfds:
                sock.close()
            self.socket_udp = None
            self.socket_udp6 = None

    def setup_tcp_server(self):
        """Start tcp server"""
        try:
            self.listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.listen_socket.bind(("0.0.0.0", self.port))
            self.listen_socket.listen(self.max_connections)
        except OSError:
            self.listen_socket = None
            self.logger.error("TCP Socket error for IPv4")
        if self.ip6_address is not None:
            try:
                self.listen_socket6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                self.listen_socket6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                self.listen_socket6.bind(("::", self.port))
                self.listen_socket6.listen(self.max_connections)
            except OSError:
                self.listen_socket6 = None
                self.logger.error("TCP Socket error for IPv6")
        if self.listen_socket is None and self.listen_socket6 is None:
            return False
        th_tcp_loop = threading.Thread(target=self.tcpserver_loop)
        th_tcp_loop.setDaemon(True)
        th_tcp_loop.start()
        return True

    def tcpserver_loop(self):
        """Message loop for TCP socket"""
        self.logger.debug("Start tcpserver_loop")
        msg_parsers = dict()
        readfds = set()
        if self.listen_socket:
            readfds.add(self.listen_socket)
        if self.listen_socket6:
            readfds.add(self.listen_socket6)
        try:
            while True:
                rready, wready, xready = select.select(readfds, [], [])
                for sock in rready:
                    if sock is self.listen_socket:
                        conn, address = self.listen_socket.accept()
                        conn.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                        #print("accept from ipv4: ", address)
                        readfds.add(conn)
                        msg_parsers[conn] = message_key_types.Message()
                    elif sock is self.listen_socket6:
                        conn, address = self.listen_socket6.accept()
                        conn.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                        #print("accept from ipv6: ", address)
                        readfds.add(conn)
                        msg_parsers[conn] = message_key_types.Message()
                    else:
                        buf = sock.recv(8192)
                        if len(buf) == 0:
                            del msg_parsers[sock]
                            sock.close()
                            readfds.remove(sock)
                        else:
                            msg_parsers[sock].recv(buf)
                            self.stats.update_stats_increment("network", "message_size_received_by_tcy", len(buf))
                            while True:
                                msg = msg_parsers[sock].parse()
                                if msg is None:
                                    break
                                #self.logger.debug("Recv_TCP at %s: data=%s" % (sock.getsockname(), msg))
                                if KeyType.destination_node_id not in msg or KeyType.domain_id not in msg:
                                    continue
                                self._process_message_base(msg[KeyType.domain_id], None, None, None, msg)

        finally:
            for sock in readfds:
                sock.close()
            self.listen_socket = None
            self.listen_socket6 = None


class NeighborInfo:
    """Manage information of neighbor nodes"""
    PURGE_INTERVAL_SEC = 300
    NODEINFO_LIFETIME = 900

    def __init__(self, network=None, domain_id=None, node_id=None, my_info=None):
        self.networking = network
        self.domain_id = domain_id
        self.my_node_id = node_id
        self.my_info = my_info
        self.admin_sequence_number = 0
        self.nodeinfo_list = dict()
        self.purge_timer = query_management.QueryEntry(expire_after=NeighborInfo.PURGE_INTERVAL_SEC,
                                                       callback_expire=self.purge, retry_count=3)

    def purge(self, query_entry):
        """Purge obsoleted entry in nodeinfo_list"""
        for node_id in list(self.nodeinfo_list.keys()):
            if not self.nodeinfo_list[node_id].is_alive or self.nodeinfo_list[node_id].updated_at + \
                    NeighborInfo.NODEINFO_LIFETIME < time.time():
                self.nodeinfo_list.pop(node_id, None)
        self.purge_timer = query_management.QueryEntry(expire_after=NeighborInfo.PURGE_INTERVAL_SEC,
                                                       callback_expire=self.purge, retry_count=3)

    def add(self, node_id, ipv4=None, ipv6=None, port=None, is_static=False, domain0=None):
        """Add or update an neighbor node entry"""
        if node_id not in self.nodeinfo_list:
            self.nodeinfo_list[node_id] = NodeInfo(node_id=node_id, ipv4=ipv4, ipv6=ipv6, port=port,
                                                   is_static=is_static, domain0=domain0)
            self.nodeinfo_list[node_id].key_manager = KeyExchangeManager(self.networking, self.domain_id, node_id)
            rand_time = random.uniform(1, KeyExchangeManager.KEY_EXCHANGE_INVOKE_MAX_BACKOFF)
            self.nodeinfo_list[node_id].key_manager.set_invoke_timer(rand_time)
            return True
        else:
            change_flag = self.nodeinfo_list[node_id].update(ipv4=ipv4, ipv6=ipv6, port=port, domain0=domain0)
            return change_flag

    def remove(self, node_id):
        """Remove entry in the nodeinfo_list"""
        if self.nodeinfo_list[node_id].key_manager is not None:
            self.nodeinfo_list[node_id].key_manager.stop_all_timers()
            self.nodeinfo_list[node_id].key_manager.unset_cipher()
        self.nodeinfo_list.pop(node_id, None)

    def show_list(self):
        """Return nodeinfo list in human readable format"""
        result = "========= node list of [%s] ==========\n" % self.my_node_id.hex()
        for nodeinfo in self.nodeinfo_list.values():
            result += "%s\n" % nodeinfo
        return result


class NodeInfo:
    """Node information entry"""
    SECURITY_STATE_NONE = 0
    SECURITY_STATE_REQUESTING = 1
    SECURITY_STATE_CONFIRMING = 2
    SECURITY_STATE_ESTABLISHED = 3

    def __init__(self, node_id=None, ipv4=None, ipv6=None, port=None, is_static=False, domain0=False):
        self.node_id = node_id
        if ipv4 is None or len(ipv4) == 0:
            self.ipv4 = None
        else:
            if isinstance(ipv4, bytes):
                self.ipv4 = ipv4.decode()
            else:
                self.ipv4 = ipv4
        if ipv6 is None or len(ipv6) == 0:
            self.ipv6 = None
        else:
            if isinstance(ipv6, bytes):
                self.ipv6 = ipv6.decode()
            else:
                self.ipv6 = ipv6
        self.port = port
        self.admin_sequence_number = 0
        self.is_static = is_static
        self.is_domain0_node = domain0
        self.created_at = self.updated_at = time.time()
        self.is_alive = True
        self.disconnect_at = 0
        self.key_manager = None

    def __lt__(self, other):
        if self.is_alive and other.is_alive:
            return is_less_than(self.node_id, other.node_id)
        elif self.is_alive and not other.is_alive:
            return True
        elif not self.is_alive and other.is_alive:
            return False
        else:
            return is_less_than(self.node_id, other.node_id)

    def __len__(self):
        return len(self.node_id)

    def __str__(self):
        ipv4 = self.ipv4
        if ipv4 is None:
            ipv4 = "0.0.0.0"
        ipv6 = self.ipv6
        if ipv6 is None:
            ipv6 = "::"
        security_state = (self.key_manager is not None and self.key_manager.state == KeyExchangeManager.STATE_ESTABLISHED)
        output = "[node_id=%s, ipv4=%s, ipv6=%s, port=%d, seq=%d, " \
                 "alive=%s, static=%s, encryption=%s, domain0=%s, time=%d]" %\
                 (binascii.b2a_hex(self.node_id), ipv4, ipv6, self.port, self.admin_sequence_number,
                  self.is_alive, self.is_static, security_state, self.is_domain0_node, self.updated_at)
        return output

    def touch(self):
        self.updated_at = time.time()
        self.is_alive = True

    def update(self, ipv4=None, ipv6=None, port=None, seq=None, domain0=None):
        """Update the entry

        Args:
            ipv4 (str): IPv4 address of the sender node
            ipv6 (str): IPv6 address of the sender node
            port (int): Port number of the sender
            sec (int): message sequence number
            domain0 (bool or None): If True, the node is domain0 manager
        Returns:
            bool: True if the entry has changed
        """
        change_flag = None
        if ipv4 is not None and self.ipv4 != ipv4:
            if isinstance(ipv4, bytes):
                self.ipv4 = ipv4.decode()
            else:
                self.ipv4 = ipv4
            if self.ipv4 != "127.0.0.1":
                change_flag = True
        if ipv6 is not None and self.ipv6 != ipv6:
            if isinstance(ipv6, bytes):
                self.ipv6 = ipv6.decode()
            else:
                self.ipv6 = ipv6
            if self.ipv6 != "::":
                change_flag = True
        if port is not None and self.port != port:
            self.port = port
            change_flag = True
        if seq is not None and self.admin_sequence_number < seq:
            self.admin_sequence_number = seq
        if domain0 is not None and self.is_domain0_node != domain0:
            self.is_domain0_node = domain0
            change_flag = True
        self.updated_at = time.time()
        self.is_alive = True
        return change_flag

    def get_nodeinfo(self):
        """Return a list of node info

        Returns:
            list: [node_id, ipv4, ipv6, port, domain0_flag, update_at]
        """
        if self.ipv4 is not None:
            ipv4 = socket.inet_pton(socket.AF_INET, self.ipv4)
        else:
            ipv4 = socket.inet_pton(socket.AF_INET, "0.0.0.0")
        if self.ipv6 is not None:
            ipv6 = socket.inet_pton(socket.AF_INET6, self.ipv6)
        else:
            ipv6 = socket.inet_pton(socket.AF_INET6, "::")
        domain0 = int(1).to_bytes(1, 'little') if self.is_domain0_node else int(0).to_bytes(1, 'little')
        return self.node_id, ipv4, ipv6, socket.htons(self.port).to_bytes(2, 'big'), domain0, int(self.updated_at).to_bytes(8, 'big')
