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
import struct
import time

import os
import sys
sys.path.extend(["../../", os.path.abspath(os.path.dirname(__file__))])
from bbc1.core import bbc_core
from bbc1.core.bbc_config import DEFAULT_P2P_PORT
from bbc1.core.bbc_types import ResourceType, InfraMessageType
from bbc1.core.topology_manager import TopologyManagerBase
from bbc1.core.user_message_routing import UserMessageRouting
from bbc1.core.data_routing import DataRouting
from bbc1.core import query_management
from bbc1.common.bbclib import NodeInfo
from bbc1.common import bbclib, message_key_types
from bbc1.common.message_key_types import to_2byte, PayloadType, KeyType
from bbc1.common import logger
from bbc1.common.bbc_error import *

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


def check_my_IPaddresses(target4='8.8.8.8', target6='2001:4860:4860::8888', port=80):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((target4, port))
        ip4 = s.getsockname()[0]
        s.close()
    except OSError:
        ip4 = None
    if socket.has_ipv6:
        try:
            s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            s.connect((target6, port))
            ip6 = s.getsockname()[0]
            s.close()
        except OSError:
            ip6 = None
    return ip4, ip6


def send_data_by_tcp(ipv4=None, ipv6=None, port=DEFAULT_P2P_PORT, msg=None):
    def worker():
        if ipv6 is not None:
            conn = socket.create_connection((ipv6, port))
        elif ipv4 is not None:
            conn = socket.create_connection((ipv4, port))
        else:
            return
        conn.sendall(msg)
        conn.close()
    gevent.spawn(worker)


def convert_to_string(array):
    for i in range(len(array)):
        if isinstance(array[i], bytes):
            array[i] = array[i].decode()
    return array


class BBcNetwork:
    """
    Socket and thread management for infrastructure layers
    """
    def __init__(self, config, core=None, p2p_port=None, use_global=True, external_ip4addr=None, external_ip6addr=None,
                 loglevel="all", logname=None):
        self.core = core
        self.user_message_routing = core.user_message_routing
        self.logger = logger.get_logger(key="bbc_network", level=loglevel, logname=logname)
        self.logname = logname
        self.config = config
        self.use_global = use_global
        conf = self.config.get_config()
        self.domains = dict()
        self.ip_address, self.ip6_address = check_my_IPaddresses()
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

    def get_my_socket_info(self):
        """
        Return waiting port and my IP address

        :return:
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
        port = socket.htons(self.port).to_bytes(2, 'big')
        return socket.inet_pton(socket.AF_INET, ipv4), socket.inet_pton(socket.AF_INET6, ipv6), port, \
               int(time.time()).to_bytes(8, 'big')

    def get_user_message_routing(self, domain_id):
        """
        Return user_message_routing object for the specified domain_id
        :param domain_id:
        :return:
        """
        return self.domains[domain_id][InfraMessageType.CATEGORY_USER]

    def get_data_routing(self, domain_id):
        """
        Return data_routing object for the specified domain_id
        :param domain_id:
        :return:
        """
        return self.domains[domain_id][InfraMessageType.CATEGORY_DATA]

    def create_domain(self, domain_id=ZEROS, network_module=None, get_new_node_id=False):
        """
        Create domain and register user in the domain

        :param domain_id:
        :param network_module: string of module script file
        :param get_new_node_id: If True, the node_id is newly created again
        :return:
        """
        if domain_id in self.domains:
            return False

        if network_module == "simple_cluster":
            nw_module = None
        elif network_module is not None:
            if isinstance(network_module, bytes):
                network_module = network_module.decode()
            nw_module = __import__(network_module)
        else:
            return None

        conf = self.config.get_domain_config(domain_id, create_if_new=True)
        if 'node_id' not in conf or get_new_node_id:
            node_id = bbclib.get_random_id()
            conf['node_id'] = bbclib.convert_id_to_string(node_id)
            self.config.update_config()
        else:
            node_id = bbclib.convert_idstring_to_bytes(conf.get('node_id'))

        self.domains[domain_id] = dict()
        self.domains[domain_id]['name'] = node_id.hex()[:4]
        self.domains[domain_id]['neighbor'] = NeighborInfo(domain_id=domain_id, node_id=node_id,
                                                           sock=self.get_my_socket_info())
        if nw_module is None:
            self.domains[domain_id][InfraMessageType.CATEGORY_TOPOLOGY] = TopologyManagerBase(network=self,
                                                                                              domain_id=domain_id)
        else:
            self.domains[domain_id][InfraMessageType.CATEGORY_TOPOLOGY] = nw_module.TopologyManager(
                network=self, config=self.config,
                domain_id=domain_id, node_id=node_id,
                loglevel=self.logger.level, logname=self.logname)
        self.core.user_message_routing.add_domain(domain_id)
        self.domains[domain_id][InfraMessageType.CATEGORY_DATA] = DataRouting(domain_id=domain_id)

        self.core.stats.update_stats_increment("network", "num_domains", 1)
        return True

    def remove_domain(self, domain_id=ZEROS):
        """
        Remove domain (remove DHT)

        :param domain_id:
        :return:
        """
        if domain_id not in self.domains:
            return
        msg = {
            KeyType.infra_msg_type: InfraMessageType.CATEGORY_NETWORK,
            KeyType.domain_id: domain_id,
            KeyType.source_node_id: self.domains[domain_id]['neighbor'].my_node_id,
            KeyType.command: InfraMessageType.NOTIFY_LEAVE,
        }
        self.broadcast_message_in_network(domain_id=domain_id, payload_type=PayloadType.Type_msgpack, msg=msg)
        del self.domains[domain_id]
        self.core.user_message_routing.remove_domain(domain_id)
        self.core.stats.update_stats_decrement("network", "num_domains", 1)

    def save_all_static_node_list(self):
        """
        Save all static nodes in the config file

        :return:
        """
        self.logger.info("Saving the current peer lists")
        for domain_id in self.domains.keys():
            conf = self.config.get_domain_config(domain_id)
            conf['static_node'] = dict()
            for node_id, nodeinfo in self.domains[domain_id]['neighbor'].nodeinfo_list.items():
                if nodeinfo.is_static:
                    nid = bbclib.convert_id_to_string(node_id)
                    info = convert_to_string([nodeinfo.ipv4, nodeinfo.ipv6, nodeinfo.port])
                    conf['static_node'][nid] = info
        self.config.update_config()
        self.logger.info("Done...")

    def send_domain_ping(self, domain_id, ipv4, ipv6, port, is_static=False):
        """
        (internal use) Send raw message to the specified node

        :param domain_id:
        :param ipv4:
        :param ipv6:
        :param port:
        :param is_static:
        :return:
        """
        if domain_id not in self.domains:
            return False
        if ipv4 is None and ipv6 is None:
            return False
        node_id = self.domains[domain_id]['neighbor'].my_node_id
        nodeinfo = NodeInfo(ipv4=ipv4, ipv6=ipv6, port=port, is_static=is_static)
        query_entry = query_management.QueryEntry(expire_after=10,
                                                  callback_error=self.domain_ping,
                                                  data={KeyType.domain_id: domain_id,
                                                        KeyType.node_id: node_id,
                                                        KeyType.peer_info: nodeinfo},
                                                  retry_count=3)
        self.domain_ping(query_entry)
        return True

    def domain_ping(self, query_entry):
        msg = {
            KeyType.infra_msg_type: InfraMessageType.CATEGORY_NETWORK,
            KeyType.domain_id: query_entry.data[KeyType.domain_id],
            KeyType.node_id: query_entry.data[KeyType.node_id],
            KeyType.domain_ping: 0,
            KeyType.nonce: query_entry.nonce,
            KeyType.static_entry: query_entry.data[KeyType.peer_info].is_static,
        }
        if self.external_ip4addr is not None:
            msg[KeyType.external_ip4addr] = self.external_ip4addr
        else:
            msg[KeyType.external_ip4addr] = self.ip_address
        if self.external_ip6addr is not None:
            msg[KeyType.external_ip6addr] = self.external_ip6addr
        else:
            msg[KeyType.external_ip6addr] = self.ip6_address
        if query_entry.data[KeyType.peer_info].ipv6 is not None:
            self.logger.debug("Send domain_ping to %s:%d" % (query_entry.data[KeyType.peer_info].ipv6,
                                                             query_entry.data[KeyType.peer_info].port))
        else:
            self.logger.debug("Send domain_ping to %s:%d" % (query_entry.data[KeyType.peer_info].ipv4,
                                                             query_entry.data[KeyType.peer_info].port))
        query_entry.update(fire_after=1)
        self.core.stats.update_stats_increment("network", "domain_ping_send", 1)
        self.send_message_in_network(query_entry.data[KeyType.peer_info], PayloadType.Type_msgpack, msg)

    def receive_domain_ping(self, domain_id, ip4, from_addr, msg):
        """
        Process received domain_ping. If KeyType.domain_ping value is 1, the sender of the ping is registered as static

        :param domain_id:
        :param ip4:       True (from IPv4) / False (from IPv6)
        :param from_addr: sender address and port (None if TCP)
        :param msg:       the message body (already deserialized)
        :param payload_type: PayloadType value of msg
        :return:
        """
        if KeyType.node_id not in msg:
            return
        self.core.stats.update_stats_increment("network", "domain_ping_receive", 1)
        node_id = msg[KeyType.node_id]
        ipv4 = msg.get(KeyType.external_ip4addr, None)
        ipv6 = msg.get(KeyType.external_ip6addr, None)
        is_static = msg.get(KeyType.static_entry, False)
        if ipv4 is None and ip4:
            ipv4 = from_addr[0]
        if ipv6 is None and not ip4:
            ipv6 = from_addr[0]
        port = from_addr[1]

        self.logger.debug("Receive domain_ping for domain %s from %s" % (binascii.b2a_hex(domain_id[:4]), from_addr))
        self.logger.debug(msg)
        if domain_id not in self.domains:
            self.logger.debug("no domain_id")
            return
        if self.domains[domain_id]['neighbor'].my_node_id == node_id:
            self.logger.debug("no other node_id")
            return

        is_new = self.add_neighbor(domain_id=domain_id, node_id=node_id, ip4=ip4, from_addr=from_addr,
                                   is_static=is_static)
        if is_new:
            self.domains[domain_id][InfraMessageType.CATEGORY_TOPOLOGY].notify_neighbor_update(node_id, is_new=True)
        if msg[KeyType.domain_ping] == 1:
            query_entry = ticker.get_entry(msg[KeyType.nonce])
            query_entry.deactivate()
        else:
            msg = {
                KeyType.infra_msg_type: InfraMessageType.CATEGORY_NETWORK,
                KeyType.domain_id: domain_id,
                KeyType.node_id: self.domains[domain_id]['neighbor'].my_node_id,
                KeyType.domain_ping: 1,
                KeyType.nonce: msg[KeyType.nonce],
                KeyType.static_entry: is_static,
            }
            if self.external_ip4addr is not None:
                msg[KeyType.external_ip4addr] = self.external_ip4addr
            else:
                msg[KeyType.external_ip4addr] = self.ip_address
            if self.external_ip6addr is not None:
                msg[KeyType.external_ip6addr] = self.external_ip6addr
            else:
                msg[KeyType.external_ip6addr] = self.ip6_address
            nodeinfo = NodeInfo(ipv4=ipv4, ipv6=ipv6, port=port)
            self.send_message_in_network(nodeinfo, PayloadType.Type_msgpack, msg)

    def send_message_in_network(self, nodeinfo, payload_type, msg):
        """
        Send message over a domain network

        :param nodeinfo: NodeInfo object
        :param payload_type: PayloadType value
        :param msg:  data body
        :return:
        """
        data_to_send = message_key_types.make_message(payload_type, msg)
        if len(data_to_send) > TCP_THRESHOLD_SIZE:
            send_data_by_tcp(ipv4=nodeinfo.ipv4, ipv6=nodeinfo.ipv6, port=nodeinfo.port, msg=data_to_send)
            return
        if nodeinfo.ipv6 is not None and self.socket_udp6 is not None:
            self.socket_udp6.sendto(data_to_send, (nodeinfo.ipv6, nodeinfo.port))
            self.core.stats.update_stats_increment("network", "packets_sent_by_udp", 1)
            return
        if nodeinfo.ipv4 is not None and self.socket_udp is not None:
            self.socket_udp.sendto(data_to_send, (nodeinfo.ipv4, nodeinfo.port))
            self.core.stats.update_stats_increment("network", "message_size_sent_by_udp", len(data_to_send))
            return

    def broadcast_message_in_network(self, domain_id, payload_type, msg):
        """
        send message to all neighbor nodes
        :param domain_id:
        :param payload_type: PayloadType value of msg
        :param msg:
        :return:
        """
        for node_id, nodeinfo in self.domains[domain_id]['neighbor'].nodeinfo_list.items():
            msg[KeyType.destination_node_id] = node_id
            self.send_message_in_network(nodeinfo, payload_type, msg)

    def add_neighbor(self, domain_id, node_id, ip4, from_addr, is_static=False):
        """
        Add node in the neighbor list
        :param domain_id:
        :param node_id:
        :param ip4:
        :param from_addr:
        :param is_static:
        :return:
        """
        if self.domains[domain_id]['neighbor'].my_node_id == node_id:
            return None
        if ip4:
            is_new = self.domains[domain_id]['neighbor'].add(node_id=node_id, ipv4=from_addr[0],
                                                             port=from_addr[1], is_static=is_static)
        else:
            is_new = self.domains[domain_id]['neighbor'].add(node_id=node_id, ipv6=from_addr[0],
                                                             port=from_addr[1], is_static=is_static)
        return is_new

    def process_message_base(self, domain_id, ip4, from_addr, msg, payload_type):
        """
        (internal use) process received message (common process for any kind of network module)
        :param domain_id: target domain_id of this message
        :param ip4:       True (from IPv4) / False (from IPv6)
        :param from_addr: sender address and port (None if TCP)
        :param msg:       the message body (already deserialized)
        :param payload_type: PayloadType value of msg
        :return:
        """
        if KeyType.infra_msg_type not in msg:
            return
        self.logger.debug("[%s] process_message(type=%d)" % (self.domains[domain_id]['name'],
                                                             int.from_bytes(msg[KeyType.infra_msg_type], 'big')))

        if msg[KeyType.infra_msg_type] == InfraMessageType.CATEGORY_NETWORK:
            self.process_message(domain_id, ip4, from_addr, msg)

        elif msg[KeyType.infra_msg_type] == InfraMessageType.CATEGORY_USER:
            self.user_message_routing.process_message(domain_id, msg)
        else:
            if msg[KeyType.infra_msg_type] in [InfraMessageType.CATEGORY_DATA, InfraMessageType.CATEGORY_TOPOLOGY]:
                self.add_neighbor(domain_id, msg[KeyType.source_node_id], ip4, from_addr)
                self.domains[domain_id][msg[KeyType.infra_msg_type]].process_message(ip4, from_addr, msg)

    def process_message(self, domain_id, ip4, from_addr, msg):
        """
        (internal use) process received message
        :param domain_id: target domain_id of this message
        :param ip4:       True (from IPv4) / False (from IPv6)
        :param from_addr: sender address and port (None if TCP)
        :param msg:       the message body (already deserialized)
        :return:
        """
        if KeyType.domain_ping in msg:
            self.receive_domain_ping(domain_id, ip4, from_addr, msg)

        elif msg[KeyType.command] == InfraMessageType.NOTIFY_LEAVE:
            if KeyType.source_node_id in msg:
                node_id = msg[KeyType.source_node_id]
                self.domains[domain_id][InfraMessageType.CATEGORY_TOPOLOGY].notify_neighbor_update(node_id,
                                                                                                   is_new=False)
                self.domains[domain_id]['neighbor'].remove(node_id)

    def setup_udp_socket(self):
        """
        (internal use) Setup UDP socket

        :return:
        """
        if self.ip_address is not None:
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
        """
        (internal use) message loop for UDP socket

        :return:
        """
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
                    ip4 = True
                    if sock is self.socket_udp:
                        data, addr = self.socket_udp.recvfrom(1500)
                    elif sock is self.socket_udp6:
                        data, addr = self.socket_udp6.recvfrom(1500)
                        ip4 = False
                    if data is not None:
                        self.core.stats.update_stats_increment("network", "packets_received_by_udp", 1)
                        msg_parser.recv(data)
                        msg = msg_parser.parse()
                        #self.logger.debug("Recv_UDP from %s: data=%s" % (addr, msg))
                        if msg_parser.payload_type == PayloadType.Type_msgpack:
                            if KeyType.domain_id not in msg:
                                continue
                            if msg[KeyType.domain_id] in self.domains:
                                self.process_message_base(msg[KeyType.domain_id], ip4, addr, msg, msg_parser.payload_type)
        finally:
            for sock in readfds:
                sock.close()
            self.socket_udp = None
            self.socket_udp6 = None

    def setup_tcp_server(self):
        """
        (internal use) start tcp server

        :return:
        """
        if self.ip_address is not None:
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
        """
        (internal use) message loop for TCP socket

        :return:
        """
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
                            self.core.stats.update_stats_increment("network", "message_size_received_by_tcy", len(buf))
                            while True:
                                msg = msg_parsers[sock].parse()
                                if msg is None:
                                    break
                                #self.logger.debug("Recv_TCP at %s: data=%s" % (sock.getsockname(), msg))
                                if msg_parsers[sock].payload_type == PayloadType.Type_msgpack:
                                    if KeyType.destination_node_id not in msg or KeyType.domain_id not in msg:
                                        continue
                                self.domains[msg[KeyType.domain_id]].process_message_base(True, None, msg,
                                                                                          msg_parsers[sock].payload_type)
        finally:
            for sock in readfds:
                sock.close()
            self.listen_socket = None
            self.listen_socket6 = None


class NeighborInfo:
    """
    Manage info of neighbor nodes
    """
    def __init__(self, domain_id=None, node_id=None, sock=None):
        self.domain_id = domain_id
        self.my_node_id = node_id
        self.my_socket_info = sock
        self.nodeinfo_list = dict()

    def add(self, node_id, ipv4=None, ipv6=None, port=None, is_static=False):
        if node_id not in self.nodeinfo_list:
            self.nodeinfo_list[node_id] = NodeInfo(node_id=node_id, ipv4=ipv4, ipv6=ipv6, port=port, is_static=is_static)
            return True
        else:
            self.nodeinfo_list[node_id].update(ipv4=ipv4, ipv6=ipv6, port=port)
            return False

    def remove(self, node_id):
        self.nodeinfo_list.pop(node_id, None)

    def renew(self, info):
        """
        (internal use) renew nodeinfo_list

        :param info:
        :return:
        """
        count = int.from_bytes(info[:4], 'big')
        for i in range(count):
            base = 4 + i * (32 + 4 + 16 + 2 + 8)
            node_id = info[base:base + 32]
            if node_id == self.my_node_id:
                continue
            ipv4 = info[base + 32:base + 36]
            ipv6 = info[base + 36:base + 52]
            port = info[base + 52:base + 54]
            updated_at = int.from_bytes(info[base + 54:base + 62], 'big')
            if node_id in self.nodeinfo_list:
                if self.nodeinfo_list[node_id].updated_at < updated_at:
                    self.nodeinfo_list[node_id].recover_nodeinfo(node_id, ipv4, ipv6, port, updated_at)
            else:
                if updated_at > time.time() - REFRESH_INTERVAL / 2:
                    self.nodeinfo_list[node_id] = NodeInfo()
                    self.nodeinfo_list[node_id].recover_nodeinfo(node_id, ipv4, ipv6, port, updated_at)

    def make_list(self):
        """
        Make binary neighbor_list (the first entry of the returned result always include the info of the node itself)

        :return: binary data of count,[node_id,ipv4,ipv6,port],[node_id,ipv4,ipv6,port],[node_id,ipv4,ipv6,port],,,,
        """
        nodeinfo = bytearray()

        # the node itself
        nodeinfo.extend(self.my_node_id)
        for item in self.my_socket_info:
            nodeinfo.extend(item)
        count = 1

        # neighboring node
        for nd in self.nodeinfo_list.keys():
            count += 1
            for item in self.nodeinfo_list[nd].get_nodeinfo():
                nodeinfo.extend(item)

        nodes = bytearray(count.to_bytes(4, 'big'))
        nodes.extend(nodeinfo)
        return bytes(nodes)

    def show_list(self):
        """
        return nodeinfo list in human readable format
        :return:
        """
        result = "========= node list of [%s] ==========\n" % self.my_node_id.hex()
        for nodeinfo in self.nodeinfo_list.values():
            result += "%s\n" % nodeinfo
        return result
