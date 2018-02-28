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
from bbc1.core.bbc_types import ResourceType, InfraMessageTypeBase
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

        nw_module = None
        if network_module is not None:
            if isinstance(network_module, bytes):
                network_module = network_module.decode()
            nw_module = __import__(network_module)

        if nw_module is None:
            return None

        conf = self.config.get_domain_config(domain_id, create_if_new=True)
        if 'node_id' not in conf or get_new_node_id:
            node_id = bbclib.get_random_id()
            conf['node_id'] = bbclib.convert_id_to_string(node_id)
            self.config.update_config()
        else:
            node_id = bbclib.convert_idstring_to_bytes(conf.get('node_id'))

        self.domains[domain_id] = nw_module.NetworkDomain(network=self, config=self.config,
                                                          domain_id=domain_id, node_id=node_id,
                                                          loglevel=self.logger.level, logname=self.logname)
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
        self.domains[domain_id].leave_domain()
        del self.domains[domain_id]
        if self.use_global and bbclib.domain_global_0 in self.domains:
            self.domains[bbclib.domain_global_0].advertise_domain_info()
        self.core.stats.update_stats_decrement("network", "num_domains", 1)

    def add_static_node_to_domain(self, domain_id, node_id, ipv4, ipv6, port):
        """
        Add static peer node for the domain

        :param domain_id:
        :param node_id:
        :param ipv4:
        :param ipv6:
        :param port:
        :return:
        """
        if domain_id not in self.domains:
            return
        self.domains[domain_id].add_peer_node_ip46(node_id, ipv4, ipv6, port)
        conf = self.config.get_domain_config(domain_id)
        if node_id not in conf['static_nodes']:
            info = convert_to_string([ipv4, ipv6, port])
            conf['static_nodes'][bbclib.convert_id_to_string(node_id)] = info
            self.core.stats.update_stats_increment("network", "peer_num", 1)

    def save_all_peer_lists(self):
        """
        Save all peer_lists in the config file

        :return:
        """
        self.logger.info("Saving the current peer lists")
        for domain_id in self.domains.keys():
            conf = self.config.get_domain_config(domain_id)
            conf['peer_list'] = dict()
            for node_id, nodeinfo in self.domains[domain_id].id_ip_mapping.items():
                nid = bbclib.convert_id_to_string(node_id)
                info = convert_to_string([nodeinfo.ipv4, nodeinfo.ipv6, nodeinfo.port])
                conf['peer_list'][nid] = info
        self.logger.info("Done...")

    def send_domain_ping(self, domain_id, ipv4, ipv6, port):
        """
        (internal use) Send raw message to the specified node

        :param domain_id:
        :param ipv4:
        :param ipv6:
        :param port:
        :return:
        """
        if domain_id not in self.domains:
            return False
        if ipv4 is None and ipv6 is None:
            return False
        node_id = self.domains[domain_id].node_id
        nodeinfo = NodeInfo(ipv4=ipv4, ipv6=ipv6, port=port)
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
            KeyType.domain_id: query_entry.data[KeyType.domain_id],
            KeyType.node_id: query_entry.data[KeyType.node_id],
            KeyType.domain_ping: 0,
            KeyType.nonce: query_entry.nonce,
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

    def receive_domain_ping(self, ip4, from_addr, msg):
        """
        Process received domain_ping. If KeyType.domain_ping value is 1, the sender of the ping is registered as static

        :param ip4:       True (from IPv4) / False (from IPv6)
        :param from_addr: sender address and port (None if TCP)
        :param msg:       the message body (already deserialized)
        :param payload_type: PayloadType value of msg
        :return:
        """
        if KeyType.domain_id not in msg or KeyType.node_id not in msg:
            return
        self.core.stats.update_stats_increment("network", "domain_ping_receive", 1)
        domain_id = msg[KeyType.domain_id]
        node_id = msg[KeyType.node_id]
        ipv4 = msg.get(KeyType.external_ip4addr, None)
        ipv6 = msg.get(KeyType.external_ip6addr, None)
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
        if self.domains[domain_id].node_id == node_id:
            self.logger.debug("no node_id")
            return

        self.add_static_node_to_domain(domain_id, node_id, ipv4, ipv6, port)
        if msg[KeyType.domain_ping] == 1:
            query_entry = ticker.get_entry(msg[KeyType.nonce])
            query_entry.deactivate()
            self.domains[domain_id].alive_check()
        else:
            msg = {
                KeyType.domain_id: domain_id,
                KeyType.node_id: self.domains[domain_id].node_id,
                KeyType.domain_ping: 1,
                KeyType.nonce: msg[KeyType.nonce],
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

    def get(self, query_entry):
        """
        (internal use) try to get resource data

        :param nonce:
        :param domain_id:
        :param resource_id:
        :param resource_type:
        :return:
        """
        domain_id = query_entry.data[KeyType.domain_id]
        if domain_id not in self.domains:
            return
        self.domains[domain_id].get_resource(query_entry)

    def put(self, domain_id=None, resource_id=None, resource_type=ResourceType.Transaction_data,
            resource=None, asset_group_id=None):
        """
        Put data in the DHT

        :param domain_id:
        :param resource_id:
        :param resource_type:
        :param resource:
        :param asset_group_id:
        :return:
        """
        if domain_id not in self.domains:
            return
        self.logger.debug("[%s] *** put(resource_id=%s) ****" % (self.domains[domain_id].shortname,
                                                                 binascii.b2a_hex(resource_id[:4])))
        self.domains[domain_id].put_resource(resource_id, resource_type, resource, asset_group_id)

    def route_message(self, domain_id=ZEROS, dst_user_id=None, src_user_id=None,
                      msg_to_send=None, payload_type=PayloadType.Type_msgpack):
        """
        Find the destination host and send it

        :param domain_id:
        :param src_user_id:   source user
        :param dst_user_id:   destination user
        :param msg_to_send:   content to send
        :param payload_type:  PayloadType value
        :return:
        """
        if domain_id not in self.domains:
            return False

        self.logger.debug("route_message to dst_user_id:%s" % (binascii.b2a_hex(dst_user_id[:2])))
        if dst_user_id in self.domains[domain_id].registered_user_id:
            self.logger.debug(" -> directly to the app")
            self.core.send_message(msg_to_send)
            return True

        query_entry = query_management.QueryEntry(expire_after=DURATION_GIVEUP_PUT,
                                                  callback_expire=self.callback_route_failure,
                                                  callback=self.forward_message,
                                                  callback_error=self.domains[domain_id].send_p2p_message,
                                                  interval=INTERVAL_RETRY,
                                                  data={KeyType.domain_id: domain_id,
                                                        KeyType.source_node_id: src_user_id,
                                                        KeyType.resource_id: dst_user_id,
                                                        'payload_type': payload_type,
                                                        'msg_to_send': msg_to_send},
                                                  retry_count=ROUTE_RETRY_COUNT)
        self.domains[domain_id].send_p2p_message(query_entry)
        self.core.stats.update_stats_increment("network", "p2p_message_count", 1)
        return True

    def forward_message(self, query_entry):
        """
        (internal use) forward message

        :param query_entry:
        :return:
        """
        if KeyType.peer_info in query_entry.data:
            nodeinfo = query_entry.data[KeyType.peer_info]
            domain_id = query_entry.data[KeyType.domain_id]
            payload_type = query_entry.data['payload_type']
            msg = self.domains[domain_id].make_message(dst_node_id=nodeinfo.node_id,
                                                       msg_type=InfraMessageTypeBase.MESSAGE_TO_USER)
            msg[KeyType.message] = query_entry.data['msg_to_send']
            self.logger.debug("[%s] forward_message to %s" % (binascii.b2a_hex(self.domains[domain_id].node_id[:2]),
                                                              binascii.b2a_hex(nodeinfo.node_id[:4])))
            self.send_message_in_network(nodeinfo, payload_type, msg=msg)
        else:
            self.logger.debug("[%s] forward_message to app" %
                              (binascii.b2a_hex(self.domains[query_entry.data[KeyType.domain_id]].node_id[:2])))
            self.core.send_message(query_entry.data['msg_to_send'])

    def callback_route_failure(self, query_entry):
        """
        (internal use) Called after several "route_message" trial

        :param query_entry:
        :return:
        """
        dat = query_entry.data['msg_to_send']
        msg = bbc_core.make_message_structure(dat[KeyType.command],
                                              query_entry.data[KeyType.source_node_id], dat[KeyType.query_id])
        self.core.error_reply(msg=msg, err_code=ENODESTINATION, txt="cannot find core node")

    def register_user_id(self, domain_id, user_id):
        """
        Register user_id connecting directly to this node in the domain

        :param domain_id:
        :param user_id:
        :return:
        """
        self.core.stats.update_stats_increment("network", "user_num", 1)
        self.domains[domain_id].register_user_id(user_id)

    def remove_user_id(self, user_id):
        """
        Remove user_id from the domain

        :param user_id:
        :return:
        """
        for domain_id in self.domains:
            self.domains[domain_id].unregister_user_id(user_id)
            self.core.stats.update_stats_decrement("network", "user_num", 1)

    def disseminate_cross_ref(self, domain_id, transaction_id):
        """
        disseminate transaction_id in the network (domain_global_0)

        :param domain_id:
        :param transaction_id:
        :return:
        """
        if self.use_global:
            msg = self.domains[bbclib.domain_global_0].make_message(dst_node_id=None,
                                                                    msg_type=InfraMessageTypeBase.NOTIFY_CROSS_REF)
            data = bytearray()
            data.extend(to_2byte(1))
            data.extend(domain_id)
            data.extend(transaction_id)
            msg[KeyType.cross_refs] = bytes(data)
            self.domains[bbclib.domain_global_0].random_send(msg, NUM_CROSS_REF_COPY)
        else:
            self.core.add_cross_ref_into_list(domain_id, transaction_id)

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
                            if KeyType.domain_ping in msg:
                                self.receive_domain_ping(ip4, addr, msg)
                                continue
                            if KeyType.destination_node_id not in msg or KeyType.domain_id not in msg:
                                continue
                            if msg[KeyType.domain_id] in self.domains:
                                self.domains[msg[KeyType.domain_id]].process_message_base(ip4, addr, msg, msg_parser.payload_type)
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


class DomainBase:
    """
    Base class of a domain
    """
    def __init__(self, network=None, config=None, domain_id=None, node_id=None, loglevel="all", logname=None):
        self.network = network
        self.config = config
        self.node_id = node_id
        self.domain_id = domain_id
        self.logger = logger.get_logger(key="domain:%s" % binascii.b2a_hex(domain_id[:4]).decode(),
                                        level=loglevel, logname=logname)
        if node_id is None:
            self.logger.error("node_id must be specified!")
            return
        self.shortname = binascii.b2a_hex(node_id[:2])  # for debugging
        self.default_payload_type = PayloadType.Type_msgpack
        self.id_ip_mapping = dict()
        self.registered_user_id = dict()
        self.user_id_forward_cache = dict()
        self.refresh_entry = None
        self.set_refresh_timer()

    def set_refresh_timer(self, interval=REFRESH_INTERVAL):
        """
        (internal use) set refresh timer

        :param interval:
        :return:
        """
        self.refresh_entry = query_management.exec_func_after(self.refresh_peer_list,
                                                              random.randint(int(interval / 2),
                                                              int(interval * 1.5)))

    def update_refresh_timer_random(self, update_time):
        """
        update refresh timer with random time (0.5*update_timer - 1.5*update_time)
        :param update_time:
        :return:
        """
        update_time += random.randint(0, int(update_time/2)) - int(update_time/4)
        self.refresh_entry.update_expiration_time(update_time)

    def refresh_peer_list(self, query_entry):
        """
        (internal use) refresh peer_list by alive_check

        :param query_entry:
        :return:
        """
        for nd in self.id_ip_mapping.keys():
            self.send_start_refresh(nd)
        self.alive_check()
        self.set_refresh_timer()

    def start_domain_manager(self):
        """
        (internal use) start domain manager loop

        :return:
        """
        th = threading.Thread(target=self.domain_manager_loop)
        th.setDaemon(True)
        th.start()

    def domain_manager_loop(self):
        """
        (internal use) maintain the domain (e.g., updating peer list and topology)

        :return:
        """
        pass

    def alive_check(self):
        """
        Check whether alive or not to update node list and to broadcast the list to others

        :return:
        """
        self.logger.error("Need to implement(override) alive_check()")

    def remove_peer_because_no_response(self, query_entry):
        """
        Remove the peer that does not respond
        :param query_entry:
        :return:
        """
        node_id = query_entry.data[KeyType.node_id]
        if node_id in self.id_ip_mapping and not self.id_ip_mapping[node_id].is_alive:
            del self.id_ip_mapping[node_id]

    def ping_with_retry(self, query_entry=None, node_id=None, retry_count=3):
        """
        Retry ping if response is not received within a given time

        :param query_entry:
        :param node_id:     target node_id (need for first trial)
        :param retry_count:
        :return:
        """
        if node_id is not None:
            query_entry = query_management.QueryEntry(expire_after=ALIVE_CHECK_PING_WAIT,
                                                      callback_expire=self.remove_peer_because_no_response,
                                                      callback_error=self.ping_with_retry,
                                                      interval=1,
                                                      data={KeyType.node_id: node_id},
                                                      retry_count=retry_count)
        else:
            node_id = query_entry.data[KeyType.node_id]
        query_entry.update()
        self.send_ping(node_id, nonce=query_entry.nonce)

    def ping_to_all_neighbors(self):
        """
        send ping to all neighbors
        :return:
        """
        for nd in self.id_ip_mapping.keys():
            self.ping_with_retry(None, nd)

    def add_peer_node_ip46(self, node_id, ipv4, ipv6, port, need_ping=False):
        """
        Add as a peer node (with ipv4 and ipv6 address)

        :param node_id:
        :param ipv4:
        :param ipv6:
        :param port:
        :return:
        """
        self.logger.debug("[%s] add_peer_node_ip46: nodeid=%s, port=%d" % (self.shortname,
                                                                           binascii.b2a_hex(node_id[:2]), port))
        self.id_ip_mapping[node_id] = NodeInfo(node_id=node_id, ipv4=ipv4, ipv6=ipv6, port=port)
        if need_ping:
            query_entry = query_management.QueryEntry(expire_after=ALIVE_CHECK_PING_WAIT,
                                                      callback_expire=self.remove_peer_because_no_response,
                                                      data={KeyType.node_id: node_id},
                                                      retry_count=0)
            self.ping_with_retry(node_id=node_id, retry_count=3)

    def add_peer_node(self, node_id, ip4, addr_info):
        """
        Add as a peer node

        :param node_id:
        :param ip4: True (IPv4)/False (IPv6)
        :param addr_info: tuple of (address, port)
        :return:
        """
        if addr_info is None:
            return True
        #print("[%s] add_peer_node: %s, %s" % (self.shortname, node_id.hex()[:4], addr_info))
        #print("[%s] current nodelist: %s" % (self.shortname, [str(m) for m in self.id_ip_mapping.values()]))
        port = addr_info[1]
        if node_id in self.id_ip_mapping:
            self.logger.debug("[%s] add_peer_node: nodeid=%s, port=%d" % (self.shortname,
                                                                          binascii.b2a_hex(node_id[:2]),
                                                                          addr_info[1]))
            if ip4:
                self.id_ip_mapping[node_id].update(ipv4=addr_info[0], port=port)
            else:
                self.id_ip_mapping[node_id].update(ipv6=addr_info[0], port=port)
            self.id_ip_mapping[node_id].touch()
            #print("[%s] updated nodelist: %s" % (self.shortname, [str(m) for m in self.id_ip_mapping.values()]))
            return False
        else:
            self.logger.debug("[%s] add_peer_node: new! nodeid=%s, port=%d" % (self.shortname,
                                                                               binascii.b2a_hex(node_id[:2]),
                                                                               addr_info[1]))
            if ip4:
                self.id_ip_mapping[node_id] = NodeInfo(node_id=node_id, ipv4=addr_info[0], ipv6=None, port=port)
            else:
                self.id_ip_mapping[node_id] = NodeInfo(node_id=node_id, ipv4=None, ipv6=addr_info[0], port=port)
            #print("[%s] new nodelist: %s" % (self.shortname, [str(m) for m in self.id_ip_mapping.values()]))
            if self.refresh_entry.rest_of_time_to_expire() > 10:
                self.update_refresh_timer_random(10)
            return True

    def remove_peer_node(self, node_id=ZEROS):
        """
        Remove node_info from the id_ip_mapping

        :param id:
        :return:
        """
        self.id_ip_mapping.pop(node_id, None)

    def make_peer_list(self):
        """
        Make binary peer_list (the first entry of the returned result always include the info of the node itself)

        :return: binary data of count,[node_id,ipv4,ipv6,port],[node_id,ipv4,ipv6,port],[node_id,ipv4,ipv6,port],,,,
        """
        nodeinfo = bytearray()

        # the node itself
        nodeinfo.extend(self.node_id)
        for item in self.network.get_my_socket_info():
            nodeinfo.extend(item)
        count = 1

        # neighboring node
        for nd in self.id_ip_mapping.keys():
            count += 1
            for item in self.id_ip_mapping[nd].get_nodeinfo():
                nodeinfo.extend(item)

        nodes = bytearray(count.to_bytes(4, 'big'))
        nodes.extend(nodeinfo)
        return bytes(nodes)

    def print_peerlist(self):
        """
        Show peer list for debugging

        :return:
        """
        pass

    def get_neighbor_nodes(self):
        """
        Return neighbor nodes (for broadcasting message)

        :return:
        """
        pass

    def register_user_id(self, user_id):
        """
        Register user_id that connect directly to this core node in the list

        :param user_id:
        :return:
        """
        #self.logger.debug("[%s] register_user_id: %s" % (self.shortname,binascii.b2a_hex(user_id[:4])))
        self.registered_user_id[user_id] = time.time()

    def unregister_user_id(self, user_id):
        """
        (internal use) remove user_id from the list

        :param user_id:
        :return:
        """
        self.registered_user_id.pop(user_id, None)

    def make_message(self, dst_node_id=None, nonce=None, msg_type=None):
        """
        (internal use) create message with basic components

        :param dst_node_id:
        :param nonce:
        :param msg_type:
        :return:
        """
        msg = {
            KeyType.source_node_id: self.node_id,
            KeyType.destination_node_id: dst_node_id,
            KeyType.domain_id: self.domain_id,
            KeyType.p2p_msg_type: msg_type,
        }
        if nonce is not None:
            msg[KeyType.nonce] = nonce
        return msg

    def send_message_to_peer(self, msg, payload_type=PayloadType.Type_msgpack):
        """
        Resolve socket for the target_id and call message send method in BBcNetwork

        :param msg:
        :param payload_type: PayloadType value
        :return:
        """
        target_id = msg[KeyType.destination_node_id]
        if target_id not in self.id_ip_mapping:
            self.logger.info("[%s] Fail to send message: no such node" % self.shortname)
            return False
        nodeinfo = self.id_ip_mapping[target_id]
        self.logger.debug("[%s] send_message_to_peer from %s to %s:type=%d:port=%d" %
                          (self.shortname,
                           binascii.b2a_hex(msg[KeyType.source_node_id][:2]),
                           binascii.b2a_hex(target_id[:2]),
                           int.from_bytes(msg[KeyType.p2p_msg_type],'big'), nodeinfo.port))

        self.network.send_message_in_network(nodeinfo, payload_type, msg=msg)
        return True

    def process_message_base(self, ip4, from_addr, msg, payload_type):
        """
        (internal use) process received message (common process for any kind of network module)

        :param ip4:       True (from IPv4) / False (from IPv6)
        :param from_addr: sender address and port (None if TCP)
        :param msg:       the message body (already deserialized)
        :param payload_type: PayloadType value of msg
        :return:
        """
        if KeyType.p2p_msg_type not in msg:
            return
        self.logger.debug("[%s] process_message(type=%d) from %s" %
                          (self.shortname,
                           int.from_bytes(msg[KeyType.p2p_msg_type], 'big'),
                           binascii.b2a_hex(msg[KeyType.source_node_id][:4])))
        if msg[KeyType.p2p_msg_type] == InfraMessageTypeBase.MESSAGE_TO_USER:
            if KeyType.message not in msg:
                return
            self.logger.debug("[%s] msg to app: %s" % (self.shortname, msg[KeyType.message]))
            self.network.core.send_message(msg[KeyType.message])

        elif msg[KeyType.p2p_msg_type] == InfraMessageTypeBase.REQUEST_PING:
            self.add_peer_node(msg[KeyType.source_node_id], ip4, from_addr)
            self.respond_ping(msg[KeyType.source_node_id], msg.get(KeyType.nonce))

        elif msg[KeyType.p2p_msg_type] == InfraMessageTypeBase.RESPONSE_PING:
            self.add_peer_node(msg[KeyType.source_node_id], ip4, from_addr)
            if KeyType.nonce in msg:
                query_entry = ticker.get_entry(msg[KeyType.nonce])
                if query_entry is not None:
                    query_entry.callback()

        elif msg[KeyType.p2p_msg_type] == InfraMessageTypeBase.RESPONSE_STORE:
            self.add_peer_node(msg[KeyType.source_node_id], ip4, from_addr)
            query_entry = ticker.get_entry(msg[KeyType.nonce])
            if query_entry is not None:
                query_entry.deactivate()

        elif msg[KeyType.p2p_msg_type] == InfraMessageTypeBase.NOTIFY_CROSS_REF:
            self.add_peer_node(msg[KeyType.source_node_id], ip4, from_addr)
            if KeyType.cross_refs in msg:
                dat = msg[KeyType.cross_refs]
                count = struct.unpack(">H", dat[:2])[0]
                ptr = 2
                for i in range(count):
                    domain_id = bytes(dat[ptr:ptr+32])
                    ptr += 32
                    transaction_id = bytes(dat[ptr:ptr+32])
                    ptr += 32
                    self.network.core.add_cross_ref_into_list(domain_id, transaction_id)

        elif msg[KeyType.p2p_msg_type] == InfraMessageTypeBase.NOTIFY_PEERLIST:
            self.renew_peerlist(msg[KeyType.peer_list])

        elif msg[KeyType.p2p_msg_type] == InfraMessageTypeBase.START_TO_REFRESH:
            self.add_peer_node(msg[KeyType.source_node_id], ip4, from_addr)
            self.refresh_entry.deactivate()
            self.set_refresh_timer()

        elif msg[KeyType.p2p_msg_type] == InfraMessageTypeBase.NOTIFY_LEAVE:
            self.remove_peer_node(msg[KeyType.source_node_id])

        else:
            self.process_message(ip4, from_addr, msg)

    def process_message(self, ip4, from_addr, msg):
        """
        (internal use) process received message for the network module (need to override)

        :param ip4:       True (from IPv4) / False (from IPv6)
        :param from_addr: sender address and port (None if TCP)
        :param msg:       the message body (already deserialized)
        :return:
        """
        pass

    def renew_peerlist(self, peerlist):
        """
        (internal use) renew peer_list

        :param peerlist:
        :return:
        """
        count = int.from_bytes(peerlist[:4], 'big')
        for i in range(count):
            base = 4 + i*(32+4+16+2+8)
            node_id = peerlist[base:base+32]
            if node_id == self.node_id:
                continue
            ipv4 = peerlist[base+32:base+36]
            ipv6 = peerlist[base+36:base+52]
            port = peerlist[base+52:base+54]
            updated_at = int.from_bytes(peerlist[base+54:base+62], 'big')
            if node_id in self.id_ip_mapping:
                if self.id_ip_mapping[node_id].updated_at < updated_at:
                    self.id_ip_mapping[node_id].recover_nodeinfo(node_id, ipv4, ipv6, port, updated_at)
                    self.send_ping(node_id, None)
            else:
                if updated_at > time.time() - REFRESH_INTERVAL/2:
                    self.id_ip_mapping[node_id] = NodeInfo()
                    self.id_ip_mapping[node_id].recover_nodeinfo(node_id, ipv4, ipv6, port, updated_at)
                    self.send_ping(node_id, None)

    def send_ping(self, target_id, nonce=None):
        msg = self.make_message(dst_node_id=target_id, nonce=nonce, msg_type=InfraMessageTypeBase.REQUEST_PING)
        return self.send_message_to_peer(msg, self.default_payload_type)

    def respond_ping(self, target_id, nonce=None):
        msg = self.make_message(dst_node_id=target_id, nonce=nonce, msg_type=InfraMessageTypeBase.RESPONSE_PING)
        return self.send_message_to_peer(msg, self.default_payload_type)

    def send_store(self, target_id, nonce, resource_id, resource, resource_type, asset_group_id=None):
        op_type = InfraMessageTypeBase.REQUEST_STORE
        msg = self.make_message(dst_node_id=target_id, nonce=nonce, msg_type=op_type)
        msg[KeyType.resource_id] = resource_id
        msg[KeyType.resource] = resource
        msg[KeyType.resource_type] = resource_type
        if asset_group_id is not None:
            msg[KeyType.asset_group_id] = asset_group_id
        return self.send_message_to_peer(msg, self.default_payload_type)

    def respond_store(self, target_id, nonce):
        msg = self.make_message(dst_node_id=target_id, nonce=nonce, msg_type=InfraMessageTypeBase.RESPONSE_STORE)
        return self.send_message_to_peer(msg, self.default_payload_type)

    def send_start_refresh(self, target_id):
        msg = self.make_message(dst_node_id=target_id, msg_type=InfraMessageTypeBase.START_TO_REFRESH)
        return self.send_message_to_peer(msg, self.default_payload_type)

    def leave_domain(self):
        msg = self.make_message(dst_node_id=ZEROS, nonce=None, msg_type=InfraMessageTypeBase.NOTIFY_LEAVE)
        nodelist = list(self.id_ip_mapping.keys())
        for nd in nodelist:
            msg[KeyType.destination_node_id] = nd
            self.send_message_to_peer(msg, self.default_payload_type)

    def random_send(self, msg, count):
        pass

    def get_resource(self, query_entry):
        pass

    def put_resource(self, resource_id, resource_type, resource, asset_group_id):
        pass

    def send_p2p_message(self, query_entry):
        pass


