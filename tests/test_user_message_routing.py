# -*- coding: utf-8 -*-
import pytest

from gevent import monkey
monkey.patch_all()
from gevent.pool import Pool
from gevent.server import StreamServer
from gevent import socket
from gevent.socket import wait_read
import threading

import shutil
import binascii
import queue
import time

import os
import sys
sys.path.extend(["../"])

from bbc1.core import bbclib
from bbc1.core.message_key_types import KeyType
from bbc1.core import bbc_network, user_message_routing, bbc_config, query_management, bbc_stats, message_key_types

LOGLEVEL = 'debug'
LOGLEVEL = 'info'

ticker = query_management.get_ticker()
core_nodes = 10
dummy_cores = [None for i in range(core_nodes)]
networkings = [None for i in range(core_nodes)]
client_socks = [None for i in range(core_nodes*2)]
user_routings = [None for i in range(core_nodes)]
result_queue = queue.Queue()

domain_id = bbclib.get_new_id("test_domain")
asset_group_id = bbclib.get_new_id("asset_group_1")
nodes = [None for i in range(core_nodes)]
users = [bbclib.get_new_id("test_user_%i" % i) for i in range(core_nodes*2)]


sample_resource_id = bbclib.get_new_id("sample_resource_id")


def get_random_data(length=16):
    import random
    source_str = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
    return "".join([random.choice(source_str) for x in range(length)])


def dummy_server_loop(socket, address):
    msg_parser = message_key_types.Message()
    try:
        while True:
            wait_read(socket.fileno())
            buf = socket.recv(8192)
            if len(buf) == 0:
                break
            msg_parser.recv(buf)
            while True:
                msg = msg_parser.parse()
                if msg is None:
                    break
                result_queue.put(msg)
    except:
        print("## disconnected")


def start_dummy_server(port):
    server = StreamServer(("0.0.0.0", port), dummy_server_loop, spawn=Pool(core_nodes*2))
    server.start()


class DummyCore:
    class DB:
        def add_domain(self, domain_id):
            pass

        def insert_transaction_locally(self, domain_id, resource_id, resource_type, data):
            print("insert_locally: domain_id=%s, resource_id=%s" % (binascii.b2a_hex(domain_id[:4]),
                                                                    binascii.b2a_hex(resource_id[:4])))

        def find_transaction_locally(self, domain_id, resource_id):
            if resource_id == sample_resource_id:
                print("find_locally: FOUND %s" % binascii.b2a_hex(resource_id[:4]))
                return b'sample_resource'
            else:
                print("find_locally: NOTFOUND!!!!!!!")
                return None

    class Storage:
        def set_storage_path(self, domain_id, storage_type, storage_path):
            pass

    def __init__(self, port):
        self.ledger_manager = DummyCore.DB()
        self.storage_manager = DummyCore.Storage()
        self.stats = bbc_stats.BBcStats()
        th = threading.Thread(target=start_dummy_server, args=(port,))
        th.setDaemon(True)
        th.start()


class TestBBcNetwork(object):

    def test_01_start(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        global dummy_cores, networkings, nodes
        user_message_routing.UserMessageRouting.REFRESH_FORWARDING_LIST_INTERVAL = 10  # for testing
        for i, nw in enumerate(networkings):
            if os.path.exists(".bbc1-%d"%i):
                shutil.rmtree(".bbc1-%d"%i)
            dummy_cores[i] = DummyCore(9000+i)
            config = bbc_config.BBcConfig(directory=".bbc1-%d"%i)
            networkings[i] = bbc_network.BBcNetwork(core=dummy_cores[i], config=config, p2p_port=6641+i, loglevel=LOGLEVEL)
            dummy_cores[i].networking = networkings[i]
            networkings[i].create_domain(domain_id=domain_id)
            user_routings[i] = networkings[i].domains[domain_id]['user']
            nodes[i] = networkings[i].domains[domain_id]['neighbor'].my_node_id
            assert nodes[i] is not None
            assert networkings[i].ip_address != ''
            print("IPv4: %s, IPv6 %s, port: %d" % (networkings[i].ip_address, networkings[i].ip6_address,
                                                   networkings[i].port))

    def test_02_set_initial_peer(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for i in range(core_nodes-5):
            networkings[i].add_neighbor(domain_id=domain_id, node_id=nodes[0],
                                        ipv4=networkings[0].ip_address, port=networkings[0].port)
            print(networkings[i].domains[domain_id]['neighbor'].show_list())

    def test_03_wait_and_show(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        print("-- wait 4 seconds --")
        time.sleep(4)
        for i in range(core_nodes):
            print(networkings[i].domains[domain_id]['neighbor'].show_list())

    def test_04_send_ping(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        ipv4 = networkings[0].ip_address
        ipv6 = networkings[0].ip6_address
        port = networkings[0].port
        for i in range(1, core_nodes):
            networkings[i].send_domain_ping(domain_id=domain_id, ipv4=ipv4, ipv6=ipv6, port=port, is_static=True)

    def test_05_wait_and_show(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        print("-- wait 10 seconds --")
        time.sleep(10)
        for i in range(core_nodes):
            print(networkings[i].domains[domain_id]['neighbor'].show_list())
            assert len(list(networkings[i].domains[domain_id]['neighbor'].nodeinfo_list.keys())) == core_nodes - 1

    def test_10_register_users(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        global client_socks
        for i in range(core_nodes):
            client_socks[i*2] = socket.create_connection(("127.0.0.1", 9000+i))
            client_socks[i*2+1] = socket.create_connection(("127.0.0.1", 9000+i))
            user_routings[i].register_user(user_id=users[i*2], socket=client_socks[i*2])
            user_routings[i].register_user(user_id=users[i*2+1], socket=client_socks[i*2+1])
            assert len(user_routings[i].registered_users) == 2

    def test_11_send_message_to_another_in_the_same_node(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        msg = {
            KeyType.domain_id: domain_id,
            KeyType.source_user_id: users[0],
            KeyType.destination_user_id: users[1],
            KeyType.message: 100,
        }
        user_routings[0].send_message_to_user(msg)
        time.sleep(1)
        recvmsg = result_queue.get()
        print(recvmsg)
        assert KeyType.reason not in recvmsg
        assert recvmsg[KeyType.message] == 100

    def test_12_send_message_to_another_in_the_different_node(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        msg = {
            KeyType.domain_id: domain_id,
            KeyType.source_user_id: users[0],
            KeyType.destination_user_id: users[2],
            KeyType.message: 200,
        }
        user_routings[0].send_message_to_user(msg)
        time.sleep(1)
        recvmsg = result_queue.get()
        print(recvmsg)
        assert KeyType.reason not in recvmsg
        assert recvmsg[KeyType.message] == 200
        assert len(user_routings[0].forwarding_entries[users[2]]['nodes']) == 1

        msg = {
            KeyType.domain_id: domain_id,
            KeyType.source_user_id: users[4],
            KeyType.destination_user_id: users[19],
            KeyType.message: 300,
        }
        user_routings[2].send_message_to_user(msg)
        time.sleep(1)
        recvmsg = result_queue.get()
        print(recvmsg)
        assert KeyType.reason not in recvmsg
        assert recvmsg[KeyType.message] == 300
        assert len(user_routings[2].forwarding_entries[users[19]]['nodes']) == 1

    def test_13_send_message_to_invalid_user(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        msg = {
            KeyType.domain_id: domain_id,
            KeyType.source_user_id: users[7],
            KeyType.destination_user_id: bbclib.get_new_id("test_user_invalid"),
            KeyType.message: 200,
        }
        user_routings[3].send_message_to_user(msg)
        time.sleep(1)
        recvmsg = result_queue.get()
        print(recvmsg)
        assert KeyType.reason in recvmsg
        assert recvmsg[KeyType.message] == 200

    def test_14_unregister_user19(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        assert len(user_routings[9].registered_users) == 2
        user_routings[9].unregister_user(user_id=users[19], socket=client_socks[19])
        assert len(user_routings[9].registered_users) == 1

    def test_15_send_message_to_user19(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        print("# users[19] originally connected with cores[9], but now unregistered.")
        msg = {
            KeyType.domain_id: domain_id,
            KeyType.source_user_id: users[4],
            KeyType.destination_user_id: users[19],
            KeyType.message: 400,
        }
        user_routings[2].send_message_to_user(msg)
        time.sleep(1)
        assert users[19] not in user_routings[2].forwarding_entries

    def test_16_wait_for_forward_list_all_purged(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        assert len(user_routings[0].forwarding_entries) == 1
        print("*** wait 10 seconds ***")
        time.sleep(10)
        for i in range(core_nodes):
            assert len(user_routings[i].forwarding_entries) == 0

    def test_17_reset_all_connections(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for i in range(core_nodes):
            user_routings[i].unregister_user(user_id=users[i*2], socket=client_socks[i*2])
            user_routings[i].unregister_user(user_id=users[i*2+1], socket=client_socks[i*2+1])
        for i in range(core_nodes):
            assert len(user_routings[i].registered_users) == 0

    def test_18_multi_connections_on_a_core(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        user_routings[0].register_user(user_id=users[0], socket=client_socks[0])
        user_routings[1].register_user(user_id=users[2], socket=client_socks[2])
        user_routings[1].register_user(user_id=users[2], socket=client_socks[3])
        assert len(user_routings[1].registered_users[users[2]]) == 2
        msg = {
            KeyType.domain_id: domain_id,
            KeyType.source_user_id: users[0],
            KeyType.destination_user_id: users[2],
            KeyType.message: 500,
        }
        user_routings[0].send_message_to_user(msg)
        time.sleep(1)
        assert result_queue.qsize() == 2
        for i in range(result_queue.qsize()):
            recv = result_queue.get()
            assert recv[KeyType.message] == 500

        user_routings[1].unregister_user(user_id=users[2], socket=client_socks[3])
        user_routings[0].send_message_to_user(msg)
        time.sleep(1)
        assert result_queue.qsize() == 1
        for i in range(result_queue.qsize()):
            recv = result_queue.get()
            assert recv[KeyType.message] == 500

    def test_19_multicast_and_multiconnection(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        user_routings[5].register_user(user_id=users[10], socket=client_socks[10])
        user_routings[2].register_user(user_id=users[4], socket=client_socks[4])
        user_routings[4].register_user(user_id=users[4], socket=client_socks[8])
        user_routings[4].register_user(user_id=users[4], socket=client_socks[9])
        assert len(user_routings[2].registered_users[users[4]]) == 1
        assert len(user_routings[4].registered_users[users[4]]) == 2
        msg = {
            KeyType.domain_id: domain_id,
            KeyType.source_user_id: users[10],
            KeyType.destination_user_id: users[4],
            KeyType.message: 600,
        }
        user_routings[5]._resolve_accommodating_core_node(dst_user_id=users[4], src_user_id=users[10])
        time.sleep(1)
        assert len(user_routings[5].forwarding_entries[users[4]]['nodes']) == 2
        # cores[2] and cores[4]

        user_routings[5].send_message_to_user(msg)
        time.sleep(1)
        assert result_queue.qsize() == 3
        for i in range(result_queue.qsize()):
            recv = result_queue.get()
            assert recv[KeyType.message] == 600


if __name__ == '__main__':
    pytest.main()
