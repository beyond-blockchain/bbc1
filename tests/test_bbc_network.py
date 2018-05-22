# -*- coding: utf-8 -*-
import pytest

import shutil
import queue
import time

import os
import sys
sys.path.extend(["../"])

from bbc1.core import bbclib
from bbc1.core import bbc_network, bbc_config, query_management, bbc_stats
from bbc1.core.topology_manager import TopologyManagerBase

LOGLEVEL = 'debug'
LOGLEVEL = 'info'

ticker = query_management.get_ticker()
core_nodes = 10
networkings = [None for i in range(core_nodes)]
nodes = [None for i in range(core_nodes)]

domain_id = bbclib.get_new_id("test_domain")
asset_group_id = bbclib.get_new_id("asset_group_1")
users = [bbclib.get_new_id("test_user_%i" % i) for i in range(core_nodes)]

result_queue = queue.Queue()

sample_resource_id = bbclib.get_new_id("sample_resource_id")


def get_random_data(length=16):
    import random
    source_str = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
    return "".join([random.choice(source_str) for x in range(length)])


class DummyCore:
    class UserMessageRouting:
        def add_domain(self, domain_id):
            pass

        def remove_domain(self, domain_id):
            pass

    def __init__(self):
        self.user_message_routing = DummyCore.UserMessageRouting()
        self.stats = bbc_stats.BBcStats()


class TestBBcNetwork(object):

    def test_01_start(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")

        TopologyManagerBase.NEIGHBOR_LIST_REFRESH_INTERVAL = 15
        dummycore = DummyCore()
        global networkings, nodes, conf
        for i, nw in enumerate(networkings):
            if os.path.exists(".bbc1-%d"%i):
                shutil.rmtree(".bbc1-%d"%i)
            config = bbc_config.BBcConfig(directory=".bbc1-%d"%i)
            networkings[i] = bbc_network.BBcNetwork(core=dummycore, config=config, p2p_port=6641+i, loglevel=LOGLEVEL)
            networkings[i].create_domain(domain_id=domain_id)
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
        for i in range(5, core_nodes):
            networkings[i].send_domain_ping(domain_id=domain_id, ipv4=ipv4, ipv6=ipv6, port=port, is_static=True)
        print("-- wait 5 seconds --")
        time.sleep(5)

    def test_05_wait_and_show(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for i in range(core_nodes):
            print(networkings[i].domains[domain_id]['neighbor'].show_list())
            assert len(list(networkings[i].domains[domain_id]['neighbor'].nodeinfo_list.keys())) == core_nodes - 1

    def test_06_leave_domain(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        networkings[core_nodes-1].remove_domain(domain_id)
        print("-- wait 5 seconds --")
        time.sleep(5)

    def test_07_wait_and_show(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for i in range(core_nodes-1):
            print(networkings[i].domains[domain_id]['neighbor'].show_list())
            assert len(list(networkings[i].domains[domain_id]['neighbor'].nodeinfo_list.keys())) == core_nodes - 2

    def test_08_long_wait_for_refresh(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        print("-- wait 20 seconds in total --")
        for i in range(4):
            time.sleep(5)
            print("* elapsed:", (i+1)*5)

    def test_09_save_list(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        networkings[0].save_all_static_node_list()
        with open(".bbc1-%d/config.json" % 0, "r") as f:
            dat = f.read()
        print(dat)


if __name__ == '__main__':
    pytest.main()
