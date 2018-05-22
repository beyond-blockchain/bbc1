# -*- coding: utf-8 -*-
import pytest

import shutil
import queue
import time

import os
import sys
sys.path.extend(["../"])

from bbc1.core import bbclib
from bbc1.core import bbc_network, bbc_config, query_management, bbc_stats, message_key_types
from bbc1.core import key_exchange_manager
from bbc1.core.topology_manager import TopologyManagerBase

LOGLEVEL = 'debug'
LOGLEVEL = 'info'

ticker = query_management.get_ticker()
core_nodes = 2
networkings = [None for i in range(core_nodes)]
nodes = [None for i in range(core_nodes)]

domain_id = bbclib.get_new_id("test_domain")
asset_group_id = bbclib.get_new_id("asset_group_1")
users = [bbclib.get_new_id("test_user_%i" % i) for i in range(core_nodes)]
key_names = [None for i in range(core_nodes)]
result_queue = queue.Queue()

sample_resource_id = bbclib.get_new_id("sample_resource_id")


def get_random_data(length=16):
    import random
    source_str = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
    return "".join([random.choice(source_str) for x in range(length)])


def sleep_tick(wait_for):
    end_time = time.time() + wait_for
    while time.time() < end_time:
        print("(%d) .. waiting" % int(time.time()))
        time.sleep(1)


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
        key_exchange_manager.KeyExchangeManager.KEY_EXCHANGE_INVOKE_MAX_BACKOFF = 1
        key_exchange_manager.KeyExchangeManager.KEY_EXCHANGE_RETRY_INTERVAL = 3
        key_exchange_manager.KeyExchangeManager.KEY_REFRESH_INTERVAL = 15
        key_exchange_manager.KeyExchangeManager.KEY_OBSOLETE_TIMER = 4
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
        for i in range(1, core_nodes):
            networkings[i].add_neighbor(domain_id=domain_id, node_id=nodes[0],
                                        ipv4=networkings[0].ip_address, port=networkings[0].port)
            print(networkings[i].domains[domain_id]['neighbor'].show_list())

    def test_03_wait_and_show(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        print("-- wait 2 seconds --")
        global key_names
        sleep_tick(2)
        for i in range(core_nodes):
            #print(networkings[i].domains[domain_id]['neighbor'].show_list())
            for nd in networkings[i].domains[domain_id]['neighbor'].nodeinfo_list.values():
                assert nd.key_manager.state == key_exchange_manager.KeyExchangeManager.STATE_ESTABLISHED
                assert nd.key_manager.key_name in message_key_types.encryptors
                key_names[i] = nd.key_manager.key_name

        for i in range(core_nodes):
            print("keynames[%d]=%s" % (i, key_names[i].hex()[:10]))
        for k in message_key_types.encryptors.keys():
            print("key_name=%s" % k.hex()[:10])

    def test_04_wait(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        print("-- wait 10 seconds (should be established) --")
        sleep_tick(10)
        for i in range(core_nodes):
            for nd in networkings[i].domains[domain_id]['neighbor'].nodeinfo_list.values():
                assert nd.key_manager.state == key_exchange_manager.KeyExchangeManager.STATE_ESTABLISHED
                assert nd.key_manager.key_name in message_key_types.encryptors
                assert key_names[i] in message_key_types.encryptors
        for k in message_key_types.encryptors.keys():
            print("key_name=%s" % k.hex()[:10])

    def test_05_wait_refresh(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        print("-- wait 15 seconds (will occur refresh and re-established) --")
        sleep_tick(15)
        for k in message_key_types.encryptors.keys():
            print("key_name=%s" % k.hex()[:10])
        for i in range(core_nodes):
            for nd in networkings[i].domains[domain_id]['neighbor'].nodeinfo_list.values():
                assert nd.key_manager.state == key_exchange_manager.KeyExchangeManager.STATE_ESTABLISHED
                assert nd.key_manager.key_name in message_key_types.encryptors
                assert key_names[i] not in message_key_types.encryptors
        assert len(message_key_types.encryptors) == 2


if __name__ == '__main__':
    pytest.main()
