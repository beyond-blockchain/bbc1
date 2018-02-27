# -*- coding: utf-8 -*-
import pytest

import binascii
import queue
import random
import time

import sys
sys.path.extend(["../"])

from bbc1.common import bbclib
from bbc1.common.message_key_types import KeyType
from bbc1.core import bbc_network, bbc_config, query_management, bbc_stats
from bbc1.core.bbc_types import ResourceType


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


def wait_results(count):
    total = 0
    for i in range(count):
        total += result_queue.get()
    return total


def get_test_func_success(query_entry):
    print("get_test_func_success: ", query_entry.data[KeyType.resource])
    result_queue.put(1)


def get_test_func_failure(query_entry):
    print("get_test_func_failure()")
    result_queue.put(0)


class DummyCore:
    class DB:
        def add_domain(self, domain_id):
            pass

        def insert_transaction_locally(self, domain_id, resource_id, resource_type, data):
            print("insert_locally: domain_id=%s, resource_id=%s" % (binascii.b2a_hex(domain_id[:4]),
                                                                    binascii.b2a_hex(resource_id[:4])))
            result_queue.put(1)

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

    def __init__(self):
        self.ledger_manager = DummyCore.DB()
        self.storage_manager = DummyCore.Storage()
        self.stats = bbc_stats.BBcStats()

    def send_message(self, data):
        print("[Core] recv=%s" % data)
        result_queue.put(1)

    def error_reply(self, msg=None, err_code=0, txt=""):
        print("[Core] error=%s" % txt)
        result_queue.put(0)

    def insert_transaction(self, asset_group_id, txdata, asset_files, no_network_put=False):
        print("[Core] insert_transaction")
        result_queue.put(1)


class TestBBcNetwork(object):

    def test_01_start(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        dummycore = DummyCore()
        from bbc1.core import simple_cluster
        simple_cluster.FORWARD_CACHE_SIZE = 5
        global networkings, nodes, conf
        for i, nw in enumerate(networkings):
            config = bbc_config.BBcConfig(directory=".bbc1-%d"%i)
            networkings[i] = bbc_network.BBcNetwork(core=dummycore, config=config, p2p_port=6641+i, loglevel=LOGLEVEL)
            networkings[i].create_domain(network_module="simple_cluster", domain_id=domain_id)
            nodes[i] = networkings[i].domains[domain_id].node_id
            assert nodes[i] is not None
            assert networkings[i].ip_address != ''
            print("IPv4: %s, IPv6 %s, port: %d" % (networkings[i].ip_address, networkings[i].ip6_address,
                                                   networkings[i].port))
        for i in range(core_nodes):
            networkings[i].register_user_id(domain_id, users[i])

    def test_02_set_initial_peer(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for i in range(core_nodes):
            networkings[i].domains[domain_id].add_peer_node(node_id=nodes[0],
                                                            ip4=True,
                                                            addr_info=(networkings[0].ip_address, networkings[0].port))
            networkings[i].domains[domain_id].print_peerlist()

    def test_03_send_ping(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for i in range(1, core_nodes):
            print("node=%d: ping_to:%s"%(i, binascii.b2a_hex(nodes[0])))
            ret = networkings[i].domains[domain_id].send_ping(nodes[0], None)
            assert ret
        print("sleep 2 seconds")
        time.sleep(2)
        networkings[0].domains[domain_id].print_peerlist()

        ret = networkings[2].domains[domain_id].send_ping(nodes[3], None)
        assert not ret

    def test_04_alive_check(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        networkings[0].domains[domain_id].alive_check()
        print("alive checking. need to wait 16 sec")
        time.sleep(16)
        networkings[1].domains[domain_id].print_peerlist()
        assert len(networkings[1].domains[domain_id].id_ip_mapping) == core_nodes-1

        ret = networkings[2].domains[domain_id].send_ping(nodes[3], None)
        assert ret

        for i in range(0, core_nodes):
            networkings[i].domains[domain_id].print_peerlist()

    def test_05_send_ping(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for i in range(1, core_nodes):
            k = random.randint(0,9)
            if i == k:
                continue
            print("node=%d: ping_to:%s"%(i, binascii.b2a_hex(nodes[k])))
            ret = networkings[i].domains[domain_id].send_ping(nodes[k], None)
            assert ret
        print("sleep 2 seconds")
        time.sleep(2)
        networkings[0].domains[domain_id].print_peerlist()

    def test_06_route_message(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for i in range(core_nodes):
            msg = {b'aaaaa': 1, b'bbbb': "AAAAAA from %d" % i}
            networkings[i].route_message(domain_id=domain_id, dst_user_id=users[0],
                                         src_user_id=users[i], msg_to_send=msg)
        print("wait queue: 10")
        total = wait_results(10)
        assert total == 10

    def test_07_route_message_with_cache(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for i in range(core_nodes):
            msg = {b'aaaaa': 1, b'bbbb': "BBBBBBB from %d" % i}
            networkings[i].route_message(domain_id=domain_id, dst_user_id=users[0],
                                         src_user_id=users[i], msg_to_send=msg)
        print("wait queue: 10")
        total = wait_results(10)
        assert total == 10

    def test_08_route_message_inavlid_user(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        dummy_user_id = bbclib.get_new_id("dummy_user_id")
        msg = {KeyType.command:3, KeyType.query_id:4, b'aaaaa': 1, b'bbbb': "CCCCCC from 1"}
        networkings[1].route_message(domain_id=domain_id, dst_user_id=dummy_user_id,
                                     src_user_id=users[1], msg_to_send=msg)
        total = wait_results(1)
        assert total == 0

    def test_09_route_message_overflow_cache(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for i in range(core_nodes):
            msg = {b'aaaaa': 1, b'bbbb': "DDDDDD from %d" % i}
            networkings[1].route_message(domain_id=domain_id,  dst_user_id=users[i],
                                         src_user_id=users[1], msg_to_send=msg)
        print("wait queue: 10")
        total = wait_results(10)
        assert total == 10

    def test_10_route_message_overflow_cache_again(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for i in range(core_nodes):
            msg = {b'aaaaa': 1, b'bbbb': "EEEEEEE from %d" % i}
            networkings[1].route_message(domain_id=domain_id, dst_user_id=users[i],
                                         src_user_id=users[1], msg_to_send=msg)
        print("wait queue: 10")
        total = wait_results(10)
        assert total == 10

    def test_11_put(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        resource = b'aaaaaa'
        resource_id = bbclib.get_new_id("dummy_resource_id")
        networkings[1].put(domain_id=domain_id, resource_id=resource_id, resource=resource)
        print("wait queue: 9")
        total = wait_results(9)
        assert total == 9

    def test_12_get(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        query_entry = query_management.QueryEntry(expire_after=10,
                                                  callback_expire=get_test_func_failure,
                                                  data={KeyType.domain_id: domain_id,
                                                        KeyType.asset_group_id: asset_group_id,
                                                        KeyType.resource_id: sample_resource_id,
                                                        KeyType.resource_type: ResourceType.Transaction_data},
                                                  retry_count=3)
        query_entry.update(2, callback=get_test_func_success)
        networkings[1].get(query_entry)
        print("wait queue: 1")
        total = wait_results(1)
        assert total == 1

    def test_12_get_failure(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        resource_id = bbclib.get_new_id("dummy_resource_id")
        query_entry = query_management.QueryEntry(expire_after=10,
                                                  callback_expire=get_test_func_failure,
                                                  data={KeyType.domain_id: domain_id,
                                                        KeyType.asset_group_id: asset_group_id,
                                                        KeyType.resource_id: resource_id,
                                                        KeyType.resource_type: ResourceType.Transaction_data},
                                                  retry_count=3)
        query_entry.update(2, callback=get_test_func_success)
        networkings[2].get(query_entry)
        print("wait queue: 1")
        total = wait_results(1)
        assert total == 0

    def test_13_leave_domain(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for i in range(2, core_nodes):
            networkings[i].remove_domain(domain_id)
        time.sleep(1)
        networkings[0].domains[domain_id].print_peerlist()


if __name__ == '__main__':
    pytest.main()
