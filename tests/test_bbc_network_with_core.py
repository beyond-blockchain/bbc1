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
from bbc1.core.bbc_types import ResourceType
from bbc1.core import query_management
from testutils import prepare, start_core_thread, get_core_client


LOGLEVEL = 'debug'
LOGLEVEL = 'info'

core_nodes = 10
client_num = 10
cores = None
clients = None
domain_id = bbclib.get_new_id("testdomain")
asset_group_id = bbclib.get_new_id("asset_group_1")

users = [bbclib.get_new_id("test_user_%i" % i) for i in range(core_nodes)]
nodes = [None for i in range(core_nodes)]
transaction = None
keypair = bbclib.KeyPair()
keypair.generate()

result_queue = queue.Queue()
sample_resource_id = bbclib.get_new_id("sample_resource_id")


def wait_results(count):
    total = 0
    for i in range(count):
        total += result_queue.get()
    return total


def get_test_func_success(query_entry):
    print("get_test_func_success: ")
    result_queue.put(1)


def get_test_func_failure(query_entry):
    print("get_test_func_failure()")
    result_queue.put(0)


def dummy_send_message(data):
    print("[Core] recv=%s" % data)
    if KeyType.reason in data:
        result_queue.put(0)
    else:
        result_queue.put(1)


class TestBBcNetworkWithCore(object):

    def test_01_start(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        prepare(core_num=core_nodes, loglevel=LOGLEVEL)
        for i in range(core_nodes):
            start_core_thread(index=i, core_port_increment=i, p2p_port_increment=i)
        time.sleep(1)

        global cores, clients
        cores, clients = get_core_client()
        from bbc1.core import simple_cluster
        simple_cluster.FORWARD_CACHE_SIZE = 5
        for i in range(core_nodes):
            cores[i].networking.create_domain(network_module="simple_cluster", domain_id=domain_id)
            cores[i].ledger_manager.add_domain(domain_id)
            nodes[i] = cores[i].networking.domains[domain_id].node_id
            cores[i].networking.register_user_id(domain_id, users[i])
            cores[i].send_message = dummy_send_message
            cores[i].storage_manager.set_storage_path(domain_id, asset_group_id)

    def test_02_set_initial_peer(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for i in range(core_nodes):
            cores[i].networking.domains[domain_id].add_peer_node(node_id=nodes[0],
                                                                 ip4=True,
                                                                 addr_info=(cores[0].networking.ip_address,
                                                                 cores[0].networking.port))
            cores[i].networking.domains[domain_id].print_peerlist()

    def test_03_send_ping(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for i in range(1, core_nodes):
            print("node=%d: ping_to:%s"%(i, binascii.b2a_hex(nodes[0])))
            query_entry = query_management.QueryEntry(expire_after=2,
                                                      callback_expire=get_test_func_failure,
                                                      data={},
                                                      retry_count=1)
            query_entry.update(2, callback=get_test_func_success)
            ret = cores[i].networking.domains[domain_id].send_ping(nodes[0], query_entry.nonce)
            assert ret
        print("wait queue: 9")
        total = wait_results(9)
        assert total == 9
        cores[0].networking.domains[domain_id].print_peerlist()

        query_entry = query_management.QueryEntry(expire_after=2,
                                                  callback_expire=get_test_func_failure,
                                                  data={},
                                                  retry_count=1)
        query_entry.update(2, callback=get_test_func_success)
        ret = cores[2].networking.domains[domain_id].send_ping(nodes[3], query_entry.nonce)
        assert not ret
        print("wait queue: 1 (** should fail to send)")
        total = wait_results(1)
        assert total == 0

    def test_04_alive_check(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for i in range(core_nodes):
            cores[i].networking.domains[domain_id].print_peerlist()

        cores[0].networking.domains[domain_id].alive_check()
        print("** wait 16 sec to finish alive_check")
        time.sleep(16)
        assert len(cores[1].networking.domains[domain_id].id_ip_mapping) == core_nodes-1

        query_entry = query_management.QueryEntry(expire_after=2,
                                                  callback_expire=get_test_func_failure,
                                                  data={},
                                                  retry_count=1)
        query_entry.update(2, callback=get_test_func_success)
        ret = cores[2].networking.domains[domain_id].send_ping(nodes[3], query_entry.nonce)
        assert ret
        print("wait queue: 1")
        total = wait_results(1)
        assert total == 1

        for i in range(core_nodes):
            cores[i].networking.domains[domain_id].print_peerlist()

    def test_05_send_ping(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for i in range(1, core_nodes):
            k = random.randint(0,9)
            if i == k:
                continue
            print("node=%d: ping_to:%s"%(i, binascii.b2a_hex(nodes[k])))
            ret = cores[i].networking.domains[domain_id].send_ping(nodes[k], None)
            assert ret
        print("** wait 2 sec")
        time.sleep(2)

    def test_06_route_message(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for i in range(core_nodes):
            msg = {KeyType.domain_id: domain_id, KeyType.destination_user_id: users[0],
                   b'data': "AAAAAA from %d" % i}
            cores[i].networking.route_message(domain_id=domain_id, asset_group_id=asset_group_id,
                                              dst_user_id=users[0], msg_to_send=msg)
        print("wait queue: 10")
        total = wait_results(10)
        assert total == 10

    def test_07_route_message_with_cache(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for i in range(core_nodes):
            msg = {KeyType.domain_id: domain_id, KeyType.destination_user_id: users[0],
                   b'data': "BBBBBB from %d" % i}
            cores[i].networking.route_message(domain_id=domain_id, asset_group_id=asset_group_id,
                                              dst_user_id=users[0], msg_to_send=msg)
        print("wait queue: 10")
        total = wait_results(10)
        assert total == 10

    def test_08_route_message_inavlid_user(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        dummy_user_id = bbclib.get_new_id("dummy_user_id")
        msg = {KeyType.command:3, KeyType.query_id:4, b'aaaaa': 1, b'bbbb': "CCCCCC from 1"}
        cores[1].networking.route_message(domain_id=domain_id, asset_group_id=asset_group_id,
                                          dst_user_id=dummy_user_id, msg_to_send=msg)
        total = wait_results(1)
        assert total == 0

    def test_09_route_message_overflow_cache(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for i in range(core_nodes):
            msg = {b'aaaaa': 1, b'bbbb': "DDDDDD from %d" % i}
            cores[1].networking.route_message(domain_id=domain_id, asset_group_id=asset_group_id,
                                              dst_user_id=users[0], msg_to_send=msg)
        print("wait queue: 10")
        total = wait_results(10)
        assert total == 10

    def test_10_route_message_overflow_cache_again(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for i in range(core_nodes):
            msg = {b'aaaaa': 1, b'bbbb': "EEEEEEE from %d" % i}
            cores[1].networking.route_message(domain_id=domain_id, asset_group_id=asset_group_id,
                                              dst_user_id=users[0], msg_to_send=msg)
        print("wait queue: 10")
        total = wait_results(10)
        assert total == 10

    def test_11_put(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        global transaction
        transaction = bbclib.make_transaction_for_base_asset(asset_group_id=asset_group_id, event_num=2)
        transaction.events[0].asset.add(user_id=users[1], asset_body=b'123456')
        transaction.events[1].asset.add(user_id=users[1], asset_file=b'abcdefg')
        sig = transaction.sign(keypair=keypair)
        transaction.add_signature(user_id=users[0], signature=sig)
        transaction.digest()
        ret = cores[3].ledger_manager.insert_locally(domain_id, asset_group_id, transaction.transaction_id,
                                                     ResourceType.Transaction_data, transaction.serialize())
        time.sleep(2)
        ret = cores[3].ledger_manager.find_locally(domain_id, asset_group_id,
                                                   transaction.transaction_id, ResourceType.Transaction_data)
        assert ret is not None

    def test_12_get(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        query_entry = query_management.QueryEntry(expire_after=10,
                                                  callback_expire=get_test_func_failure,
                                                  data={KeyType.domain_id: domain_id,
                                                        KeyType.asset_group_id: asset_group_id,
                                                        KeyType.resource_id: transaction.transaction_id,
                                                        KeyType.resource_type: ResourceType.Transaction_data},
                                                  retry_count=7)  # count=7 may be enough
        query_entry.update(2, callback=get_test_func_success)
        cores[1].networking.get(query_entry)
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
                                                  retry_count=9)
        query_entry.update(2, callback=get_test_func_success)
        cores[2].networking.get(query_entry)
        print("wait queue: 1")
        total = wait_results(1)
        assert total == 0

    def test_13_leave_domain(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for i in range(2, core_nodes):
            cores[i].networking.remove_domain(domain_id)
        time.sleep(1)
        cores[0].networking.domains[domain_id].print_peerlist()


if __name__ == '__main__':
    pytest.main()

