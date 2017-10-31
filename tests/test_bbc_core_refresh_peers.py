# -*- coding: utf-8 -*-
import pytest

import binascii
import queue
import time

import sys
sys.path.extend(["../"])
from bbc1.core.bbc_ledger import ResourceType
from bbc1.common import bbclib
from testutils import prepare, start_core_thread, get_core_client, make_client

LOGLEVEL = 'debug'
LOGLEVEL = 'info'

core_num = 10
client_num = 10
cores = None
clients = None
domain_id = bbclib.get_new_id("testdomain", include_timestamp=False)
asset_group_id = bbclib.get_new_id("asset_group_1")
transaction = None

result_queue = queue.Queue()


def make_user(index):
    global users
    keypair = bbclib.KeyPair()
    keypair.generate()
    user_info = {
        'user_id': bbclib.get_new_id("user_%i" % index),
        'keypair': keypair,
    }
    users.append(user_info)


def wait_results(count):
    total = 0
    for i in range(count):
        total += result_queue.get()
    return total


def dummy_send_message(data):
    print("[Core] recv=%s" % data)
    if KeyType.reason in data:
        result_queue.put(0)
    else:
        result_queue.put(1)


class TestBBcCore(object):

    def test_01_setup(self):
        print("-----", sys._getframe().f_code.co_name, "-----")

        prepare(core_num=core_num, client_num=client_num, loglevel=LOGLEVEL)
        for i in range(core_num):
            start_core_thread(index=i, core_port_increment=i, p2p_port_increment=i, remove_dir=False)
        time.sleep(1)
        for i in range(client_num):
            make_client(index=i, core_port_increment=0, connect_to_core=False, asset_group_id=asset_group_id)

        time.sleep(1)
        global cores, clients
        cores, clients = get_core_client()
        for i in range(core_num):
            cores[i].networking.create_domain(network_module="simple_cluster", domain_id=domain_id)
            cores[i].send_message = dummy_send_message
            cores[i].storage_manager.set_storage_path(domain_id, asset_group_id)
        print("===========")

    def test_06_make_peerlist(self):
        print("-----", sys._getframe().f_code.co_name, "-----")
        node_id = cores[0].networking.domains[domain_id].node_id
        for i in range(1, core_num):
            cores[i].networking.domains[domain_id].add_peer_node(node_id=node_id, ip4=True,
                                                                 addr_info=(cores[0].networking.ip_address,
                                                                            cores[0].networking.port))
            cores[i].networking.domains[domain_id].send_ping(node_id, None)
        time.sleep(1)
        cores[0].networking.domains[domain_id].alive_check()
        print("*** wait for 2 sec for topology construction ***")
        time.sleep(2)
        for i in range(core_num):
            cores[i].networking.domains[domain_id].print_peerlist()

    def test_07_wait(self):
        print("-----", sys._getframe().f_code.co_name, "-----")
        print("--- wait 120 sec ---")
        #time.sleep(120)

    def test_99_quit(self):
        for core in cores:
            core.networking.save_all_peer_lists()
            core.config.update_config()


if __name__ == '__main__':
    pytest.main()
