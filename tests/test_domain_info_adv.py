# -*- coding: utf-8 -*-
import pytest

import binascii
import time

import sys
sys.path.extend(["../"])
from bbc1.common import bbclib
from testutils import prepare, get_core_client, start_core_thread, make_client, domain_setup_utility

import random

LOGLEVEL = 'info'
#LOGLEVEL = 'debug'

core_num = 15
client_num = 30
cores = None
clients = None
domain_num = 3
domain_ids = [bbclib.get_new_id("testdomain%d" % i) for i in range(domain_num)]
asset_group_ids = [bbclib.get_new_id("asset_group_%d" % i) for i in range(domain_num)]

msg_processor = [None for i in range(client_num)]


class TestBBcAppClient(object):

    def test_00_setup(self):
        print("XXXXXXXXXXXXXXX change value to DOMAIN_INFO_LIFETIME = 20 in p2p_domain0.py XXXXXXXXXXXXXXX")
        print("-----", sys._getframe().f_code.co_name, "-----")
        global msg_processor
        prepare(core_num=core_num, client_num=client_num, loglevel=LOGLEVEL)
        for i in range(core_num):
            start_core_thread(index=i, core_port_increment=i, p2p_port_increment=i, use_global=True)
            domain_setup_utility(i, domain_ids[i%domain_num])
        time.sleep(1)
        for i in range(client_num):
            make_client(index=i, core_port_increment=i%core_num, asset_group_id=asset_group_ids[i%domain_num])
        time.sleep(1)
        # client: i*3 = domain[0], i*3+1 = domain[1], i*3+2 = domain[2]

        global cores, clients
        cores, clients = get_core_client()
        for i in range(client_num):
            msg_processor[i] = clients[i]['app'].callback

    def test_10_setup_network(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        node_info = []
        for i in range(domain_num):
            ret = clients[i]['app'].get_domain_peerlist(domain_id=domain_ids[i])
            assert ret
            ret = msg_processor[i].synchronize()
            node_info.append(ret[0])
        for i in range(3, client_num):
            node_id, ipv4, ipv6, port = node_info[i%domain_num]
            ret = clients[i]['app'].set_domain_static_node(domain_ids[i%domain_num], node_id, ipv4, ipv6, port)
            assert ret
            ret = msg_processor[i].synchronize()

        time.sleep(3)
        for i in range(core_num):
            for k in range(domain_num):
                if domain_ids[k] in cores[i].networking.domains:
                    cores[i].networking.domains[domain_ids[k]].print_peerlist()

    def test_11_setup_network_global(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        ret = clients[0]['app'].get_domain_peerlist(domain_id=bbclib.domain_global_0)
        assert ret
        ret = msg_processor[0].synchronize()
        node_id, ipv4, ipv6, port = ret[0]

        for i in range(1, client_num):
            ret = clients[i]['app'].set_domain_static_node(bbclib.domain_global_0, node_id, ipv4, ipv6, port)
            assert ret
            ret = msg_processor[i].synchronize()

        time.sleep(3)
        for i in range(core_num):
            cores[i].networking.domains[bbclib.domain_global_0].print_peerlist()

    def test_12_register(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for cl in clients:
            cl['app'].set_domain_id(bbclib.domain_global_0)
            ret = cl['app'].register_to_core()
            assert ret
        time.sleep(1)

    def test_13_wait(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        print("-- sleep 10 sec")
        time.sleep(10)
        print("-- sleep 10 sec")
        time.sleep(10)
        for i in range(core_num):
            cores[i].networking.domains[bbclib.domain_global_0].print_domain_info()
        print("-- sleep 10 sec")
        time.sleep(10)
        for i in range(core_num):
            cores[i].networking.domains[bbclib.domain_global_0].print_domain_info()
        print("-- sleep 10 sec")
        time.sleep(10)
        print("-- sleep 10 sec")
        time.sleep(10)
        print("-- sleep 10 sec")
        time.sleep(10)
        for i in range(core_num):
            cores[i].networking.domains[bbclib.domain_global_0].print_domain_info()

    def test_98_unregister(self):
        for cl in clients:
            ret = cl['app'].unregister_from_core()
            assert ret

    def test_99_quit(self):
        for core in cores:
            core.networking.save_all_peer_lists()
            core.config.update_config()


if __name__ == '__main__':
    pytest.main()
