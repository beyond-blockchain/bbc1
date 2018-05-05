# -*- coding: utf-8 -*-
import pytest

import time

import sys
sys.path.extend(["../"])
from bbc1.core import bbclib
from testutils import prepare, get_core_client, start_core_thread, make_client, domain_setup_utility
from bbc1.core import domain0_manager
from bbc1.core.message_key_types import KeyType


LOGLEVEL = 'info'
#LOGLEVEL = 'debug'

domain_num = 3
core_per_domain = 5
core_num = domain_num * core_per_domain
client_per_core = 2
client_num = core_num * client_per_core
cores = None
clients = None
domain_ids = [bbclib.get_new_id("testdomain%d" % i) for i in range(domain_num)]
asset_group_ids = [bbclib.get_new_id("asset_group_%d" % i) for i in range(domain_num)]

core_domains = [None for i in range(core_num)]
msg_processor = [None for i in range(client_num)]


def show_domain_list(domain_list):
    for dm in domain_list.keys():
        print(" Domain:", dm.hex())
        for nd in domain_list[dm]:
            print("   node_id:", nd.hex())


def sleep_tick(wait_for):
    print("-- sleep %d sec" % wait_for)
    end_time = time.time() + wait_for
    while time.time() < end_time:
        print("(%d) .. waiting" % int(time.time()))
        time.sleep(1)


class TestBBcAppClient(object):

    def test_00_setup(self):
        print("-----", sys._getframe().f_code.co_name, "-----")
        domain0_manager.Domain0Manager.DOMAIN_INFO_ADVERTISE_INTERVAL = 4  # just for testing
        domain0_manager.Domain0Manager.DOMAIN_INFO_LIFETIME = 8  # just for testing

        global msg_processor
        prepare(core_num=core_num, client_num=client_num, loglevel=LOGLEVEL)
        for i in range(domain_num):
            for j in range(core_per_domain):
                base_core_index = i * core_per_domain + j
                start_core_thread(index=base_core_index, core_port_increment=base_core_index,
                                  p2p_port_increment=base_core_index, use_domain0=True)
                domain_setup_utility(base_core_index, domain_ids[i])
                core_domains[base_core_index] = domain_ids[i]
        time.sleep(1)
        for i in range(domain_num):
            print("domain:", i)
            for j in range(core_per_domain):
                base_core_index = i * core_per_domain + j
                print(" base_core_index:", base_core_index)
                print("  client_index:", base_core_index*client_per_core, base_core_index*client_per_core+1)
                for k in range(client_per_core):
                    make_client(index=base_core_index*client_per_core+k,
                                core_port_increment=base_core_index, domain_id=domain_ids[i])
        time.sleep(1)

        global cores, clients
        cores, clients = get_core_client()
        for i in range(client_num):
            msg_processor[i] = clients[i]['app'].callback

    def test_1_register(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for cl in clients:
            ret = cl['app'].register_to_core()
            assert ret
        time.sleep(1)

    def test_2_setup_network(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for i in range(domain_num):
            base_client_index = i*core_per_domain*client_per_core
            #print("base_client_index:", base_client_index)
            clients[base_client_index]['app'].get_domain_neighborlist(domain_id=domain_ids[i])
            dat = msg_processor[base_client_index].synchronize()
            print("[%d] nodeinfo = %s" % (i * core_per_domain, dat[0]))
            node_id, ipv4, ipv6, port, domain0 = dat[0]
            for j in range(core_per_domain):
                c_index = base_client_index + j * client_per_core
                clients[c_index]['app'].send_domain_ping(domain_ids[i], ipv4, ipv6, port)
        print("*** wait 5 seconds ***")
        time.sleep(5)

        for i in range(domain_num):
            print(cores[i*core_per_domain].networking.domains[domain_ids[i]]['neighbor'].show_list())

    def test_11_setup_network_domain0(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        ipv4 = cores[0].networking.ip_address
        ipv6 = cores[0].networking.ip6_address
        port = cores[0].networking.port
        for i in range(1, core_num):
            cores[i].networking.send_domain_ping(domain_id=bbclib.domain_global_0, ipv4=ipv4, ipv6=ipv6, port=port, is_static=True)
        print("-- wait 5 seconds --")
        time.sleep(5)

        assert len(cores[1].networking.domains[bbclib.domain_global_0]['neighbor'].nodeinfo_list) == core_num - 1
        assert len(cores[14].networking.domains[bbclib.domain_global_0]['neighbor'].nodeinfo_list) == core_num - 1
        print(cores[1].networking.domains[bbclib.domain_global_0]['neighbor'].show_list())
        print(cores[14].networking.domains[bbclib.domain_global_0]['neighbor'].show_list())

        print("-- wait 5 seconds --")
        time.sleep(5)
        for i in range(domain_num):
            print(cores[i*core_per_domain].networking.domains[domain_ids[i]]['neighbor'].show_list())

    def test_13_wait(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        print("-- sleep 10 sec")
        time.sleep(10)
        for i in range(core_num):
            print("****** [%d] %s ******" % (i, cores[i].networking.domain0manager.my_node_id.hex()))
            dm = cores[i].networking.domain0manager.domain_list
            show_domain_list(dm)
        print("-- sleep 10 sec")

        time.sleep(10)
        for i in range(core_num):
            print("****** [%d] %s ******" % (i, cores[i].networking.domain0manager.my_node_id.hex()))
            dm = cores[i].networking.domain0manager.domain_list
            show_domain_list(dm)
            assert len(dm) == 2
            for d in dm:
                assert len(dm[d]) == 5
        print("-- sleep 5 sec")
        time.sleep(5)
        for i in range(core_num):
            nd = cores[i].networking.domain0manager.node_domain_list
            assert len(nd) == 10

    def test_14_remove_domain(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        clients[0]['app'].domain_close()
        dat = msg_processor[0].synchronize()
        assert dat[KeyType.result]
        sleep_tick(15)

        for i in range(1, 4):
            nd = cores[i].networking.domain0manager.node_domain_list
            print("node[%d]: len(node_domain_list)=%d" % (i, len(nd)))
            assert len(nd) == 10
        for i in range(5, core_num):
            nd = cores[i].networking.domain0manager.node_domain_list
            print("node[%d]: len(node_domain_list)=%d" % (i, len(nd)))
            assert len(nd) == 9

        print("****** [%d] %s ******" % (0, cores[0].networking.domain0manager.my_node_id.hex()))
        dm = cores[0].networking.domain0manager.domain_list
        show_domain_list(dm)
        assert len(dm) == 3
        for i in range(1, core_num):
            print("****** [%d] %s ******" % (i, cores[i].networking.domain0manager.my_node_id.hex()))
            dm = cores[i].networking.domain0manager.domain_list
            show_domain_list(dm)
            assert len(dm) == 2

    def test_15_remove_domain_in_all_nodes(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for i in range(1, core_num):
            clients[i*2]['app'].domain_close()
            dat = msg_processor[i*2].synchronize()
            assert dat[KeyType.result]
        sleep_tick(2)

        for i in range(core_num):
            print("****** [%d] %s ******" % (i, cores[i].networking.domain0manager.my_node_id.hex()))
            dm = cores[i].networking.domain0manager.domain_list
            show_domain_list(dm)

        sleep_tick(15)
        for i in range(core_num):
            nd = cores[i].networking.domain0manager.node_domain_list
            assert len(nd) == 0
        for i in range(core_num):
            print("****** [%d] %s ******" % (i, cores[i].networking.domain0manager.my_node_id.hex()))
            dm = cores[i].networking.domain0manager.domain_list
            show_domain_list(dm)

    def test_16_wait(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        print("-- sleep 10 sec")
        time.sleep(10)
        for i in range(core_num):
            print("****** [%d] %s ******" % (i, cores[i].networking.domain0manager.my_node_id.hex()))
            dm = cores[i].networking.domain0manager.domain_list
            show_domain_list(dm)
        print("-- sleep 10 sec")
        time.sleep(10)
        for i in range(core_num):
            print("****** [%d] %s ******" % (i, cores[i].networking.domain0manager.my_node_id.hex()))
            dm = cores[i].networking.domain0manager.domain_list
            show_domain_list(dm)
            for d in core_domains:
                assert d not in dm or len(dm[d]) == 0

    def test_98_unregister(self):
        for cl in clients:
            ret = cl['app'].unregister_from_core()
            assert ret

    def test_99_quit(self):
        for core in cores:
            core.networking.save_all_static_node_list()
            core.config.update_config()


if __name__ == '__main__':
    pytest.main()
