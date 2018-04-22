# -*- coding: utf-8 -*-
import pytest

import binascii
import time
import pprint

import sys
sys.path.extend(["../", "../utils"])
from bbc1.core import bbclib
from bbc1.core import bbc_app
from testutils import prepare, get_core_client, start_core_thread, make_client, domain_setup_utility


LOGLEVEL = 'debug'
#LOGLEVEL = 'info'

localhost = "127.0.0.1"
#localhost = "::1"

core_num = 10
client_num = 10
cores = None
clients = None
domain_id = bbclib.get_new_id("testdomain")
asset_group_id = bbclib.get_new_id("asset_group_1")
transactions = [None for i in range(client_num)]
cross_ref_list = []

msg_processor = [None for i in range(client_num)]


class MessageProcessor(bbc_app.Callback):
    def __init__(self, index=0):
        super(MessageProcessor, self).__init__(self)
        self.idx = index


class TestBBcPing(object):

    def test_00_setup(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        print("domain_id =", binascii.b2a_hex(domain_id))

        global msg_processor
        prepare(core_num=core_num, client_num=client_num, loglevel=LOGLEVEL)
        for i in range(core_num):
            start_core_thread(index=i, core_port_increment=i, p2p_port_increment=i)
        time.sleep(1)
        for i in range(client_num):
            msg_processor[i] = MessageProcessor(index=i)
            domain_setup_utility(i, domain_id)  # system administrator
            make_client(index=i, core_port_increment=i, callback=msg_processor[i])
        time.sleep(1)

        global cores, clients
        cores, clients = get_core_client()

    def test_10_register(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for cl in clients:
            ret = cl['app'].register_to_core()
            assert ret
        time.sleep(1)

    def test_11_setup_network(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        ret = clients[0]['app'].get_domain_neighborlist(domain_id=domain_id)
        assert ret
        dat = msg_processor[0].synchronize()
        print("[0] nodeinfo=",dat[0])
        node_id, ipv4, ipv6, port, domain0 = dat[0]

        for i in range(1, client_num):
            ret = clients[i]['app'].set_domain_static_node(domain_id, node_id, ipv4, ipv6, port)
            assert ret
            ret = msg_processor[i].synchronize()
            print("[%d] set_domain_static_node result is %s" %(i, ret))

    def test_12_wait_and_show_result(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        print("*** wait 5 sec, checking neighbor_list in the core ***")
        time.sleep(5)
        for i in range(client_num):
            clients[i]['app'].get_domain_neighborlist(domain_id=domain_id)
            dat = msg_processor[i].synchronize()
            assert len(dat) == core_num
            print("-------------")
            pprint.pprint(dat)

    def test_99_quit(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for core in cores:
            core.networking.save_all_static_node_list()
            ret = core.config.update_config()
            assert ret


if __name__ == '__main__':
    pytest.main()
