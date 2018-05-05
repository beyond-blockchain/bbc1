# -*- coding: utf-8 -*-
import pytest

import binascii
import time

import os
import sys
sys.path.extend(["../"])
from bbc1.core import bbclib
from bbc1.core.message_key_types import KeyType
from bbc1.core.bbc_error import *
from bbc1.core import bbc_app
from testutils import prepare, get_core_client, start_core_thread, make_client, domain_setup_utility


LOGLEVEL = 'debug'
#LOGLEVEL = 'info'


core_num = 5
client_num = 5
cores = None
clients = None
domain_id = bbclib.get_new_id("testdomain")

anycast_id = bbclib.get_new_id()

msg_processor = [None for i in range(client_num)]


class MessageProcessor(bbc_app.Callback):
    def __init__(self, index=0):
        super(MessageProcessor, self).__init__(self)
        self.idx = index

    def proc_user_message(self, dat):
        print("User[%d] receives message:%s" % (self.idx, dat[KeyType.message]))


class TestBBcAppClient(object):

    def test_00_setup(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        print("domain_id =", binascii.b2a_hex(domain_id))

        keypair = bbclib.KeyPair()
        keypair.generate()
        keyname = domain_id.hex() + ".pem"
        try:
            os.mkdir(".bbc1")
        except:
            pass
        with open(os.path.join(".bbc1", keyname), "wb") as f:
            f.write(keypair.get_private_key_in_pem())

        global msg_processor
        prepare(core_num=core_num, client_num=client_num, loglevel=LOGLEVEL)
        for i in range(core_num):
            start_core_thread(index=i, core_port_increment=i, p2p_port_increment=i)
            time.sleep(0.1)
            domain_setup_utility(i, domain_id)  # system administrator
        time.sleep(1)
        for i in range(client_num):
            msg_processor[i] = MessageProcessor(index=i)
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
        time.sleep(5)

        for i in range(client_num):
            clients[i]['app'].get_domain_neighborlist(domain_id=domain_id)
            dat = msg_processor[i].synchronize()
            assert len(dat) == core_num

    def test_12_register(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for cl in clients:
            cl['user_id'] = anycast_id
            cl['app'].set_user_id(anycast_id)
            ret = cl['app'].register_to_core(on_multiple_nodes=True)
            assert ret
        time.sleep(1)

    def test_30_messaging(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for k in range(5):
            for i in range(client_num):
                msg = "message %d" % i
                clients[i]['app'].send_message(msg, anycast_id, is_anycast=True)
        print("--- wait 3 seconds ---")
        time.sleep(3)


if __name__ == '__main__':
    pytest.main()
