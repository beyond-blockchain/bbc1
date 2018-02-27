# -*- coding: utf-8 -*-
import pytest

import binascii
import time
import random

import sys
sys.path.extend(["../", "../utils"])
from bbc1.common import bbclib
from bbc1.common.message_key_types import KeyType
from bbc1.common.bbc_error import *
from bbc1.app import bbc_app
from testutils import prepare, get_core_client, start_core_thread, make_client, wait_check_result_msg_type
from bbc_ping import send_domain_ping


LOGLEVEL = 'debug'
#LOGLEVEL = 'info'

localhost = "127.0.0.1"
#localhost = "::1"

core_num = 4
client_num = 4
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
            make_client(index=i, core_port_increment=i, callback=msg_processor[i])
        time.sleep(1)

        global cores, clients
        cores, clients = get_core_client()

    def test_10_domain_setup(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")

        for i in range(client_num):
            clients[i]['app'].domain_setup(domain_id, "simple_cluster")
            dat = wait_check_result_msg_type(clients[i]['app'].callback,
                                             bbclib.ServiceMessageType.RESPONSE_SETUP_DOMAIN)
            assert dat[KeyType.status] == ESUCCESS
            time.sleep(1)

    def test_11_domain_ping(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")

        for i in range(1, client_num):
            #print("domain_ping to port=%d" % (6641+i))
            print("domain_ping to port=%d" % (6641))
            #send_domain_ping(clients[i]['app'], domain_id, localhost, 6641)
            send_domain_ping(clients[0]['app'], domain_id, localhost, 6641+i)

    def test_12_wait_and_show_result(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        print("*** wait 5 sec, checking peer_list in the core ***")
        time.sleep(17)

        for i in range(client_num):
            clients[i]['app'].get_domain_peerlist(domain_id=domain_id)
            dat = clients[i]['app'].callback.synchronize()
            print("====== peer list [%d] =====" % i)
            for k in range(len(dat)):
                node_id, ipv4, ipv6, port = dat[k]
                if k == 0:
                    print("*myself*    %s, %s, %s, %d" % (binascii.b2a_hex(node_id[:4]), ipv4, ipv6, port))
                else:
                    print("            %s, %s, %s, %d" % (binascii.b2a_hex(node_id[:4]), ipv4, ipv6, port))
            time.sleep(1)

    def test_99_quit(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for core in cores:
            core.networking.save_all_peer_lists()
            ret = core.config.update_config()
            assert ret


if __name__ == '__main__':
    pytest.main()
