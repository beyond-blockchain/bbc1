# -*- coding: utf-8 -*-
import pytest

import binascii
import time

import sys
sys.path.extend(["../"])
from bbc1.core import bbclib, bbc_app
from bbc1.core.message_key_types import KeyType
from testutils import prepare, get_core_client, start_core_thread, make_client, domain_setup_utility


LOGLEVEL = 'debug'
#LOGLEVEL = 'none'


core_num = 5
client_num = core_num * 2
cores = None
clients = None
domain_id = bbclib.get_new_id("testdomain")
asset_group_id = bbclib.get_new_id("asset_group_1")
transactions = [None for i in range(client_num)]

msg_processor = [None for i in range(client_num)]


class MessageProcessor(bbc_app.Callback):
    def __init__(self, index=0):
        super(MessageProcessor, self).__init__(self)
        self.idx = index

    def proc_cmd_sign_request(self, dat):
        self.logger.debug("[%i] Recv SIGN_REQUEST from %s" % (self.idx, binascii.b2a_hex(dat[KeyType.source_user_id])))
        txobj, fmt_type = bbclib.deserialize(dat[KeyType.transaction_data])

        objs = dict()
        for txid, txdata in dat[KeyType.transactions].items():
            txo, fmt_type = bbclib.deserialize(txdata)
            objs[txid] = txo

        for i, reference in enumerate(txobj.references):
            event = objs[reference.transaction_id].events[reference.event_index_in_ref]
            if clients[self.idx]['user_id'] in event.mandatory_approvers:
                signature = txobj.sign(keypair=clients[self.idx]['keypair'])
                clients[self.idx]['app'].sendback_signature(asset_group_id, dat[KeyType.source_user_id],
                                                            txobj.transaction_id, i, signature)
                return


class TestBBcAppClient(object):

    def test_00_setup(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        print("domain_id =", binascii.b2a_hex(domain_id))

        global msg_processor
        prepare(core_num=core_num, client_num=client_num, loglevel=LOGLEVEL)
        for i in range(core_num):
            start_core_thread(index=i, core_port_increment=i, p2p_port_increment=i)
            time.sleep(0.1)
            domain_setup_utility(i, domain_id)  # system administrator
        time.sleep(1)
        for i in range(core_num):
            msg_processor[i*2] = MessageProcessor(index=i*2)
            make_client(index=i*2, core_port_increment=i, callback=msg_processor[i*2])
            msg_processor[i * 2 + 1] = MessageProcessor(index=i*2+1)
            make_client(index=i * 2 + 1, core_port_increment=i, callback=msg_processor[i * 2 + 1])
        time.sleep(1)

        global cores, clients
        cores, clients = get_core_client()

    def test_10_setup_network(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        ret = clients[0]['app'].get_domain_neighborlist(domain_id=domain_id)
        assert ret
        dat = msg_processor[0].synchronize()
        print("[0] nodeinfo=", dat[0])
        node_id, ipv4, ipv6, port, domain0 = dat[0]

        for i in range(1, core_num):
            clients[i*2]['app'].send_domain_ping(domain_id, ipv4, ipv6, port)
        print("*** wait 5 seconds ***")
        time.sleep(5)

        for i in range(core_num):
            print(cores[i].networking.domains[domain_id]['neighbor'].show_list())
            assert len(cores[i].networking.domains[domain_id]['neighbor'].nodeinfo_list) == core_num - 1

    def test_11_register(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        global clients
        for cl in clients:
            ret = cl['app'].register_to_core()
            assert ret
        time.sleep(1)
        for i in range(4):
            assert clients[i]['app'].request_insert_completion_notification(asset_group_id)
        time.sleep(2)

        for i in range(core_num):
            fe = cores[i].networking.domains[domain_id]['user'].forwarding_entries
            assert asset_group_id in fe
            print(fe[asset_group_id]['nodes'])
            num = len(fe[asset_group_id]['nodes'])
            if i in [0, 1]:  # core0 and core1 have forwarding entry for core1 and core0, respectively.
                assert num == 1
            else:
                assert num == 2

    def test_12_cancel_notification(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        clients[0]['app'].cancel_insert_completion_notification(asset_group_id)
        clients[2]['app'].cancel_insert_completion_notification(asset_group_id)
        time.sleep(1)

        for i in range(core_num):
            fe = cores[i].networking.domains[domain_id]['user'].forwarding_entries
            assert asset_group_id in fe
            print(fe[asset_group_id]['nodes'])
            num = len(fe[asset_group_id]['nodes'])
            if i in [0, 1]:  # core0 and core1 have forwarding entry for core1 and core0, respectively.
                assert num == 1
            else:
                assert num == 2

    def test_13_cancel_notification(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        clients[1]['app'].cancel_insert_completion_notification(asset_group_id)
        time.sleep(1)

        for i in range(core_num):
            fe = cores[i].networking.domains[domain_id]['user'].forwarding_entries
            if i == 1:  # core1 has no forwarding entry because all clients in core0 canceled multicast forwarding
                assert asset_group_id not in fe
            else:
                assert asset_group_id in fe
                print(fe[asset_group_id]['nodes'])
                num = len(fe[asset_group_id]['nodes'])
                assert num == 1


if __name__ == '__main__':
    pytest.main()
