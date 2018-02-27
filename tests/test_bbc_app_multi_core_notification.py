# -*- coding: utf-8 -*-
import pytest

import binascii
import time

import sys
sys.path.extend(["../"])
from bbc1.common import bbclib
from bbc1.common.message_key_types import KeyType
from bbc1.common.bbc_error import *
from bbc1.app import bbc_app
from testutils import prepare, get_core_client, start_core_thread, make_client, domain_setup_utility


LOGLEVEL = 'debug'
#LOGLEVEL = 'none'


core_num = 5
client_num = 5
cores = None
clients = None
domain_id = bbclib.get_new_id("testdomain")
asset_group_id = bbclib.get_new_id("asset_group_1")
transactions = [None for i in range(client_num)]
cross_ref_list = [[] for i in range(client_num)]
msg_processor = [None for i in range(client_num)]


class MessageProcessor(bbc_app.Callback):
    def __init__(self, index=0):
        super(MessageProcessor, self).__init__(self)
        self.idx = index

    def proc_cmd_sign_request(self, dat):
        self.logger.debug("[%i] Recv SIGN_REQUEST from %s" % (self.idx, binascii.b2a_hex(dat[KeyType.source_user_id])))
        txobj = bbclib.BBcTransaction()
        txobj.deserialize(dat[KeyType.transaction_data])

        objs = dict()
        for txid, txdata in dat[KeyType.transactions].items():
            txo = bbclib.BBcTransaction()
            txo.deserialize(txdata)
            objs[txid] = txo

        for i, reference in enumerate(txobj.references):
            event = objs[reference.transaction_id].events[reference.event_index_in_ref]
            if clients[self.idx]['user_id'] in event.mandatory_approvers:
                signature = txobj.sign(keypair=clients[self.idx]['keypair'])
                clients[self.idx]['app'].sendback_signature(asset_group_id, dat[KeyType.source_user_id], i, signature)
                return


class TestBBcAppClient(object):

    def test_00_setup(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        print("domain_id =", binascii.b2a_hex(domain_id))

        global msg_processor
        prepare(core_num=core_num, client_num=client_num, loglevel=LOGLEVEL)
        cni = 0
        for i in range(core_num):
            if core_num > 1:
                cni = i
            start_core_thread(index=i, core_port_increment=cni, p2p_port_increment=i)
            domain_setup_utility(i, domain_id)  # system administrator
        time.sleep(1)
        for i in range(client_num):
            if core_num > 1:
                cni = i
            msg_processor[i] = MessageProcessor(index=i)
            make_client(index=i, core_port_increment=cni, callback=msg_processor[i])
        time.sleep(1)

        global cores, clients
        cores, clients = get_core_client()

    def test_10_setup_network(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")

        ret = clients[0]['app'].get_domain_peerlist(domain_id=domain_id)
        assert ret
        dat = msg_processor[0].synchronize()
        print("[0] nodeinfo=",dat[0])
        node_id, ipv4, ipv6, port = dat[0]

        for i in range(1, client_num):
            ret = clients[i]['app'].set_domain_static_node(domain_id, node_id, ipv4, ipv6, port)
            assert ret
            ret = msg_processor[i].synchronize()
            print("[%d] set_peer result is %s" %(i, ret))
            clients[i]['app'].ping_to_all_neighbors(domain_id)
        time.sleep(2)

        cores[0].networking.domains[domain_id].alive_check()
        print("** wait 16 sec to finish alive_check")
        time.sleep(16)
        assert len(cores[1].networking.domains[domain_id].id_ip_mapping) == core_num-1
        for i in range(core_num):
            cores[i].networking.domains[domain_id].print_peerlist()

    def test_11_register(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for cl in clients:
            ret = cl['app'].register_to_core()
            assert ret
        time.sleep(1)
        for cl in clients:
            assert cl['app'].request_insert_completion_notification(asset_group_id, True)
        print("---- wait 10 sec ----")
        time.sleep(10)

    def test_12_make_transaction(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for i, cl in enumerate(clients):
            print("---- start transaction at node %d---" % i)
            user = cl['user_id']
            transactions[i] = bbclib.make_transaction_for_base_asset(asset_group_id=asset_group_id, event_num=1)
            cl['app'].get_cross_refs(asset_group_id=asset_group_id, number=2)
            dat = msg_processor[i].synchronize()
            cross_ref_list[i].extend(dat)
            if len(cross_ref_list[i]) > 0:
                transactions[i].add(cross_ref=cross_ref_list[i].pop(0))

            transactions[i].events[0].asset.add(user_id=user, asset_body="data=%d"%i)
            other_user = (i+1) % client_num
            transactions[i].events[0].add(mandatory_approver=clients[other_user]['user_id'])

            sig = transactions[i].sign(keypair=cl['keypair'])
            transactions[i].add_signature(user_id=cl['user_id'], signature=sig)

            transactions[i].digest()
            print("insert_transaction=", binascii.b2a_hex(transactions[i].transaction_id))
            ret = cl['app'].insert_transaction(transactions[i])
            assert ret
            print("  ----> wait for notification")
            for j in range(client_num):
                retdat = msg_processor[j].synchronize()
                print("[%d] notification txid=%s, asset_group=%s" % (
                    j, binascii.b2a_hex(retdat[KeyType.transaction_id]),
                    binascii.b2a_hex(retdat[KeyType.asset_group_id])
                ))

            msg_processor[i].synchronize()
            print("    ==> got notification")

    def test_20_cancel_notification(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for cl in clients:
            assert cl['app'].request_insert_completion_notification(asset_group_id, False)

    def test_21_make_transaction(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for i, cl in enumerate(clients):
            print("---- start transaction at node %d---" % i)
            user = cl['user_id']
            transactions[i] = bbclib.make_transaction_for_base_asset(asset_group_id=asset_group_id, event_num=1)
            cl['app'].get_cross_refs(asset_group_id=asset_group_id, number=2)
            dat = msg_processor[i].synchronize()
            cross_ref_list[i].extend(dat)
            if len(cross_ref_list[i]) > 0:
                transactions[i].add(cross_ref=cross_ref_list[i].pop(0))

            transactions[i].events[0].asset.add(user_id=user, asset_body="data=%d"%i)
            other_user = (i+1) % client_num
            transactions[i].events[0].add(mandatory_approver=clients[other_user]['user_id'])

            sig = transactions[i].sign(keypair=cl['keypair'])
            transactions[i].add_signature(user_id=cl['user_id'], signature=sig)

            transactions[i].digest()
            print("insert_transaction=", binascii.b2a_hex(transactions[i].transaction_id))
            ret = cl['app'].insert_transaction(transactions[i])
            assert ret
            msg_processor[i].synchronize()

    def test_22_enable_notification(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for cl in clients:
            assert cl['app'].request_insert_completion_notification(asset_group_id, True)

    def test_23_make_transaction(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for i, cl in enumerate(clients):
            print("---- start transaction at node %d---" % i)
            user = cl['user_id']
            transactions[i] = bbclib.make_transaction_for_base_asset(asset_group_id=asset_group_id, event_num=1)
            cl['app'].get_cross_refs(asset_group_id=asset_group_id, number=2)
            dat = msg_processor[i].synchronize()
            cross_ref_list[i].extend(dat)
            if len(cross_ref_list[i]) > 0:
                transactions[i].add(cross_ref=cross_ref_list[i].pop(0))

            transactions[i].events[0].asset.add(user_id=user, asset_body="data=%d"%i)
            other_user = (i+1) % client_num
            transactions[i].events[0].add(mandatory_approver=clients[other_user]['user_id'])

            sig = transactions[i].sign(keypair=cl['keypair'])
            transactions[i].add_signature(user_id=cl['user_id'], signature=sig)

            transactions[i].digest()
            print("insert_transaction=", binascii.b2a_hex(transactions[i].transaction_id))
            ret = cl['app'].insert_transaction(transactions[i])
            assert ret
            print("  ----> wait for notification")
            for j in range(client_num):
                retdat = msg_processor[j].synchronize()
                print("[%d] notification txid=%s, asset_group=%s" % (
                    j, binascii.b2a_hex(retdat[KeyType.transaction_id]),
                    binascii.b2a_hex(retdat[KeyType.asset_group_id])
                ))

            msg_processor[i].synchronize()
            print("    ==> got notification")

    @pytest.mark.unregister
    def test_98_unregister(self):
        for cl in clients:
            ret = cl['app'].unregister_from_core()
            assert ret


if __name__ == '__main__':
    pytest.main()
