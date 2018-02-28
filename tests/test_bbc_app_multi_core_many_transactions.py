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
LOGLEVEL = 'none'


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
                clients[self.idx]['app'].sendback_signature(dat[KeyType.source_user_id], i, signature)
                return


class TestBBcAppClient(object):

    def test_00_setup(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        print("domain_id =", binascii.b2a_hex(domain_id))

        global msg_processor
        prepare(core_num=core_num, client_num=client_num, loglevel=LOGLEVEL)
        for i in range(core_num):
            start_core_thread(index=i, core_port_increment=i, p2p_port_increment=i)
            domain_setup_utility(i, domain_id)  # system administrator
        time.sleep(1)
        for i in range(client_num):
            msg_processor[i] = MessageProcessor(index=i)
            make_client(index=i, core_port_increment=i, callback=msg_processor[i])
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

        clients[0]['app'].broadcast_peerlist_to_all_neighbors(domain_id)
        print("** wait 3 sec to finish alive_check")
        time.sleep(3)
        assert len(cores[1].networking.domains[domain_id].id_ip_mapping) == core_num-1
        for i in range(core_num):
            cores[i].networking.domains[domain_id].print_peerlist()

    def test_11_register(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for cl in clients:
            ret = cl['app'].register_to_core()
            assert ret
        time.sleep(1)
        print("---- wait 10 sec ----")
        time.sleep(10)

    def test_12_make_transaction(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for i, cl in enumerate(clients):
            print("---- start transaction ---")
            user = cl['user_id']
            transactions[i] = bbclib.make_transaction_for_base_asset(asset_group_id=asset_group_id, event_num=1)
            cl['app'].get_cross_refs(asset_group_id=asset_group_id, number=2)
            print("  ----> wait cross_ref")
            dat = msg_processor[i].synchronize()
            cross_ref_list[i].extend(dat)
            print("    ==> got cross_ref")
            if len(cross_ref_list[i]) > 0:
                transactions[i].add(cross_ref=cross_ref_list[i].pop(0))

            transactions[i].events[0].asset.add(user_id=user, asset_body="data=%d"%i)
            other_user = (i+1) % client_num
            transactions[i].events[0].add(mandatory_approver=clients[other_user]['user_id'])

            sig = transactions[i].sign(keypair=cl['keypair'])
            transactions[i].add_signature(user_id=cl['user_id'], signature=sig)

            transactions[i].digest()
            print("register transaction=", binascii.b2a_hex(transactions[i].transaction_id))
            ret = cl['app'].insert_transaction(transactions[i])
            assert ret
            print("  ----> wait insert")
            msg_processor[i].synchronize()
            print("    ==> got insert")

        for i in range(len(cores)):
            print("[%d] cross_ref_list=%d" % (i, len(cores[i].cross_ref_list)))

    def test_13_make_transaction(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for i, cl in enumerate(clients):
            user = cl['user_id']
            txobj = bbclib.make_transaction_for_base_asset(asset_group_id=asset_group_id, event_num=1)
            cl['app'].get_cross_refs(asset_group_id=asset_group_id, number=2)
            dat = msg_processor[i].synchronize()
            cross_ref_list[i].extend(dat)
            if len(cross_ref_list[i]) > 0:
                txobj.add(cross_ref=cross_ref_list[i].pop(0))

            txobj.events[0].asset.add(user_id=user, asset_body=b"data2=%d"%i)
            other_user = (i+1) % client_num
            txobj.events[0].add(reference_index=0, mandatory_approver=clients[other_user]['user_id'])

            reference = bbclib.add_reference_to_transaction(asset_group_id, txobj, transactions[i], 0)
            ret = cl['app'].gather_signatures(txobj, reference_obj=reference)
            assert ret
            dat = msg_processor[i].synchronize()
            assert dat[KeyType.status] == ESUCCESS
            result = dat[KeyType.result]
            txobj.references[result[0]].add_signature(user_id=result[1], signature=result[2])

            txobj.digest()
            ret = cl['app'].insert_transaction(txobj)
            assert ret
            msg_processor[i].synchronize()
            transactions[i] = txobj

        for i in range(len(cores)):
            print("[%d] cross_ref_list=%d" % (i, len(cores[i].cross_ref_list)))

    @pytest.mark.unregister
    def test_98_unregister(self):
        for cl in clients:
            ret = cl['app'].unregister_from_core()
            assert ret


if __name__ == '__main__':
    pytest.main()
