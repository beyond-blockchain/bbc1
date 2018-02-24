# -*- coding: utf-8 -*-
import pytest

import binascii
import time
import random

import sys
sys.path.extend(["../"])
from bbc1.common import bbclib
from bbc1.common.message_key_types import KeyType
from bbc1.common.bbc_error import *
from bbc1.app import bbc_app
from testutils import prepare, get_core_client, start_core_thread, make_client, domain_setup_utility


LOGLEVEL = 'debug'
#LOGLEVEL = 'info'


core_num = 5
client_num = 5
cores = None
clients = None
domain_id = bbclib.get_new_id("testdomain")
asset_group_id = bbclib.get_new_id("asset_group_1")
transactions = [None for i in range(client_num)]
cross_ref_list = []

msg_processor = [None for i in range(client_num)]

large_data = "aaaaaaaaaa" * 200


class MessageProcessor(bbc_app.Callback):
    def __init__(self, index=0):
        super(MessageProcessor, self).__init__(self)
        self.idx = index

    def proc_cmd_sign_request(self, dat):
        self.logger.info("[%d] Recv SIGN_REQUEST from %s" % (self.idx, binascii.b2a_hex(dat[KeyType.source_user_id])))
        if KeyType.transactions not in dat:
            self.logger.warn("message needs to include referred transactions")
            return
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

    def proc_resp_search_asset(self, dat):
        if KeyType.transaction_data in dat:
            self.logger.debug("OK: Asset [%s] is found." % binascii.b2a_hex(dat[KeyType.asset_id]))
            if KeyType.asset_file in dat:
                self.logger.debug(" [%s] in_storage --> %s" % (binascii.b2a_hex(dat[KeyType.asset_id][:4]),
                                                               dat[KeyType.asset_file]))
            tx_obj = bbclib.recover_transaction_object_from_rawdata(dat[KeyType.transaction_data])
            for evt in tx_obj.events:
                if evt.asset.asset_body_size > 0:
                    self.logger.debug(" [%s] asset_body --> %s" % (binascii.b2a_hex(evt.asset.asset_id[:4]),
                                                                   evt.asset.asset_body))
        else:
            self.logger.debug("NG.....")
            dat = None
        self.queue.put(dat)


class TestBBcAppClient(object):

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
            make_client(index=i, core_port_increment=i, callback=msg_processor[i], asset_group_id=asset_group_id)
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

        #cores[0].networking.domains[domain_id].alive_check()
        #print("** wait 16 sec to finish alive_check")
        #time.sleep(16)
        assert len(cores[1].networking.domains[domain_id].id_ip_mapping) == core_num-1
        for i in range(core_num):
            cores[i].networking.domains[domain_id].print_peerlist()

    def test_11_register(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for cl in clients:
            ret = cl['app'].register_to_core()
            assert ret
        time.sleep(1)

    def test_12_cross_ref(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for i, cl in enumerate(clients):
            ret = cl['app'].get_cross_refs(asset_group_id=asset_group_id, number=2)
            assert ret
            dat = msg_processor[i].synchronize()
            cross_ref_list.extend(dat)

    def test_13_insert_first_transaction(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        user = clients[0]['user_id']
        transactions[0] = bbclib.make_transaction_for_base_asset(asset_group_id=asset_group_id, event_num=2)
        transactions[0].events[0].asset.add(user_id=user, asset_body=b'123456')
        transactions[0].events[1].asset.add(user_id=user, asset_file=b'abcdefg')
        transactions[0].events[0].add(reference_index=0, mandatory_approver=user)
        if len(cross_ref_list) > 0:
            transactions[0].add(cross_ref=cross_ref_list.pop(0))

        sig = transactions[0].sign(keypair=clients[0]['keypair'])
        assert sig is not None
        if sig is None:
            print(bbclib.error_text)
            import os
            os._exit(1)
        transactions[0].add_signature(signature=sig)
        transactions[0].dump()
        transactions[0].digest()
        print("register transaction=", binascii.b2a_hex(transactions[0].transaction_id))
        ret = clients[0]['app'].insert_transaction(asset_group_id, transactions[0])
        assert ret
        msg_processor[0].synchronize()

    def test_13_gather_signature(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        prev_tx = transactions[0]
        user = clients[1]['user_id']
        transactions[1] = bbclib.make_transaction_for_base_asset(asset_group_id=asset_group_id, event_num=1)
        transactions[1].events[0].asset.add(user_id=user, asset_body=b'123456')
        if len(cross_ref_list) > 0:
            transactions[1].add(cross_ref=cross_ref_list.pop(0))

        reference = bbclib.add_reference_to_transaction(asset_group_id, transactions[1], prev_tx, 0)
        ret = clients[1]['app'].gather_signatures(asset_group_id, transactions[1], reference_obj=reference)
        assert ret
        dat = msg_processor[1].synchronize()
        assert dat[KeyType.status] == ESUCCESS
        result = dat[KeyType.result]
        transactions[1].references[result[0]].add_signature(user_id=result[1], signature=result[2])

        transactions[1].dump()
        transactions[1].digest()
        print("register transaction=", binascii.b2a_hex(transactions[1].transaction_id))
        ret = clients[1]['app'].insert_transaction(asset_group_id, transactions[1])
        assert ret
        msg_processor[1].synchronize()

    def test_17_search_asset(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        ret = clients[2]['app'].search_asset(asset_group_id, transactions[1].events[0].asset.asset_id)
        assert ret
        msg_processor[2].synchronize()

    def test_18_search_asset(self):
        print("-----", sys._getframe().f_code.co_name, "-----")
        asid = bytearray(transactions[1].events[0].asset.asset_id)
        asid[1] = 0xff
        asid[2] = 0xff
        ret = clients[3]['app'].search_asset(asset_group_id, bytes(asid))  # NG is expected
        assert ret
        print("* should be NG *")
        msg_processor[3].synchronize()

    def test_19_search_asset(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        ret = clients[0]['app'].search_asset(asset_group_id, transactions[0].events[1].asset.asset_id)
        assert ret
        msg_processor[0].synchronize()

    def test_20_search_transaction(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        print("find txid=", binascii.b2a_hex(transactions[0].transaction_id))
        ret = clients[4]['app'].search_transaction(asset_group_id, transactions[0].transaction_id)
        assert ret
        dat = msg_processor[4].synchronize()
        assert dat[KeyType.status] == 0

    def test_21_search_transaction(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        ret = clients[4]['app'].search_transaction(asset_group_id, b'4898g9fh')  # NG is expected
        assert ret
        print("* should be NG *")
        dat = msg_processor[4].synchronize()
        assert dat[KeyType.status] < 0

    def test_30_messaging(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for i in range(1, client_num):
            msg = "message to %d" % i
            ret = clients[0]['app'].send_message(msg, asset_group_id, clients[i]['user_id'])
            assert ret
        for i in range(1, client_num):
            print("recv=",msg_processor[i].synchronize()[KeyType.message])

    def test_31_messaging_tcp(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for i in range(1, client_num):
            msg = "message to %d: %s" % (i, large_data)
            ret = clients[0]['app'].send_message(msg, asset_group_id, clients[i]['user_id'])
            assert ret
        for i in range(1, client_num):
            print("recv=",msg_processor[i].synchronize()[KeyType.message])

    def test_32_messaging(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for i in range(client_num):
            k = random.randint(0, client_num-1)
            if k == i:
                continue
            msg = "message to %d" % i
            ret = clients[i]['app'].send_message(msg, asset_group_id, clients[k]['user_id'])
            print("recv=",msg_processor[k].synchronize()[KeyType.message])

    def test_33_messaging(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        msg = "message to X"
        ret = clients[0]['app'].send_message(msg, asset_group_id, bbclib.get_new_id("xxxxx"))
        print("recv=",msg_processor[0].synchronize())

    def test_97_get_stat(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for cl in clients:
            ret = cl['app'].get_stats()
            assert ret
        time.sleep(2)
        import pprint
        for i in range(1, client_num):
            pprint.pprint(msg_processor[i].synchronize()[KeyType.stats])

    def test_98_unregister(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for cl in clients:
            ret = cl['app'].unregister_from_core()
            assert ret

    def test_99_quit(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for core in cores:
            core.networking.save_all_peer_lists()
            ret = core.config.update_config()
            assert ret


if __name__ == '__main__':
    pytest.main()
