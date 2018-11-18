# -*- coding: utf-8 -*-
import pytest

import binascii
import time
import random

import os
import sys
sys.path.extend(["../", "../../"])
from bbc1.core.compat import bbclib
from bbc1.core.message_key_types import KeyType
from bbc1.core.bbc_error import *
from bbc1.core.compat import bbc_app
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
transaction_dat = None

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
                clients[self.idx]['app'].sendback_signature(dat[KeyType.source_user_id], txobj.transaction_id,
                                                            i, signature)
                return

    def proc_resp_search_asset(self, dat):
        if KeyType.transaction_data in dat:
            self.logger.debug("OK: Asset [%s] is found." % binascii.b2a_hex(dat[KeyType.asset_id]))
            tx_obj = bbclib.BBcTransaction(deserialize=dat[KeyType.transaction_data])
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
            print("Neighbor list -->", dat)
            assert len(dat) == core_num

    def test_13_insert_first_transaction(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        user = clients[0]['user_id']
        transactions[0] = bbclib.make_transaction(event_num=2, witness=True)
        transactions[0].events[0].add(reference_index=0, mandatory_approver=user)
        bbclib.add_event_asset(transactions[0], event_idx=0, asset_group_id=asset_group_id,
                               user_id=user, asset_body=b'123456')
        bbclib.add_event_asset(transactions[0], event_idx=1, asset_group_id=asset_group_id,
                               user_id=user, asset_body=b'abcdefg')

        transactions[0].witness.add_witness(user)
        sig = transactions[0].sign(keypair=clients[0]['keypair'])
        assert sig is not None
        if sig is None:
            print(bbclib.error_text)
            import os
            os._exit(1)
        transactions[0].add_signature(user_id=user, signature=sig)
        print(transactions[0])
        transactions[0].digest()
        global transaction_dat
        transaction_dat = transactions[0].serialize()
        print("register transaction=", binascii.b2a_hex(transactions[0].transaction_id))
        clients[0]['app'].insert_transaction(transactions[0])
        dat = msg_processor[0].synchronize()
        assert KeyType.transaction_id in dat
        assert dat[KeyType.transaction_id] == transactions[0].transaction_id
        time.sleep(2)

    def test_13_gather_signature(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        prev_tx = transactions[0]
        user = clients[1]['user_id']
        transactions[1] = bbclib.make_transaction(event_num=1)
        bbclib.add_event_asset(transactions[1], event_idx=0, asset_group_id=asset_group_id,
                               user_id=user, asset_body=b'123456')

        reference = bbclib.add_reference_to_transaction(transactions[1], asset_group_id, prev_tx, 0)
        clients[1]['app'].gather_signatures(transactions[1], reference_obj=reference)
        dat = msg_processor[1].synchronize()
        assert dat[KeyType.status] == ESUCCESS
        result = dat[KeyType.result]
        transactions[1].references[result[0]].add_signature(user_id=result[1], signature=result[2])

        print(transactions[1])
        transactions[1].digest()
        print("register transaction=", binascii.b2a_hex(transactions[1].transaction_id))
        clients[1]['app'].insert_transaction(transactions[1])
        dat = msg_processor[1].synchronize()
        assert KeyType.transaction_id in dat
        assert dat[KeyType.transaction_id] == transactions[1].transaction_id

    def test_17_search_asset(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        clients[2]['app'].search_transaction_with_condition(asset_group_id=asset_group_id,
                                                            asset_id=transactions[1].events[0].asset.asset_id)
        dat = msg_processor[2].synchronize()
        assert dat[KeyType.status] == 0
        assert KeyType.transactions in dat
        txobj = bbclib.BBcTransaction(deserialize=dat[KeyType.transactions][0])
        assert txobj.transaction_id == transactions[1].transaction_id

    def test_18_search_asset(self):
        print("-----", sys._getframe().f_code.co_name, "-----")
        asid = bytearray(transactions[1].events[0].asset.asset_id)
        asid[1] = 0xff
        asid[2] = 0xff
        clients[3]['app'].search_transaction_with_condition(asset_group_id=asset_group_id, asset_id=bytes(asid))
        print("* should be NG (no transaction is found) *")
        dat = msg_processor[3].synchronize()
        assert KeyType.transactions not in dat
        assert KeyType.all_asset_files not in dat

    def test_19_search_asset(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        clients[0]['app'].search_transaction_with_condition(asset_group_id=asset_group_id,
                                                            asset_id=transactions[0].events[1].asset.asset_id)
        dat = msg_processor[0].synchronize()
        assert KeyType.transactions in dat
        txobj = bbclib.BBcTransaction(deserialize=dat[KeyType.transactions][0])
        assert txobj.transaction_id == transactions[0].transaction_id

    def test_20_search_transaction(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        transactions[0] = bbclib.BBcTransaction()
        transactions[0].deserialize(transaction_dat)
        print("find txid=", binascii.b2a_hex(transactions[0].transaction_id))
        clients[4]['app'].search_transaction(transactions[0].transaction_id)
        dat = msg_processor[4].synchronize()
        assert dat[KeyType.status] == 0
        assert KeyType.transaction_id in dat
        assert dat[KeyType.transaction_id] == transactions[0].transaction_id

    def test_21_search_transaction(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        clients[4]['app'].search_transaction(b'4898g9fh')  # NG is expected
        print("* should be NG *")
        dat = msg_processor[4].synchronize()
        assert dat[KeyType.status] < 0

    def test_30_messaging(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for i in range(1, client_num):
            msg = "message to %d" % i
            ret = clients[0]['app'].send_message(msg, clients[i]['user_id'])
            assert ret
        for i in range(1, client_num):
            dat = msg_processor[i].synchronize()
            assert KeyType.message in dat
            print("recv=", dat)

    def test_31_messaging_tcp(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for i in range(1, client_num):
            msg = "message to %d: %s" % (i, large_data)
            ret = clients[0]['app'].send_message(msg, clients[i]['user_id'])
            assert ret
        for i in range(1, client_num):
            print("sync:", i)
            dat = msg_processor[i].synchronize()
            assert KeyType.message in dat
            assert len(dat[KeyType.message]) == len(msg)
            print("recv=", dat)

    def test_32_messaging(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for i in range(client_num):
            k = random.randint(0, client_num-1)
            if k == i:
                continue
            msg = "message to %d" % i
            clients[i]['app'].send_message(msg, clients[k]['user_id'])
            dat = msg_processor[k].synchronize()
            assert KeyType.message in dat
            assert KeyType.reason not in dat
            print("recv=", dat)

    def test_33_messaging(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        msg = "message to X"
        clients[0]['app'].send_message(msg, bbclib.get_new_id("xxxxx"))
        dat = msg_processor[0].synchronize()
        assert KeyType.message in dat
        assert dat[KeyType.reason] == b'Cannot find such user'
        print("recv=", dat)

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
            core.networking.save_all_static_node_list()
            ret = core.config.update_config()
            assert ret


if __name__ == '__main__':
    pytest.main()
