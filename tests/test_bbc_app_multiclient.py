# -*- coding: utf-8 -*-
import pytest

import binascii
import time

import sys
sys.path.extend(["../"])
from bbc1.core import bbclib
from bbc1.core.message_key_types import KeyType
from bbc1.core.bbc_error import *
from bbc1.core import bbc_app
from testutils import prepare, get_core_client, start_core_thread, make_client, domain_setup_utility, wait_check_result_msg_type


LOGLEVEL = 'debug'
LOGLEVEL = 'info'

core_num = 1
client_num = 5
cores = None
clients = None
domain_id = bbclib.get_new_id("testdomain")
asset_group_id = bbclib.get_new_id("asset_group_1")
transactions = [None for i in range(client_num)]
transaction_dat = None

msg_processor = [None for i in range(client_num)]


class MessageProcessor(bbc_app.Callback):
    def __init__(self, index=0):
        super(MessageProcessor, self).__init__(self)
        self.idx = index

    def proc_cmd_sign_request(self, dat):
        self.logger.debug("[%i] Recv SIGN_REQUEST from %s" % (self.idx, binascii.b2a_hex(dat[KeyType.source_user_id])))
        txobj = bbclib.BBcTransaction()
        txobj.deserialize(dat[KeyType.transaction_data])
        signature = txobj.sign(keypair=clients[self.idx]['keypair'])
        clients[self.idx]['app'].sendback_signature(dat[KeyType.source_user_id], txobj.transaction_id, signature)

    def proc_resp_insert(self, dat):
        if KeyType.transaction_id in dat:
            self.logger.debug("OK: transaction is inserted. %s" % binascii.b2a_hex(dat[KeyType.transaction_id]))
        else:
            self.logger.debug("NG.....")
        self.queue.put(dat)

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
        self.queue.put(dat)


class TestBBcAppClient(object):

    def test_00_setup(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")

        global msg_processor
        prepare(core_num=core_num, client_num=client_num, loglevel=LOGLEVEL)
        for i in range(core_num):
            start_core_thread(index=i, core_port_increment=i, p2p_port_increment=i)
            domain_setup_utility(i, domain_id)  # system administrator
        time.sleep(1)
        for i in range(client_num):
            msg_processor[i] = MessageProcessor(index=i)
            make_client(index=i, core_port_increment=0, callback=msg_processor[i])
        time.sleep(1)

        global cores, clients
        cores, clients = get_core_client()

    def test_01_register(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for cl in clients:
            ret = cl['app'].register_to_core()
            assert ret
        time.sleep(1)

    def test_02_make_transaction(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        user = clients[0]['user_id']
        transactions[0] = bbclib.make_transaction(event_num=2, witness=True)
        transactions[0].events[0].add(mandatory_approver=clients[1]['user_id'])
        bbclib.add_event_asset(transactions[0], event_idx=0, asset_group_id=asset_group_id,
                               user_id=user, asset_body=b'123456')
        bbclib.add_event_asset(transactions[0], event_idx=1, asset_group_id=asset_group_id,
                               user_id=user, asset_body=b'abcdefg')
        transactions[0].witness.add_witness(user_id=user)

    def test_04_insert(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        sig = transactions[0].sign(keypair=clients[0]['keypair'])
        assert sig is not None
        if sig is None:
            print(bbclib.error_text)
            import os
            os._exit(1)
        transactions[0].witness.add_signature(user_id=clients[0]['user_id'], signature=sig)
        print(transactions[0])
        transactions[0].digest()
        global transaction_dat
        transaction_dat = transactions[0].serialize()
        print("register transaction=", binascii.b2a_hex(transactions[0].transaction_id))
        clients[0]['app'].insert_transaction(transactions[0])
        dat = msg_processor[0].synchronize()
        assert KeyType.transaction_id in dat
        assert dat[KeyType.transaction_id] == transactions[0].transaction_id

    def test_07_search_asset_event0(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        clients[0]['app'].search_transaction_with_condition(asset_group_id=asset_group_id,
                                                            asset_id=transactions[0].events[0].asset.asset_id,
                                                            direction=1)
        dat = msg_processor[0].synchronize()
        assert dat[KeyType.status] == 0
        assert KeyType.transactions in dat
        txobj = bbclib.BBcTransaction(deserialize=dat[KeyType.transactions][0])
        assert txobj.transaction_id == transactions[0].transaction_id

    def test_08_search_asset_failure(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        asid = bytearray(transactions[0].events[0].asset.asset_id)
        asid[1] = 0xff
        asid[2] = 0xff
        clients[0]['app'].search_transaction_with_condition(asset_group_id=asset_group_id, asset_id=bytes(asid))
        print("* should be NG *")
        dat = msg_processor[0].synchronize()
        assert dat[KeyType.status] < ESUCCESS

    def test_09_search_asset_event1(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        clients[3]['app'].search_transaction_with_condition(asset_group_id=asset_group_id,
                                                            asset_id=transactions[0].events[1].asset.asset_id)
        dat = msg_processor[3].synchronize()
        assert dat[KeyType.status] == 0
        assert KeyType.transactions in dat
        txobj = bbclib.BBcTransaction(deserialize=dat[KeyType.transactions][0])
        assert txobj.transaction_id == transactions[0].transaction_id

    def test_10_search_transaction(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        transactions[0] = bbclib.BBcTransaction()
        transactions[0].deserialize(transaction_dat)
        print("find txid=", binascii.b2a_hex(transactions[0].transaction_id))
        clients[1]['app'].search_transaction(transactions[0].transaction_id)
        dat = msg_processor[1].synchronize()
        assert dat[KeyType.status] == 0
        assert KeyType.transaction_data in dat
        txobj = bbclib.BBcTransaction(deserialize=dat[KeyType.transaction_data])
        assert txobj.transaction_id == transactions[0].transaction_id

    def test_11_search_transaction(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        clients[0]['app'].search_transaction(b'4898g9fh')  # NG is expected
        print("* should be NG *")
        dat = wait_check_result_msg_type(msg_processor[0], bbclib.MsgType.RESPONSE_SEARCH_TRANSACTION)
        assert dat[KeyType.status] < ESUCCESS

    def test_20_messaging(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for i in range(1, client_num):
            msg = "message from %d" % i
            clients[0]['app'].send_message(msg, clients[i]['user_id'])
        for i in range(1, client_num):
            print("recv=",msg_processor[i].synchronize()[KeyType.message])

    @pytest.mark.unregister
    def test_98_unregister(self):
        for cl in clients:
            ret = cl['app'].unregister_from_core()
            assert ret


if __name__ == '__main__':
    pytest.main()
