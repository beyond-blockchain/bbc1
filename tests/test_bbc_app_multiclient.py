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
        signature = txobj.sign(keypair=clients[self.idx]['keypair'])
        clients[self.idx]['app'].sendback_signature(dat[KeyType.source_user_id], signature)

    def proc_resp_insert(self, dat):
        if KeyType.transaction_id in dat:
            self.logger.debug("OK: transaction is inserted. %s" % binascii.b2a_hex(dat[KeyType.transaction_id]))
        else:
            self.logger.debug("NG.....")
        self.queue.put(dat)

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
        transactions[0] = bbclib.make_transaction_for_base_asset(asset_group_id=asset_group_id, event_num=2)
        transactions[0].events[0].asset.add(user_id=user, asset_body=b'123456')
        transactions[0].events[1].asset.add(user_id=user, asset_file=b'abcdefg')
        transactions[0].events[1].add(mandatory_approver=clients[1]['user_id'])

        for i, cl in enumerate(clients):
            ret = cl['app'].get_cross_refs(asset_group_id=asset_group_id, number=2)
            assert ret
            dat = msg_processor[i].synchronize()
            cross_ref_list[i].extend(dat)

    def test_04_insert(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        sig = transactions[0].sign(keypair=clients[0]['keypair'])
        assert sig is not None
        if sig is None:
            print(bbclib.error_text)
            import os
            os._exit(1)
        transactions[0].add_signature(user_id=clients[0]['user_id'], signature=sig)
        transactions[0].dump()
        transactions[0].digest()
        global transaction_dat
        transaction_dat = transactions[0].serialize()
        print("register transaction=", binascii.b2a_hex(transactions[0].transaction_id))
        ret = clients[0]['app'].insert_transaction(transactions[0])
        assert ret
        msg_processor[0].synchronize()

    def test_07_search_asset(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        ret = clients[0]['app'].search_asset(asset_group_id, transactions[0].events[0].asset.asset_id)
        assert ret
        dat = wait_check_result_msg_type(msg_processor[0], bbclib.ServiceMessageType.RESPONSE_SEARCH_ASSET)
        assert dat[KeyType.status] == ESUCCESS

    def test_08_search_asset(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        asid = bytearray(transactions[0].events[0].asset.asset_id)
        asid[1] = 0xff
        asid[2] = 0xff
        ret = clients[0]['app'].search_asset(asset_group_id, bytes(asid))  # NG is expected
        assert ret
        print("* should be NG *")
        dat = wait_check_result_msg_type(msg_processor[0], bbclib.ServiceMessageType.RESPONSE_SEARCH_ASSET)
        assert dat[KeyType.status] < ESUCCESS

    def test_09_search_asset(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        ret = clients[0]['app'].search_asset(asset_group_id, transactions[0].events[1].asset.asset_id)
        assert ret
        dat = wait_check_result_msg_type(msg_processor[0], bbclib.ServiceMessageType.RESPONSE_SEARCH_ASSET)
        assert dat[KeyType.status] == ESUCCESS

    def test_10_search_transaction(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        transactions[0] = bbclib.BBcTransaction()
        transactions[0].deserialize(transaction_dat)
        print("find txid=", binascii.b2a_hex(transactions[0].transaction_id))
        ret = clients[0]['app'].search_transaction(transactions[0].transaction_id)
        assert ret
        dat = wait_check_result_msg_type(msg_processor[0], bbclib.ServiceMessageType.RESPONSE_SEARCH_TRANSACTION)
        assert dat[KeyType.status] == ESUCCESS

    def test_11_search_transaction(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        ret = clients[0]['app'].search_transaction(b'4898g9fh')  # NG is expected
        assert ret
        print("* should be NG *")
        dat = wait_check_result_msg_type(msg_processor[0], bbclib.ServiceMessageType.RESPONSE_SEARCH_TRANSACTION)
        assert dat[KeyType.status] < ESUCCESS

    def test_20_messaging(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for i in range(1, client_num):
            msg = "message from %d" % i
            ret = clients[0]['app'].send_message(msg, clients[i]['user_id'])
            assert ret
        for i in range(1, client_num):
            print("recv=",msg_processor[i].synchronize()[KeyType.message])

    @pytest.mark.unregister
    def test_98_unregister(self):
        for cl in clients:
            ret = cl['app'].unregister_from_core()
            assert ret


if __name__ == '__main__':
    pytest.main()
