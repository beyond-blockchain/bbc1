# -*- coding: utf-8 -*-
import pytest

import binascii
import time

import sys
sys.path.extend(["../"])
from bbc1.core import bbclib
from bbc1.core import message_key_types, bbc_app
from bbc1.core.message_key_types import KeyType
from bbc1.core.bbc_error import *
from testutils import prepare, get_core_client, start_core_thread, make_client, domain_setup_utility, wait_check_result_msg_type

LOGLEVEL = 'debug'
LOGLEVEL = 'info'

core_num = 1
client_num = 1
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

    def proc_resp_search_asset(self, dat):
        if KeyType.transaction_data in dat:
            self.logger.info("OK: Asset [%s] is found." % binascii.b2a_hex(dat[KeyType.asset_id]))
            tx_obj, fmt_type = bbclib.deserialize(dat[KeyType.transaction_data])
            for evt in tx_obj.events:
                if evt.asset.asset_body_size > 0:
                    self.logger.info(" [%s] asset_body --> %s" % (binascii.b2a_hex(evt.asset.asset_id[:4]),
                                                                  evt.asset.asset_body))
        else:
            self.logger.info("NG.....")
        self.queue.put(dat)


class TestBBcAppClient(object):

    def test_00_setup(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")

        global msg_processor
        prepare(core_num=core_num, client_num=client_num, loglevel=LOGLEVEL)
        for i in range(core_num):
            start_core_thread(index=i)
            domain_setup_utility(i, domain_id)  # system administrator
            msg_processor[i] = MessageProcessor(index=i)
            make_client(index=i, core_port_increment=0, callback=msg_processor[i])
        time.sleep(1)

        global cores, clients
        cores, clients = get_core_client()
        for i in range(client_num):
            msg_processor[i].set_client(clients[i]['app'])

    def test_01_key_exchange(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for i in range(client_num):
            clients[i]['app'].exchange_key()
            dat = msg_processor[0].synchronize()
            assert dat
        assert len(message_key_types.encryptors) == client_num * 2

    def test_02_register(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for i in range(client_num):
            ret = clients[i]['app'].register_to_core()
            assert ret

        ret = clients[0]['app'].get_domain_neighborlist(domain_id=domain_id)
        assert ret
        dat = msg_processor[0].synchronize()
        print("nodeinfo=",dat)

    def test_02_make_transaction(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        user = clients[0]['user_id']
        global transactions
        transactions[0] = bbclib.make_transaction(event_num=2, witness=True)
        transactions[0].events[0].add(reference_index=0, mandatory_approver=user)
        bbclib.add_event_asset(transactions[0], event_idx=0, asset_group_id=asset_group_id,
                               user_id=user, asset_body=b'123456')
        bbclib.add_event_asset(transactions[0], event_idx=1, asset_group_id=asset_group_id,
                               user_id=user, asset_body=b'abcdefg')

        transactions[0].witness.add_witness(user)

    def test_03_insert(self):
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
        print("register transaction=", binascii.b2a_hex(transactions[0].transaction_id))
        clients[0]['app'].insert_transaction(transactions[0])
        dat = wait_check_result_msg_type(msg_processor[0], bbclib.MsgType.RESPONSE_INSERT)
        assert dat[KeyType.status] == ESUCCESS

    def test_07_search_asset0(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        asid = transactions[0].events[0].asset.asset_id
        print(" search for asset:%s"%binascii.b2a_hex(asid))
        clients[0]['app'].search_transaction_with_condition(asset_group_id=asset_group_id, asset_id=asid)
        dat = wait_check_result_msg_type(msg_processor[0], bbclib.MsgType.RESPONSE_SEARCH_WITH_CONDITIONS)
        assert dat[KeyType.status] == ESUCCESS
        print(dat)
        assert KeyType.transactions in dat

    @pytest.mark.unregister
    def test_99_unregister(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for i in range(client_num):
            clients[i]['app'].unregister_from_core()
        time.sleep(1)
        assert len(message_key_types.encryptors) == 0


if __name__ == '__main__':
    pytest.main()

