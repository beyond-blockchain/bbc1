# -*- coding: utf-8 -*-
import pytest

import binascii
import time

import sys
sys.path.extend(["../"])
from bbc1.app import bbc_app
from bbc1.core.bbc_types import ResourceType
from bbc1.common import bbclib
from bbc1.common.message_key_types import KeyType
from bbc1.common.bbc_error import *
from testutils import prepare, get_core_client, start_core_thread, make_client, domain_setup_utility, wait_check_result_msg_type


LOGLEVEL = 'debug'
LOGLEVEL = 'info'


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
        print("-----", sys._getframe().f_code.co_name, "-----")
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
        print("-----", sys._getframe().f_code.co_name, "-----")
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

        time.sleep(3)
        for i in range(core_num):
            cores[i].networking.domains[domain_id].print_peerlist()
            cores[i].storage_manager.set_storage_path(domain_id)

    def test_11_register(self):
        print("-----", sys._getframe().f_code.co_name, "-----")
        for cl in clients:
            ret = cl['app'].register_to_core()
            assert ret
        time.sleep(1)
        print("---- wait 10 sec ----")
        time.sleep(10)

    def test_12_make_transaction(self):
        print("-----", sys._getframe().f_code.co_name, "-----")
        user = clients[0]['user_id']
        transactions[0] = bbclib.make_transaction_for_base_asset(asset_group_id=asset_group_id, event_num=1)
        transactions[0].events[0].asset.add(user_id=user, asset_file=b"data=1")
        sig = transactions[0].sign(keypair=clients[0]['keypair'])
        transactions[0].add_signature(user_id=clients[0]['user_id'], signature=sig)
        ret = clients[0]['app'].insert_transaction(asset_group_id, transactions[0])
        assert ret
        msg_processor[0].synchronize()
        print("txid:", binascii.b2a_hex(transactions[0].digest()))

    def test_13_search_transaction(self):
        print("-----", sys._getframe().f_code.co_name, "-----")
        ret = clients[4]['app'].search_transaction(asset_group_id, transactions[0].digest())
        assert ret
        dat = wait_check_result_msg_type(msg_processor[4], bbclib.ServiceMessageType.RESPONSE_SEARCH_TRANSACTION)
        assert dat[KeyType.status] == ESUCCESS

    def test_14_remove_transaction(self):
        print("-----", sys._getframe().f_code.co_name, "-----")
        cores[1].ledger_manager.remove(domain_id, asset_group_id, transactions[0].digest())

        ret = cores[1].ledger_manager.find_locally(domain_id, asset_group_id,
                                                   transactions[0].digest(), ResourceType.Transaction_data)
        assert ret is None

    def test_15_search_transaction(self):
        ret = clients[1]['app'].search_transaction(asset_group_id, transactions[0].digest())
        assert ret
        dat = msg_processor[1].synchronize()
        assert dat[KeyType.status] == 0
        print("transaction:", binascii.b2a_hex(dat[KeyType.transaction_data]))
        tx_obj = bbclib.recover_transaction_object_from_rawdata(dat[KeyType.transaction_data])
        print("txid:", binascii.b2a_hex(tx_obj.digest()))
        print("--- find_locally again ---")
        ret = cores[1].ledger_manager.find_locally(domain_id, asset_group_id,
                                                   transactions[0].digest(), ResourceType.Transaction_data)
        assert ret is not None

    def test_16_forge_transaction(self):
        print("-----", sys._getframe().f_code.co_name, "-----")
        cores[2].ledger_manager.remove(domain_id, asset_group_id, transactions[0].digest())

        transactions[1] = bbclib.make_transaction_for_base_asset(asset_group_id=asset_group_id)
        transactions[1].events[0].asset.add(user_id=clients[1]['user_id'], asset_file=b"data=2")
        sig = transactions[0].sign(keypair=clients[0]['keypair'])
        transactions[1].add_signature(user_id=clients[0]['user_id'], signature=sig)
        txdata = transactions[1].serialize()
        cores[2].ledger_manager.insert_locally(domain_id, asset_group_id, transactions[0].digest(),
                                               ResourceType.Transaction_data, txdata)
        ret = cores[2].ledger_manager.find_locally(domain_id, asset_group_id,
                                                   transactions[0].digest(), ResourceType.Transaction_data)
        print("forged_transaction:", binascii.b2a_hex(ret))
        print("forged_txid:", binascii.b2a_hex(transactions[1].digest()))

    def test_17_search_transaction(self):
        print("-----", sys._getframe().f_code.co_name, "-----")
        ret = clients[2]['app'].search_transaction(asset_group_id, transactions[0].digest())
        assert ret
        dat = wait_check_result_msg_type(msg_processor[2], bbclib.ServiceMessageType.RESPONSE_SEARCH_TRANSACTION)
        assert dat[KeyType.status] == ESUCCESS
        print("transaction:", binascii.b2a_hex(dat[KeyType.transaction_data]))
        tx_obj = bbclib.recover_transaction_object_from_rawdata(dat[KeyType.transaction_data])
        print("txid:", binascii.b2a_hex(tx_obj.digest()))

    def test_20_search_asset(self):
        print("-----", sys._getframe().f_code.co_name, "-----")
        asset_id = transactions[0].events[0].asset.asset_id
        ret = clients[3]['app'].search_asset(asset_group_id, asset_id)
        assert ret
        dat = wait_check_result_msg_type(msg_processor[3], bbclib.ServiceMessageType.RESPONSE_SEARCH_ASSET)
        assert dat[KeyType.status] == ESUCCESS
        print(dat[KeyType.asset_file])

    def test_21_remove_asset(self):
        print("-----", sys._getframe().f_code.co_name, "-----")
        asset_id = transactions[0].events[0].asset.asset_id
        cores[3].storage_manager.remove(domain_id, asset_group_id, asset_id)

        ret = cores[3].storage_manager.get_locally(domain_id, asset_group_id, asset_id)
        assert ret is None

    def test_22_search_asset(self):
        print("-----", sys._getframe().f_code.co_name, "-----")
        asset_id = transactions[0].events[0].asset.asset_id
        ret = clients[3]['app'].search_asset(asset_group_id, asset_id)
        assert ret
        dat = wait_check_result_msg_type(msg_processor[3], bbclib.ServiceMessageType.RESPONSE_SEARCH_ASSET)
        assert dat[KeyType.status] == ESUCCESS
        print(dat[KeyType.asset_file])

        ret = cores[3].storage_manager.get_locally(domain_id, asset_group_id, asset_id)
        assert ret is not None
        print(ret)

    def test_23_forge_asset(self):
        print("-----", sys._getframe().f_code.co_name, "-----")
        asset_id = transactions[0].events[0].asset.asset_id
        asset_id_str = binascii.b2a_hex(asset_id).decode()
        filepath = cores[3].storage_manager.storage_path[domain_id][asset_group_id]+"/%s" % asset_id_str
        with open(filepath, "a") as f:
            f.write("asldkfjsadkfj;asdlkfj;l")

        ret = cores[3].storage_manager.get_locally(domain_id, asset_group_id, asset_id)
        assert ret is not None
        print(ret)

    def test_24_search_asset(self):
        print("-----", sys._getframe().f_code.co_name, "-----")
        asset_id = transactions[0].events[0].asset.asset_id
        ret = clients[3]['app'].search_asset(asset_group_id, asset_id)
        assert ret
        dat = wait_check_result_msg_type(msg_processor[3], bbclib.ServiceMessageType.RESPONSE_SEARCH_ASSET)
        assert dat[KeyType.status] == ESUCCESS
        print(dat[KeyType.asset_file])

        ret = cores[3].storage_manager.get_locally(domain_id, asset_group_id, asset_id)
        assert ret is not None
        print(ret)

    def test_30_forge_transaction_and_asset(self):
        print("-----", sys._getframe().f_code.co_name, "-----")

        ret = cores[4].ledger_manager.find_locally(domain_id, asset_group_id,
                                                   transactions[0].digest(), ResourceType.Transaction_data)
        print("forged_transaction:", binascii.b2a_hex(ret))
        print("forged_txid:", binascii.b2a_hex(transactions[1].digest()))

        asset_id = transactions[0].events[0].asset.asset_id

        asset_id_str = binascii.b2a_hex(asset_id).decode()
        cores[4].storage_manager.create_new_directory(domain_id, asset_group_id)
        filepath = cores[4].storage_manager.storage_path[domain_id][asset_group_id]+"/%s" % asset_id_str
        with open(filepath, "a") as f:
            f.write("asldkfjsadkfj;asdlkfj;l")

        ret = cores[4].storage_manager.get_locally(domain_id, asset_group_id, asset_id)
        assert ret is not None
        print(ret)

    def test_31_search_asset(self):
        print("-----", sys._getframe().f_code.co_name, "-----")
        asset_id = transactions[0].events[0].asset.asset_id
        ret = clients[3]['app'].search_asset(asset_group_id, asset_id)
        assert ret
        dat = wait_check_result_msg_type(msg_processor[3], bbclib.ServiceMessageType.RESPONSE_SEARCH_ASSET)
        assert dat[KeyType.status] == ESUCCESS
        print(dat[KeyType.asset_file])
        print("transaction:", binascii.b2a_hex(dat[KeyType.transaction_data]))
        tx_obj = bbclib.recover_transaction_object_from_rawdata(dat[KeyType.transaction_data])
        print("txid:", binascii.b2a_hex(tx_obj.digest()))

        ret = cores[3].storage_manager.get_locally(domain_id, asset_group_id, asset_id)
        assert ret is not None
        print(ret)

    @pytest.mark.unregister
    def test_98_unregister(self):
        for cl in clients:
            ret = cl['app'].unregister_from_core()
            assert ret


if __name__ == '__main__':
    pytest.main()
