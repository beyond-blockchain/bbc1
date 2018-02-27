# -*- coding: utf-8 -*-
import pytest

import binascii
import queue
import time

import sys
sys.path.extend(["../"])
from bbc1.core.bbc_types import ResourceType
from bbc1.common import bbclib
from bbc1.common.message_key_types import KeyType
from testutils import prepare, start_core_thread, get_core_client, make_client

LOGLEVEL = 'debug'
LOGLEVEL = 'info'

core_num = 3
client_num = 3
cores = None
clients = None
domain_id = bbclib.get_new_id("testdomain")
asset_group_id = bbclib.get_new_id("asset_group_1")
cross_refs = []
transaction = None
txid = None

result_queue = queue.Queue()


def make_user(index):
    global users
    keypair = bbclib.KeyPair()
    keypair.generate()
    user_info = {
        'user_id': bbclib.get_new_id("user_%i" % index),
        'keypair': keypair,
    }
    users.append(user_info)


def wait_results(count):
    total = 0
    for i in range(count):
        total += result_queue.get()
    return total


def dummy_send_message(data):
    print("[Core] recv=%s" % data)
    if KeyType.reason in data:
        result_queue.put(0)
    else:
        result_queue.put(1)


class TestBBcCore(object):

    def test_01_setup(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")

        prepare(core_num=core_num, client_num=client_num, loglevel=LOGLEVEL)
        for i in range(core_num):
            start_core_thread(index=i, core_port_increment=i, p2p_port_increment=i)
        time.sleep(1)
        for i in range(client_num):
            make_client(index=i, core_port_increment=0, connect_to_core=False)

        global cores, clients
        cores, clients = get_core_client()
        for i in range(core_num):
            cores[i].networking.create_domain(network_module="simple_cluster", domain_id=domain_id)
            cores[i].ledger_manager.add_domain(domain_id)
            cores[i].send_message = dummy_send_message
            cores[i].storage_manager.set_storage_path(domain_id)

    def test_02_get_cross_ref(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for idx, core in enumerate(cores):
            ret = core.pop_cross_refs(2)
            for cross in ret:
                print("[%i] %s" % (idx, ret))
                c = bbclib.BBcCrossRef(domain_id=cross[0], transaction_id=cross[1])
                cross_refs.append(c)

    def test_03_transaction_insert(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        global transaction
        user1 = clients[1]['user_id']
        transaction = bbclib.make_transaction_for_base_asset(asset_group_id=asset_group_id, event_num=2)
        if len(cross_refs) > 0:
            transaction.add(cross_ref=cross_refs.pop(0))
        transaction.events[0].asset.add(user_id=user1, asset_body=b'123456')
        transaction.events[1].asset.add(user_id=user1, asset_file=b'abcdefg')
        transaction.get_sig_index(user1)

        sig = transaction.sign(keypair=clients[1]['keypair'])
        transaction.add_signature(user_id=user1, signature=sig)
        transaction.digest()
        transaction.dump()
        print("register transaction=", binascii.b2a_hex(transaction.transaction_id))
        asset_file = dict()
        asset_file[transaction.events[1].asset.asset_id] = transaction.events[1].asset.asset_file
        ret = cores[1].insert_transaction(domain_id, transaction.serialize(), asset_file)
        print(ret)
        for i in range(len(cores)):
            print("[%d] cross_ref_list=%d" % (i, len(cores[i].cross_ref_list)))

    def test_04_1_search_transaction_by_txid_locally(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        print(transaction.transaction_id.hex())
        ret = cores[1].search_transaction_by_txid(domain_id, transaction.transaction_id,
                                                  clients[1]['user_id'], b'aaaa')
        print(ret)
        assert ret is not None

    def test_04_2_search_asset_by_asid_locally(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        asid = transaction.events[0].asset.asset_id
        ret = cores[1].search_asset_by_asid(domain_id, asset_group_id, asid, clients[1]['user_id'], b'aaaa')
        print(ret)
        assert ret is not None

    def test_04_3_search_asset_by_asid_locally_in_storage(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        asid = transaction.events[1].asset.asset_id
        ret = cores[1].search_asset_by_asid(domain_id, asset_group_id, asid, clients[1]['user_id'], b'aaaa')
        print(ret)
        assert ret is not None

    def test_05_1_search_transaction_by_txid_other_node_not_found(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")

        # -- insert transaction only at core_node_2
        global transaction
        user1 = clients[2]['user_id']
        transaction = bbclib.make_transaction_for_base_asset(asset_group_id=asset_group_id, event_num=2)
        if len(cross_refs) > 0:
            transaction.add(cross_ref=cross_refs.pop(0))
        transaction.events[0].asset.add(user_id=user1, asset_body=b'aaddbbdd')
        transaction.events[1].asset.add(user_id=user1, asset_file=b'112423')

        for i, user in enumerate(clients):
            sig = transaction.sign(keypair=clients[i]['keypair'])
            transaction.add_signature(user_id=clients[i]['user_id'], signature=sig)
        transaction.digest()
        print("register transaction=", binascii.b2a_hex(transaction.transaction_id))
        transaction.dump()
        asset_file = dict()
        asset_file[transaction.events[1].asset.asset_id] = transaction.events[1].asset.asset_file
        cores[2].ledger_manager.insert_transaction_locally(domain_id, transaction.transaction_id,
                                                           transaction.serialize())
        asid1 = transaction.events[0].asset.asset_id
        cores[2].ledger_manager.insert_asset_info_locally(domain_id, transaction.transaction_id,
                                                          asset_group_id, asid1, clients[2]['user_id'])

        # -- search the transaction at core_node_0
        ret = cores[0].search_transaction_by_txid(domain_id, transaction.transaction_id,
                                                  clients[2]['user_id'], b'bbbb')
        print(ret)
        assert ret is None
        print("wait queue: 1")
        total = wait_results(1)
        assert total == 0

    def test_05_2_search_asset_by_asid_other_node_not_found(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        # -- search the asset at core_node_0
        asid = transaction.events[0].asset.asset_id
        ret = cores[0].search_asset_by_asid(domain_id, asset_group_id, asid, clients[1]['user_id'], b'aaaa')
        assert ret is None
        print("wait queue: 1")
        total = wait_results(1)
        assert total == 0

    def test_05_3_search_asset_by_asid_in_storage_other_node_not_found(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        # -- search the asset at core_node_0
        asid = transaction.events[1].asset.asset_id
        ret = cores[0].search_asset_by_asid(domain_id, asset_group_id, asid, clients[1]['user_id'], b'aaaa')
        assert ret is None
        print("wait queue: 1")
        total = wait_results(1)
        assert total == 0

    def test_06_make_peerlist(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        node_id = cores[0].networking.domains[domain_id].node_id
        for i in range(1, core_num):
            cores[i].networking.domains[domain_id].add_peer_node(node_id=node_id, ip4=True,
                                                                 addr_info=(cores[0].networking.ip_address,
                                                                            cores[0].networking.port))
            cores[i].networking.domains[domain_id].send_ping(node_id, None)
        time.sleep(1)
        cores[0].networking.domains[domain_id].alive_check()
        print("*** wait for 16 sec for topology construction ***")
        time.sleep(16)
        for i in range(core_num):
            cores[i].networking.domains[domain_id].print_peerlist()

    def test_07_1_search_transaction_by_txid_other_node(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        # -- search the transaction at core_node_0
        ret = cores[0].search_transaction_by_txid(domain_id, transaction.transaction_id,
                                                  clients[0]['user_id'], b'cccc')
        assert ret is None
        print("wait queue: 1")
        total = wait_results(1)
        assert total == 1

    def test_07_2_search_asset_by_asid_other_node(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        # -- search the asset at core_node_0
        asid = transaction.events[0].asset.asset_id
        ret = cores[0].search_asset_by_asid(domain_id, asset_group_id, asid, clients[0]['user_id'], b'dddd')
        assert ret is None
        print("wait queue: 1")
        total = wait_results(1)
        assert total == 1

    def test_07_3_search_asset_by_asid_other_node_not_found(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        # -- search the asset at core_node_0
        asid = transaction.events[1].asset.asset_id
        ret = cores[0].search_asset_by_asid(domain_id, asset_group_id, asid, clients[0]['user_id'], b'dddd')
        assert ret is None
        print("wait queue: 1")
        total = wait_results(1)
        assert total == 0

    def test_07_4_search_asset_by_asid_in_storage_other_node_not_found(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        # -- search the asset at core_node_0
        asid = transaction.events[1].asset.asset_id
        ret = cores[0].search_asset_by_asid(domain_id, asset_group_id, asid, clients[0]['user_id'], b'eeee')
        assert ret is None
        print("wait queue: 1")
        total = wait_results(1)
        assert total == 0

    def test_08_store_asset_2(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        # -- store asset file at core_node_2
        asid2 = transaction.events[1].asset.asset_id
        cores[2].ledger_manager.insert_asset_info_locally(domain_id, transaction.transaction_id,
                                                          asset_group_id, asid2, clients[2]['user_id'])
        cores[2].storage_manager.store_locally(domain_id, asset_group_id, asid2,
                                               transaction.events[1].asset.asset_file)

    def test_09_1_search_asset_by_asid_other_node_not_found(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        # -- search the asset at core_node_0
        asid = transaction.events[1].asset.asset_id
        ret = cores[0].search_asset_by_asid(domain_id, asset_group_id, asid, clients[0]['user_id'], b'dddd')
        assert ret is None
        print("wait queue: 1")
        total = wait_results(1)
        assert total == 1

    def test_09_2_search_asset_by_asid_in_storage_other_node_not_found(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        # -- search the asset at core_node_0
        asid = transaction.events[1].asset.asset_id
        ret = cores[0].search_asset_by_asid(domain_id, asset_group_id, asid, clients[0]['user_id'], b'eeee')
        assert ret is None
        print("wait queue: 1")
        total = wait_results(1)
        assert total == 1

    def test_10_get_cross_ref(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for idx, core in enumerate(cores):
            ret = core.pop_cross_refs(2)
            for cross in ret:
                print("[%i] %s" % (idx, ret))
                c = bbclib.BBcCrossRef(domain_id=cross[0], transaction_id=cross[1])
                cross_refs.append(c)

    def test_11_transaction_insert(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        global transaction
        user1 = clients[1]['user_id']
        transaction = bbclib.make_transaction_for_base_asset(asset_group_id=asset_group_id, event_num=2)
        if len(cross_refs) > 0:
            transaction.add(cross_ref=cross_refs.pop(0))
        transaction.events[0].asset.add(user_id=user1, asset_body=b'123456')
        transaction.events[1].asset.add(user_id=user1, asset_file=b'abcdefgh')

        for i, user in enumerate(clients):
            sig = transaction.sign(keypair=clients[i]['keypair'])
            transaction.add_signature(user_id=clients[i]['user_id'], signature=sig)
        transaction.digest()
        print("register transaction=", binascii.b2a_hex(transaction.transaction_id))
        transaction.dump()
        asset_file = dict()
        asset_file[transaction.events[1].asset.asset_id] = transaction.events[1].asset.asset_file
        ret = cores[1].insert_transaction(domain_id, transaction.serialize(), asset_file)
        print(ret)
        for i in range(len(cores)):
            print("[%d] cross_ref_list=%d" % (i, len(cores[i].cross_ref_list)))

    def test_12_transaction_search_by_userid_locally(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        ret = cores[1].search_transaction_by_userid_locally(domain_id, asset_group_id, clients[1]['user_id'],
                                                            clients[1]['user_id'], b'aaaa')
        transaction_data = ret[KeyType.transaction_data]
        txobj = bbclib.BBcTransaction()
        txobj.deserialize(transaction_data)
        txobj.dump()
        assert txobj.transaction_id == transaction.transaction_id
        print("expected: %s" % binascii.b2a_hex(transaction.transaction_id))
        print("obtained: %s" % binascii.b2a_hex(txobj.transaction_id))


if __name__ == '__main__':
    pytest.main()
