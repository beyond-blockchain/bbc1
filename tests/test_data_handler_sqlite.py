# -*- coding: utf-8 -*-
import pytest

import pprint
import sys
sys.path.extend(["../"])
from bbc1.core import bbclib
from bbc1.core import bbc_stats
from bbc1.core.data_handler import DataHandler

user_id1 = bbclib.get_new_id("destination_id_test1")
user_id2 = bbclib.get_new_id("destination_id_test2")
domain_id = bbclib.get_new_id("test_domain")
asset_group_id1 = bbclib.get_new_id("asset_group_1")
asset_group_id2 = bbclib.get_new_id("asset_group_2")
txid1 = bbclib.get_new_id("dummy_txid_1")
txid2 = bbclib.get_new_id("dummy_txid_2")
keypair1 = bbclib.KeyPair()
keypair1.generate()

transactions = list()

data_handler =None
config = {
    "domains": {
        bbclib.convert_id_to_string(domain_id): {
            "storage": {
                "type": "internal",
            },
            "db": {
                "db_type": "sqlite",
                "db_name": "testdb",
                'replication_strategy': "all",
            },
        }
    }
}


class DummyCore:
    class BBcNetwork:
        def __init__(self, core):
            self.core = core
            self.domain0manager = None

    def __init__(self):
        self.networking = DummyCore.BBcNetwork(self)
        self.stats = bbc_stats.BBcStats()


class TestDataHandler(object):

    def test_01_setup(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        global data_handler
        dummycore = DummyCore()
        conf = config["domains"][bbclib.convert_id_to_string(domain_id)]
        data_handler = DataHandler(networking=dummycore.networking, config=conf, workingdir="testdir", domain_id=domain_id)

        global transactions
        for i in range(10):
            txobj = bbclib.BBcTransaction()
            evt = bbclib.BBcEvent()
            evt.asset_group_id = asset_group_id1
            evt.asset = bbclib.BBcAsset()
            evt.asset.add(user_id=user_id1, asset_body=b'aaaaaa')
            rtn = bbclib.BBcRelation()
            rtn.asset_group_id = asset_group_id2
            rtn.asset = bbclib.BBcAsset()
            rtn.asset.add(user_id=user_id2, asset_body=b'bbbbbb', asset_file=b'cccccccccc%d' % i)
            ptr = bbclib.BBcPointer()
            ptr.add(transaction_id=txid1)
            rtn.add(pointer=ptr)
            if i > 0:
                ptr = bbclib.BBcPointer()
                ptr.add(transaction_id=transactions[-1].transaction_id)
                rtn.add(pointer=ptr)
            wit = bbclib.BBcWitness()
            txobj.add(event=evt, relation=rtn, witness=wit)
            wit.add_witness(user_id1)
            sig = txobj.sign(private_key=keypair1.private_key, public_key=keypair1.public_key)
            txobj.add_signature(user_id=user_id1, signature=sig)
            txobj.digest()
            transactions.append(txobj)

    def test_02_check_table_existence(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        ret = data_handler.db_adaptors[0].check_table_existence('transaction_table')
        assert len(ret) == 1
        ret = data_handler.db_adaptors[0].check_table_existence('asset_info_table')
        assert len(ret) == 1
        ret = data_handler.db_adaptors[0].check_table_existence('topology_table')
        assert len(ret) == 1

    def test_03_insert_transaction(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        asset_files = {
            transactions[0].relations[0].asset.asset_id: transactions[0].relations[0].asset.asset_file,
        }
        ret = data_handler.insert_transaction(bbclib.serialize(transactions[0]), transactions[0],
                                              asset_files=asset_files, no_replication=True)
        assert asset_group_id1 in ret and asset_group_id2 in ret

    def test_04_search_transaction(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        ret_txobj, ret_asset_files = data_handler.search_transaction(transaction_id=transactions[0].transaction_id)
        assert len(ret_txobj) == 1
        assert len(ret_asset_files) == 1
        print(ret_txobj)

    def test_05_insert_transaction_failures(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        ret = data_handler.insert_transaction(bbclib.serialize(transactions[0]), transactions[0], no_replication=True)
        assert ret is None

    def test_06_remove_transaction(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        data_handler.remove(transaction_id=transactions[0].transaction_id)

        ret_txobj, ret_asset_files = data_handler.search_transaction(transaction_id=transactions[0].transaction_id)
        assert ret_txobj is None
        assert ret_asset_files is None

    def test_07_insert_transactions(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for i in range(10):
            asset_files = {
                transactions[i].relations[0].asset.asset_id: transactions[i].relations[0].asset.asset_file,
            }
            ret = data_handler.insert_transaction(bbclib.serialize(transactions[i]), transactions[i],
                                                  asset_files=asset_files, no_replication=True)
            assert asset_group_id1 in ret and asset_group_id2 in ret

    def test_08_search_transaction_by_user_id(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        ret_txobj, ret_asset_files = data_handler.search_transaction(asset_group_id=asset_group_id1,
                                                                     user_id=user_id1, count=0)
        assert len(ret_txobj) == 10
        assert len(ret_asset_files) == 10
        pprint.pprint(ret_txobj, width=200)
        pprint.pprint(ret_asset_files, width=200)

    def test_09_search_transaction_topology(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        ret = data_handler.search_transaction_topology(transactions[1].transaction_id)
        assert len(ret) == 2
        for i in range(2):
            assert ret[i][2] in [txid1, transactions[0].transaction_id]

        ret = data_handler.search_transaction_topology(transactions[1].transaction_id, traverse_to_past=False)
        assert len(ret) == 1
        assert ret[0][1] == transactions[2].transaction_id

    def test_10_count_transactions(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        ret = data_handler.count_transactions(asset_group_id=asset_group_id1)
        print("(asset_group_id1) count=", ret)
        assert ret == 10

        ret = data_handler.count_transactions(user_id=user_id1)
        print("(user_id1) count=", ret)
        assert ret == 10


if __name__ == '__main__':
    pytest.main()
