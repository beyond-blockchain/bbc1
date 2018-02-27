# -*- coding: utf-8 -*-
import pytest

import sys
sys.path.extend(["../"])
from bbc1.common import bbclib
from bbc1.core import bbc_ledger, bbc_config
from bbc1.core.bbc_types import ResourceType

config = bbc_config.BBcConfig()
ledger_manager =bbc_ledger.BBcLedger(config=config)

user_id = bbclib.get_new_id("destination_id_test1")
domain_id = bbclib.get_new_id("test_domain")
asset_group_id = bbclib.get_new_id("asset_group_1")
asset_group_id2 = bbclib.get_new_id("asset_group_2")
keypair1 = bbclib.KeyPair()
keypair1.generate()

transaction1 = bbclib.make_transaction_for_base_asset(asset_group_id=asset_group_id, event_num=2)
transaction1.events[0].asset.add(user_id=user_id, asset_body=b'123456')
transaction1.events[1].asset_group_id = asset_group_id2
transaction1.events[1].asset.add(user_id=user_id, asset_body=b'abcdef')
transaction1.digest()


class TestBBcLedger(object):

    def test_01_open(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        ledger_manager.add_domain(domain_id)
        ledger_manager.open_db(domain_id, 'transaction_db')
        ledger_manager.close_db(domain_id, 'transaction_db')

    def test_02_check_table_existence(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        ledger_manager.open_db(domain_id, 'transaction_db')
        ret = ledger_manager.check_table_existence(domain_id, 'transaction_db', 'transaction_table')
        assert ret is not None

    def test_03_insert_transaction(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        global transaction1
        ret = ledger_manager.insert_transaction_locally(domain_id=domain_id,
                                                        transaction_id=transaction1.transaction_id,
                                                        data=transaction1.serialize())
        assert ret

    def test_04_remove_transaction(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        global transaction1
        ret = ledger_manager.remove(domain_id=domain_id, transaction_id=transaction1.transaction_id)
        assert ret

    def test_05_insert_transaction(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        global transaction1
        ret = ledger_manager.insert_transaction_locally(domain_id=domain_id,
                                                        transaction_id=transaction1.transaction_id,
                                                        data=transaction1.serialize())
        assert ret

    def test_06_find_transaction_1(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        dat = ledger_manager.find_transaction_locally(domain_id=domain_id, transaction_id=b'543210')
        assert dat is None
        print(dat)

    def test_07_find_transaction_2(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        global transaction1
        dat = ledger_manager.find_transaction_locally(domain_id=domain_id, transaction_id=transaction1.transaction_id)
        assert dat is not None
        print(dat.hex())

    def test_08_insert_asset_info(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        global transaction1
        transaction1.digest()
        asset = transaction1.events[0].asset
        ret = ledger_manager.insert_asset_info_locally(domain_id, transaction1.transaction_id, asset_group_id,
                                                       asset.asset_id, user_id)
        assert ret
        asset = transaction1.events[1].asset
        ret = ledger_manager.insert_asset_info_locally(domain_id, transaction1.transaction_id, asset_group_id2,
                                                       asset.asset_id, user_id)
        assert ret

        transaction2 = bbclib.make_transaction_for_base_asset(asset_group_id=asset_group_id, event_num=1)
        transaction2.events[0].asset.add(user_id=user_id, asset_body=b'123456')
        transaction2.digest()
        asset = transaction2.events[0].asset
        ret = ledger_manager.insert_asset_info_locally(domain_id, transaction2.transaction_id, asset_group_id,
                                                       asset.asset_id, user_id)
        assert ret

    def test_09_find_asset_info(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        asset = transaction1.events[0].asset
        sql = "SELECT DISTINCT transaction_id FROM asset_info_table WHERE asset_group_id = ? AND asset_id = ?"
        row = ledger_manager.find_by_sql_in_local_auxiliary_db(domain_id, sql, asset_group_id, asset.asset_id)
        assert len(row) == 1
        print(len(row), row)
        sql = "SELECT transaction_id FROM asset_info_table"
        row = ledger_manager.find_by_sql_in_local_auxiliary_db(domain_id, sql)
        assert len(row) == 3

    def test_10_find_asset_info_failure(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        asset = transaction1.events[0].asset
        sql = "SELECT DISTINCT transaction_id FROM asset_info_table WHERE asset_group_id = ? AND asset_id = ?"
        row = ledger_manager.find_by_sql_in_local_auxiliary_db(domain_id, sql, asset_group_id, b'543210')
        assert len(row) == 0
        print(row)

    def test_11_find_by_user_id(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        sql = "SELECT DISTINCT transaction_id FROM asset_info_table WHERE asset_group_id = ? AND user_id = ? limit ?"
        row = ledger_manager.find_by_sql_in_local_auxiliary_db(domain_id, sql, asset_group_id, user_id, 1)
        assert len(row) == 1
        print(row)
        sql = "SELECT DISTINCT * FROM asset_info_table WHERE asset_group_id = ? AND user_id = ? limit ?"
        row = ledger_manager.find_by_sql_in_local_auxiliary_db(domain_id, sql, asset_group_id, user_id, 2)
        assert len(row) == 2
        print(row)


if __name__ == '__main__':
    pytest.main()
