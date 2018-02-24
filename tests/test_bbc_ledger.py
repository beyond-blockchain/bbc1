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
keypair1 = bbclib.KeyPair()
keypair1.generate()

transaction1 = bbclib.make_transaction_for_base_asset(asset_group_id=asset_group_id, event_num=0)
transaction1.digest()
print("**** transaction_id:", transaction1.transaction_id)


class TestBBcLedger(object):

    def test_01_open(self):
        print("-----", sys._getframe().f_code.co_name, "-----")
        ledger_manager.add_domain(domain_id)
        ledger_manager.open_db(domain_id, 'transaction_db')
        ledger_manager.close_db(domain_id, 'transaction_db')

    def test_02_check_table_existence(self):
        print("-----", sys._getframe().f_code.co_name, "-----")
        ledger_manager.open_db(domain_id, 'transaction_db')
        ret = ledger_manager.check_table_existence(domain_id, 'transaction_db', 'transaction_table')
        assert ret is not None

    def test_03_insert_transaction(self):
        print("-----", sys._getframe().f_code.co_name, "-----")
        global transaction1
        ret = ledger_manager.insert_locally(domain_id=domain_id, asset_group_id=asset_group_id,
                                            resource_id=transaction1.transaction_id,
                                            resource_type=ResourceType.Transaction_data, data=transaction1.serialize())
        assert ret

    def test_04_remove_transaction(self):
        print("-----", sys._getframe().f_code.co_name, "-----")
        global transaction1
        ret = ledger_manager.remove(domain_id=domain_id, asset_group_id=asset_group_id,
                                    resource_id=transaction1.transaction_id)
        assert ret

    def test_05_insert_transaction(self):
        print("-----", sys._getframe().f_code.co_name, "-----")
        global transaction1
        ret = ledger_manager.insert_locally(domain_id=domain_id, asset_group_id=asset_group_id,
                                            resource_id=transaction1.transaction_id,
                                            resource_type=ResourceType.Transaction_data, data=transaction1.serialize())
        assert ret

    def test_06_find_transaction_1(self):
        print("-----", sys._getframe().f_code.co_name, "-----")
        dat = ledger_manager.find_locally(domain_id=domain_id, asset_group_id=asset_group_id,
                                          resource_id=b'543210', resource_type=ResourceType.Transaction_data)
        print(dat)
        assert dat is None

    def test_07_find_transaction_2(self):
        print("-----", sys._getframe().f_code.co_name, "-----")
        dat = ledger_manager.find_locally(domain_id=domain_id, asset_group_id=asset_group_id,
                                          resource_id=transaction1.transaction_id,
                                          resource_type=ResourceType.Transaction_data)
        print(dat)
        assert dat is not None

    def test_08_put(self):
        print("-----", sys._getframe().f_code.co_name, "-----")
        ret = ledger_manager.insert_locally(domain_id=domain_id, asset_group_id=asset_group_id,
                                            resource_id=transaction1.transaction_id,
                                            data=b'dfdaysf', resource_type=ResourceType.Transaction_data)
        assert not ret

    def test_09_get(self):
        print("-----", sys._getframe().f_code.co_name, "-----")
        ret = ledger_manager.find_locally(domain_id=domain_id, asset_group_id=asset_group_id,
                                          resource_id=transaction1.transaction_id,
                                          resource_type=ResourceType.Transaction_data)
        assert ret is not None
        print(ret)


if __name__ == '__main__':
    pytest.main()
