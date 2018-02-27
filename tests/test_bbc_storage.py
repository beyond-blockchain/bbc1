# -*- coding: utf-8 -*-
import pytest

import sys
sys.path.extend(["../"])
from bbc1.common import bbclib
from bbc1.core import bbc_storage, bbc_config

config = bbc_config.BBcConfig()
storage_manager = bbc_storage.BBcStorage(config=config)
domain_ids = [bbclib.get_new_id("test_domain_%d" % i) for i in range(3)]
asset_group_ids = [bbclib.get_new_id("asset_group_%d"%i) for i in range(3)]


class TestBBcStorage(object):

    def test_0_setup(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        storage_manager.set_storage_path(domain_ids[0])

    def test_1_put(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        ret = storage_manager.store_locally(domain_ids[0], asset_group_ids[0], b"abcdefg", b'fuawhfuawefba')
        assert ret

    def test_2_get(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        ret = storage_manager.get_locally(domain_ids[0], asset_group_ids[0], b"abcdefg")
        print(ret)
        assert ret is not None
        ret = storage_manager.get_locally(domain_ids[0], asset_group_ids[0], b"zxxv")
        print(ret)
        assert ret is None

    def test_3_remove(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        ret = storage_manager.remove(domain_ids[0], asset_group_ids[0], b"da6yfyasf")
        assert not ret
        ret = storage_manager.remove(domain_ids[0], asset_group_ids[0], b"abcdefg")
        assert ret

    def test_4_setup(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        storage_manager.set_storage_path(domain_ids[1], storage_type=bbclib.StorageType.NONE)

    def test_5(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        ret = storage_manager.store_locally(domain_ids[1], asset_group_ids[1], b"abcdefg2", b'fuawhfuawefba2')
        assert ret
        ret = storage_manager.get_locally(domain_ids[1], asset_group_ids[1], b"abcdefg2")
        print(ret)
        assert ret is None
        ret = storage_manager.get_locally(domain_ids[1], asset_group_ids[1], b"zxxv2")
        print(ret)
        assert ret is None
        ret = storage_manager.remove(domain_ids[1], asset_group_ids[1], b"da6yfyasf2")
        assert not ret
        ret = storage_manager.remove(domain_ids[1], asset_group_ids[1], b"abcdefg2")
        assert not ret

    def test_6_setup(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        storage_manager.set_storage_path(domain_ids[2],
                                         storage_type=bbclib.StorageType.FILESYSTEM,
                                         storage_path="./testdir")

    def test_7(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        ret = storage_manager.store_locally(domain_ids[2], asset_group_ids[2], b"abcdefg3", b'fuawhfuawefba3')
        assert ret
        ret = storage_manager.get_locally(domain_ids[2], asset_group_ids[2], b"abcdefg3")
        print(ret)
        assert ret is not None
        ret = storage_manager.get_locally(domain_ids[2], asset_group_ids[2], b"zxxv3")
        print(ret)
        assert ret is None
        ret = storage_manager.remove(domain_ids[2], asset_group_ids[2], b"da6yfyasf3")
        assert not ret
        ret = storage_manager.remove(domain_ids[2], asset_group_ids[2], b"abcdefg3")
        assert ret


if __name__ == '__main__':
    pytest.main()
