# -*- coding: utf-8 -*-
import pytest

import binascii
import sys
sys.path.extend(["../"])
from bbc1.core import bbclib
from bbc1.core.bbc_config import BBcConfig


config = None


class TestBBcConfig(object):

    def test_00_load(self):
        print("-----", sys._getframe().f_code.co_name, "-----")
        global config
        config = BBcConfig()
        print(config.get_config())
        assert config is not None

    def test_01_update(self):
        print("-----", sys._getframe().f_code.co_name, "-----")
        conf = config.get_config()
        conf['network']['ipv4'] = False
        with open(".bbc1/config.json", "r") as f:
            print(f.read())
        config.update_config()
        with open(".bbc1/config.json", "r") as f:
            print(f.read())

    def test_02_add_node(self):
        print("-----", sys._getframe().f_code.co_name, "-----")
        domain_id = binascii.a2b_hex("0000000000000000000000000000000000000000000000000000000000000000")
        dconf = config.get_domain_config(domain_id)
        assert dconf is not None

        node_id_str = bbclib.convert_id_to_string(bbclib.get_new_id("testnode1"))
        dconf['static_nodes'][node_id_str] = [1, 2, 3]
        config.update_config()
        with open(".bbc1/config.json", "r") as f:
            print(f.read())

