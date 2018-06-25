# -*- coding: utf-8 -*-
import pytest

import json
import time

import sys
sys.path.extend(["../"])
from bbc1.core import bbclib
from testutils import prepare, get_core_client, start_core_thread, make_client, domain_setup_utility

LOGLEVEL = 'debug'
LOGLEVEL = 'info'


core_num = 1
client_num = 1
cores = None
clients = None
domain_id = bbclib.get_new_id("testdomain")


class TestBBcAppClient(object):

    def test_00_setup(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")

        prepare(core_num=core_num, client_num=client_num)
        for i in range(core_num):
            start_core_thread(index=i)
            make_client(index=i, core_port_increment=0)
        time.sleep(1)

        global cores, clients
        cores, clients = get_core_client()

    def test_01_create_domain_with_custom_config(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        conf = {
            'workingdir': ".bbc1-9000",
            'client': {
                'port': 9000,
                'use_node_key': True,
            },
            'network': {
                'p2p_port': 6641,
                'max_connections': 10000,
            },
            'domain_key': {
                'use': False,
                'directory': ".bbc1-9000" + "/domain_keys",
                'obsolete_timeout': 30000,
            },
        }
        jsonconf = json.dumps(conf)
        clients[0]['app'].domain_setup(domain_id, config=jsonconf)
        dat = clients[0]['app'].callback.synchronize()
        print(dat)

    def test_02_get_config(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        clients[0]['app'].register_to_core()

        clients[0]['app'].get_bbc_config()
        dat = clients[0]['app'].callback.synchronize()
        print(dat)


if __name__ == '__main__':
    pytest.main()

