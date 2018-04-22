# -*- coding: utf-8 -*-
import pytest

import time
import queue

import sys
sys.path.extend(["../"])
from bbc1.core import query_management, message_key_types
from bbc1.core import key_exchange_manager
from bbc1.core import bbclib

ticker = query_management.get_ticker()
msg_queue = queue.Queue()

node_num = 4
domain_id = bbclib.get_new_id("test_domain")
node_ids = [None for i in range(node_num)]
key_managers = [None for i in range(node_num)]


class DummyNetwork:
    def send_key_exchange_message(self, domain_id, node_id, command, pubkey, nonce, random_val, key_name):
        print("send KEY_EXCHANGE message")
        msg_queue.put([domain_id, node_id, pubkey, nonce, random_val, key_name])
        return True


class TestKeyExchangeManager(object):

    def test_01_setup(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        key_exchange_manager.KeyExchangeManager.KEY_EXCHANGE_INVOKE_MAX_BACKOFF = 1
        key_exchange_manager.KeyExchangeManager.KEY_EXCHANGE_RETRY_INTERVAL = 2
        key_exchange_manager.KeyExchangeManager.KEY_REFRESH_INTERVAL = 20
        global key_managers, node_ids
        for i in range(2):
            node_ids[i] = bbclib.get_new_id("node%d"%i)
        key_managers[0] = key_exchange_manager.KeyExchangeManager(DummyNetwork(), domain_id, node_ids[1])
        key_managers[1] = key_exchange_manager.KeyExchangeManager(DummyNetwork(), domain_id, node_ids[0])

    def test_02_invoke_key_exchange(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        print("# Node0 invokes key exchange")
        key_managers[0].set_invoke_timer(1)

    def test_03_receive_request(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        print("# Node1------")
        msg = msg_queue.get()
        assert key_managers[0].state == key_exchange_manager.KeyExchangeManager.STATE_REQUESTING
        key_managers[1].receive_exchange_request(msg[2], msg[3], msg[4], msg[5])
        assert key_managers[1].state == key_exchange_manager.KeyExchangeManager.STATE_CONFIRMING
        print("# Node1 sends response")

    def test_04_receive_response(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        print("# Node0------")
        msg = msg_queue.get()
        key_managers[0].receive_exchange_response(msg[2], msg[3], msg[5])
        assert key_managers[0].state == key_exchange_manager.KeyExchangeManager.STATE_ESTABLISHED
        print("# Node0 sends confirmation")

    def test_05_confirm(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        print("# Node1------")
        print("# Node1 receives confirmation")
        msg = msg_queue.get()
        key_managers[1].receive_confirmation()
        assert key_managers[1].state == key_exchange_manager.KeyExchangeManager.STATE_ESTABLISHED

        time.sleep(1)
        assert key_managers[0].key_name in message_key_types.encryptors
        assert key_managers[1].key_name in message_key_types.encryptors


if __name__ == '__main__':
    pytest.main()

