# -*- coding: utf-8 -*-
import pytest

import binascii
import time
import json

import os
import sys
sys.path.extend(["../"])
from bbc1.core import bbclib
from bbc1.core.message_key_types import KeyType
from bbc1.core.bbc_error import *
from bbc1.core import bbc_app
from testutils import prepare, get_core_client, start_core_thread, make_client

LOGLEVEL = 'debug'
#LOGLEVEL = 'info'


core_num = 5
client_num = 5
cores = None
clients = None
keyname = None
domain_id = bbclib.get_new_id("testdomain", include_timestamp=False)
asset_group_id = bbclib.get_new_id("asset_group_1")
transactions = [None for i in range(client_num)]
transaction_dat = None

msg_processor = [None for i in range(client_num)]

large_data = "aaaaaaaaaa" * 200

config_file_content = {
    'node_key': {
        'use': True,
        'obsolete_timeout': 300,
    },
}


class MessageProcessor(bbc_app.Callback):
    def __init__(self, index=0):
        super(MessageProcessor, self).__init__(self)
        self.idx = index

    def proc_cmd_sign_request(self, dat):
        self.logger.info("[%d] Recv SIGN_REQUEST from %s" % (self.idx, binascii.b2a_hex(dat[KeyType.source_user_id])))
        if KeyType.transactions not in dat:
            self.logger.warn("message needs to include referred transactions")
            return
        txobj = bbclib.BBcTransaction()
        txobj.deserialize(dat[KeyType.transaction_data])

        objs = dict()
        for txid, txdata in dat[KeyType.transactions].items():
            txo = bbclib.BBcTransaction()
            txo.deserialize(txdata)
            objs[txid] = txo

        print(txobj)
        for i, reference in enumerate(txobj.references):
            event = objs[reference.transaction_id].events[reference.event_index_in_ref]
            if clients[self.idx]['user_id'] in event.mandatory_approvers:
                signature = txobj.sign(keypair=clients[self.idx]['keypair'])
                clients[self.idx]['app'].sendback_signature(dat[KeyType.source_user_id], txobj.transaction_id,
                                                            i, signature)
                return

    def proc_resp_search_asset(self, dat):
        if KeyType.transaction_data in dat:
            self.logger.debug("OK: Asset [%s] is found." % binascii.b2a_hex(dat[KeyType.asset_id]))
            tx_obj = bbclib.BBcTransaction(deserialize=dat[KeyType.transaction_data])
            for evt in tx_obj.events:
                if evt.asset.asset_body_size > 0:
                    self.logger.debug(" [%s] asset_body --> %s" % (binascii.b2a_hex(evt.asset.asset_id[:4]),
                                                                   evt.asset.asset_body))
        else:
            self.logger.debug("NG.....")
            dat = None
        self.queue.put(dat)


class TestBBcAppClient(object):

    def test_00_setup(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        print("domain_id =", binascii.b2a_hex(domain_id))

        global keyname
        keypair = bbclib.KeyPair()
        keypair.generate()
        keyname = os.path.join(".bbc1", domain_id.hex() + ".pem")
        try:
            os.mkdir(".bbc1")
        except:
            pass
        with open(keyname, "wb") as f:
            f.write(keypair.get_private_key_in_pem())

        keypair_dummy = bbclib.KeyPair()
        keypair_dummy.generate()
        with open(os.path.join(".bbc1", "dummy.pem"), "wb") as f:
            f.write(keypair_dummy.get_private_key_in_pem())

        with open(os.path.join(".bbc1", "testconf.json"), "wb") as f:
            f.write(json.dumps(config_file_content).encode())

        global msg_processor
        prepare(core_num=core_num, client_num=client_num,
                conf_file=os.path.join(".bbc1", "testconf.json"), loglevel=LOGLEVEL)
        for i in range(core_num):
            start_core_thread(index=i, core_port_increment=i, p2p_port_increment=i, use_nodekey=True)
            time.sleep(0.1)
        time.sleep(1)
        for i in range(client_num):
            msg_processor[i] = MessageProcessor(index=i)
            make_client(index=i, core_port_increment=i, callback=msg_processor[i])
        time.sleep(1)

        global cores, clients
        cores, clients = get_core_client()

    def test_01_set_domain_key(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        #clients[0]['app'].set_node_key(".bbc1/default_node_key.pem")  # created by bbc_core
        clients[0]['app'].set_domain_key(".bbc1/dummy.pem")

        clients[1]['app'].set_node_key(".bbc1/default_node_key.pem")  # created by bbc_core
        clients[1]['app'].set_domain_key(".bbc1/dummy.pem")

        for i in range(2, client_num):
            clients[i]['app'].set_node_key(".bbc1/default_node_key.pem")
            clients[i]['app'].set_domain_key(keyname)

        clients[0]['app'].domain_setup(domain_id)
        for i in range(1, client_num):
            clients[i]['app'].set_domain_id(domain_id)
            clients[i]['app'].domain_setup(domain_id)
            ret = msg_processor[i].synchronize()

    def test_10_register(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for i in range(client_num):
            ret = clients[i]['app'].register_to_core()
            assert ret
        time.sleep(1)

    def test_11_setup_network(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        clients[4]['app'].get_domain_neighborlist(domain_id=domain_id)
        dat = msg_processor[4].synchronize()
        print("[4] nodeinfo=",dat[0])
        node_id, ipv4, ipv6, port, domain0 = dat[0]

        clients[0]['app'].set_domain_static_node(domain_id, node_id, ipv4, ipv6, port)
        clients[1]['app'].set_domain_static_node(domain_id, node_id, ipv4, ipv6, port)
        for i in range(2, client_num-1):
            clients[i]['app'].set_domain_static_node(domain_id, node_id, ipv4, ipv6, port)
            dat = msg_processor[i].synchronize()
            print("[%d] set_domain_static_node result is %s" % (i, dat))
        print("--- wait 5 seconds ---")
        time.sleep(5)

        #clients[0]['app'].get_domain_neighborlist(domain_id=domain_id)
        #clients[1]['app'].get_domain_neighborlist(domain_id=domain_id)
        for i in range(2, client_num):
            clients[i]['app'].get_domain_neighborlist(domain_id=domain_id)
            dat = msg_processor[i].synchronize()
            print("Neighbor list -->", dat)
            assert len(dat) == core_num - 2

    def test_13_insert_first_transaction(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        user = clients[3]['user_id']
        transactions[0] = bbclib.make_transaction(event_num=2, witness=True)
        transactions[0].events[0].add(reference_index=0, mandatory_approver=user)
        bbclib.add_event_asset(transactions[0], event_idx=0, asset_group_id=asset_group_id,
                               user_id=user, asset_body=b'123456')
        bbclib.add_event_asset(transactions[0], event_idx=1, asset_group_id=asset_group_id,
                               user_id=user, asset_body=b'abcdefg')

        transactions[0].witness.add_witness(user_id=user)
        sig = transactions[0].sign(keypair=clients[0]['keypair'])
        assert sig is not None
        if sig is None:
            print(bbclib.error_text)
            import os
            os._exit(1)
        transactions[0].witness.add_signature(user_id=user, signature=sig)

        transactions[0].digest()
        print(transactions[0])
        global transaction_dat
        transaction_dat = transactions[0].serialize()
        print("register transaction=", binascii.b2a_hex(transactions[0].transaction_id))
        clients[0]['app'].insert_transaction(transactions[0])
        dat = msg_processor[0].synchronize()
        assert KeyType.reason in dat
        print("Failed: reason is", dat[KeyType.reason])
        time.sleep(2)

    def test_30_messaging(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for i in range(2, client_num-1):
            msg = "message to %d" % i
            clients[4]['app'].send_message(msg, clients[i]['user_id'])
        for i in range(2, client_num-1):
            dat = msg_processor[i].synchronize()
            assert KeyType.message in dat
            print("recv=", dat)

    def test_97_get_stat(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for cl in clients:
            ret = cl['app'].get_stats()
            assert ret
        time.sleep(2)
        import pprint
        for i in range(1, client_num):
            pprint.pprint(msg_processor[i].synchronize()[KeyType.stats])

    def test_98_unregister(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for cl in clients:
            ret = cl['app'].unregister_from_core()
            assert ret

    def test_99_quit(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for core in cores:
            core.networking.save_all_static_node_list()
            ret = core.config.update_config()
            assert ret


if __name__ == '__main__':
    pytest.main()
