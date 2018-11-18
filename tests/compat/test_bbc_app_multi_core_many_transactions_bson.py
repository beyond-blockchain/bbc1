# -*- coding: utf-8 -*-
import pytest

import binascii
import time

import sys
sys.path.extend(["../", "../.."])
from bbc1.core.compat import bbclib, bbc_app
from bbc1.core.message_key_types import KeyType
from bbc1.core.bbc_error import *
from testutils import prepare, get_core_client, start_core_thread, make_client, domain_setup_utility


LOGLEVEL = 'debug'
LOGLEVEL = 'none'


core_num = 5
client_num = 5
cores = None
clients = None
domain_id = bbclib.get_new_id("testdomain")
asset_group_id = bbclib.get_new_id("asset_group_1")
transactions = [None for i in range(client_num)]
msg_processor = [None for i in range(client_num)]
fmt = bbclib.BBcFormat.FORMAT_BSON_COMPRESS_BZ2


class MessageProcessor(bbc_app.Callback):
    def __init__(self, index=0):
        super(MessageProcessor, self).__init__(self)
        self.idx = index

    def proc_cmd_sign_request(self, dat):
        self.logger.debug("[%i] Recv SIGN_REQUEST from %s" % (self.idx, binascii.b2a_hex(dat[KeyType.source_user_id])))
        print("[%i] Recv SIGN_REQUEST from %s" % (self.idx, binascii.b2a_hex(dat[KeyType.source_user_id])))
        txobj = bbclib.BBcTransaction(deserialize=dat[KeyType.transaction_data])

        objs = dict()
        for txid, txdata in dat[KeyType.transactions].items():
            txo = bbclib.BBcTransaction()
            txo.deserialize(txdata)
            objs[txid] = txo

        for i, reference in enumerate(txobj.references):
            event = objs[reference.transaction_id].events[reference.event_index_in_ref]
            if clients[self.idx]['user_id'] in event.mandatory_approvers:
                signature = txobj.sign(keypair=clients[self.idx]['keypair'])
                clients[self.idx]['app'].sendback_signature(dat[KeyType.source_user_id], txobj.transaction_id,
                                                            i, signature)
                return


class TestBBcAppClient(object):

    def test_00_setup(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        print("domain_id =", binascii.b2a_hex(domain_id))

        global msg_processor
        prepare(core_num=core_num, client_num=client_num, loglevel=LOGLEVEL)
        for i in range(core_num):
            start_core_thread(index=i, core_port_increment=i, p2p_port_increment=i)
            domain_setup_utility(i, domain_id)  # system administrator
        time.sleep(1)
        for i in range(client_num):
            msg_processor[i] = MessageProcessor(index=i)
            make_client(index=i, core_port_increment=i, callback=msg_processor[i])
        time.sleep(1)

        global cores, clients
        cores, clients = get_core_client()

    def test_10_setup_network(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        ret = clients[0]['app'].get_domain_neighborlist(domain_id=domain_id)
        assert ret
        dat = msg_processor[0].synchronize()
        print("[0] nodeinfo=", dat[0])
        node_id, ipv4, ipv6, port, domain0 = dat[0]

        for i in range(1, client_num):
            clients[i]['app'].send_domain_ping(domain_id, ipv4, ipv6, port)
        print("*** wait 15 seconds ***")
        time.sleep(15)

        for i in range(core_num):
            print(cores[i].networking.domains[domain_id]['neighbor'].show_list())
            assert len(cores[i].networking.domains[domain_id]['neighbor'].nodeinfo_list) == core_num - 1

    def test_11_register(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for cl in clients:
            ret = cl['app'].register_to_core()
            assert ret
        time.sleep(1)

    def test_12_make_transaction(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for i, cl in enumerate(clients):
            print("---- start transaction ---")
            user = cl['user_id']
            other_user = (i+1) % client_num

            transactions[i] = bbclib.make_transaction(event_num=1, witness=True, format_type=fmt)
            transactions[i].events[0].add(mandatory_approver=clients[other_user]['user_id'])
            bbclib.add_event_asset(transactions[i], event_idx=0, asset_group_id=asset_group_id,
                                   user_id=user, asset_body=b"data=%d"%i)

            transactions[i].witness.add_witness(user_id=cl['user_id'])
            sig = transactions[i].sign(keypair=cl['keypair'])
            transactions[i].add_signature(user_id=cl['user_id'], signature=sig)

            transactions[i].digest()
            print("register transaction=", binascii.b2a_hex(transactions[i].transaction_id))
            cl['app'].insert_transaction(transactions[i])
            print("  ----> wait insert")
            dat = msg_processor[i].synchronize()
            assert KeyType.transaction_id in dat
            assert dat[KeyType.transaction_id] == transactions[i].transaction_id
            print("    ==> got insert")
        time.sleep(2)

    def test_13_make_transaction(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for i, cl in enumerate(clients):
            user = cl['user_id']
            other_user = (i + 1) % client_num

            txobj = bbclib.make_transaction(event_num=1, witness=True, format_type=fmt)
            txobj.events[0].add(reference_index=0, mandatory_approver=clients[other_user]['user_id'])
            bbclib.add_event_asset(txobj, event_idx=0, asset_group_id=asset_group_id,
                                   user_id=user, asset_body=b"data=%d"%i)
            reference = bbclib.add_reference_to_transaction(txobj, asset_group_id, transactions[i], 0)
            ret = cl['app'].gather_signatures(txobj, reference_obj=reference)
            assert ret
            dat = msg_processor[i].synchronize()
            assert dat[KeyType.status] == ESUCCESS
            result = dat[KeyType.result]
            txobj.references[result[0]].add_signature(user_id=result[1], signature=result[2])

            txobj.digest()
            cl['app'].insert_transaction(txobj)
            dat = msg_processor[i].synchronize()
            assert KeyType.transaction_id in dat
            assert dat[KeyType.transaction_id] == txobj.transaction_id
            transactions[i] = txobj

    @pytest.mark.unregister
    def test_98_unregister(self):
        for cl in clients:
            ret = cl['app'].unregister_from_core()
            assert ret


if __name__ == '__main__':
    pytest.main()
