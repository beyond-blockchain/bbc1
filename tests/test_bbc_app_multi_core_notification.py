# -*- coding: utf-8 -*-
import pytest

import binascii
import time

import sys
sys.path.extend(["../"])
from bbc1.core import bbclib
from bbc1.core.message_key_types import KeyType
from bbc1.core import bbc_app
from testutils import prepare, get_core_client, start_core_thread, make_client, domain_setup_utility


LOGLEVEL = 'debug'
#LOGLEVEL = 'none'


core_num = 5
client_num = 5
cores = None
clients = None
domain_id = bbclib.get_new_id("testdomain")
asset_group_id = bbclib.get_new_id("asset_group_1")
transactions = [None for i in range(client_num)]

msg_processor = [None for i in range(client_num)]


def check_insert_response(clnum, transaction_id):
    msg = msg_processor[clnum].synchronize()
    if msg[KeyType.command] == bbclib.MsgType.RESPONSE_INSERT:
        assert msg[KeyType.transaction_id] == transaction_id
        print("[%d] inserted" % clnum)
    elif msg[KeyType.command] == bbclib.MsgType.NOTIFY_INSERTED:
        assert KeyType.asset_group_ids in msg
        print("[%d] notification txid=%s, asset_group=%s" % (
            clnum, binascii.b2a_hex(msg[KeyType.transaction_id]),
            [binascii.b2a_hex(a) for a in msg[KeyType.asset_group_ids]]
        ))


class MessageProcessor(bbc_app.Callback):
    def __init__(self, index=0):
        super(MessageProcessor, self).__init__(self)
        self.idx = index

    def proc_cmd_sign_request(self, dat):
        self.logger.debug("[%i] Recv SIGN_REQUEST from %s" % (self.idx, binascii.b2a_hex(dat[KeyType.source_user_id])))
        txobj = bbclib.BBcTransaction()
        txobj.deserialize(dat[KeyType.transaction_data])

        objs = dict()
        for txid, txdata in dat[KeyType.transactions].items():
            txo = bbclib.BBcTransaction()
            txo.deserialize(txdata)
            objs[txid] = txo

        for i, reference in enumerate(txobj.references):
            event = objs[reference.transaction_id].events[reference.event_index_in_ref]
            if clients[self.idx]['user_id'] in event.mandatory_approvers:
                signature = txobj.sign(keypair=clients[self.idx]['keypair'])
                clients[self.idx]['app'].sendback_signature(asset_group_id, dat[KeyType.source_user_id],
                                                            txobj.transaction_id, i, signature)
                return


class TestBBcAppClient(object):

    def test_00_setup(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        print("domain_id =", binascii.b2a_hex(domain_id))

        global msg_processor
        prepare(core_num=core_num, client_num=client_num, loglevel=LOGLEVEL)
        for i in range(core_num):
            start_core_thread(index=i, core_port_increment=i, p2p_port_increment=i)
            time.sleep(0.1)
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
        print("*** wait 5 seconds ***")
        time.sleep(5)

        for i in range(core_num):
            print(cores[i].networking.domains[domain_id]['neighbor'].show_list())
            assert len(cores[i].networking.domains[domain_id]['neighbor'].nodeinfo_list) == core_num - 1

    def test_11_register(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for cl in clients:
            ret = cl['app'].register_to_core()
            assert ret
        time.sleep(1)
        for cl in clients:
            assert cl['app'].request_insert_completion_notification(asset_group_id)
        time.sleep(2)

        for i in range(core_num):
            fe = cores[i].networking.domains[domain_id]['user'].forwarding_entries
            assert asset_group_id in fe
            print("Forwarding_entries:", fe[asset_group_id]['nodes'])
            num = len(fe[asset_group_id]['nodes'])
            assert num == core_num - 1

    def test_12_make_transaction(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for i, cl in enumerate(clients):
            print("---- start transaction at node %d---" % i)
            user = cl['user_id']
            other_user = (i+1) % client_num
            transactions[i] = bbclib.make_transaction(event_num=1, witness=True)
            transactions[i].events[0].add(mandatory_approver=clients[other_user]['user_id'])
            bbclib.add_event_asset(transactions[i], event_idx=0, asset_group_id=asset_group_id,
                                   user_id=user, asset_body="data=%d"%i)

            transactions[i].witness.add_witness(user_id=cl['user_id'])
            sig = transactions[i].sign(keypair=cl['keypair'])
            transactions[i].witness.add_signature(user_id=cl['user_id'], signature=sig)

            transactions[i].digest()
            print("insert_transaction=", binascii.b2a_hex(transactions[i].transaction_id))
            cl['app'].insert_transaction(transactions[i])
            time.sleep(1)
            print("  ----> wait for notification")
            for j in range(client_num):
                check_insert_response(j, transactions[i].transaction_id)
                if i == j:
                    check_insert_response(j, transactions[i].transaction_id)

    def test_20_cancel_notification(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        clients[0]['app'].cancel_insert_completion_notification(asset_group_id)
        clients[2]['app'].cancel_insert_completion_notification(asset_group_id)
        time.sleep(1)

    def test_21_make_transaction(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for i, cl in enumerate(clients):
            print("---- start transaction at node %d---" % i)
            user = cl['user_id']
            other_user = (i+1) % client_num
            transactions[i] = bbclib.make_transaction(event_num=1, witness=True)
            transactions[i].events[0].add(mandatory_approver=clients[other_user]['user_id'])
            bbclib.add_event_asset(transactions[i], event_idx=0, asset_group_id=asset_group_id,
                                   user_id=user, asset_body="data=%d"%i)

            transactions[i].witness.add_witness(user_id=cl['user_id'])
            sig = transactions[i].sign(keypair=cl['keypair'])
            transactions[i].witness.add_signature(user_id=cl['user_id'], signature=sig)
            transactions[i].digest()
            print("insert_transaction=", binascii.b2a_hex(transactions[i].transaction_id))
            cl['app'].insert_transaction(transactions[i])
            for j in range(client_num):
                if i == j:
                    check_insert_response(j, transactions[i].transaction_id)
                if j in [1,3,4]:
                    check_insert_response(j, transactions[i].transaction_id)

    def test_22_enable_notification(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for cl in clients:
            assert cl['app'].request_insert_completion_notification(asset_group_id)
        time.sleep(2)

    def test_23_make_transaction(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for i, cl in enumerate(clients):
            print("---- start transaction at node %d---" % i)
            user = cl['user_id']
            other_user = (i+1) % client_num
            transactions[i] = bbclib.make_transaction(event_num=1, witness=True)
            transactions[i].events[0].add(mandatory_approver=clients[other_user]['user_id'])
            bbclib.add_event_asset(transactions[i], event_idx=0, asset_group_id=asset_group_id,
                                   user_id=user, asset_body="data=%d"%i)

            transactions[i].witness.add_witness(user_id=cl['user_id'])
            sig = transactions[i].sign(keypair=cl['keypair'])
            transactions[i].witness.add_signature(user_id=cl['user_id'], signature=sig)
            transactions[i].digest()
            print("insert_transaction=", binascii.b2a_hex(transactions[i].transaction_id))
            cl['app'].insert_transaction(transactions[i])
            print("  ----> wait for notification")
            for j in range(client_num):
                check_insert_response(j, transactions[i].transaction_id)
                if i == j:
                    check_insert_response(j, transactions[i].transaction_id)

    @pytest.mark.unregister
    def test_98_unregister(self):
        for cl in clients:
            ret = cl['app'].unregister_from_core()
            assert ret


if __name__ == '__main__':
    pytest.main()
