# -*- coding: utf-8 -*-
import pytest

import binascii
import time

import sys
sys.path.extend(["../"])
from bbc1.core import bbclib, bbc_app
from bbc1.core.message_key_types import KeyType
from testutils import prepare, get_core_client, start_core_thread, make_client, domain_setup_utility, get_stats, get_stat_diffs


LOGLEVEL = 'debug'
#LOGLEVEL = 'none'


core_num = 5
client_num = 5
cores = None
clients = None
domain_id = bbclib.get_new_id("testdomain")
asset_group_id1 = bbclib.get_new_id("asset_group_1")
asset_group_id2 = bbclib.get_new_id("asset_group_2")
asset_group_id3 = bbclib.get_new_id("asset_group_3")
user_id1 = bbclib.get_new_id("destination_id_test1")
user_id2 = bbclib.get_new_id("destination_id_test2")
transactions = list()
txid1 = bbclib.get_new_id("dummy_txid_1")
txid2 = bbclib.get_new_id("dummy_txid_2")
keypair1 = bbclib.KeyPair()
keypair1.generate()

msg_processor = [None for i in range(client_num)]


def prepare_transactions():
    global transactions
    for i in range(client_num*2):
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
        rtn2 = bbclib.BBcRelation()
        rtn2.asset_group_id = asset_group_id3
        rtn2.asset = bbclib.BBcAsset()
        rtn2.asset.add(user_id=user_id2, asset_body=b'cccccc')
        if i > 0:
            ptr = bbclib.BBcPointer()
            ptr.add(transaction_id=transactions[-1].transaction_id)
            rtn.add(pointer=ptr)
        wit = bbclib.BBcWitness()
        if i % 2 == 0:
            txobj.add(event=evt, relation=[rtn, rtn2], witness=wit)
        else:
            txobj.add(event=evt, relation=rtn, witness=wit)
        wit.add_witness(user_id1)
        sig = txobj.sign(private_key=keypair1.private_key, public_key=keypair1.public_key)
        txobj.add_signature(user_id=user_id1, signature=sig)
        txobj.digest()
        transactions.append(txobj)


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
        pass


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

        prepare_transactions()

    def test_10_setup_network(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        ret = clients[0]['app'].get_domain_neighborlist(domain_id=domain_id)
        assert ret
        dat = msg_processor[0].synchronize()
        print("[0] nodeinfo=", dat[0])
        node_id, ipv4, ipv6, port, domain0 = dat[0]

        for i in range(1, client_num):
            clients[i]['app'].send_domain_ping(domain_id, ipv4, ipv6, port)
        print("*** wait 10 seconds ***")
        time.sleep(10)

        for i in range(core_num):
            print(cores[i].networking.domains[domain_id]['neighbor'].show_list())
            assert len(cores[i].networking.domains[domain_id]['neighbor'].nodeinfo_list) == core_num - 1

    def test_11_register(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for cl in clients:
            ret = cl['app'].register_to_core()
            assert ret
        for cl in clients:
            assert cl['app'].request_insert_completion_notification(asset_group_id3)
        time.sleep(2)

        for i in range(core_num):
            fe = cores[i].networking.domains[domain_id]['user'].forwarding_entries
            assert asset_group_id3 in fe
            print(fe[asset_group_id3]['nodes'])
            num = len(fe[asset_group_id3]['nodes'])
            assert num == core_num - 1

    def test_12_insert_transaction(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")

        clients[0]['app'].insert_transaction(transactions[0])
        time.sleep(1)
        print("  ----> wait for notification")
        for j in range(client_num):
            check_insert_response(j, transactions[0].transaction_id)
            if j == 0:
                check_insert_response(j, transactions[0].transaction_id)
        time.sleep(1)

        clients[1]['app'].insert_transaction(transactions[1])
        time.sleep(1)
        print("  ----> wait for notification")
        check_insert_response(1, transactions[1].transaction_id)

    def test_14_cancel_notification(self):
        for i in range(core_num):
            get_stats(i)

        print("\n-----", sys._getframe().f_code.co_name, "-----")
        clients[client_num-1]['app'].cancel_insert_completion_notification(asset_group_id3)
        time.sleep(1)

    def test_15_insert_transaction(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")

        clients[0]['app'].insert_transaction(transactions[2])
        time.sleep(1)
        print("  ----> wait for notification")
        for j in range(client_num-1):  # client4 won't receive NOTIFY_INSERTED because it canceled.
            check_insert_response(j, transactions[2].transaction_id)
            if j == 0:
                check_insert_response(j, transactions[2].transaction_id)
        time.sleep(1)

        clients[1]['app'].insert_transaction(transactions[3])
        time.sleep(1)
        print("  ----> wait for notification")
        check_insert_response(1, transactions[3].transaction_id)

        for i in range(core_num):
            diff_notify = get_stat_diffs(i)['data_handler'].get('NOTIFY_INSERTED', 0)
            print("[%d] received num of NOTIFY_INSERTED = %d" % (i, diff_notify))
            if i in [0, 4]:  # core0 directly sends NOTIFY_INSERTED to client0 (so, the data_handler doesn't receive it)
                assert diff_notify == 0
            else:
                assert diff_notify == 1

    def test_20_close_client_connection(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        clients[3]['app'].connection.close()  # disconnection will invoke LEAVE_MULTICAST_RECEIVER
        time.sleep(1)

        for i in range(core_num):
            diff_val = get_stat_diffs(i)['user_message'].get('LEAVE_MULTICAST_RECEIVER', 0)
            print("[%d] received num of LEAVE_MULTICAST_RECEIVER = %d" % (i, diff_val))
            if i == 3:  # core3 is initiating node that sends LEAVE_MULTICAST_RECEIVER (no receive)
                assert diff_val == 0
            else:
                assert diff_val == 1

    def test_21_insert_transactions(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")

        clients[2]['app'].insert_transaction(transactions[4])
        time.sleep(1)
        print("  ----> wait for notification")
        for j in range(client_num-2):
            check_insert_response(j, transactions[4].transaction_id)
            if j == 2:
                check_insert_response(j, transactions[4].transaction_id)
        time.sleep(1)

        clients[1]['app'].insert_transaction(transactions[5])
        time.sleep(1)
        print("  ----> wait for notification")
        check_insert_response(1, transactions[5].transaction_id)

        for i in range(core_num):
            diff_notify = get_stat_diffs(i)['data_handler'].get('NOTIFY_INSERTED', 0)
            print("[%d] received num of NOTIFY_INSERTED = %d" % (i, diff_notify))
            if i in [2, 4]:
                assert diff_notify == 0
            else:
                assert diff_notify == 1

    def test_22_insert_transactions(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")

        clients[0]['app'].insert_transaction(transactions[6])
        time.sleep(1)
        print("  ----> wait for notification")
        for j in range(client_num-2):
            check_insert_response(j, transactions[6].transaction_id)
            if j == 0:
                check_insert_response(j, transactions[6].transaction_id)
        time.sleep(1)

        for i in range(core_num):
            diff_notify = get_stat_diffs(i)['data_handler'].get('NOTIFY_INSERTED', 0)
            print("[%d] received num of NOTIFY_INSERTED = %d" % (i, diff_notify))
            if i in [0, 3, 4]:
                assert diff_notify == 0
            else:
                assert diff_notify == 1

    @pytest.mark.unregister
    def test_98_unregister(self):
        for cl in clients:
            cl['app'].unregister_from_core()


if __name__ == '__main__':
    pytest.main()
