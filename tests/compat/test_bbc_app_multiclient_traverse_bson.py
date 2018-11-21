# -*- coding: utf-8 -*-
import pytest

import time

import sys
sys.path.extend(["../", "../.."])
from bbc1.core.compat import bbclib
from bbc1.core.message_key_types import KeyType
from testutils import prepare, get_core_client, start_core_thread, make_client, domain_setup_utility

LOGLEVEL = 'debug'
LOGLEVEL = 'info'

core_num = 1
client_num = 1
cores = None
clients = None
domain_id = bbclib.get_new_id("testdomain")
asset_group_id = bbclib.get_new_id("asset_group_1")
transactions1 = [None for i in range(20)]
transactions2 = [None for i in range(20)]
transaction_dat = None
fmt = bbclib.BBcFormat.FORMAT_BSON_COMPRESS_BZ2


class TestBBcAppClient(object):

    def test_00_setup(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        prepare(core_num=core_num, client_num=client_num, loglevel=LOGLEVEL)
        for i in range(core_num):
            start_core_thread(index=i, core_port_increment=i, p2p_port_increment=i)
            domain_setup_utility(i, domain_id)  # system administrator
        time.sleep(1)
        for i in range(client_num):
            make_client(index=i, core_port_increment=0)
        time.sleep(1)

        global cores, clients
        cores, clients = get_core_client()
        for core in cores:
            core.traverse_max_count = 11

    def test_01_register(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for cl in clients:
            ret = cl['app'].register_to_core()
            assert ret
        time.sleep(1)

    def test_02_make_transaction(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        user = clients[0]['user_id']
        kp = clients[0]['keypair']

        transactions1[0] = bbclib.make_transaction(relation_num=1, witness=True, format_type=fmt)
        bbclib.add_relation_asset(transactions1[0], relation_idx=0, asset_group_id=asset_group_id,
                                  user_id=user, asset_body=b'transaction1_0')
        transactions1[0].witness.add_witness(user)
        sig = transactions1[0].sign(keypair=kp)
        transactions1[0].witness.add_signature(user, sig)

        transactions2[0] = bbclib.make_transaction(event_num=1, witness=True, format_type=fmt)
        transactions2[0].events[0].add(mandatory_approver=user)
        bbclib.add_event_asset(transactions2[0], event_idx=0, asset_group_id=asset_group_id,
                               user_id=user, asset_body=b'transaction2_0')
        transactions2[0].witness.add_witness(user)
        sig = transactions2[0].sign(keypair=kp)
        transactions2[0].witness.add_signature(user_id=user, signature=sig)

        for i in range(1, 20):
            k = i - 1
            transactions1[i] = bbclib.make_transaction(relation_num=1, witness=True, format_type=fmt)
            bbclib.add_relation_asset(transactions1[i], 0, asset_group_id=asset_group_id, user_id=user,
                                      asset_body=b'transaction1_%d' % i)
            bbclib.add_relation_pointer(transactions1[i], 0, ref_transaction_id=transactions1[k].transaction_id,
                                        ref_asset_id=transactions1[k].relations[0].asset.asset_id)
            transactions1[i].witness.add_witness(user)
            sig = transactions1[i].sign(keypair=kp)
            transactions1[i].witness.add_signature(user, sig)

            transactions2[i] = bbclib.make_transaction(event_num=1, witness=True, format_type=fmt)
            transactions2[i].events[0].add(mandatory_approver=user)
            bbclib.add_event_asset(transactions2[i], event_idx=0, asset_group_id=asset_group_id,
                                   user_id=user, asset_body=b'transaction2_%d' % i)
            transactions2[i].witness.add_witness(user)
            bbclib.add_reference_to_transaction(transactions2[i], asset_group_id, transactions2[k], 0)
            sig = transactions2[i].sign(keypair=kp)
            transactions2[i].witness.add_signature(user_id=user, signature=sig)
            if i == 9:
                bbclib.add_reference_to_transaction(transactions2[i], asset_group_id, transactions2[5], 0)
            sig = transactions2[i].sign(keypair=kp)
            transactions2[i].references[0].add_signature(user_id=user, signature=sig)

    def test_03_insert(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for i in range(20):
            clients[0]['app'].insert_transaction(transactions1[i])
            dat = clients[0]['app'].callback.synchronize()
            assert KeyType.transaction_id in dat
            assert dat[KeyType.transaction_id] == transactions1[i].transaction_id
            clients[0]['app'].insert_transaction(transactions2[i])
            dat = clients[0]['app'].callback.synchronize()
            assert KeyType.transaction_id in dat
            assert dat[KeyType.transaction_id] == transactions2[i].transaction_id

    def test_04_search_transaction_direction_backward(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        clients[0]['app'].traverse_transactions(transactions1[1].transaction_id, direction=1, hop_count=3)
        dat = clients[0]['app'].callback.synchronize()
        assert dat[KeyType.status] == 0
        assert KeyType.transaction_tree in dat
        assert len(dat[KeyType.transaction_tree]) == 2
        asset_bodies = list()
        for i, txtree in enumerate(dat[KeyType.transaction_tree]):
            for txdat in txtree:
                txobj = bbclib.BBcTransaction(deserialize=txdat)
                asset_body = txobj.relations[0].asset.asset_body
                print("[%d] asset=%s" % (i, asset_body))
                asset_bodies.append(asset_body)
        assert b'transaction1_1' in asset_bodies
        assert b'transaction1_0' in asset_bodies

    def test_05_search_transaction_direction_forward(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        clients[0]['app'].traverse_transactions(transactions1[1].transaction_id, direction=0, hop_count=3)
        dat = clients[0]['app'].callback.synchronize()
        assert dat[KeyType.status] == 0
        assert KeyType.transaction_tree in dat
        assert len(dat[KeyType.transaction_tree]) == 3
        asset_bodies = list()
        for i, txtree in enumerate(dat[KeyType.transaction_tree]):
            for txdat in txtree:
                txobj = bbclib.BBcTransaction(deserialize=txdat)
                asset_body = txobj.relations[0].asset.asset_body
                print("[%d] asset=%s" % (i, asset_body))
                asset_bodies.append(asset_body)
        assert b'transaction1_1' in asset_bodies
        assert b'transaction1_2' in asset_bodies
        assert b'transaction1_3' in asset_bodies

    def test_06_search_transaction_direction_backward(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        clients[0]['app'].traverse_transactions(transactions2[4].transaction_id, direction=1, hop_count=3)
        dat = clients[0]['app'].callback.synchronize()
        assert dat[KeyType.status] == 0
        assert KeyType.transaction_tree in dat
        assert len(dat[KeyType.transaction_tree]) == 3
        asset_bodies = list()
        for i, txtree in enumerate(dat[KeyType.transaction_tree]):
            for txdat in txtree:
                txobj = bbclib.BBcTransaction(deserialize=txdat)
                asset_body = txobj.events[0].asset.asset_body
                print("[%d] asset=%s" % (i, asset_body))
                asset_bodies.append(asset_body)
        assert b'transaction2_4' in asset_bodies
        assert b'transaction2_3' in asset_bodies
        assert b'transaction2_2' in asset_bodies

    def test_07_search_transaction_direction_forward(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        clients[0]['app'].traverse_transactions(transactions2[4].transaction_id, direction=0, hop_count=10)
        dat = clients[0]['app'].callback.synchronize()
        assert dat[KeyType.status] == 0
        assert KeyType.transaction_tree in dat
        assert KeyType.all_included in dat and not dat[KeyType.all_included]
        print("*Expected sequences: 4-5-6-7-8, 4-5-9-10-11-12-13-14 (total txobj count=11)")
        assert len(dat[KeyType.transaction_tree]) == 8   # "4-5-9-10-11-12-13-14"
        asset_bodies = list()
        for i, txtree in enumerate(dat[KeyType.transaction_tree]):
            for txdat in txtree:
                txobj = bbclib.BBcTransaction(deserialize=txdat)
                asset_body = txobj.events[0].asset.asset_body
                print("[%d] asset=%s" % (i, asset_body))
                asset_bodies.append(asset_body)

    @pytest.mark.unregister
    def test_98_unregister(self):
        for cl in clients:
            ret = cl['app'].unregister_from_core()
            assert ret


if __name__ == '__main__':
    pytest.main()
