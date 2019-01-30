# -*- coding: utf-8 -*-
import pytest

import binascii
import sys
sys.path.extend(["../"])
from bbc1.core.bbclib import KeyPair
from bbc1.core import bbclib

users = list()
domain_id = bbclib.get_new_id("testdomain")
asset_group_id = bbclib.get_new_id("asset_group_1")


class TestBBcLib(object):

    def test_00_user_setup(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        global users
        for i in range(0, 5):
            users.append([bbclib.get_new_id("user_%d" % i), KeyPair()])
            users[i][1].generate()

    def test_01_transaction_with_relation(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        transaction1 = bbclib.make_transaction(relation_num=1, witness=True)
        bbclib.add_relation_asset(transaction1, relation_idx=0, asset_group_id=asset_group_id,
                                  user_id=users[0][0], asset_body=b'ccccc')
        for u in users:
            transaction1.witness.add_witness(user_id=u[0])

        packed_data = transaction1.pack()
        unpacked_txobj = bbclib.BBcTransaction()
        unpacked_txobj.unpack(packed_data)

        print(unpacked_txobj)
        for u in users:
            sig = unpacked_txobj.sign(keypair=u[1])
            unpacked_txobj.add_signature(user_id=u[0], signature=sig)
            transaction1.add_signature(user_id=u[0], signature=sig)

        original_packed_tx = transaction1.pack()
        recovered_packed_tx = unpacked_txobj.pack()

        assert original_packed_tx == recovered_packed_tx
        print(transaction1)

    def test_02_transaction_with_reference_relation(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        print("**** prepare original (previous) transaction to refer to")
        transaction1 = bbclib.make_transaction(event_num=1, witness=True)
        transaction1.events[0].add(mandatory_approver=users[0][0])
        transaction1.events[0].add(mandatory_approver=users[1][0])
        bbclib.add_event_asset(transaction1, event_idx=0, asset_group_id=asset_group_id, user_id=users[0][0], asset_body=b"data1")
        transaction1.witness.add_witness(user_id=users[0][0])
        sig = transaction1.sign(keypair=users[0][1])
        transaction1.add_signature(user_id=users[0][0], signature=sig)
        transaction1.digest()
        print(transaction1)

        transaction2 = bbclib.make_transaction(relation_num=1, witness=True)
        bbclib.add_relation_asset(transaction2, relation_idx=0, asset_group_id=asset_group_id,
                                  user_id=users[0][0], asset_body=b'ccccc')
        transaction2.witness.add_witness(user_id=users[2][0])
        bbclib.add_reference_to_transaction(transaction2, asset_group_id, transaction1, 0)
        transaction2.witness.add_witness(user_id=users[3][0])
        print(transaction2)

        packed_data = transaction2.pack()
        unpacked_txobj = bbclib.BBcTransaction()
        unpacked_txobj.unpack(packed_data)
        unpacked_txobj.references[0].prepare_reference(transaction1)
        #print(unpacked_txobj)

        for i in range(len(users)-2, -1, -1):
            sig = unpacked_txobj.sign(keypair=users[i][1])
            unpacked_txobj.add_signature(user_id=users[i][0], signature=sig)
            transaction2.add_signature(user_id=users[i][0], signature=sig)

        print(unpacked_txobj)
        original_packed_tx = transaction2.pack()
        recovered_packed_tx = unpacked_txobj.pack()
        assert original_packed_tx == recovered_packed_tx
