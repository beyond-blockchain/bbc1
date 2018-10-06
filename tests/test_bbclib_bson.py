# -*- coding: utf-8 -*-
import pytest

import binascii
import sys
sys.path.extend(["../"])
from bbc1.core.bbclib import BBcTransaction, BBcEvent, BBcReference, BBcWitness, BBcRelation, BBcAsset, \
    BBcCrossRef, KeyPair, KeyType
from bbc1.core import bbclib

user_id = bbclib.get_new_id("user_id_test1")
user_id2 = bbclib.get_new_id("user_id_test2")
domain_id = bbclib.get_new_id("testdomain")
asset_group_id = bbclib.get_new_id("asset_group_1")
transaction1_id = bbclib.get_new_id("transaction_1")
transaction2_id = bbclib.get_new_id("transaction_2")
keypair1 = KeyPair()
keypair1.generate()
keypair2 = KeyPair()
keypair2.generate()

transaction1 = None
asset1 = None
asset2 = None
event1 = None
event2 = None
transaction2 = None
asset_content = b'abcdefg'
fmt = bbclib.BBcFormat.FORMAT_BSON_COMPRESS_BZ2

print("\n")
print("private_key:", binascii.b2a_hex(keypair1.private_key))
print("private_key(pem):\n", keypair1.get_private_key_in_pem())
print("public_key:", binascii.b2a_hex(keypair1.public_key))


class TestBBcLib(object):

    def test_00_keypair(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        global keypair1
        kp = KeyPair(pubkey=keypair1.public_key)
        assert kp.public_key

    def test_01_asset(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        global asset1, asset2
        asset1 = BBcAsset(user_id=user_id, asset_body=b'12345678', format_type=fmt)
        asset2 = BBcAsset(user_id=user_id, asset_file=asset_content, format_type=fmt)

        # --- for checking serialization function ---
        digest = asset1.digest()
        dat = asset1.serialize()
        print("Digest:", binascii.b2a_hex(digest))
        print("Serialized data:", dat)
        asset_tmp = BBcAsset(format_type=fmt)
        asset_tmp.deserialize(dat)
        print("body_len:", asset_tmp.asset_body_size)
        if asset_tmp.asset_body_size > 0:
            print("body:", binascii.b2a_hex(asset_tmp.asset_body))
        print("digest:", binascii.b2a_hex(asset_tmp.asset_id))

    def test_02_event(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        print("asset_group_id:", binascii.b2a_hex(asset_group_id))
        global event1, event2
        event1 = BBcEvent(asset_group_id=asset_group_id, format_type=fmt)
        event1.add(asset=asset1, mandatory_approver=user_id)
        event2 = BBcEvent(asset_group_id=asset_group_id, format_type=fmt)
        event2.add(asset=asset2, mandatory_approver=user_id)

        # --- for checking serialization function ---
        dat = event1.serialize()
        print("Serialized data:", dat)
        event_tmp = BBcEvent(format_type=fmt)
        event_tmp.deserialize(dat)
        print("mandatory_approvers:", [binascii.b2a_hex(d) for d in event_tmp.mandatory_approvers])
        print("asset_id:", binascii.b2a_hex(event_tmp.asset.asset_id))

    def test_03_transaction_1(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        global transaction1
        transaction1 = BBcTransaction(format_type=fmt)
        transaction1.add(event=[event1, event2])
        dummy_cross_ref1 = BBcCrossRef(domain_id=domain_id, transaction_id=transaction1_id, format_type=fmt)
        transaction1.add(cross_ref=dummy_cross_ref1)
        dummy_cross_ref2 = BBcCrossRef(domain_id=domain_id, transaction_id=transaction2_id, format_type=fmt)
        transaction1.add(cross_ref=dummy_cross_ref2)
        witness = BBcWitness(format_type=fmt)
        transaction1.add(witness=witness)

        sig = transaction1.sign(private_key=keypair1.private_key, public_key=keypair1.public_key)
        if sig is None:
            print(bbclib.error_text)
            assert sig
        transaction1.add_signature(signature=sig)

        # --- for checking serialization function ---
        digest = transaction1.digest()
        dat = transaction1.serialize()
        print("Digest:", binascii.b2a_hex(digest))
        print("Serialized data:", binascii.b2a_hex(dat))

        transaction_tmp = BBcTransaction()
        transaction_tmp.deserialize(dat)
        transaction1 = transaction_tmp
        #transaction1.events[1].asset.add(asset_file=asset_content)
        print("transaction_id:", binascii.b2a_hex(transaction1.transaction_id))
        print("transaction_id (recalc2):", binascii.b2a_hex(transaction1.digest()))
        asset_tmp = transaction1.events[0].asset
        print("asset_id1:", binascii.b2a_hex(asset_tmp.asset_id))
        asset_tmp = transaction1.events[1].asset
        print("asset_id2:", binascii.b2a_hex(asset_tmp.asset_id))
        print(" --> asset_file_size:", asset_tmp.asset_file_size)
        print(" --> asset_file_digest:", binascii.b2a_hex(asset_tmp.asset_file_digest))
        ret = asset_tmp.recover_asset_file(asset_content)
        assert ret
        print(" --> asset_file (after recover):", asset_tmp.asset_file)

    def test_04_transaction_with_reference(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        global transaction2, event3, asset3
        asset3 = BBcAsset(format_type=fmt)
        asset3.add(asset_body=b'bbbbbbb', user_id=user_id)
        event3 = BBcEvent(asset_group_id=asset_group_id, format_type=fmt)
        event3.add(asset=asset3, option_approver_num_numerator=1, option_approver_num_denominator=2)
        event3.add(option_approver=user_id)
        event3.add(option_approver=user_id2)

        transaction2 = BBcTransaction(format_type=fmt)
        transaction2.add(event=event3)
        reference2 = BBcReference(asset_group_id=asset_group_id,
                                  transaction=transaction2, ref_transaction=transaction1,
                                  event_index_in_ref=0, format_type=fmt)
        transaction2.add(reference=reference2)
        dummy_cross_ref3 = BBcCrossRef(domain_id=domain_id, transaction_id=transaction1_id, format_type=fmt)
        transaction2.add(cross_ref=dummy_cross_ref3)

        sig = transaction2.sign(private_key=keypair1.private_key, public_key=keypair1.public_key)
        if sig is None:
            print(bbclib.error_text)
            assert sig
        reference2.add_signature(user_id=user_id, signature=sig)

        print(transaction2)

    def test_05_transaction_with_reference2(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        asset1 = BBcAsset(format_type=fmt)
        asset1.add(user_id=user_id, asset_body=b'ccccc')
        event = BBcEvent(asset_group_id=asset_group_id, format_type=fmt)
        event.add(asset=asset1, option_approver_num_numerator=1, option_approver_num_denominator=2)
        event.add(option_approver=user_id)
        event.add(option_approver=user_id2)

        global transaction1
        transaction1 = BBcTransaction(format_type=fmt)
        transaction1.add(event=event)
        reference = BBcReference(asset_group_id=asset_group_id,
                                 transaction=transaction1, ref_transaction=transaction2,
                                 event_index_in_ref=0, format_type=fmt)
        transaction1.add(reference=reference)
        dummy_cross_ref = BBcCrossRef(domain_id=domain_id, transaction_id=transaction1_id, format_type=fmt)
        transaction2.add(cross_ref=dummy_cross_ref)

        sig = transaction1.sign(private_key=keypair2.private_key, public_key=keypair2.public_key)
        if sig is None:
            print(bbclib.error_text)
            assert sig
        reference.add_signature(user_id=user_id2, signature=sig)
        sig = transaction1.sign(private_key=keypair1.private_key, public_key=keypair1.public_key)
        if sig is None:
            print(bbclib.error_text)
            assert sig
        reference.add_signature(user_id=user_id, signature=sig)

        print(transaction1)

    def test_06_transaction_with_witness(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        witness = BBcWitness(format_type=fmt)

        global transaction1
        transaction1 = BBcTransaction(format_type=fmt)
        transaction1.add(witness=witness)

        witness.add_witness(user_id)
        witness.add_witness(user_id2)

        sig = transaction1.sign(private_key=keypair2.private_key, public_key=keypair2.public_key)
        if sig is None:
            print(bbclib.error_text)
            assert sig
        witness.add_signature(user_id=user_id2, signature=sig)

        sig = transaction1.sign(private_key=keypair1.private_key, public_key=keypair1.public_key)
        if sig is None:
            print(bbclib.error_text)
            assert sig
        witness.add_signature(user_id=user_id, signature=sig)

        print(transaction1)

    def test_06_transaction_with_relation_and_witness(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        transaction1 = bbclib.make_transaction(relation_num=1, witness=True, format_type=fmt)
        bbclib.add_relation_asset(transaction1, relation_idx=0, asset_group_id=asset_group_id,
                                  user_id=user_id, asset_body=b'ccccc')
        bbclib.add_relation_pointer(transaction1, 0, ref_transaction_id=transaction2.digest())
        transaction1.witness.add_witness(user_id)
        transaction1.witness.add_witness(user_id2)

        sig = transaction1.sign(private_key=keypair2.private_key, public_key=keypair2.public_key)
        if sig is None:
            print(bbclib.error_text)
            assert sig
        transaction1.witness.add_signature(user_id=user_id2, signature=sig)

        sig = transaction1.sign(private_key=keypair1.private_key, public_key=keypair1.public_key)
        if sig is None:
            print(bbclib.error_text)
            assert sig
        transaction1.witness.add_signature(user_id=user_id, signature=sig)

        print(transaction1)

    def test_07_proof(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")

        digest = transaction1.digest()
        ret = transaction1.signatures[0].verify(digest)
        print("Proof result:", ret)
        if not ret:
            print(bbclib.error_text)
            assert ret

    def test_08_proof(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        transaction1.timestamp = transaction1.timestamp + 1
        digest = transaction1.digest()
        ret = transaction1.signatures[0].verify(digest)
        assert not ret
