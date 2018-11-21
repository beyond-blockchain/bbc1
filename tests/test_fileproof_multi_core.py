# -*- coding: utf-8 -*-
import pytest

import binascii
import time
import hashlib
import os

import sys
sys.path.extend(["../"])
from bbc1.core import bbclib
from bbc1.core.message_key_types import KeyType
from bbc1.core.bbc_error import *
from bbc1.core.bbc_config import DEFAULT_CORE_PORT
from bbc1.core import bbc_app
from examples.file_proof import file_proof
import testutils
from testutils import prepare, start_core_thread


LOGLEVEL = 'debug'
#LOGLEVEL = 'info'


core_num = 2
client_num = 2
cores = [None for i in range(core_num)]
clients = [None for i in range(client_num)]
keypairs = [None for i in range(client_num)]

domain_id = bbclib.get_new_id("file_proof_test_domain", include_timestamp=False)
asset_group_id = bbclib.get_new_id("file_proof_asset_group", include_timestamp=False)
user_ids = [bbclib.get_new_id("user_%d" % i) for i in range(client_num)]

transaction_id = None
asset_id = None
large_data = b"aaaaaaaaaa" * 200


def setup_bbc_client(port_increase=0, user_id=None):
    bbc_app_client = bbc_app.BBcAppClient(port=DEFAULT_CORE_PORT + port_increase, multiq=False, loglevel="all")
    bbc_app_client.set_user_id(user_id)
    bbc_app_client.set_domain_id(domain_id)
    bbc_app_client.set_callback(bbc_app.Callback())
    if os.path.exists(os.path.join(".bbc1-900%d" % port_increase, "node_key.pem")):
        bbc_app_client.set_node_key(os.path.join(".bbc1-900%d" % port_increase, "node_key.pem"))
    bbc_app_client.domain_setup(domain_id)
    bbc_app_client.callback.synchronize()
    return bbc_app_client


def create_transaction_object_and_send_sign_req(idx, receiver_user_id, ref_txids=None, file_data=None):
    if ref_txids is None or ref_txids[0] is None:
        ref_txids = []

    txobj = bbclib.make_transaction(relation_num=1, witness=True)
    bbclib.add_relation_asset(txobj, relation_idx=0, asset_group_id=asset_group_id,
                                   user_id=receiver_user_id, asset_body="transferred", asset_file=file_data)
    txobj.witness.add_witness(user_ids[idx])
    txobj.witness.add_witness(receiver_user_id)

    for i, ref_txid in enumerate(ref_txids):
        clients[idx].search_transaction(ref_txid)
        response_data = clients[idx].callback.synchronize()
        if response_data[KeyType.status] < ESUCCESS:
            print("ERROR: ", response_data[KeyType.reason].decode())
            sys.exit(0)
        prev_tx, fmt_type = bbclib.deserialize(response_data[KeyType.transaction_data])
        bbclib.add_relation_pointer(txobj, 0, ref_transaction_id=prev_tx.digest())

    sig_mine = txobj.sign(private_key=keypairs[idx].private_key, public_key=keypairs[idx].public_key)
    txobj.witness.add_signature(user_id=user_ids[idx], signature=sig_mine)

    asset_id = txobj.relations[0].asset.asset_id
    asset_files = {asset_id: file_data}
    ret = clients[idx].gather_signatures(txobj, destinations=[receiver_user_id], asset_files=asset_files)
    assert ret
    return txobj


class TestFileProofClient(object):

    def test_00_setup(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        print("domain_id =", binascii.b2a_hex(domain_id))

        prepare(core_num=core_num, client_num=client_num, loglevel=LOGLEVEL)
        for i in range(core_num):
            start_core_thread(index=i, core_port_increment=i, p2p_port_increment=i)
        time.sleep(1)

        global cores
        cores = testutils.cores

        for i in range(client_num):
            clients[i] = setup_bbc_client(i, user_ids[i])
            ret = clients[i].register_to_core()
            assert ret
            keypairs[i] = bbclib.KeyPair()
            keypairs[i].generate()
        time.sleep(1)

    def test_01_setup_network(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")

        clients[0].get_domain_neighborlist(domain_id=domain_id)
        dat = clients[0].callback.synchronize()
        print("[0] nodeinfo=",dat[0])
        node_id, ipv4, ipv6, port, domain0 = dat[0]

        clients[1].send_domain_ping(domain_id, ipv4, ipv6, port)  # if this line is commented out, error occurs later.

        time.sleep(3)

        for i in range(client_num):
            clients[i].get_domain_neighborlist(domain_id=domain_id)
            dat = clients[i].callback.synchronize()
            print("[%d]--> " % i)
            for k in range(len(dat)):
                node_id, ipv4, ipv6, port, domain0 = dat[k]
                if k == 0:
                    print(" *myself*    %s, %s, %s, %d" % (binascii.b2a_hex(node_id[:4]), ipv4, ipv6, port))
                else:
                    print("             %s, %s, %s, %d" % (binascii.b2a_hex(node_id[:4]), ipv4, ipv6, port))

    def test_02_register(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        for cl in clients:
            ret = cl.register_to_core()
            assert ret
        time.sleep(1)

    def test_10_store_file(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        # -- first file store by user_0
        store_transaction = bbclib.make_transaction(relation_num=1, witness=True)
        bbclib.add_relation_asset(store_transaction, relation_idx=0, asset_group_id=asset_group_id,
                                  user_id=user_ids[0], asset_body="Owner is 0", asset_file=large_data)

        store_transaction.witness.add_witness(user_ids[0])
        sig = store_transaction.sign(private_key=keypairs[0].private_key, public_key=keypairs[0].public_key)
        store_transaction.get_sig_index(user_ids[0])
        store_transaction.add_signature(user_id=user_ids[0], signature=sig)
        store_transaction.digest()
        print(store_transaction)

        global transaction_id, asset_id
        transaction_id = store_transaction.transaction_id
        asset_id = store_transaction.relations[0].asset.asset_id
        clients[0].insert_transaction(store_transaction)
        response_data = clients[0].callback.synchronize()
        if response_data[KeyType.status] < ESUCCESS:
            print("ERROR: ", response_data[KeyType.reason].decode())
            assert False
        time.sleep(1)

    def test_11_verify_file(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        # -- verify by user_1
        clients[1].search_transaction_with_condition(asset_group_id=asset_group_id, asset_id=asset_id)
        response_data = clients[1].callback.synchronize()
        assert response_data[KeyType.status] == ESUCCESS

        txobj, fmt_type = bbclib.deserialize(response_data[KeyType.transactions][0])
        digest = txobj.digest()
        ret = txobj.signatures[0].verify(digest)
        assert ret

        file_digest = hashlib.sha256(large_data).digest()
        if file_digest == txobj.relations[0].asset.asset_file_digest:
            print("oooo valid")
        else:
            print("xxxx invalid")
        print(txobj)

    def test_20_send_and_wait_file(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        # -- sender
        file_proof.key_pair = keypairs[0]
        transfer_tx = file_proof.send_signreq("user1", user_ids[1], ref_txids=[transaction_id], file_data=large_data, bbc_app_client=clients[0])

        # -- receiver
        recvdat = file_proof.wait_for_transaction_msg(bbc_app_client=clients[1])
        txobj, source_id = file_proof.pick_valid_transaction_info(received_data=recvdat, bbc_app_client=clients[1])
        signature = txobj.sign(keypair=keypairs[1])
        clients[1].sendback_signature(source_id, txobj.transaction_id, -1, signature)

        # -- sender
        transfer_tx = file_proof.wait_for_signs(transfer_tx, clients[0])

        file_proof.insert_signed_transaction_to_bbc_core(transaction=transfer_tx, bbc_app_client=clients[0])
        transaction_info = ["testfile", transfer_tx.transaction_id]
        time.sleep(1)
        clients[0].send_message(transaction_info, user_ids[1])

        # -- receiver
        response_data = clients[1].callback.synchronize(timeout=10)
        assert response_data is not None
        assert KeyType.message in response_data
        filename, txid = response_data[KeyType.message]
        print("--> file name is %s and the transaction_id is %s" % (filename, txid))
        print(transfer_tx)

    def test_98_unregister(self):
        for cl in clients:
            ret = cl.unregister_from_core()
            assert ret

    def test_99_quit(self):
        for core in cores:
            core.networking.save_all_static_node_list()
            core.config.update_config()


if __name__ == '__main__':
    pytest.main()
