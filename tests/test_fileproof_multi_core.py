# -*- coding: utf-8 -*-
import pytest

import binascii
import time
import hashlib

import sys
sys.path.extend(["../"])
from bbc1.common import bbclib
from bbc1.common.message_key_types import KeyType
from bbc1.common.bbc_error import *
from bbc1.core.bbc_config import DEFAULT_CORE_PORT
from bbc1.app import bbc_app
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
    bbc_app_client = bbc_app.BBcAppClient(port=DEFAULT_CORE_PORT+port_increase, loglevel="all")
    bbc_app_client.set_user_id(user_id)
    bbc_app_client.set_domain_id(domain_id)
    bbc_app_client.set_callback(bbc_app.Callback())
    bbc_app_client.domain_setup(domain_id)
    bbc_app_client.callback.synchronize()
    return bbc_app_client


def create_transaction_object_and_send_sign_req(idx, receiver_user_id, ref_txids=None, file_data=None):
    if ref_txids is None or ref_txids[0] is None:
        ref_txids = []
    txobj = bbclib.make_transaction_for_base_asset(asset_group_id=asset_group_id, event_num=1)

    txobj.events[0].asset.add(user_id=receiver_user_id,
                              asset_body="transferred",
                              asset_file=file_data)
    txobj.events[0].add(mandatory_approver=receiver_user_id)

    for i, ref_txid in enumerate(ref_txids):
        clients[idx].search_transaction(ref_txid)
        response_data = clients[idx].callback.synchronize()
        assert response_data[KeyType.status] == ESUCCESS
        prev_tx = bbclib.recover_transaction_object_from_rawdata(response_data[KeyType.transaction_data])
        bbclib.add_reference_to_transaction(asset_group_id, txobj, prev_tx, 0)

    sig_mine = txobj.sign(key_type=bbclib.KeyType.ECDSA_SECP256k1,
                          private_key=keypairs[idx].private_key,
                          public_key=keypairs[idx].public_key)
    txobj.references[0].add_signature(user_id=user_ids[idx], signature=sig_mine)

    asset_id = txobj.events[0].asset.asset_id
    asset_files = {asset_id: file_data}
    ret = clients[idx].gather_signatures(txobj, destinations=[receiver_user_id], asset_files=asset_files)
    assert ret
    return txobj


def wait_for_transaction_msg(bbc_app_client=None):
    response_data = bbc_app_client.callback.synchronize()
    if KeyType.transaction_data not in response_data or KeyType.all_asset_files not in response_data:
        print("**** Invalid message is received...")
        print(response_data)
        bbc_app_client.sendback_denial_of_sign(response_data[KeyType.source_user_id],
                                               response_data[KeyType.transaction_id],
                                               "Invalid message is received.")
        assert False
    return response_data


def pick_valid_transaction_info(received_data=None, bbc_app_client=None):
    transaction = bbclib.BBcTransaction()
    transaction.deserialize(received_data[KeyType.transaction_data])
    asset_files = received_data[KeyType.all_asset_files]
    asid = transaction.events[0].asset.asset_id
    assert asid in asset_files
    file_to_obtain = asset_files[asid]
    file_digest = hashlib.sha256(file_to_obtain).digest()
    print("----------------[Receiver]----------------")
    print("File digest written in the transaction data:  ",
          binascii.b2a_hex(transaction.events[0].asset.asset_file_digest).decode())
    print("File digest calculated from the received file:", binascii.b2a_hex(file_digest).decode())
    print("------------------------------------------")
    return transaction, received_data[KeyType.source_user_id]


def insert_signed_transaction_to_bbc_core(tx_obj=None, bbc_app_client=None):
    print("Insert the transaction into BBc-1")
    ret = bbc_app_client.insert_transaction(tx_obj)
    assert ret
    response_data = bbc_app_client.callback.synchronize()
    assert response_data[KeyType.status] == ESUCCESS


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
        node_id, ipv4, ipv6, port = dat[0]

        clients[1].send_domain_ping(domain_id, ipv4, ipv6, port)  # if this line is commented out, error occurs later.

        time.sleep(3)

        for i in range(client_num):
            clients[i].get_domain_neighborlist(domain_id=domain_id)
            dat = clients[i].callback.synchronize()
            print("[%d]--> " % i)
            for k in range(len(dat)):
                node_id, ipv4, ipv6, port = dat[k]
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
        store_transaction = bbclib.make_transaction_for_base_asset(asset_group_id=asset_group_id, event_num=1)
        store_transaction.events[0].add(mandatory_approver=user_ids[0])
        store_transaction.events[0].asset.add(user_id=user_ids[0],
                                              asset_body="Owner is 0",
                                              asset_file=large_data)

        sig = store_transaction.sign(key_type=bbclib.KeyType.ECDSA_SECP256k1,
                                     private_key=keypairs[0].private_key,
                                     public_key=keypairs[0].public_key)
        store_transaction.get_sig_index(user_ids[0])
        store_transaction.add_signature(user_id=user_ids[0], signature=sig)
        store_transaction.digest()
        print(store_transaction)

        global transaction_id, asset_id
        transaction_id = store_transaction.transaction_id
        asset_id = store_transaction.events[0].asset.asset_id
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

        txobj = bbclib.recover_transaction_object_from_rawdata(response_data[KeyType.transactions][0])
        digest = txobj.digest()
        ret = txobj.signatures[0].verify(digest)
        assert ret

        file_digest = hashlib.sha256(large_data).digest()
        if file_digest == txobj.events[0].asset.asset_file_digest:
            print("oooo valid")
        else:
            print("xxxx invalid")
        print(txobj)

    def test_20_send_and_wait_file(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        # -- sender
        transfer_tx = create_transaction_object_and_send_sign_req(0, user_ids[1],
                                                                  ref_txids=[transaction_id], file_data=large_data)

        # -- receiver
        recvdat = wait_for_transaction_msg(bbc_app_client=clients[1])
        txobj, source_id = pick_valid_transaction_info(received_data=recvdat,
                                                       bbc_app_client=clients[1])
        signature = txobj.sign(keypair=keypairs[1])
        clients[1].sendback_signature(source_id, txobj.transaction_id, -1, signature)

        # -- sender
        response_data = clients[0].callback.synchronize()
        assert response_data[KeyType.status] == ESUCCESS
        result = response_data[KeyType.result]
        transfer_tx.references[result[0]].add_signature(user_id=result[1], signature=result[2])
        transfer_tx.digest()
        insert_signed_transaction_to_bbc_core(tx_obj=transfer_tx, bbc_app_client=clients[0])
        transaction_info = ["testfile", transfer_tx.transaction_id]
        clients[0].send_message(transaction_info, user_ids[1])

        # -- receiver
        response_data = clients[1].callback.synchronize(timeout=10)
        assert response_data is not None
        assert KeyType.message in response_data
        filename, txid = response_data[KeyType.message]
        print("--> file name is %s and the transaction_id is %s" % (filename, txid))

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
