#!/bin/sh
""":" .

exec python "$0" "$@"
"""
# -*- coding: utf-8 -*-
"""
Copyright (c) 2017 beyond-blockchain.org.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
import argparse
import binascii
import datetime
import hashlib
import os

import sys
sys.path.extend(["../../"])
from bbc1.app import bbc_app
from bbc1.core.bbc_config import DEFAULT_CORE_PORT
from bbc1.common import bbclib
from bbc1.common.message_key_types import KeyType
from bbc1.common.bbc_error import *


PRIVATE_KEY = ".private_key"
PUBLIC_KEY = ".public_key"

domain_id = bbclib.get_new_id("file_proof_test_domain", include_timestamp=False)
asset_group_id = bbclib.get_new_id("file_proof_asset_group", include_timestamp=False)
user_name = "user_default"
user_id = None

key_pair = None


def domain_setup():
    tmpclient = bbc_app.BBcAppClient(port=DEFAULT_CORE_PORT, loglevel="all")
    tmpclient.domain_setup(domain_id, "simple_cluster")
    tmpclient.callback.synchronize()
    tmpclient.unregister_from_core()
    print("Domain %s is created." % (binascii.b2a_hex(domain_id[:4]).decode()))
    print("Setup is done.")


def setup_bbc_client():
    bbc_app_client = bbc_app.BBcAppClient(port=DEFAULT_CORE_PORT, loglevel="all")
    bbc_app_client.set_user_id(user_id)
    bbc_app_client.set_domain_id(domain_id)
    bbc_app_client.set_callback(bbc_app.Callback())
    ret = bbc_app_client.register_to_core()
    assert ret
    return bbc_app_client


def require_receiver_info_for(filename):
    print("Your name is [", user_name, "] and user_id is [", binascii.b2a_hex(user_id).decode(), "]")
    print("Please enter the receiver user_id for file %s." % filename)
    receiver_name = input('>> ')
    receiver_user_id = bbclib.get_new_id(receiver_name, include_timestamp=False)
    return receiver_name, receiver_user_id


def search_reference_txid_from_mappings(filename):
    reference_txid = None
    file_info = bbc_app.get_id_from_mappings(os.path.basename(filename), asset_group_id)
    if file_info:
        reference_txid = file_info["transaction_id"]
    return reference_txid


def create_transaction_object_for_filedata(receiver_name, receiver_user_id, ref_txids=None, file_data=None,
                                           bbc_app_client=None):
    if ref_txids is None or ref_txids[0] is None:
        ref_txids = []
    transaction = bbclib.make_transaction_for_base_asset(asset_group_id=asset_group_id, event_num=1)

    user_info_msg = "Ownership is transfered from %s to %s" % (user_name, receiver_name)
    transaction.events[0].asset.add(user_id=receiver_user_id,
                                    asset_body=user_info_msg,
                                    asset_file=file_data)
    transaction.events[0].add(mandatory_approver=receiver_user_id)

    for i, ref_txid in enumerate(ref_txids):
        bbc_app_client.search_transaction(asset_group_id, ref_txid)
        response_data = bbc_app_client.callback.synchronize()
        if response_data[KeyType.status] < ESUCCESS:
            print("ERROR: ", response_data[KeyType.reason].decode())
            sys.exit(0)
        prev_tx = bbclib.recover_transaction_object_from_rawdata(response_data[KeyType.transaction_data])
        bbclib.add_reference_to_transaction(asset_group_id, transaction, prev_tx, 0)

    sig_mine = transaction.sign(key_type=bbclib.KeyType.ECDSA_SECP256k1,
                                private_key=key_pair.private_key,
                                public_key=key_pair.public_key)
    transaction.references[0].add_signature(user_id=user_id, signature=sig_mine)

    asset_id = transaction.events[0].asset.asset_id
    asset_files = {asset_id: file_data}
    ret = bbc_app_client.gather_signatures(asset_group_id, transaction, destinations=[receiver_user_id],
                                           asset_files=asset_files)
    if not ret:
        print("Failed to send sign request")
        sys.exit(0)
    response_data = bbc_app_client.callback.synchronize()
    if response_data[KeyType.status] < ESUCCESS:
        print("Rejected because ", response_data[KeyType.reason].decode(), "")
        sys.exit(0)
    result = response_data[KeyType.result]
    transaction.get_sig_index(receiver_user_id)
    transaction.references[result[0]].add_signature(user_id=result[1], signature=result[2])

    transaction.digest()
    return transaction


def insert_signed_transaction_to_bbc_core(transaction=None, bbc_app_client=None, file_name=None):
    print("Insert the transaction into BBc-1")
    ret = bbc_app_client.insert_transaction(asset_group_id, transaction)
    assert ret
    response_data = bbc_app_client.callback.synchronize()
    if response_data[KeyType.status] < ESUCCESS:
        print("ERROR: ", response_data[KeyType.reason].decode())
        sys.exit(0)
    bbc_app.remove_id_mappings(os.path.basename(file_name), asset_group_id)


def send_transaction_info_msg(bbc_app_client=None, transaction=None, file_name=None, receiver_user_id=None):
    transaction_info = [os.path.basename(file_name), transaction.transaction_id]
    bbc_app_client.send_message(transaction_info, asset_group_id, receiver_user_id)


def wait_for_transaction_msg(bbc_app_client=None):
    print("Your name is [", user_name, "] and user_id is [", binascii.b2a_hex(user_id).decode(), "]")
    print("Waiting for file transfer.....")
    response_data = bbc_app_client.callback.synchronize()
    if KeyType.transaction_data not in response_data or KeyType.all_asset_files not in response_data:
        print("**** Invalid message is received...")
        print(response_data)
        bbc_app_client.sendback_denial_of_sign(asset_group_id, response_data[KeyType.source_user_id],
                                               "Invalid message is received.")
        sys.exit(1)
    return response_data


def pick_valid_transaction_info(received_data=None, bbc_app_client=None):
    transaction = bbclib.BBcTransaction()
    transaction.deserialize(received_data[KeyType.transaction_data])
    asset_files = received_data[KeyType.all_asset_files]
    asset_id = transaction.events[0].asset.asset_id
    if asset_id not in asset_files:
        print("**** No valid file is received...")
        print(received_data)
        bbc_app_client.sendback_denial_of_sign(asset_group_id, received_data[KeyType.source_user_id],
                                               "No valid file is received.")
        sys.exit(1)

    file_to_obtain = asset_files[asset_id]
    file_digest = hashlib.sha256(file_to_obtain).digest()
    print("--------------------------")
    print("File digest written in the transaction data:  ",
          binascii.b2a_hex(transaction.events[0].asset.asset_file_digest).decode())
    print("File digest calculated from the received file:", binascii.b2a_hex(file_digest).decode())
    print("--------------------------")
    return transaction, received_data[KeyType.source_user_id]


def prompt_user_to_accept_the_file(bbc_app_client=None, source_id=None):
    print("====> Do you want to accept the file?")
    answer = input('(Y/N) >> ')
    if answer != "Y":
        bbc_app_client.sendback_denial_of_sign(asset_group_id, source_id, "Denied to accept the file")
        sys.exit(1)


def wait_for_file_info_msg(bbc_app_client=None):
    print("Waiting for the message from the sender...")
    response_data = bbc_app_client.callback.synchronize(timeout=10)
    if response_data is None:
        print("No final message received... Ask the sender about the filename and transaction_id")
        sys.exit(0)
    if KeyType.message not in response_data:
        print("Received invalid message....")
        sys.exit(0)
    filename, transaction_id = response_data[KeyType.message]
    print("--> file name is %s and the transaction_id is %s" % (filename.decode(),
                                                                binascii.b2a_hex(transaction_id).decode()))
    return filename, transaction_id


def store_proc(file, txid=None):
    with open(file, "rb") as fin:
        data = fin.read()
    bbc_app_client = setup_bbc_client()

    store_transaction = bbclib.make_transaction_for_base_asset(asset_group_id=asset_group_id, event_num=1)
    user_info = "Owner is %s" % user_name
    store_transaction.events[0].add(mandatory_approver=user_id)
    store_transaction.events[0].asset.add(user_id=user_id,
                                          asset_body=user_info,
                                          asset_file=data)
    if txid:
        bbc_app_client.search_transaction(asset_group_id, txid)
        response_data = bbc_app_client.callback.synchronize()
        if response_data[KeyType.status] < ESUCCESS:
            print("ERROR: ", response_data[KeyType.reason].decode())
            sys.exit(0)
        prev_tx = bbclib.recover_transaction_object_from_rawdata(response_data[KeyType.transaction_data])
        reference = bbclib.add_reference_to_transaction(asset_group_id, store_transaction, prev_tx, 0)
        sig = store_transaction.sign(key_type=bbclib.KeyType.ECDSA_SECP256k1,
                                     private_key=key_pair.private_key,
                                     public_key=key_pair.public_key)
        store_transaction.references[0].add_signature(user_id=user_id, signature=sig)
    else:
        sig = store_transaction.sign(key_type=bbclib.KeyType.ECDSA_SECP256k1,
                                     private_key=key_pair.private_key,
                                     public_key=key_pair.public_key)
        store_transaction.get_sig_index(user_id)
        store_transaction.add_signature(user_id=user_id, signature=sig)
    store_transaction.digest()

    ret = bbc_app_client.insert_transaction(asset_group_id, store_transaction)
    assert ret
    response_data = bbc_app_client.callback.synchronize()
    if response_data[KeyType.status] < ESUCCESS:
        print("ERROR: ", response_data[KeyType.reason].decode())
        sys.exit(0)

    bbc_app.store_id_mappings(os.path.basename(file), asset_group_id,
                              transaction_id=response_data[KeyType.transaction_id],
                              asset_ids=store_transaction.events[0].asset.asset_id)


def store_file(file):
    fileinfo = bbc_app.get_id_from_mappings(os.path.basename(file), asset_group_id)
    if fileinfo is not None:
        print("the file already stored : %s" % os.path.basename(file))
        sys.exit(0)
    store_proc(file=file, txid=None)
    print("file stored : %s" % os.path.basename(file))
    print("done store %s" % file)


def get_file(file):
    fileinfo = bbc_app.get_id_from_mappings(os.path.basename(file), asset_group_id)
    if fileinfo is None:
        print("Not exists in local mapping cache. So, asset_id is not known...")
        sys.exit(1)

    bbc_app_client = setup_bbc_client()
    ret = bbc_app_client.search_asset(asset_group_id, fileinfo["asset_id"])
    assert ret
    response_data = bbc_app_client.callback.synchronize()
    if response_data[KeyType.status] < ESUCCESS:
        print("ERROR: ", response_data[KeyType.reason].decode())
        sys.exit(0)

    get_transaction = bbclib.recover_transaction_object_from_rawdata(response_data[KeyType.transaction_data])
    if KeyType.asset_file in response_data:
        data = response_data[KeyType.asset_file]
    else:
        data = get_transaction.events[0].asset.asset_body
    out_file_name = file
    if os.path.exists(out_file_name):
        current_datetime = datetime.datetime.now()
        time_str = current_datetime.strftime('_%Y%m%d%H%M%S')
        out_file_name += time_str
    with open(out_file_name, "wb") as outfile:
        outfile.write(data)
    print("done get %s" % out_file_name)


def remove_file(file):
    fileinfo = bbc_app.get_id_from_mappings(os.path.basename(file), asset_group_id)
    if fileinfo is None:
        print("File does not exist: %s" % os.path.basename(file))
        sys.exit(0)
    fileinfo = bbc_app.remove_id_mappings(os.path.basename(file), asset_group_id)
    print("done remove %s" % file)


def list_file():
    fileinfo = bbc_app.get_list_from_mappings(asset_group_id)
    if fileinfo is None:
        print("No files present in local mapping cache. So, asset_id is not known...")
        sys.exit(1)
    print("%s" % '\n'.join(fileinfo))


def update_file(file):
    fileinfo = bbc_app.get_id_from_mappings(os.path.basename(file), asset_group_id)
    if fileinfo is None:
        print("Not exists in local mapping cache. So, transaction_id is not known...")
        sys.exit(1)
    transaction_id = fileinfo["transaction_id"]
    # TODO consider whether to check existence of the transaction object
    store_proc(file=file, txid=transaction_id)
    print("done update %s" % os.path.basename(file))


def verify_file(file):
    fileinfo = bbc_app.get_id_from_mappings(os.path.basename(file), asset_group_id)
    if fileinfo is None:
        print("Not exists in local mapping cache. So, asset_id is not known...")
        sys.exit(1)

    bbc_app_client = setup_bbc_client()
    ret = bbc_app_client.search_asset(asset_group_id, fileinfo["asset_id"])
    assert ret
    response_data = bbc_app_client.callback.synchronize()
    if response_data[KeyType.status] < ESUCCESS:
        print("ERROR: ", response_data[KeyType.reason].decode())
        sys.exit(0)

    transaction = bbclib.recover_transaction_object_from_rawdata(response_data[KeyType.transaction_data])
    digest = transaction.digest()
    ret = transaction.signatures[0].verify(digest)
    if not ret:
        print("Transaction data is invalid.")
        sys.exit(1)
    with open(file, "rb") as fin:
        data = fin.read()

    file_digest = hashlib.sha256(data).digest()
    if file_digest == transaction.events[0].asset.asset_file_digest:
        print("%s is valid" % file)
    else:
        print("%s is invalid" % file)
    print("done verify %s" % os.path.basename(file))
    print("Content of the transaction:::")
    transaction.dump()


def create_keypair():
    keypair = bbclib.KeyPair()
    keypair.generate()
    with open(PRIVATE_KEY, "wb") as fout:
        fout.write(keypair.private_key)
    with open(PUBLIC_KEY, "wb") as fout:
        fout.write(keypair.public_key)
    print("created private_key and public_key : %s, %s" % (PRIVATE_KEY, PUBLIC_KEY))


def enter_file_wait_mode():
    bbc_app_client = setup_bbc_client()

    recvdat = wait_for_transaction_msg(bbc_app_client=bbc_app_client)
    transaction, source_id = pick_valid_transaction_info(received_data=recvdat,
                                                         bbc_app_client=bbc_app_client)

    prompt_user_to_accept_the_file(bbc_app_client=bbc_app_client, source_id=source_id)
    signature = transaction.sign(keypair=key_pair)
    bbc_app_client.sendback_signature(asset_group_id, source_id, -1, signature)
    filename, transaction_id = wait_for_file_info_msg(bbc_app_client=bbc_app_client)

    bbc_app.store_id_mappings(os.path.basename(filename.decode()),
                              asset_group_id,
                              transaction_id=transaction_id,
                              asset_ids=transaction.events[0].asset.asset_id)


def enter_file_send_mode(filename):
    receiver_name, receiver_user_id = require_receiver_info_for(filename)
    with open(filename, "rb") as fin:
        file_data = fin.read()
    txid_for_reference = search_reference_txid_from_mappings(filename)

    bbc_app_client = setup_bbc_client()
    transfer_transaction = create_transaction_object_for_filedata(receiver_name,
                                                                  receiver_user_id,
                                                                  ref_txids=[txid_for_reference],
                                                                  file_data=file_data,
                                                                  bbc_app_client=bbc_app_client)
    insert_signed_transaction_to_bbc_core(transaction=transfer_transaction,
                                          bbc_app_client=bbc_app_client,
                                          file_name=filename)
    send_transaction_info_msg(bbc_app_client=bbc_app_client,
                              transaction=transfer_transaction,
                              file_name=filename,
                              receiver_user_id=receiver_user_id)
    print("Transfer is done.....")


def sys_check(args):
    if args.command_type in ("store", "update", "verify") and \
            not os.path.exists(args.target_file):
        raise Exception("file not found : %s" % args.target_file)
    # TODO consider whether to check core accessibility
    if args.command_type != "keypair":
        if not os.path.exists(PRIVATE_KEY):
            message = "not exist private key\n"
            message += "create a key pair with keypair option"
            raise Exception(message)
        if not os.path.exists(PUBLIC_KEY):
            message = "not exist public key\n"
            message += "create a key pair with keypair option"
            raise Exception(message)
        with open(PRIVATE_KEY, "rb") as fin:
            private_key = fin.read()
        with open(PUBLIC_KEY, "rb") as fin:
            public_key = fin.read()
        global key_pair
        key_pair = bbclib.KeyPair(privkey=private_key, pubkey=public_key)


def argument_parser():
    argparser = argparse.ArgumentParser()
    subparsers = argparser.add_subparsers(dest="command_type", help='commands')
    # put command
    store_parser = subparsers.add_parser('store', help='Store a file')
    store_parser.add_argument('target_file', action='store', help='A target file')
    store_parser.add_argument('-o', '--user', action='store', help='Your name (for calculating user_id)',
                              default='user_default')
    # get command
    get_parser = subparsers.add_parser('get', help='Get a file')
    get_parser.add_argument('target_file', action='store', help='A target file')
    get_parser.add_argument('-o', '--user', action='store', help='Your name (for calculating user_id)',
                            default='user_default')
    # remove command
    get_parser = subparsers.add_parser('remove', help='Remove a file')
    get_parser.add_argument('target_file', action='store', help='A target file')
    get_parser.add_argument('-o', '--user', action='store', help='Your name (for calculating user_id)',
                            default='user_default')
    # list command
    list_parser = subparsers.add_parser('list', help='Get a file list')
    list_parser.add_argument('-o', '--user', action='store', help='Your name (for calculating user_id)',
                            default='user_default')
    # update command
    update_parser = subparsers.add_parser('update', help='Update a file')
    update_parser.add_argument('target_file', action='store', help='A target file')
    update_parser.add_argument('-o', '--user', action='store', help='Your name (for calculating user_id)',
                               default='user_default')
    # verify command
    verify_parser = subparsers.add_parser('verify', help='Verify a file')
    verify_parser.add_argument('target_file', action='store', help='A target file')
    verify_parser.add_argument('-o', '--user', action='store', help='Your name (for calculating user_id)',
                               default='user_default')
    # key pair command
    subparsers.add_parser('keypair', help='Create a key pair')
    # wait mode for receiving file
    wait_parser = subparsers.add_parser('wait', help='Wait for receiving a file')
    wait_parser.add_argument('-o', '--user', action='store', help='Your name (for calculating user_id)',
                             default='user_default')
    # send mode
    send_parser = subparsers.add_parser('send', help='Send a file')
    send_parser.add_argument('target_file', action='store', help='A target file')
    send_parser.add_argument('-o', '--user', action='store', help='Your name (for calculating user_id)',
                             default='user_default')

    # setup command
    store_parser = subparsers.add_parser('setup', help='Setup domain and asset group')
    return argparser.parse_args()


if __name__ == '__main__':
    parsed_args = argument_parser()
    try:
        sys_check(parsed_args)
    except Exception as e:
        print(str(e))
        sys.exit(0)

    if parsed_args.command_type == "keypair":
        create_keypair()
    elif parsed_args.command_type == "setup":
        domain_setup()
    else:
        user_name = parsed_args.user
        user_id = bbclib.get_new_id(user_name, include_timestamp=False)
        if parsed_args.command_type == "store":
            store_file(file=parsed_args.target_file)
        elif parsed_args.command_type == "get":
            get_file(file=parsed_args.target_file)
        elif parsed_args.command_type == "remove":
            remove_file(file=parsed_args.target_file)
        elif parsed_args.command_type == "list":
            list_file()
        elif parsed_args.command_type == "update":
            update_file(file=parsed_args.target_file)
        elif parsed_args.command_type == "verify":
            verify_file(file=parsed_args.target_file)
        elif parsed_args.command_type == "wait":
            enter_file_wait_mode()
        elif parsed_args.command_type == "send":
            enter_file_send_mode(filename=parsed_args.target_file)
    sys.exit(0)
