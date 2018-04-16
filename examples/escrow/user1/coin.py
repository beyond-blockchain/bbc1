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
import sys
import os
import datetime
import binascii
import json
from datetime import datetime

sys.path.extend(["../../../"])
from bbc1.common import bbclib
from bbc1.app import bbc_app
from bbc1.core.bbc_config import DEFAULT_CORE_PORT
from bbc1.common.message_key_types import KeyType
from bbc1.common.bbc_error import *

PRIVATE_KEY = ".private_key"
PUBLIC_KEY = ".public_key"

domain_id = bbclib.get_new_id("coindomain", include_timestamp=False)
asset_group_id = bbclib.get_new_id("coin_asset_group", include_timestamp=False)
user_id = None

key_pair = None
bbc_app_client = None


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
    #bbc_app_client.set_asset_group_id(asset_group_id)
    bbc_app_client.set_callback(bbc_app.Callback())
    ret = bbc_app_client.register_to_core()
    assert ret
    return bbc_app_client


def store_proc(data, approver_id, txid=None):
    bbc_app_client = setup_bbc_client()
    transaction = bbclib.make_transaction_for_base_asset(asset_group_id=asset_group_id, event_num=1)
    transaction.events[0].add(mandatory_approver=approver_id, asset_group_id=asset_group_id)
    transaction.events[0].asset.add(user_id=user_id, asset_body=data)
    if txid:
        bbc_app_client.search_transaction(txid)
        response_data = bbc_app_client.callback.synchronize()
        if response_data[KeyType.status] < ESUCCESS:
            print("ERROR: ", response_data[KeyType.reason].decode())
            sys.exit(0)
        prev_tx = bbclib.recover_transaction_object_from_rawdata(response_data[KeyType.transaction_data])
        reference = bbclib.add_reference_to_transaction(asset_group_id, transaction, prev_tx, 0)
        sig = transaction.sign(key_type=bbclib.KeyType.ECDSA_SECP256k1,
                                     private_key=key_pair.private_key,
                                     public_key=key_pair.public_key)
        transaction.references[0].add_signature(user_id=user_id, signature=sig)
    else:
        sig = transaction.sign(key_type=bbclib.KeyType.ECDSA_SECP256k1,
                                     private_key=key_pair.private_key,
                                     public_key=key_pair.public_key)
        transaction.add_signature(signature=sig)
    transaction.digest()
    transaction.dump()

    ret = bbc_app_client.insert_transaction(transaction)
    assert ret
    response_data = bbc_app_client.callback.synchronize()
    if response_data[KeyType.status] < ESUCCESS:
        print("ERROR: ", response_data[KeyType.reason].decode())
        sys.exit(0)
    print("TxID: %s", binascii.b2a_hex(response_data[KeyType.transaction_id]))
    print("AsID: %s", binascii.b2a_hex(transaction.events[0].asset.asset_id))

    txinfo = [transaction.transaction_id, transaction.events[0].asset.asset_id]
    return txinfo


def get_coindata(asid):
    bbc_app_client = setup_bbc_client()
    asid = binascii.unhexlify(asid)
    ret = bbc_app_client.search_transaction_with_condition(asset_group_id, asid)
    assert ret
    response_data = bbc_app_client.callback.synchronize()
    if response_data[KeyType.status] < ESUCCESS:
        print("ERROR: ", response_data[KeyType.reason].decode())
        sys.exit(0)
    get_transaction = bbclib.BBcTransaction()
    get_transaction.deserialize(response_data[KeyType.transactions][0])

    retdata = get_transaction.events[0].asset.asset_body
    refdata = get_transaction.references
    print("get: %s" % retdata)
    print("ref: %s" % refdata)
    return retdata

def create_keypair():
    keypair = bbclib.KeyPair()
    keypair.generate()
    with open(PRIVATE_KEY, "wb") as fout:
        fout.write(keypair.private_key)
    with open(PUBLIC_KEY, "wb") as fout:
        fout.write(keypair.public_key)
    print("created private_key and public_key : %s, %s" % (PRIVATE_KEY, PUBLIC_KEY))

def registration(price):
    data = {"owner":binascii.b2a_hex(user_id).decode("UTF-8"),"price":price,"date":datetime.now().strftime('%s')}
    jsondata = json.dumps(data)
    store_proc(data=jsondata, approver_id=user_id ,txid=None)
    print("Coin is generated!: %s" % jsondata)

def chown(new_owner,asid):
    asset = json.loads(get_coindata(asid).decode("UTF-8"))
    if asset["owner"] != binascii.b2a_hex(user_id).decode("UTF-8"):
        print("Owner of this coin is not you")
        return 0
    asset["owner"] = new_owner
    asset["date"] = datetime.now().strftime('%s')
    data = json.dumps(asset)

    bbc_app_client = setup_bbc_client()
    asid = binascii.unhexlify(asid)
    ret = bbc_app_client.search_transaction_with_condition(asset_group_id, asid)
    assert ret
    response_data = bbc_app_client.callback.synchronize()
    if response_data[KeyType.status] < ESUCCESS:
        print("ERROR: ", response_data[KeyType.reason].decode())
        sys.exit(0)
    get_transaction = bbclib.BBcTransaction()
    get_transaction.deserialize(response_data[KeyType.transactions][0])
    transaction_id = get_transaction.transaction_id
    transaction_info = store_proc(data, approver_id=binascii.unhexlify(new_owner),txid=transaction_id)
    bbc_app_client.send_message(transaction_info, binascii.unhexlify(new_owner))
    print("Transfer is done.....")


if __name__ == '__main__':
    if(not os.path.exists(PRIVATE_KEY) and not os.path.exists(PUBLIC_KEY)):
        create_keypair()
    with open(PRIVATE_KEY, "rb") as fin:
        private_key = fin.read()
    with open(PUBLIC_KEY, "rb") as fin:
        public_key = fin.read()

    domain_setup()

    key_pair = bbclib.KeyPair(privkey=private_key, pubkey=public_key)
    user_id = bbclib.get_new_id(str(binascii.b2a_hex(key_pair.public_key)), include_timestamp=False)
    print("welcome to sample coin manage!")
    print("Your id: %s" % binascii.b2a_hex(user_id))
    print("Type command(help to see command list)")
    while(True):
        command = input('>> ')
        if command == "help":
            print("generate - generate coin")
            print("get - get coin info")
            print("send - send coin")
            print("recieve - wait for recieve coin")
            print("exit - exit coin manage")
        elif command == "generate":
            print("Type price generate coin")
            address = input('>> ')
            registration(address)
        elif command == "get":
            print("Type AsID of coin")
            asid = input('>> ')
            get_coindata(asid)
        elif command == "send":
            print("Type AsID of coin")
            asid = input('>> ')
            asset = json.loads(get_coindata(asid).decode("UTF-8"))
            assert asset
            print("You want send coin(%s)"% asid)
            print("Type new owner ID")
            new_owner = input('>> ')
            chown(new_owner,asid)
        elif command == "exit":
            print("bye")
            sys.exit(0)
        else:
            print("command \""+command+"\" is not found")
