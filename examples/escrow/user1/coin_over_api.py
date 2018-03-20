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
import urllib.request, json


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

def bina2str(bina):
    return binascii.b2a_hex(bina).decode("utf-8")

def str2bina(str):
    str = str.encode("utf-8")
    return binascii.a2b_hex(str)


def tx_to_dict(tx):
    txdict = {}
    if tx.transaction_id is not None:
        txdict["transaction_id"] = bina2str(tx.transaction_id)
    else:
        txdict["transaction_id"] = None
    txdict["version"] = tx.version
    txdict["timestamp"] = tx.timestamp
    txdict["Event"] = []
    if len(tx.events) > 0:
        for i, evt in enumerate(tx.events):
            event = {}
            event["asset_group_id"] = bina2str(evt.asset_group_id)
            event["reference_indices"] = evt.reference_indices
            event["mandatory_approvers"] = []
            if len(evt.mandatory_approvers) > 0:
                for user in evt.mandatory_approvers:
                    event["mandatory_approvers"].append(bina2str(user))
            event["option_approvers"] = []
            if len(evt.option_approvers) > 0:
                for user in evt.option_approvers:
                    event["option_approvers"] = bina2str(user)
            event["option_approver_num_numerator"] = evt.option_approver_num_numerator
            event["option_approver_num_denominator"] = evt.option_approver_num_denominator
            event["Asset"] = {}
            event["Asset"]["asset_id"] = bina2str(evt.asset.asset_id)
            if evt.asset.user_id is not None:
                event["Asset"]["user_id"] = bina2str(evt.asset.user_id)
            else:
                event["Asset"]["user_id"] = None
            event["Asset"]["nonce"] = bina2str(evt.asset.nonce)
            event["Asset"]["file_size"] = evt.asset.asset_file_size
            if evt.asset.asset_file_digest is not None:
                event["Asset"]["file_digest"] = bina2str(evt.asset.asset_file_digest)
            event["Asset"]["body_size"] = evt.asset.asset_body_size
            event["Asset"]["body"] = bina2str(evt.asset.asset_body)
            txdict["Event"].append(event)
    txdict["Reference"] = []
    if len(tx.references) > 0:
        for i, refe in enumerate(tx.references):
            ref = {}
            ref["asset_group_id"] = bina2str(refe.asset_group_id)
            ref["transaction_id"] = bina2str(refe.transaction_id)
            ref["event_index_in_ref"] = refe.event_index_in_ref
            ref["sig_index"] = refe.sig_indices
            txdict["Reference"].append(ref)
    txdict["Cross_Ref"] = {}
    if len(tx.cross_refs) > 0:
        for i, cross in enumerate(tx.cross_refs):
            crossref = {}
            crossref["asset_group_id"] = bina2str(cross.asset_group_id)
            crossref["transaction_id"] = bina2str(cross.transaction_id)
            txdict["Cross_ref"].append(crossref)
    txdict["Signature"] = []
    if len(tx.signatures) > 0:
        for i, sig in enumerate(tx.signatures):
            sign = {}
            if sig is None:
                sign = "*RESERVED*"
                continue
            sign["type"] = sig.type
            sign["signature"] = bina2str(sig.signature)
            sign["pubkey"] = bina2str(sig.pubkey)
            txdict["Signature"].append(sign)
    return txdict

def store_proc(data, approver_id, txid=None):
    # make transaction object
    # TODO: adapt ref tx
    transaction = bbclib.make_transaction_for_base_asset(asset_group_id=asset_group_id, event_num=1)
    transaction.events[0].add(mandatory_approver=approver_id, asset_group_id=asset_group_id)
    transaction.events[0].asset.add(user_id=user_id, asset_body=data)
    '''
    if txid:
        bbc_app_client.search_transaction(asset_group_id, txid)
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
                                     keypair=key_pair)
        transaction.add_signature(signature=sig)
    '''

    # get transaction digest
    jsontx = tx_to_dict(transaction)
    obj = {"jsonrpc": "2.0",
           "method": "bbc1_GetTransactionDigest",
           "params":jsontx,
           "id": 114514
          }
    response = json_post(obj)

    # add sign to transaction json
    sig = bina2str(key_pair.sign(str2bina(response["result"])))
    sig = {
        "type":1,
        "signature": sig,
        "pubkey": bina2str(key_pair.public_key)
        }
    jsontx["Signature"].append(sig)

    # Insert Transaction
    obj = {"jsonrpc": "2.0",
           "method": "bbc1_InsertTransaction",
           "params":jsontx,
           "id": 114514
          }
    response = json_post(obj)
    print("TXID: %s" % response["result"])
    return True

def json_post(obj):
    url = "http://localhost:3000"
    method = "POST"
    headers = {"Content-Type" : "application/json"}
    json_data = json.dumps(obj).encode("utf-8")

    request = urllib.request.Request(url, data=json_data, method=method, headers=headers)
    with urllib.request.urlopen(request) as response:
        response_body = response.read().decode("utf-8")
    response = json.loads(response_body)
    return response

def get_coindata(asid):
    bbc_app_client = setup_bbc_client()
    asid = binascii.unhexlify(asid)
    ret = bbc_app_client.search_asset(asset_group_id, asid)
    assert ret
    response_data = bbc_app_client.callback.synchronize()
    if response_data[KeyType.status] < ESUCCESS:
        print("ERROR: ", response_data[KeyType.reason].decode())
        sys.exit(0)
    get_transaction = bbclib.BBcTransaction()
    get_transaction.deserialize(response_data[KeyType.transaction_data])

    retdata = get_transaction.events[0].asset.asset_body
    refdata = get_transaction.references
    print("get: %s" % retdata)
    print("ref: %s" % refdata)
    return retdata
    print("This method is not implimented over API")

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
    ret = bbc_app_client.search_asset(asset_group_id, binascii.unhexlify(asid))
    assert ret
    response_data = bbc_app_client.callback.synchronize()
    if response_data[KeyType.status] < ESUCCESS:
        print("ERROR: ", response_data[KeyType.reason].decode())
        sys.exit(0)
    get_transaction = bbclib.BBcTransaction()
    get_transaction.deserialize(response_data[KeyType.transaction_data])
    transaction_id = get_transaction.transaction_id
    transaction_info = store_proc(data, approver_id=binascii.unhexlify(new_owner),txid=transaction_id)
    bbc_app_client.send_message(transaction_info, asset_group_id, binascii.unhexlify(new_owner))
    print("Transfer is done.....")

if __name__ == '__main__':
    if(not os.path.exists(PRIVATE_KEY) and not os.path.exists(PUBLIC_KEY)):
        create_keypair()
    with open(PRIVATE_KEY, "rb") as fin:
        private_key = fin.read()
    with open(PUBLIC_KEY, "rb") as fin:
        public_key = fin.read()

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
            print("This method is not implimented over API")
            '''
            print("Type AsID of coin")
            asid = input('>> ')
            get_coindata(asid)
            '''
        elif command == "send":
            print("This method is not implimented over API")
            '''
            print("Type AsID of coin")
            asid = input('>> ')
            asset = json.loads(get_coindata(asid).decode("UTF-8"))
            assert asset
            print("You want send coin(%s)"% asid)
            print("Type new owner ID")
            new_owner = input('>> ')
            chown(new_owner,asid)
            '''
        elif command == "exit":
            print("bye")
            sys.exit(0)
        else:
            print("command \""+command+"\" is not found")
