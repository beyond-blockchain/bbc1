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

def store_proc(data, approver_id, txid=None):
    # make transaction object
    transaction = bbclib.make_transaction_for_base_asset(asset_group_id=asset_group_id, event_num=1)
    transaction.events[0].add(mandatory_approver=approver_id, asset_group_id=asset_group_id)
    transaction.events[0].asset.add(user_id=user_id, asset_body=data)
    if txid:
        obj = {"jsonrpc": "2.0",
               "method": "bbc1_GetTransaction",
               "params":{
                    "asset_group_id": bbclib.bin2str_base64(asset_group_id),
                    "tx_id": txid,
                    "user_id": bbclib.bin2str_base64(user_id),
                   },
               "id": 114514
              }
        response = json_post(obj)
        prevtx = response["result"]
        prevtx = bbclib.BBcTransaction(jsonload=prevtx)
        bbclib.add_reference_to_transaction(asset_group_id, transaction, prevtx, 0)

    # get transaction digest
    jsontx = transaction.jsondump()
    obj = {"jsonrpc": "2.0",
           "method": "bbc1_GetTransactionDigest",
           "params":jsontx,
           "id": 114514
          }
    response = json_post(obj)

    # add sign to transaction json
    sig = bbclib.bin2str_base64(key_pair.sign(binascii.a2b_base64(response["result"]["digest"].encode("utf-8"))))
    jsontx = json.loads(response["result"]["tx"])
    sig = {
        "type":1,
        "signature": sig,
        "pubkey": bbclib.bin2str_base64(key_pair.public_key)
        }
    jsontx["Signature"].append(sig)
    # Insert Transaction
    obj = {"jsonrpc": "2.0",
           "method": "bbc1_InsertTransaction",
           "params":json.dumps(jsontx),
           "id": 114514
          }
    response = json_post(obj)
    print("TXID: %s" % response["result"])
    print("ASID: %s" % jsontx["Event"][0]["Asset"]["asset_id"])
    return response["result"]

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
    obj = {"jsonrpc": "2.0",
           "method": "bbc1_GetTransactionfromAsset",
           "params":{
               "asset_group_id": bbclib.bin2str_base64(asset_group_id),
               "as_id": asid,
               "user_id": bbclib.bin2str_base64(user_id),
               },
           "id": 114514
          }
    response = json_post(obj)
    tx = response["result"]
    return tx

def send_message(dst_id, msg):
    obj = {"jsonrpc": "2.0",
           "method": "bbc1_SendMessage",
           "params":{
               "user_id": bbclib.bin2str_base64(user_id),
               "dst_user_id": dst_id,
               "msg": msg
               },
           "id": 114514
          }
    print(obj)
    response = json_post(obj)
    res = response["result"]
    print(res)
    return True

def create_keypair():
    keypair = bbclib.KeyPair()
    keypair.generate()
    with open(PRIVATE_KEY, "wb") as fout:
        fout.write(keypair.private_key)
    with open(PUBLIC_KEY, "wb") as fout:
        fout.write(keypair.public_key)
    print("created private_key and public_key : %s, %s" % (PRIVATE_KEY, PUBLIC_KEY))

def registration(price):
    data = {"owner":bbclib.bin2str_base64(user_id),"price":price,"date":datetime.now().strftime('%s')}
    jsondata = json.dumps(data)
    store_proc(data=jsondata, approver_id=user_id ,txid=None)
    print("Coin is generated!: %s" % jsondata)

def chown(new_owner, asid):
    prevtx = json.loads(get_coindata(asid))
    asset = json.loads(prevtx["Event"][0]["Asset"]["body"])
    if asset["owner"] != bbclib.bin2str_base64(user_id):
        print("Owner of this coin is not you")
        return 0
    asset["owner"] = new_owner
    asset["date"] = datetime.now().strftime('%s')
    data = json.dumps(asset)

    coin = json.loads(get_coindata(asid))
    transaction_id = coin["transaction_id"]
    new_tx_id = store_proc(data, approver_id=binascii.a2b_base64(new_owner), txid=transaction_id)
    send_message(new_owner, new_tx_id)

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
    print("Your id: %s" % bbclib.bin2str_base64(user_id))
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
            tx = json.loads(get_coindata(asid))
            print("TXID: %s" % tx["transaction_id"])
            print("ASID: %s" % tx["Event"][0]["Asset"]["asset_id"])
            print(tx["Event"][0]["Asset"]["body"])
        elif command == "send":
            print("Type AsID of coin")
            asid = input('>> ')
            tx = json.loads(get_coindata(asid))
            print("TXID: %s" % tx["transaction_id"])
            print("ASID: %s" % tx["Event"][0]["Asset"]["asset_id"])
            print(tx["Event"][0]["Asset"]["body"])
            print("You want send coin(%s)"% asid)
            print("Type new owner ID")
            new_owner = input('>> ')
            chown(new_owner, asid)
            print("Transfer is done.....")
        elif command == "exit":
            print("bye")
            sys.exit(0)
        else:
            print("command \""+command+"\" is not found")
