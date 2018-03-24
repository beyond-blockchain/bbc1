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
    # TODO: adapt ref tx
    transaction = bbclib.make_transaction_for_base_asset(asset_group_id=asset_group_id, event_num=1)
    transaction.events[0].add(mandatory_approver=approver_id, asset_group_id=asset_group_id)
    transaction.events[0].asset.add(user_id=user_id, asset_body=data)

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
    print(jsontx)
    # Insert Transaction
    obj = {"jsonrpc": "2.0",
           "method": "bbc1_InsertTransaction",
           "params":json.dumps(jsontx),
           "id": 114514
          }
    response = json_post(obj)
    print("TXID: %s" % response["result"])
    print("ASID: %s" % jsontx["Event"][0]["Asset"]["asset_id"])
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
    obj = {"jsonrpc": "2.0",
           "method": "bbc1_GetTransaction",
           "params":jsontx,
           "id": 114514
          }
    response = json_post(obj)
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
