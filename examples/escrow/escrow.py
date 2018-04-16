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
import binascii
import json
import time
import threading
from datetime import datetime


sys.path.extend(["../../"])
from bbc1.core import bbclib
from bbc1.core import bbc_app
from bbc1.core.bbc_config import DEFAULT_CORE_PORT
from bbc1.core.message_key_types import KeyType
from bbc1.core.bbc_error import *

PRIVATE_KEY = ".private_key"
PUBLIC_KEY = ".public_key"

domain_id = bbclib.get_new_id("landdomain", include_timestamp=False)
land_asset_group = bbclib.get_new_id("land_asset_group", include_timestamp=False)

coin_asset_group = bbclib.get_new_id("coin_asset_group", include_timestamp=False)

escrow = None
landasid = None
coinasid = None
user_id = None

key_pair = None
bbc_app_client = None


def setup_bbc_client():
    bbc_app_client = bbc_app.BBcAppClient(port=DEFAULT_CORE_PORT, loglevel="all")
    bbc_app_client.set_user_id(user_id)
    bbc_app_client.set_domain_id(domain_id)
    bbc_app_client.set_callback(bbc_app.Callback())
    ret = bbc_app_client.register_to_core()
    assert ret
    return bbc_app_client


def get_txid_from_asid(asset_group, asid):
    bbc_app_client = setup_bbc_client()
    ret = bbc_app_client.search_asset(asset_group, binascii.unhexlify(asid))
    assert ret
    response_data = bbc_app_client.callback.synchronize()
    get_transaction = bbclib.BBcTransaction()
    get_transaction.deserialize(response_data[KeyType.transaction_data])
    transaction_id = get_transaction.transaction_id
    return transaction_id


def add_ref_tx(asset_group,transaction,ref_tx,ref_index):
    bbc_app_client = setup_bbc_client()
    bbc_app_client.search_transaction(ref_tx)
    response_data = bbc_app_client.callback.synchronize()
    if response_data[KeyType.status] < ESUCCESS:
        print("ERROR: ", response_data[KeyType.reason].decode())
        sys.exit(0)
    prev_tx = bbclib.BBcTransaction(deserialize=response_data[KeyType.transaction_data])
    reference = bbclib.add_reference_to_transaction(transaction, asset_group, prev_tx,0)
    sig = transaction.sign(key_type=bbclib.KeyType.ECDSA_SECP256k1,
                                 private_key=key_pair.private_key,
                                 public_key=key_pair.public_key)
    transaction.references[ref_index].add_signature(user_id=user_id, signature=sig)
    if asset_group == land_asset_group:
        print("ref to land asset")

    return transaction


def get_data(asset_group,asid):
    bbc_app_client = setup_bbc_client()
    asid = binascii.unhexlify(asid)
    ret = bbc_app_client.search_asset(asset_group, asid)
    assert ret
    response_data = bbc_app_client.callback.synchronize()

    get_transaction = bbclib.BBcTransaction()
    get_transaction.deserialize(response_data[KeyType.transaction_data])
    retdata = get_transaction.events[0].asset.asset_body
    refdata = get_transaction.references
    return retdata


def sendback_exception_asset(approver_id, asset_group, asid):
    asset = json.loads(get_data(asset_group, asid).decode("UTF-8"))
    asset["owner"] = approver_id
    asset["date"] = datetime.now().strftime('%s')
    data = json.dumps(asset)

    bbc_app_client = setup_bbc_client()

    transaction = bbclib.make_transaction(event_num=1)
    transaction.events[0].add(mandatory_approver=binascii.unhexlify(approver_id))
    bbclib.add_event_asset(transaction, event_idx=0, asset_group_id=asset_group,
                           user_id=user_id, asset_body=data)

    ref_tx = get_txid_from_asid(asset_group, asid)
    transaction = add_ref_tx(asset_group, transaction, ref_tx, 0)

    transaction.digest()
    print(transaction)

    ret = bbc_app_client.insert_transaction(transaction)
    assert ret
    response_data = bbc_app_client.callback.synchronize()
    if response_data[KeyType.status] < ESUCCESS:
        print("ERROR: ", response_data[KeyType.reason].decode())
        sys.exit(0)
    print("TxID: %s", binascii.b2a_hex(response_data[KeyType.transaction_id]))
    print("AsID: %s", binascii.b2a_hex(transaction.events[0].asset.asset_id))

    bbc_app.store_id_mappings(data, asset_group,
                              transaction_id=response_data[KeyType.transaction_id],
                              asset_ids=transaction.events[0].asset.asset_id)

    txinfo = [transaction.transaction_id, transaction.events[0].asset.asset_id]
    bbc_app_client.send_message(txinfo, binascii.unhexlify(new_owner), asset_group)
    print("Transfer is done.....")


def execute_escrow():
    coinasset = json.loads(get_data(coin_asset_group, coinasid).decode("UTF-8"))
    coinasset["owner"] = escrow["owner"]
    coinasset["date"] = datetime.now().strftime('%s')
    coinasset = json.dumps(coinasset)
    cointx_id = get_txid_from_asid(coin_asset_group, coinasid)

    landasset = json.loads(get_data(land_asset_group, landasid).decode("UTF-8"))
    landasset["owner"] = escrow["newowner"]
    landasset["date"] = datetime.now().strftime('%s')
    landasset = json.dumps(landasset)
    landtx_id = get_txid_from_asid(land_asset_group, landasid)


    # Make TX
    land_client = setup_bbc_client()
    transaction = bbclib.make_transaction(event_num=2)

    # Add event and asset
    print("Add event and asset")
    bbclib.add_event_asset(transaction, event_idx=0, asset_group_id=land_asset_group,
                           user_id=user_id, asset_body=landasset)
    transaction.events[0].add(mandatory_approver=binascii.unhexlify(escrow["newowner"]))
    LAB_id = bbclib.get_new_id("LegalAffairsBureau", include_timestamp=False)
    transaction.events[0].add(option_approver=LAB_id)

    coin_client = setup_bbc_client()
    bbclib.add_event_asset(transaction, event_idx=1, asset_group_id=coin_asset_group,
                           user_id=user_id, asset_body=coinasset)
    transaction.events[1].add(mandatory_approver=binascii.unhexlify(escrow["owner"]))

    # Add reference
    print("Add reference")
    land_client.search_transaction(landtx_id)
    response_data = land_client.callback.synchronize()
    if response_data[KeyType.status] < ESUCCESS:
        print("ERROR: ", response_data[KeyType.reason].decode())
        sys.exit(0)
    prev_tx = bbclib.BBcTransaction(deserialize=response_data[KeyType.transaction_data])
    reference = bbclib.add_reference_to_transaction(transaction, land_asset_group, prev_tx, 0)

    coin_client.search_transaction(cointx_id)
    response_data = coin_client.callback.synchronize()
    if response_data[KeyType.status] < ESUCCESS:
        print("ERROR: ", response_data[KeyType.reason].decode())
        sys.exit(0)
    prev_tx = bbclib.BBcTransaction(deserialize=response_data[KeyType.transaction_data])
    reference = bbclib.add_reference_to_transaction(transaction, coin_asset_group, prev_tx,0)

    # Add signature
    print("Add signature to escrow TX")
    sig = transaction.sign(key_type=bbclib.KeyType.ECDSA_SECP256k1,
                                 private_key=key_pair.private_key,
                                 public_key=key_pair.public_key)
    transaction.references[0].add_signature(user_id=user_id, signature=sig)

    print("Get signature from LegalAffairsBureau")
    land_client.gather_signatures(transaction, destinations=[LAB_id])
    response_data = land_client.callback.synchronize()
    if response_data[KeyType.status] < ESUCCESS:
        print("Rejected because ", response_data[KeyType.reason].decode(), "")
        sys.exit(0)
    result = response_data[KeyType.result]
    transaction.get_sig_index(result[1])
    transaction.add_signature(user_id=result[1], signature=result[2])

    transaction.digest()
    print(transaction)

    print("insert coin asset group")
    ret = coin_client.insert_transaction(transaction)
    assert ret
    response_data = coin_client.callback.synchronize()
    if response_data[KeyType.status] < ESUCCESS:
        print("ERROR: ", response_data[KeyType.reason].decode())
        sys.exit(0)
    print("TxID: %s", binascii.b2a_hex(response_data[KeyType.transaction_id]))
    print("coinAsID: %s", binascii.b2a_hex(transaction.events[0].asset.asset_id))
    print("landAsID: %s", binascii.b2a_hex(transaction.events[1].asset.asset_id))

    cointxinfo = [transaction.transaction_id, transaction.events[0].asset.asset_id]
    landtxinfo = [transaction.transaction_id, transaction.events[1].asset.asset_id]

    print("insert land asset group")
    ret = land_client.insert_transaction(transaction)
    assert ret
    response_data = land_client.callback.synchronize()
    if response_data[KeyType.status] < ESUCCESS:
        print("ERROR: ", response_data[KeyType.reason].decode())
        sys.exit(0)
    print("TxID: %s", binascii.b2a_hex(response_data[KeyType.transaction_id]))
    print("coinAsID: %s", binascii.b2a_hex(transaction.events[0].asset.asset_id))
    print("landAsID: %s", binascii.b2a_hex(transaction.events[1].asset.asset_id))

    txinfo = [transaction.transaction_id, transaction.events[0].asset.asset_id]
    coin_client.send_message(txinfo, binascii.unhexlify(escrow["owner"]), coin_asset_group)
    txinfo = [transaction.transaction_id, transaction.events[1].asset.asset_id]
    land_client.send_message(txinfo, binascii.unhexlify(escrow["newowner"]), land_asset_group)
    print("Transfer is done.....")


def recive(asset_group):
    while(True):
        bbc_app_client = setup_bbc_client()
        print("Waiting for the message...")
        recvdat = bbc_app_client.callback.synchronize()
        if KeyType.message not in recvdat:
            print("message is not found")
        else:
            transaction_id, asset_id = recvdat[KeyType.message]
            print("TxID: %s" % binascii.hexlify(transaction_id))
            print("AsID: %s" % binascii.hexlify(asset_id))
            asset = get_data(asset_group, binascii.hexlify(asset_id))
            print(json.dumps(json.loads(asset.decode("utf-8")),ensure_ascii=False, indent=4, sort_keys=False))
            data = json.loads(asset)
            if asset_group == land_asset_group:
                    if data["place"] == escrow["place"]:
                        global landasid
                        landasid = binascii.hexlify(asset_id).decode("utf-8")
                        escrow["landstatus"] = "spend"
                        break
                    else:
                        print("Escrow needs %s,but %s is send" %(escrow["place"],data["place"]))
                        sendback_exception_asset(escrow["owner"], land_asset_group, binascii.hexlify(asset_id).decode("utf-8"))
            elif asset_group == coin_asset_group:
                    if data["price"] == escrow["price"]:
                        global coinasid
                        coinasid = binascii.hexlify(asset_id).decode("utf-8")
                        escrow["coinstatus"] = "spend"
                        break
                    else:
                        print("Escrow needs %s,but %s is send" %(escrow["price"],data["price"]))
                        sendback_exception_asset(escrow["newowner"], coin_asset_group, binascii.hexlify(asset_id).decode("utf-8"))


def create_keypair():
    keypair = bbclib.KeyPair()
    keypair.generate()
    with open(PRIVATE_KEY, "wb") as fout:
        fout.write(keypair.private_key)
    with open(PUBLIC_KEY, "wb") as fout:
        fout.write(keypair.public_key)
    print("created private_key and public_key : %s, %s" % (PRIVATE_KEY, PUBLIC_KEY))


if __name__ == '__main__':
    if(not os.path.exists(PRIVATE_KEY) and not os.path.exists(PUBLIC_KEY)):
        create_keypair()
    with open(PRIVATE_KEY, "rb") as fin:
        private_key = fin.read()
    with open(PUBLIC_KEY, "rb") as fin:
        public_key = fin.read()

    key_pair = bbclib.KeyPair(privkey=private_key, pubkey=public_key)
    user_id = bbclib.get_new_id(str(binascii.b2a_hex(key_pair.public_key)), include_timestamp=False)
    print("welcome to sample escrow!")

    print("Type AsID of land")
    land = input(">>")
    print("Type owner id of land")
    landowner = input(">>")
    landasset = json.loads(get_data(land_asset_group, land).decode("UTF-8"))
    if landasset["owner"] == landowner:
        print("Type price of land")
        price = input(">>")
        print("Type new owner ID of land")
        newowner = input(">>")
        escrow = {"price":price,"land":land,"place":landasset["place"],"owner":landowner,"newowner":newowner,"coinstatus":"unspend","landstatus":"unspend"}
        print("New escrow is starting...")
        print("escrow id: %s" % binascii.b2a_hex(user_id))
        print("-------------------------")
        print(json.dumps(escrow,ensure_ascii=False, indent=4, sort_keys=False))
        print("-------------------------")
        landthread = threading.Thread(target=recive,args=(land_asset_group,))
        cointhread = threading.Thread(target=recive,args=(coin_asset_group,))
        cointhread.setDaemon(True)
        landthread.setDaemon(True)
        cointhread.start()
        landthread.start()
        while(True):
            if escrow["landstatus"] == "spend":
                print("land is spend")
            else:
                print("Waiting land spend...")

            if escrow["coinstatus"] == "spend":
                print("coin is spend")
            else:
                print("Waiting coin spend...")
            if escrow["landstatus"] == "spend" and escrow["coinstatus"] == "spend":
                print("Coin and Land is spend")
                break
            time.sleep(3)
        print("Do escrow!")
        execute_escrow()
    else:
        print("owner of Land(%s) is not %s"%(land,landowner))
