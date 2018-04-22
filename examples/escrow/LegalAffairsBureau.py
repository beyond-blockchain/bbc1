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
import sqlite3

sys.path.extend(["../../"])
from bbc1.core import bbclib
from bbc1.core import bbc_app
from bbc1.core.bbc_config import DEFAULT_CORE_PORT
from bbc1.core.message_key_types import KeyType
from bbc1.core.bbc_error import *


PRIVATE_KEY = ".private_key"
PUBLIC_KEY = ".public_key"

dbpath = "land.sqlite"
con = sqlite3.connect(dbpath)

domain_id = bbclib.get_new_id("landdomain", include_timestamp=False)
asset_group_id = bbclib.get_new_id("land_asset_group", include_timestamp=False)

user_id = bbclib.get_new_id("LegalAffairsBureau", include_timestamp=False)

key_pair = None
bbc_app_client = None


def domain_setup():
    tmpclient = bbc_app.BBcAppClient(port=DEFAULT_CORE_PORT, multiq=False, loglevel="all")
    tmpclient.domain_setup(domain_id)
    tmpclient.callback.synchronize()
    tmpclient.unregister_from_core()
    print("Domain %s is created." % (binascii.b2a_hex(domain_id[:4]).decode()))
    print("Setup is done.")


def setup_bbc_client():
    bbc_app_client = bbc_app.BBcAppClient(port=DEFAULT_CORE_PORT, multiq=False, loglevel="all")
    bbc_app_client.set_user_id(user_id)
    bbc_app_client.set_domain_id(domain_id)
    bbc_app_client.set_callback(bbc_app.Callback())
    ret = bbc_app_client.register_to_core()
    assert ret
    return bbc_app_client

def create_keypair():
    keypair = bbclib.KeyPair()
    keypair.generate()
    with open(PRIVATE_KEY, "wb") as fout:
        fout.write(keypair.private_key)
    with open(PUBLIC_KEY, "wb") as fout:
        fout.write(keypair.public_key)
    print("created private_key and public_key : %s, %s" % (PRIVATE_KEY, PUBLIC_KEY))


def recive():
    bbc_app_client = setup_bbc_client()
    print("Waiting for the message of chown land...")
    recvdat = bbc_app_client.callback.synchronize()
    transaction = bbclib.BBcTransaction()
    transaction.deserialize(recvdat[KeyType.transaction_data])
    print(transaction)
    data = json.loads(transaction.events[0].asset.asset_body)
    if transaction.references:
        print("TX has reference...")
        sql = "select * from land where reftx like (?)"
        cur.execute(sql,(binascii.hexlify(transaction.references[0].transaction_id),))
        list = cur.fetchall()
        if len(list) != 0:
            print("Ref tx has alredy been referenced")
            bbc_app_client.sendback_denial_of_sign(recvdat[KeyType.source_user_id],
                                                   transaction.transaction_id,
                                                   "Ref tx has alredy been referenced")
            return 0;
        else:
            print("Ref tx has not been referenced.")
            sql = "select * from land where txid like (?)"
            cur.execute(sql,(binascii.hexlify(transaction.references[0].transaction_id),))
            list = cur.fetchall()
            if len(list) == 0:
                print("ref tx is not found")
                bbc_app_client.sendback_denial_of_sign(recvdat[KeyType.source_user_id],
                                                       transaction.transaction_id,
                                                       "Ref Tx is not found")
                return 0;
            else:
                print("Ref is correct, insert tx to our DB.")
                sql = u"insert into land(asid,txid,place,owner,reftx) values (?, ?, ?, ?, ?)"
                con.execute(sql, (binascii.hexlify(transaction.events[0].asset.asset_id), binascii.hexlify(transaction.transaction_id), data["place"], data["owner"],binascii.hexlify(transaction.references[0].transaction_id)))
                con.commit()
    else:
        print("This tx is land registration tx.")
        sql = u"insert into land(asid,txid,place,owner,reftx) values (?, ?, ?, ?, ?)"
        con.execute(sql, (binascii.hexlify(transaction.events[0].asset.asset_id), binascii.hexlify(transaction.transaction_id), data["place"], data["owner"],None))
        con.commit()

    signature = transaction.sign(keypair=key_pair)
    bbc_app_client.sendback_signature(recvdat[KeyType.source_user_id], transaction.transaction_id, 0, signature)


if __name__ == '__main__':
    if not os.path.exists(PRIVATE_KEY) and not os.path.exists(PUBLIC_KEY):
        create_keypair()
    with open(PRIVATE_KEY, "rb") as fin:
        private_key = fin.read()
    with open(PUBLIC_KEY, "rb") as fin:
        public_key = fin.read()
    key_pair = bbclib.KeyPair(privkey=private_key, pubkey=public_key)

    # If there is no table, create table.
    cur = con.execute("SELECT * FROM sqlite_master WHERE type='table' and name='land'")
    if cur.fetchone() is None:
        print("Create land table")
        con.execute("CREATE TABLE 'land' (id INTEGER PRIMARY KEY AUTOINCREMENT, asid TEXT, txid TEXT,place TEXT ,owner TEXT, reftx TEXT)")
        con.commit()

    while(True):
        recive()
    con.close()
