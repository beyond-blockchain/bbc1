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
import json
from flask import Flask, jsonify, request
import binascii
import sys

sys.path.extend(["../"])
from common import bbclib
from common.message_key_types import KeyType
from app import bbc_app
from bbc1.common.bbc_error import *

app = Flask(__name__)

#TODO:TMP set domain id and user id to bbc app
def setup_bbc_client(user_id, domain_id=bbclib.get_new_id("coindomain", include_timestamp=False)):
    bbc_app_client = bbc_app.BBcAppClient(port=bbc_app.DEFAULT_CORE_PORT, loglevel="all")
    bbc_app_client.set_user_id(user_id)
    bbc_app_client.set_domain_id(domain_id)
    bbc_app_client.set_callback(bbc_app.Callback())
    ret = bbc_app_client.register_to_core()
    assert ret
    return bbc_app_client


@app.route("/",methods=['POST'])
def request_perser():
    req = request.json
    res, msg = check_json_rpc_format(req)
    if res:
        res, result = rpc_proccess(req)
        if res:
            resbody = {"jsonrpc": "2.0", "result": result, "id": req["id"]}
        else:
            resbody = {"jsonrpc": "2.0", "error": result, "id": req["id"]}
    else:
        resbody = {"jsonrpc": "2.0", "error":msg, "id": "null"}
    return jsonify(resbody)

def check_json_rpc_format(req):
    if "jsonrpc" in req and "method" in req and "id" in req:
        return True, None
    else:
        msg = {"code":-32600, "message":"Invalid Request"}
        return False, msg

def rpc_proccess(req):
    if req["method"] == "bbc1_Hello":
        result = "Access bbc1 over HTTP!"
    elif req["method"] == "bbc1_GetTransaction":
        asset_group_id = binascii.unhexlify(req["params"]["asset_group_id"])
        txid = binascii.unhexlify(req["params"]["tx_id"])
        source_id = binascii.unhexlify(req["params"]["user_id"])
        query_id = req["id"]
        bbcapp = setup_bbc_client(source_id)
        bbcapp.search_transaction(txid)
        response_data = bbcapp.callback.synchronize()
        tx = bbclib.BBcTransaction()
        tx.deserialize(response_data[KeyType.transaction_data])
        tx.dump()
        result = tx.jsondump()
    elif req["method"] == "bbc1_GetTransactionDigest":
        tx = bbclib.BBcTransaction(jsonload=req["params"])
        digest = tx.digest()
        result["digest"] = bina2str(digest)
        result["tx"] = tx.jsondump()
    elif req["method"] == "bbc1_InsertTransaction":
        result = "Insert Transaction over HTTP!"
        tx = bbclib.BBcTransaction(jsonload=req["params"])
        source_id = str2bina(req["params"]["Event"][0]["mandatory_approvers"][0])
        asset_group_id = binascii.unhexlify(req["params"]["Event"][0]["asset_group_id"])
        bbcapp = setup_bbc_client(source_id)
        bbcapp.insert_transaction(tx)
        response_data = bbcapp.callback.synchronize()
        if response_data[KeyType.status] < ESUCCESS:
            reslut = response_data[KeyType.reason].decode()
        else:
            result = bina2str(response_data[KeyType.transaction_id])
    else:
        result = {"code": -32601,"message":"Method '"+req["method"]+"' not found"}
        return False, result
    return True, result


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=3000)
