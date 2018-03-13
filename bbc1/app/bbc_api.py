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

app = Flask(__name__)

def setup_bbc_client(user_id, asset_group_id):
    bbc_app_client = bbc_app.BBcAppClient(port=bbc_app.DEFAULT_CORE_PORT, loglevel="all")
    bbc_app_client.set_user_id(user_id)
    bbc_app_client.set_asset_group_id(asset_group_id)
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
        print(txid)
        print(source_id)
        print(query_id)
        bbcapp = setup_bbc_client(source_id, asset_group_id)
        bbcapp.search_transaction(asset_group_id, txid)
        response_data = bbcapp.callback.synchronize()
        tx = bbclib.BBcTransaction()
        tx.deserialize(response_data[KeyType.transaction_data])
        result = tx_to_dict(tx)
    elif req["method"] == "bbc1_InsertTransaction":
        result = "Insert Transaction over HTTP!"
    else:
        result = {"code": -32601,"message":"Method '"+req["method"]+"' not found"}
        return False, result
    return True, result
    '''
        asset_group_id = binascii.unhexlify(request["params"]["Event"][0]["asset_group_id"])
        tx = bbclib.make_transaction_for_base_asset(asset_group_id=asset_group_id, event_num=len(request["params"]["Event"]))
        # Add Events
        for a in range(0,len(request["params"]["Event"])):
            approver_id = binascii.unhexlify(request["params"]["Event"][a]["mandatory_approvers"][0])
            tx.events[a].add(mandatory_approver=approver_id, asset_group_id=asset_group_id)
            user_id = binascii.unhexlify(request["params"]["Event"][a]["Asset"]["user_id"])
            body = binascii.unhexlify(request["params"]["Event"][a]["Asset"]["body"])
            tx.events[a].asset.add(user_id=user_id, asset_body=body)
            tx.events[a].asset.digest()

        if len(request["params"]["Reference"]) == 0:
            tx.get_sig_index(user_id)
            # Add Signature
            for i in range(0, len(request["params"]["Signature"])):
                sig = bbclib.BBcSignature()
                sig.add(binascii.unhexlify(request["params"]["Signature"][i]["signature"]),
                        binascii.unhexlify(request["params"]["Signature"][i]["pubkey"]))
                print(tx.add_signature(user_id, sig))
        else:
            # Add Reference
            for i in range(0, len(request["params"]["Reference"])):
                asset_group_id = binascii.unhexlify(request["params"]["Reference"][i]["asset_group_id"])
                txid = binascii.unhexlify(request["params"]["Reference"][i]["transaction_id"])
                query_id = request["id"]
                res = self.search_transaction_by_txid(asset_group_id, txid, user_id, query_id)
                prev_tx = bbclib.recover_transaction_object_from_rawdata(res[KeyType.transaction_data])
                bbclib.add_reference_to_transaction(asset_group_id, tx, prev_tx, 0)
                # Add Signature
                for i in range(0, len(request["params"]["Signature"])):
                    sig = bbclib.BBcSignature()
                    sig.add(binascii.unhexlify(request["params"]["Signature"][i]["signature"]),
                            binascii.unhexlify(request["params"]["Signature"][i]["pubkey"]))
                    print(tx.references[i].add_signature(user_id, sig))
        tx = tx.serialize()
        result = self.insert_transaction(asset_group_id, tx, None)
        if not isinstance(result, dict):
            result = {"code": 1, "message":result}
            return False, result
        result = list(result.values())
        txid = binascii.hexlify(result[0])
        result = {"transaction_id": txid.decode("utf-8")}
    '''

def hex2str(hex):
    return hex.decode("utf-8")

def tx_to_dict(tx):
    txdict = {}
    if tx.transaction_id is not None:
        txdict["transaction_id"] = hex2str(binascii.b2a_hex(tx.transaction_id))
    else:
        txdict["transaction_id"] = None
    txdict["version"] = tx.version
    txdict["timestamp"] = tx.timestamp
    txdict["Event"] = []
    if len(tx.events) > 0:
        for i, evt in enumerate(tx.events):
            event = {}
            event["asset_group_id"] = hex2str(binascii.b2a_hex(evt.asset_group_id))
            event["reference_indices"] = evt.reference_indices
            event["mandatory_approvers"] = []
            if len(evt.mandatory_approvers) > 0:
                for user in evt.mandatory_approvers:
                    event["mandatory_approvers"].append(hex2str(binascii.b2a_hex(user)))
            event["option_approvers"] = []
            if len(evt.option_approvers) > 0:
                for user in evt.option_approvers:
                    event["option_approvers"] = hex2str(binascii.b2a_hex(user))
            event["option_approver_num_numerator"] = evt.option_approver_num_numerator
            event["option_approver_num_denominator"] = evt.option_approver_num_denominator
            event["Asset"] = {}
            event["Asset"]["asset_id"] = hex2str(binascii.b2a_hex(evt.asset.asset_id))
            if evt.asset.user_id is not None:
                event["Asset"]["user_id"] = hex2str(binascii.b2a_hex(evt.asset.user_id))
            else:
                event["Asset"]["user_id"] = None
            event["Asset"]["nonce"] = hex2str(binascii.b2a_hex(evt.asset.nonce))
            event["Asset"]["file_size"] = evt.asset.asset_file_size
            if evt.asset.asset_file_digest is not None:
                event["Asset"]["file_digest"] = hex2str(binascii.b2a_hex(evt.asset.asset_file_digest))
            event["Asset"]["body_size"] = evt.asset.asset_body_size
            event["Asset"]["body"] = hex2str(binascii.b2a_hex(evt.asset.asset_body))
            txdict["Event"].append(event)
    txdict["Reference"] = []
    if len(tx.references) > 0:
        for i, refe in enumerate(tx.references):
            ref = {}
            ref["asset_group_id"] = hex2str(binascii.b2a_hex(refe.asset_group_id))
            ref["transaction_id"] = hex2str(binascii.b2a_hex(refe.transaction_id))
            ref["event_index_in_ref"] = refe.event_index_in_ref
            ref["sig_index"] = refe.sig_indices
            txdict["Reference"].append(ref)
    txdict["Cross_Ref"] = {}
    if len(tx.cross_refs) > 0:
        for i, cross in enumerate(tx.cross_refs):
            crossref = {}
            crossref["asset_group_id"] = hex2str(binascii.b2a_hex(cross.asset_group_id))
            crossref["transaction_id"] = hex2str(binascii.b2a_hex(cross.transaction_id))
            txdict["Cross_ref"].append(crossref)
    txdict["Signature"] = []
    if len(tx.signatures) > 0:
        for i, sig in enumerate(tx.signatures):
            sign = {}
            if sig is None:
                sign = "*RESERVED*"
                continue
            sign["type"] = sig.type
            sign["signature"] = hex2str(binascii.b2a_hex(sig.signature))
            sign["pubkey"] = hex2str(binascii.b2a_hex(sig.pubkey))
            txdict["Signature"].append(sign)
    return txdict



if __name__ == "__main__":
    app.run(host='0.0.0.0', port=3000)
