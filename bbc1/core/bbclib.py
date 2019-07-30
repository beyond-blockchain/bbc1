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

import binascii
import bbc1.core.bbc_error as bbc_error


domain_global_0 = binascii.a2b_hex("0000000000000000000000000000000000000000000000000000000000000000")

error_code = -1
error_text = ""


import bbclib.libs.bbclib_utils as bbclib_utils
import bbclib.libs.bbclib_transaction as bbclib_transaction
import bbclib.libs.bbclib_signature as bbclib_signature
import bbclib.libs.bbclib_keypair as bbclib_keypair
import bbclib.libs.bbclib_asset as bbclib_asset
import bbclib.libs.bbclib_crossref as bbclib_crossref
import bbclib.libs.bbclib_event as bbclib_event
import bbclib.libs.bbclib_msgtype as bbclib_msgtype
import bbclib.libs.bbclib_pointer as bbclib_pointer
import bbclib.libs.bbclib_relation as bbclib_relation
import bbclib.libs.bbclib_reference as bbclib_reference
import bbclib.libs.bbclib_witness as bbclib_witness
import bbclib.compat.bbclib as bbclib_compat
import bbclib


def _set_error(code=-1, txt=""):
    global error_code
    global error_text
    error_code = code
    error_text = txt


def _reset_error():
    global error_code
    global error_text
    error_code = bbc_error.ESUCCESS
    error_text = ""


# ----
# Codes below are for backward compatibility with v1.1.x or earlier
# These codes will be removed in the future.

DEFAULT_CURVETYPE = bbclib_signature.DEFAULT_CURVETYPE

get_new_id = bbclib_utils.get_new_id
get_random_id = bbclib_utils.get_random_id
get_random_value = bbclib_utils.get_random_value
convert_id_to_string = bbclib_utils.convert_id_to_string
convert_idstring_to_bytes = bbclib_utils.convert_idstring_to_bytes
deep_copy_with_key_stringify = bbclib_utils.deep_copy_with_key_stringify
make_transaction = bbclib_utils.make_transaction
add_relation_asset = bbclib_utils.add_relation_asset
add_relation_pointer = bbclib_utils.add_relation_pointer
add_reference_to_transaction = bbclib_utils.add_reference_to_transaction
add_event_asset = bbclib_utils.add_event_asset
make_relation_with_asset = bbclib_utils.make_relation_with_asset
add_pointer_in_relation = bbclib_utils.add_pointer_in_relation
recover_signature_object = bbclib_utils.recover_signature_object
validate_transaction_object = bbclib_utils.validate_transaction_object
verify_using_cross_ref = bbclib_utils.verify_using_cross_ref

serialize = bbclib.serialize
deserialize = bbclib.deserialize

KeyType = bbclib_keypair.KeyType
MsgType = bbclib_msgtype.MsgType

BBcFormat = bbclib_compat.BBcFormat

KeyPair = bbclib_keypair.KeyPair
BBcSignature = bbclib_signature.BBcSignature
BBcTransaction = bbclib_transaction.BBcTransaction
BBcEvent = bbclib_event.BBcEvent
BBcReference = bbclib_reference.BBcReference
BBcRelation = bbclib_relation.BBcRelation
BBcPointer = bbclib_pointer.BBcPointer
BBcWitness = bbclib_witness.BBcWitness
BBcAsset = bbclib_asset.BBcAsset
BBcCrossRef = bbclib_crossref.BBcCrossRef

