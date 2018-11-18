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

current_dir = os.path.abspath(os.path.dirname(__file__))
sys.path.append(os.path.join(current_dir, "../.."))
import bbc1.core.bbclib_core as bbclib_core
import bbc1.core.compat.bbclib as bbclib_compat
import bbc1.core.bbclib_wire as bbclib_wire


def deserialize(txdata):
    """
    Deserialize binary data with 2-byte wire header

    :param txdata:
    :returns:
        BBcTransaction: BBcTransaction object
        int: 2-byte value of BBcFormat type
    """
    try:
        dat, fmt = bbclib_wire.BBcFormat.strip(txdata)
        return bbclib_core.BBcTransaction(deserialize=dat), fmt
    except:
        # -- for backward compatibility
        txobj = bbclib_compat.BBcTransaction(deserialize=txdata)
        return txobj, txobj.format_type


def serialize(txobj, format_type=bbclib_wire.BBcFormat.FORMAT_PLAIN):
    """
    Serialize transaction object with 2-byte wire header

    :param txobj: BBcTransaction object
    :param format_type: value defined in bbclib_wire.BBcFormat
    :return: binary
    """
    if txobj.transaction_data is None:
        txobj.serialize()
    try:
        return bbclib_wire.BBcFormat.generate(txobj, format_type=format_type)
    except:
        # -- for backward compatibility
        return txobj.transaction_data


# ----
# Codes below are for backward compatibility with v1.1.x or earlier
# These codes will be removed in the future.

domain_global_0 = bbclib_core.domain_global_0
error_code = bbclib_core.error_code
error_text = bbclib_core.error_text

DEFAULT_ID_LEN = bbclib_core.DEFAULT_ID_LEN
DEFAULT_CURVETYPE = bbclib_core.DEFAULT_CURVETYPE

get_new_id = bbclib_core.get_new_id
get_random_id = bbclib_core.get_random_id
get_random_value = bbclib_core.get_random_value
convert_id_to_string = bbclib_core.convert_id_to_string
convert_idstring_to_bytes = bbclib_core.convert_idstring_to_bytes
deep_copy_with_key_stringify = bbclib_core.deep_copy_with_key_stringify
make_transaction = bbclib_core.make_transaction
add_relation_asset = bbclib_core.add_relation_asset
add_relation_pointer = bbclib_core.add_relation_pointer
add_reference_to_transaction = bbclib_core.add_reference_to_transaction
add_event_asset = bbclib_core.add_event_asset
make_relation_with_asset = bbclib_core.make_relation_with_asset
add_pointer_in_relation = bbclib_core.add_pointer_in_relation
recover_signature_object = bbclib_core.recover_signature_object
validate_transaction_object = bbclib_core.validate_transaction_object
verify_using_cross_ref = bbclib_core.verify_using_cross_ref

KeyType = bbclib_core.KeyType
MsgType = bbclib_core.MsgType

BBcFormat = bbclib_compat.BBcFormat

KeyPair = bbclib_core.KeyPair
BBcSignature = bbclib_core.BBcSignature
BBcTransaction = bbclib_core.BBcTransaction
BBcEvent = bbclib_core.BBcEvent
BBcReference = bbclib_core.BBcReference
BBcRelation = bbclib_core.BBcRelation
BBcPointer = bbclib_core.BBcPointer
BBcWitness = bbclib_core.BBcWitness
BBcAsset = bbclib_core.BBcAsset
BBcCrossRef = bbclib_core.BBcCrossRef

