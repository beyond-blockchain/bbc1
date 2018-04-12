import sys
sys.path.extend(["../"])


#import unittest
import bbc1.core.message_key_types as message_key_types
import bbc1.core.bbc_error as bbc_error

from bbc1.core.bbclib import MsgType
# dummy start.
#class MsgType:
#    MESSAGE = 34
# dummy end.


def _bytes_to_str(bytes_str):
    """
    """
    return bytes_str.decode('utf-8')


def test_to_4byte():
    """
    """
    val = message_key_types.to_4byte(7)
    assert (val == b'\x00\x00\x00\x07')

    val = message_key_types.to_4byte(1, 0x20)
    assert (val == b'\x00\x00\x00\x21')

    val = message_key_types.to_4byte(8, 0x30)
    assert (val == b'\x00\x00\x00\x38')

    val = message_key_types.to_4byte(2, 0x70)
    assert (val == b'\x00\x00\x00\x72')


def test_make_message():
    """
    """
    data = {  }
    message = message_key_types.make_message(message_key_types.PayloadType.Type_msgpack, data, 0)
    # print(message)
    assert (message == b'\x00\x02\x00\x00\x00\x00\x00\x01\x80')
    assert (message[:message_key_types.Message.HEADER_LEN] == b'\x00\x02\x00\x00\x00\x00\x00\x01')


def test_make_message2():
    """
    """
    data = {
        message_key_types.KeyType.command: MsgType.MESSAGE,
        message_key_types.KeyType.asset_group_id: "asset_group_id_001",
        message_key_types.KeyType.source_user_id: "source_user_id_12345",
        message_key_types.KeyType.query_id: "query_id_67890",
        message_key_types.KeyType.status: bbc_error.ESUCCESS,
    }
    message = message_key_types.make_message(message_key_types.PayloadType.Type_msgpack, data, 0)
    # print(message)
    assert (message[:message_key_types.Message.HEADER_LEN] == b'\x00\x02\x00\x00\x00\x00\x00S')

    msg_obj = message_key_types.Message()
    msg_obj.recv(bytes(message))
    parsed_data = msg_obj.parse()
    assert (msg_obj.payload_type == message_key_types.PayloadType.Type_msgpack)
    assert (msg_obj.format_version == 0)
    assert (msg_obj.msg_len == 83)        # 'S' == 83
    print(parsed_data)
    assert (parsed_data[message_key_types.KeyType.command] == MsgType.MESSAGE)
    assert (_bytes_to_str(parsed_data[message_key_types.KeyType.asset_group_id]) == "asset_group_id_001")
    assert (_bytes_to_str(parsed_data[message_key_types.KeyType.source_user_id]) == "source_user_id_12345")
    assert (_bytes_to_str(parsed_data[message_key_types.KeyType.query_id]) == "query_id_67890")
    assert (parsed_data[message_key_types.KeyType.status] == bbc_error.ESUCCESS)

