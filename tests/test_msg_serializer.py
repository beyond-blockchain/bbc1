# -*- coding: utf-8 -*-
import pytest

import sys
sys.path.extend(["../"])
import pprint

#import unittest
from bbc1.core import bbclib
from bbc1.core import message_key_types
from bbc1.core.message_key_types import KeyType

msg_data = None


class TestMsgSerializer(object):

    def test_01_serialize(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        msg = {
            KeyType.source_node_id: bbclib.get_new_id("aaa"),
            KeyType.destination_node_id: bbclib.get_new_id("bbb"),
            KeyType.status: True,
            KeyType.random: int(8000).to_bytes(4, "little")
        }
        pprint.pprint(msg)
        global msg_data
        msg_data = message_key_types.make_TLV_formatted_message(msg)

    def test_02_deserialize(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        msg = message_key_types.make_dictionary_from_TLV_format(msg_data)
        pprint.pprint(msg)


if __name__ == '__main__':
    pytest.main()
