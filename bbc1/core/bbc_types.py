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
import os
import sys
sys.path.extend(["../../", os.path.abspath(os.path.dirname(__file__))])
from bbc1.common.message_key_types import to_2byte


class ResourceType:
    Transaction_data = 0
    Asset_ID = 1
    Asset_file = 2
    Edge_incoming = 3
    Edge_outgoing = 4
    Owner_asset = 5


class InfraMessageTypeBase:
    DOMAIN_PING = to_2byte(0)
    NOTIFY_LEAVE = to_2byte(1)
    NOTIFY_PEERLIST = to_2byte(2)
    START_TO_REFRESH = to_2byte(3)
    REQUEST_PING = to_2byte(4)
    RESPONSE_PING = to_2byte(5)

    NOTIFY_CROSS_REF = to_2byte(0, 0x10)        # only used in domain_global_0
    ADVERTISE_DOMAIN_INFO = to_2byte(1, 0x10)   # only used in domain_global_0

    REQUEST_STORE = to_2byte(0, 0x40)
    RESPONSE_STORE = to_2byte(1, 0x40)
    RESPONSE_STORE_COPY = to_2byte(2, 0x40)
    REQUEST_FIND_USER = to_2byte(3, 0x40)
    RESPONSE_FIND_USER = to_2byte(4, 0x40)
    REQUEST_FIND_VALUE = to_2byte(5, 0x40)
    RESPONSE_FIND_VALUE = to_2byte(6, 0x40)
    MESSAGE_TO_USER = to_2byte(7, 0x40)
