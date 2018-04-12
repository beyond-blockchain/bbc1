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
from bbc1.core.message_key_types import to_2byte


class ResourceType:
    Transaction_data = 0
    Asset_info = 1
    Asset_ID = 2
    Asset_file = 3
    Edge = 4


class InfraMessageCategory:
    CATEGORY_NETWORK = to_2byte(0)
    CATEGORY_TOPOLOGY = to_2byte(1)
    CATEGORY_USER = to_2byte(2)
    CATEGORY_DATA = to_2byte(3)
    CATEGORY_DOMAIN0 = to_2byte(4)
