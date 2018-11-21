# -*- coding: utf-8 -*-
"""
Copyright (c) 2018 beyond-blockchain.org.

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
sys.path.append(os.path.join(current_dir, "../../.."))
from bbc1.core.libs.bbclib_keypair import KeyType
from bbc1.core.libs.bbclib_wire import BBcFormat


DEFAULT_ID_LEN = 32
DEFAULT_CURVETYPE = KeyType.ECDSA_P256v1
DEFAULT_BBC_FORMAT = BBcFormat.FORMAT_PLAIN
