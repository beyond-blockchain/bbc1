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
from bbc1.common import message_key_types
from bbc1.common.message_key_types import PayloadType, KeyType
from bbc1.common import logger


class UserMessageRouting:
    """
    Handle message for user
    """
    def __init__(self, core=None, loglevel="all", logname=None):
        self.core = core
        self.logger = logger.get_logger(key="user_message_routing", level=loglevel, logname=logname)
        self.registered_users = dict()

    def add_domain(self, domain_id):
        """
        add domain to the registered_users list
        :param domain_id:
        :return:
        """
        self.registered_users.setdefault(domain_id, dict())

    def remove_domain(self, domain_id):
        """
        remove domain from the registered_users list
        :param domain_id:
        :return:
        """
        self.registered_users.pop(domain_id, None)

    def register_user(self, user_id, domain_id, socket):
        """
        Register user to forward message
        :param user_id:
        :param domain_id:
        :param socket:
        :return:
        """
        if domain_id not in self.registered_users:
            return
        self.registered_users[domain_id].setdefault(user_id, set())
        self.registered_users[domain_id][user_id].add(socket)

    def unregister_user(self, user_id, domain_id=None, socket=None):
        """
        Unregister user from the list
        :param user_id:
        :param domain_id:
        :param socket:
        :return:
        """
        if domain_id is None:
            for d in self.registered_users.keys():
                if socket is None:
                    self.registered_users[d].pop(user_id, None)
                else:
                    self.registered_users[d][user_id].remove(socket)
        else:
            if domain_id in self.registered_users:
                if socket is None:
                    self.registered_users[domain_id].pop(user_id, None)
                else:
                    self.registered_users[domain_id][user_id].remove(socket)

    def send_message_to_user(self, msg, domain_id=None, sock=None):
        """
        Forward message to connecting user
        :param domain_id:
        :param msg:
        :param sock:
        :return:
        """
        if sock is not None:
            self.logger.debug("msg to app: %s" % (msg[KeyType.message]))
            sock.sendall(message_key_types.make_message(PayloadType.Type_msgpack, msg))
            return

        if domain_id is None and KeyType.domain_id in msg:
            domain_id = msg[KeyType.domain_id]
        if domain_id not in self.registered_users:
            return
        if KeyType.destination_user_id not in msg:
            return

        self.logger.debug("msg to app: %s" % (msg[KeyType.message]))
        socks = self.registered_users[domain_id].pop(KeyType.destination_user_id, None)
        if socks is None:
            return
        for s in socks:
            s.sendall(message_key_types.make_message(PayloadType.Type_msgpack, msg))

    def process_message(self, domain_id, msg):
        """
        (internal use) process received message
        :param domain_id:
        :param msg:       the message body (already deserialized)
        :return:
        """
        if KeyType.message not in msg:
            return
        self.send_message_to_user(msg, domain_id=domain_id)
