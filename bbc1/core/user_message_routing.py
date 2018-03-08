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

import time
import os
import sys
sys.path.extend(["../../", os.path.abspath(os.path.dirname(__file__))])
from bbc1.common import message_key_types
from bbc1.common.message_key_types import to_2byte, PayloadType, KeyType
from bbc1.common import logger
from bbc1.core.bbc_types import InfraMessageCategory
from bbc1.core import query_management

ticker = query_management.get_ticker()


class UserMessageRouting:
    """
    Handle message for user
    """
    REFRESH_FORWARDING_LIST_INTERVAL = 300
    RESOLVE_TIMEOUT = 5
    RESOLVE_USER_LOCATION = to_2byte(0)
    RESPONSE_USER_LOCATION = to_2byte(1)
    RESPONSE_NO_SUCH_USER = to_2byte(2)
    NOTIFY_USER_LOCATION_FOR_MULTICAST = to_2byte(3)

    def __init__(self, network, domain_id, loglevel="all", logname=None):
        self.network = network
        self.domain_id = domain_id
        self.logger = logger.get_logger(key="user_message_routing", level=loglevel, logname=logname)
        self.registered_users = dict()
        self.forwarding_entries = dict()
        self.on_going_timers = set()

    def stop_all_timers(self):
        """
        Cancel all callback of query_entries
        :return:
        """
        for user_id in self.forwarding_entries.keys():
            if self.forwarding_entries[user_id]['refresh'] is not None:
                self.forwarding_entries[user_id]['refresh'].deactivate()
        for q in self.on_going_timers:
            ticker.get_entry(q).deactivate()

    def register_user(self, user_id, socket, is_multicast=False):
        """
        Register user to forward message
        :param user_id:
        :param socket:
        :param is_multicast:
        :return:
        """
        self.registered_users.setdefault(user_id, set())
        self.registered_users[user_id].add(socket)
        if is_multicast:
            self.send_multicast_notification(user_id)

    def unregister_user(self, user_id, socket=None):
        """
        Unregister user from the list
        :param user_id:
        :param socket:
        :return:
        """
        if socket is None:
            self.registered_users.pop(user_id, None)
        else:
            self.registered_users[user_id].remove(socket)
            if len(self.registered_users[user_id]) == 0:
                self.registered_users.pop(user_id, None)

    def add_user_for_forwarding(self, user_id, node_id):
        """
        Register user to forwarding list
        :param user_id:
        :param node_id:
        :return:
        """
        self.forwarding_entries.setdefault(user_id, dict())
        if 'refresh' not in self.forwarding_entries[user_id]:
            query_entry = query_management.QueryEntry(expire_after=UserMessageRouting.REFRESH_FORWARDING_LIST_INTERVAL,
                                                      callback_expire=self.remove_user_from_forwarding,
                                                      data={
                                                          KeyType.user_id: user_id,
                                                      }, retry_count=0)
            self.forwarding_entries[user_id]['refresh'] = query_entry
        else:
            self.forwarding_entries[user_id]['refresh'].update(fire_after=UserMessageRouting.REFRESH_FORWARDING_LIST_INTERVAL)
        self.forwarding_entries[user_id].setdefault('nodes', set())
        self.forwarding_entries[user_id]['nodes'].add(node_id)

    def remove_user_from_forwarding(self, query_entry=None, user_id=None, node_id=None):
        """
        Unregister user to forwarding list
        :param query_entry:
        :param user_id:
        :param node_id:
        :return:
        """
        if query_entry is not None:
            user_id = query_entry.data[KeyType.user_id]
            self.forwarding_entries.pop(user_id, None)
            return
        if user_id not in self.forwarding_entries:
            return
        self.forwarding_entries[user_id]['nodes'].remove(node_id)
        if len(self.forwarding_entries[user_id]['nodes']) == 0:
            self.forwarding_entries.pop(user_id, None)

    def send_message_to_user(self, msg, sock=None):
        """
        Forward message to connecting user
        :param msg:
        :param sock:
        :return:
        """
        if sock is not None:
            self.logger.debug("msg to app: %s" % (msg[KeyType.message]))
            sock.sendall(message_key_types.make_message(PayloadType.Type_msgpack, msg))
            return

        if KeyType.destination_user_id not in msg:
            return

        msg[KeyType.infra_msg_type] = InfraMessageCategory.CATEGORY_USER
        self.logger.debug("msg to app: %s" % (msg[KeyType.message]))
        socks = self.registered_users.get(msg[KeyType.destination_user_id], None)
        if socks is None:
            self.forward_message_to_another_node(msg)
            return
        for s in socks:
            s.sendall(message_key_types.make_message(PayloadType.Type_msgpack, msg))

    def forward_message_to_another_node(self, msg):
        """
        Try to forward message to another node
        :param msg:
        :return:
        """
        dst_user_id = msg[KeyType.destination_user_id]
        if dst_user_id in self.forwarding_entries:
            for dst_node_id in self.forwarding_entries[dst_user_id]['nodes']:
                msg[KeyType.destination_node_id] = dst_node_id
                try:
                    self.network.send_message_in_network(nodeinfo=None, payload_type=PayloadType.Type_msgpack,
                                                         domain_id=self.domain_id,msg=msg)
                except:
                    import traceback
                    traceback.print_exc()
                    pass
            return
        src_user_id = msg[KeyType.source_user_id]
        self.resolve_accommodating_core_node(dst_user_id, src_user_id, msg)

    def resolve_accommodating_core_node(self, dst_user_id, src_user_id, orig_msg=None):
        """
        Resolve which node the user connects to
        :param dst_user_id:
        :param src_user_id:
        :param orig_msg:
        :return:
        """
        if orig_msg is not None:
            query_entry = query_management.QueryEntry(expire_after=UserMessageRouting.RESOLVE_TIMEOUT,
                                                      callback_expire=self.resolve_failure,
                                                      callback=self.resolve_success,
                                                      data={
                                                          KeyType.message: orig_msg,
                                                      },
                                                      retry_count=0)
            self.on_going_timers.add(query_entry.nonce)
        msg = {
            KeyType.infra_msg_type: InfraMessageCategory.CATEGORY_USER,
            KeyType.domain_id: self.domain_id,
            KeyType.command: UserMessageRouting.RESOLVE_USER_LOCATION,
            KeyType.destination_user_id: dst_user_id,
        }
        if orig_msg is not None:
            msg[KeyType.nonce] = query_entry.nonce
        if src_user_id is not None:
            msg[KeyType.source_user_id] = src_user_id
        self.network.broadcast_message_in_network(domain_id=self.domain_id, payload_type=PayloadType.Type_msgpack, msg=msg)

    def resolve_success(self, query_entry):
        """
        Called if succeeded to resolve the location
        :param query_entry:
        :return:
        """
        self.on_going_timers.remove(query_entry.nonce)
        msg = query_entry.data[KeyType.message]
        self.forward_message_to_another_node(msg=msg)

    def resolve_failure(self, query_entry):
        """
        Called if failed to resolve the location
        :param query_entry:
        :return:
        """
        self.on_going_timers.remove(query_entry.nonce)
        msg = query_entry.data[KeyType.message]
        msg[KeyType.destination_user_id] = msg[KeyType.source_user_id]
        msg[KeyType.result] = False
        msg[KeyType.reason] = "Cannot find such user"
        self.send_message_to_user(msg)

    def send_multicast_notification(self, user_id):
        """
        Broadcast NOTIFY_USER_LOCATION_FOR_MULTICAST
        :param user_id:
        :return:
        """
        msg = {
            KeyType.infra_msg_type: InfraMessageCategory.CATEGORY_USER,
            KeyType.domain_id: self.domain_id,
            KeyType.command: UserMessageRouting.NOTIFY_USER_LOCATION_FOR_MULTICAST,
            KeyType.source_user_id: user_id,
        }
        self.network.broadcast_message_in_network(payload_type=PayloadType.Type_msgpack, msg=msg)

    def process_message(self, msg):
        """
        (internal use) process received message
        :param msg:       the message body (already deserialized)
        :return:
        """
        if KeyType.command in msg:
            if msg[KeyType.command] == UserMessageRouting.RESOLVE_USER_LOCATION:
                user_id = msg[KeyType.destination_user_id]
                if user_id not in self.registered_users:
                    return
                self.add_user_for_forwarding(msg[KeyType.source_user_id], msg[KeyType.source_node_id])
                msg[KeyType.destination_node_id] = msg[KeyType.source_node_id]
                if KeyType.source_user_id in msg:
                    msg[KeyType.destination_user_id] = msg[KeyType.source_user_id]
                msg[KeyType.source_user_id] = user_id
                msg[KeyType.command] = UserMessageRouting.RESPONSE_USER_LOCATION
                self.network.send_message_in_network(nodeinfo=None, payload_type=PayloadType.Type_msgpack,
                                                     domain_id=self.domain_id, msg=msg)

            elif msg[KeyType.command] == UserMessageRouting.RESPONSE_USER_LOCATION:
                self.add_user_for_forwarding(msg[KeyType.source_user_id], msg[KeyType.source_node_id])
                if KeyType.nonce in msg:
                    query_entry = ticker.get_entry(msg[KeyType.nonce])
                    if query_entry is not None and query_entry.active:
                        query_entry.callback()

            elif msg[KeyType.command] == UserMessageRouting.RESPONSE_NO_SUCH_USER:
                self.remove_user_from_forwarding(user_id=msg[KeyType.user_id], node_id=msg[KeyType.source_node_id])

            elif msg[KeyType.command] == UserMessageRouting.NOTIFY_USER_LOCATION_FOR_MULTICAST:
                if msg[KeyType.source_node_id] in self.forwarding_entries:
                    self.add_user_for_forwarding(msg[KeyType.source_user_id], msg[KeyType.source_node_id])

            return

        if KeyType.message in msg:
            src_user_id = msg[KeyType.source_user_id]
            if src_user_id in self.forwarding_entries:
                self.forwarding_entries[src_user_id]['refresh'].update(
                    fire_after=UserMessageRouting.REFRESH_FORWARDING_LIST_INTERVAL)
            dst_user_id = msg[KeyType.destination_user_id]
            if dst_user_id not in self.registered_users:
                retmsg = {
                    KeyType.domain_id: self.domain_id,
                    KeyType.infra_msg_type: InfraMessageCategory.CATEGORY_USER,
                    KeyType.destination_node_id: msg[KeyType.source_node_id],
                    KeyType.command: UserMessageRouting.RESPONSE_NO_SUCH_USER,
                    KeyType.user_id: dst_user_id,
                }
                self.network.send_message_in_network(nodeinfo=None, payload_type=PayloadType.Type_msgpack,
                                                     domain_id=self.domain_id, msg=retmsg)
                return
            self.send_message_to_user(msg)
