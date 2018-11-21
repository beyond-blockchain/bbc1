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

import random
import os
import sys
sys.path.extend(["../../", os.path.abspath(os.path.dirname(__file__))])
from bbc1.core.message_key_types import to_2byte, PayloadType, KeyType, InfraMessageCategory
from bbc1.core import bbclib
from bbc1.core import query_management, message_key_types, logger

ticker = query_management.get_ticker()


def direct_send_to_user(sock, msg, name=None):
    if name is None:
        sock.sendall(message_key_types.make_message(PayloadType.Type_msgpack, msg))
    else:
        sock.sendall(message_key_types.make_message(PayloadType.Type_encrypted_msgpack, msg, key_name=name))


class UserMessageRouting:
    """Handle message for clients"""
    REFRESH_FORWARDING_LIST_INTERVAL = 300
    RESOLVE_TIMEOUT = 5
    MAX_CROSS_REF_STOCK = 10
    RESOLVE_USER_LOCATION = to_2byte(0)
    RESPONSE_USER_LOCATION = to_2byte(1)
    RESPONSE_NO_SUCH_USER = to_2byte(2)
    JOIN_MULTICAST_RECEIVER = to_2byte(3)
    LEAVE_MULTICAST_RECEIVER = to_2byte(4)
    CROSS_REF_ASSIGNMENT = to_2byte(5)

    def __init__(self, networking, domain_id, loglevel="all", logname=None):
        self.networking = networking
        self.stats = networking.core.stats
        self.domain_id = domain_id
        self.logger = logger.get_logger(key="user_message_routing", level=loglevel, logname=logname)
        self.aes_name_list = dict()
        self.cross_ref_list = list()
        self.registered_users = dict()
        self.forwarding_entries = dict()
        self.on_going_timers = set()

    def stop_all_timers(self):
        """Cancel all running timers"""
        for user_id in self.forwarding_entries.keys():
            if self.forwarding_entries[user_id]['refresh'] is not None:
                self.forwarding_entries[user_id]['refresh'].deactivate()
        for q in self.on_going_timers:
            ticker.get_entry(q).deactivate()

    def set_aes_name(self, socket, name):
        """Set name for specifying AES key for message encryption

        Args:
            socket (Socket): socket for the client
            name (bytes): name of the client (4-byte random value generated in message_key_types.get_ECDH_parameters)
        """
        self.aes_name_list[socket] = name

    def register_user(self, user_id, socket, on_multiple_nodes=False):
        """Register user to forward message

        Args:
            user_id (bytes): user_id of the client
            socket (Socket): socket for the client
            on_multiple_nodes (bool): If True, the user_id is also registered in other nodes, meaning multicasting.
        """
        self.registered_users.setdefault(user_id, set())
        self.registered_users[user_id].add(socket)
        if on_multiple_nodes:
            self.send_multicast_join(user_id)

    def unregister_user(self, user_id, socket):
        """Unregister user from the list and delete AES key if exists

        Args:
            user_id (bytes): user_id of the client
            socket (Socket): socket for the client
        """
        if user_id not in self.registered_users:
            return
        self.registered_users[user_id].remove(socket)
        if len(self.registered_users[user_id]) == 0:
            self.registered_users.pop(user_id, None)
        if socket in self.aes_name_list:
            message_key_types.unset_cipher(self.aes_name_list[socket])
            del self.aes_name_list[socket]
        self.send_multicast_leave(user_id=user_id)

    def _add_user_for_forwarding(self, user_id, node_id, permanent=False):
        """Register user to forwarding list

        Args:
            user_id (bytes): target user_id
            node_id (bytes): node_id which the client with the user_id connects to
            parmanent (bool): If True, the entry won't expire
        """
        self.forwarding_entries.setdefault(user_id, dict())
        if not permanent:
            if 'refresh' not in self.forwarding_entries[user_id]:
                query_entry = query_management.QueryEntry(expire_after=UserMessageRouting.REFRESH_FORWARDING_LIST_INTERVAL,
                                                          callback_expire=self._remove_user_from_forwarding,
                                                          data={
                                                              KeyType.user_id: user_id,
                                                          }, retry_count=0)
                self.forwarding_entries[user_id]['refresh'] = query_entry
            else:
                self.forwarding_entries[user_id]['refresh'].update(fire_after=UserMessageRouting.REFRESH_FORWARDING_LIST_INTERVAL)
        self.forwarding_entries[user_id].setdefault('nodes', set())
        self.forwarding_entries[user_id]['nodes'].add(node_id)
        self.stats.update_stats("user_message", "registered_users_in_forwarding_list", len(self.forwarding_entries))

    def _remove_user_from_forwarding(self, query_entry=None, user_id=None, node_id=None):
        """Unregister user to forwarding list"""
        if query_entry is not None:
            user_id = query_entry.data[KeyType.user_id]
            self.forwarding_entries.pop(user_id, None)
            return
        if user_id not in self.forwarding_entries:
            return
        self.forwarding_entries[user_id]['nodes'].remove(node_id)
        if len(self.forwarding_entries[user_id]['nodes']) == 0:
            if 'refresh' in self.forwarding_entries[user_id]:
                self.forwarding_entries[user_id]['refresh'].deactivate()
            self.forwarding_entries.pop(user_id, None)
        self.stats.update_stats("user_message", "registered_users_in_forwarding_list", len(self.forwarding_entries))

    def send_message_to_user(self, msg, direct_only=False):
        """Forward message to connecting user

        Args:
            msg (dict): message to send
            direct_only (bool): If True, _forward_message_to_another_node is not called.
        """
        if KeyType.destination_user_id not in msg:
            return True

        msg[KeyType.infra_msg_type] = InfraMessageCategory.CATEGORY_USER
        if msg.get(KeyType.is_anycast, False):
            return self._send_anycast_message(msg)

        socks = self.registered_users.get(msg[KeyType.destination_user_id], None)
        if socks is None:
            if direct_only:
                return False
            self._forward_message_to_another_node(msg)
            return True
        count = len(socks)
        for s in socks:
            if not self._send(s, msg):
                count -= 1
        return count > 0

    def _send(self, sock, msg):
        """Raw function to send a message"""
        try:
            if sock in self.aes_name_list:
                direct_send_to_user(sock, msg, name=self.aes_name_list[sock])
            else:
                direct_send_to_user(sock, msg)
            self.stats.update_stats_increment("user_message", "sent_msg_to_user", 1)
        except:
            return False
        return True

    def _send_anycast_message(self, msg):
        """Send message as anycast"""
        dst_user_id = msg[KeyType.destination_user_id]
        if dst_user_id not in self.forwarding_entries:
            return False
        ttl = msg.get(KeyType.anycast_ttl, 0)
        if ttl == 0:
            return False
        randmax = len(self.forwarding_entries[dst_user_id]['nodes'])
        if dst_user_id in self.registered_users:
            randmax += 1
        while ttl > 0:
            idx = random.randrange(randmax)
            msg[KeyType.anycast_ttl] = ttl - 1
            ttl -= 1
            if idx == randmax - 1:
                if len(self.registered_users) > 0:
                    sock = random.choice(tuple(self.registered_users.get(dst_user_id, None)))
                    if sock is not None and self._send(sock, msg):
                        return True
            else:
                try:
                    msg[KeyType.destination_node_id] = random.choice(tuple(self.forwarding_entries[dst_user_id]['nodes']))
                    self.networking.send_message_in_network(nodeinfo=None, payload_type=PayloadType.Type_any,
                                                            domain_id=self.domain_id, msg=msg)
                except:
                    import traceback
                    traceback.print_exc()
                    continue
                return True
        return False

    def _forward_message_to_another_node(self, msg):
        """Try to forward message to another node"""
        dst_user_id = msg[KeyType.destination_user_id]
        if dst_user_id in self.forwarding_entries:
            for dst_node_id in self.forwarding_entries[dst_user_id]['nodes']:
                msg[KeyType.destination_node_id] = dst_node_id
                try:
                    self.networking.send_message_in_network(nodeinfo=None, payload_type=PayloadType.Type_any,
                                                            domain_id=self.domain_id, msg=msg)
                except:
                    import traceback
                    traceback.print_exc()
                    pass
            return
        src_user_id = msg[KeyType.source_user_id]
        self._resolve_accommodating_core_node(dst_user_id, src_user_id, msg)

    def _resolve_accommodating_core_node(self, dst_user_id, src_user_id, orig_msg=None):
        """Resolve which node the user connects to

        Find the node that accommodates the user_id first, and then, send the message to the node.

        Args:
            dst_user_id (bytes): destination user_id
            src_user_id (bytes): source user_id
            orig_msg (dict): message to send
        """
        if orig_msg is not None:
            query_entry = query_management.QueryEntry(expire_after=UserMessageRouting.RESOLVE_TIMEOUT,
                                                      callback_expire=self._resolve_failure,
                                                      callback=self._resolve_success,
                                                      data={
                                                          KeyType.message: orig_msg,
                                                      },
                                                      retry_count=0)
            self.on_going_timers.add(query_entry.nonce)
        msg = {
            KeyType.infra_msg_type: InfraMessageCategory.CATEGORY_USER,
            KeyType.domain_id: self.domain_id,
            KeyType.infra_command: UserMessageRouting.RESOLVE_USER_LOCATION,
            KeyType.destination_user_id: dst_user_id,
        }
        if orig_msg is not None:
            msg[KeyType.nonce] = query_entry.nonce
        if src_user_id is not None:
            msg[KeyType.source_user_id] = src_user_id
        self.networking.broadcast_message_in_network(domain_id=self.domain_id, msg=msg)

    def _resolve_success(self, query_entry):
        """Callback for successful of resolving the location"""
        self.on_going_timers.remove(query_entry.nonce)
        msg = query_entry.data[KeyType.message]
        self._forward_message_to_another_node(msg=msg)

    def _resolve_failure(self, query_entry):
        """Callback for failure of resolving the location"""
        self.on_going_timers.remove(query_entry.nonce)
        msg = query_entry.data[KeyType.message]
        msg[KeyType.destination_user_id] = msg[KeyType.source_user_id]
        msg[KeyType.result] = False
        msg[KeyType.reason] = "Cannot find such user"
        self.send_message_to_user(msg)

    def send_multicast_join(self, user_id, permanent=False):
        """Broadcast JOIN_MULTICAST_RECEIVER"""
        msg = {
            KeyType.infra_msg_type: InfraMessageCategory.CATEGORY_USER,
            KeyType.domain_id: self.domain_id,
            KeyType.infra_command: UserMessageRouting.JOIN_MULTICAST_RECEIVER,
            KeyType.user_id: user_id,
            KeyType.static_entry: permanent,
        }
        self.stats.update_stats_increment("multicast", "join", 1)
        self.networking.broadcast_message_in_network(domain_id=self.domain_id, msg=msg)

    def send_multicast_leave(self, user_id):
        """Broadcast LEAVE_MULTICAST_RECEIVER"""
        msg = {
            KeyType.domain_id: self.domain_id,
            KeyType.infra_msg_type: InfraMessageCategory.CATEGORY_USER,
            KeyType.infra_command: UserMessageRouting.LEAVE_MULTICAST_RECEIVER,
            KeyType.user_id: user_id,
        }
        self.stats.update_stats_increment("multicast", "leave", 1)
        self.networking.broadcast_message_in_network(domain_id=self.domain_id, msg=msg)

    def _distribute_cross_refs_to_clients(self):
        """Distribute cross ref assined by the domain0_manager to client"""
        if len(self.registered_users) == 0:
            return
        try:
            for i in range(len(self.cross_ref_list)):
                msg = {
                    KeyType.domain_id: self.domain_id,
                    KeyType.command: bbclib.MsgType.NOTIFY_CROSS_REF,
                    KeyType.destination_user_id: random.choice(tuple(self.registered_users.keys())),
                    KeyType.cross_ref: self.cross_ref_list.pop(0),
                }
                self.send_message_to_user(msg)
        except:
            import traceback
            traceback.print_exc()
            return

    def process_message(self, msg):
        """Process received message

        Args:
            msg (dict): received message
        """
        if KeyType.infra_command in msg:
            if msg[KeyType.infra_command] == UserMessageRouting.RESOLVE_USER_LOCATION:
                self.stats.update_stats_increment("user_message", "RESOLVE_USER_LOCATION", 1)
                user_id = msg[KeyType.destination_user_id]
                if user_id not in self.registered_users:
                    return
                self._add_user_for_forwarding(msg[KeyType.source_user_id], msg[KeyType.source_node_id])
                msg[KeyType.destination_node_id] = msg[KeyType.source_node_id]
                if KeyType.source_user_id in msg:
                    msg[KeyType.destination_user_id] = msg[KeyType.source_user_id]
                msg[KeyType.source_user_id] = user_id
                msg[KeyType.infra_command] = UserMessageRouting.RESPONSE_USER_LOCATION
                self.networking.send_message_in_network(nodeinfo=None, payload_type=PayloadType.Type_any,
                                                        domain_id=self.domain_id, msg=msg)

            elif msg[KeyType.infra_command] == UserMessageRouting.RESPONSE_USER_LOCATION:
                self.stats.update_stats_increment("user_message", "RESPONSE_USER_LOCATION", 1)
                self._add_user_for_forwarding(msg[KeyType.source_user_id], msg[KeyType.source_node_id])
                if KeyType.nonce in msg:
                    query_entry = ticker.get_entry(msg[KeyType.nonce])
                    if query_entry is not None and query_entry.active:
                        query_entry.callback()

            elif msg[KeyType.infra_command] == UserMessageRouting.RESPONSE_NO_SUCH_USER:
                self.stats.update_stats_increment("user_message", "RESPONSE_NO_SUCH_USER", 1)
                self._remove_user_from_forwarding(user_id=msg[KeyType.user_id], node_id=msg[KeyType.source_node_id])

            elif msg[KeyType.infra_command] == UserMessageRouting.JOIN_MULTICAST_RECEIVER:
                self.stats.update_stats_increment("user_message", "JOIN_MULTICAST_RECEIVER", 1)
                self._add_user_for_forwarding(msg[KeyType.user_id], msg[KeyType.source_node_id],
                                              permanent=msg.get(KeyType.static_entry, False))

            elif msg[KeyType.infra_command] == UserMessageRouting.LEAVE_MULTICAST_RECEIVER:
                self.stats.update_stats_increment("user_message", "LEAVE_MULTICAST_RECEIVER", 1)
                if msg[KeyType.user_id] in self.forwarding_entries:
                    self._remove_user_from_forwarding(user_id=msg[KeyType.user_id],
                                                     node_id=msg[KeyType.source_node_id])

            elif msg[KeyType.infra_command] == UserMessageRouting.CROSS_REF_ASSIGNMENT:
                self.stats.update_stats_increment("user_message", "CROSS_REF_ASSIGNMENT", 1)
                if KeyType.cross_ref in msg:
                    self.cross_ref_list.append(msg[KeyType.cross_ref])
                    if len(self.cross_ref_list) > UserMessageRouting.MAX_CROSS_REF_STOCK:
                        self._distribute_cross_refs_to_clients()

            return

        src_user_id = msg[KeyType.source_user_id]
        if src_user_id in self.forwarding_entries:
            self.forwarding_entries[src_user_id]['refresh'].update(
                fire_after=UserMessageRouting.REFRESH_FORWARDING_LIST_INTERVAL)
        dst_user_id = msg[KeyType.destination_user_id]
        if dst_user_id not in self.registered_users:
            if msg.get(KeyType.is_anycast, False):
                self._send_anycast_message(msg)
                return
            retmsg = {
                KeyType.domain_id: self.domain_id,
                KeyType.infra_msg_type: InfraMessageCategory.CATEGORY_USER,
                KeyType.destination_node_id: msg[KeyType.source_node_id],
                KeyType.infra_command: UserMessageRouting.RESPONSE_NO_SUCH_USER,
                KeyType.user_id: dst_user_id,
            }
            self.stats.update_stats_increment("user_message", "fail_to_find_user", 1)
            self.networking.send_message_in_network(nodeinfo=None, payload_type=PayloadType.Type_any,
                                                    domain_id=self.domain_id, msg=retmsg)
            return
        if KeyType.is_anycast in msg:
            del msg[KeyType.is_anycast]
        self.stats.update_stats_increment("user_message", "send_to_user", 1)
        self.send_message_to_user(msg)


class UserMessageRoutingDummy(UserMessageRouting):
    """Dummy class for bbc_core.py"""
    def stop_all_timers(self):
        pass

    def register_user(self, user_id, socket, on_multiple_nodes=False):
        pass

    def unregister_user(self, user_id, socket=None):
        pass

    def _add_user_for_forwarding(self, user_id, node_id, permanent=False):
        pass

    def _remove_user_from_forwarding(self, query_entry=None, user_id=None, node_id=None):
        pass

    def send_message_to_user(self, msg, direct_only=False):
        pass

    def _forward_message_to_another_node(self, msg):
        pass

    def _resolve_accommodating_core_node(self, dst_user_id, src_user_id, orig_msg=None):
        pass

    def _resolve_success(self, query_entry):
        pass

    def _resolve_failure(self, query_entry):
        pass

    def send_multicast_join(self, user_id, permanent=False):
        pass

    def process_message(self, msg):
        pass
