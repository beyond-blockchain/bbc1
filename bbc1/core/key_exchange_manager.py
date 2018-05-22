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
from bbc1.core import query_management, message_key_types
from bbc1.core.message_key_types import KeyType


def remove_old_key(query_entry):
    #print("===>", query_entry.data[KeyType.hint].hex()[:10])
    message_key_types.unset_cipher(query_entry.data[KeyType.hint])


class KeyExchangeManager:
    """ECDH (Elliptic Curve Diffie-Hellman) key exchange manager"""
    KEY_EXCHANGE_INVOKE_MAX_BACKOFF = 6
    KEY_EXCHANGE_RETRY_INTERVAL = 5
    KEY_REFRESH_INTERVAL = 604800
    KEY_OBSOLETE_TIMER = 10

    STATE_NONE = 0
    STATE_REQUESTING = 1
    STATE_CONFIRMING = 2
    STATE_ESTABLISHED = 3

    def __init__(self, networking, domain_id, counter_node_id):
        self.networking = networking
        self.domain_id = domain_id
        self.counter_node_id = counter_node_id
        self.state = KeyExchangeManager.STATE_NONE
        self.secret_key = None
        self.peer_public_key = None
        self.nonce = None
        self.random = None
        self.pending_key_name = None
        self.key_name = None
        self.shared_key = None
        self.timer_entry = None

    def _set_state(self, state):
        """Set state of key exchange process"""
        #print("** set state from %d to %d" % (self.state, state))
        self.state = state

    def set_cipher(self, key_name, hint):
        """Set key to the encryptor and decryptor"""
        message_key_types.set_cipher(self.shared_key, self.nonce, key_name, hint)

    def unset_cipher(self, key_name=None):
        """Unset key from the encryptor and decryptor"""
        if key_name is None:
            if self.key_name is not None:
                message_key_types.unset_cipher(self.key_name)
            if self.pending_key_name is not None:
                message_key_types.unset_cipher(self.pending_key_name)
        else:
            message_key_types.unset_cipher(key_name)

    def stop_all_timers(self):
        """Stop all timers"""
        if self.timer_entry is not None and self.timer_entry.active:
            self.timer_entry.deactivate()

    def set_invoke_timer(self, timeout, retry_entry=False):
        """Set timer for key refreshment"""
        if self.timer_entry is not None and self.timer_entry.active:
            self.timer_entry.deactivate()
        #print("(%d) set_invoke_timer:" % int(time.time()), timeout)
        self.timer_entry = query_management.QueryEntry(expire_after=timeout,
                                                       callback_expire=self._perform_key_exchange,
                                                       retry_count=0)
        if retry_entry:
            self.timer_entry.data[KeyType.retry_timer] = True

    def _set_delete_timer(self, key_name, timeout):
        """Set timer for key revocation"""
        if key_name is not None:
            #print("(%d) _set_delete_timer:" % int(time.time()), key_name.hex()[:10], timeout)
            query_management.QueryEntry(expire_after=timeout, callback_expire=remove_old_key,
                                        data={KeyType.hint: key_name}, retry_count=0)

    def _perform_key_exchange(self, query_entry):
        """Perform ECDH key exhange to establish secure channel to the node"""
        if KeyType.retry_timer in query_entry.data and query_entry.data[KeyType.retry_timer]:
            message_key_types.unset_cipher(self.pending_key_name)
            self.pending_key_name = None
        self._set_state(KeyExchangeManager.STATE_REQUESTING)
        #print("# (%d) _perform_key_exchange: to" % int(time.time()), self.counter_node_id.hex())
        self.secret_key, self.peer_public_key, self.pending_key_name = message_key_types.get_ECDH_parameters()
        self.nonce = os.urandom(16)
        self.random = os.urandom(8)
        ret = self.networking.send_key_exchange_message(self.domain_id, self.counter_node_id, "request",
                                                        self.peer_public_key, self.nonce, self.random,
                                                        self.pending_key_name)
        if not ret:
            self._set_state(KeyExchangeManager.STATE_NONE)
            message_key_types.unset_cipher(self.pending_key_name)
            message_key_types.unset_cipher(self.key_name)
            self.secret_key = None
            self.peer_public_key = None
            self.pending_key_name = None
            self.nonce = None
            self.random = None
            return
        rand_time = KeyExchangeManager.KEY_EXCHANGE_RETRY_INTERVAL*random.uniform(0.5, 1.5)
        self.set_invoke_timer(rand_time, retry_entry=True)

    def receive_exchange_request(self, pubkey, nonce, random_val, hint):
        """Procedure when receiving message with BBcNetwork.REQUEST_KEY_EXCHANGE

        Args:
            pubkey (bytes): public key
            nonce (bytes): nonce value
            random_val (bytes): random value in calculating key
        """
        if self.state != KeyExchangeManager.STATE_REQUESTING:
            #print("(%d) receive_exchange_request: processing" % int(time.time()))
            self.peer_public_key = pubkey
            self.nonce = nonce
            self.random = random_val
            self.secret_key, self.peer_public_key, self.pending_key_name = message_key_types.get_ECDH_parameters()
            self.shared_key = message_key_types.derive_shared_key(self.secret_key, pubkey, random_val)
            self._set_state(KeyExchangeManager.STATE_CONFIRMING)
            self.networking.send_key_exchange_message(self.domain_id, self.counter_node_id, "response",
                                                     self.peer_public_key, self.nonce, self.random,
                                                     self.pending_key_name)
            self.set_cipher(self.pending_key_name, hint)
        else:
            #print("(%d) receive_exchange_request: ignoring" % int(time.time()))
            message_key_types.unset_cipher(self.pending_key_name)
            self.pending_key_name = None
            if self.key_name is None:
                self._set_state(KeyExchangeManager.STATE_NONE)
            else:
                self._set_state(KeyExchangeManager.STATE_ESTABLISHED)
        rand_time = KeyExchangeManager.KEY_EXCHANGE_RETRY_INTERVAL * random.uniform(0.5, 1.5)
        if self.timer_entry is not None and self.timer_entry.active:
            self.timer_entry.update_expiration_time(rand_time)
            self.timer_entry.data[KeyType.retry_timer] = True
        else:
            self.set_invoke_timer(rand_time, retry_entry=True)

    def receive_exchange_response(self, pubkey, random_val, hint):
        """Process ECDH procedure (receiving response)"""
        #print("(%d) receive_exchange_response:" % int(time.time()))
        #print(" **> state:", self.state)
        if self.state != KeyExchangeManager.STATE_REQUESTING:
            return
        rand_time = int(KeyExchangeManager.KEY_REFRESH_INTERVAL*random.uniform(0.9, 1.1))
        self.set_invoke_timer(rand_time)
        self.shared_key = message_key_types.derive_shared_key(self.secret_key, pubkey, random_val)
        self._set_delete_timer(self.key_name, KeyExchangeManager.KEY_OBSOLETE_TIMER)
        self.networking.send_key_exchange_message(self.domain_id, self.counter_node_id, "confirm", self.peer_public_key,
                                                 self.nonce, self.random, self.pending_key_name)
        self.key_name = self.pending_key_name
        self.set_cipher(self.key_name, hint)
        self._set_state(KeyExchangeManager.STATE_ESTABLISHED)
        #print("*STATE_ESTABLISHED")

    def receive_confirmation(self):
        """Confirm that the key has been agreed"""
        #print("(%d) receive_confirmation:" % int(time.time()))
        #print(" **> state:", self.state)
        if self.state != KeyExchangeManager.STATE_CONFIRMING:
            return
        rand_time = int(KeyExchangeManager.KEY_REFRESH_INTERVAL*random.uniform(0.9, 1.1))
        self.set_invoke_timer(rand_time)
        self._set_delete_timer(self.key_name, KeyExchangeManager.KEY_OBSOLETE_TIMER)
        self.key_name = self.pending_key_name
        self._set_state(KeyExchangeManager.STATE_ESTABLISHED)
        #print("*STATE_ESTABLISHED")
