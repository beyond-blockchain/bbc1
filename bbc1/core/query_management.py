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
import threading
import copy
import random


TICK_INTERVAL = 0.05*0.98   # sec
DEFAULT_TIMEOUT = 3

ticker = None


def get_ticker(tick_interval=TICK_INTERVAL):
    global ticker
    if ticker is None:
        ticker = Ticker(tick_interval)
    return ticker


class Ticker:
    """Clock ticker for query timers"""
    def __init__(self, tick_interval=TICK_INTERVAL):
        """Create Ticker object

        Args:
            tick_interval (float): tick interval in second
        """
        self.tick_interval = tick_interval
        self.schedule = []
        self.queries = dict()
        self.lock = threading.Lock()
        th = threading.Thread(target=self._tick_loop)
        th.setDaemon(True)
        th.start()

    def _tick_loop(self):
        while True:
            need_reorder = False
            #print("%s" % [e.expire_at for e in self.schedule])
            while len(self.schedule) > 0 and self.schedule[0].fire_at <= time.time():
                with self.lock:
                    entry = self.schedule.pop(0)
                if entry.nonce in self.queries:
                    ret = entry._fire()
                    if ret:
                        del self.queries[entry.nonce]
                    else:
                        self.schedule.append(entry)
                        need_reorder = True
            if need_reorder:
                with self.lock:
                    self.schedule.sort()
            time.sleep(self.tick_interval)
            #print(".")

    def _add_entry(self, entry):
        """Add an event to the scheduler"""
        nonce = random.randint(0, 0xFFFFFFFF)  # 4-byte
        while nonce in self.queries:
            nonce = random.randint(0, 0xFFFFFFFF)  # 4-byte
        self.queries[nonce] = entry
        entry.nonce = nonce
        with self.lock:
            self.schedule.append(entry)
            self.schedule.sort(key=lambda ent: ent.fire_at)
            #print(" --> add:", entry.expire_at)
            #print("%s" % [e.expire_at for e in self.schedule])
        return nonce

    def get_entry(self, nonce):
        """Get an entry identified by nonce"""
        return self.queries.get(nonce, None)

    def del_entry(self, nonce):
        """Delete an entry from the scheduler identified by nonce"""
        entry = self.queries[nonce]
        del self.queries[entry.nonce]

    def _update_timer(self, nonce, append_new_flag):
        """Sort the list of scheduler"""
        if nonce not in self.queries:
            return
        entry = self.queries[nonce]
        with self.lock:
            if append_new_flag:
                self.schedule.append(entry)
            self.schedule.sort()

    def _refresh_timer(self):
        """Sort the list of scheduler triggered by the refresh timer"""
        with self.lock:
            self.schedule.sort()


class QueryEntry:
    """Callback manager"""
    def __init__(self, expire_after=30, callback_expire=None, callback=None, callback_error=None,
                 interval=0, data={}, retry_count=-1):
        """Create an entry. expire_after and callback_expire ensures that this entry expires eventually

        Args:
            expire_after (float): expiration time in seconds
            callback_expire (obj): callback method that will be called when expire
            callback (obj): callback method that will be called periodically or when successful
            callback_error (obj): callback method that will be called when error happens
            interval (float): interval for periodical callback
            data (dict): arbitrary parameters for callback methods
            retry_count (int): the number of retry before expiration
        """
        self.created_at = time.time()
        self.active = True
        self.expire_at = self.created_at + expire_after
        self.fire_interval = interval
        self.retry_count = retry_count
        self.callback_expire = callback_expire
        self.data = copy.deepcopy(data)
        self.fire_at = self.expire_at
        self.callback_success = callback
        self.callback_failure = callback_error
        self.entry_exists_in_ticker_scheduler = False
        self.update(init=True)
        self.nonce = ticker._add_entry(self)

    def __lt__(self, other):
        return self.fire_at < other.fire_at

    def deactivate(self):
        """Deactivate the entry"""
        self.active = False

    def update_expiration_time(self, expire_after):
        """Update the expire timer

        Args:
            expire_after (float): new expiration time in second
        """
        self.expire_at = time.time() + expire_after
        #print(" -> update_expiration_time:", self.expire_at)
        if self.fire_at > self.expire_at:
            self.fire_at = self.expire_at
            if ticker is not None:
                ticker._refresh_timer()

    def _fire(self):
        """Fire the entry

        Returns:
            bool: True if this fire is triggered by expiration
        """
        if time.time() < self.expire_at and self.retry_count != 0:
            self.entry_exists_in_ticker_scheduler = False
            if self.active and self.callback_failure is not None:
                self.callback_failure(self)
            self.retry_count -= 1
            if self.retry_count == 0 or self.fire_at + self.fire_interval > self.expire_at:
                self.fire_at = self.expire_at
            else:
                if self.fire_interval > 0:
                    self.fire_at += self.fire_interval
                else:
                    self.fire_at = self.expire_at
            return False
        else:
            if self.active and self.callback_expire is not None:
                self.deactivate()
                self.callback_expire(self)
            return True

    def update(self, fire_after=None, expire_after=None, callback=None, callback_error=None, init=False):
        """Update the entry information

        Args:
            fire_after (float): set callback (periodical) to fire after given time (in second)
            expire_after (float): set expiration timer to given time (in second)
            callback (obj): callback method that will be called periodically
            callback_error (obj): callback method that will be called when error happens
            init (bool): If True, the scheduler is sorted again
        """
        now = time.time()
        if expire_after is not None:
            self.expire_at = now + expire_after
            if self.fire_at > self.expire_at:
                self.fire_at = self.expire_at
        if fire_after is not None:
            if now + fire_after < self.expire_at:
                self.fire_at = now + fire_after
            else:
                self.fire_at = self.expire_at
        if callback is not None:
            self.callback_success = callback
        if callback_error is not None:
            self.callback_failure = callback_error
        self.active = True
        if not init:
            ticker._update_timer(self.nonce, not self.entry_exists_in_ticker_scheduler)
        self.entry_exists_in_ticker_scheduler = True

    def callback(self):
        """Call a callback function for successful case"""
        self.deactivate()
        if self.callback_success is not None:
            self.callback_success(self)

    def callback_error(self):
        """Call a callback function for failure case"""
        self.retry_count -= 1
        if self.retry_count == 0:
            return self._fire()
        if self.callback_failure is not None:
            self.callback_failure(self)
