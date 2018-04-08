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
    """
    Clock ticker for query timers
    """
    def __init__(self, tick_interval=TICK_INTERVAL):
        """
        Create Ticker object. schedule_final array is for the fail safe to avoid zombie entry.

        :param tick_interval:
        """
        self.tick_interval = tick_interval
        self.schedule = []
        self.queries = dict()
        self.lock = threading.Lock()
        th = threading.Thread(target=self.tick_loop)
        th.setDaemon(True)
        th.start()

    def tick_loop(self):
        while True:
            need_reorder = False
            #print("%s" % [e.expire_at for e in self.schedule])
            while len(self.schedule) > 0 and self.schedule[0].fire_at <= time.time():
                with self.lock:
                    entry = self.schedule.pop(0)
                if entry.nonce in self.queries:
                    ret = entry.fire()
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

    def add_entry(self, entry):
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
        return self.queries.get(nonce, None)

    def del_entry(self, nonce):
        entry = self.queries[nonce]
        del self.queries[entry.nonce]

    def update_timer(self, nonce, append_new_flag):
        if nonce not in self.queries:
            return
        entry = self.queries[nonce]
        with self.lock:
            if append_new_flag:
                self.schedule.append(entry)
            self.schedule.sort()

    def refresh_timer(self):
        with self.lock:
            self.schedule.sort()


class QueryEntry:
    """
    Querying entry
    """
    def __init__(self, expire_after=30, callback_expire=None, callback=None, callback_error=None,
                 interval=0, data={}, retry_count=-1):
        """
        Create entry. expire_after and callback_expire ensures that this entry expires eventually.

        :param expire_after:
        :param callback_expire:
        :param data:
        :param retry_count: retry count until calling callback_expire (if retry_count==-1, no limit)
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
        self.nonce = ticker.add_entry(self)

    def __lt__(self, other):
        return self.fire_at < other.fire_at

    def deactivate(self):
        """
        Deactivate the entry

        :return:
        """
        self.active = False

    def rest_of_time_to_expire(self):
        """
        Get the rest of time to expire
        :return:
        """
        return self.expire_at - time.time()

    def update_expiration_time(self, expire_after):
        """
        Update the expire timer

        :param expire_after:
        :return:
        """
        self.expire_at = time.time() + expire_after
        #print(" -> update_expiration_time:", self.expire_at)
        if self.fire_at > self.expire_at:
            self.fire_at = self.expire_at
            if ticker is not None:
                ticker.refresh_timer()

    def set_next_fire_at(self, now):
        if now + self.fire_interval < self.expire_at:
            self.fire_at = now + self.fire_interval
        else:
            self.fire_at = self.expire_at

    def fire(self):
        """
        Fire the entry

        :return: True if expire
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

    def force_expire(self):
        """
        Forcibly make the entry expire

        :return:
        """
        self.deactivate()
        self.callback_expire(self)

    def update(self, fire_after=None, expire_after=None, callback=None, callback_error=None, init=False):
        """
        Update the entry information

        :param fire_after:
        :param expire_after:
        :param callback:
        :param callback_error:
        :param init:
        :return:
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
            ticker.update_timer(self.nonce, not self.entry_exists_in_ticker_scheduler)
        self.entry_exists_in_ticker_scheduler = True

    def callback(self):
        """
        Call a callback function for successful case

        :return:
        """
        self.deactivate()
        if self.callback_success is not None:
            self.callback_success(self)

    def callback_error(self):
        """
        Call a callback function for failure case

        :return:
        """
        self.retry_count -= 1
        if self.retry_count == 0:
            return self.fire()
        if self.callback_failure is not None:
            self.callback_failure(self)


def exec_func_after(func, after):
    """
    Simple timer utility to call function after specified time (second)

    :param func:
    :param after:
    :return:
    """
    return QueryEntry(expire_after=after, callback_expire=func, retry_count=0)
