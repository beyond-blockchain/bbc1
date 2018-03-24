# -*- coding: utf-8 -*-
import pytest

import time
import queue

import sys
sys.path.extend(["../"])
from bbc1.core import query_management


ticker = None
result_queue = queue.Queue()


def callback_normal(entry):
    print("-----", sys._getframe().f_code.co_name, "-----")
    print("--> %s" % entry.data)
    result_queue.put(1)


def callback_error(entry):
    print("-----", sys._getframe().f_code.co_name, "-----")
    print("==> %s" % entry.data)
    result_queue.put(0)


def callback_expire(entry):
    print("-----", sys._getframe().f_code.co_name, "-----")
    print("==> %s" % entry.data)
    result_queue.put(-1)


def wait_results(count):
    total = 0
    for i in range(count):
        total += result_queue.get()
    return total


class TestPendingRequest(object):

    def test_01_setup(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        global ticker
        ticker = query_management.get_ticker()

    def test_02_normal_callback(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        entry = query_management.QueryEntry(expire_after=2, callback_expire=callback_expire,
                                            callback=callback_normal, callback_error=callback_error,
                                            data=[2, 2, 2])
        entry.update(fire_after=1.5)
        time.sleep(1)
        entry.callback()   # entry is deactivated in the callback
        total = wait_results(1)
        assert total == 1

    def test_02_deactivate(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        entry = query_management.QueryEntry(expire_after=3, callback_expire=callback_expire,
                                            callback=callback_normal, callback_error=callback_error,
                                            interval=2,
                                            data=[2.5, 2.5, 2.5],
                                            retry_count=1)
        print("**sleep 2.5 sec")
        time.sleep(2.5)
        entry.deactivate()

    def test_03_callback_expire(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        entry = query_management.QueryEntry(expire_after=5, callback_expire=callback_expire, data=[4, 4, 4])
        total = wait_results(1)
        assert total == -1

    def test_04_expire_callback_reschedule(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        entry = query_management.QueryEntry(expire_after=2, callback_expire=callback_expire,
                                            callback=callback_normal, callback_error=callback_error,
                                            data=[3, 3, 3])
        entry.update(expire_after=1.5)
        time.sleep(1.6)
        entry.deactivate()
        total = wait_results(1)
        assert total == -1

    def test_05_multiple_entries_normal(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        query_entries = []
        for i in range(10):
            entry = query_management.QueryEntry(expire_after=4, callback_expire=callback_expire,
                                                callback=callback_normal, callback_error=callback_error,
                                                data=[i, 0, 5])
            entry.update(fire_after=2)
            query_entries.append(entry.nonce)

        time.sleep(1)
        for i in range(10):
            entry = ticker.get_entry(query_entries[i])
            entry.callback()
            ticker.del_entry(query_entries[i])
        total = wait_results(10)
        assert total == 10

    def test_06_multiple_entries_normal_error_expire(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        query_entries = []
        for i in range(10):
            entry = query_management.QueryEntry(expire_after=5, callback_expire=callback_expire,
                                                callback=callback_normal, callback_error=callback_error,
                                                data=[i, 0, 6])
            entry.update(2)
            query_entries.append(entry.nonce)
        time.sleep(1)

        # -- normal
        for i in range(10):
            entry = ticker.get_entry(query_entries[i])
            entry.callback()
        total = wait_results(10)
        assert total == 10

        # -- error
        for i in range(10):
            entry = ticker.get_entry(query_entries[i])
            entry.update(1)
        total = wait_results(10)
        assert total == 0

        # -- finally
        time.sleep(5)
        total = wait_results(10)
        assert total == -10

    def test_99_show_scheduler(self):
        print("\n-----", sys._getframe().f_code.co_name, "-----")
        time.sleep(2)
        print(ticker.schedule)
        print(ticker.queries)


if __name__ == '__main__':
    pytest.main()

