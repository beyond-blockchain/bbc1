# -*- coding: utf-8 -*-
import pytest
import pprint

import sys
sys.path.extend(["../"])
from bbc1.core import bbc_stats

bbcstats = bbc_stats.BBcStats()


class TestBBcStats(object):

    def test_0_get(self):
        print("-----", sys._getframe().f_code.co_name, "-----")
        result = bbcstats.get_stats()
        pprint.pprint(result)

    def test_1_add_item(self):
        print("-----", sys._getframe().f_code.co_name, "-----")
        bbcstats.update_stats("cat1", "item1", 10)
        bbcstats.update_stats("cat2", "itemA", 20)
        bbcstats.update_stats("cat1", "item2", 30)

    def test_2_increment(self):
        print("-----", sys._getframe().f_code.co_name, "-----")
        bbcstats.update_stats_increment("cat1", "item2", 5)

    def test_3_get(self):
        print("-----", sys._getframe().f_code.co_name, "-----")
        result = bbcstats.get_stats()
        pprint.pprint(result)

    def test_4_remove_item(self):
        print("-----", sys._getframe().f_code.co_name, "-----")
        bbcstats.remove_stat_item("cat1", "item2")
        result = bbcstats.get_stats()
        pprint.pprint(result)

    def test_5_remove_category(self):
        print("-----", sys._getframe().f_code.co_name, "-----")
        bbcstats.remove_stat_category("cat2")
        result = bbcstats.get_stats()
        pprint.pprint(result)

    def test_6_clear(self):
        print("-----", sys._getframe().f_code.co_name, "-----")
        bbcstats.clear_stats()
        result = bbcstats.get_stats()
        pprint.pprint(result)


if __name__ == '__main__':
    pytest.main()
