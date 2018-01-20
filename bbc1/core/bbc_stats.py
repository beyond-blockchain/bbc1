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


class BBcStats:
    def __init__(self):
        self.statistics = dict()

    def clear_stats(self):
        self.statistics = dict()

    def remove_stat_item(self, category, name):
        if category not in self.statistics:
            return
        self.statistics[category].pop(name, None)

    def remove_stat_category(self, category):
        self.statistics.pop(category, None)

    def update_stats(self, category, name, value):
        self.statistics.setdefault(category, dict())[name] = value

    def update_stats_increment(self, category, name, value):
        self.statistics.setdefault(category, dict()).setdefault(name, 0)
        self.statistics[category][name] += value

    def update_stats_decrement(self, category, name, value):
        self.statistics.setdefault(category, dict()).setdefault(name, 0)
        self.statistics[category][name] -= value

    def get_stats(self):
        return self.statistics
