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
import binascii
import os

import sys
sys.path.extend(["../../"])
from bbc1.common import logger
from bbc1.common.bbclib import StorageType


class BBcStorage:
    """
    Storage manager
    """
    def __init__(self, config, core=None, loglevel="all", logname=None):
        self.logger = logger.get_logger(key="bbc_storage", level=loglevel, logname=logname)
        self.config = config
        self.core = core
        conf = self.config.get_config()
        if 'storage' in conf and 'root' in conf['storage']:
            if conf['storage']['root'].startswith("/"):
                self.storage_root = conf['storage']['root'] + "/"
            else:
                self.storage_root = conf['workingdir'] + "/"
        else:
            self.storage_root = conf['workingdir'] + "/"
        os.makedirs(self.storage_root, exist_ok=True)
        self.storage_type = dict()
        self.storage_path = dict()

    def set_storage_path(self, domain_id, storage_type=StorageType.FILESYSTEM, storage_path=None):
        """
        Set storage path for the domain

        :param domain_id:
        :param storage_type: filesystem/HTTP-PUT/HTTP-POST/NONE
        :param storage_path:    directory path or URL
        :return: True if make dir is successful
        """
        if storage_type == StorageType.NONE:
            self.storage_type.pop(domain_id, None)
            self.storage_path[domain_id] = None
            return True
        domain_id_str = binascii.b2a_hex(domain_id).decode('utf-8')
        if storage_path is None:
            storage_path = self.storage_root + domain_id_str + "/"
        if not os.path.exists(storage_path):
            os.mkdir(storage_path, 0o777)

        self.storage_type[domain_id] = storage_type
        self.storage_path.setdefault(domain_id, dict())

    def get_storage_type(self, domain_id):
        """
        Get storage type for the domain

        :param domain_id:
        :return:
        """
        if domain_id in self.storage_type:
            return self.storage_type[domain_id]
        return None

    def create_new_directory(self, domain_id, asset_group_id):
        """
        Create a new directory for new asset_group_id
        :param domain_id: domain to put in
        :param asset_group_id:
        :return:
        """
        domain_id_str = binascii.b2a_hex(domain_id).decode('utf-8')
        asset_group_id_str = binascii.b2a_hex(asset_group_id).decode('utf-8')
        storage_path = self.storage_root + domain_id_str + "/" + asset_group_id_str + "/storage/"
        if not os.path.exists(storage_path):
            os.makedirs(storage_path)
        self.storage_path[domain_id][asset_group_id] = storage_path

    def store_locally(self, domain_id, asset_group_id, asid, content):
        """
        Store data in local storage

        :param domain_id: domain to put in
        :param asset_group_id
        :param asid:
        :param content:
        :return:
        """
        if domain_id not in self.storage_type:
            return True
        elif self.storage_type[domain_id] == StorageType.FILESYSTEM:
            return self.store_in_filesystem(domain_id, asset_group_id, asid, content)

        self.logger.info("Not supported yet.")
        return False

    def store_in_filesystem(self, domain_id, asset_group_id, asid, content):
        """
        Store data in a file system

        :param domain_id: domain to put in
        :param asset_group_id
        :param asid:
        :param content:
        :return:
        """
        if asset_group_id not in self.storage_path[domain_id]:
            self.create_new_directory(domain_id, asset_group_id)
        path = self.storage_path[domain_id][asset_group_id]+"/"+binascii.b2a_hex(asid).decode('utf-8')
        with open(path, 'wb') as f:
            try:
                f.write(content)
            except:
                return False
        return os.path.exists(path)

    def get_locally(self, domain_id, asset_group_id, asid):
        """
        Get the file with the asset_id from local storage

        :param domain_id: domain to search in
        :param asset_group_id
        :param asid:   file name
        :return:       the file content (None if not found)
        """
        if domain_id not in self.storage_type:
            return None
        elif self.storage_type[domain_id] == StorageType.FILESYSTEM:
            return self.get_in_filesystem(domain_id, asset_group_id, asid)

        self.logger.info("Not supported yet.")
        return False

    def get_in_filesystem(self, domain_id, asset_group_id, asid):
        """
        Get the file with the asset_id in a file system

        :param domain_id: domain to search in
        :param asset_group_id
        :param asid:   file name
        :return:       the file content (None if not found)
        """
        if asset_group_id not in self.storage_path[domain_id]:
            return None
        path = self.storage_path[domain_id][asset_group_id]+"/"+binascii.b2a_hex(asid).decode('utf-8')
        if os.path.exists(path):
            try:
                with open(path, 'rb') as f:
                    content = f.read()
                return content
            except:
                pass
        return None

    def remove(self, domain_id, asset_group_id, asid):
        """
        Remove the file with the asset_id

        :param domain_id:
        :param asset_group_id
        :param asid:   file name
        :return:       True if succeeded
        """
        if domain_id not in self.storage_type:
            return None
        if asset_group_id not in self.storage_path[domain_id]:
            return None
        # TODO: do we need this method? If so, removing remote resources is also needed
        path = self.storage_path[domain_id][asset_group_id]+"/"+binascii.b2a_hex(asid).decode('utf-8')
        if os.path.exists(path):
            os.remove(path)
        else:
            return False
        return not os.path.exists(path)
