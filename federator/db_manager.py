# Copyright 2017 Giovanni Baggio Create Net / FBK (http://create-net.fbk.eu/)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied. See the License for the
# specific language governing permissions and limitations
# under the License.

from pymongo import MongoClient
import pymongo
import logging

from federator.common import User

LOG = logging.getLogger(__name__)


class DbManager:
    def __init__(self, db_data):
        self.mongodb_ip = db_data['ipaddr']
        self.mongodb_port = int(db_data['port'])

    def is_allright(self):
        try:
            client = MongoClient(self.mongodb_ip, self.mongodb_port)

            collections = ['users', 'nsds', 'nsrs', 'measurements']
            db_collections = client.FNRM.collection_names()
            for collection in collections:
                if collection not in db_collections:
                    client.FNRM.create_collection(collection)

            result = client.FNRM.users.index_information()
            matching_indexes = [index for index in result
                                if 'username' in index]
            if len(matching_indexes) == 0:
                client.FNRM.users.create_index([('username', pymongo.OFF)],
                                               unique=True)
            else:
                assert len(matching_indexes) == 1
                assert matching_indexes[0] == 'username_0'

            result = client.FNRM.nsds.index_information()
            matching_indexes = [index for index in result
                                if 'name' in index and 'owner' in index]
            if len(matching_indexes) == 0:
                client.FNRM.nsds.create_index(
                    [('name', pymongo.OFF), ('owner', pymongo.OFF)],
                    unique=True)
            else:
                assert len(matching_indexes) == 1
                assert matching_indexes[0] == 'name_0_owner_0'

            result = client.FNRM.measurements.index_information()
            matching_indexes = [index for index in result
                                if 'md_nsr_uuid' in index]
            if len(matching_indexes) == 0:
                client.FNRM.measurements.create_index(
                    [('md_nsr_uuid', pymongo.OFF)], unique=False)
            else:
                assert len(matching_indexes) == 1
                assert matching_indexes[0] == 'md_nsr_uuid_0'

        except Exception as e:
            LOG.error(str(e))
            return False
        return True

    def check_default_user(self, federation):
        try:
            client = MongoClient(self.mongodb_ip, self.mongodb_port)
            result = client.FNRM.users.find(
                {'username': federation['default_username']})
            if result.count() == 0:
                user_data = {'username': federation['default_username'],
                             'password': federation['default_password'],
                             'user_permissions': 'administrator'}
                default_user = User(user_data)
                client.FNRM.users.insert(default_user.to_jsondict())
        except Exception as e:
            LOG.error(str(e))
            return False
        return True
