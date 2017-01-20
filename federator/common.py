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

from enum import Enum
from datetime import datetime
import uuid
from federator.domains_manager import DomainsManager
from federator.parsers import is_uuid


class UserPermissions(Enum):
    null = 1
    administrator = 2
    user = 3
    domain = 4


class User:
    def __init__(self, data):
        self.domain_manager = None
        self._token = None
        self.username = data['username']
        self.password = data['password']
        if 'user_permissions' in data:
            self.user_permissions = UserPermissions[data['user_permissions']]
        else:
            self.user_permissions = UserPermissions.null
        if 'last_access' in data:
            self.last_access = data['last_access']
        else:
            self.last_access = datetime.utcfromtimestamp(100000)

        assert type(self.user_permissions) == UserPermissions
        assert type(self.last_access) == datetime

    def set_token(self, token):
        self._token = token

    def get_token(self):
        return self._token

    def to_jsondict(self):
        out = {
            'token': self._token,
            'username': self.username,
            'password': self.password,
            'user_permissions': self.user_permissions.name,
            'last_access': self.last_access}
        return out


class LoggedUsers:
    def __init__(self, rabbit_data, module):
        self._users = []
        self._domains_manager = DomainsManager(rabbit_data, module)

    def terminate(self):
        for user in self._users:
            self.logout(user.username)

    def login(self, user):
        token = str(uuid.uuid4())
        user.set_token(token)

        if user.user_permissions == UserPermissions.domain:
            user.domain_manager = self._domains_manager.add_domain(token, user)

        self._users.append(user)
        return token

    def logout(self, username):
        old_users = [user for user in self._users if user.username == username]
        assert len(old_users) <= 1
        if len(old_users) != 0:
            old_user = old_users[0]

            if old_user.user_permissions == UserPermissions.domain:
                self._domains_manager.remove_domain(old_user)
                old_user.domain = None

            self._users.remove(old_user)
            return True
        else:
            return False

    def get_user_from_token(self, token):
        toreturn = [user for user in self._users if user.get_token() == token]
        assert len(toreturn) <= 1
        if len(toreturn) == 0:
            return None
        else:
            return toreturn[0]

    def get_logged_users(self, username=None):
        if username is None:
            return self._users
        else:
            toreturn = [user for user in self._users
                        if user.username == username]
            assert len(toreturn) <= 1
            return toreturn

    def get_vnfs(self, mask=None):
        if mask is None:
            toreturn = [{'domain': user.username,
                         'vnfs_catalog': user.domain_manager.get_short_vnfs()}
                        for user in self._users
                        if user.domain_manager is not None]
        elif is_uuid(mask):
            toreturn = [user.domain_manager.get_vnfs(mask)
                        for user in self._users
                        if user.domain_manager is not None
                        and len(user.domain_manager.get_vnfs(mask)) > 0][0]
            if len(toreturn) == 0:
                return None
            assert len(toreturn) == 1
            toreturn = toreturn[0]
        else:
            toreturn = [{'domain': user.username,
                         'vnfs_catalog': user.domain_manager.get_short_vnfs()}
                        for user in self._users
                        if user.domain_manager is not None
                        and user.username == mask]
            assert len(toreturn) == 1

        return toreturn
