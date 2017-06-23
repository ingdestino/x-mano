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

import tornado.escape
import tornado.ioloop
import tornado.web
from pymongo import errors
from pymongo import MongoClient
from threading import Thread
import json
import logging
import datetime

from federator.parsers import json_pymongo, obj_pymongo, yaml_pymongo
from federator.common import User
from federator.common import UserPermissions
from federator.parsers import is_uuid
from federator.nsd import NSD
from federator.nsrs_manager import NSRsManager
from common.functions import perf_log


LOG = logging.getLogger(__name__)

mongodb_ip = None
mongodb_port = None
logged_users = None
nsrs_manager = None


def check_request(headers, user_permissions):
    if type(user_permissions) != list:
        user_permissions = [user_permissions]
    users = logged_users.get_logged_users()
    if 'Auth' not in headers:
        return 401
    token = headers['Auth']
    user = [user for user in users if user.get_token() == token]
    if len(user) == 0:
        return 401
    if user[0].user_permissions not in user_permissions:
        return 403
    else:
        return 0


class LoginRest(tornado.web.RequestHandler):
    class TokensMapEncoder(json.JSONEncoder):
        def default(self, obj):
            if type(obj) == User:
                user_json = obj.to_jsondict()
                last_access = user_json['last_access']
                pattern = '%Y-%m-%d %H:%M:%S.%f'
                last_access = last_access.strftime(pattern) + ' +0000'
                user_json['last_access'] = last_access
                return user_json

    def post(self, *args, **kwargs):
        try:
            request_data = json.loads(self.request.body.decode('utf-8'))
            LOG.debug(request_data)

            if request_data.keys() != {'username', 'password'}:
                self.set_status(400)
                return

            client = MongoClient(mongodb_ip, mongodb_port)
            result = client.FNRM.users.find(request_data)

            if result.count() > 0:
                assert result.count() == 1
                username = request_data['username']
                date = {"last_access": True}
                client.FNRM.users.update_one({'username': username},
                                             {'$currentDate': date})
                result = client.FNRM.users.find(request_data)

                user = User(result[0])
                # for security reasons, do not save the login password
                user.password = 'nopassword'

                logged_users.logout(user.username)
                token = logged_users.login(user)

                self.set_status(200)
                self.write({'token': token})
            else:
                self.set_status(403)
        except Exception as e:
            self.set_status(500)
            raise

    def get(self, slug=None):
        try:
            status_code = check_request(self.request.headers,
                                        [UserPermissions.administrator,
                                         UserPermissions.user])
            if status_code != 0:
                self.set_status(status_code)
                return

            token = self.request.headers['Auth']
            user = logged_users.get_user_from_token(token)
            if user.user_permissions != UserPermissions.administrator\
                    and slug != user.username:
                self.set_status(403)
                return

            toreturn = logged_users.get_logged_users(slug)

            if len(toreturn) == 0:
                self.set_status(404)
            self.write(json.dumps(toreturn, cls=self.TokensMapEncoder))
        except Exception as e:
            self.set_status(500)
            raise

    def delete(self, slug):
        try:
            status_code = check_request(self.request.headers,
                                        [UserPermissions.administrator,
                                         UserPermissions.user,
                                         UserPermissions.domain])
            if status_code != 0:
                self.set_status(status_code)
                return

            token = self.request.headers['Auth']
            user = logged_users.get_user_from_token(token)
            if user.user_permissions != UserPermissions.administrator\
                    and slug != user.username:
                self.set_status(403)
                return

            if logged_users.logout(slug):
                self.set_status(204)
            else:
                self.set_status(404)

        except Exception as e:
            self.set_status(500)
            raise


class UsersRest(tornado.web.RequestHandler):
    def post(self, *args, **kwargs):
        try:
            status_code = check_request(self.request.headers,
                                        UserPermissions.administrator)
            if status_code != 0:
                self.set_status(status_code)
                return

            request_data = json.loads(self.request.body.decode('utf-8'))
            LOG.debug(request_data)
            valid = {'username', 'password', 'user_permissions'}
            if request_data.keys() != valid:
                self.set_status(400)
                return

            user = User(request_data)
            client = MongoClient(mongodb_ip, mongodb_port)
            try:
                user_data = user.to_jsondict()
                del user_data['token']
                result = client.FNRM.users.insert(user_data)
            except errors.DuplicateKeyError as e:
                self.set_status(409)
                return

            self.set_status(201)
        except Exception as e:
            self.set_status(500)
            raise

    def delete(self, slug):
        try:
            status_code = check_request(self.request.headers,
                                        UserPermissions.administrator)
            if status_code != 0:
                self.set_status(status_code)
                return

            logged_users.logout(slug)

            client = MongoClient(mongodb_ip, mongodb_port)
            result = client.FNRM.users.delete_one({'username': slug})
            assert result.deleted_count <= 1
            if result.deleted_count == 1:
                self.set_status(204)
            else:
                self.set_status(404)

        except Exception as e:
            self.set_status(500)
            raise

    def get(self, slug=None):
        try:
            status_code = check_request(self.request.headers,
                                        UserPermissions.administrator)
            if status_code != 0:
                self.set_status(status_code)
                return

            client = MongoClient(mongodb_ip, mongodb_port)
            if slug is None:
                search_parameter = {}
            else:
                search_parameter = {'username': slug}

            result = client.FNRM.users.find(search_parameter,
                                            {'_id': 0, 'password': 0})

            toreturn = json_pymongo(result)
            self.write(toreturn)
        except Exception as e:
            self.set_status(500)
            raise


class NSDRest(tornado.web.RequestHandler):
    def post(self, *args, **kwargs):
        try:
            status_code = check_request(self.request.headers,
                                        [UserPermissions.administrator,
                                         UserPermissions.user])
            if status_code != 0:
                self.set_status(status_code)
                return

            request_data = json.loads(self.request.body.decode('utf-8'))
            LOG.debug(request_data)
            if request_data.keys() != {'nsd'}:
                self.set_status(400)
                return

            token = self.request.headers['Auth']
            user = logged_users.get_user_from_token(token)

            nsd = NSD(request_data)
            if nsd.error is not None:
                self.set_status(400)
                self.write({'error': nsd.error})
                return

            client = MongoClient(mongodb_ip, mongodb_port)
            try:
                rich_nsd = nsd.to_richdict()
                rich_nsd.update({'owner': user.username})
                result = client.FNRM.nsds.insert(rich_nsd)
            except errors.DuplicateKeyError as e:
                self.set_status(409)
                return

            self.set_status(201)
            to_return = {'nsd_uuid': nsd._uuid}
            self.write(json.dumps(to_return))
        except Exception as e:
            self.set_status(500)
            raise

    def delete(self, slug):
        try:
            status_code = check_request(self.request.headers,
                                        [UserPermissions.administrator,
                                         UserPermissions.user])
            if status_code != 0:
                self.set_status(status_code)
                return

            if not is_uuid(slug):
                self.set_status(400)
                return

            token = self.request.headers['Auth']
            user = logged_users.get_user_from_token(token)

            client = MongoClient(mongodb_ip, mongodb_port)
            delete_parameters = {'uuid': slug}
            if user.user_permissions != UserPermissions.administrator:
                delete_parameters.update({'owner': user.username})

            result = client.FNRM.nsds.delete_one(delete_parameters)
            assert result.deleted_count <= 1
            if result.deleted_count == 1:
                self.set_status(204)
            else:
                self.set_status(404)

        except Exception as e:
            self.set_status(500)
            raise

    def get(self, slug=None):
        try:
            status_code = check_request(self.request.headers,
                                        [UserPermissions.administrator,
                                         UserPermissions.user])
            if status_code != 0:
                self.set_status(status_code)
                return

            token = self.request.headers['Auth']
            user = logged_users.get_user_from_token(token)

            client = MongoClient(mongodb_ip, mongodb_port)

            mask = {'uuid': 1, 'name': 1, 'creation_datetime': 1}

            if slug is None:
                search_parameter = {}
            elif is_uuid(slug):
                search_parameter = {'uuid': slug}
                mask = {}
            else:
                search_parameter = {'$or': [{'owner': slug}, {'name': slug}]}

            if user.user_permissions != UserPermissions.administrator:
                search_parameter.update({'owner': user.username})

            mask.update({'_id': 0})
            result = client.FNRM.nsds.find(search_parameter, mask)

            toreturn = json_pymongo(result)
            self.write(toreturn)
        except Exception as e:
            self.set_status(500)
            raise


class ResourcesRest(tornado.web.RequestHandler):
    def get(self, slug=None):
        try:
            status_code = check_request(self.request.headers,
                                        [UserPermissions.administrator,
                                         UserPermissions.user])
            if status_code != 0:
                self.set_status(status_code)
                return

            vnfs = logged_users.get_vnfs(slug)
            if vnfs is None:
                self.set_status(404)
                return
            self.write(json.dumps(vnfs))
        except Exception as e:
            self.set_status(500)
            raise


class NSRRest(tornado.web.RequestHandler):
    def _get_monitors_measurs(self, client, user, uuid):
        query = list()
        match = {'uuid': uuid}
        if user.user_permissions != UserPermissions.administrator:
            match.update({'owner': user.username})
        query.append({'$match': match})

        query.append({'$lookup': {'from': 'measurements',
                                  'localField': 'uuid',
                                  'foreignField': 'md_nsr_uuid',
                                  'as': 'monitors'}})
        query.append({'$unwind': '$monitors'})
        query.append({'$group':
                     {'_id': {'monitor_name': '$monitors.monitor_name',
                              'measur_name': '$monitors.measur_name'}}})
        query.append({'$group':
                     {'_id': '$_id.monitor_name',
                      'measurs_name': {'$addToSet': '$_id.measur_name'}}})
        result = client.FNRM.nsrs.aggregate(query)
        data_json = obj_pymongo(result)
        return data_json

    def _get_measurements(self, client, mon_measur, uuid, measurs_number):
        toreturn = list()
        for monitor in mon_measur:
            monitor_name = monitor['_id']
            for measur_name in monitor['measurs_name']:
                query = list()
                query.append({'$match': {'md_nsr_uuid': uuid,
                                         'monitor_name': monitor_name,
                                         'measur_name': measur_name}})
                query.append({'$sort': {'timestamp': -1}})
                query.append({'$limit': int(measurs_number)})
                projection = {'_id': 0,
                              'timestamp': 1,
                              'value': {'$substr': ['$value', 0, -1]},
                              'value_type': 1}
                query.append({'$project': projection})
                result = client.FNRM.measurements.aggregate(query)
                data_json = obj_pymongo(result)

                target = [item for item in toreturn
                          if item['monitor']['monitor_name'] == monitor_name]
                if len(target) == 0:
                    target = {'monitor': {'monitor_name': monitor_name,
                                          'measur_name': list()}}
                    toreturn.append(target)
                else:
                    target = target[0]

                data = {'measur_name': measur_name, 'samples': data_json}
                target['monitor']['measur_name'].append(data)

        return {'measurements': toreturn}

    def _process_stats(self, client, user, uuid, n_measurements):
        schema = self._get_monitors_measurs(client, user, uuid)
        return self._get_measurements(client, schema, uuid, n_measurements)

    def get(self, slug=None):
        try:
            status_code = check_request(self.request.headers,
                                        [UserPermissions.administrator,
                                         UserPermissions.user])

            if status_code != 0:
                self.set_status(status_code)
                return

            client = MongoClient(mongodb_ip, mongodb_port)
            token = self.request.headers['Auth']
            user = logged_users.get_user_from_token(token)

            delegates = False
            if self.request.uri.split('/')[-1] == 'delegates':
                delegates = True

            on_demand = False
            if self.request.uri.split('/')[-1] == 'on_demand':
                on_demand = True

            nsr_delegates = nsrs_manager.get_delegates(slug)
            match = [deleg for deleg in nsr_delegates
                     if deleg.user == user.username]
            assert len(match) <= 1
            delegated_user = (len(match) == 1)

            if slug == 'stats':
                uuid = self.get_argument('nsr_uuid')
                measurs_number = self.get_argument('measurements')
                measurements = self._process_stats(client,
                                                   user,
                                                   uuid,
                                                   measurs_number)
                self.write(json.dumps(measurements))
                return
            else:
                extended_query = False
                mask = {'uuid': 1,
                        'owner': 1,
                        'creation_datetime': 1,
                        'status': 1}

                if slug is None:
                    search_parameter = {}

                elif is_uuid(slug):

                    search_parameter = {'uuid': slug}

                    if on_demand is False and delegates is False:
                        extended_query = True
                        mask = {}

                else:
                    search_parameter = {'owner': slug}

                if user.user_permissions != UserPermissions.administrator:
                    if not delegated_user:
                        search_parameter.update({'owner': user.username})

                if extended_query is False:
                    mask.update({'_id': 0})
                    result = client.FNRM.nsrs.find(search_parameter, mask)

                    if delegates is True:
                        if result.count() == 0:
                            self.set_status(404)
                            return
                        else:
                            nsr_data_dict = nsrs_manager.get_delegates(slug)

                    elif on_demand is True:
                        if not delegated_user and result.count() == 0:
                            self.set_status(403)
                            return
                        else:
                            nsr_data_dict = nsrs_manager.get_on_demand(slug)
                    else:
                        nsr_data_dict = result

                    if delegated_user:
                        nsr_data_dict['owner'] = '-'
                        nsr_data_dict['creation_datetime'] = datetime.min

                    nsr_data = json_pymongo(nsr_data_dict)

                else:
                    result = client.FNRM.nsrs.find(search_parameter, {'_id': 0})
                    nsr_data = obj_pymongo(result)
                    if len(nsr_data) == 0:
                        self.set_status(404)
                        return
                    else:
                        assert len(nsr_data) == 1
                        other_params_str = str(nsr_data[0]['other_params'])
                        nsr_data[0]['other_params'] = other_params_str
                        nsr_data[0]['nsd'] = yaml_pymongo(nsr_data[0]['nsd'])
                        monitors = self._process_stats(client, user, slug, '1')
                        nsr_data[0]['monitors'] = monitors
                        nsr_data = json.dumps(nsr_data)

                self.write(nsr_data)

        except Exception as e:
            self.set_status(500)
            raise

    def delete(self, slug):
        try:
            status_code = check_request(self.request.headers,
                                        [UserPermissions.administrator,
                                         UserPermissions.user])
            if status_code != 0:
                self.set_status(status_code)
                return

            if not is_uuid(slug):
                self.set_status(400)
                return

            token = self.request.headers['Auth']
            user = logged_users.get_user_from_token(token)
            nsr_owner = nsrs_manager.get_nsr_owner(slug)

            if user.user_permissions == UserPermissions.administrator \
                    or user.username == nsr_owner:
                if nsrs_manager.get_nsr_owner(slug) is not None:
                    termination_status = nsrs_manager.terminate_nsr(slug)
                    assert termination_status is True
                    assert nsrs_manager.get_nsr_owner(slug) is None

                client = MongoClient(mongodb_ip, mongodb_port)
                # fixme delete also measurements
                result = client.FNRM.nsrs.delete_one({'uuid': slug})
                assert result.deleted_count <= 1
                if result.deleted_count == 1:
                    self.set_status(204)
                else:
                    self.set_status(404)
            else:
                self.set_status(403)

        except Exception as e:
            self.set_status(500)
            raise

    def put(self, slug):
        try:
            import time
            perf_log('nsr_launch')
            perf_log('processing|nsrlaunch|nsrlaunchid')
            status_code = check_request(self.request.headers,
                                        [UserPermissions.administrator,
                                         UserPermissions.user])
            if status_code != 0:
                self.set_status(status_code)
                return
            if not is_uuid(slug):
                self.set_status(400)
                return

            token = self.request.headers['Auth']
            user = logged_users.get_user_from_token(token)
            client = MongoClient(mongodb_ip, mongodb_port)
            result = client.FNRM.nsds.find({'uuid': slug})
            if result.count() == 0:
                self.set_status(400)
                return
            assert result.count() == 1

            nsd = result[0]['nsd']
            nsr_uuid = nsrs_manager.add_nsr(nsd, user.username)
            if nsrs_manager.is_valid(nsr_uuid):
                to_return = {'nsr_uuid': nsr_uuid}
                self.write(json.dumps(to_return))
                self.set_status(201)
            else:
                self.set_status(500)

        except Exception as e:
            self.set_status(500)
            raise

    def post(self, slug):
        try:

            status_code = check_request(self.request.headers,
                                        [UserPermissions.administrator,
                                         UserPermissions.user])
            if status_code != 0:
                self.set_status(status_code)
                return

            on_demand = False
            delegate = False
            request_type = self.request.uri.split('/')[-1]
            if request_type == 'on_demand':
                on_demand = True
            if request_type == 'delegates':
                delegate = True

            if not ((on_demand or delegate) and is_uuid(slug)):
                self.set_status(400)
                return

            token = self.request.headers['Auth']
            user = logged_users.get_user_from_token(token)
            client = MongoClient(mongodb_ip, mongodb_port)

            search_parameter = {'uuid': slug}

            if user.user_permissions != UserPermissions.administrator:
                search_parameter.update({'owner': user.username})

            result = client.FNRM.nsrs.find(search_parameter)

            if result.count() == 0:
                self.set_status(404)
                return
            assert result.count() == 1

            request_data = json.loads(self.request.body.decode('utf-8'))

            if on_demand:
                nsrs_manager.set_on_demand(slug, request_data)
            elif delegate:
                nsrs_manager.set_delegates(slug, request_data)

            self.set_status(204)

        except Exception as e:
            self.set_status(500)
            raise


class Rest(Thread):
    def __init__(self, rest_data, mongodb_data, logins):
        super(Rest, self).__init__()
        self.rest_data = rest_data
        self.mongodb_data = mongodb_data
        self.logins = logins
        self.application = tornado.web.Application([
            (r"/rest/login", LoginRest),
            (r"/rest/login/", LoginRest),
            (r"/rest/login/([^/]+)", LoginRest),
            (r"/rest/users", UsersRest),
            (r"/rest/users/", UsersRest),
            (r"/rest/users/([^/]+)", UsersRest),
            (r"/rest/nsds", NSDRest),
            (r"/rest/nsds/", NSDRest),
            (r"/rest/nsds/([^/]+)", NSDRest),
            (r"/rest/resources", ResourcesRest),
            (r"/rest/resources/", ResourcesRest),
            (r"/rest/resources/([^/]+)", ResourcesRest),
            (r"/rest/nsrs", NSRRest),
            (r"/rest/nsrs/", NSRRest),
            (r"/rest/nsrs/([^/]+)", NSRRest),
            (r"/rest/nsrs/([^/]+)/on_demand", NSRRest),
            (r"/rest/nsrs/([^/]+)/delegates", NSRRest),
            (r"/rest/nsrs/([^/]+)/delegates/([^/]+)", NSRRest)])

    def run(self):
        LOG.debug('mongodb is on ip ' + self.mongodb_data['ipaddr']
                  + ' port ' + self.mongodb_data['port'])
        global mongodb_ip
        global mongodb_port
        global logged_users
        global nsrs_manager
        logged_users = self.logins
        mongodb_ip = self.mongodb_data['ipaddr']
        mongodb_port = int(self.mongodb_data['port'])
        nsrs_manager = NSRsManager(mongodb_ip, mongodb_port, logged_users)

        LOG.debug('listening on ' + self.rest_data['ipaddr']
                  + ' port ' + str(self.rest_data['port']))
        self.application.listen(self.rest_data['port'],
                                self.rest_data['ipaddr'])
        self.ioloop = tornado.ioloop.IOLoop()
        self.ioloop.current().start()

    def join(self, timeout=None):
        self.ioloop.current().stop()
        super(Rest, self).join(timeout)
        LOG.info('Rest interface closed')
