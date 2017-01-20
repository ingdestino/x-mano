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

import logging
import requests
from importlib import import_module

LOG = logging.getLogger(__name__)


class DomainsManager:
    def __init__(self, rabbit_data, managers):
        level = logging.getLevelName(rabbit_data['log_level'])
        logging.getLogger("pika").setLevel(level)

        self.managers = managers
        self.rabbit_data = rabbit_data
        self.rabbit_ip = rabbit_data['ipaddr']
        self.rabbit_port = rabbit_data['port']
        self.rabbit_config_port = rabbit_data['config_port']
        self.rabbit_username = rabbit_data['username']
        self.rabbit_password = rabbit_data['password']
        self.management_url = 'http://' \
                              + self.rabbit_username \
                              + ':' + self.rabbit_password \
                              + '@' + self.rabbit_ip \
                              + ':' + \
                              self.rabbit_config_port + '/api/'

        LOG.info('Domains will be managed with module '
                 + self.managers['manager'])

        response = requests.get(self.management_url + 'users')
        assert response.status_code == 200
        data = response.json()
        toremove = [rest_user for rest_user in data
                    if rest_user['name'] != 'admin'
                    and rest_user['name'] != 'guest']
        for rest_user in toremove:
            response = requests.delete(self.management_url
                                       + 'users/'
                                       + rest_user['name'])
            assert response.status_code == 204

        response = requests.get(self.management_url + 'queues/%2f')
        assert response.status_code == 200
        data = response.json()
        for queue in data:
            response = requests.delete(self.management_url
                                       + 'queues/%2f/'
                                       + queue['name'])
            assert response.status_code == 204

        response = requests.get(self.management_url + 'exchanges/%2f')
        assert response.status_code == 200
        data = response.json()
        for exchange in data:
            if exchange['name'].split('.')[0] not in ['amq', '']:
                response = requests.delete(self.management_url
                                           + 'exchanges/%2f/'
                                           + exchange['name'])
                assert response.status_code == 204

    def add_domain(self, token, user):
        username = user.username
        user_url = 'users/' + username
        user_permissions_url = 'permissions/%2f/' + username
        exchange_name = username + '-exchange'
        exchange_url = 'exchanges/%2f/' + exchange_name
        monitor_queue_name = username + '-monitor'
        monitor_queue_url = 'queues/%2f/' + monitor_queue_name
        to_domain_queue_name = username + '-to_domain'
        to_domain_queue_url = 'queues/%2f/' + to_domain_queue_name
        from_domain_queue_name = username + '-from_domain'
        from_domain_queue_url = 'queues/%2f/' + from_domain_queue_name

        # Create a new user on RabbitMQ
        response = requests.get(self.management_url + user_url)
        assert response.status_code == 404
        user_data = {'password': token, 'tags': ''}
        response = requests.put(self.management_url + user_url,
                                json=user_data)
        assert response.status_code == 204

        # Create an exchange
        response = requests.get(self.management_url + exchange_url)
        assert response.status_code == 404
        response = requests.put(self.management_url + exchange_url,
                                json={'type': 'direct',
                                      'auto_delete': False,
                                      'durable': True,
                                      'internal': False,
                                      'arguments': {}})
        assert response.status_code == 204

        # Give the user permission to read and write queues that have
        # its username in the queue name; i.e. this user will only be able to
        # read/write its queues, and not the ones of the other users
        response = requests.get(self.management_url + user_permissions_url)
        assert response.status_code == 404
        response = requests.put(self.management_url + user_permissions_url,
                                json={'configure': '',
                                      'write': '^' + username + '-.*',
                                      'read': '^' + username + '-.*'})
        assert response.status_code == 204

        # Create the three queues, and for each of them associate the exchange
        # The latter will forward messages in the correct queue according to the
        # routing key, which in this case is the queue name
        response = requests.get(self.management_url + monitor_queue_url)
        assert response.status_code == 404
        response = requests.put(self.management_url + monitor_queue_url,
                                json={})
        assert response.status_code == 204
        response = requests.post(self.management_url
                                 + 'bindings/%2f/e/'
                                 + exchange_name
                                 + '/q/'
                                 + monitor_queue_name,
                                 json={'routing_key': monitor_queue_name,
                                       'arguments': {}})
        assert response.status_code == 201  # in this case Rabbitmq returns 201

        response = requests.get(self.management_url + to_domain_queue_url)
        assert response.status_code == 404
        response = requests.put(self.management_url + to_domain_queue_url,
                                json={})
        assert response.status_code == 204
        response = requests.post(self.management_url
                                 + 'bindings/%2f/e/'
                                 + exchange_name
                                 + '/q/'
                                 + to_domain_queue_name,
                                 json={'routing_key': to_domain_queue_name,
                                       'arguments': {}})
        assert response.status_code == 201

        response = requests.get(self.management_url + from_domain_queue_url)
        assert response.status_code == 404
        response = requests.put(self.management_url + from_domain_queue_url,
                                json={})
        assert response.status_code == 204
        response = requests.post(self.management_url
                                 + 'bindings/%2f/e/'
                                 + exchange_name
                                 + '/q/'
                                 + from_domain_queue_name,
                                 json={'routing_key': from_domain_queue_name,
                                       'arguments': {}})
        assert response.status_code == 201

        # Load the manager specified in the config file
        manager = self.managers['manager']
        mod = import_module('federator.managers.' + manager)
        class_inst = getattr(mod, 'DomainManager')

        user_rabbit_data = dict(self.rabbit_data)
        user_rabbit_data['username'] = username
        user_rabbit_data['password'] = token

        if 'config_file' in self.managers:
            domain_manager = class_inst(user_rabbit_data,
                                        self.managers['config_file'])
        else:
            domain_manager = class_inst(user_rabbit_data, None)

        domain_manager.process_command({'header': 'init'})
        return domain_manager

    def remove_domain(self, user):
        user.domain_manager.terminate()

        response = requests.delete(self.management_url
                                   + 'users/'
                                   + user.username)
        assert response.status_code == 204

        response = requests.delete(self.management_url
                                   + 'queues/%2f/'
                                   + user.username
                                   + '-monitor')
        assert response.status_code == 204

        response = requests.delete(self.management_url
                                   + 'queues/%2f/'
                                   + user.username
                                   + '-to_domain')
        assert response.status_code == 204

        response = requests.delete(self.management_url
                                   + 'queues/%2f/'
                                   + user.username
                                   + '-from_domain')
        assert response.status_code == 204

        response = requests.delete(self.management_url
                                   + 'exchanges/%2f/'
                                   + user.username
                                   + '-exchange')
        assert response.status_code == 204
