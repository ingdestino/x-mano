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
import traceback
from common.rabbit_endpoint import RabbitEndpoint
from common.manager_abstract import ManagerAbstract

LOG = logging.getLogger(__name__)


class DomainManager(ManagerAbstract):
    def __init__(self, rabbit_data, config_file=None):
        super(DomainManager, self).__init__(rabbit_data)
        queues_dict = {self._from_domain_queue: 'consume',
                       self._to_domain_queue: 'publish',
                       self._monitor_queue: 'consume'}

        self._domain_endpoint = RabbitEndpoint(self._username,
                                               self._password,
                                               self._rabbit_ip,
                                               self._rabbit_port,
                                               self._username + '-exchange',
                                               queues_dict,
                                               self.process_message)
        self._domain_endpoint.start()

    def process_message(self, queue, message):
        try:
            if queue == self._from_domain_queue:
                if message['header'] == 'ACK1':
                    second_message = {'header': 'second message of sequence'}
                    self._domain_endpoint.send(
                        self._to_domain_queue, second_message)

                if message['header'] == 'ACK2':
                    self._domain_endpoint.send(self._to_domain_queue,
                                               {'header': 'bye'})
        except:
            traceback.print_exc()

    def process_command(self, command):
        try:
            if command['header'] == 'init':
                welcome_message = {'header': 'Welcome ' + self._username}
                self._domain_endpoint.send(self._username + '-to_domain',
                                           welcome_message)
                first_message = {'header': 'first message of sequence'}
                self._domain_endpoint.send(self._username + '-to_domain',
                                           first_message)
        except Exception:
            raise

    def stop_endpoint(self):
        return

    def is_endpoint_stopped(self):
        return self._domain_endpoint.is_endpoint_stopped()

    def terminate(self):
        self._domain_endpoint.join()
