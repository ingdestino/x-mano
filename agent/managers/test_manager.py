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

"""
Simple agent manager that tests the communication with the
federator manager

"""

import logging
import traceback
from common.rabbit_endpoint import RabbitEndpoint
from common.manager_abstract import ManagerAbstract

LOG = logging.getLogger(__name__)


class AgentManager(ManagerAbstract):
    # Start a rabbitmq endpoint, consume messages on <domain-name>-to_domain
    # and publish on the exchange of the other two queues
    def __init__(self, rabbit_data):
        super(AgentManager, self).__init__(rabbit_data)
        super(AgentManager, self)
        queues_dict = {self._from_domain_queue: 'publish',
                       self._to_domain_queue: 'consume',
                       self._monitor_queue: 'publish'}

        self._domain_endpoint = RabbitEndpoint(self._username,
                                               self._password,
                                               self._rabbit_ip,
                                               self._rabbit_port,
                                               self._username + '-exchange',
                                               queues_dict,
                                               self.process_message)
        self._domain_endpoint.start()

    # when the manager is initialized, this function is executed
    # on a separated thread.
    # This test manager receive two messages from the federator manager,
    # it replies, and finally it shutdowns when the 'bye' message is received
    def process_message(self, queue, message):
        try:
            if queue == self._to_domain_queue:
                if message['header'] == 'first message of sequence':
                    LOG.info('first message received')
                    self._domain_endpoint.send(self._from_domain_queue,
                                               {'header': 'data'})
                    self._domain_endpoint.send(self._from_domain_queue,
                                               {'header': 'data2'})
                    self._domain_endpoint.send(self._from_domain_queue,
                                               {'header': 'ACK1'})

                if message['header'] == 'second message of sequence':
                    LOG.info('second message received')
                    self._domain_endpoint.send(self._from_domain_queue,
                                               {'header': 'ACK2'})

                if message['header'] == 'bye':
                    self.terminate()

        except Exception:
            print(traceback.print_exc())

    def process_command(self, command):
        try:
            pass
        except Exception:
            pass

    def stop_endpoint(self):
        self.terminate()

    def is_endpoint_stopped(self):
        return self._domain_endpoint.is_endpoint_stopped()

    def terminate(self):
        self._domain_endpoint.join()
