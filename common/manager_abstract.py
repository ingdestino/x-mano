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
Each manager (both federator manager and federator agent)
has to implement this class, which define and handle common
operations that are in common among different managers

In particular, each manager will either publish or consume
three RabbitMQ queues:

<domain-name>-from_domain is used for messages coming from the domain (agent),
<domain-name>-to_domain is used for messages coming from the federator manager,
<domain-name>-monitor is ad dedicated channel
for statistics coming from the domain (agent)
"""

from abc import ABCMeta, abstractmethod
import logging


class ManagerAbstract:
    __metaclass__ = ABCMeta

    @abstractmethod
    def __init__(self, rabbit_data):
        level = logging.getLevelName(rabbit_data['log_level'])
        logging.getLogger("pika").setLevel(level)

        self._rabbit_ip = rabbit_data['ipaddr']
        self._rabbit_port = rabbit_data['port']
        self._username = rabbit_data['username']
        self._password = rabbit_data['password']

        self._from_domain_queue = self._username + '-from_domain'
        self._to_domain_queue = self._username + '-to_domain'
        self._monitor_queue = self._username + '-monitor'

    @abstractmethod
    def process_message(self, queue, message):
        return

    @abstractmethod
    def process_command(self, command):
        return

    @abstractmethod
    def stop_endpoint(self):
        return

    @abstractmethod
    def is_endpoint_stopped(self):
        return
