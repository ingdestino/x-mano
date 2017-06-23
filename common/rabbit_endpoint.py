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
Generic RabbitMQ endpoint
This class extends the functionalities of the Pika library
resulting in a wrapper that can be easily used for accessing
the RabbitMQ server

"""

from threading import Thread
from threading import Lock
import time
import logging
from queue import Queue
from queue import Empty
import json
import pika

LOG = logging.getLogger(__name__)


class RabbitEndpoint(Thread):
    def __init__(self, username, password, rabbit_ip, rabbit_port,
                 exchange, queues, callback=None):
        super(RabbitEndpoint, self).__init__()
        self.username = username
        self.password = password
        self.rabbit_ip = rabbit_ip
        self.rabbit_port = rabbit_port
        self.send_queue = Queue()
        self.receive_queue = Queue()
        self.send_myqueue = []
        self.receive_myqueue = []
        self.connection = None

        self.exchange = exchange
        self.queues = {}
        for queue in queues:
            self.queues[queue] = {'type': queues[queue], 'channel': None,
                                  'channel_number': -1, 'callback': callback}

        self._lock = Lock()
        self._stopped = False

    def conn_close_callback(self):
        return

    def conn_open_callback(self, connection):
        i = 1
        for queue in self.queues:
            self.queues[queue]['channel'] = connection.channel(
                self.channel_open_callback, i)
            self.queues[queue]['channel_number'] = i
            i += 1

    def channel_open_callback(self, channel):
        channel_number = channel.channel_number
        queue = [queue for queue in self.queues
                 if self.queues[queue]['channel_number'] == channel_number]
        assert len(queue) == 1
        queue = queue[0]

        if self.queues[queue]['type'] == 'consume':
            channel.basic_consume(self.callback_func,
                                  queue=queue,
                                  no_ack=True)

    def callback_func(self, channel, method, properties, body):
        try:
            queue = [queue for queue in self.queues
                     if self.queues[queue]['channel_number']
                     == channel.channel_number]
            assert len(queue) == 1
            queue = queue[0]
            self.receive_queue.put({queue: body.decode("utf-8")})
            if self.queues[queue]['callback'] is not None:
                message = json.loads(body.decode("utf-8"))
                self.queues[queue]['callback'](queue, message)
        except Exception as e:
            LOG.warning('error in pika callback function: ' + str(e))

    def run(self):
        while self.is_endpoint_stopped() is False:
            try:
                param_args = {'host': self.rabbit_ip,
                              'socket_timeout': 10,
                              'credentials': pika.PlainCredentials(
                                 self.username, self.password)}
                connection_parameters = pika.ConnectionParameters(**param_args)

                conn_args = {'parameters': connection_parameters,
                             'on_open_callback': self.conn_open_callback,
                             'on_close_callback': self.conn_close_callback}

                self.connection = pika.SelectConnection(**conn_args)

                self.connection.add_timeout(2, self.mycallbacktimer)
                self.connection.ioloop.start()
            except Exception as e:
                LOG.warning(e)
            finally:
                if not self.is_endpoint_stopped():
                    time.sleep(10)
                    LOG.info('resetting connection')
                    if self.connection.is_open():
                        self.connection.close()

    def mycallbacktimer(self):
        try:
            while True:
                item = self.send_queue.get(False)
                queue = list(item.keys())[0]
                command = item[queue]
                self.send_myqueue.append((queue, command))
        except Empty:
            pass

        to_be_removed_commands = []
        for queue, command in self.send_myqueue:
            try:
                self.queues[queue]['channel'].basic_publish(
                    exchange=self.exchange,
                    routing_key=queue,
                    body=command)
                to_be_removed_commands.append((queue, command))
            except Exception as e:
                LOG.warning('exception in rabbit callback' + str(e))
                break

        for queue, command in to_be_removed_commands:
            self.send_myqueue.remove((queue, command))
        self.connection.add_timeout(0.001, self.mycallbacktimer)

        if self.is_endpoint_stopped():
            self.connection.close()

    def send(self, queue, message):
        self.send_queue.put({queue: json.dumps(message)})
        return

    def is_endpoint_stopped(self):
        with self._lock:
            return self._stopped

    def join(self, timeout=None):
        try:
            with self._lock:
                self._stopped = True
        except Exception as e:
            LOG.warning(e)
