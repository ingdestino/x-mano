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

from configobj import ConfigObj
import logging
import traceback
import time
from pymongo import MongoClient
from uuid import uuid4
from common.rabbit_endpoint import RabbitEndpoint
from common.functions import perf_log, PERF_ENABLED
from common.manager_abstract import ManagerAbstract
from common.packets import VNFModelPkt, NSRStatusPkt, FedConnClosePkt,\
    ActionResponsePkt, MeasurementPkt, NSRNotificationPkt
from federator.rest import nsrs_manager

LOG = logging.getLogger(__name__)


class DomainManager(ManagerAbstract):
    def __init__(self, rabbit_data, config_file):
        super(DomainManager, self).__init__(rabbit_data)
        config = ConfigObj(config_file)
        mongodb_ip = config['MONGODB']['ipaddr']
        mongodb_port = config['MONGODB']['port']
        self.client = MongoClient(mongodb_ip, int(mongodb_port))

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
        self._shutdown_ack = False

        self._vnfs = []

    def get_short_vnfs(self):
        toreturn = []
        for vnf in self._vnfs:
            toreturn.append({'federation_id': vnf['federation_id'],
                            'name': vnf['name'],
                             'vendor': vnf['vendor'],
                             'version': vnf['version']})
        return toreturn

    def get_vnfs(self, vnf_id=None):
        return [vnf for vnf in self._vnfs
                if vnf_id is None or vnf['federation_id'] == vnf_id]

    def process_message(self, queue, message):
        perf_log('communication|' + self._username + '|' + message['perf_id'])
        perf_log('processing|'
                 + message['header'].replace(' ', '')
                 + '|newmessage')
        try:
            if queue == self._from_domain_queue:
                assert type(message) != str
                LOG.debug('Received message with header: ' + message['header'])

                if message['header'] == 'OK_init':
                    LOG.info('initialization completed')

                if message['header'] == 'vnf':
                    vnf_model_pkt = VNFModelPkt(message)
                    vnf_model = vnf_model_pkt.vnf
                    vnf_model['federation_id'] = str(uuid4())
                    self._vnfs.append(vnf_model)

                if message['header'] == 'nsr_status':
                    nsr_status_pkt = NSRStatusPkt(message)
                    nsrs_manager.sdnsr_status_changed(self._username,
                                                      nsr_status_pkt)

                if message['header'] == 'nsr_notification':
                    nsr_notification_pkt = NSRNotificationPkt(message)
                    nsrs_manager.sdnsr_notification(self._username,
                                                    nsr_notification_pkt)

                if message['header'] == 'OK_action':
                    action_response_pkt = ActionResponsePkt(message)
                    nsrs_manager.update_actions_status(self._username,
                                                       action_response_pkt)

                if message['header'] == 'OK_shutdown':
                    self._shutdown_ack = True

            if queue == self._monitor_queue:
                assert type(message) != str
                measurement_pkt = MeasurementPkt(message)
                nsrs_manager.monitor_update(measurement_pkt)
                self.client.FNRM.measurements.insert(
                    measurement_pkt.to_mongodb())

        except Exception:
            traceback.print_exc()

        perf_log('processing|'
                 + message['header'].replace(' ', '')
                 + '|newmessage')

    def process_command(self, command):
        try:
            if PERF_ENABLED:
                perf_id = str(uuid4())
                command.update({'perf_id': perf_id})
                perf_log('communication|' + self._username + '|' + perf_id)

            if command['header'] == 'init':
                # todo define a packet
                welcome_message = {'header': 'Welcome ' + self._username,
                                   'perf_id': str(uuid4())}
                self._domain_endpoint.send(self._to_domain_queue,
                                           welcome_message)
                # fixme dirty
                self._domain_endpoint.send(self._to_domain_queue,
                                           {'header': 'init',
                                            'perf_id': str(uuid4())})
            else:
                self._domain_endpoint.send(self._to_domain_queue, command)
        except Exception:
            raise

    def stop_endpoint(self):
        self.terminate()

    def is_endpoint_stopped(self):
        return self._domain_endpoint.is_endpoint_stopped()

    # fixme, either add terminate function to abstract,
    # fixme or go through process_command
    def terminate(self):
        fed_conn_close_pkt = FedConnClosePkt()
        fed_conn_close_pkt.build()
        self.process_command(fed_conn_close_pkt.get_packet())
        count = 3
        timeout = False
        while not self._shutdown_ack:
            time.sleep(1)
            count -= 1
            if count == 0:
                timeout = True
                break
        if timeout:
            LOG.debug('timeout during FA shutdown')
        else:
            LOG.debug('FA exited')

        self._domain_endpoint.join()
