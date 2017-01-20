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
from pymongo import MongoClient
from federator.nsr import NSR
from federator.parsers import obj_pymongo
from common.packets import ActionResponsePkt, NSRStatusPkt, NSRNotificationPkt

LOG = logging.getLogger(__name__)


class NSRsManager:
    def __init__(self, mongodb_ip, mongodb_port, loggedusers):
        self.nsrs = {}
        self._mongodb_ip = mongodb_ip
        self._mongodb_port = mongodb_port
        self.logged_users = loggedusers

        LOG.debug('Loading nsrs from database')
        self._mongodb_client = MongoClient(self._mongodb_ip, self._mongodb_port)
        result = self._mongodb_client.FNRM.nsrs.find()
        for item in obj_pymongo(result):
            nsr = NSR(item,
                      self._mongodb_ip,
                      self._mongodb_port,
                      self.logged_users)
            if nsr.is_valid():
                uuid = nsr.get_uuid()
                self.nsrs[uuid] = nsr
            else:
                LOG.error('Troubles in loading the nsrs')

    def add_nsr(self, nsd, owner):
        nsr = NSR({'owner': owner, 'nsd': nsd},
                  self._mongodb_ip,
                  self._mongodb_port,
                  self.logged_users)
        uuid = nsr.get_uuid()
        self.nsrs[uuid] = nsr
        nsr.start()
        return uuid

    def sdnsr_status_changed(self, domain, nsr_status_pkt):
        assert isinstance(nsr_status_pkt, NSRStatusPkt)
        LOG.debug('Domain '
                  + domain
                  + ' has changed status to '
                  + nsr_status_pkt.status.name)
        nsr = self.nsrs[nsr_status_pkt.md_nsr_uuid]
        nsr.change_status(domain, nsr_status_pkt)

    def sdnsr_notification(self, domain, nsr_notification_pkt):
        assert isinstance(nsr_notification_pkt, NSRNotificationPkt)
        LOG.debug('Domain '
                  + domain
                  + ' has received notification:'
                  + nsr_notification_pkt.name)
        nsr = self.nsrs[nsr_notification_pkt.md_nsr_uuid]
        nsr.new_notification(nsr_notification_pkt)

    def update_actions_status(self, domain, action_response_pkt):
        assert isinstance(action_response_pkt, ActionResponsePkt)
        action_name = action_response_pkt.action_name
        LOG.debug('Domain ' + domain + ' has run action: ' + action_name)
        nsr_uuid = action_response_pkt.md_nsr_uuid
        nsr = self.nsrs[nsr_uuid]
        nsr.update_actions_status(domain, action_response_pkt)

    def terminate_nsr(self, uuid):
        LOG.debug('Deleting nsr ' + uuid)
        if uuid in self.nsrs:
            nsr = self.nsrs[uuid]
            correct_termination = nsr.terminate()
            if correct_termination:
                del self.nsrs[uuid]
            return correct_termination
        else:
            return False

    def monitor_update(self, measurement_pkt):
        nsr_uuid = measurement_pkt.md_nsr_uuid
        if nsr_uuid in self.nsrs:
            nsr = self.nsrs[nsr_uuid]
            nsr.monitor_update(measurement_pkt)
        else:
            LOG.warning('dropping measurement from nsr '
                        + nsr_uuid
                        + ' since it does not exist')

    def get_nsr_owner(self, uuid):
        if uuid not in self.nsrs:
            return None
        return self.nsrs[uuid].get_owner()

    def is_valid(self, uuid):
        return self.nsrs[uuid].is_valid()
