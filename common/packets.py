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

from datetime import datetime
from abc import ABCMeta, abstractmethod
from common.gen_nsr_status_enum import GENNSRStatus


class PacketAbstract:
    __metaclass__ = ABCMeta

    @abstractmethod
    def __init__(self, packet=None):
        if packet is not None:
            self._header = packet['header']
            if 'body' in packet:
                self._body = packet['body']
            else:
                self._body = None
        else:
            self._header = None
            self._body = None

        self._reply_header = None
        self._reply_body = None

    @abstractmethod
    def get_packet(self):
        return {'header': self._header, 'body': self._body}

    def pkt_builder(self, header, body):
        self._header = header
        self._body = body

    def get_reply(self):
        return {'header': self._reply_header, 'body': self._reply_body}


class InitPkt(PacketAbstract):
    def __init__(self, packet=None):
        super(InitPkt, self).__init__(packet)
        self._reply_header = 'OK_init'

    def get_packet(self):
        return super(InitPkt, self).get_packet()

    def get_reply(self):
        return super(InitPkt, self).get_reply()


class VNFModelPkt(PacketAbstract):
    def __init__(self, packet=None):
        super(VNFModelPkt, self).__init__(packet)
        if packet is not None:
            self.vnf = self._body

    def build(self, vnf):
        super(VNFModelPkt, self).pkt_builder('vnf', vnf)

    def get_packet(self):
        return super(VNFModelPkt, self).get_packet()


class NSRRunPkt(PacketAbstract):
    def __init__(self, packet=None):
        super(NSRRunPkt, self).__init__(packet)
        if packet is not None:
            self.sd_nsd = self._body['sd_nsd']
            self.md_nsr_uuid = self._body['md_nsr_uuid']

    def build(self):
        super(NSRRunPkt, self).pkt_builder('vnf', None)

    def get_packet(self):
        return super(NSRRunPkt, self).get_packet()


class NSRStatusPkt(PacketAbstract):
    def __init__(self, packet=None):
        super(NSRStatusPkt, self).__init__(packet)
        if packet is not None:
            self.md_nsr_uuid = self._body['md_nsr_uuid']
            self.status = GENNSRStatus[self._body['status']]
            self.other_params = self._body['other_params']

    def build(self, uuid, status, other_params=None):
        body = dict()
        body['md_nsr_uuid'] = uuid
        body['status'] = status.name
        body['other_params'] = other_params
        super(NSRStatusPkt, self).pkt_builder('nsr_status', body)

    def get_packet(self):
        return super(NSRStatusPkt, self).get_packet()


class NSRNotificationPkt(PacketAbstract):
    def __init__(self, packet=None):
        super(NSRNotificationPkt, self).__init__(packet)
        if packet is not None:
            self.md_nsr_uuid = self._body['md_nsr_uuid']
            self.name = self._body['name']
            self.value = self._body['value']
            self.other_params = self._body['other_params']

    def build(self, uuid, name, value, other_params=None):
        body = dict()
        body['md_nsr_uuid'] = uuid
        body['name'] = name
        body['value'] = value
        body['other_params'] = other_params
        super(NSRNotificationPkt, self).pkt_builder('nsr_notification', body)

    def get_packet(self):
        return super(NSRNotificationPkt, self).get_packet()


class NSRDeletePkt(PacketAbstract):
    def __init__(self, packet=None):
        super(NSRDeletePkt, self).__init__(packet)
        if packet is not None:
            self.md_nsr_uuid = self._body['md_nsr_uuid']

    def build(self, md_nsr_uuid):
        body = dict()
        body['md_nsr_uuid'] = md_nsr_uuid
        super(NSRDeletePkt, self).pkt_builder('nsr_delete', body)

    def get_packet(self):
        return super(NSRDeletePkt, self).get_packet()


class ActionPkt(PacketAbstract):
    class ActionObj:
        def __init__(self, action_obj=None):
            if action_obj is not None:
                self.name = action_obj['name']
                if 'params' in action_obj:
                    self.params = action_obj['params']
                else:
                    self.params = None
                if 'return_value' in action_obj:
                    self.return_value = action_obj['return_value']
                else:
                    self.return_value = None

        def build(self, name, params, return_value):
            self.name = name
            self.params = params
            self.return_value = return_value

        def get_packet(self):
            return {'name': self.name,
                    'params': self.params,
                    'return_value': self.return_value}

    def __init__(self, packet=None):
        super(ActionPkt, self).__init__(packet)
        if packet is not None:
            self.md_nsr_uuid = self._body['md_nsr_uuid']
            self.vnf_name = self._body['vnf_name']
            self.action_obj = self.ActionObj(self._body['action_obj'])

    def set_action_obj(self, action):
        self.action_obj = self.ActionObj(action)

    def build(self):
        body = dict()
        body['md_nsr_uuid'] = self.md_nsr_uuid
        body['vnf_name'] = self.vnf_name
        body['action_obj'] = self.action_obj.get_packet()
        super(ActionPkt, self).pkt_builder('action', body)

    def get_packet(self):
        return super(ActionPkt, self).get_packet()


class ActionResponsePkt(PacketAbstract):
    class ReturnValue:
        def __init__(self, param_name, param_value):
            self._param_name = param_name
            self._param_value = param_value

        def to_dict(self):
            return {self._param_name: self._param_value}

    def __init__(self, packet=None):
        super(ActionResponsePkt, self).__init__(packet)
        self.return_value = None
        if packet is not None:
            self.action_name = self._body['action_name']
            self.md_nsr_uuid = self._body['md_nsr_uuid']
            if 'return_value' in self._body:
                self.return_value = self._body['return_value']

    def set_return_value(self, param_name, param_value):
        self.return_value = self.ReturnValue(param_name, param_value)

    def build(self, action_name, md_nsr_uuid):
        body = dict()
        body['action_name'] = action_name
        body['md_nsr_uuid'] = md_nsr_uuid
        if self.return_value is not None:
            body['return_value'] = self.return_value.to_dict()
        super(ActionResponsePkt, self).pkt_builder('OK_action', body)

    def get_packet(self):
        return super(ActionResponsePkt, self).get_packet()


class FedConnClosePkt(PacketAbstract):
    def __init__(self, packet=None):
        super(FedConnClosePkt, self).__init__(packet)
        self._reply_header = 'OK_shutdown'

    def build(self):
        super(FedConnClosePkt, self).pkt_builder('bye', None)

    def get_packet(self):
        return super(FedConnClosePkt, self).get_packet()

    def get_reply(self):
        return super(FedConnClosePkt, self).get_reply()


class MeasurementPkt(PacketAbstract):
    def __init__(self, packet=None):
        super(MeasurementPkt, self).__init__(packet)
        if packet is not None:
            self.md_nsr_uuid = self._body['md_nsr_uuid']
            self.monitor_name = self._body['monitor_name']
            self.measur_name = self._body['measur_name']
            self.timestamp = datetime.fromtimestamp(self._body['timestamp'])
            self.value_type = self._body['value_type']
            self.value = None
            if self.value_type == 'integer':
                self.value = int(self._body['value'])
            if self.value_type == 'string':
                self.value = str(self._body['value'])
            if self.value_type == 'float':
                self.value = float(self._body['value'])
            if self.value is None:
                raise Exception

    def build(self, md_nsr_uuid, monitor_name, measur_name, value, timestamp,
              value_type):
        body = dict()
        body['md_nsr_uuid'] = md_nsr_uuid
        body['monitor_name'] = monitor_name
        body['measur_name'] = measur_name
        body['value'] = value
        body['timestamp'] = timestamp.timestamp()
        body['value_type'] = value_type
        super(MeasurementPkt, self).pkt_builder('measurement', body)

    def get_packet(self):
        return super(MeasurementPkt, self).get_packet()

    def to_mongodb(self):
        toreturn = dict()
        toreturn['md_nsr_uuid'] = self.md_nsr_uuid
        toreturn['monitor_name'] = self.monitor_name
        toreturn['measur_name'] = self.measur_name
        toreturn['value'] = self.value
        toreturn['timestamp'] = self.timestamp
        toreturn['value_type'] = self.value_type
        return toreturn
