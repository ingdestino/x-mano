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
import pytz
import traceback
import logging
from uuid import uuid4
from pymongo import MongoClient
from threading import Thread
import time
import re
from federator.tosca_engine import process_mdns
from common.gen_nsr_status_enum import GENNSRStatus
from common.functions import perf_log
from common.packets import NSRDeletePkt, NSRStatusPkt, ActionPkt,\
    ActionResponsePkt, NSRNotificationPkt
from common.functions import truly_deepcopy

LOG = logging.getLogger(__name__)


class NSR:
    def __init__(self, nsr_data, mongodb_ip, mongodb_port, logged_users):
        try:
            self._valid = True
            self._recovered = False
            self._mongodb_ip = mongodb_ip
            self._mongodb_port = mongodb_port
            self._mongodb_client = MongoClient(self._mongodb_ip,
                                               self._mongodb_port)
            self._logged_users = logged_users

            self._sd_statuses = {}
            self._nsd = nsr_data['nsd']
            self._owner = nsr_data['owner']
            self._variables = {}
            self._other_params = {}

            self._last_measurements = {}

            self._handlers_status = {}
            self._action_status = {}
            self._action_uuid_handler_map = {}

            self._delegates = {}

            if 'uuid' in nsr_data:
                self._uuid = nsr_data['uuid']
            else:
                self._uuid = str(uuid4())
            if 'status' in nsr_data:
                self._status = GENNSRStatus[nsr_data['status']]
                self._recovered = True
            else:
                self._status = GENNSRStatus.null
            if 'creation_datetime' in nsr_data:
                self._creation_datetime = nsr_data['creation_datetime']
            else:
                self._creation_datetime = datetime.now(tz=pytz.utc)

            self._sd_nsds = process_mdns(self._nsd)
            self.vnfname_location = {}

            if 'vnfds' in self._nsd['MD_NS']:
                for item in self._nsd['MD_NS']['vnfds']:
                    self.vnfname_location[item['name']] = item['location']

            for location in self.vnfname_location.values():
                self._sd_statuses[location] = GENNSRStatus.null
                null_status_name = GENNSRStatus.null.name
                self._variables[location.upper() + '_STATUS'] = null_status_name
            self._check_triggers()

        except Exception as e:
            self._valid = False
            LOG.warning(e)
            traceback.print_exc()

    def start(self):
        for domain_name in self._sd_nsds.keys():
            if self._recovered:
                # fixme, use nsr packet
                packet = {'header': 'recover_nsr',
                          'body': {'sd_nsd': self._sd_nsds[domain_name],
                                   'md_nsr_uuid': self._uuid}}
            else:
                packet = {'header': 'run_nsr',
                          'body': {'sd_nsd': self._sd_nsds[domain_name],
                                   'md_nsr_uuid': self._uuid}}

            self._send_todomain(domain_name, packet)
        perf_log('processing|nsrlaunch|nsrlaunchid')

        if not self._recovered:
            self._mongodb_client.FNRM.nsrs.insert(self.to_dict())

    def _update_nsr_db(self):
        result = self._mongodb_client.FNRM.nsrs.update_one(
            {'uuid': self._uuid},
            {'$set': {'status': self._status.name,
                      'other_params': self._other_params}},
            upsert=False)
        assert result.matched_count == 1

    def _fill_variables(self, data):
        if isinstance(data, dict):
            for key in data:
                value = data[key]
                if type(key) == str and key == 'code':
                    variables = re.findall('\[\^(.*?)\]', value)
                    for variable in variables:
                        if variable not in self._variables:
                            self._variables[variable] = None
                        # safely stringify variable,
                        # the final string will be evaluated as code
                        LOG.debug('assigning \"'
                                  + str(self._variables[variable])
                                  + '\", type '
                                  + str(type(self._variables[variable]))
                                  + ' to ' + variable)
                        value = value.replace('[^' + variable + ']',
                                              str(self._variables[variable]))
                    data[key] = value

                elif type(value) == str and len(value) > 0 and value[0] == '^':
                    variable = value[1:]
                    if variable not in self._variables:
                        self._variables[variable] = None
                    LOG.debug('assigning \"'
                              + str(self._variables[variable])
                              + '\", type '
                              + str(type(self._variables[variable]))
                              + ' to ' + variable)
                    data[key] = self._variables[variable]

            return {k: self._fill_variables(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self._fill_variables(elem) for elem in data]
        else:
            return data

    def _process_condition(self, condition):

        status = None

        if type(condition) == dict and len(condition.keys()) == 1:

            if list(condition.keys())[0] == 'and':
                status = True
                for sub_condition in condition['and']:
                    status = status and self._process_condition(sub_condition)
            if list(condition.keys())[0] == 'or':
                status = False
                for sub_condition in condition['or']:
                    status = status or self._process_condition(sub_condition)

        elif type(condition) == list and len(condition) == 1:

            status = self._process_condition(condition[0])

        else:

            items = []
            for item in [condition['left_item'], condition['right_item']]:
                # todo update
                '''
                if item['type'] == 'monitor.alarms.measurement':
                    monitor = item['monitor']
                    measurement = item['measurement']
                    last_measur = self._last_measurements[monitor][measurement]
                    items.append(last_measur['value'])
                '''

                if item['type'].split('.')[1] == 'vartype':
                    value_type = item['type'].split('.')[2]
                    if 'value' in item and item['value'] is not None:
                        if value_type == 'integer':
                            items.append(int(item['value']))
                        if value_type == 'string':
                            items.append(str(item['value']))
                        if value_type == 'float':
                            items.append(float(item['value']))
                        if value_type == 'bool':
                            items.append(bool(item['value']))
                        if value_type == 'null':
                            items.append(None)
                    else:
                        items.append(None)

            assert len(items) == 2
            operator = condition['operator']
            if operator == '>':
                status = items[0] > items[1]
            if operator == '<':
                status = items[0] < items[1]
            if operator == '==':
                status = items[0] == items[1]
            if operator == '!=':
                status = items[0] != items[1]

        return status

    def _check_triggers(self):
        LOG.debug('Checking triggers...')
        if 'Triggers' in self._nsd['MD_NS']:
            for trigger in self._nsd['MD_NS']['Triggers']:
                trigger_name = trigger['name']
                assert trigger['type'] == 'triggers.trigger'
                condition = trigger['condition']
                condition = self._fill_variables(truly_deepcopy(condition))
                LOG.debug(str(condition))
                triggered_event = self._process_condition(condition)
                assert type(triggered_event) == bool
                if triggered_event:
                    LOG.debug('trigger ' + trigger_name + ' has triggered')
                    steps = truly_deepcopy(trigger['steps'])

                    handler_name = trigger_name

                    if handler_name not in self._handlers_status:
                        self._handlers_status[handler_name] = False

                    if self._handlers_status[handler_name] is False:

                        self._handlers_status[handler_name] = True
                        thread = Thread(target=self.actions_manager,
                                        args=[steps, handler_name])
                        LOG.debug(handler_name + ' thread has started')
                        thread.start()

    def _send_todomain(self, domain_name, packet):
        domain_user = self._logged_users.get_logged_users(domain_name)
        if len(domain_user) == 1:
            domain_user = domain_user[0]
            domain_user.domain_manager.process_command(packet)
        else:
            LOG.warning('Domain '
                        + domain_name
                        + ' is unreachable, nsr uuid: '
                        + self._uuid)

    def change_status(self, domain, nsr_status_pkt):
        assert isinstance(nsr_status_pkt, NSRStatusPkt)

        status = nsr_status_pkt.status

        self._sd_statuses[domain] = status
        self._variables[domain.upper() + '_STATUS'] = status.name
        self._check_triggers()

    def new_notification(self, nsr_notification_pkt):
        assert isinstance(nsr_notification_pkt, NSRNotificationPkt)
        notification_name = nsr_notification_pkt.name
        notification_value = nsr_notification_pkt.value
        notification_other_params = nsr_notification_pkt.other_params

        self._variables[notification_name] = notification_value
        self._variables[notification_name + '*'] = notification_other_params
        self._check_triggers()

    def _process_step(self, step, handler_name):

        # fixme, detect unrecognized step
        if step['type'] == 'steps.vnf_action_step':
            self._action_status[handler_name] = set()
            actions_sent = set()
            for vnf in step['involved_vnfs']:
                assert vnf['type'] == 'tosca.nodes.steps.involved_vnf'
                for action in vnf['actions']:
                    assert action['type'] == 'tosca.nodes.steps.action'
                    if 'params' in action \
                            and action['params'] is not None:
                        params = action['params']
                        action['params'] = self._fill_variables(params)

                    domain_name = self.vnfname_location[vnf['name']]
                    LOG.debug('sending action '
                              + action['name']
                              + ' of vnf '
                              + vnf['name']
                              + ' to domain '
                              + domain_name)
                    actions_sent.add(domain_name + action['name'])
                    action_pkt = ActionPkt()
                    action_pkt.set_action_obj(action)
                    action_uuid = str(uuid4())
                    action_pkt.build(self._uuid, vnf['name'], action_uuid)
                    self._action_uuid_handler_map[action_uuid] = handler_name
                    self._send_todomain(domain_name,
                                        action_pkt.get_packet())

            while self._action_status[handler_name] != actions_sent:
                LOG.debug(handler_name
                          + ' is waiting for action(s) response(s)')
                time.sleep(1)
            del self._action_status[handler_name]

        if step['type'] == 'steps.elaboration_step':
            for elaboration in step['elaborations']:
                elaboration_type = elaboration['type']
                plain_eval_keyword = 'steps.elaboration_step.evaluation'
                fm_eval_keyword = 'steps.elaboration_step.FMfunction'

                if elaboration_type == plain_eval_keyword:
                    filled_elaboration = truly_deepcopy(elaboration)
                    self._fill_variables(filled_elaboration)
                    code = filled_elaboration['code']
                    LOG.debug('executing code ' + code)
                    store_in = filled_elaboration['store_in']
                    try:
                        # todo use exec
                        self._variables[store_in] = eval(code)
                        LOG.debug('code execution returned: \''
                                  + str(self._variables[store_in])
                                  + ' type: \''
                                  + str(type(self._variables[store_in]))
                                  + '\''
                                  + '\' stored in variable ' + store_in)
                    except Exception as e:
                        LOG.error('error in evaluating code: ' + str(e))
                        self._variables[store_in] = None

                if elaboration_type == fm_eval_keyword:
                    function_name = elaboration['name']
                    if function_name == 'CHANGE_STATUS':
                        params = elaboration['params']
                        assert len(params) == 1
                        param = params[0]
                        assert param['name'] == 'status'
                        status = self._status.fromstring(param['value'])
                        assert status.name == param['value']
                        self._status = status
                        self._variables['STATUS'] = status.name
                        self._update_nsr_db()
                    if function_name == 'UPDATE_OTHER_PARAMS':
                        params = elaboration['params']
                        assert len(params) == 2
                        params_dict = {}
                        for param in params:
                            params_dict[param['name']] = param['value']
                        assert 'data' in params_dict
                        assert 'section_name' in params_dict

                        section_name = params_dict['section_name']
                        data = params_dict['data']

                        if data[0] == '^':
                            self._other_params[section_name] = \
                                self._variables[data[1:]]
                        else:
                            self._other_params[section_name] = data

                        self._update_nsr_db()

                        LOG.debug('other_params in section_name: '
                                  + section_name
                                  + ' have been updated')

    def actions_manager(self, steps, handler_name):
        try:
            LOG.debug('Sending actions for ' + self._nsd['name'])
            for step in steps:
                LOG.debug('current step = ' + step['name'])
                self._process_step(step, handler_name)

            LOG.debug('Steps procedure finished')
        except Exception:
            error = traceback.format_exc()
            LOG.error(error)
        finally:
            self._handlers_status[handler_name] = False
            LOG.debug(handler_name + ' thread has finished')

    def update_actions_status(self, domain, action_response_pkt):
        assert isinstance(action_response_pkt, ActionResponsePkt)
        action_name = action_response_pkt.action_name
        action_uuid = action_response_pkt.action_uuid
        handler_name = self._action_uuid_handler_map[action_uuid]
        self._action_status[handler_name].add(domain + action_name)
        del self._action_uuid_handler_map[action_uuid]

        if action_response_pkt.return_value is not None:
            variable = action_response_pkt.return_value
            LOG.debug('Storing variable ' + str(variable))
            self._variables.update(variable)
            # todo save at FM level the variable name of the returned value

    def get_on_demand(self):

        if 'On_demand' not in self._nsd['MD_NS']:
            return []

        on_demand_list = truly_deepcopy(self._nsd['MD_NS']['On_demand'])

        for on_demand in on_demand_list:
            for param in on_demand['params']:

                variable_name = param['variable_name']

                if variable_name in self._variables:
                    param['value'] = str(self._variables[variable_name])
                else:
                    param['value'] = 'None'

        return on_demand_list

    def set_on_demand(self, on_demand_list):

        if 'On_demand' not in self._nsd['MD_NS']:
            return 404

        nsd_od_varnames = [od['name'] for od in self._nsd['MD_NS']['On_demand']]
        req_od_varnames = [od['name'] for od in on_demand_list]

        if not set(nsd_od_varnames).issuperset(req_od_varnames):
            return 404

        for on_demand in on_demand_list:

            self._variables[on_demand['variable_name']] = True
            # fixme, find a way to autoreset on_demand triggering variable

            for param in on_demand['params']:

                variable_name = param['variable_name']
                type = param['type']
                readonly = param['readonly']

                if readonly is False:
                    value = None
                    if type == 'integer':
                        value = int(param['value'])
                    if type == 'string':
                        value = param['value'] # check on rest whether it is a string

                    self._variables['_' + variable_name] = value

        self._check_triggers()

    def get_delegates(self):
        return list(self._delegates.values())

    def set_delegates(self, delegate):

        if 'On_demand' not in self._nsd['MD_NS']:
            return 404  # there cannot be delegates if there are no on_demands

        on_demands = [od['name'] for od in self._nsd['MD_NS']['On_demand']]

        if set(delegate.keys()) != {'on_demand', 'user', 'permissions'}:
            return 400

        if delegate['on_demand'] not in on_demands:
            return 404

        uuid_str = str(uuid4())
        delegate['delegate_uuid'] = uuid_str
        self._delegates[uuid_str] = delegate

    def delete_delegate(self, delegate_uuid):
        del self._delegates[delegate_uuid]

    def get_uuid(self):
        return self._uuid

    def get_owner(self):
        return self._owner

    def is_valid(self):
        return self._valid

    def to_dict(self):
        toreturn = {'nsd': self._nsd,
                    'owner': self._owner,
                    'uuid': self._uuid,
                    'creation_datetime': self._creation_datetime,
                    'status': self._status.name,
                    'other_params': self._other_params}
        return toreturn

    def terminate(self):
        for domain_name in self._sd_nsds:
            domain_user = self._logged_users.get_logged_users(domain_name)
            if len(domain_user) == 0:
                LOG.info('domain '
                         + domain_name
                         + ' is not reacheable anymore, '
                           'ignoring termination process on this domain')
            else:
                nsr_delete_pkt = NSRDeletePkt()
                nsr_delete_pkt.build(self._uuid)
                self._send_todomain(domain_name, nsr_delete_pkt.get_packet())
        return True

    def _send_action(self, domain_name, action_pkt):
        self._send_todomain(domain_name, action_pkt.get_packet())
