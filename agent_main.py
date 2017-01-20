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
Entry point of the federator agent
"""

import logging
import configobj
import time
import requests
import sys
from os.path import basename
from importlib import import_module
from common.functions import get_os, OS, perf_init

# todo try catch and log errors


def main(config_file):
    config = configobj.ConfigObj(config_file)

    level = logging.getLevelName(config['LOGGING']['level'])
    logging.basicConfig(filename=config['LOGGING']['file'],
                        filemode=config['LOGGING']['filemode'],
                        level=level)
    console = logging.StreamHandler()
    console.setLevel(level)
    formatter = logging.Formatter('%(name)-40s: %(levelname)-8s %(message)s')
    console.setFormatter(formatter)
    logging.getLogger('').addHandler(console)
    log = logging.getLogger(__name__)

    log.info('Federation Agent, FBK Create-Net')
    log.info('Loading profile "' + basename(config_file) + '"')

    if 'PERF' in config:
        log.info('Performance measurement enabled')
        perf_init(config['PERF']['file'])
    else:
        log.info('Performance measurement disabled')

    log.info('Connecting to Federator')

    credentials = {k: v for k, v in config['FEDERATION'].items()
                   if k == 'username' or k == 'password'}
    domain_ip = config['FEDERATION']['ipaddr']
    domain_port = config['FEDERATION']['port']
    login_url = 'http://' + domain_ip + ':' + domain_port + '/rest/login/'

    # Login to the federator manager and get the security token
    response = requests.post(login_url, json=credentials)
    assert response.status_code == 200
    token = response.json()['token']

    # The security token is the password for accessing RabbitMQ server
    rabbit_data = config['RABBIT']
    rabbit_data.update({'username': credentials['username'], 'password': token})

    # Load the module specified in the configuration parameters
    manager = config['MODULE']['manager']
    mod = import_module('agent.managers.' + manager)
    class_inst = getattr(mod, 'AgentManager')
    if 'config_file' in config['MODULE']:
        manager = class_inst(rabbit_data, config['MODULE']['config_file'])
    else:
        manager = class_inst(rabbit_data)
    log.info('Loaded module ' + config['MODULE']['manager'])

    endpoint_stopped = False
    try:
        while not manager.is_endpoint_stopped():
            time.sleep(1)
        endpoint_stopped = True
    except KeyboardInterrupt:
        manager.stop_endpoint()
        timer = 3
        while timer > 0:
            timer -= 1
            if manager.is_endpoint_stopped():
                endpoint_stopped = True
                break
            else:
                log.info('Waiting for endpoint to stop')
                time.sleep(1)
    if endpoint_stopped:
        log.info('Endpoint has stopped')
    else:
        log.error('Troubles in terminating endpoint')

    # Logout from federation
    log.info('Logging out from federation')
    response = requests.delete(login_url + credentials['username'],
                               headers={'Auth': token})
    if response.status_code == 204:
        log.info('Logged out from federation')
    else:
        log.error('return code was ' + str(response.status_code))

# Profiles contains data for agent initialization
# if no profile is provided, the default one is loaded
if __name__ == "__main__":
    if len(sys.argv) > 1:
        CONFIG_FILE = sys.argv[1]
    else:
        if get_os() == OS.Windows:
            CONFIG_FILE = 'C:\\federation\\config\\FA\\agent_default.cfg'
        else:
            CONFIG_FILE = '/etc/FA/federator_default.cfg'
    main(CONFIG_FILE)
