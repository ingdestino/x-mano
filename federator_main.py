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

import sys
import logging
import configobj
import time
from os.path import basename
from federator.db_manager import DbManager
from federator.rest import Rest
from federator.common import LoggedUsers
from common.functions import get_os, OS, perf_init

# todo try catch and log errors
if len(sys.argv) > 1:
    CONFIG_FILE = sys.argv[1]
else:
    if get_os() == OS.Windows:
        CONFIG_FILE = 'C:\\federation\\config\\FM\\federator_default.cfg'
    else:
        CONFIG_FILE = '/etc/federation/FM/federator_default.cfg'


config = configobj.ConfigObj(CONFIG_FILE)
# fixme check whether file has been found
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


log.info('Federator Manager, FBK Create-Net')
log.info('Loading profile "' + basename(CONFIG_FILE) + '"')

db_manager = DbManager(config['MONGODB'])
if not db_manager.is_allright():
    log.error('problems in the database')
    exit()
if not db_manager.check_default_user(config['FEDERATION']):
    log.error('problems with default credentials')
    exit()

logged_users = LoggedUsers(config['RABBIT'], config['MODULE'])

oRest = Rest(config['REST'], config['MONGODB'], logged_users)
oRest.start()

if 'PERF' in config and 'file' in config['PERF']:
    log.info('Performance measurement enabled')
    perf_init(config['PERF']['file'])
else:
    log.info('Performance measurement disabled')

log.info('Federator initializaton completed')

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    logged_users.terminate()
