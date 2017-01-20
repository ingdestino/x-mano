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
import yaml
import json
import traceback
import logging
from uuid import uuid4

LOG = logging.getLogger(__name__)


class NSD:
    def __init__(self, nsd_rest):
        self.error = None
        try:
            self._nsd = yaml.load(nsd_rest['nsd'])
            if 'uuid' not in nsd_rest:
                self._uuid = str(uuid4())
            if 'creation_datetime' not in nsd_rest:
                self._creation_datetime = datetime.now(tz=pytz.utc)
            if 'name' not in nsd_rest:
                self._name = self._nsd['name']
        except Exception as e:
            self.error = str(e)
            LOG.warning(e)
            traceback.print_exc()

    def _get_richnsd(self):
        return {'name': self._name,
                'creation_datetime': self._creation_datetime,
                'nsd': self._nsd,
                'uuid': self._uuid}

    def to_richjsondict(self):
        return json.dumps(self._get_richnsd())

    def to_richdict(self):
        return self._get_richnsd()
