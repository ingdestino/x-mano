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

from copy import deepcopy
from enum import Enum
import os
import time


class OS(Enum):
    Windows = 1,
    Unix_Like = 2,
    Unknown = 3


def get_os():
    current_os = os.name
    if current_os == 'nt':
        return OS.Windows
    elif current_os == 'posix':
        return OS.Unix_Like
    else:
        return OS.Unknown


def get_slash(os_enum):
    if os_enum == OS.Windows:
        return '\\'
    if os_enum == OS.Unix_Like:
        return '/'


def truly_deepcopy(obj):
    if isinstance(obj, dict):
        return {deepcopy(key): deepcopy(value) for key, value in obj.items()}
    if hasattr(obj, '__iter__'):
        return type(obj)(deepcopy(item) for item in obj)
    return obj


PERF_ENABLED = False
PERF_FILE = None


def perf_init(file):
    global PERF_ENABLED
    PERF_ENABLED = True
    global PERF_FILE
    PERF_FILE = open(file, mode='w')


def perf_log(text):
    if PERF_ENABLED:
        PERF_FILE.write('***' + text + ' ' + str(time.time()) + '\r')
        PERF_FILE.flush()
