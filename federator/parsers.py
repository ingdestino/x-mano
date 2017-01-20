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

from bson import json_util
import json
import yaml
from uuid import UUID
from enum import Enum
from datetime import datetime


class DataTypeEnum(Enum):
    json = 1
    obj = 2


def json_python_dict(bson_data):
    return json.dumps(bson_data, default=json_util.default)


def json_pymongo(bson_data):
    return json.dumps(_pymongo_parser(bson_data, DataTypeEnum.json))


def obj_pymongo(bson_data):
    return _pymongo_parser(bson_data, DataTypeEnum.obj)


def yaml_pymongo(bson_data):
    return yaml.dump(_pymongo_parser(bson_data, DataTypeEnum.json),
                     default_flow_style=False)


def _pymongo_parser(bson_data, return_type):
    unformatted_json = json_util.dumps(bson_data)
    unformatted_data = json.loads(unformatted_json)
    return _traverse(unformatted_data, return_type)


def _traverse(obj, return_type):
    if isinstance(obj, dict):
        if '$date' in obj:
            wrong_datetime = obj['$date']
            correct_datetime = datetime.utcfromtimestamp(
                wrong_datetime / 1000).strftime(
                '%Y-%m-%d %H:%M:%S.%f') + ' +0000'
            return correct_datetime
        if 'nsd' in obj and return_type == DataTypeEnum.json:
            obj['nsd'] = yaml.dump(obj['nsd'], default_flow_style=False)

        return {k: _traverse(v, return_type) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_traverse(elem, return_type) for elem in obj]
    else:
        return obj


def is_uuid(uuid_string):
    try:
        if type(uuid_string) != str:
            raise ValueError
        val = UUID(uuid_string, version=4)
    except ValueError:
        return False
    return val.hex == uuid_string.replace('-', '')
