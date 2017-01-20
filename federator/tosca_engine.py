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

import traceback
import logging

LOG = logging.getLogger(__name__)


def process_mdns(mdns):
    try:
        sdnss = {}
        for vnf in mdns['MD_NS']['vnfds']:
            location = vnf['location']
            if location not in sdnss:
                sdnss[location] = {}
                sdnss[location]['SD_NS'] = {}
                sdnss[location]['SD_NS']['vnfds'] = []
                sdnss[location]['SD_NS']['VLs'] = []
                sdnss[location]['SD_NS']['CPs'] = []
                sdnss[location]['SD_NS']['FPs'] = []
                sdnss[location]['SD_NS']['FGs'] = []

            sdnss[location]['SD_NS']['vnfds'].append(vnf)

        vnfname_location = {}
        for item in mdns['MD_NS']['vnfds']:
            vnfname_location[item['name']] = item['location']

        vlname_vlobject = {}
        if 'VLs' in mdns['MD_NS'] and mdns['MD_NS']['VLs'] is not None:
            for item in mdns['MD_NS']['VLs']:
                vlname_vlobject[item['name']] = item

        cpname_location = {}
        cpname_cpobject = {}
        if 'CPs' in mdns['MD_NS'] and mdns['MD_NS']['CPs'] is not None:
            for cp in mdns['MD_NS']['CPs']:
                vnf_name = cp['virtualbinding']
                location = vnfname_location[vnf_name]
                cpname_location[cp['name']] = location
                cpname_cpobject[cp['name']] = cp

                sdnss[location]['SD_NS']['CPs'].append(cp)
                if cp['virtualLink'] is not None:
                    vlname = cp['virtualLink']
                    vlobject = vlname_vlobject[vlname]
                    if vlobject not in sdnss[location]['SD_NS']['VLs']:
                        sdnss[location]['SD_NS']['VLs'].append(vlobject)

        if 'FPs' in mdns['MD_NS'] and mdns['MD_NS']['FPs'] is not None:
            for fp in mdns['MD_NS']['FPs']:
                assert fp['type'] == 'tosca.nodes.nfv.FP'
                for cp_name in fp['path']:
                    location = cpname_location[cp_name]
                    sd_fp = [sd_fp for sd_fp in sdnss[location]['SD_NS']['FPs']
                             if sd_fp['name'] == fp['name']]
                    if len(sd_fp) == 0:
                        clear_fp = dict(fp)
                        clear_fp['path'] = list()
                        sdnss[location]['SD_NS']['FPs'].append(clear_fp)
                        sd_fp = clear_fp
                    else:
                        sd_fp = sd_fp[0]

                    index = sdnss[location]['SD_NS']['FPs'].index(sd_fp)
                    path = sdnss[location]['SD_NS']['FPs'][index]['path']
                    path.append(cp_name)

        # todo add FGs (decice whether it has to be implemented)

        #  MONITOR RELATED PARAMETERS
        if 'MD_Mon' in mdns and 'monitors' in mdns['MD_Mon']:
            for monitor in mdns['MD_Mon']['monitors']:
                assert monitor['type'] == 'monitor.nodes.nfv.VNF'
                location = vnfname_location[monitor['name']]
                if 'SD_Mon' not in sdnss[location]:
                    sdnss[location]['SD_Mon'] = dict()
                if 'monitors' not in sdnss[location]['SD_Mon']:
                    sdnss[location]['SD_Mon']['monitors'] = list()
                sdnss[location]['SD_Mon']['monitors'].append(monitor)

        for location in sdnss:
            prot_vers_keyword = 'tosca_FDs_protocol_version'
            sdnss[location][prot_vers_keyword] = mdns[prot_vers_keyword]
            sdnss[location]['description'] = mdns['description']
            sdnss[location]['name'] = mdns['name']

        return sdnss

    except Exception as e:
        LOG.warning(e)
        traceback.print_exc()
        return None
