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

import unittest
from threading import Thread
import subprocess
import xmlrunner
from common.functions import get_os, OS


class AgentLauncher(Thread):
    def __init__(self, config_file):
        super(AgentLauncher, self).__init__()
        self.process = None
        self._config_file = config_file
        self.output = ''

    def run(self):
        self.process = subprocess.Popen(['python3',
                                         'agent_main.py',
                                         self._config_file],
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT)

        for line in iter(self.process.stdout.readline, b''):
            line_formatted = line.rstrip().decode('utf-8')
            self.output += line_formatted
            print(line_formatted)


class ClassTests01TestManager(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(ClassTests01TestManager, self).__init__(*args, **kwargs)

    def test_run_two_test_managers(self):
        if get_os() == OS.Windows:
            root = 'C:\\federation\\config\\FA\\'
        else:
            root = '/etc/federation/FA/'
        config_file_1 = root + 'agent_test_manager_domain1.cfg'
        config_file_2 = root + 'agent_test_manager_domain2.cfg'

        agent_launcher1 = AgentLauncher(config_file_1)
        agent_launcher1.start()
        agent_launcher2 = AgentLauncher(config_file_2)
        agent_launcher2.start()

        agent_launcher1.join()
        agent_launcher2.join()
        import time
        while agent_launcher1.process and agent_launcher2.is_alive():
            time.sleep(1)

        self.assertIn('second message received', agent_launcher1.output)
        self.assertIn('second message received', agent_launcher2.output)

if __name__ == '__main__':
    unittest.main(testRunner=xmlrunner.XMLTestRunner(output='test-reports'))
