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
import requests
import yaml
import xmlrunner
import sys

ip = ''
argv = sys.argv
for i in range(0, len(argv)):
    if argv[i] == 'ip':
        ip = sys.argv[i + 1]
        break
if ip == '':
    ip = '127.0.0.1'

rest_root = 'http://' + ip + ':8888/rest/'

current_self = None


def do_login(login_data):
    data = login_data
    response = requests.post(rest_root + 'login/', json=data)
    current_self.assertEqual(response.status_code, 200)
    return response.json()['token']


class LoginsData:
    # admin = default account with administrator permissions
    # pippo = account with administrator permissions
    # pluto = account with user permissions
    # domain_1  = account with domain permissions

    adminlogin = {'username': 'admin', 'password': 'qwerty'}
    pippologin = {'username': 'pippo', 'password': 'zxcvbn'}
    plutologin = {'username': 'pluto', 'password': 'poiuyt'}
    pippo_user_correct = {'username': 'pippo',
                          'password': 'zxcvbn',
                          'user_permissions': 'administrator'}
    pippo_user_malformed = {'username': 'pippo',
                            'passgggword': 'zxcvbn',
                            'user_permissions': 'administrator'}
    pippo_user_incomplete = {'username': 'pippo', 'password': 'zxcvbn'}
    pluto_user_correct = {'username': 'pluto',
                          'password': 'poiuyt',
                          'user_permissions': 'user'}

    domain_1_login = {'username': 'domain1', 'password': 'asdfgh'}
    domain_1_user = {'username': 'domain1',
                     'password': 'asdfgh',
                     'user_permissions': 'domain'}
    domain_2_login = {'username': 'domain2', 'password': 'asdfghddd'}
    domain_2_user = {'username': 'domain2',
                     'password': 'asdfghddd',
                     'user_permissions': 'domain'}


class ClassTests01TestRESTLogin(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(ClassTests01TestRESTLogin, self).__init__(*args, **kwargs)
        global current_self
        current_self = self

    def test_broken_login(self):

        # EMPTY REQUEST
        response = requests.post(rest_root + 'login/', '')
        self.assertEqual(response.status_code, 500)

        # EMPTY JSON
        data = {}
        response = requests.post(rest_root + 'login/', json=data)
        self.assertEqual(response.status_code, 400)

        # MALFORMED LOGIN
        data = {'usernsfsd': '', 'pssswodsrd': 'wrong_password'}
        response = requests.post(rest_root + 'login/', json=data)
        self.assertEqual(response.status_code, 400)

        # WRONG LOGIN
        data = {'username': 'wrong', 'password': 'wrong_password'}
        response = requests.post(rest_root + 'login/', json=data)
        self.assertEqual(response.status_code, 403)

    def test_correct_login(self):
        # CORRECT LOGIN
        data = {'username': 'admin', 'password': 'qwerty'}
        response = requests.post(rest_root + 'login/', json=data)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn('token', data)
        self.assertIs(type(data['token']), str)

    def test_login_logout(self):
        # ADD USER Pippo
        # do login again, check whether old token is replaced
        token = do_login(LoginsData.adminlogin)
        data = LoginsData.pippo_user_correct
        response = requests.post(rest_root + 'users/', json=data,
                                 headers={'Auth': token})
        self.assertIn(response.status_code, [201, 409])

        # ADD USER Pluto
        # do login again, check whether old token is replaced
        token = do_login(LoginsData.adminlogin)
        data = LoginsData.pluto_user_correct
        response = requests.post(rest_root + 'users/', json=data,
                                 headers={'Auth': token})
        self.assertIn(response.status_code, [201, 409])

        admintoken = do_login(LoginsData.adminlogin)
        pippotoken = do_login(LoginsData.pippologin)
        plutotoken = do_login(LoginsData.plutologin)

        # ADMIN GET LOGIN
        response = requests.get(rest_root + 'login',
                                headers={'Auth': admintoken})
        self.assertEqual(response.status_code, 200)

        # ADMIN DELETE NON EXISTING LOGIN
        response = requests.delete(rest_root + 'login/fakelogin',
                                   headers={'Auth': admintoken})
        self.assertEqual(response.status_code, 404)

        # ADMIN DELETE ADMIN LOGIN
        response = requests.delete(rest_root + 'login/admin',
                                   headers={'Auth': admintoken})
        self.assertEqual(response.status_code, 204)

        # ADMIN DELETE PIPPO LOGIN
        response = requests.delete(rest_root + 'login/pippo',
                                   headers={'Auth': admintoken})
        self.assertEqual(response.status_code, 401)

        # PLUTO DELETE PIPPO LOGIN
        response = requests.delete(rest_root + 'login/pippo',
                                   headers={'Auth': plutotoken})
        self.assertEqual(response.status_code, 403)

        # PIPPO GET LOGIN
        response = requests.get(rest_root + 'login',
                                headers={'Auth': pippotoken})
        self.assertEquals(response.status_code, 200)

        # PLUTO GET PLUTO LOGIN
        response = requests.get(rest_root + 'login/pluto',
                                headers={'Auth': plutotoken})
        self.assertEquals(response.status_code, 200)

        # PLUTO GET LOGIN
        response = requests.get(rest_root + 'login',
                                headers={'Auth': plutotoken})
        self.assertEquals(response.status_code, 403)

        # PLUTO DELETE PLUTO LOGIN
        response = requests.delete(rest_root + 'login/pluto',
                                   headers={'Auth': plutotoken})
        self.assertEqual(response.status_code, 204)

        # PIPPO DELETE PLUTO LOGIN
        response = requests.delete(rest_root + 'login/pluto',
                                   headers={'Auth': pippotoken})
        self.assertEqual(response.status_code, 404)

        # PIPPO GET PIPPO LOGIN
        response = requests.get(rest_root + 'login/pippo',
                                headers={'Auth': pippotoken})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data), 1)
        pippo_json = data[0]
        self.assertEqual(pippo_json['username'], 'pippo')
        self.assertEqual(pippo_json['password'], 'nopassword')
        self.assertEqual(pippo_json['user_permissions'], 'administrator')
        self.assertEqual(pippo_json['token'], pippotoken)
        self.assertNotEqual(pippo_json['last_access'], None)

        # PIPPO GET PLUTO LOGIN
        response = requests.get(rest_root + 'login/pluto',
                                headers={'Auth': pippotoken})
        self.assertEqual(response.status_code, 404)

    def test_double_login(self):
        admintoken1 = do_login(LoginsData.adminlogin)

        # ADMIN 1 GET LOGIN
        response = requests.get(rest_root + 'login',
                                headers={'Auth': admintoken1})
        self.assertEqual(response.status_code, 200)

        admintoken2 = do_login(LoginsData.adminlogin)

        # ADMIN 2 GET LOGIN
        response = requests.get(rest_root + 'login',
                                headers={'Auth': admintoken2})
        self.assertEqual(response.status_code, 200)

        # ADMIN 2 GET LOGIN WITH OLD TOKEN
        response = requests.get(rest_root + 'login',
                                headers={'Auth': admintoken1})
        self.assertEqual(response.status_code, 401)


class ClassTests02TestRESTUsers(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(ClassTests02TestRESTUsers, self).__init__(*args, **kwargs)
        global current_self
        current_self = self

    def test_broken_requests(self):
        token = do_login(LoginsData.adminlogin)
        # NO TOKEN IN ADD USER REQUEST
        data = LoginsData.pippo_user_correct
        response = requests.post(rest_root + 'users/', json=data)
        self.assertEqual(response.status_code, 401)

        # MALFORMED ADD USER REQUEST
        # no login, check whether token is still there
        data = LoginsData.pippo_user_malformed
        response = requests.post(rest_root + 'users/', json=data,
                                 headers={'Auth': token})
        self.assertEqual(response.status_code, 400)

        # INCOMPLETE ADD USER REQUEST FIELDS
        # do login again, check whether old token is replaced
        token = do_login(LoginsData.adminlogin)
        data = LoginsData.pippo_user_incomplete
        response = requests.post(rest_root + 'users/', json=data,
                                 headers={'Auth': token})
        self.assertEqual(response.status_code, 400)

    def test_procedure(self):
        # DELETE USER Pippo
        token = do_login(LoginsData.adminlogin)
        response = requests.delete(rest_root + 'users/pippo',
                                   headers={'Auth': token})
        self.assertIn(response.status_code, [204, 404])

        # DELETE USER Pluto
        token = do_login(LoginsData.adminlogin)
        response = requests.delete(rest_root + 'users/pluto',
                                   headers={'Auth': token})
        self.assertIn(response.status_code, [204, 404])

        # DUPLICATE DELETE USER Pluto
        # no login, check whether token is still there
        response = requests.delete(rest_root + 'users/pluto',
                                   headers={'Auth': token})
        self.assertEqual(response.status_code, 404)

        # LIST USERS, EMPTY REQUEST
        # no login, check whether token is still there
        token = do_login(LoginsData.adminlogin)
        response = requests.get(rest_root + 'users/',
                                headers={'Auth': token})
        self.assertEqual(response.status_code, 200)

        # CORRECT ADD USER Pippo
        # do login again, check whether old token is replaced
        token = do_login(LoginsData.adminlogin)
        data = LoginsData.pippo_user_correct
        response = requests.post(rest_root + 'users/', json=data,
                                 headers={'Auth': token})
        self.assertEqual(response.status_code, 201)

        # CORRECT ADD USER Pluto
        # do login again, check whether old token is replaced
        token = do_login(LoginsData.adminlogin)
        data = LoginsData.pluto_user_correct
        response = requests.post(rest_root + 'users/', json=data,
                                 headers={'Auth': token})
        self.assertEqual(response.status_code, 201)

        # DUPLICATE ADD USER Pippo
        # do login again, check whether old token is replaced
        token = do_login(LoginsData.adminlogin)
        data = LoginsData.pippo_user_correct
        response = requests.post(rest_root + 'users/', json=data,
                                 headers={'Auth': token})
        self.assertEqual(response.status_code, 409)

        # LIST USERS, EMPTY JSON REQUEST
        # no login, check whether token is still there
        response = requests.get(rest_root + 'users/', json={},
                                headers={'Auth': token})
        self.assertEqual(response.status_code, 200)

        # GET PIPPO
        token = do_login(LoginsData.adminlogin)
        response = requests.get(rest_root + 'users/pippo',
                                headers={'Auth': token})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]['username'], 'pippo')
        self.assertNotIn('password', data[0])
        self.assertEquals(type(data[0]['last_access']), str)

        # GET PIPPO (PLUTO LOGIN)
        token = do_login(LoginsData.plutologin)
        response = requests.get(rest_root + 'users/pippo',
                                headers={'Auth': token})
        self.assertEqual(response.status_code, 403)

        # LIST USERS (PLUTO LOGIN)
        response = requests.get(rest_root + 'users/',
                                headers={'Auth': token})
        self.assertEqual(response.status_code, 403)

        # LIST USERS (PIPPO LOGIN)
        token = do_login(LoginsData.pippologin)
        response = requests.get(rest_root + 'users/',
                                headers={'Auth': token})
        self.assertEqual(response.status_code, 200)


class ClassTests03TestNSDRest(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(ClassTests03TestNSDRest, self).__init__(*args, **kwargs)
        global current_self
        current_self = self

    def test_procedure(self):
        pippotoken = do_login(LoginsData.pippologin)
        plutotoken = do_login(LoginsData.plutologin)

        # GET ALL NSDs AND DELETE THEM ALL (pippo login)
        response = requests.get(rest_root + 'nsds',
                                headers={'Auth': pippotoken})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        for nsd in data:
            self.assertEqual(nsd.keys(), {'uuid', 'name', 'creation_datetime'})
            response = requests.delete(rest_root + 'nsds/' + nsd['uuid'],
                                       headers={'Auth': pippotoken})
            self.assertEqual(response.status_code, 204)

        # SAMPLE TOSCA
        sample_tosca = """
tosca_FDs_protocol_version: 1.0
description: Multi-domain tosca network service.
name: embedded name

MD_NS:
  terrestrial_VNF:
    CPs:
      - internet_interface
      - interdomain_interface
    location: Domain 1 (terrestrial)
  satellite_VNF:
    CPs:
      - satellite_interface
      - interdomain_interface
    location: Domain 2 (satellite)
        """

        # ADD NSD (pippo login)
        data = {'nsd': sample_tosca}
        response = requests.post(rest_root + 'nsds/', json=data,
                                 headers={'Auth': pippotoken})
        self.assertEqual(response.status_code, 201)
        returned_data = response.json()
        self.assertIn('nsd_uuid', returned_data)
        pippo_returned_uuid = returned_data['nsd_uuid']

        # ADD IT AGAIN (pippo login)
        response = requests.post(rest_root + 'nsds/', json=data,
                                 headers={'Auth': pippotoken})
        self.assertEqual(response.status_code, 409)

        # ADD IT AGAIN (pluto login)
        response = requests.post(rest_root + 'nsds/', json=data,
                                 headers={'Auth': plutotoken})
        self.assertEqual(response.status_code, 201)
        returned_data = response.json()
        self.assertIn('nsd_uuid', returned_data)
        pluto_returned_uuid = returned_data['nsd_uuid']

        # GET PIPPO FULL NSD FROM UUID (pippo login)
        response = requests.get(rest_root + 'nsds/' + pippo_returned_uuid,
                                headers={'Auth': pippotoken})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data), 1)
        nsd = data[0]
        self.assertEqual(nsd.keys(),
                         {'uuid', 'name', 'creation_datetime', 'owner', 'nsd'})
        returned_tosca = nsd['nsd']
        self.assertEqual(yaml.load(returned_tosca), yaml.load(sample_tosca))

        # GET PLUTO FULL NSD FROM UUID (pluto login)
        response = requests.get(rest_root + 'nsds/' + pluto_returned_uuid,
                                headers={'Auth': plutotoken})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data), 1)

        # GET PLUTO FULL NSD FROM UUID (pippo login)
        response = requests.get(rest_root + 'nsds/' + pluto_returned_uuid,
                                headers={'Auth': pippotoken})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data), 1)

        # GET PIPPO FULL NSD FROM UUID (pluto login)
        response = requests.get(rest_root + 'nsds/' + pippo_returned_uuid,
                                headers={'Auth': plutotoken})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data), 0)

        # GET PIPPO SHORT NSDs (pippo login)
        response = requests.get(rest_root + 'nsds/pippo',
                                headers={'Auth': pippotoken})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data), 1)

        # GET PLUTO SHORT NSDs (pluto login)
        response = requests.get(rest_root + 'nsds/pluto',
                                headers={'Auth': plutotoken})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data), 1)

        # GET PLUTO SHORT NSDs (pippo login)
        response = requests.get(rest_root + 'nsds/pluto',
                                headers={'Auth': pippotoken})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data), 1)

        # GET PIPPO SHORT NSDs (pluto login)
        response = requests.get(rest_root + 'nsds/pippo',
                                headers={'Auth': plutotoken})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data), 0)

        # GET PLUTO NSD (pluto login) no slug
        response = requests.get(rest_root + 'nsds',
                                headers={'Auth': plutotoken})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data), 1)

        # DELETE PIPPO NSD (pluto login)
        response = requests.delete(rest_root + 'nsds/' + pippo_returned_uuid,
                                   headers={'Auth': plutotoken})
        self.assertEqual(response.status_code, 404)

        # DELETE PLUTO NSD (pluto login)
        response = requests.delete(rest_root + 'nsds/' + pluto_returned_uuid,
                                   headers={'Auth': plutotoken})
        self.assertEqual(response.status_code, 204)

        # DELETE PIPPO NSD (pippo login)
        response = requests.delete(rest_root + 'nsds/' + pippo_returned_uuid,
                                   headers={'Auth': pippotoken})
        self.assertEqual(response.status_code, 204)

        # ADD NSD AGAIN (pippo login) in order to keep at least one in db
        data = {'nsd': sample_tosca}
        response = requests.post(rest_root + 'nsds/', json=data,
                                 headers={'Auth': pippotoken})
        self.assertEqual(response.status_code, 201)


if __name__ == '__main__':
    unittest.main(testRunner=xmlrunner.XMLTestRunner(output='test-reports'))
