# -*- coding: utf-8 -*-

import pytest
from flask import json
from base64 import b64encode
from time import time

from se_leg_op.storage import OpStorageWrapper
from tests.plugins.test_nstic_vetting_process.test_vetting_result import config_envvar, inject_app, mock_soap_client
from tests.plugins.test_nstic_vetting_process.test_vetting_result import SUCCESSFUL_VETTING_RESULT, TEST_CLIENT_ID
from tests.plugins.test_nstic_vetting_process.test_vetting_result import TEST_REDIRECT_URI, TEST_CLIENT_SECRET

__author__ = 'lundberg'


API_ENDPOINT = '/yubico/api/v1/states'
THE_TIME = time()


@pytest.fixture
def userinfo():
    return {
        'vetting_result': {
            'data': SUCCESSFUL_VETTING_RESULT,
            'vetting_time': THE_TIME
        }
    }


@pytest.fixture
def states():
    return [
        {
            'created': THE_TIME,
            'state': '4c31121c-9767-471b-9020-8c2bfcdcad50',
            'client_id': TEST_CLIENT_ID,
            'user_id': '5f66e244-f922-4b52-bbcb-d80b98b8fa57'
        },
        {
            'created': THE_TIME,
            'state': '856352c5-20f7-4d0a-b9e4-e0bbf5b573a7',
            'client_id': TEST_CLIENT_ID,
            'user_id': 'b24bd8a4-3215-4570-b1c0-a846a701e9b3'
        },
        {
            'created': THE_TIME,
            'state': '6b2230ef-f855-4457-9e43-ddcdc75a541e',
            'client_id': TEST_CLIENT_ID,
            'user_id': '9ba87583-346d-4916-94f0-ec4eab5c8fb5'
        },
        {
            'created': THE_TIME,
            'state': '95ed786b-5e5c-4bc5-a377-9bdc12b7949e',
            'client_id': TEST_CLIENT_ID,
            'user_id': 'b418e271-c4bf-4fb0-881f-385bc0d762e6'
        },
        {
            'created': THE_TIME,
            'state': '9bdc12b7949e-4bc5-5e5c-a377-95ed786b',
            'client_id': 'another_client_id',
            'user_id': '385bc0d762e6-c4bf-4fb0-881f-b418e271'
        },
        {
            'created': THE_TIME,
            'state': '9bdc12b7949e-5e5c-4bc5-a377-95ed786b',
            'client_id': 'another_client_id',
            'user_id': '385bc0d762e6-4fb0-c4bf-881f-b418e271'
        },
    ]


@pytest.fixture
def basic_auth_header(user=TEST_CLIENT_ID, password=TEST_CLIENT_SECRET):
    return {
        'Authorization': 'Basic ' + b64encode(bytes('{}:{}'.format(
            user, password), encoding='utf-8')).decode("ascii")
    }


@pytest.mark.usefixtures('mock_soap_client', 'config_envvar', 'inject_app', 'create_client_in_db',
                         'create_states_in_db')
class TestYubicoApi(object):
    @pytest.fixture
    def create_client_in_db(self, request):
        db_uri = request.instance.app.config['DB_URI']
        client_db = OpStorageWrapper(db_uri, 'clients')
        client_db[TEST_CLIENT_ID] = {
            'redirect_uris': [TEST_REDIRECT_URI],
            'client_secret': TEST_CLIENT_SECRET,
            'response_types': ['code'],
            'vetting_policy': 'POST_AUTH'
        }
        self.app.provider.clients = client_db
        self.app.config['YUBICO_API_CLIENTS'] = [TEST_CLIENT_ID]
        self.app.config['YUBICO_API_ADMINS'] = {'admin': {'secret': 'admin'}}

    @pytest.fixture
    def create_states_in_db(self, request, states, userinfo):
        db_uri = request.instance.app.config['DB_URI']
        userinfodb = OpStorageWrapper(db_uri, 'userinfo')
        yubico_states = OpStorageWrapper(db_uri, 'yubico_states')
        # Drop previous states
        yubico_states._coll.drop()
        for state in states:
            yubico_states[state['state']] = state
            userinfodb[state['user_id']] = userinfo
        self.app.yubico_states = yubico_states
        self.app.users = userinfodb

    @staticmethod
    def get_json(response):
        return json.loads(response.get_data(as_text=True))

    @pytest.mark.parametrize('user_and_password', [
        {'user': 'test', 'password': 'test'},
        {'user': TEST_CLIENT_ID, 'password': 'wrong_password'},
        {'user': 'wrong_user', 'password': TEST_CLIENT_SECRET},
        {'user': TEST_CLIENT_ID, 'password': False},
    ])
    def test_get_states_endpoint_unauthorized(self, user_and_password):
        # No auth header
        resp = self.app.test_client().get(API_ENDPOINT)
        assert resp.status_code == 401
        # Try different wrong auth headers
        resp = self.app.test_client().get(API_ENDPOINT, headers=basic_auth_header(**user_and_password))
        assert resp.status_code == 401

    def test_get_states_endpoint(self, basic_auth_header):
        resp = self.app.test_client().get(API_ENDPOINT, headers=basic_auth_header)
        assert resp.status_code == 200
        json_resp = self.get_json(resp)
        assert len(json_resp['states']) == 4
        state = json_resp['states'][0]
        assert 'created' in state
        assert 'state' in state
        assert 'userinfo' in state
        assert 'vetting_result' in state['userinfo']

    def test_get_states_endpoint_admin(self):
        resp = self.app.test_client().get(API_ENDPOINT, headers=basic_auth_header('admin', 'admin'))
        assert resp.status_code == 200
        json_resp = self.get_json(resp)
        assert len(json_resp['states']) == 6

    def test_update_states_endpoint(self, basic_auth_header):
        data = {'states': []}
        for state in states():
            # Just use the clients states
            if state['client_id'] == TEST_CLIENT_ID:
                state['userinfo'] = userinfo()
                state['test_update'] = True
                data['states'].append(state)
        resp = self.app.test_client().post(API_ENDPOINT, headers=basic_auth_header, content_type='application/json',
                                           data=json.dumps(data))
        assert resp.status_code == 202

        # Check if update was saved correctly
        resp = self.app.test_client().get(API_ENDPOINT, headers=basic_auth_header)
        assert resp.status_code == 200
        json_resp = self.get_json(resp)
        for state in json_resp['states']:
            assert 'test_update' in state
            assert 'created' in state
            assert 'state' in state
            assert 'userinfo' in state
            assert 'vetting_result' in state['userinfo']

    def test_update_states_endpoint_admin(self):
        data = {'states': []}
        for state in states():
            state['userinfo'] = userinfo()
            state['test_update'] = True
            data['states'].append(state)
        resp = self.app.test_client().post(API_ENDPOINT, headers=basic_auth_header('admin', 'admin'),
                                           content_type='application/json', data=json.dumps(data))
        assert resp.status_code == 202

        # Check if update was saved correctly
        resp = self.app.test_client().get(API_ENDPOINT, headers=basic_auth_header('admin', 'admin'))
        assert resp.status_code == 200
        json_resp = self.get_json(resp)
        for state in json_resp['states']:
            assert 'test_update' in state
            assert 'created' in state
            assert 'state' in state
            assert 'userinfo' in state
            assert 'vetting_result' in state['userinfo']

    def test_update_states_and_userinfo_endpoint(self, basic_auth_header):
        data = {'states': []}
        for state in states():
            # Just use the clients states
            if state['client_id'] == TEST_CLIENT_ID:
                userinfo_dict = userinfo()
                userinfo_dict['vetting_result']['test_update'] = True
                state['userinfo'] = userinfo_dict
                state['test_update'] = True
                data['states'].append(state)
        resp = self.app.test_client().post(API_ENDPOINT, headers=basic_auth_header, content_type='application/json',
                                           data=json.dumps(data))
        assert resp.status_code == 202

        # Check if update was saved correctly
        resp = self.app.test_client().get(API_ENDPOINT, headers=basic_auth_header)
        assert resp.status_code == 200
        json_resp = self.get_json(resp)
        for state in json_resp['states']:
            assert 'test_update' in state
            assert 'created' in state
            assert 'state' in state
            assert 'userinfo' in state
            assert 'vetting_result' in state['userinfo']
            assert 'test_update' in state['userinfo']['vetting_result']

    def test_update_states_endpoint_unauthorized_states(self, basic_auth_header):
        data = {'states': []}
        for state in states():
            state['userinfo'] = userinfo()
            state['test_update'] = True
            data['states'].append(state)
        resp = self.app.test_client().post(API_ENDPOINT, headers=basic_auth_header, content_type='application/json',
                                           data=json.dumps(data))
        assert resp.status_code == 422

        # Check error message
        json_resp = self.get_json(resp)
        assert json_resp['status'] == 'Unprocessable Entity'
        assert json_resp['errors'] == ['9bdc12b7949e-4bc5-5e5c-a377-95ed786b', '9bdc12b7949e-5e5c-4bc5-a377-95ed786b']

        # Check if update was saved correctly for states with correct auth
        resp = self.app.test_client().get(API_ENDPOINT, headers=basic_auth_header)
        assert resp.status_code == 200
        json_resp = self.get_json(resp)
        for state in json_resp['states']:
            assert 'test_update' in state
            assert 'created' in state
            assert 'state' in state
            assert 'userinfo' in state
            assert 'vetting_result' in state['userinfo']

    def test_get_state_endpoint(self, basic_auth_header):
        state_id = states()[0]['state']
        endpoint = API_ENDPOINT + '/{}'.format(state_id)
        resp = self.app.test_client().get(endpoint, headers=basic_auth_header)
        assert resp.status_code == 200
        json_resp = self.get_json(resp)
        assert 'created' in json_resp
        assert 'state' in json_resp
        assert 'userinfo' in json_resp
        assert 'vetting_result' in json_resp['userinfo']

    def test_get_state_endpoint_admin(self):
        state_id = states()[0]['state']
        endpoint = API_ENDPOINT + '/{}'.format(state_id)
        resp = self.app.test_client().get(endpoint, headers=basic_auth_header('admin', 'admin'))
        assert resp.status_code == 200
        json_resp = self.get_json(resp)
        assert 'created' in json_resp
        assert 'state' in json_resp
        assert 'userinfo' in json_resp
        assert 'vetting_result' in json_resp['userinfo']

    @pytest.mark.parametrize('state_id', [
        'unknown state',
        '9bdc12b7949e-5e5c-4bc5-a377-95ed786b'
    ])
    def test_get_state_endpoint_unauthorized_state(self, basic_auth_header, state_id):
        endpoint = API_ENDPOINT + '/{}'.format(state_id)
        resp = self.app.test_client().get(endpoint, headers=basic_auth_header)
        assert resp.status_code == 404
        json_resp = self.get_json(resp)
        assert json_resp['status'] == 'Not Found'
        assert json_resp['errors'] == [state_id]

    def test_create_state_endpoint(self, basic_auth_header):
        data = states()[0]
        data['state'] = 'new state id'
        data['test_update'] = True
        endpoint = API_ENDPOINT + '/{}'.format(data['state'])
        resp = self.app.test_client().post(endpoint, headers=basic_auth_header, content_type='application/json',
                                           data=json.dumps(data))
        assert resp.status_code == 201

        db_state = self.app.yubico_states['new state id']
        assert 'test_update' in db_state
        assert 'created' in db_state
        assert db_state['state'] == 'new state id'

    def test_create_state_endpoint_admin(self):
        data = states()[0]
        data['state'] = 'new state id'
        data['test_update'] = True
        endpoint = API_ENDPOINT + '/{}'.format(data['state'])
        resp = self.app.test_client().post(endpoint, headers=basic_auth_header('admin', 'admin'),
                                           content_type='application/json', data=json.dumps(data))
        assert resp.status_code == 201

        resp = self.app.test_client().get(endpoint, headers=basic_auth_header('admin', 'admin'))
        assert resp.status_code == 200
        json_resp = self.get_json(resp)
        assert 'test_update' in json_resp
        assert 'created' in json_resp
        assert 'state' in json_resp
        assert 'userinfo' in json_resp
        assert json_resp['userinfo'] is None

    def test_update_state_endpoint(self, basic_auth_header):
        data = states()[0]
        data['test_update'] = True
        endpoint = API_ENDPOINT + '/{}'.format(data['state'])
        resp = self.app.test_client().post(endpoint, headers=basic_auth_header, content_type='application/json',
                                           data=json.dumps(data))
        assert resp.status_code == 202
        resp = self.app.test_client().get(endpoint, headers=basic_auth_header)
        assert resp.status_code == 200
        json_resp = self.get_json(resp)
        assert 'test_update' in json_resp
        assert 'created' in json_resp
        assert 'state' in json_resp
        assert 'userinfo' in json_resp
        assert 'vetting_result' in json_resp['userinfo']

    def test_update_state_endpoint_admin(self):
        data = states()[0]
        data['test_update'] = True
        endpoint = API_ENDPOINT + '/{}'.format(data['state'])
        resp = self.app.test_client().post(endpoint, headers=basic_auth_header('admin', 'admin'),
                                           content_type='application/json', data=json.dumps(data))
        assert resp.status_code == 202
        resp = self.app.test_client().get(endpoint, headers=basic_auth_header('admin', 'admin'))
        assert resp.status_code == 200
        json_resp = self.get_json(resp)
        assert 'test_update' in json_resp
        assert 'created' in json_resp
        assert 'state' in json_resp
        assert 'userinfo' in json_resp
        assert 'vetting_result' in json_resp['userinfo']

    @pytest.mark.parametrize('state_id', [
        '9bdc12b7949e-5e5c-4bc5-a377-95ed786b'
    ])
    def test_update_state_endpoint_unauthorized_state(self, basic_auth_header, state_id):
        data = states()[0]
        data['test_update'] = True
        endpoint = API_ENDPOINT + '/{}'.format(state_id)
        resp = self.app.test_client().post(endpoint, headers=basic_auth_header, content_type='application/json',
                                           data=json.dumps(data))
        assert resp.status_code == 404
        json_resp = self.get_json(resp)
        assert json_resp['status'] == 'Not Found'
        assert json_resp['errors'] == [state_id]

    def test_delete_state_endpoint(self, basic_auth_header):
        state = states()[0]
        endpoint = API_ENDPOINT + '/{}'.format(state['state'])
        resp = self.app.test_client().delete(endpoint, headers=basic_auth_header)
        assert resp.status_code == 200
        # Check if it the state was removed
        resp = self.app.test_client().delete(endpoint, headers=basic_auth_header)
        assert resp.status_code == 404
        json_resp = self.get_json(resp)
        assert json_resp['status'] == 'Not Found'
        assert json_resp['errors'] == [state['state']]
        # Check if the associated userinfo was removed
        with pytest.raises(KeyError):
            userinfo_doc = self.app.users[state['user_id']]

    def test_delete_state_endpoint_admin(self):
        state = states()[0]
        endpoint = API_ENDPOINT + '/{}'.format(state['state'])
        resp = self.app.test_client().delete(endpoint, headers=basic_auth_header('admin', 'admin'))
        assert resp.status_code == 200
        # Check if it the state was removed
        resp = self.app.test_client().delete(endpoint, headers=basic_auth_header('admin', 'admin'))
        assert resp.status_code == 404
        json_resp = self.get_json(resp)
        assert json_resp['status'] == 'Not Found'
        assert json_resp['errors'] == [state['state']]
        # Check if the associated userinfo was removed
        with pytest.raises(KeyError):
            userinfo_doc = self.app.users[state['user_id']]

    @pytest.mark.parametrize('state_id', [
        'unknown state',
        '9bdc12b7949e-5e5c-4bc5-a377-95ed786b'
    ])
    def test_delete_state_endpoint_unauthorized_state(self, basic_auth_header, state_id):
        endpoint = API_ENDPOINT + '/{}'.format(state_id)
        resp = self.app.test_client().delete(endpoint, headers=basic_auth_header, content_type='application/json')
        assert resp.status_code == 404
        json_resp = self.get_json(resp)
        assert json_resp['status'] == 'Not Found'
        assert json_resp['errors'] == [state_id]

    def test_delete_state_endpoint_missing_user_id(self):
        no_user_id_state = {
            'created': THE_TIME,
            'state': '95ed786b-5e5c-4bc5-a377-9bdc12b7949e',
            'client_id': TEST_CLIENT_ID
        }
        self.app.yubico_states[no_user_id_state['state']] = no_user_id_state
        endpoint = API_ENDPOINT + '/{}'.format(no_user_id_state['state'])
        resp = self.app.test_client().delete(endpoint, headers=basic_auth_header('admin', 'admin'))
        assert resp.status_code == 200
        # Check if it the state was removed
        resp = self.app.test_client().delete(endpoint, headers=basic_auth_header('admin', 'admin'))
        assert resp.status_code == 404
        json_resp = self.get_json(resp)
        assert json_resp['status'] == 'Not Found'
        assert json_resp['errors'] == [no_user_id_state['state']]
