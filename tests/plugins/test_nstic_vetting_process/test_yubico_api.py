# -*- coding: utf-8 -*-

import pytest
import responses
import json
from time import time
from base64 import b64encode

from se_leg_op.storage import OpStorageWrapper
from tests.plugins.test_nstic_vetting_process.test_vetting_result import config_envvar, inject_app, mock_soap_client
from tests.plugins.test_nstic_vetting_process.test_vetting_result import SUCCESSFUL_VETTING_RESULT, TEST_CLIENT_ID
from tests.plugins.test_nstic_vetting_process.test_vetting_result import TEST_REDIRECT_URI, TEST_CLIENT_SECRET

__author__ = 'lundberg'


API_ENDPOINT = '/yubico/api/v1/states'


@pytest.fixture
def userinfo():
    return {
        'vetting_result': {
            'data': SUCCESSFUL_VETTING_RESULT,
            'vetting_time': time()
        }
    }


@pytest.fixture
def states():
    return [
        {
            'created': time(),
            'state': '4c31121c-9767-471b-9020-8c2bfcdcad50',
            'client_id': TEST_CLIENT_ID,
            'user_id': '5f66e244-f922-4b52-bbcb-d80b98b8fa57'
        },
        {
            'created': time(),
            'state': '856352c5-20f7-4d0a-b9e4-e0bbf5b573a7',
            'client_id': TEST_CLIENT_ID,
            'user_id': 'b24bd8a4-3215-4570-b1c0-a846a701e9b3'
        },
        {
            'created': time(),
            'state': '6b2230ef-f855-4457-9e43-ddcdc75a541e',
            'client_id': TEST_CLIENT_ID,
            'user_id': '9ba87583-346d-4916-94f0-ec4eab5c8fb5'
        },
        {
            'created': time(),
            'state': '95ed786b-5e5c-4bc5-a377-9bdc12b7949e',
            'client_id': TEST_CLIENT_ID,
            'user_id': 'b418e271-c4bf-4fb0-881f-385bc0d762e6'
        },
        {
            'created': time(),
            'state': '9bdc12b7949e-4bc5-5e5c-a377-95ed786b',
            'client_id': 'another_client_id',
            'user_id': '385bc0d762e6-c4bf-4fb0-881f-b418e271'
        },
        {
            'created': time(),
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


@pytest.mark.usefixtures('mock_soap_client', 'config_envvar', 'inject_app', 'create_client_in_db', 'states', 'userinfo')
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

    @pytest.fixture
    def create_states_in_db(self, request, states, userinfo):
        db_uri = request.instance.app.config['DB_URI']
        userinfodb = OpStorageWrapper(db_uri, 'userinfo')
        yubico_states = OpStorageWrapper(db_uri, 'yubico_states')
        for state in states:
            yubico_states[state['state']] = state
            userinfodb[state['user_id']] = userinfo
        self.app.yubico_states = yubico_states
        self.app.users = userinfodb

    @pytest.mark.parametrize('user_and_password', [
        {'user': 'test', 'password': 'test'},
        {'user': TEST_CLIENT_ID, 'password': 'wrong_password'},
        {'user': 'wrong_user', 'password': TEST_CLIENT_SECRET},
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
