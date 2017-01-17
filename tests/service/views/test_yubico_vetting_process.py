import json
from urllib.parse import parse_qsl, urlparse

import pytest
import responses
from rq.worker import SimpleWorker

from se_leg_op.storage import OpStorageWrapper

TEST_CLIENT_ID = 'client2'
TEST_CLIENT_SECRET = 'secret'
TEST_REDIRECT_URI = 'https://client2.example.com/redirect_uri'

TEST_USER_ID = 'user2'

VETTING_RESULT_ENDPOINT = '/yubico/vetting-result'
VETTING_DATA = {'placeholder': 'data'}

@pytest.fixture
def authn_request_args():
    return {
        'client_id': TEST_CLIENT_ID,
        'redirect_uri': TEST_REDIRECT_URI,
        'user_id': TEST_USER_ID,
        'response_type': 'code',
        'scope': 'openid',
        'nonce': 'nonce',
        'state': 'state'
    }


@pytest.mark.usefixtures('inject_app', 'create_client_in_db')
class TestVettingResultEndpoint(object):
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

    @responses.activate
    def test_vetting_endpoint(self, authn_request_args):
        responses.add(responses.GET, TEST_REDIRECT_URI, status=200)
        nonce = authn_request_args['nonce']
        self.app.authn_requests[nonce] = authn_request_args

        token = 'token'
        qrdata = '1' + json.dumps({'nonce': nonce, 'token': token})
        resp = self.app.test_client().post(VETTING_RESULT_ENDPOINT,
                                           data={'qrcode': qrdata, 'data': json.dumps(VETTING_DATA)})

        assert resp.status_code == 200
        # verify the original authentication request is not removed
        assert nonce in self.app.authn_requests
        # verify the posted data ends up in the userinfo document
        assert self.app.users[TEST_USER_ID]['data'] == VETTING_DATA

    @pytest.mark.parametrize('parameters', [
        {'data': json.dumps(VETTING_DATA)},  # missing 'qrcode'
        {'qrcode': 'nonce token'},  # missing 'identity'
    ])
    def test_vetting_endpoint_with_missing_data(self, parameters):
        resp = self.app.test_client().post(VETTING_RESULT_ENDPOINT, data=parameters)
        assert resp.status_code == 400

    @pytest.mark.parametrize('qrdata', [
        '',  # no qr data
        '1foobar',  # invalid data
        '1{"token": "token"}',  # missing 'nonce'
        '1{"nonce": "nonce"}',  # missing 'token'
        '2{"token": "token", "nonce": "nonce"}'  # invalid qr version
    ])
    def test_vetting_endpoint_with_invalid_qr_data(self, authn_request_args, qrdata):
        resp = self.app.test_client().post(VETTING_RESULT_ENDPOINT, data={'qrcode': qrdata,
                                                                          'data': json.dumps(VETTING_DATA)})
        assert resp.status_code == 400

    def test_unexpected_nonce(self):
        resp = self.app.test_client().post(VETTING_RESULT_ENDPOINT, data={'qrcode': 'unexpected token',
                                                                          'data': json.dumps(VETTING_DATA)})
        assert resp.status_code == 400
