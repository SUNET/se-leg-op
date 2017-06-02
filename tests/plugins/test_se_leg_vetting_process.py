import json
from urllib.parse import parse_qsl, urlparse

import pytest
import responses
from rq.worker import SimpleWorker

from se_leg_op.storage import OpStorageWrapper

TEST_CLIENT_ID = 'client1'
TEST_CLIENT_SECRET = 'secret'
TEST_REDIRECT_URI = 'https://client.example.com/redirect_uri'

TEST_USER_ID = 'user1'

EXTRA_CONFIG = {
    'PACKAGES': ['se_leg_op.plugins.se_leg_vetting_process']
}


@pytest.fixture
def authn_request_args():
    return {
        'client_id': TEST_CLIENT_ID,
        'redirect_uri': TEST_REDIRECT_URI,
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
            'response_types': ['code']
        }
        self.app.provider.clients = client_db

    @responses.activate
    def test_vetting_endpoint(self, authn_request_args):
        responses.add(responses.GET, TEST_REDIRECT_URI, status=200)
        nonce = authn_request_args['nonce']
        self.app.authn_requests[nonce] = authn_request_args

        token = 'token'
        qrdata = '1' + json.dumps({'nonce': nonce, 'token': token})
        data = {'qrcode': qrdata, 'identity': TEST_USER_ID}
        resp = self.app.test_client().post('/vetting-result', data=json.dumps(data), content_type='application/json')

        assert resp.status_code == 200
        # verify the original authentication request has been handled
        assert nonce not in self.app.authn_requests
        assert self.app.users[TEST_USER_ID]['identity'] == TEST_USER_ID

        # force sending response from message queue from http://python-rq.org/docs/testing/
        worker = SimpleWorker([self.app.authn_response_queue], connection=self.app.authn_response_queue.connection)
        worker.work(burst=True)

        # verify the authentication response has been sent to the client
        parsed_response = dict(parse_qsl(urlparse(responses.calls[0].request.url).query))
        assert 'code' in parsed_response
        assert parsed_response['state'] == authn_request_args['state']
        assert parsed_response['code'] in self.app.provider.authz_state.authorization_codes
        assert responses.calls[0].request.headers['Authorization'] == 'Bearer ' + token

    @pytest.mark.parametrize('parameters', [
        {'identity': TEST_USER_ID},  # missing 'qrcode'
        {'qrcode': 'nonce token'},  # missing 'identity'
    ])
    def test_vetting_endpoint_with_missing_data(self, parameters):
        resp = self.app.test_client().post('/vetting-result', data=json.dumps(parameters),
                                           content_type='application/json')
        assert resp.status_code == 400

    @pytest.mark.parametrize('qrdata', [
        '',  # no qr data
        '1foobar',  # invalid data
        '1{"token": "token"}',  # missing 'nonce'
        '1{"nonce": "nonce"}',  # missing 'token'
        '2{"token": "token", "nonce": "nonce"}'  # invalid qr version
    ])
    def test_vetting_endpoint_with_invalid_qr_data(self, qrdata):
        data = {'qrcode': qrdata, 'identity': TEST_USER_ID}
        resp = self.app.test_client().post('/vetting-result', data=json.dumps(data), content_type='application/json')
        assert resp.status_code == 400

    def test_unexpected_nonce(self):
        data = {'qrcode': 'unexpected token', 'identity': TEST_USER_ID}
        resp = self.app.test_client().post('/vetting-result', data=json.dumps(data), content_type='application/json')
        assert resp.status_code == 400
