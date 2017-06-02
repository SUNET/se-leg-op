import base64
import json
from urllib.parse import urlparse

import pytest
import responses
from oic.oic.message import AuthorizationResponse, AccessTokenResponse, OpenIDSchema, ClaimsRequest, Claims
from rq.worker import SimpleWorker

from se_leg_op.storage import OpStorageWrapper

TEST_CLIENT_ID = 'client1'
TEST_CLIENT_SECRET = 'my_secret'
TEST_REDIRECT_URI = 'https://client.example.com/redirect_uri'
TEST_USER_ID = 'user1'
TEST_NONCE = 'nonce'
TEST_TOKEN = 'token'


@pytest.mark.usefixtures('inject_app', 'create_client_in_db')
class TestApp(object):
    def make_authentication_request(self, response_type):
        request_args = {
            'scope': 'openid',
            'client_id': TEST_CLIENT_ID,
            'redirect_uri': TEST_REDIRECT_URI,
            'response_type': response_type,
            'nonce': TEST_NONCE,
            'claims': ClaimsRequest(userinfo=Claims(identity=None)).to_json()
        }

        resp = self.app.test_client().post('/authentication', data=request_args)
        assert resp.status_code == 200
        assert len(responses.calls) == 0  # redirect_uri has not be called with error

    def post_vetting_result(self):
        vetting_result = {
            'qrcode': '1' + json.dumps({'nonce': TEST_NONCE, 'token': TEST_TOKEN}),
            'identity': TEST_USER_ID
        }
        resp = self.app.test_client().post('/vetting-result', data=json.dumps(vetting_result),
                                           content_type='application/json')
        assert resp.status_code == 200

        # force all authentication responses to be sent
        worker = SimpleWorker([self.app.authn_response_queue], connection=self.app.authn_response_queue.connection)
        worker.work(burst=True)

    def parse_authentication_response(self, redirect_uri, fragment_encoded=False):
        parsed_url = urlparse(redirect_uri)
        if fragment_encoded:
            response = parsed_url.fragment
        else:
            response = parsed_url.query
        authn_response = AuthorizationResponse().from_urlencoded(response)
        assert authn_response.verify(key=[self.app.provider.signing_key])
        return authn_response

    def make_code_exchange_request(self, code):
        request_args = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': TEST_REDIRECT_URI
        }
        resp = self.app.test_client().post('/token', data=request_args, headers=self.create_basic_auth_header())
        assert resp.status_code == 200
        token_response = AccessTokenResponse().from_json(resp.data.decode('utf-8'))
        assert token_response.verify(key=[self.app.provider.signing_key])
        return token_response

    def make_userinfo_request(self, access_token):
        resp = self.app.test_client().get('/userinfo', headers={'Authorization': 'Bearer {}'.format(access_token)})
        assert resp.status_code == 200
        userinfo = OpenIDSchema().from_json(resp.data.decode('utf-8'))
        userinfo.verify()
        return userinfo

    def make_refresh_request(self, refresh_token):
        request_args = {
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token,
        }
        resp = self.app.test_client().post('/token', data=request_args, headers=self.create_basic_auth_header())
        assert resp.status_code == 200
        token_response = AccessTokenResponse().from_json(resp.data.decode('utf-8'))
        assert token_response.verify()
        return token_response

    def create_basic_auth_header(self):
        credentials = TEST_CLIENT_ID + ':' + TEST_CLIENT_SECRET
        auth = base64.urlsafe_b64encode(credentials.encode('utf-8')).decode('utf-8')
        return {'Authorization': 'Basic {}'.format(auth)}

    @pytest.fixture
    def create_client_in_db(self, request):
        db_uri = request.instance.app.config['DB_URI']
        client_db = OpStorageWrapper(db_uri, 'clients')
        client_db[TEST_CLIENT_ID] = {
            'redirect_uris': [TEST_REDIRECT_URI],
            'response_types': ['code', 'code id_token token'],
            'client_secret': TEST_CLIENT_SECRET
        }
        self.app.provider.clients = client_db

    @responses.activate
    def test_code_flow(self):
        responses.add(responses.GET, TEST_REDIRECT_URI, status=200)

        self.make_authentication_request('code')
        # approved vetting happens
        self.post_vetting_result()

        authn_response = self.parse_authentication_response(responses.calls[0].request.url)
        token_resp = self.make_code_exchange_request(authn_response['code'])
        userinfo = self.make_userinfo_request(token_resp['access_token'])
        assert token_resp['id_token']['sub'] == userinfo['sub']

        # refresh token and use it
        refresh_resp = self.make_refresh_request(token_resp['refresh_token'])
        userinfo = self.make_userinfo_request(refresh_resp['access_token'])
        assert token_resp['id_token']['sub'] == userinfo['sub']
        assert userinfo['identity'] == TEST_USER_ID

    @responses.activate
    def test_hybrid_flow(self):
        responses.add(responses.GET, TEST_REDIRECT_URI, status=200)

        self.make_authentication_request('code id_token token')
        # approved vetting happens
        self.post_vetting_result()

        authn_response = self.parse_authentication_response(responses.calls[0].request.url, fragment_encoded=True)
        token_resp = self.make_code_exchange_request(authn_response['code'])
        userinfo = self.make_userinfo_request(token_resp['access_token'])
        assert authn_response['id_token']['sub'] == token_resp['id_token']['sub'] == userinfo['sub']

        # refresh token and use it
        refresh_resp = self.make_refresh_request(token_resp['refresh_token'])
        userinfo = self.make_userinfo_request(refresh_resp['access_token'])
        assert token_resp['id_token']['sub'] == userinfo['sub']
        assert userinfo['identity'] == TEST_USER_ID
