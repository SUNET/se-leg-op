import base64
import os
from urllib.parse import urlparse

import pytest
import responses
from oic.oic.message import AuthorizationResponse, AccessTokenResponse, OpenIDSchema

from se_leg_op.service.app import SE_LEG_PROVIDER_SETTINGS_ENVVAR, ShelveWrapper
from se_leg_op.service.app import oidc_provider_init_app

TEST_CLIENT_ID = 'client1'
TEST_CLIENT_SECRET = 'my_secret'
TEST_REDIRECT_URI = 'https://client.example.com/redirect_uri'
TEST_USER_ID = 'user1'
TEST_NONCE = 'nonce'


@pytest.fixture
def inject_app(request, tmpdir):
    os.chdir(str(tmpdir))
    os.environ[SE_LEG_PROVIDER_SETTINGS_ENVVAR] = './app_config.py'
    request.instance.app = oidc_provider_init_app(__name__)


@pytest.mark.usefixtures('inject_app', 'create_client_in_db')
class TestApp(object):
    def make_authentication_request(self, response_type):
        request_args = {
            'scope': 'openid',
            'client_id': TEST_CLIENT_ID,
            'redirect_uri': TEST_REDIRECT_URI,
            'response_type': response_type,
            'response_mode': 'query',
            'nonce': TEST_NONCE
        }

        resp = self.app.test_client().post('/authentication', data=request_args)
        assert resp.status_code == 200
        assert len(responses.calls) == 0  # redirect_uri has not be called with error

    def post_vetting_result(self):
        vetting_result = {
            'nonce': TEST_NONCE,
            'identity': TEST_USER_ID
        }
        resp = self.app.test_client().post('/vetting-result', data=vetting_result)
        assert resp.status_code == 200

    def parse_authentication_response(self, redirect_uri):
        authn_response = AuthorizationResponse().from_urlencoded(urlparse(redirect_uri).query)
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
    def create_client_in_db(self, tmpdir):
        client_db_path = os.path.join(str(tmpdir), 'clients')
        client_db = ShelveWrapper(client_db_path)
        client_db[TEST_CLIENT_ID] = {
            'redirect_uris': [TEST_REDIRECT_URI],
            'response_types': [['code'], ['code', 'id_token', 'token']],
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

    @responses.activate
    def test_hybrid_flow(self):
        responses.add(responses.GET, TEST_REDIRECT_URI, status=200)

        self.make_authentication_request('code id_token token')
        # approved vetting happens
        self.post_vetting_result()

        authn_response = self.parse_authentication_response(responses.calls[0].request.url)
        token_resp = self.make_code_exchange_request(authn_response['code'])
        userinfo = self.make_userinfo_request(token_resp['access_token'])
        assert authn_response['id_token']['sub'] == token_resp['id_token']['sub'] == userinfo['sub']

        # refresh token and use it
        refresh_resp = self.make_refresh_request(token_resp['refresh_token'])
        userinfo = self.make_userinfo_request(refresh_resp['access_token'])
        assert token_resp['id_token']['sub'] == userinfo['sub']
