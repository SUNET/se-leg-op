import base64
import datetime as dt
import json
import os
import re
import time
from unittest.mock import Mock, patch
from urllib.parse import urlparse, parse_qsl

import pytest
import responses
from jwkest.jwk import RSAKey, import_rsa_key
from oic.oic.message import AuthorizationRequest, IdToken, ClaimsRequest, Claims
from pyop.exceptions import InvalidAuthenticationRequest
from rq.worker import SimpleWorker

from se_leg_op.storage import OpStorageWrapper

TEST_CLIENT_ID = 'client1'
TEST_CLIENT_SECRET = 'secret'
TEST_REDIRECT_URI = 'https://client.example.com/redirect_uri'
TEST_USER_ID = 'user1'

POST_AUTH_TEST_CLIENT_ID = 'client2'
POST_AUTH_TEST_CLIENT_SECRET = 'secret'
POST_AUTH_TEST_REDIRECT_URI = 'https://client2.example.com/redirect_uri'


@pytest.fixture
def authn_request_args():
    return {
        'client_id': TEST_CLIENT_ID,
        'redirect_uri': TEST_REDIRECT_URI,
        'response_type': 'code',
        'scope': 'openid',
        'nonce': 'nonce'
    }

@pytest.fixture
def post_auth_authn_request_args():
    return {
        'client_id': POST_AUTH_TEST_CLIENT_ID,
        'redirect_uri': POST_AUTH_TEST_REDIRECT_URI,
        'response_type': 'code',
        'scope': 'openid',
        'nonce': 'nonce',
        'token': 'token'
    }

@pytest.mark.usefixtures('inject_app')
class TestConfiguration(object):
    def test_config(self):
        assert self.app.provider.provider_configuration['issuer'] == 'https://localhost:5000'
        assert self.app.provider.provider_configuration['authorization_endpoint'] == \
               'https://localhost:5000/authentication'
        assert self.app.provider.provider_configuration['jwks_uri'] == 'https://localhost:5000/jwks'
        assert self.app.provider.provider_configuration['token_endpoint'] == 'https://localhost:5000/token'
        assert self.app.provider.provider_configuration['userinfo_endpoint'] == 'https://localhost:5000/userinfo'
        assert self.app.provider.provider_configuration['scopes_supported'] == ['openid']
        assert self.app.provider.provider_configuration['response_types_supported'] == ['code', 'code id_token',
                                                                                        'code token',
                                                                                        'code id_token token']
        assert self.app.provider.provider_configuration['response_modes_supported'] == ['query', 'fragment']
        assert self.app.provider.provider_configuration['grant_types_supported'] == ['authorization_code', 'implicit']
        assert self.app.provider.provider_configuration['subject_types_supported'] == \
               ['pairwise']  # TODO should 'public' be supported too?
        assert self.app.provider.provider_configuration['id_token_signing_alg_values_supported'] == ['RS256']
        assert self.app.provider.provider_configuration['token_endpoint_auth_methods_supported'] == \
               ['client_secret_basic']
        assert self.app.provider.provider_configuration['claims_parameter_supported'] == True

        assert self.app.provider.signing_key.kid == 'test_kid'
        assert self.app.provider.signing_key.alg == 'RS256'
        assert self.app.provider.authz_state._subject_identifier_factory.hash_salt == 'test_salt'


@pytest.mark.usefixtures('inject_app', 'create_client_in_db')
class TestAuthenticationEndpoint(object):
    def test_authentication_endpoint_reject_wrong_http_method(self):
        resp = self.app.test_client().get('/authentication')
        assert resp.status_code == 405  # "Method not allowed"

    def force_send_all_queued_messages(self):
        worker = SimpleWorker([self.app.authn_response_queue], connection=self.app.authn_response_queue.connection)
        worker.work(burst=True)

    @pytest.fixture
    def create_client_in_db(self, request):
        db_uri = request.instance.app.config['DB_URI']
        client_db = OpStorageWrapper(db_uri, 'clients')
        client_db[TEST_CLIENT_ID] = {
            'redirect_uris': [TEST_REDIRECT_URI],
            'response_types': ['code'],
        }
        client_db[POST_AUTH_TEST_CLIENT_ID] = {
            'redirect_uris': [POST_AUTH_TEST_REDIRECT_URI],
            'response_types': ['code'],
            'vetting_policy': 'POST_AUTH'
        }
        self.app.provider.clients = client_db

    def test_authentication_endpoint(self, authn_request_args):
        nonce = authn_request_args['nonce']

        resp = self.app.test_client().post('/authentication', data=authn_request_args)
        assert resp.status_code == 200
        assert self.app.authn_requests[nonce] == authn_request_args

    def test_authentication_endpoint_post_auth(self, post_auth_authn_request_args):
        nonce = post_auth_authn_request_args['nonce']

        resp = self.app.test_client().post('/authentication', data=post_auth_authn_request_args)
        assert resp.status_code == 200
        assert 'user_id' in self.app.authn_requests[nonce]
        post_auth_authn_request_args['user_id'] = self.app.authn_requests[nonce]['user_id']
        assert self.app.authn_requests[nonce] == post_auth_authn_request_args

    @responses.activate
    def test_error_response(self, authn_request_args):
        exception = InvalidAuthenticationRequest('test', AuthorizationRequest(**authn_request_args), 'invalid_request')
        parse_auth_req_mock = Mock(side_effect=exception)
        self.app.provider.parse_authentication_request = parse_auth_req_mock

        responses.add(responses.GET, TEST_REDIRECT_URI, status=200)

        resp = self.app.test_client().post('/authentication', data={})
        assert resp.status_code == 200

        self.force_send_all_queued_messages()
        parsed = urlparse(responses.calls[0].request.url)
        assert dict(parse_qsl(parsed.query)) == {'error': 'invalid_request', 'error_message': 'test'}

    def test_error_response_no_token_post_auth(self, post_auth_authn_request_args):
        post_auth_authn_request_args.pop('token')
        resp = self.app.test_client().post('/authentication', data=post_auth_authn_request_args)
        assert resp.status_code == 400
        assert b'Token missing' in resp.data

    @responses.activate
    def test_fragment_encoded_error_response(self, authn_request_args):
        authn_request_args['response_type'] = 'code id_token'
        exception = InvalidAuthenticationRequest('test', AuthorizationRequest(**authn_request_args), 'invalid_request')
        parse_auth_req_mock = Mock(side_effect=exception)
        self.app.provider.parse_authentication_request = parse_auth_req_mock

        url_re = re.compile(r'{}#.*'.format(TEST_REDIRECT_URI))  # requests library does not allow ignoring fragment
        responses.add(responses.GET, url_re, status=200)

        resp = self.app.test_client().post('/authentication', data={})
        assert resp.status_code == 200

        self.force_send_all_queued_messages()
        parsed = urlparse(responses.calls[0].request.url)
        assert dict(parse_qsl(parsed.fragment)) == {'error': 'invalid_request', 'error_message': 'test'}

    def test_bad_request_with_invalid_redirect_uri(self, authn_request_args):
        authn_request_args['redirect_uri'] = 'https://invalid.com'

        resp = self.app.test_client().post('/authentication', data=authn_request_args)
        assert resp.status_code == 400

    @responses.activate
    def test_reject_authn_request_without_nonce(self, authn_request_args):
        del authn_request_args['nonce']
        responses.add(responses.GET, TEST_REDIRECT_URI, status=200)
        resp = self.app.test_client().post('/authentication', data=authn_request_args)

        assert resp.status_code == 200

        self.force_send_all_queued_messages()
        parsed_response = dict(parse_qsl(urlparse(responses.calls[0].request.url).query))
        assert parsed_response['error'] == 'invalid_request'
        assert 'nonce' in parsed_response['error_message']


@pytest.mark.usefixtures('inject_app', 'create_client_in_db')
class TestTokenEndpoint(object):
    MOCK_TIME = Mock(return_value=time.mktime(dt.datetime(2016, 6, 21).timetuple()))

    def set_create_subject_identifier(self):
        return self.app.provider.authz_state.get_subject_identifier('pairwise', TEST_USER_ID,
                                                                    urlparse(TEST_REDIRECT_URI).netloc)

    def create_basic_auth(self, client_id=TEST_CLIENT_ID, client_secret=TEST_CLIENT_SECRET):
        credentials = client_id + ':' + client_secret
        auth = base64.urlsafe_b64encode(credentials.encode('utf-8')).decode('utf-8')
        return 'Basic {}'.format(auth)

    def create_refresh_token(self, authn_request_args):
        sub = self.set_create_subject_identifier()
        auth_req = AuthorizationRequest().from_dict(authn_request_args)
        access_token = self.app.provider.authz_state.create_access_token(auth_req, sub)
        return self.app.provider.authz_state.create_refresh_token(access_token.value)

    def assert_id_token_base_claims(self, jws, verification_key, provider, auth_req):
        id_token = IdToken().from_jwt(jws, key=[verification_key])
        assert id_token['nonce'] == auth_req['nonce']
        assert id_token['iss'] == provider.provider_configuration['issuer']
        assert provider.authz_state.get_user_id_for_subject_identifier(id_token['sub']) == TEST_USER_ID
        assert id_token['iat'] == self.MOCK_TIME.return_value
        assert id_token['exp'] == id_token['iat'] + provider.id_token_lifetime
        assert TEST_CLIENT_ID in id_token['aud']

        return id_token

    @pytest.fixture
    def create_client_in_db(self, request):
        db_uri = request.instance.app.config['DB_URI']
        client_db = OpStorageWrapper(db_uri, 'clients')
        client_db[TEST_CLIENT_ID] = {
            'client_secret': TEST_CLIENT_SECRET,
            'token_endpoint_auth_method': 'client_secret_basic'
        }
        self.app.provider.clients = client_db

    @pytest.fixture
    def code_exchange_request_args(self):
        return {
            'grant_type': 'authorization_code',
            'code': None,
            'redirect_uri': TEST_REDIRECT_URI,
        }

    @pytest.fixture
    def refresh_token_request_args(self):
        return {
            'grant_type': 'refresh_token',
            'refresh_token': None,
        }

    @patch('time.time', MOCK_TIME)
    def test_token_endpoint_with_auth_code(self, code_exchange_request_args, authn_request_args):
        sub = self.set_create_subject_identifier()
        vetting_time = 23
        code_exchange_request_args['code'] = self.app.provider.authz_state.create_authorization_code(
            AuthorizationRequest(**authn_request_args), sub)
        self.app.users[TEST_USER_ID] = {'vetting_time': vetting_time}

        resp = self.app.test_client().post('/token', data=code_exchange_request_args,
                                           headers={'Authorization': self.create_basic_auth()})
        assert resp.status_code == 200
        parsed_response = json.loads(resp.data.decode('utf-8'))
        assert parsed_response['access_token'] in self.app.provider.authz_state.access_tokens
        assert parsed_response['refresh_token'] in self.app.provider.authz_state.refresh_tokens
        id_token = self.assert_id_token_base_claims(parsed_response['id_token'], self.app.provider.signing_key,
                                                    self.app.provider, authn_request_args)
        assert id_token['vetting_time'] == vetting_time

    def test_token_endpoint_with_refresh_token(self, refresh_token_request_args, authn_request_args):
        refresh_token_request_args['refresh_token'] = self.create_refresh_token(authn_request_args)
        resp = self.app.test_client().post('/token', data=refresh_token_request_args,
                                           headers={'Authorization': self.create_basic_auth()})
        assert resp.status_code == 200
        parsed_response = json.loads(resp.data.decode('utf-8'))
        assert parsed_response['access_token'] in self.app.provider.authz_state.access_tokens

    @pytest.mark.parametrize('missing_parameter', [
        'grant_type',
        'code',
        'redirect_uri'
    ])
    def test_code_exchange_request_with_missing_parameter(self, missing_parameter, code_exchange_request_args):
        del code_exchange_request_args[missing_parameter]
        resp = self.app.test_client().post('/token', data=code_exchange_request_args,
                                           headers={'Authorization': self.create_basic_auth()})
        assert resp.status_code == 400
        parsed_response = json.loads(resp.data.decode('utf-8'))
        assert parsed_response['error'] == 'invalid_request'

    @pytest.mark.parametrize('missing_parameter', [
        'grant_type',
        'refresh_token',
    ])
    def test_refresh_token_request_with_missing_parameter(self, missing_parameter, refresh_token_request_args):
        del refresh_token_request_args[missing_parameter]
        resp = self.app.test_client().post('/token', data=refresh_token_request_args,
                                           headers={'Authorization': self.create_basic_auth()})
        assert resp.status_code == 400
        parsed_response = json.loads(resp.data.decode('utf-8'))
        assert parsed_response['error'] == 'invalid_request'

    def test_invalid_client_auth(self):
        resp = self.app.test_client().post('/token', headers={'Authorization': 'invalid'})
        assert resp.status_code == 401
        assert resp.headers['WWW-Authenticate'] == 'Basic'
        parsed_response = json.loads(resp.data.decode('utf-8'))
        assert parsed_response['error'] == 'invalid_client'

    def test_invalid_code_in_exchange_request(self, code_exchange_request_args):
        code_exchange_request_args['code'] = 'invalid'
        resp = self.app.test_client().post('/token', data=code_exchange_request_args,
                                           headers={'Authorization': self.create_basic_auth()})
        assert resp.status_code == 400
        parsed_response = json.loads(resp.data.decode('utf-8'))
        assert parsed_response['error'] == 'invalid_grant'

    def test_invalid_refresh_token_in_exchange_request(self, refresh_token_request_args):
        refresh_token_request_args['refresh_token'] = 'invalid'
        resp = self.app.test_client().post('/token', data=refresh_token_request_args,
                                           headers={'Authorization': self.create_basic_auth()})
        assert resp.status_code == 400
        parsed_response = json.loads(resp.data.decode('utf-8'))
        assert parsed_response['error'] == 'invalid_grant'

    def test_invalid_grant_type(self):
        resp = self.app.test_client().post('/token', data={'grant_type': 'invalid'},
                                           headers={'Authorization': self.create_basic_auth()})

        assert resp.status_code == 400
        parsed_response = json.loads(resp.data.decode('utf-8'))
        assert parsed_response['error'] == 'unsupported_grant_type'

    def test_invalid_scope_in_refresh_request(self, refresh_token_request_args, authn_request_args):
        refresh_token_request_args['scope'] = 'openid extra'
        refresh_token_request_args['refresh_token'] = self.create_refresh_token(authn_request_args)
        resp = self.app.test_client().post('/token', data=refresh_token_request_args,
                                           headers={'Authorization': self.create_basic_auth()})

        assert resp.status_code == 400
        parsed_response = json.loads(resp.data.decode('utf-8'))
        assert parsed_response['error'] == 'invalid_scope'


@pytest.mark.usefixtures('inject_app')
class TestUserInfoEndpoint(object):
    HTTP_METHODS = ['GET', 'POST']

    def create_access_token(self, authn_request_args):
        sub = self.app.provider.authz_state.get_subject_identifier('pairwise', TEST_USER_ID, 'client1.example.com')
        auth_req = AuthorizationRequest().from_dict(authn_request_args)
        access_token = self.app.provider.authz_state.create_access_token(auth_req, sub)
        return access_token.value

    @pytest.mark.parametrize('method', HTTP_METHODS)
    def test_invalid_access_token(self, method):
        resp = self.app.test_client().open('/userinfo', headers={'Authorization': 'Bearer invalid'}, method=method)
        assert resp.status_code == 401
        assert resp.headers['WWW-Authenticate'] == 'Bearer'
        parsed_response = json.loads(resp.data.decode('utf-8'))
        assert parsed_response['error'] == 'invalid_token'

    @pytest.mark.parametrize('method', HTTP_METHODS)
    def test_no_access_token(self, method):
        resp = self.app.test_client().open('/userinfo', method=method)
        assert resp.status_code == 401
        assert resp.headers['WWW-Authenticate'] == 'Bearer'

    @pytest.mark.parametrize('method', HTTP_METHODS)
    def test_userinfo_endpoint(self, method, authn_request_args):
        expected_userinfo = {
            'email': 'test@example.com',
            'name': 'Test T. Testing',
            'nickname': 'Tester',
            'middle_name': 'Theodore'
        }

        authn_request_args['scope'] = 'openid profile'
        authn_request_args['claims'] = ClaimsRequest(userinfo=Claims(email=None))
        access_token = self.create_access_token(authn_request_args)
        self.app.users[TEST_USER_ID] = expected_userinfo

        resp = self.app.test_client().open('/userinfo', headers={'Authorization': 'Bearer {}'.format(access_token)},
                                           method=method)
        assert resp.status_code == 200
        parsed_resp = json.loads(resp.data.decode('utf-8'))

        response_sub = parsed_resp.pop('sub')
        assert parsed_resp == expected_userinfo
        assert self.app.provider.authz_state.get_user_id_for_subject_identifier(response_sub) == TEST_USER_ID


@pytest.mark.usefixtures('inject_app')
class TestProviderConfigurationEndpoint(object):
    def test_configuration_endpoint(self):
        resp = self.app.test_client().get('/.well-known/openid-configuration')
        assert resp.status_code == 200
        assert json.loads(resp.data.decode('utf-8')) == self.app.provider.provider_configuration.to_dict()


@pytest.mark.usefixtures('inject_app')
class TestJWKSEndpoint(object):
    def test_jwks_endpoint(self):
        resp = self.app.test_client().get('/jwks')
        assert resp.status_code == 200
        jwks = json.loads(resp.data.decode('utf-8'))
        assert len(jwks['keys']) == 1
        jwks_key = RSAKey(**jwks['keys'][0])

        basename = os.path.dirname(os.path.realpath(__file__))
        with open(os.path.join(basename, '../private.pem')) as f:
            expected_key = RSAKey(key=import_rsa_key(f.read()), kid=jwks_key.kid, alg='RS256')

        assert jwks_key == expected_key
