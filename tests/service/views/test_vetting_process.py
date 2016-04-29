import os
from urllib.parse import parse_qsl, urlparse

import pytest
import responses
from rq.worker import SimpleWorker

from se_leg_op.service.app import oidc_provider_init_app, SE_LEG_PROVIDER_SETTINGS_ENVVAR, MongoWrapper
from tests.storage.mongodb import MongoTemporaryInstance
from tests.storage.redis import RedisTemporaryInstance

TEST_CLIENT_ID = 'client1'
TEST_CLIENT_SECRET = 'secret'
TEST_REDIRECT_URI = 'https://client.example.com/redirect_uri'

TEST_USER_ID = 'user1'


@pytest.yield_fixture
def mongodb():
    tmp_db = MongoTemporaryInstance()
    yield tmp_db
    tmp_db.shutdown()


@pytest.yield_fixture
def redis():
    tmp_redis = RedisTemporaryInstance()
    yield tmp_redis
    tmp_redis.shutdown()


@pytest.fixture
def inject_app(request, tmpdir, mongodb, redis):
    os.chdir(str(tmpdir))
    os.environ[SE_LEG_PROVIDER_SETTINGS_ENVVAR] = './app_config.py'
    config = {
        '_mongodb': mongodb,
        'DB_URI': mongodb.get_uri(),
        'REDIS_URI': redis.get_uri()
    }
    app = oidc_provider_init_app(__name__, config=config)
    app.authn_response_queue.empty()
    request.instance.app = app


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
        client_db = MongoWrapper(db_uri, 'se_leg_op', 'clients')
        client_db[TEST_CLIENT_ID] = {
            'redirect_uris': [TEST_REDIRECT_URI],
            'client_secret': TEST_CLIENT_SECRET,
            'response_types': [['code']]
        }
        self.app.provider.clients = client_db

    @responses.activate
    def test_vetting_endpoint(self, authn_request_args):
        responses.add(responses.GET, TEST_REDIRECT_URI, status=200)
        nonce = authn_request_args['nonce']
        self.app.authn_requests[nonce] = authn_request_args

        resp = self.app.test_client().post('/vetting-result', data={'nonce': nonce,
                                                                    'identity': TEST_USER_ID})

        assert resp.status_code == 200
        # verify the original authentication request has been handled
        assert nonce not in self.app.authn_requests
        assert TEST_USER_ID in self.app.provider.userinfo

        # force sending response from message queue from http://python-rq.org/docs/testing/
        worker = SimpleWorker([self.app.authn_response_queue], connection=self.app.authn_response_queue.connection)
        worker.work(burst=True)

        # verify the authentication response has been sent to the client
        parsed_response = dict(parse_qsl(urlparse(responses.calls[0].request.url).query))
        assert 'code' in parsed_response
        assert parsed_response['state'] == authn_request_args['state']
        assert parsed_response['code'] in self.app.provider.authz_state.authorization_codes

    @pytest.mark.parametrize('parameters', [
        {'identity': TEST_USER_ID},  # missing 'nonce'
        {'nonce': 'nonce'},  # missing 'identity'
    ])
    def test_vetting_endpoint_with_missing_data(self, parameters):
        resp = self.app.test_client().post('/vetting-result', data=parameters)
        assert resp.status_code == 400

    def test_unexpected_nonce(self):
        resp = self.app.test_client().post('/vetting-result', data={'nonce': 'unexpected',
                                                                    'identity': TEST_USER_ID})
        assert resp.status_code == 400
