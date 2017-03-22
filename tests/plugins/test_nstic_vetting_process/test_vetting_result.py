
import pytest
import responses
import datetime
import json
import pkg_resources
from os import path
from tempfile import NamedTemporaryFile
from unittest import mock
from urllib import parse
from rq import SimpleWorker

from se_leg_op.storage import OpStorageWrapper
from tests.conftest import inject_app as main_inject_app

TEST_CLIENT_ID = 'client2'
TEST_CLIENT_SECRET = 'secret'
TEST_REDIRECT_URI = 'https://client2.example.com/redirect_uri'

TEST_USER_ID = 'user2'

VETTING_RESULT_ENDPOINT = '/yubico/vetting-result'
VETTING_DATA = {
    "mibi": {
        "MibiVersion": "1.5",
        "Autocapture": "1",
        "Device": "angler",
        "Document":
            "DRIVER_LICENSE",
        "Torch": "OFF",
        "ImageWidth": "1920",
        "ImageHeight": "1080",
        "1080p": "true",
        "720p": "true",
        "AutoFocus": "true",
        "ContVideoFocus": "true",
        "ContPictureFocus": "true",
        "Manufacturer": "Huawei",
        "MiSnapVersion": "3.1",
        "SDKVersion": "MiSnap3.1",
        "Model": "Nexus 6P",
        "Orientation": "PORTRAIT_UPSIDE_DOWN",
        "OS": "6.0",
        "Platform": "Android",
        "MiSnapResultCode": "SuccessVideo",
        "UXP": [
            {"RL": [2423]},
            {"FO": [2447]},
            {"SA": [2766]},
            {"FF": [2840]},
            {"MC": [2965, 0]},
            {"IB": [2966]},
            {"NF": [2966, 0]},
            {"MC": [3105, 0]},
            {"NF": [3105, 0]},
            {"MC": [3305, 93]},
            {"RR": [3428]},
            {"MC": [3478, 99]},
            {"CF": [3482, 555]},
            {"MC": [3639, 99]},
            {"CF": [3639, 578]},
            {"MC": [3791, 99]},
            {"CF": [3791, 560]},
            {"MC": [3923, 100]},
            {"CF": [3924, 546]},
            {"MC": [4041, 0]},
            {"MC": [4158, 99]},
            {"MC": [4243, 0]},
            {"MC": [4326, 0]},
            {"NF": [4327, 0]},
            {"MC": [4392, 0]},
            {"NF": [4393, 0]},
            {"MC": [4529, 100]},
            {"MC": [4719, 100]},
            {"CF": [4722, 558]},
            {"MC": [4931, 100]},
            {"CF": [4931, 559]},
            {"MC": [5183, 100]},
            {"CF": [5183, 577]},
            {"MC": [5409, 100]},
            {"CF": [5409, 584]},
            {"MC": [5657, 100]},
            {"MV": [5658]},
            {"MT": [5660]},
            {"MA": [5660, 3]},
            {"MB": [5660, 521]},
            {"MS": [5660, 530]},
            {"MW": [5660, 603]},
            {"MT": [5660]},
            {"DR": [5661]}
        ],
        "Parameters": {
            "MiSnapDocumentType": "DRIVER_LICENSE",
            "MiSnapCaptureMode": "2"
        },
        "Changed Parameters": {}
    },
    "encodedData": "ZnJvbnRfaW1hZ2U=",
    "barcode": "YmFyY29kZQ== ZGF0YQ=="
}
SUCCESSFUL_SOAP_RESPONSE = {
    'header': {
        'Metadata': {
            'SessionReferenceId': 'SessionReferenceId',
            'TransactionReferenceId': 123456789,
            'XIPVersion': '2.4'
        }
    },
    'body': {
        'Response': {
            'Errors': None,
            'Images': None,
            'Status': 'Successful',
            'MoreData': {},
            'ExtractedData': {
                'Address': {
                    'Address1': 'ADDRESS',
                    'AddressLine2': None,
                    'AptNumber': None,
                    'City': 'CITY',
                    'POBox': None,
                    'StateAbbr': 'ST',
                    'StreetName': 'STREET NAME',
                    'StreetNumber': '123',
                    'Zip': '12345-1234'
                },
                'Class': 'R',
                'Dob': datetime.datetime(1989, 3, 16, 0, 0),
                'ExpirationDate': datetime.datetime(2016, 3, 16, 0, 0),
                'Id': '123123123',
                'IssueDate': datetime.datetime(2009, 2, 7, 0, 0),
                'Name': {
                    'FirstName': 'JANE',
                    'LastName': 'MOON',
                    'MiddleName': 'SHERRY',
                    'Suffix': None
                },
                'Sex': 'F',
                'State': {
                    'Abbreviation': 'ST',
                    'Name': 'State'
                }
            },
            'ComparisonResult': {
                'MoreData': {},
                'DataMatchScore': 1000
            }
        }
    }
}

SUCCESSFUL_VETTING_RESULT = {
    'extracted_data': {
        'Sex': 'F',
        'ExpirationDate': datetime.datetime(2016, 3, 16, 0, 0),
        'Id': '123123123', 'Dob': datetime.datetime(1989, 3, 16, 0, 0),
        'Class': 'R',
        'Name': {
            'FirstName': 'JANE',
            'Suffix': None,
            'MiddleName': 'SHERRY',
            'LastName': 'MOON'
        },
        'State': {
            'Name': 'State',
            'Abbreviation': 'ST'
        },
        'IssueDate': datetime.datetime(2009, 2, 7, 0, 0),
        'Address': {
            'POBox': None,
            'AptNumber': None,
            'City': 'CITY',
            'StateAbbr': 'ST',
            'AddressLine2': None,
            'StreetNumber': '123',
            'Zip': '12345-1234',
            'StreetName': 'STREET NAME',
            'Address1': 'ADDRESS'
        }
    },
    'status': 'Successful',
    'data_match_score': 1000
}


@pytest.yield_fixture
def config_envvar(mongodb_instance, redis_instance):
    config_values = {
        'basepath': path.dirname(pkg_resources.resource_filename(__name__, '../../service/app_config.py')),
        'db_uri': mongodb_instance.get_uri(),
        'redis_uri': redis_instance.get_uri()
    }
    config_content = """
import os

TESTING = True
SERVER_NAME = "localhost:5000"

basepath = '{basepath}'

PROVIDER_SIGNING_KEY = {{
    'PATH': os.path.join(basepath, 'private.pem'),
    'KID': 'test_kid'
}}

PROVIDER_SUBJECT_IDENTIFIER_HASH_SALT = 'test_salt'

PACKAGES = ['se_leg_op.plugins.nstic_vetting_process']
EXTENSIONS = ['se_leg_op.plugins.nstic_vetting_process.license_service']

MOBILE_VERIFY_WSDL = 'https://localhost/wsdl'
MOBILE_VERIFY_USERNAME = 'soap_user'
MOBILE_VERIFY_PASSWORD = 'secret'
MOBILE_VERIFY_TENANT_REF = 'tenant_ref'

NSTIC_VETTING_PROCESS_AUDIT_LOG_FILE = '/dev/null'

DB_URI = '{db_uri}'
REDIS_URI = '{redis_uri}'
PREFERRED_URL_SCHEME = 'https'
    """.format(**config_values)
    config_file = NamedTemporaryFile()
    config_file.write(bytes(config_content, 'utf-8'))
    config_file.flush()
    yield config_file.name


@pytest.fixture
def inject_app(request, tmpdir, mongodb_instance, redis_instance, config_envvar):
    main_inject_app(request, tmpdir, mongodb_instance, redis_instance, config_envvar)
    request.instance.app.mobile_verify_service_queue.empty()


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


@pytest.fixture
def vetting_data():
    return parse.quote(json.dumps(VETTING_DATA))


@pytest.yield_fixture
def mock_soap_client():
    patcher = mock.patch('se_leg_op.plugins.nstic_vetting_process.license_service.MitekMobileVerifyService',
                         new=mock.Mock)
    soap_client = patcher.start()
    soap_client.verify = mock.Mock(return_value=SUCCESSFUL_SOAP_RESPONSE)
    yield soap_client
    patcher.stop()


@pytest.mark.usefixtures('mock_soap_client', 'config_envvar', 'inject_app', 'create_client_in_db')
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

    def force_send_all_queued_messages(self):
        worker = SimpleWorker([self.app.mobile_verify_service_queue],
                              connection=self.app.mobile_verify_service_queue.connection)
        worker.work(burst=True)

    @responses.activate
    def test_vetting_endpoint(self, authn_request_args, vetting_data):
        responses.add(responses.GET, TEST_REDIRECT_URI, status=200)
        nonce = authn_request_args['nonce']
        self.app.authn_requests[nonce] = authn_request_args
        state = self.app.authn_requests[nonce]['state']
        self.app.users[TEST_USER_ID] = {}

        token = 'token'
        qrdata = '1' + json.dumps({'nonce': nonce, 'token': token})
        resp = self.app.test_client().post(VETTING_RESULT_ENDPOINT, data={'qrcode': qrdata, 'data': vetting_data})

        assert resp.status_code == 200
        # verify the original authentication request is removed
        assert nonce not in self.app.authn_requests
        # check yubico state
        assert state in self.app.yubico_states
        # Force processing if message queue
        self.force_send_all_queued_messages()
        # verify the posted data ends up in the userinfo document
        # Just check keys as the datetimes are different due to mongodb
        assert self.app.users[TEST_USER_ID]['vetting_result']['data'].keys() == SUCCESSFUL_VETTING_RESULT.keys()

    # XXX: Remove after development
    @responses.activate
    def test_vetting_endpoint_development_nonce(self, vetting_data):
        self.app.config['TEST_NONCE'] = 'test'
        responses.add(responses.GET, TEST_REDIRECT_URI, status=200)

        token = 'token'
        qrdata = '1' + json.dumps({'nonce': 'test', 'token': token})
        resp = self.app.test_client().post(VETTING_RESULT_ENDPOINT, data={'qrcode': qrdata, 'data': vetting_data})

        assert resp.status_code == 200
    # XXX: End remove after development

    @pytest.mark.parametrize('malformed_vetting_data', [
        '',  # no data
        '{"test": "{"malformed": "data"}"',  # invalid json
        '{"encodedData":"", "barcode":""}',  # missing 'mibi'
        '{"mibi": "", "barcode":""}',  # missing 'encodedData'
        '{"mibi": "", "encodedData":""}',  # missing 'barcode'
    ])
    @responses.activate
    def test_vetting_endpoint_malformed_json(self, authn_request_args, malformed_vetting_data):
        nonce = authn_request_args['nonce']
        self.app.authn_requests[nonce] = authn_request_args
        responses.add(responses.GET, TEST_REDIRECT_URI, status=200)

        token = 'token'
        qrdata = '1' + json.dumps({'nonce': 'test', 'token': token})
        resp = self.app.test_client().post(VETTING_RESULT_ENDPOINT, data={'qrcode': qrdata,
                                                                          'data': malformed_vetting_data})

        assert resp.status_code == 400

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
    def test_vetting_endpoint_with_invalid_qr_data(self, qrdata, vetting_data):
        resp = self.app.test_client().post(VETTING_RESULT_ENDPOINT, data={'qrcode': qrdata, 'data': vetting_data})
        assert resp.status_code == 400

    def test_unexpected_nonce(self):
        resp = self.app.test_client().post(VETTING_RESULT_ENDPOINT, data={'qrcode': 'unexpected token',
                                                                          'data': vetting_data})
        assert resp.status_code == 400
