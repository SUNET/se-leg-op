import uuid
import json
from unittest.mock import Mock, patch
from urllib.parse import parse_qsl, urlparse

import pytest
import responses
from rq.worker import SimpleWorker

from se_leg_op.storage import OpStorageWrapper

TEST_CLIENT_ID = 'client1'
TEST_CLIENT_SECRET = 'secret'
TEST_REDIRECT_URI = 'https://client.example.com/redirect_uri'

TEST_USER_SSN = '190101016426'
TEST_USER_ID = '3cffd22a-b695-4ce7-96ef-bf86545279fd'

VETTING_RESULT_ENDPOINT = '/verisec/vetting-result'

EXTRA_CONFIG = {
    'PACKAGES': ['se_leg_op.plugins.verisec_vetting_process']
}

DEMO_RESPONSE_DATA_X5T = \
'eyJ4NXQiOiJId01IS19nYjNfaXVORjFhZHZNdGxHMC1mVXMiLCJhbGciOiJSUzI1N\
iJ9.eyJyZWYiOiJKbk9EeFowd2EzZGdLTHFHOWxLZ0pUd0p0d3FyOVlYeGtrSURDW\
Dh6Y2NhNU93b0xSYzRZRkFSakpsM0drQ3pCIiwib3BhcXVlIjoiMXtcIm5vbmNlXC\
I6IFwiY2FiYWM1N2ItZTYyYy00OWRiLWIxMDItNDVkYjI1Mzg0YjY5XCIsIFwidG9\
rZW5cIjogXCJkNDgzNDU4NC04YTQ3LTRlNGYtYTAzNi01MDJjYWI1MmYzZTBcIn0i\
LCJjb3VudHJ5IjoiU0UiLCJzc24iOiIxOTAxMDEwMTY0MjYifQ.Pdx29MuHxLLHH7\
SvBSgIDAQ9r7HHseCu7kDjtTQTAUMypcLwn63wolzn0KMoPQaE1Dv2hGPfNZ7oUyt\
Ky-MQruHKY6UPQLiNUdPK0XKkM5lME1dwPBahCjAzL-ICxrAv6cBUn3EoAKtvXuXR\
jAzEzsHTmQniHTxnux_wzLiY82cFmsf4z-iAR959MGcYkYwqt0FRcmDws1fWFOJPN\
Pu2DPlp_DqzPV2vQycBiI56GB2UTTmM-G5AVQBGCb_P9YLGRMyblgGGe-eUpnOymI\
duZ7ya2FjVEt2Ys6wNZXkNUHI11IVmBtGbXpJYW1Vn9gfHwQFvtIxvOQw5AzixBZu\
C4A'

EXAMPLE_RESPONSE_DATA = \
'eyJhbGciOiJSUzI1NiIsIng1YyI6WyJNSUlEa3pDQ0FudWdBd0lCQWdJRVBhVXFle\
kFOQmdrcWhraUc5dzBCQVFzRkFEQjZNUXN3Q1FZRFZRUUdFd0pUUlRFU01CQUdBMV\
VFQ0JNSlUzUnZZMnRvYjJ4dE1SSXdFQVlEVlFRSEV3bFRkRzlqYTJodmJHMHhFakF\
RQmdOVkJBb1RDVVp5WldwaElHVkpSREVOTUFzR0ExVUVDeE1FVkdWemRERWdNQjRH\
QTFVRUF4TVhSbkpsYW1FZ1pVbEVJRVJ2WTNWdFpXNTBZWFJwYjI0d0hoY05NVGN3T\
kRFek1UUTBOVFEyV2hjTk1UY3dOekV5TVRRME5UUTJXakI2TVFzd0NRWURWUVFHRX\
dKVFJURVNNQkFHQTFVRUNCTUpVM1J2WTJ0b2IyeHRNUkl3RUFZRFZRUUhFd2xUZEc\
5amEyaHZiRzB4RWpBUUJnTlZCQW9UQ1VaeVpXcGhJR1ZKUkRFTk1Bc0dBMVVFQ3hN\
RVZHVnpkREVnTUI0R0ExVUVBeE1YUm5KbGFtRWdaVWxFSUVSdlkzVnRaVzUwWVhSc\
GIyNHdnZ0VpTUEwR0NTcUdTSWIzRFFFQkFRVUFBNElCRHdBd2dnRUtBb0lCQVFDUy\
tBUnRjSTByZEhGVWtHMFRNcVpxSzByajVmQ3QyeldxWWtJYVdOb2ptZHZxa3ZsbTF\
jbm9idWlNOGY2endhbW5rMjNaOHA1OUQ1MzE0dVBrb1NWb2RoMEtHZGJzb2J1YVlk\
aXJ1Tkp4RUplRjkwcHJcL3Axa0VEQVFMRnA5UHFFV2N0OG5telg5YktKQzhvUm53N\
ExsVW9pYUhMMzRtdlJnSFZ3em42MXVNc2w0bzc4T0R6VEhGb3daZ3FURjRyM0VaZn\
lKQXZBT2dlYjhtYmJnaGtMR3ZpYXkyUlwvMDRlK3dwd0RpVTVhTkpMeW84UGdkTTJ\
VelwvQVRxTEQyVm9Vc1dpRW85Q3YzTVZVYWJ2eko3RHVmNFZDZmx2c0ZYRW03OEc4\
VzNwdmFVbDFIQ3FTM0kwRHBoR0dMdW9ydmN0VVY0ZFRZQ2g2QTZcL0tUUjBpSUNpZ\
EFcL0FnTUJBQUdqSVRBZk1CMEdBMVVkRGdRV0JCUVwvZ1JJa3puajZKejJDb1R0Sm\
pBNDdJQ1NFUWpBTkJna3Foa2lHOXcwQkFRc0ZBQU9DQVFFQUJcLzk3Q1lDQTROVW5\
2Y2RrbVVqc1wvNEgzY0F1d2xDQitZclBmeWMwVVNiTE4xV1pqSjM1ZFhaVmpzeG9h\
NlhQSnB6a1dLbENWek1hbTF0UGo3WnpcL0N0N3UrdmloaXdKMVVXRUVKZXpNa0YwT\
Th6d09EVHpEQjJZNlF0bTloOEhDek5OWUtYSldVTkFienNMcW5WMnMzTm4ySU1LOT\
VVRFdMUXBQbVJaS3lNTStjekVlckVBTithMTRRMDJLYTF1VEhkQzVyQ2NkTmNiNFZ\
pOG54WHg4ZXdPYXEwdWNyS1NiSEx6ajZqRVRvRWhLRjJTV2w1THVYUG9MYmM5NjFM\
c1BsSk1xMUs4Q2tLQU5Sc3pkWVBraUlNS3hWU0puVjNXdGFKWDdha0NFQUw1MGFKa\
npjWlFJWWlaczhEUWJWd20rU1dqTzNXMlRQMnAzM0t2bXp1dmphQT09Il19.\
eyJyZWYiOiIxMjM0LjU2NzguOTAxMi4zNDU2Iiwib3BhcXVlIjoiQUJDREVGR0hJS\
ktMTU5PUFJTVFVWV1hZWjAxMjM0NTY3ODkwMTIzNCIsInNzbiI6IjE5OTAxMDEwMT\
AxMCIsImNvdW50cnkiOiJTRSJ9.\
Wp_DuQcyuocGN7r-_Uj1jaJlVtYRjQ1UtWZegnWqeMtw2VpE6tL3qBX6MEDI055iy\
3FMKtiQOXByfAvubbWKlMs7iTBtk-e8wnRPckH-pizfCyG-ieaaix-zZ2f5UGltNp\
UEE4-Hk_on5qxwPt7s5flOfKCwYN5CDmTgmIsRkFWR_gLfjk_ySlyywPh8knoy5vn\
D6hJpe6OZotkojEPzTfQ4TsysIsf2i-Dj_9fAyl--UgMPT4JuHk3ddVNhq9JnB_j2\
M9EkYjM6ad_xEKldraS5xEJCVaEYa6oyBDzj9zUU61a71vp3C5uEi_yBA49Z6rxWE\
LhJjjgvjogq4TEQEQ'

EXAMPLE_RESPONSE_DATA_INVALID_UTF8 = \
'eyJhbGciOiJSUzI1NiIsIng1YyI6WyJNSUlEa3pDQ0FudWdBd0lCQWdJRVBhVXFle\
kFOQmdrcWhraUc5dzBCQVFzRkFEQjZNUXN3Q1FZRFZRUUdFd0pUUlRFU01CQUdBMV\
VFQ0JNSlUzUnZZMnRvYjJ4dE1SSXdFQVlEVlFRSEV3bFRkRzlqYTJodmJHMHhFakF\
RQmdOVkJBb1RDVVp5WldwaElHVkpSREVOTUFzR0ExVUVDeE1FVkdWemRERWdNQjRH\
QTFVRUF4TVhSbkpsYW1FZ1pVbEVJRVJ2WTNWdFpXNTBZWFJwYjI0d0hoY05NVGN3T\
kRFek1UUTBOVFEyV2hjTk1UY3dOekV5TVRRME5UUTJXakI2TVFzd0NRWURWUVFHRX\
dKVFJURVNNQkFHQTFVRUNCTUpVM1J2WTJ0b2IyeHRNUkl3RUFZRFZRUUhFd2xUZEc\
5amEyaHZiRzB4RWpBUUJnTlZCQW9UQ1VaeVpXcGhJR1ZKUkRFTk1Bc0dBMVVFQ3hN\
RVZHVnpkREVnTUI0R0ExVUVBeE1YUm5KbGFtRWdaVWxFSUVSdlkzVnRaVzUwWVhSc\
GIyNHdnZ0VpTUEwR0NTcUdTSWIzRFFFQkFRVUFBNElCRHdBd2dnRUtBb0lCQVFDUy\
tBUnRjSTByZEhGVWtHMFRNcVpxSzByajVmQ3QyeldxWWtJYVdOb2ptZHZxa3ZsbTF\
jbm9idWlNOGY2endhbW5rMjNaOHA1OUQ1MzE0dVBrb1NWb2RoMEtHZGJzb2J1YVlk\
aXJ1Tkp4RUplRjkwcHJcL3Axa0VEQVFMRnA5UHFFV2N0OG5telg5YktKQzhvUm53N\
ExsVW9pYUhMMzRtdlJnSFZ3em42MXVNc2w0bzc4T0R6VEhGb3daZ3FURjRyM0VaZn\
lKQXZBT2dlYjhtYmJnaGtMR3ZpYXkyUlwvMDRlK3dwd0RpVTVhTkpMeW84UGdkTTJ\
VelwvQVRxTEQyVm9Vc1dpRW85Q3YzTVZVYWJ2eko3RHVmNFZDZmx2c0ZYRW03OEc4\
VzNwdmFVbDFIQ3FTM0kwRHBoR0dMdW9ydmN0VVY0ZFRZQ2g2QTZcL0tUUjBpSUNpZ\
EFcL0FnTUJBQUdqSVRBZk1CMEdBMVVkRGdRV0JCUVwvZ1JJa3puajZKejJDb1R0Sm\
pBNDdJQ1NFUWpBTkJna3Foa2lHOXcwQkFRc0ZBQU9DQVFFQUJcLzk3Q1lDQTROVW5\
2Y2RrbVVqc1wvNEgzY0F1d2xDQitZclBmeWMwVVNiTE4xV1pqSjM1ZFhaVmpzeG9h\
NlhQSnB6a1dLbENWek1hbTF0UGo3WnpcL0N0N3UrdmloaXdKMVVXRUVKZXpNa0YwT\
Th6d09EVHpEQjJZNlF0bTloOEhDek5OWUtYSldVTkFienNMcW5WMnMzTm4ySU1LOT\
VVRFdMUXBQbVJaS3lNTStjekVlckVBTithMTRRMDJLYTF1VEhkQzVyQ2NkTmNiNFZ\
pOG54WHg4ZXdPYXEwdWNyS1NiSEx6ajZqRVRvRWhLRjJTV2w1THVYUG9MYmM5NjFM\
c1BsSk1xMUs4Q2tLQU5Sc3pkWVBraUlNS3hWU0puVjNXdGFKWDdha0NFQUw1MGFKa\
npjWlFJWWlaczhEUWJWd20rU1dqTzNXMlRQMnAzM0t2bXp1dmphQT09Il19.\
eyJyZWYiOiIxMjM0LjU2NzguOTAxMi4zNDU2Iiwib3BhcXVlIjoiQUJDREVGR0hJS\
eyJyZWYiOiIxMjM0LjU2NzguOTAxMi4zNDU2Iiwib3BhcXVlIjoiQUJDREVGR0hJS\
AxMCIsImNvdW50cnkiOiJTRSJ9.\
Wp_DuQcyuocGN7r-_Uj1jaJlVtYRjQ1UtWZegnWqeMtw2VpE6tL3qBX6MEDI055iy\
3FMKtiQOXByfAvubbWKlMs7iTBtk-e8wnRPckH-pizfCyG-ieaaix-zZ2f5UGltNp\
UEE4-Hk_on5qxwPt7s5flOfKCwYN5CDmTgmIsRkFWR_gLfjk_ySlyywPh8knoy5vn\
D6hJpe6OZotkojEPzTfQ4TsysIsf2i-Dj_9fAyl--UgMPT4JuHk3ddVNhq9JnB_j2\
M9EkYjM6ad_xEKldraS5xEJCVaEYa6oyBDzj9zUU61a71vp3C5uEi_yBA49Z6rxWE\
LhJjjgvjogq4TEQEQ'

FREJA_CALLBACK_WRONG_X5T_CERT = \
"-----BEGIN CERTIFICATE-----\n"\
"MIIGODCCBCCgAwIBAgIUdxOCM0ShYGSRH6uHRMXj9bKkgV4wDQYJKoZIhvcNAQEL"\
"BQAwUTELMAkGA1UEBhMCU0UxEzARBgNVBAoTClZlcmlzZWMgQUIxEjAQBgNVBAsT"\
"CUZyZWphIGVJRDEZMBcGA1UEAxMQUlNBIFRlc3QgUm9vdCBDQTAeFw0xNzA1MTcx"\
"NDQyNTJaFw0yNzA1MTcxNDQyNTJaMIGDMQswCQYDVQQGEwJTRTESMBAGA1UEBxMJ"\
"U3RvY2tob2xtMRQwEgYDVQRhEws1NTkxMTAtNDgwNjEdMBsGA1UEChMUVmVyaXNl"\
"YyBGcmVqYSBlSUQgQUIxDTALBgNVBAsTBFRlc3QxHDAaBgNVBAMTE1JTQSBURVNU"\
"IElzc3VpbmcgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDSUhGD"\
"HHpqhp9OmA2f8HjKHd+JJDtexrVQetyZujZfig8UV6y85nEcAw7Fh1kEG9I3JHe/"\
"PNmBL/y9NaRbqywgR8evU0l5wSBlevGelz9H+neGVEFvKkHmFOvr7f7c5bVWa/UR"\
"zTmCfWAolKvY+AwKlIkdTE1eptn8M940YFvUULBhLaDSZXNhvv6EZT9w2xTT4ZyH"\
"wd8faLfEvtGs+13KrAhutaJJYY6Xq0Fn9Q71sX/x5T7dG5InSiEPYNggW9pRVkx6"\
"1mdbpiz6waGsNrMo0wOyX8/wfptgQ81B4BUnKT89F3NOh9M7ZJN9+sRtX0kWLLRZ"\
"SN+Rg1Yy73D68B0xAgMBAAGjggHTMIIBzzAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0T"\
"AQH/BAgwBgEB/wIBADBPBggrBgEFBQcBAQRDMEEwPwYIKwYBBQUHMAGGM2h0dHA6"\
"Ly9yb290Y2FsYWIzMS50ZXN0LmZyZWphZWlkLmNvbTo4Nzc3L2Fkc3Mvb2NzcDAf"\
"BgNVHSMEGDAWgBTKsOy5V8OcPa05ihP68DW67Ax3ijCBuAYDVR0gBIGwMIGtMIGq"\
"BgUqAwQFBjCBoDA4BggrBgEFBQcCARYsaHR0cHM6Ly9jcHMudGVzdC5mcmVqYWVp"\
"ZC5jb20vY3BzL2luZGV4Lmh0bWwwZAYIKwYBBQUHAgIwWAxWVGhpcyBjZXJ0aWZp"\
"Y2F0ZSBoYXMgYmVlbiBpc3N1ZWQgIGluIGFjY29yZGFuY2Ugd2l0aCB0aGUgRnJl"\
"amEgZUlEIFRFU1QgUG9saWN5IENvbnRyb2wwXQYDVR0fBFYwVDBSoFCgToZMaHR0"\
"cDovL3Jvb3RjYWxhYjMxLnRlc3QuZnJlamFlaWQuY29tOjg3NzcvYWRzcy9jcmxz"\
"L2ZyZWphZWlkX3JzYV9yb290X2NhLmNybDAdBgNVHQ4EFgQUanyKD51wDhzaXy2g"\
"PCZfiOgVv5wwDQYJKoZIhvcNAQELBQADggIBAGzHkEkVDMqcA+GRTAvW2OW1tDZo"\
"FljM+w1AuQz380kmMamAl4f+Imw3UsT3JhXPZaJNVofqPBO/FiooO9mPIf8jMxrx"\
"Lfm/p/2n9K49RYwgRNDwVyW59c1H0jvHePpfaRtPS2ov0eI+QSMvk14/phIv/bkN"\
"d+0OVp0qgTVTTwwAvUQJ2P9cDK3OIj7H0vJhhw7ux66gNMHf+InERrbu0Si5rQem"\
"SafaQTS6N0QNtJVAafRYDM/FTOdPulbxkbktybjMiDTuJ3MvhqKv5zCR8noYwEBP"\
"VrePAvg6bwb0K1aCAQm4IsWBCKF4t6sqjrvaq/3jUo+M65Tp0AKTKn4B8nmTvGv9"\
"lT4PgsCTwwXbIUcW5rfsmE9wVpRfieG7Gx62ydHPlIPkTChUzs/joju8sykVnssF"\
"1YDqQlgMa2Sp+kx5i7eijX1ejcJh+pmuQTQnXj6sDJry81OtqDO7D7DhaUHfGLil"\
"mXurAolujmll5MabdBEq3E4TTebvv6WSNpEYwQ1S+8eE+9slLnmhR2RSNpWGDQ/l"\
"WwFoAsTCjG+e9f57mGUlmSeU6zERIxieER7wMM7EaqWaYo6JbeOhusbdTU/LmsyA"\
"8fZYp+gn/FM8Wl8eh1qj/GIcAdDAIO3k8mqA98sWR7Mx5vgdRNcmpCtOQxxiijC7"\
"MRbYKeBk4HOtXw9e\n"\
"-----END CERTIFICATE-----"


@pytest.fixture
def authn_request_args():
    return {
        'client_id': TEST_CLIENT_ID,
        'redirect_uri': TEST_REDIRECT_URI,
        'user_id': TEST_USER_ID,
        'response_type': 'code',
        'scope': 'openid',
        'nonce': 'cabac57b-e62c-49db-b102-45db25384b69',
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

@pytest.mark.usefixtures('inject_app')
class TestVettingResultEndpoint(object):
    MOCK_UUID = Mock(return_value=uuid.UUID('3cffd22a-b695-4ce7-96ef-bf86545279fd'))

    def test_vetting_endpoint_with_missing_data(self):
        resp = self.app.test_client().post(VETTING_RESULT_ENDPOINT,
                                           content_type='application/jose')

        assert resp.data == b'missing or invalid JSON'
        assert resp.status_code == 400

    @pytest.mark.parametrize('parameters', [
        {'iaResponseData': 'not a valid JWS'},
    ])
    def test_vetting_endpoint_with_invalid_jws(self, parameters):
        resp = self.app.test_client().post(VETTING_RESULT_ENDPOINT, data=json.dumps(parameters),
                                           content_type='application/jose')

        assert resp.data == b'iaResponseData is not a JWS'
        assert resp.status_code == 400

    @pytest.mark.parametrize('parameters', [
        {'iaResponseData': EXAMPLE_RESPONSE_DATA},
    ])
    def test_vetting_endpoint_with_doc_example_jws_invalid_mime(self, parameters):
        resp = self.app.test_client().post(VETTING_RESULT_ENDPOINT, data=json.dumps(parameters),
                                           content_type='application/x-www-form-urlencoded')

        assert resp.data == b'Invalid MIME'
        assert resp.status_code == 400

    @pytest.mark.parametrize('parameters', [
        {'iaResponseData': EXAMPLE_RESPONSE_DATA_INVALID_UTF8},
    ])
    def test_vetting_endpoint_with_doc_example_jws_invalid_utf8(self, parameters):
        resp = self.app.test_client().post(VETTING_RESULT_ENDPOINT, data=json.dumps(parameters),
                                           content_type='application/jose')

        assert resp.data == b'Incorrect UTF-8 in iaResponseData'
        assert resp.status_code == 400


    @pytest.mark.parametrize('parameters', [
        {'iaResponseData': EXAMPLE_RESPONSE_DATA},
    ])
    def test_vetting_endpoint_with_doc_example_jws_invalid_signature(self, parameters):
        resp = self.app.test_client().post(VETTING_RESULT_ENDPOINT, data=json.dumps(parameters),
                                           content_type='application/jose')

        assert resp.data == b'Invalid signature'
        assert resp.status_code == 400

    @pytest.mark.parametrize('parameters', [
        {'iaResponseData': DEMO_RESPONSE_DATA_X5T},
    ])
    def test_vetting_endpoint_with_demo_jws_wrong_key(self, parameters):
        self.app.config['FREJA_CALLBACK_X5T_CERT'] = FREJA_CALLBACK_WRONG_X5T_CERT
        resp = self.app.test_client().post(VETTING_RESULT_ENDPOINT, data=json.dumps(parameters),
                                           content_type='application/jose')

        assert resp.data == b'Invalid signature'
        assert resp.status_code == 400

    @pytest.mark.parametrize('parameters', [
        {'iaResponseData': DEMO_RESPONSE_DATA_X5T},
    ])
    def test_vetting_endpoint_with_demo_jws_unknown_nonce(self, parameters):
        resp = self.app.test_client().post(VETTING_RESULT_ENDPOINT, data=json.dumps(parameters),
                                           content_type='application/jose')
        assert resp.data == b'Unknown nonce in verified JWS payload'
        assert resp.status_code == 400

    @patch('uuid.uuid4', MOCK_UUID)
    @responses.activate
    @pytest.mark.parametrize('parameters', [
        {'iaResponseData': DEMO_RESPONSE_DATA_X5T},
    ])
    def test_vetting_endpoint_with_demo_jws(self, authn_request_args, parameters):
        # This is more or less a copy of test_vetting_endpoint() in test_se_leg_vetting_process.py
        responses.add(responses.GET, TEST_REDIRECT_URI, status=200)
        nonce = authn_request_args['nonce']
        self.app.authn_requests[nonce] = authn_request_args

        token = 'd4834584-8a47-4e4f-a036-502cab52f3e0'

        resp = self.app.test_client().post(VETTING_RESULT_ENDPOINT, data=json.dumps(parameters),
                                           content_type='application/jose')
        assert resp.data == b'OK'
        assert resp.status_code == 200

        assert nonce not in self.app.authn_requests

        assert self.app.users[TEST_USER_ID]['results']['freja_eid']['ssn'] == TEST_USER_SSN

        # force sending response from message queue from http://python-rq.org/docs/testing/
        worker = SimpleWorker([self.app.authn_response_queue], connection=self.app.authn_response_queue.connection)
        worker.work(burst=True)

        # verify the authentication response has been sent to the client
        parsed_response = dict(parse_qsl(urlparse(responses.calls[0].request.url).query))
        assert 'code' in parsed_response
        assert parsed_response['state'] == authn_request_args['state']
        assert parsed_response['code'] in self.app.provider.authz_state.authorization_codes
        assert responses.calls[0].request.headers['Authorization'] == 'Bearer ' + token
