import os

TESTING = True
SERVER_NAME = "localhost:5000"

basepath = os.path.dirname(os.path.realpath(__file__))

PROVIDER_SIGNING_KEY = {
    'PATH': os.path.join(basepath, 'private.pem'),
    'KID': 'test_kid'
}

PROVIDER_SUBJECT_IDENTIFIER_HASH_SALT = 'test_salt'

# The original vetting process needs to be loaded to test the full flow of the app
PACKAGES = ['se_leg_op.plugins.se_leg_vetting_process']

# This is the certificate used in the demo environment.
# For production this will of course need to be replaced with another cert.
FREJA_CALLBACK_X5T_CERT = \
"-----BEGIN CERTIFICATE-----\n"\
"MIIEETCCAvmgAwIBAgIUTeCJ0hz3mbtyONBEiap7su74LZwwDQYJKoZIhvcNAQEL"\
"BQAwgYMxCzAJBgNVBAYTAlNFMRIwEAYDVQQHEwlTdG9ja2hvbG0xFDASBgNVBGET"\
"CzU1OTExMC00ODA2MR0wGwYDVQQKExRWZXJpc2VjIEZyZWphIGVJRCBBQjENMAsG"\
"A1UECxMEVGVzdDEcMBoGA1UEAxMTUlNBIFRFU1QgSXNzdWluZyBDQTAeFw0xNzA3"\
"MTIxNTIwMTNaFw0yMDA3MTIxNTIwMTNaMIGKMQswCQYDVQQGEwJTRTESMBAGA1UE"\
"BxMJU3RvY2tob2xtMRQwEgYDVQRhEws1NTkxMTAtNDgwNjEdMBsGA1UEChMUVmVy"\
"aXNlYyBGcmVqYSBlSUQgQUIxDTALBgNVBAsTBFRlc3QxIzAhBgNVBAMTGkZyZWph"\
"IGVJRCBURVNUIE9yZyBTaWduaW5nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB"\
"CgKCAQEAgMINs87TiouDPSSmpn05kZv9TN8XdopcHnElp6ElJLpQh3oYGIL4B71o"\
"IgF3r8zRWq8kQoJlYMugmhsld0r0EsUJbsrcjBJ5CJ1WYZg1Vu8FpYLKoaFRI/qx"\
"T6xCMvd238Q99Sdl6G6O9sQQoFq10EaYBa970Tl3nDziQQ6bbSNkZoOYIZoicx4+"\
"1XFsrGiru8o8QIyc3g0eSgrd3esbUkuk0eH65SeaaOCrsaCOpJUqEziD+el4R6d4"\
"0dTz/uxWmNpGKF4BmsNWeQi9b4gDYuFqNYhs7bnahvkK6LvtDThV79395px/oUz5"\
"BEDdVwjxPJzgaAuUHE+6A1dMapkjsQIDAQABo3QwcjAOBgNVHQ8BAf8EBAMCBsAw"\
"DAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBRqfIoPnXAOHNpfLaA8Jl+I6BW/nDAS"\
"BgNVHSAECzAJMAcGBSoDBAUKMB0GA1UdDgQWBBT7j90x8xG2Sg2p7dCiEpsq3mo5"\
"PTANBgkqhkiG9w0BAQsFAAOCAQEAaKEIpRJvhXcN3MvP7MIMzzuKh2O8kRVRQAoK"\
"Cj0K0R9tTUFS5Ang1fEGMxIfLBohOlRhXgKtqJuB33IKzjyA/1IBuRUg2bEyecBf"\
"45IohG+vn4fAHWTJcwVChHWcOUH+Uv1g7NX593nugv0fFdPqt0JCnsFx2c/r9oym"\
"+VPP7p04BbXzYUk+17qmFBP/yNlltjzfeVnIOk4HauR9i94FrfynuZLuItB6ySCV"\
"mOlfA0r1pHv5sofBEirhwceIw1EtFqEDstI+7XZMXgDwSRYFc1pTjrWMaua2Uktm"\
"JyWZPfIY69pi/z4u+uAnlPuQZnksaGdZiIcAyrt5IXpNCU5wyg==\n"\
"-----END CERTIFICATE-----"

FREJA_TEST_NONCE = ''
