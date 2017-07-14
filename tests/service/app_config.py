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

# This is the first certificate in the chain used in the demo environment.
# For production this will of course need to be replaced with another cert.
FREJA_CALLBACK_X5C_CERT = "-----BEGIN CERTIFICATE-----\n"\
"MIID8TCCAtmgAwIBAgIUALt51skmJ6GUf2ZkkSvjGUY1dxYwDQYJKoZIhvcNAQELBQAwgYMxCzAJ"\
"BgNVBAYTAlNFMRIwEAYDVQQHEwlTdG9ja2hvbG0xFDASBgNVBGETCzU1OTExMC00ODA2MR0wGwYD"\
"VQQKExRWZXJpc2VjIEZyZWphIGVJRCBBQjENMAsGA1UECxMEVGVzdDEcMBoGA1UEAxMTUlNBIFRF"\
"U1QgSXNzdWluZyBDQTAeFw0xNzA2MjAwODAyNTBaFw0yMDA2MjAwODAyNTBaMGsxCzAJBgNVBAYT"\
"AlNFMRIwEAYDVQQHEwlTdG9ja2hvbG0xHTAbBgNVBAoTFFZlcmlzZWMgRnJlamEgZUlEIEFCMQ0w"\
"CwYDVQQLEwRUZXN0MRowGAYDVQQDExFGcmVqYSBlSUQgc2lnbmluZzCCASIwDQYJKoZIhvcNAQEB"\
"BQADggEPADCCAQoCggEBAJ1MM/iW5BX8Lflja1dxN4kncPH3V38kLtZey+1zm/yrXTa5pN1esnl1"\
"aGyM/M+z9VGFtG3SzYnQrL9qX1sB6yU4SYB4J7l9SURck6aP+JxQwHsjNToDHxMtNZXXNWOPlMUu"\
"zpPVcrJbs7g91y6RmPVW8FD2NomXdsVVCbD7xM37nNo5Hkqx6fBE1FudO6HyqQ0jmS+Nc7uZ45nd"\
"4n8No0Gm4sXWYpZrBcFFBisYFET5g3oI+WEkwNorJC+LHw/mh8eIGzW64xXRAQ3y88dtNnoKCbUM"\
"969vb75MVHm8/cYtsAT/XBYsgqiddv2CIU6IjH15ZdYqO+D1MsDeYc9AOtcCAwEAAaN0MHIwDgYD"\
"VR0PAQH/BAQDAgbAMAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAUanyKD51wDhzaXy2gPCZfiOgV"\
"v5wwEgYDVR0gBAswCTAHBgUqAwQFCjAdBgNVHQ4EFgQUaP4VKbJQaWf8zunbM28p/4getuswDQYJ"\
"KoZIhvcNAQELBQADggEBAKnhyzgtkW6ssCYA4UgnnN5tQeXDROxnTQ40TDQYoFfUDMF9s5EH7dwd"\
"7KuUs6FyJHI5rQ0uXesJJS4tGvWQThKdbxJohhnetZ6IRdlSpSWqkDa+Q7KX0m+0LTqnT1tuCMIi"\
"q+vclrSzThqJCjv8bM1W6FskrG95u6zu3Jj1E37UqcApl1zqr43RAeYel6S4q2gs2FDcBibGIJoN"\
"InkMPCQZB/SK+PGjcAYhL6yB0NbC+o6LU5VfxZ374+KqDbid/5I3VDWPX2k75/BRF1KlLRU8GqcJ"\
"W2JguU/TlJTAtYjJ7tu4iZmfkHVY08efiizPBGHvwU84pDAYUaf3XWbxJ98=\n"\
"-----END CERTIFICATE-----"