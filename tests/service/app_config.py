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
