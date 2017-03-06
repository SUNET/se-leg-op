# -*- coding: utf-8 -*-

import logging
import time
from flask.config import Config

from ...service.app import SE_LEG_PROVIDER_SETTINGS_ENVVAR
from ...storage import OpStorageWrapper
from .license_service import LicenseService

__author__ = 'lundberg'

logger = logging.getLogger(__name__)

# Read conf
config = Config('')
config.from_envvar(SE_LEG_PROVIDER_SETTINGS_ENVVAR)
wsdl = config['MOBILE_VERIFY_WSDL']
username = config['MOBILE_VERIFY_USERNAME']
password = config['MOBILE_VERIFY_PASSWORD']
tenant_reference_number = config['MOBILE_VERIFY_TENANT_REF']

# Init service and db
license_service = LicenseService(wsdl, username, password, tenant_reference_number)
users = OpStorageWrapper(config['DB_URI'], 'userinfo')


def verify_license(user_id, front_image_data, barcode, mibi_data):

    response = license_service.verify(front_image_data, barcode, mibi_data)

    logger.debug('Parsed response:')
    logger.debug(response)

    # TODO: Log verification attempt
    # TODO: Use response['header']['Metadata']['TransactionReferenceId'],
    # TODO: response['header']['Metadata']['SessionReferenceId'] and auth_req

    if not response['body']['Response']['Errors'] is None:
        logger.error('Verify license failed:')
        logger.error(response['body']['Response']['Errors'])
        # TODO: Do we want to add this to userinfo?
        return

    # Successful response received, save the verification response
    userinfo = users[user_id]
    if 'vetting_results' not in userinfo:
        userinfo = {'vetting_results': []}

    data = {
        'extracted_data': response['body']['Response']['ExtractedData'],
        'data_match_score': response['body']['Response']['ComparisonResult']['DataMatchScore']
    }
    userinfo['vetting_results'].append({'vetting_time': time.time(), 'data': data})
    users[user_id] = userinfo
