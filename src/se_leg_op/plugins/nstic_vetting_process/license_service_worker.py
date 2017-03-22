# -*- coding: utf-8 -*-

import logging
import time
from flask.config import Config

from ...service.app import SE_LEG_PROVIDER_SETTINGS_ENVVAR
from ...storage import OpStorageWrapper
from .license_service import LicenseService
from .config import NSTIC_VETTING_PROCESS_AUDIT_LOG_FILE, NSTIC_VETTING_PROCESS_AUDIT_LOGGING

__author__ = 'lundberg'

logger = logging.getLogger(__name__)

# Read conf
config = Config('')
config.from_envvar(SE_LEG_PROVIDER_SETTINGS_ENVVAR)
wsdl = config['MOBILE_VERIFY_WSDL']
username = config['MOBILE_VERIFY_USERNAME']
password = config['MOBILE_VERIFY_PASSWORD']
tenant_reference_number = config['MOBILE_VERIFY_TENANT_REF']

# Set up audit logging
audit_log_file = config.get('NSTIC_VETTING_PROCESS_AUDIT_LOG_FILE', NSTIC_VETTING_PROCESS_AUDIT_LOG_FILE)
audit_log_config = config.get('NSTIC_VETTING_PROCESS_AUDIT_LOGGING', NSTIC_VETTING_PROCESS_AUDIT_LOGGING)
try:
    audit_log_config['handlers']['nstic_vetting_process_audit']['filename'] = audit_log_file
except KeyError:
    # The supplied logging config does not use a log file
    pass
logging.config.dictConfig(audit_log_config)
audit_logger = logging.getLogger('nstic_vetting_process_audit')

# Init service and db
license_service = LicenseService(wsdl, username, password, tenant_reference_number)
users = OpStorageWrapper(config['DB_URI'], 'userinfo')


def verify_license(auth_req, front_image_data, barcode, mibi_data):

    response = license_service.verify(front_image_data, barcode, mibi_data)

    logger.debug('Parsed response:')
    logger.debug(response)

    audit_log_msg = 'License verification of state {} returned with status {} and a confidence score of {}. Transaction reference id: {}.'.format(
        auth_req['state'], response['body']['Response']['Status'],
        response['body']['Response']['ComparisonResult']['DataMatchScore'],
        response['header']['Metadata']['TransactionReferenceId'],
    )
    audit_logger.info(audit_log_msg)

    if not response['body']['Response']['Errors'] is None:
        logger.error('Verify license failed:')
        logger.error(response['body']['Response']['Errors'])

    # Successful response received, save the verification response
    user_id = auth_req['user_id']
    userinfo = users[user_id]
    data = {
        'status': response['body']['Response']['Status'],
        'extracted_data': response['body']['Response']['ExtractedData'],
        'data_match_score': response['body']['Response']['ComparisonResult']['DataMatchScore']
    }
    userinfo['vetting_result'] = {'vetting_time': time.time(), 'data': data}
    users[user_id] = userinfo
