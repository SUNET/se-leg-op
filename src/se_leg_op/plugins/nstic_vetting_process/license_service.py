# -*- coding: utf-8 -*-

from flask import current_app
import time
import logging

from mitek_mobile_verify.services import MitekMobileVerifyService
from mitek_mobile_verify.plugins import DoctorPlugin
from mitek_mobile_verify.models.requests import PhotoVerifyRequest
from mitek_mobile_verify.models.headers import DeviceMetaData, WebRequestMetadataHeader, MibiDataHeader

__author__ = 'lundberg'

logger = logging.getLogger(__name__)


class LicenseService(object):

    def __init__(self, wsdl, username, password, tenant_reference_number):
        # DoctorPlugin is needed to deserialize the response correctly
        self.soap_service = MitekMobileVerifyService(wsdl, username, password, plugins=[DoctorPlugin()])
        self.tenant_reference_number = tenant_reference_number
        logger.info('Loaded LicenseService')

    def create_headers(self, mibi_data=None):
        web_req_metadata = WebRequestMetadataHeader(tenant_reference=self.tenant_reference_number)
        device_metadata = DeviceMetaData()
        mibi_data = MibiDataHeader(mibi_data=mibi_data)
        return device_metadata, web_req_metadata, mibi_data

    @staticmethod
    def create_request(front_image_data, barcode_data):
        req = PhotoVerifyRequest()
        req.back_image = req.create_image(hints=[{'PDF417': barcode_data}])
        req.front_image = req.create_image(image_data=front_image_data)
        return req

    def verify(self, front_image_data, barcode_data, mibi_data):
        device_metadata, web_req_metadata, mibi_data = self.create_headers(mibi_data)
        req = self.create_request(front_image_data, barcode_data)
        logger.info('Trying to make LicenseService verify call to soap service')
        response = self.soap_service.verify(req, device_metadata, web_req_metadata, mibi_data)
        logger.info('Returning response from soap service')
        return response


# Hook for flask-registry
def setup_app(app):
    wsdl = app.config['MOBILE_VERIFY_WSDL']
    username = app.config['MOBILE_VERIFY_USERNAME']
    password = app.config['MOBILE_VERIFY_PASSWORD']
    tenant_reference_number = app.config['MOBILE_VERIFY_TENANT_REF']
    app.license_service = LicenseService(wsdl, username, password, tenant_reference_number)


def verify_license(auth_req, front_image_data, barcode, mibi_data):

    user_id = auth_req['user_id']
    response = current_app.license_service.verify(front_image_data, barcode, mibi_data)

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
    userinfo = current_app.users[user_id]
    if 'vetting_results' not in userinfo:
        userinfo = {'vetting_results': []}

    data = {
        'extracted_data': response['body']['Response']['ExtractedData'],
        'data_match_score': response['body']['Response']['ComparisonResult']['DataMatchScore']
    }
    userinfo['vetting_results'].append({'vetting_time': time.time(), 'data': data})
    current_app.users[user_id] = userinfo
