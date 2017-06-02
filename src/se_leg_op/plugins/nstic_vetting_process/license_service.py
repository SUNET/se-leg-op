# -*- coding: utf-8 -*-

import logging
import json
import base64
import redis
from redis import StrictRedis, sentinel
import rq
from se_leg_op.storage import OpStorageWrapper

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


# Hook for flask-registry extensions
def setup_app(app):
    app.yubico_states = OpStorageWrapper(app.config['DB_URI'], 'yubico_states')
    app.mobile_verify_service_queue = init_mobile_verify_service_queue(app.config)


def init_mobile_verify_service_queue(config):
    if config.get('REDIS_SENTINEL_HOSTS') and config.get('REDIS_SENTINEL_SERVICE_NAME'):
        _port = config['REDIS_PORT']
        _hosts = config['REDIS_SENTINEL_HOSTS']
        _name = config['REDIS_SENTINEL_SERVICE_NAME']
        host_port = [(x, _port) for x in _hosts]
        manager = sentinel.Sentinel(host_port, socket_timeout=0.1)
        pool = sentinel.SentinelConnectionPool(_name, manager)
    else:
        pool = redis.ConnectionPool.from_url(config['REDIS_URI'])

    connection = StrictRedis(connection_pool=pool)
    return rq.Queue('mobile_verify_service_queue', connection=connection)


def parse_vetting_data(data):
    """
    :param data: vetting data
    :type data: dict
    :return: parsed data
    :rtype: dict
    """
    parsed_data = {}
    # The soap service wants the mibi data in a json string
    parsed_data['mibi_data'] = json.dumps(data['mibi'])
    # The soap service wants to encode the image data so lets decode it here
    parsed_data['front_image_data'] = base64.b64decode(data['encodedData'])
    parsed_data['barcode_data'] = data['barcode']
    return parsed_data
