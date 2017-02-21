# -*- coding: utf-8 -*-

from flask import current_app
import redis
import redis.sentinel
import rq
from redis.client import StrictRedis
import time
import logging

from mitek_mobile_verify.services import MitekMobileVerifyService
from mitek_mobile_verify.plugins import DoctorPlugin
from mitek_mobile_verify.models.requests import PhotoVerifyRequest
from mitek_mobile_verify.models.headers import DeviceMetaData, WebRequestMetadataHeader, MibiDataHeader

__author__ = 'lundberg'

logger = logging.getLogger(__name__)


def init_mobile_verify_service(extra_plugins=list()):
    wsdl = current_app.config['MOBILE_VERIFY_WSDL']
    username = current_app.config['MOBILE_VERIFY_USERNAME']
    password = current_app.config['MOBILE_VERIFY_PASSWORD']
    # DoctorPlugin is needed to deserialize the response correctly
    plugins = [DoctorPlugin()]
    plugins.extend(extra_plugins)
    current_app.mobile_verify_service_queue = init_mobile_verify_queue(current_app.config)
    return MitekMobileVerifyService(wsdl, username, password, plugins=plugins)


def init_mobile_verify_queue(config):
    if config.get('REDIS_SENTINEL_HOSTS') and config.get('REDIS_SENTINEL_SERVICE_NAME'):
        _port = config['REDIS_PORT']
        _hosts = config['REDIS_SENTINEL_HOSTS']
        _name = config['REDIS_SENTINEL_SERVICE_NAME']
        host_port = [(x, _port) for x in _hosts]
        manager = redis.sentinel.Sentinel(host_port, socket_timeout=0.1)
        pool = redis.sentinel.SentinelConnectionPool(_name, manager)
    else:
        pool = redis.ConnectionPool.from_url(config['REDIS_URI'])

    connection = StrictRedis(connection_pool=pool)
    return rq.Queue('mobile_verify_service_queue', connection=connection)


def create_headers(mibi_data=None):
    tenant_reference_number = current_app.config['MOBILE_VERIFY_TENANT_REF']
    web_req_metadata = WebRequestMetadataHeader(tenant_reference=tenant_reference_number)
    device_metadata = DeviceMetaData()
    mibi_data = MibiDataHeader(mibi_data=mibi_data)
    return web_req_metadata, device_metadata, mibi_data


def create_request(front_image_data, back_image_data):
    req = PhotoVerifyRequest()
    req.back_image = req.create_image(hints=[{'PDF417': back_image_data}])
    req.front_image = req.create_image(image_data=front_image_data)
    return req


def verify_license_task(auth_req, front_image_data, back_image_data, mibi_data):
    user_id = auth_req['user_id']
    web_req_metadata, device_metadata, mibi_data = create_headers(mibi_data)
    req = create_request(front_image_data, back_image_data)
    response = current_app.verify_license_service.verify(req, device_metadata, web_req_metadata, mibi_data)

    # TODO: Log verification attempt
    # TODO: Use response['header']['Metadata']['TransactionReferenceId'],
    # TODO: response['header']['Metadata']['SessionReferenceId'] and auth_req

    if response['body']['Response']['Status'] is not 'Successful':
        logger.error('Verify license failed:')
        logger.error(repr(response['body']['Response']['Errors']))
        return  # TODO: When should we retry?

    # Successful response received, save the verification response
    userinfo = current_app.users[user_id]
    if 'vetting_results' not in userinfo:
        userinfo = {'vetting_results': []}
    userinfo['vetting_results'].append({'vetting_time': time.time(), 'data': response['body']['Response']})
    current_app.users[user_id] = userinfo
