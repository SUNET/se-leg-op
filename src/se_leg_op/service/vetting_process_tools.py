# -*- coding: utf-8 -*-

import json
import uuid
import datetime
from flask.globals import current_app
from oic.oic.message import AuthorizationRequest

__author__ = 'lundberg'


class InvalidOpaqueDataError(Exception):
    pass


def parse_opaque_data(opaque_data):
    if not opaque_data:
        raise InvalidOpaqueDataError('No opaque data passed to the function')

    opaque_data_version = opaque_data[0]
    if opaque_data_version != '1':
        raise InvalidOpaqueDataError('Invalid opaque data version')

    try:
        opaque_data_deserialized = json.loads(opaque_data[1:])
    except ValueError as e:
        raise InvalidOpaqueDataError('Invalid formatted opaque data')

    if not all(key in opaque_data_deserialized for key in ('nonce', 'token')):
        raise InvalidOpaqueDataError('Invalid opaque data: nonce or token is missing')

    return opaque_data_deserialized


def create_authentication_response(auth_req, user_id=None, extra_userinfo=None):
    """
    :param auth_req: Authentication request
    :type auth_req: oic.oic.message.AuthorizationRequest
    :param user_id: Local identifier for the user
    :type user_id: str|None
    :param extra_userinfo: Extra user info
    :type extra_userinfo: dict|callable|None
    :return: Authentication response
    :rtype: oic.oic.message.AuthorizationResponse

    Creates an authentication response from an authentication request. Generates an user_id if one isn't
    provided.
    """

    if user_id is None:
        user_id = str(uuid.uuid4())
        # Persist a connection between authn request and generated user id
        auth_req_dict = auth_req.to_dict()
        auth_req_dict['user_id'] = user_id
        current_app.authn_requests[auth_req['nonce']] = auth_req_dict
        # Initialize empy userinfo
        current_app.users[user_id] = {}
    authn_response = current_app.provider.authorize(AuthorizationRequest().from_dict(auth_req), user_id,
                                                    extra_userinfo)
    return authn_response


def compute_credibility_score(nonce, credibility_data):
    """
    :param nonce: Auth requests nonce
    :param credibility_data: Collection of credibility data

    :type nonce: str
    :type credibility_data: dict

    :return: credibility score
    :rtype: int
    """
    current_app.logger.info('Computing credibility score for {}:'.format(nonce))
    # Ocular validation
    if not credibility_data.get('ocular_validation', False):
        current_app.logger.info('{} failed ocular validation'.format(nonce))
        return 0
    # Document identifier
    if not credibility_data.get('document_identifier'):
        # TODO: Use document identifier to check if document is valid
        current_app.logger.info('{} had no document identifier'.format(nonce))
        return 0
    # Expiry date
    expiry_date = datetime.datetime.fromtimestamp(credibility_data.get('expiry_date', 0))
    if expiry_date.date() < datetime.date.today():
        current_app.logger.info('{} failed expiry date check'.format(nonce))
        return 0
    current_app.logger.info('All credibility checks completed for {}'.format(nonce))
    return 100
