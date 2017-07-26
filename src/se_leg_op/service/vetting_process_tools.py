# -*- coding: utf-8 -*-

import json
import uuid
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
