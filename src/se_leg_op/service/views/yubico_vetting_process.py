# -*- coding: utf-8 -*-

import time
import flask
import json
from flask.blueprints import Blueprint
from flask.globals import current_app
from flask.helpers import make_response
from oic.oic.message import AuthorizationRequest
from pyop.util import should_fragment_encode

from .oidc_provider import extra_userinfo
from ...service.response_sender import deliver_response_task
from ...service.vetting_process_tools import parse_qrdata, InvalidQrDataError, create_authentication_response

__author__ = 'lundberg'

yubico_vetting_process_views = Blueprint('yubico_vetting_process', __name__, url_prefix='/yubico')


@yubico_vetting_process_views.route('/vetting-result', methods=['POST'])
def vetting_result():
    data = flask.request.form['data']
    qrcode = flask.request.form['qrcode']

    try:
        qrdata = parse_qrdata(qrcode)
    except InvalidQrDataError as e:
        return make_response(str(e), 400)

    try:
        auth_req_data = current_app.authn_requests[qrdata['nonce']]
    except KeyError:
        current_app.logger.debug('Received unknown nonce \'%s\'', qrdata['nonce'])
        return make_response('Unknown nonce', 400)

    auth_req = AuthorizationRequest(**auth_req_data)
    user_id = auth_req['user_id']

    # TODO Use vetting data to verify a users drivers license
    vetting_data = json.loads(data)
    # TODO store necessary user info
    current_app.users[user_id] = {'vetting_time': time.time(), 'data': vetting_data}

    return make_response('OK', 200)
