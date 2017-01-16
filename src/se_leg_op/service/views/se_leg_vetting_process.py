# -*- coding: utf-8 -*-

import time
import flask
from flask.blueprints import Blueprint
from flask.globals import current_app
from flask.helpers import make_response
from oic.oic.message import AuthorizationRequest

from ...service.vetting_process_tools import parse_qrdata, InvalidQrDataError, deliver_authn_response


se_leg_vetting_process_views = Blueprint('se_leg_vetting_process', __name__, url_prefix='')


@se_leg_vetting_process_views.route('/vetting-result', methods=['POST'])
def vetting_result():
    identity = flask.request.form['identity']
    qrcode = flask.request.form['qrcode']

    try:
        qrdata = parse_qrdata(qrcode)
    except InvalidQrDataError as e:
        return make_response(str(e), 400)

    auth_req_data = current_app.authn_requests.pop(qrdata['nonce'], None)
    if auth_req_data is None:
        current_app.logger.debug('Received unknown nonce \'%s\'', qrdata['nonce'])
        return make_response('Unknown nonce', 400)

    auth_req = AuthorizationRequest(**auth_req_data)
    # TODO store necessary user info
    current_app.users[identity] = {'vetting_time': time.time(),
                                   'identity': identity}

    deliver_authn_response(auth_req, identity, qrdata['token'])

    return make_response('OK', 200)


@se_leg_vetting_process_views.route('/update-user-data', methods=['POST'])
def update_user_data():
    raise NotImplementedError()
