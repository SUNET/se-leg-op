# -*- coding: utf-8 -*-

import time
import flask
from flask.blueprints import Blueprint
from flask.globals import current_app
from flask.helpers import make_response
from oic.oic.message import AuthorizationRequest
from pyop.util import should_fragment_encode

from ...service.views.oidc_provider import extra_userinfo
from ...service.response_sender import deliver_response_task
from ...service.vetting_process_tools import parse_opaque_data, InvalidOpaqueDataError, create_authentication_response


se_leg_vetting_process_views = Blueprint('se_leg_vetting_process', __name__, url_prefix='')

# registry hook
blueprints = [se_leg_vetting_process_views]


@se_leg_vetting_process_views.route('/vetting-result', methods=['POST'])
def vetting_result():
    data = flask.request.get_json()
    identity = data.get('identity')
    qrcode = data.get('qrcode')

    if not identity:
        return make_response('Missing identity', 400)

    try:
        qrdata = parse_opaque_data(qrcode)
    except InvalidOpaqueDataError as e:
        # This is by design since we want the message from this exception
        return make_response(str(e), 400)

    auth_req_data = current_app.authn_requests.pop(qrdata['nonce'], None)
    if auth_req_data is None:
        current_app.logger.debug('Received unknown nonce \'%s\'', qrdata['nonce'])
        return make_response('Unknown nonce', 400)

    auth_req = AuthorizationRequest(**auth_req_data)

    # TODO store necessary user info
    current_app.users[identity] = {'vetting_time': time.time(), 'identity': identity}

    authn_response = create_authentication_response(auth_req, identity, extra_userinfo)
    response_url = authn_response.request(auth_req['redirect_uri'], should_fragment_encode(auth_req))
    headers = {'Authorization': 'Bearer {}'.format(qrdata['token'])}
    current_app.authn_response_queue.enqueue(deliver_response_task, response_url, headers=headers)

    return make_response('OK', 200)


@se_leg_vetting_process_views.route('/update-user-data', methods=['POST'])
def update_user_data():
    raise NotImplementedError()
