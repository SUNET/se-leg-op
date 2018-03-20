# -*- coding: utf-8 -*-

import time
from flask import Blueprint, current_app, request, abort
from flask.helpers import make_response
from oic.oic.message import AuthorizationRequest
from pyop.util import should_fragment_encode
from functools import wraps

from ...service.views.oidc_provider import extra_userinfo
from ...service.response_sender import deliver_response_task
from ...service.vetting_process_tools import parse_opaque_data, InvalidOpaqueDataError, create_authentication_response


se_leg_vetting_process_views = Blueprint('se_leg_vetting_process', __name__, url_prefix='')

# registry hook
blueprints = [se_leg_vetting_process_views]


def authorize(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.authorization:
            username = request.authorization['username']
            password = request.authorization['password']
            current_app.logger.info('Trying to authorize {}'.format(username))
            try:
                secret = None
                if username in current_app.config['SELEG_VETTING_APPS']:
                    vetting_app = current_app.config['SELEG_VETTING_APPS'][username]
                    secret = vetting_app['secret']
                    kwargs['ra_app'] = username
                if secret and secret == password:
                    return f(*args, **kwargs)
                current_app.logger.error('Authorization failure: Wrong password for {}'.format(username))
            except KeyError as e:
                current_app.logger.error('Authorization failure: KeyError {}'.format(e))
        abort(401)
    return decorated_function


@se_leg_vetting_process_views.route('/vetting-result', methods=['POST'])
@authorize
def vetting_result(ra_app):
    current_app.logger.info('Received vetting result from {}'.format(ra_app))
    data = request.get_json()
    current_app.logger.debug('Data received {}'.format(data))
    identity = data.get('identity')
    qrcode = data.get('qrcode')
    metadata = data.get('meta', {})  # Default to empty dict

    if not identity:
        return make_response('Missing identity', 400)

    try:
        qrdata = parse_opaque_data(qrcode)
    except InvalidOpaqueDataError as e:
        # This is by design since we want the message from this exception
        current_app.logger.error('Received invalid opaque data: {}'.format(e))
        return make_response(str(e), 400)

    # Collect more metadata
    metadata['opaque'] = qrcode
    metadata['ra_app'] = ra_app

    auth_req_data = current_app.authn_requests.pop(qrdata['nonce'], None)
    if auth_req_data is None:
        current_app.logger.error('Received unknown nonce \'%s\'', qrdata['nonce'])
        return make_response('Unknown nonce', 400)

    auth_req = AuthorizationRequest(**auth_req_data)

    # TODO store necessary user info
    current_app.users[identity] = {'vetting_time': time.time(), 'identity': identity, 'metadata': metadata}

    authn_response = create_authentication_response(auth_req, identity, extra_userinfo)
    response_url = authn_response.request(auth_req['redirect_uri'], should_fragment_encode(auth_req))
    headers = {'Authorization': 'Bearer {}'.format(qrdata['token'])}
    current_app.authn_response_queue.enqueue(deliver_response_task, response_url, headers=headers)
    current_app.logger.info('Vetting result from {} delivered as authn response to {}'.format(ra_app, response_url))
    return make_response('OK', 200)


@se_leg_vetting_process_views.route('/update-user-data', methods=['POST'])
def update_user_data():
    raise NotImplementedError()
