# -*- coding: utf-8 -*-

import time
from datetime import timedelta
from flask import Blueprint, current_app, request, abort
from flask.helpers import make_response
from functools import wraps

from se_leg_op.service.vetting_process_tools import parse_opaque_data, InvalidOpaqueDataError
from se_leg_op.service.vetting_process_tools import compute_credibility_score
from se_leg_op.plugins.se_leg_vetting_process.delayed_response_sender import delayed_authn_response_task


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

    auth_req_data = current_app.authn_requests.pop(qrdata['nonce'], None)
    if auth_req_data is None:
        current_app.logger.error('Received unknown nonce \'%s\'', qrdata['nonce'])
        return make_response('Unknown nonce', 400)

    # Collect more metadata
    metadata['opaque'] = qrcode
    metadata['ra_app'] = ra_app
    # Compute credibility score from metadata
    metadata['score'] = compute_credibility_score(qrdata['nonce'], metadata)
    # Remove unneeded metadata
    metadata.pop('expiry_date', None)
    metadata.pop('ocular_validation', None)
    metadata.pop('document_identifier', None)

    # Save userinfo
    current_app.users[identity] = {'vetting_time': time.time(), 'identity': identity, 'metadata': metadata}

    # Need a minimal app config to work during tests...
    # TODO: Remove the minimal config
    app_config = {
        'DB_URI': current_app.config['DB_URI'],
        'REDIS_URI': current_app.config['REDIS_URI'],
        'PREFERRED_URL_SCHEME': current_app.config['PREFERRED_URL_SCHEME'],
    }

    # Enqueue the delayed authn response
    seconds_delay = current_app.config['SELEG_AUTHN_RESPONSE_DELAY']
    current_app.authn_response_delay_queue.enqueue_in(timedelta(seconds=seconds_delay), delayed_authn_response_task,
                                                      auth_req_data, qrdata['token'], identity,
                                                      app_config)

    current_app.logger.info('Vetting result from {}. Delivering authn response in {} seconds'.format(
        ra_app, seconds_delay))
    return make_response('OK', 200)


@se_leg_vetting_process_views.route('/update-user-data', methods=['POST'])
def update_user_data():
    raise NotImplementedError()
