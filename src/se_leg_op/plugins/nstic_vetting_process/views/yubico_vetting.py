# -*- coding: utf-8 -*-

import flask
from flask.blueprints import Blueprint
from flask.globals import current_app
from flask.helpers import make_response
from oic.oic.message import AuthorizationRequest
from time import time

from se_leg_op.service.vetting_process_tools import parse_qrdata, InvalidQrDataError
from ..license_service import parse_vetting_data
from ..license_service_worker import verify_license

__author__ = 'lundberg'

yubico_vetting_process_views = Blueprint('yubico_vetting_process', __name__, url_prefix='/yubico')


@yubico_vetting_process_views.route('/vetting-result', methods=['POST'])
def vetting_result():
    data = flask.request.get_json()

    try:
        qrdata = parse_qrdata(data['qrcode'])
    except InvalidQrDataError as e:
        return make_response(str(e), 400)

    auth_req_data = current_app.authn_requests.pop(qrdata['nonce'])
    if not auth_req_data:
        # XXX: Short circuit vetting process for special nonce during development
        if qrdata['nonce'] in current_app.config.get('TEST_NONCE', []):
            current_app.logger.debug('Found test nonce {}'.format(qrdata['nonce']))
            return development_license_check(data)
        # XXX: End remove later
        current_app.logger.debug('Received unknown nonce \'{}\''.format(qrdata['nonce']))
        return make_response('Unknown nonce', 400)

    auth_req = AuthorizationRequest(**auth_req_data)
    user_id = auth_req['user_id']

    try:
        current_app.logger.debug('Vetting data received: {}'.format(data))
        # Check vetting data received
        parsed_data = parse_vetting_data(data)
        current_app.logger.debug('Vetting data parsed: {!r}'.format(parsed_data))
    except ValueError as e:
        current_app.logger.error('Received malformed vetting data \'{}\''.format(data))
        current_app.logger.error(e)
        return make_response('Malformed vetting data', 400)
    except KeyError as e:
        current_app.logger.error('Missing vetting data: \'{}\''.format(e))
        return make_response('Missing vetting data: {}'.format(e), 400)

    # Save information needed for the next vetting step that uses the api
    try:
        yubico_state = current_app.yubico_states[auth_req['state']]
    except KeyError:
        yubico_state = {
            'created': time(),
            'state': auth_req['state'],
            'client_id': auth_req['client_id'],
            'user_id': user_id
        }
    else:
        # Yubico state already created via the api
        yubico_state.update({'client_id': auth_req['client_id'], 'user_id': user_id})
    current_app.yubico_states[auth_req['state']] = yubico_state

    # Add soap license check to queue
    current_app.mobile_verify_service_queue.enqueue(verify_license, auth_req.to_dict(), parsed_data['front_image_data'],
                                                    parsed_data['barcode_data'], parsed_data['mibi_data'])

    return make_response('OK', 200)


# XXX: Remove after development
def development_license_check(data):
    # TODO: What do we want to do here?
    current_app.logger.debug('Test data received: {}'.format(data))
    try:
        parsed_data = parse_vetting_data(data)
        current_app.logger.debug('Test data json parsed: {!r}'.format(parsed_data))
    except ValueError as e:
        current_app.logger.error('Received malformed json:')
        current_app.logger.error(e)
        return make_response('Malformed json data', 400)
    except KeyError as e:
        current_app.logger.error('Missing vetting data: \'{}\''.format(e))
        return make_response('Missing vetting data: {}'.format(e), 400)
    return make_response('OK', 200)
# XXX: End remove



