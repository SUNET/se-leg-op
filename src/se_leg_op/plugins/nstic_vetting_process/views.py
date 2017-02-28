# -*- coding: utf-8 -*-

import flask
import json
import base64

from flask.blueprints import Blueprint
from flask.globals import current_app
from flask.helpers import make_response
from oic.oic.message import AuthorizationRequest

from ...service.vetting_process_tools import parse_qrdata, InvalidQrDataError
from .auth import authorize_client
from .license_service import verify_license

__author__ = 'lundberg'

yubico_vetting_process_views = Blueprint('yubico_vetting_process', __name__, url_prefix='/yubico')

# registry hook
blueprints = [yubico_vetting_process_views]


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
        # XXX: Short circuit vetting process for special nonce during development
        if qrdata['nonce'] in current_app.config.get('TEST_NONCE', []):
            current_app.logger.debug('Found test nonce {}'.format(qrdata['nonce']))
            development_license_check(data)
            return make_response('OK', 200)
        # XXX: Remove later

        current_app.logger.debug('Received unknown nonce \'%s\'', qrdata['nonce'])
        return make_response('Unknown nonce', 400)

    auth_req = AuthorizationRequest(**auth_req_data)

    # Check vetting data received
    try:
        vetting_data = json.loads(data)
        mibi_data = vetting_data['mibi_data']
        # The soap service wants to encode the image data so lets decode it here
        front_image_data = base64.b64decode(vetting_data['front_image_data'])
        back_image_data = vetting_data['back_image_data']
    except ValueError:
        current_app.logger.debug('Received malformed json \'%s\'', data)
        return make_response('Malformed json data', 400)
    except KeyError as e:
        current_app.logger.debug('Missing vetting data: \'%s\'', e)
        return make_response('Missing vetting data: {}'.format(e), 400)

    verify_license(auth_req, front_image_data, back_image_data, mibi_data)

    return make_response('OK', 200)


def development_license_check(data):
    # TODO: What do we want to do here?
    current_app.logger.debug('Test data received: {}'.format(data))


@yubico_vetting_process_views.route('/vettings', methods=['GET'])
@authorize_client
def get_vettings(client_id):
    current_app.logger.info('Client {} requested vettings'.format(client_id))
    result = {'vettings': []}
    i = 0
    for key, data in current_app.authn_requests.get_documents_by_attr('data.client_id', client_id, False):
        i += 1
        vetting = {'state': data['state']}
        user_id = data['user_id']
        try:
            userinfo = current_app.users[user_id]
        except KeyError:
            userinfo = {}
        vetting['vetting_results'] = userinfo.get('vetting_results')
        result['vettings'].append(vetting)

    current_app.logger.debug('Returned {} vettings for client {}'.format(i, client_id))
    return flask.jsonify(result)


@yubico_vetting_process_views.route('/vettings', methods=['POST'])
@authorize_client
def update_vettings(client_id):
    current_app.logger.info('Client {} updated vettings'.format(client_id))
    return flask.jsonify(flask.request.json)
