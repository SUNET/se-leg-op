# -*- coding: utf-8 -*-

import time
import flask
import json
from functools import wraps
from flask.blueprints import Blueprint
from flask.globals import current_app
from flask.helpers import make_response
from oic.oic.message import AuthorizationRequest

from ...service.vetting_process_tools import parse_qrdata, InvalidQrDataError

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
        # XXX: Short circuit vetting process for special nonce during development
        if qrdata['nonce'] in current_app.config.get('TEST_NONCE', []):
            current_app.logger.debug('Found test nonce {}'.format(qrdata['nonce']))
            development_license_check(data)
            return make_response('OK', 200)
        # XXX: Remove later

        current_app.logger.debug('Received unknown nonce \'%s\'', qrdata['nonce'])
        return make_response('Unknown nonce', 400)

    auth_req = AuthorizationRequest(**auth_req_data)
    user_id = auth_req['user_id']

    # TODO Use vetting data to verify a users drivers license
    vetting_data = json.loads(data)

    # TODO store necessary user info
    userinfo = current_app.users[user_id]
    if 'vetting_results' not in userinfo:
        userinfo = {'vetting_results': []}
    userinfo['vetting_results'].append({'vetting_time': time.time(), 'data': vetting_data})
    current_app.users[user_id] = userinfo

    return make_response('OK', 200)


def development_license_check(data):
    # TODO: What do we want to do here?
    current_app.logger.debug('Test data received: {}'.format(data))


def authorize_client(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if flask.request.authorization:
            client_id = flask.request.authorization['username']
            password = flask.request.authorization['password']
            current_app.logger.info('Trying to authorize {}'.format(client_id))
            try:
                client = current_app.provider.clients[client_id]
                if client['client_secret'] == password:
                    kwargs['client_id'] = client_id
                    return f(*args, **kwargs)
                current_app.logger.error('Authorization failure: Wrong password for {}'.format(client_id))
            except KeyError as e:
                current_app.logger.error('Authorization failure: KeyError {}'.format(e))
        flask.abort(401)
    return decorated_function


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
