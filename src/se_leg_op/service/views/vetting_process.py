import json
import time

import flask
from flask.blueprints import Blueprint
from flask.globals import current_app
from flask.helpers import make_response
from oic.oic.message import AuthorizationRequest
from pyop.util import should_fragment_encode

from .oidc_provider import extra_userinfo
from ...service.response_sender import deliver_response_task

vetting_process_views = Blueprint('vetting_process', __name__, url_prefix='')


class InvalidQrDataError(Exception):
    pass


def _parse_qrdata(qrcode):
    if not qrcode:
        raise InvalidQrDataError('Empty QR code version')

    qr_version = qrcode[0]
    if qr_version != '1':
        raise InvalidQrDataError('Invalid QR code version')

    try:
        qrdata = json.loads(qrcode[1:])
    except ValueError as e:
        raise InvalidQrDataError('Invalid QR code')

    if not all(key in qrdata for key in ('nonce', 'token')):
        raise InvalidQrDataError('Invalid QR code')

    return qrdata


@vetting_process_views.route('/vetting-result', methods=['POST'])
def vetting_result():
    identity = flask.request.form['identity']
    qrcode = flask.request.form['qrcode']

    try:
        qrdata = _parse_qrdata(qrcode)
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

    authn_response = current_app.provider.authorize(AuthorizationRequest().from_dict(auth_req), identity,
                                                    extra_userinfo)
    response_url = authn_response.request(auth_req['redirect_uri'], should_fragment_encode(auth_req))

    headers = {'Authorization': 'Bearer {}'.format(qrdata['token'])}
    current_app.authn_response_queue.enqueue(deliver_response_task, response_url, headers=headers)
    return make_response('OK', 200)


@vetting_process_views.route('/update-user-data', methods=['POST'])
def update_user_data():
    raise NotImplementedError()
