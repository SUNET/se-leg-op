import time
import json
from base64 import urlsafe_b64decode
from builtins import UnicodeDecodeError

# JSONDecodeError is only available from Python > 3.4
try:
    from json import JSONDecodeError
except ImportError:
    JSONDecodeError = ValueError

import flask
from flask.blueprints import Blueprint
from flask.globals import current_app
from flask.helpers import make_response

from Cryptodome.PublicKey import RSA

from jwkest.jws import JWS
from jwkest.jwk import RSAKey
from jwkest.jwk import KEYS

from jwkest import BadSignature

from oic.oic.message import AuthorizationRequest

from pyop.util import should_fragment_encode

from ...service.views.oidc_provider import extra_userinfo
from ...service.response_sender import deliver_response_task
from ...service.vetting_process_tools import parse_opaque_data, InvalidOpaqueDataError, create_authentication_response

from ...service.vetting_process_tools import parse_opaque_data, InvalidOpaqueDataError


verisec_vetting_process_views = Blueprint('verisec_vetting_process', __name__, url_prefix='/verisec')

# registry hook
blueprints = [verisec_vetting_process_views]


@verisec_vetting_process_views.route('/vetting-result', methods=['POST'])
def vetting_result():
    if not current_app.config.get('FREJA_CALLBACK_X5C_CERT'):
        current_app.logger.info('Configuration error: FREJA_CALLBACK_X5C_CERT is not set')
        return make_response('Configuration error', 500)

    _freja_callback_x5c_cert = current_app.config.get('FREJA_CALLBACK_X5C_CERT')
    _freja_callback_x5c_pub_key = RSA.importKey(_freja_callback_x5c_cert)
    _freja_callback_rsa_pub_key = RSAKey()
    _freja_callback_rsa_pub_key.load_key(_freja_callback_x5c_pub_key)

    current_app.logger.debug('flask.request.headers: \'{!s}\''.format(flask.request.headers))
    current_app.logger.debug('flask.request.data: \'{!s}\''.format(flask.request.get_data()))

    try:
        if flask.request.headers['Content-Type'] == 'application/jose':
            current_app.logger.info('Received a callback with MIME application/jose')
        else:
            current_app.logger.info('Received a callback with an invalid MIME: \'{!s}\''
                                    .format(flask.request.headers['Content-Type']))
            return make_response('Invalid MIME', 400)
    except KeyError:
        current_app.logger.info('Received a callback without a MIME')
        return make_response('No MIME specified', 400)

    try:
        data = flask.request.get_json(force=True)
    except:
        current_app.logger.info('Invalid verisec callback: missing or invalid JSON')
        return make_response('missing or invalid JSON', 400)

    if not data:
        current_app.logger.info('Invalid verisec callback: no JSON data provided')
        return make_response('Missing JSON data', 400)

    ia_response_data = data.get('iaResponseData')

    if not ia_response_data:
        current_app.logger.info('Missing iaResponseData in verisec callback: \'{!s}\''.format(data))
        return make_response('Missing iaResponseData', 400)

    current_app.logger.info('Received verisec iaResponseData: \'{!s}\''.format(ia_response_data))

    jws_parts = ia_response_data.split('.')

    # A correctly formatted JWS is made up of 3 parts
    if len(jws_parts) != 3:
        current_app.logger.info('iaResponseData response doesn\'t seems to be a JWS')
        return make_response('iaResponseData is not a JWS', 400)

    # This is for testing only and therefore we do not verify the JWS yet
    unverified_header = jws_parts[0]
    unverified_payload = jws_parts[1]

    # It should be possible to base64 decode the header and payload
    try:
        # urlsafe_b64decode returns bytes object so we decode to get str aka utf8
        unverified_header_decoded = urlsafe_b64decode(unverified_header + '=' * (4 - (len(unverified_header) % 4))).decode('utf8')
        unverified_payload_decoded = urlsafe_b64decode(unverified_payload + '=' * (4 - (len(unverified_payload) % 4))).decode('utf8')
    except UnicodeDecodeError:
        current_app.logger.info('Couldn\'t urlsafe_b64decode iaResponseData because it contains invalid UTF-8')
        return make_response('Incorrect UTF-8 in iaResponseData', 400)
    except TypeError:
        current_app.logger.info('Couldn\'t urlsafe_b64decode iaResponseData')
        return make_response('Incorrect base64 encoded iaResponseData', 400)

    try:
        json.loads(unverified_header_decoded)
        json.loads(unverified_payload_decoded)
    except JSONDecodeError:
        current_app.logger.info('Incorrect UTF-8 BOM or invalid JSON data from base64 decoded iaResponseData')
        return make_response('Incorrectly encoded JSON in base64 decoded iaResponseData', 400)
    except TypeError:
        current_app.logger.info('JSON in base64 decoded iaResponseData is not str')
        return make_response('Incorrectly encoded JSON in base64 decoded iaResponseData', 400)

    try:
        verified_payload = JWS().verify_compact(ia_response_data, keys=[_freja_callback_rsa_pub_key], sigalg='RS256')
    except BadSignature as e:
        current_app.logger.info('The JWS was not properly signed')
        return make_response('Invalid signature', 400)
    except Exception as e:
        current_app.logger.info(str(e))
        return make_response('Invalid JWS', 400)

    try:
        verified_payload_country = verified_payload.pop('country')
        verified_payload_opaque = verified_payload.pop('opaque') # The opaque contains nonce and token
        verified_payload_ref = verified_payload.pop('ref')
        verified_payload_ssn = verified_payload.pop('ssn')
    except KeyError:
        current_app.logger.info('The verified JWS payload is missing some required claims')
        return make_response('The verified JWS payload is missing some required claims', 400)

    # Make sure that we have processed all claims in the payload
    if len(verified_payload) == 0:

        try:
            verified_opaque_deserialized = parse_opaque_data(verified_payload_opaque)
        except InvalidOpaqueDataError as e:
            # This is by design since we want the message from this exception
            return make_response(str(e), 400)

        auth_req_data = current_app.authn_requests.pop(verified_opaque_deserialized['nonce'], None)
        if not auth_req_data:
            current_app.logger.info('Unknown nonce in verified JWS payload: \'{!s}\''.format(verified_opaque_deserialized['nonce']))
            return make_response('Unknown nonce in verified JWS payload', 400)

        current_app.users[verified_payload_ssn] = {'vetting_time': time.time(), 'identity': verified_payload_ssn}

        auth_req = AuthorizationRequest(**auth_req_data)
        authn_response = create_authentication_response(auth_req=auth_req,
                                                        user_id=verified_payload_ssn,
                                                        extra_userinfo=extra_userinfo)

        response_url = authn_response.request(auth_req['redirect_uri'], should_fragment_encode(auth_req))
        headers = {'Authorization': 'Bearer {}'.format(verified_opaque_deserialized['token'])}
        current_app.authn_response_queue.enqueue(deliver_response_task, response_url, headers=headers)

        return make_response('OK', 200)

    current_app.logger.info('Received an invalid verisec callback')
    return make_response('Invalid request', 400)
