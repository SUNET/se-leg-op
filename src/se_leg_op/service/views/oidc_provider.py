import flask
from flask import Blueprint
from flask import current_app
from flask import jsonify
from flask.helpers import make_response
from oic.oic.message import TokenErrorResponse, UserInfoErrorResponse
from pyop.access_token import AccessToken, BearerTokenError
from pyop.exceptions import InvalidAuthenticationRequest, InvalidAccessToken, InvalidClientAuthentication, OAuthError
from pyop.util import should_fragment_encode

from se_leg_op.service.response_sender import deliver_response_task
from se_leg_op.service.vetting_process_tools import create_authentication_response

oidc_provider_views = Blueprint('oidc_provider', __name__, url_prefix='')


@oidc_provider_views.route('/')
def index():
    return ''


@oidc_provider_views.route('/authentication', methods=['POST'])
def authentication_endpoint():
    # parse authentication request
    try:
        auth_req = current_app.provider.parse_authentication_request(flask.request.get_data().decode('utf-8'),
                                                                     flask.request.headers)
        current_app.authn_requests[auth_req['nonce']] = auth_req.to_dict()

        # Check client vetting method
        client = current_app.provider.clients[auth_req['client_id']]
        if client.get('vetting_policy') == 'POST_AUTH':
            # Return a authn response immediately
            authn_response = create_authentication_response(auth_req)
            response_url = authn_response.request(auth_req['redirect_uri'], should_fragment_encode(auth_req))
            try:
                headers = {'Authorization': 'Bearer {}'.format(auth_req['token'])}
            except KeyError:
                # Bearer Token needs to be supplied with the auth request for instant responses
                raise InvalidAuthenticationRequest('Token missing', auth_req)
            current_app.authn_response_queue.enqueue(deliver_response_task, response_url, headers=headers)

    except InvalidAuthenticationRequest as e:
        current_app.logger.debug('received invalid authn request', exc_info=True)
        error_url = e.to_error_url()
        if error_url:
            current_app.authn_response_queue.enqueue(deliver_response_task, error_url)
            return make_response('OK', 200)
        else:
            # deliver directly to client since we're only supporting POST
            return make_response('Something went wrong: {}'.format(str(e)), 400)

    return make_response('OK', 200)


@oidc_provider_views.route('/.well-known/openid-configuration')
def provider_configuration():
    return jsonify(current_app.provider.provider_configuration.to_dict())


@oidc_provider_views.route('/jwks')
def jwks_uri():
    return jsonify(current_app.provider.jwks)


@oidc_provider_views.route('/token', methods=['POST'])
def token_endpoint():
    try:
        token_response = current_app.provider.handle_token_request(flask.request.get_data().decode('utf-8'),
                                                                   flask.request.headers, extra_userinfo)
        return jsonify(token_response.to_dict())
    except InvalidClientAuthentication as e:
        current_app.logger.debug('invalid client authentication at token endpoint', exc_info=True)
        error_resp = TokenErrorResponse(error='invalid_client', error_description=str(e))
        response = make_response(error_resp.to_json(), 401)
        response.headers['Content-Type'] = 'application/json'
        response.headers['WWW-Authenticate'] = 'Basic'
        return response
    except OAuthError as e:
        current_app.logger.debug('invalid request: %s', str(e), exc_info=True)
        error_resp = TokenErrorResponse(error=e.oauth_error, error_description=str(e))
        response = make_response(error_resp.to_json(), 400)
        response.headers['Content-Type'] = 'application/json'
        return response


@oidc_provider_views.route('/userinfo', methods=['GET', 'POST'])
def userinfo_endpoint():
    try:
        response = current_app.provider.handle_userinfo_request(flask.request.get_data().decode('utf-8'),
                                                                flask.request.headers)
        return jsonify(response.to_dict())
    except (BearerTokenError, InvalidAccessToken) as e:
        error_resp = UserInfoErrorResponse(error='invalid_token', error_description=str(e))
        response = make_response(error_resp.to_json(), 401)
        response.headers['WWW-Authenticate'] = AccessToken.BEARER_TOKEN_TYPE
        response.headers['Content-Type'] = 'application/json'
        return response


def extra_userinfo(user_id, client_id):
    try:
        vetting_time = current_app.provider.userinfo[user_id]['vetting_time']
    except KeyError:
        vetting_time = None
    return {'vetting_time': vetting_time}
