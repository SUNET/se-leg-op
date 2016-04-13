import flask
import requests
from flask import Blueprint
from flask import current_app
from flask import jsonify
from flask.helpers import make_response
from oic.oic.message import TokenErrorResponse, UserInfoErrorResponse

from ...access_token import AccessToken, BearerTokenError
from ...authz_state import InvalidAccessToken
from ...authz_state import InvalidAuthorizationCode, InvalidRefreshToken, InvalidScope
from ...client_authentication import InvalidClientAuthentication
from ...provider import InvalidAuthenticationRequest
from ...provider import InvalidTokenRequest

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
    except InvalidAuthenticationRequest as e:
        current_app.logger.debug('received invalid authn request', exc_info=True)
        error_url = e.to_error_url()
        if error_url:
            return deliver_response_to_redirect_uri(error_url)
        else:
            # deliver directly to client since we're only supporting POST
            return make_response('Something went wrong: {}'.format(str(e)), 400)

    return make_response('OK', 200)


@oidc_provider_views.route('/.well-known/openid-configuration')
def provider_configuration():
    return jsonify(current_app.provider.provider_configuration)


@oidc_provider_views.route('/jwks')
def jwks_uri():
    return jsonify(current_app.provider.jwks)


@oidc_provider_views.route('/token', methods=['POST'])
def token_endpoint():
    try:
        token_response = current_app.provider.handle_token_request(flask.request.get_data().decode('utf-8'),
                                                                   flask.request.headers, extra_userinfo)
        return jsonify(token_response.to_dict())
    except InvalidTokenRequest as e:
        current_app.logger.debug('received invalid token request', exc_info=True)
        error_resp = TokenErrorResponse(error=e.oauth_error, error_description=str(e))
        response = make_response(error_resp.to_json(), 400)
        response.headers['Content-Type'] = 'application/json'
        return response
    except InvalidClientAuthentication as e:
        current_app.logger.debug('invalid client authentication at token endpoint', exc_info=True)
        error_resp = TokenErrorResponse(error='invalid_client', error_description=str(e))
        response = make_response(error_resp.to_json(), 401)
        response.headers['Content-Type'] = 'application/json'
        response.headers['WWW-Authenticate'] = 'Basic'
        return response
    except (InvalidAuthorizationCode, InvalidRefreshToken) as e:
        current_app.logger.debug('invalid authorization grant received', exc_info=True)
        error_resp = TokenErrorResponse(error='invalid_grant', error_description=str(e))
        response = make_response(error_resp.to_json(), 400)
        response.headers['Content-Type'] = 'application/json'
        return response
    except InvalidScope as e:
        current_app.logger.debug('invalid scope requested at token endpoint', exc_info=True)
        error_resp = TokenErrorResponse(error='invalid_scope', error_description=str(e))
        response = make_response(error_resp.to_json(), 400)
        response.headers['Content-Type'] = 'application/json'
        return response


@oidc_provider_views.route('/userinfo', methods=['GET', 'POST'])
def userinfo_endpoint():
    try:
        response = current_app.provider.handle_userinfo_request(flask.request.get_data().decode('utf-8'),
                                                                flask.request.headers)
        return jsonify(response.to_dict())
    except InvalidAccessToken as e:
        error_resp = UserInfoErrorResponse(error='invalid_token', error_description=str(e))
        response = make_response(error_resp.to_json(), 401)
        response.headers['WWW-Authenticate'] = AccessToken.BEARER_TOKEN_TYPE
        response.headers['Content-Type'] = 'application/json'
        return response
    except BearerTokenError as e:
        response = make_response('', 401)
        response.headers['WWW-Authenticate'] = AccessToken.BEARER_TOKEN_TYPE
        response.headers['Content-Type'] = 'application/json'
        return response


def deliver_response_to_redirect_uri(response_url):
    try:
        resp = requests.get(response_url)
    except requests.exceptions.RequestException as e:
        current_app.logger.debug('could not deliver response to client', exc_info=True)
        return make_response('Something went wrong: {}'.format(str(e)), 400)

    if resp.status_code != 200:
        current_app.logger.debug('client responded with \'%s\' on response to redirect_uri \'%s\'',
                                 resp.status_code, resp.request.url)
        return make_response('Something went wrong: unexpected status \'{}\' from redirect_uri'
                             .format(resp.status_code), 400)

    return make_response('OK', 200)


def extra_userinfo(user_id, client_id):
    return {'vetting_time': current_app.provider.userinfo[user_id]['vetting_time']}
