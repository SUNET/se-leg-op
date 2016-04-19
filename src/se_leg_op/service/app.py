import logging

from flask.app import Flask
from flask.helpers import url_for
from jwkest.jwk import RSAKey, import_rsa_key

from ..storage import MongoWrapper
from ..authz_state import AuthorizationState
from ..provider import InvalidAuthenticationRequest
from ..provider import Provider
from ..subject_identifier import HashBasedSubjectIdentifierFactory
from ..userinfo import Userinfo

SE_LEG_PROVIDER_SETTINGS_ENVVAR = 'SE_LEG_PROVIDER_SETTINGS'


def _request_contains_nonce(authentication_request):
    if 'nonce' not in authentication_request:
        raise InvalidAuthenticationRequest('The request does not contain a nonce', authentication_request,
                                           oauth_error='invalid_request')


def init_authorization_state(app):
    sub_hash_salt = app.config['PROVIDER_SUBJECT_IDENTIFIER_HASH_SALT']
    authz_code_db = MongoWrapper(app.config['DB_URI'], 'se_leg_op', 'authz_codes')
    access_token_db = MongoWrapper(app.config['DB_URI'], 'se_leg_op', 'access_tokens')
    refresh_token_db = MongoWrapper(app.config['DB_URI'], 'se_leg_op', 'refresh_tokens')
    sub_db = MongoWrapper(app.config['DB_URI'], 'se_leg_op', 'subject_identifiers')
    return AuthorizationState(HashBasedSubjectIdentifierFactory(sub_hash_salt), authz_code_db, access_token_db,
                              refresh_token_db, sub_db)


def init_oidc_provider(app):
    with app.app_context():
        issuer = url_for('oidc_provider.index')[:-1]
        authentication_endpoint = url_for('oidc_provider.authentication_endpoint')
        jwks_uri = url_for('oidc_provider.jwks_uri')
        token_endpoint = url_for('oidc_provider.token_endpoint')
        userinfo_endpoint = url_for('oidc_provider.userinfo_endpoint')

    configuration_information = {
        'issuer': issuer,
        'authorization_endpoint': authentication_endpoint,
        'jwks_uri': jwks_uri,
        'token_endpoint': token_endpoint,
        'userinfo_endpoint': userinfo_endpoint,
        'scopes_supported': ['openid'],
        'response_types_supported': ['code', 'code id_token', 'code token', 'code id_token token'],  # code and hybrid
        'response_modes_supported': ['query', 'fragment'],
        'grant_types_supported': ['authorization_code', 'implicit'],
        'subject_types_supported': ['pairwise'],
        'token_endpoint_auth_methods_supported': ['client_secret_basic'],
        'claims_parameter_supported': True
    }

    clients_db = MongoWrapper(app.config['DB_URI'], 'se_leg_op', 'clients')
    userinfo_db = Userinfo(app.users)
    with open(app.config['PROVIDER_SIGNING_KEY']['PATH']) as f:
        key = f.read()
    signing_key = RSAKey(key=import_rsa_key(key), kid=app.config['PROVIDER_SIGNING_KEY']['KID'], alg='RS256')
    provider = Provider(signing_key, configuration_information, init_authorization_state(app), clients_db, userinfo_db)

    provider.authentication_request_validators.append(_request_contains_nonce)

    return provider


def oidc_provider_init_app(name=None, config=None):
    name = name or __name__
    app = Flask(name)
    app.config.from_envvar(SE_LEG_PROVIDER_SETTINGS_ENVVAR)
    if config:
        app.config.update(config)

    app.authn_requests = MongoWrapper(app.config['DB_URI'], 'se_leg_op', 'authn_requests')
    app.users = MongoWrapper(app.config['DB_URI'], 'se_leg_op', 'userinfo')

    logging.basicConfig(level=logging.DEBUG)

    from .views.oidc_provider import oidc_provider_views
    app.register_blueprint(oidc_provider_views)
    from .views.vetting_process import vetting_process_views
    app.register_blueprint(vetting_process_views)

    # Initialize the oidc_provider after views to be able to set correct urls
    app.provider = init_oidc_provider(app)

    return app
