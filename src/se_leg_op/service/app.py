import redis
import redis.sentinel
import rq
from flask.app import Flask
from flask.helpers import url_for
from jwkest.jwk import RSAKey, import_rsa_key
from pyop.authz_state import AuthorizationState
from pyop.exceptions import InvalidAuthenticationRequest
from pyop.provider import Provider
from pyop.subject_identifier import HashBasedSubjectIdentifierFactory
from pyop.userinfo import Userinfo
from redis.client import StrictRedis

from ..storage import OpStorageWrapper

SE_LEG_PROVIDER_SETTINGS_ENVVAR = 'SE_LEG_PROVIDER_SETTINGS'


def _request_contains_nonce(authentication_request):
    if 'nonce' not in authentication_request:
        raise InvalidAuthenticationRequest('The request does not contain a nonce', authentication_request,
                                           oauth_error='invalid_request')


def init_authorization_state(app):
    sub_hash_salt = app.config['PROVIDER_SUBJECT_IDENTIFIER_HASH_SALT']
    authz_code_db = OpStorageWrapper(app.config['DB_URI'], 'authz_codes')
    access_token_db = OpStorageWrapper(app.config['DB_URI'], 'access_tokens')
    refresh_token_db = OpStorageWrapper(app.config['DB_URI'], 'refresh_tokens')
    sub_db = OpStorageWrapper(app.config['DB_URI'], 'subject_identifiers')
    return AuthorizationState(HashBasedSubjectIdentifierFactory(sub_hash_salt), authz_code_db, access_token_db,
                              refresh_token_db, sub_db, refresh_token_lifetime=60 * 60 * 24 * 365)


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

    clients_db = OpStorageWrapper(app.config['DB_URI'], 'clients')
    userinfo_db = Userinfo(app.users)
    with open(app.config['PROVIDER_SIGNING_KEY']['PATH']) as f:
        key = f.read()
    signing_key = RSAKey(key=import_rsa_key(key), kid=app.config['PROVIDER_SIGNING_KEY']['KID'], alg='RS256')
    provider = Provider(signing_key, configuration_information, init_authorization_state(app), clients_db, userinfo_db)

    provider.authentication_request_validators.append(_request_contains_nonce)

    return provider


def init_authn_response_queue(config):
    if config.get('REDIS_SENTINEL_HOSTS') and config.get('REDIS_SENTINEL_SERVICE_NAME'):
        _port = config['REDIS_PORT']
        _hosts = config['REDIS_SENTINEL_HOSTS']
        _name = config['REDIS_SENTINEL_SERVICE_NAME']
        host_port = [(x, _port) for x in _hosts]
        manager = redis.sentinel.Sentinel(host_port, socket_timeout=0.1)
        pool = redis.sentinel.SentinelConnectionPool(_name, manager)
    else:
        pool = redis.ConnectionPool.from_url(config['REDIS_URI'])

    connection = StrictRedis(connection_pool=pool)
    return rq.Queue('authn_responses', connection=connection)


def oidc_provider_init_app(name=None, config=None):
    name = name or __name__
    app = Flask(name)
    app.config.from_envvar(SE_LEG_PROVIDER_SETTINGS_ENVVAR)
    if config:
        app.config.update(config)

    app.authn_requests = OpStorageWrapper(app.config['DB_URI'], 'authn_requests')
    app.users = OpStorageWrapper(app.config['DB_URI'], 'userinfo')
    app.authn_response_queue = init_authn_response_queue(app.config)

    from .views.oidc_provider import oidc_provider_views
    app.register_blueprint(oidc_provider_views)
    from .views.se_leg_vetting_process import se_leg_vetting_process_views
    app.register_blueprint(se_leg_vetting_process_views)

    # Initialize the oidc_provider after views to be able to set correct urls
    app.provider = init_oidc_provider(app)

    return app
