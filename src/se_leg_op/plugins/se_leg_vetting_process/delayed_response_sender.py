
from se_leg_op.service.views.oidc_provider import extra_userinfo
from se_leg_op.service.response_sender import deliver_response_task

from oic.oic.message import AuthorizationRequest
from pyop.util import should_fragment_encode
from se_leg_op.service.app import oidc_provider_init_app
from se_leg_op.service.vetting_process_tools import create_authentication_response


def delayed_authn_response_task(nonce, bearer_token, identity, app_config=None):
    """
    :param nonce: Nonce from QR data
    :type nonce: str
    :param bearer_token: Token from QR data
    :type bearer_token: str
    :param identity: Users identity
    :type identity: str
    :param app_config: Minimal config for making tests work
    :type app_config:
    :return:
    :rtype:
    """
    auth_req = AuthorizationRequest(**nonce)
    app = oidc_provider_init_app(__name__, config=app_config)
    with app.app_context():
        authn_response = create_authentication_response(auth_req, identity, extra_userinfo)
    response_url = authn_response.request(auth_req['redirect_uri'], should_fragment_encode(auth_req))
    headers = {'Authorization': 'Bearer {}'.format(bearer_token)}
    deliver_response_task(response_url, headers=headers)
