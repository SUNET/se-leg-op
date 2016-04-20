import flask
import time
from flask.blueprints import Blueprint
from flask.globals import current_app
from flask.helpers import make_response
from oic.oic.message import AuthorizationRequest

from ...provider import should_fragment_encode
from .oidc_provider import deliver_response_to_redirect_uri
from .oidc_provider import extra_userinfo

vetting_process_views = Blueprint('vetting_process', __name__, url_prefix='')


@vetting_process_views.route('/vetting-result', methods=['POST'])
def vetting_result():
    identity = flask.request.form['identity']
    nonce = flask.request.form['nonce']
    auth_req_data = current_app.authn_requests.pop(nonce, None)
    if auth_req_data is None:
        current_app.logger.debug('Received unknown nonce \'%s\'', nonce)
        return make_response('Unknown nonce', 400)

    auth_req = AuthorizationRequest(**auth_req_data)
    # TODO store necessary user info
    current_app.users[identity] = {'vetting_time': time.time()}

    authn_response = current_app.provider.authorize(AuthorizationRequest().from_dict(auth_req), identity,
                                                    extra_userinfo)
    response_url = authn_response.request(auth_req['redirect_uri'], should_fragment_encode(auth_req))
    return deliver_response_to_redirect_uri(response_url)


@vetting_process_views.route('/update-user-data', methods=['POST'])
def update_user_data():
    raise NotImplementedError()
