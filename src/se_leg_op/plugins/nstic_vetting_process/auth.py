# -*- coding: utf-8 -*-

from flask import current_app, request, abort
from functools import wraps

__author__ = 'lundberg'


def authorize_client(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.authorization:
            client_id = request.authorization['username']
            password = request.authorization['password']
            current_app.logger.info('Trying to authorize {}'.format(client_id))
            try:
                client = current_app.provider.clients[client_id]
                if client['client_secret'] == password:
                    kwargs['client_id'] = client_id
                    return f(*args, **kwargs)
                current_app.logger.error('Authorization failure: Wrong password for {}'.format(client_id))
            except KeyError as e:
                current_app.logger.error('Authorization failure: KeyError {}'.format(e))
        abort(401)
    return decorated_function
