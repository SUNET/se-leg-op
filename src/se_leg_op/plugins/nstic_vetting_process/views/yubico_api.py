# -*- coding: utf-8 -*-

from flask import Blueprint, json, current_app, request, abort
from time import time
from functools import wraps


__author__ = 'lundberg'

yubico_api_v1_views = Blueprint('yubico_api_v1_views', __name__, url_prefix='/yubico/api/v1')


def authorize(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.authorization:
            username = request.authorization['username']
            password = request.authorization['password']
            current_app.logger.info('Trying to authorize {}'.format(username))
            try:
                secret = False
                if username in current_app.config['YUBICO_API_CLIENTS']:
                    client = current_app.provider.clients[username]
                    secret = client['client_secret']
                    kwargs['username'] = username
                elif username in current_app.config['YUBICO_API_ADMINS']:
                    admin = current_app.config['YUBICO_API_ADMINS'][username]
                    secret = admin['secret']
                    kwargs['username'] = 'admin'
                if secret and secret == password:
                    return f(*args, **kwargs)
                current_app.logger.error('Authorization failure: Wrong password for {}'.format(username))
            except KeyError as e:
                current_app.logger.error('Authorization failure: KeyError {}'.format(e))
        abort(401)
    return decorated_function


def create_json_response(data, status=200):
    response = current_app.response_class(
        response=json.dumps(data),
        status=status,
        mimetype='application/json'
    )
    return response


def create_db_state(state_id, data):
    """
    :param state_id: State id
    :type state_id: str
    :param data: Incoming state data
    :type data: dict
    """
    # Don't let the client change the original keys
    # userinfo is not part of the state document in the db
    for ro_key in ['created', 'state', 'client_id', 'user_id', 'userinfo']:
        data.pop(ro_key, None)
    state = {
        'created': time(),
        'state': state_id
    }
    if data:
        state.update(data)
    # Save state
    current_app.yubico_states[state['state']] = state


def update_db_state(state, data):
    """
    :param state: State from db
    :type state: dict
    :param data: Incoming state data
    :type data: dict
    """
    # Don't let the client change the original keys
    # userinfo is not part of the state document in the db
    for ro_key in ['created', 'state', 'client_id', 'user_id', 'userinfo']:
        data.pop(ro_key, None)
    # Update state
    if data:
        state.update(data)
        # Save state
        current_app.yubico_states[state['state']] = state


def update_db_userinfo(user_id, data):
    """
    :param user_id: user_id
    :type user_id: str
    :param data: data to update userinfo with
    :type data: dict
    """
    if data:
        userinfo = current_app.users[user_id]
        userinfo.update(data)
        current_app.users[user_id] = userinfo


@yubico_api_v1_views.route('/states', methods=['GET'])
@authorize
def get_states(username):
    current_app.logger.info('Client {} requested vetting states'.format(username))
    result = {'states': []}
    i = 0

    if username == 'admin':
        # Allow all states for admin
        states = current_app.yubico_states.items()
    else:
        states = current_app.yubico_states.get_documents_by_attr('data.client_id', username, False)

    for key, state in states:
        i += 1
        user_id = state.get('user_id')
        try:
            userinfo = current_app.users[user_id]
        except KeyError:
            current_app.logger.warning('userinfo {} missing for state {}'.format(user_id, state['state']))
            userinfo = None
        state['userinfo'] = userinfo
        result['states'].append(state)
    current_app.logger.debug('Returned {} vetting states for client {}'.format(i, username))
    return create_json_response(result)


@yubico_api_v1_views.route('/states/<string:state_id>', methods=['GET'])
@authorize
def get_state(username, state_id):
    current_app.logger.info('Client {} requested vetting state {}'.format(username, state_id))
    try:
        state = current_app.yubico_states[state_id]
        # Check if the client is allowed to fetch the state
        if username != 'admin' and username != state['client_id']:
            raise KeyError
    except KeyError:
        current_app.logger.warning('Client {} tried to get unknown state {}'.format(username, state_id))
        return create_json_response({'status': 'Not Found', 'errors': [state_id]}, 404)

    user_id = state.get('user_id')
    try:
        userinfo = current_app.users[user_id]
    except KeyError:
        current_app.logger.warning('userinfo {} missing for state {}'.format(user_id, state['state']))
        userinfo = None
    state['userinfo'] = userinfo
    return create_json_response(state)


@yubico_api_v1_views.route('/states', methods=['POST', 'PUT', 'PATCH'])
@authorize
def update_states(username):
    data = request.get_json()
    if not data:
        return create_json_response({'status': 'Bad Request', 'error': 'No data'}, status=400)
    current_app.logger.debug('data: {}'.format(data))

    if username == 'admin':
        # Allow all states for admin
        states = dict(current_app.yubico_states.items())
    else:
        states = dict(current_app.yubico_states.get_documents_by_attr('data.client_id', username, False))

    errors = []
    try:
        for item in data['states']:
            # Only let the client modify it's own states
            if item['state'] not in states:
                errors.append(item['state'])
                continue
            state = states[item['state']]
            update_db_userinfo(state['user_id'], item.get('userinfo', dict()))
            update_db_state(state, item)
        current_app.logger.info('Client {} updated states'.format(username))
    except KeyError as e:
        current_app.logger.error('{}'.format(e))
        return create_json_response({'status': 'Bad Request', 'error': '{}'.format(e)}, status=400)
    if errors:
        current_app.logger.warning('Client {} tried to update unknown states {}'.format(username, errors))
        return create_json_response({'status': 'Unprocessable Entity', 'errors': errors}, 422)
    return create_json_response({'status': 'Accepted'}, 202)


@yubico_api_v1_views.route('/states/<string:state_id>', methods=['POST', 'PUT', 'PATCH'])
@authorize
def update_state(username, state_id):
    data = request.get_json()
    try:
        state = current_app.yubico_states[state_id]
        # Check if the client is allowed to update the state
        if username != 'admin' and username != state['client_id']:
            current_app.logger.warning('Client {} tried to update unknown state {}'.format(username, state_id))
            return create_json_response({'status': 'Not Found', 'errors': [state_id]}, 404)
    except KeyError:
        # Create new state
        create_db_state(state_id, data)
        return create_json_response({'status': 'Created'}, 201)
    # Update state and userinfo
    update_db_userinfo(state['user_id'], data.get('userinfo', dict()))
    update_db_state(state, data)
    current_app.logger.info('Client {} updated vetting state {}'.format(username, state_id))
    return create_json_response({'status': 'Accepted'}, 202)


@yubico_api_v1_views.route('/states/<string:state_id>', methods=['DELETE'])
@authorize
def delete_state(username, state_id):
    try:
        state = current_app.yubico_states[state_id]
        # Check if the client is allowed to delete the state
        if username != 'admin' and username != state['client_id']:
            raise KeyError
    except KeyError:
        current_app.logger.warning('Client {} tried to delete unknown state {}'.format(username, state_id))
        return create_json_response({'status': 'Not Found', 'errors': [state_id]}, 404)
    del current_app.users[state['user_id']]
    del current_app.yubico_states[state_id]
    return create_json_response({'status': 'OK'})
