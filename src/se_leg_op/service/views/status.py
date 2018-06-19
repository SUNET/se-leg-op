# -*- coding: utf-8 -*-

from flask import Blueprint
from flask import current_app
from flask import jsonify
import redis
import redis.sentinel

__author__ = 'lundberg'

status_views = Blueprint('status', __name__, url_prefix='/status')


def _check_mongo():
    db = current_app.authn_requests._db
    try:
        """
        From mongo_client.py:
        Starting with version 3.0 the :class:`MongoClient`
        constructor no longer blocks while connecting to the server or
        servers, and it no longer raises
        :class:`~pymongo.errors.ConnectionFailure` if they are
        unavailable, nor :class:`~pymongo.errors.ConfigurationError`
        if the user's credentials are wrong. Instead, the constructor
        returns immediately and launches the connection process on
        background threads. You can check if the server is available
        like this::

        from pymongo.errors import ConnectionFailure
        client = MongoClient()
        try:
            # The ismaster command is cheap and does not require auth.
            client.admin.command('ismaster')
        except ConnectionFailure:
            print("Server not available")
        """
        return db.get_connection().admin.command('ismaster')
    except Exception as exc:
        current_app.logger.warning('Mongodb health check failed: {}'.format(exc))
        return False


def _check_redis():
    config = current_app.config
    if config.get('REDIS_SENTINEL_HOSTS') and config.get('REDIS_SENTINEL_SERVICE_NAME'):
        _port = config['REDIS_PORT']
        _hosts = config['REDIS_SENTINEL_HOSTS']
        _name = config['REDIS_SENTINEL_SERVICE_NAME']
        host_port = [(x, _port) for x in _hosts]
        manager = redis.sentinel.Sentinel(host_port, socket_timeout=0.1)
        pool = redis.sentinel.SentinelConnectionPool(_name, manager)
    else:
        pool = redis.ConnectionPool.from_url(config['REDIS_URI'])
    try:
        client = redis.StrictRedis(connection_pool=pool)
        pong = client.ping()
        if pong:
            return True
        current_app.logger.warning('Redis health check failed: response == {!r}'.format(pong))
    except Exception as exc:
        current_app.logger.warning('Redis health check failed: {}'.format(exc))
        return False
    return False


@status_views.route('/healthy', methods=['GET'])
def health_check():
    res = {'status': 'STATUS_FAIL'}
    if not _check_mongo():
        res['reason'] = 'mongodb check failed'
        current_app.logger.warning('mongodb check failed')
    elif not _check_redis():
        res['reason'] = 'redis check failed'
        current_app.logger.warning('redis check failed')
    else:
        res['status'] = 'STATUS_OK'
        res['reason'] = 'Databases tested OK'
    return jsonify(res)
