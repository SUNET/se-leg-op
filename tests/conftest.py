# -*- coding: utf-8 -*-
import atexit
import os
import random
import shutil
import subprocess
import tempfile
import time
import pkg_resources

import pymongo
import pytest
import redis

from se_leg_op.service.app import SE_LEG_PROVIDER_SETTINGS_ENVVAR, oidc_provider_init_app


class MongoTemporaryInstance(object):
    """Singleton to manage a temporary MongoDB instance

    Use this for testing purpose only. The instance is automatically destroyed
    at the end of the program.

    """
    _instance = None

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
            atexit.register(cls._instance.shutdown)
        return cls._instance

    def __init__(self):
        self._tmpdir = tempfile.mkdtemp()
        self._port = random.randint(40000, 50000)
        self._process = subprocess.Popen(['mongod', '--bind_ip', 'localhost',
                                          '--port', str(self._port),
                                          '--dbpath', self._tmpdir,
                                          '--nojournal', '--nohttpinterface',
                                          '--noauth', '--smallfiles',
                                          '--syncdelay', '0',
                                          '--nssize', '1', ],
                                         stdout=open('/tmp/mongo-temp.log', 'wb'),
                                         stderr=subprocess.STDOUT)

        # XXX: wait for the instance to be ready
        #      Mongo is ready in a glance, we just wait to be able to open a
        #      Connection.
        for i in range(10):
            time.sleep(0.2)
            try:
                self._conn = pymongo.MongoClient('localhost', self._port)
            except pymongo.errors.ConnectionFailure:
                continue
            else:
                break
        else:
            self.shutdown()
            assert False, 'Cannot connect to the mongodb test instance'

    @property
    def conn(self):
        return self._conn

    @property
    def port(self):
        return self._port

    def shutdown(self):
        if self._process:
            self._process.terminate()
            self._process.wait()
            self._process = None
            shutil.rmtree(self._tmpdir, ignore_errors=True)

    def get_uri(self):
        """
        Convenience function to get a mongodb URI to the temporary database.

        :return: URI
        """
        return 'mongodb://localhost:{port!s}'.format(port=self.port)


class RedisTemporaryInstance(object):
    """Singleton to manage a temporary Redis instance
    Use this for testing purpose only. The instance is automatically destroyed
    at the end of the program.
    """
    _instance = None

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
            atexit.register(cls._instance.shutdown)
        return cls._instance

    def __init__(self):
        self._port = random.randint(40000, 50000)
        self._process = subprocess.Popen(['redis-server',
                                          '--port', str(self._port),
                                          '--daemonize', 'no',
                                          '--bind', '0.0.0.0',
                                          '--databases', '1', ],
                                         stdout=open('/tmp/redis-temp.log', 'wb'),
                                         stderr=subprocess.STDOUT)

        for i in range(10):
            time.sleep(0.2)
            try:
                self._conn = redis.Redis('localhost', self._port, 0)
                self._conn.set('dummy', 'dummy')
            except redis.exceptions.ConnectionError:
                continue
            else:
                break
        else:
            self.shutdown()
            assert False, 'Cannot connect to the redis test instance'

    @property
    def conn(self):
        return self._conn

    @property
    def port(self):
        return self._port

    def shutdown(self):
        if self._process:
            self._process.terminate()
            self._process.wait()
            self._process = None

    def get_uri(self):
        """
        Convenience function to get a redis URI to the temporary database.
        :return: redis://host:port/dbname
        """
        return 'redis://localhost:{}/0'.format(self.port)


@pytest.yield_fixture
def mongodb_instance():
    tmp_db = MongoTemporaryInstance()
    yield tmp_db
    tmp_db.shutdown()


@pytest.yield_fixture
def redis_instance():
    tmp_redis = RedisTemporaryInstance()
    yield tmp_redis
    tmp_redis.shutdown()


@pytest.fixture
def config_envvar():
    return pkg_resources.resource_filename(__name__, './service/app_config.py')


@pytest.fixture
def inject_app(request, tmpdir, mongodb_instance, redis_instance, config_envvar):
    os.chdir(str(tmpdir))
    os.environ[SE_LEG_PROVIDER_SETTINGS_ENVVAR] = config_envvar
    config = {
        '_mongodb': mongodb_instance,
        'DB_URI': mongodb_instance.get_uri(),
        'REDIS_URI': redis_instance.get_uri(),
        'PREFERRED_URL_SCHEME': 'https'
    }
    extra_config = getattr(request.module, "EXTRA_CONFIG", {})
    config.update(extra_config)
    app = oidc_provider_init_app(__name__, config=config)
    app.authn_response_queue.empty()
    request.instance.app = app
