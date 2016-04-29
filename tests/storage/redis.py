import atexit
import random
import subprocess
import time

import redis


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
