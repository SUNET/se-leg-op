# -*- coding: utf-8 -*-

__author__ = 'lundberg'


# Adapted from https://stackoverflow.com/questions/18967441/add-a-prefix-to-all-flask-routes/36033627#36033627
class LocalhostMiddleware(object):

    def __init__(self, app, server_name=''):
        self.app = app
        if server_name is None:
            server_name = ''
        self.server_name = server_name

    def __call__(self, environ, start_response):
        # Handle localhost requests for health checks
        if environ.get('REMOTE_ADDR') == '127.0.0.1':
            environ['HTTP_HOST'] = self.server_name
        return self.app(environ, start_response)
