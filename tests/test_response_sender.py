from unittest.mock import Mock
from urllib.parse import urlparse

import pytest
import responses
import rq
from oic.oic.message import AuthorizationResponse, AuthorizationRequest
from redis.client import StrictRedis

from se_leg_op.response_sender import deliver_response_task


@pytest.fixture
def message_queue():
    return rq.Queue(async=False, connection=Mock(spec=StrictRedis))


class TestDeliverResponse(object):
    @responses.activate
    def test_response_is_delivered(self, message_queue):
        redirect_uri = 'https://client.example.com/redirect_uri'
        responses.add(responses.GET, redirect_uri, status=200)
        authentication_response = AuthorizationResponse(code='foobar')
        message_queue.enqueue(deliver_response_task, authentication_response.request(redirect_uri))

        assert len(responses.calls) == 1
        parsed_url = urlparse(responses.calls[0].request.url)
        assert parsed_url[:3] == urlparse(redirect_uri)[:3]
        parsed_resp = AuthorizationResponse().from_urlencoded(parsed_url.query)
        assert parsed_resp == authentication_response
