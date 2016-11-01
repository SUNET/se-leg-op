import logging

import requests

logger = logging.getLogger(__name__)


def deliver_response_task(response_url, **kwargs):
    # type: (str) -> None
    """
    Make a synchronous request to the specified url.
    """
    try:
        resp = requests.get(response_url, **kwargs)
    except requests.exceptions.RequestException as e:
        logger.debug('could not deliver response to client', exc_info=True)
        raise

    if resp.status_code != 200:
        logger.debug('client responded with unexpected http status \'%s\' on response to redirect_uri \'%s\'',
                     resp.status_code, resp.request.url)
