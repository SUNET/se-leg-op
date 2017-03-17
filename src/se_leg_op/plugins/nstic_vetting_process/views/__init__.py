# -*- coding: utf-8 -*-

from .yubico_vetting import yubico_vetting_process_views
from .yubico_api import yubico_api_v1_views

__author__ = 'lundberg'


# flask registry hook
blueprints = [yubico_vetting_process_views, yubico_api_v1_views]
