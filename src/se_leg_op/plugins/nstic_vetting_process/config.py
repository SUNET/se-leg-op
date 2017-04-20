# -*- coding: utf-8 -*-
__author__ = 'lundberg'

# Configuration for the nstic_vetting_process plugin

## API CONFIG
YUBICO_API_CLIENTS = []
YUBICO_API_ADMINS = {}

## VETTING CONFIG

# Mobile verify service information
MOBILE_VERIFY_WSDL = None
MOBILE_VERIFY_USERNAME = None
MOBILE_VERIFY_PASSWORD = None
MOBILE_VERIFY_TENANT_REF = None

NSTIC_VETTING_PROCESS_AUDIT_LOG_FILE = '/var/log/op/plugins/nstic-vetting-process-audit.log'

NSTIC_VETTING_PROCESS_AUDIT_LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'nstic_vetting_process_audit': {
            'format': '%(asctime)s %(message)s',
            'datefmt': '%Y-%m-%dT%H:%M:%S%z'
        },
    },
    'handlers': {
        'nstic_vetting_process_audit': {
            'level': 'INFO',
            'formatter': 'nstic_vetting_process_audit',
            'class': 'logging.FileHandler',
            'filename': NSTIC_VETTING_PROCESS_AUDIT_LOG_FILE,
        },
    },
    'loggers': {
        'nstic_vetting_process_audit': {
            'handlers': ['nstic_vetting_process_audit'],
            'level': 'INFO',
            'propagate': False,
        },
    },
}
