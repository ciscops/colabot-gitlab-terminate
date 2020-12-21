# -*- coding: utf-8 -*-

import os


class DefaultConfig:
    K8S_TOKEN = os.environ.get('K8S_TOKEN', 'xxxx')
    K8S_CLUSTER = os.environ.get('K8S_CLUSTER', 'abc12345')
    AWS_REGION = os.environ.get('AWS_REGION', 'us-east-1')
    AWS_KEY = os.environ.get('AWS_KEY', 'xxxx')
    AWS_SECRET = os.environ.get('AWS_SECRET', 'xxxx')
    AWX_SERVER = os.environ.get('AWX_SERVER', 'xxxx')
    AWX_USERNAME = os.environ.get('AWX_USERNAME', '')
    AWX_PASSWORD = os.environ.get('AWX_PASSWORD', '')
    AWX_TERMINATE_GITLAB_JOB = os.environ.get('AWX_TERMINATE_GITLAB_JOB', '')
    WEBEX_BEARER = os.environ.get('WEBEX_BEARER', '')
    DAYS_BEFORE_WARNINGS = os.environ.get('DAYS_BEFORE_WARNINGS', '7')
    DAYS_OF_WARNINGS = os.environ.get('DAYS_OF_WARNINGS', '7')

