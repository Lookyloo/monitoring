#!/usr/bin/env python3

from functools import cache
from importlib.metadata import version

from .default import get_homedir


@cache
def get_useragent_for_requests():
    return f'WebMonitoring / {version("webmonitoring")}'


@cache
def get_email_template() -> str:
    with (get_homedir() / 'config' / 'email.tmpl').open() as f:
        return f.read()
