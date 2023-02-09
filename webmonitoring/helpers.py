#!/usr/bin/env python3

from functools import cache
from importlib.metadata import version


@cache
def get_useragent_for_requests():
    return f'WebMonitoring / {version("webmonitoring")}'
