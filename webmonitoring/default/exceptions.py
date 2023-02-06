#!/usr/bin/env python3


class WebMonitoringException(Exception):
    pass


class MissingEnv(WebMonitoringException):
    pass


class CreateDirectoryException(WebMonitoringException):
    pass


class ConfigError(WebMonitoringException):
    pass
