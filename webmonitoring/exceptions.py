#!/usr/bin/env python3

from .default import WebMonitoringException


class TimeError(WebMonitoringException):
    pass


class CannotCompare(WebMonitoringException):
    pass


class InvalidSettings(WebMonitoringException):
    pass


class UnknownUUID(WebMonitoringException):
    pass


class AlreadyMonitored(WebMonitoringException):
    pass


class AlreadyExpired(WebMonitoringException):
    pass
