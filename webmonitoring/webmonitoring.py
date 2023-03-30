#!/usr/bin/env python3

import json
import logging

from uuid import uuid4

from datetime import datetime, timedelta
from logging import LoggerAdapter
from typing import Any, Optional, Union, List, Dict, Tuple, TypedDict, MutableMapping, overload, Mapping

from cron_converter import Cron  # type: ignore
from pylookyloo import Lookyloo
from redis import ConnectionPool, Redis
from redis.connection import UnixDomainSocketConnection

from .default import get_config, get_socket_path
from .exceptions import TimeError, CannotCompare, InvalidSettings
from .helpers import get_useragent_for_requests


class CaptureSettings(TypedDict, total=False):
    '''The capture settings that can be passed to Lookyloo.'''

    url: Optional[str]
    document_name: Optional[str]
    document: Optional[str]
    browser: Optional[str]
    device_name: Optional[str]
    user_agent: Optional[str]
    proxy: Optional[Union[str, Dict[str, str]]]
    general_timeout_in_sec: Optional[int]
    cookies: Optional[List[Dict[str, Any]]]
    headers: Optional[Union[str, Dict[str, str]]]
    http_credentials: Optional[Dict[str, int]]
    viewport: Optional[Dict[str, int]]
    referer: Optional[str]

    listing: Optional[bool]


class CompareSettings(TypedDict, total=False):
    '''The settings that can be passed to the compare method on lookyloo side to filter out some differences'''

    ressources_ignore_domains: Optional[List[str]]
    ressources_ignore_regexes: Optional[List[str]]


class MonitorSettings(TypedDict, total=False):
    capture_settings: CaptureSettings
    frequency: str
    expire_at: Optional[str]
    collection: Optional[str]
    compare_settings: Optional[CompareSettings]


class MonitoringInstanceSettings(TypedDict):
    min_frequency: int
    max_captures: int
    force_expire: bool


def for_redis(data: Mapping) -> Dict[str, Union[int, str, float]]:
    mapping_capture: Dict[str, Union[float, int, str]] = {}
    for key, value in data.items():
        if value is None:
            continue
        if isinstance(value, bool):
            mapping_capture[key] = 1 if value else 0
        elif isinstance(value, (list, dict)):
            if value:
                mapping_capture[key] = json.dumps(value)
        elif isinstance(value, (int, float, str)):
            mapping_capture[key] = value
        else:
            raise Exception(f'Invalid type: {key} - {value}')
    return mapping_capture


class MonitoringLogAdapter(LoggerAdapter):
    """
    Prepend log entry with the UUID of the monitoring
    """
    def process(self, msg: str, kwargs: MutableMapping[str, Any]) -> Tuple[str, MutableMapping[str, Any]]:
        if self.extra:
            return '[%s] %s' % (self.extra['uuid'], msg), kwargs
        return msg, kwargs


class Monitoring():

    def __init__(self) -> None:
        self.master_logger = logging.getLogger(f'{self.__class__.__name__}')
        self.master_logger.setLevel(get_config('generic', 'loglevel'))

        self.redis_pool: ConnectionPool = ConnectionPool(connection_class=UnixDomainSocketConnection,
                                                         path=get_socket_path('cache'), decode_responses=True)
        self.lookyloo = Lookyloo(root_url=get_config('generic', 'lookyloo_url'),
                                 useragent=get_useragent_for_requests())

        # Pop a range of keys
        lua = """
        local key = KEYS[1]
        local now = ARGV[1]
        local elems = redis.call('ZRANGE', key, 0, now, 'BYSCORE')
        if #(elems) > 0 then
          redis.call('ZREM', key, unpack(elems))
        end
        return elems
        """
        self.redis_zpoprangebyscore = self.redis.register_script(lua)

        # If for any reason the config is broken, we want that to fail hard.
        self.min_frequency = int(get_config('generic', 'min_frequency'))
        self.max_captures = int(get_config('generic', 'max_captures'))
        self.force_expire = get_config('generic', 'force_expire')

    @property
    def redis(self):
        return Redis(connection_pool=self.redis_pool)

    def check_redis_up(self):
        return self.redis.ping()

    def settings(self) -> MonitoringInstanceSettings:
        return {'min_frequency': get_config('generic', 'min_frequency'),
                'max_captures': get_config('generic', 'max_captures'),
                'force_expire': get_config('generic', 'force_expire')
                }

    def get_collections(self):
        return self.redis.smembers('collections')

    def get_expired(self, collection: Optional[str]=None) -> List[Dict[str, Any]]:
        return self._get_index('expired', collection)

    def get_monitored(self, collection: Optional[str]=None) -> List[Dict[str, Any]]:
        return self._get_index('monitored', collection)

    def _get_index(self, key: str, collection: Optional[str]) -> List[Dict[str, Any]]:
        to_return = []
        for m in self.redis.sscan_iter(key):
            if collection and not self.redis.sismember(f'collections:{collection}', m):
                continue
            details = self.get_monitored_details(m)
            to_return.append(details)
        return to_return

    def get_monitored_details(self, monitor_uuid: str) -> Dict[str, Any]:
        to_return: Dict[str, Any] = {'uuid': monitor_uuid}
        to_return['capture_settings'] = self.get_monitored_settings(monitor_uuid)
        try:
            to_return['next_capture'] = self.get_next_capture(monitor_uuid)
        except TimeError:
            # No next capture set, expired
            pass
        if captures_ts := self.redis.zrevrangebyscore(f'{monitor_uuid}:captures', '+Inf', 0, withscores=True):
            to_return['last_capture'] = datetime.fromtimestamp(captures_ts[0][1])
            to_return['number_captures'] = len(captures_ts)
        else:
            to_return['number_captures'] = 0
        return to_return

    def get_monitored_settings(self, monitor_uuid: str) -> Dict[str, Any]:
        return self.redis.hgetall(f'{monitor_uuid}:capture_settings')

    def _next_run_from_cron(self, cron_string: str, /) -> datetime:
        try:
            cron = Cron(cron_string)
            reference = datetime.now()
            schedule = cron.schedule(reference)
            return schedule.next()
        except ValueError as e:
            raise TimeError(f'Invalid cron format: {cron_string} - {e}')

    @overload
    def monitor(self, /, *, monitor_settings: MonitorSettings) -> str:
        ...

    @overload
    def monitor(self, capture_settings: CaptureSettings, /, frequency: str, *,
                expire_at: Optional[Union[datetime, str, int, float]]=None,
                collection: Optional[str]=None, compare_settings: Optional[CompareSettings]=None) -> str:
        ...

    def monitor(self, capture_settings: Optional[CaptureSettings]=None,
                /, frequency: Optional[str]=None, *,
                expire_at: Optional[Union[datetime, str, int, float]]=None,
                collection: Optional[str]=None,
                compare_settings: Optional[CompareSettings]=None,
                monitor_settings: Optional[MonitorSettings]=None) -> str:

        monitor_uuid = str(uuid4())
        logger = MonitoringLogAdapter(self.master_logger, {'uuid': monitor_uuid})
        if monitor_settings:
            capture_settings = monitor_settings.get('capture_settings')
            frequency = monitor_settings.get('frequency')
            expire_at = monitor_settings.get('expire_at')
            collection = monitor_settings.get('collection')
            compare_settings = monitor_settings.get('compare_settings')

        if not capture_settings:
            logger.critical('No capture settings')
            raise InvalidSettings('The capture settings are missing.')
        if not frequency:
            logger.critical('No frequency')
            raise InvalidSettings('The frequency missing.')

        p = self.redis.pipeline()
        p.hset(f'{monitor_uuid}:capture_settings', mapping=for_redis(capture_settings))
        p.set(f'{monitor_uuid}:frequency', frequency)
        if collection:
            p.set(f'{monitor_uuid}:collection', collection)
            p.sadd('collections', collection)
            p.sadd(f'collections:{collection}', monitor_uuid)
            logger.info(f'Capture added to monitoring in collection "{collection}"')
        else:
            logger.info('Capture added to monitoring')

        if expire_at:
            if isinstance(expire_at, (str, int, float)):
                _expire = float(expire_at)
            if isinstance(expire_at, datetime):
                _expire = expire_at.timestamp()
            if _expire < datetime.now().timestamp():
                # The expiration time is in the past.
                raise TimeError('Expiration time in the past.')
            p.set(f'{monitor_uuid}:expire', _expire)

        if compare_settings:
            p.hset(f'{monitor_uuid}:compare_settings', mapping=for_redis(compare_settings))

        p.sadd('monitored', monitor_uuid)
        p.execute()
        return monitor_uuid

    def stop_monitor(self, monitor_uuid: str) -> bool:
        p = self.redis.pipeline()
        p.set(f'{monitor_uuid}:expire', datetime.now().timestamp())
        p.zrem('monitoring_queue', monitor_uuid)
        p.execute()
        return True

    def compare_captures(self, monitor_uuid: str):
        if not self.redis.exists(f'{monitor_uuid}:captures'):
            raise CannotCompare(f'Monitoring UUID unknown: {monitor_uuid}')
        # Get all the capture UUIDs from most recent to oldest
        capture_uuids = self.redis.zrevrangebyscore(f'{monitor_uuid}:captures', '+Inf', 0, withscores=True)
        if len(capture_uuids) < 2:
            raise CannotCompare(f'Only one capture, nothing to compare ({monitor_uuid})')
        # NOTE For now, only compare the last two captures, later we will compare more
        if _compare_settings := self.redis.hgetall(f'{monitor_uuid}:compare_settings'):
            compare_settings: CompareSettings = {}
            if ressources_ignore_domains := _compare_settings.get('ressources_ignore_domains'):
                compare_settings['ressources_ignore_domains'] = json.loads(ressources_ignore_domains)
            if ressources_ignore_regexes := _compare_settings.get('ressources_ignore_regexes'):
                compare_settings['ressources_ignore_regexes'] = json.loads(ressources_ignore_regexes)
            compare_result = self.lookyloo.compare_captures(capture_uuids[0][0], capture_uuids[1][0],
                                                            compare_settings=compare_settings)
        else:
            compare_result = self.lookyloo.compare_captures(capture_uuids[0][0], capture_uuids[1][0])
        return compare_result

    def update_monitoring_queue(self):
        for monitor_uuid in self.redis.smembers('monitored'):
            logger = MonitoringLogAdapter(self.master_logger, {'uuid': monitor_uuid})
            if existing_next_run := self.redis.zscore('monitoring_queue', monitor_uuid):
                # don't do anything, let the next capture happen
                # FIXME: Probaby change that if the interval is shorter than the next capture (=> changed)
                logger.debug(f'Already scheduled for {datetime.fromtimestamp(existing_next_run)}')
                continue
            _expire = self.redis.get(f'{monitor_uuid}:expire')
            if _expire and datetime.now().timestamp() > float(_expire):
                # Monitoring expired
                self.redis.smove('monitored', 'expired', monitor_uuid)
                logger.info('Expiration timestamp reached.')
                continue
            elif self.force_expire and self.redis.zcard(f'{monitor_uuid}:captures') > self.max_captures:
                # Force expire monitoring
                self.redis.smove('monitored', 'expired', monitor_uuid)
                logger.info('Maximum amount of captures reached, expire..')
                continue

            freq = self.redis.get(f'{monitor_uuid}:frequency')
            next_run = {monitor_uuid: 0.0}
            if not self.redis.exists(f'{monitor_uuid}:captures'):
                # if the capture was triggered recently enough on lookyloo, it will just pick the capture UUID
                next_run[monitor_uuid] = datetime.now().timestamp()
            else:
                if freq == 'hourly':
                    next_run[monitor_uuid] = (datetime.now() + timedelta(hours=1)).timestamp()
                elif freq == 'daily':
                    next_run[monitor_uuid] = (datetime.now() + timedelta(days=1)).timestamp()
                else:
                    try:
                        next_run[monitor_uuid] = self._next_run_from_cron(freq).timestamp()
                    except TimeError as e:
                        logger.warning(f'Invalid cron string: {e}')
                        next_run[monitor_uuid] = (datetime.now() + timedelta(seconds=self.min_frequency + 60)).timestamp()
                # Make sure the next capture is not scheduled for in a too short interval
                interval_next_capture = next_run[monitor_uuid] - datetime.now().timestamp()
                if interval_next_capture < self.min_frequency:
                    logger.warning(f'The next capture is scheduled too soon: {interval_next_capture}s. Minimal interval: {self.min_frequency}s.')
                    next_run[monitor_uuid] = (datetime.now() + timedelta(seconds=self.min_frequency)).timestamp()
            logger.info(f'Scheduled for {datetime.fromtimestamp(next_run[monitor_uuid])}')
            self.redis.zadd('monitoring_queue', mapping=next_run)

    def get_next_capture(self, monitor_uuid: str) -> datetime:
        ts = self.redis.zscore('monitoring_queue', monitor_uuid)
        if not ts:
            raise TimeError('No scheduled capture')
        return datetime.fromtimestamp(ts)

    def process_monitoring_queue(self):
        now = datetime.now().timestamp()
        for monitor_uuid in self.redis_zpoprangebyscore(keys=['monitoring_queue'], args=[now]):
            logger = MonitoringLogAdapter(self.master_logger, {'uuid': monitor_uuid})
            settings: CaptureSettings = self.redis.hgetall(f'{monitor_uuid}:capture_settings')
            settings['listing'] = False
            logger.info('Trigering capture')
            new_capture_uuid = self.lookyloo.submit(capture_settings=settings, quiet=True)
            if not self.redis.zscore(f'{monitor_uuid}:captures', new_capture_uuid):
                self.redis.zadd(f'{monitor_uuid}:captures', mapping={new_capture_uuid: now})
