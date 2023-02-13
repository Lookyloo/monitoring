#!/usr/bin/env python3

import logging

from uuid import uuid4

from datetime import datetime, timedelta
from typing import MutableMapping, Any, Optional, Union, List, Dict, Tuple

from pylookyloo import Lookyloo
from redis import ConnectionPool, Redis
from redis.connection import UnixDomainSocketConnection

from .default import get_config, get_socket_path
from .helpers import get_useragent_for_requests


class Monitoring():

    def __init__(self) -> None:
        self.logger = logging.getLogger(f'{self.__class__.__name__}')
        self.logger.setLevel(get_config('generic', 'loglevel'))

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

    @property
    def redis(self):
        return Redis(connection_pool=self.redis_pool)

    def check_redis_up(self):
        return self.redis.ping()

    def get_collections(self):
        return self.redis.smembers('collections')

    def get_monitored(self, collection: Optional[str]=None) -> List[Tuple[str, Dict[str, Any]]]:
        key = 'monitored'
        if collection:
            key = f'{key}:{collection}'
        to_return = []
        for m in self.redis.sscan_iter(key):
            details = {'status': (True, '')}
            if self.redis.zcard(f'{m}:captures') < 2:
                details['status'] = (False, 'Cannot compare, not enough captures.')
            to_return.append((m, details))
        return to_return

    def get_monitored_settings(self, monitor_uuid: str) -> Dict[str, Any]:
        return self.redis.hgetall(f'{monitor_uuid}:capture_settings')

    def monitor(self, capture_settings: MutableMapping[str, Any], /, frequency: str, *,
                expire_at: Optional[Union[datetime, str, int, float]]=None, collection: Optional[str]=None):
        monitor_uuid = str(uuid4())
        p = self.redis.pipeline()
        p.hset(f'{monitor_uuid}:capture_settings', mapping=capture_settings)
        p.set(f'{monitor_uuid}:frequency', frequency)
        if collection:
            p.set(f'{monitor_uuid}:collection', collection)
            p.sadd('collections', collection)
            p.sadd(f'monitored:{collection}', monitor_uuid)
        if expire_at:
            if isinstance(expire_at, (str, int, float)):
                _expire = float(expire_at)
            if isinstance(expire_at, datetime):
                _expire = expire_at.timestamp()
            if _expire < datetime.now().timestamp():
                # The expiration time is in the past.
                raise Exception('Expiration time in the past.')
            p.set(f'{monitor_uuid}:expire', _expire)
        p.sadd('monitored', monitor_uuid)
        p.execute()
        return monitor_uuid

    def compare_captures(self, monitor_uuid: str):
        if not self.redis.exists(f'{monitor_uuid}:captures'):
            raise Exception(f'Monitoring UUID unknown: {monitor_uuid}')
        # Get all the capture UUIDs from most recent to oldest
        capture_uuids = self.redis.zrevrangebyscore(f'{monitor_uuid}:captures', '+Inf', 0, withscores=True)
        if len(capture_uuids) < 2:
            raise Exception(f'Only one capture, nothing to compare ({monitor_uuid})')
        # NOTE For now, only compare the last two captures, later we will compare more
        compare_result = self.lookyloo.compare_captures(capture_uuids[0][0], capture_uuids[1][0])
        return compare_result

    def update_monitoring_queue(self):
        for monitor_uuid in self.redis.smembers('monitored'):
            if self.redis.zscore('monitoring_queue', monitor_uuid):
                # don't do anything, let the next capture happen
                # FIXME: Probaby change that if the interval is shorter than the next capture (=> changed)
                continue
            _expire = self.redis.get(f'{monitor_uuid}:expire')
            if _expire and datetime.now().timestamp() < _expire:
                # Monitoring expired
                self.redis.smove('monitored', 'expired_monitored', monitor_uuid)
                continue
            freq = self.redis.get(f'{monitor_uuid}:frequency')
            # WIP, few hardcoded values - later, use the cron format too
            next_run = {monitor_uuid: 0.0}
            if not self.redis.exists(f'{monitor_uuid}:captures'):
                next_run[monitor_uuid] = datetime.now().timestamp()
            else:
                if freq == 'hourly':
                    next_run[monitor_uuid] = (datetime.now() + timedelta(hours=1)).timestamp()
                elif freq == 'daily':
                    next_run[monitor_uuid] = (datetime.now() + timedelta(days=1)).timestamp()
                else:
                    raise Exception(f'Frequency unsupported: {freq}')
            self.redis.zadd('monitoring_queue', mapping=next_run)

    def process_monitoring_queue(self):
        now = datetime.now().timestamp()
        for monitor_uuid in self.redis_zpoprangebyscore(keys=['monitoring_queue'], args=[now]):
            settings = self.redis.hgetall(f'{monitor_uuid}:capture_settings')
            new_capture_uuid = self.lookyloo.enqueue(**settings, quiet=True)
            if not self.redis.zscore(f'{monitor_uuid}:captures', new_capture_uuid):
                self.redis.zadd(f'{monitor_uuid}:captures', mapping={new_capture_uuid: now})
