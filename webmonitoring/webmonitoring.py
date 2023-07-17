#!/usr/bin/env python3

import json
import logging

from uuid import uuid4

from datetime import datetime, timedelta
from email.message import EmailMessage
from logging import LoggerAdapter
from typing import Any, Optional, Union, List, Dict, Tuple, TypedDict, MutableMapping, overload, Mapping

from cron_converter import Cron  # type: ignore
from pylookyloo import Lookyloo, CaptureSettings
from redis import ConnectionPool, Redis
from redis.connection import UnixDomainSocketConnection

from .default import get_config, get_socket_path
from .exceptions import TimeError, CannotCompare, InvalidSettings, UnknownUUID, AlreadyExpired, AlreadyMonitored
from .helpers import get_useragent_for_requests, get_email_template
from .mail import Mail


class CompareSettings(TypedDict, total=False):
    '''The settings that can be passed to the compare method on lookyloo side to filter out some differences'''

    ressources_ignore_domains: Optional[List[str]]
    ressources_ignore_regexes: Optional[List[str]]


class NotificationSettings(TypedDict, total=False):
    '''The notification settings for a monitoring'''

    email: str


class MonitorSettings(TypedDict, total=False):
    capture_settings: CaptureSettings
    frequency: str
    expire_at: Optional[Union[str, datetime]]
    collection: Optional[str]
    compare_settings: Optional[CompareSettings]
    notification: Optional[NotificationSettings]

    # This UUID is used when we trigger an update on the settings
    monitor_uuid: Optional[str]


class MonitoringInstanceSettings(TypedDict):
    min_frequency: int
    max_captures: int
    force_expire: bool


def for_redis(data: Optional[Mapping]) -> Optional[Dict[str, Union[int, str, float]]]:
    if not data:
        return None
    mapping_capture: Dict[str, Union[float, int, str]] = {}
    for key, value in data.items():
        if value in [None, '']:
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

    def get_expired_entries(self, collection: Optional[str]=None) -> List[Dict[str, Any]]:
        return self._get_index('expired', collection)

    def get_monitored_entries(self, collection: Optional[str]=None) -> List[Dict[str, Any]]:
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
        to_return['capture_settings'] = self.get_capture_settings(monitor_uuid)
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

    def get_capture_settings(self, monitor_uuid: str) -> CaptureSettings:
        return self.redis.hgetall(f'{monitor_uuid}:capture_settings')

    def get_monitor_settings(self, monitor_uuid: str) -> MonitorSettings:
        to_return: MonitorSettings = {'frequency': self.redis.get(f'{monitor_uuid}:frequency'),
                                      'capture_settings': self.get_capture_settings(monitor_uuid)}
        if expire_at := self.redis.get(f'{monitor_uuid}:expire'):
            try:
                to_return['expire_at'] = datetime.fromtimestamp(float(expire_at))
            except Exception:
                to_return['expire_at'] = expire_at
        if collection := self.redis.get(f'{monitor_uuid}:collection'):
            to_return['collection'] = collection
        if compare_settings := self.get_compare_settings(monitor_uuid):
            to_return['compare_settings'] = compare_settings
        if notification := self.redis.hgetall(f'{monitor_uuid}:notification'):
            to_return['notification'] = notification
        return to_return

    def get_compare_settings(self, monitor_uuid: str) -> CompareSettings:
        return {k: json.loads(v)
                for k, v in self.redis.hgetall(f'{monitor_uuid}:compare_settings').items()}  # type: ignore

    def _next_run_from_cron(self, cron_string: str, /) -> datetime:
        try:
            cron = Cron(cron_string)
            reference = datetime.now()
            schedule = cron.schedule(reference)
            return schedule.next()
        except ValueError as e:
            raise TimeError(f'Invalid cron format: {cron_string} - {e}')

    @overload
    def monitor(self, *, monitor_settings: MonitorSettings) -> str:
        """Start a new monitoring with a MonitorSettings object"""
        ...

    @overload
    def monitor(self, *, capture_settings: CaptureSettings, frequency: str,
                expire_at: Optional[Union[datetime, str, int, float]]=None,
                collection: Optional[str]=None, compare_settings: Optional[CompareSettings]=None,
                notification: Optional[NotificationSettings]=None) -> str:
        """Start a new monitoring with individual parameters"""
        ...

    @overload
    def monitor(self, *, monitor_uuid: str, capture_settings: Optional[CaptureSettings]=None,
                frequency: Optional[str]=None,
                expire_at: Optional[Union[datetime, str, int, float]]=None,
                collection: Optional[str]=None, compare_settings: Optional[CompareSettings]=None,
                notification: Optional[NotificationSettings]=None) -> str:
        """Update an existing monitoring with individual parameters"""
        ...

    def monitor(self, *, capture_settings: Optional[CaptureSettings]=None,
                frequency: Optional[str]=None,
                expire_at: Optional[Union[datetime, str, int, float]]=None,
                collection: Optional[str]=None,
                compare_settings: Optional[CompareSettings]=None,
                notification: Optional[NotificationSettings]=None,
                monitor_settings: Optional[MonitorSettings]=None,
                monitor_uuid: Optional[str]=None) -> str:
        is_update = False
        if monitor_uuid:
            if self.redis.exists(f'{monitor_uuid}:captures'):
                is_update = True
            else:
                raise UnknownUUID(f'Monitoring UUID unknown: {monitor_uuid}')
        else:
            monitor_uuid = str(uuid4())
        logger = MonitoringLogAdapter(self.master_logger, {'uuid': monitor_uuid})
        if monitor_settings:
            capture_settings = monitor_settings.get('capture_settings')
            frequency = monitor_settings.get('frequency')
            expire_at = monitor_settings.get('expire_at')
            collection = monitor_settings.get('collection')
            compare_settings = monitor_settings.get('compare_settings')
            notification = monitor_settings.get('notification')

        if not capture_settings and not is_update:
            logger.critical('No capture settings')
            raise InvalidSettings('The capture settings are missing.')
        if not frequency and not is_update:
            logger.critical('No frequency')
            raise InvalidSettings('The frequency missing.')

        p = self.redis.pipeline()
        if capture_settings:
            p.hset(f'{monitor_uuid}:capture_settings', mapping=for_redis(capture_settings))
        if frequency:
            p.set(f'{monitor_uuid}:frequency', frequency.lower())

        if collection:
            p.set(f'{monitor_uuid}:collection', collection)
            p.sadd('collections', collection)
            p.sadd(f'collections:{collection}', monitor_uuid)
            logger.info(f'Capture added to monitoring in collection "{collection}"')
        elif is_update:
            p.delete(f'{monitor_uuid}:collection')
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
            _compare_settings = for_redis(compare_settings)
            if _compare_settings:
                p.hset(f'{monitor_uuid}:compare_settings', mapping=_compare_settings)
            if is_update and _compare_settings is not None:
                # the keys with empty values have been removed
                # On update, we want to remove them from the hash too
                if to_delete := compare_settings.keys() - _compare_settings.keys():
                    p.hdel(f'{monitor_uuid}:compare_settings', *to_delete)

        if notification:
            _notification = for_redis(notification)
            if _notification:
                p.hset(f'{monitor_uuid}:notification', mapping=_notification)
            if is_update and _notification is not None:
                # the keys with empty values have been removed
                # On update, we want to remove them from the hash too
                if to_delete := notification.keys() - _notification.keys():
                    p.hdel(f'{monitor_uuid}:notification', *to_delete)

        p.sadd('monitored', monitor_uuid)
        p.execute()
        return monitor_uuid

    def stop_monitor(self, monitor_uuid: str) -> bool:
        if not self.redis.exists(f'{monitor_uuid}:captures'):
            raise UnknownUUID(f'Monitoring UUID unknown: {monitor_uuid}')
        if not self.redis.sismember('monitored', monitor_uuid):
            raise AlreadyExpired(f'{monitor_uuid} is already expired')
        p = self.redis.pipeline()
        p.set(f'{monitor_uuid}:expire', datetime.now().timestamp())
        p.zrem('monitoring_queue', monitor_uuid)
        p.execute()
        return True

    def start_monitor(self, monitor_uuid: str) -> bool:
        if not self.redis.exists(f'{monitor_uuid}:captures'):
            raise UnknownUUID(f'Monitoring UUID unknown: {monitor_uuid}')
        if self.redis.sismember('monitored', monitor_uuid):
            raise AlreadyMonitored(f'{monitor_uuid} is already monitored')
        p = self.redis.pipeline()
        p.delete(f'{monitor_uuid}:expire')
        p.smove('expired', 'monitored', monitor_uuid)
        p.hincrby(f'{monitor_uuid}:capture_settings', 'restarted')
        p.execute()
        return True

    def compare_captures(self, monitor_uuid: str) -> Dict[str, Any]:
        if not self.redis.exists(f'{monitor_uuid}:captures'):
            raise CannotCompare(f'Monitoring UUID unknown: {monitor_uuid}')
        # Get all the capture UUIDs from most recent to oldest
        capture_uuids = self.redis.zrevrangebyscore(f'{monitor_uuid}:captures', '+Inf', 0, withscores=True)
        if len(capture_uuids) < 2:
            raise CannotCompare(f'Only one capture, nothing to compare ({monitor_uuid})')
        # NOTE For now, only compare the last two captures, later we will compare more
        if compare_settings := self.get_compare_settings(monitor_uuid):
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
            elif self.force_expire:
                _nb_restarts = self.redis.hget(f'{monitor_uuid}:capture_settings', 'restarted')
                if not _nb_restarts:
                    nb_restarts = 1
                else:
                    nb_restarts = int(_nb_restarts) + 1
                if self.redis.zcard(f'{monitor_uuid}:captures') > self.max_captures * nb_restarts:
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
            settings['listing'] = False  # force the monitored capture our of the lookyloo index page
            logger.info('Trigering capture')
            new_capture_uuid = self.lookyloo.submit(capture_settings=settings, quiet=True)
            if not self.redis.zscore(f'{monitor_uuid}:captures', new_capture_uuid):
                self.redis.zadd(f'{monitor_uuid}:captures', mapping={new_capture_uuid: now})
                # Check if the monitoring settings have notification settings
                if self.redis.exists(f'{monitor_uuid}:notification'):
                    # Flag it for the notification mechanism
                    self.redis.hset('to_notify', mapping={monitor_uuid: new_capture_uuid})

    def process_notifications(self):
        # Iterate over monitoring that requires a notification
        for monitor_uuid, capture_uuid in self.redis.hgetall('to_notify').items():
            logger = MonitoringLogAdapter(self.master_logger, {'uuid': monitor_uuid})
            capture_status = self.lookyloo.get_status(capture_uuid)
            if 'status_code' not in capture_status:
                logger.critical(f'Incorrect response from Lookyloo: {capture_status}, retry later.')
                continue
            # check if capture is done
            if capture_status['status_code'] in [0, 2]:
                logger.info(f'Capture ongoing ({capture_uuid}), retry later.')
            elif capture_status['status_code'] == -1:
                logger.warning(f'Unable to find capture {capture_uuid} in lookyloo, discarding.')
                self.redis.hdel('to_notify', monitor_uuid)
            elif capture_status['status_code'] == 1:
                logger.debug(f'Capture {capture_uuid} done, trigering notification.')
                self.redis.hdel('to_notify', monitor_uuid)
                self.notify(monitor_uuid)
            else:
                logger.critical(f'Incorrect response from Lookyloo: {capture_status}, retry later.')

    def prepare_notification_mail(self, mail_to: str, monitor_uuid: str, comparison_results: Dict[str, Any]) -> EmailMessage:
        logger = MonitoringLogAdapter(self.master_logger, {'uuid': monitor_uuid})
        capture_settings = self.get_capture_settings(monitor_uuid)
        captured_url = capture_settings['url']
        email_config = get_config('generic', 'email')
        msg = EmailMessage()
        msg['Subject'] = f"Monitoring notification for {captured_url} ({monitor_uuid})"
        msg['From'] = email_config['from']
        # if isinstance(mail_to, str):
        msg['To'] = mail_to
        # else:
        #     msg['To'] = ', '.join(mail_to)
        details = ''
        # For not, only add differences in the mail
        for compare_key, compare_details in comparison_results.items():
            if compare_key in ['root_url', 'final_url', 'final_hostname', 'final_status_code', 'error']:
                if isinstance(compare_details['details'], (str, int)):
                    # no difference
                    continue
                details += f'  * {compare_details["message"]} - Before: {compare_details["details"][0]} / After {compare_details["details"][1]}\n'
            elif compare_key == 'redirects':
                details += '  * Redirects:\n'
                if not isinstance(compare_details['length']['details'], int):
                    details += f'  * {compare_details["length"]["message"]} - Before: {compare_details["length"]["details"][0]} / After {compare_details["length"]["details"][1]}\n'
                for node_info in compare_details['nodes']:
                    for node_key, node_details in node_info.items():
                        if isinstance(node_details['details'], (str, int)):
                            # no difference
                            continue
                        details += f'    * {node_details["message"]} - Before: {node_details["details"][0]} / After {node_details["details"][1]}\n'

            elif compare_key == 'ressources':
                if compare_details.get('left'):
                    details += '  * Ressources only in old capture:\n'
                    details += '\n    * '.join(compare_details['left'])
                    details += '\n'
                if compare_details.get('right'):
                    details += '  * Ressources only in new capture:\n'
                    details += '\n    * '.join(compare_details['right'])
                    details += '\n'
            else:
                # unexpected key name
                pass
        body = get_email_template()
        try:
            recipient = msg['To'].addresses[0].display_name if msg['To'].addresses[0].display_name else msg['To'].addresses[0]
        except Exception as e:
            recipient = 'Not a valid address'
            logger.critical(f'Unable to get a recipient email address: {mail_to} - {e}')
        body = body.format(recipient=recipient,
                           sender=msg['From'].addresses[0].display_name,
                           monitor_uuid=monitor_uuid,
                           captured_url=captured_url,
                           domain=email_config["domain"],
                           details_differences=details)
        msg.set_content(body)
        msg.add_attachment(json.dumps(comparison_results, indent=2), filename='comparison.json')
        return msg

    def notify(self, monitor_uuid: str):
        logger = MonitoringLogAdapter(self.master_logger, {'uuid': monitor_uuid})
        notification_settings: NotificationSettings
        if notification_settings := self.redis.hgetall(f'{monitor_uuid}:notification'):
            if not notification_settings.get('email'):
                logger.warning('Email to notify missing in notification settings, skip.')
                return

            try:
                results = self.compare_captures(monitor_uuid)
                if 'different' in results and results['different'] is False:
                    # No difference, do not notify.
                    logger.info('No differences between the last two captures, skip notification.')
                    return
                mail = self.prepare_notification_mail(
                    mail_to=notification_settings['email'],
                    monitor_uuid=monitor_uuid,
                    comparison_results=results)
                if Mail.send(mail):
                    logger.debug('Notification sent successfully')
                else:
                    logger.debug('Unable to send notification')
            except CannotCompare as e:
                logger.warning(f'Unable to run a comparison: {e}')
        else:
            logger.warning('No notification settings, ignore.')
