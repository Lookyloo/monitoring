#!/usr/bin/env python3

import logging
import logging.config

from webmonitoring.default import AbstractManager, get_config
from webmonitoring.webmonitoring import Monitoring

logging.config.dictConfig(get_config('logging'))


class QueueManager(AbstractManager):

    def __init__(self, loglevel: int=logging.INFO):
        super().__init__(loglevel)
        self.script_name = 'monitoring_queue_manager'
        self.monitoring = Monitoring()

    def _to_run_forever(self):
        self.monitoring.update_monitoring_queue()
        self.monitoring.process_monitoring_queue()


def main():
    qm = QueueManager()
    qm.run(sleep_in_sec=10)


if __name__ == '__main__':
    main()
