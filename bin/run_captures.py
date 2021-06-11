#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import argparse

from lookyloo_monitoring.capture_project import CaptureProject

logging.basicConfig(format='%(asctime)s %(name)s %(levelname)s:%(message)s',
                    level=logging.INFO, datefmt='%I:%M:%S')


def main():
    parser = argparse.ArgumentParser(description='Capture a list of websites')
    parser.add_argument('--lookyloo_url', default="https://lookyloo.circl.lu/", help='URL of the lookyloo instance.')
    parser.add_argument('-p', '--project', required=True, help="Project to capture")
    parser.add_argument('--stats-only', default=False, action='store_true', help="Only get stats, no trigger")
    args = parser.parse_args()

    captures = CaptureProject(args.project, lookyloo_url=args.lookyloo_url)
    if not args.stats_only:
        captures.trigger_captures()
    captures.make_stats()
    graphes = captures.prepare_graphs()
    for g in graphes:
        g.show()


if __name__ == '__main__':
    main()
