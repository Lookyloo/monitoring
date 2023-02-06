#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import hashlib
import logging
import time
import json

from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import List

import plotly.graph_objects as go  # type: ignore
from plotly.subplots import make_subplots  # type: ignore

from pylookyloo import Lookyloo


class CaptureProject():

    def __init__(self, project_name: str, projects_root: Path=Path('projects'), lookyloo_url: str='https://lookyloo.circl.lu/'):
        self.logger = logging.getLogger(f'{self.__class__.__name__}')
        self.lookyloo = Lookyloo(lookyloo_url)
        if not self.lookyloo.is_up:
            raise Exception(f'Unable to reach lookyloo: {lookyloo_url}')
        self.project_dir = projects_root / project_name
        list_file = self.project_dir / 'list.txt'
        if not list_file.exists():
            raise Exception(f'No list available in project {project_name} - {list_file}')

        with list_file.open() as f:
            self.urls = set(line.strip() for line in f.readlines())

        if not self.urls:
            raise Exception(f'No URLs in the list file: {list_file}')

    def trigger_captures(self):
        captures = [(url, self.lookyloo.enqueue(url, listing=True, quiet=True)) for url in self.urls]
        while captures:
            waiting = []
            for url, uuid in captures:
                status = self.lookyloo.get_status(uuid)
                if status['status_code'] in [0, 2]:
                    # Capture queued or ongoing
                    waiting.append((url, uuid))
                    self.logger.info(f'Still waiting on {url} / {uuid}.')
                elif status['status_code'] == -1:
                    # uuid not present, the capture failed
                    self.logger.warning(f'Capture for {url} failed.')
                else:  # status_code == 1, capture done
                    info = self.lookyloo.get_info(uuid)
                    h = hashlib.md5(url.encode()).hexdigest()
                    capture_dir = self.project_dir / h
                    capture_dir.mkdir(parents=True, exist_ok=True)
                    with (capture_dir / info['capture_time']).open('w') as f:
                        f.write(uuid)
                    self.logger.info(f'{url} is done - {uuid}.')
            if waiting:
                time.sleep(5)
            captures = waiting

    def make_stats(self):
        for url in self.urls:
            h = hashlib.md5(url.encode()).hexdigest()
            if not (self.project_dir / h).exists():
                continue
            out_json = self.project_dir / h / 'all_stats.json'
            if out_json.exists():
                out_json.unlink()
            to_save = {}
            for capture in sorted((self.project_dir / h).glob('*')):
                with capture.open() as f:
                    uuid = f.read()
                    stats = self.lookyloo.get_capture_stats(uuid)
                    to_save[capture.name] = stats
                    to_save[capture.name]['uuid'] = uuid
            with out_json.open('w') as f:
                json.dump(to_save, f, indent=2)

    def prepare_graphs(self):
        figures = []
        for url in self.urls:
            h = hashlib.md5(url.encode()).hexdigest()
            if not ((self.project_dir / h).exists() and (self.project_dir / h / 'all_stats.json').exists()):
                continue
            with (self.project_dir / h / 'all_stats.json').open() as f:
                stats = json.load(f)

            timestamps = list(stats.keys())
            uuids: List[str] = []

            fig = make_subplots(
                rows=2, cols=1,
                shared_xaxes=True,
                vertical_spacing=0.03,
                specs=[[{"type": "scatter"}],
                       [{"type": "table"}]]
            )

            y_lists = defaultdict(list)
            uuids = []
            for ts, ts_data in stats.items():
                for data_name, data_value in ts_data.items():
                    if data_name == 'uuid':
                        # This won't be displayed in the plot but used for a link
                        uuids.append(f'<a href="{self.lookyloo.root_url}/tree/{data_value}">Open capture on lookyloo</a>')
                    else:
                        if data_name == 'total_load_time':
                            # convert to seconds
                            t = datetime.strptime(data_value, "%H:%M:%S.%f")
                            data_value = timedelta(hours=t.hour, minutes=t.minute, seconds=t.second, microseconds=t.microsecond).total_seconds()
                        y_lists[data_name].append(data_value)

            for name, l in y_lists.items():
                if name == "total_size_responses":
                    fig.add_trace(go.Scatter(x=timestamps, y=l,
                                             mode='lines+markers',
                                             name=name,
                                             yaxis="y2"))
                else:
                    fig.add_trace(go.Scatter(x=timestamps, y=l,
                                             mode='lines+markers',
                                             name=name))

            fig.add_trace(
                go.Table(
                    header=dict(
                        values=["Date", "Lookyloo link", "Total Hostnames", "Total URLs", "Total Unique URLs", "Total Unique Hostnames", "Total cookies sent", "Total cookies Received", "Tree Depth", "Redirects to landing page", "Cumulative Load time (in seconds)", "Total size"],
                        font=dict(size=10),
                        align="left"
                    ),
                    cells=dict(
                        values=[timestamps, uuids] + [value for value in y_lists.values()],
                        align="left")
                ),
                row=2, col=1
            )

            fig.update_layout(
                yaxis=dict(
                    title="Unique stuff",
                    titlefont=dict(
                        color="#1f77b4"
                    ),
                    tickfont=dict(
                        color="#1f77b4"
                    )
                ),
                yaxis2=dict(
                    title="Responses size",
                    titlefont=dict(
                        color="#ff7f0e"
                    ),
                    tickfont=dict(
                        color="#ff7f0e"
                    ),
                    anchor="x",
                    overlaying="y",
                    side="right"
                )
            )
            fig.update_layout(hovermode="x unified")
            fig.update_layout(
                title_text=url,
                height=1200
            )
            figures.append(fig)
        return figures
