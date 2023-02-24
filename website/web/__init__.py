#!/usr/bin/env python3

import json

from importlib.metadata import version
from typing import Dict, Any, List, Tuple, Optional

from flask import Flask, request, render_template
from flask_bootstrap import Bootstrap5  # type: ignore
from flask_restx import Api, Resource, fields  # type: ignore

from webmonitoring.exceptions import TimeError
from webmonitoring.webmonitoring import Monitoring

from .helpers import get_secret_key
from .proxied import ReverseProxied

app: Flask = Flask(__name__)
app.wsgi_app = ReverseProxied(app.wsgi_app)  # type: ignore

app.config['SECRET_KEY'] = get_secret_key()

Bootstrap5(app)
app.config['BOOTSTRAP_SERVE_LOCAL'] = True
app.config['SESSION_COOKIE_NAME'] = 'lookyloo_webmonitoring'
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
app.debug = False

monitoring: Monitoring = Monitoring()


@app.route('/', methods=['GET'])
def index():
    if request.method == 'HEAD':
        # Just returns ack if the webserver is running
        return 'Ack'
    return render_template('index.html')


@app.route('/collections', methods=['GET'])
def collections():
    collections = monitoring.get_collections()
    return render_template('collections.html', collections=collections)


def _index(index_type: str, collection: Optional[str]):
    if index_type == 'monitored':
        to_index = monitoring.get_monitored(collection=collection)
    elif index_type == 'expired':
        to_index = monitoring.get_expired(collection=collection)
    else:
        raise Exception(f'Can only be monitored or expired, not {index_type}')
    return render_template(f'{index_type}.html', monitored_index=to_index)


@app.route('/monitored', methods=['GET'])
@app.route('/monitored/<string:collection>', methods=['GET'])
def monitored(collection: Optional[str]=None):
    return _index('monitored', collection)


@app.route('/expired', methods=['GET'])
@app.route('/expired/<string:collection>', methods=['GET'])
def expired(collection: Optional[str]=None):
    return _index('expired', collection)


@app.route('/changes_tracking/<string:monitor_uuid>', methods=['GET'])
def changes_tracking(monitor_uuid: str):
    details = monitoring.get_monitored_details(monitor_uuid)
    if details['number_captures'] < 2:
        changes = {}
    else:
        changes = monitoring.compare_captures(monitor_uuid)
    return render_template('changes_tracking.html',
                           details=details,
                           changes=changes,
                           changes_txt=json.dumps(changes, indent=2))


api = Api(app, title='Web Monitoring API',
          description='API to query the web monitoring.',
          doc='/doc/',
          version=version('webmonitoring'))


@api.route('/redis_up')
@api.doc(description='Check if redis is up and running')
class RedisUp(Resource):

    def get(self):
        return monitoring.check_redis_up()


capture_settings_mapping = api.model('CaptureSettings', {
    'url': fields.Url(description="The URL to capture")
})


monitor_fields_post = api.model('MonitorFieldsPost', {
    'capture_settings': fields.Nested(capture_settings_mapping, description="The capture settings"),
    'frequency': fields.String('The frequency of the capture'),
    'expire_at': fields.String('When the monitoring expires, empty means never'),
    'collection': fields.String('The name of the collection')
})


@api.route('/monitor')
@api.doc(description='Add a capture in the monitoring')
class Monitor(Resource):

    @api.doc(body=monitor_fields_post)
    def post(self):
        monit: Dict[str, Any] = request.get_json(force=True)
        monitor_uuid = monitoring.monitor(monit['capture_settings'], frequency=monit['frequency'],
                                          expire_at=monit.get('expire_at'), collection=monit.get('collection'))
        return monitor_uuid


@api.route('/stop_monitor/<string:monitor_uuid>')
@api.doc(description='Stop monitoring',
         params={'monitor_uuid': 'The monitoring UUID'})
class StopMonitor(Resource):

    def post(self, monitor_uuid: str):
        return monitoring.stop_monitor(monitor_uuid)


@api.route('/json/changes/<string:monitor_uuid>')
@api.doc(description='Compare the captures for a specific monitored entry',
         params={'monitor_uuid': 'The monitoring UUID'})
class JsonCompare(Resource):

    def get(self, monitor_uuid: str):
        return monitoring.compare_captures(monitor_uuid)


@api.route('/json/collections')
@api.doc(description='Get the list of existing collections')
class JsonCollections(Resource):

    def get(self):
        return list(monitoring.get_collections())


@api.route('/json/monitored',
           doc={'description': 'Get the list of monitored UUIDs'})
@api.route('/json/monitored/<string:collection>',
           doc={'description': 'Get the list of monitored UUIDs, for a specific collection',
                'collection': 'Limit the response to a specific collection'})
class JsonMonitored(Resource):

    def get(self, collection: Optional[str]=None):
        return monitoring.get_monitored(collection)


@api.route('/json/expired',
           doc={'description': 'Get the list of expired UUIDs'})
@api.route('/json/expired/<string:collection>',
           doc={'description': 'Get the list of expired UUIDs, for a specific collection',
                'collection': 'Limit the response to a specific collection'})
class JsonExpired(Resource):

    def get(self, collection: Optional[str]=None):
        return monitoring.get_expired(collection)
