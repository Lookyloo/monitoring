#!/usr/bin/env python3

import json

from importlib.metadata import version
from typing import Dict, Any, List, Tuple, Optional

from flask import Flask, request, render_template
from flask_bootstrap import Bootstrap5  # type: ignore
from flask_restx import Api, Resource, fields  # type: ignore

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


@app.route('/collections', methods=['GET'])
def collections():
    collections = monitoring.get_collections()
    return render_template('collections.html', collections=collections)


@app.route('/monitored', methods=['GET'])
@app.route('/monitored/<string:collection>', methods=['GET'])
def monitored(collection: Optional[str]=None):
    if request.method == 'HEAD':
        # Just returns ack if the webserver is running
        return 'Ack'
    monitored_index: List[Tuple[str, str, Dict[str, Any]]] = []
    for uuid, details in monitoring.get_monitored(collection=collection):
        settings = monitoring.get_monitored_settings(uuid)
        monitored_index.append((uuid, settings['url'], details))
    return render_template('monitored.html', monitored_index=monitored_index)


@app.route('/changes_tracking/<string:monitor_uuid>', methods=['GET'])
def changes_tracking(monitor_uuid: str):
    changes = monitoring.compare_captures(monitor_uuid)
    return render_template('changes_tracking.html',
                           changes=changes,
                           changes_txt=json.dumps(changes, indent=2))


api = Api(app, title='Web Monitoring API',
          description='API to query the web monitoring.',
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
        monit: Dict[str, Any] = request.get_json(force=True)  # type: ignore
        monitor_uuid = monitoring.monitor(monit['capture_settings'], frequency=monit['frequency'],
                                          expire_at=monit.get('expire_at'), collection=monit.get('collection'))
        return monitor_uuid


@api.route('/json/<string:monitor_uuid>')
@api.doc(description='Compare the captures for a specific monitored entry',
         params={'monitor_uuid': 'The monitoring UUID'})
class Compare(Resource):

    def get(self, monitor_uuid: str):
        return monitoring.compare_captures(monitor_uuid)
