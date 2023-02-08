#!/usr/bin/env python3

from importlib.metadata import version
from flask import Flask, request
from flask_restx import Api, Resource, fields  # type: ignore

from webmonitoring.webmonitoring import Monitoring

from .helpers import get_secret_key
from .proxied import ReverseProxied

app: Flask = Flask(__name__)

app.wsgi_app = ReverseProxied(app.wsgi_app)  # type: ignore

app.config['SECRET_KEY'] = get_secret_key()

api = Api(app, title='Web Monitoring API',
          description='API to query the web monitoring.',
          version=version('webmonitoring'))

monitoring: Monitoring = Monitoring()


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
        monit = request.get_json(force=True)  # type: ignore
        print(monit)
        monitor_uuid = monitoring.monitor(monit['capture_settings'], frequency=monit['frequency'],
                                          expire_at=monit.get('expire_at'), collection=monit.get('collection'))
        # TODO: get that somewhere else.
        monitoring.update_monitoring_queue()
        monitoring.process_monitoring_queue()
        return monitor_uuid
