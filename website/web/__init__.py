#!/usr/bin/env python3

import json

from datetime import datetime
from importlib.metadata import version
from typing import Dict, Any, Optional, get_type_hints

from flask import Flask, request, render_template, flash, redirect, url_for
from flask_bootstrap import Bootstrap5  # type: ignore
import flask_login  # type: ignore
from flask_restx import Api, Resource, fields, abort  # type: ignore
from flask_wtf import FlaskForm  # type: ignore
from werkzeug.security import check_password_hash
from wtforms import Form, StringField, DateTimeField, FieldList, FormField, EmailField, validators  # type: ignore

from webmonitoring.exceptions import CannotCompare, AlreadyExpired, AlreadyMonitored, UnknownUUID, InvalidSettings, TimeError
from webmonitoring.webmonitoring import Monitoring, CompareSettings, NotificationSettings

from .helpers import get_secret_key, build_users_table, User, load_user_from_request
from .proxied import ReverseProxied

app: Flask = Flask(__name__)
app.wsgi_app = ReverseProxied(app.wsgi_app)  # type: ignore

app.config['SECRET_KEY'] = get_secret_key()

Bootstrap5(app)
app.config['BOOTSTRAP_SERVE_LOCAL'] = True
app.config['SESSION_COOKIE_NAME'] = 'lookyloo_webmonitoring'
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
app.debug = False

# Auth stuff
login_manager = flask_login.LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def user_loader(username):
    if username not in build_users_table():
        return None
    user = User()
    user.id = username
    return user


@login_manager.request_loader
def _load_user_from_request(request):
    return load_user_from_request(request)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return '''
               <form action='login' method='POST'>
                <input type='text' name='username' id='username' placeholder='username'/>
                <input type='password' name='password' id='password' placeholder='password'/>
                <input type='submit' name='submit'/>
               </form>
               '''

    username = request.form['username']
    users_table = build_users_table()
    if username in users_table and check_password_hash(users_table[username]['password'], request.form['password']):
        user = User()
        user.id = username
        flask_login.login_user(user)
        flash(f'Logged in as: {flask_login.current_user.id}', 'success')
    else:
        flash(f'Unable to login as: {username}', 'error')

    return redirect(url_for('index'))


@app.route('/logout')
@flask_login.login_required
def logout():
    flask_login.logout_user()
    flash('Successfully logged out.', 'success')
    return redirect(url_for('index'))


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
        to_index = monitoring.get_monitored_entries(collection=collection)
    elif index_type == 'expired':
        to_index = monitoring.get_expired_entries(collection=collection)
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


class CompareSettingsForm(Form):
    ressources_ignore_domains = FieldList(StringField('Domain'), label="Domains to ignore in comparison", min_entries=5)
    ressources_ignore_regexes = FieldList(StringField('Regex'), label="Regexes in URLs to ignore in comparison", min_entries=5)


class NotificationForm(Form):
    email = EmailField('Email to notify')


class MonitoringForm(FlaskForm):
    frequency = StringField(label='Capture frequency', validators=[validators.DataRequired()])
    expire_at = DateTimeField('Expire monitoring at', validators=[validators.Optional()])
    collection = StringField('Collection of the monitored URL')
    compare_settings = FormField(CompareSettingsForm)
    notification = FormField(NotificationForm)


@app.route('/changes_tracking/<string:monitor_uuid>', methods=['GET', 'POST'])
def changes_tracking(monitor_uuid: str):
    form = MonitoringForm()
    if form.validate_on_submit():
        if not flask_login.current_user.is_authenticated:
            flash("You must be authenticated to change the settings.", 'error')
        else:
            # Cleanup compare settings
            compare_settings: CompareSettings = {}
            for k in get_type_hints(CompareSettings).keys():
                if values := form.compare_settings.data[k]:
                    # Empty list is fine, it is how we remove all entries
                    compare_settings[k] = [x for x in set(values) if x != '']  # type: ignore

            notification: NotificationSettings = {}
            for k in get_type_hints(NotificationSettings).keys():
                notification[k] = form.notification.data[k]  # type: ignore
            try:
                monitoring.monitor(
                    monitor_uuid=monitor_uuid,
                    frequency=form.frequency.data if form.frequency.data else None,
                    expire_at=form.expire_at.data if form.expire_at.data else None,
                    collection=form.collection.data if form.collection.data else None,
                    compare_settings=compare_settings if compare_settings else None,
                    notification=notification if notification else None
                )
            except Exception as e:
                flash(str(e), 'error')

    elif form.errors:
        for key, message in form.errors.items():
            flash(f'{key}: {message}', 'error')

    monitor_settings = monitoring.get_monitor_settings(monitor_uuid)
    form = MonitoringForm(data=monitor_settings)
    details = monitoring.get_monitored_details(monitor_uuid)
    if details['number_captures'] < 2:
        changes = {}
    else:
        changes = monitoring.compare_captures(monitor_uuid)
    return render_template('changes_tracking.html',
                           monitor_uuid=monitor_uuid,
                           monitoring_form=form,
                           details=details,
                           changes=changes,
                           changes_txt=json.dumps(changes, indent=2))


# ################## API ##################

# Query API
authorizations = {
    'apikey': {
        'type': 'apiKey',
        'in': 'header',
        'name': 'Authorization'
    }
}

api = Api(app, title='Web Monitoring API',
          description='API to query the web monitoring.',
          doc='/doc/',
          version=version('webmonitoring'),
          authorizations=authorizations)


def api_auth_check(method):
    if flask_login.current_user.is_authenticated or load_user_from_request(request):
        return method
    abort(403, 'Authentication required.')


token_request_fields = api.model('AuthTokenFields', {
    'username': fields.String(description="Your username", required=True),
    'password': fields.String(description="Your password", required=True),
})


@api.route('/json/get_token')
@api.doc(description='Get the API token required for authenticated calls')
class AuthToken(Resource):

    users_table = build_users_table()

    @api.param('username', 'Your username')
    @api.param('password', 'Your password')
    def get(self):
        username: Optional[str] = request.args['username'] if request.args.get('username') else None
        password: Optional[str] = request.args['password'] if request.args.get('password') else None
        if username and password and username in self.users_table and check_password_hash(self.users_table[username]['password'], password):
            return {'authkey': self.users_table[username]['authkey']}
        return {'error': 'User/Password invalid.'}, 401

    @api.doc(body=token_request_fields)
    def post(self):
        auth: Dict = request.get_json(force=True)
        if 'username' in auth and 'password' in auth:  # Expected keys in json
            if (auth['username'] in self.users_table
                    and check_password_hash(self.users_table[auth['username']]['password'], auth['password'])):
                return {'authkey': self.users_table[auth['username']]['authkey']}
        return {'error': 'User/Password invalid.'}, 401


@api.route('/redis_up')
@api.doc(description='Check if redis is up and running')
class RedisUp(Resource):

    def get(self):
        return monitoring.check_redis_up()


capture_settings_mapping = api.model('CaptureSettings', {
    'url': fields.String(description="The URL to capture")
})

compare_settings_mapping = api.model('CompareSettings', {
    'ressources_ignore_domains': fields.List(fields.String(description="A domain to ignore")),
    'ressources_ignore_regexes': fields.List(fields.String(description="A regex to match anything in a URL"))
})

notification_mapping = api.model('NotificationSettings', {
    'email': fields.String(description="The email to notify.")
})

monitor_fields_post = api.model('MonitorFieldsPost', {
    'capture_settings': fields.Nested(capture_settings_mapping, description="The capture settings"),
    'frequency': fields.String('The frequency of the capture'),
    'expire_at': fields.String('When the monitoring expires, empty means never'),
    'collection': fields.String('The name of the collection'),
    'compare_settings': fields.Nested(compare_settings_mapping, description="The settings to compare captures."),
    'notification': fields.Nested(notification_mapping, description="The notification settings.")
})


@api.route('/monitor')
@api.doc(description='Add a capture in the monitoring. The capture_settings key accepts all the settings supported by lookyloo.')
class Monitor(Resource):

    @api.doc(body=monitor_fields_post)
    def post(self):
        monit: Dict[str, Any] = request.get_json(force=True)
        monitor_uuid = monitoring.monitor(capture_settings=monit['capture_settings'], frequency=monit['frequency'],
                                          expire_at=monit.get('expire_at'), collection=monit.get('collection'),
                                          compare_settings=monit.get('compare_settings'),
                                          notification=monit.get('notification'))
        return monitor_uuid


@api.route('/settings_monitor/<string:monitor_uuid>')
@api.doc(description='Get the settings of a monitoring',
         params={'monitor_uuid': 'The monitoring UUID'})
class SettingsMonitor(Resource):

    def get(self, monitor_uuid: str):
        settings = monitoring.get_monitor_settings(monitor_uuid)
        if 'expire_at' in settings and settings['expire_at'] is not None and isinstance(settings['expire_at'], datetime):
            settings['expire_at'] = settings['expire_at'].timestamp()
        return settings


@api.route('/update_monitor/<string:monitor_uuid>')
@api.doc(description='Change the settings of a monitoring',
         params={'monitor_uuid': 'The monitoring UUID'},
         security='apikey')
class UpdateMonitor(Resource):
    method_decorators = [api_auth_check]

    @api.doc(body=monitor_fields_post)
    def post(self, monitor_uuid: str):
        monit: Dict[str, Any] = request.get_json(force=True)
        try:
            monitor_uuid = monitoring.monitor(monitor_uuid=monitor_uuid,
                                              capture_settings=monit.get('capture_settings'),
                                              frequency=monit.get('frequency'),
                                              expire_at=monit.get('expire_at'),
                                              collection=monit.get('collection'),
                                              compare_settings=monit.get('compare_settings'),
                                              notification=monit.get('notification'))
            return monitor_uuid
        except (UnknownUUID, InvalidSettings, TimeError) as e:
            return {'message': str(e)}


@api.route('/stop_monitor/<string:monitor_uuid>')
@api.doc(description='Stop monitoring',
         params={'monitor_uuid': 'The monitoring UUID'},
         security='apikey')
class StopMonitor(Resource):
    method_decorators = [api_auth_check]

    def post(self, monitor_uuid: str):
        try:
            return monitoring.stop_monitor(monitor_uuid)
        except (UnknownUUID, AlreadyExpired) as e:
            return {'message': str(e)}


@api.route('/start_monitor/<string:monitor_uuid>')
@api.doc(description='Start monitoring',
         params={'monitor_uuid': 'The monitoring UUID'},
         security='apikey')
class StartMonitor(Resource):
    method_decorators = [api_auth_check]

    def post(self, monitor_uuid: str):
        try:
            return monitoring.start_monitor(monitor_uuid)
        except (UnknownUUID, AlreadyMonitored) as e:
            return {'message': str(e)}


@api.route('/json/changes/<string:monitor_uuid>')
@api.doc(description='Compare the captures for a specific monitored entry',
         params={'monitor_uuid': 'The monitoring UUID'})
class JsonCompare(Resource):

    def get(self, monitor_uuid: str):
        try:
            return monitoring.compare_captures(monitor_uuid)
        except CannotCompare as e:
            return {'error': str(e)}


@api.route('/json/collections')
@api.doc(description='Get the list of existing collections')
class JsonCollections(Resource):

    def get(self):
        return list(monitoring.get_collections())


monitor_field_response = api.model('MonitorFieldResponse', {
    'uuid': fields.String(),
    'capture_settings': fields.Nested(capture_settings_mapping),
    'next_capture': fields.DateTime(),
    'last_capture': fields.DateTime(),
    'number_captures': fields.Integer(),
})


@api.route('/json/monitored',
           doc={'description': 'Get the list of monitored UUIDs'})
@api.route('/json/monitored/<string:collection>',
           doc={'description': 'Get the list of monitored UUIDs, for a specific collection',
                'collection': 'Limit the response to a specific collection'})
class JsonMonitored(Resource):

    @api.marshal_with(monitor_field_response, skip_none=True)
    def get(self, collection: Optional[str]=None):
        return monitoring.get_monitored_entries(collection)


@api.route('/json/expired',
           doc={'description': 'Get the list of expired UUIDs'})
@api.route('/json/expired/<string:collection>',
           doc={'description': 'Get the list of expired UUIDs, for a specific collection',
                'collection': 'Limit the response to a specific collection'})
class JsonExpired(Resource):

    @api.marshal_with(monitor_field_response, skip_none=True)
    def get(self, collection: Optional[str]=None):
        return monitoring.get_expired_entries(collection)


@api.route('/json/settings')
@api.doc(description='Get generic settings for the monitoring instance')
class JsonSettings(Resource):

    def get(self):
        return monitoring.settings()
