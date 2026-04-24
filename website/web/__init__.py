#!/usr/bin/env python3

from __future__ import annotations

import json

from importlib.metadata import version
from datetime import datetime
from typing import Any

from flask import Flask, Request, request, render_template, flash, redirect, url_for, Response, make_response
from flask_bootstrap import Bootstrap5  # type: ignore
import flask_login  # type: ignore
from flask_restx import Api, Resource, fields, abort  # type: ignore
from flask_wtf import FlaskForm  # type: ignore
from werkzeug.security import check_password_hash
from werkzeug.wrappers.response import Response as WerkzeugResponse
from wtforms import Form, SelectField, StringField, DateTimeLocalField, FieldList, FormField, EmailField, BooleanField, validators  # type: ignore

from webmonitoring.default import get_config
from webmonitoring.exceptions import CannotCompare, AlreadyExpired, AlreadyMonitored, UnknownUUID, InvalidSettings, TimeError
from webmonitoring.webmonitoring import Monitoring

from .helpers import get_secret_key, build_users_table, User, load_user_from_request, sri_load
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


ignore_sri = get_config('generic', 'ignore_sri')


def get_sri(directory: str, filename: str) -> str:
    if ignore_sri:
        return ""
    sha512 = sri_load()[directory][filename]
    return f'integrity=sha512-{sha512}'


app.jinja_env.globals.update(get_sri=get_sri)


@login_manager.user_loader  # type: ignore[untyped-decorator]
def user_loader(username: str) -> User | None:
    if username not in build_users_table():
        return None
    user = User()
    user.id = username
    return user


@login_manager.request_loader  # type: ignore[untyped-decorator]
def _load_user_from_request(request: Request) -> User | None:
    return load_user_from_request(request)


@app.route('/login', methods=['GET', 'POST'])
def login() -> WerkzeugResponse | str | Response:
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
@flask_login.login_required  # type: ignore[untyped-decorator]
def logout() -> WerkzeugResponse:
    flask_login.logout_user()
    flash('Successfully logged out.', 'success')
    return redirect(url_for('index'))


monitoring: Monitoring = Monitoring()


@app.route('/', methods=['GET'])
def index() -> str:
    if request.method == 'HEAD':
        # Just returns ack if the webserver is running
        return 'Ack'
    return render_template('index.html')


@app.route('/collections', methods=['GET'])
def collections() -> str:
    collections: set[str] = monitoring.get_collections()
    if not flask_login.current_user.is_authenticated:
        # strip collections that are too long (unless you're logged in)
        collections = {c for c in collections if len(c) < 30}
    return render_template('collections.html', collections=collections)


def _index(index_type: str, collection: str | None) -> str:
    if index_type == 'monitored':
        to_index = monitoring.get_monitored_entries(collection=collection)
    elif index_type == 'expired':
        to_index = monitoring.get_expired_entries(collection=collection)
    else:
        raise Exception(f'Can only be monitored or expired, not {index_type}')
    return render_template(f'{index_type}.html', monitored_index=to_index)


@app.route('/monitored', methods=['GET'])
@app.route('/monitored/<string:collection>', methods=['GET'])
def monitored(collection: str | None=None) -> str:
    return _index('monitored', collection)


@app.route('/expired', methods=['GET'])
@app.route('/expired/<string:collection>', methods=['GET'])
def expired(collection: str | None=None) -> str:
    return _index('expired', collection)


class CompareSettingsForm(Form):  # type: ignore[misc]
    ressources_ignore_domains = FieldList(StringField('Domain'), label="Domains to ignore in comparison", min_entries=5)
    ressources_ignore_regexes = FieldList(StringField('Regex'), label="Regexes in URLs to ignore in comparison", min_entries=5)
    ignore_ips = BooleanField(label='Ignore IPs in comparison', description='Avoid flagging two captures are different when served on CDNs.')
    skip_failed_captures = BooleanField(label='Skip failed captures', description='Avoid attempting to compare two captures when one of them failed.')


class NotificationForm(Form):  # type: ignore[misc]
    email = EmailField('Email to notify')


class MonitoringForm(FlaskForm):  # type: ignore[misc]
    frequency = SelectField(label='Capture frequency', choices=[('daily', 'Daily'), ('hourly', 'Hourly')], validators=[validators.input_required()])
    expire_at = DateTimeLocalField('Expire monitoring at', validators=[validators.Optional()])
    collection = StringField('Collection of the monitored URL')
    never_expire = BooleanField(label='Never expire the monitoring', description='Avoid expiring the monitoring after a certain amount of captures.')
    compare_settings = FormField(CompareSettingsForm)
    notification = FormField(NotificationForm)


@app.route('/changes_tracking/<string:monitor_uuid>', methods=['GET', 'POST'])
def changes_tracking(monitor_uuid: str) -> str:
    form = MonitoringForm()
    if form.validate_on_submit():
        if not flask_login.current_user.is_authenticated:
            flash("You must be authenticated to change the settings.", 'error')
        else:
            try:
                monitoring.monitor(
                    monitor_uuid=monitor_uuid,
                    frequency=form.frequency.data if form.frequency.data else None,
                    expire_at=form.expire_at.data if form.expire_at.data else None,
                    never_expire=True if form.never_expire.data else False,
                    collection=form.collection.data if form.collection.data else None,
                    compare_settings=form.compare_settings.data if form.compare_settings.data else None,
                    notification=form.notification.data if form.notification.data else None
                )
            except Exception as e:
                flash(str(e), 'error')

    elif form.errors:
        for key, message in form.errors.items():
            flash(f'{key}: {message}', 'error')

    try:
        monitor_settings = monitoring.get_monitor_settings(monitor_uuid)
    except Exception:
        return f'Invalid uuid: {monitor_uuid}'
    data_to_render = monitor_settings.model_dump(exclude_none=True)
    if 'expire_at' in data_to_render:
        data_to_render['expire_at'] = datetime.fromtimestamp(data_to_render['expire_at'])
    form = MonitoringForm(data=data_to_render)
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


def api_auth_check(method):  # type: ignore[no-untyped-def]
    if flask_login.current_user.is_authenticated or load_user_from_request(request):
        return method
    abort(403, 'Authentication required.')


token_request_fields = api.model('AuthTokenFields', {
    'username': fields.String(description="Your username", required=True),
    'password': fields.String(description="Your password", required=True),
})


@api.route('/json/get_token')
@api.doc(description='Get the API token required for authenticated calls')
class AuthToken(Resource):  # type: ignore[misc]

    users_table = build_users_table()

    @api.param('username', 'Your username')  # type: ignore[untyped-decorator]
    @api.param('password', 'Your password')  # type: ignore[untyped-decorator]
    def get(self) -> Response:
        username: str | None = request.args['username'] if request.args.get('username') else None
        password: str | None = request.args['password'] if request.args.get('password') else None
        if username and password and username in self.users_table and check_password_hash(self.users_table[username]['password'], password):
            return make_response({'authkey': self.users_table[username]['authkey']})
        return make_response({'error': 'User/Password invalid.'}, 401)

    @api.doc(body=token_request_fields)  # type: ignore[untyped-decorator]
    def post(self) -> Response:
        auth: dict[str, Any] = request.get_json(force=True)
        if 'username' in auth and 'password' in auth:  # Expected keys in json
            if (auth['username'] in self.users_table
                    and check_password_hash(self.users_table[auth['username']]['password'], auth['password'])):
                return make_response({'authkey': self.users_table[auth['username']]['authkey']})
        return make_response({'error': 'User/Password invalid.'}, 401)


@api.route('/redis_up')
@api.doc(description='Check if redis is up and running')
class RedisUp(Resource):  # type: ignore[misc]

    def get(self) -> bool:
        return monitoring.check_redis_up()


capture_settings_mapping = api.model('CaptureSettings', {
    'url': fields.String(description="The URL to capture")
})

compare_settings_mapping = api.model('CompareSettings', {
    'ressources_ignore_domains': fields.List(fields.String(description="A domain to ignore")),
    'ressources_ignore_regexes': fields.List(fields.String(description="A regex to match anything in a URL")),
    'ignore_ips': fields.Boolean(False, description='Ignore IPs when comparing nodes. Avoid flagging two captures are different when served on CDNs.'),
    'skip_failed_captures': fields.Boolean(False, description='Skip failed captures. Avoid attempting to compare two captures when one of them failed.'),
})

notification_mapping = api.model('NotificationSettings', {
    'email': fields.String(description="The email to notify.")
})

monitor_fields_post = api.model('MonitorFieldsPost', {
    'capture_settings': fields.Nested(capture_settings_mapping, description="The capture settings"),
    'frequency': fields.String('The frequency of the capture'),
    'expire_at': fields.String('When the monitoring expires, empty means never'),
    'never_expire': fields.Boolean(label='Never expire the monitoring', description='Allows to keep the monitoring going forever.'),
    'collection': fields.String('The name of the collection'),
    'compare_settings': fields.Nested(compare_settings_mapping, description="The settings to compare captures."),
    'notification': fields.Nested(notification_mapping, description="The notification settings.")
})


@api.route('/monitor')
@api.doc(description='Add a capture in the monitoring. The capture_settings key accepts all the settings supported by lookyloo.')
class Monitor(Resource):  # type: ignore[misc]

    @api.doc(body=monitor_fields_post)  # type: ignore[untyped-decorator]
    def post(self) -> Response:
        monit: dict[str, Any] = request.get_json(force=True)
        try:
            monitor_uuid = monitoring.monitor(capture_settings=monit['capture_settings'], frequency=monit['frequency'],
                                              expire_at=monit.get('expire_at'), collection=monit.get('collection'),
                                              compare_settings=monit.get('compare_settings'),
                                              never_expire=monit.get('never_expire', False),
                                              notification=monit.get('notification'))
            return make_response(monitor_uuid)
        except TimeError:
            return make_response({'message': 'expire at is in the past, cannot monitor.'}, 403)


@api.route('/settings_monitor/<string:monitor_uuid>')
@api.doc(description='Get the settings of a monitoring',
         params={'monitor_uuid': 'The monitoring UUID'})
class SettingsMonitor(Resource):  # type: ignore[misc]

    def get(self, monitor_uuid: str) -> str:
        settings = monitoring.get_monitor_settings(monitor_uuid)
        return settings.model_dump_json(exclude_none=True)


@api.route('/update_monitor/<string:monitor_uuid>')
@api.doc(description='Change the settings of a monitoring',
         params={'monitor_uuid': 'The monitoring UUID'},
         security='apikey')
class UpdateMonitor(Resource):  # type: ignore[misc]
    method_decorators = [api_auth_check]

    @api.doc(body=monitor_fields_post)  # type: ignore[untyped-decorator]
    def post(self, monitor_uuid: str) -> Response:
        monit: dict[str, Any] = request.get_json(force=True)
        try:
            monitor_uuid = monitoring.monitor(monitor_uuid=monitor_uuid,
                                              capture_settings=monit.get('capture_settings'),
                                              frequency=monit.get('frequency'),
                                              expire_at=monit.get('expire_at'),
                                              collection=monit.get('collection'),
                                              compare_settings=monit.get('compare_settings'),
                                              never_expire=monit.get('never_expire', False),
                                              notification=monit.get('notification'))
            return make_response(monitor_uuid)
        except (UnknownUUID, InvalidSettings, TimeError) as e:
            return make_response({'message': str(e)}, 500)


@api.route('/stop_monitor/<string:monitor_uuid>')
@api.doc(description='Stop monitoring',
         params={'monitor_uuid': 'The monitoring UUID'},
         security='apikey')
class StopMonitor(Resource):  # type: ignore[misc]
    method_decorators = [api_auth_check]

    def post(self, monitor_uuid: str) -> Response | bool:
        try:
            return monitoring.stop_monitor(monitor_uuid)
        except (UnknownUUID, AlreadyExpired) as e:
            return make_response({'message': str(e)})


@api.route('/start_monitor/<string:monitor_uuid>')
@api.doc(description='Start monitoring',
         params={'monitor_uuid': 'The monitoring UUID'},
         security='apikey')
class StartMonitor(Resource):  # type: ignore[misc]
    method_decorators = [api_auth_check]

    def post(self, monitor_uuid: str) -> Response | bool:
        try:
            return monitoring.start_monitor(monitor_uuid)
        except (UnknownUUID, AlreadyMonitored) as e:
            return make_response({'message': str(e)})


@api.route('/json/changes/<string:monitor_uuid>')
@api.doc(description='Compare the captures for a specific monitored entry',
         params={'monitor_uuid': 'The monitoring UUID'})
class JsonCompare(Resource):  # type: ignore[misc]

    def get(self, monitor_uuid: str) -> Response:
        try:
            return make_response(monitoring.compare_captures(monitor_uuid))
        except CannotCompare as e:
            return make_response({'error': str(e)})


@api.route('/json/collections')
@api.doc(description='Get the list of existing collections',
         security='apikey')
class JsonCollections(Resource):  # type: ignore[misc]

    def get(self) -> Response:
        collections = monitoring.get_collections()
        if not (flask_login.current_user.is_authenticated or load_user_from_request(request)):
            # strip collections that are too long (unless you're logged in)
            collections = {c for c in collections if len(c) < 30}
        return make_response(list(collections))


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
class JsonMonitored(Resource):  # type: ignore[misc]

    def get(self, collection: str | None=None) -> Response:
        return make_response(monitoring.get_monitored_entries(collection))


@api.route('/json/expired',
           doc={'description': 'Get the list of expired UUIDs'})
@api.route('/json/expired/<string:collection>',
           doc={'description': 'Get the list of expired UUIDs, for a specific collection',
                'collection': 'Limit the response to a specific collection'})
class JsonExpired(Resource):  # type: ignore[misc]

    def get(self, collection: str | None=None) -> Response:
        return make_response(monitoring.get_expired_entries(collection))


@api.route('/json/settings')
@api.doc(description='Get generic settings for the monitoring instance')
class JsonSettings(Resource):  # type: ignore[misc]

    def get(self) -> Response:
        return make_response(monitoring.settings())
