from flask import Blueprint, render_template, request, make_response, session, jsonify, redirect, url_for, current_app as app
from models.restaurant import Admin
from utils.db import db
from datetime import datetime, timedelta
from functools import wraps
import bcrypt
import jwt

admin = Blueprint('admin', __name__, url_prefix='/admin')


@admin.route('/')
def home():
    return render_template('/admin/home.html')


@admin.route("/register", methods=['GET'])
def register_get():
    return render_template('/admin/registration.html')


@admin.route('/register', methods=['POST'])
def register_post():
    username = request.form.get('username')
    password = request.form.get('password')
    encrypted_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    new_admin = Admin(username, encrypted_password.decode('utf-8'))

    db.session.add(new_admin)
    db.session.commit()

    return "admin registered"


@admin.route('/login', methods=['GET'])
def login_get():
    return render_template("/admin/login.html")


@admin.route("/login", methods=['POST'])
def login_post():
    username = request.form.get('username')
    password = request.form.get('password')

    user = Admin.query.filter_by(username=username).first()

    if user is None:
        return 'Invalid username'

    encrypted_password = user.password.encode('utf-8')
    if bcrypt.checkpw(password.encode('utf-8'), encrypted_password):
        session['logged_in'] = True

        token = jwt.encode({
            'user': request.form.get('username'),
            'exp': int((datetime.utcnow() + timedelta(minutes=10)).timestamp())
        }, app.config['SECRET_KEY'], algorithm='HS256')

        session['token'] = token

        return "logged in"

    else:
        return make_response('Unable to verify', 403, {'Status': 'Invalid password'})


@admin.route('/logout', methods=['GET'])
def logout_get():
    session.pop('token', None)
    session.pop('logged_in', None)
    return render_template("/admin/logout.html")


def check_token(func):
    @wraps(func)
    def decorated(*args, **kwargs):
        token = session.get('token')
        if not token:
            return jsonify({'error': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = Admin.query.filter_by(username=data['user']).first()
        except:
            return jsonify({'error': 'Token is invalid or has expired!'}), 401

        return func(current_user, *args, **kwargs)

    return decorated


@admin.route('/dish/add', methods=['GET'])
@check_token
def add_dishes(current_user):
    return "add dishes"


@admin.route('/dish/update', methods=['GET'])
@check_token
def update_dishes(current_user):
    return "update dishes"


@admin.route('/dish/show', methods=['GET'])
@check_token
def show_dishes(current_user):
    return "show dishes"


@admin.route('/dish/earnings', methods=['GET'])
@check_token
def earnings(current_user):
    return "show earnings"

