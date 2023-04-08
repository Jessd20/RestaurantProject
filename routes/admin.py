from flask import Blueprint, render_template, request, make_response, session, jsonify, current_app as app
from models.restaurant import Admin, Dish, Order
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
    restaurant = request.form.get('restaurant')
    username = request.form.get('username')
    password = request.form.get('password')
    encrypted_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    new_admin = Admin(restaurant,username, encrypted_password.decode('utf-8'))

    db.session.add(new_admin)
    db.session.commit()

    return "admin registered"


@admin.route('/login', methods=['GET'])
def login_get():
    if session.get('logged_in'):
        return 'You are already logged in'
    else:
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

        token = jwt.encode({
            'user': request.form.get('username'),
            'exp': int((datetime.utcnow() + timedelta(minutes=5)).timestamp())
        }, app.config['SECRET_KEY'], algorithm='HS256')

        session['token'] = token
        session['logged_in'] = True

        return "logged in"

    else:
        return make_response('Unable to verify', 403, {'Status': 'Invalid password'})


@admin.route('/logout', methods=['GET'])
def logout_get():
    if not session.get('logged_in'):
        return 'You are not logged in'
    else:
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
            if data['exp'] < datetime.utcnow().timestamp():
                session.pop('token', None)
                session.pop('logged_in', None)
                return jsonify({'error': 'Token has expired!'}), 401
        except:
            return jsonify({'error': 'Token is invalid or has expired!'}), 401

        return func(current_user, *args, **kwargs)

    return decorated


@admin.route('/dish/add', methods=['GET'])
@check_token
def add_dishes_get(current_user):
    dishes = Dish.query.filter_by(admin_id=current_user.id).all()
    return render_template("/admin/add_dish.html", dishes=dishes)


@admin.route('/dish/add', methods=['POST'])
@check_token
def add_dishes_post(current_user):
    name = request.form.get('name')
    price = request.form.get('price')
    url_image = request.form.get('url_image')
    status = request.form.get('status')
    admin_id = current_user.id

    new_dish = Dish(name, price, url_image, status, admin_id)

    db.session.add(new_dish)
    db.session.commit()

    return "dish added"


@admin.route('/dish/update/<dish_id>', methods=['GET'])
@check_token
def update_dish_get(current_user, dish_id):
    dish = Dish.query.get(dish_id)
    if current_user.id != dish.admin_id:
        return "dish not found"
    else:
        return render_template("/admin/update_dish.html", dish=dish)


@admin.route('/dish/update/<dish_id>', methods=['POST'])
@check_token
def update_dish(current_user, dish_id):
    dish = Dish.query.get(dish_id)
    dish.name = request.form.get('name')
    dish.price = (request.form.get('price'))
    dish.url_image = request.form.get('url_image')
    dish.status = request.form.get('status')

    db.session.commit()

    return "dish updated"


@admin.route('/dish/delete/<dish_id>')
@check_token
def delete_dish(current_user, dish_id):
    dish = Dish.query.get(dish_id)
    if dish.admin_id == current_user.id:
        db.session.delete(dish)
        db.session.commit()
        return "dish deleted"
    else:
        return "dish not found"


@admin.route('/dish/earnings', methods=['GET'])
@check_token
def earnings(current_user):
    orders = Order.query.filter_by(admin_id=current_user.id).all()
    total_gain = 0
    for order in orders:
        total_gain += float(order.total)

    total_gain = round(total_gain, 2)

    return render_template("/admin/earning.html", orders=orders, total_gain=total_gain)
