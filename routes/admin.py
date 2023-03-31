from flask import Blueprint, render_template, request
from models.restaurant import Admin
from utils.db import db
import bcrypt

admin = Blueprint('admin', __name__, url_prefix='/admin')


@admin.route("/")
def home():
    return render_template("admin/home.html")


@admin.route("/register", methods=['GET'])
def register_get():
    return render_template("admin/registration.html")


@admin.route("/register", methods=['POST'])
def register_post():
    username = request.form.get('username')
    password = request.form.get('password')
    encrypted_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    new_admin = Admin(username, encrypted_password.decode('utf-8'))

    db.session.add(new_admin)
    db.session.commit()

    return "admin registered"


@admin.route("/login", methods=['GET'])
def login_get():
    return render_template("admin/login.html")


@admin.route("/login", methods=['POST'])
def login_post():
    username = request.form.get('username')
    password = request.form.get('password')

    admin = Admin.query.filter_by(username=username).first()

    if admin is None:
        return "Invalid username"

    encrypted_password = admin.password.encode('utf-8')
    if bcrypt.checkpw(password.encode('utf-8'), encrypted_password):
        return "Login successful"
    else:
        return "Invalid password"
