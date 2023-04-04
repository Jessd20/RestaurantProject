from flask import Flask
from routes.admin import admin
from routes.restaurants import restaurants
from utils.db import db

app = Flask(__name__)

app.config['SECRET_KEY'] = 'c01a7501f4324857ae65adefe0a1a09b'

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://restaurant:restaurant@localhost/restaurantdb'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

app.register_blueprint(admin)
app.register_blueprint(restaurants)

