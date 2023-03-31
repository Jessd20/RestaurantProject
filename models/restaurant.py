from utils.db import db


class Admin(db.Model):
    __tablename__ = 'admins'

    id = db.Column(db.Integer, primary_key=True, index=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String, nullable=False)

    dishes = db.relationship('Dish', back_populates='admin')
    orders = db.relationship('Order', back_populates='admin')

    def __init__(self, username, password):
        self.username = username
        self.password = password


class Dish(db.Model):
    __tablename__ = 'dishes'

    id = db.Column(db.Integer, primary_key=True, index=True)
    name = db.Column(db.String(20), nullable=False)
    price = db.Column(db.Integer, nullable=False)
    url_image = db.Column(db.String, nullable=False)
    is_active = db.Column(db.Boolean, nullable=False)
    admin_id = db.Column(db.Integer, db.ForeignKey('admins.id'), nullable=False)

    admin = db.relationship('Admin', back_populates='dishes')

    def __init__(self, name, price, url_image, is_active, admin_id):
        self.name = name
        self.price = price
        self.url_image = url_image
        self.is_active = is_active
        self.admin_id = admin_id


class Order(db.Model):
    __tablename__ = 'orders'

    id = db.Column(db.Integer, primary_key=True, index=True)
    name = db.Column(db.String(20), nullable=False)
    amount = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Integer, nullable=False)
    total = db.Column(db.Integer, nullable=False)
    admin_id = db.Column(db.Integer, db.ForeignKey('admins.id'), nullable=False)

    admin = db.relationship('Admin', back_populates='orders')

    def __init__(self, name, amount, price, total, admin_id):
        self.name = name
        self.amount = amount
        self.price = price
        self.total = total
        self.admin_id = admin_id
