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
    name = db.Column(db.String(50), nullable=False)
    price = db.Column(db.String, nullable=False)
    url_image = db.Column(db.String, nullable=False)
    is_available = db.Column(db.String, nullable=False)
    admin_id = db.Column(db.Integer, db.ForeignKey('admins.id'), nullable=False)

    admin = db.relationship('Admin', back_populates='dishes')

    def __init__(self, name, price, url_image, is_available, admin_id):
        self.name = name
        self.price = price
        self.url_image = url_image
        self.is_available = is_available
        self.admin_id = admin_id


class Order(db.Model):
    __tablename__ = 'orders'

    id = db.Column(db.Integer, primary_key=True, index=True)
    name = db.Column(db.String(50), nullable=False)
    quantity = db.Column(db.String, nullable=False)
    price = db.Column(db.String, nullable=False)
    total = db.Column(db.String, nullable=False)
    admin_id = db.Column(db.Integer, db.ForeignKey('admins.id'), nullable=False)

    admin = db.relationship('Admin', back_populates='orders')

    def __init__(self, name, quantity, price, total, admin_id):
        self.name = name
        self.quantity = quantity
        self.price = price
        self.total = total
        self.admin_id = admin_id
