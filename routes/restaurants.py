from flask import Blueprint, render_template, request
from models.restaurant import Admin, Dish, Order
from utils.db import db
import re

restaurants = Blueprint('restaurants', __name__, url_prefix='/restaurants')
order_list = []


@restaurants.route('/')
def home():
    restaurants = Admin.query.all()
    return render_template('/restaurant/home.html', restaurants=restaurants)


@restaurants.route('/<restaurant_id>/dishes', methods=['GET'])
def dishes_get(restaurant_id):
    dishes = Dish.query.filter_by(admin_id=restaurant_id).filter_by(is_available="True").all()
    return render_template('/restaurant/dishes.html', dishes=dishes, restaurant_id=restaurant_id)


def validate(quantity):

    if not re.match(r'^\d+$', quantity):
        return False


@restaurants.route('/<restaurant_id>/dishes', methods=['POST'])
def dishes_post(restaurant_id):
    dish_id = request.form.get('dish_id')
    dish = Dish.query.get(dish_id)

    if str(dish.admin_id) != restaurant_id:
        return "You are not authorized to buy this dish"
    elif dish.is_available == "False":
        return "This dish is not available"
    else:
        name = dish.name
        quantity = request.form.get('quantity')
        price = dish.price
        total = str(float(price) * int(quantity))

        new_order = Order(name, quantity, price, total, restaurant_id)
        order_list.append(new_order)

        return "dish ordered"


@restaurants.route('/dishes/buying')
def buying():
    message = "You ordered: \n"

    for order in order_list:
        db.session.add(order)
        db.session.commit()
        message += "Dish: " + order.name + "\nQuantity: " + order.quantity + "\nTotal: " + order.total + "\n\n"

    order_list.clear()
    return message
