# Restaurant API Project

This is a Flask Web Application that provides a dashboard for restaurant admins to manage their dishes and view earnings.
Also, it provides a public API for users to view the dishes and order them.

## Installation
* Install Python 3.11
* Clone the repository
* Create a virtual environment using `python -m venv .venv`
* Activate the virtual environment using `source .venv/bin/activate`'
* Install pip using `sudo apt install python3-pip`
* Install the requirements using `pip install -r requirements.txt`
* Install Postgres and create a database named `restaurantdb` and a user named `restaurant` with password `restaurant`
* Run the command `python index.py` to start the server

## Features
* Register a new restaurant admin account
* Login and logout of the admin account
* Dashboard for restaurant admins to manage their dishes
* View earnings from the restaurant's orders
* View all dishes from all restaurants for users
* Order dishes from restaurants

## API Endpoints
The API provides the following endpoints:

### Restaurant Admin Endpoints
* `POST /admin/register` - Register a new admin account.
* `POST /admin/login` - Login to an admin account.
* `GET /admin/logout` - Logout of an admin account.
* `GET /admin/dish/add` - Get the page for adding a new dish.
* `POST /admin/dish/add` - Add a new dish.
* `GET /admin/dish/update/<dish_id>` - Get the page for editing a dish.
* `POST /admin/dish/update/<dish_id>` - Edit an existing dish.
* `GET /admin/dish/<dish_id>/delete` - Delete a dish.
* `GET /admin/dish/earnings` - Get the earnings from the restaurant's orders.

### User Endpoints
* `GET /restaurants` - Get all dishes from all restaurants.
* `GET /restaurant/<restaurant_id>/dishes` - Get all dishes from a restaurant.
* `POST /restaurant/<restaurant_id>/dishes` - Order dishes from a restaurant.
* `GET /restaurant/dishes/buying` - Get all dishes that have been ordered. 

