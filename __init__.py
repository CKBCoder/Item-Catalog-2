#!/usr/bin/env python3

from flask import Flask, render_template, request, redirect, jsonify, url_for
from flask import flash, make_response
from flask import session as login_session
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
from pprint import pprint
import httplib2
import random
import string
import json
import requests
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()


class User(Base):
    """Class to create the table 'user'."""

    __tablename__ = "user"

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    picture = Column(String(250))


class Category(Base):
    """Class to create the table 'category'."""

    __tablename__ = "category"

    id = Column(Integer, primary_key=True)
    name = Column(String(50), nullable=False)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""

        return {
            'id': self.id,
            'name': self.name,
            'user_id': self.user_id
        }


class Item(Base):
    """Class to create the table 'item'."""

    __tablename__ = "item"

    id = Column(Integer, primary_key=True)
    name = Column(String(80), nullable=False)
    description = Column(String(250))
    category_id = Column(Integer, ForeignKey('category.id'))
    category = relationship(Category)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""

        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'user_id': self.user_id,
            'category_id': self.category_id
        }


engine = create_engine('sqlite:///itemcatalog.db')
Base.metadata.create_all(engine)


# Bind the above engine to a session.
Session = sessionmaker(bind=engine)

# Create a Session object.
session = Session()

user1 = User(
    name='Chandrakant Bharti',
    email='chandrakant.bharti@gmail.com',
    picture=''
)

session.add(user1)
session.commit()

category1 = Category(
    name='Cricket',
    user=user1
)

session.add(category1)
session.commit()

item1 = Item(
    name='Bat',
    description='Use it to hit the ball and score runs.',
    category=category1,
    user=user1
)

session.add(item1)
session.commit()

category1 = Category(
    name='Soccer',
    user=user1
)

session.add(category1)
session.commit()

category1 = Category(
    name='Tennis',
    user=user1
)

session.add(category1)
session.commit()

category1 = Category(
    name='Badminton',
    user=user1
)

session.add(category1)
session.commit()

category1 = Category(
    name='Basketball',
    user=user1
)

session.add(category1)
session.commit()

category1 = Category(
    name='Baseball',
    user=user1
)

session.add(category1)
session.commit()

category1 = Category(
    name='Hockey',
    user=user1
)

session.add(category1)
session.commit()


print('Finished populating the database!')



app = Flask(__name__)

# Load the Google Sign-in API Client ID.
CLIENT_ID = json.loads(
    open('client_id.json', 'r').read())['web']['client_id']

# Redirect to login page.
@app.route('/')
@app.route('/catalog/')
@app.route('/catalog/items/')
def home():
    """Route to the homepage."""
    categories = session.query(Category).all()
    items = session.query(Item).all()
    return render_template(
        'index.html', categories=categories, items=items)


# Create anti-forgery state token
@app.route('/login/')
def login():
    """Route to the login page and create anti-forgery state token."""
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in range(32))
    login_session['state'] = state
    return render_template("login.html", STATE=state)


# Connect to the Google Sign-in oAuth method.
@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_id.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    google_id = credentials.id_token['sub']
    if result['user_id'] != google_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_google_id = login_session.get('google_id')
    if stored_access_token is not None and google_id == stored_google_id:
        response = make_response(
            json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['google_id'] = google_id

    # Get user info.
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # See if the user exists. If it doesn't, make a new one.
    user_id = get_user_id(data["email"])
    if not user_id:
        user_id = create_user(login_session)
    login_session['user_id'] = user_id

    # Show a welcome screen upon successful login.
    output = ''
    output += '<h2>Welcome, '
    output += login_session['username']
    output += '!</h2>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px; '
    output += 'border-radius: 150px;'
    output += '-webkit-border-radius: 150px;-moz-border-radius: 150px;">'
    flash("You are now logged in as %s!" % login_session['username'])
    return output


# Disconnect Google Account.
def gdisconnect():
    """Disconnect the Google account of the current logged-in user."""
    # Only disconnect the connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    if result['status'] == '200':
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(
            json.dumps('Failed to revoke token for given user.'), 400)
        response.headers['Content-Type'] = 'application/json'
        return response


# Log out the currently connected user.
@app.route('/logout')
def logout():
    """Log out the currently connected user."""
    if 'username' in login_session:
        gdisconnect()
        del login_session['google_id']
        del login_session['access_token']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        flash("You have been successfully logged out!")
        return redirect(url_for('home'))
    else:
        flash("You were not logged in!")
        return redirect(url_for('home'))


# Create new user.
def create_user(login_session):
    """Crate a new user."""
    new_user = User(
        name=login_session['username'],
        email=login_session['email'],
        picture=login_session['picture']
    )
    session.add(new_user)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def get_user_info(user_id):
    """Get user information by ID."""
    user = session.query(User).filter_by(id=user_id).one()
    return user


def get_user_id(email):
    """Get user ID by email."""
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


# Create a new item.
@app.route("/catalog/item/new/", methods=['GET', 'POST'])
def add_item():
    """Create a new item."""
    if 'username' not in login_session:
        flash("Please log in to continue.")
        return redirect(url_for('login'))
    elif request.method == 'POST':
        # Check if the item already exists in the database.
        # If it does, display an error.
        item = session.query(Item).filter_by(name=request.form['name']).first()
        if item:
            if item.name == request.form['name']:
                flash('The item already exists in the database!')
                return redirect(url_for("add_item"))
        new_item = Item(
            name=request.form['name'],
            category_id=request.form['category'],
            description=request.form['description'],
            user_id=login_session['user_id']
        )
        session.add(new_item)
        session.commit()
        flash('New item successfully created!')
        return redirect(url_for('home'))
    else:
        items = session.query(Item).\
                filter_by(user_id=login_session['user_id']).all()
        categories = session.query(Category).\
            filter_by(user_id=login_session['user_id']).all()
        return render_template(
            'new-item.html',
            items=items,
            categories=categories
        )


# Create new item by Category ID.
@app.route("/catalog/category/<int:category_id>/item/new/",
           methods=['GET', 'POST'])
def add_item_by_category(category_id):
    """Create new item by Category ID."""
    if 'username' not in login_session:
        flash("You were not authorised to access that page.")
        return redirect(url_for('login'))
    elif request.method == 'POST':
        # Check if the item already exists in the database.
        # If it does, display an error.
        item = session.query(Item).filter_by(name=request.form['name']).first()
        if item:
            if item.name == request.form['name']:
                flash('The item already exists in the database!')
                return redirect(url_for("add_item"))
        new_item = Item(
            name=request.form['name'],
            category_id=category_id,
            description=request.form['description'],
            user_id=login_session['user_id'])
        session.add(new_item)
        session.commit()
        flash('New item successfully created!')
        return redirect(url_for('show_items_in_category',
                                category_id=category_id))
    else:
        category = session.query(Category).filter_by(id=category_id).first()
        return render_template('new-item-2.html', category=category)


# Check if the item exists in the database,
def exists_item(item_id):
    """Check if the item exists in the database."""
    item = session.query(Item).filter_by(id=item_id).first()
    if item is not None:
        return True
    else:
        return False


# Check if the category exists in the database.
def exists_category(category_id):
    """Check if the category exists in the database."""
    category = session.query(Category).filter_by(id=category_id).first()
    if category is not None:
        return True
    else:
        return False


# View an item by its ID.
@app.route('/catalog/item/<int:item_id>/')
def view_item(item_id):
    """View an item by its ID."""
    if exists_item(item_id):
        item = session.query(Item).filter_by(id=item_id).first()
        category = session.query(Category)\
            .filter_by(id=item.category_id).first()
        owner = session.query(User).filter_by(id=item.user_id).first()
        return render_template(
            "view-item.html",
            item=item,
            category=category,
            owner=owner
        )
    else:
        flash('We are unable to process your request right now.')
        return redirect(url_for('home'))


# Edit existing item.
@app.route("/catalog/item/<int:item_id>/edit/", methods=['GET', 'POST'])
def edit_item(item_id):
    """Edit existing item."""
    if 'username' not in login_session:
        flash("Please log in to continue.")
        return redirect(url_for('login'))

    if not exists_item(item_id):
        flash("We are unable to process your request right now.")
        return redirect(url_for('home'))

    item = session.query(Item).filter_by(id=item_id).first()
    if login_session['user_id'] != item.user_id:
        flash("You were not authorised to access that page.")
        return redirect(url_for('home'))

    if request.method == 'POST':
        if request.form['name']:
            item.name = request.form['name']
        if request.form['description']:
            item.description = request.form['description']
        if request.form['category']:
            item.category_id = request.form['category']
        session.add(item)
        session.commit()
        flash('Item successfully updated!')
        return redirect(url_for('view_item', item_id=item_id))
    else:
        categories = session.query(Category).\
            filter_by(user_id=login_session['user_id']).all()
        return render_template(
            'edit-item.html',
            item=item,
            categories=categories
        )


# Delete existing item.
@app.route("/catalog/item/<int:item_id>/delete/", methods=['GET', 'POST'])
def delete_item(item_id):
    """Delete existing item."""
    if 'username' not in login_session:
        flash("Please log in to continue.")
        return redirect(url_for('login'))

    if not exists_item(item_id):
        flash("We are unable to process your request right now.")
        return redirect(url_for('home'))

    item = session.query(Item).filter_by(id=item_id).first()
    if login_session['user_id'] != item.user_id:
        flash("You were not authorised to access that page.")
        return redirect(url_for('home'))

    if request.method == 'POST':
        session.delete(item)
        session.commit()
        flash("Item successfully deleted!")
        return redirect(url_for('home'))
    else:
        return render_template('delete-item.html', item=item)


# Show items in a particular category.
@app.route('/catalog/category/<int:category_id>/items/')
def show_items_in_category(category_id):
    """# Show items in a particular category."""
    if not exists_category(category_id):
        flash("We are unable to process your request right now.")
        return redirect(url_for('home'))

    categories = session.query(Category).all()
    category = session.query(Category).filter_by(id=category_id).first()
    items = session.query(Item).filter_by(category_id=category.id).all()
    total = session.query(Item).filter_by(category_id=category.id).count()
    return render_template(
        'items.html',
        categories=categories,
        category=category,
        items=items,
        total=total)


# JSON Endpoints

# Return JSON of all the items in the catalog.
@app.route('/api/v1/items/JSON')
def show_catalog_json():
    """Return JSON of all the items in the catalog."""
    items = session.query(Item).order_by(Item.id.desc())
    return jsonify(catalog=[i.serialize for i in items])


# Return JSON of a particular item in the catalog.
@app.route(
    '/api/v1/categories/<int:category_id>/item/<int:item_id>/JSON')
def catalog_item_json(category_id, item_id):
    """Return JSON of a particular item in the catalog."""
    if exists_category(category_id) and exists_item(item_id):
        item = session.query(Item)\
               .filter_by(id=item_id, category_id=category_id).first()
        if item is not None:
            return jsonify(item=item.serialize)
        else:
            return jsonify(
                error='item {} does not belong to category {}.'
                .format(item_id, category_id))
    else:
        return jsonify(error='The item or the category does not exist.')


# Return JSON of all the categories in the catalog.
@app.route('/api/v1/categories/JSON')
def categories_json():
    """Returns JSON of all the categories in the catalog."""
    categories = session.query(Category).all()
    return jsonify(categories=[i.serialize for i in categories])


if __name__ == "__main__":
    app.secret_key = 'm6l711k31gjbermi32aodo7ee6ucnu1e'
    app.run(host="0.0.0.0", port=5000, debug=True)
