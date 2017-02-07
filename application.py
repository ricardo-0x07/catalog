# MIT License

# Copyright (c) 2016 Clive Cadogan

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.


from functools import wraps
from flask import Flask, render_template, request, redirect, jsonify, url_for, flash, abort
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, User, Catalog, Item

from flask import session as login_session
import random
import string

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Catalog Application"

# Connect to Database and create database session
# engine = create_engine('sqlite:///catalog.db')
# psycopg2
engine = create_engine('postgresql+psycopg2://catalog:catalog1232@localhost/catalog')

Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


@app.route('/login')
def showLogin():
    """Create anti-forgery state token.

    Return: renders the login page.
    """
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # Set new random CRSF TOKEN value
    app.jinja_env.globals['_csrf_token'] = generate_csrf_token()
    return render_template('login.html', STATE=state)


@app.before_request
def csrf_protect():
    """Check csrf token on post requests."""
    if request.method == "POST":
        token = login_session['_csrf_token']
        if '_csrf_token' in request.form:
            if not token or token != request.form['_csrf_token']:
                abort(403)
        else:
            if not token or token != request.args.get('token'):
                abort(403)


def generate_csrf_token():
    """Generate csrf tokens and store in session.

    Return: generated csrf token
    """
    if '_csrf_token' not in login_session:
        login_session['_csrf_token'] = ''.join(random.
                                               choice(string.ascii_uppercase +
                                                      string.digits) for x
                                               in xrange(32))
    return login_session['_csrf_token']


def login_required(f):
    """Wrap and replace function.

    Args: f: decorated function.
    Return: the decorated function.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        """Check if a suser is loggin..

        Return: renders login page if a user is not logged in.
        or returns the decorated function.
        """
        if 'username' not in login_session:
            return redirect(url_for('showLogin', next=request.url))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/fbconnect', methods=['POST', 'GET'])
def fbconnect():
    """Sign user in with facebook credentials.

    Return: a Invalid state parameter message when state parameter is not valid
     or Success message when user has successfully signed in with facebook
     credentials.
    """
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    # Exchange client token for long-live server-side token with GET
    # /oauth/access_token?grant_type=fb_exchange_token&client_id=
    # {app-id}&client_secret={app-secret}&fb_exchange_token=
    # {short-lived-token}
    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_secret']
    print 'app_id'
    print app_id
    print 'app_secret'
    print app_secret
    print 'access_token'
    print access_token
    url = """https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s""" % (
        app_id, app_secret, access_token)
    print 'url'
    print url
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    print 'token result'
    print result

    # Use token to get user from API
    # userinfo_url = "https://graph.facebook.com/v2.4/me"
    # strip expire tag from token
    token = result.split('&')[0]

    url = "https://graph.facebook.com/v2.4/me?%s&fields=name,id,email" % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    print 'fields result'
    print result
    # Print 'url sent for API access:%s'% url
    # print 'API JSON result: %s' % result
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data['name']
    login_session['email'] = data['email']
    login_session['facebook_id'] = data['id']

    # get user picture
    url = """https://graph.facebook.com/v2.4/me/picture?%s&redirect=0&height=200&width=200""" % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    print 'picture result'
    print result
    # Print 'url sent for API access:%s'% url
    # print 'API JSON result: %s' % result
    data = json.loads(result)
    login_session['picture'] = 'picture'

    user_id = getUserID(login_session['email'])
    if user_id is None:
        user_id = createuser(login_session)

    login_session['user_id'] = user_id
    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output


@app.route('/gconnect', methods=['POST', 'GET'])
def gconnect():
    """Sign users in with google credentials.

    Return: a Invalid state parameter message when state parameter is not valid
     or Success message when user has successfully signed in with google
     credentials.
    """
    print "request.args.get('state')"
    print request.args.get('state')
    if request.args.get('state') != login_session['state']:
        print request.args.get('state')
        print login_session['state']
        print 'Invalid state'
        response = make_response(json.dumps('Invalid state'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    code = request.data
    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        print 'Failed to upgrade the authorization code.'
        response = make_response(json.dumps(
            'Failed to upgrade the authorization code.', 401))
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
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        print "Token's user ID doesn't match given user ID."
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        print "Token's client ID does not match app's."
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['credentials'] = credentials
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()
    login_session['provider'] = 'google'
    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    user_id = getUserID(data['email'])
    if user_id is None:
        user_id = createuser(login_session)

    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output


# User Helper Functions
def createuser(login_session):
    """Create a new user.

    Args: login_session: login session object.
    Return: users id number.
    """
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    """Retrieve user object from database.

    Args: user_id: users id number.
    Return: user oject.
    """
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    """get user's id.

    Args: email: user email address.
    Return: user's id number of None is user does not exists in database.
    """
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


def getcategoryid(name):
    """Get category's id.

    Args: name: category name.
    Return: category's id number of None is category does not exists in database.
    """
    try:
        category = session.query(Catalog).filter_by(name=name).one()
        return category.id
    except:
        return None


def getitemid(name, category_id):
    """Get item's id.

    Args: name: item's name. category_id: items category id.
    Return: item's id number of None is item does not exists in database.
    """
    try:
        item = session.query(Item).filter(
            Item.name==name, Item.catalog_id==category_id).one()
        return item.id
    except:
        return None


@app.route('/disconnect', methods=['POST', 'GET'])
def disconnect():
    """Sign users out based on providers.

    Return: renders cataog.
    """
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['credentials']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']

        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out")
        return redirect(url_for('showCatalog'))
    else:
        flash("You were not logged in!")
        return redirect(url_for('showCatalog'))


@app.route('/fbdisconnect', methods=['POST', 'GET'])
def fbdisconnect():
    """Sign users out with facebook credetials.

    Return: message: 'You  have been successfully logged out!.
    """
    facebook_id = login_session['facebook_id']
    url = 'https://graph.facebook.com/%s/permissions' % facebook_id
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return 'You  have been successfully logged out!'


@app.route('/gdisconnect', methods=['POST', 'GET'])
def gdisconnect():
    """Sign users out with gololge credetials.

    Return: success or failure response.
    """
    credentials = login_session['credentials']
    print 'In gdisconnect access token is %s', credentials
    print 'User name is: '
    print login_session['username']

    # Only disconnect a connected user.
    # credentials = login_session['credentials']
    if credentials is None:
        response = make_response(json.dumps(
            'Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    #  Execute HTTP GET request to revike current token.
    access_token = credentials.access_token
    print 'access_token'
    print access_token
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print 'result'
    print result

    print 'status'
    print result['status']
    if result['status'] == 200:
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps(
            'Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


# JSON APIs to view Catalog Information
@app.route('/catalog/<category_name>/item.json')
def catalogjson(category_name):
    """Create json format of a category's items.

    Return: JSOn object of the specified categories items.
    """
    category = session.query(Catalog).filter_by(name=category_name).one()
    items = session.query(Item).filter_by(catalog=category).all()
    return jsonify({'items': [i.serialize for i in items]})


@app.route('/catalog.json')
def catalogsjson():
    """Create json format of the entire catalog with category's and thier items.

    Return: JSON object of the entire catalo with it's categories and relatated
    items.
    """
    catalogs = session.query(Catalog).all()
    return jsonify(categories=[r.serialize for r in catalogs])


# Show all categories
@app.route('/')
@app.route('/catalog/')
def showCatalog():
    """Show all categories.

    Return: response to render catalog.
    """
    catalogs = session.query(Catalog).order_by(asc(Catalog.name)).all()
    items = session.query(Item).order_by(asc(Item.created)).limit(10).all()
    print 'catalogs'
    print catalogs
    return render_template('catalog.html', catalogs=catalogs, items=items)


# Create a new catalog
@app.route('/catalog/new/', methods=['GET', 'POST'])
@login_required
def newCategory():
    """Show all categories.

    Return: response to render catalog.
    """
    if request.method == 'POST':
        category_id = getcategoryid(request.form['name'])
        if category_id == None:
            newCategory = Catalog(name=request.form['name'],
                                  user_id=login_session['user_id'])
            session.add(newCategory)
            flash('New Catalog %s Successfully Created' % newCategory.name)
            session.commit()
            return redirect(url_for('showCatalog'))
        else:
            flash('The %s category already exists! Kindly create a new category.' %
                  request.form['name'])
            return redirect(url_for('showCatalog'))
    else:
        # Set new random CRSF TOKEN value
        app.jinja_env.globals['_csrf_token'] = generate_csrf_token()
        return render_template('newCategory.html')

# Edit a catalog


@app.route('/catalog/<category_name>/edit/', methods=['GET', 'POST'])
@login_required
def editCategory(category_name):
    """Show all categories.

    arges: category_name: name of the category to be edited.
    Return: response to render the edit category form to allow editing of the
    category or the catalog after the category has been edited.
    """
    print 'editCategory'
    editcategory = session.query(Catalog).filter_by(name=category_name).one()
    if editcategory.user.name != login_session['username']:
        print "if editcategory.user_id != login_session['user_id']:"
        return """<script>function myFunction() {alert('You are not authorized to edit this category. Please create your own category in order to edit.');}</script><body onload='myFunction()''>"""
    if request.method == 'POST':
        print "if request.method == 'POST':"
        if request.form['name']:
            editcategory.name = request.form['name']
            flash('Catalog Successfully Edited %s' % editcategory.name)
            return redirect(url_for('showCatalog'))
    else:
        print " else:"
        # Set new random CRSF TOKEN value
        app.jinja_env.globals['_csrf_token'] = generate_csrf_token()
        return render_template('editCategory.html', category=editcategory)


# Delete a catalog
@app.route('/catalog/<category_name>/delete/', methods=['GET', 'POST'])
@login_required
def deleteCategory(category_name):
    """Delete the specified category.

    arges: category_name: name of the category to be deleted.
    Return: response to render the delete category form to allow editing of the
    category or the catalog after the category has been deleted.
    """
    categorytodelete = session.query(
        Catalog).filter_by(name=category_name).one()
    if categorytodelete.user.name != login_session['username']:
        return """<script>function myFunction() {alert('You are not authorized to delete this category. Please create your own category in order to delete.');}</script><body onload='myFunction()''>"""
    if request.method == 'POST':
        session.delete(categorytodelete)
        flash('%s Successfully Deleted' % categorytodelete.name)
        session.commit()
        return redirect(url_for('showCatalog'))
    else:
        # Set new random CRSF TOKEN value
        app.jinja_env.globals['_csrf_token'] = generate_csrf_token()
        return render_template('deleteCategory.html', category=categorytodelete)


# Show a catalog's items
@app.route('/catalog/<category_name>/')
@app.route('/catalog/<category_name>/items/')
def showItems(category_name):
    """Show items for a specified category.

    arges: category_name: name of the category for which items are to be
    displayed.
    Return: response to render the category items.
    """
    category = session.query(Catalog).filter_by(name=category_name).one()
    items = session.query(Item).filter_by(catalog_id=category.id).all()
    categories = session.query(Catalog).order_by(asc(Catalog.name)).all()
    creator = getUserInfo(category.user_id)
    return render_template('items.html', items=items,
                           category=category,
                           creator=creator,
                           categories=categories)


# Create a new item
@app.route('/catalog/<category_name>/items/new/', methods=['GET', 'POST'])
@login_required
def newItem(category_name):
    """Create new item for a specified category.

    arges: category_name: name of the category for which the new item wil be
    created.
    Return: response to render the new item form or
    the category items after the new item has been created.
    """
    category = session.query(Catalog).filter_by(name=category_name).one()
    if category.user.name != login_session['username']:
        return """<script>function myFunction() {alert('You are not authorized to add items to this category. Please create your own category in order to add items.');}</script><body onload='myFunction()''>"""
    if request.method == 'POST':
        item_id = getitemid(request.form['name'], category.id)
        print 'item_id'
        print item_id
        if item_id == None:
            newitem = Item(name=request.form['name'],
                           description=request.form['description'],
                           price=request.form['price'],
                           photo=request.form['photo'],
                           catalog_id=category.id,
                           user_id=category.user_id)
            session.add(newitem)
            session.commit()
            flash('New Item Successfully Created')
            return redirect(url_for('showItems', category_name=category_name))
        else:
            flash('The %s item already exists! Kindly create a new item.' %
                  request.form['name'])
            return redirect(url_for('showItems', category_name=category_name))
    else:
        # Set new random CRSF TOKEN value
        app.jinja_env.globals['_csrf_token'] = generate_csrf_token()
        return render_template('newitem.html', category=category)


@app.route('/catalog/<category_name>/<item_name>/view')
def viewItem(category_name, item_name):
    """Render an item.

    arges: category_name: name of the category for the item to be viewed.
    item_name: name of the item to be viewed.
    Return: response to render item.html.
    """
    item = session.query(Item).filter_by(name=item_name).one()
    category = session.query(Catalog).filter_by(name=category_name).one()
    return render_template('item.html', category=category, item=item)


# Edit a item
@app.route('/catalog/<category_name>/<item_name>/edit', methods=['GET', 'POST'])
def editItem(category_name, item_name):
    """Edit an item.

    arges: category_name: name of the category for the item to be edited.
    item_name: name of the item to be edited.
    Return: response to render edititem.html.
    """
    if 'username' not in login_session:
        return redirect('/login')
    editeditem = session.query(Item).filter_by(name=item_name).one()
    category = session.query(Catalog).filter_by(name=category_name).one()
    if category.user.name != login_session['username']:
        return """<script>function myFunction() {alert('You are not authorized to edit items to this category. Please create your own category in order to edit items.');}</script><body onload='myFunction()''>"""
    if request.method == 'POST':
        if request.form['name']:
            editeditem.name = request.form['name']
        if request.form['description']:
            editeditem.description = request.form['description']
        if request.form['price']:
            editeditem.price = request.form['price']
        if request.form['photo']:
            editeditem.photo = request.form['photo']
        session.add(editeditem)
        session.commit()
        flash('Item Successfully Edited')
        return redirect(url_for('showItems', category_name=category.name))
    else:
        # Set new random CRSF TOKEN value
        app.jinja_env.globals['_csrf_token'] = generate_csrf_token()
        return render_template('edititem.html', category=category,
                               item=editeditem)


# Delete a item
@app.route('/catalog/<category_name>/<item_name>/delete',
           methods=['GET', 'POST'])
@login_required
def deleteItem(category_name, item_name):
    """Delete an item.

    arges: category_name: name of the category for the item to be deleted.
    item_name: name of the item to be deleted.
    Return: response to render deleteitem.html.
    """
    category = session.query(Catalog).filter_by(name=category_name).one()
    itemtodelete = session.query(Item).filter_by(name=item_name).one()
    if login_session['username'] != category.user.name:
        return """<script>function myFunction() {alert('You are not authorized to delete items to this category. Please create your own category in order to delete items.');}</script><body onload='myFunction()''>"""
    if request.method == 'POST':
        session.delete(itemtodelete)
        session.commit()
        flash('Item Successfully Deleted')
        return redirect(url_for('showItems', category_name=category_name))
    else:
        # Set new random CRSF TOKEN value
        app.jinja_env.globals['_csrf_token'] = generate_csrf_token()
        return render_template('deleteitem.html', item=itemtodelete)


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
