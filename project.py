from flask import Flask, render_template, request, redirect,jsonify, url_for, flash
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, User, Catalog, Item

from flask import session as login_session
import random, string

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

#Connect to Database and create database session
engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


@app.route('/fbconnect', methods=['POST', 'GET'])
def fbconnect():
  if request.args.get('state') != login_session['state']:
    response = make_response(json.dumps('Invalid state parameter.'), 401)
    response.headers['Content-Type'] = 'application/json'
    return response
  access_token = request.data

  #Exchange client token for long-live server-side token with GET /oauth/ access_token?grant_type=fb_exchange_token&client_id={app-id}&client_secret={app-secret}&fb_exchange_token={short-lived-token}
  app_id = json.loads(open('fb_client_secrets.json', 'r').read())['web']['app_id']
  app_secret = json.loads(open('fb_client_secrets.json', 'r').read())['web']['app_secret']
  print 'app_id'
  print app_id
  print 'app_secret'
  print app_secret
  print 'access_token'
  print access_token
  url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (app_id,app_secret, access_token)
  h = httplib2.Http()
  result = h.request(url, 'GET')[1]
  print 'token result'
  print result

  # Use token to get user from API 
  userinfo_url = "https://graph.facebook.com/v2.4/me"
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
  url = "https://graph.facebook.com/v2.4/me/picture?%s&redirect=0&height=200&width=200" % token
  h = httplib2.Http()
  result = h.request(url, 'GET')[1]
  print 'picture result'
  print result
  # Print 'url sent for API access:%s'% url
  # print 'API JSON result: %s' % result
  data = json.loads(result)
  login_session['picture'] = 'picture'

  user_id = getUserID(login_session['email'])
  if user_id  == None:
    user_id = createUser(login_session)

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
    response = make_response(json.dumps('Failed to upgrade the authorization code.', 401))
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
  if user_id  == None:
    user_id = createUser(login_session)

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


def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    print 'user_id'
    print user_id
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


@app.route('/disconnect', methods=['POST', 'GET'])
def disconnect():
  if 'provider' in login_session:
    if login_session['provider'] == 'google':
      gdisconnect()
      # del login_session['credentials']
      # del login_session['gplus_id']
    if login_session['provider'] == 'facebook':
      fbdisconnect()
      # del login_session['facebook_id']
    #  Reset the user's session.
    # del login_session['username']
    # del login_session['email']
    # del login_session['picture']
    # del login_session['provider']
    # del login_session['user_id']

    flash("You have successfully been logged out")
    return redirect(url_for('showCatalogs'))
  else:
    flash("You were not logged in!")
    response = make_response(json.dumps('Failed to revoke token for given user.', 400))
    return redirect(url_for('showCatalogs'))


@app.route('/fbdisconnect', methods=['POST', 'GET'])
def fbdisconnect():
  facebook_id = login_session['facebook_id']
  url = 'https://graph.facebook.com/%s/permissions' % facebook_id
  h = httplib2.Http()
  result = h.request(url, 'DELETE')[1]
  del login_session['user_id']
  del login_session['facebook_id']
  del login_session['username']
  del login_session['email']
  del login_session['picture']
  del login_session['provider']
  
  return 'You  have been successfully logged out!'


@app.route('/gdisconnect', methods=['POST', 'GET'])
def gdisconnect():
  credentials = login_session['credentials']
  print 'In gdisconnect access token is %s', credentials
  print 'User name is: ' 
  print login_session['username']

  # Only disconnect a connected user.
  # credentials = login_session['credentials']
  if credentials is None:
    response = make_response(json.dumps('Current user not connected.'), 401)
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
    print 'status'
    print result['status']
    #  Reset the user's session.
    del login_session['credentials']
    del login_session['gplus_id']
    del login_session['username']
    del login_session['email']
    del login_session['picture']
    del login_session['provider']
    
    response = make_response(json.dumps('Successfully disconnected.'), 200)
    response.headers['Content-Type'] = 'application/json'
    return response
  else:

    response = make_response(json.dumps('Failed to revoke token for given user.', 400))
    response.headers['Content-Type'] = 'application/json'
    return response


#JSON APIs to view Catalog Information
@app.route('/catalog/<int:catalog_id>/item/JSON')
def catalogJSON(catalog_id):
    catalog = session.query(Catalog).filter_by(id = catalog_id).one()
    items = session.query(Item).filter_by(catalog_id = catalog_id).all()
    return jsonify(items=[i.serialize for i in items])


@app.route('/catalog/<int:catalog_id>/item/<int:item_id>/JSON')
def itemJSON(catalog_id, item_id):
    item = session.query(Item).filter_by(id = item_id).one()
    return jsonify(item=item.serialize)

@app.route('/catalog/JSON')
def catalogsJSON():
    catalogs = session.query(Catalog).all()
    return jsonify(catalogs= [r.serialize for r in catalogs])


#Show all catalogs
@app.route('/')
@app.route('/catalog/')
def showCatalogs():
  catalogs = session.query(Catalog).order_by(asc(Catalog.name)).all()
  items = session.query(Item).order_by(asc(Item.created)).limit(10).all()
  print 'catalogs'
  print catalogs
  if 'username' not in login_session:
    return render_template('publiccatalog.html', catalogs = catalogs, items = items)
  else: 
    return render_template('catalog.html', catalogs = catalogs, items = items)

#Create a new catalog
@app.route('/catalog/new/', methods=['GET','POST'])
def newCatalog():
  if 'username' not in login_session:
    return redirect('/login')
  if request.method == 'POST':
      newCatalog = Catalog(name=request.form['name'],
                                 user_id=login_session['user_id'])
      session.add(newCatalog)
      flash('New Catalog %s Successfully Created' % newCatalog.name)
      session.commit()
      return redirect(url_for('showCatalogs'))
  else:
      return render_template('newCatalog.html')

#Edit a catalog
@app.route('/catalog/<int:catalog_id>/edit/', methods=['GET', 'POST'])
def editCatalog(catalog_id):
  editedCatalog = session.query(Catalog).filter_by(id=catalog_id).one()
  if 'username' not in login_session:
      return redirect('/login')
  if editedCatalog.user_id != login_session['user_id']:
      return "<script>function myFunction() {alert('You are not authorized to edit this catalog. Please create your own catalog in order to edit.');}</script><body onload='myFunction()''>"
  if request.method == 'POST':
    if request.form['name']:
      editedCatalog.name = request.form['name']
      flash('Catalog Successfully Edited %s' % editedCatalog.name)
      return redirect(url_for('showCatalogs'))
  else:
    return render_template('editCatalog.html', catalog=editedCatalog)


#Delete a catalog
@app.route('/catalog/<int:catalog_id>/delete/', methods=['GET','POST'])
def deleteCatalog(catalog_id):
    catalogToDelete = session.query(Catalog).filter_by(id=catalog_id).one()
    if 'username' not in login_session:
        return redirect('/login')
    if catalogToDelete.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authorized to delete this catalog. Please create your own catalog in order to delete.');}</script><body onload='myFunction()''>"
    if request.method == 'POST':
      session.delete(catalogToDelete)
      flash('%s Successfully Deleted' % catalogToDelete.name)
      session.commit()
      return redirect(url_for('showCatalogs', catalog_id=catalog_id))
    else:
      return render_template('deleteCatalog.html',catalog=catalogToDelete)

#Show a catalog's items
@app.route('/catalog/<int:catalog_id>/')
@app.route('/catalog/<int:catalog_id>/items/')
def showItems(catalog_id):
    print 'catalog_id'
    print catalog_id
    catalog = session.query(Catalog).filter_by(id=catalog_id).one()
    items = session.query(Item).filter_by(catalog_id=catalog_id).all()
    catalogs = session.query(Catalog).order_by(asc(Catalog.name)).all()
    creator = getUserInfo(catalog.user_id)
    if 'username' not in login_session or catalog.user_id != login_session['user_id']:
        return render_template('publicitems.html', items=items,
                               catalog=catalog,
                               creator=creator,
                               catalogs=catalogs)
    else:
        return render_template('items.html', items=items,
                               catalog=catalog,
                               creator=creator,
                               catalogs=catalogs)
     


# Create a new item
@app.route('/catalog/<int:catalog_id>/items/new/', methods=['GET', 'POST'])
def newItem(catalog_id):
    if 'username' not in login_session:
        return redirect('/login')
    catalog = session.query(Catalog).filter_by(id=catalog_id).one()
    if login_session['user_id'] != catalog.user_id:
        return "<script>function myFunction() {alert('You are not authorized to add items to this catalog. Please create your own catalog in order to add items.');}</script><body onload='myFunction()''>"
    if request.method == 'POST':
        newItem = Item(name=request.form['name'],
                       description=request.form['description'],
                       price=request.form['price'],
                       catalog_id=catalog_id,
                       user_id=catalog.user_id)
        session.add(newItem)
        session.commit()
        flash('New Item Successfully Created')
        return redirect(url_for('showItems', catalog_id=catalog.id))
    else:
        return render_template('newitem.html', catalog=catalog)

# Edit a item
@app.route('/catalog/<int:catalog_id>/items/<int:item_id>/edit', methods=['GET', 'POST'])
def editItem(catalog_id, item_id):

    if 'username' not in login_session:
        return redirect('/login')
    editedItem = session.query(Item).filter_by(id=item_id).one()
    catalog = session.query(Catalog).filter_by(id=catalog_id).one()
    if login_session['user_id'] != catalog.user_id:
        return "<script>function myFunction() {alert('You are not authorized to edit items to this catalog. Please create your own catalog in order to edit items.');}</script><body onload='myFunction()''>"
    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['description']:
            editedItem.description = request.form['description']
        if request.form['price']:
            editedItem.price = request.form['price']
        session.add(editedItem)
        session.commit() 
        flash('Item Successfully Edited')
        return redirect(url_for('showItems', catalog_id = catalog_id))
    else:
        return render_template('edititem.html', catalog_id = catalog_id, item_id = item_id, item = editedItem)


#Delete a item
@app.route('/catalog/<int:catalog_id>/items/<int:item_id>/delete', methods=['GET', 'POST'])
def deleteItem(catalog_id, item_id):
    if 'username' not in login_session:
        return redirect('/login')
    catalog = session.query(Catalog).filter_by(id=catalog_id).one()
    itemToDelete = session.query(Item).filter_by(id=item_id).one()
    if login_session['user_id'] != catalog.user_id:
        return "<script>function myFunction() {alert('You are not authorized to delete items to this catalog. Please create your own catalog in order to delete items.');}</script><body onload='myFunction()''>"
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash('Item Successfully Deleted')
        return redirect(url_for('showItems', catalog_id=catalog_id))
    else:
        return render_template('deleteitem.html', item=itemToDelete)




if __name__ == '__main__':
  app.secret_key = 'super_secret_key'
  app.debug = True
  app.run(host = '0.0.0.0', port = 5000)
