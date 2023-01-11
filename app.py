from flask import Flask, render_template, flash, redirect, url_for, session, request, send_from_directory, logging
from flask_mysqldb import MySQL
from wtforms import Form, StringField, TextAreaField, PasswordField, DecimalField, validators
from passlib.hash import sha256_crypt
from functools import wraps
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge
import os

#pip install flask-mysqldb
#pip install flask-WTF
#pip install passlib

app = Flask(__name__)
app.config['UPLOAD_DIRECTORY'] = 'static/files'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 *1024 # 16MB
app.config['ALLOWED_EXTENSIONS'] = ['.jpeg', 'jpeg', '.png', '.gif']

# Config MySQL
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'jobolflask'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
# initialize MySQL
mysql = MySQL(app)

# Index
@app.route('/')
def index():
    return render_template('home.html')

# About
@app.route('/about')
def about():
    return render_template('about.html')

# Check if user is logged in
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, Please login', 'danger')
            return redirect(url_for('login'))
    return wrap

# Prevent access to logged users
def login_not_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "logged_in" in session:
            return redirect(url_for('index'))
        else:
            return f(*args, **kwargs)
    return decorated_function

# Listings
@app.route('/listings')
def listings():
    # Create Cursor
    cur = mysql.connection.cursor()

    # Get listings
    result = cur.execute("SELECT * FROM listings")

    listings = cur.fetchall()

    if result > 0:
        return render_template('listings.html', listings=listings)
    else:
        msg = 'No Item Lists Found'
        return render_template('listings.html', msg=msg)
    
    # Close connection
    cur.close()

# Single listing
@app.route('/listing/<string:id>')
@is_logged_in
def listing(id):
     # Create Cursor
    cur = mysql.connection.cursor()

    # Get articles
    result = cur.execute("SELECT * FROM listings WHERE id = %s", [id])

    listing = cur.fetchone()

    return render_template('listing.html', listing=listing)

# Register form class
class RegisterForm(Form):
    name = StringField('Name', [validators.Length(min=1, max=50)])
    username = StringField('Username', [validators.Length(min=4, max=25)])
    email = StringField('Email', [validators.Length(min=6, max=50)])
    password = PasswordField('Password',[
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Password do not match')
    ])
    confirm = PasswordField('Confirm Password')

# User Register
@app.route('/register', methods = ['GET', 'POST'])
@login_not_required
def register():
    form=RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email = form.email.data
        username = form.username.data 
        password = sha256_crypt.encrypt(str(form.password.data)) 

        # Create cursor
        cur = mysql.connection.cursor()

        # Execute query
        cur.execute("INSERT INTO users(name, email, username, password) VALUES(%s, %s, %s, %s)", (name, email, username, password))

        # Commit to db
        mysql.connection.commit()

        #Close Connection
        cur.close()

        flash('You are now registered and can login', 'success')
        return redirect(url_for('index')) 

    return render_template('register.html', form=form)

# User login
@app.route('/login', methods = ['GET', 'POST'])
@login_not_required
def login():
    if request.method == "POST":
        # Get form fields
        username = request.form['username']
        password_candidate = request.form['password'] 

        # Create cursor
        cur = mysql.connection.cursor()

        # Get user by username
        result = cur.execute("SELECT * FROM users WHERE username = %s", [username])

        if result > 0:
            # Get stored hash
            data = cur.fetchone()
            password = data['password']

            # Compare passwords
            if sha256_crypt.verify(password_candidate, password):
                # Passed
                session['logged_in'] = True
                session['username'] = username

                flash('You are now logged in', 'success')
                return redirect(url_for('dashboard'))
            else:
                error = 'Invalid login'
                return render_template('login.html', error=error)  
            # Close connection
            cur.close()
        else:
            error = 'Username not found'
            return render_template('login.html', error=error) 

    return render_template('login.html') 


# Logout
@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect (url_for('login'))

# Dashboard
@app.route('/dashboard')
@is_logged_in
def dashboard():
    
    # Create Cursor
    cur = mysql.connection.cursor()

    # Get articles
    username = session['username']
    result = cur.execute("SELECT * FROM listings WHERE username = %s", [username])

    listings = cur.fetchall()

    if result > 0:
        return render_template('dashboard.html', listings=listings)
    else:
        msg = 'No Item Lists Found'
        return render_template('dashboard.html', msg=msg)
    
    # Close connection
    cur.close()

# listing form class
class ListingForm(Form):
    title = StringField('Title', [validators.Length(min=1, max=100)])
    company = StringField('Company', [validators.Length(min=1, max=100)])
    body = TextAreaField('Body')
    salary = DecimalField('Salary', [validators.DataRequired()])

# Add listing
@app.route('/add_listing', methods = ['GET', 'POST'])
@is_logged_in
def add_listing():
   
    form = ListingForm(request.form)
    if request.method == 'POST' and form.validate():
        title = form.title.data
        company = form.company.data
        body = form.body.data
        salary = form.salary.data
        try:
            file = request.files['file']
            extension = os.path.splitext(file.filename)[1]
            if file:

                if extension not in app.config['ALLOWED_EXTENSIONS']:
                    flash('File is not an image', 'danger')
                    return redirect (url_for('dashboard'))

                file.save(os.path.join(
                    app.config['UPLOAD_DIRECTORY'],
                    secure_filename(file.filename)
                ))
        except RequestEntityTooLarge:
            flash('File too large, it must not exceed 16MB', 'danger')
            return redirect (url_for('dashboard'))

        # Create cursor
        cur = mysql.connection.cursor()

        # Execute query
        cur.execute("INSERT INTO listings(title, company, body, salary, file, username) VALUES (%s, %s, %s, %s, %s, %s)", (title, company, body, salary, secure_filename(file.filename), session['username']))

        # Commit to db
        mysql.connection.commit()

        # Close connection
        cur.close()

        flash('List Created', 'success')

        return redirect (url_for('dashboard'))
    
    return render_template('add_listing.html', form=form)

# Edit listing
@app.route('/edit_listing/<string:id>', methods = ['GET', 'POST'])
@is_logged_in
def edit_listing(id):

    # Create cursor
    cur = mysql.connection.cursor()

    # Get listing by id
    result = cur.execute('SELECT * FROM listings WHERE id = %s', [id])

    listing =  cur.fetchone()
    cur.close()

    # Get form
    form = ListingForm(request.form)

    # Populate listing form fields
    form.title.data = listing['title']
    form.company.data = listing['company']
    form.body.data = listing['body']
    form.salary.data = listing['salary']

    if request.method == 'POST' and form.validate():
        title = request.form['title']
        company = request.form['company']
        body = request.form['body']
        salary = request.form['salary']
        try:
            file = request.files['file']
            extension = os.path.splitext(file.filename)[1]
            if file:

                if extension not in app.config['ALLOWED_EXTENSIONS']:
                    flash('File is not an image', 'danger')
                    return redirect (url_for('dashboard'))

                file.save(os.path.join(
                    app.config['UPLOAD_DIRECTORY'],
                    secure_filename(file.filename)
                ))
        except RequestEntityTooLarge:
            flash('File too large, it must not exceed 16MB', 'danger')
            return redirect (url_for('dashboard'))

        # Create cursor
        cur = mysql.connection.cursor()
        app.logger.info(title)

        # Execute query
        cur.execute("UPDATE listings SET title=%s, company=%s, body=%s, salary=%s, file=%s WHERE id = %s", ([title, company, body, salary, secure_filename(file.filename), id]))

        # Commit to db
        mysql.connection.commit()

        # Close connection
        cur.close()

        flash('List Updated', 'success')

        return redirect (url_for('dashboard'))
    
    if listing['username'] != session['username']:
        flash('Unauthorized, Please login', 'danger')
        return redirect (url_for('index'))
    else:
        return render_template('edit_listing.html', form=form)

# Delete listing
@app.route('/delete_listing/<string:id>', methods = ['POST'])
@is_logged_in
def delete_listing(id):
    # Create Cursor
    cur =  mysql.connection.cursor()

    # Execute
    cur.execute("DELETE FROM listings WHERE id = %s", [id])

    # Commit to db
    mysql.connection.commit()

    # Close connection
    cur.close()

    flash('List Deleted', 'success')

    return redirect (url_for('dashboard'))

# Search listing
@app.route('/search_listing/<string:value>', methods = ['GET', 'POST'])
def search_listing(value):
    if request.method == 'POST':
        value =  value
    # Create cursor
    cur = mysql.connection.cursor()

    # Get listing by value
    result = cur.execute('SELECT * FROM listings WHERE title = %s OR company = %s', [value, value])

    listings = cur.fetchall()
    # Close connection
    cur.close()

    if result > 0:
        return render_template('search_listing.html', listings=listings)
    else:
        msg = 'No Item Lists Found'
        return render_template('search_listing.html', msg=msg)
    
# Search Result
@app.route('/result/<string:title>', methods = ['GET', 'POST'])
def searched(title):
    
     # Create Cursor
    cur = mysql.connection.cursor()

    # Get result
    result = cur.execute('SELECT * FROM listings WHERE title = %s OR company = %s', [title, title])

    listing = cur.fetchone()

    # Close connection
    cur.close()

    return render_template('listing.html', listing=listing)

@app.route('/serve-image/<filename>', methods=['GET'])
def serve_image(filename):
  return send_from_directory(app.config['UPLOAD_DIRECTORY'], filename)
    

if __name__ == '__main__':
    app.secret_key='secret24'
    app.run(debug=True) 