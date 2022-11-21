"""
This is a web application that helps the user to track their BMI progress.

This web applications is made using Flask
framework with Python and WTForms, connected to database using SQLAlchemy.

@autor      Oriol Ventosa Freire
@licence    GNU GPL
@copyright  (C) Oriol Ventosa Freire 2022

"""

# Import Flask framework otherwise we cannot use it with our web app
from flask import Flask, render_template, abort, request, redirect, url_for, session
# Import module for HTTP exceptions, e.g. handle unknown/unpredicted URL addresses
# This will hangle e.g. 404 Not Found error or 500 Internal Server error
from werkzeug.exceptions import HTTPException

# Import Flask WTForms module to work with web forms
from flask_wtf import FlaskForm
# Import web form elements that will be used in web forms
from wtforms import StringField, SubmitField, PasswordField, SelectField, BooleanField
# Import web form element validators to validate values inputted by user
from wtforms.validators import DataRequired, Length

# Import Flask SQLAlchemy modules
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import ForeignKey, exc

# Import Datetime module to work with date/time values
from datetime import datetime

# Import Hashlib library to use MD5 method for password encryption
from hashlib import md5


# ========== Create web application ========== #

# Create new instance of a web application
app = Flask(__name__)
# Import web application configuration options from external python file
app.config.from_pyfile('config1.py')

# Connect web application to the database
db = SQLAlchemy(app)


# ========== Handle web application routes ========== #
#
#  HTTP method | URL path               | Controller function
# -------------+------------------------+----------------------
#  GET         | /                      | index()
#  GET         | /benchmark/            | benchmark()
#  GET         | /results/<id>          | benchmark(id)
#  GET, POST   | /result/add            | add_result()
#  GET, POST   | /result/edit/<id>      | edit_result(id)
#  GET, POST   | /result/delete/<id>    | delete_result(id)


# ============================================================ #

# -------------+------------------------+----------------------
#  GET, POST   | /login                 | login_user()
#  GET, POST   | /logout                | logout_user()
#  GET, POST   | /password              | change_password()
#  GET, POST   | /register              | new_account()
#  GET, POST   | /user/add              | add_user()
#  GET, POST   | /user/edit/<id>        | edit_user(id)
#  GET, POST   | /user/delete/<id>      | delete_user(id)
#  GET         | /admin                 | admin()
# -------------+------------------------+----------------------


# Display index page
@app.route('/')
def index():
    # Display index page
    return render_template('index.html', user=session)


# Display user's results and benchmark
@app.route('/benchmark')
def benchmark():
    # If user is not logged-in, abort viewing
    if not session or session['loggedin'] == False:
        message = 'You do not have access permission.'
        abort(401, message)

    # Get specific user's results based on category ID

    results = db.session.query(Result).filter(Result.user_id == session['user_id'])  # all results

    """
    resultsDay = db.session.query(Result).filter(
        (Result.user_id == session['user_id']),
        (Result.daytime == 1))  # ""and Result.morning == 1""

    resultsNight = db.session.query(Result).filter(
        (Result.user_id == session['user_id']),
        (Result.daytime == 0))  # ""and Result.night == 1""
    """

    # for result in results:
    #    result.BMI = round(float(result.weight) / float(result.height) ** 2, 1)

    if results.count() == 0:
        results = None
        labels = None
        data_s = None
        data_d = None
    else:
        # Format data to be used in graph
        labels = []
        data_s = []
        data_d = []
        for result in results:
            labels.append(str(result.date.strftime('%d. %m. %Y')))
            data_s.append(result.systolic)
            data_d.append(result.diastolic)
# this line above puts the height in the y axis instead of showing the bmi on the y axis
    # Get category title from category ID
    # title = get_category_title_from_id(id)

    data = {
        # 'title': title,
        # 'benchmark': benchmark,
        'results': results,
        'labels': labels,
        'data_s': data_s,
        'data_d': data_d
    }

    # Display page with the results/benchmark
    return render_template('benchmark.html', data=data, user=session)


# Add user's result to the database
@app.route('/result/add', methods=['GET', 'POST'])
def add_result():
    # If user is not logged-in, abort adding
    if not session or session['loggedin'] == False:
        message = 'You do not have access permission.'
        abort(401, message)

    # Use form
    form = AddResultForm()

    # Process form
    if form.validate_on_submit():
        # Handle adding data to the database'
        if request.method == 'POST' and 'submit' in request.form:
            # Create data record

                record = Result(
                    user_id=session['user_id'],
                    diastolic=request.form.get('diastolic'),
                    systolic=request.form.get('systolic'),
                    daytime=request.form.get('daytime'),
                    date=datetime.strptime(request.form.get('date'), '%d. %m. %Y')
                )
                # Save data to the database
                db.session.add(record)
                db.session.commit()
                # Return to benchmark page
                return redirect(url_for('benchmark'))
    # Display page with the form
    return render_template('result_form.html', form=form, user=session)


# Edit user's result in the database
@app.route('/result/edit/<id>', methods=['GET', 'POST'])
def edit_result(id):
    # Get existing record from database
    record = db.session.query(Result).get(id)
    # print(id)
    # print(record)

    # If there is no record, abort editing
    if not record:
        message = 'Result with this ID cannot be found. Either it was deleted or it did not exist in the first place.'
        abort(404, message)

    # If user is not logged-in, abort editing
    if not session or session['loggedin'] == False:
        message = 'You do not have access permission.'
        abort(401, message)

    # If logged-in user is not an owner or admin, abort editing
    if record.user_id != session['user_id'] and session['is_admin'] == False:
        message = 'You are not authorized to edit this result.'
        abort(403, message)

    # Format date from what is saved in the database
    # to what we need in the form input box ...
    # e.g: from '2022-05-23 00:00:00' to '23. 05. 2022'
    record.date = record.date.strftime('%d. %m. %Y')

    # Use form
    form = EditResultForm(obj=record)

    # Process form
    if form.validate_on_submit():
        print("Form validates")
        # Handle updating data in the database
        if request.method == 'POST' and 'submit' in request.form:
            print("Processing form")
            # Update data record
            record.weight = request.form.get('weight')

            #record.bmi    = round(float(request.form.get('weight')) / float(request.form.get('height')) ** 2, 1)
            record.date = datetime.strptime(
                request.form.get('date'), '%d. %m. %Y')

            # Save data to the database
            db.session.commit()

            # Return to benchmark page
            return redirect(url_for('benchmark'))

    # Display page with the form
    return render_template('result_form.html', form=form, user=session)


# Delete user's result from the database
@app.route('/result/delete/<id>', methods=['GET', 'POST'])
def delete_result(id):
    # Get existing record from database
    record = db.session.query(Result).get(id)

    # If there is no record, abort deleting
    if not record:
        message = 'Result with this ID cannot be found. Either it was deleted or it did not exist in the first place.'
        abort(404, message)

    # If user is not logged-in, abort deleting
    if not session or session['loggedin'] == False:
        message = 'You do not have access permission.'
        abort(401, message)

    # If logged-in user is not an owner or admin, abort deleting
    if record.user_id != session['user_id'] and session['is_admin'] == False:
        message = 'You are not authorized to delete this result.'
        abort(403, message)

    # Use form
    form = DeleteResultForm()

    # Process form
    if form.validate_on_submit():
        # Handle updating data in the database
        if request.method == 'POST' and 'submit' in request.form:

            # Delete data from the database
            db.session.delete(record)
            db.session.commit()

            # Return to benchmark page
            return redirect(url_for('benchmark'))

    # Display page with the form
    return render_template('remove_form.html', form=form, user=session)

# Add benchmark to the database
###########################################################


@app.route('/benchmark/add', methods=['GET', 'POST'])
def add_benchmark():
    # If user is not logged-in, abort adding
    if not session or session['loggedin'] == False:
        message = 'You do not have access permission.'
        abort(401, message)

    # Use form
    form = AddBenchmarkForm()

    # Process form
    if form.validate_on_submit():
        # Handle adding data to the database
        if request.method == 'POST' and 'submit' in request.form:
            # Create data record
            record = Benchmark(
                user_id=session['user_id'],
                type=int(request.form.get('type')),
                category=int(request.form.get('category')),
                result=request.form.get('result'),
                date=datetime.strptime(request.form.get('date'), '%d. %m. %Y'),
            )

            # Save data to the database
            db.session.add(record)
            db.session.commit()

            # Return to benchmark page
            return redirect(url_for('results'))

    # Display page with the form
    return render_template('benchmark_form.html', form=form, user=session)

# Edit benchmark in the database


@app.route('/benchmark/edit/<id>', methods=['GET', 'POST'])
def edit_benchmark(id):
    # Get existing record from database
    record = db.session.query(Benchmark).get(id)

    # If there is no record, abort editing
    if not record:
        message = 'Benchmark with this ID cannot be found. Either it was deleted or it did not exist in the first place.'
        abort(404, message)

    # If user is not logged-in, abort editing
    if not session or session['loggedin'] == False:
        message = 'You do not have access permission.'
        abort(401, message)

    # If logged-in user is not an owner or admin, abort editing
    if record.user_id != session['user_id'] and session['is_admin'] == False:
        message = 'You are not authorized to edit this benchmark.'
        abort(403, message)

    # Format date from what is saved in the database
    # to what we need in the form input box ...
    # e.g: from '2022-05-23 00:00:00' to '23. 05. 2022'
    record.date = record.date.strftime('%d. %m. %Y')

    # Use form
    form = EditBenchmarkForm(obj=record)

    # Process form
    if form.validate_on_submit():
        # Handle updating data in the database
        if request.method == 'POST' and 'submit' in request.form:
            # Update data record
            record.type = int(request.form.get('type'))
            record.category = int(request.form.get('category'))
            record.result = request.form.get('result')
            record.date = datetime.strptime(
                request.form.get('date'), '%d. %m. %Y')

            # Save data to the database
            db.session.commit()

            # Return to benchmark page
            return redirect(url_for('results'))

    # Display page with the form
    return render_template('benchmark_form.html', form=form, user=session)


# Delete benchmark from the database
@app.route('/benchmark/delete/<id>', methods=['GET', 'POST'])
def delete_benchmark(id):
    # Get existing record from database
    record = db.session.query(Benchmark).get(id)

    # If there is no record, abort deleting
    if not record:
        message = 'Benchmark with this ID cannot be found. Either it was deleted or it did not exist in the first place.'
        abort(404, message)

    # If user is not logged-in, abort deleting
    if not session or session['loggedin'] == False:
        message = 'You do not have access permission.'
        abort(401, message)

    # If logged-in user is not an owner or admin, abort deleting
    if record.user_id != session['user_id'] and session['is_admin'] == False:
        message = 'You are not authorized to delete this benchmark.'
        abort(403, message)

    # Use form
    form = DeleteBenchmarkForm()

    # Process form
    if form.validate_on_submit():
        # Handle updating data in the database
        if request.method == 'POST' and 'submit' in request.form:

            # Delete data from the database
            db.session.delete(record)
            db.session.commit()

            # Return to benchmark page
            return redirect(url_for('results'))

    # Display page with the form
    return render_template('remove_form.html', form=form, user=session)
###########################################################

# Login user


@app.route('/login', methods=['GET', 'POST'])
def login_user():
    # If user is already logged-in, abort
    for item in session:
        print(item)
    if session and ('loggedin' in session.keys() and session['loggedin'] == True):
        message = 'You are already signed in.'
        abort(200, message)

    # Setup form
    form = LoginForm()

    # Process form before populating it with default values
    if form.validate_on_submit():
        if request.method == 'POST' and 'submit' in request.form:
            # Get user data from the database
            user = db.session.query(User).filter_by(
                username=request.form.get('username')).first()

            # Handle user login
            if user:
                password = md5(request.form.get(
                    'password').encode('utf-8')).hexdigest()
                if user.password.lower() == password:
                    session['firstname'] = user.firstname
                    session['lastname'] = user.lastname
                    session['username'] = user.username
                    session['user_id'] = user.id
                    session['loggedin'] = True
                    session['is_admin'] = user.is_admin
                else:
                    # Incorrect password
                    return redirect(url_for('login_user'))
            else:
                # User not found
                message = 'User with this ID cannot be found. Either it was deleted or it did not exist in the first place.'
                abort(404, message)

            # Return to index page
            return redirect(url_for('index'))

    # Display page with the form
    return render_template('login_form.html', form=form, user=session)


# Logout user
@app.route('/logout', methods=['GET', 'POST'])
def logout_user():
    # If user is not logged-in, abort deleting
    if not session or ('loggedin' in session.keys() and session['loggedin'] == False):
        message = 'You do not have access permission.'
        abort(401, message)

    # Setup form
    form = LogoutForm()

    # Process form before populating it with default values
    if form.validate_on_submit():
        # Handle user logout
        if request.method == 'POST' and 'submit' in request.form:
            # Clear session with user's data
            session.clear()

            # Return to index page
            return redirect(url_for('index'))

    # Display page with the form
    return render_template('remove_form.html', form=form, user=session)


# Change user's password
@app.route('/password', methods=['GET', 'POST'])
def change_password():
    # Get user data from the database
    user = User.query.filter_by(username=session['username']).first()

    # If there is no user, abort editing
    if not user:
        message = 'User with this ID cannot be found. Either it was deleted or it did not exist in the first place.'
        abort(404, message)

    # If user is not logged-in, abort editing
    if not session or session['loggedin'] == False:
        message = 'You do not have access permission.'
        abort(401, message)

    # If logged-in user is not an owner, abort editing
    # Note: admins are not allowed to change user's password, only user can do that
    if user.id != session['user_id']:
        message = 'You are not authorized to change this password.'
        abort(403, message)

    # Setup form
    form = ChangePasswordForm()

    # Process form before populating it with default values
    if form.validate_on_submit():
        # Handle user password change
        if request.method == 'POST' and 'submit' in request.form:

            password = md5(form.password.data.encode('utf-8')).hexdigest()
            if user.password.lower() == password and \
               form.passnew1.data == form.passnew2.data:

                # Change user password in the database
                user.password = md5(
                    form.passnew1.data.encode('utf-8')).hexdigest()
                db.session.commit()
            else:
                # Incorrect current password or unmatching new password
                message = 'Either your current password is incorrect or new passwords do not match.'
                abort(400, message)

        # Return to index page
        return redirect(url_for('index'))

    # Display page with the form
    return render_template('passwd_form.html', form=form, user=session)


# Register new user's account
@app.route('/register', methods=['GET', 'POST'])
def new_account():
    # Setup form
    form = NewAccountForm()

    # Process form; no default values here
    if form.validate_on_submit():
        # Handle adding user to the database
        if request.method == 'POST' and 'submit' in request.form:

            # Create user record
            record = User(
                firstname=request.form.get('firstname'),
                lastname=request.form.get('lastname'),
                username=request.form.get('username'),
                password=md5(request.form.get(
                    'password').encode('utf-8')).hexdigest(),
                birth_date=datetime.strptime(
                    request.form.get('birth_date'), '%d. %m. %Y'),
                is_admin=False
            )
            try:
                # Try saving user to the database
                db.session.add(record)
                db.session.commit()
            except exc.IntegrityError:
                # Undo writing to the database if IntegrityError
                # This means that user with that username already exists
                db.session.rollback()
                # So raise error and abort
                message = 'SQLAlchemy IntegrityError: This username already exists in the database. Select different username when creating a new user.'
                abort(500, message)

            # Return to index page
            return redirect(url_for('index'))

    # Display page with the form
    return render_template('user_form.html', form=form, user=session)


# Add user to the database
@app.route('/user/add', methods=['GET', 'POST'])
def add_user():
    # If user is not logged-in, abort adding
    if not session or session['loggedin'] == False:
        message = 'You do not have access permission.'
        abort(401, message)

    # If logged-in user is not an admin, abort adding
    # Note: only admins are allowed to edit users
    if session['is_admin'] == False:
        message = 'You are not authorized to edit this user.'
        abort(403, message)

    # Setup form
    form = AddUserForm()

    # Process form; no default values here
    if form.validate_on_submit():
        # Handle adding user to the database
        if request.method == 'POST' and 'submit' in request.form:

            # Create user record
            record = User(
                firstname=request.form.get('firstname'),
                lastname=request.form.get('lastname'),
                username=request.form.get('username'),
                password=md5(request.form.get(
                    'password').encode('utf-8')).hexdigest(),
                birth_date=datetime.strptime(
                    request.form.get('birth_date'), '%d. %m. %Y'),
                is_admin=request.form.get('is_admin')
            )
            try:
                # Try saving user to the database
                db.session.add(record)
                db.session.commit()
            except exc.IntegrityError:
                # Undo writing to the database if IntegrityError
                # This means that user with that username already exists
                db.session.rollback()
                # So raise error and abort
                message = 'SQLAlchemy IntegrityError: This username already exists in the database. Select different username when creating a new user.'
                abort(500, message)

            # Return to admin page
            return redirect(url_for('admin'))

    # Display page with the form
    return render_template('user_form.html', form=form, user=session)


# Edit user in the database
@app.route('/user/edit/<id>', methods=['GET', 'POST'])
def edit_user(id):
    # Get an existing user
    record = db.session.query(User).get(id)

    # If there is no record, abort editing
    if not record:
        message = 'User with this ID cannot be found. Either it was deleted or it did not exist in the first place.'
        abort(404, message)

    # If user is not logged-in, abort editing
    if not session or session['loggedin'] == False:
        message = 'You do not have access permission.'
        abort(401, message)

    # If logged-in user is not an admin, abort editing
    # Note: only admins are allowed to edit users
    if session['is_admin'] == False:
        message = 'You are not authorized to edit this user.'
        abort(403, message)

    # Also abort editing main admin (ID = 1)
    if int(id) == 1:
        message = 'You are not authorized to edit main admin.'
        abort(403, message)

    # Format date from what is saved in the database
    # to what we need in the form input box ...
    # e.g: from '2022-05-23 00:00:00' to '23. 05. 2022'
    record.birth_date = record.birth_date.strftime('%d. %m. %Y')

    # Setup form
    form = EditUserForm(obj=record)

    # Process form; no default values here
    if form.validate_on_submit():
        # Handle updating user in the database
        if request.method == 'POST' and 'submit' in request.form:

            # Save user details to the database
            # User should not be able to change their username
            # Password can be changed using separate form
            record.firstname = request.form.get('firstname')
            record.lastname = request.form.get('lastname')
            record.birth_date = datetime.strptime(
                request.form.get('birth_date'), '%d. %m. %Y')
            record.is_admin = True if request.form.get(
                'is_admin') == 'y' else False

            # Save data to the database
            db.session.commit()

            # Return to admin page
            return redirect(url_for('admin'))

    # Display page with the form
    return render_template('user_form.html', form=form, user=session)


# Delete user from the database
@app.route('/user/delete/<id>', methods=['GET', 'POST'])
def delete_user(id):
    # Get a given existing user
    record = db.session.query(User).get(id)

    # If there is no record, abort editing
    if not record:
        message = 'User with this ID cannot be found. Either it was deleted or it did not exist in the first place.'
        abort(404, message)

    # If user is not logged-in, abort editing
    if not session or session['loggedin'] == False:
        message = 'You do not have access permission.'
        abort(401, message)

    # If logged-in user is not an admin, abort editing
    # Note: only admins are allowed to delete users
    if session['is_admin'] == False or id == 1:
        message = 'You are not authorized to delete this user.'
        abort(403, message)

    # Also abort deleting main admin (ID = 1)
    if int(id) == 1:
        message = 'You are not authorized to delete main admin.'
        abort(403, message)

    # Setup form
    form = DeleteUserForm()

    # Process form; no default values here
    if form.validate_on_submit():
        # Handle deleting user from the database
        if request.method == 'POST' and 'submit' in request.form:

            # Delete user from the database
            db.session.delete(record)
            db.session.commit()

            # Return to admin page
            return redirect(url_for('admin'))

    # Display page with the form
    return render_template('remove_form.html', form=form, user=session)


# Administration section of the web application
@app.route('/admin', methods=['GET', 'POST'])
def admin():
    # If user is not logged-in, abort editing
    if not session or session['loggedin'] == False:
        message = 'You do not have access permission.'
        abort(401, message)

    # If logged-in user is not an admin, abort editing
    # Note: only admins are allowed to delete users
    if session['is_admin'] == False:
        message = 'You are not authorized to access administration section.'
        abort(403, message)

    # Get all users from the database
    users = db.session.query(User).all()
    if len(users) == 0:
        users = None

    data = {
        'title': 'User administration',
        'users': users,
    }

    # Display user administration page
    return render_template('admin.html', data=data, user=session)


# Handle HTTP Exceptions
@app.errorhandler(HTTPException)
def handle_error(error):
    # Display error page
    return render_template('error.html', error=error, user=session), error.code


# Function to get available benchmarks
def get_benchmarks():
    # Maybe later we can save benchmarks to the database
    # and get their names from database here, but for now:

    # Regular users can only add their PB and SB
    benchmarks = [
        (5, 'Personal Best'),
        (6, 'Season Best'),
    ]

    # Admins can add all benchmarks
    if session and ('is_admin' in session.keys() and session['is_admin'] == True):
        benchmarks = [
            (1, 'World Record'),
            (2, 'Olympic Record'),
            (3, 'European Record'),
            (4, 'National Record'),
            (5, 'Personal Best'),
            (6, 'Season Best'),
        ]

    return benchmarks


# ========== Form definitions ========== #

# Form to add result
class AddResultForm(FlaskForm):
    title = 'Add result'
    systolic = StringField(
        'Systolic',
        validators=[DataRequired(
            'You must provide your systolic blood pressure reading.')],
        render_kw={'placeholder': 'Systolic'}
    )
    diastolic = StringField(
        'Diastolic',
        validators=[DataRequired(
            'You must provide your diastolic blood pressure reading.')],
        render_kw={'placeholder': 'Diastolic'}
    )
    daytime = BooleanField(
        'daytime',
        render_kw={
            'data-toggle': 'toggle',
            'data-size': 's',  # Extra small
            'data-on': 'Morning',
            'data-off': 'Night',
            'data-onstyle': 'warning',
            'data-offstyle': 'dark'
        }
    )
    date = StringField(
        'Date of measuring',
        render_kw={
            'data-provide': 'datepicker'
        },
        validators=[DataRequired('You must provide a date.')]
    )
    submit = SubmitField('Create')


# Form to edit result
class EditResultForm(FlaskForm):
    title = 'Edit result'
    diastolic = StringField(
        'Diastolic',  # previously said weight in kg
        validators=[DataRequired('You must provide event name.')]
        #  choices = get_categories(),
        # Make sure that values are integers,otherwise
        # form validation will not validate the form.

    )
    systolic = StringField(
        'Systolic',  # previsouly said heigt in metres
        validators=[DataRequired('You must provide event name.')]
    )
    date = StringField(
        'Date of measuring',
        validators=[DataRequired('You must provide event date.')]
    )
    submit = SubmitField('Update')


# Form to delete result
class DeleteResultForm(FlaskForm):
    title = 'Delete result'
    message = 'Do you really want to delete this result? It cannot be undone.'
    submit = SubmitField('Delete')


# Form to add benchmark
class AddBenchmarkForm(FlaskForm):
    title = 'Add benchmark'
    type = SelectField(
        'Benchmark type',
        choices=get_benchmarks(),
        # Make sure that values are integers,otherwise
        # form validation will not validate the form.
        coerce=int
    )
    category = SelectField(
        'Category',
        # choices = get_categories(),
        # Make sure that values are integers,otherwise
        # form validation will not validate the form.
        coerce=int
    )
    date = StringField(
        'Benchmark date',
        validators=[DataRequired('You must provide benchmark date.')]
    )
    result = StringField(
        'Benchmark result',
        validators=[DataRequired('You must provide benchmark result.')]
    )
    submit = SubmitField('Create')


# Form to edit benchmark
class EditBenchmarkForm(FlaskForm):
    title = 'Edit benchmark'
    type = SelectField(
        'Benchmark type',
        choices=get_benchmarks(),
        # Make sure that values are integers,otherwise
        # form validation will not validate the form.
        coerce=int
    )
    category = SelectField(
        'Category',
        # choices = get_categories(),
        # Make sure that values are integers,otherwise
        # form validation will not validate the form.
        coerce=int
    )
    date = StringField(
        'Benchmark date',
        validators=[DataRequired('You must provide benchmark date.')]
    )
    result = StringField(
        'Benchmark result',
        validators=[DataRequired('You must provide benchmark result.')]
    )
    submit = SubmitField('Update')


# Form to delete benchmark
class DeleteBenchmarkForm(FlaskForm):
    title = 'Delete benchmark'
    message = 'Do you really want to delete this benchmark? It cannot be undone.'
    submit = SubmitField('Delete')


# Form to sign in user
class LoginForm(FlaskForm):
    title = 'Sign in'
    username = StringField(
        'Username',
        validators=[DataRequired('You must provide username to sign in!')]
    )
    password = PasswordField(
        'Password',
        validators=[
            DataRequired('You must provide password to sign in!'),
            Length(5, 20, 'Your password is either too short or too long!')
        ],
        description='Password must be between 5 and 20 characters.'
    )
    submit = SubmitField('Sign in')


# Form to sign out user
class LogoutForm(FlaskForm):
    title = 'Sign out'
    message = 'Are you sure you want to sign out?'
    submit = SubmitField('Sign out')


# Form to change user password
class ChangePasswordForm(FlaskForm):
    title = 'Change password'
    message = 'To change your password first enter your current password and then enter your new password twice.'
    password = PasswordField(
        'Current password',
        validators=[
            DataRequired('You must provide password.'),
            Length(5, 20, 'The password is either too short or too long.')
        ],
    )
    passnew1 = PasswordField(
        'New password',
        validators=[
            DataRequired('You must provide password.'),
            Length(5, 20, 'The password is either too short or too long.')
        ],
        description='Password must be between 5 and 20 characters.'
    )
    passnew2 = PasswordField(
        'New password again',
        validators=[
            DataRequired('You must provide password.'),
            Length(5, 20, 'The password is either too short or too long.')
        ],
    )
    submit = SubmitField('Change')


# Form to register new account
class NewAccountForm(FlaskForm):
    title = 'Create account'
    register = True
    firstname = StringField(
        'First name',
        validators=[DataRequired('You must provide first name.')]
    )
    lastname = StringField(
        'Last name',
        validators=[DataRequired('You must provide last name.')]
    )
    username = StringField(
        'Username',
        validators=[DataRequired('You must provide username.')]
    )
    password = PasswordField(
        'Password',
        validators=[
            DataRequired('You must provide password.'),
            Length(5, 20, 'The password is either too short or too long.')
        ],
        description='Password must be between 5 and 20 characters.'
    )
    birth_date = StringField(
        'Birth date',
        validators=[DataRequired('You must provide birth date.')]
    )
    submit = SubmitField('Create')


# Form to add new user
class AddUserForm(FlaskForm):
    title = 'Add user'
    firstname = StringField(
        'First name',
        validators=[DataRequired('You must provide first name.')]
    )
    lastname = StringField(
        'Last name',
        validators=[DataRequired('You must provide last name.')]
    )
    username = StringField(
        'Username',
        validators=[DataRequired('You must provide username.')]
    )
    password = PasswordField(
        'Password',
        validators=[
            DataRequired('You must provide password.'),
            Length(5, 20, 'The password is either too short or too long.')
        ],
        description='Password must be between 5 and 20 characters.'
    )
    birth_date = StringField(
        'Birth date',
        validators=[DataRequired('You must provide birth date.')]
    )
    is_admin = BooleanField(
        'Admin rights?',
        render_kw={
            'data-toggle': 'toggle',
            'data-size': 'xs',  # Extra small
            'data-on': 'Yes',
            'data-off': 'No',
            'data-onstyle': 'success',
            'data-offstyle': 'danger'
        }
    )
    submit = SubmitField('Create')


# Form to edit user
class EditUserForm(FlaskForm):
    title = 'Edit user'
    firstname = StringField(
        'First name',
        validators=[DataRequired('You must provide first name.')]
    )
    lastname = StringField(
        'Last name',
        validators=[DataRequired('You must provide last name.')]
    )
    # Username must be disabled, so it cannot be changed in order to stay unique.
    username = StringField(
        'Username',
        render_kw={
            'disabled': 'disabled'
        }
    )
    birth_date = StringField(
        'Birth date',
        validators=[DataRequired('You must provide birth date.')]
    )
    is_admin = BooleanField(
        'Admin rights?',
        render_kw={
            'data-toggle': 'toggle',
            'data-size': 'xs',  # Extra small
            'data-on': 'Yes',
            'data-off': 'No',
            'data-onstyle': 'success',
            'data-offstyle': 'danger'
        }
    )
    submit = SubmitField('Update')


# Form to delete user
class DeleteUserForm(FlaskForm):
    title = 'Delete user'
    message = 'Do you really want to delete this user? It cannot be undone.'
    submit = SubmitField('Delete')


# ========== Create database models ========== #

# Database model for User entity
class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, nullable=False,
                   primary_key=True, autoincrement=True)
    firstname = db.Column(db.String, nullable=False)
    lastname = db.Column(db.String, nullable=False)
    username = db.Column(db.String, nullable=False, unique=True)
    # Don't forget to MD5 encode it!
    password = db.Column(db.String, nullable=False)
    birth_date = db.Column(db.DateTime, nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    def __init__(self, firstname, lastname, username, password, birth_date, is_admin=False):
        self.firstname = firstname
        self.lastname = lastname
        self.username = username
        self.password = password
        self.birth_date = birth_date
        self.is_admin = is_admin

    def __repr__(self):
        return '<User %r>' % self.username


# Database model for Result entity
class Result(db.Model):
    __tablename__ = 'result'
    id = db.Column(db.Integer, nullable=False,
                   primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey(User.id))
    diastolic = db.Column(db.String, nullable=False)
    systolic = db.Column(db.String, nullable=False)
    daytime = db.Column(db.Integer, nullable=False, default=0)
    date = db.Column(db.DateTime, nullable=False)
    # Relationship
    user = db.relationship('User')

#    def __init__(self, user_id, weight, height, date, bmi):
#       self.user_id  = user_id
#       self.weight   = weight
#       self.height   = height
#       self.bmi      = round(float(weight) / float(height) ** 2, 1)
#       self.date     = date
#
#   def __repr__(self):
#       return '<Result %r>' % self.weight


# Database model for Benchmark entity
class Benchmark(db.Model):
    __tablename__ = 'benchmark'
    id = db.Column(db.Integer, nullable=False,
                   primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey(User.id))
    type = db.Column(db.Integer, default=0)
    category = db.Column(db.Integer, default=0)
    result = db.Column(db.String, nullable=False)
    date = db.Column(db.DateTime, nullable=False)
    # Relationship
    user = db.relationship('User')

    def __init__(self, user_id, type, category, result, date):
        self.user_id = user_id
        self.type = type
        self.category = category
        self.result = result
        self.date = date

    def __repr__(self):
        return '<Benchmark %r>' % self.type


# ========== Create DB with default values ========== #

with app.app_context():
    # Create the database/tables if it/they don't exist yet
    # This call has to be after database model definitions!
    db.create_all()

    # Check if 'admin' user exist in the database
    exists = User.query.filter_by(username='admin').first()

    # Add 'admin' user to the database if there are no users
    if not exists:
        admin = User(
            firstname='Admin',
            lastname='User',
            username='admin',
            password=md5('admin'.encode('utf-8')).hexdigest(),
            birth_date=datetime.now(),
            is_admin=True
        )
        db.session.add(admin)
        db.session.commit()


# ========== Run web application ========== #

# Run the web server
if __name__ == '__main__':
    app.run(debug=True)
