"""
    Taylor Augustin
    SDEV 300 / 7380
    Lab 8 Security and Cipher Tools
    December 08, 2023
"""

from datetime import datetime
import os # system management
import csv # CSV management
import re # to enfore password complexity
from passlib.hash import sha256_crypt # Password hashing management
from flask import Flask, render_template, url_for, flash, redirect, request, session
from api_practice import get_weather

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24) # Generate a key for flash

# File Management
def read_file(file_path):
    ''' Read data from file and store it to data[] '''
    data = [] # append user data to

    if os.path.exists(file_path):
        with open(file_path, 'r', newline='', encoding='utf-8') as file:
            reader = csv.DictReader(file)
            for row in reader:
                data.append(row)
    return data

USER_FILE = "account_login.csv"                     # File of Log In Credentials
COMMON_PASSWORDS = read_file('CommonPassword.txt')  # File of common bad passwords
FAILED_LOGIN_FILE = 'failed_login_log.csv'          # File of failed

# Access Controller
def require_login():
    '''Prevent access to pages without being loged in'''
    # Check if the user is logged in
    if 'user_id' not in session:
        flash('You must be logged in to access this page.', 'error') # Messages to user
        return redirect(url_for('login'))
    return None

# Authentication logic functions
@app.before_request
def before_request():
    'Prevent access to pages without being logged in'
    if request.endpoint in ['home', 'us_states', 'contact', 'update_password']:
        return require_login()
    return None

def writefile(users):
    " Write new user data from file and store it in user_file: data from file "
    existing_users = read_file(USER_FILE)

    with open(USER_FILE, 'w', newline='', encoding='utf-8') as file:
        fieldnames = ['fname', 'lname', 'user', 'hashed_pass']
        writer = csv.DictWriter(file, fieldnames=fieldnames)

        # Write the header if the file is empty
        if file.tell() == 0:
            writer.writeheader()

        # Write the combined data (existing_users + users) back to the CSV file
        writer.writerows(existing_users + users)

def get_home_data():
    'Reurn Data to be used by the home page'
    return {
        'youtube': {
            'osaka': 'https://www.youtube.com/embed/7efZG282TN8',
            'kyoto': 'https://www.youtube.com/embed/qYXJEx9vmi0'
        },
        'curr_time': datetime.now().strftime("%I:%M %p"),
        'curr_date': datetime.now().strftime("%m-%d-%Y"),
    }

def get_client_ip():
    'Return the client ip address - Even if application behind a proxy'
    # Check if X-Forwarded-For header is present
    if 'X-Forwarded-For' in request.headers:
        client_ip = request.headers['X-Forwarded-For'].split(',')[0].strip()
    else:
        # If X-Forwarded-For is not present, use the remote_addr
        client_ip = request.remote_addr
    return client_ip

def log_fail_attemps(username):
    'Log username, password, time/date, IP address of failled login attempts'
    attemptees = [] # Declare dict to write to file
    curr_date_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    user_ip = get_client_ip()

    # Append the fail attempt
    attemptees.append({'username': username, 'date_time': curr_date_time, 'ip_address': user_ip})

    with open(FAILED_LOGIN_FILE, 'a', newline='', encoding='utf-8') as file:
        fieldnames = ['username', 'date_time', 'ip_address']
        writer = csv.DictWriter(file, fieldnames=fieldnames)

        # Write the header if the file is empty
        if file.tell() == 0:
            writer.writeheader()
        # Append the data to the CSV file
        writer.writerows(attemptees)

# Account Registration
def is_username_taken(username):
    'Check if username already exist in database'
    users = read_file(USER_FILE) # Read the user database
    # grab all the usernames from the database
    existing_usernames = [user.get('user', '') for user in users]
    return username in existing_usernames

def is_complex_password(password):
    ''' Returns True if Password includes 1 upper/lower, number and, special character'''
    complex_pattern = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$_!-%*?&])[A-Za-z\d@$_!-%*?&]{12,}$"
    is_complex = False

    if bool(re.match(complex_pattern, password)): # return True if pass is complex
        is_complex = True

    return is_complex

def is_common_password(password):
    "Returns True if passwords is in COMMON_PASSWORDS list"
    is_common = False

    for common_password in COMMON_PASSWORDS: # Iterate over the list of common passwords
        if password == common_password['COMMON']: # compared the user's password to the list
            is_common = True
            break
    return is_common

# Log in
def verify_user(username, password):
    """ Check if the user credential exist in the database """
    users = read_file(USER_FILE)

    for user in users:
        if user['user'] == username:
            # User found, check password
            if sha256_crypt.verify(password, user['hashed_pass']):
                msg = f'Logged In Successful | Welcome {user["fname"]} {user["lname"]}'
                flash(msg, 'success')
                # return user if found and password mathces
                return user  # Successful login
    return None  # User not found or credentials don't match

def register_user(f_name, l_name, username, password):
    """Handle user registration."""
    # Check if the username already exists
    if is_username_taken(username):
        return {'success': False, 'message': 'Username already taken. | Try Again.',
                'category': 'error'}

    # Check if the password is a common password
    if is_common_password(password):
        return {'success': False, 'message': 'Common Password | Try Again',
                'category': 'error'}

    # Check for password complexity
    if not is_complex_password(password):
        return {'success': False, 'message': 'Weak Password | Try again',
            'category': 'error'}

    # Generate hash using sha256 library
    hashed_pass = sha256_crypt.hash(password)

    # Declare a new dictionary
    user_data = {'fname': f_name, 'lname': l_name, 'user': username,
                 'hashed_pass': hashed_pass}

    # Write the updated data back to the CSV file
    writefile([user_data])

    return {'success': True, 'message': 'Registration Successful | Please Log In!',
            'category': 'success'}

def update_user(username, old_password, new_password1, new_password2):
    """Handle user password update."""
    existing_users = read_file(USER_FILE)

    # Find the associated user data
    for user in existing_users:
        if user['user'] == username and sha256_crypt.verify(old_password, user['hashed_pass']):
            # Check if the new passwords match each other
            if new_password1 != new_password2:
                return {'success': False, 'message': 'Both new password must match',
                        'category': 'error'}

            # Check if the new password is the same as the old password
            if sha256_crypt.verify(new_password1, user['hashed_pass']):
                return {'success': False, 'message': 'New password cannot be the old password',
                        'category': 'error'}

            # Check if the new password is in the common password list
            if is_common_password(new_password1):
                return {'success': False, 'message': 'Common Password | Try Again',
                        'category': 'error'}

            # Check for password complexity
            if not is_complex_password(new_password1):
                return {'success': False, 'message': 'Weak Password | Try again',
                        'category': 'error'}

            # Update the hashed password in the existing users
            user['hashed_pass'] = sha256_crypt.hash(new_password1)

            # Write the updated data back to the CSV file
            with open(USER_FILE, 'w', newline='', encoding='utf-8') as file:
                fieldnames = ['fname', 'lname', 'user', 'hashed_pass']
                writer = csv.DictWriter(file, fieldnames=fieldnames)

                # Write the header
                writer.writeheader()

                # Write the combined data (existing_users) back to the CSV file
                writer.writerows(existing_users)

            return {'success': True, 'message': 'Password changed successfully!',
                    'category': 'success'}

    # If no matching user is found
    return {'success': False, 'message': 'Invalid old password. Password not changed.',
            'category': 'error'}

# -------------------------- Page routes --------------------

@app.route('/update_password', methods=['GET', 'POST'])
def update_password():
    """Route for updating user password."""
    if request.method == 'POST':
        username = session.get('user_id')  # Grab current username from session key
        old_password = request.form['old_password']
        new_password1 = request.form['new_password1']
        new_password2 = request.form['new_password2']

        # Call the update_user function to handle password update
        update_user_result = update_user(username, old_password, new_password1, new_password2)

        # Flash the message returned by update_user
        flash(update_user_result['message'], update_user_result['category'])

        if update_user_result['success']:
            return redirect(url_for('home'))  # Redirect to the home page

    # Render the update_password.html template if the request method is GET
    return render_template('update_password.html')

@app.route('/') # index
@app.route('/login', methods=['GET', 'POST'])
def login():
    " route to Account LogIn form "
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = verify_user(username, password)

        if user:
            # Registration successful
            session['user_id'] = user['user'] # Keep track of log in info
            return redirect(url_for('home'))
        log_fail_attemps(username)

        flash('Invalid username or password', 'error')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Account Registration form."""
    if request.method == 'POST':
        # Store User input
        first_name = request.form['fname']
        last_name = request.form['lname']
        username = request.form['username']
        password = request.form['password']

        # Attempt to register the user
        registration_result = register_user(first_name, last_name, username, password)

        # Check the registration result
        if registration_result['success']:
            # grab the flash message
            flash(registration_result['message'], registration_result['category'])
            return redirect(url_for('login')) # redirect to home page

        # Registration failed
        flash(registration_result['message'], registration_result['category'])
        return redirect(url_for('register'))
    return render_template('register.html')

@app.route('/home')
def home():
    """Routes to Home Page with data for youtube links"""
    return render_template('home.html', **get_home_data())

@app.route('/weather', methods=['GET', 'POST'])
def weather():
    """Search and display weather"""
    if request.method == 'POST':
        city_name = request.form['city_name']
        weather_data = get_weather(city_name)
        
        return render_template('display_weather.html', weather_data=weather_data)
    return render_template('weather.html')

@app.route('/display_weather')
def display_weather():
    """Display the search city weather"""
    render_template('display_weather.html')

@app.route('/contact')
def contact():
    '''contact page'''
    return render_template('contact.html')

@app.route('/us_states')
def us_states():
    """ route to Page displaying US States flowers"""
    return render_template('us_states.html')

@app.route('/logout')
def logout():
    ''' Log out page - Remove user session ID from the session '''
    session.pop('user_id', None)
    flash('You have been logged out.', 'success')
    # Redirect to the log in page
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True, port=5000, host='0.0.0.0')
