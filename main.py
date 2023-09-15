from flask import Flask, redirect, request, render_template, url_for, flash, send_from_directory
from werkzeug.utils import secure_filename
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import sqlite3
import os
import requests
import logging
from os import listdir
from flask import session
from uuid import uuid4



print("All modules loaded...🥳🥳")

# Configure the logging
# Create a custom logger
logger = logging.getLogger('my_logger')
logger.setLevel(logging.INFO)

# Create handlers
file_handler = logging.FileHandler('app.log')
file_handler.setLevel(logging.INFO)

# Create formatters and add it to handlers
formatter = logging.Formatter('%(asctime)s - %(message)s')
file_handler.setFormatter(formatter)

# Add handlers to the logger
logger.addHandler(file_handler)



# Dauth configuration
DAUTH_CLIENT_ID = "kYsE8Z7gKhwpjrRQ"
DAUTH_CLIENT_SECRET = "JcUl7AqXe.WvXzNmE6ilS.ukIk~jFxQX"
DAUTH_REDIRECT_URI = "http://165.232.188.128:8000/callback"
DAUTH_AUTHORIZE_URL = "https://auth.delta.nitt.edu/authorize"
DAUTH_TOKEN_URL = "https://auth.delta.nitt.edu/api/oauth/token"
DAUTH_USER_URL = "https://auth.delta.nitt.edu/api/resources/user"

app = Flask(__name__)
bcrypt = Bcrypt(app)

# //2^20 bytes or 16MB
UPLOAD_FOLDER = 'static'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 
ALLOWED_EXTENSIONS = set(['pdf'])

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///main.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config["SECRET_KEY"] = "secret"
db = SQLAlchemy(app)
migrate = Migrate(app, db) 
app.app_context().push()

# session life 
from datetime import timedelta
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'dauth_login'  # Redirect to DAuth login


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

from datetime import datetime
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), nullable=False, unique=True)
    dauth_id = db.Column(db.String(120), unique=True)  # DAuth unique identifier
    dauth_token = db.Column(db.String(255))  # DAuth token (if needed)
    upload_access = db.Column(db.String(10), default='pending')
    request_status = db.Column(db.String(10), default='pending')
    session_id = db.Column(db.String(36), unique=True, nullable=True)
    session_creation_time = db.Column(db.DateTime, nullable=True)


# sessin decorator for all routes
from functools import wraps
from flask import redirect, url_for, session

def session_validation_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        session_id = session.get('session_id')
        if session_id != current_user.session_id:
            logout_user()
            return redirect(url_for('dauth_login'))
        
        # Check for session expiration
        session_lifetime = app.config['PERMANENT_SESSION_LIFETIME']
        if current_user.session_creation_time is None:
            logout_user()
            return redirect(url_for('dauth_login'))
        
        if datetime.utcnow() - current_user.session_creation_time > session_lifetime:
            logout_user()
            return redirect(url_for('dauth_login'))
        
        return f(*args, **kwargs)
    return decorated_function



# ... (existing classes, routes, and functions)

@app.route('/index')
@login_required
@session_validation_required
def homepage():
    return render_template('homepage.html')


# DAuth login route
@app.route('/dauth_login')
def dauth_login():
    authorization_url = f"{DAUTH_AUTHORIZE_URL}?response_type=code&client_id={DAUTH_CLIENT_ID}&redirect_uri={DAUTH_REDIRECT_URI}&scope=user"  # Added user scope
    return redirect(authorization_url)

# @app.route('/signup')
# def signup():
#     # Redirect to Delta Auth signup or any other desired signup system
#     return redirect('DAUTH_AUTHORIZE_URL')


# DAuth callback route
@app.route('/callback')
def callback():
    code = request.args.get('code')
    data = {
        'client_id': DAUTH_CLIENT_ID,
        'client_secret': DAUTH_CLIENT_SECRET,
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': DAUTH_REDIRECT_URI
    }
    response = requests.post(DAUTH_TOKEN_URL, data=data)

    if response.status_code != 200:
        print(f"Error: {response.status_code}")
        print(response.text)
        return "Error in callback in token response"

    token_data = response.json()
    access_token = token_data['access_token']

    headers = {'Authorization': f'Bearer {access_token}'}
    user_response = requests.post(DAUTH_USER_URL, headers=headers)  # POST request to /api/resources/user

    if user_response.status_code != 200:
        print(f"Error: {user_response.status_code}")
        print(user_response.text)
        return "Error in callback in user_response-2"

    user_data = user_response.json()
    # print(user_data)

    # Retrieve DAuth ID and email from user_data (adjust as needed)
    dauth_id = user_data['id']
    email = user_data['email']

    # Check if user exists in your database
    user = User.query.filter_by(dauth_id=dauth_id).first()

    if user is None:
        # Create a new user if not found
        user = User(username=email.split('@')[0], email=email, password="DAuthUser", dauth_id=dauth_id, request_status='pending')
        db.session.add(user)
        db.session.commit()

    else:
        session_id = str(uuid4())
        user.session_id = session_id
        user.session_creation_time = datetime.utcnow()
        db.session.commit()
        session['session_id'] = session_id

    # Log the user in
    login_user(user)
    logger.info(f"User {user.username} logged in")
    return redirect(url_for('index'))

# Admin panel
@app.route('/admin', methods=['GET', 'POST'])
@login_required
@session_validation_required
def admin_panel():
    if current_user.username != '205121038':
        return redirect(url_for('homepage'))

    users = User.query.all()

    if request.method == 'POST':
        user_id = request.form['user_id']
        user = User.query.get(user_id)
        
        if 'request_action' in request.form:
            request_action = request.form['request_action']
            user.request_status = request_action
        if 'upload_action' in request.form:
            upload_action = request.form['upload_action']
            user.upload_access = upload_action
        
        db.session.commit()

    return render_template('admin.html', users=users)


# request upload routes

@app.route('/request_upload', methods=['GET', 'POST'])
#@login_required
@session_validation_required
def request_upload():
    current_user.request_status = 'request'
    db.session.commit()
    return redirect(url_for('homepage'))

# UPLOADING FILE PART

 
def allowed_file(filename):
 return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload')
#@login_required
@session_validation_required
def upload_form():
    if current_user.upload_access != 'accept' and current_user.username != '205121038':
        return redirect(url_for('homepage'))

    conn = sqlite3.connect('file_database.db')
    c = conn.cursor()
    c.execute('CREATE TABLE IF NOT EXISTS files (serial_no INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, course TEXT, subject TEXT, filename TEXT, status TEXT DEFAULT "pending")')
    conn.commit()
    c.execute('SELECT * FROM files')
    files = c.fetchall()
    conn.close()
    return render_template('upload.html', files=files)


TEMP_UPLOAD_FOLDER = 'temp_uploads'
app.config['TEMP_UPLOAD_FOLDER'] = TEMP_UPLOAD_FOLDER

@app.route('/upload', methods=['POST'])
#@login_required
@session_validation_required
def upload_file():
    if current_user.upload_access != 'accept' and current_user.username != '205121038':
        return redirect(url_for('homepage'))
        
    if request.method == 'POST':
        if 'files[]' not in request.files:
            flash('No file part')
            return redirect(request.url)

        course = request.form['course']
        subject = request.form['subject']
        folder_path = os.path.join(app.config['TEMP_UPLOAD_FOLDER'], course, subject)
        if not os.path.exists(folder_path):
            os.makedirs(folder_path)

        files = request.files.getlist('files[]')
        username = current_user.username

        for file in files:
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(folder_path, filename))
                roll_number = current_user.username  # Assuming the username is the roll number
                logger.info(f'File uploaded: {filename} by roll number: {roll_number}')

                conn = sqlite3.connect('file_database.db')
                c = conn.cursor()
                c.execute('INSERT INTO files (username, course, subject, filename) VALUES (?, ?, ?, ?)', (username, course, subject, filename)) # Removed semester
                conn.commit()
                conn.close()

        flash('File(s) successfully uploaded')
        return render_template('success.html')  # Render the success page
    return render_template('upload.html')


def get_files_for_subject(subject_name):
    subject_path = os.path.join('static', 'MCA', subject_name.replace(" ", "_"))
    if os.path.exists(subject_path):
        return os.listdir(subject_path)
    else:
        return []


# publish panel
@app.route('/publish_panel', methods=['GET', 'POST'])
@login_required
@session_validation_required
def publish_panel():
    if current_user.username != '205121038':  # Assuming '205121038' is the admin's username
        return redirect(url_for('homepage'))

    conn = sqlite3.connect('file_database.db')
    c = conn.cursor()
    c.execute('SELECT * FROM files WHERE status="pending" or status="reject"')
    pending_files = c.fetchall()
    conn.close()

    if request.method == 'POST':
        file_id = request.form['file_id']
        action = request.form['action']

        conn = sqlite3.connect('file_database.db')
        c = conn.cursor()

        if action == 'publish':
            # Move the file from the temp directory to the main directory
            file_data = [f for f in pending_files if f[0] == int(file_id)][0]
            _, _, course, subject, filename, _ = file_data
            temp_path = os.path.join(app.config['TEMP_UPLOAD_FOLDER'], course, subject, filename)
            main_path = os.path.join(app.config['UPLOAD_FOLDER'], course, subject, filename)
            # Ensure the destination directory exists
            main_dir = os.path.dirname(main_path)
            if not os.path.exists(main_dir):
                os.makedirs(main_dir)
            os.rename(temp_path, main_path)
            c.execute('UPDATE files SET status="published" WHERE serial_no=?', (file_id,))
            # Logging the publish action
            logger.info(f"File {filename} published by admin {current_user.username}")

        elif action == 'delete':
            # Delete the file from the temp directory
            file_data = [f for f in pending_files if f[0] == int(file_id)][0]
            _, _, course, subject, filename, _ = file_data
            temp_path = os.path.join(app.config['TEMP_UPLOAD_FOLDER'], course, subject, filename)
            os.remove(temp_path)
            c.execute('UPDATE files SET status="deleted" WHERE serial_no=?', (file_id,))
            # Logging the delete action
            logger.info(f"File {filename} deleted by admin {current_user.username}")

        if action == 'preview':
            return redirect(url_for('preview_file', file_id=file_id))


        conn.commit()
        conn.close()
        return redirect(url_for('publish_panel'))

    return render_template('publish_panel.html', files=pending_files)

# preview files before publish

from flask import send_file

@app.route('/preview_file/<file_id>')
#@login_required
@session_validation_required
def preview_file(file_id):
    # Retrieve the file data from the database using the file ID
    conn = sqlite3.connect('file_database.db')
    c = conn.cursor()
    c.execute('SELECT * FROM files WHERE serial_no=?', (file_id,))
    file_data = c.fetchone()
    conn.close()

    # Assuming file_data[4] contains the filename
    filename = file_data[4]

    # Define the path to the file
    file_path = os.path.join(app.config['TEMP_UPLOAD_FOLDER'], file_data[2], file_data[3], filename)

    # Check if the file exists
    if not os.path.exists(file_path):
        flash('File not found')
        return redirect(url_for('publish_panel'))

    # Display the file in a preview page (you'll need to create a template for this)
    return render_template('preview_file.html', file_path=url_for('serve_file', file_id=file_id), filename=filename)

@app.route('/serve_file/<file_id>')
#@login_required
@session_validation_required
def serve_file(file_id):
    # Retrieve the file data from the database using the file ID
    conn = sqlite3.connect('file_database.db')
    c = conn.cursor()
    c.execute('SELECT * FROM files WHERE serial_no=?', (file_id,))
    file_data = c.fetchone()
    conn.close()

    # Define the path to the file
    file_path = os.path.join(app.config['TEMP_UPLOAD_FOLDER'], file_data[2], file_data[3], file_data[4])

    # Serve the file
    return send_file(file_path)



@app.route('/static/<path:filename>')
#@login_required
@session_validation_required
def download_file(filename):
    return send_from_directory('static', filename, as_attachment=True)



@app.route('/')  # decorator defines the
def index():
    return render_template('index.html')

@app.route('/mca')
#@login_required
@session_validation_required
def mca():
    subjects = [
    "PSP-Problem Solving and Programming",
    "MFCA-Mathematical Foundations of Computer Applications",
    "DLCO-Digital Logic and Computer Organization",
    "DSA-Data Structures and Applications",
    "OS-Operating Systems",
    "PSLP-Problem Solving Lab using Python",
    "DSLC-Data Structures Lab using C",
    "DAA-Design and Analysis of Algorithms",
    "DBMS-Database Management Systems",
    "PSM-Probability and Statistical Methods",
    "OOP-Object Oriented Programming",
    "CN-Computer Networks",
    "DBMSL-DBMS Lab",
    "CNL-Computer Networks Lab",
    "DMW-Data Mining and Warehousing",
    "CI-Computational Intelligence",
    "SE-Software Engineering",
    "AFM-Accounting and Financial Management",
    "DML-Data Mining Lab",
    "BC-Business Communication",
    "MLDL-Machine Learning and Deep Learning",
    "WTA-Web Technology and Its Applications",
    "PDC-Parallel and Distributed Computing",
    "PW-Project Work - Phase I",
    "IS-Information Security",
    "CC-Cloud Computing",
    "OB-Organizational Behaviour",
    "ISL-Information Security Lab",
    "CCL-Cloud Computing Lab"
]

    return render_template('mca.html', subjects=subjects)


@app.route('/subject/<subject_name>')
#@login_required
@session_validation_required
def subject_page(subject_name):
    subject_path = os.path.join(app.config['UPLOAD_FOLDER'], 'MCA',subject_name)
    files = listdir(subject_path) if os.path.exists(subject_path) else ""
    return render_template('subject_page.html', subject_name=subject_name, files=files)



@app.route('/about')  # decorator defines the
#@login_required
@session_validation_required
def about():
    return render_template('about.html', name= "Deepak")

# @app.route('/logout', methods=['GET', 'POST'])
# @login_required
# @session_validation_required
# def logout():
#     username = current_user.username
#     logout_user()
#     logger.info(f"User {username} logged out")
#     return redirect(url_for('dauth_login'))

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    current_user.session_id = None
    current_user.session_creation_time = None
    db.session.commit()
    session.pop('session_id', None)
    logout_user()
    return redirect(url_for('index'))



if __name__ == '__main__':
    db.create_all()
    app.run(debug=True,port=8000)
 
