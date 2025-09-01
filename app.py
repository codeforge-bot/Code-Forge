# --- Core Imports ---
import os
import uuid
import random
import re
from datetime import datetime
from collections import defaultdict

# --- Flask and SocketIO Imports ---
import eventlet
eventlet.monkey_patch() # Required for async operations
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_socketio import SocketIO, join_room, leave_room, send, emit

# --- Security and Utility Imports ---
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

# --- Database Imports ---
import psycopg2
from psycopg2.extras import DictCursor

# --- Cloud Services Imports ---
import cloudinary
import cloudinary.uploader
import smtplib
from email.message import EmailMessage
from smtplib import SMTPAuthenticationError, SMTPConnectError

import requests
from google_auth_oauthlib.flow import Flow
import google.auth.transport.requests
from pip._vendor import cachecontrol

# ==============================================================================
# FLASK APP & EXTENSION INITIALIZATION
# ==============================================================================

app = Flask(__name__)
# Use environment variables for production; provide a default for local development
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'a_strong_default_secret_key_for_dev')

# Configure SocketIO for real-time communication, allowing all origins for deployment flexibility
socketio = SocketIO(app, async_mode='eventlet', cors_allowed_origins="*")

# ==============================================================================
# GOOGLE OAUTH CONFIGURATION
# ==============================================================================
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1" # ONLY for local testing. Remove in production if not needed.
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET")

# The path to the client secrets file downloaded from Google Cloud Console
client_config = {
    "web": {
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "redirect_uris": ["https://code-forge-9aq0.onrender.com/callback"],
        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs"
    }
}

flow = Flow.from_client_config(
    client_config=client_config,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="https://code-forge-9aq0.onrender.com/callback"
)

# ==============================================================================
# CONFIGURATION FROM ENVIRONMENT VARIABLES
# ==============================================================================

# --- Database Configuration ---
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    print("FATAL ERROR: DATABASE_URL environment variable is not set.")

# --- Cloudinary Configuration ---
try:
    cloudinary.config(
        cloud_name = os.environ.get('CLOUD_NAME'),
        api_key = os.environ.get('API_KEY'),
        api_secret = os.environ.get('API_SECRET')
    )
except Exception as e:
    print(f"WARNING: Cloudinary is not configured. File uploads will fail. Error: {e}")

# --- Email Configuration ---
EMAIL_ADDRESS = os.environ.get("EMAIL_USER")
EMAIL_PASSWORD = os.environ.get("EMAIL_PASS")
if not EMAIL_ADDRESS or not EMAIL_PASSWORD:
    print("WARNING: Email credentials (EMAIL_USER, EMAIL_PASS) are not set. OTP and welcome emails will fail.")


# --- File Upload Configuration ---
ALLOWED_SUBMISSION_EXTENSIONS = {'pdf', 'ppt', 'pptx', 'doc', 'docx', 'zip', 'rar'}
ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

def allowed_file(filename, allowed_extensions):
    """Checks if a file's extension is in the allowed set."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

# ==============================================================================
# DATABASE HELPER FUNCTIONS
# ==============================================================================

def get_db_connection():
    """Establishes and returns a connection to the PostgreSQL database."""
    try:
        # Using DictCursor to get rows as dictionary-like objects
        conn = psycopg2.connect(DATABASE_URL, cursor_factory=DictCursor)
        return conn
    except psycopg2.Error as e:
        print(f"DATABASE CONNECTION ERROR: {e}")
        flash("Database connection error. Please contact support.", "danger")
        return None

def get_user_by_id(user_id):
    """Fetches user data by user_id from the unified 'users' table."""
    conn = get_db_connection()
    if not conn: return None
    
    try:
        with conn.cursor() as cur:
            # NOTE: This assumes a unified 'users' table for all roles
            cur.execute("SELECT * FROM users WHERE user_id = %s", (user_id,))
            user_data = cur.fetchone()
            return dict(user_data) if user_data else None
    except psycopg2.Error as e:
        print(f"Database error in get_user_by_id: {e}")
        return None
    finally:
        if conn: conn.close()

# ==============================================================================
# EMAIL HELPER FUNCTIONS
# ==============================================================================

def send_otp(receiver_email, otp):
    """Sends a One-Time Password to the specified email address."""
    if not EMAIL_ADDRESS or not EMAIL_PASSWORD:
        flash("Email sending failed: Server not configured. Contact admin.", "danger")
        return False

    msg = EmailMessage()
    msg['Subject'] = 'Your OTP for Code Forge Verification'
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = receiver_email
    msg.set_content(f'Your One-Time Password is: {otp}\n\nThis OTP is valid for 10 minutes.')

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            smtp.send_message(msg)
        flash("An OTP has been sent to your email.", "info")
        return True
    except Exception as e:
        print(f"[EMAIL ERROR] Failed to send OTP to {receiver_email}. Error: {e}")
        flash("An error occurred while sending the OTP. Please try again.", "danger")
    return False

def send_welcome_email(receiver_email, name, user_id):
    """Sends a welcome email with the user's ID upon successful registration."""
    if not EMAIL_ADDRESS or not EMAIL_PASSWORD:
        return False # Fail silently, as this is non-critical

    msg = EmailMessage()
    msg['Subject'] = 'Welcome to Code Forge! 🎉'
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = receiver_email
    msg.set_content(f'''Hi {name},

Welcome to the Code Forge community! We're thrilled to have you on board.

Your journey to innovate, collaborate, and create starts now. Here is your unique User ID for logging in:

User ID: {user_id}

Keep it safe! We can't wait to see what you'll build with us.

Best,
The Code Forge Team''')

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            smtp.send_message(msg)
        return True
    except Exception as e:
        print(f"[EMAIL ERROR] Failed to send welcome email to {receiver_email}. Error: {e}")
    return False

# ==============================================================================
# CORE ROUTES (Home, Login, Logout, Dashboard)
# ==============================================================================

@app.route('/')
def home():
    """Renders the public home page with events and winner announcements."""
    conn = get_db_connection()
    if not conn:
        return render_template('home.html', events=[], results={})

    events = []
    grouped_results = defaultdict(list)
    try:
        with conn.cursor() as cur:
            # Fetch all events for the home page
            cur.execute("SELECT id, title, short_description, date, image_url FROM events ORDER BY date DESC")
            events = cur.fetchall()

            # Fetch winners and group them by event title
            cur.execute("""
                SELECT event_title, position, winner_name
                FROM event_results
                ORDER BY event_title,
                         CASE WHEN position LIKE '1%' THEN 1 WHEN position LIKE '2%' THEN 2 WHEN position LIKE '3%' THEN 3 ELSE 4 END
            """)
            for result in cur.fetchall():
                grouped_results[result['event_title']].append((result['position'], result['winner_name']))
    except psycopg2.Error as e:
        print(f"HOME PAGE DATA ERROR: {e}")
        flash("Error loading page data.", "danger")
    finally:
        if conn: conn.close()
        
    return render_template('home.html', events=events, results=dict(grouped_results))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login for all roles from a single, unified 'users' table."""
    if request.method == 'POST':
        user_id_attempt = request.form.get('user_id')
        password_attempt = request.form.get('password')
        
        print("\n" + "="*40)
        print(f"LOGIN ATTEMPT: User ID '{user_id_attempt}'")
        print("="*40)

        conn = get_db_connection()
        if not conn: return render_template('login.html')

        try:
            with conn.cursor() as cur:
                # A single query to the unified users table
                print("Checking users table for all roles...")
                cur.execute("SELECT user_id, name, role, password FROM users WHERE user_id = %s", (user_id_attempt,))
                user = cur.fetchone()

                if user:
                    print(f"Found potential user: {user['user_id']} ({user['name']}) with role: {user['role']}")
                    if check_password_hash(user['password'], password_attempt):
                        print("✅ Password MATCHED.")
                        session['user_id'] = user['user_id']
                        session['user'] = user['name']
                        session['role'] = user['role']
                        flash(f"Welcome back, {user['name']}!", "success")
                        return redirect(url_for('dashboard'))
                    else:
                        print("❌ Password FAILED.")
                else:
                    print("User ID not found in the database.")
                
                print("No user found or password incorrect for all checks.")
                flash("Invalid User ID or Password.", "danger")
        except psycopg2.Error as e:
            print(f"LOGIN ERROR: {e}")
            flash("A database error occurred during login.", "danger")
        finally:
            if conn: conn.close()

    return render_template('login.html')

@app.route("/login/google")
def login_google():
    """Redirects to Google's authorization page."""
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)


@app.route("/callback")
def callback():
    """Handles the callback from Google after authentication."""
    flow.fetch_token(authorization_response=request.url)

    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    # Fetch user profile information from Google
    user_info_response = requests.get(
        "https://www.googleapis.com/oauth2/v1/userinfo",
        headers={"Authorization": f"Bearer {credentials.token}"},
    ).json()

    user_email = user_info_response.get("email")
    user_name = user_info_response.get("name")

    if not user_email:
        flash("Could not retrieve email from Google. Please try again.", "danger")
        return redirect(url_for('login'))

    conn = get_db_connection()
    if not conn:
        return redirect(url_for('login'))

    try:
        with conn.cursor() as cur:
            # Check if the user already exists in the database
            cur.execute("SELECT * FROM users WHERE email = %s", (user_email,))
            user = cur.fetchone()

            if user:
                # User exists, log them in
                session['user_id'] = user['user_id']
                session['user'] = user['name']
                session['role'] = user['role']
            else:
                # User does not exist, create a new account (sign-up)
                user_id = str(uuid.uuid4())[:8]
                # Generate a dummy password as it's required by the schema but won't be used
                hashed_password = generate_password_hash(str(uuid.uuid4()))

                cur.execute("""
                    INSERT INTO users (user_id, name, email, password, role)
                    VALUES (%s, %s, %s, %s, %s)
                """, (user_id, user_name, user_email, hashed_password, 'student')) # Default role is 'student'
                conn.commit()

                # Log the new user in
                session['user_id'] = user_id
                session['user'] = user_name
                session['role'] = 'student'

        flash(f"Welcome, {session['user']}!", "success")
        return redirect(url_for('dashboard'))

    except psycopg2.Error as e:
        conn.rollback()
        print(f"GOOGLE SIGN-IN DB ERROR: {e}")
        flash("A database error occurred during sign-in.", "danger")
        return redirect(url_for('login'))
    finally:
        if conn: conn.close()


@app.route("/protected_area")
def protected_area():
    if "google_id" not in session:
        return redirect(url_for("login"))
    return "You are in the protected area!"

@app.route('/logout')
def logout():
    """Logs out the current user and clears the session."""
    session.clear()
    flash("You have been logged out successfully.", "info")
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    """Redirects authenticated users to their respective dashboards."""
    if 'role' in session:
        role = session['role']
        if role == 'student':
            return redirect(url_for('student_dashboard'))
        elif role == 'admin':
            return redirect(url_for('admin_dashboard'))
        elif role == 'mentor':
            return redirect(url_for('mentor_dashboard'))
    
    flash("Please log in to access your dashboard.", "warning")
    return redirect(url_for('login'))

# ==============================================================================
# REGISTRATION ROUTES
# ==============================================================================

@app.route('/register_student', methods=['GET', 'POST'])
def register_student():
    """Handles the first step of student registration (info collection and OTP)."""
    if request.method == 'POST':
        # Store form data in session to persist across steps
        session['registration_data'] = {
            'name': request.form['name'],
            'college': request.form['college'],
            'roll_no': request.form['roll_no'],
            'email': request.form['email']
        }
        
        # OTP is only required for non-"marwadi" colleges
        if "marwadi" not in session['registration_data']['college'].lower():
            otp = str(random.randint(100000, 999999))
            session['otp'] = otp
            if send_otp(session['registration_data']['email'], otp):
                return redirect(url_for('verify_otp'))
            else:
                # If OTP sending fails, stay on the page with an error
                return render_template('register_step1.html')
        else:
            # Marwadi students can skip OTP verification
            return redirect(url_for('register_details'))

    return render_template('register_step1.html')

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    """Handles OTP verification for non-Marwadi students."""
    if 'registration_data' not in session:
        return redirect(url_for('register_student'))

    if request.method == 'POST':
        otp_input = request.form.get('otp')
        if otp_input == session.get('otp'):
            session.pop('otp', None) # Clear OTP after successful verification
            flash("OTP Verified Successfully!", "success")
            return redirect(url_for('register_details'))
        else:
            flash("Invalid OTP. Please try again.", "danger")
    
    return render_template('verify_otp.html', email=session['registration_data']['email'])


@app.route('/register_details', methods=['GET', 'POST'])
def register_details():
    """Handles the final step of student registration (detailed info and DB insertion)."""
    if 'registration_data' not in session:
        flash("Please start the registration process from the beginning.", "warning")
        return redirect(url_for('register_student'))

    if request.method == 'POST':
        password = request.form['password']
        if password != request.form['confirm_password']:
            flash("Passwords do not match!", "danger")
            return render_template('register_details.html')
            
        # --- SERVER-SIDE PASSWORD VALIDATION ---
        if len(password) < 8 or not re.search("[a-z]", password) or not re.search("[A-Z]", password) or not re.search("[0-9]", password) or not re.search("[!@#$%^&*]", password):
            flash("Password does not meet the requirements.", "danger")
            return render_template('register_details.html')

        hashed_password = generate_password_hash(password)
        user_id = str(uuid.uuid4())[:8] # Generate a unique user ID

        conn = get_db_connection()
        if not conn: return render_template('register_details.html')

        try:
            with conn.cursor() as cur:
                cur.execute('''
                    INSERT INTO users (user_id, name, college, roll_no, email, address, contact, role, year, branch, department, password)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ''', (
                    user_id, session['registration_data']['name'], session['registration_data']['college'],
                    session['registration_data']['roll_no'], session['registration_data']['email'],
                    request.form['address'], request.form['contact'], 'student', request.form['year'],
                    request.form['branch'], request.form['department'], hashed_password
                ))
            conn.commit()

            send_welcome_email(session['registration_data']['email'], session['registration_data']['name'], user_id)
            
            # Log the user in immediately after registration
            session['user_id'] = user_id
            session['user'] = session['registration_data']['name']
            session['role'] = 'student'
            session.pop('registration_data', None) # Clean up session

            flash(f"Registration successful! Your User ID is {user_id}. Please keep it safe.", "success")
            return redirect(url_for('dashboard'))

        except psycopg2.Error as e:
            conn.rollback()
            print(f"STUDENT REGISTRATION ERROR: {e}")
            flash("Registration failed due to a database error. It's possible the email or roll number is already in use.", "danger")
        finally:
            if conn: conn.close()

    return render_template('register_details.html')


@app.route('/register_mentor', methods=['GET', 'POST'])
def register_mentor():
    """Handles mentor registration."""
    if request.method == 'POST':
        password = request.form['password']
        if password != request.form['confirm_password']:
            flash("Passwords do not match!", "danger")
            return render_template('register_mentor.html')

        # --- SERVER-SIDE PASSWORD VALIDATION ---
        if len(password) < 8 or not re.search("[a-z]", password) or not re.search("[A-Z]", password) or not re.search("[0-9]", password) or not re.search("[!@#$%^&*]", password):
            flash("Password does not meet the requirements.", "danger")
            return render_template('register_mentor.html')

        hashed_password = generate_password_hash(password)
        user_id = str(uuid.uuid4())[:8]

        conn = get_db_connection()
        if not conn: return render_template('register_mentor.html')

        try:
            with conn.cursor() as cur:
                # Inserting into the unified 'users' table with role 'mentor'
                cur.execute('''
                    INSERT INTO users (user_id, name, college, email, expertise, skills, password, role)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                ''', (
                    user_id, request.form['name'], request.form['college'], request.form['email'],
                    request.form['expertise'], request.form['skills'], hashed_password, 'mentor'
                ))
            conn.commit()

            send_welcome_email(request.form['email'], request.form['name'], user_id)
            
            session['user_id'] = user_id
            session['user'] = request.form['name']
            session['role'] = 'mentor'

            flash(f"Mentor registration successful! Your User ID is {user_id}.", "success")
            return redirect(url_for('dashboard'))
        except psycopg2.Error as e:
            conn.rollback()
            print(f"MENTOR REGISTRATION ERROR: {e}")
            flash("Registration failed. The email may already be in use.", "danger")
        finally:
            if conn: conn.close()

    return render_template('register_mentor.html')

# ==============================================================================
# ADMIN-SPECIFIC ROUTES
# ==============================================================================

@app.route('/admin_dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    """Admin dashboard for creating events and viewing statistics."""
    if session.get('role') != 'admin':
        flash("Unauthorized access.", "danger")
        return redirect(url_for('login'))

    conn = get_db_connection()
    if not conn: return render_template('admin_dashboard.html', event_stats=[])

    try:
        with conn.cursor() as cur:
            if request.method == 'POST':
                # --- Event Creation Logic ---
                image_url = None
                image_file = request.files.get('event_image')
                if image_file and allowed_file(image_file.filename, ALLOWED_IMAGE_EXTENSIONS):
                    try:
                        upload_result = cloudinary.uploader.upload(image_file, folder="event_images")
                        image_url = upload_result.get('secure_url')
                    except Exception as e:
                        print(f"CLOUDINARY UPLOAD ERROR: {e}")
                        flash(f"Event image upload failed: {e}", "danger")
                
                cur.execute(
                    "INSERT INTO events (title, short_description, description, date, image_url) VALUES (%s, %s, %s, %s, %s) RETURNING id",
                    (request.form['title'], request.form['short_description'], request.form['description'], request.form['date'], image_url)
                )
                event_id = cur.fetchone()['id']

                # Add stages for the new event
                stages = request.form.getlist('stage_title[]')
                deadlines = request.form.getlist('deadline[]')
                for stage_title, deadline in zip(stages, deadlines):
                    if stage_title and deadline: # Ensure stage is not empty
                        cur.execute(
                            'INSERT INTO event_stages (event_id, stage_title, deadline) VALUES (%s, %s, %s)',
                            (event_id, stage_title, deadline)
                        )
                conn.commit()
                flash("Event created successfully!", "success")
                return redirect(url_for('admin_dashboard'))

            # --- Data Fetching for Display (Optimized) ---
            # Single query to get events and their registration/submission counts
            cur.execute("""
                SELECT
                    e.id, e.title, e.date, e.image_url,
                    COUNT(DISTINCT r.id) AS registered_count,
                    COUNT(DISTINCT s.id) AS submitted_count
                FROM events e
                LEFT JOIN event_registrations r ON e.id = r.event_id
                LEFT JOIN submissions s ON e.id = s.event_id
                GROUP BY e.id
                ORDER BY e.date DESC
            """)
            event_stats = cur.fetchall()

    except psycopg2.Error as e:
        conn.rollback()
        print(f"ADMIN DASHBOARD ERROR: {e}")
        flash("A database error occurred on the admin dashboard.", "danger")
        event_stats = []
    finally:
        if conn: conn.close()

    return render_template('admin_dashboard.html', event_stats=event_stats)

@app.route('/delete_event/<int:event_id>', methods=['POST'])
def delete_event(event_id):
    """Handles deletion of an event and all associated data."""
    if session.get('role') != 'admin':
        flash("Unauthorized access.", "danger")
        return redirect(url_for('login'))

    conn = get_db_connection()
    if not conn: return redirect(url_for('admin_dashboard'))

    try:
        with conn.cursor() as cur:
            # NOTE: The database schema should have ON DELETE CASCADE for related tables
            # (event_registrations, event_stages, submissions, event_results)
            # This makes deletion much cleaner and safer.
            cur.execute("DELETE FROM events WHERE id = %s", (event_id,))
        conn.commit()
        flash("Event and all associated data deleted successfully.", "success")
    except psycopg2.Error as e:
        conn.rollback()
        print(f"DELETE EVENT ERROR: {e}")
        flash("Database error during event deletion.", "danger")
    finally:
        if conn: conn.close()

    return redirect(url_for('admin_dashboard'))

@app.route('/announce_winner', methods=['POST'])
def announce_winner():
    """Handles announcing winners for an event."""
    if session.get('role') != 'admin':
        flash("Unauthorized access.", "danger")
        return redirect(url_for('login'))

    event_id = request.form['event_id']
    event_title = request.form['event_title']
    conn = get_db_connection()
    if not conn: return redirect(url_for('admin_dashboard'))

    try:
        with conn.cursor() as cur:
            # Clear previous results for this event to prevent duplicates
            cur.execute("DELETE FROM event_results WHERE event_id = %s", (event_id,))
            
            for i in range(1, 4): # For positions 1, 2, 3
                position = request.form.get(f'position{i}')
                name = request.form.get(f'name{i}')
                if name and position:
                    cur.execute(
                        "INSERT INTO event_results (event_id, event_title, position, winner_name) VALUES (%s, %s, %s, %s)",
                        (event_id, event_title, position, name)
                    )
        conn.commit()
        flash("Winners announced successfully!", "success")
    except psycopg2.Error as e:
        conn.rollback()
        print(f"ANNOUNCE WINNER ERROR: {e}")
        flash("Database error while announcing winners.", "danger")
    finally:
        if conn: conn.close()

    return redirect(url_for('admin_dashboard'))

@app.route('/view_all_users')
def view_all_users():
    """Displays a list of all users for the admin."""
    if session.get('role') != 'admin':
        flash("Unauthorized access.", "danger")
        return redirect(url_for('login'))

    conn = get_db_connection()
    if not conn: return render_template('view_all_users.html', users=[])

    try:
        with conn.cursor() as cur:
            # A single query to get all users, ordered by role and then name
            cur.execute("SELECT user_id, name, email, role, college, contact FROM users ORDER BY role, name ASC")
            users = cur.fetchall()
    except psycopg2.Error as e:
        print(f"VIEW ALL USERS ERROR: {e}")
        flash("Database error fetching user list.", "danger")
        users = []
    finally:
        if conn: conn.close()

    return render_template('view_all_users.html', users=users)

# ==============================================================================
# STUDENT-SPECIFIC ROUTES
# ==============================================================================

@app.route('/student_dashboard')
def student_dashboard():
    """Renders the student dashboard with available events and results."""
    if session.get('role') != 'student':
        flash("Unauthorized access.", "danger")
        return redirect(url_for('login'))

    conn = get_db_connection()
    if not conn: return render_template('student_dashboard.html', student=None, events=[], results={})

    student_info = get_user_by_id(session['user_id'])
    events = []
    grouped_results = defaultdict(list)
    try:
        with conn.cursor() as cur:
            # Fetch all events that the student has NOT registered for
            cur.execute("""
                SELECT e.id, e.title, e.short_description, e.date, e.image_url
                FROM events e
                WHERE e.id NOT IN (SELECT event_id FROM event_registrations WHERE user_id = %s)
                ORDER BY e.date DESC
            """, (session['user_id'],))
            events = cur.fetchall()

            # Fetch and group winner announcements
            cur.execute("""
                SELECT event_title, position, winner_name FROM event_results
                ORDER BY event_title, CASE WHEN position LIKE '1%' THEN 1 WHEN position LIKE '2%' THEN 2 ELSE 3 END
            """)
            for result in cur.fetchall():
                grouped_results[result['event_title']].append((result['position'], result['winner_name']))
    except psycopg2.Error as e:
        print(f"STUDENT DASHBOARD ERROR: {e}")
        flash("Database error on student dashboard.", "danger")
    finally:
        if conn: conn.close()

    return render_template('student_dashboard.html', student=student_info, events=events, results=dict(grouped_results))

@app.route('/event/<int:event_id>', methods=['GET', 'POST'])
def event_detail(event_id):
    """Displays event details and handles student registration for the event."""
    if session.get('role') != 'student':
        flash("Please log in as a student to view event details.", "warning")
        return redirect(url_for('login'))

    conn = get_db_connection()
    if not conn: return redirect(url_for('student_dashboard'))

    try:
        with conn.cursor() as cur:
            if request.method == 'POST':
                # Handle event registration
                cur.execute("INSERT INTO event_registrations (user_id, event_id) VALUES (%s, %s)", (session['user_id'], event_id))
                conn.commit()
                flash("You have successfully registered for this event!", "success")
                return redirect(url_for('student_registered_events'))

            # Fetch event details and registration status
            cur.execute("SELECT * FROM events WHERE id = %s", (event_id,))
            event = cur.fetchone()
            cur.execute("SELECT id FROM event_registrations WHERE user_id = %s AND event_id = %s", (session['user_id'], event_id))
            is_registered = cur.fetchone() is not None
    except psycopg2.Error as e:
        conn.rollback()
        print(f"EVENT DETAIL ERROR: {e}")
        flash("Database error on event detail page.", "danger")
        return redirect(url_for('student_dashboard'))
    finally:
        if conn: conn.close()
        
    return render_template('event_detail.html', event=event, registered=is_registered)

@app.route('/registered_events')
def student_registered_events():
    """Displays events a student is registered for, along with submission status."""
    if session.get('role') != 'student':
        flash("Unauthorized access.", "danger")
        return redirect(url_for('login'))

    conn = get_db_connection()
    if not conn: return render_template('registered_events.html', events=[])

    events_data = []
    try:
        with conn.cursor() as cur:
            # Optimized query to get registered events, their stages, and submission status in one go
            cur.execute("""
                SELECT
                    e.id AS event_id, e.title, e.short_description, e.date, e.image_url,
                    es.id AS stage_id, es.stage_title, es.deadline,
                    s.submission_text, s.submission_file_url, s.submitted_on
                FROM event_registrations er
                JOIN events e ON er.event_id = e.id
                JOIN event_stages es ON e.id = es.event_id
                LEFT JOIN submissions s ON er.user_id = s.user_id AND es.id = s.stage_id
                WHERE er.user_id = %s
                ORDER BY e.date DESC, es.deadline ASC;
            """, (session['user_id'],))
            
            # Process the flat results into a nested structure
            processed_events = {}
            for row in cur.fetchall():
                event_id = row['event_id']
                if event_id not in processed_events:
                    processed_events[event_id] = {
                        'id': event_id, 'title': row['title'], 'short_description': row['short_description'],
                        'date': row['date'], 'image_url': row['image_url'], 'stages': []
                    }
                
                processed_events[event_id]['stages'].append({
                    'id': row['stage_id'], 'stage_title': row['stage_title'], 'deadline': row['deadline'],
                    'submission_text': row['submission_text'], 'submission_file_url': row['submission_file_url'],
                    'submitted_on': row['submitted_on'],
                    'status': 'Submitted' if row['submitted_on'] else 'Not Submitted'
                })
            events_data = list(processed_events.values())

    except psycopg2.Error as e:
        print(f"REGISTERED EVENTS ERROR: {e}")
        flash("Database error fetching registered events.", "danger")
    finally:
        if conn: conn.close()

    return render_template('registered_events.html', events=events_data)


@app.route('/submit/<int:event_id>/<int:stage_id>', methods=['GET', 'POST'])
def submit_stage(event_id, stage_id):
    """Handles student submission for a specific event stage."""
    if session.get('role') != 'student':
        flash("Unauthorized access.", "danger")
        return redirect(url_for('login'))

    conn = get_db_connection()
    if not conn: return redirect(url_for('student_registered_events'))

    try:
        with conn.cursor() as cur:
            cur.execute("SELECT stage_title, deadline FROM event_stages WHERE id = %s", (stage_id,))
            stage = cur.fetchone()
            if not stage:
                flash("Invalid stage.", "danger")
                return redirect(url_for('student_registered_events'))

            # Corrected deadline check: allows submission on the deadline day
            if datetime.now().date() > stage['deadline']:
                flash("Submission deadline has passed!", "danger")
                return redirect(url_for('student_registered_events'))

            cur.execute("SELECT id FROM submissions WHERE user_id = %s AND stage_id = %s", (session['user_id'], stage_id))
            if cur.fetchone():
                flash("You have already submitted for this stage.", "warning")
                return redirect(url_for('student_registered_events'))

            if request.method == 'POST':
                file_url = None
                file = request.files.get('submission_file')
                if file and allowed_file(file.filename, ALLOWED_SUBMISSION_EXTENSIONS):
                    try:
                        upload_result = cloudinary.uploader.upload(file, resource_type="raw", folder="submissions")
                        file_url = upload_result.get('secure_url')
                    except Exception as e:
                        print(f"SUBMISSION UPLOAD ERROR: {e}")
                        flash(f"Submission file upload failed: {e}", "danger")
                        return render_template('submit_stage.html', stage=stage, event_id=event_id, stage_id=stage_id)
                
                cur.execute(
                    "INSERT INTO submissions (user_id, event_id, stage_id, submission_text, submission_file_url, submitted_on) VALUES (%s, %s, %s, %s, %s, %s)",
                    (session['user_id'], event_id, stage_id, request.form.get('submission_text'), file_url, datetime.now())
                )
                conn.commit()
                flash("Submission successful!", "success")
                return redirect(url_for('student_registered_events'))

    except psycopg2.Error as e:
        conn.rollback()
        print(f"SUBMISSION ERROR: {e}")
        flash("Database error during submission.", "danger")
    finally:
        if conn: conn.close()
    
    return render_template('submit_stage.html', stage=stage, event_id=event_id, stage_id=stage_id)


@app.route('/profile', methods=['GET', 'POST'])
def profile():
    """Displays and allows updating of user profile."""
    if 'user_id' not in session:
        flash("Please log in to view your profile.", "warning")
        return redirect(url_for('login'))

    user_data = get_user_by_id(session['user_id'])
    if not user_data:
        session.clear()
        flash("Could not find user data. Please log in again.", "danger")
        return redirect(url_for('login'))

    if request.method == 'POST':
        conn = get_db_connection()
        if not conn: return render_template('profile.html', user_data=user_data)
        
        try:
            with conn.cursor() as cur:
                # Update fields common to all roles
                cur.execute(
                    "UPDATE users SET contact = %s, address = %s WHERE user_id = %s",
                    (request.form.get('contact'), request.form.get('address'), session['user_id'])
                )
                # Update student-specific fields
                if session['role'] == 'student':
                    cur.execute(
                        "UPDATE users SET year = %s, branch = %s, department = %s WHERE user_id = %s",
                        (request.form.get('year'), request.form.get('branch'), request.form.get('department'), session['user_id'])
                    )
            conn.commit()
            flash("Profile updated successfully!", "success")
            return redirect(url_for('profile')) # Redirect to refresh data
        except psycopg2.Error as e:
            conn.rollback()
            print(f"PROFILE UPDATE ERROR: {e}")
            flash("Database error during profile update.", "danger")
        finally:
            if conn: conn.close()

    return render_template('profile.html', user_data=user_data)

@app.route('/change_password', methods=['POST'])
def change_password():
    """Allows authenticated users to change their password."""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_data = get_user_by_id(session['user_id'])
    if not user_data or not check_password_hash(user_data['password'], request.form.get('current_password')):
        flash("Current password incorrect.", "danger")
        return redirect(url_for('profile'))

    new_password = request.form.get('new_password')
    if new_password != request.form.get('confirm_new_password'):
        flash("New passwords do not match.", "danger")
        return redirect(url_for('profile'))
        
    # --- SERVER-SIDE PASSWORD VALIDATION ---
    if len(new_password) < 8 or not re.search("[a-z]", new_password) or not re.search("[A-Z]", new_password) or not re.search("[0-9]", new_password) or not re.search("[!@#$%^&*]", new_password):
        flash("New password does not meet the security requirements.", "danger")
        return redirect(url_for('profile'))

    hashed_password = generate_password_hash(new_password)
    conn = get_db_connection()
    if not conn: return redirect(url_for('profile'))

    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE users SET password = %s WHERE user_id = %s", (hashed_password, session['user_id']))
        conn.commit()
        flash("Password changed successfully!", "success")
    except psycopg2.Error as e:
        conn.rollback()
        print(f"CHANGE PASSWORD ERROR: {e}")
        flash("Database error during password change.", "danger")
    finally:
        if conn: conn.close()

    return redirect(url_for('profile'))

# ==============================================================================
# MENTOR-SPECIFIC ROUTES
# ==============================================================================

@app.route('/mentor_dashboard')
def mentor_dashboard():
    """Renders the mentor dashboard."""
    if session.get('role') != 'mentor':
        flash("Unauthorized access.", "danger")
        return redirect(url_for('login'))
    # This can be expanded with mentor-specific functionality
    return render_template('mentor_dashboard.html', user=get_user_by_id(session['user_id']))

@app.route('/view_progress/<int:event_id>')
def view_progress(event_id):
    """Displays submission progress for an event (for admins and mentors)."""
    if session.get('role') not in ['admin', 'mentor']:
        flash("Unauthorized access.", "danger")
        return redirect(url_for('login'))

    conn = get_db_connection()
    if not conn: return redirect(url_for('dashboard'))

    progress = []
    stages = []
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id, stage_title FROM event_stages WHERE event_id = %s ORDER BY deadline ASC", (event_id,))
            stage_data = cur.fetchall()
            if not stage_data:
                flash("No stages found for this event.", "warning")
                return redirect(url_for('dashboard'))

            stages = [row['stage_title'] for row in stage_data]
            stage_id_map = {row['stage_title']: row['id'] for row in stage_data}

            # Fetch all participants for the event
            cur.execute("""
                SELECT u.user_id, u.name, u.email, u.college, u.roll_no
                FROM event_registrations r JOIN users u ON r.user_id = u.user_id
                WHERE r.event_id = %s
            """, (event_id,))
            participants = cur.fetchall()

            # --- OPTIMIZATION: Fetch all submissions for the event in ONE query ---
            cur.execute("SELECT user_id, stage_id, submission_file_url, submission_text FROM submissions WHERE event_id = %s", (event_id,))
            submissions_map = {(s['user_id'], s['stage_id']): s for s in cur.fetchall()}

            # --- Process data in Python (NO DB calls inside the loop) ---
            for user in participants:
                user_info = dict(user)
                user_info['stage_status'] = {}
                for stage_title in stages:
                    stage_id = stage_id_map[stage_title]
                    submission = submissions_map.get((user['user_id'], stage_id))
                    user_info['stage_status'][stage_title] = {
                        'status': '✅' if submission else '❌',
                        'file': submission['submission_file_url'] if submission else None,
                        'text': submission['submission_text'] if submission else None
                    }
                progress.append(user_info)
    except psycopg2.Error as e:
        print(f"VIEW PROGRESS ERROR: {e}")
        flash("Database error viewing progress.", "danger")
    finally:
        if conn: conn.close()

    return render_template('view_progress.html', progress=progress, stages=stages, event_id=event_id)

# ==============================================================================
# BRAINSTORM ROOM (CHAT) ROUTES & SOCKETIO EVENTS
# ==============================================================================

@app.route('/brainstorm', methods=['GET', 'POST'])
def brainstorm():
    """Lists brainstorm rooms and handles room creation."""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    if not conn: return render_template('brainstorm.html', rooms=[])

    try:
        with conn.cursor() as cur:
            if request.method == 'POST':
                room_title = request.form.get('room_title')
                if not room_title:
                    flash("Room title cannot be empty.", "danger")
                else:
                    room_id = str(uuid.uuid4())[:8]
                    cur.execute(
                        "INSERT INTO brainstorm_rooms (room_id, title, created_by) VALUES (%s, %s, %s)",
                        (room_id, room_title, session['user_id'])
                    )
                    conn.commit()
                    flash("Room created successfully!", "success")
                    return redirect(url_for('join_brainstorm_room', room_id=room_id))

            # Fetch all rooms with creator's name
            cur.execute("""
                SELECT br.room_id, br.title, br.created_at, u.name AS creator_name
                FROM brainstorm_rooms br
                JOIN users u ON br.created_by = u.user_id
                ORDER BY br.created_at DESC
            """)
            rooms = cur.fetchall()
    except psycopg2.Error as e:
        conn.rollback()
        print(f"BRAINSTORM ERROR: {e}")
        flash("A database error occurred.", "danger")
        rooms = []
    finally:
        if conn: conn.close()

    return render_template('brainstorm.html', rooms=rooms)

@app.route('/brainstorm/room/<room_id>')
def join_brainstorm_room(room_id):
    """Renders the chat room page."""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    if not conn: return redirect(url_for('brainstorm'))

    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM brainstorm_chats WHERE room_id = %s ORDER BY timestamp ASC", (room_id,))
            chat_history = cur.fetchall()
            cur.execute("SELECT * FROM brainstorm_room_files WHERE room_id = %s ORDER BY uploaded_at ASC", (room_id,))
            shared_files = cur.fetchall()
    except psycopg2.Error as e:
        print(f"BRAINSTORM ROOM LOAD ERROR: {e}")
        flash("Error loading room data.", "danger")
        chat_history, shared_files = [], []
    finally:
        if conn: conn.close()

    return render_template('brainstorm_room.html', room_id=room_id, user=session['user'], chat_history=chat_history, shared_files=shared_files)

@app.route('/brainstorm/upload/<room_id>', methods=['POST'])
def upload_file_brainstorm(room_id):
    """Handles file uploads to a brainstorm room via AJAX."""
    if 'user_id' not in session:
        return jsonify(status='error', message='Unauthorized'), 401

    file = request.files.get('file')
    if not file or not allowed_file(file.filename, ALLOWED_SUBMISSION_EXTENSIONS):
        return jsonify(status='error', message='Invalid or no file provided.'), 400

    try:
        upload_result = cloudinary.uploader.upload(file, resource_type="raw", folder=f"brainstorm_rooms/{room_id}")
        file_url = upload_result['secure_url']
        
        conn = get_db_connection()
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO brainstorm_room_files (room_id, filename, file_url, uploaded_by_user) VALUES (%s, %s, %s, %s)",
                (room_id, file.filename, file_url, session['user'])
            )
        conn.commit()
        
        # Notify other users in the room via SocketIO
        socketio.emit('file_shared', {
            'user': session['user'], 'filename': file.filename, 'file_url': file_url, 'timestamp': datetime.now().isoformat()
        }, to=room_id)
        
        return jsonify(status='success', message='File uploaded.')
    except Exception as e:
        print(f"BRAINSTORM UPLOAD ERROR: {e}")
        return jsonify(status='error', message='File upload failed.'), 500
    finally:
        if 'conn' in locals() and conn: conn.close()

@socketio.on('join')
def handle_join(data):
    """Handles a user joining a SocketIO room."""
    room = data.get('room')
    user = data.get('user')
    join_room(room)
    emit('message', {'user': 'System', 'msg': f"{user} has joined the room.", 'timestamp': datetime.now().isoformat()}, to=room)

@socketio.on('send_message')
def handle_message(data):
    """Handles receiving a message, saving it, and broadcasting it."""
    room, user, msg = data.get('room'), data.get('user'), data.get('msg')
    if not all([room, user, msg]): return

    conn = get_db_connection()
    if not conn: return # Fail silently on the backend

    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO brainstorm_chats (room_id, username, message) VALUES (%s, %s, %s)",
                (room, user, msg)
            )
        conn.commit()
        # Broadcast the message to everyone in the room
        emit('message', {'user': user, 'msg': msg, 'timestamp': datetime.now().isoformat()}, to=room)
    except psycopg2.Error as e:
        conn.rollback()
        print(f"CHAT MESSAGE SAVE ERROR: {e}")
    finally:
        if conn: conn.close()

# ==============================================================================
# APP RUNNER
# ==============================================================================

if __name__ == '__main__':
    # Use socketio.run() to correctly start the eventlet server
    # The host and port are important for running inside containers or on cloud platforms
    port = int(os.environ.get('PORT', 5000))
    socketio.run(app, host='0.0.0.0', port=port, debug=False)

