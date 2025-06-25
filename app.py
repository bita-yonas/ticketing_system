import sqlite3
from flask import (
    Flask, g, render_template, request,
    redirect, url_for, session, abort, flash, jsonify
)
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os
from datetime import datetime
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
import jwt
import requests
import firebase_admin
from firebase_admin import credentials, auth
from flask_mail import Mail, Message
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import resend

# Load environment variables
load_dotenv()

# Initialize Resend
resend.api_key = os.getenv('RESEND_API_KEY')

# Only import Firebase if not running on Vercel
RUNNING_ON_VERCEL = os.environ.get('VERCEL_ENV') == 'production'

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'replace-with-a-secure-random-key')
app.config['DATABASE']   = ':memory:' if RUNNING_ON_VERCEL else 'tickets.db'
app.config['CLERK_PUBLISHABLE_KEY'] = os.getenv('CLERK_PUBLISHABLE_KEY')
app.config['CLERK_SECRET_KEY'] = os.getenv('CLERK_SECRET_KEY')

# Gmail configuration
GMAIL_ADDRESS = "bitayonas@gmail.com"
GMAIL_PASSWORD = os.getenv('GMAIL_APP_PASSWORD')  # You'll need to set this up

# Directory to store uploaded images
app.config['UPLOAD_PATH'] = os.path.join(app.root_path, 'static', 'uploads')

# Firebase configuration
app.config.update(
    FIREBASE_API_KEY=os.environ.get('FIREBASE_API_KEY'),
    FIREBASE_AUTH_DOMAIN=os.environ.get('FIREBASE_AUTH_DOMAIN'),
    FIREBASE_PROJECT_ID=os.environ.get('FIREBASE_PROJECT_ID'),
    FIREBASE_STORAGE_BUCKET=os.environ.get('FIREBASE_STORAGE_BUCKET'),
    FIREBASE_MESSAGING_SENDER_ID=os.environ.get('FIREBASE_MESSAGING_SENDER_ID'),
    FIREBASE_APP_ID=os.environ.get('FIREBASE_APP_ID')
)

# Initialize Firebase Admin SDK
if not RUNNING_ON_VERCEL and os.environ.get('FIREBASE_PROJECT_ID'):
    cred = credentials.Certificate({
        "type": "service_account",
        "project_id": os.environ.get('FIREBASE_PROJECT_ID'),
        "private_key_id": os.environ.get('FIREBASE_PRIVATE_KEY_ID'),
        "private_key": os.environ.get('FIREBASE_PRIVATE_KEY', '').replace('\\n', '\n'),
        "client_email": os.environ.get('FIREBASE_CLIENT_EMAIL'),
        "client_id": os.environ.get('FIREBASE_CLIENT_ID'),
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
        "client_x509_cert_url": os.environ.get('FIREBASE_CLIENT_CERT_URL')
    })
    try:
        firebase_admin.initialize_app(cred)
    except ValueError:
        # App already initialized
        pass

# --- Database helpers ---
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(app.config['DATABASE'])
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(error=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    # 1) Create base tables
    with app.open_resource('schema.sql') as f:
        db.executescript(f.read().decode())
    # 2) Inspect columns
    cols = [c['name'] for c in db.execute("PRAGMA table_info(users);").fetchall()]
    # 3) Add email if missing
    if 'email' not in cols:
        db.execute(
            "ALTER TABLE users ADD COLUMN email TEXT UNIQUE NOT NULL DEFAULT '';"
        )
    # 5) Add role if missing
    if 'role' not in cols:
        db.execute(
            "ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user';")
    # 6) Add agent_category if missing
    if 'agent_category' not in cols:
        db.execute(
            "ALTER TABLE users ADD COLUMN agent_category TEXT;")
    # 7) Add assigned_agent_id to tickets if missing
    tbl_cols = [c['name'] for c in db.execute("PRAGMA table_info(tickets);").fetchall()]
    if 'assigned_agent_id' not in tbl_cols:
        db.execute(
            "ALTER TABLE tickets ADD COLUMN assigned_agent_id INTEGER;")
    # Articles table management removed
    db.commit()

# --- Auth helpers ---
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('user_id'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('user_id'):
            return redirect(url_for('login'))
            
        # Check both is_admin flag and role
        if not session.get('is_admin') and session.get('role') != 'admin':
            abort(403)
        return f(*args, **kwargs)
    return decorated

# Add a new decorator for super admin only functions
def super_admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('user_id'):
            return redirect(url_for('login'))
            
        # Check both is_admin flag and role
        if not session.get('is_admin') or session.get('role') != 'admin':
            abort(403)
        return f(*args, **kwargs)
    return decorated

# Add a new decorator for article management permissions
def article_admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('user_id'):
            return redirect(url_for('login'))
            
        # Get user's role
        role = session.get('role')
        
        # Allow access for super admin and department admins
        if role == 'admin' or role in ['it_admin', 'facilities_admin', 'academic_admin', 'administrative_admin']:
            return f(*args, **kwargs)
            
        abort(403)
    return decorated

# --- Routes ---
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        login_val = request.form['login']
        password  = request.form['password']
        db = get_db()
        user = db.execute(
            """
            SELECT * FROM users
            WHERE username = ? OR email = ?
            """,
            (login_val, login_val)
        ).fetchone()
        if user and check_password_hash(user['password'], password):
            session['user_id']  = user['id']
            session['is_admin'] = user['role'] == 'admin'
            session['username'] = user['username']
            session['role'] = user['role']
            return redirect(url_for('list_tickets'))
        error = 'Invalid credentials'
    return render_template('login.html', error=error, clerk_publishable_key=app.config['CLERK_PUBLISHABLE_KEY'])

@app.route('/clerk-callback')
def clerk_callback():
    session_token = request.args.get('session_token')
    if not session_token:
        return redirect(url_for('login'))

    try:
        # Verify the session token with Clerk's API
        headers = {
            'Authorization': f'Bearer {app.config["CLERK_SECRET_KEY"]}',
            'Content-Type': 'application/json'
        }
        response = requests.get(
            f'https://api.clerk.dev/v1/sessions/{session_token}',
            headers=headers
        )
        
        if response.status_code != 200:
            raise Exception('Invalid session token')
            
        session_data = response.json()
        user_id = session_data['user_id']
        
        # Get user details from Clerk
        user_response = requests.get(
            f'https://api.clerk.dev/v1/users/{user_id}',
            headers=headers
        )
        
        if user_response.status_code != 200:
            raise Exception('Failed to get user details')
            
        user_data = user_response.json()
        email = user_data['email_addresses'][0]['email_address']
        username = user_data.get('username') or email.split('@')[0]
        
        # Check if user exists in our database
        db = get_db()
        user = db.execute(
            'SELECT * FROM users WHERE email = ?',
            (email,)
        ).fetchone()
        
        if not user:
            # Create new user in our database
            db.execute(
                'INSERT INTO users (username, email, password, is_admin) VALUES (?, ?, ?, ?)',
                (username, email, 'clerk-auth', False)
            )
            db.commit()
            user = db.execute(
                'SELECT * FROM users WHERE email = ?',
                (email,)
            ).fetchone()
        
        # Set session variables
        session['user_id'] = user['id']
        session['is_admin'] = bool(user['is_admin'])
        session['username'] = user['username']
        
        return redirect(url_for('list_tickets'))
        
    except Exception as e:
        print(f"Error in Clerk callback: {e}")
        return redirect(url_for('login'))

@app.route('/notifications')
@login_required
def notifications():
    # TODO: fetch real data
    return render_template('notifications.html')

@app.route('/profile')
@login_required
def profile():
    # TODO: fetch real data
    return render_template('profile.html')


@app.route('/profile/edit')
@login_required
def profile_edit():
    # TODO: render a form for editing user details
    return render_template('profile_edit.html')


@app.route('/login/email', methods=['GET', 'POST'])
def login_email():
    error = None
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        db = get_db()
        user = db.execute(
            'SELECT * FROM users WHERE email = ?',
            (email,)
        ).fetchone()
        if user and check_password_hash(user['password'], password):
            session['user_id']  = user['id']
            session['is_admin'] = bool(user['is_admin'])
            session['username'] = user['username']
            return redirect(url_for('list_tickets'))
        error = 'Invalid credentials'
    return render_template('login_email.html', error=error)

@app.route('/logout')
@login_required
def logout():
    # Clear Flask session
    session.clear()
    
    # Add JavaScript to sign out from Firebase
    return """
        <script src="https://www.gstatic.com/firebasejs/10.8.0/firebase-app-compat.js"></script>
        <script src="https://www.gstatic.com/firebasejs/10.8.0/firebase-auth-compat.js"></script>
        <script>
            const firebaseConfig = {
                apiKey: "%s",
                authDomain: "%s",
                projectId: "%s",
                storageBucket: "%s",
                messagingSenderId: "%s",
                appId: "%s"
            };
            
            // Initialize Firebase
            firebase.initializeApp(firebaseConfig);
            
            // Sign out from Firebase and redirect
            firebase.auth().signOut().then(() => {
                window.location.href = '/login';
            }).catch((error) => {
                console.error('Error signing out:', error);
                window.location.href = '/login';
            });
        </script>
    """ % (
        app.config['FIREBASE_API_KEY'],
        app.config['FIREBASE_AUTH_DOMAIN'],
        app.config['FIREBASE_PROJECT_ID'],
        app.config['FIREBASE_STORAGE_BUCKET'],
        app.config['FIREBASE_MESSAGING_SENDER_ID'],
        app.config['FIREBASE_APP_ID']
    )

@app.route('/help_articles')
@login_required
def help_articles():
    return render_template('help_articles.html')
    
@app.route('/all_articles')
@login_required
def all_articles():
    db = get_db()
    # Fetch published articles without icon fields
    rows = db.execute(
        'SELECT slug, title, category, substr(content,1,150) AS snippet '
        'FROM articles WHERE published = 1 ORDER BY created_at DESC'
    ).fetchall()
    # Annotate each article with icon and badge classes based on category
    articles = []
    for row in rows:
        art = dict(row)
        if art['category'] == 'IT Support':
            art['icon'] = 'wifi'
            art['icon_bg'] = 'bg-success-subtle'
            art['icon_color'] = 'text-success'
            art['category_slug'] = 'it'
        elif art['category'] == 'Academic Services':
            art['icon'] = 'mortarboard-fill'
            art['icon_bg'] = 'bg-primary-subtle'
            art['icon_color'] = 'text-primary'
            art['category_slug'] = 'academic'
        elif art['category'] == 'Facilities & Events':
            art['icon'] = 'calendar-date'
            art['icon_bg'] = 'bg-info-subtle'
            art['icon_color'] = 'text-info'
            art['category_slug'] = 'facilities'
        elif art['category'] == 'Administrative Services':
            art['icon'] = 'person-badge'
            art['icon_bg'] = 'bg-warning-subtle'
            art['icon_color'] = 'text-warning'
            art['category_slug'] = 'admin'
        else:
            art['icon'] = 'file-earmark-text'
            art['icon_bg'] = 'bg-secondary-subtle'
            art['icon_color'] = 'text-secondary'
            art['category_slug'] = art['category'].lower().replace(' & ', '').replace(' ', '-')
        articles.append(art)
    return render_template('all_articles.html', articles=articles)

@app.route('/services')
@login_required
def services():
    """List available services from the database."""
    db = get_db()
    services = db.execute(
        'SELECT slug, title, description, icon, color FROM services ORDER BY id'
    ).fetchall()
    return render_template('services.html', services=services)

@app.route('/kb_search')
@login_required
def kb_search():
    """Search published KB articles dynamically in the database"""
    query = request.args.get('q', '').strip()
    if not query:
        return redirect(url_for('help_articles'))

    db = get_db()
    like_q = f"%{query}%"
    rows = db.execute(
        'SELECT slug, title, category, substr(content,1,150) AS snippet '
        'FROM articles WHERE published = 1 '
        'AND (title LIKE ? OR content LIKE ? OR category LIKE ?) '
        'ORDER BY created_at DESC',
        (like_q, like_q, like_q)
    ).fetchall()
    # Annotate each result with icon classes and slugs
    articles = []
    for row in rows:
        art = dict(row)
        if art['category'] == 'IT Support': icon, bg, color, slug = 'wifi', 'bg-success-subtle', 'text-success', 'it'
        elif art['category'] == 'Academic Services': icon, bg, color, slug = 'mortarboard-fill', 'bg-primary-subtle', 'text-primary', 'academic'
        elif art['category'] == 'Facilities & Events': icon, bg, color, slug = 'calendar-date', 'bg-info-subtle', 'text-info', 'facilities'
        elif art['category'] == 'Administrative Services': icon, bg, color, slug = 'person-badge', 'bg-warning-subtle', 'text-warning', 'admin'
        else: icon, bg, color, slug = 'file-earmark-text', 'bg-secondary-subtle', 'text-secondary', art['category'].lower().replace(' & ', '').replace(' ', '-')
        art['icon'], art['icon_bg'], art['icon_color'], art['category_slug'] = icon, bg, color, slug
        articles.append(art)
    return render_template('kb_search.html', articles=articles, query=query)

@app.route('/search')
@login_required
def search():
    query = request.args.get('q', '').strip()
    if not query:
        return redirect(url_for('list_tickets'))
    
    db = get_db()
    search_term = f'%{query}%'
    results = {
        'tickets': [],
        'services': [],
        'help_articles': []
    }
    
    # Search tickets
    if session['is_admin']:
        tickets = db.execute(
            '''
            SELECT t.*, u.username 
            FROM tickets t
            JOIN users u ON u.id = t.user_id
            WHERE t.title LIKE ?
               OR t.description LIKE ?
               OR COALESCE(t.service_type, '') LIKE ?
               OR COALESCE(t.document_type, '') LIKE ?
               OR COALESCE(t.device_type, '') LIKE ?
               OR COALESCE(t.location, '') LIKE ?
               OR COALESCE(t.id_type, '') LIKE ?
               OR u.username LIKE ?
            ORDER BY t.created_at DESC
            ''',
            (search_term,) * 8
        ).fetchall()
    else:
        tickets = db.execute(
            '''
            SELECT t.*, u.username 
            FROM tickets t
            JOIN users u ON u.id = t.user_id
            WHERE t.user_id = ?
              AND (t.title LIKE ?
                   OR t.description LIKE ?
                   OR COALESCE(t.service_type, '') LIKE ?
                   OR COALESCE(t.document_type, '') LIKE ?
                   OR COALESCE(t.device_type, '') LIKE ?
                   OR COALESCE(t.location, '') LIKE ?
                   OR COALESCE(t.id_type, '') LIKE ?)
            ORDER BY t.created_at DESC
            ''',
            (session['user_id'], search_term) + (search_term,) * 6
        ).fetchall()

    # Convert timestamps to ISO format for tickets
    for ticket in tickets:
        ticket = dict(ticket)
        ticket['created_at'] = format_timestamp(ticket['created_at'])
        results['tickets'].append(ticket)

    # Search services
    services = [
        {
            'id': 'academic',
            'title': 'Academic & Records',
            'description': 'Request transcripts, enrollment verification, and grade appeals',
            'icon': 'mortarboard-fill',
            'color': 'primary'
        },
        {
            'id': 'it_support',
            'title': 'IT Support',
            'description': 'Get help with WiFi, software, and account access',
            'icon': 'pc-display',
            'color': 'success'
        },
        {
            'id': 'facilities',
            'title': 'Facilities & Events',
            'description': 'Book rooms, report maintenance issues, or request event support',
            'icon': 'building',
            'color': 'info'
        },
        {
            'id': 'admin_services',
            'title': 'Administrative Services',
            'description': 'ID cards, parking permits, and document requests',
            'icon': 'folder',
            'color': 'warning'
        }
    ]
    
    # Filter services based on search term
    results['services'] = [
        service for service in services
        if query.lower() in service['title'].lower() or
           query.lower() in service['description'].lower()
    ]

    # Search help articles
    help_articles = [
        # IT Support
        {
            'id': 'wifi',
            'title': 'Campus WiFi Setup Guide',
            'description': 'Step-by-step guide for connecting to the campus wireless network',
            'category': 'IT Support',
            'icon': 'wifi',
            'icon_bg': 'bg-success-subtle',
            'icon_color': 'text-success',
            'slug': 'wifi-setup'
        },
        {
            'id': 'password',
            'title': 'Account Password Reset Guide',
            'description': 'Instructions for resetting your account password',
            'category': 'IT Support',
            'icon': 'key-fill',
            'icon_bg': 'bg-success-subtle',
            'icon_color': 'text-success',
            'slug': 'password-reset'
        },
        {
            'id': 'software',
            'title': 'Accessing Campus Software',
            'description': 'How to access and install licensed software for students and staff',
            'category': 'IT Support',
            'icon': 'box-fill',
            'icon_bg': 'bg-success-subtle',
            'icon_color': 'text-success',
            'slug': 'software-access'
        },
        
        # Academic Services
        {
            'id': 'transcript',
            'title': 'How to Request Official Transcripts',
            'description': 'Learn how to request and receive your official academic transcripts',
            'category': 'Academic Services',
            'icon': 'mortarboard-fill',
            'icon_bg': 'bg-primary-subtle',
            'icon_color': 'text-primary',
            'slug': 'transcript-request'
        },
        {
            'id': 'enrollment',
            'title': 'Enrollment Verification Guide',
            'description': 'How to verify your enrollment status for insurance or employment purposes',
            'category': 'Academic Services',
            'icon': 'check-circle-fill',
            'icon_bg': 'bg-primary-subtle',
            'icon_color': 'text-primary',
            'slug': 'enrollment-verification'
        },
        
        # Facilities & Events
        {
            'id': 'rooms',
            'title': 'How to Book Campus Rooms',
            'description': 'Guide to reserving classrooms, meeting spaces, and event venues',
            'category': 'Facilities & Events',
            'icon': 'calendar-date',
            'icon_bg': 'bg-info-subtle',
            'icon_color': 'text-info',
            'slug': 'room-booking'
        },
        {
            'id': 'maintenance',
            'title': 'Submitting Maintenance Requests',
            'description': 'How to report facility issues and track maintenance requests',
            'category': 'Facilities & Events',
            'icon': 'tools',
            'icon_bg': 'bg-info-subtle',
            'icon_color': 'text-info',
            'slug': 'maintenance-request'
        },
        
        # Administrative Services
        {
            'id': 'idcard',
            'title': 'Student ID Card Services',
            'description': 'Information about obtaining, replacing, and using your student ID card',
            'category': 'Administrative Services',
            'icon': 'person-badge',
            'icon_bg': 'bg-warning-subtle',
            'icon_color': 'text-warning',
            'slug': 'id-card'
        },
        {
            'id': 'parking',
            'title': 'Parking Permit Information',
            'description': 'Learn how to request and manage campus parking permits',
            'category': 'Administrative Services',
            'icon': 'p-circle',
            'icon_bg': 'bg-warning-subtle',
            'icon_color': 'text-warning',
            'slug': 'parking-permit'
        }
    ]
    
    # Filter help articles based on search term
    results['help_articles'] = [
        article for article in help_articles
        if query.lower() in article['title'].lower() or
           query.lower() in article['description'].lower() or
           query.lower() in article['category'].lower()
    ]
    
    return render_template('search.html', results=results, query=query)

def format_timestamp(timestamp):
    """Convert SQLite timestamp to ISO format with UTC timezone"""
    if not timestamp:
        return None
    try:
        dt = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S')
        return dt.strftime('%Y-%m-%dT%H:%M:%SZ')
    except ValueError:
        return timestamp

@app.route('/tickets')
@login_required
def list_tickets():
    db = get_db()
    view = request.args.get('view')
    
    # Determine current user's role and department
    user = db.execute(
        'SELECT role, agent_category FROM users WHERE id = ?',
        (session['user_id'],)
    ).fetchone()
    role = user['role']
    dept = user['agent_category']
    
    # Map department display name to service_type slug
    dept_map = {
        'IT Support': 'it_support',
        'Academic Services': 'academic',
        'Facilities & Events': 'facilities',
        'Administrative Services': 'admin_services'
    }
    dept_slug = dept_map.get(dept)

    # Map admin roles to their departments
    admin_dept_map = {
        'it_admin': ('IT Support', 'it_support'),
        'facilities_admin': ('Facilities & Events', 'facilities'),
        'academic_admin': ('Academic Services', 'academic'),
        'administrative_admin': ('Administrative Services', 'admin_services')
    }

    # Handle department-specific views for admins
    dept_views = {
        'it_department': 'it_support',
        'facilities_department': 'facilities',
        'academic_department': 'academic',
        'administrative_department': 'admin_services'
    }

    if role == 'admin':
        # Super admin sees all tickets
        tickets = db.execute(
            '''
            SELECT t.*, u.username 
            FROM tickets t
            JOIN users u ON u.id = t.user_id 
            ORDER BY t.created_at DESC
            '''
        ).fetchall()
    elif role.endswith('_admin'):
        # Department admin sees only their department's tickets
        dept_name, dept_slug = admin_dept_map[role]
        tickets = db.execute(
            '''
            SELECT t.*, u.username
            FROM tickets t
            JOIN users u ON u.id = t.user_id
            WHERE t.service_type = ?
            ORDER BY t.created_at DESC
            ''',
            (dept_slug,)
        ).fetchall()
    elif role == 'super_agent':
        if view == 'all_departments':
            # Super agents can see all tickets from all departments
            tickets = db.execute(
                '''
                SELECT t.*, u.username
                FROM tickets t
                JOIN users u ON u.id = t.user_id
                ORDER BY t.created_at DESC
                '''
            ).fetchall()
        elif view == 'assigned':
            # Show tickets assigned to this super agent
            tickets = db.execute(
                '''
                SELECT t.*, u.username
                FROM tickets t
                JOIN users u ON u.id = t.user_id
                WHERE t.assigned_agent_id = ?
                ORDER BY t.created_at DESC
                ''',
                (session['user_id'],)
            ).fetchall()
        else:
            # Default view shows tickets from their department
            tickets = db.execute(
                '''
                SELECT t.*, u.username
                FROM tickets t
                JOIN users u ON u.id = t.user_id
                WHERE t.service_type = ?
                ORDER BY t.created_at DESC
                ''',
                (dept_slug,)
            ).fetchall()
    elif role == 'agent':
        if view == 'assigned':
            # Show only tickets assigned to this agent
            tickets = db.execute(
                '''
                SELECT t.*, u.username
                FROM tickets t
                JOIN users u ON u.id = t.user_id
                WHERE t.assigned_agent_id = ?
                ORDER BY t.created_at DESC
                ''',
                (session['user_id'],)
            ).fetchall()
        else:
            # Show all tickets in their department that can be assigned
            tickets = db.execute(
                '''
                SELECT t.*, u.username
                FROM tickets t
                JOIN users u ON u.id = t.user_id
                WHERE t.service_type = ? AND (t.assigned_agent_id IS NULL OR t.assigned_agent_id = ?)
                ORDER BY t.created_at DESC
                ''',
                (dept_slug, session['user_id'])
            ).fetchall()
    else:
        # Regular users see only their own tickets
        tickets = db.execute(
            '''
            SELECT t.*, u.username 
            FROM tickets t
            JOIN users u ON u.id = t.user_id
            WHERE t.user_id = ?
            ORDER BY t.created_at DESC
            ''',
            (session['user_id'],)
        ).fetchall()
    
    # Convert timestamps to ISO format
    for ticket in tickets:
        ticket = dict(ticket)
        ticket['created_at'] = format_timestamp(ticket['created_at'])
    
    return render_template('tickets.html', tickets=tickets, view=view, user_role=role)

@app.route('/new_ticket', methods=['GET', 'POST'])
@login_required
def new_ticket():
    if request.method == 'GET':
        service = request.args.get('service')
        today = datetime.now().strftime('%Y-%m-%d')
        return render_template('new_ticket.html', service=service, today=today)
    
    if request.method == 'POST':
        db = get_db()
        
        # Common fields
        title = request.form['title']
        description = request.form['description']
        service_type = request.form.get('service_type')
        
        # Initialize fields dictionary
        fields = {}
        
        if service_type:
            # Service-specific ticket
            fields.update({
                'service_type': service_type,
                'document_type': request.form.get('document_type'),
                'delivery_method': request.form.get('delivery_method'),
                'device_type': request.form.get('device_type'),
                'operating_system': request.form.get('operating_system'),
                'location': request.form.get('location'),
                'room': request.form.get('room'),
                'preferred_date': request.form.get('preferred_date'),
                'id_type': request.form.get('id_type'),
                'urgency': request.form.get('urgency'),
                'first_name': request.form.get('first_name'),
                'last_name': request.form.get('last_name'),
                'email': request.form.get('email'),
                'phone': request.form.get('phone')
            })
        else:
            # General ticket
            fields.update({
                'user_type': request.form.get('user_type'),
                'group_id': request.form.get('group_id'),
                'category_id': request.form.get('category_id'),
                'requester_email': request.form.get('requester_email'),
                'first_name': request.form.get('first_name'),
                'last_name': request.form.get('last_name'),
                'phone': request.form.get('phone'),
                'building': request.form.get('building'),
                'room': request.form.get('room')
            })
        
        # Remove None values
        fields = {k: v for k, v in fields.items() if v is not None}
        
        # Build the SQL query dynamically
        columns = ['title', 'description', 'user_id'] + list(fields.keys())
        values = [title, description, session['user_id']] + list(fields.values())
        placeholders = ','.join(['?' for _ in range(len(columns))])
        
        query = f'''
            INSERT INTO tickets ({','.join(columns)})
            VALUES ({placeholders})
        '''
        
        db.execute(query, values)
        db.commit()
        
        return redirect(url_for('list_tickets'))

@app.route('/tickets/<int:ticket_id>')
@login_required
def ticket_detail(ticket_id):
    db = get_db()
    ticket = db.execute('''
        SELECT t.*, u.username 
        FROM tickets t 
        JOIN users u ON t.user_id = u.id 
        WHERE t.id = ?
    ''', [ticket_id]).fetchone()
    
    if ticket is None:
        abort(404)
        
    # Get comments for the ticket
    comments = db.execute('''
        SELECT c.*, u.username, u.is_admin
        FROM comments c
        JOIN users u ON c.user_id = u.id
        WHERE c.ticket_id = ?
        ORDER BY c.created_at ASC
    ''', [ticket_id]).fetchall()
    
    # Fetch available agents for assignment
    agents = db.execute(
        'SELECT id, username, agent_category FROM users WHERE role = ? ORDER BY username',
        ('agent',)
    ).fetchall()
    
    return render_template('ticket_detail.html', ticket=ticket, comments=comments, agents=agents)

@app.route('/tickets/<int:ticket_id>/comments', methods=['POST'])
@login_required
def add_comment(ticket_id):
    db = get_db()
    
    # Check if ticket exists
    ticket = db.execute('SELECT id FROM tickets WHERE id = ?', [ticket_id]).fetchone()
    if ticket is None:
        abort(404)
    
    content = request.form.get('content')
    if not content or not content.strip():
        flash('Comment cannot be empty', 'error')
        return redirect(url_for('ticket_detail', ticket_id=ticket_id))
    
    db.execute('''
        INSERT INTO comments (ticket_id, user_id, content)
        VALUES (?, ?, ?)
    ''', [ticket_id, session['user_id'], content.strip()])
    db.commit()
    
    return redirect(url_for('ticket_detail', ticket_id=ticket_id))

@app.route('/tickets/<int:ticket_id>/status', methods=['PATCH'])
@login_required
def update_status(ticket_id):
    new_status = request.get_json().get('status')
    db = get_db()
    
    # Get ticket and user details
    ticket = db.execute(
        'SELECT t.*, u.email as user_email, u.username as user_username FROM tickets t JOIN users u ON t.user_id = u.id WHERE t.id = ?',
        [ticket_id]
    ).fetchone()
    
    if not ticket:
        abort(404)
    
    # Update the ticket status
    db.execute(
        'UPDATE tickets SET status = ? WHERE id = ?',
        (new_status, ticket_id)
    )
    db.commit()
    
    # Send email notification if ticket is closed
    if new_status.lower() == 'closed':
        try:
            email_data = {
                "from": "STAC IT Support <support@stacticket.com>",
                "reply_to": "support@stacticket.com",
                "to": ticket['user_email'],
                "subject": f"St. Thomas Aquinas College - IT Support Ticket #{ticket['id']} Resolved",
                "headers": {
                    "List-Unsubscribe": "<mailto:support@stacticket.com?subject=unsubscribe>",
                    "Precedence": "bulk",
                    "X-Entity-Ref-ID": f"stac-ticket-{ticket['id']}",
                    "X-Priority": "3",
                    "X-MSMail-Priority": "Normal"
                },
                "html": f"""
                    <!DOCTYPE html>
                    <html>
                    <head>
                        <meta charset="UTF-8">
                        <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    </head>
                    <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                        <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                            <div style="text-align: center; margin-bottom: 20px;">
                                <h1 style="color: #003366; margin: 0;">St. Thomas Aquinas College</h1>
                                <p style="color: #666; margin: 5px 0;">IT Support Ticket System</p>
                            </div>
                            
                            <div style="background-color: #f8f9fa; padding: 20px; border-radius: 5px; margin-bottom: 20px;">
                                <h2 style="color: #003366; margin-top: 0;">Ticket Resolved</h2>
                                <p>Dear {ticket['user_username']},</p>
                                <p>Your support ticket has been resolved and closed.</p>
                                
                                <div style="background-color: white; padding: 15px; border-radius: 5px; margin: 20px 0;">
                                    <h3 style="color: #003366; margin-top: 0;">Ticket Information</h3>
                                    <p style="margin: 5px 0;"><strong>Ticket Reference:</strong> STAC-{ticket['id']}</p>
                                    <p style="margin: 5px 0;"><strong>Subject:</strong> {ticket['title']}</p>
                                    <p style="margin: 5px 0;"><strong>Status:</strong> Closed</p>
                                </div>
                                
                                <p>If you need to reopen this ticket or have any further questions, please don't hesitate to contact us.</p>
                                
                                <div style="margin-top: 30px;">
                                    <p style="margin-bottom: 5px;">Best regards,</p>
                                    <p style="margin-top: 0;">STAC IT Support Team</p>
                                </div>
                            </div>
                        </div>
                    </body>
                    </html>
                """
            }
            resend.Emails.send(email_data)
        except Exception as e:
            print(f"Error sending email: {e}")
    
    return '', 204

@app.route('/admin')
@login_required
@admin_required
def admin_console():
    db = get_db()
    
    # Get current user's role and determine permissions
    user = db.execute(
        'SELECT role FROM users WHERE id = ?',
        (session['user_id'],)
    ).fetchone()
    
    # Map admin roles to their departments
    admin_dept_map = {
        'it_admin': ('IT Support', 'it_support'),
        'facilities_admin': ('Facilities & Events', 'facilities'),
        'academic_admin': ('Academic Services', 'academic'),
        'administrative_admin': ('Administrative Services', 'admin_services')
    }
    
    if user['role'] == 'admin':
        # Super admin sees everything
        users = db.execute(
            'SELECT id, username, email, is_admin, role, agent_category FROM users ORDER BY username'
        ).fetchall()
        tickets = db.execute(
            '''
            SELECT t.id, t.title, t.status, t.created_at, u.username,
                   ROW_NUMBER() OVER (ORDER BY t.created_at ASC) as display_id
            FROM tickets t
            JOIN users u ON u.id = t.user_id
            ORDER BY t.created_at ASC
            '''
        ).fetchall()
    else:
        # Department admin sees only their department
        dept_name, dept_slug = admin_dept_map[user['role']]
        
        # Only show users from their department
        users = db.execute(
            '''
            SELECT id, username, email, is_admin, role, agent_category 
            FROM users 
            WHERE agent_category = ? 
            AND role NOT IN ('admin', 'it_admin', 'facilities_admin', 'academic_admin', 'administrative_admin')
            ORDER BY username
            ''',
            (dept_name,)
        ).fetchall()
        
        # Only show tickets from their department
        tickets = db.execute(
            '''
            SELECT t.id, t.title, t.status, t.created_at, u.username,
                   ROW_NUMBER() OVER (ORDER BY t.created_at ASC) as display_id
            FROM tickets t
            JOIN users u ON u.id = t.user_id
            WHERE t.service_type = ?
            ORDER BY t.created_at ASC
            ''',
            (dept_slug,)
        ).fetchall()
    
    return render_template('admin.html', users=users, tickets=tickets, user_role=user['role'])

@app.route('/admin/articles')
@login_required
@article_admin_required
def admin_articles():
    """List all articles for admin management."""
    db = get_db()
    role = session.get('role')
    
    # Map admin roles to their departments
    admin_dept_map = {
        'it_admin': 'IT Support',
        'facilities_admin': 'Facilities & Events',
        'academic_admin': 'Academic Services',
        'administrative_admin': 'Administrative Services'
    }
    
    if role == 'admin':
        # Super admin sees all articles
        articles = db.execute(
            'SELECT id, title, slug, category, published, created_at, updated_at'
            ' FROM articles ORDER BY created_at DESC'
        ).fetchall()
    else:
        # Department admin sees only their department's articles
        dept = admin_dept_map.get(role)
        articles = db.execute(
            'SELECT id, title, slug, category, published, created_at, updated_at'
            ' FROM articles WHERE category = ? ORDER BY created_at DESC',
            (dept,)
        ).fetchall()
    
    return render_template('admin_articles.html', articles=articles, user_role=role)

@app.route('/admin/articles/new', methods=['GET', 'POST'])
@login_required
@article_admin_required
def new_article():
    """Create a new knowledge base article."""
    db = get_db()
    role = session.get('role')
    
    # Map admin roles to their departments
    admin_dept_map = {
        'it_admin': 'IT Support',
        'facilities_admin': 'Facilities & Events',
        'academic_admin': 'Academic Services',
        'administrative_admin': 'Administrative Services'
    }
    
    if request.method == 'POST':
        title = request.form['title']
        slug = request.form['slug']
        
        # Get category based on role
        if role == 'admin':
            category = request.form['category']
        else:
            category = admin_dept_map.get(role)
            if not category:
                flash('Invalid department administrator role.', 'error')
                return redirect(url_for('new_article'))
        
        content = request.form['content']
        published = 1 if request.form.get('published') else 0
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        try:
            db.execute(
                'INSERT INTO articles (title, slug, category, content, published, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
                (title, slug, category, content, published, now, now)
            )
            db.commit()
            return redirect(url_for('admin_articles'))
        except sqlite3.IntegrityError:
            flash('Article with this slug already exists.', 'error')
    
    return render_template('article_form.html', article=None, user_role=role)

@app.route('/admin/articles/<int:article_id>/edit', methods=['GET', 'POST'])
@login_required
@article_admin_required
def edit_article(article_id):
    """Edit an existing knowledge base article."""
    db = get_db()
    role = session.get('role')
    
    # Map admin roles to their departments
    admin_dept_map = {
        'it_admin': 'IT Support',
        'facilities_admin': 'Facilities & Events',
        'academic_admin': 'Academic Services',
        'administrative_admin': 'Administrative Services'
    }
    
    # Get the article
    article = db.execute('SELECT * FROM articles WHERE id = ?', (article_id,)).fetchone()
    if not article:
        abort(404)
    
    # Check if department admin has permission to edit this article
    if role != 'admin':
        allowed_category = admin_dept_map.get(role)
        if article['category'] != allowed_category:
            abort(403)
    
    if request.method == 'POST':
        title = request.form['title']
        slug = request.form['slug']
        
        # Get category based on role
        if role == 'admin':
            category = request.form['category']
        else:
            category = admin_dept_map.get(role)
            if not category:
                flash('Invalid department administrator role.', 'error')
                return redirect(url_for('edit_article', article_id=article_id))
        
        content = request.form['content']
        published = 1 if request.form.get('published') else 0
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        try:
            db.execute(
                'UPDATE articles SET title = ?, slug = ?, category = ?, content = ?, published = ?, updated_at = ? WHERE id = ?',
                (title, slug, category, content, published, now, article_id)
            )
            db.commit()
            return redirect(url_for('admin_articles'))
        except sqlite3.IntegrityError:
            flash('Article with this slug already exists.', 'error')
    
    return render_template('article_form.html', article=article, user_role=role)

@app.route('/admin/articles/<int:article_id>/delete', methods=['POST'])
@login_required
@article_admin_required
def delete_article_admin(article_id):
    """Delete a knowledge base article."""
    db = get_db()
    role = session.get('role')
    
    # Map admin roles to their departments
    admin_dept_map = {
        'it_admin': 'IT Support',
        'facilities_admin': 'Facilities & Events',
        'academic_admin': 'Academic Services',
        'administrative_admin': 'Administrative Services'
    }
    
    # Get the article
    article = db.execute('SELECT category FROM articles WHERE id = ?', (article_id,)).fetchone()
    if not article:
        abort(404)
    
    # Check if department admin has permission to delete this article
    if role != 'admin':
        allowed_category = admin_dept_map.get(role)
        if article['category'] != allowed_category:
            abort(403)
    
    db.execute('DELETE FROM articles WHERE id = ?', (article_id,))
    db.commit()
    return redirect(url_for('admin_articles'))

@app.route('/article/<slug>')
@login_required
def article(slug):
    # Try loading from the database
    db = get_db()
    db_article = db.execute('SELECT * FROM articles WHERE slug = ?', (slug,)).fetchone()
    if db_article:
        # Found in DB: convert to dict and annotate icon/badge classes
        art = dict(db_article)
        if art['category'] == 'IT Support':
            icon, icon_bg, icon_color = 'wifi', 'bg-success-subtle', 'text-success'
        elif art['category'] == 'Academic Services':
            icon, icon_bg, icon_color = 'mortarboard-fill', 'bg-primary-subtle', 'text-primary'
        elif art['category'] == 'Facilities & Events':
            icon, icon_bg, icon_color = 'calendar-date', 'bg-info-subtle', 'text-info'
        elif art['category'] == 'Administrative Services':
            icon, icon_bg, icon_color = 'person-badge', 'bg-warning-subtle', 'text-warning'
        else:
            icon, icon_bg, icon_color = 'file-earmark-text', 'bg-secondary-subtle', 'text-secondary'
        art['icon'] = icon
        art['icon_bg'] = icon_bg
        art['icon_color'] = icon_color
    else:
        # Fallback to static in-memory articles
        static_articles = [
            {'id':'wifi','title':'Campus WiFi Setup Guide','description':'Step-by-step guide for connecting to the campus wireless network','category':'IT Support','icon':'wifi','icon_bg':'bg-success-subtle','icon_color':'text-success','slug':'wifi-setup'},
            {'id':'password','title':'Account Password Reset Guide','description':'Instructions for resetting your account password','category':'IT Support','icon':'key-fill','icon_bg':'bg-success-subtle','icon_color':'text-success','slug':'password-reset'},
            {'id':'software','title':'Accessing Campus Software','description':'How to access and install licensed software for students and staff','category':'IT Support','icon':'box-fill','icon_bg':'bg-success-subtle','icon_color':'text-success','slug':'software-access'},
            {'id':'transcript','title':'How to Request Official Transcripts','description':'Learn how to request and receive your official academic transcripts','category':'Academic Services','icon':'mortarboard-fill','icon_bg':'bg-primary-subtle','icon_color':'text-primary','slug':'transcript-request'},
            {'id':'enrollment','title':'Enrollment Verification Guide','description':'How to verify your enrollment status for insurance or employment purposes','category':'Academic Services','icon':'check-circle-fill','icon_bg':'bg-primary-subtle','icon_color':'text-primary','slug':'enrollment-verification'},
            {'id':'rooms','title':'How to Book Campus Rooms','description':'Guide to reserving classrooms, meeting spaces, and event venues','category':'Facilities & Events','icon':'calendar-date','icon_bg':'bg-info-subtle','icon_color':'text-info','slug':'room-booking'},
            {'id':'maintenance','title':'Submitting Maintenance Requests','description':'How to report facility issues and track maintenance requests','category':'Facilities & Events','icon':'tools','icon_bg':'bg-info-subtle','icon_color':'text-info','slug':'maintenance-request'},
            {'id':'idcard','title':'Student ID Card Services','description':'Information about obtaining, replacing, and using your student ID card','category':'Administrative Services','icon':'person-badge','icon_bg':'bg-warning-subtle','icon_color':'text-warning','slug':'id-card'},
            {'id':'parking','title':'Parking Permit Information','description':'Learn how to request and manage campus parking permits','category':'Administrative Services','icon':'p-circle','icon_bg':'bg-warning-subtle','icon_color':'text-warning','slug':'parking-permit'}
        ]
        fallback = next((a for a in static_articles if a['slug'] == slug), None)
        if not fallback:
            abort(404)
        # Use static fallback article
        art = fallback.copy()
        # Generate extended generic placeholder content for fallback articles
        art['content'] = f'''
<h2>Overview</h2>
<p>{art.get('description', '')}</p>

<h2>Getting Started</h2>
<p>This section provides an introduction to {art.get('title')}, covering prerequisites and basic setup required to get started successfully.</p>

<h2>Use Cases</h2>
<p>Explore typical scenarios where {art.get('title')} is commonly applied:</p>
<ul>
  <li>Scenario 1: Explanation of a common usage scenario.</li>
  <li>Scenario 2: Description of another typical scenario.</li>
  <li>Scenario 3: Further examples of usage.</li>
                    </ul>

<h2>Best Practices</h2>
<p>Follow these best practices for optimal results:</p>
<ol>
  <li>Practice 1: Detailed guideline.</li>
  <li>Practice 2: Detailed guideline.</li>
  <li>Practice 3: Detailed guideline.</li>
                    </ol>

<h2>Examples</h2>
<p>Here's an illustrative example demonstrating typical usage of {art.get('title')}:</p>
<pre><code># Pseudocode or sample snippet demonstrating the feature
# Placeholder content for example.
</code></pre>

<h2>Tips &amp; Tricks</h2>
<p>Enhance your workflow with these tips:</p>
<ul>
  <li>Tip A: Pro tip description.</li>
  <li>Tip B: Pro tip description.</li>
  <li>Tip C: Pro tip description.</li>
                </ul>

<h2>Troubleshooting</h2>
<p>If you encounter any issues, consider the following troubleshooting steps:</p>
<ul>
  <li>Review system logs for error details.</li>
  <li>Verify all configuration settings.</li>
  <li>Consult documentation or support channels if needed.</li>
            </ul>

<h2>FAQs</h2>
<dl>
  <dt>Question 1?</dt><dd>Answer to question 1 with detailed guidance.</dd>
  <dt>Question 2?</dt><dd>Answer to question 2 clarifying common concerns.</dd>
  <dt>Question 3?</dt><dd>Answer to question 3 with reference links.</dd>
</dl>

<h2>Additional Resources</h2>
<p>For further reading, visit the <a href="https://support.example.com">support portal</a> or contact our support team directly.</p>

<p>Sed nec diam eu diam mattis viverra. Nulla fringilla, orci ac euismod semper, magna diam porttitor mauris, quis sollicitudin sapien justo in libero.</p>
<p>Lorem ipsum dolor sit amet, consectetur adipiscing elit. Vestibulum vehicula ex eu sapien fermentum, at facilisis urna cursus.</p>
<p>Praesent consequat nunc ut metus tincidunt, vitae tristique lacus gravida. Integer ac commodo erat.</p>
<p>Morbi dictum magna vel eros scelerisque, in pulvinar felis vestibulum. Donec at mi non elit elementum luctus.</p>
<p>Nulla facilisi. Proin ultricies risus at est feugiat, eget lobortis tortor vulputate.</p>
<p>Curabitur euismod, tortor vitae placerat gravida, risus tellus ultricies nunc, sed molestie dolor mauris eu est.</p>
'''
    
    return render_template('article.html', article=art)

@app.route('/article/<int:article_id>', methods=['DELETE', 'POST'])
@login_required
@article_admin_required
def delete_article(article_id):
    # Article delete route removed
    return redirect(url_for('home'))

@app.route('/article/form', methods=['GET', 'POST'])
@app.route('/article/form/<int:article_id>', methods=['GET', 'POST'])
@login_required
@article_admin_required
def article_form(article_id=None):
    # Article form route removed
    return redirect(url_for('home'))

@app.route('/upload_image', methods=['POST'])
@login_required
@article_admin_required
def upload_image():
    """Handle image uploads from CKEditor and return the file URL."""
    file = request.files.get('upload')
    if not file:
        return jsonify({'error': 'No file uploaded'}), 400
    filename = secure_filename(file.filename)
    upload_path = app.config['UPLOAD_PATH']
    os.makedirs(upload_path, exist_ok=True)
    filepath = os.path.join(upload_path, filename)
    file.save(filepath)
    url = url_for('static', filename='uploads/' + filename)
    return jsonify({'url': url})

# --- User Management Routes ---
@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    """List all users for admin management."""
    db = get_db()
    users = db.execute('SELECT id, username, email, is_admin, role, agent_category FROM users ORDER BY username').fetchall()
    return render_template('admin_users.html', users=users)

@app.route('/admin/users/new', methods=['GET', 'POST'])
@login_required
@admin_required
def new_user():
    """Create a new user account."""
    db = get_db()
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        role = request.form.get('role', 'agent')
        is_admin = 1 if role == 'admin' else 0
        agent_category = request.form.get('agent_category') if role in ('agent', 'super_agent') else None
        try:
            db.execute(
                'INSERT INTO users (username, email, password, is_admin, role, agent_category) VALUES (?, ?, ?, ?, ?, ?)',
                (username, email, password, is_admin, role, agent_category)
            )
            db.commit()
            return redirect(url_for('admin_users'))
        except sqlite3.IntegrityError:
            flash('Username or email already exists', 'error')
    return render_template('user_form.html', user=None)

@app.route('/admin/users/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_user(user_id):
    """Edit an existing user account."""
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    if not user:
        abort(404)
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        role = request.form.get('role', 'agent')
        is_admin = 1 if role == 'admin' else 0
        agent_category = request.form.get('agent_category') if role in ('agent', 'super_agent') else None
        password_raw = request.form.get('password')
        password = generate_password_hash(password_raw) if password_raw else user['password']
        try:
            db.execute(
                'UPDATE users SET username = ?, email = ?, password = ?, is_admin = ?, role = ?, agent_category = ? WHERE id = ?',
                (username, email, password, is_admin, role, agent_category, user_id)
            )
            db.commit()
            return redirect(url_for('admin_users'))
        except sqlite3.IntegrityError:
            flash('Username or email already exists', 'error')
    return render_template('user_form.html', user=user)

@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    """Delete a user account."""
    db = get_db()
    db.execute('DELETE FROM users WHERE id = ?', (user_id,))
    db.commit()
    return redirect(url_for('admin_users'))

@app.route('/tickets/<int:ticket_id>/assign', methods=['POST'])
@login_required
@admin_required
def assign_ticket(ticket_id):
    """Assign a ticket to an agent."""
    agent_id = request.form.get('assigned_agent_id')
    db = get_db()
    
    # Get ticket details
    ticket = db.execute('SELECT t.*, u.email as user_email, u.username as user_username FROM tickets t JOIN users u ON t.user_id = u.id WHERE t.id = ?', [ticket_id]).fetchone()
    
    # Get agent details including their email
    agent = db.execute('SELECT * FROM users WHERE id = ?', [agent_id]).fetchone()
    
    if agent:
        try:
            # Update the ticket assignment and set status to in_progress
            db.execute('UPDATE tickets SET assigned_agent_id = ?, status = ? WHERE id = ?', [agent_id, 'in_progress', ticket_id])
            db.commit()
            
            # Send email notification to the agent only
            try:
                agent_email = {
                    "from": "STAC IT Support <support@stacticket.com>",
                    "reply_to": "support@stacticket.com",
                    "to": agent['email'],
                    "subject": f"St. Thomas Aquinas College - IT Support Ticket #{ticket['id']} Assignment",
                    "headers": {
                        "List-Unsubscribe": "<mailto:support@stacticket.com?subject=unsubscribe>",
                        "Precedence": "bulk",
                        "X-Entity-Ref-ID": f"stac-ticket-{ticket['id']}",
                        "X-Priority": "3",
                        "X-MSMail-Priority": "Normal"
                    },
                    "html": f"""
                        <!DOCTYPE html>
                        <html>
                        <head>
                            <meta charset="UTF-8">
                            <meta name="viewport" content="width=device-width, initial-scale=1.0">
                        </head>
                        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                            <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                                <div style="text-align: center; margin-bottom: 20px;">
                                    <h1 style="color: #003366; margin: 0;">St. Thomas Aquinas College</h1>
                                    <p style="color: #666; margin: 5px 0;">IT Support Ticket System</p>
                                </div>
                                
                                <div style="background-color: #f8f9fa; padding: 20px; border-radius: 5px; margin-bottom: 20px;">
                                    <h2 style="color: #003366; margin-top: 0;">IT Support Ticket Assignment</h2>
                                    <p>Dear {agent['username']},</p>
                                    <p>A new IT support ticket has been assigned to you in the STAC Support System.</p>
                                    
                                    <div style="background-color: white; padding: 15px; border-radius: 5px; margin: 20px 0;">
                                        <h3 style="color: #003366; margin-top: 0;">Ticket Information</h3>
                                        <p style="margin: 5px 0;"><strong>Ticket Reference:</strong> STAC-{ticket['id']}</p>
                                        <p style="margin: 5px 0;"><strong>Subject:</strong> {ticket['title']}</p>
                                        <p style="margin: 5px 0;"><strong>Details:</strong> {ticket['description']}</p>
                                        <p style="margin: 15px 0 5px;"><strong>Status:</strong> In Progress</p>
                                    </div>
                                </div>
                            </div>
                        </body>
                        </html>
                    """
                }
                
                resend.Emails.send(agent_email)
                flash('Ticket assigned successfully and agent notification sent.')
            except Exception as e:
                print(f"Error sending email: {e}")
                flash('Ticket assigned but there was an error sending the email notification.')
            
            return redirect(url_for('ticket_detail', ticket_id=ticket_id))
            
        except Exception as e:
            print(f"Error assigning ticket: {e}")
            db.rollback()
            flash('Error assigning ticket. Please try again.')
            return redirect(url_for('ticket_detail', ticket_id=ticket_id))
    
    flash('Error: Agent not found.')
    return redirect(url_for('ticket_detail', ticket_id=ticket_id))

@app.route('/admin/services')
@login_required
@admin_required
def admin_services():
    """List all services for admin management."""
    db = get_db()
    services = db.execute(
        'SELECT id, slug, title, description, icon, color FROM services ORDER BY id'
    ).fetchall()
    return render_template('admin_services.html', services=services)

@app.route('/admin/services/new', methods=['GET', 'POST'])
@login_required
@admin_required
def new_service():
    """Create a new service entry."""
    db = get_db()
    if request.method == 'POST':
        slug = request.form['slug']
        title = request.form['title']
        description = request.form.get('description')
        icon = request.form.get('icon')
        color = request.form.get('color')
        try:
            db.execute(
                'INSERT INTO services (slug, title, description, icon, color) VALUES (?, ?, ?, ?, ?)',
                (slug, title, description, icon, color)
            )
            db.commit()
            return redirect(url_for('admin_services'))
        except sqlite3.IntegrityError:
            flash('Slug must be unique', 'error')
    return render_template('service_form.html', service=None)

@app.route('/admin/services/<int:service_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_service(service_id):
    """Edit an existing service entry."""
    db = get_db()
    service = db.execute('SELECT * FROM services WHERE id = ?', (service_id,)).fetchone()
    if not service:
            abort(404)
    if request.method == 'POST':
        slug = request.form['slug']
        title = request.form['title']
        description = request.form.get('description')
        icon = request.form.get('icon')
        color = request.form.get('color')
        try:
            db.execute(
                'UPDATE services SET slug = ?, title = ?, description = ?, icon = ?, color = ? WHERE id = ?',
                (slug, title, description, icon, color, service_id)
            )
            db.commit()
            return redirect(url_for('admin_services'))
        except sqlite3.IntegrityError:
            flash('Slug must be unique', 'error')
    return render_template('service_form.html', service=service)

@app.route('/admin/services/<int:service_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_service(service_id):
    """Delete a service from the catalog."""
    db = get_db()
    db.execute('DELETE FROM services WHERE id = ?', (service_id,))
    db.commit()
    return redirect(url_for('admin_services'))

@app.route('/firebase-callback')
def firebase_callback():
    if RUNNING_ON_VERCEL:
        return redirect(url_for('login', error='Firebase auth not available'))
        
    try:
        # Get the ID token from the query string
        id_token = request.args.get('token')
        if not id_token:
            return redirect(url_for('login', error='No token provided'))

        # Verify the ID token
        decoded_token = auth.verify_id_token(id_token)
        user_id = decoded_token['uid']
        email = decoded_token.get('email', '')
        name = decoded_token.get('name', '')

        # List of admin emails
        admin_emails = [
            'bitayonas@gmail.com',
            'nabbiw21@stac.edu',
            'rbeyene22@stac.edu'
        ]

        # Check if user exists in our database
        db = get_db()
        user = db.execute(
            'SELECT * FROM users WHERE email = ?',
            (email,)
        ).fetchone()

        if not user:
            # Create new user in our database
            # Make the specific emails admin
            is_admin = email in admin_emails
            role = 'admin' if is_admin else 'user'
            
            # Generate a unique username
            base_username = name.lower().replace(' ', '_')
            username = base_username
            counter = 1
            
            while True:
                existing = db.execute(
                    'SELECT 1 FROM users WHERE username = ?',
                    (username,)
                ).fetchone()
                if not existing:
                    break
                username = f"{base_username}_{counter}"
                counter += 1
            
            try:
                db.execute(
                    'INSERT INTO users (username, email, password, is_admin, role) VALUES (?, ?, ?, ?, ?)',
                    (username, email, 'firebase-auth', is_admin, role)
                )
                db.commit()
                user = db.execute(
                    'SELECT * FROM users WHERE email = ?',
                    (email,)
                ).fetchone()
            except sqlite3.IntegrityError as e:
                print(f"Database error during user creation: {e}")
                return redirect(url_for('login', error='Error creating user account'))
                
        elif email in admin_emails and (not user['is_admin'] or user['role'] != 'admin'):
            # Update existing user to be admin if they weren't already
            db.execute(
                'UPDATE users SET is_admin = 1, role = "admin" WHERE email = ?',
                (email,)
            )
            db.commit()
            user = db.execute(
                'SELECT * FROM users WHERE email = ?',
                (email,)
            ).fetchone()

        # Set session variables
        session['user_id'] = user['id']
        session['is_admin'] = user['role'] == 'admin'
        session['username'] = user['username']
        session['role'] = user['role']
        
        return redirect(url_for('home'))
    except Exception as e:
        print(f"Firebase authentication error: {str(e)}")
        return redirect(url_for('login', error='Authentication failed'))

# --- App startup ---
if __name__ == '__main__':
    with app.app_context():
        # Ensure upload directory exists
        os.makedirs(app.config['UPLOAD_PATH'], exist_ok=True)
        init_db()
        db = get_db()
        # Seed admin
        admin = db.execute(
            'SELECT * FROM users WHERE username = ?', ('admin',)
        ).fetchone()
        if not admin:
            db.execute(
                'INSERT INTO users (username, email, password, is_admin, role) VALUES (?, ?, ?, ?, ?)',
                ('admin', 'nanabanyinabbiw12@gmail.com',
                 generate_password_hash('password123'), 1, 'admin')
            )
        # Seed regular user
        user = db.execute(
            'SELECT * FROM users WHERE username = ?', ('regular_user',)
        ).fetchone()
        if not user:
            db.execute(
                'INSERT INTO users (username, email, password, is_admin, role) VALUES (?, ?, ?, ?, ?)',
                ('regular_user', 'user@example.com',
                 generate_password_hash('password1234'), 0, 'user')
            )
        # Seed default KB articles if missing
        default_articles = [
            {'title':'Campus WiFi Setup Guide','description':'Step-by-step guide for connecting to the campus wireless network','category':'IT Support','slug':'wifi-setup'},
            {'title':'Account Password Reset Guide','description':'Instructions for resetting your account password','category':'IT Support','slug':'password-reset'},
            {'title':'Accessing Campus Software','description':'How to access and install licensed software for students and staff','category':'IT Support','slug':'software-access'},
            {'title':'How to Request Official Transcripts','description':'Learn how to request and receive your official academic transcripts','category':'Academic Services','slug':'transcript-request'},
            {'title':'Enrollment Verification Guide','description':'How to verify your enrollment status for insurance or employment purposes','category':'Academic Services','slug':'enrollment-verification'},
            {'title':'How to Book Campus Rooms','description':'Guide to reserving classrooms, meeting spaces, and event venues','category':'Facilities & Events','slug':'room-booking'},
            {'title':'Submitting Maintenance Requests','description':'How to report facility issues and track maintenance requests','category':'Facilities & Events','slug':'maintenance-request'},
            {'title':'Student ID Card Services','description':'Information about obtaining, replacing, and using your student ID card','category':'Administrative Services','slug':'id-card'},
            {'title':'Parking Permit Information','description':'Learn how to request and manage campus parking permits','category':'Administrative Services','slug':'parking-permit'}
        ]
        for a in default_articles:
            exists = db.execute('SELECT 1 FROM articles WHERE slug = ?', (a['slug'],)).fetchone()
            if not exists:
                now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                content = f"<p>{a['description']}</p>"
                db.execute(
                    'INSERT OR IGNORE INTO articles (title, slug, category, content, published, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
                    (a['title'], a['slug'], a['category'], content, 1, now, now)
                )
        # Seed default services if missing
        # Define default service entries
        default_services = [
            {'slug':'academic','title':'Academic & Records','description':'Request transcripts, enrollment verification, and grade appeals','icon':'mortarboard-fill','color':'primary'},
            {'slug':'it_support','title':'IT Support','description':'Get help with WiFi, software, and account access','icon':'pc-display','color':'success'},
            {'slug':'facilities','title':'Facilities & Events','description':'Book rooms, report maintenance issues, or request event support','icon':'building','color':'info'},
            {'slug':'admin_services','title':'Administrative Services','description':'ID cards, parking permits, and document requests','icon':'folder','color':'warning'}
        ]
        for s in default_services:
            exists_s = db.execute('SELECT 1 FROM services WHERE slug = ?', (s['slug'],)).fetchone()
            if not exists_s:
                db.execute(
                    'INSERT OR IGNORE INTO services (slug, title, description, icon, color) VALUES (?, ?, ?, ?, ?)',
                    (s['slug'], s['title'], s['description'], s['icon'], s['color'])
                )
        db.commit()
    app.run(debug=True, port=5050)