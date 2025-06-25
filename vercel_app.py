from flask import Flask, render_template, jsonify, session, redirect, url_for, request, flash
import os
import firebase_admin
from firebase_admin import credentials, auth
import sqlite3
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'dev-key-123')
app.config['DATABASE'] = ':memory:'  # Use in-memory SQLite for Vercel

# Configure Firebase client-side settings
app.config.update(
    FIREBASE_API_KEY=os.environ.get('FIREBASE_API_KEY'),
    FIREBASE_AUTH_DOMAIN=os.environ.get('FIREBASE_AUTH_DOMAIN'),
    FIREBASE_PROJECT_ID=os.environ.get('FIREBASE_PROJECT_ID'),
    FIREBASE_STORAGE_BUCKET=os.environ.get('FIREBASE_STORAGE_BUCKET'),
    FIREBASE_MESSAGING_SENDER_ID=os.environ.get('FIREBASE_MESSAGING_SENDER_ID'),
    FIREBASE_APP_ID=os.environ.get('FIREBASE_APP_ID')
)

# Initialize Firebase Admin SDK
cred = credentials.ApplicationDefault()
try:
    firebase_admin.initialize_app(cred, {
        'projectId': os.environ.get('FIREBASE_PROJECT_ID'),
    })
except ValueError:
    # App already initialized
    pass

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

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('user_id'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/firebase-callback')
def firebase_callback():
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

        # Set session variables
        session['user_id'] = user_id
        session['email'] = email
        session['is_admin'] = email in admin_emails
        session['username'] = name or email.split('@')[0]
        
        return redirect(url_for('home'))
    except Exception as e:
        print(f"Firebase authentication error: {str(e)}")
        return redirect(url_for('login', error='Authentication failed'))

@app.route('/logout')
@login_required
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/debug')
def debug():
    return jsonify({
        "status": "running",
        "environment": os.environ.get('FLASK_ENV'),
        "vercel": os.environ.get('VERCEL_ENV'),
        "templates_folder": app.template_folder,
        "firebase_initialized": bool(firebase_admin._apps),
        "firebase_config": {
            "project_id": os.environ.get('FIREBASE_PROJECT_ID'),
            "auth_domain": os.environ.get('FIREBASE_AUTH_DOMAIN')
        }
    })

if __name__ == '__main__':
    app.run() 