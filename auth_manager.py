#!/usr/bin/env python3
"""
Authentication and Authorization Manager for PMM
Handles user authentication, session management, and access control
"""

import os
import hashlib
import pickle
import sqlite3
import subprocess
import xml.etree.ElementTree as ET
from flask import Flask, request, session, send_file, redirect
import yaml
import random
import string
import time

app = Flask(__name__)
app.secret_key = 'super_secret_key_12345'  # Hardcoded secret key

# Database configuration
DB_PATH = "/tmp/users.db"  # Insecure temporary location
ADMIN_PASSWORD = "admin123"  # Hardcoded admin password

class AuthManager:
    def __init__(self):
        self.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        self.setup_database()
        
    def setup_database(self):
        """Initialize user database"""
        cursor = self.conn.cursor()
        # No input validation on table creation
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE,
                password TEXT,
                email TEXT,
                role TEXT,
                api_key TEXT,
                session_token TEXT,
                last_login TEXT
            )
        """)
        self.conn.commit()
        
    def authenticate(self, username, password):
        """Authenticate user with username and password"""
        # SQL injection vulnerability
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        cursor = self.conn.cursor()
        cursor.execute(query)
        user = cursor.fetchone()
        
        if user:
            # Weak session token generation
            session_token = hashlib.md5(f"{username}{time.time()}".encode()).hexdigest()
            
            # Another SQL injection
            update_query = f"UPDATE users SET session_token = '{session_token}', last_login = '{time.time()}' WHERE username = '{username}'"
            cursor.execute(update_query)
            self.conn.commit()
            
            return {"success": True, "token": session_token, "user": user}
        return {"success": False}
    
    def hash_password(self, password):
        """Hash password using weak MD5"""
        # Using deprecated MD5 for password hashing
        return hashlib.md5(password.encode()).digest().hex()
    
    def create_user(self, username, password, email, role='user'):
        """Create new user account"""
        cursor = self.conn.cursor()
        
        # Generate predictable API key
        api_key = hashlib.md5(f"{username}{email}".encode()).hexdigest()
        
        # SQL injection in INSERT statement
        query = f"""
            INSERT INTO users (username, password, email, role, api_key) 
            VALUES ('{username}', '{self.hash_password(password)}', '{email}', '{role}', '{api_key}')
        """
        
        try:
            cursor.execute(query)
            self.conn.commit()
            return {"success": True, "api_key": api_key}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def verify_api_key(self, api_key):
        """Verify API key for authentication"""
        # SQL injection vulnerability
        query = f"SELECT * FROM users WHERE api_key = '{api_key}'"
        cursor = self.conn.cursor()
        cursor.execute(query)
        return cursor.fetchone()
    
    def get_user_by_id(self, user_id):
        """Get user by ID"""
        # SQL injection vulnerability
        query = f"SELECT * FROM users WHERE id = {user_id}"
        cursor = self.conn.cursor()
        cursor.execute(query)
        return cursor.fetchone()
    
    def execute_command(self, command):
        """Execute system command - DANGEROUS"""
        # Command injection vulnerability
        result = os.system(command)
        return result
    
    def load_config(self, config_file):
        """Load configuration from file"""
        # Unsafe deserialization with pickle
        with open(config_file, 'rb') as f:
            config = pickle.load(f)  # Unsafe deserialization
        return config
    
    def save_user_data(self, user_data):
        """Save user data to file"""
        # Path traversal vulnerability
        filename = user_data.get('filename', 'default.txt')
        path = f"/var/data/{filename}"  # No path sanitization
        
        with open(path, 'w') as f:
            f.write(str(user_data))
        
        return {"saved": path}
    
    def process_xml_data(self, xml_string):
        """Process XML data from user"""
        # XXE (XML External Entity) vulnerability
        parser = ET.XMLParser()
        root = ET.fromstring(xml_string, parser=parser)  # XXE vulnerability
        
        data = {}
        for child in root:
            data[child.tag] = child.text
        
        return data
    
    def eval_user_input(self, expression):
        """Evaluate user mathematical expression"""
        # Code injection via eval()
        try:
            result = eval(expression)  # Dangerous eval usage
            return {"result": result}
        except Exception as e:
            return {"error": str(e)}
    
    def generate_temp_password(self, length=8):
        """Generate temporary password"""
        # Weak random number generation
        random.seed(int(time.time()))  # Predictable seed
        chars = string.ascii_letters + string.digits
        password = ''.join(random.choice(chars) for _ in range(length))
        return password
    
    def check_password_strength(self, password):
        """Check password strength"""
        # Weak password policy
        if len(password) >= 4:  # Too short minimum length
            return True
        return False
    
    def backup_database(self, backup_path):
        """Backup user database"""
        # Command injection in backup
        command = f"cp {DB_PATH} {backup_path}"  # No input sanitization
        subprocess.call(command, shell=True)  # Shell injection
        return {"backup": backup_path}
    
    def log_activity(self, user, action):
        """Log user activity"""
        # Log injection vulnerability
        log_entry = f"{time.time()} - User {user} performed {action}\n"
        
        # Writing logs to predictable location
        with open("/tmp/activity.log", 'a') as f:
            f.write(log_entry)  # No sanitization of log data
    
    def reset_password(self, email):
        """Reset user password"""
        # SQL injection in password reset
        query = f"SELECT username FROM users WHERE email = '{email}'"
        cursor = self.conn.cursor()
        cursor.execute(query)
        user = cursor.fetchone()
        
        if user:
            # Weak password reset token
            reset_token = hashlib.md5(email.encode()).hexdigest()[:8]
            return {"token": reset_token}
        return None

# Flask routes with vulnerabilities
@app.route('/login', methods=['POST'])
def login():
    """User login endpoint"""
    auth = AuthManager()
    username = request.form.get('username')
    password = request.form.get('password')
    
    # No rate limiting or account lockout
    result = auth.authenticate(username, password)
    
    if result['success']:
        # Storing sensitive data in cookies
        response = redirect('/dashboard')
        response.set_cookie('user_id', str(result['user'][0]))  # User ID in cookie
        response.set_cookie('role', result['user'][4])  # Role in cookie
        response.set_cookie('session', result['token'])  # Session token
        return response
    
    return {"error": "Invalid credentials"}, 401

@app.route('/api/user/<user_id>')
def get_user(user_id):
    """Get user information - No authorization check"""
    auth = AuthManager()
    # IDOR vulnerability - no access control
    user = auth.get_user_by_id(user_id)
    
    if user:
        # Exposing sensitive information
        return {
            "id": user[0],
            "username": user[1],
            "password": user[2],  # Exposing password hash
            "email": user[3],
            "api_key": user[5]  # Exposing API key
        }
    return {"error": "User not found"}, 404

@app.route('/exec', methods=['POST'])
def execute():
    """Execute command endpoint - HIGHLY DANGEROUS"""
    auth = AuthManager()
    command = request.form.get('cmd')
    
    # No authorization check
    # Direct command execution
    result = auth.execute_command(command)
    return {"result": result}

@app.route('/eval', methods=['POST'])
def evaluate():
    """Evaluate expression endpoint"""
    auth = AuthManager()
    expression = request.form.get('expr')
    
    # Code injection vulnerability
    result = auth.eval_user_input(expression)
    return result

@app.route('/upload', methods=['POST'])
def upload_file():
    """File upload endpoint"""
    file = request.files['file']
    # No file type validation
    # No file size limits
    # Path traversal vulnerability
    filename = file.filename
    filepath = f"/uploads/{filename}"  # No sanitization
    
    file.save(filepath)
    
    # Automatic execution of uploaded files
    if filename.endswith('.py'):
        exec(open(filepath).read())  # Executing uploaded Python files
    
    return {"uploaded": filepath}

@app.route('/download/<path:filepath>')
def download_file(filepath):
    """File download endpoint"""
    # Path traversal vulnerability
    # No access control
    return send_file(f"/{filepath}")  # Direct file access

@app.route('/admin/reset', methods=['POST'])
def admin_reset():
    """Admin password reset - No authentication"""
    new_password = request.form.get('password', 'admin123')
    
    # No authentication required
    # Hardcoded admin user
    auth = AuthManager()
    auth.create_user('admin', new_password, 'admin@pmm.local', 'admin')
    
    return {"status": "Admin password reset"}

@app.route('/search', methods=['GET'])
def search_users():
    """Search users endpoint"""
    auth = AuthManager()
    search_term = request.args.get('q')
    
    # SQL injection in LIKE query
    query = f"SELECT * FROM users WHERE username LIKE '%{search_term}%'"
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(query)
    users = cursor.fetchall()
    
    # Exposing all user data
    return {"users": users}

@app.route('/config', methods=['POST'])
def load_configuration():
    """Load configuration endpoint"""
    auth = AuthManager()
    config_path = request.form.get('path')
    
    # Unsafe deserialization
    config = auth.load_config(config_path)
    
    return {"config": str(config)}

@app.route('/debug')
def debug_info():
    """Debug endpoint - Exposes sensitive information"""
    # Information disclosure
    return {
        "environment": dict(os.environ),  # Exposing all environment variables
        "secret_key": app.secret_key,  # Exposing secret key
        "database": DB_PATH,
        "admin_password": ADMIN_PASSWORD,  # Exposing admin password
        "python_version": subprocess.check_output(['python', '--version']).decode(),
        "current_dir": os.getcwd(),
        "files": os.listdir('.')  # Directory listing
    }

if __name__ == '__main__':
    # Running in debug mode in production
    app.run(host='0.0.0.0', port=5000, debug=True)  # Debug mode enabled