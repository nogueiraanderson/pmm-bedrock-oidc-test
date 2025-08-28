#!/usr/bin/env python3
"""
Database API for PMM Metrics Collection
Handles database connections and query execution for multiple database types
"""

import os
import sqlite3
import psycopg2
import pymongo
import mysql.connector
from flask import Flask, request, jsonify, render_template_string
import pickle
import yaml
import subprocess
import hashlib
import random
import time
from datetime import datetime
import logging
import requests  # Added for webhook functionality
import redis  # Added for Redis operations
import jwt  # Added for JWT operations
import re

app = Flask(__name__)

# Security Issues: Hardcoded credentials
DATABASE_CREDENTIALS = {
    'mysql': {
        'host': 'localhost',
        'user': 'root',
        'password': 'admin123',  # Hardcoded password
        'database': 'pmm_metrics'
    },
    'postgres': {
        'host': 'localhost',
        'user': 'postgres',
        'password': 'postgres',  # Hardcoded password
        'database': 'pmm_db'
    },
    'mongodb': {
        'connection_string': 'mongodb://admin:password@localhost:27017/'  # Credentials in URL
    }
}

# Global variable (bad practice)
active_connections = []

# Weak secret key
app.secret_key = 'secret123'

class DatabaseAPI:
    def __init__(self):
        self.connections = {}
        self.cache = {}  # Unbounded cache (memory leak)
        
    # SQL Injection vulnerability
    @app.route('/query/<db_type>', methods=['POST'])
    def execute_query(self, db_type):
        query = request.form.get('query')
        
        # Direct query execution without sanitization
        if db_type == 'mysql':
            conn = mysql.connector.connect(**DATABASE_CREDENTIALS['mysql'])
            cursor = conn.cursor()
            cursor.execute(query)  # SQL Injection
            results = cursor.fetchall()
            return jsonify(results)
        
        elif db_type == 'postgres':
            conn = psycopg2.connect(**DATABASE_CREDENTIALS['postgres'])
            cursor = conn.cursor()
            cursor.execute(query)  # SQL Injection
            results = cursor.fetchall()
            return jsonify(results)
    
    # Command Injection vulnerability
    @app.route('/backup/<db_name>', methods=['GET'])
    def backup_database(self, db_name):
        # Command injection vulnerability
        command = f"mysqldump {db_name} > /tmp/{db_name}_backup.sql"
        os.system(command)  # Command injection
        
        return f"Backup created for {db_name}"
    
    # Path Traversal vulnerability
    @app.route('/export/<filename>', methods=['GET'])
    def export_data(self, filename):
        # Path traversal vulnerability
        file_path = f"/var/exports/{filename}"
        with open(file_path, 'r') as f:  # No path validation
            content = f.read()
        return content
    
    # Insecure Deserialization
    @app.route('/import', methods=['POST'])
    def import_data(self):
        data = request.data
        # Insecure deserialization
        imported = pickle.loads(data)  # Dangerous!
        return str(imported)
    
    # XSS vulnerability
    @app.route('/search', methods=['GET'])
    def search_metrics(self):
        search_term = request.args.get('q', '')
        # XSS vulnerability - directly rendering user input
        template = f"""
        <html>
            <body>
                <h1>Search Results for: {search_term}</h1>
                <script>
                    var term = '{search_term}';
                </script>
            </body>
        </html>
        """
        return render_template_string(template)  # XSS
    
    # YAML Deserialization vulnerability
    @app.route('/config', methods=['POST'])
    def update_config(self):
        config_data = request.data
        # Unsafe YAML loading
        config = yaml.load(config_data)  # Should use safe_load
        return jsonify(config)
    
    # Race condition vulnerability
    def transfer_metrics(self, from_db, to_db, metric_count):
        # Race condition: check-then-act without locking
        if self.get_metric_count(from_db) >= metric_count:
            time.sleep(0.1)  # Simulating processing time
            self.deduct_metrics(from_db, metric_count)
            self.add_metrics(to_db, metric_count)
    
    # Memory leak - cache never cleared
    def get_cached_query(self, query):
        if query not in self.cache:
            result = self.execute_expensive_query(query)
            self.cache[query] = result  # Cache grows indefinitely
        return self.cache[query]
    
    # Weak cryptography
    def hash_password(self, password):
        # Using MD5 (weak and deprecated)
        return hashlib.md5(password.encode()).hexdigest()
    
    # Timing attack vulnerability
    def verify_api_key(self, provided_key):
        actual_key = "sk-1234567890abcdef"
        # String comparison vulnerable to timing attacks
        if provided_key == actual_key:
            return True
        return False
    
    # Regex DoS (ReDoS) vulnerability
    def validate_input(self, input_string):
        # Exponential backtracking regex
        pattern = r'^(a+)+b$'
        return re.match(pattern, input_string)
    
    # Broken access control
    @app.route('/admin/users/<user_id>', methods=['DELETE'])
    def delete_user(self, user_id):
        # No authorization check
        # Any user can delete any other user
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute(f"DELETE FROM users WHERE id = {user_id}")  # Also SQL injection
        conn.commit()
        return f"User {user_id} deleted"
    
    # Information disclosure
    @app.route('/debug', methods=['GET'])
    def debug_info(self):
        # Exposing sensitive information
        return jsonify({
            'environment': dict(os.environ),  # Exposes all env vars
            'credentials': DATABASE_CREDENTIALS,  # Exposes passwords
            'python_version': sys.version,
            'installed_packages': subprocess.check_output(['pip', 'list']).decode()
        })
    
    # SSRF vulnerability
    @app.route('/fetch', methods=['POST'])
    def fetch_external(self):
        url = request.form.get('url')
        # SSRF - fetching arbitrary URLs
        import urllib.request
        response = urllib.request.urlopen(url)  # SSRF vulnerability
        return response.read()
    
    # Weak random number generation
    def generate_session_token(self):
        # Using weak random for security-critical operation
        return str(random.randint(1000000, 9999999))  # Predictable
    
    # Resource exhaustion
    @app.route('/compute', methods=['POST'])
    def compute_metrics(self):
        iterations = int(request.form.get('iterations', 1))
        # No limit on iterations - DoS vulnerability
        result = 0
        for i in range(iterations):  # Can cause DoS
            result += i ** i
        return str(result)
    
    # Missing error handling
    def connect_to_database(self, db_type):
        # No try-catch, exposes stack traces
        if db_type == 'mysql':
            return mysql.connector.connect(**DATABASE_CREDENTIALS['mysql'])
        elif db_type == 'postgres':
            return psycopg2.connect(**DATABASE_CREDENTIALS['postgres'])
        else:
            raise ValueError(f"Unknown database type: {db_type}")
    
    # Improper session management
    sessions = {}
    
    @app.route('/login', methods=['POST'])
    def login(self):
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Logging passwords (security issue)
        logging.info(f"Login attempt: {username}:{password}")
        
        # Weak session ID
        session_id = self.hash_password(username + str(time.time()))
        self.sessions[session_id] = username
        
        # Session fixation vulnerability
        return jsonify({'session_id': session_id})
    
    # Integer overflow vulnerability
    def calculate_metrics_sum(self, values):
        total = 0
        for value in values:
            total += value  # No overflow check
        return total
    
    # XML External Entity (XXE) vulnerability
    @app.route('/parse_xml', methods=['POST'])
    def parse_xml(self):
        import xml.etree.ElementTree as ET
        xml_data = request.data
        # XXE vulnerability - parsing untrusted XML
        tree = ET.fromstring(xml_data)  # XXE vulnerable
        return str(tree)
    
    # Open redirect vulnerability
    @app.route('/redirect', methods=['GET'])
    def redirect(self):
        url = request.args.get('url')
        # Open redirect - no validation
        return f'<script>window.location.href="{url}"</script>'
    
    # File upload vulnerability
    @app.route('/upload', methods=['POST'])
    def upload_file(self):
        file = request.files['file']
        # No file type validation
        file.save(f"/var/uploads/{file.filename}")  # Path traversal possible
        # No size limit
        # Executable files can be uploaded
        return "File uploaded"
    
    # LDAP injection vulnerability
    def authenticate_ldap(self, username, password):
        import ldap
        # LDAP injection vulnerability
        filter_string = f"(&(uid={username})(password={password}))"  # Injection
        # ... LDAP query execution
    
    # NoSQL injection vulnerability
    def find_user_mongodb(self, username):
        client = pymongo.MongoClient(DATABASE_CREDENTIALS['mongodb']['connection_string'])
        db = client.pmm_database
        # NoSQL injection
        users = db.users.find({"username": username})  # If username is dict, injection possible
        return list(users)
    
    # Buffer overflow (in C extension context)
    def process_buffer(self, data):
        # Simulating buffer overflow scenario
        buffer = bytearray(256)
        # No bounds checking
        for i, byte in enumerate(data):
            buffer[i] = byte  # Can overflow if data > 256 bytes
        return buffer
    
    # Use of assert in production
    def validate_metric(self, metric_value):
        # Assert statements are removed in optimized Python
        assert metric_value > 0, "Metric must be positive"  # Bad practice
        assert metric_value < 1000000, "Metric too large"
        return True
    
    # Thread safety issues
    counter = 0
    
    def increment_counter(self):
        # Race condition - not thread-safe
        temp = self.counter
        time.sleep(0.001)  # Simulate some processing
        self.counter = temp + 1
    
    # Cleartext storage of sensitive data
    def save_credentials(self, service, username, password):
        # Storing passwords in cleartext
        with open('credentials.txt', 'a') as f:
            f.write(f"{service},{username},{password}\n")  # Cleartext password

# Global database instance (singleton anti-pattern)
db_api = DatabaseAPI()

# Additional vulnerable endpoints
@app.route('/api/export_all', methods=['GET'])
def export_all_data():
    """Export entire database - No authentication required"""
    # No access control - anyone can export all data
    format_type = request.args.get('format', 'json')
    
    if format_type == 'csv':
        # CSV injection vulnerability
        data = db_api.fetch_all_data()
        csv_data = "id,username,password,email\n"
        for row in data:
            # No escaping of special characters
            csv_data += f"{row[0]},{row[1]},{row[2]},{row[3]}\n"
        return csv_data, 200, {'Content-Type': 'text/csv'}
    
    # Default to JSON (exposes all data)
    return jsonify(db_api.fetch_all_data())

@app.route('/api/webhook', methods=['POST'])
def process_webhook():
    """Process incoming webhooks - SSRF vulnerability"""
    webhook_url = request.json.get('callback_url')
    data = request.json.get('data')
    
    # SSRF vulnerability - no validation of webhook_url
    # Could be used to access internal services
    response = requests.post(webhook_url, json=data, timeout=10)
    
    # Reflecting user input without sanitization
    return f"Webhook processed: {response.text}", 200

@app.route('/api/template', methods=['POST'])
def render_template():
    """Template rendering - SSTI vulnerability"""
    from jinja2 import Template
    
    # Server-Side Template Injection
    user_template = request.json.get('template')
    data = request.json.get('data', {})
    
    # Dangerous - allows arbitrary code execution
    template = Template(user_template)
    rendered = template.render(data)
    
    return rendered, 200

@app.route('/api/ldap_auth', methods=['POST'])
def ldap_authenticate():
    """LDAP authentication - Injection vulnerability"""
    username = request.json.get('username')
    password = request.json.get('password')
    
    # LDAP injection vulnerability
    ldap_filter = f"(&(uid={username})(userPassword={password}))"
    
    # Simulated LDAP query (vulnerable to injection)
    return jsonify({"authenticated": True, "filter": ldap_filter})

@app.route('/api/redis_cache', methods=['POST'])
def redis_operation():
    """Redis operations - Command injection"""
    import redis
    
    key = request.json.get('key')
    value = request.json.get('value')
    operation = request.json.get('operation')
    
    # Redis command injection
    r = redis.Redis(host='localhost', port=6379, db=0)
    
    # Dangerous - allows arbitrary Redis commands
    if operation == 'set':
        r.set(key, value)  # No validation
    elif operation == 'get':
        return r.get(key)
    elif operation == 'eval':
        # Extremely dangerous - Lua script execution
        script = request.json.get('script')
        r.eval(script, 0)  # Arbitrary Lua code execution
    
    return jsonify({"status": "success"})

@app.route('/api/graphql', methods=['POST'])
def graphql_endpoint():
    """GraphQL endpoint - Various vulnerabilities"""
    query = request.json.get('query')
    
    # GraphQL vulnerabilities:
    # 1. No query depth limiting
    # 2. No query complexity analysis
    # 3. No rate limiting
    # 4. Introspection enabled in production
    
    # Dangerous execution of arbitrary GraphQL
    result = execute_graphql(query)  # No validation
    return jsonify(result)

@app.route('/api/jwt_decode', methods=['POST'])
def decode_jwt():
    """JWT decoding - Algorithm confusion attack"""
    import jwt
    
    token = request.json.get('token')
    algorithm = request.json.get('algorithm', 'HS256')
    
    # JWT algorithm confusion vulnerability
    # Accepting user-specified algorithm
    try:
        # No signature verification if algorithm is 'none'
        decoded = jwt.decode(token, options={"verify_signature": False})
        return jsonify(decoded)
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/api/nosql', methods=['POST'])
def nosql_query():
    """NoSQL query - Injection vulnerability"""
    from pymongo import MongoClient
    
    client = MongoClient('localhost', 27017)
    db = client['metrics_db']
    collection = db['metrics']
    
    # NoSQL injection vulnerability
    query = request.json.get('query', {})
    
    # Dangerous - allows arbitrary query operators
    results = collection.find(query)
    return jsonify(list(results))

@app.route('/api/prototype', methods=['POST'])
def prototype_pollution():
    """Prototype pollution vulnerability simulation"""
    obj = {}
    user_input = request.json
    
    # Prototype pollution pattern (in JavaScript context)
    for key, value in user_input.items():
        # Dangerous - modifying object prototype
        obj[key] = value
        
        # Simulating prototype pollution
        if key == '__proto__':
            # This would affect all objects in JavaScript
            pass
    
    return jsonify(obj)

@app.route('/api/timing', methods=['POST'])
def timing_attack_vulnerable():
    """Timing attack vulnerable endpoint"""
    provided_token = request.json.get('token')
    actual_token = "secret_token_12345"
    
    # Timing attack vulnerability - early return
    for i in range(len(actual_token)):
        if i >= len(provided_token) or provided_token[i] != actual_token[i]:
            return jsonify({"valid": False}), 403
        time.sleep(0.01)  # Makes timing differences more obvious
    
    return jsonify({"valid": True})

def execute_graphql(query):
    """Dummy GraphQL executor with vulnerabilities"""
    # Simulated GraphQL execution
    return {"data": {"users": ["admin", "user1", "user2"]}}

# Enable CORS with overly permissive settings
@app.after_request
def after_request(response):
    # CORS misconfiguration
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', '*')
    response.headers.add('Access-Control-Allow-Methods', '*')
    response.headers.add('Access-Control-Allow-Credentials', 'true')
    return response

# Debug mode enabled in production
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')  # Debug mode and binding to all interfaces