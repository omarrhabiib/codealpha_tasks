import os
import subprocess
import pickle
import sqlite3
import hashlib
from flask import Flask, request, render_template_string

app = Flask(__name__)

# Hardcoded Secret
app.config['SECRET_KEY'] = 'this_is_a_very_secret_key'

# Database connection (example)
DATABASE = '/tmp/database.db'

def get_db():
    conn = sqlite3.connect(DATABASE)
    return conn

# SQL Injection Vulnerability
@app.route('/user')
def get_user():
    user_id = request.args.get('id')
    db = get_db()
    cursor = db.cursor()
    # Bad practice: Directly formatting SQL query with user input
    query = "SELECT * FROM users WHERE id = '{}'".format(user_id)
    cursor.execute(query)
    user_data = cursor.fetchone()
    db.close()
    return str(user_data)

# Command Injection Vulnerability
@app.route('/ping')
def ping_host():
    host = request.args.get('host')
    # Bad practice: Using user input directly in a shell command
    cmd = "ping -c 1 " + host
    output = subprocess.check_output(cmd, shell=True)
    return output

# Insecure Deserialization
@app.route('/load_prefs', methods=['POST'])
def load_preferences():
    data = request.get_data()
    # Bad practice: Using pickle with untrusted data
    preferences = pickle.loads(data)
    return "Preferences loaded: {}".format(preferences)

# Use of eval (Dangerous)
@app.route('/calculate')
def calculate():
    expression = request.args.get('expr')
    # Bad practice: Using eval with user input
    result = eval(expression)
    return "Result: {}".format(result)

# Weak Password Hashing
def store_password(username, password):
    db = get_db()
    cursor = db.cursor()
    # Bad practice: Using MD5 for password hashing
    hashed_password = hashlib.md5(password.encode()).hexdigest()
    cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed_password))
    db.commit()
    db.close()

# Cross-Site Scripting (XSS) via render_template_string
@app.route('/greet')
def greet_user():
    name = request.args.get('name', 'Guest')
    # Bad practice: Rendering user input directly in template without escaping
    template = f"<h1>Hello, {name}!</h1>"
    return render_template_string(template)

if __name__ == '__main__':
    # Bad practice: Running in debug mode in production-like code
    # Bad practice: Binding to 0.0.0.0 without considering security implications
    app.run(debug=True, host='0.0.0.0', port=5000)

