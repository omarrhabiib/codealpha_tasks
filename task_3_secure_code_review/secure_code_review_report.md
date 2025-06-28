# Secure Code Review Report: vulnerable_app.py

This report details the security vulnerabilities and bad coding practices identified in the sample Python application `vulnerable_app.py`.

## Summary of Findings

Multiple vulnerabilities were identified, ranging from high to medium risk. These include injection flaws, insecure handling of data, use of dangerous functions, and insecure configuration.

---

## Detailed Findings



### 1. Hardcoded Secret Key

**Description:** The Flask application uses a hardcoded secret key directly in the configuration. Secret keys are crucial for session security and other cryptographic operations. Hardcoding them makes them easily discoverable if the source code is exposed.

**Risk Level:** Medium

**Vulnerable Code Snippet:**
```python
# Hardcoded Secret
app.config["SECRET_KEY"] = "this_is_a_very_secret_key"
```
(Line 11)

**Recommendation:** Store secret keys securely outside the codebase. Use environment variables or a dedicated secrets management system (like HashiCorp Vault, AWS Secrets Manager, or Azure Key Vault) to load the secret key at runtime. Ensure the key is strong and randomly generated.

**Example (using environment variable):**
```python
import os
# ...
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", "default_fallback_key_for_dev") # Fallback only for development
```

---



### 2. SQL Injection (SQLi)

**Description:** The `/user` endpoint constructs an SQL query by directly embedding user-provided input (`user_id`) into the query string using string formatting. This allows an attacker to manipulate the SQL query by providing malicious input, potentially leading to unauthorized data access, modification, or deletion.

**Risk Level:** High

**Vulnerable Code Snippet:**
```python
@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    db = get_db()
    cursor = db.cursor()
    # Bad practice: Directly formatting SQL query with user input
    query = "SELECT * FROM users WHERE id = \'{}\'.format(user_id)
    cursor.execute(query) # Vulnerable execution
    user_data = cursor.fetchone()
    db.close()
    return str(user_data)
```
(Lines 21-29, specifically line 26)

**Recommendation:** Always use parameterized queries (also known as prepared statements) to handle user input in SQL queries. The database driver will safely handle the input, preventing injection attacks.

**Example (using parameterized query with `sqlite3`):**
```python
@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    db = get_db()
    cursor = db.cursor()
    # Secure practice: Using parameterized query
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))
    user_data = cursor.fetchone()
    db.close()
    return str(user_data)
```

---



### 3. Command Injection

**Description:** The `/ping` endpoint takes user input (`host`) and incorporates it directly into a shell command string that is executed using `subprocess.check_output` with `shell=True`. This allows an attacker to inject arbitrary shell commands by manipulating the `host` parameter (e.g., `"; ls -la` or `127.0.0.1; rm -rf /`).

**Risk Level:** High

**Vulnerable Code Snippet:**
```python
@app.route("/ping")
def ping_host():
    host = request.args.get("host")
    # Bad practice: Using user input directly in a shell command
    cmd = "ping -c 1 " + host
    output = subprocess.check_output(cmd, shell=True) # Vulnerable execution
    return output
```
(Lines 32-37, specifically line 36)

**Recommendation:** Avoid using `shell=True` with `subprocess` functions if possible, especially when incorporating user input. Pass the command and arguments as a list to avoid shell interpretation. If user input must be part of a command, validate and sanitize it strictly. For network utilities like ping, ensure the input is a valid IP address or hostname.

**Example (safer approach, still requires input validation):**
```python
import shlex

@app.route("/ping")
def ping_host():
    host = request.args.get("host")
    # Add strong validation for 'host' here (e.g., regex for IP/hostname)
    if not is_valid_host(host): # Assuming is_valid_host function exists
        return "Invalid host format", 400
    
    command = ["ping", "-c", "1", host]
    try:
        # Secure practice: Pass command as a list, avoids shell=True
        output = subprocess.check_output(command, stderr=subprocess.STDOUT, timeout=5)
        return output
    except subprocess.CalledProcessError as e:
        return f"Error executing ping: {e.output.decode()}", 500
    except subprocess.TimeoutExpired:
        return "Ping command timed out", 500
```

---



### 4. Insecure Deserialization

**Description:** The `/load_prefs` endpoint deserializes data directly from the request body using `pickle.loads()`. Pickle is known to be insecure when used with untrusted data, as specially crafted pickled objects can lead to arbitrary code execution during deserialization.

**Risk Level:** High

**Vulnerable Code Snippet:**
```python
@app.route("/load_prefs", methods=["POST"])
def load_preferences():
    data = request.get_data()
    # Bad practice: Using pickle with untrusted data
    preferences = pickle.loads(data) # Vulnerable deserialization
    return "Preferences loaded: {}".format(preferences)
```
(Lines 40-44, specifically line 43)

**Recommendation:** Avoid using `pickle` for deserializing data from untrusted sources like user requests. Use safer serialization formats like JSON, which do not carry executable code. If complex object serialization is required, ensure the data is signed or encrypted to verify its integrity and origin before deserialization, or use libraries specifically designed for safe object serialization.

**Example (using JSON):**
```python
import json

@app.route("/load_prefs", methods=["POST"])
def load_preferences():
    try:
        data = request.get_json()
        if data is None:
            return "Invalid JSON data", 400
        # Process the data safely
        preferences = data 
        return "Preferences loaded: {}".format(preferences)
    except json.JSONDecodeError:
        return "Invalid JSON format", 400
```

---



### 5. Use of `eval()` with User Input

**Description:** The `/calculate` endpoint uses the `eval()` function to execute a mathematical expression provided by the user via the `expr` parameter. The `eval()` function executes arbitrary Python code passed to it as a string. Allowing user input to be processed by `eval()` is extremely dangerous and can lead to arbitrary code execution on the server.

**Risk Level:** High

**Vulnerable Code Snippet:**
```python
@app.route("/calculate")
def calculate():
    expression = request.args.get("expr")
    # Bad practice: Using eval with user input
    result = eval(expression) # Vulnerable execution
    return "Result: {}".format(result)
```
(Lines 47-52, specifically line 51)

**Recommendation:** Never use `eval()` with untrusted input. If you need to evaluate mathematical expressions, use safer alternatives like `ast.literal_eval` for simple literal structures or dedicated expression evaluation libraries (like `numexpr`) that parse and evaluate expressions in a controlled environment without executing arbitrary code.

**Example (using `ast.literal_eval` for simple cases, though not suitable for math expressions):**
```python
import ast

# Note: ast.literal_eval only handles literals (strings, numbers, tuples, lists, dicts, booleans, None)
# It does NOT evaluate mathematical expressions. For that, a dedicated parser is needed.
# This example shows replacing eval, but a math parser would be the correct solution here.

@app.route("/calculate")
def calculate():
    expression = request.args.get("expr")
    try:
        # Example using a safe evaluation library (conceptual - requires installing e.g., numexpr)
        # import numexpr
        # result = numexpr.evaluate(expression).item() 
        
        # Or implement a very strict parser/validator for simple math operations
        # For demonstration, we'll just return an error as eval is too risky
        return "Direct evaluation of arbitrary expressions is not supported.", 400
        
    except Exception as e:
        return f"Error processing expression: {e}", 400
```

---



### 6. Weak Password Hashing

**Description:** The `store_password` function uses the MD5 algorithm to hash passwords before storing them in the database. MD5 is a cryptographically broken hashing algorithm and is highly susceptible to collision attacks and rainbow table attacks, making it unsuitable for password storage.

**Risk Level:** High

**Vulnerable Code Snippet:**
```python
def store_password(username, password):
    db = get_db()
    cursor = db.cursor()
    # Bad practice: Using MD5 for password hashing
    hashed_password = hashlib.md5(password.encode()).hexdigest() # Weak hashing algorithm
    cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed_password))
    db.commit()
    db.close()
```
(Lines 55-62, specifically line 60)

**Recommendation:** Use a strong, adaptive password hashing algorithm like Argon2 (preferred), scrypt, or bcrypt. These algorithms incorporate salting automatically (or require it) and are computationally intensive, making brute-force and rainbow table attacks much more difficult. Use libraries like `passlib` to simplify implementation.

**Example (using `passlib` with bcrypt):**
```python
from passlib.context import CryptContext

# Configure passlib context (do this once, e.g., globally)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def store_password(username, password):
    db = get_db()
    cursor = db.cursor()
    # Secure practice: Using bcrypt for password hashing via passlib
    hashed_password = pwd_context.hash(password)
    cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed_password))
    db.commit()
    db.close()

# Function to verify password (example)
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)
```

---



### 7. Cross-Site Scripting (XSS)

**Description:** The `/greet` endpoint takes user input (`name`) and directly includes it in an HTML template string that is rendered using `render_template_string`. Since the input is not sanitized or escaped, an attacker can inject malicious scripts (e.g., `<script>alert('XSS')</script>`) via the `name` parameter, which will then be executed in the browser of users visiting this endpoint.

**Risk Level:** Medium

**Vulnerable Code Snippet:**
```python
@app.route("/greet")
def greet_user():
    name = request.args.get("name", "Guest")
    # Bad practice: Rendering user input directly in template without escaping
    template = f"<h1>Hello, {name}!</h1>" # User input directly in f-string
    return render_template_string(template) # Vulnerable rendering
```
(Lines 65-70, specifically lines 69 and 70)

**Recommendation:** Always escape user-controlled input before rendering it in HTML templates. When using Flask and Jinja2 (which `render_template_string` uses), leverage the built-in autoescaping feature. If constructing HTML manually or within contexts where autoescaping might not apply, use escaping functions like `markupsafe.escape` explicitly.

**Example (using Jinja2 autoescaping with `render_template_string`):**
```python
from markupsafe import escape
from flask import render_template_string

@app.route("/greet")
def greet_user():
    name = request.args.get("name", "Guest")
    # Secure practice: Pass user input to the template context
    # Jinja2 (used by render_template_string) will autoescape by default
    template = "<h1>Hello, {{ user_name }}!</h1>"
    return render_template_string(template, user_name=name)

# Example (explicit escaping if needed):
@app.route("/greet_manual_escape")
def greet_user_manual_escape():
    name = request.args.get("name", "Guest")
    safe_name = escape(name) # Explicitly escape the user input
    template = f"<h1>Hello, {safe_name}!</h1>"
    return template # Assuming this is rendered safely elsewhere or is not HTML
```

---



### 8. Insecure Debug Mode and Network Binding

**Description:** The application is run using Flask's built-in development server with `debug=True` and `host=\'0.0.0.0\`. 
- **Debug Mode:** Enabling debug mode (`debug=True`) in a production or publicly accessible environment is highly insecure. It exposes the Werkzeug interactive debugger, which allows arbitrary Python code execution if an error occurs and the debugger PIN is compromised or not set.
- **Binding to 0.0.0.0:** Binding to `0.0.0.0` makes the server listen on all available network interfaces. While sometimes necessary, it can unintentionally expose the development server (and the debugger, if enabled) to the network, increasing the attack surface.

**Risk Level:** 
- Debug Mode Enabled: High (if accessible)
- Binding to 0.0.0.0: Low/Medium (increases exposure, risk amplified by debug mode)

**Vulnerable Code Snippet:**
```python
if __name__ == \'__main__\':
    # Bad practice: Running in debug mode in production-like code
    # Bad practice: Binding to 0.0.0.0 without considering security implications
    app.run(debug=True, host=\'0.0.0.0\', port=5000)
```
(Lines 72-75, specifically line 75)

**Recommendation:** 
- **Disable Debug Mode:** Never run a Flask application with `debug=True` in production. Control the debug flag using environment variables or configuration files, ensuring it's disabled by default.
- **Use a Production WSGI Server:** Do not use Flask's built-in development server (`app.run()`) for production deployments. Use a robust WSGI server like Gunicorn or uWSGI, typically placed behind a reverse proxy like Nginx.
- **Appropriate Binding:** During development, bind to `127.0.0.1` (localhost) unless external access on the local network is specifically required. Production WSGI servers handle binding appropriately based on their configuration.

**Example (Production Setup - Conceptual):**

1.  **Modify `app.run` for development only:**
    ```python
    if __name__ == \'__main__\':
        # For development only - controlled by environment variable
        debug_mode = os.environ.get("FLASK_DEBUG", "False").lower() == "true"
        app.run(debug=debug_mode, host=\'127.0.0.1\', port=5000) 
    ```
2.  **Run with Gunicorn (in production):**
    ```bash
    # Example command line for running with Gunicorn
    # Ensure FLASK_DEBUG is NOT set to true in the production environment
    gunicorn --bind 0.0.0.0:5000 vulnerable_app:app 
    ```
    (Typically, Gunicorn would be configured to bind to a Unix socket or `127.0.0.1` and fronted by Nginx).

---


