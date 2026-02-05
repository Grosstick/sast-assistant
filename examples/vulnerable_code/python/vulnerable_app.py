"""
Vulnerable Python Application - For Testing SAST Assistant

This file contains intentionally vulnerable code for SQL injection and XSS.
DO NOT use this code in production!
"""

import sqlite3
from flask import Flask, request, render_template_string


app = Flask(__name__)


# =============================================================================
# SQL INJECTION VULNERABILITIES
# =============================================================================

def get_user_unsafe(user_id: str) -> dict:
    """
    VULNERABLE: SQL injection via string concatenation.
    
    An attacker could input: ' OR '1'='1' --
    This would return all users instead of just one.
    """
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # BAD: String concatenation with user input
    query = "SELECT * FROM users WHERE id = '" + user_id + "'"
    cursor.execute(query)
    
    result = cursor.fetchone()
    conn.close()
    return result


def search_products_unsafe(search_term: str) -> list:
    """
    VULNERABLE: SQL injection via f-string formatting.
    
    An attacker could input: ' UNION SELECT password FROM users --
    """
    conn = sqlite3.connect('products.db')
    cursor = conn.cursor()
    
    # BAD: F-string with user input
    query = f"SELECT * FROM products WHERE name LIKE '%{search_term}%'"
    cursor.execute(query)
    
    results = cursor.fetchall()
    conn.close()
    return results


def login_unsafe(username: str, password: str) -> bool:
    """
    VULNERABLE: SQL injection in authentication.
    
    An attacker could bypass authentication with:
    username: admin' --
    password: anything
    """
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # BAD: String formatting in authentication query
    query = "SELECT * FROM users WHERE username = '{}' AND password = '{}'".format(
        username, password
    )
    cursor.execute(query)
    
    user = cursor.fetchone()
    conn.close()
    return user is not None


# SAFE ALTERNATIVES

def get_user_safe(user_id: str) -> dict:
    """
    SAFE: Using parameterized query.
    """
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # GOOD: Parameterized query
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))
    
    result = cursor.fetchone()
    conn.close()
    return result


def login_safe(username: str, password: str) -> bool:
    """
    SAFE: Using parameterized query for authentication.
    """
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # GOOD: Parameterized query
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    cursor.execute(query, (username, password))
    
    user = cursor.fetchone()
    conn.close()
    return user is not None


# =============================================================================
# XSS (CROSS-SITE SCRIPTING) VULNERABILITIES
# =============================================================================

@app.route('/greet')
def greet_unsafe():
    """
    VULNERABLE: Reflected XSS via unescaped user input.
    
    An attacker could craft a URL like:
    /greet?name=<script>alert('XSS')</script>
    """
    name = request.args.get('name', 'Guest')
    
    # BAD: Directly embedding user input in HTML
    html = f"<h1>Hello, {name}!</h1>"
    return html


@app.route('/comment')
def show_comment_unsafe():
    """
    VULNERABLE: Stored XSS - comment is displayed without escaping.
    """
    comment = request.args.get('comment', '')
    
    # BAD: render_template_string with user input not escaped
    template = "<div class='comment'>" + comment + "</div>"
    return render_template_string(template)


@app.route('/profile')
def profile_unsafe():
    """
    VULNERABLE: XSS in multiple contexts.
    """
    username = request.args.get('user', 'anonymous')
    bio = request.args.get('bio', '')
    
    # BAD: User input in multiple HTML contexts
    html = f"""
    <html>
    <head><title>{username}'s Profile</title></head>
    <body>
        <h1>Welcome, {username}</h1>
        <div class="bio">{bio}</div>
        <script>
            var user = "{username}";
            console.log("Loaded profile for: " + user);
        </script>
    </body>
    </html>
    """
    return html


@app.route('/search')
def search_results_unsafe():
    """
    VULNERABLE: Reflected XSS in search results.
    """
    query = request.args.get('q', '')
    
    # BAD: Echoing search query without escaping
    html = f"<p>Search results for: {query}</p><ul><li>No results found</li></ul>"
    return html


# SAFE ALTERNATIVES

@app.route('/greet-safe')
def greet_safe():
    """
    SAFE: Using Jinja2 template with auto-escaping.
    """
    name = request.args.get('name', 'Guest')
    
    # GOOD: Using render_template_string with proper escaping
    template = "<h1>Hello, {{ name | e }}!</h1>"
    return render_template_string(template, name=name)


@app.route('/profile-safe')
def profile_safe():
    """
    SAFE: Using proper template with escaping.
    """
    from markupsafe import escape
    
    username = escape(request.args.get('user', 'anonymous'))
    bio = escape(request.args.get('bio', ''))
    
    # GOOD: Using escape() for all user input
    template = """
    <html>
    <head><title>{{ username }}'s Profile</title></head>
    <body>
        <h1>Welcome, {{ username }}</h1>
        <div class="bio">{{ bio }}</div>
    </body>
    </html>
    """
    return render_template_string(template, username=username, bio=bio)


if __name__ == '__main__':
    # DO NOT run this in production!
    app.run(debug=True)
