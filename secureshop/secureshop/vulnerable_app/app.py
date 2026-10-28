"""
SecureShop - INTENTIONALLY VULNERABLE e-commerce app, built for a
Red Team / Application Security lab assignment.

DO NOT deploy this anywhere but localhost / an isolated lab VM.
DO NOT point OWASP ZAP (or anything else) at any target other than
http://127.0.0.1:8080 that you yourself are running.

Every vulnerability below is marked "VULN (OWASP category)" so you
can map ZAP findings back to the code that causes them.
"""
import os
import sqlite3

from flask import Flask, g, redirect, request, render_template_string, session, url_for

app = Flask(__name__)

# VULN (A05 - Security Misconfiguration): hardcoded, trivially-guessable secret key.
app.secret_key = "supersecret123"

# VULN (A05 - Security Misconfiguration): debug mode left on. This exposes the
# Werkzeug interactive debugger/stack traces to anyone who can trigger an
# unhandled exception, and (with the debugger PIN disabled) can lead to RCE.
app.config["DEBUG"] = True

DB_PATH = os.path.join(os.path.dirname(__file__), "secureshop.db")


def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_db(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    cur = db.cursor()
    cur.executescript(
        """
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS products;
        DROP TABLE IF EXISTS orders;

        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,   -- VULN (A07): plaintext password storage
            is_admin INTEGER DEFAULT 0
        );

        CREATE TABLE products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            price REAL NOT NULL
        );

        CREATE TABLE orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            product_name TEXT NOT NULL,
            total REAL NOT NULL
        );
        """
    )
    # VULN (A05): default / weak admin credentials shipped in the seed data.
    cur.execute(
        "INSERT INTO users (username, password, is_admin) VALUES ('admin', 'admin123', 1)"
    )
    cur.execute(
        "INSERT INTO users (username, password, is_admin) VALUES ('alice', 'alicepass', 0)"
    )
    cur.execute(
        "INSERT INTO users (username, password, is_admin) VALUES ('bob', 'bobpass', 0)"
    )
    cur.executemany(
        "INSERT INTO products (name, description, price) VALUES (?,?,?)",
        [
            ("Wireless Mouse", "Ergonomic 2.4GHz mouse", 19.99),
            ("Mechanical Keyboard", "RGB backlit keyboard", 59.99),
            ("USB-C Hub", "7-in-1 hub", 24.99),
            ("Webcam 1080p", "Full HD webcam", 34.99),
        ],
    )
    cur.executemany(
        "INSERT INTO orders (user_id, product_name, total) VALUES (?,?,?)",
        [
            (2, "Wireless Mouse", 19.99),
            (3, "Mechanical Keyboard", 59.99),
        ],
    )
    db.commit()
    db.close()


BASE = """
<!doctype html><html><head><title>SecureShop</title></head><body>
<h2><a href="/">SecureShop</a></h2>
<a href="/products">Products</a> | <a href="/cart">Cart</a> | <a href="/profile">Profile</a> |
<a href="/orders">Orders</a> | <a href="/admin">Admin</a> |
{% if session.get('username') %}
 Logged in as {{ session['username'] }} (<a href="/logout">logout</a>)
{% else %}
 <a href="/login">Login</a> | <a href="/register">Register</a>
{% endif %}
<hr>{{ body|safe }}
</body></html>
"""


def page(body):
    return render_template_string(BASE, body=body)


@app.route("/")
def home():
    return page("<h3>Welcome to SecureShop</h3><p>Internal e-commerce demo (lab build).</p>")


@app.route("/register", methods=["GET", "POST"])
def register():
    msg = ""
    if request.method == "POST":
        u = request.form["username"]
        p = request.form["password"]
        db = get_db()
        try:
            db.execute("INSERT INTO users (username, password) VALUES (?, ?)", (u, p))
            db.commit()
            msg = "Registered. You can log in now."
        except sqlite3.IntegrityError:
            msg = "Username taken."
    return page(
        f"""{msg}<form method="post">
        Username: <input name="username"><br>
        Password: <input name="password" type="password"><br>
        <input type="submit" value="Register"></form>"""
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""
    if request.method == "POST":
        u = request.form["username"]
        p = request.form["password"]
        db = get_db()
        # VULN (A03 - Injection): query built via string interpolation.
        # Example payload for the username field:  ' OR '1'='1
        query = f"SELECT * FROM users WHERE username = '{u}' AND password = '{p}'"
        row = db.execute(query).fetchone()
        # VULN (A09 - Logging/Monitoring failure): no record is kept of
        # successful or failed login attempts anywhere in this app.
        if row:
            session["username"] = row["username"]
            session["user_id"] = row["id"]
            session["is_admin"] = bool(row["is_admin"])
            return redirect(url_for("home"))
        error = "Invalid credentials."
    return page(
        f"""{error}<form method="post">
        Username: <input name="username"><br>
        Password: <input name="password" type="password"><br>
        <input type="submit" value="Login"></form>"""
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


@app.route("/products")
def products():
    db = get_db()
    rows = db.execute("SELECT * FROM products").fetchall()
    items = "".join(f'<li><a href="/product/{r["id"]}">{r["name"]}</a> - ${r["price"]}</li>' for r in rows)
    return page(
        f'<h3>Products</h3><ul>{items}</ul>'
        f'<form action="/search">Search: <input name="q"><input type="submit"></form>'
    )


@app.route("/search")
def search():
    q = request.args.get("q", "")
    db = get_db()
    # VULN (A03 - Injection): unparameterized LIKE query.
    # Try: q = %'  UNION SELECT id,username,password,is_admin FROM users-- -
    query = f"SELECT * FROM products WHERE name LIKE '%{q}%'"
    try:
        rows = db.execute(query).fetchall()
        items = "".join(f'<li>{r["name"]} - ${r["price"]}</li>' for r in rows)
    except sqlite3.OperationalError as e:
        # VULN (A05 - Security Misconfiguration): verbose DB error + raw query
        # reflected straight back to the client.
        return page(f"<pre>DB ERROR: {e}\nQuery was: {query}</pre>")
    # VULN (A03 - Injection / Reflected XSS): q is reflected without escaping.
    # Try: q = <script>alert(document.cookie)</script>
    return page(f"<h3>Results for: {q}</h3><ul>{items}</ul>")


@app.route("/product/<int:pid>")
def product_detail(pid):
    db = get_db()
    r = db.execute("SELECT * FROM products WHERE id=?", (pid,)).fetchone()
    if not r:
        return page("Not found"), 404
    return page(f"<h3>{r['name']}</h3><p>{r['description']}</p><p>${r['price']}</p>")


@app.route("/cart")
def cart():
    return page("<h3>Cart</h3><p>(demo - empty)</p>")


@app.route("/profile")
def profile():
    if "username" not in session:
        return redirect(url_for("login"))
    return page(f"<h3>Profile</h3><p>Username: {session['username']}</p>")


@app.route("/orders")
def orders():
    if "username" not in session:
        return redirect(url_for("login"))
    db = get_db()
    rows = db.execute("SELECT * FROM orders WHERE user_id=?", (session["user_id"],)).fetchall()
    items = "".join(
        f'<li><a href="/order/{r["id"]}">Order #{r["id"]}</a> - {r["product_name"]} ${r["total"]}</li>'
        for r in rows
    )
    return page(f"<h3>Your Orders</h3><ul>{items}</ul>")


@app.route("/order/<int:oid>")
def order_detail(oid):
    if "username" not in session:
        return redirect(url_for("login"))
    db = get_db()
    # VULN (A01 - Broken Access Control / IDOR): no check that this order
    # belongs to the logged-in user. Any authenticated user can walk
    # /order/1, /order/2, ... and read other users' orders.
    r = db.execute("SELECT * FROM orders WHERE id=?", (oid,)).fetchone()
    if not r:
        return page("Not found"), 404
    return page(
        f"<h3>Order #{r['id']}</h3><p>Product: {r['product_name']}</p>"
        f"<p>Total: ${r['total']}</p><p>Belongs to user_id: {r['user_id']}</p>"
    )


@app.route("/admin")
def admin():
    # VULN (A01 - Broken Access Control): only checks that *someone* is
    # logged in, not that they hold the is_admin flag. Any registered user
    # (e.g. the 'alice' account created above) can browse straight to
    # /admin and see the full user list.
    if "username" not in session:
        return redirect(url_for("login"))
    db = get_db()
    users = db.execute("SELECT * FROM users").fetchall()
    rows = "".join(f"<li>{u['username']} (admin={u['is_admin']})</li>" for u in users)
    return page(f"<h3>Admin Panel</h3><p>Logged in as {session['username']}</p><ul>{rows}</ul>")


if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        init_db()
    # Bind to localhost only for the lab. Keep debug=True to reproduce the
    # A05 misconfiguration finding during the ZAP scan.
    app.run(host="127.0.0.1", port=8080, debug=True)
