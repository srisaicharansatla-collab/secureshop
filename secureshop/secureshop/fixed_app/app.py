"""
SecureShop - REMEDIATED version.

This mirrors vulnerable_app/app.py feature-for-feature so you can run the
same ZAP scan against it and show a before/after. Each fix below is tagged
with the OWASP category and finding it addresses.
"""
import logging
import os
import secrets
import sqlite3

from flask import Flask, g, redirect, request, render_template_string, session, url_for
from markupsafe import escape
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)

# FIX (A05): random secret key per run, read from env in real deployments.
app.secret_key = os.environ.get("SECUREShop_SECRET_KEY", secrets.token_hex(32))

# FIX (A05): debug mode off; FIX (A07): hardened session cookie flags.
app.config.update(
    DEBUG=False,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    # SESSION_COOKIE_SECURE=True,  # enable once served over HTTPS
)

DB_PATH = os.path.join(os.path.dirname(__file__), "secureshop.db")

# FIX (A09): structured logging of security-relevant events.
logging.basicConfig(
    filename=os.path.join(os.path.dirname(__file__), "security.log"),
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
security_log = logging.getLogger("secureshop.security")


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
            password_hash TEXT NOT NULL,   -- FIX (A07): hashed, not plaintext
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
    # FIX (A05): admin password is randomly generated at setup time and
    # printed once, instead of a hardcoded default credential.
    admin_password = os.environ.get("SECUREShop_ADMIN_PASSWORD") or secrets.token_urlsafe(12)
    cur.execute(
        "INSERT INTO users (username, password_hash, is_admin) VALUES ('admin', ?, 1)",
        (generate_password_hash(admin_password),),
    )
    cur.execute(
        "INSERT INTO users (username, password_hash, is_admin) VALUES ('alice', ?, 0)",
        (generate_password_hash("alicepass"),),
    )
    cur.execute(
        "INSERT INTO users (username, password_hash, is_admin) VALUES ('bob', ?, 0)",
        (generate_password_hash("bobpass"),),
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
    print(f"[setup] generated admin password: {admin_password}")


# FIX (A03 / XSS): templating uses {{ }} so Jinja2 autoescapes all
# interpolated values by default, instead of building raw HTML strings.
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
<hr>
{{ body_html|safe }}
</body></html>
"""
# NOTE: body_html is a trusted HTML skeleton assembled by this file. Any
# user-controlled value placed inside it is passed through escape() first
# (see search(), register(), product_detail(), etc.) before being embedded,
# so nothing user-controlled ever reaches the page unescaped.


def page(body_html):
    return render_template_string(BASE, body_html=body_html)


@app.route("/")
def home():
    return page("<h3>Welcome to SecureShop</h3><p>Internal e-commerce demo (lab build - remediated).</p>")


@app.route("/register", methods=["GET", "POST"])
def register():
    msg = ""
    if request.method == "POST":
        u = request.form["username"]
        p = request.form["password"]
        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (u, generate_password_hash(p)),
            )
            db.commit()
            msg = "Registered. You can log in now."
        except sqlite3.IntegrityError:
            msg = "Username taken."
    return page(
        f"""{escape(msg)}<form method="post">
        Username: <input name="username"><br>
        Password: <input name="password" type="password"><br>
        <input type="submit" value="Register"></form>"""
    )


# FIX (A07): simple in-memory lockout after repeated failed logins.
_failed_attempts = {}
MAX_ATTEMPTS = 5


@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""
    if request.method == "POST":
        u = request.form["username"]
        p = request.form["password"]
        ip = request.remote_addr

        if _failed_attempts.get((ip, u), 0) >= MAX_ATTEMPTS:
            security_log.warning("login locked out ip=%s user=%s", ip, u)
            return page("Too many failed attempts. Try again later."), 429

        db = get_db()
        # FIX (A03): parameterized query, no string interpolation.
        row = db.execute("SELECT * FROM users WHERE username = ?", (u,)).fetchone()
        if row and check_password_hash(row["password_hash"], p):
            session.clear()
            session["username"] = row["username"]
            session["user_id"] = row["id"]
            session["is_admin"] = bool(row["is_admin"])
            _failed_attempts.pop((ip, u), None)
            security_log.info("login success ip=%s user=%s", ip, u)
            return redirect(url_for("home"))

        _failed_attempts[(ip, u)] = _failed_attempts.get((ip, u), 0) + 1
        security_log.warning("login failed ip=%s user=%s", ip, u)
        error = "Invalid credentials."
    return page(
        f"""{escape(error)}<form method="post">
        Username: <input name="username"><br>
        Password: <input name="password" type="password"><br>
        <input type="submit" value="Login"></form>"""
    )


@app.route("/logout")
def logout():
    security_log.info("logout user=%s", session.get("username"))
    session.clear()
    return redirect(url_for("home"))


@app.route("/products")
def products():
    db = get_db()
    rows = db.execute("SELECT * FROM products").fetchall()
    items = "".join(
        f'<li><a href="/product/{r["id"]}">{escape(r["name"])}</a> - ${r["price"]}</li>' for r in rows
    )
    return page(
        f'<h3>Products</h3><ul>{items}</ul>'
        f'<form action="/search">Search: <input name="q"><input type="submit"></form>'
    )


@app.route("/search")
def search():
    q = request.args.get("q", "")
    db = get_db()
    # FIX (A03): parameterized LIKE query.
    rows = db.execute("SELECT * FROM products WHERE name LIKE ?", (f"%{q}%",)).fetchall()
    items = "".join(f'<li>{escape(r["name"])} - ${r["price"]}</li>' for r in rows)
    # FIX (XSS): q is escaped before being embedded in HTML.
    return page(f"<h3>Results for: {escape(q)}</h3><ul>{items}</ul>")


@app.route("/product/<int:pid>")
def product_detail(pid):
    db = get_db()
    r = db.execute("SELECT * FROM products WHERE id=?", (pid,)).fetchone()
    if not r:
        return page("Not found"), 404
    return page(f"<h3>{escape(r['name'])}</h3><p>{escape(r['description'])}</p><p>${r['price']}</p>")


@app.route("/cart")
def cart():
    return page("<h3>Cart</h3><p>(demo - empty)</p>")


@app.route("/profile")
def profile():
    if "username" not in session:
        return redirect(url_for("login"))
    return page(f"<h3>Profile</h3><p>Username: {escape(session['username'])}</p>")


@app.route("/orders")
def orders():
    if "username" not in session:
        return redirect(url_for("login"))
    db = get_db()
    rows = db.execute("SELECT * FROM orders WHERE user_id=?", (session["user_id"],)).fetchall()
    items = "".join(
        f'<li><a href="/order/{r["id"]}">Order #{r["id"]}</a> - {escape(r["product_name"])} ${r["total"]}</li>'
        for r in rows
    )
    return page(f"<h3>Your Orders</h3><ul>{items}</ul>")


@app.route("/order/<int:oid>")
def order_detail(oid):
    if "username" not in session:
        return redirect(url_for("login"))
    db = get_db()
    r = db.execute("SELECT * FROM orders WHERE id=?", (oid,)).fetchone()
    if not r:
        return page("Not found"), 404
    # FIX (A01 / IDOR): enforce that the order belongs to the requester,
    # unless they are an admin.
    if r["user_id"] != session["user_id"] and not session.get("is_admin"):
        security_log.warning(
            "blocked IDOR attempt user=%s tried order=%s", session.get("username"), oid
        )
        return page("Forbidden"), 403
    return page(
        f"<h3>Order #{r['id']}</h3><p>Product: {escape(r['product_name'])}</p>"
        f"<p>Total: ${r['total']}</p>"
    )


def require_admin():
    return "username" in session and session.get("is_admin")


@app.route("/admin")
def admin():
    # FIX (A01): explicit role check, not just "is someone logged in".
    if not require_admin():
        security_log.warning(
            "blocked non-admin access to /admin user=%s", session.get("username")
        )
        return redirect(url_for("login"))
    db = get_db()
    users = db.execute("SELECT * FROM users").fetchall()
    rows = "".join(f"<li>{escape(u['username'])} (admin={u['is_admin']})</li>" for u in users)
    return page(f"<h3>Admin Panel</h3><p>Logged in as {escape(session['username'])}</p><ul>{rows}</ul>")


if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        init_db()
    app.run(host="127.0.0.1", port=8081, debug=False)
