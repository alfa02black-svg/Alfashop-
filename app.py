import os
import sqlite3
import hashlib
import json
from flask import Flask, render_template, request, redirect, session, send_file, flash, abort, jsonify
from datetime import datetime
from io import BytesIO

app = Flask(__name__)
app.secret_key = os.environ.get("ALFASHOP_SECRET", "alfashop-secret-key")

DB_PATH = "database.db"

# --------------- Database helpers ---------------
def db_connect():
    con = sqlite3.connect(DB_PATH, check_same_thread=False)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    con = db_connect()
    cur = con.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        is_admin INTEGER DEFAULT 0,
        created_at TEXT
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS products(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        price REAL,
        description TEXT,
        created_at TEXT
    )
    """)
    con.commit()
    con.close()

def hash_pw(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()

def ensure_seed_data():
    con = db_connect()
    cur = con.cursor()
    # if no admin exists, create admin
    cur.execute("SELECT COUNT(*) as cnt FROM users")
    if cur.fetchone()["cnt"] == 0:
        pw = hash_pw("admin123")
        cur.execute("INSERT INTO users (username,password,is_admin,created_at) VALUES (?,?,1,?)",
                    ("admin", pw, datetime.utcnow().isoformat()))
    # seed products if none
    cur.execute("SELECT COUNT(*) as cnt FROM products")
    if cur.fetchone()["cnt"] == 0:
        sample = [
            ("Smartphone X", 299.99, "A powerful smartphone with great camera."),
            ("Wireless Headphones", 59.99, "Comfortable and long battery life."),
            ("USB-C Charger", 12.50, "Fast charging USB-C adapter.")
        ]
        for name, price, desc in sample:
            cur.execute("INSERT INTO products (name,price,description,created_at) VALUES (?,?,?,?)",
                        (name, price, desc, datetime.utcnow().isoformat()))
    con.commit()
    con.close()

# initialize DB and seed
init_db()
ensure_seed_data()

# --------------- Auth helpers ---------------
def logged_in():
    return "user" in session

def is_admin():
    return session.get("admin", 0) == 1

# --------------- Routes ---------------
@app.route("/")
def index():
    return redirect("/store")

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","")
        if len(username) < 3 or len(password) < 4:
            flash("Username must be 3+ chars and password 4+ chars", "error")
            return redirect("/register")
        con = db_connect()
        cur = con.cursor()
        try:
            cur.execute("INSERT INTO users (username,password,created_at) VALUES (?,?,?)",
                        (username, hash_pw(password), datetime.utcnow().isoformat()))
            con.commit()
            flash("Registered successfully. Please login.", "success")
            return redirect("/login")
        except sqlite3.IntegrityError:
            flash("Username already exists.", "error")
            return redirect("/register")
        finally:
            con.close()
    return render_template("register.html")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","")
        con = db_connect()
        cur = con.cursor()
        cur.execute("SELECT * FROM users WHERE username=? AND password=?", (username, hash_pw(password)))
        user = cur.fetchone()
        con.close()
        if user:
            session["user"] = user["username"]
            session["admin"] = user["is_admin"]
            flash("Logged in successfully.", "success")
            return redirect("/admin" if user["is_admin"] == 1 else "/store")
        else:
            flash("Wrong username or password.", "error")
            return redirect("/login")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

@app.route("/store")
def store():
    q = request.args.get("q","").strip()
    con = db_connect()
    cur = con.cursor()
    if q:
        cur.execute("SELECT * FROM products WHERE name LIKE ? OR description LIKE ?", ('%'+q+'%','%'+q+'%'))
    else:
        cur.execute("SELECT * FROM products")
    products = cur.fetchall()
    con.close()
    return render_template("store.html", products=products, query=q)

# Admin panel
@app.route("/admin")
def admin_panel():
    if not logged_in() or not is_admin():
        flash("Admin login required.", "error")
        return redirect("/login")
    con = db_connect()
    cur = con.cursor()
    cur.execute("SELECT * FROM products ORDER BY id DESC")
    products = cur.fetchall()
    con.close()
    return render_template("admin.html", products=products)

@app.route("/add_product", methods=["POST"])
def add_product():
    if not is_admin():
        abort(403)
    name = request.form.get("name","").strip()
    price = request.form.get("price","0").strip()
    desc = request.form.get("description","").strip()
    try:
        price_val = float(price)
    except:
        flash("Price must be a number.", "error")
        return redirect("/admin")
    con = db_connect()
    cur = con.cursor()
    cur.execute("INSERT INTO products (name,price,description,created_at) VALUES (?,?,?,?)",
                (name, price_val, desc, datetime.utcnow().isoformat()))
    con.commit()
    con.close()
    flash("Product added.", "success")
    return redirect("/admin")

@app.route("/delete_product/<int:pid>", methods=["POST"])
def delete_product(pid):
    if not is_admin():
        abort(403)
    con = db_connect()
    cur = con.cursor()
    cur.execute("DELETE FROM products WHERE id=?", (pid,))
    con.commit()
    con.close()
    flash("Product deleted.", "success")
    return redirect("/admin")

# Backup (render as page and also download JSON)
@app.route("/backup")
def backup():
    if not logged_in() or not is_admin():
        flash("Admin login required.", "error")
        return redirect("/login")
    con = db_connect()
    cur = con.cursor()
    cur.execute("SELECT * FROM products")
    products = [dict(row) for row in cur.fetchall()]
    con.close()
    return render_template("backup.html", products=products)

@app.route("/download_backup")
def download_backup():
    if not logged_in() or not is_admin():
        abort(403)
    con = db_connect()
    cur = con.cursor()
    cur.execute("SELECT * FROM products")
    products = [dict(row) for row in cur.fetchall()]
    con.close()
    b = BytesIO()
    b.write(json.dumps(products, indent=2, ensure_ascii=False).encode("utf-8"))
    b.seek(0)
    return send_file(b, mimetype="application/json", download_name="products_backup.json", as_attachment=True)

# simple API for live search (optional)
@app.route("/api/search")
def api_search():
    q = request.args.get("q","").strip()
    con = db_connect()
    cur = con.cursor()
    if q:
        cur.execute("SELECT * FROM products WHERE name LIKE ? OR description LIKE ?", ('%'+q+'%','%'+q+'%'))
    else:
        cur.execute("SELECT * FROM products")
    results = [dict(r) for r in cur.fetchall()]
    con.close()
    return jsonify(results)

# Error handlers
@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404

@app.errorhandler(403)
def forbidden(e):
    return "Forbidden", 403

@app.errorhandler(500)
def server_error(e):
    return "Internal Server Error", 500

if __name__ == "__main__":
    # for local debug
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
