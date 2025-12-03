from flask import Flask, render_template, request, redirect, session
import sqlite3, hashlib, os

app = Flask(__name__)
app.secret_key = "alfashop-secret-key"

# ------------------------------------
# Database Connection
# ------------------------------------
def db():
    return sqlite3.connect("database.db", check_same_thread=False)

# Create tables on first run
con = db()
cur = con.cursor()

cur.execute("""
CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    is_admin INTEGER DEFAULT 0
)
""")

cur.execute("""
CREATE TABLE IF NOT EXISTS products(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    price REAL,
    description TEXT
)
""")

con.commit()


# ------------------------------------
# Helper Functions
# ------------------------------------
def hash_pw(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def logged_in():
    return "user" in session

def admin():
    return session.get("admin", 0) == 1


# ------------------------------------
# Routes
# ------------------------------------

@app.route("/")
def home():
    return redirect("/store")

# Register Page
@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = hash_pw(request.form["password"])

        con = db()
        cur = con.cursor()

        try:
            cur.execute("INSERT INTO users(username,password) VALUES(?,?)",
                        (username,password))
            con.commit()
            return redirect("/login")
        except:
            return "Username already exists!"
        
    return render_template("register.html")

# Login Page
@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = hash_pw(request.form["password"])

        con = db()
        cur = con.cursor()
        cur.execute("SELECT * FROM users WHERE username=? AND password=?",
                    (username, password))
        user = cur.fetchone()

        if user:
            session["user"] = user[1]
            session["admin"] = user[3]
            return redirect("/admin" if user[3] == 1 else "/store")
        else:
            return "Wrong username or password!"

    return render_template("login.html")


# Store Page
@app.route("/store")
def store():
    con = db()
    cur = con.cursor()

    q = request.args.get("q","")
    if q:
        cur.execute("SELECT * FROM products WHERE name LIKE ?", ('%'+q+'%',))
    else:
        cur.execute("SELECT * FROM products")

    products = cur.fetchall()
    return render_template("store.html", products=products)


# Admin Panel
@app.route("/admin")
def admin_panel():
    if not logged_in() or not admin():
        return redirect("/login")

    con = db()
    cur = con.cursor()
    cur.execute("SELECT * FROM products")
    products = cur.fetchall()

    return render_template("admin.html", products=products)


# Add Product
@app.route("/add_product", methods=["POST"])
def add_product():
    if not admin():
        return redirect("/login")

    name = request.form["name"]
    price = request.form["price"]
    desc = request.form["description"]

    con = db()
    cur = con.cursor()
    cur.execute("INSERT INTO products(name,price,description) VALUES(?,?,?)",
                (name,price,desc))
    con.commit()

    return redirect("/admin")


# Backup Page
@app.route("/backup")
def backup():
    if not admin():
        return redirect("/login")

    con = db()
    cur = con.cursor()
    cur.execute("SELECT * FROM products")
    products = cur.fetchall()

    return render_template("backup.html", products=products)


# Logout
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


if __name__ == "__main__":
    app.run(debug=True)