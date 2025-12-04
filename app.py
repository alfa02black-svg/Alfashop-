from flask import Flask, request, redirect, url_for, session, render_template_string
import sqlite3

app = Flask(__name__)
app.secret_key = "supersecretkey"

# Initialize database
conn = sqlite3.connect("database.db", check_same_thread=False)
c = conn.cursor()
c.execute("""CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                password TEXT,
                is_admin INTEGER DEFAULT 0
            )""")
c.execute("""CREATE TABLE IF NOT EXISTS products (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                price REAL
            )""")
conn.commit()

# ---------------- Home ----------------
@app.route("/")
def home():
    user = session.get("username")
    return render_template_string("""
    <html>
    <head>
        <title>AlfaShop Home</title>
        <style>
            body { font-family: Arial; text-align: center; background:#f0f0f0; }
            a { text-decoration: none; margin: 10px; display: inline-block; }
            .btn { padding: 10px 20px; background: #4CAF50; color:white; border-radius:5px;}
        </style>
    </head>
    <body>
        <h1>Welcome to AlfaShop</h1>
        {% if user %}
            <p>Hello, {{ user }}!</p>
            <a class="btn" href="/store">Go to Store</a>
            <a class="btn" href="/user_panel">User Panel</a>
            {% if session.get('is_admin') %}
                <a class="btn" href="/admin_panel">Admin Panel</a>
            {% endif %}
            <a class="btn" href="/logout">Logout</a>
        {% else %}
            <a class="btn" href="/login">Login</a>
            <a class="btn" href="/register">Register</a>
        {% endif %}
    </body>
    </html>
    """, user=user)

# ---------------- Register ----------------
@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        try:
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
            conn.commit()
            return redirect(url_for("login"))
        except:
            return "Username already exists!"
    return render_template_string("""
    <h2>Register</h2>
    <form method="post">
        Username: <input type="text" name="username" required><br><br>
        Password: <input type="password" name="password" required><br><br>
        <input type="submit" value="Register">
    </form>
    <a href="/">Back Home</a>
    """)

# ---------------- Login ----------------
@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
        user = c.fetchone()
        if user:
            session["username"] = username
            session["is_admin"] = bool(user[3])
            return redirect(url_for("home"))
        return "Invalid login!"
    return render_template_string("""
    <h2>Login</h2>
    <form method="post">
        Username: <input type="text" name="username" required><br><br>
        Password: <input type="password" name="password" required><br><br>
        <input type="submit" value="Login">
    </form>
    <a href="/">Back Home</a>
    """)

# ---------------- Logout ----------------
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

# ---------------- Store ----------------
@app.route("/store")
def store():
    c.execute("SELECT * FROM products")
    products = c.fetchall()
    return render_template_string("""
    <h2>Store Page</h2>
    <form method="get" action="/store">
        Search: <input type="text" name="q">
        <input type="submit" value="Search">
    </form>
    <ul>
    {% for p in products %}
        {% if request.args.get('q') in p[1] or not request.args.get('q') %}
            <li>{{ p[1] }} - ${{ p[2] }}</li>
        {% endif %}
    {% endfor %}
    </ul>
    <a href="/">Back Home</a>
    """, products=products)

# ---------------- Admin Panel ----------------
@app.route("/admin_panel", methods=["GET","POST"])
def admin_panel():
    if not session.get("is_admin"):
        return redirect("/")
    if request.method=="POST":
        name = request.form["name"]
        price = float(request.form["price"])
        c.execute("INSERT INTO products (name, price) VALUES (?,?)", (name, price))
        conn.commit()
    c.execute("SELECT * FROM products")
    products = c.fetchall()
    return render_template_string("""
    <h2>Admin Panel</h2>
    <form method="post">
        Product Name: <input type="text" name="name" required>
        Price: <input type="number" name="price" step="0.01" required>
        <input type="submit" value="Add Product">
    </form>
    <h3>All Products:</h3>
    <ul>
    {% for p in products %}
        <li>{{ p[1] }} - ${{ p[2] }}</li>
    {% endfor %}
    </ul>
    <a href="/">Back Home</a>
    """, products=products)

# ---------------- User Panel ----------------
@app.route("/user_panel")
def user_panel():
    if not session.get("username"):
        return redirect("/login")
    c.execute("SELECT * FROM products")
    products = c.fetchall()
    return render_template_string("""
    <h2>User Panel</h2>
    <ul>
    {% for p in products %}
        <li>{{ p[1] }} - ${{ p[2] }}</li>
    {% endfor %}
    </ul>
    <a href="/">Back Home</a>
    """, products=products)

# ---------------- Run ----------------
if __name__=="__main__":
    app.run(host="0.0.0.0", port=10000)
