from flask import Flask, request, session, redirect, render_template_string
import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.urandom(32)  # strong secret key

DB = "lab.db"

def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            password TEXT,
            role TEXT
        )
    """)
    c.execute("DELETE FROM users")
    
    # insert users with hashed passwords
    c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
              ('rama', generate_password_hash('1234'), 'user'))
    c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
              ('admin', generate_password_hash('admin123'), 'admin'))
    
    conn.commit()
    conn.close()

@app.route("/")
def home():
    return "Welcome to the Cyber Lab (Secure Version)"

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        conn = sqlite3.connect(DB)
        c = conn.cursor()
        query = "SELECT * FROM users WHERE username = ?"
        user = c.execute(query, (username,)).fetchone()
        conn.close()

        if user and check_password_hash(user[2], password):
            session["user_id"] = user[0]
            session["role"] = user[3]
            return redirect("/dashboard")
        return "Invalid credentials"

    return '''
        <form method="POST">
            Username: <input name="username"><br>
            Password: <input name="password"><br>
            <input type="submit">
        </form>
    '''

@app.route("/dashboard")
def dashboard():
    if not session.get("user_id"):
        return redirect("/login")

    return """
        <h1>Dashboard</h1>
        <a href="/profile">My Profile</a><br>
        <a href="/admin">Admin Panel</a><br>
        <a href="/search">Search User</a>
    """


@app.route("/profile")
def profile():
    if not session.get("user_id"):
        return redirect("/login")

    user_id = session["user_id"]  # use session only

    conn = sqlite3.connect(DB)
    c = conn.cursor()
    user = c.execute("SELECT username, role FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()

    return f"Username: {user[0]} | Role: {user[1]}"

@app.route("/admin")
def admin():
    if session.get("role") == "admin":
        return "Welcome Admin"
    return "Access Denied"

@app.route("/search")
def search():
    if not session.get("user_id"):
        return redirect("/login")

    q = request.args.get("q", "")

    conn = sqlite3.connect(DB)
    c = conn.cursor()
    results = c.execute("SELECT username FROM users WHERE username LIKE ?", (f"%{q}%",)).fetchall()
    conn.close()
    for r in results:
output += f"<p>{r[0]}</p>"

    return render_template_string(output)

if __name__ == "__main__":
    init_db()

    output = "<h3>Results:</h3>"
    app.run(debug=True, use_reloader=False)
