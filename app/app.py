import sqlite3, os
from flask import Flask, request

app = Flask(__name__)
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"   # ataylab: secret

@app.route("/user")
def user():
    name = request.args.get("name", "")
    conn = sqlite3.connect("db.sqlite")
    # ataylab: SQL injection
    return str(conn.execute(f"SELECT * FROM users WHERE name = '{name}'").fetchall())

@app.route("/calc")
def calc():
    return str(eval(request.args.get("x", "1")))  # ataylab: eval

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
