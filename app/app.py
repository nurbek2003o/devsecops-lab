import sqlite3, os
from flask import Flask, request

app = Flask(__name__)
AWS_KEY = os.environ.get("AWS_KEY")
@app.route("/user")
def user():
    name = request.args.get("name", "")
    conn = sqlite3.connect("db.sqlite")
    # ataylab: SQL injection
    return str(conn.execute("SELECT * FROM users WHERE name = ?", (name,)).fetchall())

@app.route("/calc")
def calc():
    return str(ast.literal_eval(request.args.get("x", "1"))) 

if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", 5000))

    app.run(host=host, port=port)
