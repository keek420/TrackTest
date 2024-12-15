from flask import Flask, request, jsonify
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3

app = Flask(__name__)
auth = HTTPBasicAuth()

DATABASE = 'database.db'

def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY,
                        user_id TEXT UNIQUE NOT NULL,
                        password TEXT NOT NULL,
                        nickname TEXT,
                        comment TEXT)''')
        # 初期データの追加
    initial_user_id = "TaroYamada"
    initial_password = generate_password_hash("PaSSwd4TY")
    initial_nickname = "たろー"
    initial_comment = "僕は元気です"
    try:
        cursor.execute("INSERT INTO users (user_id, password, nickname, comment) VALUES (?, ?, ?, ?)", 
                       (initial_user_id, initial_password, initial_nickname, initial_comment))
    except sqlite3.IntegrityError:
        pass  # 初期データが既に存在する場合は無視
    conn.commit()
    conn.close()

@auth.verify_password
def verify_password(user_id, password):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT password FROM users WHERE user_id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    if row and check_password_hash(row[0], password):
        return user_id
    return None

@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    user_id = data.get('user_id')
    password = data.get('password')

    if not user_id or not password:
        return jsonify(message="Account creation failed", cause="Required user_id and password"), 400

    if len(user_id) < 6 or len(user_id) > 20 or not user_id.isalnum():
        return jsonify(message="Account creation failed", cause="Incorrect character pattern"), 400

    if len(password) < 8 or len(password) > 20:
        return jsonify(message="Account creation failed", cause="Input length is incorrect"), 400

    hashed_password = generate_password_hash(password)
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (user_id, password, nickname) VALUES (?, ?, ?)", 
                       (user_id, hashed_password, user_id))
        conn.commit()
        conn.close()
    except sqlite3.IntegrityError:
        return jsonify(message="Account creation failed", cause="Already same user_id is used"), 400

    return jsonify(message="Account successfully created", user={"user_id": user_id, "nickname": user_id}), 200

@app.route('/users/<user_id>', methods=['GET'])
@auth.login_required
def get_user(user_id):
    if auth.current_user() != user_id:
        return jsonify(message="Authentication failed"), 401

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT user_id, nickname, comment FROM users WHERE user_id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()

    if row:
        return jsonify(message="User details by user_id", user={"user_id": row[0], "nickname": row[1], "comment": row[2] or ""}), 200
    else:
        return jsonify(message="No user found"), 404

@app.route('/users/<user_id>', methods=['PATCH'])
@auth.login_required
def update_user(user_id):
    if auth.current_user() != user_id:
        return jsonify(message="No permission for update"), 403

    data = request.get_json()
    nickname = data.get('nickname')
    comment = data.get('comment')

    if nickname is None and comment is None:
        return jsonify(message="User updation failed", cause="Required nickname or comment"), 400

    if nickname and len(nickname) > 30:
        return jsonify(message="User updation failed", cause="Invalid nickname or comment"), 400

    if comment and len(comment) > 100:
        return jsonify(message="User updation failed", cause="Invalid nickname or comment"), 400

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE user_id = ?", (user_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return jsonify(message="No user found"), 404

    if nickname is not None:
        cursor.execute("UPDATE users SET nickname = ? WHERE user_id = ?", (nickname or user_id, user_id))
    if comment is not None:
        cursor.execute("UPDATE users SET comment = ? WHERE user_id = ?", (comment, user_id))

    conn.commit()
    conn.close()
    return jsonify(message="User successfully updated", user={"nickname": nickname or user_id, "comment": comment or ""}), 200

@app.route('/close', methods=['POST'])
@auth.login_required
def close_account():
    user_id = auth.current_user()
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE user_id = ?", (user_id,))
    conn.commit()
    conn.close()
    return jsonify(message="Account and user successfully removed"), 200

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
