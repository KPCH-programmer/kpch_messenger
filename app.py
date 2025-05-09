
import sqlite3
from flask import Flask, request, jsonify, render_template, g, session, redirect, url_for
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(
    __name__,
    template_folder='.',
    static_folder='.',
    static_url_path=''
)
app.config['SECRET_KEY'] = 'your-secret-key'
DATABASE = 'chat.db'

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

def init_db():
    db = get_db()
    cur = db.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            from_user TEXT NOT NULL,
            to_user TEXT NOT NULL,
            msg TEXT NOT NULL,
            ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL
        )
    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS group_members (
            group_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            FOREIGN KEY(group_id) REFERENCES groups(id)
        )
    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS group_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id INTEGER NOT NULL,
            from_user TEXT NOT NULL,
            msg TEXT NOT NULL,
            ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(group_id) REFERENCES groups(id)
        )
    ''')
    db.commit()
@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        u = request.form.get('username', '').strip()
        p = request.form.get('password', '').strip()
        if not u or not p:
            error = 'Введите логин и пароль'
        else:
            db = get_db()
            cur = db.cursor()
            cur.execute('SELECT 1 FROM users WHERE username = ?', (u,))
            if cur.fetchone():
                error = 'Логин занят'
            else:
                hashed = generate_password_hash(p)
                cur.execute('INSERT INTO users (username, password) VALUES (?, ?)', (u, hashed))
                db.commit()
                session['username'] = u
                return redirect(url_for('index'))
    return render_template('register.html', error=error)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        u = request.form.get('username', '').strip()
        p = request.form.get('password', '').strip()
        db = get_db()
        cur = db.cursor()
        cur.execute('SELECT password FROM users WHERE username = ?', (u,))
        row = cur.fetchone()
        if row and check_password_hash(row[0], p):
            session['username'] = u
            return redirect(url_for('index'))
        error = 'Неверный логин или пароль'
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

def get_all_users():
    cur = get_db().cursor()
    cur.execute('SELECT username FROM users')
    return [r[0] for r in cur.fetchall()]

@app.route('/')
@login_required
def index():
    me = session['username']
    others = [u for u in get_all_users() if u != me]
    db = get_db()
    cur = db.cursor()
    cur.execute('''
        SELECT g.id, g.name
        FROM groups g
        JOIN group_members m ON g.id = m.group_id
        WHERE m.username = ?
    ''', (me,))
    groups = cur.fetchall()
    return render_template('index.html', username=me, others=others, groups=groups)

@app.route('/create_group', methods=['GET', 'POST'])
@login_required
def create_group():
    me = session['username']
    cur = get_db().cursor()
    cur.execute('SELECT username FROM users')
    possible = [r[0] for r in cur.fetchall()]
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        members = request.form.getlist('members')
        if me not in members:
            members.append(me)
        if not name or not members:
            return render_template('create_group.html', username=me, possible=possible, error='Введите имя и участников')
        db = get_db()
        cur = db.cursor()
        cur.execute('INSERT INTO groups (name) VALUES (?)', (name,))
        gid = cur.lastrowid
        for u in set(members):
            cur.execute('INSERT INTO group_members (group_id, username) VALUES (?, ?)', (gid, u))
        db.commit()
        return redirect(url_for('index'))
    return render_template('create_group.html', username=me, possible=possible)

@app.route('/group/<int:group_id>')
@login_required
def group_chat(group_id):
    me = session['username']
    db = get_db(); cur = db.cursor()
    cur.execute('SELECT 1 FROM group_members WHERE group_id = ? AND username = ?', (group_id, me))
    if not cur.fetchone():
        return redirect(url_for('index'))
    cur.execute('SELECT name FROM groups WHERE id = ?', (group_id,))
    name = cur.fetchone()[0]
    cur.execute('SELECT username FROM group_members WHERE group_id = ?', (group_id,))
    members = [r[0] for r in cur.fetchall()]
    return render_template('group.html', username=me, group_id=group_id, group_name=name, members=members)

@app.route('/group_messages/<int:group_id>', methods=['GET'])
@login_required
def get_group_messages(group_id):
    me = session['username']
    cur = get_db().cursor()
    cur.execute('SELECT 1 FROM group_members WHERE group_id = ? AND username = ?', (group_id, me))
    if not cur.fetchone():
        return jsonify([]), 403
    cur.execute('SELECT from_user, msg FROM group_messages WHERE group_id = ? ORDER BY id', (group_id,))
    rows = cur.fetchall()
    return jsonify([{'username': r[0], 'msg': r[1]} for r in rows])

@app.route('/message/group/<int:group_id>', methods=['POST'])
@login_required
def post_group_message(group_id):
    me = session['username']
    data = request.get_json(force=True)
    msg = data.get('msg', '').strip()
    if not msg:
        return jsonify({"status": "empty"}), 400
    db = get_db(); cur = db.cursor()
    cur.execute('INSERT INTO group_messages (group_id, from_user, msg) VALUES (?, ?, ?)', (group_id, me, msg))
    db.commit()
    return jsonify({"status": "ok"}), 201

@app.route('/chat/<other>')
@login_required
def chat(other):
    if other not in get_all_users():
        return redirect(url_for('index'))
    return render_template('chat.html', username=session['username'], other=other)

@app.route('/messages/<other>', methods=['GET'])
@login_required
def get_messages(other):
    me = session['username']
    db = get_db(); cur = db.cursor()
    cur.execute('''
        SELECT from_user, msg FROM messages
        WHERE (from_user=? AND to_user=?) OR (from_user=? AND to_user=?)
        ORDER BY id
    ''', (me, other, other, me))
    rows = cur.fetchall()
    return jsonify([{'username': r[0], 'msg': r[1]} for r in rows])

@app.route('/message/<other>', methods=['POST'])
@login_required
def post_message(other):
    data = request.get_json(force=True)
    msg = data.get('msg', '').strip()
    if not msg:
        return jsonify({"status": "empty"}), 400
    me = session['username']
    db = get_db(); cur = db.cursor()
    cur.execute('INSERT INTO messages (from_user, to_user, msg) VALUES (?, ?, ?)', (me, other, msg))
    db.commit()
    return jsonify({"status": "ok"}), 201

if __name__ == '__main__':
    with app.app_context():
        init_db()
    app.run(debug=True)
import sqlite3
from flask import Flask, request, jsonify, render_template, g, session, redirect, url_for
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
DATABASE = 'chat.db'

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

def init_db():
    db = get_db()
    cur = db.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            from_user TEXT NOT NULL,
            to_user TEXT NOT NULL,
            msg TEXT NOT NULL,
            ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL
        )
    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS group_members (
            group_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            FOREIGN KEY(group_id) REFERENCES groups(id)
        )
    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS group_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id INTEGER NOT NULL,
            from_user TEXT NOT NULL,
            msg TEXT NOT NULL,
            ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(group_id) REFERENCES groups(id)
        )
    ''')
    db.commit()

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        u = request.form.get('username', '').strip()
        p = request.form.get('password', '').strip()
        if not u or not p:
            error = 'Введите логин и пароль'
        else:
            db = get_db()
            cur = db.cursor()
            cur.execute('SELECT 1 FROM users WHERE username = ?', (u,))
            if cur.fetchone():
                error = 'Логин занят'
            else:
                hashed = generate_password_hash(p)
                cur.execute('INSERT INTO users (username, password) VALUES (?, ?)', (u, hashed))
                db.commit()
                session['username'] = u
                return redirect(url_for('index'))
    return render_template('register.html', error=error)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        u = request.form.get('username', '').strip()
        p = request.form.get('password', '').strip()
        db = get_db()
        cur = db.cursor()
        cur.execute('SELECT password FROM users WHERE username = ?', (u,))
        row = cur.fetchone()
        if row and check_password_hash(row[0], p):
            session['username'] = u
            return redirect(url_for('index'))
        error = 'Неверный логин или пароль'
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

def get_all_users():
    cur = get_db().cursor()
    cur.execute('SELECT username FROM users')
    return [r[0] for r in cur.fetchall()]

@app.route('/')
@login_required
def index():
    me = session['username']
    others = [u for u in get_all_users() if u != me]
    db = get_db()
    cur = db.cursor()
    cur.execute('''
        SELECT g.id, g.name
        FROM groups g
        JOIN group_members m ON g.id = m.group_id
        WHERE m.username = ?
    ''', (me,))
    groups = cur.fetchall()
    return render_template('index.html', username=me, others=others, groups=groups)

@app.route('/create_group', methods=['GET', 'POST'])
@login_required
def create_group():
    me = session['username']
    cur = get_db().cursor()
    cur.execute('SELECT username FROM users')
    possible = [r[0] for r in cur.fetchall()]
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        members = request.form.getlist('members')
        if me not in members:
            members.append(me)
        if not name or not members:
            return render_template('create_group.html', username=me, possible=possible, error='Введите имя и участников')
        db = get_db()
        cur = db.cursor()
        cur.execute('INSERT INTO groups (name) VALUES (?)', (name,))
        gid = cur.lastrowid
        for u in set(members):
            cur.execute('INSERT INTO group_members (group_id, username) VALUES (?, ?)', (gid, u))
        db.commit()
        return redirect(url_for('index'))
    return render_template('create_group.html', username=me, possible=possible)

@app.route('/group/<int:group_id>')
@login_required
def group_chat(group_id):
    me = session['username']
    db = get_db(); cur = db.cursor()
    cur.execute('SELECT 1 FROM group_members WHERE group_id = ? AND username = ?', (group_id, me))
    if not cur.fetchone():
        return redirect(url_for('index'))
    cur.execute('SELECT name FROM groups WHERE id = ?', (group_id,))
    name = cur.fetchone()[0]
    cur.execute('SELECT username FROM group_members WHERE group_id = ?', (group_id,))
    members = [r[0] for r in cur.fetchall()]
    return render_template('group.html', username=me, group_id=group_id, group_name=name, members=members)

@app.route('/group_messages/<int:group_id>', methods=['GET'])
@login_required
def get_group_messages(group_id):
    me = session['username']
    cur = get_db().cursor()
    cur.execute('SELECT 1 FROM group_members WHERE group_id = ? AND username = ?', (group_id, me))
    if not cur.fetchone():
        return jsonify([]), 403
    cur.execute('SELECT from_user, msg FROM group_messages WHERE group_id = ? ORDER BY id', (group_id,))
    rows = cur.fetchall()
    return jsonify([{'username': r[0], 'msg': r[1]} for r in rows])

@app.route('/message/group/<int:group_id>', methods=['POST'])
@login_required
def post_group_message(group_id):
    me = session['username']
    data = request.get_json(force=True)
    msg = data.get('msg', '').strip()
    if not msg:
        return jsonify({"status": "empty"}), 400
    db = get_db(); cur = db.cursor()
    cur.execute('INSERT INTO group_messages (group_id, from_user, msg) VALUES (?, ?, ?)', (group_id, me, msg))
    db.commit()
    return jsonify({"status": "ok"}), 201

@app.route('/chat/<other>')
@login_required
def chat(other):
    if other not in get_all_users():
        return redirect(url_for('index'))
    return render_template('chat.html', username=session['username'], other=other)

@app.route('/messages/<other>', methods=['GET'])
@login_required
def get_messages(other):
    me = session['username']
    db = get_db(); cur = db.cursor()
    cur.execute('''
        SELECT from_user, msg FROM messages
        WHERE (from_user=? AND to_user=?) OR (from_user=? AND to_user=?)
        ORDER BY id
    ''', (me, other, other, me))
    rows = cur.fetchall()
    return jsonify([{'username': r[0], 'msg': r[1]} for r in rows])

@app.route('/message/<other>', methods=['POST'])
@login_required
def post_message(other):
    data = request.get_json(force=True)
    msg = data.get('msg', '').strip()
    if not msg:
        return jsonify({"status": "empty"}), 400
    me = session['username']
    db = get_db(); cur = db.cursor()
    cur.execute('INSERT INTO messages (from_user, to_user, msg) VALUES (?, ?, ?)', (me, other, msg))
    db.commit()
    return jsonify({"status": "ok"}), 201
def get_sidebar_data():
    me = session['username']
    # все другие пользователи
    cur = get_db().cursor()
    cur.execute('SELECT username FROM users WHERE username != ?', (me,))
    others = [r[0] for r in cur.fetchall()]
    # группы, в которых я участник
    cur.execute('''
      SELECT g.id, g.name
      FROM groups g
      JOIN group_members m ON g.id = m.group_id
      WHERE m.username = ?
    ''', (me,))
    groups = cur.fetchall()
    return others, groups

@app.route('/')
@login_required
def index():
    me = session['username']
    others, groups = get_sidebar_data()
    return render_template('index.html',
                           username=me,
                           others=others,
                           groups=groups)

@app.route('/chat/<other>')
@login_required
def chat(other):
    me = session['username']
    if other == me:
        return redirect(url_for('index'))
    # проверим, что такой пользователь есть
    cur = get_db().cursor()
    cur.execute('SELECT 1 FROM users WHERE username = ?', (other,))
    if not cur.fetchone():
        return redirect(url_for('index'))

    # sidebar
    others, groups = get_sidebar_data()
    return render_template('chat.html',
                           username=me,
                           other=other,
                           others=others,
                           groups=groups)

@app.route('/group/<int:group_id>')
@login_required
def group_chat(group_id):
    me = session['username']
    db = get_db(); cur = db.cursor()
    # проверка доступа
    cur.execute('SELECT 1 FROM group_members WHERE group_id=? AND username=?',
                (group_id, me))
    if not cur.fetchone():
        return redirect(url_for('index'))
    # детали группы
    cur.execute('SELECT name FROM groups WHERE id=?', (group_id,))
    name = cur.fetchone()[0]
    cur.execute('SELECT username FROM group_members WHERE group_id=?',
                (group_id,))
    members = [r[0] for r in cur.fetchall()]

    # sidebar
    others, groups = get_sidebar_data()
    return render_template('group.html',
                           username=me,
                           group_id=group_id,
                           group_name=name,
                           members=members,
                           others=others,
                           groups=groups)

if __name__ == '__main__':
    with app.app_context():
        init_db()
    app.run(debug=True)
