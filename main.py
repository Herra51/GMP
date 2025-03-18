from flask import Flask, render_template, jsonify, request, redirect, url_for, session
import pymysql
import bcrypt
from models.password_generator import PasswordGenerator
import multiprocessing
from functools import wraps
import uuid
import base64

app = Flask(__name__)
app.secret_key = '0arzghBRjO5eANgqXvyEd7/EZsYejnV5z3bQkiPQYw4='

def get_db_connection():
    return pymysql.connect(
        host='localhost',
        user='root',
        password='root',
        database='GMP',
        cursorclass=pymysql.cursors.DictCursor
    )

def generate_password_wrapper(pg):
    return pg.generate_encrypted_password()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
@login_required
def home():
    return render_template('index.html', username=session['username'])

@app.route('/generate_password')
def generate_password():
    password_generator = PasswordGenerator()
    multiprocessing.freeze_support()
    with multiprocessing.Pool() as pool:
        encrypted_passwords = pool.map(generate_password_wrapper, [password_generator] * 100)
    return jsonify({"passwords": encrypted_passwords})

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO user (username, email, password) VALUES (%s, %s, %s)", (username, email, hashed_password))
            conn.commit()
        except pymysql.Error as e:
            print(f"An error occurred Mysql: {e}")
        except Exception as e:
            print(e)
        finally:
            conn.close()

        return redirect(url_for('login'))
    return render_template('auth/register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT * FROM user WHERE username = %s", (username,))
            user = cursor.fetchone()
        except pymysql.Error as e:
            print(f"An error occurred Mysql: {e}")
        except Exception as e:
            print(e)
        finally:
            conn.close()

        if user and bcrypt.checkpw(password.encode('utf-8'), user[3].encode('utf-8')):
            session['username'] = user[1]
            return redirect(url_for('home'))
        return 'Invalid username or password'
    return render_template('auth/login.html')


@app.route('/password_list')
@login_required
def password_list():
    username = session['username']
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            """SELECT platform_name, password, created_at
            FROM password WHERE user_id = (SELECT id_user FROM user WHERE username = %s)""",
            (username,)
        )
        passwords = cursor.fetchall()
        # Decrypt passwords
                # Decrypt passwords
        key = "a" * 32  # Use the same key as in the add_password route
        password_generator = PasswordGenerator(key)
        for password in passwords:
            try:
                # Directly decrypt the base64-encoded password
                password['password'] = password_generator.decrypt(password['password']).decode('utf-8')
            except Exception as e:
                password['password'] = f"Error decrypting password: {str(e)}"
    except pymysql.Error as e:
        print(f"An error occurred Mysql: {e}")
    except Exception as e:
        print(e)
    finally:
        conn.close()
    return render_template('password_list.html', passwords=passwords)

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))


@app.route('/add_password', methods=['POST'])
@login_required
def add_password():
    if request.method == 'POST':
        data = request.json
        platform_name = data.get('platform_name')
        password = data.get('password')
        username = session['username']

        # Convert the password to bytes
        password = password.encode('utf-8')
        key = "a" * 32
        password_generator = PasswordGenerator(key)
        encrypted = password_generator.encrypt(password).decode('utf-8')  # Decode to store as a string

        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(
                """INSERT INTO password (platform_name, password, user_id)
                VALUES (%s, %s, (SELECT id_user FROM user WHERE username = %s))""",
                (platform_name, encrypted, username)
            )
            conn.commit()
        except pymysql.Error as e:
            print(f"An error occurred Mysql: {e}")
        except Exception as e:
            print(e)
        finally:
            conn.close()

        return jsonify({"message": "Password added successfully"}), 201

@app.route('/share_password/<int:password_id>', methods=['POST'])
@login_required
def share_password(password_id):
    share_token = str(uuid.uuid4())  # Génère un token unique
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO shared_password (password_id, share_token) VALUES (%s, %s)",
        (password_id, share_token)
    )
    conn.commit()
    conn.close()
    share_link = f"{request.host_url}shared/{share_token}"
    return jsonify({"share_link": share_link})


@app.route('/shared/<share_token>', methods=['GET'])
def get_shared_password(share_token):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "SELECT p.password FROM password p "
            "JOIN shared_password sp ON p.id_password = sp.password_id "
            "WHERE sp.share_token = %s",
            (share_token,)
        )
        shared_password = cursor.fetchone()
        if not shared_password:
            return "Invalid or expired link", 404
        # Delete the shared password after it has been accessed
        cursor.execute(
            "DELETE FROM shared_password WHERE share_token = %s",
            (share_token,)
        )
        conn.commit()
    except pymysql.Error as e:
        print(f"An error occurred Mysql: {e}")
    except Exception as e:
        print(e)
    finally:
        conn.close()

    if shared_password:
        return jsonify({"password": shared_password[0]})
    return "Invalid or expired link", 404


if __name__ == '__main__':
    app.run(debug=True)