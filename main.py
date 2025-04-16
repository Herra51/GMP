from flask import Flask, render_template, jsonify, request, redirect, url_for, session
import pymysql
import bcrypt
from models.password_generator import PasswordGenerator
import multiprocessing
from functools import wraps
import uuid, os
from dotenv import load_dotenv
from libs.categories_user import get_categories
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')

def get_db_connection():
    return pymysql.connect(
        host=os.getenv('DB_HOST'),
        user=os.getenv('DB_USER'),
        password=os.getenv('DB_PASSWORD'),
        database=os.getenv('DB_DATABASE'),
        cursorclass=pymysql.cursors.DictCursor
    )

def generate_password_wrapper(pg):
    return pg.generate_encrypted_password()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
@login_required
def home():
    return render_template('index.html', username=session['user_id'])

@app.route('/generate_password')
def generate_password():
    key = os.getenv('ENCRYPTION_KEY').encode('utf-8')
    password_generator = PasswordGenerator(key)
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
        if user and bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            session['user_id'] = user['id_user']
            print(user['id_user'])
            return redirect(url_for('home'))
        return render_template('auth/login.html', message='Invalid username or password')
    return render_template('auth/login.html')

# Route to get all passwords
@app.route('/password_list')
@login_required
def password_list():
    user_id = session['user_id']
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            """SELECT password.id_password, password.platform_name, password.password, password.created_at,IFNULL(category_name,'') as category_name
            FROM password 
            LEFT JOIN password_category ON password.category_id = password_category.id_password_category
            WHERE password.user_id = (SELECT id_user FROM user WHERE id_user = %s)
            ORDER BY category_name""",
            (user_id,)
        )
        passwords = cursor.fetchall()
        key = os.getenv('ENCRYPTION_KEY').encode('utf-8')
        password_generator = PasswordGenerator(key)
        for password in passwords:
            try:
                # Directly decrypt the base64-encoded password
                password['password'] = password_generator.decrypt(password['password']).decode('utf-8')
            except Exception as e:
                password['password'] = f"Error decrypting password: {str(e)}"
        categories = get_categories()
        print("passwords", passwords)
        print("categories", categories)
        return render_template('password_list.html', passwords=passwords, categories=categories)
    except pymysql.Error as e:
        print(f"An error occurred Mysql: {e}")
    except Exception as e:
        print(e)
    finally:
        conn.close()

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))


@app.route('/add_password', methods=['POST'])
@login_required
def add_password():
    if request.method == 'POST':
        data = request.json
        platform_name = data.get('platform_name')
        password = data.get('password')
        user_id = session['user_id']
        category_id = data.get('category_id')
        if not category_id:
            category_id = 0
        # Convert the password to bytes
        password = password.encode('utf-8')
        key = os.getenv('ENCRYPTION_KEY')
        password_generator = PasswordGenerator(key)
        encrypted = password_generator.encrypt(password).decode('utf-8')

        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(
                """INSERT INTO password (platform_name, password, user_id, category_id)
                VALUES (%s, %s, (SELECT id_user FROM user WHERE id_user = %s), %s)""",
                (platform_name, encrypted, user_id, category_id)
            )
            conn.commit()
        except pymysql.Error as e:
            print(f"An error occurred Mysql: {e}")
        except Exception as e:
            print(e)
        finally:
            conn.close()

        return jsonify({"success": True, "message": "Password added successfully"}), 201

# Route to edit a password
@app.route('/edit', methods=['PUT'])
@login_required
def edit_password():
    data = request.get_json()
    idPassword = data.get('id')
    newPassword = data.get('password')
    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            SELECT * FROM user
            WHERE id_user = %s
            """, (user_id,)
        )
        user = cursor.fetchone()
        if not user:
            return jsonify({"success": False, "message": "User not found"}), 404
        
        password = newPassword.encode('utf-8')
        key = os.getenv('ENCRYPTION_KEY')
        password_generator = PasswordGenerator(key)
        encrypted = password_generator.encrypt(password).decode('utf-8')

        cursor.execute(
            """
            UPDATE password
            SET password = %s
            WHERE user_id = %s AND id_password = %s
            """, (encrypted, user_id, idPassword)
        )
        conn.commit()
        return jsonify({"success": True, "message": "Password updated successfully"}), 200
    except pymysql.Error as e:
        print(f"An error occurred Mysql: {e}")
        return jsonify({"success": False, "message": "Database error"}), 500
    except Exception as e:
        print(e)
        return jsonify({"success": False, "message": "An unexpected error occurred"}), 500
    finally:
        conn.close()

# Route to delete a password
@app.route('/delete', methods=['DELETE'])
@login_required
def delete_password():
    data = request.get_json()
    idPassword = data.get('id')
    user_id = session['user_id']
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT * FROM user
            WHERE id_user = %s
            """, (user_id,)
        )
        user = cursor.fetchone()
        if not user:
            print("User not found")
            return jsonify({"success": False, "message": "User not found"}), 404

        cursor.execute(
            """
            DELETE FROM password
            WHERE user_id = %s AND id_password = %s
            """, (user_id, idPassword)
        )
        conn.commit()
        return jsonify({"success": True, "message": "Password deleted successfully"}), 200
    except pymysql.Error as e:
        print(f"An error occurred Mysql: {e}")
        return jsonify({"success": False, "message": "Database error"}), 500
    except Exception as e:
        print(e)
        return jsonify({"success": False, "message": "An unexpected error occurred"}), 500
    finally:
        conn.close()


@app.route('/share_password', methods=['POST'])
@login_required
def share_password():
    data = request.get_json()
    password_id = data.get('id')
    share_token = str(uuid.uuid4())
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO shared_password (password_id, share_token) VALUES (%s, %s)",
        (password_id, share_token)
    )
    conn.commit()
    conn.close()
    share_link = f"{request.host_url}shared/{share_token}"
    return jsonify({"success": True, "share_link": share_link})


@app.route('/shared/<share_token>', methods=['GET'])
def get_shared_password(share_token):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Récupérer le mot de passe partagé
        cursor.execute(
            """
            SELECT p.platform_name, p.password, sp.id_shared_password
            FROM shared_password sp
            JOIN password p ON sp.password_id = p.id_password
            WHERE sp.share_token = %s
            """, (share_token,)
        )
        shared_password = cursor.fetchone()
        if not shared_password:
            return render_template('show_password.html', error="Lien invalide ou expiré.")
        
        # Déchiffrer le mot de passe
        key = os.getenv('ENCRYPTION_KEY').encode('utf-8')
        password_generator = PasswordGenerator(key)
        try:
            decrypted_password = password_generator.decrypt(shared_password['password']).decode('utf-8')
        except Exception as e:
            decrypted_password = f"Erreur lors du déchiffrement : {str(e)}"
        
        # Supprimer le lien de partage après utilisation
        cursor.execute(
            """
            DELETE FROM shared_password
            WHERE id_shared_password = %s
            """, (shared_password['id_shared_password'],)
        )
        conn.commit()

        return render_template('show_password.html', platform=shared_password['platform_name'], password=decrypted_password)
    except Exception as e:
        print(e)
        return render_template('show_password.html', error="Une erreur est survenue.")
    finally:
        conn.close()


@app.route('/filter_passwords', methods=['POST'])
@login_required
def filter_passwords():
    data = request.get_json()  # Retrieve JSON data from the POST request
    category_id = data.get('category')  # Extract 'category' from the JSON body
    user_id = session['user_id']
    conn = get_db_connection()
    cursor = conn.cursor()
    
    print("category_id", category_id)
    print("user_id", user_id)
    try:
        if not category_id:
            cursor.execute(
                """
                SELECT password.id_password, password.platform_name, password.password, password.created_at,IFNULL(category_name,'') as category_name
                FROM password 
                LEFT JOIN password_category ON password.category_id = password_category.id_password_category
                WHERE password.user_id = (SELECT id_user FROM user WHERE id_user = %s)
                ORDER BY category_name
                """, (user_id,)
            )
        else:
            cursor.execute(
                """
                SELECT password.id_password, password.platform_name, password.password, password.created_at,IFNULL(category_name,'') as category_name
                FROM password 
                LEFT JOIN password_category ON password.category_id = password_category.id_password_category
                WHERE password.category_id = %s AND password.user_id = (SELECT id_user FROM user WHERE id_user = %s)
                """, (category_id, user_id)
            )
        passwords = cursor.fetchall()
        key = os.getenv('ENCRYPTION_KEY').encode('utf-8')
        password_generator = PasswordGenerator(key)
        for password in passwords:
            try:
                # Directly decrypt the base64-encoded password
                password['password'] = password_generator.decrypt(password['password']).decode('utf-8')
            except Exception as e:
                password['password'] = f"Error decrypting password: {str(e)}"
        return jsonify({"passwords": passwords})  # Return JSON response
    except pymysql.Error as e:
        print(f"An error occurred Mysql: {e}")
        return jsonify({"error": "Database error"}), 500
    except Exception as e:
        print(e)
        return jsonify({"error": "An unexpected error occurred"}), 500
    finally:
        conn.close()
        
if __name__ == '__main__':
    app.run(debug=True)