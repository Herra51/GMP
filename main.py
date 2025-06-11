from flask import Flask, render_template, jsonify, request, redirect, url_for, session, send_file
import pymysql
import bcrypt
from models.password_generator import PasswordGenerator
from models.generate_kdbx_file import generate_kdbx
import multiprocessing
from functools import wraps
import uuid, os
from dotenv import load_dotenv
from libs.categories_user import get_categories
import hashlib
import secrets
import pyotp
import qrcode
import io

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

@app.route('/generate_password')
def generate_password():
    user_id = session['user_id']
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT password FROM user WHERE id_user = %s", (user_id,))
        user = cursor.fetchone()
    except pymysql.Error as e:
        print(f"An error occurred Mysql: {e}")
        return render_template('index.html', passwords=[], categories=[], error="Erreur MySQL lors de la récupération des mots de passe.", username=session['user_id'])
    except Exception as e:
        print(e)
        return render_template('index.html', passwords=[], categories=[], error="Erreur inattendue lors de la récupération des mots de passe.", username=session['user_id'])
    finally:
        conn.close()
    key = os.getenv('ENCRYPTION_KEY').encode('utf-8')
    password_generator = PasswordGenerator(key)
    multiprocessing.freeze_support()
    with multiprocessing.Pool() as pool:
        encrypted_passwords = pool.map(generate_password_wrapper, [password_generator] * 100)
    return jsonify({"passwords": encrypted_passwords})

def derive_key(password, salt, iterations=100_000):
    # PBKDF2-HMAC-SHA256
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations, dklen=32)

# --- INSCRIPTION ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            # Vérifie si username ou email existe déjà
            cursor.execute("SELECT 1 FROM user WHERE username = %s OR email = %s", (username, email))
            if cursor.fetchone():
                return render_template('auth/register.html', message="Nom d'utilisateur ou email déjà utilisé.")
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            encryption_salt = secrets.token_bytes(16)
            cursor.execute(
                "INSERT INTO user (username, email, password, encryption_salt) VALUES (%s, %s, %s, %s)",
                (username, email, hashed_password, encryption_salt)
            )
            conn.commit()
        except pymysql.Error as e:
            print(f"An error occurred Mysql: {e}")
            return render_template('auth/register.html', message="Erreur MySQL lors de l'inscription.")
        except Exception as e:
            print(e)
            return render_template('auth/register.html', message="Erreur inattendue lors de l'inscription.")
        finally:
            conn.close()
        return redirect(url_for('login'))
    return render_template('auth/register.html')

# --- CONNEXION ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        otp_code = request.form.get('otp_code')  # Peut être None si non envoyé

        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT * FROM user WHERE username = %s", (username,))
            user = cursor.fetchone()
        except pymysql.Error as e:
            print(f"An error occurred Mysql: {e}")
            return render_template('auth/login.html', message='Erreur MySQL')
        except Exception as e:
            print(e)
            return render_template('auth/login.html', message='Erreur inattendue')
        finally:
            conn.close()

        if user:
            stored_password = user.get('password')
            if stored_password and bcrypt.checkpw(password.encode('utf-8'), stored_password.encode('utf-8')):
                otp_secret = user.get('otp_secret')
                # Si l'utilisateur a activé la 2FA
                if otp_secret:
                    # Si le code OTP n'est pas encore soumis, affiche le formulaire OTP
                    if not otp_code:
                        return render_template('auth/otp.html', username=username, password=password)
                    # Vérifie le code OTP
                    if not pyotp.TOTP(otp_secret).verify(otp_code):
                        return render_template('auth/otp.html', username=username, password=password, message='Code 2FA invalide')
                # Authentification réussie
                session['user_id'] = user['id_user']
                # Dérive la clé à partir du mot de passe de connexion et du sel stocké
                salt = user['encryption_salt']
                if isinstance(salt, str):
                    salt = salt.encode('latin1')  # ou base64 decode selon stockage
                derived_key = derive_key(password, salt)
                session['encryption_key'] = derived_key.hex()  # Stocke la clé dérivée (hex) en session
                return redirect(url_for('index'))
            else:
                return render_template('auth/login.html', message='Invalid username or password')
        else:
            return render_template('auth/login.html', message='Invalid username or password')
    return render_template('auth/login.html')

# --- UTILISATION DE LA CLÉ DÉRIVÉE ---
def get_encryption_key():
    # Récupère la clé dérivée depuis la session (hex -> bytes)
    return bytes.fromhex(session['encryption_key'])

# --- AJOUT/MODIF/LECTURE DE MOTS DE PASSE ---
@app.route('/')
@login_required
def index():
    user_id = session['user_id']
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            """SELECT password.id_password, password.platform_name, password.password, password.login, password.url, password.created_at, IFNULL(category_name,'Aucune') as category_name, password_category.id_password_category
            FROM password 
            LEFT JOIN password_category ON password.category_id = password_category.id_password_category
            WHERE password.user_id = (SELECT id_user FROM user WHERE id_user = %s)
            ORDER BY category_name""",
            (user_id,)
        )
        passwords = cursor.fetchall()
        key = get_encryption_key()
        password_generator = PasswordGenerator(key)
        for password in passwords:
            try:
                password['password'] = password_generator.decrypt(password['password']).decode('utf-8')
            except Exception as e:
                password['password'] = f"Error decrypting password: {str(e)}"
        categories = get_categories()
        return render_template('index.html', passwords=passwords, categories=categories, username=session['user_id'])
    except pymysql.Error as e:
        print(f"An error occurred Mysql: {e}")
        return render_template('index.html', passwords=[], categories=[], error="Erreur MySQL lors de la récupération des mots de passe.", username=session['user_id'])
    except Exception as e:
        print(e)
        return render_template('index.html', passwords=[], categories=[], error="Erreur inattendue lors de la récupération des mots de passe.", username=session['user_id'])
    finally:
        conn.close()

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    user_id = session['user_id']
    current_password = request.form['current_password']
    new_password = request.form['new_password']

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Récupérer l'ancien hash et le sel actuel
        cursor.execute("SELECT password, encryption_salt FROM user WHERE id_user = %s", (user_id,))
        user = cursor.fetchone()
        if not user or not bcrypt.checkpw(current_password.encode('utf-8'), user['password'].encode('utf-8')):
            message = "Mot de passe actuel incorrect."
        else:
            # 1. Générer un nouveau sel
            new_salt = secrets.token_bytes(16)
            # 2. Dériver la nouvelle clé
            new_derived_key = derive_key(new_password, new_salt)
            # 3. Dériver l'ancienne clé
            old_salt = user['encryption_salt']
            if isinstance(old_salt, str):
                old_salt = old_salt.encode('latin1')
            old_derived_key = derive_key(current_password, old_salt)
            # 4. Récupérer tous les mots de passe de l'utilisateur
            cursor.execute("SELECT id_password, password FROM password WHERE user_id = %s", (user_id,))
            passwords = cursor.fetchall()
            # 5. Pour chaque mot de passe, déchiffrer avec l'ancienne clé puis ré-encrypter avec la nouvelle
            old_pg = PasswordGenerator(old_derived_key)
            new_pg = PasswordGenerator(new_derived_key)
            for pwd in passwords:
                try:
                    decrypted = old_pg.decrypt(pwd['password'])
                    re_encrypted = new_pg.encrypt(decrypted).decode('utf-8')
                    cursor.execute(
                        "UPDATE password SET password = %s WHERE id_password = %s",
                        (re_encrypted, pwd['id_password'])
                    )
                except Exception as e:
                    print(f"Erreur lors du ré-encryptage du mot de passe {pwd['id_password']} : {e}")
            # 6. Mettre à jour le hash, le nouveau sel et commit
            hashed_new = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
            cursor.execute(
                "UPDATE user SET password = %s, encryption_salt = %s WHERE id_user = %s",
                (hashed_new, new_salt, user_id)
            )
            conn.commit()
            # 7. Mettre à jour la clé dérivée en session
            session['encryption_key'] = new_derived_key.hex()
            message = "Mot de passe modifié avec succès."
    except Exception as e:
        print(e)
        message = "Erreur lors du changement de mot de passe."
    finally:
        conn.close()
    return redirect(url_for('settings', message=message))

@app.route('/parametres', methods=['GET', 'POST'])
@login_required
def settings():
    user_id = session['user_id']
    message = request.args.get('message')
    share_message = None
    show_disable_2fa_form = request.args.get('show_disable_2fa_form', False)
    conn = get_db_connection()
    cursor = conn.cursor()
    if request.method == 'POST':
        # Mise à jour des paramètres de partage
        default_views = int(request.form.get('default_views', 1))
        default_expiry = int(request.form.get('default_expiry', 120))
        cursor.execute(
            "UPDATE user SET default_share_views=%s, default_share_expiry_minutes=%s WHERE id_user=%s",
            (default_views, default_expiry, user_id)
        )
        conn.commit()
        share_message = "Paramètres de partage mis à jour."
    try:
        cursor.execute(
            """
            SELECT category_name, created_at, (SELECT COUNT(*) FROM password WHERE category_id = id_password_category) as password_count
            FROM password_category
            WHERE user_id = %s
            """, (user_id,)
        )
        categories = cursor.fetchall()
        cursor.execute("SELECT default_share_views, default_share_expiry_minutes FROM user WHERE id_user=%s", (user_id,))
        share_settings = cursor.fetchone()
        
        cursor.execute("SELECT otp_secret FROM user WHERE id_user = %s", (user_id,))
        user = cursor.fetchone()
        return render_template(
            'parametres.html',
            categories=categories,
            message=message,
            user=user,
            show_disable_2fa_form=show_disable_2fa_form,
            share_settings={
                'views_left': share_settings['default_share_views'],
                'expiry_minutes': share_settings['default_share_expiry_minutes']
            },
            share_message=share_message
        )
    except pymysql.Error as e:
        print(f"An error occurred Mysql: {e}")
        # On tente de récupérer user et categories même en cas d'erreur
        try:
            cursor.execute("SELECT otp_secret FROM user WHERE id_user = %s", (user_id,))
            user = cursor.fetchone()
        except Exception:
            user = None
        try:
            cursor.execute(
                """
                SELECT category_name, created_at, (SELECT COUNT(*) FROM password WHERE category_id = id_password_category) as password_count
                FROM password_category
                WHERE user_id = %s
                """, (user_id,)
            )
            categories = cursor.fetchall()
        except Exception:
            categories = []
        return render_template(
            'parametres.html',
            categories=categories,
            user=user,
            error="Erreur lors de la récupération des catégories.",
            share_settings={'views_left': 1, 'expiry_minutes': 120}
        )
    except Exception as e:
        print(e)
        try:
            cursor.execute("SELECT otp_secret FROM user WHERE id_user = %s", (user_id,))
            user = cursor.fetchone()
        except Exception:
            user = None
        try:
            cursor.execute(
                """
                SELECT category_name, created_at, (SELECT COUNT(*) FROM password WHERE category_id = id_password_category) as password_count
                FROM password_category
                WHERE user_id = %s
                """, (user_id,)
            )
            categories = cursor.fetchall()
        except Exception:
            categories = []
        return render_template(
            'parametres.html',
            categories=categories,
            user=user,
            error="Une erreur inattendue est survenue.",
            share_settings={'views_left': 1, 'expiry_minutes': 120}
        )
    finally:
        conn.close()

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('encryption_key', None)
    return redirect(url_for('login'))

@app.route('/add_category', methods=['POST'])
@login_required
def add_category():
    if request.method == 'POST':
        category_name = request.form['category_name']
        user_id = session['user_id']
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO password_category (category_name, user_id) VALUES (%s, %s)",
                (category_name, user_id)
            )
            conn.commit()
            return jsonify({"success": True})
        except pymysql.Error as e:
            print(f"An error occurred Mysql: {e}")
            return jsonify({"success": False, "error": str(e)}), 500
        except Exception as e:
            print(e)
            return jsonify({"success": False, "error": str(e)}), 500
        finally:
            conn.close()

@app.route('/add_password', methods=['POST'])
@login_required
def add_password():
    if request.method == 'POST':
        data = request.json
        platform_name = data.get('platform_name')
        password = data.get('password')
        login = data.get('login')
        url = data.get('url')
        user_id = session['user_id']
        category_id = data.get('category_id')
        if not category_id:
            category_id = 0
        password = password.encode('utf-8')
        key = get_encryption_key()
        password_generator = PasswordGenerator(key)
        encrypted = password_generator.encrypt(password).decode('utf-8')

        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(
                """INSERT INTO password (platform_name, password, login, url, user_id, category_id)
                VALUES (%s, %s, %s, %s, (SELECT id_user FROM user WHERE id_user = %s), %s)""",
                (platform_name, encrypted, login, url, user_id, category_id)
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
    user_id = session['user_id']

    # Champs à modifier
    newPassword = data.get('password')
    category_id = data.get('category_id')
    platform_name = data.get('platform_name')
    login = data.get('login')
    url = data.get('url')

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

        # Construction dynamique de la requête UPDATE
        update_fields = []
        update_values = []

        if category_id is not None:
            update_fields.append("category_id = %s")
            update_values.append(category_id)
        if platform_name is not None:
            update_fields.append("platform_name = %s")
            update_values.append(platform_name)
        if login is not None:
            update_fields.append("login = %s")
            update_values.append(login)
        if url is not None:
            update_fields.append("url = %s")
            update_values.append(url)
        if newPassword:
            key = os.getenv('ENCRYPTION_KEY')
            password_generator = PasswordGenerator(key)
            encrypted = password_generator.encrypt(newPassword.encode('utf-8')).decode('utf-8')
            update_fields.append("password = %s")
            update_values.append(encrypted)

        if not update_fields:
            return jsonify({"success": False, "message": "Aucune donnée à modifier"}), 400

        update_values.extend([user_id, idPassword])

        cursor.execute(
            f"""
            UPDATE password
            SET {', '.join(update_fields)}
            WHERE user_id = %s AND id_password = %s
            """,
            tuple(update_values)
        )
        conn.commit()
        return jsonify({"success": True, "message": "Password entry updated successfully"}), 200
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
    user_id = session['user_id']
    conn = get_db_connection()
    cursor = conn.cursor()
    # Récupère les paramètres de partage de l'utilisateur
    cursor.execute("SELECT default_share_views, default_share_expiry_minutes FROM user WHERE id_user=%s", (user_id,))
    user_settings = cursor.fetchone() or {'default_share_views': 1, 'default_share_expiry_minutes': 120}
    views_left = user_settings['default_share_views']
    expiry_minutes = user_settings['default_share_expiry_minutes']
    expires_at = None
    if expiry_minutes and expiry_minutes > 0:
        cursor.execute("SELECT NOW() + INTERVAL %s MINUTE as expires_at", (expiry_minutes,))
        expires_at = cursor.fetchone()['expires_at']
    share_token = str(uuid.uuid4())
    cursor.execute(
        "INSERT INTO shared_password (password_id, share_token, views_left, expires_at) VALUES (%s, %s, %s, %s)",
        (password_id, share_token, views_left, expires_at)
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
        cursor.execute(
            """
            SELECT p.platform_name, p.password, sp.id_shared_password, sp.views_left, sp.expires_at
            FROM shared_password sp
            JOIN password p ON sp.password_id = p.id_password
            WHERE sp.share_token = %s
            """, (share_token,)
        )
        shared_password = cursor.fetchone()
        if not shared_password:
            return render_template('show_password.html', error="Lien invalide ou expiré.")
        # Vérifie expiration
        if shared_password['expires_at']:
            cursor.execute("SELECT NOW() as now")
            now = cursor.fetchone()['now']
            if shared_password['expires_at'] < now:
                cursor.execute("DELETE FROM shared_password WHERE id_shared_password = %s", (shared_password['id_shared_password'],))
                conn.commit()
                return render_template('show_password.html', error="Lien expiré.")
        # Vérifie le nombre de vues (sauf si illimité)
        if shared_password['views_left'] == 0:
            cursor.execute("DELETE FROM shared_password WHERE id_shared_password = %s", (shared_password['id_shared_password'],))
            conn.commit()
            return render_template('show_password.html', error="Lien expiré ou nombre de vues dépassé.")
        # Décrypte le mot de passe
        key = get_encryption_key() if 'encryption_key' in session else None
        if not key:
            return render_template('show_password.html', error="Session expirée, veuillez vous reconnecter.")
        password_generator = PasswordGenerator(key)
        try:
            decrypted_password = password_generator.decrypt(shared_password['password']).decode('utf-8')
        except Exception as e:
            decrypted_password = f"Erreur lors du déchiffrement : {str(e)}"
        # Décrémente views_left si pas illimité
        if shared_password['views_left'] > 0:
            cursor.execute(
                "UPDATE shared_password SET views_left = views_left - 1 WHERE id_shared_password = %s",
                (shared_password['id_shared_password'],)
            )
            # Supprime si on arrive à 0
            cursor.execute(
                "DELETE FROM shared_password WHERE id_shared_password = %s AND views_left = 0",
                (shared_password['id_shared_password'],)
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
    
    try:
        if not category_id:
            cursor.execute(
                """
                SELECT password.id_password, password.platform_name, password.password, password.login, password.url, password.created_at, IFNULL(category_name,'Aucune') as category_name
                FROM password 
                LEFT JOIN password_category ON password.category_id = password_category.id_password_category
                WHERE password.user_id = (SELECT id_user FROM user WHERE id_user = %s)
                ORDER BY category_name
                """, (user_id,)
            )
        else:
            cursor.execute(
                """
                SELECT password.id_password, password.platform_name, password.password, password.login, password.url, password.created_at, IFNULL(category_name,'') as category_name
                FROM password 
                LEFT JOIN password_category ON password.category_id = password_category.id_password_category
                WHERE password.category_id = %s AND password.user_id = (SELECT id_user FROM user WHERE id_user = %s)
                """, (category_id, user_id)
            )
        passwords = cursor.fetchall()
        key = get_encryption_key()
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

@app.route('/generate_kdbx', methods=['POST'])
@login_required
def generate_kdbx_route():
    user_id = session['user_id']
    data = request.get_json()  # Récupérer les données du corps de la requête
    password = data.get('password')  # Extraire le mot de passe du JSON
    
    if not password:
        return jsonify({"error": "Password is required"}), 400
    
    
    
    return generate_kdbx(user_id, get_db_connection(), password, get_encryption_key())


@app.route('/rename_category', methods=['POST'])
@login_required
def rename_category():
    data = request.get_json()
    cat_id = data.get('id')
    new_name = data.get('new_name')
    user_id = session['user_id']
    if not cat_id or not new_name:
        return jsonify({'success': False, 'error': 'Données manquantes'}), 400
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "UPDATE password_category SET category_name = %s WHERE id_password_category = %s AND user_id = %s",
            (new_name, cat_id, user_id)
        )
        conn.commit()
        return jsonify({'success': True})
    except Exception as e:
        print(e)
        return jsonify({'success': False, 'error': 'Erreur lors du renommage'}), 500
    finally:
        conn.close()

@app.route('/delete_category', methods=['POST'])
@login_required
def delete_category():
    data = request.get_json()
    cat_id = data.get('id')
    user_id = session['user_id']
    if not cat_id:
        return jsonify({'success': False, 'error': 'ID manquant'}), 400
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "DELETE FROM password_category WHERE id_password_category = %s AND user_id = %s",
            (cat_id, user_id)
        )
        conn.commit()
        return jsonify({'success': True})
    except Exception as e:
        print(e)
        return jsonify({'success': False, 'error': 'Erreur lors de la suppression'}), 500
    finally:
        conn.close()

import base64

@app.route('/enable_2fa', methods=['GET', 'POST'])
@login_required
def enable_2fa():
    user_id = session['user_id']
    conn = get_db_connection()
    cursor = conn.cursor()
    qrcode_data = None
    otp_secret = None
    message = None

    if request.method == 'POST':
        # ... ton code existant ...
        pass  # (garde le reste de ton code ici)
    else:
        session.pop('otp_secret_tmp', None)

    # Récupère les catégories et l'état 2FA pour affichage
    cursor.execute(
        """
        SELECT category_name, created_at, (SELECT COUNT(*) FROM password WHERE category_id = id_password_category) as password_count
        FROM password_category
        WHERE user_id = %s
        """, (user_id,)
    )
    categories = cursor.fetchall()
    cursor.execute("SELECT otp_secret FROM user WHERE id_user = %s", (user_id,))
    user = cursor.fetchone()
    cursor.execute("SELECT default_share_views, default_share_expiry_minutes FROM user WHERE id_user=%s", (user_id,))
    share_settings = cursor.fetchone() or {'default_share_views': 1, 'default_share_expiry_minutes': 120}
    conn.close()

    return render_template(
        'parametres.html',
        categories=categories,
        user=user,
        qrcode_data=qrcode_data,
        otp_secret=otp_secret,
        message=message,
        share_settings={
            'views_left': share_settings['default_share_views'],
            'expiry_minutes': share_settings['default_share_expiry_minutes']
        }
    )

@app.route('/disable_2fa', methods=['POST', 'GET'])
@login_required
def disable_2fa():
    user_id = session['user_id']
    message = None

    if request.method == 'POST':
        otp_code = request.form.get('otp_code')
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT otp_secret FROM user WHERE id_user = %s", (user_id,))
        user = cursor.fetchone()
        if user and user['otp_secret']:
            totp = pyotp.TOTP(user['otp_secret'])
            if totp.verify(otp_code):
                cursor.execute("UPDATE user SET otp_secret = NULL WHERE id_user = %s", (user_id,))
                conn.commit()
                conn.close()
                message = "Double authentification désactivée avec succès."
                return redirect(url_for('settings', message=message))
            else:
                message = "Code 2FA incorrect."
        else:
            message = "Aucune double authentification activée."
        conn.close()
        # Affiche à nouveau le formulaire avec le message d'erreur
        return render_template(
            'parametres.html',
            categories=get_categories(),
            user=user,
            show_disable_2fa_form=True,
            message=message
        )
    else:
        # Affiche le formulaire pour entrer le code 2FA
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT otp_secret FROM user WHERE id_user = %s", (user_id,))
        user = cursor.fetchone()
        conn.close()
        return render_template(
            'parametres.html',
            categories=get_categories(),
            user=user,
            show_disable_2fa_form=True,
            message=message
        )

if __name__ == '__main__':
    app.run(debug=True)