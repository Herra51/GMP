from collections import defaultdict
from flask import request, jsonify
from pykeepass import create_database, PyKeePass
from .password_generator import PasswordGenerator

def generate_kdbx(user_id,bdd_connection,master_password):
    try:
        # Récupérer l'ID utilisateur depuis les données POST
        if not user_id:
            return jsonify({'error': 'User ID is required'}), 400

        # récupère les infos en base de données
        
        # Exemple de récupération d'informations utilisateur depuis la base de données
        cursor = bdd_connection.cursor()
        query = """SELECT 
                    password.id_password
                    , IFNULL(password.platform_name,'') AS platform_name 
                    , password.login
                    , password.password
                    , password.created_at
                    ,IFNULL(category_name,'Aucune') as category_name
                FROM 
                    password 
                LEFT JOIN password_category ON password.category_id = password_category.id_password_category
                WHERE 
                    password.user_id = (SELECT id_user FROM user WHERE id_user = %s)
                ORDER BY 
                    category_name """
        cursor.execute(query, (user_id,))
        user_credentials = cursor.fetchall()
        if not user_credentials:
            return jsonify({'error': 'No credentials found for this user'}), 404

        cursor.close()
        # Regrouper les données par category_name
        grouped_data = defaultdict(list)
        for credential in user_credentials:
            print(credential)
            grouped_data[credential['category_name']].append({
                'id_password': credential['id_password'],
                'platform_name': credential['platform_name'],
                'login': credential['login'],  # on remplace login par username
                'password': credential['password'],
                'created_at': credential['created_at']
                
            })
            # grouped_data[credential['category_name']].append({
            #     'id_password': credential['id_password'],
            #     'platform_name': credential['platform_name'],
            #     'username': credential['login'],  # on remplace login par username
            #     'password': credential['password'],
            #     'created_at': credential['created_at']
            # })
        # Chemin du fichier .kdbx à créer (inclure l'ID utilisateur dans le nom)
        kdbx_file = f'user_{user_id}.kdbx'

        # Créer un nouveau fichier KeePass
        create_database(kdbx_file, password=master_password)

        # Charger le fichier KeePass pour y ajouter des entrées
        kp = PyKeePass(kdbx_file, password=master_password)
        
        # Ajouter les groupes et les entrées dans le fichier KeePass
        for category, credentials in grouped_data.items():
            print(f'Adding group: {category}')
            print(credentials)
            group = kp.add_group(kp.root_group, category)
            for credential in credentials:
                print(f'Adding entry: {credential["platform_name"]}')
                print(credential)
                try:
                    decrypted_password = PasswordGenerator.decrypt(credential['password'])
                except Exception as e:
                    print(f"Error decrypting password for {credential['platform_name']}: {e}")
                    decrypted_password = ''  # ou continue pour ignorer cette entrée
                print(f'Decrypted password: {decrypted_password}')
                kp.add_entry(
                    group,
                    title=credential['platform_name'],
                    username=credential['login'],
                    password=decrypted_password
                )
        # Sauvegarder les modifications
        kp.save()
        print(f'KeePass file generated: {kdbx_file}')
        return jsonify({'message': f'KeePass file generated: {kdbx_file}'}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500
