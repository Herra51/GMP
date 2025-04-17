from collections import defaultdict
from flask import request, jsonify
from pykeepass import create_database, PyKeePass
def generate_kdbx(user_id,bdd_connection):
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
            
        cursor.close()
        # Regrouper les données par category_name
        grouped_data = defaultdict(list)
        for credential in user_credentials:
            grouped_data[credential['category_name']].append({
                'id_password': credential['id_password'],
                'platform_name': credential['platform_name'],
                'login': credential['login'],
                'password': credential['password'],
                'created_at': credential['created_at']
            })
        # Chemin du fichier .kdbx à créer (inclure l'ID utilisateur dans le nom)
        kdbx_file = f'user_{user_id}.kdbx'
        master_password = '1234'

        # Créer un nouveau fichier KeePass
        create_database(kdbx_file, password=master_password)

        # Charger le fichier KeePass pour y ajouter des entrées
        kp = PyKeePass(kdbx_file, password=master_password)

        # Ajouter les groupes et les entrées dans le fichier KeePass
        for category, credentials in grouped_data.items():
            group = kp.add_group(kp.root_group, category)
            for credential in credentials:
                kp.add_entry(
                    group,
                    title=credential['platform_name'],
                    username=f"user_{credential['id_password']}",
                    password=credential['password']
                )
        # Sauvegarder les modifications
        kp.save()
        print(f'KeePass file generated: {kdbx_file}')
        return jsonify({'message': f'KeePass file generated: {kdbx_file}'}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500
