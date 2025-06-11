# GMP – Gestionnaire de Mots de Passe

GMP est une application web Flask permettant de gérer, stocker et partager vos mots de passe de manière sécurisée.  
Elle propose la génération, le chiffrement, la catégorisation et l’export de vos mots de passe.

## Fonctionnalités

- **Authentification sécurisée** (bcrypt)
- **Ajout, modification, suppression** de mots de passe
- **Catégorisation** des mots de passe
- **Générateur de mots de passe** robuste
- **Partage de mot de passe** via lien à usage unique
- **Export KeePass (.kdbx)**
- **Historisation** des modifications (triggers SQL)
- **Interface web responsive** (Bootstrap)

## Installation

1. **Cloner le dépôt**
   ```sh
   git clone https://github.com/Herra51/GMP
   cd GMP
   ```

2. **Installer les dépendances**
   ```sh
   pip install -r requirements.txt
   ```

3. **Configurer les variables d’environnement**

   Crée un fichier `.env` à la racine :
   ```
   SECRET_KEY=une_clé_secrète
   DB_HOST=localhost
   DB_USER=ton_utilisateur
   DB_PASSWORD=ton_mot_de_passe
   DB_DATABASE=nom_de_la_base
   ENCRYPTION_KEY=une_clé_AES_16_24_ou_32_bytes
   ```

4. **Initialiser la base de données**

   Exécute le script SQL :
   ```sh
   mysql -u <user> -p < ./sql/bd.sql
   ```

   Pour l’historisation :
   ```sh
   mysql -u <user> -p < ./sql/procedure_historisation.sql
   ```

5. **Lancer l’application**
   ```sh
   python main.py
   ```

   Accède à [http://localhost:5000](http://localhost:5000)

## Structure du projet

```
.
├── main.py
├── models/
├── libs/
├── templates/
├── tests/
├── requirements.txt
├── .env
├── sql/
│   ├── bd.sql
│   └── procedure_historisation.sql
└── README.md
```

## Tests

Lance les tests unitaires avec :
```sh
python -m unittest discover tests
```

## Technologies

- Python, Flask
- PyMySQL, bcrypt, python-dotenv
- PyCryptodome (AES)
- PyKeePass (export .kdbx)
- Bootstrap

## Sécurité

- Les mots de passe sont chiffrés en AES (clé dans `.env`)
- Les mots de passe utilisateurs sont hashés avec bcrypt
- Les liens de partage sont à usage unique

## Auteurs

- Valentin
- Cantin

---

**Licence** : MIT