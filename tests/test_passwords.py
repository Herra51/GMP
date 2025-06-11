import unittest
from main import app

class PasswordsTestCase(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        self.client = app.test_client()
        # Simuler une session utilisateur connectée
        with self.client.session_transaction() as sess:
            sess['user_id'] = 1  # Remplace 1 par un id_user valide dans ta base de test

    def test_index_requires_login(self):
        # Déconnexion pour tester la redirection
        with self.client.session_transaction() as sess:
            sess.pop('user_id', None)
        response = self.client.get('/', follow_redirects=True)
        self.assertIn(b'Login', response.data)

    def test_index_page_loads(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'category', response.data)  # À adapter selon le contenu réel de la page

if __name__ == '__main__':
    unittest.main()