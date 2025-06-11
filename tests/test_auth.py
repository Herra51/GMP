import unittest
from main import app

class AuthTestCase(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        self.client = app.test_client()

    def test_login_page_loads(self):
        response = self.client.get('/login')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Login', response.data)

    def test_register_page_loads(self):
        response = self.client.get('/register')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Register', response.data)

    # Exemple de test d'échec de connexion
    def test_login_fail(self):
        response = self.client.post('/login', data={
            'username': 'wronguser',
            'password': 'wrongpass'
        }, follow_redirects=True)
        self.assertIn(b'Invalid username or password', response.data)

if __name__ == '__main__':
    unittest.main()