
from django_ldap_pixiedust import sync
from django.test import TestCase
from django_auth_ldap.tests import TestSettings

from django.contrib.auth.models import User, Group

from fixtures import mock_ldap
from django_auth_ldap import backend

backend.LDAPBackend.ldap = mock_ldap

from django_ldap_pixiedust import settings

class TestUserSync(TestCase):
    
    def setUp(self):
        settings.ldap_settings = TestSettings(
            AUTH_PROFILE_MODULE='django_ldap_pixiedust.PixieDustTestProfile',
            AUTH_LDAP_USER_ATTR_MAP = {
                'email': 'mail',
                },
            AUTH_LDAP_PROFILE_ATTR_MAP = {
                'location': 'location',
                },
        )
        sync.activate(True, True, True)
        
    def tearDown(self):
        sync.deactivate()
    
    def test_create_new_user(self):
        mock_ldap.reset()
        u = User(username="fred",
                 email="foo@example.com",
                 password="sha1$SALT$4242",
                 )
        u.save()
        self.assertEqual(mock_ldap.ldap_methods_called(), [
            'initialize',
            'simple_bind_s',
            'search_s',
            'add_s',
        ])
        self.assertEqual(mock_ldap.ldap_methods_called_with_arguments()[3][1], {
            'who': 'uid=fred,ou=users,dc=test',
            'attrs': [
                ('objectClass', ['organizationalPerson', 'inetOrgPerson']),
                ('mail', ['foo@example.com']),
                ('userPassword', ['{SSHA}QkJTQUxU']),
            ]})
        
    def test_create_existing_user(self):
        mock_ldap.reset()
        u = User(username="bob",
                 email="foo@example.com",
                 password="sha1$SALT$4242",
                 )
        u.save()
        self.assertEqual(mock_ldap.ldap_methods_called(), [
            'initialize',
            'simple_bind_s',
            'search_s',
            'search_s',
            'modify_s',
        ])
        
    def test_update_user(self):
        u = User(username="bill",
                 email="foo@example.com",
                 password="sha1$SALT$4242",
                 )
        u.save()
        mock_ldap.reset()
        mock_ldap.set_return_value('search_s', 
                                   ('uid=bill,ou=users,dc=test',
                                    0,
                                    '(objectClass=*)',
                                    None,
                                    0), [('uid=bill,ou=users,dc=test',[
                                        ('objectClass', ['organizationalPerson', 'inetOrgPerson']),
                                        ('mail', ['foo@example.com']),
                                        ('userPassword', ['{SSHA}QkJTQUxU']),
                                        ])])
                                   
        u.email = 'bar@example.com'
        u.save()
        self.assertEqual(mock_ldap.ldap_methods_called(), ['initialize', 'simple_bind_s', 'search_s', 'search_s', 'modify_s'])
        self.assertEqual(mock_ldap.ldap_methods_called_with_arguments()[4][1], {
            'who': 'uid=bill,ou=users,dc=test',
            'attrs': [(1, 'mail', None), (0, 'mail', ['bar@example.com'])]
            })
        
    def test_update_user_profile(self):
        u = User(username="bill",
                 email="foo@example.com",
                 password="sha1$SALT$4242",
                 )
        u.save()
        profile = u.get_profile()
        profile.location = "London"
        profile.save()
        

        
