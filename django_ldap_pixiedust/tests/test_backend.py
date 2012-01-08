
from django_auth_ldap.config import LDAPSearch
from django_auth_ldap.backend import LDAPBackend, _LDAPUser

from django_ldap_pixiedust import settings
from django_ldap_pixiedust import backend
from django_ldap_pixiedust import sync

from .fixtures import mock_ldap, LDAPTest, TestSettings
from . import fixtures

class TestLDAPUser(_LDAPUser):
    pass

class DecoupledBackend(backend.DecoupledUserClassMixin, LDAPBackend):
    userclass = TestLDAPUser
    ldap = mock_ldap
    
class TestDecoupledUserClassMixin(LDAPTest):

    def setUp(self):
        LDAPTest.setUp(self)
        self.backend = DecoupledBackend()

    def test_authenticate(self):
        sync.activate(sync_user=False, sync_groups=False, sync_profile=False)
        self._init_settings(
            AUTH_LDAP_USER_DN_TEMPLATE = "uid=%(user)s,ou=users,dc=test",
            AUTH_LDAP_USER_ATTR_MAP = { 'email': 'mail'},
            )
        self.mock_ldap.set_return_value('simple_bind_s',
                                        ('uid=bob,ou=users,dc=test', 'password2'), None)
        user = self.backend.authenticate('bob', 'password2')
        self.failUnless(isinstance(user.ldap_user, TestLDAPUser))
        

backend.EmailLoginBackend.ldap = mock_ldap

class TestEmailLogin(LDAPTest):

    def setUp(self):
        LDAPTest.setUp(self)
        self.backend = backend.EmailLoginBackend()

    def test_authenticate(self):
        sync.activate(sync_user=False, sync_groups=False, sync_profile=False)
        self._init_settings(
            LDAP_PIXIEDUST_LOGIN_SEARCH=LDAPSearch("ou=users,dc=test",
                                                      self.mock_ldap.SCOPE_ONELEVEL,
                                                      '(mail=%(user)s)'),
            AUTH_LDAP_USER_DN_TEMPLATE = "uid=%(user)s,ou=users,dc=test",
            AUTH_LDAP_USER_ATTR_MAP = { 'email': 'mail'},
            )
        self.mock_ldap.set_return_value('search_s',
            ('ou=users,dc=test',
             self.mock_ldap.SCOPE_ONELEVEL,
             "(mail=bob@example.com)", None, 0),
            [fixtures.bob])
        self.mock_ldap.set_return_value('simple_bind_s',
                                        ('uid=bob,ou=users,dc=test', 'password2'), None)
        user = self.backend.authenticate('bob@example.com', 'password2')
        self.assertEqual(user.username, u'bob')
        self.assertEqual(user.email, u'bob@example.com')

        