from django_auth_ldap.tests import TestSettings, MockLDAP as BaseMockLDAP
from django.test import TestCase
from django_auth_ldap.config import _LDAPConfig
import logging

from django_ldap_pixiedust import settings

alice = ("uid=alice,ou=users,dc=test", {
        'uid': ['alice'],
        'objectClass': ['organizationalPerson', 'inetOrgPerson'],
        'mail': ['alice@example.com'],
        'userPassword': ['password1'],
    })

bob = ("uid=bob,ou=users,dc=test", {
        'uid': ['bob'],
        'objectClass': ['organizationalPerson', 'inetOrgPerson'],
        'mail': ['bob@example.com'],
        'userPassword': ['password2'],
    })

class MockLDAP(BaseMockLDAP):
    
    class OBJECT_CLASS_VIOLATION(Exception): pass
    
    MOD_ADD = 0
    MOD_DELETE = 1
    MOD_REPLACE = 2
    
    def add_s(self, dn, attrs):
        self._record_call('add_s', {
            'who': dn,
            'attrs': attrs,
            })
        attrs = tuple((x, tuple(y)) for x,y in attrs)
        value = self._get_return_value('add_s', (dn, attrs))
        return value
    
    def modify_s(self, dn, attrs):
        
        def _tuplify(operation, attribute, values):
            if operation == 1:
                return (operation, attribute, values)
            else:
                return (operation, attribute, tuple(values))
        self._record_call('modify_s', {
            'who': dn,
            'attrs': attrs,
            })
        attrs = tuple(_tuplify(x,y,z) for (x,y,z) in attrs)
        value = self._get_return_value('modify_s', (dn, attrs))
        return value
        
    
mock_ldap = MockLDAP({
    alice[0]: alice[1],
    bob[0]: bob[1],
})




class LDAPTest(TestCase):

    def setUp(self):
        self.configure_logger()
        self.mock_ldap = mock_ldap
        self.mock_ldap.reset()
        _LDAPConfig.ldap = mock_ldap

    logging_configured = False
    @classmethod
    def configure_logger(cls):
        if not cls.logging_configured:
            logger = logging.getLogger('django_auth_ldap')
            formatter = logging.Formatter("LDAP auth - %(levelname)s - %(message)s")
            handler = logging.StreamHandler()

            handler.setLevel(logging.DEBUG)
            handler.setFormatter(formatter)
            logger.addHandler(handler)

            logger.setLevel(logging.CRITICAL)

            cls.logging_configured = True

    def _init_settings(self, **kw):
        from django_auth_ldap import backend
        backend.ldap_settings = settings.ldap_settings = TestSettings(**kw)
        from django_ldap_pixiedust import sync
