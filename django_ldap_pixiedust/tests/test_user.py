# -*- coding: UTF-8 -*-

from .fixtures import mock_ldap, LDAPTest, TestSettings
from django_ldap_pixiedust import settings
from django_ldap_pixiedust import backend
from django_ldap_pixiedust.user import generate_attrs, SynchronisingUserAdapter
from django_auth_ldap.config import LDAPSearch
from django_auth_ldap.backend import _LDAPUser, LDAPBackend
from django.test import TestCase
from django.contrib.auth.models import User

from . import fixtures

class Vanilla:
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)
            

class TestGenerateAttrs(TestCase):
    
    def test_empty(self):
        attrs = generate_attrs(Vanilla(), {})
        self.failUnlessEqual(attrs, {})
        
    def test_simple(self):
        attrs = generate_attrs(Vanilla(foo='x',bar='y'), 
                               {'foo': 'ldap_foo',
                                'bar': 'ldap_bar'})
        self.failUnlessEqual(dict(attrs), 
                             {'ldap_foo': ['x'],
                              'ldap_bar': ['y']})
        
    def test_int(self):
        attrs = generate_attrs(Vanilla(bar=10), 
                               {'bar': 'ldap_bar'})
        self.failUnlessEqual(dict(attrs), {'ldap_bar': ['10']})
        
    def test_unicode(self):
        attrs = generate_attrs(Vanilla(bar=u"£"), {'bar': 'ldap_bar'})
        self.failUnlessEqual(dict(attrs), {'ldap_bar': [unicode.encode(u"£", "UTF-8")]})
        
        
    def test_empty_string(self):
        attrs = generate_attrs(Vanilla(bar=''), {'bar': 'ldap_bar'})
        self.failUnlessEqual(dict(attrs), {})
        
    def test_zero(self):
        attrs = generate_attrs(Vanilla(bar=0), {'bar': 'ldap_bar'})
        self.failUnlessEqual(dict(attrs), {})

        
class TestUser(Vanilla):
    
    def __init__(self, username, **kw):
        Vanilla.__init__(self, username=username, **kw)
        self.ldap_user = TestLDAPUser(LDAPBackend(), user=self)

class TestLDAPUser(_LDAPUser):
    def __init__(self, backend, username=None, user=None):
        _LDAPUser.__init__(self, backend, username, user)
        self.ldap = mock_ldap
    
        
class TestSynchronisingUserAdapter(TestCase):
    
    def test_dn(self):
        user = TestUser("bill")
        fixture = SynchronisingUserAdapter(user)
        self.assertEqual(fixture.dn, "uid=bill,ou=users,dc=test")
        
    def test_user_attrs(self):
        settings.ldap_settings = TestSettings(
            AUTH_LDAP_USER_ATTR_MAP = {
                'foo': 'ldap_foo',
                'bar': 'ldap_bar',
                },
            LDAP_PIXIEDUST_DEFAULT_ATTR_MAP = {
                'frob': 'nicate'
            })
        user = TestUser(username="bill", foo='x', bar='y', password='sha1$SALT$4242')
        fixture = SynchronisingUserAdapter(user)
        self.failUnlessEqual(fixture.user_attrs(), {
            'ldap_foo': ['x'],
            'ldap_bar': ['y'],
            'frob': ['nicate'],
            'objectClass': ['organizationalPerson', 'inetOrgPerson'],
            'userPassword': ['{SSHA}QkJTQUxU'],
            })
        
    def test_reset_ldap_password(self):
        user = TestUser("bill")
        mock_ldap.reset()
        fixture = SynchronisingUserAdapter(user)
        fixture.reset_ldap_password()
        self.assertEqual(mock_ldap.ldap_methods_called(), ['initialize', 'simple_bind_s', 'modify_s'])
        self.assertEqual(mock_ldap.ldap_methods_called_with_arguments()[2][1], {
                         'who': 'uid=bill,ou=users,dc=test',
                         'attrs': [(2, 'userPassword', '{SSHA}!')],
        })
        
