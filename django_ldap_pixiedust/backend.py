
from __future__ import absolute_import

from django.contrib.auth import models as auth_models
from django.contrib.auth.models import User, Group
from django.utils.encoding import smart_str
from django.utils.hashcompat import sha_constructor, md5_constructor
from django_auth_ldap.backend import LDAPBackend, _LDAPUser
from collections import defaultdict
from django.db import models

import uuid
import logging

from .user import SynchronisingUserAdapter
from .utils import django_password_to_ldap
from .ldap import LDAPConnectionMixin
from . import settings

logger = logging.getLogger('django_ldap_pixiedust')

class DecoupledUserClassMixin(object):
    """ Make it easy to use a different _LDAPUser class from within the backend. """
    userclass = _LDAPUser
    def authenticate(self, username, password):
        ldap_user = self.userclass(self, username=username)
        user = ldap_user.authenticate(password)
        return user

    def get_user(self, user_id):
        user = None
        try:
            user = User.objects.get(pk=user_id)
            self.userclass(self, user=user) # sets user.ldap_user
        except User.DoesNotExist:
            pass
        return user

if settings.ldap_settings.LDAP_PIXIEDUST_COMPATIBLE_PASSWORDS:
    # monkeypatch django.contrib.auth to alter the digest mechanism
    # look away now
    def get_hexdigest(algorithm, salt, raw_password):

        """ replacement hashing mechanism that hashes password first, instead
        of salt first. This means that generated passwords are valid for LDAP
        as well as Django.

        Only supports SHA1. """

        raw_password, salt = smart_str(raw_password), smart_str(salt)
        if algorithm == 'crypt':
            try:
                import crypt
            except ImportError:
                raise ValueError('"crypt" password algorithm not supported in this environment')
            return crypt.crypt(raw_password, salt)

        if algorithm == 'md5':
            return md5_constructor(salt + raw_password).hexdigest()
        elif algorithm == 'sha1':
            # in django by default this is salt + raw_password
            return sha_constructor(raw_password + salt).hexdigest()
        raise ValueError("Got unknown password algorithm type in password.")
    auth_models.get_hexdigest = get_hexdigest

class EmailLoginBackend(LDAPConnectionMixin, LDAPBackend):

    """ Locates the user by email address, even though their dn is determined by a unique username. """

    def authenticate(self, username, password):
        """ This actually takes the email address as the username, but
        assembles a user based on the correct DN by searching first using the
        login search configuration, then delegating user creation back to the
        usual mechanism. """

        search = settings.ldap_settings.LDAP_PIXIEDUST_LOGIN_SEARCH
        results = search.execute(self._get_connection(), {"user": username})
        if results is not None and len(results) == 1:
            id_attr = settings.ldap_settings.LDAP_PIXIEDUST_USERNAME_DN_ATTRIBUTE
            user_dn, user_attrs = results[0]
            if id_attr in user_attrs:
                real_username = user_attrs[id_attr][0]
                return super(EmailLoginBackend, self).authenticate(real_username, password)
            else:
                raise ValueError("LDAP User %r does not have username attribute %r" % (user_dn, id_attr))

