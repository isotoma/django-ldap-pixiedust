
from __future__ import absolute_import

from . import settings
import ldap

class LDAPConnectionMixin(object):

    """ Based on equivalent code in django-auth-ldap. """

    def _bind(self):
        """
        Binds to the LDAP server with AUTH_LDAP_BIND_DN and
        AUTH_LDAP_BIND_PASSWORD.
        """
        self._bind_as(settings.ldap_settings.AUTH_LDAP_BIND_DN,
            settings.ldap_settings.AUTH_LDAP_BIND_PASSWORD)

        self._connection_bound = True

    def _bind_as(self, bind_dn, bind_password):
        """
        Binds to the LDAP server with the given credentials. This does not trap
        exceptions.

        If successful, we set self._connection_bound to False under the
        assumption that we're not binding as the default user. Callers can set
        it to True as appropriate.
        """
        self._get_connection().simple_bind_s(bind_dn.encode('utf-8'),
            bind_password.encode('utf-8'))

        self._connection_bound = False

    # TODO: this is pretty fugly. a bunch of this stuff should be in 
    # __init__ really, but I've delayed refactoring to stop this getting
    # confused with the historical connection stuff from django_auth_ldap
    def _get_connection(self):
        """
        Returns our cached LDAPObject, which may or may not be bound.
        """
        if not hasattr(self, 'ldap'):
            self.ldap = ldap
        if not hasattr(self, '_connection'):
            self._connection = None
        if self._connection is None:
            self._connection = self.ldap.initialize(settings.ldap_settings.AUTH_LDAP_SERVER_URI)

            for opt, value in settings.ldap_settings.AUTH_LDAP_CONNECTION_OPTIONS.iteritems():
                self._connection.set_option(opt, value)

            if settings.ldap_settings.AUTH_LDAP_START_TLS:
                #logger.debug("Initiating TLS")
                self._connection.start_tls_s()

        return self._connection

