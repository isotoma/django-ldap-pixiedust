""" LDAP Pixiedust

Sprinkles magic pixie dust over your Django/LDAP integration.

In particular it provides:

 * A backend that can authenticate by e-mail, but otherwise play nicely with
 * standard Django a set of hooks that will magically synchronise changes to users, groups and profiles back to your LDAP database

"""

from .backend import EmailLoginBackend
from .ldap import LDAPConnectionMixin
from . import sync

