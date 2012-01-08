
""" Synchronise the Django user, profile and group tables against LDAP. """

from django.core.management.base import BaseCommand
from optparse import make_option
import ldap
from django_ldap_pixiedust import settings
from django_ldap_pixiedust.ldap import LDAPConnectionMixin
from django_ldap_pixiedust.user import SynchronisingUserAdapter
from django_auth_ldap.backend import LDAPBackend, _LDAPUser
from django.contrib.auth.models import User
from django_ldap_pixiedust import sync

class Command(BaseCommand):
    
    help = "example help"
    
    option_list = BaseCommand.option_list + (
        make_option("--verbose", action="store_true", default=False),
        )
    
    def handle(self, *args, **options):
        for arg in args:
            handler = getattr(self, "handle_" + arg)
            handler(**options)
    
    def handle_fromldap(self, **options):
        synchroniser = sync.LDAPSynchroniser()
        synchroniser.synchronise_from_ldap()
        
    def handle_toldap(self, **options):
        synchroniser = sync.LDAPSynchroniser()
        synchroniser.synchronise_to_ldap()
