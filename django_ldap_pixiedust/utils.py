
from django.contrib.auth.models import User
from django_auth_ldap.backend import LDAPBackend

from base64 import encodestring
import uuid

#http://www.openldap.org/faq/data/cache/347.html
def django_password_to_ldap(django_password):
    """ Django and LDAP use different mechanisms for encoding passwords. """
    scheme, salt, hexpasswd = django_password.split("$")
    if scheme != 'sha1':
        raise KeyError("scheme %r is not supported by django-ldap-pixiedust" % scheme)
    passwd = hexpasswd.decode('hex')
    return "{SSHA}" + encodestring(passwd + str(salt)).rstrip()

def new_uid():
    """ A utility class to generate UIDs for your new users, if you are using email address for logins. """
    return str(uuid.uuid1())[:30]

def reset_ldap_password(username):
    """ Set the user's ldap password to something that can never be entered,
    effectively locking the account. We do not sync these passwords from
    django, because django_auth_ldap sets all new accounts to these
    passwords. """
    
    from django_ldap_pixiedust.user import SynchronisingUserAdapter
    backend = LDAPBackend()
    user = User.objects.get(username=username)
    ldap_user = backend.get_user(user.id)
    sync = SynchronisingUserAdapter(ldap_user)
    sync.reset_ldap_password()
    