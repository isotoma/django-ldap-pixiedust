from django_auth_ldap.backend import LDAPSettings as BaseLDAPSettings

class LDAPSettings(BaseLDAPSettings):
    pass

LDAPSettings.defaults.update({
    'LDAP_PIXIEDUST_SYNC_USER': False,
    'LDAP_PIXIEDUST_SYNC_PROFILE': False,
    'LDAP_PIXIEDUST_SYNC_GROUPS': False,
    'LDAP_PIXIEDUST_LOGIN_SEARCH': None,
    'LDAP_PIXIEDUST_GROUP_DN_TEMPLATE': '',
    'LDAP_PIXIEDUST_COMPATIBLE_PASSWORDS': False,
    'LDAP_PIXIEDUST_USER_OBJECTCLASSES': [
        'organizationalPerson',
        'inetOrgPerson',
        ],
    'LDAP_PIXIEDUST_USERNAME_DN_ATTRIBUTE': 'uid',
    'LDAP_PIXIEDUST_DEFAULT_ATTR_MAP': {},
    'AUTH_PROFILE_MODULE': '',
    'LDAP_PIXIEDUST_ALL_USERS': None,
    'LDAP_PIXIEDUST_GROUP_OBJECTCLASS': 'groupOfNames',
    })

ldap_settings = LDAPSettings()
