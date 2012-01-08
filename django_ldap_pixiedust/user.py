
from __future__ import absolute_import

from collections import defaultdict
from django_auth_ldap.backend import _LDAPUser
from ldap import modlist, SCOPE_BASE, NO_SUCH_OBJECT, MOD_ADD, MOD_DELETE, TYPE_OR_VALUE_EXISTS, OBJECT_CLASS_VIOLATION
import logging

from . import settings
from .utils import django_password_to_ldap

logger = logging.getLogger("django_ldap_pixiedust")

class DjangoLDAPPixieDustError(Exception):
    """ An exception that should never occur. """

def generate_attrs(instance, attr_map):
    """ This will NOT generate attributes for empty strings or zeros. This is
    probably a bug. """
    attrs = defaultdict(lambda: [])
    for django_name, ldap_name in attr_map.items():
        value = getattr(instance, django_name, None)
        if not value:
            continue # TODO: something cleverer
        elif type(value) == type(u''):
            attrs[ldap_name].append(unicode.encode(value, "UTF-8"))
        else:
            attrs[ldap_name].append(str(value))
    return attrs

class SynchronisingUserAdapter(object):
    
    """ This adapts an _LDAPUser object that has been initialised with a correct User object.  The layers and layers of wrapping allow this to sit on top of the existing code, but is kind of confusing.
    
    The recommended incantation to go from a Django User object to a correctly set up adapter is::
    
        ldap_user = backend.get_user(user.id)
        sync = SynchronisingUserAdapter(ldap_user)
        
    """

    group_type = settings.ldap_settings.AUTH_LDAP_GROUP_TYPE
    group_template = settings.ldap_settings.LDAP_PIXIEDUST_GROUP_DN_TEMPLATE

    def __init__(self, original):
        self.original = original
        self.bound = False
        
    def reset_ldap_password(self):
        """ Set the LDAP Password to an impossible value """
        self.connection.modify_s(self.dn, [(self.ldap.MOD_REPLACE,
                                            'userPassword',
                                            '{SSHA}!')])

    @property
    def dn(self):
        dn = self.original.ldap_user.dn
        if type(dn) == type(u''):
            return unicode.encode(dn, 'UTF-8')
        else:
            return dn

    @property
    def connection(self):
        conn = self.original.ldap_user._get_connection()
        if not self.bound:
            self.original.ldap_user._bind()
            self.bound = True
        return conn
    
    @property
    def ldap(self):
        return self.original.ldap_user.ldap

    def user_attrs(self):
        """ Create a set of user attributes based on the state of the django user object. """
        attrs = generate_attrs(self.original, settings.ldap_settings.AUTH_LDAP_USER_ATTR_MAP)
        for name, value in settings.ldap_settings.LDAP_PIXIEDUST_DEFAULT_ATTR_MAP.items():
            if not attrs[name]:
                attrs[name].append(value)
        attrs['objectClass'] = settings.ldap_settings.LDAP_PIXIEDUST_USER_OBJECTCLASSES
        if self.original.password and self.original.password != '!':
            attrs['userPassword'].append(django_password_to_ldap(self.original.password))
        return dict(attrs)
    
    def profile_attrs(self):
        attrs = generate_attrs(self.original.get_profile(), settings.ldap_settings.AUTH_LDAP_PROFILE_ATTR_MAP)
        return dict(attrs)

    def create_ldap_user(self):
        new_attrs = self.user_attrs()
        attrs = modlist.addModlist(new_attrs)
        self.connection.add_s(self.dn, attrs)
        self.update_flagged_groups()

    def get_ldap_attrs(self):
        results = self.connection.search_s(self.dn, SCOPE_BASE)
        if results and len(results) == 1:
            return dict(results[0][1])

    def update_ldap_user(self):
        """ Only updates those attributes the user object controls. """
        old_attrs = self.get_ldap_attrs()
        new_attrs = old_attrs.copy()
        new_attrs.update(self.user_attrs())
        attrs = modlist.modifyModlist(old_attrs, new_attrs)
        self.connection.modify_s(self.dn, attrs)
        self.update_flagged_groups()

    def update_ldap_profile(self):
        """ Only updates those attributes the user profile controls. """
        old_attrs = self.get_ldap_attrs()
        new_attrs = old_attrs.copy()
        new_attrs.update(self.profile_attrs())
        attrs = modlist.modifyModlist(old_attrs, new_attrs)
        self.connection.modify_s(self.dn, attrs)
        self.update_profile_flagged_groups()

    def synchronise(self, created=False):
        # ignoring created since it seems to be unreliable
        if not self.ldap_user_exists():
            self.create_ldap_user()
        else:
            self.update_ldap_user()

    def synchronise_profile(self, created=False):
        if not self.ldap_user_exists():
            raise DjangoLDAPPixieDustError("Profile requested to be synchronised for a non-existent user")
        self.update_ldap_profile()
        
    def synchronise_groups(self):
        self.clear_groups()
        self.group_add(self.original.groups.iterator())

    def ldap_user_exists(self):
        try:
            results = self.connection.search_s(self.original.ldap_user.dn, SCOPE_BASE)
            if results is None:
                return False
            return True
        except self.original.ldap_user.ldap.NO_SUCH_OBJECT:
            return False
        
    def flagged_groups(self):
        """ A list of DNs for groups that are managed by flags on the user or profile objects. These should not be cleared by clear_groups! """
        
        d = settings.ldap_settings.AUTH_LDAP_USER_FLAGS_BY_GROUP.values() + \
            settings.ldap_settings.AUTH_LDAP_PROFILE_FLAGS_BY_GROUP.values()
        return set(d)

    def clear_groups(self):
        logger.debug("Clearing %r from all groups" % (self.dn,))
        group = self.group_type
        flagged = self.flagged_groups()
        # TODO ensure query does not return all members
        for group_dn, group_attrs in settings.ldap_settings.AUTH_LDAP_GROUP_SEARCH.execute(self.connection):
            if group_dn not in flagged and \
               group.is_member(self.original.ldap_user, group_dn):
                try:
                    self.connection.modify_s(group_dn, [(self.original.ldap_user.ldap.MOD_DELETE,
                                                         self.group_type.member_attr,
                                                         [self.dn])])
                except OBJECT_CLASS_VIOLATION, e:
                    logger.warning("Unable to remove %r from %r because it is the last remaining member." % (self.original, group_dn))

    def _group_dn(self, group):
        return self.group_template % {'group': group.name}
    
    def group_exists(self, group_dn):
        try:
            self.connection.search_s(group_dn, self.ldap.SCOPE_BASE)
            return True
        except self.ldap.NO_SUCH_OBJECT:
            return False
        
    def group_add(self, groups):
        for g in groups:
            group_dn = self._group_dn(g)
            if not self.group_exists(group_dn):
                self.group_create(g)
            else:
                self._group_add(group_dn)
                
    def group_create(self, group):
        """ Create an LDAP group with this user as the only member """
        group_dn = self._group_dn(group)
        attrs = {
            self.group_type.name_attr: [group.name.encode('utf-8')],
            'objectClass': [settings.ldap_settings.LDAP_PIXIEDUST_GROUP_OBJECTCLASS],
            self.group_type.member_attr: [self.dn],
            }
        self.connection.add_s(group_dn, modlist.addModlist(attrs))
        
    def _group_add(self, group_dn):
        """ Add this user to the specified LDAP group. """
        try:
            logger.debug("Adding %r to %r" % (self.dn, group_dn))
            self.connection.modify_s(group_dn, [(self.ldap.MOD_ADD,
                                                 self.group_type.member_attr,
                                                 self.dn)])
        except self.ldap.TYPE_OR_VALUE_EXISTS:
            pass
        
    def group_remove(self, groups):
        for g in groups:
            group_dn = self.group_template % {'group': g.name}
            self._group_remove(group_dn)
            
    def _group_remove(self, group_dn):
        try:
            logger.debug("Removing %r from %r" % (self.dn, group_dn))
            self.connection.modify_s(group_dn, [(self.ldap.MOD_DELETE,
                                                 self.group_type.member_attr,
                                                 self.dn)])
        except self.ldap.NO_SUCH_ATTRIBUTE:
            pass

    def update_flagged_groups(self):
        """ Update any group membership that's taken from the
        AUTH_LDAP_USER_FLAGS_BY_GROUP parameter. """
        
        self._update_flagged_groups(self.original, settings.ldap_settings.AUTH_LDAP_USER_FLAGS_BY_GROUP)
                        
    def update_profile_flagged_groups(self):        
        profile = self.original.get_profile()
        self._update_flagged_groups(profile, settings.ldap_settings.AUTH_LDAP_PROFILE_FLAGS_BY_GROUP)
        
    def _update_flagged_groups(self, instance, flag_map):
        for flag, group_dn in flag_map.items():
            value = getattr(instance, flag)
            if value:
                self._group_add(group_dn)
            else:
                self._group_remove(group_dn)
