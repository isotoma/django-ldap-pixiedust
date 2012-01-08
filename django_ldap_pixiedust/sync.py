from django.contrib.auth.models import Group, User
from django_auth_ldap.backend import LDAPBackend, _LDAPUser
from django.db.models.signals import post_save, post_delete, m2m_changed

from . import backend, ldap, settings
from .user import SynchronisingUserAdapter

import logging

logger = logging.getLogger("django_ldap_pixiedust")

def group_sync_handler(sender, instance, action, pk_set, **kwargs):
    if sender == User.groups.through:
        user = LDAPBackend().get_user(instance.id)
        sync = SynchronisingUserAdapter(user)
        if pk_set is not None:
            groups = [Group.objects.get(pk=x) for x in pk_set]
        if action == 'post_clear':
            sync.clear_groups()
        elif action == 'post_add':
            sync.group_add(groups)
        elif action == 'post_remove':
            sync.group_remove(groups)

def profile_sync_handler(sender, instance, created, **kwargs):
    from django.db import models
    app_label, model_name = settings.ldap_settings.AUTH_PROFILE_MODULE.split('.')
    profile_model = models.get_model(app_label, model_name)
    
    # we're getting the octopus profile, not the pixiedust profile
    if sender == profile_model:
        user = LDAPBackend().get_user(instance.id)
        sync = SynchronisingUserAdapter(user)
        sync.synchronise_profile(created)
            
def user_sync_handler(sender, **kwargs):
    instance = kwargs.pop('instance', None)
    created = kwargs.pop('created', None)
    backend = LDAPBackend()
    if sender == User:
        user = backend.get_user(instance.id)
        sync = SynchronisingUserAdapter(user)
        sync.synchronise(created)

def activate(sync_user, sync_groups, sync_profile):
    if sync_groups:
        logger.warning("Group changes will be synchronised to LDAP")
        m2m_changed.connect(group_sync_handler)
    else:
        m2m_changed.disconnect(group_sync_handler)
    
    if sync_user:
        logger.warning("User changes will be synchronised to LDAP")
        post_save.connect(user_sync_handler)
    else:
        post_save.disconnect(user_sync_handler)
    
    if sync_profile:
        logger.warning("User profile changes will be synchronised to LDAP")
        post_save.connect(profile_sync_handler)
    else:
        post_save.disconnect(profile_sync_handler)

def deactivate():
    activate(False, False, False)
    
def activate_fromsettings():
    activate(settings.ldap_settings.LDAP_PIXIEDUST_SYNC_USER,
             settings.ldap_settings.LDAP_PIXIEDUST_SYNC_GROUPS,
             settings.ldap_settings.LDAP_PIXIEDUST_SYNC_PROFILE
             )
    
# this is our default
activate_fromsettings()

class LDAPSynchroniser(ldap.LDAPConnectionMixin):
    
    """ This provides complete database synchronisation - either from or to
    the LDAP server. This will synchronise every user and group. It's called
    by the "ldapsync" management command. """
    
    def __init__(self):
        self.conn = self._get_connection()
        self.backend = LDAPBackend()
    
    def ldap_users(self):
        search = settings.ldap_settings.LDAP_PIXIEDUST_ALL_USERS
        for dn, attrs in search.execute(self.conn):
            user_id = attrs[settings.ldap_settings.LDAP_PIXIEDUST_USERNAME_DN_ATTRIBUTE][0]
            yield _LDAPUser(self.backend, username=user_id)
            
    def model_users(self):
        return User.objects.all()
            
    def synchronise_from_ldap(self):
        deactivate()
        for user in self.ldap_users():
            logger.debug("Synchronising %r" % repr(user))
            user._get_or_create_user()
        activate_fromsettings()
            
    def synchronise_to_ldap(self):
        for user in self.model_users():
            ldap_user = self.backend.get_user(user.id)
            sync = SynchronisingUserAdapter(ldap_user)
            logger.debug("Synchronising %r" % repr(user))
            sync.synchronise_groups() # must happen first, because it clears groups!
            sync.synchronise()
            sync.synchronise_profile()

