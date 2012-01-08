from django.db import models


class PixieDustTestProfile(models.Model):
    """
    A user profile model for use by unit tests. This has nothing to do with the
    authentication backend itself.
    """
    user = models.OneToOneField('auth.User')
    location = models.CharField(max_length=100)
    is_special = models.BooleanField(default=False)
    populated = models.BooleanField(default=False)
