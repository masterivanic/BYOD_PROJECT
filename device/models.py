from django.db import models
from django.contrib.auth.models import  User 


class Device(models.Model):
    name = models.CharField(max_length=100, default='Android Device')
    android_id = models.CharField(max_length=25, primary_key=True)
    build_number = models.CharField(max_length=25)
    operating_system_version = models.CharField(max_length=25)
    created = models.DateTimeField(auto_now_add=True)
    modified = models.DateTimeField(auto_now=True)
    model = models.CharField(max_length=40, null=False, blank=False)

    user = models.ForeignKey(User)

    def __str__(self):
        return self.name

class Operation(object):
    pass

