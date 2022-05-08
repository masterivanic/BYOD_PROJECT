

from django.db import models

class Owner(models.Model):
    name = models.CharField(max_length=50)
    email = models.EmailField(max_length=254)
    department = models.CharField(max_length=50)
    
    class Meta:
        ordering = ['name']

    def __str__(self):
        return self.name

DEFAULT_OWNER_ID = 1

class Device(models.Model):
    owner = models.ForeignKey(Owner, on_delete=models.CASCADE, blank=True , default= DEFAULT_OWNER_ID)
    ip_address = models.CharField(max_length=50)
    mac_address = models.CharField(max_length=100)
    hostname = models.CharField(max_length=50)
    os = models.CharField(max_length=50)

    class Meta:
        ordering = ['hostname']
    
    def __str__(self):
        return self.hostname

#pour gerer les privileges....
class Privileges(models.Model):
    _type = models.CharField(max_length=350)
