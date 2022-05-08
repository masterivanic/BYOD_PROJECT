from django.contrib import admin
from .models  import Device , Owner
# Register your models here.

admin.site.register(Owner)
admin.site.register(Device)

