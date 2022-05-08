from django.forms import fields
from .models import Owner , Device
from django import forms

#model form to edit user
class OwnerForm(forms.ModelForm):
    class Meta:
        model = Owner
        fields = ("name", "email", "department")

class DeviceForm(forms.ModelForm):
    class Meta:
        model = Device
        fields = ("owner", "ip_address" , "hostname" )
