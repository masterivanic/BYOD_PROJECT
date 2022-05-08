

from os import name
from django.contrib import admin
from django.urls import path
from django.conf.urls.static import static  
from  django.conf import  settings
from gestionBYOD.views import *

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', login_option, name='index'),
    path('home/', home, name='home'),
    path('home/device/', device, name='device'),
    path('home/device/update/<int:id>', associate_device, name='associate'),
    path('home/device/associate/', show_user_device , name='user_device'),
    path('home/users/', users, name='users'),
    path('home/users/add/', edit_owners , name='create_user'),
    path('home/users/update/<int:id>', edit_owners , name='update_user'),
    path('home/users/update', view_edit, name='view_edit'),
    path('home/users/delete/<int:id>', delete_user , name='delete_user'),
    path('logout/', logout_option, name='logout'),
    path('home/scan/', network_scan, name='scan'),
    path('home/scan/result/', ip_results, name='ip'),
    path('home/rapid/result/', rapid_scan , name='fast_scan'),
    
    path('home/device/get/', get_host_by_ip, name='by_ip'),
    path('home/device/get/mac/', get_host_by_mac, name='by_mac'),

    path('home/device/analyse/<int:id>' , service_turn, name = "analyse"),
    path('home/device/malware/<int:id>', detect_malware, name='malware'),
    path('home/device/trafic/<int:id>', check_trafic, name='traffic'),

    path('home/network/', entire_network, name= 'network'),
    path('home/network/disconnect/', disconnect_device, name= 'disconnect'),
    path('home/network/localisation/', check_localisation, name= 'localisation'),
    path('home/network/check/', check_port , name= 'check_port'),
    path('home/network/scan/', scan_entire_network, name='entire_network')

] 

urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT) 
