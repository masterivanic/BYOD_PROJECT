from threading import local
from django.db.models.expressions import F
from django.shortcuts import redirect, render , HttpResponseRedirect, resolve_url
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.conf import settings
from django.contrib import messages
from django.http import *
from .utils import DetectNetwork
from .models import Device,Owner
from .forms import OwnerForm ,DeviceForm
import time
import folium 
import geocoder
from json import dumps


from .window import InterfaceAPP
from tkinter import *
from tkinter.messagebox import showinfo

# Create your views here.
@login_required
def home(request):
    device = Owner.objects.all()
    users = []
    for user in device:
        users.append(user.name)
    
    finale_tab = []
    for names in users:
        user = Owner.objects.get(name=names)
        number_device = Device.objects.filter(owner=user).count()
        finale_tab.append((names,  number_device))

    users_name, device_number = [] , []
    for i in finale_tab:
        users_name.append(i[0])
        device_number.append(i[1])

    users_name = dumps(users_name)
    device_number = dumps(device_number)
    
    return render(request, 'index.html',locals())

def device(request):
    computers = Device.objects.all()
    return render(request, 'device.html', locals())

def users(request):
    users = Owner.objects.all()
    return render(request, 'users.html',locals())

def ip_results(request):
    return render(request, 'results.html')

#edit users 
def edit_owners(request, id=0):
    if request.method == 'GET':
        if id == 0:
            form = OwnerForm()
        else:
            owner = Owner.objects.get(pk=id)
            form = OwnerForm(instance=owner)
        
        return render(request, 'edit.html', locals())
    else:
        if id == 0:
            form = OwnerForm(request.POST)
        else:
            owner = Owner.objects.get(pk=id)
            form = OwnerForm(request.POST, instance=owner)
        
        if form.is_valid():
            form.save()
            messages.success(request, "successfully saved...")
    
    return render(request, 'edit.html', locals())


def associate_device(request, id=0):
    if request.method == 'GET':
        if id == 0:
            form = DeviceForm()
        else:
            device = Device.objects.get(pk=id)
            form = DeviceForm(instance=device)
        return render(request, 'device_edit.html', locals())
    else:
        if id == 0:
            form = DeviceForm(request.POST)
        else:
            device = Device.objects.get(pk=id)
            form = DeviceForm(request.POST, instance=device)

        if form.is_valid():
            form.save()
            messages.success(request, "successfully attributed...")
    
    return render(request, 'device_edit.html', locals())


def show_user_device(request):
    try:
        device = Device.objects.all()
    except Device.DoesNotExist:
        raise Http404
    return render(request , 'device_user.html' , {'device': device})


def view_edit(request):
    form = OwnerForm()
    return render(request, 'edit.html', locals())

#delete a user of a device....
def delete_user(request, id):
    try:
        user = Owner.objects.get(pk=id)
        user.delete()
    except Owner.DoesNotExist:
        raise Http404
    return redirect("/home/users/")


def afterLogin(request):
    return redirect('/')


def login_option(request):
    if request.method == 'POST':
        username,  password  = request.POST.get('username', False) , request.POST.get('password', False)
        user = authenticate(username=username , password=password)
        if user is not None and user.is_active:
            login(request, user)
            return HttpResponseRedirect(settings.LOGIN_REDIRECT_URL)
        else:
            messages.error(request, "Username or password incorrect")

    return render(request, 'login.html', {})

def logout_option(request):
    logout(request)
    return render(request, 'login.html', {})

def network_scan(request):
    entries = Device.objects.all()
    entries.delete()

    tab_adresses , device_info = [] , []
    if request.method == 'POST':
        ip = request.POST.get('ip' , False)
        adresses = DetectNetwork().scan(ip)
        if adresses:
            for key, value in adresses.items():
                tab_adresses.append((key, value))
                
            for i in tab_adresses:
                ip = DetectNetwork().get_device_info(i[0])
                device_info.append(ip)

            try:
                for device in device_info:
                    devices = Device(ip_address=device['IP'],  mac_address=device['MAC Address'],  hostname=device['Hostname'], os=device['Os'])
                    devices.save()
                print('save successfully...')
            except Exception as e:
                print(e)

            messages.success(request, 'ip found')
        else:
            messages.error(request, 'not devices found on this network')
        return render(request, 'scan.html', locals())

    return render(request, 'scan.html', {})

    
#rapid scan of network...
def rapid_scan(request):
    entries = Device.objects.all()
    entries.delete()
    device_info ,  tab_adresses = [], []

    addresses = DetectNetwork().fast_scan()
    if addresses:
        for key, value in addresses.items():
                tab_adresses.append((key, value))
                
        for i in tab_adresses:
            ip = DetectNetwork().get_device_info(i[0])
            device_info.append(ip)

        try:
            for device in device_info:
                devices = Device(ip_address=device['IP'],  mac_address=device['MAC Address'],  hostname=device['Hostname'], os=device['Os'])
                devices.save()
                print('save successfully...')
        except Exception as e:
            print(e)
            messages.success(request, 'ip found')
    else:
        messages.error(request, "no devices found on this network")

    return render(request, 'scan_fast.html', locals())

def get_host_by_ip(request):
    if request.method == 'POST':
        host  = request.POST.get('host_ip')
        print(host)
        infos = []
        value = DetectNetwork().get_specific_host(host)
        print("value = ", value)
        
        if len(value) != 0:
            result = DetectNetwork().get_device_info(value[0])
            infos.append(result)
            print("tab value: " , infos)
            print(result)
            
            for device in infos:
                devices = Device(ip_address=device['IP'],  mac_address=device['MAC Address'],  hostname=device['Hostname'], os=device['Os'])
                devices.save()
                ip = device['IP']
                hostnames = device['Hostname']
        else:
            messages.error(request, 'device not found on this network')
        
    return render(request, 'specific.html', locals())
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   

def get_host_by_mac(request):
    mac = request.POST.get('ip', False)
    value = DetectNetwork().get_host_by_mac(mac)
    if value:
        messages.success(request, 'device found')
    else:
        messages.error(request, 'device not found on this network')
        
    return render(request, 'mac.html', locals())

def service_turn(request, id):
    tab_result = []
    computers = Device.objects.all()
    try:
        device_ip = Device.objects.get(pk=id).ip_address
        result = DetectNetwork().get_service_turn_on(device_ip)  
        tab_result.append(result)
    except Device.DoesNotExist:
        raise Http404
    
    return render(request, 'analyse_result.html', locals())


def detect_malware(request, id):
    tab_results = []
    computers = Device.objects.all()
    try:
        device_ip = Device.objects.get(pk=id).ip_address
        result = DetectNetwork().malware_detect(device_ip)
        tab_results.append(result)
    except Device.DoesNotExist:
        raise Http404
    
    return render(request, 'analyse_result.html', locals())

def check_trafic(request, id):
    computers = Device.objects.all()
    try:
        device_ip = Device.objects.get(pk=id).ip_address
        DetectNetwork().host_sniffer(device_ip)
        messages.success(request, "check result on wireshark")
    except Device.DoesNotExist:
        raise Http404

    return render(request, 'traffic.html', locals())


def entire_network(request):
    return render(request, 'network.html', {})


def check_port(request):
    host , port = request.POST.get('hostname', False), request.POST.get('port', False)
    result = DetectNetwork().check_port(host,port)
    if result:
        messages.success(request, f"port {port} is open on {host}")
    else:
        messages.error(request, f"port {port} is down on {host}")
    return render(request, 'network.html', {})

def check_localisation(request):
    host = request.POST.get('hostname', False)
    g = geocoder.ipinfo(host)
    params = g.latlng  #[lat , lng]
    location = geocoder.osm(g.city)
    country = location.country
    lat , long = params[0], params[1]

    if lat == None or long == None:
        m = folium.Map(location=[19, -12], zoom_start=2)
        m = m._repr_html_()
        context = {'m': m,}
        messages.error(request, 'localisation does not exist or check your network connection')
        return render(request, 'maps.html', context)
    else:
        m = folium.Map(location=[19, -12], zoom_start=2)
        folium.Marker([lat, long], tooltip='click here').add_to(m)
        m = m._repr_html_()
        context = {'m': m,}
        return render(request, 'maps.html', context)

def disconnect_device(request):
    host = request.POST.get('hostname', False)
    try:
        DetectNetwork().disconnect_device(host)
        messages.success(request, f"{host} disconnect succesfully...")
    except Exception as err:
        print(err)
    return render(request, 'network.html', {})
    
   
        
def scan_entire_network(request):
    value = DetectNetwork().scan_all_network()
    return render(request, 'network.html', locals())
   

    