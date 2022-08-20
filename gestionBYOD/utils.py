
import sys
import socket
import re
import subprocess
import shlex
import threading as thread
from scapy.all import *
#from .models import Device

from multiprocessing import Process
from proxy import Proxy
from .networkInterface import DetectNetworkInterface


class DetectNetwork(DetectNetworkInterface):

    """
        This class decribe all actions we can do
        with network programming, just take a look...
    """

    def __init__(self, host:str ="localhost") -> None:
        self.__host = host  # variable prive

    @classmethod
    def create_from_ip(cls, hostname, ip_adress):
        return cls(hostname, ip_adress)

    def _get_host(self) -> str:
        return self.__host

    def _set_host(self, host: str) -> None:
        self.__host = host

    property(fget=_get_host, fset=_set_host, doc="Value")


    def seperate_ip(self, ip: str):
        ip = str(ip).split('.')
        host_part = ip[-1]
        ip_part = ".".join(ip[:3]) + "."

        return ip_part, host_part


    @staticmethod
    def scan(ip):
        hosts, x = [], 0
        adresses = {}
        ip_part, host_part = DetectNetwork().seperate_ip(ip)
        while x <= 254:
            p = subprocess.Popen(
                'ping  ' + ip_part + str(x) + "-n  1 ", stdout=subprocess.PIPE, shell=True)
            out, error = p.communicate()
            out = str(out)
            find = re.search("Destination host unreachable", out)

            if find is None:
                hosts.append(ip_part+str(x))
                x = x+1

            # threads = thread.Thread(target=DetectNetwork().get_all_host(hosts))
            # threads.start()
            # threads.join()

            # adresses = DetectNetwork().get_all_host(hosts)

            for host in hosts:
                try:
                    name, a, b = socket.gethostbyaddr(host)
                    adresses[host] = name
                except:
                    name = "Not Found"
                print("|" + host + " |" + name)

        return adresses

    """
        check if  a specify host is available
        on a network by using the ping command
    """

    def get_resolution_name(self):
        name, a, b = socket.gethostbyaddr(self.__host)
        return ip, name

    def get_specific_host(self, host: str):
        adresses = []
        rep, non_rep = sr(IP(dst=host) / ICMP(), timeout=100)
        for elt in rep:
            if elt[1].type == 0:
                adresses.append(elt[1].src)
                print(elt[1].src + ' a renvoye un reply')

        return adresses

    """
        host make a ARP request, and get answer
        so can get mac address of a host.
    """

    def get_host_by_mac(self, mac_address):
        try:
            my_ip_address = IP(dst="0.0.0.0").src  # get my ip address
            ip_part, host_part = DetectNetwork().seperate_ip(my_ip_address)
            ip_value = ip_part + "0"
            network_ip = ip_value + "/24"
            local_devices = arping(network_ip)
            local_macs = [device[1].src for device in local_devices[0]]
            if mac_address in local_macs:
                return True
            else:
                return False
        except Exception as e:
            print(e)

    # get all host true DNS name define of a computer
    def get_all_host(self, hosts: list) -> dict:
        adresses = {}
        for host in hosts:
            try:
                name, a, b = socket.gethostbyaddr(host)
                adresses[host] = name
            except:
                name = "Not Found"
            print("|" + host + " |" + name)

        return adresses

    """
    realise un ping de tous les hotes
        vers l'hote principale (computer analyser)
        Utilise ICMP() envoie un paquet echo-request et attend echo-reply
        IMCP() === ping command
    """

    @staticmethod
    def fast_scan():
        adresses, taken_address = [], []
        address = {}
        my_ip_address = IP(dst="0.0.0.0").src  # get my ip address
        ip_part, host_part = DetectNetwork().seperate_ip(my_ip_address)

        for i in range(2, 8):
            ip_value = ip_part + str(i)
            print(ip_value)
            rep, non_rep = sr(IP(dst=ip_value) / ICMP(), timeout=10)
            for elt in rep:
                if elt[1].type == 0:
                    adresses.append(elt[1].src)
                    print(elt[1].src + ' a renvoye un reply')

            for host in adresses:
                try:
                    name, a, b = socket.gethostbyaddr(host)
                    address[host] = name
                except:
                    name = "Not Found"
                print("|" + host + " |" + name)

        return address

    """"
    @get_open_port
        get information about all port status of a device
        do it by establish a TCP connection between 2 devices
    """

    def get_open_port(self, host):
        conf.verb = 0
        SYN = 0x02
        ACK = 0x10
        SYNACK = SYN | ACK

        for port in range(0, 6500):
            syn_pkt = IP(dst=host) / TCP(dport=port,
                                         flags='S')  # creer le paquet IP
            synack_pkt = sr1(syn_pkt, timeout=1)  # envoi le paquet

            if synack_pkt is None:
                print("cannot reach host {} on {}".format(host, port))
            elif synack_pkt['TCP'].flags == SYNACK:
                print("{} open ".format(port))
            else:
                print("{} closed".format(port))

    """
        @get_os_device
            get os  information about a device 
            check the ttl (time to live) of packet
            when ttl <= 64 os detected is linux else os detected is windows
            ...
            check here documentation here : ......................
    """

    def get_os_device(self, host) -> str:
        pack = IP(dst=host)/ICMP()
        response = sr1(pack, timeout=1, verbose=False)

        if response == None:
            return "no response"
        elif IP in response:
            if response[0].ttl <= 64:  # accede au ttl du paquet emis
                os = "linux"
            else:
                os = "windows"
        return os

    """
    @get_device_info
        get information device by checking ARP tables  of device
        so we can check mac address, ip by arp request over Ethernet
    """

    def get_device_info(self, host) -> list:
        result = {}
        try:
            broadcast = Ether(dst='ff:ff:ff:ff:ff:ff')
            arp_request = ARP(pdst=host)
            arp_request_broadcast = broadcast / arp_request  # creer une requete arp
        except:
            raise Exception("host not found")

        ans_all, ans = srp(arp_request_broadcast, timeout=2, verbose=False)
        for sent, received in ans_all:
            name, a, b = socket.gethostbyaddr(received.psrc)
            operating = DetectNetwork().get_os_device(received.psrc)
            result = {
                'IP': received.psrc,
                'MAC Address': received.hwsrc,
                'Hostname': name,
                'Os': operating
            }

        return result

    """
    detect open port of a host
    for multiple port just enter a tuple
    """

    def tcp_scan(self, host, port):
        result = []
        try:
            # creer un paquet (protocole TCP/IP)
            syn = IP(dst=host)/TCP(dport=port, flags='S')
        except socket.gaierror:
            raise ValueError('Hostname {} is not resolved'.format(host))

        ans, unans = sr(syn, timeout=2, retry=1)  # envoi le paquet

        for sent, received in ans:
            # verifie le flag (drapeau) de notre paquet
            if received[TCP].flags == "SA":
                result.append(received[TCP].sport)

        return result

    def connect_to_proxy(self):
        proxy = Proxy([
            "--hostname", "192.168.43.211",
            "--port", "4546",
        ])
        current_proxy = proxy.proxy
        res = proxy.test_proxy(current_proxy)
        print(res)

        if res == 1:
            print("Success")
        else:
            print("failure")

    """
    give more details about traffic of a host
    while opening wireshark
    sniff tous les paquets en ouvrant wireshark pour voir plus de details
    """

    def host_sniffer(self, host):
        try:
            wireshark(sniff(count=50, filter="host " + str(host),
                      prn=lambda x: x.sniffed_on+": " + x.summary()))
        except Exception as e:
            print(e)

    """
        deconnexion d'un appareil a un reseau wifi par desauthentification 
        par l'envoi d'une trame de desauthentification
    """

    def disconnect_device(self, host):
        #device = Device.objects.get(pk=id)
        target_mac = DetectNetwork().get_device_info(host)['MAC Address']
        gateway_mac = DetectNetwork().get_device_info(
            "192.168.43.1")['MAC Address']
        dot11 = Dot11(addr1=target_mac, addr2=gateway_mac, addr3=gateway_mac)
        packet = RadioTap()/dot11/Dot11Deauth(reason=7)  # trame de desauthentification
        try:
            sendp(packet, inter=0.1, count=100, verbose=1)
        except Exception as err:
            print(err)


    def get_service_turn_on(self, host) -> str:
        output_result = ''
        command_stdout = subprocess.Popen(
            ['nmap', str(host)], 
            stdout=subprocess.PIPE
        )
        try:
            output, err = command_stdout.communicate(timeout=10)
            output_result = output.decode('utf-8', 'ignore')
        except Exception as e:
            print(e)
            command_stdout.kill()

        return output_result


    def malware_detect(self, host) -> str:
        output_result = ''
        command_line = "nmap -sV --script=http-malware-host  " + str(host)
        argument = shlex.split(command_line)
        command_stdout = subprocess.Popen(argument, stdout=subprocess.PIPE)
        try:
            output, err = command_stdout.communicate()
            output_result = output.decode('utf-8', 'ignore')
        except:
            command_stdout.kill()

        return output_result

  
    def found_device(self, host):
        command_line = "ping " + str(host)
        argument = shlex.split(command_line)
        command = subprocess.Popen(
            argument, stdout=subprocess.PIPE, shell=True)
        try:
            out, err = command.communicate()
            print(out)
        except Exception as e:
            command.kill()

        return out


    def scan_all_network(self):
        output_result = ''
        my_ip = IP(dst="0.0.0.0").src
        ip_network, host = DetectNetwork().seperate_ip(my_ip)
        ip_network = ip_network + '0'

        # command_line = "nmap 192.168.43.0/24"
        command_line = "nmap " + ip_network + "/24"
        argument = shlex.split(command_line)
        command = subprocess.Popen(
            argument, stdout=subprocess.PIPE, shell=True)
        try:
            out, err = command.communicate()
            output_result = out.decode('utf-8', 'ignore')
        except Exception as e:
            command.kill()

        return output_result

 
    def check_port(self, host, port) -> bool:
        conf.verb = 0
        is_open = False
        SYN, ACK = 0x02, 0x10
        SYNACK = SYN | ACK

        try:
            syn_pkt = IP(dst=host) / TCP(dport=port, flags='S')
            synack_pkt = sr1(syn_pkt, timeout=1)
        except socket.gaierror:
            raise ValueError("Hostname is not resolved")

        if int(port) <= 65534:
            if synack_pkt is None:
                print("cannot reach host")
            elif synack_pkt['TCP'].flags == SYNACK:
                is_open = True
            else:
                is_open = False
        else:
            print("Undefined port")
        return is_open


if __name__ == "__main__":
    #interact(mydict = globals(), mybanner= "Mon code interactif a moi")
    a = DetectNetwork()
    print(a._get_host())
    print(a._DetectNetwork__host + " anotation")
    a._set_host("127.0.0.01")
    print(a._get_host())
    print(id(a))
