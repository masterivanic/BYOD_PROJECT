

import abc


class DetectNetworkFormalInterface(metaclass=abc.ABCMeta):

    @classmethod
    def __subclasshook__(cls, subclass):
        return (hasattr(subclass, 'seperate_ip') and
                callable(subclass.seperate_ip) and
                hasattr(subclass, 'scan') and
                callable(subclass.scan) and
                hasattr(subclass, 'get_resolution_name') and
                callable(subclass.get_resolution_name) and
                hasattr(subclass, 'get_service_turn_on') and
                callable(subclass.get_service_turn_on) and
                hasattr(subclass, 'malware_detect') and
                callable(subclass.malware_detect) and
                callable(subclass.found_device) and
                hasattr(subclass, 'found_device') and
                callable(subclass.scan_all_network) and
                hasattr(subclass, 'scan_all_network') and
                callable(subclass.check_port) and
                hasattr(subclass, 'check_port') or
                NotImplemented)

    @abc.abstractmethod
    def seperate_ip(self, ip: str):
        """ 
            return host and ip address
            for a given address 
        """
        pass

    @abc.abstractmethod
    def scan(self):
        """
            @scan
            scan() -> none: this method check all available host in a network
            using the ping command like  ex: ping host -n 1 
            resolve hostname by using socket API 
        """
        pass

    @abc.abstractmethod
    def get_resolution_name(self):
        pass

    @abc.abstractmethod
    def get_service_turn_on(self, host) -> str:
        """
        @get_service_turn
            get service turn on a device by nmap scan..
            check documentation here: https://nmap.org     
        """
        pass

    @abc.abstractmethod
    def malware_detect(self, host) -> str:
        """
            @malware_detect
                malware scan with nmap
                check documentation here: https://nmap.org   
        """
        pass

    @abc.abstractmethod
    def found_device(self, host):
        """
            @found_device
                check if device is up or down with ping command
        """
        pass

    @abc.abstractmethod
    def scan_all_network(self):
        """
            @scan_all_network
                scan the entire network
        """
        pass

    @abc.abstractmethod
    def check_port(self, host, port) -> bool:
        """
            @check_port
            get status port of a port, check if it's up or down
            do by implement a TCP connection
        """
        pass
