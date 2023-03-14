from abc import ABC, abstractmethod

class Protocol(ABC):

    @abstractmethod
    def aplies(self, protocol : bytes):
        pass

    @abstractmethod
    def name(self):
        pass
        
    @abstractmethod
    def analyze(self, packet : bytes):
        pass

class Arp(Protocol):

    def __init__(self):
        self.proto = b'\x08\x06'
        pass

    def aplies(self, protocol : bytes):
        if(protocol == self.proto):
            return True
    
    def name(self):
        return 'ARP'

    def analyze(self, packet : bytes):
        print(packet)

class Ipv4(Protocol):

    def __init__(self):
        self.proto = b'\x08\x00'
        pass

    def aplies(self, protocol : bytes):
        if(protocol == self.proto):
            return True
        
    def name(self):
        return 'IPV4'

    def analyze(self, packet : bytes):
        print(packet)

class Ipv6(Protocol):

    def __init__(self):
        self.proto = b'\x08\xDD'
        pass

    def aplies(self, protocol : bytes):
        if(protocol == self.proto):
            return True
       
    def name(self):
        return 'IPV6'
    
    def analyze(self, packet : bytes):
        print(packet)
    