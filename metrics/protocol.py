from abc import ABC, abstractmethod
from struct import unpack

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
        arp = unpack("!2s2s1s1s2s6s4s6s4s",packet[14:42])
        hw_add_type=arp[0]
        proto_add_type=arp[1]
        hw_add_len=arp[2]
        proto_add_len=arp[3]
        operation=arp[4]
        src_hw_add=arp[5]
        src_proto_add=arp[6]
        targ_hw_add=arp[7]
        targ_hw_add=arp[8]

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
    