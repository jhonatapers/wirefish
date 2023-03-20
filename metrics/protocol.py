from typing import List
from abc import ABC, abstractmethod
from struct import unpack
from util.byte import Byte

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

class Other(Protocol):

    def __init__(self):
        pass

    def aplies(self, protocol : bytes):
        return True
       
    def name(self):
        return 'OTHER'
    
    def analyze(self, packet : bytes):
        print('    \\')
        print('      | NETWORK '+self.name()+' :')
        

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
        arp = unpack("!2s2s1s1s2s6s4s6s4s",packet[:28])
        hw_add_type=arp[0]
        proto_add_type=arp[1]
        hw_add_len=arp[2]
        proto_add_len=arp[3]
        operation=arp[4]
        src_hw_add=arp[5]
        src_proto_add=arp[6]
        targ_hw_add=arp[7]
        targ_hw_add=arp[8]
        print(packet)

class Ipv4(Protocol):

    def __init__(self):
        self.proto = b'\x08\x00'
        self.protocols : List[Protocol] = [Tcp(),Udp(),Icmp()]
        pass

    def aplies(self, protocol : bytes):
        if(protocol == self.proto):
            return True
        
    def name(self):
        return 'IPV4'

    def analyze(self, packet : bytes):
        ipv4 = unpack("!1s1s2s2s2s1s1s2s4s4s4s", packet[:24])
        version_and_ihl=Byte.to_bits(ord(ipv4[0])) #half byte + half byte
        version=Byte.from_bit_array(version_and_ihl[0:4])
        ihl=Byte.from_bit_array(version_and_ihl[4:8])
        type_service=ipv4[1]
        total_length=ipv4[2]
        identification=ipv4[3]
        flags_and_fragment_offset=ipv4[4] #half byte + reamain
        time_to_live=ipv4[5]
        proto=ipv4[6]
        header_checksum=ipv4[7]
        source_adress=ipv4[8]
        destination_adress=ipv4[9]
        options=ipv4[10]

        for protocol in self.protocols:
            if(protocol.aplies(proto)):
                print('    \\')
                print('      | NETWORK '+self.name()+' :')
                print('       \\ IP HEADER')
                print('         | Version: ' + str(version))
                print('         | Ihl: ' + str(ihl))
                print('         | Destination Adress: ' + Byte.to_ipv4(destination_adress))
                print('         | Source Adress: ' + Byte.to_ipv4(source_adress))
                print('         | Protocol: ' + protocol.name())
                protocol.analyze(packet[24:])

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
        print(self.name())

class Tcp(Protocol):

    def __init__(self):
        self.proto = b'\x06'
        self.protocols : List[Protocol] = [Http()]
        pass

    def aplies(self, protocol : bytes):
        if(protocol == self.proto):
            return True
       
    def name(self):
        return 'TCP'
    
    def analyze(self, packet : bytes):
        tcp = unpack("!2s2s4s4s1s1s2s", packet[:16])
        source_port=tcp[0]
        destination_port=tcp[1]
        sequence_nunber=tcp[2]
        ack_number=tcp[3]
        off_set_and_reserved=tcp[4]
        flags=tcp[5]
        window=tcp[6]

        print('          \\')
        print('            | Transport '+ self.name() +' :')
        print('             \\')
        print('               | Source Port: ' + str(Byte.to_port(source_port)))
        print('               | Destination Port: ' + str(Byte.to_port(destination_port)))

        for protocol in self.protocols:
            if(protocol.aplies(Byte.to_port(source_port))):
                protocol.analyze(packet)
                
        for protocol in self.protocols:
            if(protocol.aplies(Byte.to_port(destination_port))):
                protocol.analyze(packet)
        

class Udp(Protocol):

    def __init__(self):
        self.proto = b'\x17'
        pass

    def aplies(self, protocol : bytes):
        if(protocol == self.proto):
            return True
       
    def name(self):
        return 'UDP'
    
    def analyze(self, packet : bytes):
        print(packet)
        print(self.name())

class Icmp(Protocol):

    def __init__(self):
        self.proto = b'\x01'
        pass

    def aplies(self, protocol : bytes):
        if(protocol == self.proto):
            return True
       
    def name(self):
        return 'ICMP'
    
    def analyze(self, packet : bytes):
        print('                \\')
        print('                  | Application: ' + self.name())

class Http(Protocol):
        
    def __init__(self):
        self.port = 80
        pass

    def aplies(self, port : int):
        if(port == self.port):
            return True
       
    def name(self):
        return 'HTTP'
    
    def analyze(self, packet : bytes):
        print('                \\')
        print('                  | Application: ' + self.name())

class Tls(Protocol):
        
    def __init__(self):
        self.port = 443
        pass

    def aplies(self, port : int):
        if(port == self.port):
            return True
       
    def name(self):
        return 'TLS(Https)'
    
    def analyze(self, packet : bytes):
        print('                \\')
        print('                  | Application: ' + self.name())