from typing import List
from abc import ABC, abstractmethod
from struct import unpack
from util.byte import Byte

class Protocol(ABC):

    @abstractmethod
    def applies(self, protocol : bytes):
        pass

    @abstractmethod
    def name(self):
        pass
        
    @abstractmethod
    def analyze(self, packet : bytes):
        pass

    @abstractmethod
    def metrics(self,total_patckets:int):
        pass

class Arp(Protocol):

    def __init__(self):
        self.proto = b'\x08\x06'
        self.count=0
        self.count_reply=0
        self.count_request=0
        pass

    def applies(self, protocol : bytes):
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
        print('      | NETWORK '+self.name()+' :')
        print('       \\ ARP HEADER')
        print('         | Operation: ' + self.operation(operation))
        self.count+=1
    
    def metrics(self,total_patckets:int):
        print('--------------------------------')
        print(self.name()+' -> Total: '+str(self.count) + ' Percent: ' + '{0:.2f}%'.format((self.count/total_patckets)*100))
        print(self.name()+'_Request : -> Total: '+str(self.count_request) + ' Percent: ' '{0:.2f}%'.format((self.count_request/total_patckets)*100))
        print(self.name()+'_Reply : -> Total: '+str(self.count_reply) + ' Percent: ' '{0:.2f}%'.format((self.count_reply/total_patckets)*100))

    def operation(self, operation : bytes):
        op = Byte.to_decimal(operation)
        if op == 1:
            self.count_request+=1
            return 'Request'
        elif op ==  2:
            self.count_reply+=1
            return 'Reply'
            


class Ipv4(Protocol):

    def __init__(self,protocols : List[Protocol]):
        self.proto = b'\x08\x00'
        self.protocols=protocols
        self.count=0
        pass

    def applies(self, protocol : bytes):
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
        source_address=ipv4[8]
        destination_address=ipv4[9]
        options=ipv4[10]

        for protocol in self.protocols:
            if(protocol.applies(proto)):
                print('      | NETWORK '+self.name()+' :')
                print('       \\ IP HEADER')
                print('         | Version: ' + str(version))
                print('         | Ihl: ' + str(ihl))
                print('         | Destination Adress: ' + Byte.to_ipv4(destination_address))
                print('         | Source Adress: ' + Byte.to_ipv4(source_address))
                print('         | Protocol: ' + protocol.name())
                print('          \\')
                protocol.analyze(packet[24:])

        self.count+=1

    def metrics(self,total_patckets:int):
        print('--------------------------------')
        print(self.name()+' -> Total: '+str(self.count) + ' Percent: ' + '{0:.2f}%'.format((self.count/total_patckets)*100))

class Ipv6(Protocol):

    def __init__(self,protocols : List[Protocol] ):
        self.proto = b'\x86\xdd'
        self.protocols =protocols
        self.count=0
        pass

    def applies(self, protocol : bytes):
        if(protocol == self.proto):
            return True
       
    def name(self):
        return 'IPV6'
    
    def analyze(self, packet : bytes):
        ipv6 = unpack("4s2s1s1s16s16s", packet[:40])
        next_header=ipv6[2]
        source_address=ipv6[4]
        destination_address=ipv6[5]

        for protocol in self.protocols:
            if(protocol.applies(next_header)):
                print('      | NETWORK '+self.name()+' :')
                print('       \\ IP HEADER')
                print('         | Destination Adress: ' + Byte.to_ipv6(destination_address))
                print('         | Source Adress: ' + Byte.to_ipv6(source_address))
                print('         | Protocol: ' + protocol.name())
                print('          \\')
                protocol.analyze(packet[24:])
        self.count+=1

    def metrics(self,total_patckets:int):
        print('--------------------------------')
        print(self.name()+' -> Total: '+str(self.count) + ' Percent: ' + '{0:.2f}%'.format((self.count/total_patckets)*100))

class Tcp(Protocol):

    def __init__(self, protocols : List[Protocol]):
        self.proto = b'\x06'
        self.protocols=protocols
        self.count=0
        self.port_uses={}
        pass

    def applies(self, protocol : bytes):
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

        print('            | Transport '+ self.name() +' :')
        print('             \\')
        print('               | Source Port: ' + str(Byte.to_port(source_port)))
        print('               | Destination Port: ' + str(Byte.to_port(destination_port)))
        

        source_proto : Protocol = OtherApplication()
        for protocol in self.protocols:
            if(protocol.applies(Byte.to_port(source_port))):
                source_proto = protocol
        print('                \\')
        source_proto.analyze(packet)
        #self.port_use(Byte.to_port(source_port))
                
        destination_proto : Protocol = OtherApplication()
        for protocol in self.protocols:
            if(protocol.applies(Byte.to_port(destination_port))):
                destination_proto = protocol
        print('                \\')
        destination_proto.analyze(packet)
        self.port_use(Byte.to_port(source_port))

        self.count+=1

    def port_use(self, port:int):
        if port in self.port_uses:
            self.port_uses[port]+=1
        else:
            self.port_uses[port]=1

    def metrics(self,total_patckets:int):
        print('--------------------------------')
        print(self.name()+' -> Total: '+str(self.count) + ' Percent: ' + '{0:.2f}%'.format((self.count/total_patckets)*100))
        self.most_used_ports(self.port_uses)
    
    def most_used_ports(self, port_uses):
        most_used_ports=dict(sorted(port_uses.items(), key=lambda x: x[1], reverse=True))
        max_iterations=5
        current_iteration=0
        for key,value in most_used_ports.items():
            if max_iterations == current_iteration:
                break;
            print('PORT: '+str(key)+' USES: '+str(value))
            current_iteration+=1
        

class Udp(Protocol):

    def __init__(self, protocols : List[Protocol]):
        self.proto = b'\x17'
        self.protocols=protocols
        self.count=0
        self.port_uses = {}
        pass

    def applies(self, protocol : bytes):
        if(protocol == self.proto):
            return True
       
    def name(self):
        return 'UDP'
    
    def analyze(self, packet : bytes):
        udp = unpack("!2s2s2s2s", packet[:8])
        source_port=udp[0]
        destination_port=udp[1]
        length=udp[2]
        checksum=udp[3]

        print('          \\')
        print('            | Transport '+ self.name() +' :')
        print('             \\')
        print('               | Source Port: ' + str(Byte.to_port(source_port)))
        print('               | Destination Port: ' + str(Byte.to_port(destination_port)))

        source_proto : Protocol = OtherApplication()
        for protocol in self.protocols:
            if(protocol.applies(Byte.to_port(source_port))):
                source_proto = protocol
        print('                \\')
        source_proto.analyze(packet)
        #self.port_use(Byte.to_port(source_port))
                
        destination_proto : Protocol = OtherApplication()
        for protocol in self.protocols:
            if(protocol.applies(Byte.to_port(destination_port))):
                destination_proto = protocol
        print('                \\')
        destination_proto.analyze(packet)
        self.port_use(Byte.to_port(source_port))

        self.count+=1

    def port_use(self, port:int):
        if port in self.port_uses:
            self.port_uses[port]+=1
        else:
            self.port_uses[port]=1

    def metrics(self,total_patckets:int):
        print('--------------------------------')
        print(self.name()+' -> Total: '+str(self.count) + ' Percent: ' + '{0:.2f}%'.format((self.count/total_patckets)*100))
        self.most_used_ports(self.port_uses)
    
    def most_used_ports(self, port_uses):
        most_used_ports=dict(sorted(port_uses.items(), key=lambda x: x[1], reverse=True))

        max_iterations=5
        current_iteration=0
        for key,value in most_used_ports.items():
            if max_iterations == current_iteration:
                break;
            print('PORT: '+str(key)+' USES: '+str(value))
            current_iteration+=1

class Icmp(Protocol):

    def __init__(self):
        self.proto = b'\x01'
        self.count=0
        pass

    def applies(self, protocol : bytes):
        if(protocol == self.proto):
            return True
       
    def name(self):
        return 'ICMP'
    
    def analyze(self, packet : bytes):
        print('                \\')
        print('                  | Application: ' + self.name())
        self.count+=1
        
    def metrics(self,total_patckets:int):
        print('--------------------------------')
        print(self.name()+' -> Total: '+str(self.count) + ' Percent: ' + '{0:.2f}%'.format((self.count/total_patckets)*100))
    

class IcmpV6(Protocol):

    def __init__(self):
        self.proto = b'\x3a'
        self.count=0
        pass

    def applies(self, protocol : bytes):
        if(protocol == self.proto):
            return True
       
    def name(self):
        return 'ICMPv6'
    
    def analyze(self, packet : bytes):
        print('                \\')
        print('                  | Application: ' + self.name())
        self.count+=0

    def metrics(self,total_patckets:int):
        print('--------------------------------')
        print(self.name()+' -> Total: '+str(self.count) + ' Percent: ' + '{0:.2f}%'.format((self.count/total_patckets)*100))

class Http(Protocol):
        
    def __init__(self):
        self.port = 80
        self.count=0
        pass

    def applies(self, port : int):
        if(port == self.port):
            return True
       
    def name(self):
        return 'HTTP'
    
    def analyze(self, packet : bytes):
        print('                \\')
        print('                  | Application: ' + self.name())
        self.count+=0

    def metrics(self,total_patckets:int):
        print('--------------------------------')
        print(self.name()+' -> Total: '+str(self.count) + ' Percent: ' + '{0:.2f}%'.format((self.count/total_patckets)*100))

class Tls(Protocol):
        
    def __init__(self):
        self.port = 443
        self.count=0
        pass

    def applies(self, port : int):
        if(port == self.port):
            return True
       
    def name(self):
        return 'TLS(Https)'
    
    def analyze(self, packet : bytes):
        print('                \\')
        print('                  | Application: ' + self.name())
        self.count+=0

    def metrics(self,total_patckets:int):
        print('--------------------------------')
        print(self.name()+' -> Total: '+str(self.count) + ' Percent: ' + '{0:.2f}%'.format((self.count/total_patckets)*100))

class OtherApplication(Protocol):

    def __init__(self):
        self.count=0
        pass

    def applies(self, protocol : bytes):
        return True
       
    def name(self):
        return 'OTHER APPLICATION'
    
    def analyze(self, packet : bytes):
        print('                \\')
        print('                  | Application: ' + self.name())
        self.count+=0

    def metrics(self,total_patckets:int):
        print('--------------------------------')
        print(self.name()+' -> Total: '+str(self.count) + ' Percent: ' + '{0:.2f}%'.format((self.count/total_patckets)*100))