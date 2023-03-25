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
        return protocol == self.proto
    
    def name(self):
        return 'ARP'

    def analyze(self, packet : bytes):
        arp = unpack("!2s2s1s1s2s6s4s6s4s",packet[:28])
        operation=arp[4]
        self.operation(operation)
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
        return protocol == self.proto
        
    def name(self):
        return 'IPV4'

    def analyze(self, packet : bytes):
        ipv4 = unpack("!1s1s2s2s2s1s1s2s4s4s4s", packet[:24])
        proto=ipv4[6]

        for protocol in self.protocols:
            if(protocol.applies(proto)):
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
        return protocol == self.proto
       
    def name(self):
        return 'IPV6'
    
    def analyze(self, packet : bytes):
        ipv6 = unpack("4s2s1s1s16s16s", packet[:40])
        next_header=ipv6[2]
        source_address=ipv6[4]
        destination_address=ipv6[5]

        for protocol in self.protocols:
            if(protocol.applies(next_header)):
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
        return protocol == self.proto
       
    def name(self):
        return 'TCP'
    
    def analyze(self, packet : bytes):
        tcp = unpack("!2s2s4s4s1s1s2s", packet[:16])
        source_port=tcp[0]
        destination_port=tcp[1]


        other_protocol:OtherApplication
        for protocol in self.protocols:
            if(protocol.name() == OtherApplication().name()):
                other_protocol = protocol

        destination_proto=other_protocol
        for protocol in self.protocols:
            if(protocol.applies(destination_port) and protocol.name() != OtherApplication().name()):
                destination_proto = protocol
                other=False

        source_proto=other_protocol
        for protocol in self.protocols:
            if(protocol.applies(source_port) and protocol.name() != OtherApplication().name()):
                source_proto = protocol
                
        if destination_proto.name() != OtherApplication().name():
                destination_proto.analyze(packet)
                self.port_use(Byte.to_port(destination_port))
        else:
            source_proto.analyze(packet)
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
        self.proto = b'\x11'
        self.protocols=protocols
        self.count=0
        self.port_uses = {}
        pass

    def applies(self, protocol : bytes):
        return protocol == self.proto
       
    def name(self):
        return 'UDP'
    
    def analyze(self, packet : bytes):
        udp = unpack("!2s2s2s2s", packet[:8])
        source_port=udp[0]
        destination_port=udp[1]

        if(source_port == b'\x00C' or destination_port == b'\x00C'):
            b = 'merda'

        other_protocol:OtherApplication
        for protocol in self.protocols:
            if(protocol.name() == OtherApplication().name()):
                other_protocol = protocol

        destination_proto=other_protocol
        for protocol in self.protocols:
            if(protocol.applies(destination_port) and protocol.name() != OtherApplication().name()):
                destination_proto = protocol
                other=False

        source_proto=other_protocol
        for protocol in self.protocols:
            if(protocol.applies(source_port) and protocol.name() != OtherApplication().name()):
                source_proto = protocol
                
        if destination_proto.name() != OtherApplication().name():
                destination_proto.analyze(packet)
                self.port_use(Byte.to_port(destination_port))
        else:
            source_proto.analyze(packet)
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
        return protocol == self.proto
       
    def name(self):
        return 'ICMP'
    
    def analyze(self, packet : bytes):
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
        return protocol == self.proto
       
    def name(self):
        return 'ICMPv6'
    
    def analyze(self, packet : bytes):
        self.count+=1

    def metrics(self,total_patckets:int):
        print('--------------------------------')
        print(self.name()+' -> Total: '+str(self.count) + ' Percent: ' + '{0:.2f}%'.format((self.count/total_patckets)*100))

class Http(Protocol):
        
    def __init__(self):
        self.port:int=80
        self.count=0
        pass

    def applies(self, port : bytes):
        return Byte.to_port(port)==self.port
       
    def name(self):
        return 'HTTP'
    
    def analyze(self, packet : bytes):
        self.count+=1

    def metrics(self,total_patckets:int):
        print('--------------------------------')
        print(self.name()+' -> Total: '+str(self.count) + ' Percent: ' + '{0:.2f}%'.format((self.count/total_patckets)*100))

class Tls(Protocol):
        
    def __init__(self):
        self.port:int=443
        self.count=0
        pass

    def applies(self, port : bytes):
        return Byte.to_port(port)==self.port
       
    def name(self):
        return 'TLS(Https)'
    
    def analyze(self, packet : bytes):
        self.count+=1

    def metrics(self,total_patckets:int):
        print('--------------------------------')
        print(self.name()+' -> Total: '+str(self.count) + ' Percent: ' + '{0:.2f}%'.format((self.count/total_patckets)*100))

class Dns(Protocol):
        
    def __init__(self):
        self.port:int=53
        self.count=0
        pass

    def applies(self, port : bytes):
        return Byte.to_port(port)==self.port
       
    def name(self):
        return 'DNS'
    
    def analyze(self, packet : bytes):
        self.count+=1

    def metrics(self,total_patckets:int):
        print('--------------------------------')
        print(self.name()+' -> Total: '+str(self.count) + ' Percent: ' + '{0:.2f}%'.format((self.count/total_patckets)*100))

class Dhcp(Protocol):
        
    def __init__(self):
        self.port:int=67
        self.count=0
        pass

    def applies(self, port : bytes):
        return Byte.to_port(port)==self.port
       
    def name(self):
        return 'DHCP'
    
    def analyze(self, packet : bytes):
        self.count+=1

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
        self.count+=1

    def metrics(self,total_patckets:int):
        print('--------------------------------')
        print(self.name()+' -> Total: '+str(self.count) + ' Percent: ' + '{0:.2f}%'.format((self.count/total_patckets)*100))