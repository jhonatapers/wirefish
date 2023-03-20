from typing import List
from binascii import hexlify
from util.byte import Byte
from struct import unpack
from metrics.protocol import Protocol, Arp, Ipv4, Ipv6, Other
from vo.packet import Packet

class Metrics:

    def __init__(self):
        self.packets : List[Packet] = []
        self.protocols : List[Protocol] = [Arp(), Ipv4(), Ipv6()]

    def analyzepacket(self, packet : Packet):

        self.packets.append(packet)

        ethernetHeader= unpack("!6s6s2s",packet.data[0:14])
        destinationMAC:bytes= ethernetHeader[0]
        sourceMAC:bytes = ethernetHeader[1]
        proto:bytes= ethernetHeader[2]
        
        
        strategy : Protocol = Other()
        for protocol in self.protocols:
            if(protocol.aplies(proto)):
                strategy = protocol

        print('---------------------------------------------')
        print('PACKET -> ('+str(packet.index)+')')
        print('| ENLACE HEADER:')
        print(' \\')
        print('   | Destination MAC: ' + Byte.to_mac_adress(destinationMAC))
        print('   | Source MAC: ' + Byte.to_mac_adress(sourceMAC))
        print('   | Protocol: ' + protocol.name())

        strategy.analyze(packet.data[14:])
        print('---------------------------------------------')
            

    def finalmetrics(self):
        print(self.packets)

    
