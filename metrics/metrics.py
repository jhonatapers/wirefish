from typing import List
from binascii import hexlify
from util.byte import Byte
from struct import unpack
from metrics.protocol import Protocol, Arp, Ipv4, Ipv6
from vo.packet import Packet

class Metrics:

    def __init__(self,protocols : List[Protocol]):
        self.packets:List[Packet]=[]
        self.protocols=protocols
        self.count=0;

    def analyzepacket(self, packet : Packet):

        self.packets.append(packet)

        ethernetHeader= unpack("!6s6s2s",packet.data[0:14])
        destinationMAC:bytes= ethernetHeader[0]
        sourceMAC:bytes = ethernetHeader[1]
        proto:bytes= ethernetHeader[2]
        
        for protocol in self.protocols:
            if(protocol.applies(proto)):
                print('---------------------------------------------')
                print('PACKET -> ('+str(packet.index)+')')
                print('| ENLACE HEADER:')
                print(' \\')
                print('   | Destination MAC: ' + Byte.to_mac_adress(destinationMAC))
                print('   | Source MAC: ' + Byte.to_mac_adress(sourceMAC))
                print('   | Protocol: ' + protocol.name())
                print('    \\')

                protocol.analyze(packet.data[14:])

                print('PACKET:')
                print(packet.data)
                print('---------------------------------------------')
                self.count+=1
            

    def finalmetrics(self):
        for protocol in self.protocols:
            print(protocol.name() + str(protocol.counter()))

    
