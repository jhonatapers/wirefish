from typing import List
from binascii import hexlify
from struct import unpack
from metrics.protocol import Protocol
from vo.packet import Packet

class Metrics:

    def __init__(self, protocols : List[Protocol]):
        self.packets : List[Packet] = []
        self.protocols : List[Protocol] = protocols

    def analyzepacket(self, packet : Packet):

        self.packets.append(packet)

        ethernetHeader= unpack("!6s6s2s",packet.data[0:14])
        destinationMAC:bytes= ethernetHeader[0]
        sourceMAC:bytes = ethernetHeader[1]
        proto:bytes= ethernetHeader[2]

        for protocol in self.protocols:
            if(protocol.aplies(proto)):
                print('---------------------------------------------')
                print('PACKET -> ('+str(packet.index)+')')
                print('ENLACE:')
                print('Destination MAC: ' + self.macadress(destinationMAC))
                print('Source MAC: ' + self.macadress(sourceMAC))
                print('Protocol: ' + protocol.name())
                print('')

                protocol.analyze(packet.data)
                print('---------------------------------------------')

    def macadress(self, mac_bytes : bytes):
        return ':'.join(['{:02x}'.format(b) for b in mac_bytes])

    def finalmetrics(self):
        print(self.packets)

    
