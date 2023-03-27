from typing import List
from binascii import hexlify
from util.byte import Byte
from struct import unpack
from metrics.protocol import Protocol
from vo.packet import Packet

class Metrics:

    def __init__(self,protocols : List[Protocol], all_protocols : List[Protocol]):
        self.packets:List[Packet]=[]
        self.protocols=protocols
        self.all_protocols=all_protocols
        self.count=0;

    def analyzepacket(self, packet : Packet):

        self.packets.append(packet)



        ethernetHeader= unpack("!6s6s2s",packet.data[0:14])
        destinationMAC:bytes= ethernetHeader[0]
        sourceMAC:bytes = ethernetHeader[1]
        proto:bytes= ethernetHeader[2]
        
        for protocol in self.protocols:
            if(protocol.applies(proto)):
                protocol.analyze(packet.data[14:])
                self.count+=1
            

    def finalmetrics(self,total_patckets:int):
        for protocol in self.all_protocols:
            protocol.metrics(total_patckets)
        total_packets = len(self.packets)
        total_lenght=0
        for packet in self.packets:
            total_lenght+=len(packet.data)

        print('--------------------------------------------')

        print('Avarage packet lenght: ' + str(total_lenght/total_packets))

        min_lenght=len(min(self.packets, key=lambda p: len(p.data)).data)
        max_lenght=len(max(self.packets, key=lambda p: len(p.data)).data)

        print('Min packet lenght: ' + str(min_lenght))
        print('Max packet lenght: ' + str(max_lenght))

    
