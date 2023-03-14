import socket

from metrics.metrics import Metrics
from vo.packet import Packet

class Wirefish:
    
    def __init__(self, metrics : Metrics):
        self.metrics = metrics
        self.socketraw : socket.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    def availableInterfaces(self):
        return socket.if_nameindex()

    def run(self, interface : str, maxPackets: int):

        self.socketraw.bind((interface, socket.INADDR_ANY))

        index = 0
        while (index < maxPackets):
            data, addr = self.socketraw.recvfrom(65535)
            self.metrics.analyzepacket(Packet(index, data))
            index+=1


            


#estrategias = [ipv4.ipv4(), ipv6.ipv6(), arp.arp()]

# create a raw socket for network capture
#s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

# bind the socket to a network interface
#s.bind(('eth0', 0))
# bind the socket to a WLAN interface
#s.bind(('enp4s0f1', socket.INADDR_ANY))

# capture packets
# while (index < )):
#     data, addr = s.recvfrom(65535) 
    
#     ethernetHeader=data[0:14]
#     ethrheader=struct.unpack("!6s6s2s",ethernetHeader)
#     destinationMAC= binascii.hexlify(ethrheader[0])
#     sourceMAC= binascii.hexlify(ethrheader[1])
#     protocol= binascii.hexlify(ethrheader[2])

#     for estrategia in self.str:
#         if(estrategia.aplies(ethrheader[2])):
#            estrategia.addPacket(data)
    
    # print('*/*/*/*/*/*/')
    # print(destinationIP)
    # print(sourceIP)
    # print(protocol)
    # print(receivedPacket)
    # print('*/*/*/*/*/*/')
    #definimos a porta maxima para pegar todas
    # print('\n')
    # print("Received packet from:", addr)
    # print(data)
    # aham= binascii.hexlify(data)
    # print('-------------')
    # print(aham)