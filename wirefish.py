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