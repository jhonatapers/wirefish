import socket

from metrics.metrics import Metrics
from vo.packet import Packet

class Wirefish:
    
    def __init__(self, metrics : Metrics):
        self.total_patckets=0
        self.metrics = metrics
        self.socketraw : socket.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    def availableInterfaces(self):
        return socket.if_nameindex()

    def run(self, interface, maxPackets: int):

        self.socketraw.bind((interface[1], 0))

        index = 0
        while (index < maxPackets):
            data, addr = self.socketraw.recvfrom(65535)
            self.metrics.analyzepacket(Packet(index, data))
            index+=1
            self.total_patckets+=1

    def final_metrics(self):
        self.metrics.finalmetrics(self.total_patckets)
  
         