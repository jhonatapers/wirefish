from typing import List
from metrics.metrics import Metrics
from metrics.protocol import Protocol, Arp, Ipv4, Ipv6
from wirefish import Wirefish

protocols : List[Protocol] = [Arp(), Ipv4(), Ipv6()]
metrics = Metrics(protocols)
wirefish = Wirefish(metrics)

def selectinterface():
    interfaces = wirefish.availableInterfaces()
    print('Available interfaces:')
    for interface in interfaces:
        print(interface[0], ' - Interface name:', interface[1])

    inpt = input("Select a interface (or 0 to quit)")
    if(inpt.isdigit()):
        if(int(inpt) > 0):
            interface = interfaces[int(inpt)-1][1]
        else:
            return int(inpt)-1
    else:
        interface = inpt

    return interface

def selectmaxpackets():
    inpt = input("Set max packets to analyze (or 0 to quit)")
    if(inpt.isdigit()):
        if(int(inpt) > 0):
            maxpackets = int(inpt)
        else:
            return -1
    else:
        print('Error... wirefish is closing...')
        maxpackets = -1
    return maxpackets

while True:
    interface = selectinterface()
    if(interface == -1):
        break

    maxpackets = selectmaxpackets() 
    if(maxpackets == -1):
        break     

    wirefish.run(interface, maxpackets)


print(metrics)