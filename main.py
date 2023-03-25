from typing import List
from metrics.metrics import Metrics
from wirefish import Wirefish
from metrics.protocol import Arp, Ipv4, Ipv6, Tcp, Udp, Dns, Icmp, IcmpV6, Http, Tls, Dhcp, OtherApplication


other_application=OtherApplication()
tls=Tls()
dhcp=Dhcp()
http=Http()
icmpv6=IcmpV6()
icmp=Icmp()
dns=Dns()
udp=Udp([dns,dhcp,other_application])
tcp=Tcp([dns,http,tls,other_application])
ipv6=Ipv6([udp,tcp,icmpv6])
ipv4=Ipv4([udp,tcp,icmp])
arp=Arp()


metrics = Metrics([arp,ipv4,ipv6], [other_application,dhcp,tls,http,icmp,icmpv6,dns,udp,tcp,ipv6,ipv4,arp])
wirefish = Wirefish(metrics)

def select_interface():
    interfaces = wirefish.availableInterfaces()
    print('Available interfaces:')
    for interface in interfaces:
        print(interface[0], ' - Interface name:', interface[1])

    inpt = input("Select a interface (or 0 to quit)")
    if(inpt.isdigit()):
        if(int(inpt) > 0):
            interface = interfaces[int(inpt)-1]
        else:
            return int(inpt)-1
    else:
        interface = inpt

    return interface

def select_max_packets():
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
    interface = select_interface()
    if(interface == -1):
        break

    maxpackets = select_max_packets() 
    if(maxpackets == -1):
        break     

    wirefish.run(interface, maxpackets)
    wirefish.final_metrics()
    print('----------------------------')