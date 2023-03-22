from typing import List
from socket import socket

class Byte:

    def to_decimal(bytes : bytes):
        return int(bytes.hex(), 16)

    def to_bits(b):
        bits = bin(b)[2:].rjust(8, '0')
        return [int(bit) for bit in bits]

    def from_bit_array(bits : List[int]):
        return int(''.join(map(str, bits)), 2)
    
    def to_mac_adress(mac_bytes : bytes):
        return ':'.join(['{:02x}'.format(b) for b in mac_bytes])

    def to_ipv4(ipvv4 : bytes):
        return '.'.join([str(int('{:03x}'.format(b),16)) for b in ipvv4])
    
    def to_ipv6(ipv6 : bytes):
        return ipv6#socket.inet_ntop(socket.AF_INET6, ipv6)
    
    def to_port(port: bytes):
        return  int.from_bytes(port, byteorder='big')
