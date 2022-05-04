from email.headerregistry import HeaderRegistry
from re import S
import socket
import struct
import sys

def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

def ipv4(addr):
    return '.'.join(map(str, addr))

def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]



def main():
    
    # c:\Users\Jan\Desktop\I\UPM\Trabajo de Fin de Grado\dave\node
    HOST = socket.gethostbyname(socket.gethostname())
    print("HOST:", HOST)

    conn = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_IP) 
    # create a raw socket and bind it to the public interface

    conn.bind(('192.168.1.33', 0))

    # Include IP headers

    conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    #receives all packets

    conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    #s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

    while True:
        raw_data, addr = conn.recvfrom(65535)
        dest_mac, src_mac, proto, data = ethernet_frame(raw_data)
        print('\nEthernet Frame:')
        print('Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, proto))

if __name__ == '__main__':
    main()
