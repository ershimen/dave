import socket
import struct
import sys

def get_mac_addr(bytes_addr):
    bytes_str = map('{:02X}'.format, bytes_addr)
    return ':'.join(bytes_str)

def ethernet_frame(data):
    print(data)
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[14:])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[:14] 



def main():
    conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    HOST = socket.gethostbyname(socket.gethostname())
    print("HOST: %s" % HOST)
    conn.bind((HOST, 0))

    conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    while True:
        raw_data, addr = conn.recvfrom(65535)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\nEthernet Frame:')
        print('Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))

if __name__ == '__main__':
    main()

import pcap
from construct.protocols.ipstack import ip_stack

def print_packet(pktlen, data, timestamp):
    if not data:
        return

    stack = ip_stack.parse(data)
    payload = stack.next.next.next
    print(payload)


p = pcap.pcapObject()
p.open_live('eth0', 1600, 0, 100)
p.setfilter('dst port 80', 0, 0)

print('Press CTRL+C to end capture')
try:
    while True:
        p.dispatch(1, print_packet)
except KeyboardInterrupt:
    print # Empty line where ^C from CTRL+C is displayed
    print('%d packets received, %d packets dropped, %d packets dropped by interface' % p.stats())