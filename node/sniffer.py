from logging.config import listen
from struct import pack
import pyshark
import sys
import os
import socket
import json
from time import sleep
from threading import Thread, Lock
import subprocess

# global mutex for port list
mutex = Lock()
ports = list()

def addPort(port):
    mutex.acquire()
    ports.append(port)
    mutex.release()

def sniffer(packet_filter):
    capture = pyshark.LiveCapture(interface='Adapter for loopback traffic capture', bpf_filter=packet_filter)

    app_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    addr = ("127.0.0.1", 3333)#----------------------------------------- ver puerto en js!!!!!

    for packet in capture.sniff_continuously(packet_count=100):
        if str(packet.tcp.flags_push) == "1": # si es un paquete con contenido
            #print("ports: srcport: {}, dstport: {}, port: {}".format(packet.tcp.srcport, packet.tcp.dstport, packet.tcp.port))
            print("New packet: from {} to {}".format(packet.tcp.srcport, packet.tcp.dstport))
            msg = "".join(map(lambda c: chr(int(c, 16)), str(packet.tcp.payload).split(':')))
            app_server.sendto(bytes(msg, encoding='utf-8'), addr)
            print("'" + msg + "'")
            print()

def connect_broker(broker_ip, broker_port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((broker_ip, broker_port))

def add_port_packet_filter(packet_filter, port):
    if packet_filter == "":
        return "tcp port %d" % port
    return packet_filter + " or tcp port %d" % port

# proceso que interactua con el nodo
def udp_listener(process, packet_filter, node_port):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as listener:
        listener.bind(("", 0))
        listener_port = listener.getsockname()[1]
        print("Listening on port %d" % listener_port)
        print("localhost:%d:%s" % (listener_port, node_port))
        print("ncat.exe -u 127.0.0.1", listener_port)
        print("""{"type": "STOP", "args":"STOP"}""")
        end = False
        while not end:
            msg_raw, addr = listener.recvfrom(2048)
            #print("---------msg from %s:%s" % (addr[0], addr[1]))
            #print("------------- %s" % msg_raw)
            msg = json.loads(msg_raw.decode())
            #print("msg:", msg)
            final_msg = b'%s\n' % bytes(msg["args"], encoding='utf-8')
            #print("final_msg: \"%s\"" % final_msg)
            process.stdin.write(final_msg)
            process.stdin.flush()
            if msg["type"] == "STOP":
                end = True
                continue
            if msg["type"] == "START":
                #sniffer_thread = Thread(target=sniffer, args=(packet_filter,))
                #sniffer_thread.start()
                continue
            if msg["type"] == "ADD":
                print("Adding:", final_msg)
                continue
            # if add



# argv[1]: ports separated with commas
def main2():
    # if len(sys.argv) < 4:
    #     print("Error: se necesita indicar la ip, el puerto y una lista de puertos")
    #     exit(1)
    
    # argv[0] -> ports

    # Parse main args
    #broker_ip = sys.argv[1]
    #broker_port = sys.argv[2]
    if len(sys.argv) == 2:
        ports = sys.argv[1].split(',')
        packet_filter = "tcp port {}".format(ports[0])
        for p in range(len(ports)-1):
            packet_filter = packet_filter + " or tcp port {}".format(ports[p+1])
    else:
        ports = ""
        packet_filter = ""

    print("packet_filter:", packet_filter)

    # Connect to broker
    #connect_broker(broker_ip, broker_port)
    
    # sniffer(packet_filter)


    # Start node
    process = subprocess.Popen('go run ./node/node.go', text=False, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=False, shell=True)

    # Get process port from stdout
    node_port = ""
    while process.poll() is None:
        line = process.stdout.readline().decode()
        if line != "":
            print(">>> ", line, sep='', end='')
            node_port = line[1:line.index(']')]
            break
    print("node_port: \"%s\"" % node_port)

    # Start sniffer
    # sniffer_thread = Thread(target=sniffer, args=(packet_filter,))
    # sniffer_thread.start()
    
    # Start node
    #process.stdin.write(b'START\n')
    #process.stdin.flush()

    # Start listener socket
    udp_listener_thread = Thread(target=udp_listener, args=(process, packet_filter, node_port))
    udp_listener_thread.start()


    while process.poll() is None:
        line = process.stdout.readline().decode()
        if line != "":
            print(">>> ", line, sep='', end='')

    # Wait for processes to end
    #sniffer_thread.join()
    udp_listener_thread.join()

    
    # while process.poll() is None:
    #     print("waiting for line...")
    #     line = process.stdout.readline()
    #     print("got line")
    #     if line != "":
    #         print(line)
    #         if node_port != "":
    #             node_port = line[1:line.index(']')]
    #             print("Node port is", node_port)
    #         if n_lines == 0:
    #             print("sending stop")
    #             process.stdin.write(b'STOP\n')
    #             process.stdin.flush()
    #         n_lines = n_lines - 1
    
    process.wait()
    print("return_code:", process.returncode)


########################################################################




import socket
import struct
import textwrap

def get_mac_addr(addr):
    bytes_str = map('{:02x}'.format, addr)
    return ':'.join(bytes_str).upper()

def ipv4(addr):
    return '.'.join(map(str, addr))

def ethernet_fram(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

def unpack_ipv4(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, ip_proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, ip_proto, ipv4(src), ipv4(target), data[header_length:]

def tcp_segment(data):
    src_port, dest_port, sequence, ack, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, ack, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        try:
            raw_data, addr = conn.recvfrom(65535)
            dest_mac, src_mac, eth_proto, data = ethernet_fram(raw_data)
            # print('\nEthernet Frame:')
            # print('Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))

            if eth_proto == 8: # ipv4
                version, header_length, ttl, proto, src, target, data = unpack_ipv4(data)
                # print('IPv4 Packet:')
                # print('Version: {}, Header length: {}, TTL: {}'.format(version, header_length, ttl))
                # print('Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))

                if proto == 6: # TCP
                    src_port, dest_port, sequence, ack, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, packet_data = tcp_segment(data)
                    # print('TCP Segment:')
                    # print('Source Port: {}, Destination Port: {}'.format(src_port, dest_port))

                    if dest_port == 12345 and flag_psh == 1:
                        print('\nEthernet Frame:')
                        print('Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))
                        print('IPv4 Packet:')
                        print('Version: {}, Header length: {}, TTL: {}'.format(version, header_length, ttl))
                        print('Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))
                        print('TCP Segment:')
                        print('Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
                        print('Sequence: {}, Ack: {}'.format(sequence, ack))
                        print('Flags: URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
                        print('Data: {}'.format(packet_data))

        except KeyboardInterrupt:
            break



if __name__ == '__main__':
    main()












########################################################################









if __name__ == '__main__':
    main()