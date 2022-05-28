from logging.config import listen
import struct
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

cont = True

def addPort(port):
    mutex.acquire()
    ports.append(port)
    mutex.release()

def sniffer():
    global cont

    app_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    manager_addr = ("127.0.0.1", 3333)

    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while cont:
        # Get new packet
        raw_data, addr = conn.recvfrom(65535)
        
        # Get destination MAC, source MAC and ethernet protocol
        dest_mac, src_mac, eth_proto = struct.unpack('! 6s 6s H', raw_data[:14])
        eth_proto = socket.htons(eth_proto)
        data = raw_data[14:]

        # If packet is IPv4
        if eth_proto == 8:
            version_header_length = data[0]
            version = version_header_length >> 4
            header_length = (version_header_length & 15) * 4
            ttl, ip_proto, src_ip, target_ip = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
            data = data[header_length:]

            # If TCP protocol
            if ip_proto == 6:
                src_port, dest_port, sequence, ack, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
                offset = (offset_reserved_flags >> 12) * 4
                flag_urg = (offset_reserved_flags & 32) >> 5
                flag_ack = (offset_reserved_flags & 16) >> 4
                flag_psh = (offset_reserved_flags & 8) >> 3
                flag_rst = (offset_reserved_flags & 4) >> 2
                flag_syn = (offset_reserved_flags & 2) >> 1
                flag_fin = offset_reserved_flags & 1
                data = data[offset:]

                # If packet has content
                if flag_psh == 1 and dest_port in ports:
                    # print('\nEthernet Frame:')
                    # print('Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))
                    # print('IPv4 Packet:')
                    # print('Version: {}, Header length: {}, TTL: {}'.format(version, header_length, ttl))
                    # print('Protocol: {}, Source: {}, Target: {}'.format(ip_proto, src_ip, target_ip))
                    # print('TCP Segment:')
                    # print('Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
                    # print('Sequence: {}, Ack: {}'.format(sequence, ack))
                    # print('Flags: URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
                    # print('Data: {}'.format(data))
                    captured_msg = json.loads(data.decode())

                    captured_msg["SrcPort"] = captured_msg["SenderPort"]
                    captured_msg["SrcIp"] = "localhost"
                    captured_msg["DstPort"] = dest_port
                    captured_msg["DstIp"] = "localhost"

                    app_server.sendto(bytes(json.dumps(captured_msg), encoding='utf-8'), manager_addr)

# proceso que interactua con el nodo
def udp_listener(process, packet_filter, node_port):
    global cont
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as listener:
        listener.bind(("", 0))
        listener_port = listener.getsockname()[1]
        print("localhost:%d:%s" % (listener_port, node_port))
        print("ncat.exe -u 127.0.0.1", listener_port)
        print("""{"type": "STOP", "args":"STOP"}""")
        end = False
        while cont:
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
                cont = False
                continue
            if msg["type"] == "START":
                continue
            if msg["type"] == "ADD":
                print("Adding:", final_msg)
                addPort(int(final_msg[14:-1]))
                continue

def main():
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
    sniffer_thread = Thread(target=sniffer, args=())
    sniffer_thread.start()
    
    # Start listener socket
    udp_listener_thread = Thread(target=udp_listener, args=(process, packet_filter, node_port))
    udp_listener_thread.start()

    while process.poll() is None:
        line = process.stdout.readline().decode()
        if line != "":
            print(">>> ", line, sep='', end='')

    # Wait for processes to end
    sniffer_thread.join()
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

if __name__ == '__main__':
    main()
