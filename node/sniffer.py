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
def udp_listener(process, packet_filter):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as listener:
        listener.bind(("", 0))
        print("Listening on port %d" % listener.getsockname()[1])
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
                sniffer_thread = Thread(target=sniffer, args=(packet_filter,))
                sniffer_thread.start()
                continue
            # if add



# argv[1]: ports separated with commas
def main():
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
        print(line, end='')
        if line != "":
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
    udp_listener_thread = Thread(target=udp_listener, args=(process, packet_filter))
    udp_listener_thread.start()


    while process.poll() is None:
        line = process.stdout.readline().decode()
        print(line, end='')

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


if __name__ == '__main__':
    main()