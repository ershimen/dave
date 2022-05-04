import pyshark
import sys
import socket
from threading import Thread, Lock

# global mutex for port list
mutex = Lock()
ports = list()

def addPort(port):
    mutex.acquire()
    ports.append(port)
    mutex.release()

# argv[1]: ports separated with commas
def main():
    if len(sys.argv) < 4:
        print("Error: se necesita indicar la ip, el puerto y una lista de puertos")
        exit(1)
    
    # Parse main args
    broker_ip = sys.argv[1]
    broker_port = sys.argv[2]
    ports = sys.argv[3].split(',')

    print("ports: ", ports, sep='')

    packet_filter = "tcp port {}".format(ports[0])
    for p in range(len(ports)-1):
        packet_filter = packet_filter + " or tcp port {}".format(ports[p+1])
    
    print(packet_filter)

    # Connect to broker
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((broker_ip, broker_port))
    


    capture = pyshark.LiveCapture(interface='Adapter for loopback traffic capture', bpf_filter=packet_filter)

    for packet in capture.sniff_continuously(packet_count=100):
        if str(packet.tcp.flags_push) == "1": # si es un paquete con contenido
            print("ports: srcport: {}, dstport: {}, port: {}".format(packet.tcp.srcport, packet.tcp.dstport, packet.tcp.port))
            print("New packet: from {} to {}".format(packet.tcp.srcport, packet.tcp.dstport))
            print("'" + "".join(map(lambda c: chr(int(c, 16)), str(packet.tcp.payload).split(':'))) + "'")
            print()





if __name__ == '__main__':
    main()