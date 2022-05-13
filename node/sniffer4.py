import dpkt, pcap
pc = pcap.pcap()     # construct pcap object
pc.setfilter('icmp') # filter out unwanted packets
for timestamp, packet in pc:
    try:
        print(dpkt.ethernet.Ethernet(packet))
    except KeyboardInterrupt:
        print("end")
        break
