import logging

from scapy.all import *
from scapy.layers.inet import UDP
from header_definition import *
import pymysql
from mysql import create_table,deal_data

def get_if():
    ifs = get_if_list()
    iface = None
    for i in ifs:
        if "eth0" in i:
            iface = i
            break
    if iface == None:
        print("cannot find the interface")
        exit(1)
    return iface


iface = get_if()
#iface="WLAN"

def packet_show(pkt):
    pkt = bytes(pkt)
    ether = Ether(pkt)
    print("Ethernet Header:")
    print(f"  dst = {ether.dst}")
    print(f"  src = {ether.src}")
    print(f"  type = 0x{ether.type:04x}")
    ipv4 = IP(bytes(ether.payload))
    print(f"IPv4 Header:")
    print(f"  version = {ipv4.version}")
    print(f"  ihl = {ipv4.ihl}")
    print(f"  tos = {ipv4.tos}")
    print(f"  len = {ipv4.len}")
    print(f"  id = {ipv4.id}")
    print(f"  flags = {ipv4.flags}")
    print(f"  frag = {ipv4.frag}")
    print(f"  ttl = {ipv4.ttl}")
    print(f"  proto = {ipv4.proto}")
    print(f"  chksum = {ipv4.chksum}")
    print(f"  src = {ipv4.src}")
    print(f"  dst = {ipv4.dst}")
    probe_header = probe_t(bytes(ipv4.payload))
    print(f"Probe Header:")
    print(f"  data_cnt = {probe_header.data_cnt}")
    list=[]
    if probe_header.data_cnt > 0:
        probe_data = probe_data_h(bytes(probe_header.payload))
        list.append(probe_data)
        for i in range(probe_header.data_cnt):
            print(f" probe_data_{i + 1}")
            print(f"  swid={probe_data.swid}")
            print(f"  ingress_port={probe_data.ingress_port}")
            print(f"  egress_port={probe_data.egress_port}")
            print(f"  ingress_byte_cnt={probe_data.ingress_byte_cnt}")
            print(f"  egress_byte_cnt={probe_data.egress_byte_cnt}")
            print(f"  ingress_last_time={probe_data.ingress_last_time}")
            print(f"  ingress_cur_time={probe_data.ingress_cur_time}")
            print(f"  egress_last_time={probe_data.egress_last_time}")
            print(f"  egress_cur_time={probe_data.egress_cur_time}")
            print(f"  ingress_packet_count={probe_data.ingress_packet_count}")
            print(f"  egress_packet_count={probe_data.egress_packet_count}")
            if i <= probe_header.data_cnt - 2:
                probe_data = probe_data_h(bytes(probe_data.payload))
                list.append(probe_data)
        deal_data(conn,cursor,list)


def packet_handler(pkt):
    if pkt.haslayer(probe_t):
        print(f"got a packet and the length is {len(pkt)}")
        packet_show(pkt)
        sys.stdout.flush()


def receive_packets():
    print(f"start receiving on {iface}")
    sniff(iface=iface, prn=packet_handler)

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    conn = pymysql.connect(
    host='10.0.0.1',
    user='maomao',
    password='maoshuoyuA100%',
    unix_socket="/var/run/mysqld/mysqld.sock"
)
    logging.info(f"Connected to {conn}")
    cursor = conn.cursor()

    create_table(conn,cursor)

    receive_packets()

    cursor.close()
    conn.close()
