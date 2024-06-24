import argparse
import functools
import time

from scapy.arch import get_if_hwaddr
from scapy.interfaces import get_if_list
from scapy.sendrecv import sendp

from header_definition import *  # 确保你正确导入了定义
import threading
import logging


def get_if(interface):
    ifs = get_if_list()
    iface = None
    for i in ifs:
        if interface in i:
            iface = i
            break
    if iface is None:
        print(f"cannot find the {interface}")
        exit(1)
    return iface


def send_packet(interval=1):                    #这是一个装饰器，send_ipv4_tcp1中只定义数据包的结构
    def decorator(func):
        def wrapper(*args, **kwargs):
            packet = func(*args, **kwargs)
            logging.info(f"send packet length {len(packet)} bytes from {iface} interval {interval}")
            packet.show2()
            time.sleep(1)
            sendp(packet, iface=iface, inter=interval, realtime=True, loop=1)
            return packet

        return wrapper

    return decorator


def send_ipv4_tcp1():
    packet = (Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff") /
              IP(src='10.0.0.1', dst='10.0.0.2') / TCP(dport=7777))
    return packet


def send_ipv4_tcp2():
    packet = (Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff") /
              IP(src='10.0.0.1', dst='10.0.0.2') / TCP(dport=8888))
    return packet


def send_ipv4_tcp3():
    packet = (Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff") /
              IP(src='10.0.0.1', dst='10.0.0.2') / TCP(dport=9999))
    return packet


def send_INT_route1():
    packet = Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff") / \
             IPv6(nh=43) / srv6h_t(segment_left=0, last_entry=4) / srv6_list_t(segment_id="::100") / \
             srv6_list_t(segment_id="::200") / srv6_list_t(segment_id="::300") / \
             srv6_list_t(segment_id="::400") / srv6_list_t(segment_id="::500") / \
             IP(src='10.0.0.1', dst='10.0.0.2', proto=150) / probe_t(data_cnt=0)
    return packet


def send_INT_route2():
    packet = Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff") / \
             IPv6(nh=43) / srv6h_t(segment_left=0, last_entry=3) / srv6_list_t(segment_id="::100") / \
             srv6_list_t(segment_id="::260") / srv6_list_t(segment_id="::400") / \
             srv6_list_t(segment_id="::500") / \
             IP(src='10.0.0.1', dst='10.0.0.2', proto=150) / probe_t(data_cnt=0)
    return packet


def send_INT_route3():
    packet = Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff") / \
             IPv6(nh=43) / srv6h_t(segment_left=0, last_entry=4) / srv6_list_t(segment_id="::100") / \
             srv6_list_t(segment_id="::250") / srv6_list_t(segment_id="::350") / \
             srv6_list_t(segment_id="::400") / srv6_list_t(segment_id="::500") / \
             IP(src='10.0.0.1', dst='10.0.0.2', proto=150) / probe_t(data_cnt=0)
    return packet


def send_INT_test():
    packet = Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff") / \
             IP(src='10.0.0.1', dst='10.0.0.2', proto=150) / probe_t(data_cnt=5) / \
             probe_data_h(swid=1, ingress_port=1, egress_port=2, ingress_byte_cnt=1000, egress_byte_cnt=1500,
                          ingress_last_time=123456789012, ingress_cur_time=123456789112, egress_last_time=123456789212,
                          egress_cur_time=123456789312,
                          ingress_packet_count=50, egress_packet_count=75) / \
             probe_data_h(swid=2, ingress_port=3, egress_port=4, ingress_byte_cnt=2000, egress_byte_cnt=2500,
                          ingress_last_time=123456789013, ingress_cur_time=123456789113, egress_last_time=123456789213,
                          egress_cur_time=123456789313,
                          ingress_packet_count=60, egress_packet_count=85) / \
             probe_data_h(swid=3, ingress_port=5, egress_port=6, ingress_byte_cnt=3000, egress_byte_cnt=3500,
                          ingress_last_time=123456789014, ingress_cur_time=123456789114, egress_last_time=123456789214,
                          egress_cur_time=123456789314,
                          ingress_packet_count=70, egress_packet_count=95) / \
             probe_data_h(swid=4, ingress_port=7, egress_port=8, ingress_byte_cnt=4000, egress_byte_cnt=4500,
                          ingress_last_time=123456789015, ingress_cur_time=123456789115, egress_last_time=123456789215,
                          egress_cur_time=123456789315,
                          ingress_packet_count=80, egress_packet_count=105) / \
             probe_data_h(swid=5, ingress_port=9, egress_port=10, ingress_byte_cnt=5000, egress_byte_cnt=5500,
                          ingress_last_time=123456789016, ingress_cur_time=123456789116, egress_last_time=123456789216,
                          egress_cur_time=123456789316,
                          ingress_packet_count=90, egress_packet_count=115)
    return packet


if __name__ == '__main__':
    #iface = get_if("eth0")
    iface = "WLAN"
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s  - %(name)s - %(levelname)s - %(message)s')
    logger = logging.getLogger(__name__)
    parser = argparse.ArgumentParser(description="packet sender script")
    parser.add_argument("packet_types", nargs="+",
                        choices=["tcp1", "tcp2", "tcp3", "route1", "route2", "route3", "test"],
                        help="types of packet to send")
    parser.add_argument("-t", nargs="*",type=float,
                        help="the interval between sending packets")
    args = parser.parse_args()
    packets = {
        "tcp1": send_ipv4_tcp1,
        "tcp2": send_ipv4_tcp2,
        "tcp3": send_ipv4_tcp3,
        "route1": send_INT_route1,
        "route2": send_INT_route2,
        "route3": send_INT_route3,
        "test": send_INT_test
    }
    list_types = args.packet_types
    list_interval = args.t
    if list_interval==None:
        list_interval=[]
    if len(list_types) > len(list_interval):                   #让每个发送包的类型都能有一个interval参数对应上，比如tcp1 tcp2 对应 3 1
        for i in range(len(list_types) - len(list_interval)):
            list_interval.append(1)
    threads = []
    logger.info(print(list_interval))
    index = 0
    for packet_type in args.packet_types:
        packet = packets[packet_type]
        packet_to_send= functools.partial(send_packet(list_interval[index])(packet))
        thread = threading.Thread(target=packet_to_send)
        threads.append(thread)
        index += 1
    for thread in threads:
        thread.start()
