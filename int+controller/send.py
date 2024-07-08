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

def send_INT_packet():
    packet=Ether(src=get_if_hwaddr(get_if("eth0")),dst="ff:ff:ff:ff:ff:ff")/\
        IPv6(src="::1",dst="::2")/srv6h_t(segment_left=0,last_entry=8)/\
        srv6_list_t(segment_id="::300")/srv6_list_t(segment_id="::100")/\
        srv6_list_t(segment_id="::300")/srv6_list_t(segment_id="::200")/\
        srv6_list_t(segment_id="::100")/srv6_list_t(segment_id="::400")/\
        srv6_list_t(segment_id="::100")/srv6_list_t(segment_id="::200")/\
        srv6_list_t(segment_id="::200")/IP()/probe_t(data_cnt=0)
    print(f"length of the INT packet is {len(packet)} bytes")
    sendp(packet,iface=get_if('eth0'),inter=1, realtime=True, loop=1)
if __name__=='__main__':
    send_INT_packet()
