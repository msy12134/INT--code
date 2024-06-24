from scapy.fields import BitField, IP6Field
from scapy.layers.inet import IP, ICMP, UDP, TCP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.packet import Packet, bind_layers

class probe_t(Packet):
    name = "probe"
    fields_desc = [
        BitField('data_cnt', 0, 8)
    ]

class probe_data_h(Packet):
    name = "probe_data"
    fields_desc = [
        BitField('swid', 0, 8),
        BitField('ingress_port', 0, 8),
        BitField('egress_port', 0, 8),
        BitField('ingress_byte_cnt', 0, 32),
        BitField('egress_byte_cnt', 0, 32),
        BitField('ingress_last_time', 0, 48),
        BitField('ingress_cur_time', 0, 48),
        BitField('egress_last_time', 0, 48),
        BitField('egress_cur_time', 0, 48),
        BitField('ingress_packet_count', 0, 32),
        BitField('egress_packet_count', 0, 32),
    ]
class srv6h_t(Packet):
    name = "srv6h"
    fields_desc = [
        BitField('next_hdr', 0, 8),
        BitField('hdr_ext_len', 0, 8),
        BitField('routing_type', 0, 8),
        BitField('segment_left', 0, 8),
        BitField('last_entry', 0, 8),
        BitField('flags', 0, 8),
        BitField('tag', 0, 16),
    ]
class srv6_list_t(Packet):
    name = "srv6_list"
    fields_desc = [
        IP6Field('segment_id',"::100")
    ]
bind_layers(Ether,IP,type=0x0800)
bind_layers(IP,probe_t,proto=150)
bind_layers(probe_t,probe_data_h)
bind_layers(probe_data_h,probe_data_h)
bind_layers(Ether,IPv6,type=0x86dd)
bind_layers(IPv6,srv6h_t)
