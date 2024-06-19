import time
import pydivert


# File that contains all the available functions for whitelisted packets to be saved in a Rule

def get_packet_length(packet: pydivert.Packet):
    # returns packet length
    return len(str(packet))


def get_arrival_time(_):
    return time.time()


def get_source_port(packet: pydivert.Packet):
    return packet.tcp.src_port


def get_src_ip(packet: pydivert.Packet):
    return packet.ip.src_addr


def get_dst_ip(packet: pydivert.Packet):
    return packet.ip.dst_addr
