import socket

from .DNS_send import build_query
from .DNS_receive import parse_dns_packet
from .DNS_constants import *


def resolve(domain_name, record_type):
    nameserver = "198.41.0.4"
    while True:
        print(f"Querying {nameserver} for {domain_name}")
        response = send_query(nameserver, domain_name, record_type)
        if ip := get_answer(response):
            return ip
        elif nsIP := get_nameserver_ip(response):
            nameserver = nsIP
        # New case: look up the nameserver's IP address if there is one
        elif ns_domain := get_nameserver(response):
            nameserver = resolve(ns_domain, TYPE_A)
        else:
            raise Exception("something went wrong")

def send_query(ip_address, domain_name, record_type):
    query = build_query(domain_name, record_type)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(query, (ip_address, 53))

    data, _ = sock.recvfrom(1024)
    return parse_dns_packet(data)

def get_answer(packet):
    for x in packet.answers:
        if x.qtype == TYPE_A:
            return x.data
        
def get_nameserver_ip(packet):
    for x in packet.additionals:
        if x.qtype == TYPE_A:
            return x.data
        
def get_nameserver(packet):
    # return the first NS record in the Authority section
    for x in packet.authorities:
        if x.qtype_ == TYPE_NS:
            return x.data.decode('utf-8')