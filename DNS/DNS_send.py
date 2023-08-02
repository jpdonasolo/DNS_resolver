import random
import struct
import dataclasses

from .DNS_structs import *
from .DNS_constants import *


def build_query(domain_name, record_type):
    name = encode_dns_name(domain_name)
    id = random.randint(0, 65535)

    # RECRUSION_DESIRED = 1 << 8
    flags = 0

    header = DNSHeader(id=id, flags=flags, num_questions=1)
    question = DNSQuestion(name=name, qtype=record_type, qclass=CLASS_IN)

    return header_to_bytes(header) + question_to_bytes(question)

def question_to_bytes(question):
    name = question.name
    qtype = struct.pack('!HH', question.qtype, question.qclass)
    return name + qtype

def header_to_bytes(header):
    fields = dataclasses.astuple(header)
    return struct.pack('!HHHHHH', *fields)

def encode_dns_name(name):
    encoded = b''
    labels = name.encode('ascii').split(b'.')
    for label in labels:
        length = len(label)
        encoded += bytes([length])
        encoded += label
    encoded += b'\x00'
    return encoded