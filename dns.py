import typing
from enum import Enum
from io import BytesIO
from struct import pack, unpack

class Qr(Enum):
    question = 0
    response = 1

class Opcode(Enum):
    query = 0
    iquery = 1
    qtatus = 2
    notify = 4
    update = 5

class Rcode(Enum):
    no_error = 0
    format_error = 1
    server_failure = 2
    name_error = 3
    not_implemented = 4
    refused = 5
    yx_domain = 6
    yx_rr_set = 7
    nx_rr_set = 8
    not_auth = 9
    not_zone = 10

class Qtype(Enum):
    a = 1
    ns = 2
    cname = 5
    soa = 6
    wks = 11
    ptr = 12
    mx = 15
    srv = 33
    aaaa = 28
    any = 255

class Qclass(Enum):
    internet = 1
    chaos = 3
    hesiod = 4

DnsMsg = typing.NamedTuple('DnsMsg', [
    ('id', int),
    ('qr', Qr),
    ('opcode', Opcode),
    ('aa', bool),
    ('tc', bool),
    ('rd', bool),
    ('ra', bool),
    ('ad', bool),
    ('cd', bool),
    ('rcode', Rcode),
    ('qdcount', int),
    ('ancouont', int),
    ('nscount', int),
    ('arcount', int),
    ('qname', str),
    ('qtype', Qtype),
    ('qclass', Qclass)
])

def decode_qname(qname : bytes) -> str:
    """ \x03www\x06domain\x03tld\x00 -> www.domain.tld. """
    labels = []
    while qname:
        count = int(qname[0])
        qname = qname[1:]
        label = qname[0:count]
        label = label
        labels.append(label)
        qname = qname[count:]
    name = '.'.join(label.decode('utf-8') for label in labels)
    return name

def put(m: DnsMsg) -> bytes:
    pass

def bit(bitfld : int, pos : int) -> bool:
    """ pos: begining from the less significant byte at index 0 """
    return bitfld & (1 << pos) != 0

def parse(b: bytes) -> DnsMsg:
    b = BytesIO(b)
    # Message ID
    msg_id, = unpack('h', b.read(2)) # 16 bits
    # Header
    header, = unpack('h', b.read(2)) # 16 bits
    qr = bit(header, 15)
    opcode = (header >> 11) & 0x0f # header[1:4]
    aa = bit(header, 10)
    tc = bit(header, 9)
    rd = bit(header, 8)
    ra = bit(header, 7)
    z  = bit(header, 6)
    ad = bit(header, 5)
    cd = bit(header, 4)
    rcode = header & 0x0f # Last nibble
    qd, an, ns, ar = unpack('hhhh', b.read(8)) # 4x16 bits
    # QName
    qname = b''
    while True:
        label_len = b.read(1)
        qname += label_len
        if label_len == b'\00':
            break
    b.read(1)
    print(qname)
    qtype, qclass = unpack('hh', b.read(4)) # 2x16 bits

    print('qtype', qtype)
    dns_msg = DnsMsg(
        msg_id,
        Qr(qr), Opcode(opcode), aa, tc, rd, ra, ad, cd, rcode,
        qd, an, ns, ar,
        decode_qname(qname), Qtype(qtype), Qclass(qclass)
    )
    return dns_msg


