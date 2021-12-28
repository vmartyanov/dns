"""Implementation of DNS protocol. Mainly client-side."""
#RFC 1035
import random
import socket
import struct

#TYPES
A       = 1
NS      = 2
MD      = 3     #obsolete
MF      = 4     #obsolete
CNAME   = 5
SOA     = 6
MB      = 7     #experimental
MG      = 8     #experimental
MR      = 9     #experimental
NULL    = 10    #experimental
WKS         = 11
PTR         = 12
HINFO       = 13
MINFO       = 14
MX          = 15
TXT         = 16
RP          = 17
AAAA        = 28
LOC         = 29
SRV         = 33
NAPTR       = 35
DNAME       = 39
DS          = 43
SSHFP       = 44
RRSIG       = 46
NSEC        = 47
DNSKEY      = 48
NSEC3       = 50
NSEC3PARAM  = 51
TLSA        = 52
OPENPGPKEY  = 61
SPF         = 99
AXFR        = 252
CAA         = 257

PRIV65534   = 65534
TYPES = {0: "UNKNOWN", 1: "A", 2: "NS", 3: "MD", 4: "MF", 5: "CNAME", 6: "SOA", 7: "MB", 8: "MG",
            9: "MR",
        10: "NULL", 11: "WKS", 12: "PTR", 13: "HINFO", 14: "MINFO", 15: "MX", 16: "TXT", 17: "RP",
        28: "AAAA", 29: "LOC",
        33: "SRV", 35: "NAPTR", 39: "DNAME",
        43: "DS", 44: "SSHFP", 46: "RRSIG", 47: "NSEC", 48: "DNSKEY",
        50: "NSEC3", 51: "NSEC3PARAM", 52: "TLSA",
        61: "OPENPGPKEY",
        99: "SPF",
        252: "AXFR", 257: "CAA",
        65534: "PRIV65534"
        }

#OPCODES
QUERY   = 0
IQUERY  = 1
STATUS  = 2
OPCODES = {0: "QUERY", 1: "IQUERY", 2: "STATUS"}

#CLASSES
IN      = 1
CS      = 2
CH      = 3
HS      = 4
CLASSES = {0: "UNKNWON", 1: "IN", 2: "CS", 3: "CH", 4: "HS"}

#RCODES
R_OK            = 0
R_FORMATERR     = 1
R_SERVFAIL      = 2
R_NAMEERR       = 3
R_NOTIMPL       = 4
R_REFUSED       = 5
RCODES = {0: "No error", 1: "Format error", 2: "Server failure", 3: "Name error",
            4: "Not Implemented", 5: "Refused"}


class DNSException(Exception):
    """All our exceptions."""


def read_name(data: bytes, start_offset: int) -> tuple[str, int]:
    """Read DNS name (with compression!) from the whole message starting at specified offset."""
    ret_len = 0
    ret_str = ""
    while True:
        l = data[start_offset + ret_len]
        if l >= 0xC0:     #offset
            offset = struct.unpack("!H", data[start_offset + ret_len : start_offset + ret_len + 2])[0]
            offset = offset & 0x3FFF

            label, _ = read_name(data, offset)

            ret_str += label
            ret_len += 2
            break       #because pointer is ALWAYS the last element
        #else...
        ret_len += 1
        if l == 0:
            break
        ret_str += data[start_offset + ret_len: start_offset + ret_len + l].decode() + "."
        ret_len += l

    if not ret_str:
        return ("<ROOT>", ret_len)
    if ret_str[-1] == ".":
        ret_str = ret_str[:-1]
    return (ret_str, ret_len)

class MessageHeader():      # pylint: disable=too-many-instance-attributes
    """DNS message header."""
    def __init__(self) -> None:
        self.ID = random.randrange(0, 0xFFFF)                   # pylint: disable=invalid-name
        self.QR = 0                                             # pylint: disable=invalid-name
        self.OPCODE = 0                                         # pylint: disable=invalid-name
        self.AA = 0                                             # pylint: disable=invalid-name
        self.TC = 0                                             # pylint: disable=invalid-name
        self.RD = 0                                             # pylint: disable=invalid-name
        self.RA = 0                                             # pylint: disable=invalid-name
        self.Z = 0                                              # pylint: disable=invalid-name
        self.RCODE = 0                                          # pylint: disable=invalid-name

        #they will be set by DNSMessage
        self.QDCOUNT = 0                                        # pylint: disable=invalid-name
        self.ANCOUNT = 0                                        # pylint: disable=invalid-name
        self.NSCOUNT = 0                                        # pylint: disable=invalid-name
        self.ARCOUNT = 0                                        # pylint: disable=invalid-name

    def __bytes__(self) -> bytes:
        """Convert to bytes."""
        ret = struct.pack("!H", self.ID)        #ID

        i = (self.QR & 0x01) << 15
        i = i + ((self.OPCODE& 0x0F) << 14)
        i = i + ((self.AA & 0x01) << 10)
        i = i + ((self.TC & 0x01) << 9)
        i = i + ((self.RD & 0x01) << 8)

        i = i + ((self.RA & 0x01) << 7)
        i = i + ((self.Z & 0x07) << 6)
        i = i + (self.RCODE & 0x0F)
        ret += struct.pack("!H", i)        #QR, Opcode, AA, TC, RD, RA, Z, RCODE

        ret += struct.pack("!HHHH", self.QDCOUNT, self.ANCOUNT, self.NSCOUNT, self.ARCOUNT)
        return ret

    def __len__(self) -> int:
        """Return length of message header - 6 words always."""
        return 6 * 2

    def read(self, data: bytes) -> int:
        """Deserialize object from data."""
        if len(data) < len(self):
            return 0
        self.ID, i = struct.unpack("!HH", data[:4])

        self.QR = (i >> 15) & 0x01
        self.OPCODE = (i >> 11) & 0x0F
        self.AA = (i >> 10) & 0x01
        self.TC = (i >> 9) & 0x01
        self.RD = (i >> 8) & 0x01
        self.RA = (i >> 7) & 0x01
        self.Z = (i >> 4) & 0x07
        self.RCODE = i & 0x0F

        self.QDCOUNT, self.ANCOUNT = struct.unpack("!HH", data[4 : 8])
        self.NSCOUNT, self.ARCOUNT = struct.unpack("!HH", data[8 : 12])
        return len(self)

class ResourceRecord():
    """Resource record."""
    def __init__(self) -> None:
        self.name = ""
        self.rdata_type = 0
        self.rdata_class = 0
        self.ttl = 0
        self.rdata_len = 0
        self.rdata = "NOT IMPLEMENTED"

    def __bytes__(self) -> bytes:
        raise NotImplementedError

    def read(self, data: bytes, offset: int) -> int:
        """Deserialize object from data."""
        self.name, length = read_name(data, offset)
        offset += length

        self.rdata_type, self.rdata_class = struct.unpack("!HH", data[offset : offset + 4])
        offset += 4

        self.ttl, self.rdata_len = struct.unpack("!LH", data[offset : offset + 6])
        offset += 6

        if self.rdata_class == IN:
            if self.rdata_type == NS:
                self.rdata, _ = read_name(data, offset)
        else:
            self.rdata = "UNSUPPORTED CLASS"

        return length + 10 + self.rdata_len

class DNSQuestion():
    """DNS question."""
    def __init__(self) -> None:
        self.name = ""
        self.type = 0
        self.q_class = 0

    def __bytes__(self) -> bytes:
        """Convert to bytes."""
        ret = b""
        parts = self.name.split('.')
        for part in parts:
            part_len = len(part)
            if part_len > 63:
                raise DNSException("Name is too long")
            ret += struct.pack("B", part_len)
            ret += part.encode()

        ret += struct.pack("!BHH", 0x00, self.type, self.q_class)
        return ret

    def read(self, data: bytes, offset: int) -> int:
        """Deserialize object from bytes."""
        self.name, length = read_name(data, offset)
        offset += length
        self.type, self.q_class = struct.unpack("!HH", data[offset : offset + 4])
        return length + 4

class DNSMessage():
    """DNS message."""
    def __init__(self, data: None|bytes = None) -> None:
        self.header = MessageHeader()
        self.questions: list[DNSQuestion] = []
        self.answers: list[ResourceRecord] = []
        self.authorities: list[ResourceRecord] = []
        self.additionals: list[ResourceRecord] = []

        if data:
            self.read(data)

    def __bytes__(self) -> bytes:
        """Convert to bytes."""
        self.header.QDCOUNT = len(self.questions)
        self.header.ANCOUNT = len(self.answers)
        self.header.NSCOUNT = len(self.authorities)
        self.header.ARCOUNT = len(self.additionals)

        ret = bytes(self.header)

        for question in self.questions:
            ret += bytes(question)
        for answer in self.answers:
            ret += bytes(answer)
        for authority in self.authorities:
            ret += bytes(authority)
        for additional in self.additionals:
            ret += bytes(additional)
        return ret

    def read(self, data: bytes) -> None:
        """Deserialize object from data."""
        pos = self.header.read(data)

        self.questions.clear()
        for _ in range(self.header.QDCOUNT):
            question = DNSQuestion()
            pos += question.read(data, pos)
            self.questions.append(question)

        self.answers.clear()
        for _ in range(self.header.ANCOUNT):
            record = ResourceRecord()
            pos += record.read(data, pos)
            self.answers.append(record)

        self.authorities.clear()
        for _ in range(self.header.NSCOUNT):
            record = ResourceRecord()
            pos += record.read(data, pos)
            self.authorities.append(record)

        self.additionals.clear()
        for _ in range(self.header.ARCOUNT):
            record = ResourceRecord()
            pos += record.read(data, pos)
            self.additionals.append(record)

def udp_query(domain: str,          # pylint: disable=too-many-arguments
              q_type: int,
              server: str = "8.8.8.8",
              port: int = 53,
              timeout: float = 2,
              recursive: bool = True
             ) -> list[ResourceRecord]:
    """Perform simple UDP query."""

    ret:list[ResourceRecord] = []
    #Creating a message
    message = DNSMessage()
    message.header.OPCODE = QUERY
    if recursive:
        message.header.RD = 1
    question = DNSQuestion()
    question.name = domain
    question.type = q_type
    question.q_class = IN
    message.questions.append(question)

    #sending request
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    data = bytes(message)
    if len(data) > 512:
        raise DNSException("UDP message is too long for DNS!")
    sock.sendto(data, (server, port))

    #reading response
    try:
        reply = sock.recv(512)
    except TimeoutError:
        reply = b""

    for answer in DNSMessage(reply).answers:
        if answer.rdata_type != q_type:     #YES, WE CAN receive extra responses
            continue
        ret.append(answer)
    return ret

def read_message_tcp(sock: socket.socket) -> bytes:
    """Read TCP DNS message."""
    ret = b""
    try:
        message_len = sock.recv(2)
        ret = ret + message_len
        expected_len = 2 + struct.unpack("!H", message_len)[0]
        while True:
            portion_len = expected_len - len(ret)     #How many bytes left
            if portion_len == 0:
                break
            portion_len = min(1024, portion_len)

            data = sock.recv(portion_len)
            ret = ret + data
    except Exception:
        pass
    return ret


def axfr_query(domain: str,
               server: str,
               port: int = 53,
               timeout: float = 2,
               recursive: bool = True
              ) -> list[ResourceRecord]:
    """Perform TCP AXFR query."""
    ret: list[ResourceRecord] = []

    #Creating a message
    message = DNSMessage()
    message.header.OPCODE = QUERY
    if recursive:
        message.header.RD = 1
    question = DNSQuestion()
    question.name = domain
    question.type = AXFR
    question.q_class = IN
    message.questions.append(question)

    #RFC 5936, sending data to server
    message_data = bytes(message)
    data = struct.pack("!H", len(message_data)) + message_data

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((server, port))
    except (TimeoutError, socket.gaierror):
        return ret

    sock.sendall(data)

    while True:
        message_bytes = read_message_tcp(sock)
        message_bytes = message_bytes[2:]       #remove expected len
        response = DNSMessage()
        response.read(message_bytes)

        #error or no answers.
        if (response.header.RCODE != R_OK or response.header.ANCOUNT == 0):
            break

        ret += response.answers
        #last (but not the only!) response is SOA - finishing
        if len(ret) > 0 and ret[-1].rdata_type == SOA:
            break

    sock.close()
    return ret
