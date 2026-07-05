"""
Packet Decoder - Parse raw bytes into structured data
Supports: Ethernet, IP, IPv6, TCP, UDP, ICMP, ARP, ICMPv6, IGMP, DHCP, NTP
Plus deep decoders: DNS, HTTP, TLS (SNI), QUIC (initial)

Two-tier strategy:
- Fast decode: headers (L2-L4) - cheap, runs on every packet
- Deep decode: payload/protocol-specific (L7) - opt-in via decoder flag
"""

from dataclasses import dataclass, field
from typing import Optional, Tuple
import struct
import socket

from .constants import (
    ETHERTYPE_IP, ETHERTYPE_ARP, ETHERTYPE_IPV6, ETHERTYPE_VLAN,
    ETHERTYPE_NAMES, PROTO_NAMES, PROTO_TCP, PROTO_UDP, PROTO_ICMP,
    PROTO_ICMPV6, PROTO_IGMP,
    tcp_flags_str, ICMP_TYPE_NAMES, ICMPV6_TYPE_NAMES, IGMP_TYPE_NAMES,
    ARP_OP_NAMES, DHCP_MSG_NAMES, DNS_TYPE_NAMES, DNS_RCODE_NAMES,
    TLS_VERSION_NAMES, HTTP_STATUS_CODES, WELL_KNOWN_PORTS,
    DEFAULT_PAYLOAD_SNIPPET_BYTES,
)


@dataclass(slots=True)
class PacketInfo:
    """Basic packet info for queue/display"""
    stt: int                    # Packet sequence number
    ts_sec: int                 # Timestamp seconds
    ts_usec: int                # Timestamp microseconds
    caplen: int = 0             # Captured length
    origlen: int = 0            # Original length
    data: bytes = field(default_factory=bytes)  # Raw packet data


@dataclass(slots=True)
class EthernetHeader:
    dst_mac: str
    src_mac: str
    ethertype: int
    ethertype_name: str = ""


@dataclass(slots=True)
class IPv4Header:
    version: int
    ihl: int                    # Header length
    tos: int
    total_length: int
    identification: int
    flags: int
    fragment_offset: int
    ttl: int
    protocol: int
    checksum: int
    src_ip: str
    dst_ip: str
    protocol_name: str = ""


@dataclass
class IPv6Header:
    version: int
    traffic_class: int
    flow_label: int
    payload_length: int
    next_header: int
    hop_limit: int
    src_ip: str
    dst_ip: str
    next_header_name: str = ""


@dataclass(slots=True)
class TCPHeader:
    src_port: int
    dst_port: int
    seq: int
    ack: int
    data_offset: int
    reserved: int
    flags: int
    window: int
    checksum: int
    urgent: int
    flags_str: str = ""


@dataclass(slots=True)
class UDPHeader:
    src_port: int
    dst_port: int
    length: int
    checksum: int


@dataclass
class ICMPHeader:
    icmp_type: int
    code: int
    checksum: int
    type_name: str = ""


@dataclass
class ICMPv6Header:
    icmp_type: int
    code: int
    checksum: int
    type_name: str = ""


@dataclass
class IGMPHeader:
    igmp_type: int
    max_resp_time: int
    checksum: int
    group_address: str = ""
    type_name: str = ""


@dataclass
class ARPHeader:
    hw_type: int
    proto_type: int
    hw_size: int
    proto_size: int
    opcode: int
    sender_mac: str
    sender_ip: str
    target_mac: str
    target_ip: str
    op_name: str = ""


@dataclass
class DHCPInfo:
    """DHCP option-level information"""
    msg_type: int = 0
    msg_type_name: str = ""
    server_ip: str = ""
    client_ip: str = ""
    your_ip: str = ""
    transaction_id: int = 0
    is_dhcp: bool = False


@dataclass
class DNSInfo:
    """DNS query/response summary"""
    transaction_id: int = 0
    is_query: bool = False
    is_response: bool = False
    qr: int = 0
    opcode: int = 0
    rcode: int = 0
    rcode_name: str = ""
    qtype: int = 0
    qtype_name: str = ""
    qname: str = ""
    ancount: int = 0
    answers: list = field(default_factory=list)  # list[str] of answer names


@dataclass
class HTTPInfo:
    """HTTP request/response summary"""
    method: str = ""
    host: str = ""
    uri: str = ""
    user_agent: str = ""
    status_code: int = 0
    status_text: str = ""
    content_type: str = ""
    is_request: bool = False
    is_response: bool = False
    version: str = ""


@dataclass
class TLSInfo:
    """TLS ClientHello / ServerHello summary"""
    is_tls: bool = False
    record_type: int = 0
    version: int = 0
    version_name: str = ""
    sni: str = ""              # Server Name Indication
    cipher_suite: int = 0
    handshake_type: int = 0
    is_client_hello: bool = False
    is_server_hello: bool = False


@dataclass
class NTPInfo:
    """NTP packet summary"""
    is_ntp: bool = False
    li: int = 0                # Leap indicator
    vn: int = 0                # Version number
    mode: int = 0
    stratum: int = 0
    poll: int = 0
    precision: int = 0
    reference_id: str = ""


@dataclass
class QUICInfo:
    """QUIC initial packet (long header) summary"""
    is_quic: bool = False
    long_header: bool = False
    version: int = 0
    dcid: bytes = b""
    scid: bytes = b""
    sni: str = ""              # ALPN/SNI extracted from ClientHello inside QUIC


@dataclass
class ProtocolInfo:
    """
    Kết quả detect protocol ở mức application-layer.
    Chỉ một trong các field được set tùy protocol.
    """
    name: str = "UNKNOWN"       # DNS, HTTP, TLS, DHCP, NTP, QUIC, ...
    dns: Optional[DNSInfo] = None
    http: Optional[HTTPInfo] = None
    tls: Optional[TLSInfo] = None
    dhcp: Optional[DHCPInfo] = None
    ntp: Optional[NTPInfo] = None
    quic: Optional[QUICInfo] = None

    @property
    def is_app_protocol(self) -> bool:
        return self.name not in ("UNKNOWN", "TCP", "UDP", "ICMP", "ARP",
                                  "ICMPv6", "IGMP", "IPv4", "IPv6")


@dataclass(slots=True)
class DecodedPacket:
    """Fully decoded packet with all layers"""
    raw_data: bytes
    ethernet: Optional[EthernetHeader] = None
    ipv4: Optional[IPv4Header] = None
    ipv6: Optional[IPv6Header] = None
    tcp: Optional[TCPHeader] = None
    udp: Optional[UDPHeader] = None
    icmp: Optional[ICMPHeader] = None
    icmpv6: Optional[ICMPv6Header] = None
    igmp: Optional[IGMPHeader] = None
    arp: Optional[ARPHeader] = None

    # Computed summary fields
    protocol_name: str = "UNKNOWN"
    src_addr: str = ""
    dst_addr: str = ""
    src_port: int = 0
    dst_port: int = 0
    info_str: str = ""
    payload: bytes = field(default_factory=bytes)
    payload_snippet: str = ""    # First N bytes ASCII-safe (cho list view)
    payload_len: int = 0

    # Application-layer info (filled khi deep decode chạy)
    proto: ProtocolInfo = field(default_factory=ProtocolInfo)


def mac_to_str(mac_bytes: bytes) -> str:
    """Convert 6-byte MAC to string (tối ưu: dùng bytes.hex())."""
    return mac_bytes[:6].hex(':')


# Cache translation table cho make_payload_snippet (computed once)
_SNIPPET_TABLE = bytes((b if 32 <= b < 127 else 46) for b in range(256))


def make_payload_snippet(data: bytes, max_len: int = DEFAULT_PAYLOAD_SNIPPET_BYTES) -> str:
    """
    Lấy first N bytes của payload, chuyển sang ASCII-safe text.
    Tối ưu: dùng cached translation table (256 bytes, computed once).
    """
    if not data:
        return ""
    chunk = data[:max_len]
    return chunk.translate(_SNIPPET_TABLE).decode('ascii', errors='replace')


def decode_ethernet(data: bytes) -> tuple[Optional[EthernetHeader], int]:
    """Decode Ethernet header, return (header, offset)"""
    if len(data) < 14:
        return None, 0

    dst_mac = mac_to_str(data[0:6])
    src_mac = mac_to_str(data[6:12])
    ethertype = struct.unpack('!H', data[12:14])[0]

    offset = 14

    # Handle VLAN tag
    if ethertype == ETHERTYPE_VLAN:
        if len(data) < 18:
            return None, 0
        ethertype = struct.unpack('!H', data[16:18])[0]
        offset = 18

    return EthernetHeader(
        dst_mac=dst_mac,
        src_mac=src_mac,
        ethertype=ethertype,
        ethertype_name=ETHERTYPE_NAMES.get(ethertype, f"0x{ethertype:04x}")
    ), offset


def decode_ipv4(data: bytes) -> tuple[Optional[IPv4Header], int]:
    """Decode IPv4 header, return (header, header_length)"""
    if len(data) < 20:
        return None, 0

    version_ihl = data[0]
    version = (version_ihl >> 4) & 0x0F
    ihl = (version_ihl & 0x0F) * 4

    if version != 4 or len(data) < ihl:
        return None, 0

    tos = data[1]
    total_length = struct.unpack('!H', data[2:4])[0]
    identification = struct.unpack('!H', data[4:6])[0]
    flags_frag = struct.unpack('!H', data[6:8])[0]
    flags = (flags_frag >> 13) & 0x07
    fragment_offset = flags_frag & 0x1FFF
    ttl = data[8]
    protocol = data[9]
    checksum = struct.unpack('!H', data[10:12])[0]
    src_ip = socket.inet_ntoa(data[12:16])
    dst_ip = socket.inet_ntoa(data[16:20])

    return IPv4Header(
        version=version,
        ihl=ihl,
        tos=tos,
        total_length=total_length,
        identification=identification,
        flags=flags,
        fragment_offset=fragment_offset,
        ttl=ttl,
        protocol=protocol,
        checksum=checksum,
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol_name=PROTO_NAMES.get(protocol, str(protocol))
    ), ihl


def decode_ipv6(data: bytes) -> tuple[Optional[IPv6Header], int]:
    """Decode IPv6 header, return (header, header_length)"""
    if len(data) < 40:
        return None, 0

    first_word = struct.unpack('!I', data[0:4])[0]
    version = (first_word >> 28) & 0x0F
    traffic_class = (first_word >> 20) & 0xFF
    flow_label = first_word & 0xFFFFF

    if version != 6:
        return None, 0

    payload_length = struct.unpack('!H', data[4:6])[0]
    next_header = data[6]
    hop_limit = data[7]
    src_ip = socket.inet_ntop(socket.AF_INET6, data[8:24])
    dst_ip = socket.inet_ntop(socket.AF_INET6, data[24:40])

    return IPv6Header(
        version=version,
        traffic_class=traffic_class,
        flow_label=flow_label,
        payload_length=payload_length,
        next_header=next_header,
        hop_limit=hop_limit,
        src_ip=src_ip,
        dst_ip=dst_ip,
        next_header_name=PROTO_NAMES.get(next_header, str(next_header))
    ), 40


def decode_tcp(data: bytes) -> tuple[Optional[TCPHeader], int]:
    """Decode TCP header, return (header, header_length)"""
    if len(data) < 20:
        return None, 0

    src_port = struct.unpack('!H', data[0:2])[0]
    dst_port = struct.unpack('!H', data[2:4])[0]
    seq = struct.unpack('!I', data[4:8])[0]
    ack = struct.unpack('!I', data[8:12])[0]
    data_offset_reserved = data[12]
    data_offset = ((data_offset_reserved >> 4) & 0x0F) * 4
    reserved = data_offset_reserved & 0x0F
    flags = data[13]
    window = struct.unpack('!H', data[14:16])[0]
    checksum = struct.unpack('!H', data[16:18])[0]
    urgent = struct.unpack('!H', data[18:20])[0]

    return TCPHeader(
        src_port=src_port,
        dst_port=dst_port,
        seq=seq,
        ack=ack,
        data_offset=data_offset,
        reserved=reserved,
        flags=flags,
        window=window,
        checksum=checksum,
        urgent=urgent,
        flags_str=tcp_flags_str(flags)
    ), data_offset


def decode_udp(data: bytes) -> tuple[Optional[UDPHeader], int]:
    """Decode UDP header, return (header, 8)"""
    if len(data) < 8:
        return None, 0

    src_port = struct.unpack('!H', data[0:2])[0]
    dst_port = struct.unpack('!H', data[2:4])[0]
    length = struct.unpack('!H', data[4:6])[0]
    checksum = struct.unpack('!H', data[6:8])[0]

    return UDPHeader(
        src_port=src_port,
        dst_port=dst_port,
        length=length,
        checksum=checksum
    ), 8


def decode_icmp(data: bytes) -> tuple[Optional[ICMPHeader], int]:
    """Decode ICMP header, return (header, 8)"""
    if len(data) < 8:
        return None, 0

    icmp_type = data[0]
    code = data[1]
    checksum = struct.unpack('!H', data[2:4])[0]

    return ICMPHeader(
        icmp_type=icmp_type,
        code=code,
        checksum=checksum,
        type_name=ICMP_TYPE_NAMES.get(icmp_type, f"Type {icmp_type}")
    ), 8


def decode_icmpv6(data: bytes) -> tuple[Optional[ICMPv6Header], int]:
    """Decode ICMPv6 header"""
    if len(data) < 8:
        return None, 0

    icmp_type = data[0]
    code = data[1]
    checksum = struct.unpack('!H', data[2:4])[0]

    return ICMPv6Header(
        icmp_type=icmp_type,
        code=code,
        checksum=checksum,
        type_name=ICMPV6_TYPE_NAMES.get(icmp_type, f"Type {icmp_type}")
    ), 8


def decode_igmp(data: bytes) -> tuple[Optional[IGMPHeader], int]:
    """Decode IGMPv2/v3 header (8 bytes)"""
    if len(data) < 8:
        return None, 0

    igmp_type = data[0]
    max_resp_time = data[1]
    checksum = struct.unpack('!H', data[2:4])[0]
    try:
        group_address = socket.inet_ntoa(data[4:8])
    except Exception:
        group_address = ""

    return IGMPHeader(
        igmp_type=igmp_type,
        max_resp_time=max_resp_time,
        checksum=checksum,
        group_address=group_address,
        type_name=IGMP_TYPE_NAMES.get(igmp_type, f"Type 0x{igmp_type:02x}")
    ), 8


def decode_arp(data: bytes) -> tuple[Optional[ARPHeader], int]:
    """Decode ARP header, return (header, 28)"""
    if len(data) < 28:
        return None, 0

    hw_type = struct.unpack('!H', data[0:2])[0]
    proto_type = struct.unpack('!H', data[2:4])[0]
    hw_size = data[4]
    proto_size = data[5]
    opcode = struct.unpack('!H', data[6:8])[0]
    sender_mac = mac_to_str(data[8:14])
    sender_ip = socket.inet_ntoa(data[14:18])
    target_mac = mac_to_str(data[18:24])
    target_ip = socket.inet_ntoa(data[24:28])

    return ARPHeader(
        hw_type=hw_type,
        proto_type=proto_type,
        hw_size=hw_size,
        proto_size=proto_size,
        opcode=opcode,
        sender_mac=sender_mac,
        sender_ip=sender_ip,
        target_mac=target_mac,
        target_ip=target_ip,
        op_name=ARP_OP_NAMES.get(opcode, f"Op {opcode}")
    ), 28


def get_port_name(port: int) -> str:
    """Get well-known port name"""
    return WELL_KNOWN_PORTS.get(port, "")


# ----------------------------------------------------------------------------
# Deep decoders (L7) - chỉ chạy khi payload hợp lệ
# ----------------------------------------------------------------------------

def _decode_dns_name(data: bytes, offset: int) -> tuple[str, int]:
    """
    Decode DNS name theo label format (RFC 1035).
    Trả về (name_string, new_offset).
    """
    labels = []
    jumped = False
    orig_offset = offset
    max_jumps = 5
    jumps = 0
    end_offset = offset

    while offset < len(data):
        length = data[offset]
        if length == 0:
            offset += 1
            end_offset = offset
            break
        if (length & 0xC0) == 0xC0:
            # Pointer
            if offset + 1 >= len(data) or jumps >= max_jumps:
                return ".".join(labels), min(offset + 2, len(data))
            ptr = struct.unpack('!H', data[offset:offset+2])[0] & 0x3FFF
            if not jumped:
                end_offset = offset + 2
                jumped = True
            offset = ptr
            jumps += 1
            continue
        offset += 1
        if offset + length > len(data):
            return ".".join(labels), end_offset
        try:
            labels.append(data[offset:offset+length].decode('utf-8', errors='replace'))
        except Exception:
            labels.append('')
        offset += length

    return ".".join(labels), end_offset if jumped else offset


def decode_dns(payload: bytes) -> Optional[DNSInfo]:
    """
    Decode DNS query/response. Returns None nếu payload không hợp lệ.
    Hỗ trợ 1 question + N answers đơn giản.
    """
    if len(payload) < 12:
        return None

    try:
        tid = struct.unpack('!H', payload[0:2])[0]
        flags = struct.unpack('!H', payload[2:4])[0]
        qr = (flags >> 15) & 0x01
        opcode = (flags >> 11) & 0x0F
        rcode = flags & 0x0F
        qdcount = struct.unpack('!H', payload[4:6])[0]
        ancount = struct.unpack('!H', payload[6:8])[0]
    except struct.error:
        return None

    info = DNSInfo(
        transaction_id=tid,
        is_query=(qr == 0),
        is_response=(qr == 1),
        qr=qr,
        opcode=opcode,
        rcode=rcode,
        rcode_name=DNS_RCODE_NAMES.get(rcode, f"RCODE {rcode}"),
        ancount=ancount,
    )

    offset = 12
    # Parse first question
    if qdcount > 0 and offset < len(payload):
        qname, offset = _decode_dns_name(payload, offset)
        if offset + 4 <= len(payload):
            qtype = struct.unpack('!H', payload[offset:offset+2])[0]
            offset += 4
            info.qname = qname
            info.qtype = qtype
            info.qtype_name = DNS_TYPE_NAMES.get(qtype, f"Type {qtype}")

    # Parse first few answer names (chỉ lấy tên, không phân tích đầy đủ)
    for _ in range(min(ancount, 4)):
        if offset >= len(payload):
            break
        name, offset = _decode_dns_name(payload, offset)
        if offset + 10 > len(payload):
            break
        # skip type(2) class(2) ttl(4) rdlength(2)
        try:
            rdlength = struct.unpack('!H', payload[offset+8:offset+10])[0]
        except struct.error:
            break
        offset += 10 + rdlength
        if name:
            info.answers.append(name)

    return info


def decode_http(payload: bytes) -> Optional[HTTPInfo]:
    """
    Decode HTTP request/response. Rất simple - chỉ parse dòng đầu + headers phổ biến.
    """
    if len(payload) < 4:
        return None
    try:
        text = payload[:2048].decode('utf-8', errors='replace')
    except Exception:
        return None

    info = HTTPInfo()
    lines = text.split('\r\n')
    if not lines:
        return None
    first = lines[0]

    if first.startswith('HTTP/'):
        info.is_response = True
        info.version = first[5:8] if len(first) > 8 else ""
        parts = first.split(' ', 2)
        if len(parts) >= 2:
            try:
                info.status_code = int(parts[1])
            except ValueError:
                pass
            info.status_text = parts[2] if len(parts) > 2 else HTTP_STATUS_CODES.get(info.status_code, "")
    else:
        # Method path HTTP/x.y
        parts = first.split(' ')
        if len(parts) >= 3 and parts[2].startswith('HTTP/'):
            info.is_request = True
            info.method = parts[0]
            info.uri = parts[1]
            info.version = parts[2][5:] if len(parts[2]) > 5 else ""

    # Parse common headers
    for line in lines[1:50]:
        if not line or ':' not in line:
            continue
        k, _, v = line.partition(':')
        k_l = k.strip().lower()
        v = v.strip()
        if k_l == 'host' and not info.host:
            info.host = v
        elif k_l == 'user-agent' and not info.user_agent:
            info.user_agent = v[:200]
        elif k_l == 'content-type' and not info.content_type:
            info.content_type = v

    if not info.is_request and not info.is_response:
        return None
    return info


def decode_tls(payload: bytes) -> Optional[TLSInfo]:
    """
    Decode TLS record (tối thiểu). Phát hiện ClientHello/ServerHello và SNI.
    """
    if len(payload) < 5:
        return None
    info = TLSInfo(is_tls=True)
    info.record_type = payload[0]
    info.version = struct.unpack('!H', payload[1:3])[0]
    info.version_name = TLS_VERSION_NAMES.get(info.version, f"0x{info.version:04x}")

    # Skip non-handshake
    if info.record_type != 0x16:  # Handshake
        return info

    # Handshake header starts at offset 5 (skip TLS record header)
    if len(payload) < 9:
        return info
    hs_type = payload[5]
    info.handshake_type = hs_type
    if hs_type == 1:
        info.is_client_hello = True
    elif hs_type == 2:
        info.is_server_hello = True
    else:
        return info

    # Walk to extensions area in ClientHello
    if info.is_client_hello and len(payload) >= 9:
        # Layout from offset 0 of TLS record:
        #   0: record_type (1)
        #   1-2: record version (2)
        #   3-4: record length (2)
        #   5: handshake type (1)
        #   6-8: handshake length (3 bytes)
        #   9-10: client_version (2)
        #   11-42: random (32)
        #   43: session_id_length (1)
        #   44+: session_id, cipher_suites, compression, extensions
        idx = 43
        if idx >= len(payload):
            return info
        sid_len = payload[idx]
        idx += 1 + sid_len
        if idx + 2 > len(payload):
            return info
        # cipher suites
        cs_len = struct.unpack('!H', payload[idx:idx+2])[0]
        idx += 2 + cs_len
        if idx + 1 > len(payload):
            return info
        # compression methods
        comp_len = payload[idx]
        idx += 1 + comp_len
        if idx + 2 > len(payload):
            return info
        # extensions length
        ext_len = struct.unpack('!H', payload[idx:idx+2])[0]
        idx += 2
        ext_end = idx + ext_len

        # Walk extensions, find SNI (type 0x0000)
        while idx + 4 <= ext_end and idx + 4 <= len(payload):
            ext_type = struct.unpack('!H', payload[idx:idx+2])[0]
            ext_size = struct.unpack('!H', payload[idx+2:idx+4])[0]
            idx += 4
            if ext_type == 0x0000 and idx + 5 <= len(payload):
                # SNI extension structure:
                #   list_length (2 bytes)
                #   name_type (1 byte) = 0 for host_name
                #   name_length (2 bytes)
                #   name (name_length bytes)
                if idx + 5 <= len(payload):
                    list_len = struct.unpack('!H', payload[idx:idx+2])[0]
                    name_type = payload[idx+2]
                    name_len = struct.unpack('!H', payload[idx+3:idx+5])[0]
                    name_start = idx + 5
                    name_end = name_start + name_len
                    if name_end <= len(payload) and name_type == 0:
                        try:
                            info.sni = payload[name_start:name_end].decode('utf-8', errors='replace')
                        except Exception:
                            pass
                break
            idx += ext_size

    return info


def decode_dhcp(payload: bytes) -> Optional[DHCPInfo]:
    """
    Decode DHCP options (giả định payload là UDP payload với src/dst port 67/68).
    Format: xid(4) yiaddr(4) siaddr(4) giaddr(4) chaddr(16) sname(64) file(128) options
    """
    if len(payload) < 240:
        return None
    info = DHCPInfo()
    try:
        info.transaction_id = struct.unpack('!I', payload[4:8])[0]
        info.your_ip = socket.inet_ntoa(payload[16:20])
        info.server_ip = socket.inet_ntoa(payload[20:24])
    except (struct.error, OSError):
        pass

    # Options start at offset 240, magic cookie 0x63825363
    if len(payload) < 244:
        return info
    if payload[236:240] != b'\x63\x82\x53\x63':
        return info
    info.is_dhcp = True

    offset = 240
    while offset + 2 <= len(payload):
        opt = payload[offset]
        if opt == 0xFF:  # End
            break
        if opt == 0x00:  # Pad
            offset += 1
            continue
        if offset + 2 > len(payload):
            break
        length = payload[offset + 1]
        if opt == 53 and length >= 1 and offset + 2 < len(payload):
            msg_type = payload[offset + 2]
            info.msg_type = msg_type
            info.msg_type_name = DHCP_MSG_NAMES.get(msg_type, f"Type {msg_type}")
        elif opt == 54 and length >= 4 and offset + 6 <= len(payload):
            try:
                info.server_ip = socket.inet_ntoa(payload[offset + 2:offset + 6])
            except OSError:
                pass
        offset += 2 + length

    return info


def decode_ntp(payload: bytes) -> Optional[NTPInfo]:
    """
    Decode NTP v3/v4 packet (48 bytes).
    """
    if len(payload) < 48:
        return None
    info = NTPInfo(is_ntp=True)
    li_vn_mode = payload[0]
    info.li = (li_vn_mode >> 6) & 0x03
    info.vn = (li_vn_mode >> 3) & 0x07
    info.mode = li_vn_mode & 0x07
    info.stratum = payload[1]
    info.poll = payload[2]
    info.precision = struct.unpack('!b', bytes([payload[3]]))[0]
    # reference id: 4 bytes
    try:
        info.reference_id = payload[12:16].decode('ascii', errors='replace')
    except Exception:
        info.reference_id = ""
    return info


def decode_quic(payload: bytes) -> Optional[QUICInfo]:
    """
    Decode QUIC Initial packet (long header) - rất simple, chỉ header + sniff ClientHello.
    Long header bit = payload[0] & 0x80.
    """
    if len(payload) < 7:
        return None
    info = QUICInfo(is_quic=True)
    first = payload[0]
    info.long_header = bool(first & 0x80)
    if not info.long_header:
        return info
    # Version ở byte 1..4
    info.version = struct.unpack('!I', payload[1:5])[0]
    dcil = payload[5]
    if 6 + dcil >= len(payload):
        return info
    info.dcid = payload[6:6 + dcil]
    scil = payload[6 + dcil]
    scid_start = 6 + dcil + 1
    if scid_start + scil > len(payload):
        return info
    info.scid = payload[scid_start:scid_start + scil]

    # Sniff ClientHello bên trong QUIC Initial - thử detect "client_hello"
    try:
        idx = payload.find(b'client_hello')
        if idx > 0:
            # Tìm SNI extension "\x00\x00" tiếp theo trong vài KB
            sub = payload[idx:idx + 4096]
            # Đơn giản: tìm byte 0x00 0x00 (server_name extension type)
            for off in range(0, len(sub) - 7):
                if sub[off] == 0x00 and sub[off+1] == 0x00:
                    # list_length 2 bytes
                    if off + 7 < len(sub):
                        try:
                            name_len = struct.unpack('!H', sub[off+5:off+7])[0]
                            if 0 < name_len < 256 and off + 7 + name_len <= len(sub):
                                info.sni = sub[off+7:off+7+name_len].decode('utf-8', errors='replace')
                                break
                        except struct.error:
                            pass
    except Exception:
        pass

    return info


# ----------------------------------------------------------------------------
# Public API: 2-tier decode
# ----------------------------------------------------------------------------

def detect_protocol(transport: str, src_port: int, dst_port: int, payload: bytes) -> ProtocolInfo:
    """
    Heuristic L7 detection dựa trên port + payload sniffing.
    Chạy SAU khi fast decode đã biết transport.
    """
    info = ProtocolInfo()
    if not payload:
        return info

    # Port-based fast path
    if transport == "UDP":
        if src_port == 53 or dst_port == 53:
            dns = decode_dns(payload)
            if dns:
                info.name = "DNS"
                info.dns = dns
                return info
        if src_port == 67 or dst_port == 67 or src_port == 68 or dst_port == 68:
            dhcp = decode_dhcp(payload)
            if dhcp and dhcp.is_dhcp:
                info.name = "DHCP"
                info.dhcp = dhcp
                return info
        if src_port == 123 or dst_port == 123:
            ntp = decode_ntp(payload)
            if ntp:
                info.name = "NTP"
                info.ntp = ntp
                return info
        if src_port == 443 or dst_port == 443:
            # QUIC heuristic: long header starts with version 0x00000001 or known QUIC version
            if payload and (payload[0] & 0xC0) == 0xC0:
                quic = decode_quic(payload)
                if quic and quic.is_quic:
                    info.name = "QUIC"
                    info.quic = quic
                    return info

    if transport == "TCP":
        # TLS detection: record type 0x16 (handshake) at offset 0
        if len(payload) >= 5 and payload[0] == 0x16:
            tls = decode_tls(payload)
            if tls and tls.is_tls:
                info.name = "TLS"
                info.tls = tls
                return info
        # HTTP
        if src_port == 80 or dst_port == 80 or src_port == 8080 or dst_port == 8080 \
                or src_port == 8000 or dst_port == 8000:
            http = decode_http(payload)
            if http:
                info.name = "HTTP"
                info.http = http
                return info

    return info


def decode_packet(data: bytes, deep: bool = False) -> DecodedPacket:
    """
    Decode raw packet bytes thành DecodedPacket.

    Args:
        data: Raw packet bytes
        deep: Nếu True, chạy thêm L7 detection (DNS/HTTP/TLS/DHCP/NTP/QUIC).
              Mặc định False (fast path chỉ headers).
    """
    result = DecodedPacket(raw_data=data)
    offset = 0

    # Layer 2: Ethernet
    eth, eth_len = decode_ethernet(data)
    if not eth:
        return result
    result.ethernet = eth
    offset = eth_len

    transport = "UNKNOWN"
    src_port = dst_port = 0

    # Layer 3: Network
    if eth.ethertype == ETHERTYPE_IP:
        ipv4, ip_len = decode_ipv4(data[offset:])
        if ipv4:
            result.ipv4 = ipv4
            result.src_addr = ipv4.src_ip
            result.dst_addr = ipv4.dst_ip
            result.protocol_name = ipv4.protocol_name
            transport = ipv4.protocol_name
            offset += ip_len

            # Layer 4: Transport
            if ipv4.protocol == PROTO_TCP:
                tcp, tcp_len = decode_tcp(data[offset:])
                if tcp:
                    result.tcp = tcp
                    result.src_port = tcp.src_port
                    result.dst_port = tcp.dst_port
                    src_port, dst_port = tcp.src_port, tcp.dst_port
                    result.payload = data[offset + tcp_len:]
                    port_info = ""
                    src_name = get_port_name(tcp.src_port)
                    dst_name = get_port_name(tcp.dst_port)
                    if src_name:
                        port_info = f" ({src_name})"
                    elif dst_name:
                        port_info = f" ({dst_name})"
                    result.info_str = f"{tcp.src_port} → {tcp.dst_port}{port_info} {tcp.flags_str} Seq={tcp.seq}"

            elif ipv4.protocol == PROTO_UDP:
                udp, udp_len = decode_udp(data[offset:])
                if udp:
                    result.udp = udp
                    result.src_port = udp.src_port
                    result.dst_port = udp.dst_port
                    src_port, dst_port = udp.src_port, udp.dst_port
                    result.payload = data[offset + udp_len:]
                    port_info = ""
                    src_name = get_port_name(udp.src_port)
                    dst_name = get_port_name(udp.dst_port)
                    if src_name:
                        port_info = f" ({src_name})"
                    elif dst_name:
                        port_info = f" ({dst_name})"
                    result.info_str = f"{udp.src_port} → {udp.dst_port}{port_info} Len={udp.length}"

            elif ipv4.protocol == PROTO_ICMP:
                icmp, icmp_len = decode_icmp(data[offset:])
                if icmp:
                    result.icmp = icmp
                    result.payload = data[offset + icmp_len:]
                    result.info_str = f"{icmp.type_name} (code={icmp.code})"

            elif ipv4.protocol == PROTO_ICMPV6:
                icmp6, icmp6_len = decode_icmpv6(data[offset:])
                if icmp6:
                    result.icmpv6 = icmp6
                    result.payload = data[offset + icmp6_len:]
                    result.info_str = f"{icmp6.type_name} (code={icmp6.code})"

            elif ipv4.protocol == PROTO_IGMP:
                igmp, igmp_len = decode_igmp(data[offset:])
                if igmp:
                    result.igmp = igmp
                    result.payload = data[offset + igmp_len:]
                    result.info_str = f"{igmp.type_name} group={igmp.group_address}"

    elif eth.ethertype == ETHERTYPE_IPV6:
        ipv6, ip_len = decode_ipv6(data[offset:])
        if ipv6:
            result.ipv6 = ipv6
            result.src_addr = ipv6.src_ip
            result.dst_addr = ipv6.dst_ip
            result.protocol_name = "IPv6"
            offset += ip_len

            if ipv6.next_header == PROTO_TCP:
                tcp, tcp_len = decode_tcp(data[offset:])
                if tcp:
                    result.tcp = tcp
                    result.protocol_name = "TCP"
                    result.src_port = tcp.src_port
                    result.dst_port = tcp.dst_port
                    src_port, dst_port = tcp.src_port, tcp.dst_port
                    result.payload = data[offset + tcp_len:]
                    result.info_str = f"{tcp.src_port} → {tcp.dst_port} {tcp.flags_str}"

            elif ipv6.next_header == PROTO_UDP:
                udp, _ = decode_udp(data[offset:])
                if udp:
                    result.udp = udp
                    result.protocol_name = "UDP"
                    result.src_port = udp.src_port
                    result.dst_port = udp.dst_port
                    src_port, dst_port = udp.src_port, udp.dst_port
                    result.payload = data[offset + 8:]
                    result.info_str = f"{udp.src_port} → {udp.dst_port}"

            elif ipv6.next_header == PROTO_ICMPV6:
                icmp6, icmp6_len = decode_icmpv6(data[offset:])
                if icmp6:
                    result.icmpv6 = icmp6
                    result.protocol_name = "ICMPv6"
                    result.payload = data[offset + icmp6_len:]
                    result.info_str = f"{icmp6.type_name} (code={icmp6.code})"

    elif eth.ethertype == ETHERTYPE_ARP:
        arp, _ = decode_arp(data[offset:])
        if arp:
            result.arp = arp
            result.protocol_name = "ARP"
            result.src_addr = arp.sender_ip
            result.dst_addr = arp.target_ip
            result.info_str = f"{arp.op_name}: {arp.sender_ip} → {arp.target_ip}"

    result.payload_len = len(result.payload)
    result.payload_snippet = make_payload_snippet(result.payload)

    # Deep L7 detection (opt-in)
    if deep and result.payload:
        result.proto = detect_protocol(transport, src_port, dst_port, result.payload)
        if result.proto.is_app_protocol:
            result.protocol_name = result.proto.name

    return result
