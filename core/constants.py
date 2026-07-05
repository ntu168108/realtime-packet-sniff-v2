"""
Constants for SNIFF tool
- Protocol numbers
- TCP flags
- Ethernet types
- Default configurations
"""

# Ethernet Types (EtherType)
ETHERTYPE_IP = 0x0800
ETHERTYPE_ARP = 0x0806
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_VLAN = 0x8100

ETHERTYPE_NAMES = {
    ETHERTYPE_IP: "IPv4",
    ETHERTYPE_ARP: "ARP",
    ETHERTYPE_IPV6: "IPv6",
    ETHERTYPE_VLAN: "VLAN",
}

# IP Protocol Numbers
PROTO_ICMP = 1
PROTO_IGMP = 2
PROTO_TCP = 6
PROTO_UDP = 17
PROTO_ICMPV6 = 58

PROTO_NAMES = {
    PROTO_ICMP: "ICMP",
    PROTO_IGMP: "IGMP",
    PROTO_TCP: "TCP",
    PROTO_UDP: "UDP",
    PROTO_ICMPV6: "ICMPv6",
}

# TCP Flags
TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10
TCP_URG = 0x20
TCP_ECE = 0x40
TCP_CWR = 0x80

TCP_FLAG_NAMES = {
    TCP_FIN: "FIN",
    TCP_SYN: "SYN",
    TCP_RST: "RST",
    TCP_PSH: "PSH",
    TCP_ACK: "ACK",
    TCP_URG: "URG",
    TCP_ECE: "ECE",
    TCP_CWR: "CWR",
}

def tcp_flags_str(flags: int) -> str:
    """Convert TCP flags to string like [SYN,ACK]"""
    result = []
    for flag_val, flag_name in TCP_FLAG_NAMES.items():
        if flags & flag_val:
            result.append(flag_name)
    return "[" + ",".join(result) + "]" if result else ""

# ICMP Types
ICMP_ECHO_REPLY = 0
ICMP_DEST_UNREACHABLE = 3
ICMP_REDIRECT = 5
ICMP_ECHO_REQUEST = 8
ICMP_TIME_EXCEEDED = 11

ICMP_TYPE_NAMES = {
    ICMP_ECHO_REPLY: "Echo Reply",
    ICMP_DEST_UNREACHABLE: "Destination Unreachable",
    ICMP_REDIRECT: "Redirect",
    ICMP_ECHO_REQUEST: "Echo Request",
    ICMP_TIME_EXCEEDED: "Time Exceeded",
}

# ICMPv6 Types
ICMPV6_DEST_UNREACHABLE = 1
ICMPV6_PACKET_TOO_BIG = 2
ICMPV6_TIME_EXCEEDED = 3
ICMPV6_ECHO_REQUEST = 128
ICMPV6_ECHO_REPLY = 129
ICMPV6_ROUTER_SOLICIT = 133
ICMPV6_ROUTER_ADVERT = 134
ICMPV6_NEIGHBOR_SOLICIT = 135
ICMPV6_NEIGHBOR_ADVERT = 136

ICMPV6_TYPE_NAMES = {
    ICMPV6_DEST_UNREACHABLE: "Dest Unreachable",
    ICMPV6_PACKET_TOO_BIG: "Packet Too Big",
    ICMPV6_TIME_EXCEEDED: "Time Exceeded",
    ICMPV6_ECHO_REQUEST: "Echo Request",
    ICMPV6_ECHO_REPLY: "Echo Reply",
    ICMPV6_ROUTER_SOLICIT: "Router Solicitation",
    ICMPV6_ROUTER_ADVERT: "Router Advertisement",
    ICMPV6_NEIGHBOR_SOLICIT: "Neighbor Solicitation",
    ICMPV6_NEIGHBOR_ADVERT: "Neighbor Advertisement",
}

# IGMP Types
IGMP_QUERY = 0x11
IGMP_V1_REPORT = 0x12
IGMP_V2_REPORT = 0x16
IGMP_V3_REPORT = 0x22
IGMP_LEAVE = 0x17

IGMP_TYPE_NAMES = {
    IGMP_QUERY: "Membership Query",
    IGMP_V1_REPORT: "v1 Membership Report",
    IGMP_V2_REPORT: "v2 Membership Report",
    IGMP_V3_REPORT: "v3 Membership Report",
    IGMP_LEAVE: "Leave Group",
}

# ARP Operations
ARP_REQUEST = 1
ARP_REPLY = 2

ARP_OP_NAMES = {
    ARP_REQUEST: "Request",
    ARP_REPLY: "Reply",
}

# DHCP Message Types
DHCP_DISCOVER = 1
DHCP_OFFER = 2
DHCP_REQUEST = 3
DHCP_DECLINE = 4
DHCP_ACK = 5
DHCP_NAK = 6
DHCP_RELEASE = 7
DHCP_INFORM = 8

DHCP_MSG_NAMES = {
    DHCP_DISCOVER: "Discover",
    DHCP_OFFER: "Offer",
    DHCP_REQUEST: "Request",
    DHCP_DECLINE: "Decline",
    DHCP_ACK: "ACK",
    DHCP_NAK: "NAK",
    DHCP_RELEASE: "Release",
    DHCP_INFORM: "Inform",
}

# DNS Record Types (RFC 1035 + extensions)
DNS_TYPE_A = 1
DNS_TYPE_NS = 2
DNS_TYPE_CNAME = 5
DNS_TYPE_SOA = 6
DNS_TYPE_PTR = 12
DNS_TYPE_MX = 15
DNS_TYPE_TXT = 16
DNS_TYPE_AAAA = 28
DNS_TYPE_SRV = 33
DNS_TYPE_OPT = 41
DNS_TYPE_HTTPS = 65
DNS_TYPE_ANY = 255

DNS_TYPE_NAMES = {
    DNS_TYPE_A: "A",
    DNS_TYPE_NS: "NS",
    DNS_TYPE_CNAME: "CNAME",
    DNS_TYPE_SOA: "SOA",
    DNS_TYPE_PTR: "PTR",
    DNS_TYPE_MX: "MX",
    DNS_TYPE_TXT: "TXT",
    DNS_TYPE_AAAA: "AAAA",
    DNS_TYPE_SRV: "SRV",
    DNS_TYPE_OPT: "OPT",
    DNS_TYPE_HTTPS: "HTTPS",
    DNS_TYPE_ANY: "ANY",
}

# DNS Response Codes (RCODE)
DNS_RCODE_NOERROR = 0
DNS_RCODE_FORMERR = 1
DNS_RCODE_SERVFAIL = 2
DNS_RCODE_NXDOMAIN = 3
DNS_RCODE_NOTIMP = 4
DNS_RCODE_REFUSED = 5

DNS_RCODE_NAMES = {
    DNS_RCODE_NOERROR: "NOERROR",
    DNS_RCODE_FORMERR: "FORMERR",
    DNS_RCODE_SERVFAIL: "SERVFAIL",
    DNS_RCODE_NXDOMAIN: "NXDOMAIN",
    DNS_RCODE_NOTIMP: "NOTIMP",
    DNS_RCODE_REFUSED: "REFUSED",
}

# HTTP Status Codes (subset phổ biến)
HTTP_STATUS_CODES = {
    100: "Continue",
    101: "Switching Protocols",
    200: "OK",
    201: "Created",
    204: "No Content",
    206: "Partial Content",
    301: "Moved Permanently",
    302: "Found",
    304: "Not Modified",
    307: "Temporary Redirect",
    308: "Permanent Redirect",
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    408: "Request Timeout",
    409: "Conflict",
    410: "Gone",
    429: "Too Many Requests",
    500: "Internal Server Error",
    501: "Not Implemented",
    502: "Bad Gateway",
    503: "Service Unavailable",
    504: "Gateway Timeout",
}

# Common ports - mở rộng cho HTTP/3, QUIC, WireGuard, DoH, etc
WELL_KNOWN_PORTS = {
    # Classic
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    67: "DHCP-S",
    68: "DHCP-C",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    119: "NNTP",
    123: "NTP",
    137: "NetBIOS-NS",
    138: "NetBIOS-DGM",
    139: "NetBIOS-SSN",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP-TRAP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    514: "Syslog",
    515: "LPD",
    587: "SMTP-Submission",
    631: "IPP",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    # Database
    1433: "MSSQL",
    1521: "Oracle",
    1812: "RADIUS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
    # Web/Proxy
    8080: "HTTP-ALT",
    8443: "HTTPS-ALT",
    8888: "HTTP-ALT2",
    # Modern
    853: "DoT/DoQ",               # RFC 9250 (DoT originally; DoQ shares port)
    4433: "HTTPS-ALT3",
    51820: "WireGuard",           # WireGuard VPN
    # HTTP/3 + QUIC
    443: "HTTPS/QUIC",            # HTTP/3 (over QUIC, same port as HTTPS)
    # DoH (DNS over HTTPS) uses standard HTTPS port; detected by content
    # mDNS
    5353: "mDNS",
    # LLMNR
    5355: "LLMNR",
    # SIP/VoIP
    5060: "SIP",
    5061: "SIPS",
}

# TLS Versions
TLS_VERSION_NAMES = {
    0x0300: "SSLv3",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}

# Default configurations
DEFAULT_SNAPLEN = 1518          # Capture up to 1518 bytes per packet
DEFAULT_BUFFER_SIZE = 2097152   # 2MB ring buffer
DEFAULT_PROMISC = True          # Promiscuous mode on
DEFAULT_RETENTION_DAYS = 7      # Keep PCAP files for 7 days
DEFAULT_MAX_MEMORY_MB = 500     # Max memory usage
DEFAULT_QUEUE_SIZE = 10000      # Packet queue size (legacy)
DEFAULT_UI_CACHE_SIZE = 5000    # UI packet cache size

# New tunables cho high-throughput
DEFAULT_BATCH_SIZE_PCAP = 256   # Packets per PcapWriter batch (was 100)
DEFAULT_RING_BUFFER_SIZE = 65536  # SPSC ring buffer capacity (64K packets)
MAX_DISPLAY_FILTER_LEN = 1024   # Max display filter string length
DEFAULT_PAYLOAD_SNIPPET_BYTES = 64  # ASCII payload snippet length
DEFAULT_MAX_FILE_SIZE = 500 * 1024 * 1024  # 500MB size-based rotation

# Snaplen options
SNAPLEN_OPTIONS = {
    64: "64 bytes (headers only)",
    128: "128 bytes (small)",
    256: "256 bytes (medium)",
    512: "512 bytes (large)",
    1518: "1518 bytes (full Ethernet)",
    4096: "4096 bytes (jumbo)",
    65535: "65535 bytes (max)",
}

# Buffer profiles
BUFFER_PROFILES = {
    "low": {
        "buffer_size": 1048576,     # 1MB
        "queue_size": 5000,
        "ring_buffer_size": 16384,
        "batch_size": 64,
        "desc": "Thấp - Tiết kiệm RAM",
    },
    "balanced": {
        "buffer_size": 2097152,     # 2MB
        "queue_size": 10000,
        "ring_buffer_size": 65536,
        "batch_size": 256,
        "desc": "Cân bằng - Mặc định",
    },
    "fast": {
        "buffer_size": 4194304,     # 4MB
        "queue_size": 20000,
        "ring_buffer_size": 131072,
        "batch_size": 512,
        "desc": "Nhanh - Tốc độ cao",
    },
    "max": {
        "buffer_size": 8388608,     # 8MB
        "queue_size": 50000,
        "ring_buffer_size": 262144,
        "batch_size": 1024,
        "desc": "Tối đa - Không drop",
    },
}

# PCAP file header constants
PCAP_MAGIC = 0xa1b2c3d4          # Standard pcap magic number
PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4
PCAP_LINKTYPE_ETHERNET = 1

# Time constants
STATS_UPDATE_INTERVAL = 2.0     # Update stats every 2 seconds
UI_REFRESH_INTERVAL = 0.1       # UI refresh rate (10 FPS)
DROP_STATS_UPDATE_INTERVAL = 2.0  # Read /proc/net/dev every 2s

# Protocol family for stats aggregation
PROTOCOL_FAMILIES = ("TCP", "UDP", "ICMP", "ICMPv6", "ARP", "IGMP",
                     "DNS", "HTTP", "TLS", "QUIC", "DHCP", "NTP", "OTHER")

# Conversation (5-tuple) tracking
CONVERSATION_TIMEOUT_SEC = 60   # Idle timeout for flow expiry
CONVERSATION_MAX_ENTRIES = 8192  # Hard cap on tracked flows
