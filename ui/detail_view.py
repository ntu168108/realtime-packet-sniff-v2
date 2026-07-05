"""
Detail View - Xem chi tiết packet với hexdump + ASCII
Refactored: payload inspector, protocol-specific fields, save, follow stream
"""

import sys
import os
from typing import Optional, List, Tuple, Callable, Any
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ui.colors import (
    clear_screen, print_header, print_divider, print_menu_item,
    bold, cyan, green, yellow, red, dim, magenta, white,
    show_cursor, format_protocol,
)
from core.decoder import (
    decode_packet, PacketInfo, DecodedPacket,
    DNSInfo, HTTPInfo, TLSInfo, DHCPInfo,
)
from core.pcap_writer import PcapWriter


# ============================================================
# Hexdump helpers
# ============================================================

def hexdump_payload(payload: bytes, max_bytes: int = 256, offset: int = 0) -> List[str]:
    """
    Hexdump cho payload với pagination (chỉ in `max_bytes` từ `offset`).
    Returns list of formatted lines (không print).
    """
    lines = []
    if not payload:
        return [dim("  (payload trống)")]

    end = min(offset + max_bytes, len(payload))
    chunk = payload[offset:end]

    for i in range(0, len(chunk), 16):
        sub = chunk[i:i + 16]
        hex_part = ' '.join(f'{b:02x}' for b in sub)
        hex_part = hex_part.ljust(16 * 3 - 1)
        ascii_part = ''.join(
            chr(b) if 32 <= b < 127 else '.' for b in sub
        )
        lines.append(
            f"  {dim(f'{offset + i:08x}')}  {hex_part}  {dim('|')}{ascii_part}{dim('|')}"
        )

    if end < len(payload):
        lines.append(dim(f"  ... còn {len(payload) - end} bytes (gõ 'n' để xem tiếp, 'p' để lùi)"))

    return lines


# ============================================================
# Protocol-specific field renderers
# ============================================================

def _render_dns(dns: DNSInfo) -> List[str]:
    lines = [bold("═══ DNS ═══")]
    if dns.is_query:
        lines.append(f"  Loại:      {cyan('QUERY')}")
    elif dns.is_response:
        lines.append(f"  Loại:      {cyan('RESPONSE')} (RCODE: {dns.rcode_name})")
    else:
        lines.append(f"  Loại:      {dim('N/A')}")

    lines.append(f"  TxID:      {hex(dns.transaction_id)}")
    lines.append(f"  Query:     {green(dns.qname or '(none)')}")
    lines.append(f"  Type:      {yellow(dns.qtype_name or str(dns.qtype))}")
    lines.append(f"  Answers:   {dns.ancount}")

    if dns.answers:
        lines.append(f"  {dim('Answer records:')}")
        for a in dns.answers[:5]:
            lines.append(f"    - {a}")
        if len(dns.answers) > 5:
            lines.append(dim(f"    ... +{len(dns.answers) - 5} more"))
    return lines


def _render_http(http: HTTPInfo) -> List[str]:
    lines = [bold("═══ HTTP ═══")]
    if http.is_request:
        lines.append(f"  Loại:      {cyan('REQUEST')}")
        lines.append(f"  Method:    {green(http.method)}")
        lines.append(f"  URI:       {yellow(http.uri)}")
        lines.append(f"  Host:      {cyan(http.host)}")
        lines.append(f"  Version:   {dim(http.version)}")
        if http.user_agent:
            lines.append(f"  User-Agent: {dim(http.user_agent[:80])}")
    elif http.is_response:
        lines.append(f"  Loại:      {cyan('RESPONSE')}")
        lines.append(f"  Status:    {yellow(f'{http.status_code} {http.status_text}')}")
        lines.append(f"  Version:   {dim(http.version)}")
        if http.content_type:
            lines.append(f"  Content-Type: {dim(http.content_type)}")
    else:
        lines.append(dim("  (Không parse được HTTP)"))
    return lines


def _render_tls(tls: TLSInfo) -> List[str]:
    lines = [bold("═══ TLS ═══")]
    if not tls.is_tls:
        lines.append(dim("  (Không phải TLS record hợp lệ)"))
        return lines

    lines.append(f"  Version:        {yellow(tls.version_name)}")
    if tls.is_client_hello:
        lines.append(f"  Loại:          {cyan('ClientHello')}")
    elif tls.is_server_hello:
        lines.append(f"  Loại:          {cyan('ServerHello')}")
    if tls.sni:
        lines.append(f"  SNI:           {green(tls.sni)}")
    if tls.cipher_suite:
        lines.append(f"  Cipher Suite:  {hex(tls.cipher_suite)}")
    return lines


def _render_dhcp(dhcp: DHCPInfo) -> List[str]:
    lines = [bold("═══ DHCP ═══")]
    lines.append(f"  Msg Type:    {cyan(dhcp.msg_type_name)} ({dhcp.msg_type})")
    lines.append(f"  TxID:        {hex(dhcp.transaction_id)}")
    if dhcp.client_ip:
        lines.append(f"  Client IP:   {green(dhcp.client_ip)}")
    if dhcp.your_ip:
        lines.append(f"  Your IP:     {green(dhcp.your_ip)}")
    if dhcp.server_ip:
        lines.append(f"  Server IP:   {green(dhcp.server_ip)}")
    return lines


# ============================================================
# PacketDetailView
# ============================================================

class PacketDetailView:
    """
    Hiển thị chi tiết packet:

    - Decode các layer + protocol-specific fields
    - Hexdump + ASCII payload (paginated)
    - Save packet ra PCAP riêng
    - Follow stream (cùng 5-tuple)
    """

    def __init__(self):
        # Paginator state cho payload
        self._payload_offset = 0
        self._payload_max = 256

    def show(
        self,
        pkt_info: PacketInfo,
        on_back: Optional[Callable] = None,
        save_dir: Optional[str] = None,
        follow_stream_callback: Optional[Callable[[PacketInfo], List[PacketInfo]]] = None,
    ):
        """
        Args:
            pkt_info: Thông tin packet
            on_back: Callback khi quay lại
            save_dir: Thư mục lưu packet (cho save feature)
            follow_stream_callback: Optional callback trả về list packets cùng flow
        """
        show_cursor()
        decoded = decode_packet(pkt_info.data)
        self._payload_offset = 0

        while True:
            clear_screen()
            print_header(f" CHI TIẾT GÓI #{pkt_info.stt} ", '═')
            print()

            # Basic info
            print(bold("═══ THÔNG TIN CHUNG ═══"))
            print(f"  STT:        {cyan(str(pkt_info.stt))}")
            print(f"  Thời gian:  {pkt_info.ts_sec}.{pkt_info.ts_usec:06d}")
            print(f"  Độ dài:     {pkt_info.caplen} bytes (gốc: {pkt_info.origlen} bytes)")
            print(f"  Protocol:   {format_protocol(decoded)}")
            print()

            # Ethernet
            if decoded.ethernet:
                eth = decoded.ethernet
                print(bold("═══ ETHERNET ═══"))
                print(f"  MAC nguồn:  {cyan(eth.src_mac)}")
                print(f"  MAC đích:   {cyan(eth.dst_mac)}")
                print(f"  EtherType:  {hex(eth.ethertype)} ({eth.ethertype_name})")
                print()

            # IPv4
            if decoded.ipv4:
                ip = decoded.ipv4
                print(bold("═══ IPv4 ═══"))
                print(f"  Version:    {ip.version}")
                print(f"  IHL:        {ip.ihl} bytes")
                print(f"  ToS:        {ip.tos}")
                print(f"  Length:     {ip.total_length}")
                print(f"  ID:         {ip.identification}")
                print(f"  Flags:      {ip.flags}")
                print(f"  Frag Off:   {ip.fragment_offset}")
                print(f"  TTL:        {ip.ttl}")
                print(f"  Protocol:   {ip.protocol} ({ip.protocol_name})")
                print(f"  Checksum:   {hex(ip.checksum)}")
                print(f"  Nguồn:      {green(ip.src_ip)}")
                print(f"  Đích:       {green(ip.dst_ip)}")
                print()

            # IPv6
            if decoded.ipv6:
                ip6 = decoded.ipv6
                print(bold("═══ IPv6 ═══"))
                print(f"  Version:      {ip6.version}")
                print(f"  Traffic Cls:  {ip6.traffic_class}")
                print(f"  Flow Label:   {ip6.flow_label}")
                print(f"  Payload Len:  {ip6.payload_length}")
                print(f"  Next Header:  {ip6.next_header}")
                print(f"  Hop Limit:    {ip6.hop_limit}")
                print(f"  Nguồn:        {green(ip6.src_ip)}")
                print(f"  Đích:         {green(ip6.dst_ip)}")
                print()

            # TCP
            if decoded.tcp:
                tcp = decoded.tcp
                print(bold("═══ TCP ═══"))
                print(f"  Port nguồn: {yellow(str(tcp.src_port))}")
                print(f"  Port đích:  {yellow(str(tcp.dst_port))}")
                print(f"  Seq:        {tcp.seq}")
                print(f"  Ack:        {tcp.ack}")
                print(f"  Data Off:   {tcp.data_offset} ({tcp.data_offset * 4} bytes)")
                # Highlight flags theo màu
                flag_color = red if (tcp.flags & 0x04) else (green if (tcp.flags & 0x02) else magenta)
                print(f"  Flags:      {flag_color(tcp.flags_str)} ({hex(tcp.flags)})")
                print(f"  Window:     {tcp.window}")
                print(f"  Checksum:   {hex(tcp.checksum)}")
                print(f"  Urgent:     {tcp.urgent}")
                print()

            # UDP
            if decoded.udp:
                udp = decoded.udp
                print(bold("═══ UDP ═══"))
                print(f"  Port nguồn: {yellow(str(udp.src_port))}")
                print(f"  Port đích:  {yellow(str(udp.dst_port))}")
                print(f"  Length:     {udp.length}")
                print(f"  Checksum:   {hex(udp.checksum)}")
                print()

            # ICMP
            if decoded.icmp:
                icmp = decoded.icmp
                print(bold("═══ ICMP ═══"))
                print(f"  Type:       {magenta(icmp.type_name)} ({icmp.icmp_type})")
                print(f"  Code:       {icmp.code}")
                print(f"  Checksum:   {hex(icmp.checksum)}")
                print()

            # ARP
            if decoded.arp:
                arp = decoded.arp
                print(bold("═══ ARP ═══"))
                print(f"  Operation:    {magenta(arp.op_name)} ({arp.opcode})")
                print(f"  Sender MAC:   {cyan(arp.sender_mac)}")
                print(f"  Sender IP:    {green(arp.sender_ip)}")
                print(f"  Target MAC:   {cyan(arp.target_mac)}")
                print(f"  Target IP:    {green(arp.target_ip)}")
                print()

            # Protocol-specific (DNS, HTTP, TLS, DHCP)
            if decoded.proto and decoded.proto.is_app_protocol:
                if decoded.proto.dns:
                    print('\n'.join(_render_dns(decoded.proto.dns)))
                    print()
                if decoded.proto.http:
                    print('\n'.join(_render_http(decoded.proto.http)))
                    print()
                if decoded.proto.tls:
                    print('\n'.join(_render_tls(decoded.proto.tls)))
                    print()
                if decoded.proto.dhcp:
                    print('\n'.join(_render_dhcp(decoded.proto.dhcp)))
                    print()

            # Payload inspector
            print(bold("═══ PAYLOAD INSPECTOR ═══"))
            if decoded.payload:
                total = len(decoded.payload)
                print(f"  Payload size: {total} bytes "
                      f"(đang xem {self._payload_offset}-{min(self._payload_offset + self._payload_max, total)})")
                print(f"  Protocol: {format_protocol(decoded)}")
                print()
                for line in hexdump_payload(decoded.payload,
                                             max_bytes=self._payload_max,
                                             offset=self._payload_offset):
                    print(line)
                print()
                print(dim(f"  [n] Next page | [p] Prev page | [g] Go to offset"))
            else:
                print(dim("  (Không có payload)"))

            print()
            print_divider()
            print()

            # Menu
            print_menu_item('1', 'Quay lại danh sách')
            print_menu_item('2', 'Lưu gói này ra file PCAP riêng' if save_dir else '(Save - không có save_dir)')
            if follow_stream_callback:
                print_menu_item('f', 'Follow stream (cùng 5-tuple)')
            print_menu_item('n', 'Payload: trang tiếp')
            print_menu_item('p', 'Payload: trang trước')
            print_menu_item('0', 'Thoát về menu chính')
            print()

            try:
                choice = input(f"{cyan('Chọn')} [0-2/f/n/p]: ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                return

            if choice == '1':
                if on_back:
                    on_back()
                return
            elif choice == '2' and save_dir:
                self._save_single_packet(pkt_info, save_dir)
            elif choice == 'f' and follow_stream_callback:
                self._show_follow_stream(pkt_info, follow_stream_callback)
            elif choice == 'n':
                if decoded.payload:
                    self._payload_offset = min(
                        self._payload_offset + self._payload_max,
                        max(0, len(decoded.payload) - 1)
                    )
            elif choice == 'p':
                if decoded.payload:
                    self._payload_offset = max(0, self._payload_offset - self._payload_max)
            elif choice == '0':
                return

    def _save_single_packet(self, pkt_info: PacketInfo, save_dir: str):
        """Lưu một packet ra file riêng."""
        os.makedirs(save_dir, exist_ok=True)

        filename = f"packet_{pkt_info.stt}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
        filepath = os.path.join(save_dir, filename)

        try:
            writer = PcapWriter(filepath, snaplen=65535)
            writer.open()
            writer.write_packet(
                pkt_info.ts_sec,
                pkt_info.ts_usec,
                pkt_info.data,
                pkt_info.origlen,
            )
            writer.close()
            print(green(f"\n[OK] Đã lưu: {filepath}"))
        except Exception as e:
            print(red(f"\n[Lỗi] Không lưu được file: {e}"))

        input("\nNhấn Enter để tiếp tục...")

    def _show_follow_stream(
        self,
        pkt_info: PacketInfo,
        callback: Callable[[PacketInfo], List[PacketInfo]],
    ):
        """
        Hiển thị các packet cùng flow (5-tuple: proto + src/dst + ports).
        """
        try:
            related = callback(pkt_info)
        except Exception as e:
            print(red(f"\n[Lỗi] Follow stream: {e}"))
            input("\nNhấn Enter để tiếp tục...")
            return

        clear_screen()
        print_header(f" FOLLOW STREAM - Gói #{pkt_info.stt} ", '═')
        print()
        print(dim(f"  Tìm thấy {len(related)} packet cùng flow (5-tuple):"))
        print()

        if not related:
            print(dim("  (Không có packet nào cùng flow)"))
        else:
            # Show 20 packet đầu tiên
            print(bold(f"  {'STT':<8} {'Thời gian':<14} {'Nguồn':<24} {'Đích':<24} {'Proto':<8} {'Dài':<6}"))
            print(dim('  ' + '─' * 90))
            for pkt, decoded in related[:20]:
                if decoded is None:
                    decoded = decode_packet(pkt.data)
                src = f"{decoded.src_addr}:{decoded.src_port}" if decoded and decoded.src_port else (decoded.src_addr if decoded else '-')
                dst = f"{decoded.dst_addr}:{decoded.dst_port}" if decoded and decoded.dst_port else (decoded.dst_addr if decoded else '-')
                proto = decoded.protocol_name if decoded else '?'
                t = f"{pkt.ts_sec % 10000}.{pkt.ts_usec // 1000:03d}"
                print(f"  {pkt.stt:<8} {t:<14} {src[:24]:<24} {dst[:24]:<24} {proto:<8} {pkt.origlen:<6}")

            if len(related) > 20:
                print(dim(f"\n  ... còn {len(related) - 20} packet nữa ..."))

        print()
        input("Nhấn Enter để quay lại...")