"""Interactive menu mode entry point."""

import time
from pathlib import Path

from ui.menu import MainMenu
from ui.colors import red, bold, info, success
from core.constants import (
    DEFAULT_SNAPLEN, DEFAULT_PROMISC, DEFAULT_RETENTION_DAYS,
)
from core.decoder import decode_packet
from cli.app import SniffApp


def run_menu_mode(data_dir: str):
    """Run interactive menu mode"""

    def on_quick_capture(interface: str, settings: dict):
        app = SniffApp(
            data_dir=settings.get('base_dir', data_dir),
            interface=interface,
            snaplen=settings.get('snaplen', DEFAULT_SNAPLEN),
            promisc=settings.get('promisc', DEFAULT_PROMISC),
            buffer_profile=settings.get('buffer_profile', 'balanced'),
            retention_days=settings.get('retention_days', DEFAULT_RETENTION_DAYS),
        )
        app.run_interactive()

    def on_advanced_capture(interface: str, settings: dict):
        app = SniffApp(
            data_dir=settings.get('base_dir', data_dir),
            interface=interface,
            snaplen=settings.get('snaplen', DEFAULT_SNAPLEN),
            promisc=settings.get('promisc', DEFAULT_PROMISC),
            buffer_profile=settings.get('buffer_profile', 'balanced'),
            retention_days=settings.get('retention_days', DEFAULT_RETENTION_DAYS),
            enable_modules=len(settings.get('modules', [])) > 0,
        )
        app.run_interactive()

    def on_open_pcap(base_dir: str):
        from ui.colors import print_menu_item, cyan, dim
        from core.pcap_writer import PcapReader
        from ui.detail_view import PacketDetailView

        raw_dir = Path(base_dir) / "raw"
        if not raw_dir.exists():
            print(red("Chưa có file PCAP nào!"))
            input("Nhấn Enter để tiếp tục...")
            return
        pcap_files = list(raw_dir.rglob("*.pcap"))
        if not pcap_files:
            print(red("Không tìm thấy file PCAP nào!"))
            input("Nhấn Enter để tiếp tục...")
            return
        pcap_files.sort(key=lambda f: f.stat().st_mtime, reverse=True)
        print(bold("Danh sách file PCAP (mới nhất trước):"))
        print()
        for i, f in enumerate(pcap_files[:20], 1):
            size = f.stat().st_size
            mtime = time.strftime('%Y-%m-%d %H:%M', time.localtime(f.stat().st_mtime))
            print(f"  [{i}] {f.name} ({size:,} bytes) - {mtime}")
        if len(pcap_files) > 20:
            print(dim(f"  ... và {len(pcap_files) - 20} file khác"))
        print()
        print_menu_item('0', 'Quay lại')
        print()
        choice = input(f"{cyan('Chọn file')} [0-{min(20, len(pcap_files))}]: ").strip()
        if choice == '0' or not choice:
            return
        try:
            idx = int(choice) - 1
            if 0 <= idx < min(20, len(pcap_files)):
                filepath = pcap_files[idx]
                print(info(f"Đang đọc {filepath.name}..."))
                with PcapReader(str(filepath)) as reader:
                    packets = list(reader)
                if not packets:
                    print(red("File rỗng!"))
                    input("Nhấn Enter để tiếp tục...")
                    return
                print(success(f"Đọc được {len(packets)} gói"))
                print()
                print(bold("Các gói trong file:"))
                print()
                for i, pkt in enumerate(packets[:20], 1):
                    try:
                        decoded = decode_packet(pkt.data)
                        proto = decoded.protocol_name if decoded else 'UNKNOWN'
                        src = decoded.src_addr or '-'
                        dst = decoded.dst_addr or '-'
                        if decoded and decoded.src_port:
                            src = f"{src}:{decoded.src_port}"
                        if decoded and decoded.dst_port:
                            dst = f"{dst}:{decoded.dst_port}"
                        if len(src) > 25:
                            src = src[:22] + '...'
                        if len(dst) > 25:
                            dst = dst[:22] + '...'
                        print(f"  [{i:2}] {proto:8} {src:25} -> {dst:25} ({pkt.caplen} bytes)")
                    except Exception:
                        print(f"  [{i:2}] #{pkt.stt} - {pkt.caplen} bytes")
                print()
                detail_choice = input(
                    f"{cyan('Xem chi tiết gói')} [1-{min(20, len(packets))}] "
                    f"hoặc Enter để quay lại: "
                ).strip()
                if detail_choice:
                    try:
                        pkt_idx = int(detail_choice) - 1
                        if 0 <= pkt_idx < min(20, len(packets)):
                            detail_view = PacketDetailView()
                            detail_view.show(packets[pkt_idx], on_back=None)
                    except ValueError:
                        pass
        except ValueError:
            pass

    menu = MainMenu(
        on_quick_capture=on_quick_capture,
        on_advanced_capture=on_advanced_capture,
        on_open_pcap=on_open_pcap,
        on_settings=lambda: None,
    )
    menu.show()
