# Changelog

All notable changes to `realtime-packet-sniff-v2` are documented in this file.

## [Unreleased] - fix/ci-red-docs-strict-and-dosguard-race-on-py310

Hai workflow đang báo đỏ trên `main` (`Docs`, `Web GUI`). Vá cả hai.

### Fixed
- **`Docs` đỏ: `mkdocs build --strict` abort.** Báo cáo
  `docs/reports/2026-07-17-phan-loai-sai-3-kich-ban.md` có link tương đối trỏ
  RA NGOÀI cây `docs/`
  (`../../Extraction-and-classification/.../unified_classifier.py`) — mkdocs
  không phân giải được, phát WARNING, và `--strict` biến warning thành lỗi. Đổi
  sang URL GitHub tuyệt đối theo đúng convention các doc khác trong repo đang
  dùng. Đồng thời sửa anchor nội bộ `#8-trạng-thái-khắc-phục-2026-07-24` →
  `#8-trang-thai-khac-phuc-2026-07-24`: mkdocs slugify bỏ dấu tiếng Việt và xoá
  hẳn ký tự `đ`, nên anchor có dấu không bao giờ khớp. Đã dựng lại site tại chỗ
  bằng `mkdocs build --strict` để xác nhận sạch.
- **`Web GUI` đỏ trên Python 3.10 (3.11/3.12 xanh): race condition trong
  `DosGuard` CHƯA được vá thật.** `test_no_race_between_capture_thread_and_monitor_thread`
  vẫn tái tạo được `RuntimeError: dictionary changed size during iteration`.
  Bản vá trước chỉ hoán đổi tham chiếu `counts, self._dst_counts = self._dst_counts, {}`
  và lập luận rằng thao tác nguyên tử dưới GIL là đủ. **Lập luận đó sai:**
  `_note_dst()` copy tham chiếu dict vào biến local *trước* khi ghi, nên nếu
  luồng giám sát hoán đổi đúng giữa hai bước thì phép ghi vẫn rơi vào dict CŨ —
  chính dict đang được lặp. Đã chứng minh cơ chế một cách tất định (không cần
  đa luồng): giữ tham chiếu → hoán đổi → ghi qua tham chiếu cũ → `RuntimeError`.
  Vá bằng `threading.Lock` bao **cả** phép ghi trong `_note_dst()` và phép hoán
  đổi trong `_update_hot_victim()`; vòng lặp tổng hợp chạy NGOÀI khoá nên thời
  gian giữ khoá là một phép tăng counter hoặc một phép hoán đổi.

### Added
- 3 test trong `tests/integration_tests/test_dos_guard.py` kiểm tra **trực tiếp
  bất biến của khoá** thay vì phụ thuộc lịch biểu luồng:
  `test_note_dst_serialises_on_counts_lock`,
  `test_update_hot_victim_swaps_counts_under_lock`,
  `test_hot_victim_still_detected_after_locking`. Lý do cần chúng: test race
  theo thời gian có sẵn **tái tạo được lỗi trên Python 3.10 nhưng không trên
  3.12**, nên bug đã lọt qua CI ở 3.12 hơn một lần. Ba test mới tất định và bắt
  lỗi trên mọi phiên bản — đã kiểm chứng bằng cách tạm bỏ khoá: test đỏ đúng
  như mong đợi, khôi phục khoá thì xanh.

## [Unreleased] - fix/scan-vs-flood-misclassification

Vá lỗi phân loại sai lớn nhất mà báo cáo thực nghiệm
[`docs/reports/2026-07-17-phan-loai-sai-3-kich-ban.md`](docs/reports/2026-07-17-phan-loai-sai-3-kich-ban.md)
ghi nhận: cả 3 kịch bản tấn công (SYN scan, `nmap -sV -O`, nikto+SQLi) đều sinh
ra hàng loạt nhãn `DoS` dù không kịch bản nào là DoS thật (Exp1: 248/377 luồng
sai, Exp2: 995/1015 luồng sai).

### Fixed
- **Port-scan bị gán nhầm nhãn DoS hàng loạt.** Cổng volumetric trước đây chỉ
  đếm số flow flood-like theo `dstip`, khiến một cuộc quét 500–1000 cổng vào
  một host trở nên không phân biệt được với SYN-flood: cả hai đều là "rất nhiều
  flow flood-like đổ về cùng 1 đích". Bổ sung điều kiện độ đa dạng cổng đích
  (`DOS_MAX_DPORT_SPREAD`, mặc định 8): một đích chỉ được coi là đang chịu flood
  khi lượng flow flood-like đổ về nó **tập trung vào ít cổng**. Đây là đặc trưng
  duy nhất còn phân biệt được hai loại ở tầng flow-only.
  Đo trực tiếp trên cùng một tập dữ liệu qua classifier cũ và mới:
  KB1 (500 cổng, 1 host) **500/500 → 0/500** nhãn DoS (493 `Reconnaissance`,
  7 `Suspicious-Low-Volume`); flood thật (1 cổng, 500 flow) giữ nguyên
  **500/500** phát hiện đúng.
- **`rate` (tỷ số `spkts/dur`) kích hoạt cổng DoS trên flow đơn gói.** Một
  probe 1 gói với `dur` cỡ 0,2 ms đạt `rate = 5000`, chạm thẳng
  `DOS_HIGH_RATE` — trong khi 1 gói tin không cấu thành "tốc độ cao" theo bất
  kỳ nghĩa nào. Ranh giới `DoS`/`Reconnaissance` vì thế chỉ cách nhau vài trăm
  micro-giây độ trễ mạng (`dur=0.000577` → DoS, `dur=0.000705` → Recon), hoàn
  toàn không ổn định. Bổ sung yêu cầu số gói tối thiểu
  (`DOS_MIN_PKTS_FOR_RATE`, mặc định 4) trước khi tín hiệu `rate` được tin cậy.
- **Nhãn trung tính `Suspicious-Low-Volume` không còn ghi đè nhãn họ hợp lệ.**
  Sau khi cổng đa dạng cổng loại port-scan khỏi DoS, toàn bộ flow scan trở thành
  `flood_like_ungated`; nếu giữ nguyên logic cũ chúng sẽ bị gán
  `Suspicious-Low-Volume` — chỉ đổi một nhãn sai lấy một nhãn sai khác. Các flow
  này đã có `reconnaissance_score` vượt ngưỡng, nên nhãn trung tính giờ chỉ áp
  cho flow flood-like mà **không họ nào nhận**
  (`flood_like_ungated & ~has_family`).
- **`dport` thiếu làm phình số cổng riêng biệt → bỏ lọt flood 100%** (lỗi phát
  sinh khi cài đặt cổng spread ở trên, phát hiện và vá trước khi triển khai).
  Đếm cổng riêng biệt trên giá trị `dport` thô là sai khi `dport` là `NaN` —
  xảy ra thật với flow **ICMP** (không có cổng đích) và ô CSV rỗng: từ Python
  3.10 `hash(NaN)` dựa trên `id()` và `nan != nan`, nên **mỗi `NaN` là một phần
  tử set riêng**. Kết quả đo được: flood 500 flow với `dport=NaN` cho
  `spread=500` > ngưỡng → `dst_pressure=False` → **500/500 → 0/500 DoS, bỏ lọt
  hoàn toàn**. Đã chuẩn hoá `dport` về `int64` với sentinel `-1` cho giá trị
  thiếu (tách biệt với cổng `0` hợp lệ) để chúng đếm là đúng một cổng.

### Added
- 6 test hồi quy trong `tests/test_unified_classifier.py`: port-scan không ra
  DoS, port-scan ra đúng `Reconnaissance`, flood 1 cổng vẫn ra DoS (kiểm soát
  false-negative), probe đơn gói rate cao không kích hoạt cổng DoS, flood
  trải 5 cổng (trong ngưỡng spread) vẫn ra DoS, và flood với `dport`
  thiếu (`NaN`/`""`/`None`) vẫn ra DoS.
- 2 biến môi trường hiệu chỉnh: `DOS_MAX_DPORT_SPREAD`, `DOS_MIN_PKTS_FOR_RATE`
  — xem bảng ở `docs/operations/deployment.vi.md` §11.3.

### Verified on production data
- Đã export lại **chính các flow của 3 kịch bản** từ `network_ids.flows_all`
  (de-dup 7× của bảng Merge) và chạy qua classifier sau vá với cùng đầu vào.
  Nhãn cũ đọc từ ClickHouse tái tạo đúng Bảng 3.1 của báo cáo, nên phép so sánh
  hợp lệ. Kết quả: **1748 nhãn `DoS` → 0**, cụ thể 07:15 495→0, 07:17 248→0,
  07:21 995→0, 07:22 3→0, và 7 flow đơn lẻ ngày 07-24 →0. **Không flow nào mới
  trở thành DoS.** Xem `docs/reports/2026-07-17-phan-loai-sai-3-kich-ban.md`
  §8.3b.
- Phát hiện đi kèm: **toàn bộ 1748 nhãn `DoS` hệ thống từng sinh ra đều là
  false-positive** — dữ liệu đã lưu không chứa flood thật nào; mọi khung có nhãn
  DoS đều mang chữ ký port-scan hoặc là flow đơn lẻ 1–2 gói.
- **Chưa xác minh:** kiểm soát false-negative trên traffic sống
  (`hping3 -S --rand-source` phải vẫn ra nhãn DoS) chưa chạy được — `hping3`/
  `nmap` chưa cài trên máy sniff và `sudo` cần mật khẩu. Kiểm soát hiện tại chỉ
  dựa trên 4 kịch bản flood tổng hợp + 6 test hồi quy. Xem §8.3c.

### Known limitations
- **Scan hẹp (≤ `DOS_MAX_DPORT_SPREAD` cổng) vào 1 host với ≥ 40 flow vẫn bị
  gán DoS.** Đây là vùng chồng lấn thật ở tầng flow-only — 60 flow dồn vào 6
  cổng của một máy về mặt thống kê *đúng là* giống flood. Phân biệt triệt để
  cần tín hiệu ngoài flow (nhịp thời gian giữa các probe, hoặc trạng thái phản
  hồi RST của victim). **Không** vá bằng cách hạ `DOS_MAX_DPORT_SPREAD` — làm
  vậy sẽ bỏ lọt flood đa cổng thật.
- Ngưỡng `8` và `4` chọn theo thực nghiệm trên traffic LAN của lab này, không
  phải hằng số phổ quát; hiệu chỉnh qua biến môi trường khi triển khai nơi khác.
- Nhãn `Suspicious-Low-Volume` vẫn **chưa có biểu diễn riêng ở tầng
  dashboard/ClickHouse** (tồn đọng từ bản vá trước). Bản vá này làm nhãn đó
  xuất hiện ít hơn hẳn (scan giờ ra `Reconnaissance`) nhưng không xử lý khoảng
  trống hiển thị đó.
- Không chạm tới nguyên nhân gốc rễ #3 của báo cáo (thiếu DPI/TLS → Exploits/
  SQLi chỉ suy luận gián tiếp từ hình dạng luồng) và cũng chưa thêm cột
  `dos_reason` mà báo cáo đề xuất để tách nguồn gốc nhãn DoS
  (`dst_pressure` vs `high_rate`) — cả hai là hạng mục riêng, lớn hơn một PR.

## [Unreleased] - fix/dosguard-race-and-classifier-gating-edge-cases

Tự triển khai thực nghiệm rà soát repo (gọi trực tiếp `DosGuard` và
`unified_classifier.classify_segment()` giống cách `run_producer.py` gọi
chúng trong sản xuất, do sandbox không có `CAP_NET_RAW` để phát lại traffic
thật). Tìm và vá được 2 lỗi tái tạo bằng thực nghiệm + 1 lỗ hổng thiết kế ở
biên ngưỡng.

### Fixed
- **Race condition trong `DosGuard._update_hot_victim()`** (`integration/dos_guard.py`):
  luồng giám sát 1Hz lặp trực tiếp trên `self._dst_counts` trong khi luồng bắt
  gói (`should_keep()` → `_note_dst()`) ghi thêm key mới vào cùng dict không
  khóa → `RuntimeError: dictionary changed size during iteration`. Tái tạo
  được bằng stress test (6 luồng bắt gói + 1 luồng giám sát, ép
  `sys.setswitchinterval(1e-6)` để mở rộng cửa sổ race). Vá bằng cách hoán đổi
  dict ra ngoài (atomically dưới GIL) trước khi lặp, thay vì lặp trên dict
  đang sống rồi reset ở cuối. Thêm test hồi quy
  `test_no_race_between_capture_thread_and_monitor_thread` vào
  `tests/integration_tests/test_dos_guard.py`. Nâng log exception trong
  `_dos_guard_loop` (`integration/run_producer.py`) từ `debug` lên `warning`
  kèm traceback — trước đây bị nuốt âm thầm ở mức không ai xem trong production.
- **Heuristic `.255` loại nhầm victim hợp lệ khỏi toàn bộ phân loại**
  (`Extraction-and-classification/MODULE_PHANLOAI/unified_classifier.py`):
  `_multicast_broadcast_dst_mask()`/`_benign_infra_mask()` coi mọi IP kết
  thúc `.255` là broadcast /24 — sai với mạng lớn hơn /24 (VLSM /23+, nơi
  `.255` là host hợp lệ). Thực nghiệm: SYN-flood 60-flow giống hệt nhau, đổi
  victim từ `.135` sang `.255` khiến kết quả từ `DoS×60` thành `Normal×60`
  (bỏ lọt 100%). Thêm biến môi trường `LAN_CIDRS` (CSV các CIDR mạng LAN thật)
  để tính broadcast address CHÍNH XÁC theo subnet mask (`ipaddress` module)
  thay vì suy đoán octet cuối; không cấu hình `LAN_CIDRS` → không áp mask này
  nữa (an toàn hơn mặc định: sót vài gói broadcast /24 còn hơn loại nhầm
  victim /23+).
- **Ngưỡng cứng `DOS_MIN_FLOWS_PER_DST=40` gây gán nhầm họ thay vì bỏ lọt
  trung tính** (`_detect_dos()`/`classify_segment()`): SYN-flood dưới ngưỡng
  volumetric (39 flow) không rớt về `Normal` mà bị gán nhầm `Reconnaissance`
  vì đặc trưng 1-gói khớp gần hết chữ ký recon. Thực nghiệm: 39 flow →
  `Reconnaissance` (sai), 40 flow → `DoS` (đúng). Thêm nhãn trung tính mới
  `Suspicious-Low-Volume` cho flow flood-like chưa qua cổng volumetric, thay
  vì để rơi tự do vào vòng chấm điểm 6 họ.

Chi tiết đầy đủ (thực nghiệm tái tạo, plan khắc phục dài hạn, giới hạn của
thực nghiệm) xem báo cáo đính kèm phiên làm việc (không nằm trong repo này).

## [Unreleased] - fix/sniff-web-node-version-requirement

Reproduced live: installing Node 18.19.1 per the old docs, `install_web.sh`
ran `npm install` clean (only an `EBADENGINE` warning), then `npm run build`
crashed immediately with `SyntaxError: The requested module 'node:util'
does not provide an export named 'styleText'`.

### Fixed
- **`sniff-web/web/package.json` pins `vite@8` / `@vitejs/plugin-react@6`,
  both requiring Node `^20.19.0 || >=22.12.0`** (confirmed via
  `npm view vite engines` / `npm view @vitejs/plugin-react engines`) — the
  `styleText` API used by rolldown (vite 8's bundler) only exists from Node
  20.12+. Docs previously said "18+", which is wrong for the currently
  pinned versions.
  - `docs/getting-started/installation.md` / `.vi.md` untouched (no Node
    requirement there); `docs/operations/deployment.md` / `.vi.md` §11.1:
    corrected the Node.js requirement row to **20.19+ (or 22.12+, Node 22
    LTS recommended)**, added a callout explaining the failure mode up
    front, added NodeSource + nvm upgrade instructions, and added a
    "clean reinstall" step for anyone who already ran `npm install` under
    an old Node.
  - `docs/operations/troubleshooting.md` / `deployment.vi.md` §11.4: added
    a row mapping the `styleText` SyntaxError to its fix; corrected two
    adjacent rows that still said "Node 18+" / "NodeSource 20.x".
- **`sniff-web/scripts/install_web.sh`** — the auto-upgrade check
  (`NODE_MAJOR -lt 18`) didn't match the real requirement above, so a
  machine with Node 18, 19, 20.0–20.18, or 21.x would pass the check
  and still hit the same crash even through the "zero-touch" installer.
  Replaced with a proper major.minor check against
  `^20.19.0 || >=22.12.0`, and changed the NodeSource fallback from
  `setup_20.x` to `setup_22.x` to match the docs' Node 22 LTS
  recommendation.

Verified: `mkdocs build --strict` (0 warnings); `bash -n install_web.sh`
(syntax OK); manually exercised the new version-check logic against all
boundary cases (18.x, 19.x, 20.0–20.18, 21.x correctly rejected; 20.19+,
22.12+, 23+ correctly accepted).

## [Unreleased] - fix/installation-doc-clickhouse-password

### Fixed
- **`docs/getting-started/installation.md` / `installation.vi.md`, §4.1
  ClickHouse install** — the documented command set
  `CLICKHOUSE_PASSWORD` via `export` and then ran `sudo apt-get install`
  as a separate command. This is unreliable: `sudo` resets the entire
  environment by default (`env_reset` in `/etc/sudoers`), keeping only a
  small whitelist (`PATH`, `HOME`, `TERM`, ...) that does not include
  `CLICKHOUSE_PASSWORD`. The package's postinst script runs as root but
  never sees the variable, so it silently creates the `default` user with
  an **empty password** instead of the documented one — confirmed via
  actual install log (`Password for the default user is an empty
  string.`) — which then makes §4.3's connection check fail with `Code:
  516 ... Authentication failed`. Replaced with
  `sudo env VAR=val ... apt-get install ...`, which passes the env vars
  straight into the child process without going through sudo's reset
  step. Added a callout explaining the root cause and a new
  "If the password is wrong after install" section right after §4.3 with
  a non-destructive fix (remove `/etc/clickhouse-server/users.d/default-password.xml`
  if present, set `password_sha256_hex` in `users.xml`, restart the
  service) for anyone who already hit this with the old instructions.

Verified: `mkdocs build --strict` — 0 warnings.

## [Unreleased] - fix/mkdocs-site-i18n-and-mermaid

Audited the actual **built/published** docs site (`mkdocs build --strict`,
not just the raw markdown source) since that's what users read on GitHub
Pages. Found issues invisible from reading the `.md` files directly.

### Added
- `docs/getting-started/configuration.vi.md` and
  `docs/operations/architecture.vi.md` — full Vietnamese translations.
  Previously these 2 pages had no `.vi.md` counterpart, so on the `/vi/`
  site the nav label was translated ("Cấu hình", "Kiến trúc") but the page
  body silently rendered in English — confirmed by inspecting the built
  HTML (`<title>Kiến trúc - realtime-packet-sniff</title>` over an
  `<h1>Architecture</h1>` body).

### Fixed
- **Mermaid diagram in `architecture.md`/`architecture.vi.md` never
  rendered as a diagram** — `mkdocs.yml`'s `pymdownx.superfences` had no
  `custom_fences` mapping for `mermaid`, which Material for MkDocs requires
  to turn a ` ```mermaid ` block into `<pre class="mermaid">` (and load its
  renderer). Confirmed via built output: without the fix the block stayed
  literal ` <pre><code>flowchart LR... ` text; with it, `class="mermaid"`
  appears and Material's bundled JS (`bundle.*.min.js`, confirmed contains
  mermaid support) picks it up. This affected the real GitHub Pages site,
  not just this repo checkout.
- **Internal AI-agent planning doc leaked onto the public docs site** —
  `docs/superpowers/plans/2026-07-12-dosguard-adaptive-backpressure.md` (a
  `superpowers:writing-plans` implementation plan, not user documentation)
  was outside the `nav:` but still built, deployed, and indexed in the
  site's search (confirmed present in `site/search/search_index.json`).
  Added `exclude_docs: superpowers/` to `mkdocs.yml` so it's excluded from
  the build entirely.
- **Broken cross-language anchor**: `architecture.md` links to
  `deployment.md#day-to-day-operations`; the heading in
  `deployment.vi.md` is translated to "Vận hành hàng ngày", which
  mkdocs' slugifier turns into `#van-hanh-hang-ngay` — so on the `/vi/`
  site that link resolved to the right page but didn't scroll to the
  section. Added an explicit `<span id="day-to-day-operations">` anchor
  right above the Vietnamese heading so both anchor names resolve.

Verified: `mkdocs build --strict` exits 0 with zero warnings (previously
logged 2 INFO-level issues — nav-excluded file present, cross-language
anchor mismatch — that `--strict` doesn't fail on but are real content
bugs); manually inspected the built HTML for both languages to confirm
the mermaid class, the Vietnamese page bodies, and the fixed anchor.

## [Unreleased] - fix/capture-table-mac-position-and-ipv6-overflow

### Fixed
- **Capture page packet table: MAC address line landed in the wrong spot /
  overlapped the next row.** `PacketTable.tsx`'s `@tanstack/react-virtual`
  virtualizer used a fixed `estimateSize: () => 34` for every row, but rows
  with a `src_mac`/`dst_mac` render 2 lines (IP:port, then MAC on its own
  line via `<br/>`) and are taller than 34px in the real DOM. Since
  virtualized rows are absolutely positioned from the *estimated* cumulative
  height, the next row's `translateY` didn't account for the extra line,
  so it started before the MAC line finished rendering — visually the MAC
  text (or the row below it) landed on top of the next packet's row. Fixed
  by wiring up `virtualizer.measureElement` (ref + `data-index`) on each row
  and dropping the fixed `height`, so react-virtual measures each row's
  real rendered height and positions subsequent rows correctly instead of
  guessing.
- **Long addresses (mainly IPv6) overflowed into the next column/box**
  instead of wrapping or truncating, in 3 places:
  - `PacketTable.tsx`'s Source/Destination cells are a fixed 190px grid
    column; an IPv6 address is one long unbreakable token with no spaces,
    so without `overflow-wrap` the browser doesn't wrap it and it bleeds
    into the Destination column. Added `overflowWrap: 'anywhere'`.
  - `.top-flow` (Dashboard "Top talkers" and Capture "Live conversations"
    cards) and `.alert-row .label`/`.flow` (AlertFeed) are `1fr` grid
    tracks with no `overflow`/`text-overflow`/`min-width: 0` — a long IPv6
    `src → dst` string forced the row wider than its card, pushing into or
    overlapping the fixed-width KB/packet-count/copy-button columns next to
    it. Added `min-width: 0` + `overflow: hidden` + `text-overflow: ellipsis`
    + `white-space: nowrap` so long flows truncate with `…` instead of
    spilling into neighboring cells.

Verified: `tsc && vite build` and `vitest run` (3/3) both pass; manually
reasoned through both a 39-char IPv6 literal and a MAC-bearing row to
confirm the fixed-width/fixed-height assumptions that caused the overlap
are gone.

## [Unreleased] - fix/deployment-docs-new-machine-audit

### Fixed
- **`deploy/systemd/kafka.service` would fail to start on any fresh machine
  where the login user isn't literally named `tu`.** The unit file ships
  `User=tu` as a placeholder meant to be patched to the real user during
  install (same pattern as `ec-consumer.service`), but
  `docs/operations/deployment.md`/`deployment.vi.md` Step 9.2's `sed` command
  only patched `ec-consumer.service`, never `kafka.service`. Since Step 10.1
  (`sudo systemctl start kafka`) is the very first service started, this
  broke the whole pipeline at the first command on any machine other than
  the original author's. Added `kafka.service` to the patch command in both
  language versions.
- `kafka.service` was also missing `ExecStop=/opt/kafka/bin/kafka-server-stop.sh`
  even though both docs' "unit file reference" already documented it as
  present — added it for a clean shutdown instead of relying on the default
  SIGTERM. The reference snippets in both docs were also out of sync with
  the real file (missing `User=tu` / `Environment=KAFKA_HEAP_OPTS=...`);
  updated to match.
- `docs/getting-started/installation.md`/`installation.vi.md` — the package
  version table (`clickhouse-driver`, `pandas`, `numpy`, `pyyaml`, `scapy`)
  had drifted from the pinned versions in `requirements-integration.txt`;
  updated to match, and added the now-bundled `pytest` dependency. Also
  bumped the stale `**Version:** v0.4.0` banner (CHANGELOG has since moved
  through v1.0.0, v1.1.0, and further unreleased work) and the "36 automated
  tests" count in the directory reference, now 52.
- `docs/operations/deployment.md` Step 11.2.1 listed `sniff-web/requirements-web.txt`'s
  packages incompletely (missing `python-multipart`, `websockets`, `httpx2`
  which are all in the actual file).

Found by auditing "set this project up on a brand-new machine from the docs
alone" end to end and diffing every doc claim (unit files, package tables,
test counts, version banners) against the actual tracked files.

## [Unreleased] - fix/ec-stale-docs-windows-cleanup-and-merge-order

### Fixed
- **`MODULE_PHANLOAI/tests/integration/test_wrapper_end_to_end.py`** — 5 of
  42 tests in the module failed with `No such file or directory` because
  the 7 per-family scripts (`dos_feature_filter.py`, `generic_feature_filter.py`,
  ...) they invoked had already been consolidated into a single
  `family_filter.py --class <Name>` (see its docstring), but the integration
  tests were never updated to match. Updated all invocations; 42/42 pass now.
- **Extraction-and-classification/README.md**, **MODULE_TRICHXUAT/README.md**,
  **MODULE_AUTO/README_AUTO.md** documented the same removed per-family
  scripts, plus a stale `Python\EaF\...` directory layout and Windows/WSL
  `py -3`/PowerShell command examples that don't match the actual repo
  layout (`Extraction-and-classification/` is the root) or runtime
  (native Linux). Rewrote the usage examples and directory diagram to match
  reality, and pointed the default output-dir example at
  `NB15_OUTPUT_DIR`/the real default instead of a hard-coded Windows path.
- **`check_output.sh`, `verify_output.sh`, `preview.sh`, `debug_zeek.sh`,
  `debug_merge.sh`** hard-coded one developer's personal
  `/mnt/c/.../Downloads/...` or `/mnt/d/...` WSL paths. They now take the
  target CSV/work-dir path as a required `$1` argument.
- **`config.py`, `argus_handler.py`, `zeek_handler.py`** — removed the
  `IS_WINDOWS`/`win_to_wsl_path()`/`wsl_run()` code path entirely. The
  pipeline only ever runs on native Linux (`sys.platform` never starts with
  `"win"` here), so that branch was dead code; call `subprocess.run()`
  directly instead. `install_tools.sh`'s "(WSL)" label was corrected too —
  it's plain `apt-get` on Ubuntu, no WSL-specific step involved.
- **`data_merger.py`** — Argus and Zeek flows sharing the same 5-tuple were
  paired up by *file order* (`groupby(MERGE_KEYS).cumcount()`) rather than by
  actual flow start time, so if the two tools ever emitted same-tuple flows
  in a different relative order, `service`/`state` from Zeek could get
  attached to the wrong Argus flow. `zeek_handler.py` now also extracts
  conn.log's `ts` field into a new `zeek_ts` column (internal only, dropped
  before the final CSV is written); `data_merger.py` sorts both sides by
  their start-time column (`stime` for Argus, `zeek_ts` for Zeek) before
  assigning the occurrence index, so the Nth flow of a repeated 5-tuple is
  matched by chronological order instead of incidental file order.

Verified end-to-end on a real capture: ran `extractor.py` +
`add_features.py` against an existing pcap under `/var/lib/sniff-web/sniff_data/`,
same row count (3,793) and same 40/50-column NB15 schema as before these
changes, with no `zeek_ts`/`_occ` columns leaking into the output CSV.

## [Unreleased] - feat/web-ui-overhaul-2026-07-14

Dashboard/Capture UI overhaul in one push. Full detail (rationale, gotchas,
"don't re-add this" notes) lives in `sniff-web/docs/WEB_GUI.md`; this entry
is the flat summary. All 0 new npm/pip dependencies throughout.

### Added
- **Dashboard**: donut charts (hand-rolled SVG, no chart library) for protocol
  breakdown and attack-family share; click-through navigation from ClickHouse
  count cards / service tiles to their detail pages (`/clickhouse?table=...`,
  `/services`); page-load stagger reveal; count-up number tweening.
- **Capture page**: MAC address (`src_mac`/`dst_mac`) shown under each
  IP:port in the live packet table (free — already parsed in the fast decode
  path); ring-buffer fill bar + drop-cause breakdown (`queue_dropped` vs
  `write_dropped`); capture uptime + active interface in the status line;
  live conversations panel (`GET /api/capture/conversations`, existed
  server-side but was never wired to any page); protocol breakdown mini;
  opt-in **deep decode (L7)** toggle (`GET/POST /api/capture/deep-decode`) for
  DNS/HTTP/TLS-SNI/DHCP/NTP/QUIC info in the Info column, off by default.
- **Theme**: "Obsidian" — off-black background, single slate-blue accent
  (`#4a7ba6`), white headline text/numbers (was the accent color before).

### Fixed
- **ClickHouse per-family cards showed identical numbers on every family**
  (`flows_dos`, `flows_exploits`, ... all read the same `count()` because all
  7 tables share the same underlying flow set) — looked like fake/uniform
  data. Now queries `WHERE is_attack = 1` per family, so cards and the
  attack-family donut show real classification differences. `flows_all`
  stays a true total. See `sniff-web/docs/WEB_GUI.md` for the full
  explanation and the schema doc in `docs/operations/architecture.md`.
- Traffic gauges (PPS/KB-s) pegging into the red-danger zone on minor
  fluctuation — max was derived only from the 10s-cadence summary snapshot
  while the displayed value came from a faster WS stream; now tracks a
  rolling peak from live WS values too, with 2x headroom instead of 1.2x.
- Capture page's packet-table card getting squeezed to near-zero height once
  more panels were added below it (root container forced
  `height: calc(100vh - 88px)` with `flex:1` fighting new siblings for space);
  fixed height (480px) instead, page scrolls normally.
- Gauge needle/arc, Sparkline draw-in: previously instant redraws, now
  transition smoothly via CSS (`stroke-dasharray`/`transform`) — no JS
  animation library involved.

### Removed
- **`/system` page** (hostname/uptime/CPU/mem/disk/NIC) end-to-end: route,
  sidebar entry, `TopBar` uptime/load/CPU line, `SystemInfo` type, and the
  `/api/system/info` backend endpoint — irrelevant to the IDS's actual job.
- An ambient scanline/vignette full-page overlay, added then removed same
  day after it read as visually cluttered.

## [Unreleased] - fix/capture-page-filter-autoscroll

### Fixed
- **Web UI: search filter and auto-scroll toggle on the Capture page now work.**
  `sniff-web/web/src/pages/Capture.tsx` was passing `PacketTableInner` a
  hard-coded `filter=""` / `autoScroll={true}` with no-op setters
  (`setFilter={() => {}}`, `setAutoScroll={() => {}}`), so typing in the packet
  search box or toggling auto-scroll had no visible effect. Replaced with real
  `useState` (`tableFilter`, `autoScroll`) wired to the component's props.

## [Unreleased] - feat/dosguard-adaptive-backpressure

### Added
- **DosGuard backpressure mode (NIC-agnostic self-protection).** The capture-side
  load valve now sheds based on real pipeline saturation — kernel/queue drops and
  ring-buffer fill from `CaptureEngine.get_status()` — via an AIMD controller,
  instead of relying only on an absolute `pps` threshold that mis-scales on
  10G/100G links. Effective sampling is `max(backpressure, pps)`; the pps path is
  retained for small/lab LANs. Config: `dos_backpressure`, `dos_queue_high_ratio`,
  `dos_queue_low_ratio`.
- **Per-destination surgical shedding.** While shedding is active, the guard
  identifies a concentrated flood victim (≥ `dos_victim_share` of packets and
  over `dos_victim_min_pps`) and sheds only that destination's traffic, keeping
  every other destination at full fidelity — so a flood aimed at one host no
  longer forces uniform sampling of legitimate traffic. Destination is parsed from
  the raw frame only while `dos_active` (zero added cost in normal operation).
  Config: `dos_victim_share`, `dos_victim_min_pps`, `dos_max_drop`.

### Changed
- `integration/run_producer.py` now imports `kafka` lazily (inside `_make_producer`)
  so the module's pure helpers are importable/testable without kafka-python.

### Notes
- `DosGuard.update()` and `should_keep()` remain backward compatible
  (`update(pps)` / `should_keep(seq)` still valid); new inputs are keyword-only /
  optional. No ClickHouse schema, sink, Kafka, or classifier changes.
- Full-packet capture on this Python/Scapy path is not intended for sustained
  10G/100G; see `docs/operations/architecture.md` (Adaptive DoS self-protection).

## [Unreleased] - fix/classification-accuracy-real-traffic

Xác thực bằng thực nghiệm tấn công thật (Kali `192.168.106.60` → Ubuntu VM
`192.168.101.135`, 11 họ: baseline/DoS×4/Exploits/Fuzzers/Generic/Analysis/
Reconnaissance/Shellcode) rồi đối chiếu `flows_all` với ground-truth pcap. Hệ
thu thập (Argus/Zeek) hoạt động đúng, nhưng **tầng phân loại sai gần như tuyệt
đối**: DoS 0/65.356 flow flood, tổng đúng-nhãn-họ 0,076%. Bản này sửa tận gốc.

### Fixed — phân loại đúng trên traffic thật
- **DoS bị bỏ lọt 100%.** Ngưỡng `signatures/dos.json` kế thừa UNSW-NB15
  (`sttl>=142.5`, `sload>=44.7M`, `rate>=112.841`) giả định traffic đã spoofed
  TTL / nhiều gói. Flood `hping3 --rand-source` thật bị Argus gộp thành flow
  **1 gói** (`rate=0`, `sload=0`, `sttl=64`) nên KHÔNG bao giờ chạm ngưỡng. Lõi
  `dos_classifier.py` (chấm điểm CỘNG DỒN theo `state/synack/dttl/dbytes`) bắt
  được flood 1-gói nhưng chỉ IN ra terminal, không ghi `predicted_class`.
  → Thêm **`MODULE_PHANLOAI/unified_classifier.py`**: dùng lõi cộng dồn + **cổng
  volumetric cấp segment** (đếm số flow flood-like tới cùng `dstip`) rồi ghi nhãn
  DoS thật vào ClickHouse. Kết quả trên dữ liệu thật: **DoS 0% → 100%**.
- **1 flow mang nhiều nhãn cùng lúc → đếm 7 lần.** 7 filter chạy độc lập, không
  argmax; 1 flow flood 1-gói trúng cả Fuzzers VÀ Reconnaissance. `flows_all` là
  Merge của 7 bảng nên flow đó xuất hiện tới 7 dòng. → unified_classifier **hợp
  nhất về đúng 1 nhãn/flow** theo ưu tiên (DoS > Exploits > Shellcode > Generic >
  Analysis > Reconnaissance > Fuzzers), rồi ghi 7 CSV per-family với nhãn tấn công
  chỉ ở đúng 1 bảng. Schema/sink/Grafana KHÔNG đổi.
- **False-positive khổng lồ trên traffic nền LAN thật** (86,8% flow benign bị gắn
  cờ). Chữ ký NB15 chỉ định nghĩa cho tcp/udp/icmp nhưng khớp cả frame L2
  (ARP/STP/ethertype số/ipv6-icmp), mDNS/SSDP multicast (sttl=255), DNS, và
  download HTTPS ra ngoài. → Thêm 3 cổng nguyên tắc: chỉ phân loại họ trên IP
  transport thật; loại hạ tầng LAN benign (multicast/broadcast/mDNS/SSDP/DHCP/
  NetBIOS/DNS/NTP); và mô hình đe doạ LAN (`dttl>=FAMILY_MIN_DTTL` hoặc one-way —
  tấn công nhắm host nội bộ ít hop). **FP benign 86,8% → 0,6%**, recall attack
  không đổi (DoS 100%, Exploits 76,7%).
- **`predicted_class = 'DoS'` toàn false-positive.** 2.808/2.808 flow từng gắn
  DoS đều là mDNS/STP benign, 0 liên quan tấn công. `dos_classifier.py` chỉ loại
  multicast theo `srcip`, bỏ sót đích multicast (SSDP `239.255.255.250`). → Vá
  loại đích multicast/broadcast khỏi DoS.
- **`dos_classifier.py` crash trên NumPy ≥ 2.0** (`np.char.startswith` trên mảng
  object dtype ném `UFuncNoLoopError`; box chạy numpy 2.2.6). → Thay bằng pandas
  `.str` (bất biến theo phiên bản NumPy).
- **Zeek làm hỏng cả segment khi không sinh `conn.log`** (segment chỉ có
  ARP/STP/gói dị dạng → `RuntimeError` → mất trắng segment; 2 segment bị mất ngay
  sau đợt tấn công trong dữ liệu thật). → Ghi `zeek_temp.csv` rỗng và tiếp tục với
  đặc trưng Argus (merge `how=outer`).
- **Cột họ trong `pipeline_runs` luôn bằng nhau, `total_flows` = 7×.**
  `insert_family` trả về tổng số dòng (mọi bảng đều chứa toàn bộ flow) nên
  dos/exploits/... đều = N và total = 7N — vô nghĩa. → Trả về **số detection thật**
  (`is_attack=1`) của từng họ; với mô hình 1-nhãn, `total_flows` = tổng flow tấn
  công thật trong segment.

### Added
- `MODULE_PHANLOAI/unified_classifier.py` — bộ phân loại hợp nhất 1-nhãn/flow +
  phát hiện DoS volumetric. Cấu hình qua env: `DOS_MIN_FLOWS_PER_DST` (40),
  `DOS_HIGH_RATE` (5000), `FAMILY_MIN_DTTL` (60), `DOS_SYN/UDP/ICMP_THRESHOLD`.
- `MODULE_PHANLOAI/tests/test_unified_classifier.py` — 9 test bám kịch bản traffic
  thật (flood 1-gói→DoS, mDNS/SSDP→Normal, HTTPS ngoài→Normal, exploit nội bộ→
  Exploits, L2→Normal, single-label, FP thấp).

## [Unreleased] - fix/ec-pipeline-real-data-bugs

### Fixed
- **Extract+Classify stage never produced real flow data — every segment
  either crashed or fell through to nothing**, discovered while deploying the
  full stack (Kafka + ClickHouse + Grafana + Argus + Zeek) end-to-end and
  driving it with live captured traffic. Six separate bugs, each blocking the
  next step in the chain:
  - **`Extraction-and-classification/MODULE_TRICHXUAT/extractor.py`** —
    `main()` called `setup_logging(verbose=...)` but the function was never
    defined in the module (`NameError`). Added a `setup_logging()` that wires
    `logging.basicConfig` to the module's existing `LOG_FORMAT`/`LOG_DATE_FMT`.
  - **`Extraction-and-classification/MODULE_TRICHXUAT/zeek_handler.py`** —
    the CSV-writing loop iterated an undefined `wanted_fields` name; the
    actual computed column list is `csv_columns` (`NameError`).
  - **`Extraction-and-classification/MODULE_TRICHXUAT/add_features.py`** —
    `parse_dtcpb` / `parse_service` are vectorized (`Series -> Series`)
    functions but were invoked via `.apply(...)`, which calls them per-scalar
    instead, raising `AttributeError: 'int' object has no attribute 'fillna'`.
    Call them directly on the column instead.
  - **`Extraction-and-classification/MODULE_AUTO/auto_pipeline.py`** — imported
    `family_filter` without first adding `MODULE_PHANLOAI` to `sys.path`
    (`ModuleNotFoundError`) in step 3/4 (the 7 per-family filters).
  - **`integration/ec_consumer.py`** (root cause of "no real data ever reaches
    ClickHouse") — `default_runner()` globbed all 7 families from
    `CSV/CSV_Full_feature/`, but `auto_pipeline.py` actually writes each
    family's filtered CSV into its own `CSV/Filter_<Family>_feature/`
    directory. The consumer never found real per-family output, so every
    segment was marked `status=failed` and ClickHouse never got real rows.
  - **`Extraction-and-classification/MODULE_PHANLOAI/dos_classifier.py`** —
    `np.char.startswith()` does not accept a tuple of prefixes the way
    Python's `str.startswith()` does; it broadcasts element-wise against the
    input array, so passing a 17-item multicast-prefix tuple raised
    `ValueError: operands could not be broadcast together` whenever a
    segment's row count wasn't exactly 17. This silently killed the DoS
    classification step (masked by a blanket except/warn), leaving
    `predicted_class` empty in ClickHouse. Fixed by OR-ing the per-prefix
    boolean masks in a loop instead.
- Also required, at the infra level (not a code bug but a deployment gotcha
  worth documenting): Kafka's default `message.max.bytes` (1 MiB) rejects
  pcap segment blobs larger than that even though the producer's
  `max_request_size` is already sized for `segment_max_bytes` — see the new
  Step 3.4 in [Installation](docs/getting-started/installation.md) and the
  Troubleshooting entry for `MessageSizeTooLargeError`.

Verified end-to-end on a live deployment: captured real traffic → Kafka →
Argus/Zeek → 7 family filters → DoS classifier → ClickHouse now shows real,
non-sample flow rows with populated `predicted_class` for every new segment.

## [Unreleased] - fix/flow-gia-va-mat-goi

### Fixed
- **Flow giả trong ClickHouse** — trước đây mọi flow là dữ liệu mẫu synthetic
  (`10.0.0.5→10.0.0.9`, `udp:53`, `src_mac=ff:ff:ff:ff:ff:ff`, feature toàn 0),
  hoàn toàn không phải traffic bắt được.
  - Bỏ 8 file mẫu `Extraction-and-classification/CSV/CSV_Full_feature/sample_*`
    (bị consumer tái dùng) + gitignore output runtime.
  - **`integration/ec_consumer.py`** — `default_runner._collect_outputs()` neo
    theo stem của segment (`name.startswith(base + "_")`), không còn nhặt file
    mẫu/segment khác qua fast-path.
  - **`integration/clickhouse_sink.py`** — guard `_is_placeholder_row()` loại dòng
    broadcast-src-MAC / feature=0; ép `predicted_class` rỗng → `Normal`; chặn nạp
    khi 0 dòng hợp lệ.
  - **Sửa guard loại nhầm CSV thưa (hồi quy CI):** phiên bản đầu coi `src_mac`
    RỖNG/THIẾU và cột volume vắng mặt là "giả", làm rớt mọi dòng của CSV chỉ có
    `srcip/dstip/sport` → 6 job Backend đỏ (`test_sink_handles_missing_columns`,
    `test_sink_batches_large_csv`). Guard nay chỉ loại khi `src_mac` HIỆN DIỆN và
    là broadcast/all-zero, hoặc toàn bộ cột volume ĐỀU CÓ và = 0; thiếu cột không
    còn bị coi là giả (giữ đúng hợp đồng "tolerate missing columns" của sink).
    Thêm test `test_sink_rejects_placeholder_fake_flows` khoá lại hành vi này.
- **Mất ~60% gói khi tải cao** (đo bằng thiết bị bắt song song, tập trung ở burst).
  - **`config.yaml.example`** — `buffer_profile: max`, `ring_buffer_size: 1048576`,
    `batch_size: 1024`, `gc_interval: 0`.
  - **`core/capture.py`** — `_update_drop_stats()` đọc đúng drop hàng đợi từ
    `RingBuffer.dropped` (drop-oldest trước đây đếm thiếu vì `put_nowait()` luôn True).

### Added
- **`core/native_writer.py`** — `DumpcapWriter`: ghi PCAP bằng chứng qua `dumpcap`
  (kernel buffer lớn) gần như không drop; phơi `drop_stats()` để giám sát.
- **`integration/run_producer.py`** — gắn `DumpcapWriter` (tùy chọn qua
  `capture.evidence_dumpcap`, hỏng thì bỏ qua, không chặn producer) + log
  `evidence_drop` trong cảnh báo DoS.
- Docs: khuyến nghị tinh chỉnh chống burst (`docs/getting-started/configuration.md`),
  bước xóa CSV mẫu + truy vấn nghiệm thu chống flow-giả (`docs/operations/deployment.md`).

## [v1.1.0] - 2026-07-06

### Added
- **DoS self-protection (load-shedding) layer** so a packet flood can no longer OOM the host. Previously the only DoS detection ran at the *end* of the pipeline (`dos_classifier`), so a flood exhausted RAM before it was ever flagged. Detection now happens at capture ingest:
  - **`integration/dos_guard.py` (new)** — `DosGuard` detects floods from the capture engine's `pps` and sheds load by keeping only 1/N packets. Hysteresis via `dos_trigger_pps` (default 50k) / `dos_clear_pps` (15k) / `dos_target_pps` (10k). `should_keep()` is a per-packet, lock-free decision.
  - **`integration/run_producer.py`** — wires `DosGuard` into the capture callback (`on_pkt` drops flood packets) and runs a 1 Hz monitor thread that logs `DoS SUSPECTED pps=… giu_1/N top_talkers=…`.
  - **`integration/kafka_segmenter.py`** — new hard cap `segment_max_packets` (default 100k); a segment now flushes on packet count too, not just bytes/time (a 64 MiB flood segment held ~880k tiny packets).
  - **`integration/ec_consumer.py`** — circuit breaker: segments above `EC_MAX_PKTS_PER_SEGMENT` (default 150k) are marked `dos_shed` and skip the heavy Argus/Zeek/pandas extraction; `main()` now commits `dos_shed` so oversized segments are not reprocessed forever.
  - **`integration/config.py`** — defaults for `kafka.segment_max_packets` and `capture.dos_trigger_pps` / `dos_clear_pps` / `dos_target_pps`.

### Fixed
- **`core/capture.py` could not be imported** — it imported `BoundedRingBuffer` from `core/buffer.py`, which never defined that class, raising `ImportError` on every load of the capture engine. Added `BoundedRingBuffer` (a bounded, drop-newest back-pressure ring buffer).

## [v1.0.0] - 2026-07-05

### Added
- **New repository `ntu168108/realtime-packet-sniff-v2`**: a polished, "clean" version hosted on GitHub Pages with bilingual docs (English + Vietnamese via `mkdocs-static-i18n`).
- **MkDocs site** (`mkdocs.yml`, `docs/`): English + Vietnamese documentation covering Quickstart, Installation, Configuration, Deployment, Architecture, and Troubleshooting.
- **CI matrix** (`.github/workflows/web-gui.yml`): Python 3.10 / 3.11 / 3.12 × Ubuntu 22.04 / 24.04 for backend tests; Node 20 / 22 for frontend build.
- **Docs CI** (`.github/workflows/docs.yml`): builds mkdocs with `--strict` and deploys to GitHub Pages on push to `main`.
- **Release workflow** (`.github/workflows/release.yml`): tag-driven GitHub Release with auto-generated notes.
- **Best-practices files**: PR template, bug/feature issue templates, `CODEOWNERS`, weekly `dependabot.yml` (pip + GitHub Actions), `SECURITY.md`, `CONTRIBUTING.md`.
- **Dependabot** groups all Python deps into a single weekly PR.
### Changed
- Repository restructured: `README_VI.md`, `DEPLOYMENT.md`, `HUONG_DAN_TRIEN_KHAI.md` are removed; their content is migrated into `docs/` (English) and `docs/*.vi.md` (Vietnamese).
- Root `README.md` slimmed to ~50 lines pointing to the docs site.
- All source file paths in docs use v2 repo URL (`github.com/ntu168108/realtime-packet-sniff-v2`).

## [v0.4.0] - 2026-06-29

### Added
- **Web `/capture` syncs `sniff-producer`**: clicking Start on the Capture page now also rewrites `capture.interface` in `config.yaml` and triggers `sudo systemctl restart sniff-producer`, so the web UI and the Kafka/ClickHouse classification pipeline always point at the same NIC. The sudoers allowlist installed by `install_web.sh` covers this; if the allowlist is missing the API response surfaces the error.
- **`/credentials` auto-detects IP per interface**: the host field used to surface URLs for Grafana, ClickHouse, Kafka, and the sniff-web UI itself is now the IPv4 address of the currently-captured interface (via `psutil.net_if_addrs()`), with the previous behavior as fallback.
### Changed
- `POST /api/capture/start` response now includes a `sniff_producer` block with `config_updated`, `config_msg`, `restarted`, `restart_msg` so the UI can surface sync failures.

## [v0.3.0] - earlier
- Initial public release (DEPLOYMENT.md baseline).
