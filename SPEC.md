# Đặc tả hệ thống: `cf-edge` (OpenWrt Event-Driven Cloudflare DDNS, PPPoE Guard & Edge DDoS Shield)

## 1. Mục tiêu & Ràng buộc kỹ thuật (Constraints)
- **Ngôn ngữ:** Pure Go (`CGO_ENABLED=0`), biên dịch thành **1 file static binary duy nhất (`cf-edge`)**, không phụ thuộc `curl`, `jq`, `awk`, `nslookup`, `uhttpd`.
- **Nền tảng mục tiêu:** OpenWrt / ImmortalWrt `linux/arm64` (Filogic 820, Amlogic X96 Air) và `linux/amd64` (Mini PC N100). Tối ưu RAM thấp (chạy tốt với `GOMEMLIMIT=32MiB`).
- **Quản trị sạch (Modularity):**
  - Tách cấu trúc rõ ràng: `cmd/cf-edge/`, `internal/{config,ipwatch,cloudflare,reconcile,pppoeguard,ddos,notify,state}`.
  - Mỗi file `.go` tập trung 1 trách nhiệm, khuyến nghị <= 250 dòng.
  - Bắt buộc có Unit Test (`go test ./...`) cho các module lõi (IP filtering, Cloudflare API mock, DNS reconcile logic, DDoS detector state machine).
- **Single Binary CLI:**
  - `cf-edge daemon -c /etc/cf-edge/config.yaml` (chạy dưới `procd`)
  - `cf-edge update [--force]` (ép cập nhật DDNS ngay)
  - `cf-edge status` (xem IP hiện tại, trạng thái shield, trạng thái PPPoE)
  - `cf-edge shield enter|exit|status` (điều khiển chế độ ẩn mình thủ công)
  - `cf-edge self-update` (tải binary mới nhất từ GitHub Releases và thay thế nguyên tử)
- **Tách biệt Config & State:** File cấu hình `/etc/cf-edge/config.yaml` là **chỉ đọc (read-only)**; toàn bộ cache động (`record_id`, `last_ip_v4`, `last_ip_v6`) lưu trong RAM và ghi ra `/tmp/cf-edge-state.json`. Chỉ riêng file khóa chống DDoS lưu trên flash tại `/etc/cf-edge/shield.lock` để sống sót qua reboot.

---

## 2. Cấu trúc cấu hình đầu vào (`/etc/cf-edge/config.yaml`)
Mỗi router chỉ lưu cấu hình và API Token phạm vi hẹp của riêng nó (Zero-Trust giữa các node):

```yaml
node_name: "x96air" # Mặc định lấy os.Hostname() nếu bỏ trống

wan:
  iface_v4: "wan"
  iface_v6: "wan6"       # Bỏ trống nếu node không dùng IPv6
  overlay_iface: "wt0"   # Interface NetBird/WireGuard (dùng cho DDoS detector)

cloudflare:
  zone_id: "..."
  api_token: "..."       # Chỉ cấp quyền Zone:DNS:Edit
  records:
    - subdomain: "wg-x96air.diepkhoa.io.vn"
      ipv4: true
      ipv6: true
      proxied: false     # Nếu true thì bỏ qua đối soát DNS định kỳ

reconcile:
  enabled: true
  interval: "10m"
  resolvers: ["1.1.1.1:53", "8.8.8.8:53", "1.0.0.1:53"]

# Tùy chọn: Chỉ bật trên router VNPT hay bị netifd khóa AUTH_FAILED
pppoe_guard:
  enabled: false
  boot_grace: "90s"
  initial_wait: "45s"
  ping_targets: ["1.1.1.1", "8.8.8.8", "203.162.4.190"]

# Tùy chọn: Chỉ bật trên Edge Router (vd X96 Air) phối hợp với Cloudflare Worker
ddos_shield:
  enabled: false
  worker_url: "https://maintenance.diepkhoa.io.vn"
  worker_token: "..."
  wan_ingress_port: 443
  check_interval: "5s"
  sustain_duration: "25s"        # Phải vượt ngưỡng liên tục 25s mới kích hoạt
  conntrack_threshold: 5000      # Ngưỡng kết nối nf_conntrack
  junk_mbps_threshold: 300       # Ngưỡng (RX_WAN - TX_OVERLAY) Mbps
  rx_pps_threshold: 45000        # Ngưỡng bão gói tin RX PPS trên WAN
  max_redials_per_hour: 3        # Giới hạn chống spam BRAS ISP
  status_poll_interval: "2m"     # Chu kỳ hỏi Worker /edge/status CHỈ KHI đang trong shield

telegram:
  enabled: true
  bot_token: "..."
  chat_id: "..."


## 3. Đặc tả các Module chức năng

### 3.1. Module Thu thập IP WAN (`internal/ipwatch`)
- Chỉ thu thập IP WAN của chính router (KHÔNG có `TARGET_MAC`).
- Chỉ chạy luồng IPv6 nếu có ít nhất 1 record bật `ipv6: true` (tránh chờ 30s vô ích trên node chỉ dùng IPv4).
- Thu thập song song IPv4 & IPv6, tối đa **6 lần thử**, cách nhau **5 giây** (hỗ trợ hủy ngay bằng `context.Context` khi có sự kiện mới đến).
- **IPv4 Discovery:**
  1. Lấy IPv4 từ `ubus call network.interface.<iface_v4> status` (fallback: IPv4 của device giữ default route, loại trừ `wg*`, `wt*`, `warp*`, `tun*`).
  2. Kiểm tra dải Private/CGNAT (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10`). Nếu thuộc dải này -> probe IP public qua IPv4 (timeout 3s): ưu tiên `https://1.1.1.1/cdn-cgi/trace` (parse `ip=`), dự phòng `https://api.ipify.org`.
  3. Nếu đang sau NAT mà không probe được IP public -> trả về rỗng để retry (tuyệt đối không đẩy Private IP lên Cloudflare).
- **IPv6 Discovery:**
  1. Đọc địa chỉ trên L3 WAN device (lấy từ `ubus` của `iface_v6` -> `iface_v4`) qua Linux Netlink / `ip -6 addr`:
     - Chỉ chấp nhận **Global Unicast (`2000::/3`)** (loại bỏ `fe80::/10` link-local và `fc00::/7` ULA).
     - **Loại bỏ địa chỉ có cờ `deprecated`** (`IFA_F_DEPRECATED` / preferred_lft == 0).
  2. Fallback cuối: gọi `https://api64.ipify.org` (timeout 3s) bind vào WAN device, chỉ chấp nhận địa chỉ trong dải `2000::/3`.
- **Event Listener:**
  - Chạy `ubus listen network.interface` (tự khởi động lại stream nếu đứt kết nối).
  - Bắt sự kiện `ifup` / `ifupdate` khớp `iface_v4` hoặc `iface_v6`.
  - Khi nhận sự kiện: hủy lượt update cũ đang dở (nếu có) bằng `context.CancelFunc` (preemption sạch, không rò goroutine) và kích hoạt cập nhật mới. **Bỏ qua hoàn toàn nếu đang ở trạng thái DDoS Shield (`/etc/cf-edge/shield.lock` tồn tại).**

### 3.2. Module Cập nhật Cloudflare DDNS (`internal/cloudflare`)
- Dùng `sync.Mutex` tuần tự hóa mọi thao tác ghi DNS để chống race condition.
- Cooldown 10s cho trigger thường; `--force` bỏ qua cooldown và kiểm tra lại với Cloudflare API.
- Quy trình với từng record và loại (`A` / `AAAA`):
  1. Nếu chưa có `record_id` trong state hoặc đang chạy `--force`: gọi `GET /zones/{zone_id}/dns_records?type={A|AAAA}&name={subdomain}` (retry 3 lần, nghỉ 5s):
     - Giữ bản ghi đầu tiên khớp `content == target_ip` làm `record_id`.
     - Gọi `DELETE` dọn sạch mọi bản ghi trùng lặp hoặc sai IP (stale).
     - Nếu đã khớp đúng `target_ip` -> cập nhật state và kết thúc (không gọi PUT thừa).
  2. Tạo mới (`POST`) hoặc cập nhật (`PUT`) với `ttl: 60`, `proxied: <config>`.
     - Retry tối đa 3 lần (nghỉ 5s) khi lỗi mạng/5xx.
     - Nếu API trả về lỗi ID không tồn tại (`not found` / `not a valid` / `does not exist`) -> xóa `record_id` trong state và tự chuyển sang `POST`.
  3. Khi thành công: lưu state, gửi thông báo Telegram (kiểm tra rõ HTTP `200` và JSON `"ok": true`).
- Global Retry: nếu kết thúc lượt vẫn còn record lỗi, nghỉ 15s và thử lại tối đa 3 lượt (tôn trọng `context` hủy).

### 3.3. Module Đối soát DNS định kỳ (`internal/reconcile`)
- Chờ 15s sau khi daemon khởi động, sau đó lặp theo `reconcile.interval` (mặc định `10m`).
- Bỏ qua toàn bộ nếu `shield.lock` đang tồn tại, và bỏ qua các record có `proxied: true`.
- Truy vấn DNS trực tiếp bằng pure Go UDP/TCP DNS resolver tới lần lượt `1.1.1.1:53`, `8.8.8.8:53`, `1.0.0.1:53` (vượt qua cache nội bộ router):
  - Nếu cả 3 server đều timeout/lỗi mạng -> phân loại `NET_ERROR` -> **bỏ qua**, không hành động.
  - Nếu kết quả là `NXDOMAIN`, `NODATA`, IP trả về thuộc dải Cloudflare Proxy (lấy động từ `https://api.cloudflare.com/client/v4/ips` và cache 24h, có fallback tĩnh), hoặc khác với IP hiện tại trong state -> kích hoạt `--force` update cho đúng subdomain đó.

### 3.4. Module PPPoE Guard (Tùy chọn, `internal/pppoeguard`)
- Chia sẻ chung luồng sự kiện `ubus listen network.interface` từ `ipwatch` (0% CPU khi WAN ổn định).
- Khi boot: chờ đủ `boot_grace` (90s). Nếu WAN chưa `up`, hoặc khi nhận sự kiện `ifdown` / `ifup-failed` trên `iface_v4`:
  1. Đợi `initial_wait` (45s) cho `pppd` tự xử lý trước.
  2. Kiểm tra trạng thái qua `ubus call network.interface.<iface_v4> status`: phải có `up == true`, có địa chỉ IPv4, và ping thông ít nhất 1 mốc trong `ping_targets` qua đúng `l3_device`.
  3. Nếu chưa khỏe:
     - Khi `pending == false` (dính `proto_block_restart` / `AUTH_FAILED`): gọi `ubus call ... down` -> nghỉ 10s -> `ubus call ... up`.
     - Khi treo `pending == true` quá 3 chu kỳ: ép `down` -> nghỉ 15s -> `up`.
  4. Giãn cách lặp: 60s cho 5 lần đầu, 120s cho các lần tiếp theo cho đến khi WAN khỏe lại hoàn toàn rồi đi ngủ.

### 3.5. Module Edge Anti-DDoS Shield (`internal/ddos`)
- Chỉ chạy khi `ddos_shield.enabled: true`.
- **Phát hiện đa tín hiệu (chu kỳ 5s, gần như 0% CPU):**
  - Đọc `/proc/sys/net/netfilter/nf_conntrack_count`, `/sys/class/net/<wan_l3>/statistics/{rx_bytes,rx_packets}` và `/sys/class/net/<overlay_iface>/statistics/tx_bytes`.
  - Kích hoạt khi vượt ngưỡng liên tục trong `sustain_duration` (25s):
    - `conntrack > conntrack_threshold`, HOẶC
    - `(RX_WAN_Mbps - TX_OVERLAY_Mbps) > junk_mbps_threshold` kèm mất gói ra ngoài (`ping` fail) hoặc `RX_PPS > rx_pps_threshold`.
  - Đảm bảo không báo giả lúc mất mạng ISP (mất mạng ISP có `RX_WAN ≈ 0`).
- **Quy trình `enter_shield` (bảo vệ bởi Mutex + giới hạn `max_redials_per_hour`):**
  1. Ghi file khóa bền `/etc/cf-edge/shield.lock` (chặn tuyệt đối mọi luồng DDNS đẩy IP lên Cloudflare).
  2. Chặn cổng `wan_ingress_port` (443) chiều vào từ WAN bằng `nft` (vẫn giữ NetBird/overlay sống 100%).
  3. Ngắt và quay lại cả `iface_v4` và `iface_v6` (nghỉ 20s cho BRAS xả phiên), chờ có mạng lại tối đa **120s** (có timeout, không lặp vô hạn).
  4. Gửi `POST <worker_url>/edge/ddos` (header `Authorization: Bearer <worker_token>`, JSON `{"new_ip":"...","reason":"..."}`, retry tối đa 5 lần) và bắn thông báo Telegram.
- **Vòng chờ phục hồi (chỉ chạy khi tồn tại `/etc/cf-edge/shield.lock`):**
  - Khi daemon khởi động lại sau mất điện, nếu thấy `/etc/cf-edge/shield.lock` -> tự động áp lại rule chặn port 443 WAN và tiếp tục vòng chờ.
  - Cứ mỗi `status_poll_interval` (2 phút), gọi `GET <worker_url>/edge/status` (có Bearer token).
  - Khi Worker trả về `{"action": "resume"}` (hoặc người dùng chạy `cf-edge shield exit`):
    1. Gỡ rule chặn port 443 WAN.
    2. Xóa `/etc/cf-edge/shield.lock`.
    3. Gọi ngay `update --force` để đẩy chuẩn cả IPv4 + IPv6 mới lên Cloudflare DNS.

---

## 4. Yêu cầu Build & Triển khai OpenWrt
- Có file `.github/workflows/release.yml` tự động chạy `go test ./...` và build binary cho `linux/arm64`, `linux/amd64` kèm SHA256 checksum khi tạo git tag.
- Có sẵn 1 file `openwrt/cf-edge.init` chuẩn `procd` (bật `respawn`, đặt `GOMEMLIMIT=32MiB`) và `openwrt/install.sh` tự tải đúng kiến trúc từ GitHub Releases.
```

---