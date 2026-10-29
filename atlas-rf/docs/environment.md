> Current hardening update: the earlier whole-root Bubblewrap test below is historical. The required offline profile now fails at NETLINK_ROUTE setup despite successful user/required namespace probes. See [security.md](security.md); execution fails closed.

# ATLAS RF environment compatibility report

Inspected: **2026-10-29, approximately 16:48–16:50 UTC**. These are observations from the actual command execution environment, not the requested target specification. No root escalation, package installation, Android settings changes, hardware emulation, radio scanning or packet capture was performed. A minimal Bubblewrap process was launched to check executable operation; no persistent configuration was changed.

## Status meanings

- **SUPPORTED**: directly observed or exercised in this execution context, within the stated scope.
- **UNSUPPORTED**: unavailable or explicitly denied in this execution context. This does not establish permanent absence on the Android host or in an unrestricted terminal.
- **UNVERIFIED**: evidence is insufficient, or end-to-end operation was not exercised. Installed tools alone do not prove usable functionality.

## Compatibility summary

| Area | Status | Evidence and practical effect |
| --- | --- | --- |
| Debian ARM64 execution | SUPPORTED | Debian 13.7 (trixie), `aarch64`; Python runs locally |
| Memory and private storage | SUPPORTED | 5.9 GiB RAM; about 4.9 GiB available at inspection; about 86 GiB available on guest root filesystem |
| Actual Pixel model / Tensor G5 identity | UNVERIFIED | Guest CPU descriptions are available, but do not independently identify the phone model or marketed SoC |
| Guest interface inventory through sysfs | SUPPORTED | Virtio `enp0s14` is up; remaining entries listed below |
| Current-process netlink inspection | UNSUPPORTED | `ip` and `ss` report `Operation not permitted` |
| Live guest route/neighbor collector here | UNSUPPORTED | Existing `collect network` requires `ip -j` netlink access |
| Reachability from an ordinary interactive Debian session | UNVERIFIED | Current process is restricted; sysfs and `/proc/net` views differ |
| Physical Wi-Fi / nl80211 PHY access here | UNSUPPORTED | `/sys/class/ieee80211` absent, no interface wireless/phy80211 entry, no `/proc/net/wireless` devices |
| Bluetooth HCI access here | UNSUPPORTED | `/sys/class/bluetooth` absent; no visible HCI controller |
| Monitor mode / raw capture of Android radios | UNSUPPORTED | No radio PHY/HCI exposure; no effective Linux capabilities |
| Shared Android directory visibility | SUPPORTED | `/mnt/shared` is an Android virtiofs mount; standard public directory names readable |
| Guest writes to Android share here | UNSUPPORTED | Effective virtiofs mount is `ro`; `test -w` fails |
| Android app export → guest import | UNVERIFIED | Appropriate architecture, but no companion APK or real export has been tested |
| Python / Rust / Node execution | SUPPORTED | Version commands succeed; exact versions below |
| npm command in current PATH | UNSUPPORTED | `npm: command not found`; Node itself exists |
| Basic Bubblewrap invocation | SUPPORTED | `bwrap --ro-bind / / -- /bin/true` returns 0 |
| Full intended plugin sandbox policy | UNVERIFIED | No plugin policy, full namespace matrix or containment audit was exercised |
| Existing offline ATLAS pipeline | SUPPORTED | Prior validation: imports, SQLite, reports and dashboard; see `VALIDATION.md` |

## 1. CPU architecture and kernel

Commands: `uname -a`, `uname -m`, `lscpu`, `cat /etc/os-release`.

```text
Linux debian 6.12.93-android16-6-g3a7d1771d492-ab16496487-4k
#1 SMP PREEMPT Fri Oct 2 02:49:14 UTC 2026 aarch64 GNU/Linux
Debian GNU/Linux 13 (trixie), DEBIAN_VERSION_FULL=13.7
Architecture: aarch64, little-endian, 64-bit
Online CPUs: 0-7 (8 total)
Reported core models: Cortex-A520 (2), Cortex-X4 (1), Cortex-A725 (5)
```

**SUPPORTED:** ARM64 userland and kernel execution. ARM SIMD and crypto flags are reported by `lscpu`. **UNVERIFIED:** mapping those virtualized/reported CPU identities to a particular phone SKU, sustained CPU performance, battery cost and thermal throttling. Kernel naming alone is not a verified Android host build/API-level inventory.

## 2. RAM and storage

Commands: `cat /proc/meminfo`, `free -h`, `df -hT / /home/droid /tmp`, `df -B1 / /tmp`, `lsblk -o NAME,TYPE,SIZE,FSTYPE,MOUNTPOINTS`.

| Resource | Observed snapshot |
| --- | --- |
| Total RAM | 6,186,084 KiB (about 5.90 GiB) |
| Available RAM | 5,119,540 KiB in initial sample (about 4.88 GiB); fluctuates |
| Swap | 1,546,492 KiB (about 1.47 GiB), unused; zram0 |
| Root filesystem | ext4, 229,284,573,184 bytes total (about 213.54 GiB) |
| Root available | 92,430,626,816 bytes (about 86.08 GiB) in byte-level sample |
| `/tmp` | tmpfs, about 2.95 GiB; consumes memory, not durable storage |
| Block inventory | vda about 217 GiB with root partition; vdb about 11.1 MiB cloud-init ISO; vdc about 217 GiB mounted `/mnt/backup` |

**SUPPORTED:** resource headroom for the existing bounded Python/SQLite pipeline. `df` available space is the operative storage figure; do not infer usable capacity from total minus used. Device and filesystem sizes need not match. Backup contents were not inspected and availability is not a guarantee of writable capacity. Cgroup `memory.max`, `memory.current` and `cpu.max` were not visible at the probed paths: **UNVERIFIED** process-specific resource ceiling. Do not allocate all visible RAM or use tmpfs as historical storage.

## 3. Network interfaces and execution visibility

Commands: `ip -j address show`, `ip -j route show`, `ss -lntu`, `ls -la /sys/class/net`, reads of each interface's `type`, `operstate`, `mtu`, `cat /proc/net/dev`, `cat /proc/net/route`, `cat /proc/net/if_inet6`, `readlink /proc/self/ns/net /proc/1/ns/net`.

| Sysfs interface | State | MTU | Interpretation |
| --- | --- | --- | --- |
| `enp0s14` | up | 1500 | Path contains `virtio13/net/enp0s14`; virtual Ethernet, not a Wi-Fi adapter |
| `lo` | unknown | 65536 | Loopback |
| `dummy0`, `ifb0`, `ifb1` | down | 1500 | Virtual interfaces |
| `gretap0`, `erspan0` | down | 1462, 1450 | Virtual tunnel interfaces |
| `gre0`, `tunl0` | down | 1476, 1480 | Virtual tunnel interfaces |
| `ip_vti0`, `ip6_vti0` | down | 1480, 1364 | Virtual tunnel interfaces |
| `ip6gre0`, `ip6tnl0`, `sit0` | down | 1448, 1452, 1480 | Virtual tunnel interfaces |

`ip` cannot open a netlink socket. `ss` also emits netlink denial; its empty table is **not** proof of no sockets. `/proc/net/dev` lists loopback and tunnel entries but omits sysfs's `enp0s14`; `/proc/net/route` has a header and no IPv4 routes. `/proc/net/if_inet6` shows loopback only. Current process and visible PID 1 both show `net:[4026533047]`; that does not identify an outer VM/Android host namespace.

This is consistent with an isolated command execution network view alongside a broader mounted sysfs view. **UNVERIFIED:** the exact outer namespace configuration, guest IP/gateway, Android LAN routing, DNS operation and internet reachability. Do not report the sysfs interface as usable from this process. `/etc/resolv.conf` names `127.0.0.53`; configuration is not a successful DNS test. Prior real-socket test failed at socket creation with `EPERM`; this inspection did not send network probes.

## 4. Wireless PHY devices

Commands: `ls -la /sys/class/ieee80211`, inspection of `/sys/class/net/*/wireless` and `*/phy80211`, `cat /proc/net/wireless`, `ls -la /dev/rfkill /dev/bus/usb`, USB sysfs listing.

- `/sys/class/ieee80211`: does not exist.
- No `wireless` or `phy80211` entries under the visible network interfaces.
- `/proc/net/wireless`: headers only.
- `/dev/rfkill` and `/dev/bus/usb`: absent in this execution view.
- USB sysfs shows root hubs (`usb1`, `usb2` and their interfaces), not a visible wireless dongle.

**UNSUPPORTED:** direct Wi-Fi scanning, monitor mode or RF capture here. **UNVERIFIED:** Android host radio inventory, physical dongle attachment outside this view and future guest USB forwarding. Missing userspace tools are an additional issue; installing them would not supply a PHY.

## 5. Bluetooth HCI controllers

Command: `ls -la /sys/class/bluetooth`; tool inventory below.

The Bluetooth class path does not exist, so no `hci*` controller is exposed. BlueZ tools are absent. **UNSUPPORTED:** direct Linux BLE discovery in this execution context. **UNVERIFIED:** Android host Bluetooth state and Android app permission availability. No simulated scan results were generated.

## 6. Linux capabilities and security boundary

Commands: `id`, `cat /proc/self/status`, checks for `capsh` and `getpcaps`, `cat /proc/sys/kernel/unprivileged_userns_clone`.

```text
uid=1000(droid) gid=100(users)
CapInh: 0000000000000000
CapPrm: 0000000000000000
CapEff: 0000000000000000
CapBnd: 0000000000000000
CapAmb: 0000000000000000
NoNewPrivs: 1
Seccomp: 2
Seccomp_filters: 1
Cpus_allowed_list: 0-7
```

**SUPPORTED:** reading numeric capability masks without extra packages. **UNSUPPORTED:** effective `CAP_NET_ADMIN`, `CAP_NET_RAW`, `CAP_SYS_ADMIN` and every other Linux capability in this process. `capsh`, `getpcaps`, `getcap` are not in PATH. The unprivileged-userns sysctl probed above is absent; that alone does not establish whether all namespace creation is forbidden. Basic Bubblewrap execution succeeds, but does not restore hardware or networking access.

The user is not root. Even root in Debian would not imply Android system privileges, permission to invoke host radio APIs, or hardware passthrough. No sudo/root attempt, capability grant, seccomp change, SELinux change, rfkill toggle, adb command or Android security setting change was made. The exact source of each syscall denial is **UNVERIFIED**; an active seccomp filter is observed, not fully decoded.

## 7. Shared Android storage

Commands: `findmnt -rn -T /mnt/shared -o TARGET,SOURCE,FSTYPE,OPTIONS`, `stat -f /mnt/shared`, `df -hT /mnt/shared`, `ls -ld` and `test -r` / `test -w` on candidate paths.

```text
/mnt/shared systemd-1 autofs rw,...
/mnt/shared android virtiofs ro,nosuid,nodev,relatime
android virtiofs: about 229 GiB total, 141 GiB used, 88 GiB available
/mnt/shared: readable, write-access-check=no
/mnt/shared/Documents: readable, write-access-check=no
/mnt/shared/Download: readable, write-access-check=no
/sdcard: absent
/storage/emulated/0: absent
```

The effective virtiofs mount is **read-only**, even though its covering automount entry says `rw` and directory mode bits look writable. Public Android directory names are visible; private contents were not read. `/mnt/shared/Android` has no usable permission bits in this view.

**SUPPORTED:** directory visibility and metadata reading. **UNSUPPORTED:** guest writes through this mount here. **UNVERIFIED:** app-export propagation and reading a real ATLAS export file. No write test or remount was attempted. Store SQLite and reports under private guest storage; a proposed companion can write on the Android side and the guest can attempt a read-only import. The companion must select an actual local document provider/location visible through this share, not assume any SAF URI maps to it.

## 8. Runtime and Bubblewrap versions

| Command | Observed result | Status |
| --- | --- | --- |
| `python3 --version` | Python 3.13.5 | SUPPORTED |
| `rustc --version` | rustc 1.85.1 (4eb161250 2025-03-15), built from source tarball | SUPPORTED version invocation; compiling a project UNVERIFIED |
| `cargo --version` | cargo 1.85.1 (d73d2caf9 2024-12-31) | SUPPORTED version invocation; dependency downloads UNVERIFIED |
| `node --version` | v20.19.2 | SUPPORTED |
| `npm --version` | command not found | UNSUPPORTED in current PATH |
| `bwrap --version` | bubblewrap 0.12.0 | SUPPORTED |
| `bwrap --ro-bind / / -- /bin/true` | exit 0 | SUPPORTED basic invocation only |
| `bash --version` | GNU bash 5.2.37, aarch64-unknown-linux-gnu | SUPPORTED |

No requirement to use Rust or Node is introduced; the current core remains standard-library Python. The minimal Bubblewrap test is not a recommended isolation policy: binding the whole filesystem is only an execution check.

## 9. Networking utilities

Inventory method: `command -v` for every name below. Presence means installed/in PATH, not successful network operation.

**Present:** `ip`, `ss`, `networkctl`, `ping`, `ping6`, `traceroute`, `host`, `resolvectl`, `curl`, `wget`, `openssl`, `nc`, `socat`, `tcpdump`, `lspci`, `unshare`, `bwrap`, `timeout` (all resolve under `/usr/bin`).

**Absent in PATH:** `iw`, `iwconfig`, `rfkill`, `bluetoothctl`, `btmgmt`, `hciconfig`, `nmcli`, `ifconfig`, `route`, `arp`, `tracepath`, `dig`, `nslookup`, `ncat`, `nmap`, `tshark`, `ethtool`, `lsusb`, `capsh`, `getcap`, `getpcaps`.

Versions exercised:

```text
ip / ss: iproute2-6.15.0 (ip reports libbpf 1.5.0)
curl: 8.14.1, aarch64-unknown-linux-gnu
OpenSSL: 3.5.7, 9 Jun 2026
ping: iputils 20240905
```

**UNSUPPORTED here:** current `ip`/`ss` netlink operations; raw packet capture has no demonstrated privilege or radio. `tcpdump` presence is not permission to capture. **UNVERIFIED:** functional operation of other networking utilities; no DNS, ping, TCP, traceroute or capture operation was initiated during this inspection.

## Resulting implementation direction

Use the existing local analysis/import/reporting path. Do not attempt to unlock phone radios from Debian. Because no physical guest Wi-Fi/Bluetooth adapter is exposed, the next collection boundary is the **proposed Android API bridge** specified in [android-bridge.md](android-bridge.md). Its initial transport is one-way Android file export → shared read-only guest file → existing bounded JSONL importer. An APK, real permission grants, successful scans and end-to-end file transfer remain **UNVERIFIED**; this report does not represent them as implemented.
