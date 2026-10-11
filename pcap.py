"""
Reader for packet captures (pcap and pcapng).

A capture file on a server is itself evidence of eavesdropping: it tells you when a sniffer ran
(the packet timestamps), what it grabbed, and sometimes plaintext credentials the attacker was
after. This reader turns each packet into one readable, timestamped line so the normal viewer,
search and timeline work on it, and it raises findings for:

  * the capture itself, with its real time window and how much it caught;
  * plaintext credentials inside the traffic (HTTP Basic, FTP/POP/IMAP/SMTP logins, and obvious
    user=/password= form fields);
  * ARP anomalies that mean a man-in-the-middle: one IP claimed by several MACs, or one MAC
    claiming many IPs (the fingerprint of arpspoof / ettercap).

Only headers and the first bytes of each payload are read; it never needs the whole file in memory.
"""
import ipaddress
import re
import struct
from collections import Counter, defaultdict

import analyzers as az
import artifacts as art

SNAP_KEEP = 600           # bytes of each packet we look at
MAX_PACKETS = 400000      # stop after this many (very large captures)

LINKTYPES = {0: "loopback", 1: "ethernet", 101: "raw-ip", 113: "linux-cooked", 276: "linux-cooked2",
             127: "radiotap", 105: "wifi", 12: "raw-ip", 51: "pppoe"}

R_HTTP_REQ = re.compile(rb"^(GET|POST|PUT|HEAD|DELETE|PATCH|OPTIONS) (\S+) HTTP/(1\.[01])")
R_HTTP_HOST = re.compile(rb"\r\nHost:\s*([^\r\n]+)", re.I)
R_HTTP_AUTH = re.compile(rb"\r\nAuthorization:\s*Basic\s+([A-Za-z0-9+/=]+)", re.I)
R_HTTP_COOKIE = re.compile(rb"\r\n(?:Cookie|Set-Cookie):\s*([^\r\n]{0,200})", re.I)
R_FORM_CRED = re.compile(rb"(?i)(?:^|[?&])(user(?:name)?|login|email|pass(?:word|wd)?|pwd)=([^&\s]{1,80})")
R_FTP = re.compile(rb"^(USER|PASS)\s+([^\r\n]{1,120})", re.I)
R_SMTP_AUTH = re.compile(rb"^(AUTH LOGIN|AUTH PLAIN|MAIL FROM|RCPT TO)[:\s]", re.I)
R_IMAP_POP = re.compile(rb"^(?:\S+ )?(LOGIN|USER|PASS)\s+([^\r\n]{1,120})", re.I)


def _mac(b):
    return ":".join("%02x" % x for x in b)


class PcapReader:
    def __init__(self, path, rel):
        self.path = path
        self.rel = rel
        self.hf = None            # set by the indexer to a linux.HostFile so we can add facts/findings
        self.info = {"packets": 0, "first": None, "last": None, "bytes": 0}
        self.arp_ip_macs = defaultdict(set)     # ip -> {mac}
        self.arp_mac_ips = defaultdict(set)     # mac -> {ip}
        self.arp_replies = Counter()
        self.creds = []           # (line_no, ts, kind, detail)
        self.talkers = Counter()
        self.services = Counter()
        self._cred_seen = set()
        self.qnames = []          # (line, ts, name)
        self.icmp = {}            # (src, dst) -> [count, payload bytes, first line, first ts]

    # ---- container parsing -------------------------------------------------
    def lines(self):
        with art.open_decoded(self.path) as fh:       # .pcap.gz / .pcap.xz too
            magic = fh.peek(4)[:4]
            if magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
                yield from self._pcap(fh)
            elif magic == b"\x0a\x0d\x0d\x0a":
                yield from self._pcapng(fh)
            else:
                return

    def _pcap(self, fh):
        hdr = fh.read(24)
        if len(hdr) < 24:
            return
        le = hdr[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1")
        end = "<" if le else ">"
        nano = hdr[:4] in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
        linktype = struct.unpack(end + "I", hdr[20:24])[0] & 0xffff
        n = 0
        while True:
            rh = fh.read(16)
            if len(rh) < 16:
                break
            ts_s, ts_frac, caplen, origlen = struct.unpack(end + "IIII", rh)
            data = fh.read(min(caplen, SNAP_KEEP))
            if caplen > SNAP_KEEP:
                fh.seek(caplen - SNAP_KEEP, 1)
            ts = ts_s + ts_frac / (1e9 if nano else 1e6)
            n += 1
            line = self._packet(n, ts, data, origlen, linktype)
            if line:
                yield line
            if n >= MAX_PACKETS:
                break

    def _pcapng(self, fh):
        end = "<"
        linktypes = {}
        iface = 0
        n = 0
        while True:
            bh = fh.read(8)
            if len(bh) < 8:
                break
            btype, blen = struct.unpack(end + "II", bh)
            if n == 0 and btype == 0x0A0D0D0A:
                bom = fh.read(4)
                if bom == b"\x4d\x3c\x2b\x1a":
                    end = ">"
                blen = struct.unpack(end + "I", bh[4:8])[0]
                rest = fh.read(blen - 12)
                continue
            body = fh.read(blen - 12)
            fh.read(4)  # trailing block length
            if btype == 0x00000001:  # interface description
                lt = struct.unpack(end + "H", body[:2])[0]
                linktypes[len(linktypes)] = lt
            elif btype in (0x00000006, 0x00000003):  # enhanced / simple packet
                if btype == 0x00000006:
                    ifid, th, tl, caplen, origlen = struct.unpack(end + "IIIII", body[:20])
                    ts = ((th << 32) | tl) / 1e6
                    data = body[20:20 + min(caplen, SNAP_KEEP)]
                    lt = linktypes.get(ifid, 1)
                else:
                    origlen = struct.unpack(end + "I", body[:4])[0]
                    data = body[4:4 + min(origlen, SNAP_KEEP)]
                    ts = None
                    lt = linktypes.get(0, 1)
                n += 1
                line = self._packet(n, ts, data, origlen, lt)
                if line:
                    yield line
                if n >= MAX_PACKETS:
                    break

    # ---- per-packet --------------------------------------------------------
    def _packet(self, n, ts, data, origlen, linktype):
        self.info["packets"] += 1
        self.info["bytes"] += origlen
        tss = az.epoch_to_ts(ts) if ts else None
        if ts:
            self.info["first"] = min(self.info["first"], ts) if self.info["first"] else ts
            self.info["last"] = max(self.info["last"] or 0, ts)
        off, ethertype = self._l2(data, linktype)
        if ethertype is None:
            return f"{tss or ''}\tpacket {n}\t{origlen} bytes" if tss else None
        if ethertype == 0x0806:
            return self._arp(n, tss, data, off)
        if ethertype == 0x0800:
            return self._ipv4(n, tss, data, off, origlen)
        if ethertype == 0x86DD:
            return f"{tss or ''}\tIPv6\t{origlen} bytes"
        return f"{tss or ''}\tether type 0x{ethertype:04x}\t{origlen} bytes"

    def _l2(self, data, linktype):
        if linktype in (1, 105):        # ethernet
            if len(data) < 14:
                return 0, None
            et = struct.unpack(">H", data[12:14])[0]
            if et == 0x8100 and len(data) >= 18:   # VLAN tag
                return 18, struct.unpack(">H", data[16:18])[0]
            return 14, et
        if linktype in (101, 12):       # raw IP
            return 0, 0x0800
        if linktype in (113, 276):      # linux cooked
            if len(data) < 16:
                return 0, None
            return 16, struct.unpack(">H", data[14:16])[0]
        if linktype == 0:               # BSD loopback
            return 4, 0x0800
        return 0, None

    def _arp(self, n, tss, data, off):
        if len(data) < off + 28:
            return f"{tss or ''}\tARP\t(truncated)"
        op = struct.unpack(">H", data[off + 6:off + 8])[0]
        sha = _mac(data[off + 8:off + 14])
        spa = str(ipaddress.IPv4Address(data[off + 14:off + 18]))
        tpa = str(ipaddress.IPv4Address(data[off + 24:off + 28]))
        kind = {1: "who-has", 2: "is-at"}.get(op, f"op{op}")
        if op == 2:  # reply: the material for MITM detection
            self.arp_ip_macs[spa].add(sha)
            self.arp_mac_ips[sha].add(spa)
            self.arp_replies[(spa, sha)] += 1
        return f"{tss or ''}\tARP {kind}\t{spa} ({sha}) -> {tpa}"

    def _ipv4(self, n, tss, data, off, origlen):
        if len(data) < off + 20:
            return f"{tss or ''}\tIPv4\t(truncated)"
        ihl = (data[off] & 0x0f) * 4
        proto = data[off + 9]
        src = str(ipaddress.IPv4Address(data[off + 12:off + 16]))
        dst = str(ipaddress.IPv4Address(data[off + 16:off + 20]))
        l4 = off + ihl
        if proto == 6 and len(data) >= l4 + 20:      # TCP
            sport, dport = struct.unpack(">HH", data[l4:l4 + 4])
            doff = (data[l4 + 12] >> 4) * 4
            payload = data[l4 + doff:]
            self.talkers[f"{src} -> {dst}"] += 1
            self.services[dport] += 1
            svc = self._svc(dport) or self._svc(sport)
            if payload:
                self._creds(n, tss, src, dst, sport, dport, payload)
            info = f":{dport}" + (f" {svc}" if svc else "")
            preview = self._preview(payload)
            return f"{tss or ''}\tTCP\t{src}:{sport} -> {dst}{info}\t{preview}"
        if proto == 17 and len(data) >= l4 + 8:      # UDP
            sport, dport = struct.unpack(">HH", data[l4:l4 + 4])
            svc = self._svc(dport) or self._svc(sport)
            if dport == 53 or sport == 53:
                q = self._dns(data[l4 + 8:])
                if q and dport == 53 and len(self.qnames) < 300000:
                    self.qnames.append((n, tss, q))
                return f"{tss or ''}\tDNS\t{src}:{sport} -> {dst}:{dport}\t{q}"
            return f"{tss or ''}\tUDP\t{src}:{sport} -> {dst}:{dport}" + (f" {svc}" if svc else "")
        if proto == 1:
            plen = max(0, len(data) - l4 - 8)
            k = (src, dst)
            x = self.icmp.get(k)
            if x is None:
                x = self.icmp[k] = [0, 0, n, tss]
            x[0] += 1
            x[1] += plen
            return f"{tss or ''}\tICMP\t{src} -> {dst}\t{plen} bytes payload"
        return f"{tss or ''}\tIP proto {proto}\t{src} -> {dst}"

    SERVICES = {20: "ftp-data", 21: "ftp", 23: "telnet", 25: "smtp", 80: "http", 110: "pop3", 143: "imap",
                389: "ldap", 587: "smtp", 8080: "http-alt", 3306: "mysql", 5432: "postgres", 6379: "redis",
                27017: "mongo", 5060: "sip", 161: "snmp"}

    def _svc(self, port):
        return self.SERVICES.get(port)

    def _preview(self, payload):
        if not payload:
            return ""
        m = R_HTTP_REQ.match(payload)
        if m:
            host = R_HTTP_HOST.search(payload)
            return f"{m.group(1).decode()} {(host.group(1).decode('latin1') if host else '')}{m.group(2).decode('latin1')}"[:120]
        txt = payload[:80].decode("latin1")
        printable = sum(32 <= ord(c) < 127 for c in txt)
        return re.sub(r"\s+", " ", txt).strip()[:80] if printable > len(txt) * 0.7 else ""

    def _dns(self, payload):
        if len(payload) < 12:
            return ""
        try:
            qd = struct.unpack(">H", payload[4:6])[0]
            i, labels = 12, []
            while i < len(payload) and payload[i]:
                ln = payload[i]
                if ln > 63 or i + 1 + ln > len(payload):
                    break
                labels.append(payload[i + 1:i + 1 + ln].decode("latin1"))
                i += 1 + ln
            return ".".join(labels)[:120]
        except (struct.error, IndexError):
            return ""

    def _creds(self, n, tss, src, dst, sport, dport, payload):
        found = []
        m = R_HTTP_AUTH.search(payload)
        if m:
            import base64
            try:
                found.append(("HTTP Basic auth", base64.b64decode(m.group(1)).decode("latin1")[:80]))
            except Exception:
                pass
        m = R_HTTP_REQ.match(payload)
        if m:
            for fm in R_FORM_CRED.finditer(m.group(2) + b" " + payload):
                found.append(("HTTP form field", f"{fm.group(1).decode('latin1')}={fm.group(2).decode('latin1')}"[:80]))
        if dport in (21, 20) or sport in (21, 20):
            fm = R_FTP.match(payload)
            if fm:
                found.append(("FTP " + fm.group(1).decode().lower(), fm.group(2).decode("latin1")[:80]))
        if dport in (110, 143) or sport in (110, 143):
            fm = R_IMAP_POP.match(payload)
            if fm:
                found.append((f"{'POP3' if dport == 110 or sport == 110 else 'IMAP'} {fm.group(1).decode().lower()}", fm.group(2).decode("latin1")[:80]))
        if dport in (25, 587) or sport in (25, 587):
            if R_SMTP_AUTH.match(payload):
                found.append(("SMTP auth", payload[:60].decode("latin1").strip()))
        for kind, detail in found:
            key = (kind, detail)
            if key in self._cred_seen:
                continue
            self._cred_seen.add(key)
            self.creds.append((n, tss, f"{src}->{dst}:{dport}", kind, detail))

    # ---- summary and findings ---------------------------------------------
    def finish(self):
        i = self.info
        first, last = az.epoch_to_ts(i["first"]) if i["first"] else None, az.epoch_to_ts(i["last"]) if i["last"] else None
        if self.hf is None:
            return
        dur = ""
        if i["first"] and i["last"]:
            secs = int(i["last"] - i["first"])
            dur = f", {secs // 3600}h{secs % 3600 // 60:02d}m" if secs >= 3600 else f", {secs // 60}m{secs % 60:02d}s" if secs >= 60 else f", {secs}s"
        self.hf.fact("capture", 1, first, self.rel, packets=i["packets"], bytes=i["bytes"], first=first, last=last,
                     top_talkers=self.talkers.most_common(5), services=self.services.most_common(6))
        self.hf.find("packet_capture_file", 1, first, ts_end=last,
                     snippet=f"{i['packets']:,} packets, {i['bytes'] / 1e6:.1f} MB{dur}"
                             + (f", captured {first} to {last} UTC" if first else "")
                             + (f"; {len(self.creds)} plaintext credential(s) inside" if self.creds else ""))
        for line_no, tss, flow, kind, detail in self.creds[:200]:
            self.hf.find("cleartext_creds", line_no, tss, snippet=f"{kind} in {self.rel}: {detail} ({flow})")
            self.hf.fact("sniffed_cred", line_no, tss, kind, flow=flow, detail=detail, file=self.rel)
            self.hf.decoded.append((line_no, f"captured {kind}", f"{detail} ({flow})"))
        # tunnels hidden in DNS and ICMP
        import webaccess
        for t in webaccess.dns_tunnel_check(q for _n, _t, q in self.qnames):
            first = next((x for x in self.qnames if x[2].lower().endswith(t["domain"])), self.qnames[0])
            self.hf.find("dns_tunnel", first[0], first[1],
                         snippet=f"{t['domain']}: {t['unique']:,} different subdomains in {t['queries']:,} queries "
                                 f"(labels {t['avg_label']} chars, entropy {t['entropy']}), e.g. {t['examples'][0][:80]} — in {self.rel}")
        for (src, dst), (cnt, pbytes, n0, t0) in self.icmp.items():
            if cnt >= 30 and pbytes / cnt >= 100:
                self.hf.find("icmp_tunnel", n0, t0, snippet=f"{cnt} ICMP packets {src} -> {dst} carrying {pbytes // cnt} bytes each "
                                                            f"on average (normal ping: 32-56) — data hidden in ICMP, in {self.rel}")
        # ARP MITM: one IP with several MACs, or one MAC claiming many IPs
        for ip, macs in self.arp_ip_macs.items():
            if len(macs) > 1:
                self.hf.find("arp_conflict", 1, first, ts_end=last,
                             snippet=f"{ip} answered from {len(macs)} different MACs in {self.rel}: {', '.join(sorted(macs))}"
                                     f" — ARP spoofing / man-in-the-middle")
                self.hf.fact("arp_conflict", 1, first, ip, macs=sorted(macs), file=self.rel)
        for mac, ips in self.arp_mac_ips.items():
            if len(ips) >= 4:
                self.hf.find("arp_conflict", 1, first, ts_end=last,
                             snippet=f"one MAC {mac} claimed {len(ips)} IP addresses in {self.rel} "
                                     f"(e.g. {', '.join(sorted(ips)[:6])}) — ARP spoofing")


PCAP_RULES = {
    "packet_capture_file": ("high", "sniffing", "Packet capture file (recorded network traffic)"),
    "cleartext_creds": ("high", "sniffing", "Plaintext credentials captured in network traffic"),
    "arp_conflict": ("high", "sniffing", "Conflicting ARP replies in a capture (man-in-the-middle)"),
}
