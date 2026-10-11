"""
Debian baseline diff.

"What on this machine is ordinary Debian, and what is not?" This reads dpkg's own records
(the .md5sums and .list files under /var/lib/dpkg/info, and the conffile hashes in
/var/lib/dpkg/status) and classifies every file under the system tree:

    standard       present and matches the checksum dpkg recorded for its package
    modified       present but differs from its package (a conffile you changed, or a trojaned binary)
    missing        a package expects this file but it is not in the collected evidence
    unowned        a file in a system folder that no installed package put there
    unverifiable   present and owned, but dpkg kept no md5 for it (or the file's hash wasn't computed)

It also diffs the installed package set against a base-Debian/common set, so additions an intruder
made (nmap, socat, a compiler) stand out from packages a normal server would have.

The result is one `baseline` fact (the summary and samples) used by the Host view's "Debian baseline"
section; the per-file findings (pkg_file_modified, unowned_binary, conffile_modified) are still raised
by linux._verify_packages so they flow into Triage and the timelines as before. This module adds the
whole-system picture and the diffs that view needs.
"""
import json
import re

import analyzers as az

# Directories that belong to the OS; anything here should normally be accounted for by a package.
SYSTEM_TREE = ("bin/", "sbin/", "lib/", "lib32/", "lib64/", "libx32/", "usr/", "etc/", "boot/")
# ...except these subtrees are expected to hold local, unpackaged content on a normal system.
LOCAL_OK = re.compile(
    r"^(?:etc/(?:hostname|hosts|machine-id|mtab|resolv\.conf|fstab|crypttab|adjtime|localtime|timezone|"
    r"network/|netplan/|NetworkManager/system-connections/|ssh/ssh_host_|ssl/private/|"
    r"ssl/certs/|letsencrypt/|cron\.d/|systemd/system/(?:multi-user|sysinit|getty|sockets|timers)\.target\.wants/|"
    r"apt/sources\.list|apt/apt\.conf\.d/|default/|init\.d/\.depend|ld\.so\.cache|"
    r"[\w.-]+\.d/|subuid|subgid|group-?|passwd-?|shadow-?|gshadow-?)"
    r"|usr/(?:local/|share/(?:man/|doc/|locale/|mime/|applications/|fonts/|ca-certificates/)|"
    r"lib/(?:python3(?:\.\d+)?/dist-packages/|node_modules/|modules/)|src/)"
    r"|var/|boot/(?:grub/grub\.cfg|grub/grubenv)"
    r"|usr/lib/(?:python3(?:\.\d+)?/dist-packages/|.*/__pycache__/))")
# Package names a routine Debian server install carries, so "extra" means genuinely added.
BASE_PKGS = set("""
base-files base-passwd bash bsdutils coreutils dash debconf debconf-i18n debian-archive-keyring
diffutils dpkg e2fsprogs findutils gcc-12-base gpgv grep gzip hostname init init-system-helpers
libacl1 libattr1 libaudit-common libaudit1 libblkid1 libbz2-1.0 libc-bin libc6 libcap-ng0 libcap2
libcom-err2 libcrypt1 libdb5.3 libdebconfclient0 libext2fs2 libffi8 libgcc-s1 libgcrypt20 libgmp10
libgnutls30 libgpg-error0 libhogweed6 libidn2-0 liblz4-1 liblzma5 libmd0 libmount1 libncursesw6
libnettle8 libp11-kit0 libpam-modules libpam-modules-bin libpam-runtime libpam0g libpcre2-8-0
libseccomp2 libselinux1 libsemanage-common libsemanage2 libsepol2 libsmartcols1 libss2 libssl3
libstdc++6 libsystemd0 libtasn1-6 libtinfo6 libudev1 libunistring2 libuuid1 libxxhash0 libzstd1
login logsave lsb-base mawk mount ncurses-base ncurses-bin passwd perl-base sed sensible-utils
sysvinit-utils tar tzdata util-linux util-linux-extra zlib1g
adduser apt apt-utils ca-certificates cron curl debian-faq dbus dmidecode dpkg-dev file gettext-base
gnupg groff-base ifupdown iproute2 iptables iputils-ping isc-dhcp-client kmod less libpam-systemd
locales logrotate man-db manpages nano netbase openssh-client openssh-server openssl procps
python3 python3-minimal readline-common rsync rsyslog sudo systemd systemd-sysv systemd-timesyncd
traceroute ucf udev vim-common vim-tiny wget whiptail xz-utils
grub-common grub-pc grub2-common linux-base console-setup keyboard-configuration
""".split())
# Common, legitimate server packages: still shown, but not alarming by themselves.
COMMON_SERVER_PKGS = set("""
nginx nginx-common nginx-core nginx-full apache2 apache2-bin apache2-data apache2-utils
mysql-server mariadb-server mariadb-common mysql-common default-mysql-server postgresql postgresql-common
php php-fpm php-cli php-common php-mysql php-curl php-gd php-mbstring php-xml redis redis-server
certbot python3-certbot-nginx python3-certbot-apache fail2ban ufw unattended-upgrades
nodejs npm git htop tmux screen zip unzip net-tools dnsutils bind9-dnsutils jq
postfix dovecot-core exim4 exim4-base exim4-config
docker-ce docker-ce-cli containerd.io docker.io
python3-pip python3-venv python3-dev build-essential snapd
""".split())
# Offensive / dual-use packages worth calling out explicitly if installed.
SUSPICIOUS_PKGS = set("""
nmap masscan zmap hydra john hashcat medusa ncrack netcat-traditional ncat socat proxychains
proxychains4 tor torsocks sshpass tcpdump tshark wireshark sqlmap nikto gobuster dirb wfuzz
aircrack-ng ettercap-text-only ettercap-graphical responder crackmapexec metasploit-framework chisel
xmrig hping3 arp-scan dsniff netdiscover p0f mitmproxy iodine ptunnel dns2tcp nbtscan smbclient
impacket-scripts python3-impacket wireguard wireguard-tools openvpn
""".split())


def _ns_ts(ns):
    return az.epoch_to_ts(ns / 1e9) if ns else None


def build(con, files):
    """Produce the baseline diff. Writes one 'baseline' case fact. Returns nothing extra for
    findings (those are already raised by _verify_packages)."""
    con.execute("DELETE FROM facts WHERE scope='case' AND kind='baseline'")
    info = [r for r in con.execute("SELECT id, rel FROM files WHERE rel LIKE '%var/lib/dpkg/info/%.md5sums' "
                                   "OR rel LIKE '%var/lib/dpkg/info/%.list'")]
    status_rows = list(con.execute("SELECT id, rel FROM files WHERE rel LIKE '%var/lib/dpkg/status'"))
    if not info and not status_rows:
        con.execute("INSERT INTO facts(kind, scope, ts, subject, data) VALUES('baseline','case',NULL,'baseline',?)",
                    (json.dumps({"available": False,
                                 "reason": "No dpkg records found. Collect /var/lib/dpkg (info and status) alongside the "
                                           "system folders so Crumbs can tell standard Debian files from added or changed ones."}),))
        return

    prefix = (info[0]["rel"].split("var/lib/dpkg/info/")[0] if info
              else status_rows[0]["rel"].split("var/lib/dpkg/status")[0])
    by_rel = {f["rel"]: f for f in files}

    # expected md5 per path, and the full owned set; also which package owns each path
    expected, owned, owner = {}, set(), {}
    for r in info:
        pkg = r["rel"].rsplit("/", 1)[-1].rsplit(".", 1)[0].split(":")[0]
        is_md5 = r["rel"].endswith(".md5sums")
        for l in con.execute("SELECT text FROM lines WHERE file_id=?", (r["id"],)):
            t = (l[0] or "").strip()
            if not t:
                continue
            if is_md5:
                p = t.split(None, 1)
                if len(p) == 2 and len(p[0]) == 32:
                    path = prefix + p[1]
                    expected[path] = (p[0], pkg)
                    owned.add(path)
                    owner.setdefault(path, pkg)
            else:
                path = prefix + t.lstrip("/")
                owned.add(path)
                owner.setdefault(path, pkg)

    # installed packages, versions and conffile hashes from dpkg status
    installed, conffiles = {}, {}
    for r in status_rows:
        pkg = ver = None
        in_conf = False
        for l in con.execute("SELECT text FROM lines WHERE file_id=? ORDER BY line_no", (r["id"],)):
            t = l[0] if l[0] is not None else ""
            if t.startswith("Package: "):
                pkg, ver, in_conf = t[9:].strip(), None, False
            elif t.startswith("Version: ") and pkg:
                ver = t[9:].strip()
                installed[pkg] = ver
            elif t.startswith("Conffiles:"):
                in_conf = True
            elif in_conf and t.startswith(" "):
                m = re.match(r"^ (/\S+) ([0-9a-f]{32})(?: (obsolete|newconffile))?$", t)
                if m:
                    conffiles[prefix + m.group(1).lstrip("/")] = (m.group(2), pkg)
            elif t and not t.startswith(" "):
                in_conf = False

    # classify every collected file under the system tree
    counts = {"standard": 0, "modified": 0, "unowned": 0, "unverifiable": 0}
    modified, unowned = [], []
    conf_changed = []
    for f in files:
        rel = f["rel"]
        if not rel.startswith(prefix):
            continue
        sub = rel[len(prefix):]
        if not sub.startswith(SYSTEM_TREE):
            continue
        is_elf = (f.get("magic") or "").startswith("ELF")
        full = rel
        if full in expected:
            md5, pkg = expected[full]
            if f.get("md5"):
                if f["md5"] == md5:
                    counts["standard"] += 1
                else:
                    counts["modified"] += 1
                    modified.append({"path": "/" + sub, "package": pkg, "file_id": f["id"], "ts": _ns_ts(f["mtime_ns"]),
                                     "elf": is_elf, "conffile": full in conffiles})
            else:
                counts["unverifiable"] += 1
        elif full in conffiles:
            want, pkg = conffiles[full]
            if f.get("md5") and f["md5"] != want:
                counts["modified"] += 1
                conf_changed.append({"path": "/" + sub, "package": pkg, "file_id": f["id"], "ts": _ns_ts(f["mtime_ns"])})
            elif f.get("md5"):
                counts["standard"] += 1
            else:
                counts["unverifiable"] += 1
        elif full in owned:
            counts["unverifiable"] += 1   # owned but dpkg kept no md5 (e.g. directories, generated files)
        else:
            if LOCAL_OK.match(sub):
                continue   # expected local content, not part of the OS baseline
            counts["unowned"] += 1
            unowned.append({"path": "/" + sub, "file_id": f["id"], "ts": _ns_ts(f["mtime_ns"]), "elf": is_elf,
                            "size": f["size"], "in_bin": sub.startswith(("bin/", "sbin/", "usr/bin/", "usr/sbin/",
                                                                         "usr/local/bin/", "usr/local/sbin/"))})

    # package-set diff
    extra_sus, extra_other, extra_common = [], [], []
    for pkg, ver in sorted(installed.items()):
        base = pkg.split(":")[0]
        if base in BASE_PKGS:
            continue
        entry = {"package": base, "version": ver}
        if base in SUSPICIOUS_PKGS:
            extra_sus.append(entry)
        elif base in COMMON_SERVER_PKGS:
            extra_common.append(entry)
        else:
            extra_other.append(entry)

    # files a package expects but that are missing from the evidence (only meaningful on a full image)
    missing = 0
    if len(files) > 2000:   # heuristic: only trust "missing" when the collection looks whole
        present = set(by_rel)
        for path in expected:
            if path not in present and not LOCAL_OK.match(path[len(prefix):]):
                missing += 1

    bulk = counts["standard"] + counts["modified"] >= 20 and \
        counts["modified"] > 2 * max(1, counts["standard"])   # most files differ → wrong package versions collected

    modified.sort(key=lambda x: (not x["elf"], x["ts"] or ""))
    unowned.sort(key=lambda x: (not x["in_bin"], not x["elf"], x["ts"] or ""))
    data = {
        "available": True, "prefix": prefix, "counts": counts, "missing": missing,
        "version_warning": bulk,
        "installed_total": len(installed),
        "modified": modified[:400], "modified_total": len(modified),
        "conffiles_changed": conf_changed[:200], "conffiles_changed_total": len(conf_changed),
        "unowned": unowned[:400], "unowned_total": counts["unowned"],
        "extra_suspicious": extra_sus, "extra_common": extra_common,
        "extra_other": extra_other[:400], "extra_other_total": len(extra_other),
    }
    con.execute("INSERT INTO facts(kind, scope, ts, subject, data) VALUES('baseline','case',NULL,'baseline',?)",
                (json.dumps(data),))


def report(con):
    r = con.execute("SELECT data FROM facts WHERE kind='baseline' LIMIT 1").fetchone()
    return json.loads(r[0]) if r else {"available": False, "reason": "Not analysed yet."}
