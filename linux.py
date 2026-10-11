"""
Debian / Linux host forensics.

Recognises system artifacts by their path, parses them into structured *facts* (accounts,
SSH keys, logins, sudo, persistence, packages, commands, network contacts) and raises
findings. The case-wide pass correlates them: password guessing that succeeded, SSH keys
used for logins that are no longer authorised anywhere, system binaries that differ from
their Debian package, SUID or ELF files where they do not belong, deceptive names.
"""
import base64
import binascii
import hashlib
import ipaddress
import json
import re
import struct
from urllib.parse import unquote

import analyzers as az
import artifacts as art
import traffic
import pcap
import webaccess
import baseline

# ------------------------------------------------------------------ catalog ---
HOST_RULES = {
    "system_account_shell": ("high", "credential", "System account with a login shell and a password"),
    "empty_password": ("high", "credential", "Account with an empty password"),
    "weak_hash": ("low", "credential", "Password hash uses an outdated algorithm"),
    "weird_home": ("medium", "credential", "Account home in a temporary or hidden location"),
    "duplicate_uid": ("medium", "credential", "Several accounts share one UID"),
    "account_added": ("medium", "credential", "Account created"),
    "account_removed": ("medium", "credential", "Account deleted"),
    "account_modified": ("medium", "credential", "Account changed (password, groups, shell, lock)"),
    "privileged_group": ("low", "privilege", "Member of an administrative group"),
    "root_equivalent_group": ("medium", "privilege", "Member of a group that is root-equivalent (docker, lxd, disk, shadow, root)"),
    "sudo_nopasswd": ("medium", "privilege", "sudo rule that needs no password"),
    "sudo_logging_off": ("high", "defense_evasion", "sudo logging disabled"),
    "sudo_denied": ("low", "auth", "sudo refused (wrong password or not allowed)"),
    "ssh_key": ("low", "credential", "SSH key authorised for login"),
    "ssh_key_root": ("medium", "credential", "SSH key authorised for root"),
    "ssh_key_options": ("medium", "credential", "SSH key with a forced command or other options"),
    "ssh_key_unknown_login": ("medium", "credential", "Login with an SSH key that is no longer authorised anywhere"),
    "sshd_risky": ("medium", "credential", "Risky SSH server setting"),
    "sshd_quiet": ("high", "defense_evasion", "SSH server logging turned down"),
    "sshd_port": ("low", "credential", "SSH server listening on an extra or unusual port"),
    "brute_force_success": ("high", "auth", "Password guessing that succeeded"),
    "brute_force": ("medium", "recon", "Password guessing from one source"),
    "root_login_remote": ("medium", "auth", "Direct root login over SSH from outside"),
    "cron_suspicious": ("high", "persistence", "Scheduled job runs something suspicious"),
    "cron_entry": ("low", "persistence", "Scheduled job in a user crontab"),
    "systemd_suspicious": ("high", "persistence", "Service runs something suspicious or from an unusual place"),
    "systemd_user_unit": ("medium", "persistence", "Per-user systemd service"),
    "systemd_unit_unowned": ("medium", "persistence", "Service not installed by any package"),
    "initscript_entry": ("medium", "persistence", "Command added to rc.local"),
    "initscript_suspicious": ("high", "persistence", "Boot script runs something suspicious"),
    "shellrc_suspicious": ("high", "persistence", "Login script hijacks commands or runs something suspicious"),
    "ld_preload": ("high", "rootkit", "Library force-loaded into every program (ld.so.preload)"),
    "pam_suspicious": ("high", "rootkit", "Suspicious PAM authentication module"),
    "kernel_module_boot": ("low", "rootkit", "Kernel module loaded at boot by configuration"),
    "wtmp_wiped": ("high", "log_tampering", "Login records wiped (zeroed) in wtmp / btmp / utmp"),
    "wtmp_backwards": ("medium", "log_tampering", "Login records out of time order"),
    "utmp_truncated": ("medium", "log_tampering", "Login record file ends in a partial record"),
    "pkg_file_modified": ("high", "rootkit", "System file differs from its Debian package"),
    "conffile_modified": ("medium", "persistence", "Security-relevant package config changed"),
    "unowned_binary": ("high", "persistence", "Program in a system folder that no package installed"),
    "suid_unusual": ("high", "privilege", "SUID / SGID program not from a package or in an unusual place"),
    "elf_in_tmp": ("high", "execution", "Program stored in a temporary or hidden folder"),
    "weird_name": ("high", "hiding", "File or folder with a deceptive name ('...', spaces)"),
    "vim_edited_sensitive": ("medium", "leftover", "Sensitive file edited in vim"),
    "audit_rules_changed": ("high", "defense_evasion", "Audit rules removed or auditing switched off"),
    "hidden_audit_command": ("high", "execution", "Command reconstructed from auditd"),
}
HOST_RULES.update(traffic.EPISODE_RULES)
HOST_RULES.update(pcap.PCAP_RULES)
HOST_RULES.update(webaccess.WEB_RULES)
for _rid, (_sev, _cat, _desc) in HOST_RULES.items():
    az.RULE_INFO[_rid] = {"severity": _sev, "category": _cat, "description": _desc}

# ------------------------------------------------------------ path → kind ---
PATH_KINDS = [
    ("mail_queue", r"(^|/)var/spool/exim4?/input/(?:.+/)?[^/]+-H$|(^|/)var/spool/postfix/(deferred|active|incoming|hold|maildrop)/.+"),
    ("mail_log", r"(^|/)(mail\.(log|info|warn|err)|maillog)(\.\d+)?(\.(?:gz|bz2|xz))?$|(^|/)exim4?/(main|reject|panic)log(\.\d+)?(\.(?:gz|bz2|xz))?$|(^|/)exim_(main|reject|panic)log$"),
    ("kern_log", r"(^|/)(kern\.log|ufw\.log|iptables\.log|firewall\.log|dmesg)(\.\d+)?(\.(?:gz|bz2|xz))?$"),
    ("pcap", r"(?i)\.(pcap|pcapng|cap|dmp)(\.\d+)?$"),
    ("web_access", r"(^|/)(?:[\w.-]*[._-])?access(?:[._-]log|_log)(?:[._-][\w-]+)?(\.\d+)?(\.(?:gz|bz2|xz))?$|(^|/)(?:nginx|apache2?|httpd|lighttpd)/[^/]*access[^/]*$"),
    ("tunnel_config", r"(^|/)etc/tor/torrc(\.d/[^/]+)?$|(^|/)etc/wireguard/[^/]+\.conf$|(?i:\.ovpn)$|(^|/)etc/openvpn/(?:client/)?[^/]+\.conf$|"
                      r"(^|/)(?i:frpc?)[^/]*\.(?:ini|toml|ya?ml)$|(^|/)\.cloudflared/[^/]+\.ya?ml$|(^|/)\.?ngrok2?/ngrok\.ya?ml$|(^|/)ngrok\.ya?ml$|"
                      r"(^|/)etc/rinetd\.conf$|(^|/)3proxy\.cfg$|(^|/)etc/danted\.conf$|(^|/)var/lib/tailscale/tailscaled\.state$|"
                      r"(^|/)var/lib/zerotier-one/(?:identity\.public|networks\.d/[^/]+\.conf)$|(^|/)etc/stunnel/[^/]+\.conf$|(^|/)\.ssh/config$"),
    ("net_config", r"(^|/)etc/(sysctl\.conf|sysctl\.d/[^/]+|iptables/rules\.v[46]|nftables\.conf|hosts|resolv\.conf|dnsmasq\.conf|dnsmasq\.d/[^/]+|network/interfaces|NetworkManager/|systemd/network/)|(^|/)etc/systemd/resolved\.conf$"),
    ("passwd", r"(^|/)passwd-?$"),
    ("shadow", r"(^|/)shadow-?$"),
    ("group", r"(^|/)group-?$"),
    ("sudoers", r"(^|/)sudoers$|(^|/)sudoers\.d/[^/]+$"),
    ("authorized_keys", r"(^|/)authorized_keys2?$"),
    ("sshd_config", r"(^|/)sshd_config$|(^|/)sshd_config\.d/[^/]+\.conf$"),
    ("cron", r"(^|/)(crontab|anacrontab)$|(^|/)cron\.d/[^/]+$|(^|/)var/spool/cron/(crontabs/)?[^/]+$|(^|/)cron\.(hourly|daily|weekly|monthly)/[^/]+$"),
    ("systemd_unit", r"(^|/)systemd/(system|user)/.+\.(service|timer|socket|path)$|(^|/)\.config/systemd/user/.+\.(service|timer)$"),
    ("initscript", r"(^|/)rc\.local$|(^|/)init\.d/[^/]+$"),
    ("shellrc", r"(^|/)(\.bashrc|\.profile|\.bash_profile|\.bash_login|\.bash_logout|\.zshrc|\.zprofile|\.zshenv|bash\.bashrc|environment)$|(^|/)etc/profile$|(^|/)profile\.d/[^/]+$"),
    ("ld_preload", r"(^|/)ld\.so\.preload$"),
    ("pam", r"(^|/)pam\.d/[^/]+$"),
    ("modules", r"(^|/)etc/modules$|(^|/)modules-load\.d/[^/]+$"),
    ("apt_history", r"(^|/)apt/history\.log(\.\d+)?(\.(?:gz|bz2|xz))?$"),
    ("dpkg_log", r"(^|/)dpkg\.log(\.\d+)?(\.(?:gz|bz2|xz))?$"),
    ("auth_log", r"(^|/)(auth\.log|secure|syslog|messages|daemon\.log)(\.\d+)?(\.(?:gz|bz2|xz))?$|(^|/)journal[^/]*\.(txt|log)$"),
    ("audit_log", r"(^|/)audit\.log(\.\d+)?(\.(?:gz|bz2|xz))?$"),
    ("utmp", r"(^|/)(wtmp|btmp|utmp)([.-][\w.-]+)?$"),
    ("lastlog", r"(^|/)lastlog$"),
    ("viminfo", r"(^|/)\.viminfo$"),
    ("wget_hsts", r"(^|/)\.wget-hsts$"),
    ("known_hosts", r"(^|/)known_hosts$"),
    ("host_info", r"(^|/)etc/(os-release|debian_version|hostname|timezone)$|(^|/)usr/lib/os-release$"),
    ("localtime", r"(^|/)etc/localtime$"),
    ("dpkg_info", r"(^|/)var/lib/dpkg/info/[^/]+\.(md5sums|list|conffiles|postinst|preinst|prerm|postrm|triggers|shlibs|symbols|templates|config)$"),
    ("dpkg_status", r"(^|/)var/lib/dpkg/status(-old)?$"),
    ("bash_completion", r"(^|/)(?:usr/share|etc)/bash[-_]completion(?:\.d|s)/[^/]+$|(^|/)usr/share/bash-completion/completions/[^/]+$"),
]
_PATH_RX = [(k, re.compile(rx)) for k, rx in PATH_KINDS]
QUIET_KINDS = {"dpkg_info", "dpkg_status", "bash_completion"}  # large reference data: no entity / rule extraction
BINARY_KINDS = {"utmp", "lastlog", "localtime", "pcap"}


def path_kind(rel):
    if "!/" in rel:
        return None      # inside an archive: indexed and searchable, but may come from another machine
    for k, rx in _PATH_RX:
        if rx.search(rel):
            return k
    return None


def owner_from_path(rel):
    m = re.search(r"(?:^|/)home/([^/]+)/", rel)
    if m:
        return m.group(1)
    if re.search(r"(?:^|/)root/", rel):
        return "root"
    m = re.search(r"(?:^|/)var/spool/cron/(?:crontabs/)?([^/]+)$", rel)
    if m:
        return m.group(1)
    return None


# ------------------------------------------------------ suspicious commands ---
_SUS = [
    (re.compile(r"\b(?:curl|wget|fetch|tftp|lwp-download|aria2c)\b", re.I), "downloads from the network"),
    (re.compile(r"\|\s*(?:sudo\s+)?(?:ba|da|z|k)?sh\b|\|\s*python[23]?\b|\|\s*perl\b", re.I), "pipes into a shell"),
    (re.compile(r"/dev/(?:tcp|udp)/|\bbash\s+-i\b|\bnc(?:at)?\s+(?:-\w+\s+)*-[ec]\b|\bmkfifo\b|\bsocat\b.*(?:exec|system):|\btelnet\s+\S+\s+\d+\s*\|", re.I), "reverse shell"),
    (re.compile(r"base64\s+(?:-d|--decode)|\bxxd\s+-r|openssl\s+(?:enc|base64)\s+.*-d\b|\beval\b", re.I), "decodes or evals hidden code"),
    (re.compile(r"(?:^|[\s'\"=:])(?:/tmp|/var/tmp|/dev/shm|/run/shm)/", re.I), "uses a temporary folder"),
    (re.compile(r"/\.[^/\s.][^/\s]*/|/\.\.\.|/\. ", re.I), "uses a hidden path"),
    (re.compile(r"\bpython[23]?\s+-c\b|\bperl\s+-e\b|\bphp\s+-r\b|\bruby\s+-e\b", re.I), "interpreter one-liner"),
    (re.compile(r"\bnohup\b|\bsetsid\b|\bdisown\b|>\s*/dev/null\s+2>&1\s*&|\s&\s*$", re.I), "runs detached in the background"),
    (re.compile(r"\bxmrig\b|stratum\+tcp|\bminerd\b|--donate-level", re.I), "crypto miner"),
    (re.compile(r"\bchmod\s+(?:\+x|[0-7]*7[0-7]*)\s+\S*(?:/tmp|/dev/shm|/var/tmp)", re.I), "makes a temporary file executable"),
]
_STRONG = {"pipes into a shell", "reverse shell", "decodes or evals hidden code", "crypto miner"}


def suspicious_reasons(cmd):
    return [label for rx, label in _SUS if rx.search(cmd)]


def is_strong(reasons):
    return len(reasons) >= 2 or bool(_STRONG & set(reasons))


def ssh_fingerprint(b64):
    try:
        blob = base64.b64decode(b64 + "=" * (-len(b64) % 4))
    except (binascii.Error, ValueError):
        return None
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


def is_public_ip(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (a.is_private or a.is_loopback or a.is_link_local or a.is_reserved or a.is_multicast)


# ---------------------------------------------------------- regex library ---
R_ACCEPT = re.compile(r"sshd\[\d+\]: Accepted (\S+) for (\S+) from (\S+) port (\d+)(?: ssh2)?(?:: (\S+) (SHA256:[A-Za-z0-9+/=]+|MD5:[0-9a-f:]+|[0-9a-f:]{47}))?")
R_FAIL = re.compile(r"sshd\[\d+\]: Failed (\S+) for (invalid user )?(\S*) from (\S+) port (\d+)")
R_INVALID = re.compile(r"sshd\[\d+\]: Invalid user (\S*) from (\S+)")
R_SUDO = re.compile(r"\bsudo(?:\[\d+\])?:\s+(\S+) : (.*?)(?:TTY=(\S+) ; )?PWD=(\S+) ; USER=(\S+) ; (?:ENV=.*? ; )?(?:COMMAND=(.*))?$")
R_SU = re.compile(r"\bsu(?:\[\d+\])?: (?:\(to (\S+)\) (\S+) on (\S+)|pam_unix\(su(?:-l)?:session\): session opened for user (\S+?)(?:\(uid=\d+\))? by (\S*?)(?:\(uid=\d+\))?\s*$|FAILED SU \(to (\S+)\) (\S+) on (\S+))")
R_USERADD = re.compile(r"useradd\[\d+\]: new user: name=([^,]+), UID=(\d+), GID=(\d+), home=([^,]+), shell=([^,\s]+)")
R_GROUPMEM = re.compile(r"(?:usermod|gpasswd|useradd)\[\d+\]: (?:add|add member) '?([^' ]+)'? to (?:shadow )?group '?([^' ]+)'?")
R_PASSWD = re.compile(r"(?:passwd|chpasswd)\[\d+\]: (?:pam_unix\((?:passwd|chpasswd):chauthtok\): )?password (?:changed|updated) for (\S+)")
R_USERDEL = re.compile(r"userdel\[\d+\]: (?:delete user|removed group|delete) '([^']+)'")
R_USERMOD = re.compile(r"usermod\[\d+\]: (?:change user '([^']+)' (\w+)(?: from '([^']*)' to '([^']*)')?|lock user '([^']+)' password|unlock user '([^']+)' password)")
R_LISTEN = re.compile(r"sshd\[\d+\]: Server listening on (\S+) port (\d+)")
R_AUDIT = re.compile(r"type=(\w+) msg=audit\((\d+)\.\d+:(\d+)\):\s?(.*)")
R_KV = re.compile(r"(\w+)=(\"[^\"]*\"|'[^']*'|\S+)")
R_APT_PKG = re.compile(r"([A-Za-z0-9][\w.+-]*)(?::(\w+))? \(([^)]*)\)")
R_DPKG = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) (install|upgrade|remove|purge) ([^\s:]+)(?::(\w+))? (\S+) (\S+)")

OFFENSIVE_PKGS = {"nmap", "masscan", "zmap", "hydra", "john", "hashcat", "medusa", "ncrack", "netcat-traditional", "ncat",
                  "socat", "proxychains", "proxychains4", "tor", "torsocks", "sshpass", "tcpdump", "tshark", "wireshark",
                  "sqlmap", "nikto", "gobuster", "dirb", "wfuzz", "aircrack-ng", "ettercap-text-only", "ettercap-graphical",
                  "responder", "crackmapexec", "metasploit-framework", "chisel", "xmrig", "hping3", "arp-scan", "dsniff",
                  "netdiscover", "ophcrack", "p0f", "sslsplit", "mitmproxy", "iodine", "ptunnel", "dns2tcp", "nbtscan",
                  "smbclient", "impacket-scripts", "python3-impacket", "whois", "lynx"}
BUILD_PKGS = {"gcc", "g++", "make", "build-essential", "clang", "cmake", "nasm", "binutils", "golang", "golang-go",
              "rustc", "cargo", "musl-tools", "upx-ucl"}
SECURITY_PKGS = {"auditd", "rsyslog", "syslog-ng", "fail2ban", "apparmor", "apparmor-utils", "clamav", "clamav-daemon",
                 "aide", "rkhunter", "chkrootkit", "ufw", "osquery", "wazuh-agent", "sysmonforlinux", "logrotate",
                 "auditbeat", "filebeat", "falcon-sensor", "tripwire", "samhain", "selinux-basics", "acct", "psacct",
                 "unattended-upgrades", "systemd-journal-remote", "libpam-google-authenticator", "needrestart"}
PRIV_GROUPS = {"sudo", "adm", "wheel", "admin", "staff"}
ROOT_EQUIV_GROUPS = {"root", "docker", "lxd", "lxc", "disk", "shadow", "kmem", "libvirt"}
NOLOGIN = re.compile(r"(nologin|/false|/sync|/halt|/shutdown)$")
SENSITIVE_EDIT = re.compile(r"^/etc/(passwd|shadow|group|sudoers|ssh/|pam\.d/|crontab|cron\.|rc\.local|ld\.so|profile|"
                            r"bash\.bashrc|systemd/|hosts|resolv\.conf|audit/|rsyslog)|/\.ssh/|/\.bashrc|/\.profile|"
                            r"/var/log/|/var/spool/cron|/etc/init\.d/")


def _dur(sec):
    sec = int(abs(sec))
    return f"{sec} s" if sec < 120 else f"{sec // 60} min" if sec < 7200 else f"{sec / 3600:.1f} h" if sec < 172800 else f"{sec / 86400:.1f} days"


# -------------------------------------------------------- per-file analysis ---
class HostFile:
    """Collects facts, findings and decoded text for one artifact while its lines stream by."""

    def __init__(self, kind, rel, mtime_ts):
        self.kind, self.rel, self.mtime_ts = kind, rel, mtime_ts
        self.owner = owner_from_path(rel)
        self.findings = []   # (rule, line_no, ts, ts_end, snippet, detail)
        self.facts = []      # (kind, line_no, ts, subject, data)
        self.decoded = []    # (line_no, method, text)
        self.st = {}
        self.fn = getattr(self, "f_" + kind, None)
        self.traffic = traffic.Traffic(kind) if kind in ("mail_log", "auth_log", "kern_log", "mail_queue") else None
        self.dhcp = traffic.Traffic("auth_log") if kind == "auth_log" else None  # syslog carries dhcpd messages
        self.web = webaccess.WebLog(rel) if kind == "web_access" else None

    def feed(self, n, line, ts):
        if not line:
            return
        try:
            if self.fn:
                self.fn(n, line, ts)
            if self.traffic:
                self.traffic.feed(n, line, ts)
            if self.traffic and hasattr(self.traffic, 'feed_dhcp') and ts:
                self.traffic.feed_dhcp(ts, n, line)
            if self.web:
                self.web.feed(n, line, ts)
        except (ValueError, IndexError, UnicodeDecodeError, struct.error):
            pass

    def finish(self):
        end = getattr(self, "end_" + self.kind, None)
        if end:
            end()
        if self.traffic:
            self.facts.extend(self.traffic.facts())
            q = self.traffic.qnames
            if q:
                for t in webaccess.dns_tunnel_check(x[2] for x in q):
                    first = next((x for x in q if x[2].strip(".").lower().endswith(t["domain"])), q[0])
                    self.find("dns_tunnel", first[0], first[1],
                              f"{t['domain']}: {t['unique']:,} different subdomains in {t['queries']:,} queries, labels {t['avg_label']} chars "
                              f"on average (entropy {t['entropy']}), e.g. {t['examples'][0][:80]}")
        if self.web:
            self.facts.extend(self.web.facts())
            for rule, n, ts, snip in self.web.finds:
                self.find(rule, n, ts, snip)
        return self

    _TUN_KEYS = re.compile(r"(?i)^\s*(HiddenServiceDir|HiddenServicePort|SocksPort|ORPort|Endpoint|AllowedIPs|PersistentKeepalive|remote\s|"
                           r"server_addr|serverAddr|server_port|remote_port|local_port|tunnel:|credentials-file|authtoken|"
                           r"proto\s|connect\s*=|accept\s*=|ProxyCommand|LocalForward|RemoteForward|DynamicForward|"
                           r"\d{1,3}(?:\.\d{1,3}){3}\s+\d+\s+\S+\s+\d+)")

    def f_tunnel_config(self, n, line, ts):
        s_ = line.strip()
        if n == 1 or not self.st.get("announced"):
            name = self.rel.rsplit("/", 1)[-1]
            kind = ("Tor" if "tor" in self.rel else "WireGuard" if "wireguard" in self.rel else "OpenVPN" if "openvpn" in self.rel or
                    self.rel.lower().endswith(".ovpn") else "frp" if "frp" in name.lower() else "cloudflared" if "cloudflared" in self.rel else
                    "ngrok" if "ngrok" in self.rel else "Tailscale" if "tailscale" in self.rel else "ZeroTier" if "zerotier" in self.rel else
                    "rinetd" if "rinetd" in self.rel else "SOCKS proxy" if "3proxy" in name or "danted" in name else
                    "stunnel" if "stunnel" in self.rel else "SSH client config")
            self.st["announced"] = True
            self.st["kind"] = kind
            if kind != "SSH client config":
                self.find("tunnel_installed", n, self.mtime_ts, f"{kind} configuration {self.rel} (last changed {self.mtime_ts} UTC)")
        if s_ and not s_.startswith(("#", ";")) and self._TUN_KEYS.search(s_):
            if self.st.get("kind") == "SSH client config" and not re.search(r"(?i)RemoteForward|DynamicForward|ProxyCommand", s_):
                return
            self.fact("channel_config", n, self.mtime_ts, self.st.get("kind", "?"), entry=s_[:300], file=self.rel)
            if self.st.get("kind") == "SSH client config":
                self.find("tunnel_installed", n, self.mtime_ts, f"SSH forwarding configured in {self.rel}: {s_[:200]}")
            elif re.search(r"(?i)HiddenServicePort|Endpoint|^remote\s|server_addr|serverAddr|tunnel:|RemoteForward", s_):
                self.find("tunnel_installed", n, self.mtime_ts, f"{self.st.get('kind')}: {s_[:200]} ({self.rel})")

    def find(self, rule, n, ts, snippet, ts_end=None, detail=None):
        self.findings.append((rule, n, ts, ts_end, snippet[:600], json.dumps(detail) if detail else None))

    def fact(self, kind, n, ts, subject, **data):
        self.facts.append((kind, n, ts, subject, data))

    # --- accounts ----------------------------------------------------------
    def f_passwd(self, n, line, ts):
        if line.startswith("#"):
            return
        p = line.split(":")
        if len(p) < 7:
            return
        self.fact("account", n, None, p[0], uid=int(p[2]), gid=int(p[3]), gecos=p[4], home=p[5], shell=p[6],
                  pw_field=p[1], backup=self.rel.endswith("-"))

    def f_shadow(self, n, line, ts):
        p = line.split(":")
        if len(p) < 3:
            return
        h = p[1]
        status = "empty" if h == "" else "locked" if h.startswith(("!", "*")) else "set"
        algo = {"$1$": "MD5", "$2": "bcrypt", "$5$": "SHA-256", "$6$": "SHA-512", "$y$": "yescrypt", "$7$": "scrypt",
                "$gy$": "gost-yescrypt"}
        a = next((v for k, v in algo.items() if h.lstrip("!").startswith(k)), "DES" if status == "set" and len(h) == 13 else None)
        chg = az.epoch_to_ts(int(p[2]) * 86400) if len(p) > 2 and p[2].isdigit() else None
        self.fact("shadow", n, chg, p[0], status=status, algo=a, backup=self.rel.endswith("-"),
                  expires=p[7] if len(p) > 7 else "")

    def f_group(self, n, line, ts):
        p = line.split(":")
        if len(p) < 4:
            return
        members = [m for m in p[3].split(",") if m]
        self.fact("group", n, None, p[0], gid=int(p[2]) if p[2].isdigit() else None, members=members,
                  backup=self.rel.endswith("-"))

    def f_sudoers(self, n, line, ts):
        s = line.strip()
        if not s or (s.startswith("#") and not s.startswith(("#include", "#includedir"))):
            return
        if s.startswith("Defaults"):
            if re.search(r"!\s*(?:syslog|logfile|log_input|log_output|use_pty)\b|\blogfile\s*=\s*/dev/null", s):
                self.find("sudo_logging_off", n, self.mtime_ts, s)
            self.fact("sudo_rule", n, None, "Defaults", rule=s)
            return
        m = re.match(r"(\S+)\s+(\S+)\s*=\s*(\([^)]*\))?\s*((?:\w+:\s*)*)(.*)$", s)
        if m:
            who, tags, cmds = m.group(1), m.group(4) or "", m.group(5)
            nopw = "NOPASSWD" in tags
            self.fact("sudo_rule", n, None, who, rule=s, nopasswd=nopw, runas=m.group(3) or "", commands=cmds)
            if nopw and re.search(r"\bALL\b", cmds):
                self.find("sudo_nopasswd", n, self.mtime_ts, s)

    # --- ssh ---------------------------------------------------------------
    def f_authorized_keys(self, n, line, ts):
        s = line.strip()
        if not s or s.startswith("#"):
            return
        m = re.search(r"(?:^|\s)((?:ssh-(?:rsa|dss|ed25519)|ecdsa-sha2-\S+|sk-\S+@openssh\.com))\s+([A-Za-z0-9+/=]{40,})(?:\s+(.*))?$", s)
        if not m:
            return
        opts = s[:m.start(1)].strip()
        fp = ssh_fingerprint(m.group(2))
        owner = self.owner or "?"
        self.fact("ssh_key", n, self.mtime_ts, owner, type=m.group(1), fingerprint=fp, comment=m.group(3) or "",
                  options=opts, file=self.rel)
        desc = f"{owner}: {m.group(1)} {fp} {m.group(3) or ''}".strip()
        if opts and re.search(r"command=|environment=|permitopen|no-pty|from=", opts):
            self.find("ssh_key_options", n, self.mtime_ts, f"{desc} with options {opts[:200]}")
        elif owner == "root":
            self.find("ssh_key_root", n, self.mtime_ts, desc)
        else:
            self.find("ssh_key", n, self.mtime_ts, desc)

    def f_sshd_config(self, n, line, ts):
        s = line.strip()
        if not s or s.startswith("#"):
            return
        parts = s.split(None, 1)
        if len(parts) < 2:
            return
        k, v = parts[0].lower(), parts[1].strip()
        self.fact("ssh_config", n, None, parts[0], value=v, file=self.rel)
        risky = {
            "permitrootlogin": v.lower() == "yes",
            "permitemptypasswords": v.lower() == "yes",
            "authorizedkeysfile": not set(v.split()) <= {".ssh/authorized_keys", ".ssh/authorized_keys2", "%h/.ssh/authorized_keys"},
            "authorizedkeyscommand": v.lower() != "none",
            "permituserenvironment": v.lower() == "yes",
            "gatewayports": v.lower() in ("yes", "clientspecified"),
            "passwordauthentication": v.lower() == "yes",
            "usepam": v.lower() == "no",
            "permittunnel": v.lower() in ("yes", "point-to-point", "ethernet"),
        }
        if k in ("loglevel",) and v.upper() in ("QUIET", "FATAL", "ERROR"):
            self.find("sshd_quiet", n, self.mtime_ts, s)
        elif k == "port":
            self.st.setdefault("ports", []).append((n, v))
        elif risky.get(k):
            self.find("sshd_risky", n, self.mtime_ts, s)

    def end_sshd_config(self):
        ports = self.st.get("ports", [])
        if len(ports) > 1 or any(p != "22" for _n, p in ports):
            for n, p in ports:
                self.find("sshd_port", n, self.mtime_ts, f"Port {p}" + (" (one of several)" if len(ports) > 1 else ""))

    def f_known_hosts(self, n, line, ts):
        s = line.strip()
        if not s or s.startswith("#"):
            return
        host = s.split()[0]
        hashed = host.startswith("|1|")
        self.fact("net_contact", n, None, "(hashed)" if hashed else host, via="ssh known_hosts",
                  owner=self.owner, hashed=hashed)

    def f_wget_hsts(self, n, line, ts):
        if line.startswith("#"):
            return
        p = line.split()
        if len(p) >= 4 and p[3].isdigit():
            t = az.epoch_to_ts(int(p[3]))
            self.fact("net_contact", n, t, p[0], via="wget (HSTS cache)", owner=self.owner)

    # --- persistence -----------------------------------------------------------
    def f_cron(self, n, line, ts):
        s = line.strip()
        if not s or s.startswith("#"):
            return
        is_script = "/cron." in self.rel and not self.rel.endswith(("crontab", "anacrontab")) and "/cron.d/" not in self.rel
        if is_script:
            r = suspicious_reasons(s)
            if r and is_strong(r):
                self.find("cron_suspicious", n, self.mtime_ts, f"{self.rel}: {s}  [{', '.join(r)}]")
                self.fact("persistence", n, self.mtime_ts, self.rel, mechanism="cron script", entry=s, reasons=r)
            return
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*\s*=", s):  # MAILTO=, PATH=
            if re.match(r"^(?:LD_PRELOAD|PATH)\s*=.*(?:/tmp|/dev/shm|/\.)", s):
                self.find("cron_suspicious", n, self.mtime_ts, s)
            return
        system_fmt = "/cron.d/" in self.rel or self.rel.endswith("/crontab") or self.rel == "crontab"
        if s.startswith("@"):
            f = s.split(None, 2 if system_fmt else 1)
            sched, user, cmd = f[0], (f[1] if system_fmt and len(f) > 2 else self.owner), f[-1]
        else:
            f = s.split(None, 6 if system_fmt else 5)
            if len(f) < (7 if system_fmt else 6):
                return
            sched = " ".join(f[:5])
            user, cmd = (f[5], f[6]) if system_fmt else (self.owner, f[5])
        r = suspicious_reasons(cmd)
        self.fact("persistence", n, self.mtime_ts, user or "?", mechanism="cron", schedule=sched, entry=cmd,
                  file=self.rel, reasons=r)
        if r:
            self.find("cron_suspicious", n, self.mtime_ts, f"[{user}] {sched} {cmd}  [{', '.join(r)}]")
        elif "/var/spool/cron" in self.rel:
            self.find("cron_entry", n, self.mtime_ts, f"[{user}] {sched} {cmd}")

    def f_systemd_unit(self, n, line, ts):
        s = line.strip()
        m = re.match(r"(Exec\w*)\s*=\s*(.+)$", s)
        if not m:
            if s.startswith("Description="):
                self.st["desc"] = s.split("=", 1)[1]
            return
        cmd = m.group(2)
        binary = cmd.lstrip("-@:+!").split()[0] if cmd.strip() else ""
        r = suspicious_reasons(cmd)
        if re.match(r"(/tmp|/var/tmp|/dev/shm|/home|/root|/run/user)/", binary) or "/." in binary:
            r.append("program lives in a user or temporary folder")
        unit = self.rel.rsplit("/", 1)[-1]
        self.fact("persistence", n, self.mtime_ts, unit, mechanism="systemd", entry=f"{m.group(1)}={cmd}",
                  file=self.rel, reasons=r, user_unit="/user/" in self.rel)
        if r:
            self.find("systemd_suspicious", n, self.mtime_ts, f"{unit}: {m.group(1)}={cmd}  [{', '.join(r)}]")
        elif "/user/" in self.rel and m.group(1) == "ExecStart":
            self.find("systemd_user_unit", n, self.mtime_ts, f"{self.rel}: {cmd}")

    def f_initscript(self, n, line, ts):
        s = line.strip()
        if not s or s.startswith("#") or s in ("exit 0", "exit"):
            return
        r = suspicious_reasons(s)
        if self.rel.endswith("rc.local"):
            self.fact("persistence", n, self.mtime_ts, "rc.local", mechanism="rc.local", entry=s, reasons=r)
            self.find("initscript_suspicious" if r else "initscript_entry", n, self.mtime_ts,
                      s + (f"  [{', '.join(r)}]" if r else ""))
        elif r and is_strong(r):
            self.fact("persistence", n, self.mtime_ts, self.rel, mechanism="init.d", entry=s, reasons=r)
            self.find("initscript_suspicious", n, self.mtime_ts, f"{self.rel}: {s}  [{', '.join(r)}]")

    _RC_HIJACK = re.compile(r"^\s*alias\s+(sudo|su|ssh|scp|ls|ps|netstat|ss|top|htop|lsof|find|history|w|who|last|passwd|cat|kill)=", re.I)
    _RC_OTHER = re.compile(r"\bLD_PRELOAD\s*=|\bPROMPT_COMMAND\s*=|\btrap\s+.+\bDEBUG\b|export\s+PATH\s*=\s*['\"]?(?:/tmp|/dev/shm|/var/tmp|\.:|~/\.|\$HOME/\.)|\bLD_LIBRARY_PATH\s*=.*(?:/tmp|/dev/shm|/\.)", re.I)

    def f_shellrc(self, n, line, ts):
        s = line.strip()
        if not s or s.startswith("#"):
            return
        why = []
        m = self._RC_HIJACK.match(s)
        if m:
            why.append(f"replaces the '{m.group(1)}' command")
        if self._RC_OTHER.search(s):
            why.append("changes how every command runs")
        r = suspicious_reasons(s)
        if is_strong(r) or why:
            why += r
            self.fact("persistence", n, self.mtime_ts, self.owner or self.rel, mechanism="shell startup", entry=s, file=self.rel, reasons=why)
            self.find("shellrc_suspicious", n, self.mtime_ts, f"{self.rel}: {s}  [{', '.join(why)}]")

    def f_ld_preload(self, n, line, ts):
        s = line.strip()
        if s and not s.startswith("#"):
            self.fact("persistence", n, self.mtime_ts, "ld.so.preload", mechanism="ld.so.preload", entry=s, reasons=["preloaded into every process"])
            self.find("ld_preload", n, self.mtime_ts, s)

    def f_pam(self, n, line, ts):
        s = line.strip()
        if not s or s.startswith("#") or s.startswith("@include"):
            return
        p = s.split()
        if len(p) < 3:
            return
        typ, ctrl, mod = p[0].lstrip("-"), p[1], p[2]
        why = []
        if "pam_exec.so" in mod:
            why.append("runs an external program during login")
        if "pam_permit.so" in mod and typ == "auth" and ctrl in ("sufficient", "required", "[success=done", "requisite"):
            why.append("lets anyone authenticate")
        if mod.startswith("/") and not re.match(r"^/(?:usr/)?lib(?:64)?/(?:[\w-]+/)?security/", mod):
            why.append("module loaded from an unusual path")
        if why:
            self.fact("persistence", n, self.mtime_ts, self.rel.rsplit("/", 1)[-1], mechanism="PAM", entry=s, reasons=why)
            self.find("pam_suspicious", n, self.mtime_ts, f"{self.rel}: {s}  [{', '.join(why)}]")

    def f_modules(self, n, line, ts):
        s = line.strip()
        if s and not s.startswith("#"):
            self.fact("persistence", n, self.mtime_ts, s.split()[0], mechanism="kernel module at boot", entry=s, reasons=[])
            self.find("kernel_module_boot", n, self.mtime_ts, f"{self.rel}: {s}")

    # --- logs -----------------------------------------------------------------
    def f_auth_log(self, n, line, ts):
        if "sshd[" in line:
            m = R_ACCEPT.search(line)
            if m:
                method, user, ip, port, ktype, fp = m.groups()
                self.fact("login", n, ts, user, ip=ip, port=int(port), method=method, result="success",
                          key_type=ktype, fingerprint=fp, via="sshd")
                return
            m = R_FAIL.search(line)
            if m:
                method, inv, user, ip, port = m.groups()
                self.fact("login", n, ts, user or "?", ip=ip, port=int(port), method=method,
                          result="invalid" if inv else "failed", via="sshd")
                return
            m = R_INVALID.search(line)
            if m:
                self.fact("login", n, ts, m.group(1) or "?", ip=m.group(2), method="", result="invalid", via="sshd")
                return
            m = R_LISTEN.search(line)
            if m:
                self.fact("sshd_listen", n, ts, m.group(2), address=m.group(1))
                return
        if "sudo" in line:
            m = R_SUDO.search(line)
            if m:
                user, pre, tty, pwd, target, cmd = m.groups()
                ok = not pre.strip()
                self.fact("sudo", n, ts, user, target=target, command=cmd or "", cwd=pwd, tty=tty or "", ok=ok,
                          problem=pre.strip(" ;"))
                if not ok:
                    self.find("sudo_denied", n, ts, f"{user} → {target}: {pre.strip(' ;')} ({cmd or ''})")
                return
        if "su" in line:
            m = R_SU.search(line)
            if m:
                g = m.groups()
                if g[0]:
                    self.fact("su", n, ts, g[1], target=g[0], tty=g[2], ok=True)
                elif g[3]:
                    self.fact("su", n, ts, g[4] or "?", target=g[3], ok=True)
                elif g[5]:
                    self.fact("su", n, ts, g[6], target=g[5], tty=g[7], ok=False)
                return
        for rx, what in ((R_USERADD, "created"), (R_GROUPMEM, "group"), (R_PASSWD, "password"),
                         (R_USERDEL, "deleted"), (R_USERMOD, "modified")):
            m = rx.search(line)
            if not m:
                continue
            g = m.groups()
            if what == "created":
                self.fact("account_change", n, ts, g[0], change="created", uid=int(g[1]), home=g[3], shell=g[4])
            elif what == "group":
                self.fact("account_change", n, ts, g[0], change=f"added to group {g[1]}")
            elif what == "password":
                self.fact("account_change", n, ts, g[0], change="password changed")
            elif what == "deleted":
                self.fact("account_change", n, ts, g[0], change="deleted")
                self.find("account_removed", n, ts, f"account {g[0]} deleted")
            else:
                who = g[0] or g[4] or g[5]
                change = f"{g[1]} changed" + (f" from '{g[2]}' to '{g[3]}'" if g[2] is not None else "") if g[0] else \
                    ("password locked" if g[4] else "password unlocked")
                self.fact("account_change", n, ts, who, change=change)
            return

    def f_audit_log(self, n, line, ts):
        m = R_AUDIT.search(line)
        if not m:
            return
        typ, epoch, serial, rest = m.group(1), int(m.group(2)), m.group(3), m.group(4)
        t = ts or az.epoch_to_ts(epoch)
        kv = {k: v.strip("\"'") for k, v in R_KV.findall(rest)}
        ev = self.st.setdefault("ev", {})
        if typ == "SYSCALL":
            ev.setdefault(serial, {}).update({k: kv.get(k) for k in ("auid", "uid", "euid", "exe", "comm", "success", "key", "tty")})
        elif typ == "EXECVE":
            args = []
            raw = dict(R_KV.findall(rest))
            i = 0
            while f"a{i}" in raw:
                v = raw[f"a{i}"]
                if v.startswith('"'):
                    args.append(v.strip('"'))
                else:
                    try:
                        args.append(bytes.fromhex(v).decode("utf-8", "replace"))
                    except ValueError:
                        args.append(v)
                i += 1
            cmd = " ".join(args)
            e = ev.setdefault(serial, {})
            e.update(cmd=cmd, line=n, ts=t)
        elif typ == "CWD":
            ev.setdefault(serial, {})["cwd"] = kv.get("cwd")
        elif typ == "PROCTITLE":
            v = dict(R_KV.findall(rest)).get("proctitle", "")
            if v and not v.startswith('"'):
                try:
                    title = bytes.fromhex(v).replace(b"\x00", b" ").decode("utf-8", "replace").strip()
                    e = ev.setdefault(serial, {})
                    e.setdefault("cmd", title)
                    e.setdefault("line", n)
                    e.setdefault("ts", t)
                except ValueError:
                    pass
        elif typ in ("USER_LOGIN", "USER_AUTH", "USER_ERR"):
            inner = dict(R_KV.findall(rest.replace("msg='", "").rstrip("'")))
            acct = (inner.get("acct") or inner.get("id") or "?").strip('"')
            addr = inner.get("addr", "?")
            res = inner.get("res", "").strip("'")
            if typ == "USER_LOGIN" or res.startswith("failed"):
                self.fact("login", n, t, acct, ip=addr, method=(inner.get("exe") or "").strip('"').rsplit("/", 1)[-1],
                          result="success" if res.startswith("success") else "failed", via="auditd")
        elif typ in ("ADD_USER", "DEL_USER", "ADD_GROUP", "DEL_GROUP", "USER_CHAUTHTOK", "USER_MGMT", "GRP_MGMT"):
            inner = dict(R_KV.findall(rest.replace("msg='", "").rstrip("'")))
            who = (inner.get("acct") or inner.get("id") or "?").strip('"')
            op = (inner.get("op") or typ).strip('"')
            self.fact("account_change", n, t, who, change=op, via="auditd")
        elif typ == "CONFIG_CHANGE":
            if re.search(r"op=(?:remove_rule|del_rule)|audit_enabled=0|op=set.*enabled=0", rest):
                self.find("audit_rules_changed", n, t, rest[:300])

    def end_audit_log(self):
        for serial, e in self.st.get("ev", {}).items():
            if not e.get("cmd"):
                continue
            self.fact("command", e.get("line"), e.get("ts"), e.get("auid") or "?", command=e["cmd"], exe=e.get("exe"),
                      uid=e.get("uid"), cwd=e.get("cwd"), via="auditd", success=e.get("success"))

    def f_apt_history(self, n, line, ts):
        s = line.strip()
        if s.startswith("Start-Date:"):
            d = re.sub(r"\s+", " ", s.split(":", 1)[1].strip())
            self.st["blk"] = {"ts": az.parse_timestamp(d), "line": n}
        elif ":" in s and "blk" in self.st:
            k, v = s.split(":", 1)
            blk = self.st["blk"]
            if k in ("Commandline", "Requested-By"):
                blk[k] = v.strip()
            elif k in ("Install", "Upgrade", "Remove", "Purge", "Reinstall", "Downgrade"):
                for pm in R_APT_PKG.finditer(v):
                    pkg, arch, ver = pm.groups()
                    self._package(n, blk["ts"], pkg, k.lower(), ver, blk.get("Requested-By", ""), blk.get("Commandline", ""), "apt")

    def f_dpkg_log(self, n, line, ts):
        m = R_DPKG.match(line)
        if m:
            t, action, pkg, arch, old, new = m.groups()
            self._package(n, t, pkg, action, new if new != "<none>" else old, "", "", "dpkg")

    def _package(self, n, ts, pkg, action, ver, who, cmdline, via):
        self.fact("package", n, ts, pkg, action=action, version=ver, requested_by=who, commandline=cmdline, via=via)


    def f_viminfo(self, n, line, ts):
        if line.startswith("> "):
            self.st["file"] = (line[2:].strip(), n)
        elif line.startswith("\t*\t") and "file" in self.st:
            p = line.split("\t")
            if len(p) > 2 and p[2].isdigit():
                path, ln = self.st.pop("file")
                t = az.epoch_to_ts(int(p[2]))
                path = path.replace("~", f"/home/{self.owner}" if self.owner and self.owner != "root" else "/root", 1)
                self.fact("file_edited", ln, t, path, via="vim", owner=self.owner)
                if SENSITIVE_EDIT.search(path):
                    self.find("vim_edited_sensitive", ln, t, f"{self.owner or '?'} edited {path} at {t}")
        elif line.startswith(":") and len(line) > 1:
            self.st["cmd"] = (line[1:], n)
        elif line.startswith("|2,") and "cmd" in self.st:
            m = re.match(r"\|2,\d+,(\d{9,10}),", line)
            cmd, ln = self.st.pop("cmd")
            t = az.epoch_to_ts(int(m.group(1))) if m else None
            self.fact("command", ln, t, self.owner or "?", command=":" + cmd, via="vim command line")

    def f_host_info(self, n, line, ts):
        name = self.rel.rsplit("/", 1)[-1]
        s = line.strip()
        if name == "os-release":
            m = re.match(r'(PRETTY_NAME|VERSION_CODENAME)="?([^"]*)"?', s)
            if m:
                self.fact("host", n, None, m.group(1).lower(), value=m.group(2))
        elif s and n == 1:
            self.fact("host", n, None, {"debian_version": "debian_version", "hostname": "hostname",
                                        "timezone": "timezone"}.get(name, name), value=s)


# --------------------------------------------------------- binary artifacts ---
UTMP_SIZE = 384
UT_TYPES = {0: "EMPTY", 1: "RUN_LVL", 2: "BOOT_TIME", 3: "NEW_TIME", 4: "OLD_TIME", 5: "INIT", 6: "LOGIN",
            7: "USER", 8: "DEAD", 9: "ACCOUNTING"}


def _cstr(b):
    return b.split(b"\x00", 1)[0].decode("utf-8", "replace")


class UtmpReader:
    """wtmp / btmp / utmp: one line per record. Zeroed records (what log cleaners leave) and
    out-of-order records are tracked for the integrity findings."""

    def __init__(self, path, rel):
        self.path, self.rel = path, rel
        self.failed = "btmp" in rel.rsplit("/", 1)[-1]
        self.hf = HostFile("utmp", rel, None)
        self.info = {"records": 0, "zeroed": 0, "partial_bytes": 0}

    def lines(self):
        data = art.read_decoded(self.path)
        n_rec = len(data) // UTMP_SIZE
        self.info["partial_bytes"] = len(data) % UTMP_SIZE
        prev_t = None
        prev_ts = None
        zero_run = None  # [first_index, count, ts_before]
        max_t = 0
        for i in range(n_rec):
            rec = data[i * UTMP_SIZE:(i + 1) * UTMP_SIZE]
            n = i + 1
            if not rec.strip(b"\x00"):
                self.info["zeroed"] += 1
                if zero_run is None:
                    zero_run = [n, 0, prev_ts]
                zero_run[1] += 1
                yield (f"[record {n}] ZEROED: all 384 bytes are NUL (entry wiped)", None)
                continue
            typ, pid = struct.unpack_from("<hxxi", rec, 0)
            line_, user, host = _cstr(rec[8:40]), _cstr(rec[44:76]), _cstr(rec[76:332])
            sec, usec = struct.unpack_from("<ii", rec, 340)
            addr = rec[348:364]
            ip = ""
            if addr.strip(b"\x00"):
                ip = str(ipaddress.IPv4Address(addr[:4])) if not addr[4:].strip(b"\x00") else str(ipaddress.IPv6Address(addr))
            ts = az.epoch_to_ts(sec + usec / 1e6) if sec > 0 else None
            if zero_run is not None:
                self.hf.find("wtmp_wiped", zero_run[0], zero_run[2], f"{zero_run[1]} record(s) starting at record "
                             f"{zero_run[0]} wiped, between {zero_run[2] or 'the start'} and {ts or '?'}", ts_end=ts)
                zero_run = None
            tname = UT_TYPES.get(typ, str(typ))
            self.info["records"] += 1
            if sec and max_t and sec < max_t - 300 and typ in (7, 8, 6):
                self.hf.find("wtmp_backwards", n, ts, f"record {n} ({tname} {user}) dated {ts}, "
                             f"{_dur(max_t - sec)} before earlier records")
            max_t = max(max_t, sec)
            if typ == 7 or (self.failed and typ in (6, 7)):
                self.hf.fact("login", n, ts, user or "?", ip=ip or host, host=host, tty=line_,
                             result="failed" if self.failed else "session", via=self.rel.rsplit("/", 1)[-1], pid=pid)
            elif typ == 2:
                self.hf.fact("boot", n, ts, "reboot", kernel=host)
            prev_t, prev_ts = sec, ts
            yield (f"{tname:9} user={user} tty={line_} host={host} ip={ip} pid={pid}", ts)
        if zero_run is not None:
            self.hf.find("wtmp_wiped", zero_run[0], zero_run[2], f"last {zero_run[1]} record(s) wiped, "
                         f"after {zero_run[2] or 'the start'}")
        if self.info["partial_bytes"]:
            self.hf.find("utmp_truncated", n_rec + 1, None, f"{self.info['partial_bytes']} bytes left over after "
                         f"{n_rec} whole records: cut or edited by hand")


class LastlogReader:
    def __init__(self, path, rel):
        self.path, self.rel = path, rel
        self.hf = HostFile("lastlog", rel, None)

    def lines(self):
        data = art.read_decoded(self.path)
        size = 292
        for uid in range(len(data) // size):
            rec = data[uid * size:(uid + 1) * size]
            t = struct.unpack_from("<i", rec, 0)[0]
            if not t:
                continue
            ts = az.epoch_to_ts(t)
            line_, host = _cstr(rec[4:36]), _cstr(rec[36:292])
            self.hf.fact("lastlog", uid + 1, ts, str(uid), uid=uid, tty=line_, host=host)
            yield (f"uid={uid} last login {ts} UTC on {line_} from {host}", ts)


def tz_from_tzif(path):
    try:
        data = open(path, "rb").read()
    except OSError:
        return None
    if not data.startswith(b"TZif"):
        return None
    tail = data.rstrip(b"\n").rsplit(b"\n", 1)[-1]
    try:
        s = tail.decode("ascii")
    except UnicodeDecodeError:
        return None
    return s if 0 < len(s) < 80 else None


# ------------------------------------------------------------ whole case ---
def analyze_case(con, files):
    """Correlations across artifacts. Returns findings as
    (rule, file_id, line_no, ts, ts_end, snippet, detail) tuples."""
    out = []
    facts = {}
    for r in con.execute("SELECT kind, file_id, line_no, ts, subject, data FROM facts WHERE scope='file'"):
        d = json.loads(r["data"]) if r["data"] else {}
        d.update(_file=r["file_id"], _line=r["line_no"], _ts=r["ts"], _subject=r["subject"])
        facts.setdefault(r["kind"], []).append(d)

    # --- accounts
    accounts = [a for a in facts.get("account", []) if not a["backup"]]
    backups = [a for a in facts.get("account", []) if a["backup"]]
    shadow = {s["_subject"]: s for s in facts.get("shadow", []) if not s["backup"]}
    by_uid = {}
    for a in accounts:
        name, uid = a["_subject"], a["uid"]
        by_uid.setdefault(uid, []).append(a)
        sh = shadow.get(name)
        status = sh["status"] if sh else ("set" if a["pw_field"] not in ("x", "*", "!", "") else "empty" if a["pw_field"] == "" else None)
        if 0 < uid < 1000 and not NOLOGIN.search(a["shell"]) and status == "set":
            out.append(("system_account_shell", a["_file"], a["_line"], sh["_ts"] if sh else None, None,
                        f"{name} (UID {uid}) has shell {a['shell']} and a password", None))
        if status == "empty" and not NOLOGIN.search(a["shell"]):
            out.append(("empty_password", (sh or a)["_file"], (sh or a)["_line"], None, None, f"{name} can log in without a password", None))
        if sh and sh.get("algo") in ("MD5", "DES"):
            out.append(("weak_hash", sh["_file"], sh["_line"], sh["_ts"], None, f"{name}: {sh['algo']} password hash", None))
        if re.match(r"^/(tmp|var/tmp|dev/shm)(/|$)|/\.", a["home"]):
            out.append(("weird_home", a["_file"], a["_line"], None, None, f"{name} home is {a['home']}", None))
    for uid, lst in by_uid.items():
        if len(lst) > 1:
            out.append(("duplicate_uid", lst[0]["_file"], lst[0]["_line"], None, None,
                        f"UID {uid} used by {', '.join(x['_subject'] for x in lst)}", None))
    if backups and accounts:
        cur = {a["_subject"] for a in accounts}
        old = {a["_subject"] for a in backups}
        mt = {f["id"]: f for f in files}
        pf = accounts[0]["_file"]
        when = _ns_ts(mt.get(pf, {}).get("mtime_ns"))
        for name in sorted(cur - old):
            a = next(x for x in accounts if x["_subject"] == name)
            out.append(("account_added", a["_file"], a["_line"], when, None,
                        f"{name} (UID {a['uid']}) is in passwd but not in the backup passwd-: added at or before {when}", None))
        for name in sorted(old - cur):
            a = next(x for x in backups if x["_subject"] == name)
            out.append(("account_removed", a["_file"], a["_line"], when, None,
                        f"{name} (UID {a['uid']}) is only in the backup passwd-: deleted at or before {when}", None))
    for g in facts.get("group", []):
        if g["backup"]:
            continue
        for m in g["members"]:
            if g["_subject"] in ROOT_EQUIV_GROUPS:
                out.append(("root_equivalent_group", g["_file"], g["_line"], None, None, f"{m} is in group {g['_subject']}", None))
            elif g["_subject"] in PRIV_GROUPS:
                out.append(("privileged_group", g["_file"], g["_line"], None, None, f"{m} is in group {g['_subject']}", None))

    # --- logins: guessing, root from outside, keys no longer authorised
    uniq = {}
    for l in facts.get("login", []):
        if not l["_ts"]:
            continue
        res = "fail" if l["result"] in ("failed", "invalid") else l["result"]
        uniq.setdefault((l["_ts"], l["_subject"], l.get("ip"), res), l)
    logins = sorted(uniq.values(), key=lambda l: l["_ts"])
    fails, reported = {}, set()
    for l in logins:
        ip = l.get("ip") or "?"
        if l["result"] in ("failed", "invalid"):
            fails.setdefault(ip, []).append(l)
        elif l["result"] == "success":
            recent = [f for f in fails.get(ip, []) if (az.ts_to_epoch(l["_ts"]) or 0) - (az.ts_to_epoch(f["_ts"]) or 0) <= 86400]
            if len(recent) >= 10 and ip not in reported:
                reported.add(ip)
                users = sorted({f["_subject"] for f in recent})
                out.append(("brute_force_success", l["_file"], l["_line"], l["_ts"], None,
                            f"{ip}: {len(recent)} failed attempts ({', '.join(users[:6])}{'…' if len(users) > 6 else ''}) "
                            f"from {recent[0]['_ts']}, then {l['_subject']} logged in with {l.get('method') or 'a password'}", None))
            if l["_subject"] == "root" and is_public_ip(ip):
                out.append(("root_login_remote", l["_file"], l["_line"], l["_ts"], None,
                            f"root logged in from {ip} with {l.get('method')}", None))
    for ip, fl in fails.items():
        if len(fl) >= 20 and ip not in reported:
            out.append(("brute_force", fl[0]["_file"], fl[0]["_line"], fl[0]["_ts"], fl[-1]["_ts"],
                        f"{ip}: {len(fl)} failed logins for {len({f['_subject'] for f in fl})} usernames", None))
    known_fp = {k["fingerprint"] for k in facts.get("ssh_key", []) if k.get("fingerprint")}
    if known_fp:
        seen = set()
        for l in logins:
            fp = l.get("fingerprint")
            if l["result"] == "success" and fp and fp.startswith("SHA256:") and fp not in known_fp and fp not in seen:
                seen.add(fp)
                uses = [x for x in logins if x.get("fingerprint") == fp]
                out.append(("ssh_key_unknown_login", l["_file"], l["_line"], l["_ts"], uses[-1]["_ts"],
                            f"{l['_subject']} from {l['ip']} with {l.get('key_type')} key {fp}, used {len(uses)} time(s); "
                            f"no collected authorized_keys has it (removed after use, or kept elsewhere)", None))

    # --- floods and starvation, grouped into numbered episodes
    out += traffic.detect_episodes(con, files)

    # --- files on disk: dpkg verification, unowned programs, SUID, ELF in tmp, deceptive names
    out += _verify_packages(con, files)
    try:
        baseline.build(con, files)
    except Exception:
        pass
    for f in files:
        rel = f["rel"]
        parts = rel.split("/")
        if any(re.fullmatch(r"\.{3,}|\s.*|.*\s|\.\s.*|\.\.\s*.+", p) for p in parts):
            out.append(("weird_name", f["id"], None, _ns_ts(f["mtime_ns"]), None, f"'{rel}'", None))
        if (f.get("magic") or "").startswith("ELF") and re.search(r"(?:^|/)(?:tmp|var/tmp|dev/shm|run/shm)/|/\.[^/]+/", rel):
            out.append(("elf_in_tmp", f["id"], None, _ns_ts(f["mtime_ns"]), None, f"{rel} ({f['size']:,} bytes, sha256 {f['sha256'][:16]}…)", None))
    return out


def _ns_ts(ns):
    return az.epoch_to_ts(ns / 1e9) if ns else None


SYSTEM_BIN_DIRS = ("bin/", "sbin/", "usr/bin/", "usr/sbin/", "usr/local/bin/", "usr/local/sbin/")
SECURITY_CONFFILES = re.compile(r"^/etc/(ssh/|pam\.d/|sudoers|crontab|cron\.|rsyslog|audit/|ld\.so|profile|bash\.bashrc|"
                                r"security/|systemd/|login\.defs|nsswitch|hosts\.(allow|deny)|init\.d/)")


def _verify_packages(con, files):
    """Compare files with the checksums Debian recorded when each package was installed."""
    out = []
    info = [r for r in con.execute("SELECT id, rel FROM files WHERE rel LIKE '%var/lib/dpkg/info/%.md5sums' "
                                   "OR rel LIKE '%var/lib/dpkg/info/%.list'")]
    if not info:
        return out
    prefix = info[0]["rel"].split("var/lib/dpkg/info/")[0]
    by_rel = {f["rel"]: f for f in files}
    expected, owned = {}, set()
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
                    expected[prefix + p[1]] = (p[0], pkg)
                    owned.add(prefix + p[1])
            else:
                owned.add(prefix + t.lstrip("/"))
    # conffiles recorded in dpkg status
    for r in con.execute("SELECT id FROM files WHERE rel = ?", (prefix + "var/lib/dpkg/status",)):
        pkg = None
        for l in con.execute("SELECT text FROM lines WHERE file_id=? ORDER BY line_no", (r["id"],)):
            t = l[0] or ""
            if t.startswith("Package: "):
                pkg = t[9:].strip()
            m = re.match(r"^ (/\S+) ([0-9a-f]{32})(?: obsolete)?$", t)
            if m and SECURITY_CONFFILES.search(m.group(1)):
                f = by_rel.get(prefix + m.group(1).lstrip("/"))
                if f and f.get("md5") and f["md5"] != m.group(2):
                    out.append(("conffile_modified", f["id"], None, _ns_ts(f["mtime_ns"]), None,
                                f"{m.group(1)} (package {pkg}) differs from the installed default; last modified {_ns_ts(f['mtime_ns'])} UTC", None))
    checked = mismatched = 0
    mism = []
    for rel, (md5, pkg) in expected.items():
        f = by_rel.get(rel)
        if not f or not f.get("md5"):
            continue
        checked += 1
        if f["md5"] != md5:
            mismatched += 1
            mism.append((f, pkg, md5))
    bulk = checked >= 20 and mismatched / checked > 0.5
    for f, pkg, md5 in mism[:500]:
        note = " (most files differ: the collected packages may be a different version)" if bulk else ""
        out.append(("pkg_file_modified", f["id"], None, _ns_ts(f["mtime_ns"]), None,
                    f"/{f['rel'][len(prefix):]} from package {pkg}: md5 {f['md5']} expected {md5}; modified "
                    f"{_ns_ts(f['mtime_ns'])} UTC{note}", None))
    if owned:
        for f in files:
            rel = f["rel"]
            if not rel.startswith(prefix):
                continue
            sub = rel[len(prefix):]
            is_elf = (f.get("magic") or "").startswith("ELF")
            if rel in owned:
                continue
            if sub.startswith(SYSTEM_BIN_DIRS) and "/" not in sub.split("/", 2)[-1] and (is_elf or f["size"] < 1_000_000):
                local = sub.startswith("usr/local/")
                if not local or is_elf:
                    out.append(("unowned_binary", f["id"], None, _ns_ts(f["mtime_ns"]), None,
                                f"/{sub} ({'ELF program' if is_elf else 'script or file'}) is not listed in any package; "
                                f"modified {_ns_ts(f['mtime_ns'])} UTC", None))
            elif is_elf and re.match(r"(?:usr/)?lib(?:64)?/(?:[\w-]+/)?security/pam_", sub):
                out.append(("pam_suspicious", f["id"], None, _ns_ts(f["mtime_ns"]), None,
                            f"/{sub}: PAM module not installed by any package", None))
            elif re.match(r"(?:etc|usr/lib|lib)/systemd/system/[^/]+\.(service|timer)$", sub):
                out.append(("systemd_unit_unowned", f["id"], None, _ns_ts(f["mtime_ns"]), None,
                            f"/{sub} not installed by any package; modified {_ns_ts(f['mtime_ns'])} UTC", None))
    # SUID / SGID (only if modes survived the copy)
    modes = {f["mode"] & 0o7777 for f in files if f.get("mode")}
    if len(modes) > 2:
        for f in files:
            m = f.get("mode") or 0
            if m & 0o6000 and not f["rel"].startswith(prefix + "proc/"):
                unusual = not f["rel"].startswith(tuple(prefix + d for d in ("bin/", "sbin/", "usr/bin/", "usr/sbin/", "usr/lib/", "lib/")))
                if unusual or (owned and f["rel"] not in owned):
                    out.append(("suid_unusual", f["id"], None, _ns_ts(f["mtime_ns"]), None,
                                f"/{f['rel'][len(prefix):]} mode {oct(m & 0o7777)}; modified {_ns_ts(f['mtime_ns'])} UTC", None))
    return out


# host findings that restate a line rule on the same line: the host version (with reasons) wins
SUPERSEDES = {
    "pam_suspicious": ("pam_backdoor",), "sshd_risky": ("ssh_config_weakened",), "sshd_quiet": ("ssh_config_weakened",),
    "sudo_nopasswd": ("sudoers_edit",), "sudo_logging_off": ("sudoers_edit",), "shellrc_suspicious": ("shell_hijack", "hiding"),
    "ld_preload": ("preload_rootkit",), "cron_suspicious": ("cron_reboot", "lolbin", "hiding", "reverse_shell", "tool_download"),
    "systemd_suspicious": ("hiding", "systemd_persistence"), "initscript_suspicious": ("hiding",),
}
