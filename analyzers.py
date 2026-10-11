"""
Auto-analysis: IOC / entity extraction, detection rules (including anti-forensics),
timestamp parsing, and the catalog of file- and case-level tampering checks.
Everything is plain regex + stdlib so it runs offline.
"""
import base64
import binascii
import calendar
import ipaddress
import re
from datetime import datetime, timezone

MAX_ANALYZE_CHARS = 20000  # regex analysis is limited to the first N chars of a line

# ---------------------------------------------------------------- entities ---
_TLDS = (
    "com|net|org|io|gov|edu|mil|int|info|biz|co|me|tv|cc|ws|su|us|uk|de|fr|it|es|nl|be|ch|at|pl|cz|sk|"
    "hu|ro|bg|ru|ua|by|kz|cn|jp|kr|in|ir|tr|br|ar|mx|ca|au|nz|za|ng|eu|asia|xyz|top|online|site|club|"
    "app|dev|cloud|ai|tech|live|shop|store|pw|tk|ml|ga|cf|gq|icu|buzz|link|click|work|onion|local|"
    "lan|internal|corp|home|arpa"
)

ENTITY_PATTERNS = {
    "ipv4": re.compile(
        r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?!\.?\d)"
    ),
    "ipv6": re.compile(r"(?<![\w:.])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:])"),
    "email": re.compile(r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b"),
    "url": re.compile(r"\b(?:https?|hxxps?|ftp|wss?)://[^\s\"'<>\[\]()`|]{3,}", re.I),
    "domain": re.compile(
        r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+(?:" + _TLDS + r")\b(?![.-]?\w)", re.I
    ),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "mac": re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b"),
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I),
    # tolerate JSON-escaped double backslashes (C:\\Windows\\...)
    "win_path": re.compile(r"\b[A-Za-z]:\\{1,2}(?:[^\\\s/:*?\"<>|,;]+\\{1,2})*[^\\\s/:*?\"<>|,;]*"),
    # patterns with a capture group store group(1)
    "user": re.compile(
        r"(?:\b(?:user(?:name)?|login|account|uid|acct)[\"']?\s*[:=]\s*[\"']?|"
        r"\bfor (?:invalid user |illegal user )?|\buser )([A-Za-z0-9._@\\$-]{2,64})",
        re.I,
    ),
}

# cheap substring pre-checks so we skip regexes that cannot match
_HINTS = {"ipv4": ".", "ipv6": ":", "email": "@", "url": "://", "domain": ".", "mac": None,
          "cve": "cve-", "win_path": ":\\"}

_USER_STOPWORDS = {
    "from", "to", "the", "a", "an", "is", "not", "on", "in", "and", "or", "null", "none", "true",
    "false", "unknown", "by", "with", "of", "id", "name", "agent", "user", "session", "request",
    "this", "that", "was", "has", "been", "invalid", "illegal", "at", "for",
}


def classify_ip(value):
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return None
    if ip.is_loopback:
        return "loopback"
    if ip.is_private:
        return "private"
    if ip.is_multicast:
        return "multicast"
    if ip.is_reserved or ip.is_unspecified or ip.is_link_local:
        return "reserved"
    return "public"


def extract_entities(text):
    """Yield (type, value, meta) tuples found in one line."""
    if len(text) > MAX_ANALYZE_CHARS:
        text = text[:MAX_ANALYZE_CHARS]
    seen = set()
    low = text.lower()
    for etype, rx in ENTITY_PATTERNS.items():
        hint = _HINTS.get(etype)
        if hint and hint not in low:
            continue
        for m in rx.finditer(text):
            value = m.group(1) if rx.groups else m.group(0)
            if not value:
                continue
            meta = None
            if etype == "ipv4":
                meta = classify_ip(value)
            elif etype == "ipv6":
                if value.count(":") < 2 or len(value) < 3:
                    continue
                try:
                    value = str(ipaddress.IPv6Address(value))
                except ValueError:
                    continue
                if value == "::":
                    continue
                meta = classify_ip(value)
            elif etype == "url":
                value = value.rstrip(".,;:'\"")
            elif etype == "domain":
                value = value.lower()
            elif etype in ("md5", "sha1", "sha256", "mac"):
                if len(set(value.lower())) < 5:  # 0000000..., ffffff...
                    continue
                value = value.lower()
            elif etype == "cve":
                value = value.upper()
            elif etype == "win_path":
                value = value.replace("\\\\", "\\")
                if len(value) <= 3:
                    continue
            elif etype == "user":
                value = value.strip("\"'.,;")
                if value.lower() in _USER_STOPWORDS or len(value) < 2:
                    continue
            key = (etype, value)
            if key in seen:
                continue
            seen.add(key)
            yield etype, value, meta


# -------------------------------------------------------------- categories ---
CATEGORIES = {
    # anti-forensics / tampering
    "deletion": "Deletion",
    "wiping": "Wiping & overwriting",
    "log_tampering": "Log tampering",
    "timestomp": "Timestamp manipulation",
    "defense_evasion": "Logging & defences disabled",
    "obfuscation": "Obfuscation & encoding",
    "hiding": "Hiding & disguise",
    "rename": "Renames & copies",
    "leftover": "Leftovers & traces",
    # attacker activity
    "access": "Initial access & logins",
    "persistence": "Persistence",
    "privilege": "Privilege & accounts",
    "credential": "Credential theft",
    "c2": "Tunnels, C2 & remote shells",
    "tooling": "Attacker tooling",
    "impact": "Mining & impact",
    # general
    "persistence": "Persistence",
    "credential": "Accounts & credentials",
    "lateral": "Lateral movement",
    "rootkit": "Rootkits & system tampering",
    "webshell": "Web shells",
    "miner": "Crypto mining",
    "dos": "Flooding & starvation",
    "sniffing": "Eavesdropping & interception",
    "secret": "Exposed secrets",
    "exfil": "Data exfiltration",
    "attack": "Attack patterns",
    "execution": "Suspicious execution",
    "auth": "Authentication",
    "recon": "Scanning & recon",
    "windows": "Windows events",
    "error": "Errors & crashes",
}
TAMPER_CATEGORIES = {"deletion", "wiping", "log_tampering", "timestomp", "defense_evasion",
                     "obfuscation", "hiding", "rename", "leftover", "rootkit"}
INTRUSION_CATEGORIES = {"persistence", "credential", "lateral", "rootkit", "webshell", "miner", "privilege",
                        "execution", "exfil", "attack", "auth", "recon", "access", "tooling", "impact", "c2", "dos", "sniffing"}
ACTIVITY_CATEGORIES = {"access", "persistence", "privilege", "credential", "c2", "tooling", "impact", "exfil", "execution", "recon", "attack", "secret"}
TIMELINE_CATEGORIES = TAMPER_CATEGORIES | ACTIVITY_CATEGORIES

# ------------------------------------------------------------ line rules ---
# (rule_id, severity, category, description, regex, pre-check substrings or None)
# The pre-check list must contain at least one substring that every match includes
# (compared against the lower-cased line), so skipping never loses a hit.
_RULES = [
    # --- secrets
    ("aws_access_key", "high", "secret", "AWS access key ID", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", ("akia", "asia")),
    ("private_key", "high", "secret", "Private key material",
     r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY", ("private key",)),
    ("github_token", "high", "secret", "GitHub token", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b", ("gh",)),
    ("slack_token", "high", "secret", "Slack token", r"\bxox[abprs]-[A-Za-z0-9-]{10,}", ("xox",)),
    ("generic_secret", "medium", "secret", "Password / secret / API key assignment",
     r"(?i)(?<![a-z])(?:pass(?:word|wd)?|secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)[\"']?\s*[:=]\s*[\"']?(?!chauthtok|session\b|auth\b|account\b)[^\s\"',;&)]{4,}",
     ("pass", "secret", "key", "token")),
    ("jwt", "medium", "secret", "JSON Web Token", r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}", ("eyj",)),
    # --- attacks
    ("sqli", "high", "attack", "SQL injection pattern",
     r"(?i)(\bunion\b(?:\s|%20|\+|/\*.*?\*/)+(?:all(?:\s|%20|\+)+)?select\b|'\s*or\s+'?1'?\s*=\s*'?1|\bor\s+1\s*=\s*1\b|(?:(?:\b|%20|\+)(?:and|or|select|if|waitfor)(?:\s|%20|\+|\()+|['\x22`]\s*(?:\|\||;|\+)?\s*)sleep\(\s*\d+\s*\)|\bbenchmark\(|information_schema|xp_cmdshell|\bwaitfor\s+delay\b)",
     ("select", "'", "or", "sleep", "benchmark", "information_schema", "xp_cmdshell", "waitfor")),
    ("xss", "medium", "attack", "Cross-site scripting pattern",
     r"(?i)(<script\b|%3Cscript|javascript:|\bonerror\s*=|\bonload\s*=|<svg[^>]*onload)", ("script", "javascript:", "onerror", "onload")),
    ("path_traversal", "medium", "attack", "Path traversal",
     r"(?i)(\.\./\.\./|\.\.\\\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f|%252e%252e)", ("..", "%2e", "%252e")),
    ("sensitive_file", "medium", "attack", "Access to sensitive file",
     r"(?i)(/etc/passwd|/etc/shadow|\\system32\\config\\sam|\bid_rsa\b|\.htpasswd|\bweb\.config\b|/\.env\b|/\.git/config|wp-config\.php)",
     ("passwd", "shadow", "sam", "id_rsa", "htpasswd", "web.config", ".env", ".git", "wp-config")),
    # --- execution
    ("encoded_powershell", "high", "obfuscation", "Encoded PowerShell command",
     r"(?i)powershell(?:\.exe)?\b.{0,200}?\s[-/]e(?:nc|ncodedcommand|n|c)?\s+[A-Za-z0-9+/=]{20,}", ("powershell",)),
    ("lolbin", "high", "execution", "Suspicious command / living-off-the-land binary",
     r"(?i)(\bmimikatz\b|sekurlsa::|certutil(?:\.exe)?\s+.*-urlcache|bitsadmin\s+/transfer|\bregsvr32\b.*scrobj|"
     r"\bwmic\b.*process\s+call\s+create|net\s+user\s+\S+\s+\S*\s*/add|"
     r"\bnc(?:at)?\s+-[a-z]*e\s|bash\s+-i\s*>&|/dev/tcp/\d|curl\s+[^|\n]{1,300}\|\s*(?:ba)?sh\b|"
     r"wget\s+[^|\n]{1,300}\|\s*(?:ba)?sh\b|chmod\s+\+x\s+/tmp/|\bIEX\s*\(|DownloadString\()",
     ("mimikatz", "sekurlsa", "certutil", "bitsadmin", "regsvr32", "wmic", "net", "nc", "bash", "/dev/tcp",
      "curl", "wget", "chmod", "iex", "downloadstring")),
    ("priv_escalation", "medium", "privilege", "Privilege change",
     r"(?i)(sudo:.*COMMAND=|session opened for user root|added to (?:the )?(?:group )?['\"]?(?:administrators|sudoers|wheel|domain admins))",
     ("sudo", "root", "added to")),
    ("win_event", "medium", "windows", "Notable Windows event ID",
     r"(?i)\bEvent_?ID[\"']?\s*[:=>]\s*[\"']?(4625|4648|4672|4720|4722|4724|4728|4732|4756|7045|4697|4698|4688)\b", ("event",)),
    ("auth_failure", "low", "auth", "Authentication failure",
     r"(?i)(failed password|authentication fail|invalid user|login failed|failed login|access denied|\b401\b.{0,40}unauthori[sz]ed|permission denied|bad password)",
     ("fail", "invalid", "denied", "unauthori", "bad password")),
    ("scanner", "low", "recon", "Scanner / offensive tool signature",
     r"(?i)\b(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|wpscan|hydra|metasploit|nuclei|zgrab|feroxbuster|ffuf|acunetix|burp\s?suite)\b",
     ("sqlmap", "nikto", "nmap", "masscan", "dirbuster", "gobuster", "wpscan", "hydra", "metasploit", "nuclei",
      "zgrab", "feroxbuster", "ffuf", "acunetix", "burp")),
    ("long_base64", "low", "obfuscation", "Long base64 blob", r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{160,}={0,2}", None),
    ("error", "info", "error", "Error / crash keyword",
     r"(?i)\b(critical|fatal|panic|segfault|unhandled exception|traceback \(most recent)",
     ("critical", "fatal", "panic", "segfault", "exception", "traceback")),

    # --- anti-forensics: logs
    ("log_cleared", "high", "log_tampering", "Event log cleared or cleared by command",
     r"(?i)(\bEvent_?ID[\"']?\s*[:=>]\s*[\"']?(?:1102|104)\b|\bLogFileCleared\b|audit log was cleared|log file was cleared|"
     r"wevtutil(?:\.exe)?\s+(?:cl|clear-log)\b|Clear-EventLog|Remove-EventLog|Limit-EventLog|\[System\.Diagnostics\.Eventing\.Reader\.EventLogSession\].*ClearLog)",
     ("event", "logfilecleared", "cleared", "wevtutil", "clear-eventlog", "remove-eventlog", "limit-eventlog", "clearlog")),
    ("log_truncated_cmd", "high", "log_tampering", "Log file emptied or deleted by command",
     r"(?i)((?:^|[\s;&|(])(?::|echo\s*(?:\"\"|'')?|cat\s+/dev/null)?\s*>\s*\S*(?:/var/log/\S*|\.log\b|wtmp|btmp|lastlog|utmp)|"
     r"truncate\s+(?:-\w+\s+)*-s\s*0\s+\S+|cp\s+/dev/null\s+\S+|rm\s+(?:-\w+\s+)*\S*/var/log/\S*|"
     r"journalctl\s+--(?:vacuum-\w+|rotate)|logrotate\s+-f|\butmpdump\b|\bwtmpclean\b)",
     (">", "truncate", "/dev/null", "/var/log", "journalctl", "logrotate", "utmpdump", "wtmpclean")),
    ("log_lines_deleted", "high", "log_tampering", "Lines deleted from a log file",
     r"(?i)(\bsed\s+(?:-\w+\s+)*-i\S*\s+(?:-\w+\s+)*['\"]?\S*/d['\"]?\s+\S*(?:/var/log/|\.log\b|history|wtmp|btmp)|"
     r"\bgrep\s+-v\s+.+>\s*\S*(?:/var/log/|\.log\b|history)|\bperl\s+-i\S*\s+.*(?:/var/log/|\.log\b))",
     ("sed", "grep", "perl")),
    ("history_tampering", "high", "log_tampering", "Shell history cleared or disabled",
     r"(?i)(history\s+-c\b|history\s+-w\s+/dev/null|unset\s+HISTFILE|HISTFILE=/dev/null|HISTSIZE=0|HISTFILESIZE=0|"
     r"set\s+\+o\s+history|ln\s+-sf?\s+/dev/null\s+\S*history|rm\s+(?:-\w+\s+)*\S*\.(?:bash|zsh|sh)_history|"
     r"Clear-History|Remove-Item\s+.*(?:ConsoleHost_history|HistorySavePath)|HistorySaveStyle\s+SaveNothing)",
     ("hist",)),
    ("logging_disabled", "high", "defense_evasion", "Logging, auditing or security tooling disabled",
     r"(?i)(auditctl\s+-(?:D\b|e\s*0)|systemctl\s+(?:stop|disable|mask|kill)\s+(?:auditd|rsyslog|syslog-ng|systemd-journald|sysmon\S*|falcon\S*|osqueryd)|"
     r"service\s+(?:auditd|rsyslog|syslog)\s+stop|\bsc(?:\.exe)?\s+(?:stop|config|delete)\s+(?:eventlog|sysmon\S*|windefend)|"
     r"Set-MpPreference\s+-Disable\w+|auditpol(?:\.exe)?\s+/(?:clear|remove)|auditpol(?:\.exe)?\s+/set\s+.*(?:success|failure):disable|"
     r"Stop-Service\s+.*(?:EventLog|Sysmon|WinDefend)|\bfltmc(?:\.exe)?\s+unload|sysmon(?:64)?(?:\.exe)?\s+-u\b|"
     r"\bEvent_?ID[\"']?\s*[:=>]\s*[\"']?1100\b|\bServiceShutdown\b)",
     ("audit", "systemctl", "service", "sc", "set-mppreference", "stop-service", "fltmc", "sysmon", "1100", "serviceshutdown")),
    # --- anti-forensics: deleting & wiping
    ("secure_delete", "high", "wiping", "Secure deletion / wiping tool",
     r"(?i)(\bshred\s+(?:-\w+\s+)*\S|\bsrm\s+(?:-\w+\s+)*\S|\bwipe\s+-\w|\bsdelete(?:64)?(?:\.exe)?\b|cipher(?:\.exe)?\s+/w|"
     r"\bdd\s+if=/dev/(?:zero|urandom|random)\s+of=|\bbleachbit\b|fsutil(?:\.exe)?\s+(?:usn\s+deletejournal|file\s+setzerodata))",
     ("shred", "srm", "wipe", "sdelete", "cipher", "dd ", "bleachbit", "fsutil")),
    ("backup_deletion", "high", "wiping", "Shadow copies / backups deleted",
     r"(?i)(vssadmin(?:\.exe)?\s+delete\s+shadows|wmic(?:\.exe)?\s+shadowcopy\s+delete|Win32_ShadowCopy.*Delete|"
     r"bcdedit(?:\.exe)?\s+/set\s+\S*\s*recoveryenabled\s+no|wbadmin(?:\.exe)?\s+delete\s+(?:catalog|systemstatebackup|backup))",
     ("vssadmin", "shadowcopy", "bcdedit", "wbadmin")),
    ("delete_command", "medium", "deletion", "Recursive / forced deletion command",
     r"(?i)(\brm\s+-(?:\w*r\w*f|\w*f\w*r)\w*\s+\S+|Remove-Item\s+.*-(?:Recurse|Force)|\bdel(?:\.exe)?\s+(?:/[fsqa]\s+)+|"
     r"\brmdir\s+/s|\bRD\s+/S\b|\bfind\s+.+-delete\b|shutil\.rmtree\(|\bunlink\s+/\S+)",
     ("rm", "remove-item", "del", "rmdir", "rd ", "find", "rmtree", "unlink")),
    ("file_deleted_event", "medium", "deletion", "File deletion recorded (USN / Sysmon / Security / auditd)",
     r"(?i)(\bEvent_?ID[\"']?\s*[:=>]\s*[\"']?(?:4660|23|26)\b|\bFileDelete\b|\bFileDeleteDetected\b|nametype=DELETE|"
     r"\bsyscall=(?:unlink|unlinkat|rmdir|87|263|84)\b|Accesses:\s*DELETE\b|\bIN_DELETE(?:_SELF)?\b)",
     ("event", "filedelete", "nametype=delete", "syscall=", "accesses", "in_delete")),
    ("file_overwritten_event", "medium", "wiping", "File overwritten or truncated (USN journal)",
     r"(?i)\b(DataOverwrite|DataTruncation|O_TRUNC)\b", ("dataoverwrite", "datatruncation", "o_trunc")),
    ("file_renamed_event", "low", "rename", "File renamed or moved",
     r"(?i)(\bRenameOldName\b|\bRenameNewName\b|\bsyscall=(?:rename|renameat2?|82|264|316)\b|\bRename-Item\b|\bmove(?:\.exe)?\s+/y\b)",
     ("rename", "syscall=", "move")),
    # --- anti-forensics: time
    ("timestomp_cmd", "high", "timestomp", "File timestamps changed on purpose",
     r"(?i)(\btimestomp\b|\btouch\s+(?:-\w+\s+)*-[a-z]*[tdr]\s+\S|\btouch\s+--(?:date|reference)|\bSetFileTime\b|"
     r"\.(?:CreationTime|LastWriteTime|LastAccessTime)(?:Utc)?\s*=|PreviousCreationUtcTime|\bSetMace\b|\bnTimestomp\b|debugfs\s+-w)",
     ("timestomp", "touch", "setfiletime", "creationtime", "lastwritetime", "lastaccesstime", "previouscreationutctime",
      "setmace", "debugfs")),
    ("clock_change", "medium", "timestomp", "System clock changed",
     r"(?i)(\bEvent_?ID[\"']?\s*[:=>]\s*[\"']?4616\b|\bdate\s+-s\s|\btimedatectl\s+set-time|\bSet-Date\b|\bhwclock\s+--set|"
     r"Time has been changed|system time was changed)",
     ("event", "date -s", "timedatectl", "set-date", "hwclock", "time has been changed", "system time was changed")),
    # --- anti-forensics: obfuscation & hiding
    ("obfuscation", "medium", "obfuscation", "Obfuscated or encoded payload",
     r"(?i)(FromBase64String|\[char\]\s*\d+\s*\+|\[char\[\]\]|-join\s*\(?\s*\[char|-bxor\s+\d|\[string\]::join|"
     r"[a-z]`[a-z]`[a-z]|['\"](?:\{\d+\}){2,}['\"]\s*-f\b|base64\s+(?:-d|--decode)\b|\bxxd\s+-r|certutil(?:\.exe)?\s+-decode|"
     r"openssl\s+(?:enc|base64)\s+.*-d\b|gzinflate\s*\(|str_rot13\s*\(|"
     r"eval\s*\(\s*(?:base64_decode|gzinflate|atob|unescape|String\.fromCharCode)|String\.fromCharCode\s*\(\s*\d+\s*,|"
     r"(?:\\x[0-9a-f]{2}){16,}|(?:%[0-9a-f]{2}){24,}|\brev\s*\|\s*(?:ba)?sh\b|python[23]?\s+-c\s+.{0,60}(?:exec|b64decode))",
     ("base64", "char", "bxor", "join", "`", "-f", "xxd", "certutil", "openssl", "gzinflate", "rot13", "eval",
      "fromcharcode", "\\x", "%", "rev", "python")),
    ("encrypt_cmd", "medium", "obfuscation", "Files encrypted or packed with a password",
     r"(?i)(openssl\s+enc\s+-(?:aes|des|chacha|bf)|\bgpg\s+(?:-\w+\s+)*(?:-c|--symmetric|-e|--encrypt)\b|"
     r"\b7z(?:a|\.exe)?\s+a\s+.*-p\S*|\bzip\s+(?:-\w+\s+)*-(?:P|e)\b|\brar\s+a\s+.*-hp)",
     ("openssl", "gpg", "7z", "zip", "rar")),
    ("rootkit_name", "high", "rootkit", "Known Linux rootkit",
     r"(?i)\b(diamorphine|reptile_cmd|reptile|suterusu|azazel|jynx2?|beurk|bdvl|bedevil|vlany|libprocesshider|processhider|"
     r"brokepkg|kovid|boopkit|symbiote|umbreon|caraxes|puszek|khook|singularity)\b",
     ("diamorphine", "reptile", "suterusu", "azazel", "jynx", "beurk", "bdvl", "bedevil", "vlany", "processhider",
      "brokepkg", "kovid", "boopkit", "symbiote", "umbreon", "caraxes", "puszek", "khook", "singularity")),
    ("kernel_taint", "medium", "rootkit", "Unsigned or out-of-tree kernel module loaded",
     r"(?i)(loading out-of-tree module taints kernel|module verification failed|tainting kernel|\bunsigned module\b)",
     ("taint", "verification failed", "unsigned module")),
    ("privesc_exploit", "high", "privilege", "Named privilege-escalation exploit",
     r"(?i)(\bdirty_?(?:pipe|cow|cred)\b|\bpwnkit\b|GCONV_PATH=|\bsudo\s+-u\s*#-1|\bbaron_?samedit\b|\bexploit\w*\.(?:c|py|sh|pl|elf)\b|"
     r"\bopenssl\s+passwd\s+-(?:1|5|6|crypt)\b|\bCVE-20\d\d-\d{4,}\.(?:c|py|sh)\b)",
     ("dirty", "pwnkit", "gconv", "sudo", "baron", "exploit", "openssl", "cve-")),
    ("lateral_movement", "medium", "lateral", "Connections to other systems",
     r"(?i)(\bssh\s+(?:-\w+\s+(?:\S+\s+)?)*-i\s+\S+|\bssh-keyscan\b|\bp(?:arallel-)?ssh\s+-h\b|\bansible\s+\S+\s+-m\s+(?:shell|command|raw)|"
     r"\bssh\s+(?:-\w+\s+)*[\w.-]+@\d{1,3}(?:\.\d{1,3}){3}\b|\bscp\s+(?:-\w+\s+)*[\w.-]+@\d{1,3}(?:\.\d{1,3}){3}:)",
     ("ssh", "scp", "ansible")),
    ("security_disabled", "high", "defense_evasion", "Security process killed or kernel hardening switched off",
     r"(?i)(\bkill(?:all)?\s+(?:-9\s+|-KILL\s+)?\S*(?:auditd|rsyslogd|fail2ban|falcon|osqueryd|wazuh|clamd|aide)\b|"
     r"\bpkill\s+(?:-9\s+)?(?:-f\s+)?\S*(?:auditd|rsyslogd|fail2ban|falcon|osqueryd|wazuh)|"
     r"(?:echo\s+[0-2]\s*>|sysctl\s+-w)\s*\S*(?:kernel[/.](?:yama[/.]ptrace_scope|kptr_restrict|dmesg_restrict|randomize_va_space|modules_disabled)))",
     ("kill", "pkill", "kernel")),
    ("web_cmd_param", "high", "attack", "Command passed in a web request",
     r"(?i)[?&](?:cmd|exec|command|execute|shell|run|c|x)=[^&\s\"]*?(?:whoami|\bid\b|uname|/etc/passwd|wget|curl|bash|/bin/sh|\bnc\b|python|perl|chmod|base64|ifconfig|\bls\b|cat(?:%20|\+))",
     ("cmd=", "exec=", "command=", "execute=", "shell=", "run=", "?c=", "&c=", "?x=", "&x=")),
    ("dos_tool", "high", "dos", "Flooding / denial-of-service tool",
     r"(?i)(\bhping3?\b[^\n]*(?:--flood|-i\s*u\d+|--faster)|\bt50\s|\bmausezahn\b|\bmz\s+\S+\s+[^\n]*-c\s*0\b|\bslowloris\b|\bslowhttptest\b|"
     r"\bgoldeneye(?:\.py)?\b|\bhulk\.py\b|\bmdk[34]\b|\byersinia\b|\bdhcpstarv\b|\bdhcpig\b|\bxerxes\b|\bthc-ssl-dos\b|"
     r"\bsmtp[-_]?(?:flood|bomb|stress|dos)\w*|\bmail[-_]?bomb\w*|\bmailbomber\b|\bpostal\s+-m\b|\brabid\s+-[a-z]|\b(?:ddos|dos)[-_]?(?:attack|tool|script)\b)",
     ("hping", "t50", "mausezahn", "mz ", "slowloris", "slowhttptest", "goldeneye", "hulk", "mdk", "yersinia", "dhcpstarv",
      "dhcpig", "xerxes", "thc-ssl-dos", "flood", "bomb", "smtp-stress", "smtp_stress", "smtpstress", "smtp-dos", "smtp_dos",
      "smtpdos", "postal", "rabid", "ddos", "dos-", "dos_")),
    ("mail_loop", "high", "dos", "Loop that sends mail or opens SMTP connections",
     r"(?i)\b(?:for|while|until)\b[^\n]{0,200}?\bdo\b[^\n]{0,300}?(?:\bsendmail\b|\bmailx?\s+-|\bmail\s+-s\b|\bswaks\b|\bmutt\s|\bmsmtp\b|\bsendemail\b|"
     r"\bexim4?\s+-|\bnc(?:at)?\s+(?:-\w+\s+(?:\d+\s+)?)*[\w.-]+\s+(?:25|465|587)\b|\btelnet\s+[\w.-]+\s+25\b|smtplib)"
     r"|\bseq\s+\d+\s+\d{3,}[^\n]*\|\s*xargs[^\n]*(?:sendmail|mail|swaks|nc)\b"
     r"|for\s+\w+\s+in\s+range\(\s*\d{3,}[^\n]*|while\s+(?:True|1)\s*:"
     r"|\b(?:foreach|for|while)\s*\([^\n]{0,200}?\)\s*\{?[^\n]{0,300}?\b(?:mail|wp_mail|mb_send_mail)\s*\(",
     ("for", "while", "until", "seq", "range(")),
    ("smtp_tooling", "medium", "dos", "Mail sent by script or raw SMTP connection",
     r"(?i)(\bswaks\b|\bsmtplib\.SMTP(?:_SSL)?\s*\(|\bsendemail\s+-|\bPHPMailer\b|\bmail\s*\(\s*\$_(?:GET|POST|REQUEST)|\bsmtp-user-enum\b|"
     r"\bnc(?:at)?\s+(?:-\w+\s+(?:\d+\s+)?)*[\w.-]+\s+(?:25|465|587)\s*(?:<|$|&|\|)|\btelnet\s+[\w.-]+\s+25\b|openssl\s+s_client\s+[^\n]*:(?:25|465|587)\b|"
     r"\bsendmail\s+-(?:t|oi|i)\b[^\n]*<\s*\S+|\bexim4?\s+-bm?\s)",
     ("swaks", "smtplib", "sendemail", "phpmailer", "mail(", "mail (", "smtp-user-enum", "nc ", "ncat ", "telnet ", "s_client",
      "sendmail -", "exim -", "exim4 -")),
    ("resource_exhaustion", "medium", "dos", "System resources exhausted or deliberately consumed",
     r"(?i)(Possible SYN flooding on port|nf_conntrack: (?:nf_conntrack: )?table full|Out of memory: Kill(?:ed)? process|invoked oom-killer|"
     r"fork: (?:retry: )?(?:Resource temporarily unavailable|Cannot allocate memory)|Too many open files|TCP: out of memory|neighbour table overflow|"
     r":\(\)\s*\{\s*:\|:\s*&\s*\}\s*;\s*:|\bstress(?:-ng)?\s+--(?:cpu|vm|io|hdd|fork|sock)|\bfallocate\s+-l\s*\d+[GT]|"
     r"\bdd\s+if=/dev/(?:zero|urandom)\s+of=(?!/dev/)\S+[^\n]*count=\d{4,})",
     ("syn flooding", "nf_conntrack", "out of memory", "oom-killer", "fork:", "too many open files", "neighbour table", ":()", "stress",
      "fallocate", "dd ")),
    ("smtp_saturation", "medium", "dos", "Mail server at its connection limit",
     r"(?i)(has reached its process limit|Connection (?:rate|concurrency) limit exceeded|too many connections from|refused: too many connections|"
     r"TCP/IP connection count = \d{3,}|too many concurrent SMTP connections|Connection count limit exceeded)",
     ("process limit", "limit exceeded", "too many", "connection count")),
    ("promiscuous_mode", "medium", "sniffing", "Interface put into promiscuous mode (packet capture)",
     r"(?i)(device \S+ entered promiscuous mode|\S+: entered promiscuous mode|type=ANOM_PROMISCUOUS|promiscuous mode (?:enabled|entered))",
     ("promiscuous",)),
    ("packet_capture", "high", "sniffing", "Packet capture / sniffer tool",
     r"(?i)(\btcpdump\b(?:[^\n]*\s-[a-zA-Z]*[wi]\b|[^\n]*\s-(?:w|i)\s|\s*$)|\btshark\b|\bdumpcap\b|\btcpflow\b|\bngrep\b|\bnetsniff-ng\b|\bnfsniff\b|"
     r"\bwireshark\b|\btcpick\b|\bnettl\b|\bmirror(?:tap)?\b|\bdsniff\b|\burlsnarf\b|\bmailsnarf\b|\bwebspy\b|\bdriftnet\b|\bfilesnarf\b|\bmsgsnarf\b|"
     r"\bpcapdump\b|\bnproxy\b|scapy[^\n]*\bsniff\s*\(|\bsniff\s*\([^\n]*(?:iface|prn|filter)|\braw\s*socket|socket\.socket\([^\n]*(?:AF_PACKET|SOCK_RAW)|\bsetcap\b[^\n]*cap_net_raw)",
     ("tcpdump", "tshark", "dumpcap", "tcpflow", "ngrep", "netsniff", "nfsniff", "wireshark", "tcpick", "nettl", "mirror",
      "dsniff", "urlsnarf", "mailsnarf", "webspy", "driftnet", "filesnarf", "msgsnarf", "pcapdump", "nproxy", "sniff", "raw", "socket", "setcap")),
    ("arp_spoof", "high", "sniffing", "ARP spoofing / man-in-the-middle tool or event",
     r"(?i)(\barpspoof\b|\bettercap\b|\bbettercap\b|\bmitmf\b|\bmitm6\b|\bresponder(?:\.py)?\b|\bnetcommander\b|\barpoison\b|\barp-sk\b|\barpreplace\b|"
     r"\bmacof\b|\bkickstarter\b|is using my IP address|(?:\bARP\b[^\n]*|arpwatch[^\n]*)(?:flip flop|changed ethernet address|moved from|new activity|reused old ethernet)|"
     r"received packet on \S+ with own address as source|duplicate (?:IP )?address \S+ detected)",
     ("arpspoof", "ettercap", "bettercap", "mitmf", "mitm6", "responder", "netcommander", "arpoison", "arp-sk", "arpreplace",
      "macof", "kickstarter", "is using my ip", "arp", "own address as source", "duplicate", "flip flop", "arpwatch")),
    ("traffic_redirect", "high", "sniffing", "Traffic redirected or intercepted (MITM plumbing)",
     r"(?i)(net\.ipv[46]\.(?:conf\.(?:all|default|[\w.*-]+)\.)?(?:ip_forward|forwarding)\s*=\s*1|\bip_forward\b[^\n]*\b1\b|echo\s+1\s*>\s*/proc/sys/net/ipv[46]/(?:ip_forward|conf/\S+/forwarding)|"
     r"iptables[^\n]*-j\s+(?:REDIRECT|DNAT|NFQUEUE|TPROXY)\b|iptables[^\n]*-t\s+nat[^\n]*-A\b|nft[^\n]*\b(?:dnat|redirect|tproxy)\b|"
     r"\bsslstrip\b|\bsslsplit\b|\bmitmproxy\b|\bmitmdump\b|\bmitmweb\b|\bbdfproxy\b|\bethercap\b|\btcpkill\b|\btcpnice\b|\bicmp_redirect\b[^\n]*\b1\b|"
     r"\bip\s+route\s+(?:add|replace|change)\b|\bip\s+neigh(?:bour)?\s+(?:add|replace|change)\b|\bebtables\b[^\n]*-j|\btc\s+qdisc\s+add[^\n]*netem|SSLKEYLOGFILE=)",
     ("ip_forward", "forwarding", "redirect", "dnat", "nfqueue", "tproxy", "nat", "sslstrip", "sslsplit", "mitmproxy",
      "mitmdump", "mitmweb", "bdfproxy", "ethercap", "tcpkill", "tcpnice", "icmp_redirect", "ip route", "ip neigh",
      "ebtables", "netem", "sslkeylogfile")),
    ("dns_tamper", "high", "sniffing", "DNS redirection / spoofing",
     r"(?i)(\bdnsspoof\b|\bdnschef\b|dnsmasq[^\n]*\baddress=/|\baddress=/[^/\n]+/\d{1,3}(?:\.\d{1,3}){3}|"
     r"\bnameserver\s+(?!127\.0\.0\.1|::1|127\.0\.0\.53)\d{1,3}(?:\.\d{1,3}){3}|DHCPACK[^\n]*(?:rogue|unexpected)|"
     r"not authoritative[^\n]*answering|\bfakedns\b|\bdns2proxy\b)",
     ("dnsspoof", "dnschef", "address=/", "nameserver", "dhcpack", "authoritative", "fakedns", "dns2proxy")),
    ("rogue_ca", "high", "sniffing", "Certificate authority added (TLS interception)",
     r"(?i)(update-ca-certificates\b|/usr/local/share/ca-certificates/|/etc/ssl/certs/[^\n]*(?:mitm|proxy|interception)|"
     r"\bcertutil\b[^\n]*-A\b[^\n]*-t\s*['\"]?C|trust\s+anchor\b|keytool[^\n]*-importcert)",
     ("update-ca-certificates", "ca-certificates", "/etc/ssl/certs", "certutil", "trust anchor", "keytool")),
    ("covert_tunnel", "high", "c2", "Covert tunnel, VPN mesh or anonymising network",
     r"(?i)(\btor\s+(?:-f|--runasdaemon|--hash)|\bHiddenService(?:Dir|Port)\b|\.onion\b|\btorsocks\b|"
     r"\bwg-quick\s+up\b|\bwg\s+set\b|\btailscaled?\b[^\n]*(?:\bup\b|--authkey|tskey-)|\bzerotier-(?:cli|one)\b|\bnebula\s+-config\b|"
     r"\bopenvpn\s+(?:--config|--remote|--daemon)|\bsocat\b[^\n]*TCP4?6?-LISTEN:\d+[^\n]*(?:TCP4?6?|OPENSSL|SOCKS4A?):|"
     r"\bncat\b[^\n]*--(?:broker|sh-exec|exec|proxy-type)|\brinetd\b|\b3proxy\b|\bmicrosocks\b|\bdanted\b|\bsockd\b|"
     r"\bdns2tcp[cd]?\b|\bdnstt-(?:client|server)\b|\bptunnel(?:-ng)?\b|\bicmpsh\b|\bhans\s+-[cs]\b|\bicmptunnel\b|\bpingtunnel\b|"
     r"\budp2raw\b|\bkcptun\b|\bregeorg\b|\bneo-?regeorg\b|\bneoreg(?:\.py)?\b|\btunna\b|\babptts\b|\bpystinger\b|\bsuo5\b|\breduh\b|"
     r"\bssh\b[^\n]*\s-[a-zA-Z]*w\s*\d+:\d+|\bssh\b[^\n]*-o\s*(?:Tunnel|PermitLocalCommand)=|\bproxytunnel\b|\bhttptunnel\b|\bhts\s+-F|\bhtc\s+-F|"
     r"\bsshuttle\b|\bxray\b[^\n]*run|\bv2ray\b|\btrojan-go\b|\bshadowsocks\b|\bss-(?:local|server|redir)\b|\bbore\s+local\b|\blocaltunnel\b|\bpagekite\b)",
     ("tor", "hiddenservice", ".onion", "torsocks", "wg", "tailscale", "tskey", "zerotier", "nebula", "openvpn", "socat",
      "ncat", "rinetd", "3proxy", "microsocks", "danted", "sockd", "dns2tcp", "dnstt", "ptunnel", "icmpsh", "hans",
      "icmptunnel", "pingtunnel", "udp2raw", "kcptun", "regeorg", "neoreg", "tunna", "abptts", "pystinger", "suo5", "reduh", "ssh",
      "proxytunnel", "httptunnel", "hts", "htc", "sshuttle", "xray", "v2ray", "trojan", "shadowsocks", "ss-", "bore", "localtunnel", "pagekite")),
    ("ssh_forwarding_log", "medium", "c2", "SSH port forwarding / tunnel in use",
     r"(?i)(server_request_tcpip_forward|tcpip-forward\s+(?:listen|request)|Received request to (?:connect to host \S+ port \d+|listen)|"
     r"direct-tcpip|forwarded-tcpip|channel \d+: (?:new|connected) \[(?:direct|forwarded)-tcpip\]|Accepted forwarding|"
     r"cancel-tcpip-forward|streamlocal-forward|tun-request|channel_input_open: ctype (?:direct|forwarded)-tcpip)",
     ("tcpip", "received request to", "accepted forwarding", "streamlocal", "tun-request", "channel_input_open")),
    ("suspicious_socket", "high", "c2", "Live connection or listener held by a shell, interpreter, relay or deleted/temp program",
     r"(?i)(?:ESTAB(?:LISHED)?|LISTEN|SYN-SENT|CLOSE-WAIT)\b[^\n]*?(?:users:\(\(\"(?:bash|sh|dash|zsh|ksh|python\d?(?:\.\d+)?|perl|php(?:-fpm)?\d*|nc|ncat|netcat|socat|ruby|node|lua|busybox|telnet|curl|wget|openssl)\"|"
     r"\b\d+/(?:bash|sh|dash|zsh|python\d?|perl|php\d*|nc|ncat|netcat|socat|ruby|node|telnet|openssl)\b|\(deleted\)|"
     r"\s/(?:tmp|dev/shm|var/tmp)/\S+|users:\(\(\"\.[\w.-]+\")",
     ("estab", "listen", "syn-sent", "close-wait")),
    ("promiscuous", "medium", "recon", "Network sniffing",
     r"(?i)entered promiscuous mode|\btcpdump\s+(?:-\w+\s+)*-[wi]\b|\btshark\s", ("promiscuous", "tcpdump", "tshark")),
    ("hiding", "medium", "hiding", "File hidden, staged in a hidden folder, or made immutable",
     r"(?i)((?:/tmp|/var/tmp|/dev/shm)/\.(?!X11-unix|ICE-unix|font-unix|XIM-unix|Test-unix)[\w-]+|attrib(?:\.exe)?\s+[^\n]*\+[hs]\b|\bchattr\s+\+[ia]\b|SetFileAttributes.*HIDDEN|"
     r"\bmv\s+\S+\s+\S*/\.\.\.?(?:\s|/|$)|\bmkdir\s+(?:-p\s+)?\S*/\.\.\.|/dev/shm/\.\w|\$\{IFS\})",
     ("/tmp/.", "/dev/shm/.", "attrib", "chattr", "setfileattributes", "mv", "mkdir", "ifs")),
    # ======================= Linux / Debian post-exploitation =======================
    # --- persistence
    ("cron_persistence", "high", "persistence", "Cron job added from the command line",
     r"(?i)(crontab\s+-l[^|\n]*;\s*echo[^|\n]*\)\s*\|\s*crontab\s+-|echo\s+.+>>?\s*\S*(?:/etc/crontab|/etc/cron\.\w+/|/var/spool/cron/)|crontab\s+/tmp/|crontab\s+\S*/\.\S+)",
     ("crontab", "/etc/cron", "/var/spool/cron")),
    ("cron_reboot", "medium", "persistence", "Cron @reboot entry", r"(?i)^\s*@reboot\s+\S", ("@reboot",)),
    ("crontab_removed", "medium", "defense_evasion", "Crontab removed", r"(?i)\bcrontab\s+(?:-u\s+\S+\s+)?-r\b", ("crontab",)),
    ("systemd_persistence", "medium", "persistence", "systemd service created or enabled",
     r"(?i)(systemctl\s+(?:--user\s+)?(?:enable|link|preset)\s+(?:--now\s+)?\S+|(?:cat|tee|echo|cp|mv)\b[^\n]*\s/(?:etc|lib|usr/lib)/systemd/system/\S+\.(?:service|timer)|\.config/systemd/user/\S+\.service|update-rc\.d\s+\S+\s+(?:defaults|enable))",
     ("systemctl", "systemd/system", "systemd/user", "update-rc.d")),
    ("ssh_key_added", "high", "persistence", "SSH key planted in authorized_keys",
     r"(?i)(>>?\s*\S*authorized_keys2?\b|tee\s+(?:-a\s+)?\S*authorized_keys|cp\s+\S+\s+\S*authorized_keys|ssh-copy-id\s)",
     ("authorized_keys", "ssh-copy-id")),
    ("preload_rootkit", "high", "persistence", "ld.so.preload / LD_PRELOAD hijack (userland rootkit)",
     r"(?i)(/etc/ld\.so\.preload|\bLD_PRELOAD=\S+|\bLD_LIBRARY_PATH=/(?:tmp|dev/shm|var/tmp)\b)", ("ld.so.preload", "ld_preload", "ld_library_path")),
    ("shell_startup_edit", "high", "persistence", "Shell startup file modified from the command line",
     r"(?i)(>>?\s*\S*(?:\.bashrc|\.bash_profile|\.profile|\.bash_logout|\.zshrc|/etc/profile(?:\.d/\S*)?|/etc/bash\.bashrc|/etc/rc\.local|/etc/update-motd\.d/\S+))",
     ("bashrc", "profile", "bash_logout", "zshrc", "rc.local", "update-motd")),
    ("shell_hijack", "high", "credential", "Command hijacked with an alias, function or PROMPT_COMMAND",
     r"(?i)(^|[;\s])(alias\s+(?:sudo|su|ssh|ls|ps|netstat|ss|top|passwd|lsof|find|kill)=|(?:function\s+)?(?:sudo|su|ssh|passwd)\s*\(\)\s*\{|PROMPT_COMMAND=)",
     ("alias", "()", "prompt_command")),
    ("kernel_module", "high", "persistence", "Kernel module loaded from a non-standard place (possible rootkit)",
     r"(?i)(\binsmod\s+\S+\.ko\b|\bmodprobe\s+(?:-\w+\s+)*\S*/(?:tmp|dev/shm|var/tmp|home|root)/|echo\s+\S+\s*>>?\s*/etc/modules\b|/etc/modules-load\.d/\S+|\b(?:diamorphine|reptile|suterusu|kovid|adore-ng|rkduck)\b)",
     ("insmod", "modprobe", "/etc/modules", "diamorphine", "reptile", "suterusu", "kovid", "adore", "rkduck")),
    ("pam_backdoor", "high", "persistence", "PAM configuration or module tampering",
     r"(?i)(pam_exec\.so|pam_permit\.so\s*$|\bauth\s+sufficient\s+pam_permit|>>?\s*\S*/etc/pam\.d/|/lib/\S*security/pam_\w+\.so\s*(?:$|\s)(?=.*(?:cp|mv|wget|curl|gcc)))",
     ("pam_exec", "pam_permit", "pam.d", "security/pam_")),
    ("apt_hook", "high", "persistence", "APT / dpkg hook runs a command", r"(?i)(?:APT::Update::(?:Pre|Post)-Invoke|DPkg::(?:Pre|Post)-Invoke)\S*\s*\{?\s*\"", ("invoke",)),
    ("udev_run", "medium", "persistence", "udev rule runs a program", r"(?i)\bRUN\+?=\s*\"[^\"]*(?:/tmp|/dev/shm|/var/tmp|bash|sh\s+-c|curl|wget|nc\b)", ("run",)),
    ("xdg_autostart", "low", "persistence", "Desktop autostart entry", r"(?i)\.config/autostart/\S+\.desktop|^X-GNOME-Autostart", ("autostart",)),
    # --- accounts & privilege
    ("account_created", "medium", "privilege", "User account created",
     r"(?i)(\buseradd\b|\badduser\s+(?!--system)\S|new user: name=|\bnewusers\b)", ("useradd", "adduser", "new user", "newusers")),
    ("uid0_account", "high", "privilege", "Account created or changed to UID 0 (root clone)",
     r"(?i)(\buseradd\b[^\n]*(?:-o\b[^\n]*-u\s*0\b|-u\s*0\b[^\n]*-o\b|--non-unique)|\busermod\b[^\n]*-u\s*0\b|new user: name=\S+, UID=0\b|:x?:0:0:[^:]*:[^:]*:/bin/(?:ba|z|da)?sh\b(?<!^root:x:0:0:root:/root:/bin/bash))",
     ("useradd", "usermod", "uid=0", ":0:0:")),
    ("group_escalation", "high", "privilege", "User added to a privileged group",
     r"(?i)(\busermod\b[^\n]*-a?G\s+\S*\b(?:sudo|adm|root|wheel|docker|lxd|disk|shadow|admin)\b|\bgpasswd\s+-a\s+\S+\s+(?:sudo|adm|root|wheel|docker|lxd|disk)|add '\S+' to (?:shadow )?group '(?:sudo|adm|root|wheel|docker|lxd|disk|admin)'|\badduser\s+\S+\s+(?:sudo|adm|docker|lxd|disk)\b)",
     ("usermod", "gpasswd", "to group", "to shadow group", "adduser")),
    ("sudoers_edit", "high", "privilege", "sudoers changed / passwordless sudo",
     r"(?i)(>>?\s*/etc/sudoers(?:\.d/\S*)?|\bNOPASSWD:\s*ALL\b|tee\s+(?:-a\s+)?/etc/sudoers|visudo\s+-f)", ("sudoers", "nopasswd", "visudo")),
    ("password_change", "low", "privilege", "Password changed", r"(?i)(password changed for \S+|\bchpasswd\b|\bpasswd\s+(?:-\w+\s+)*\w+\s*$|echo\s+\S+:\S+\s*\|\s*chpasswd)", ("password changed", "chpasswd", "passwd")),
    ("suid_set", "high", "privilege", "SUID/SGID bit or capability set (privilege backdoor)",
     r"(?i)(\bchmod\s+(?:-\w+\s+)*(?:[ugoa]*\+[rwx]*s[rwx]*|[2467][0-7]{3})\s+\S+|\bsetcap\s+\S*cap_(?:setuid|setgid|sys_admin|dac_override|sys_ptrace)|\bcp\s+/bin/(?:ba)?sh\s+\S+\s*;?\s*chmod)",
     ("chmod", "setcap", "cp")),
    ("sudo_command", "info", "privilege", "Command run with sudo", r"sudo:\s+\S+\s*:.*COMMAND=", ("command=",)),
    ("su_session", "low", "privilege", "User switched with su", r"(?i)(\bsu:\s*\(to \S+\)|\bsu\[\d+\]: pam_unix\(su(?:-l)?:session\): session opened)", ("su",)),
    ("ssh_config_weakened", "medium", "defense_evasion", "SSH server settings weakened",
     r"(?i)^\s*(?:PermitRootLogin\s+yes|PermitEmptyPasswords\s+yes|AuthorizedKeysFile\s+(?!\.ssh/authorized_keys)\S+|StrictModes\s+no)", ("permitrootlogin", "permitemptypasswords", "authorizedkeysfile", "strictmodes")),
    # --- initial access
    ("ssh_login", "info", "access", "Successful SSH login", r"sshd\[\d+\]: Accepted (?:password|publickey|keyboard-interactive/pam|gssapi\S*|hostbased) for \S+ from \S+", ("accepted",)),
    ("ssh_root_login", "medium", "access", "Direct SSH login as root", r"sshd\[\d+\]: Accepted \S+ for root from \S+", ("accepted",)),
    ("webshell", "high", "execution", "Web shell code",
     r"(?i)((?:system|exec|shell_exec|passthru|popen|proc_open|assert|eval|pcntl_exec)\s*\(\s*(?:@?\$_(?:GET|POST|REQUEST|COOKIE|SERVER)|base64_decode\s*\(\s*\$_)|preg_replace\s*\(\s*['\"].*/e['\"]|\$_(?:GET|POST|REQUEST)\s*\[\s*['\"]?\w+['\"]?\s*\]\s*\(\s*\$_)",
     ("$_", "preg_replace")),
    ("webshell_access", "medium", "access", "Request to a script in an upload/temp folder (possible web shell)",
     r"(?i)\"(?:POST|GET) /\S*(?:upload|images?|img|tmp|temp|cache|files|media|assets|wp-content/uploads)/\S*\.(?:php\d?|phtml|phar|jsp|aspx?|cgi|pl|py)(?:\?\S*)? HTTP", ("upload", "image", "img", "tmp", "temp", "cache", "files", "media", "assets")),
    # --- credential access
    ("credential_access", "high", "credential", "Credential theft technique",
     r"(?i)(\b(?:cat|cp|less|more|head|tail|strings|base64|scp)\s+(?:\S+\s+)*/etc/(?:shadow|gshadow)\b|\bunshadow\b|\bjohn\s+|\bhashcat\b|\bmimipenguin\b|\bLaZagne\b|/proc/\d+/mem\b|\bgdb\s+(?:-\w+\s+)*-p\s+\d|\bstrace\s+(?:-\w+\s+)*-p\s+\d+[^\n]*(?:read|write)|\bstrace\b[^\n]*\bsshd\b|\b(?:cat|cp|scp|tar)\s+\S*\.ssh/id_(?:rsa|dsa|ecdsa|ed25519)\b|SSH_AUTH_SOCK=/tmp/ssh-|\bkeyctl\s+(?:print|pipe|read)|\btcpdump\s+[^\n]*-w\s|\b3snake\b|\bsshLooter\b|\.aws/credentials|\.docker/config\.json|\.kube/config|\.git-credentials)",
     ("shadow", "unshadow", "john", "hashcat", "mimipenguin", "lazagne", "/proc/", "gdb", "strace", "id_", "ssh_auth_sock",
      "keyctl", "tcpdump", "3snake", "sshlooter", ".aws", ".docker", ".kube", ".git-credentials")),
    # --- recon / privesc tooling
    ("linux_recon", "medium", "recon", "Post-exploitation reconnaissance",
     r"(?i)(\blinpeas\b|\bLinEnum\b|linux-exploit-suggester|\blse\.sh\b|\bpspy(?:32|64)?\b|\bfind\s+/\s+[^\n]*-perm\s+(?:-|/)?(?:4000|u=s|2000|g=s)|\bsudo\s+-l\b|\bgetcap\s+-r\s+/|\bunix-privesc-check\b|\bdeepce\b|cat\s+/proc/version|\bupc\.sh\b)",
     ("linpeas", "linenum", "exploit-suggester", "lse.sh", "pspy", "-perm", "sudo -l", "getcap", "privesc", "deepce", "/proc/version", "upc.sh")),
    ("tool_download", "high", "tooling", "Tool downloaded into a temp or hidden location",
     r"(?i)(\b(?:wget|curl)\b[^\n]*(?:-[oO]\s*|--output(?:-document)?[= ]\s*|-P\s*)(?:/tmp|/dev/shm|/var/tmp|/run/shm|\S*/\.\w)|\b(?:wget|curl)\s+[^\n|]*\s-[a-zA-Z]*\s*(?:/tmp|/dev/shm)/|\bcd\s+(?:/tmp|/dev/shm|/var/tmp)\S*\s*[;&]+\s*(?:wget|curl))",
     ("wget", "curl")),
    ("compile_on_host", "medium", "tooling", "Code compiled on the server", r"(?i)\b(?:gcc|cc|g\+\+|clang|make)\b[^\n]*(?:-o\s+\S*(?:/tmp|/dev/shm|/var/tmp|\.\w)|\S+\.c\b[^\n]*-o\s)", ("gcc", "cc", "g++", "clang", "make")),
    ("package_tooling", "medium", "tooling", "Offensive or dual-use package installed",
     r"(?i)\binstall\b[^\n]{0,200}?\b(nmap|netcat(?:-\w+)?|ncat|socat|masscan|zmap|hydra|john|hashcat|tcpdump|tshark|proxychains4?|tor|sshpass|sqlmap|hping3|dsniff|ettercap\S*|responder|crackmapexec|python3-impacket|impacket-scripts|chisel|gcc|build-essential|make|gdb|strace|ltrace|upx-ucl|ngrok|nc)(?=[:\s]|$)",
     ("install",)),
    ("package_security_removed", "high", "defense_evasion", "Security or logging package removed",
     r"(?i)\b(?:remove|purge|autoremove)\b[^\n]{0,200}?\b(auditd|audispd-plugins|rsyslog|syslog-ng|fail2ban|apparmor|clamav\S*|aide|tripwire|rkhunter|chkrootkit|ossec\S*|wazuh-agent|falco|osquery|sysdig|systemd-journal-remote|unattended-upgrades|ufw|lynis|auditbeat|filebeat|crowdstrike\S*|falcon-sensor)(?=[:\s]|$)",
     ("remove", "purge")),
    # --- tunnels, C2, remote shells
    ("reverse_shell", "high", "c2", "Reverse / bind shell",
     r"(?i)(/dev/(?:tcp|udp)/[\w.-]+/\d+|\bmkfifo\s+\S+[^\n]*\|\s*(?:/bin/)?(?:ba|z|da)?sh|\bnc(?:at)?\s+(?:-\w+\s+)*-[a-z]*[ec]\s+(?:/bin/)?(?:ba|z|da)?sh|\bnc(?:at)?\s+-[a-z]*l[a-z]*v?[a-z]*p?\s+\d+|\bsocat\b[^\n]*\bexec:|\bsocat\b[^\n]*\btcp(?:4|6)?(?:-listen)?:|python[23]?\s+-c\s+[^\n]*socket[^\n]*(?:subprocess|pty|dup2)|perl\s+-e\s+[^\n]*socket|php\s+-r\s+[^\n]*fsockopen|ruby\s+-rsocket|openssl\s+s_client\s+[^\n]*\|\s*(?:/bin/)?(?:ba)?sh|\bpty\.spawn\()",
     ("/dev/tcp", "/dev/udp", "mkfifo", "nc", "socat", "python", "perl", "php", "ruby", "openssl", "pty.spawn")),
    ("tunnel", "high", "c2", "Tunnel or proxy to the outside",
     r"(?i)(\bngrok\b|\bchisel\s+(?:client|server)|\bfrp[cs]\b|\bgost\s+-L|\bligolo\b|\biodine\b|\bdnscat2?\b|\bssh\s+(?:-\w+\s+)*-[a-zA-Z]*[RDL]\s*(?:\d|\[|\S+:\d)|\bssh\s+[^\n]*-o\s*(?:StrictHostKeyChecking=no|UserKnownHostsFile=/dev/null)|\bsshpass\b|\bproxychains\S*|\bautossh\b|\bcloudflared\s+tunnel|\brevsocks\b|\bstowaway\b)",
     ("ngrok", "chisel", "frp", "gost", "ligolo", "iodine", "dnscat", "ssh", "sshpass", "proxychains", "autossh", "cloudflared", "revsocks", "stowaway")),
    ("miner", "high", "impact", "Crypto-miner",
     r"(?i)(\bxmrig\b|stratum\+(?:tcp|ssl|tls)://|\bminerd\b|\bcpuminer\b|--donate-level|\bnanopool\b|\bsupportxmr\b|\bminexmr\b|\bc3pool\b|\bkinsing\b|\bkdevtmpfsi\b|\bxmr-stak\b|\bt-rex\b)",
     ("xmrig", "stratum", "minerd", "cpuminer", "donate-level", "nanopool", "supportxmr", "minexmr", "c3pool", "kinsing", "kdevtmpfsi", "xmr-stak", "t-rex")),
    # --- defence evasion (Linux)
    ("firewall_disabled", "medium", "defense_evasion", "Firewall or MAC protection disabled",
     r"(?i)(\biptables\s+(?:-t\s+\w+\s+)?-F\b|\biptables\s+-P\s+INPUT\s+ACCEPT|\bufw\s+disable\b|\bnft\s+flush\s+ruleset|\bsetenforce\s+0\b|\baa-teardown\b|\bsystemctl\s+(?:stop|disable)\s+(?:apparmor|ufw|firewalld|nftables|fail2ban)|\bapparmor_parser\s+-R)",
     ("iptables", "ufw", "nft", "setenforce", "aa-teardown", "systemctl", "apparmor_parser")),
    ("process_hiding", "high", "hiding", "Process hidden (bind mount over /proc, fake name)",
     r"(?i)(\bmount\s+(?:-o\s+bind|--bind|-B)\s+\S+\s+/proc/\d+|\bexec\s+-a\s+['\"]?\[?(?:kworker|kthreadd|ksoftirqd|migration|rcu_\w+|systemd\S*)|\bprctl\b[^\n]*PR_SET_NAME|\bhidepid=)",
     ("mount", "exec -a", "prctl", "hidepid")),
    ("history_evasion", "medium", "log_tampering", "Shell history evasion",
     r"(?i)(\bHISTIGNORE=|\bHISTCONTROL=ignore(?:space|both)|\bunset\s+HISTSIZE\b|\bkill\s+-9\s+\$\$|\bexport\s+HISTTIMEFORMAT=\s*$|\bbash\s+--norc\s+--noprofile|\bsh\s+-c\s+['\"]\s+)",
     ("hist", "kill -9", "--norc", "sh -c")),
    ("container_escape", "high", "privilege", "Container escape or host mount",
     r"(?i)(\bdocker\s+run\b[^\n]*(?:--privileged|-v\s+/:/|--pid=host|--net=host[^\n]*--privileged)|\bnsenter\s+(?:-\w+\s+)*-t\s+1\b|\blxc\s+config\s+[^\n]*security\.privileged\s+true|\bmount\s+/dev/(?:sd|xvd|nvme|vd)\w*\s+/\S+|\bchroot\s+/(?:mnt|host)\b)",
     ("docker", "nsenter", "lxc", "mount", "chroot")),
    ("staging_serve", "medium", "exfil", "Files served or packed for pickup",
     r"(?i)(python[23]?\s+-m\s+(?:http\.server|SimpleHTTPServer)|\bphp\s+-S\s+0\.0\.0\.0|\btar\b[^\n]*\|\s*(?:nc|ncat|ssh|curl|openssl)\b|\brsync\b[^\n]*\s\S+@[\w.-]+:|\b(?:transfer\.sh|file\.io|0x0\.st|termbin\.com|anonfiles|gofile\.io|pastebin\.com/raw|temp\.sh|bashupload)\b)",
     ("python", "php", "tar", "rsync", "transfer.sh", "file.io", "0x0.st", "termbin", "anonfiles", "gofile", "pastebin", "temp.sh", "bashupload")),
    ("exfiltration", "medium", "exfil", "Data sent out of the system",
     r"(?i)(\bcurl\s+.*(?:-T\s|--upload-file|-F\s*['\"]?\w+=@|--data-binary\s+@)|\bwget\s+.*--post-file|\bscp\s+\S+\s+\S+@\S+:|"
     r"\brclone\s+(?:copy|sync|move)\b|\bnc(?:at)?\s+\S+\s+\d+\s*<|Invoke-WebRequest\s+.*-InFile|\bmegacmd|\bmega-put\b)",
     ("curl", "wget", "scp", "rclone", "nc", "invoke-webrequest", "mega")),
    ("cover_tracks_search", "low", "leftover", "Search or note about covering tracks",
     r"(?i)\b(?:clear|delete|wipe|erase|remove|hide|cover)(?:\+|\s|%20)+(?:\w+(?:\+|\s|%20)+){0,2}"
     r"(?:logs?|history|tracks|traces|evidence|event(?:\+|\s|%20)?logs?)\b",
     ("log", "history", "track", "trace", "evidence")),
]

def trie_regex(words, keep_all=False):
    """One regex for 'any of these substrings', shaped as a prefix tree so shared prefixes are
    tested once. Much faster than a flat alternation of hundreds of literals. Optional parts are
    greedy, so a match is the longest word starting at that position."""
    words = sorted(set(words), key=len)
    kept = []
    for w in words:  # a word that contains a shorter hint adds nothing to an "any of" test
        if keep_all or not any(k in w for k in kept):
            kept.append(w)
    trie = {}
    for w in kept:
        node = trie
        for ch in w:
            node = node.setdefault(ch, {})
        node[""] = True

    def build(node):
        if "" in node and len(node) == 1:
            return ""
        alts = [re.escape(ch) + build(sub) for ch, sub in sorted(node.items()) if ch]
        body = alts[0] if len(alts) == 1 else "(?:" + "|".join(alts) + ")"
        return "(?:" + body + ")?" if "" in node else body
    return re.compile(build(trie))


FINDING_RULES = [(rid, sev, re.compile(rx), trie_regex(hints) if hints else None)
                 for rid, sev, _cat, _desc, rx, hints in _RULES]
# One alternation of every hint substring: if a line contains none of them, only the handful of
# hint-less rules can match, so the per-rule loop is skipped. Cheap C-level pre-filter.
_ALL_HINTS = sorted({h for _r, _s, _c, _d, _rx, hints in _RULES if hints for h in hints}, key=len, reverse=True)
_ANY_HINT = trie_regex(_ALL_HINTS)
# Inverted index: one left-to-right scan finds every hint in a line (the longest hint starting at
# each position; any shorter hint there is a prefix of it), then only the rules owning those hints run.
_HINT_SCAN = re.compile("(?=(" + trie_regex(_ALL_HINTS, keep_all=True).pattern + "))")
_HINT_RULES = {}
for _i, (_rid, _s, _c, _d, _rx, _hints) in enumerate(_RULES):
    for _h in (_hints or ()):
        _HINT_RULES.setdefault(_h, set()).add(_i)
_HINT_MAXLEN = max(map(len, _ALL_HINTS)) if _ALL_HINTS else 0
_HINTLESS_IDX = {i for i, r in enumerate(FINDING_RULES) if r[3] is None}
_HINTLESS = [(rid, sev, rx) for rid, sev, rx, hints in FINDING_RULES if hints is None]
RULE_INFO = {rid: {"severity": sev, "category": cat, "description": desc} for rid, sev, cat, desc, _rx, _h in _RULES}

# ------------------------------------------------ file- and case-level rules ---
FILE_RULES = {
    # file content
    "nul_truncation": ("high", "log_tampering", "File starts with NUL bytes: truncated while a program kept writing"),
    "nul_region": ("medium", "wiping", "Block of NUL bytes inside a text file (zeroed or overwritten)"),
    "all_zero": ("high", "wiping", "File is entirely NUL bytes (wiped)"),
    "empty_file": ("low", "wiping", "Empty file (possibly truncated)"),
    "compressed_truncated": ("medium", "log_tampering", "Compressed file ends early or is damaged: only part of it could be read (cut short, partly overwritten or carved)"),
    "archive_path_escape": ("high", "hiding", "Archive holds file names that climb out of the extraction folder (../ or absolute paths): built to overwrite files elsewhere when unpacked"),
    "archive_truncated": ("medium", "log_tampering", "Archive ends early or is damaged: only some of its files could be read"),
    "high_entropy_text": ("high", "wiping", "Text-type file holds random-looking data (overwritten or encrypted)"),
    "magic_mismatch": ("high", "hiding", "File content does not match its extension"),
    "openssl_encrypted": ("medium", "obfuscation", "OpenSSL-encrypted file"),
    "ransom_extension": ("medium", "obfuscation", "Extension typical of encrypted files"),
    # log continuity
    "log_gap": ("medium", "log_tampering", "Unusual silence in a log (entries may have been removed)"),
    "log_backwards": ("medium", "log_tampering", "Log time runs backwards (entries inserted or clock changed)"),
    "record_gap": ("high", "log_tampering", "Missing record numbers in an event log (records removed)"),
    "entries_after_mtime": ("high", "timestomp", "Log has entries dated after the file's modified time"),
    "edited_after_entries": ("low", "log_tampering", "Log modified long after its last entry"),
    "evtx_dirty": ("low", "log_tampering", "Event log file was not closed cleanly"),
    # artifacts
    "recycle_bin": ("medium", "deletion", "Recycle Bin record of a deleted file"),
    "trash_info": ("medium", "deletion", "Desktop Trash record of a deleted file"),
    "vim_swap": ("low", "leftover", "Editor swap file: someone was editing a file"),
    "mft_si_fn": ("high", "timestomp", "MFT: $STANDARD_INFORMATION earlier than $FILE_NAME (timestomp indicator)"),
    "mft_usec_zero": ("medium", "timestomp", "MFT: timestamp with zero sub-seconds"),
    # filesystem metadata (case-wide)
    "future_mtime": ("high", "timestomp", "Modified time is in the future"),
    "zero_ns_mtime": ("medium", "timestomp", "Whole-second modified time where others have sub-seconds (set by a tool)"),
    "backdated_mtime": ("high", "timestomp", "Modified time set back: metadata changed much later"),
    "mass_modification": ("medium", "wiping", "Many files modified within minutes (mass overwrite / encryption)"),
    "metadata_burst": ("low", "timestomp", "Many files had metadata changed within minutes (chmod / touch / move)"),
    "dir_changed_after_children": ("medium", "deletion", "Folder changed after all its current contents (something removed or renamed out)"),
    "rotation_missing": ("medium", "deletion", "Rotated log files missing from a sequence"),
    "rotation_gap": ("low", "log_tampering", "Time gap between consecutive rotated logs"),
    "duplicate_content": ("low", "rename", "Identical content under different names"),
    "diverging_versions": ("low", "rename", "Same file name with different content"),
    "leftover_file": ("low", "leftover", "Backup, temp or lock file left behind"),
}
for _rid, (_sev, _cat, _desc) in FILE_RULES.items():
    RULE_INFO[_rid] = {"severity": _sev, "category": _cat, "description": _desc}

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}

_B64_ARG = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")


def _decode_b64(blob, utf16=False):
    """Best-effort base64 decode; returns printable text or None."""
    try:
        raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
        txt = raw.decode("utf-16-le" if utf16 else "utf-8")
    except (ValueError, UnicodeDecodeError, binascii.Error):
        return None
    printable = sum(c.isprintable() or c in "\r\n\t" for c in txt)
    return txt if txt and printable / len(txt) > 0.9 else None


def run_rules(text):
    """Yield (rule_id, severity, snippet) for each rule that fires on a line.
    Encoded PowerShell and long base64 blobs get a decoded preview appended."""
    if len(text) > MAX_ANALYZE_CHARS:
        text = text[:MAX_ANALYZE_CHARS]
    low = text.lower()
    if not _ANY_HINT.search(low):
        for rid, sev, rx in _HINTLESS:
            m = rx.search(text)
            if m:
                a = max(0, m.start() - 60)
                yield rid, sev, (("…" if a else "") + text[a:m.end() + 140].strip())[:260]
        return
    todo = set(_HINTLESS_IDX)
    seen = set()
    for m0 in _HINT_SCAN.finditer(low):
        w = m0.group(1)
        if w in seen:
            continue
        seen.add(w)
        for k in range(1, len(w) + 1):
            idx = _HINT_RULES.get(w[:k])
            if idx:
                todo |= idx
    for i in sorted(todo):
        rid, sev, rx, hints = FINDING_RULES[i]
        m = rx.search(text)
        if not m:
            continue
        a = max(0, m.start() - 60)
        snip = (("…" if a else "") + text[a:m.end() + 140].strip())[:260]
        if rid in ("encoded_powershell", "long_base64"):
            blobs = _B64_ARG.findall(m.group(0))
            if blobs:
                dec = _decode_b64(max(blobs, key=len), utf16=rid == "encoded_powershell")
                if dec:
                    snip = snip[:120] + "  ⇒ decoded: " + " ".join(dec.split())[:300]
        yield rid, sev, snip


# -------------------------------------------------------------- timestamps ---
_MONTHS = {m: i for i, m in enumerate(
    ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"], 1)}

_TS_ISO = re.compile(
    r"\b((?:19|20)\d\d)[-/.](0[1-9]|1[0-2])[-/.](0[1-9]|[12]\d|3[01])(?:[T_]| {1,2})([01]\d|2[0-3]):([0-5]\d)(?::([0-5]\d))?")
_TS_AUDIT = re.compile(r"audit\((1\d{9})\.\d+:\d+\)")
_TS_APACHE = re.compile(r"\b(0[1-9]|[12]\d|3[01])/([A-Za-z]{3})/((?:19|20)\d\d):([01]\d|2[0-3]):([0-5]\d):([0-5]\d)")
_TS_SYSLOG = re.compile(r"^(?:<\d+>)?([A-Z][a-z]{2})\s+([ 1-3]?\d)\s+([01]\d|2[0-3]):([0-5]\d):([0-5]\d)")
_TS_ZSH = re.compile(r"^: (1\d{9}):\d+;")
_TS_AUDIT = re.compile(r"\baudit\((1\d{9})\.\d{3}:\d+\)")
_TS_US = re.compile(
    r"\b(0?[1-9]|1[0-2])/(0?[1-9]|[12]\d|3[01])/((?:19|20)\d\d)[ ,T]+(0?\d|1\d|2[0-3]):([0-5]\d)(?::([0-5]\d))?\s*([AaPp][Mm])?")
_TS_EU = re.compile(r"\b(0?[1-9]|[12]\d|3[01])\.(0?[1-9]|1[0-2])\.((?:19|20)\d\d)\s+([01]?\d|2[0-3]):([0-5]\d)(?::([0-5]\d))?")
_TS_EPOCH = re.compile(r"[\"']?(?:time(?:stamp)?|ts|@timestamp|epoch|date|created|modified)[\"']?\s*[:=]\s*[\"']?(1[2-9]\d{8})(\d{3})?\b", re.I)
HIST_TS = re.compile(r"^#(1\d{9})\s*$")  # bash history with HISTTIMEFORMAT


def _fmt(y, mo, d, h, mi, s):
    return f"{int(y):04d}-{int(mo):02d}-{int(d):02d} {int(h):02d}:{int(mi):02d}:{int(s or 0):02d}"


def epoch_to_ts(e):
    try:
        if not (0 < e < 4102444800):
            return None
        return datetime.fromtimestamp(e, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    except (OverflowError, OSError, ValueError):
        return None


def ts_to_epoch(ts):
    try:
        return calendar.timegm((int(ts[0:4]), int(ts[5:7]), int(ts[8:10]), int(ts[11:13]), int(ts[14:16]),
                                int(ts[17:19]) if len(ts) >= 19 else 0))
    except (ValueError, TypeError):
        return None


def parse_timestamp(text, default_year=None, ref_epoch=None):
    """Return 'YYYY-MM-DD HH:MM:SS' for the first recognisable timestamp in a line, else None.
    Syslog lines carry no year: default_year is used, stepping back a year if that would put
    the entry after ref_epoch (the file's modified time)."""
    head = text[:400]
    m = _TS_ISO.search(head)
    if m:
        return _fmt(*m.groups())
    m = _TS_APACHE.search(head)
    if m:
        d, mon, y, h, mi, s = m.groups()
        mo = _MONTHS.get(mon.lower())
        if mo:
            return _fmt(y, mo, d, h, mi, s)
    m = _TS_SYSLOG.search(head)
    if m and default_year:
        mon, d, h, mi, s = m.groups()
        mo = _MONTHS.get(mon.lower())
        if mo:
            ts = _fmt(default_year, mo, d, h, mi, s)
            if ref_epoch and (ts_to_epoch(ts) or 0) > ref_epoch + 30 * 86400:
                ts = _fmt(default_year - 1, mo, d, h, mi, s)
            return ts
    m = _TS_ZSH.search(head) or _TS_AUDIT.search(head)
    if m:
        return epoch_to_ts(int(m.group(1)))
    m = _TS_US.search(head)
    if m:
        mo, d, y, h, mi, s, ampm = m.groups()
        h = int(h)
        if ampm:
            h = (h % 12) + (12 if ampm.lower() == "pm" else 0)
        return _fmt(y, mo, d, h, mi, s)
    m = _TS_EU.search(head)
    if m:
        d, mo, y, h, mi, s = m.groups()
        return _fmt(y, mo, d, h, mi, s)
    m = _TS_AUDIT.search(head)
    if m:
        return epoch_to_ts(int(m.group(1)))
    m = _TS_EPOCH.search(head)
    if m:
        return epoch_to_ts(int(m.group(1)))
    return None


# ------------------------------------------------------- filename helpers ---
TEXT_LIKE_EXT = {".log", ".txt", ".csv", ".tsv", ".json", ".jsonl", ".ndjson", ".xml", ".conf", ".cfg", ".ini",
                 ".yaml", ".yml", ".md", ".html", ".htm", ".js", ".ps1", ".psm1", ".bat", ".cmd", ".sh", ".py",
                 ".php", ".sql", ".env", ".out", ".err", ".audit", ".syslog", ".properties", ".toml"}
LEFTOVER_RX = re.compile(
    r"(?i)(^\..+\.sw[a-p]$|\.swp$|~$|\.(?:bak|old|orig|tmp|temp|save|backup|bkp|un~|rej|part|crdownload)$|"
    r"^#.+#$|^\.~lock\.|^~\$|^\.nfs[0-9a-f]{8,})")
RANSOM_EXT_RX = re.compile(r"(?i)\.(?:enc|encrypted|locked|crypt|crypted|cry|crypto|locky|wncry|wnry|ryk|lockbit|"
                           r"akira|blackcat|conti|cerber|zepto)$")
ROTATION_RX = re.compile(r"^(?P<base>.+?)\.(?P<n>\d{1,3})(?P<comp>\.(?:gz|bz2|xz|zip))?$")
RECORD_ID_RX = re.compile(
    r"(?i)(?:EventRecordID|RecordNumber|record_?id|RecordId)[\"'>\s:=]{1,4}(\d{1,12})|audit\(\d+\.\d+:(\d+)\)")


# ------------------------------------------------ entity plausibility checks ---
_ESCAPE_SEG = re.compile(r"^[A-Za-z][^\w\s.\-$~]")  # \w'…, \n(…, \h'…  -> regex / escape residue


def plausible_win_path(v):
    """Reject strings that only look like C:\\... because of regex escapes, code or binary noise."""
    body = v[3:] if len(v) > 3 else ""
    if not body or any(c in v for c in "'`\"^"):
        return False
    segs = [s for s in body.split("\\") if s]
    if not segs:
        return False
    for s in segs:
        if _ESCAPE_SEG.match(s):
            return False
        if s.count("(") != s.count(")") or s.count("[") != s.count("]") or s.count("{") != s.count("}"):
            return False
    good = sum(c.isalnum() or c in " ._-\\$~" for c in v)
    if good / len(v) < 0.85:
        return False
    return any(sum(c.isalpha() for c in s) >= 2 for s in segs)


ENTITY_VALIDATORS = {"win_path": plausible_win_path}

_orig_extract_entities = extract_entities


def extract_entities(text):  # noqa: F811  (wraps the extractor with validators)
    for etype, value, meta in _orig_extract_entities(text):
        check = ENTITY_VALIDATORS.get(etype)
        if check is None or check(value):
            yield etype, value, meta


# ------------------------------------------------------------- line times ---
def _loose_time(s):
    """Parse a timestamp or a bare date written in a command argument."""
    s = s.strip().strip("\"'")
    ts = parse_timestamp(s)
    if ts:
        return ts
    m = re.search(r"\b((?:19|20)\d\d)[-/.](\d\d?)[-/.](\d\d?)\b", s)
    if m:
        return _fmt(m.group(1), m.group(2), m.group(3), 0, 0, 0)
    m = re.search(r"\b(\d\d?)/(\d\d?)/((?:19|20)\d\d)\b", s)
    if m:
        return _fmt(m.group(3), m.group(1), m.group(2), 0, 0, 0)
    return None


def _touch_t(v):
    """touch -t [[CC]YY]MMDDhhmm[.ss]"""
    m = re.fullmatch(r"(\d{8,12})(?:\.(\d\d))?", v)
    if not m:
        return None
    d, ss = m.group(1), m.group(2) or "00"
    if len(d) == 12:
        y, rest = d[:4], d[4:]
    elif len(d) == 10:
        y, rest = ("19" if int(d[:2]) >= 69 else "20") + d[:2], d[2:]
    elif len(d) == 8:
        y, rest = str(datetime.now().year), d
    else:
        return None
    try:
        return _fmt(y, rest[0:2], rest[2:4], rest[4:6], rest[6:8], ss)
    except ValueError:
        return None


_SET_PATTERNS = [
    # (regex, label, parser) — group 1 is the value the command sets
    (re.compile(r"\btouch\s+(?:-\w+\s+)*-[a-z]*t\s+(\d{8,12}(?:\.\d\d)?)"), "touch -t sets file times", _touch_t),
    (re.compile(r"\btouch\s+(?:-\w+\s+)*(?:-[a-z]*d|--date)[= ]\s*(\"[^\"]+\"|'[^']+'|\S+)"), "touch -d sets file times", _loose_time),
    (re.compile(r"(?i)\.(?:CreationTime|LastWriteTime|LastAccessTime)(?:Utc)?\s*=\s*(?:\(?\s*(?:Get-Date|\[datetime\])\s*)?(\"[^\"]+\"|'[^']+')"),
     "PowerShell sets a file time", _loose_time),
    (re.compile(r"(?i)\bdate\s+(?:-u\s+)?(?:-s|--set)[= ]\s*(\"[^\"]+\"|'[^']+'|\S+)"), "date -s sets the system clock", _loose_time),
    (re.compile(r"(?i)\btimedatectl\s+set-time\s+(\"[^\"]+\"|'[^']+'|\S+)"), "timedatectl sets the system clock", _loose_time),
    (re.compile(r"(?i)\bSet-Date\s+(?:-Date\s+)?(\"[^\"]+\"|'[^']+'|\S+)"), "Set-Date sets the system clock", _loose_time),
    (re.compile(r"(?i)(?<!Previous)CreationUtcTime[\"']?\s*[:=>]\s*[\"']?([0-9][0-9:. /T-]{9,})"), "new creation time (Sysmon event 2)", _loose_time),
]
_PREV_PATTERNS = [
    (re.compile(r"(?i)PreviousCreationUtcTime[\"']?\s*[:=>]\s*[\"']?([0-9][0-9:. /T-]{9,})"), "original creation time (Sysmon event 2)"),
]
_REF_TOUCH = re.compile(r"\btouch\s+(?:-\w+\s+)*(?:-[a-z]*r|--reference)[= ]\s*(\S+)")
_NUM_TIME = re.compile(r"(?<![\w.])(?:0x(01d[0-9a-f]{13})|(1[23]\d{16})|(1[23]\d{15})|(1[2-9]\d{14})|(1[2-9]\d{11})|(1[2-9]\d{8})|0x([56][0-9a-f]{7}))(?![\w])", re.I)
_ALL_TS = [_TS_ISO, _TS_APACHE, _TS_US, _TS_EU]


def line_times(text, own_ts=None, limit=12):
    """Every time mentioned in a line, labelled by role:
    'line'     the time the line was written (what Crumbs sorts by)
    'set'      a time a command writes onto a file or clock: the claimed / fake time
    'previous' the value before a change (Sysmon's PreviousCreationUtcTime): the real one
    'written'  other readable times in the text
    'decoded'  numbers that decode to plausible dates (epoch, ms, µs, FILETIME, WebKit, hex)"""
    text = text[:MAX_ANALYZE_CHARS]
    out, seen = [], set()

    def add(raw, ts, role, kind):
        key = (ts, role)
        if not ts or key in seen or len(out) >= limit:
            return
        seen.add(key)
        out.append({"raw": raw[:80], "ts": ts, "role": role, "kind": kind})

    for rx, label, parse in _SET_PATTERNS:
        for m in rx.finditer(text):
            add(m.group(1), parse(m.group(1)), "set", label)
    for rx, label in _PREV_PATTERNS:
        for m in rx.finditer(text):
            add(m.group(1), _loose_time(m.group(1)), "previous", label)
    m = _REF_TOUCH.search(text)
    if m:
        out.append({"raw": m.group(1), "ts": None, "role": "set", "kind": f"touch -r copies the times of {m.group(1)}"})
    claimed = {x["raw"] for x in out}
    if own_ts:
        add(own_ts, own_ts, "line", "time of this entry")
    for rx in _ALL_TS:
        for m in rx.finditer(text):
            if any(m.group(0) in c or c in m.group(0) for c in claimed):
                continue
            ts = parse_timestamp(m.group(0))
            if ts and ts != own_ts:
                add(m.group(0), ts, "written", "timestamp in the text")
    for m in _NUM_TIME.finditer(text):
        ft_hex, ft, wk, us, ms, s, hx = m.groups()
        try:
            if ft_hex:
                ts, kind = epoch_to_ts(int(ft_hex, 16) / 1e7 - 11644473600), "FILETIME (hex)"
            elif ft:
                ts, kind = epoch_to_ts(int(ft) / 1e7 - 11644473600), "FILETIME"
            elif wk:
                ts, kind = epoch_to_ts(int(wk) / 1e6 - 11644473600), "WebKit / Chrome time"
            elif us:
                ts, kind = epoch_to_ts(int(us) / 1e6), "Unix microseconds"
            elif ms:
                ts, kind = epoch_to_ts(int(ms) / 1e3), "Unix milliseconds"
            elif s:
                ts, kind = epoch_to_ts(int(s)), "Unix seconds"
            else:
                ts, kind = epoch_to_ts(int(hx, 16)), "Unix seconds (hex)"
        except ValueError:
            continue
        if ts and ts != own_ts:
            add(m.group(0), ts, "decoded", kind + ", UTC")
    return out


# ------------------------------------------------------------ deobfuscation ---
import gzip as _gzip
import zlib as _zlib
from urllib.parse import unquote_plus as _unquote_plus

_KEYWORDS = ("http", "https", "powershell", "cmd.exe", "cmd /c", "iex", "invoke", "system32", "windows", "/bin/",
             "bash", "wget", "curl", "password", "admin", ".exe", ".dll", ".ps1", "download", "net.webclient",
             "frombase64", "select", "echo", "user", "shell", "exec", "eval", "/tmp/", "c:\\", "function", "return")
_B64 = re.compile(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=])")
_B64URL = re.compile(r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{24,}={0,2}(?![A-Za-z0-9_=-])")
_HEX = re.compile(r"(?<![0-9a-fA-F])(?:0x)?((?:[0-9a-fA-F]{2}){8,})(?![0-9a-fA-F])")
_HEX_ESC = re.compile(r"(?:\\x[0-9a-fA-F]{2}){4,}")
_U_ESC = re.compile(r"(?:\\u[0-9a-fA-F]{4}){3,}")
_CHARS_PS = re.compile(r"\[char\]\s*(0x[0-9a-f]+|\d+)", re.I)
_CHARS_JS = re.compile(r"fromCharCode\s*\(\s*([\d\s,]+)\)", re.I)
_CHARS_CHR = re.compile(r"\bchrw?\s*\(\s*(\d+)\s*\)", re.I)
_NUMLIST = re.compile(r"[(\[{@]\s*((?:\d{2,3}\s*,\s*){5,}\d{2,3})\s*[)\]}]")
_PS_FMT = re.compile(r"\(\s*[\"']((?:\{\d+\})+)[\"']\s*-f\s*((?:[\"'][^\"']*[\"']\s*,?\s*)+)\)", re.I)


def _kw_score(s):
    low = s.lower()
    return sum(k in low for k in _KEYWORDS)


def _printable_ratio(s):
    return sum(c.isprintable() or c in "\r\n\t" for c in s) / len(s) if s else 0


def _bytes_to_text(b):
    """Best text rendering of decoded bytes, or None if it is not text."""
    if len(b) >= 4 and b[:2] == b"\x1f\x8b":
        try:
            t, how = _bytes_to_text(_gzip.decompress(b))
            if t:
                return t, "gzip" + (" → " + how if how else "")
        except (OSError, EOFError):
            pass
    for wbits, name in ((-15, "deflate"), (15, "zlib")):
        try:
            inner = _zlib.decompress(b, wbits)
            if inner:
                t = _bytes_to_text(inner)
                if t[0]:
                    return t[0], name + (" → " + t[1] if t[1] else "")
        except _zlib.error:
            pass
    if len(b) >= 4 and b[1::2].count(0) > 0.4 * len(b[1::2]):
        try:
            t = b.decode("utf-16-le")
            if _printable_ratio(t) > 0.9:
                return t, "utf-16"
        except UnicodeDecodeError:
            pass
    for enc in ("utf-8", "latin-1"):
        try:
            t = b.decode(enc)
        except UnicodeDecodeError:
            continue
        ascii_ok = sum(32 <= ord(c) < 127 or c in "\r\n\t" for c in t) / len(t)
        if ascii_ok > 0.9 and sum(c.isalnum() or c == " " for c in t) / len(t) > 0.5:
            return t, ""
        break
    return None, ""


def _xor_brute(b):
    """Single-byte XOR key that turns bytes into readable text, if any."""
    if len(b) < 8:
        return None
    best = None
    for k in range(1, 256):
        x = bytes(c ^ k for c in b[:4096])
        try:
            t = x.decode("latin-1")
        except UnicodeDecodeError:
            continue
        p = sum(32 <= ord(c) < 127 or c in "\r\n\t" for c in t) / len(t)
        alpha = sum(("a" <= c.lower() <= "z") or c == " " for c in t) / len(t)
        score = p + alpha + 0.2 * _kw_score(t)
        if p > 0.95 and alpha > 0.6 and (_kw_score(t) or re.search(r"(?:[A-Za-z]{3,}[ ./:\\_-]+){3,}", t)) \
                and (best is None or score > best[0]):
            best = (score, k, bytes(c ^ k for c in b).decode("latin-1"))
    return best


_AUDIT_ARG = re.compile(r'\ba(\d+)=("(?:[^"\\]|\\.)*"|[0-9A-Fa-f]+|\(null\))')
_AUDIT_HEXFIELD = re.compile(r'\b(proctitle|cmd)=("[^"]*"|[0-9A-Fa-f]{4,})')


def _audit_val(v):
    if v.startswith('"'):
        return v[1:-1]
    if v == "(null)":
        return ""
    try:
        return bytes.fromhex(v).decode("utf-8", "replace").replace("\x00", " ").strip()
    except ValueError:
        return v


def audit_command(text):
    """auditd EXECVE a0..aN / PROCTITLE / USER_CMD hex fields -> readable command line."""
    if "type=EXECVE" in text:
        args = sorted(((int(n), _audit_val(v)) for n, v in _AUDIT_ARG.findall(text)), key=lambda x: x[0])
        if args:
            return " ".join(a for _n, a in args)
    m = _AUDIT_HEXFIELD.search(text)
    if m:
        return _audit_val(m.group(2))
    return None


def decode_candidates(text, depth=0):
    """Try common encodings and obfuscation tricks; return readable results only."""
    text = text[:MAX_ANALYZE_CHARS]
    out, seen = [], {text.strip()}

    def add(method, src, res):
        if res is None:
            return
        res = res.replace("\x00", "").strip()
        if len(res) < 3 or res in seen or len(out) >= 25:
            return
        seen.add(res)
        out.append({"method": method, "input": src[:120], "output": res[:4000]})
        if depth < 2:
            for sub in decode_candidates(res, depth + 1)[:4]:
                if sub["output"] not in seen:
                    seen.add(sub["output"])
                    out.append({"method": method + " → " + sub["method"], "input": src[:120], "output": sub["output"]})

    def from_bytes(method, src, b):
        t, how = _bytes_to_text(b)
        if t:
            add(method + (" → " + how if how else ""), src, t)
        else:
            x = _xor_brute(b)
            if x:
                add(f"{method} → XOR key 0x{x[1]:02x}", src, x[2])

    if "type=EXECVE" in text or "proctitle=" in text or "type=USER_CMD" in text:
        cmd = audit_command(text)
        if cmd:
            add("auditd command", text[:60], cmd)
    for rx, name, alt in ((_B64, "base64", None), (_B64URL, "base64url", ("-", "+", "_", "/"))):
        for m in rx.finditer(text):
            s = m.group(0)
            if s.isalpha() and (s.islower() or s.isupper()):
                continue  # plain words
            if all(c in "0123456789abcdefABCDEF" for c in s):
                continue  # hashes and hex are handled below
            if name == "base64url" and not any(c in s for c in "-_"):
                continue
            t = s.replace(alt[0], alt[1]).replace(alt[2], alt[3]) if alt else s
            try:
                b = base64.b64decode(t + "=" * (-len(t) % 4), validate=True)
            except (ValueError, binascii.Error):
                continue
            from_bytes(name, s, b)
    for m in _HEX.finditer(text):
        h = m.group(1)
        if h.isdigit() or len(set(h.lower())) < 6:
            continue
        from_bytes("hex", m.group(0), bytes.fromhex(h))
    for m in _HEX_ESC.finditer(text):
        from_bytes("\\x escapes", m.group(0), bytes.fromhex(m.group(0).replace("\\x", "")))
    for m in _U_ESC.finditer(text):
        add("\\u escapes", m.group(0), "".join(chr(int(x, 16)) for x in re.findall(r"\\u([0-9a-fA-F]{4})", m.group(0))))
    if len(re.findall(r"%[0-9a-fA-F]{2}", text)) >= 3:
        add("URL decoding", text, _unquote_plus(text))
    chars = _CHARS_PS.findall(text)
    if len(chars) >= 3:
        add("[char] codes", " ".join(chars[:10]), "".join(chr(int(c, 0)) for c in chars if int(c, 0) < 0x110000))
    for m in _CHARS_JS.finditer(text):
        nums = [int(x) for x in re.findall(r"\d+", m.group(1))]
        add("fromCharCode", m.group(0), "".join(chr(n) for n in nums if n < 0x110000))
    chr_ = _CHARS_CHR.findall(text)
    if len(chr_) >= 3:
        add("chr() codes", " ".join(chr_[:10]), "".join(chr(int(c)) for c in chr_ if int(c) < 0x110000))
    for m in _NUMLIST.finditer(text):
        nums = [int(x) for x in re.findall(r"\d+", m.group(1))]
        if all(9 <= n < 127 for n in nums):
            add("number list as characters", m.group(0), "".join(chr(n) for n in nums))
    # PowerShell string tricks: format operator, backticks, concatenation
    ps = text
    for _ in range(3):
        m = _PS_FMT.search(ps)
        if not m:
            break
        parts = re.findall(r"[\"']([^\"']*)[\"']", m.group(2))
        try:
            rebuilt = "".join(parts[int(i)] for i in re.findall(r"\{(\d+)\}", m.group(1)))
        except (IndexError, ValueError):
            break
        ps = ps[:m.start()] + "'" + rebuilt + "'" + ps[m.end():]
    ps = re.sub(r"`(?=[A-Za-z])", "", ps)
    ps = re.sub(r"([\"'])\s*\+\s*\1", "", ps)
    if ps != text:
        add("PowerShell / script string tricks removed", text, ps)
    rv = text[::-1]
    if _kw_score(rv) > _kw_score(text):
        add("reversed", text, rv)
    import codecs as _codecs
    r13 = _codecs.encode(text, "rot13")
    if _kw_score(r13) > _kw_score(text) + 1:
        add("ROT13", text, r13)
    return out


_ENCODED_HINT = re.compile(r"type=EXECVE|proctitle=|type=USER_CMD|[A-Za-z0-9+/]{40,}={0,2}|(?:\\x[0-9a-fA-F]{2}){8,}|fromCharCode|\[char\]|(?:%[0-9a-fA-F]{2}){8,}|`[a-z]`|-f\s*['\"]", re.I)
_OBF_RULES = {"obfuscation", "encoded_powershell", "long_base64"}


def hidden_rules(text, fired):
    """Decode a line's encoded parts and run the rules on what they hide.
    Yields (rule_id, severity, snippet) with the decoding path in the snippet."""
    if not (fired & _OBF_RULES or _ENCODED_HINT.search(text[:MAX_ANALYZE_CHARS])):
        return
    seen = set()
    for d in decode_candidates(text)[:8]:
        for rid, sev, snip in run_rules(d["output"]):
            if rid in _OBF_RULES or rid in seen:
                continue
            seen.add(rid)
            yield rid, sev, f"hidden in {d['method']}: {snip}"


_SET_HINT = re.compile(r"(?i)touch|time\s*=|date|creationutctime")


def line_timestamp(text, default_year=None, ref_epoch=None):
    """The time a line was written. Like parse_timestamp, but skips times that a command on the
    line sets (touch -d, date -s, .LastWriteTime =, Sysmon CreationUtcTime...), which are claims,
    not the moment of writing. Returns None if only claimed times are present."""
    ts = parse_timestamp(text, default_year, ref_epoch)
    if not ts or not _SET_HINT.search(text[:400]):
        return ts
    claimed = {x["ts"] for x in line_times(text) if x["role"] in ("set", "previous")}
    if ts not in claimed:
        return ts
    for rx in _ALL_TS:
        for m in rx.finditer(text[:2000]):
            t2 = parse_timestamp(m.group(0))
            if t2 and t2 not in claimed:
                return t2
    return None
