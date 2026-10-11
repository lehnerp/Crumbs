"""
Breadcrumbs of tools that are not part of a base Debian install.

A clean Debian web server ships a known set of packages. Anything an intruder brings - a SOCKS
proxy, a tunneller, a sniffer, a scanner, a C2 agent - is either an extra package, a dropped
binary, a config file, or just a name that shows up in logs, history and scripts. This module
carries a catalogue of such tools (grouped by what they are for) and finds every breadcrumb:

  * an executable of that name in a program folder, or anywhere outside a package;
  * a package of that name in apt / dpkg history;
  * a configuration file the tool uses;
  * the name mentioned in a command, a log line, a script or decoded content.

Each tool that leaves any breadcrumb becomes a `tool_present` fact and (for the offensive /
dual-use ones) a finding, with where it was seen and when. Base-system programs are deliberately
excluded so this stays signal, not noise.
"""
import json
import re
from collections import defaultdict

import analyzers as az

# category -> list of (canonical name, alt names/binaries, [regex word fragments])
CATALOG = {
    "tunnel/proxy": [
        ("socat", ["socat"]), ("netcat-traditional", ["netcat-traditional", "nc.traditional"]),
        ("ncat", ["ncat"]), ("sshuttle", ["sshuttle"]), ("proxychains", ["proxychains", "proxychains4", "proxychains-ng"]),
        ("3proxy", ["3proxy"]), ("microsocks", ["microsocks"]), ("dante", ["danted", "sockd", "dante-server"]),
        ("redsocks", ["redsocks"]), ("gost", ["gost"]), ("chisel", ["chisel"]), ("frp", ["frpc", "frps"]),
        ("ligolo-ng", ["ligolo", "ligolo-ng", "agent", "proxy"]), ("revsocks", ["revsocks"]), ("rathole", ["rathole"]),
        ("stowaway", ["stowaway"]), ("pivotnacci", ["pivotnacci"]), ("nps", ["nps", "npc"]), ("rinetd", ["rinetd"]),
        ("stunnel", ["stunnel", "stunnel4"]), ("bore", ["bore"]), ("localtunnel", ["localtunnel", "lt"]),
        ("ngrok", ["ngrok"]), ("cloudflared", ["cloudflared"]), ("pagekite", ["pagekite"]), ("wstunnel", ["wstunnel"]),
    ],
    "vpn/mesh/anon": [
        ("tor", ["tor", "torsocks", "torify"]), ("wireguard", ["wg", "wg-quick", "wireguard"]),
        ("tailscale", ["tailscale", "tailscaled"]), ("zerotier", ["zerotier-cli", "zerotier-one"]),
        ("nebula", ["nebula"]), ("openvpn", ["openvpn"]), ("softether", ["vpnclient", "vpnserver", "vpncmd"]),
        ("i2p", ["i2prouter", "i2pd"]),
    ],
    "censorship-evasion/C2 transport": [
        ("shadowsocks", ["ss-local", "ss-server", "ss-redir", "sslocal", "ssserver", "shadowsocks"]),
        ("v2ray", ["v2ray"]), ("xray", ["xray"]), ("trojan", ["trojan", "trojan-go"]),
        ("hysteria", ["hysteria"]), ("naiveproxy", ["naive", "naiveproxy"]), ("gost-plugin", ["gost-plugin"]),
    ],
    "dns/icmp tunnel": [
        ("iodine", ["iodine", "iodined"]), ("dnscat2", ["dnscat", "dnscat2"]), ("dns2tcp", ["dns2tcp", "dns2tcpc", "dns2tcpd"]),
        ("dnstt", ["dnstt-client", "dnstt-server"]), ("ptunnel", ["ptunnel", "ptunnel-ng"]), ("icmpsh", ["icmpsh"]),
        ("hans", ["hans"]), ("icmptunnel", ["icmptunnel"]), ("pingtunnel", ["pingtunnel"]), ("udp2raw", ["udp2raw"]),
        ("kcptun", ["kcptun", "kcpclient", "kcpserver"]),
    ],
    "web tunnel": [
        ("reGeorg", ["regeorg", "reGeorgSocksProxy"]), ("neo-reGeorg", ["neoreg", "neo-regeorg"]),
        ("tunna", ["tunna"]), ("abptts", ["abptts"]), ("pystinger", ["pystinger", "stinger_server", "stinger_client"]),
        ("suo5", ["suo5"]), ("reDuh", ["reduh"]),
    ],
    "sniffer/MITM": [
        ("tcpdump", ["tcpdump"]), ("tshark", ["tshark", "wireshark", "dumpcap"]), ("ngrep", ["ngrep"]),
        ("netsniff-ng", ["netsniff-ng"]), ("dsniff", ["dsniff", "urlsnarf", "mailsnarf", "msgsnarf", "filesnarf", "webspy"]),
        ("ettercap", ["ettercap"]), ("bettercap", ["bettercap"]), ("arpspoof", ["arpspoof"]),
        ("responder", ["responder"]), ("mitm6", ["mitm6"]), ("sslstrip", ["sslstrip", "sslstrip2"]),
        ("sslsplit", ["sslsplit"]), ("mitmproxy", ["mitmproxy", "mitmdump", "mitmweb"]), ("bdfproxy", ["bdfproxy"]),
        ("driftnet", ["driftnet"]), ("singularity", ["singularity"]),  # DNS rebinding framework
    ],
    "scanner/recon": [
        ("nmap", ["nmap"]), ("masscan", ["masscan"]), ("zmap", ["zmap"]), ("rustscan", ["rustscan"]),
        ("naabu", ["naabu"]), ("nuclei", ["nuclei"]), ("httpx", ["httpx"]), ("zgrab", ["zgrab", "zgrab2"]),
        ("gobuster", ["gobuster"]), ("ffuf", ["ffuf"]), ("feroxbuster", ["feroxbuster"]), ("dirsearch", ["dirsearch"]),
        ("nikto", ["nikto"]), ("wpscan", ["wpscan"]), ("whatweb", ["whatweb"]), ("arp-scan", ["arp-scan"]),
        ("netdiscover", ["netdiscover"]), ("fscan", ["fscan"]), ("kscan", ["kscan"]),
    ],
    "exploit/cracking": [
        ("sqlmap", ["sqlmap"]), ("hydra", ["hydra"]), ("medusa", ["medusa"]), ("ncrack", ["ncrack"]),
        ("john", ["john"]), ("hashcat", ["hashcat"]), ("crackmapexec", ["crackmapexec", "cme", "nxc", "netexec"]),
        ("impacket", ["impacket", "psexec.py", "secretsdump.py", "wmiexec.py", "smbexec.py", "GetUserSPNs.py"]),
        ("metasploit", ["msfconsole", "msfvenom", "meterpreter"]), ("sliver", ["sliver-client", "sliver-server"]),
        ("havoc", ["havoc"]), ("villain", ["villain"]), ("pwncat", ["pwncat", "pwncat-cs"]), ("evil-winrm", ["evil-winrm"]),
    ],
    "post-exploitation/privesc": [
        ("linpeas", ["linpeas"]), ("linenum", ["linenum"]), ("les", ["linux-exploit-suggester", "les.sh"]),
        ("pspy", ["pspy", "pspy32", "pspy64"]), ("deepce", ["deepce"]), ("traitor", ["traitor"]),
        ("mimipenguin", ["mimipenguin"]), ("lazagne", ["lazagne"]), ("gtfoblookup", ["gtfoblookup"]),
    ],
    "rootkit": [
        ("diamorphine", ["diamorphine"]), ("reptile", ["reptile"]), ("suterusu", ["suterusu"]), ("azazel", ["azazel"]),
        ("jynx", ["jynx", "jynx2"]), ("beurk", ["beurk"]), ("bdvl", ["bdvl", "bedevil"]), ("vlany", ["vlany"]),
        ("libprocesshider", ["libprocesshider", "processhider"]), ("brokepkg", ["brokepkg"]), ("symbiote", ["symbiote"]),
    ],
    "miner": [
        ("xmrig", ["xmrig"]), ("xmr-stak", ["xmr-stak"]), ("cpuminer", ["cpuminer", "minerd"]),
        ("kinsing", ["kinsing", "kdevtmpfsi"]),
    ],
    "offensive web middleware": [
        ("rack-attack", ["rack-attack", "rack_attack"]),  # abused for throttling bypass / recon in Rack apps
    ],
}
# which categories are offensive enough to raise a finding even on a single mention
OFFENSIVE_CATS = {"censorship-evasion/C2 transport", "dns/icmp tunnel", "web tunnel", "sniffer/MITM",
                  "scanner/recon", "exploit/cracking", "post-exploitation/privesc", "rootkit", "miner"}
# dual-use: only a finding when found as a dropped binary / extra package / its own config, not a mere mention
DUALUSE_CATS = {"tunnel/proxy", "vpn/mesh/anon", "offensive web middleware"}

# Plain-language description of each tool — shown in the Tools view and in the report so
# an investigator who hasn't heard of "diamorphine" knows what they're looking at.
TOOL_DESC = {
    # tunnel / proxy
    "socat":            "Swiss-army relay: connects two byte streams of almost any type (TCP, UDP, TLS, files, shells). Commonly abused to forward ports, create reverse shells, or bridge traffic between network segments.",
    "netcat-traditional": "Classic 'network cat' that reads and writes raw TCP/UDP. The go-to tool for reverse shells, port scanning, and ad-hoc data transfer.",
    "ncat":             "Nmap's modern netcat replacement, with TLS, proxying and connection brokering built in. Used for the same reverse-shell and pivoting purposes as netcat.",
    "sshuttle":         "Transparent VPN-over-SSH that forwards all TCP traffic through an SSH connection without requiring root on the server. Attackers use it to reach internal hosts through a compromised jump box.",
    "proxychains":      "Forces any program's network traffic through a chain of SOCKS or HTTP proxies. Used to anonymise attacker tooling or route it through already-compromised hosts.",
    "3proxy":           "Tiny but full-featured proxy server supporting HTTP CONNECT, SOCKS4/5 and TCP port-forwarding. Often dropped as a pivot point inside a network.",
    "microsocks":       "Minimal SOCKS5 proxy in a single small binary — easy to upload and run on a compromised host to relay traffic further into the network.",
    "dante":            "Full SOCKS4/5 server daemon (package: dante-server). Installed on a compromised host to give the attacker a persistent SOCKS proxy into the network.",
    "redsocks":         "Redirects any TCP connection transparently through a SOCKS or HTTP proxy. Used alongside iptables to silently reroute traffic on a compromised machine.",
    "gost":             "Go Simple Tunnel: proxy and tunnelling tool supporting HTTP, SOCKS5, Shadowsocks and WebSocket. Used for pivoting and C2 channel obfuscation.",
    "chisel":           "HTTP/WebSocket tunnel that creates a TCP tunnel over HTTP or HTTPS. Widely used in intrusions because it blends with normal web traffic and needs no special firewall rules.",
    "frp":              "Fast Reverse Proxy (frpc = client, frps = server). Maps internal services to an external frp server controlled by the attacker, providing persistent inbound access past NAT.",
    "ligolo-ng":        "Agent-and-proxy tunnel that lets an attacker route traffic to internal networks through a compromised host using a TUN interface, without needing a SOCKS proxy on every tool.",
    "revsocks":         "Reverse-SOCKS5 proxy: the compromised host connects outbound to the attacker's server and a SOCKS proxy opens there, bypassing inbound firewall rules.",
    "rathole":          "Rust-based secure tunnel for exposing internal services through NAT, similar to frp. Used for persistent backdoor access.",
    "stowaway":         "Multi-level SOCKS proxy and pivot tool designed for penetration testing and used by attackers to build tunnelled networks through chains of compromised hosts.",
    "pivotnacci":       "Pivoting tool that routes SOCKS traffic over HTTP(S) sessions to a deployed web agent, blending C2 traffic with web requests.",
    "nps":              "Intranet penetration proxy (npc = client). Tunnels internal services to an external server; provides a web UI for managing tunnels.",
    "rinetd":           "Simple TCP/UDP port redirector — one config line forwards a local port to any remote address. Very lightweight and easy to run persistently.",
    "stunnel":          "Wraps plain TCP connections inside TLS. Used by attackers to encrypt non-TLS C2 channels or proxy traffic so it looks like legitimate HTTPS.",
    "bore":             "Minimal Rust tool that exposes local ports to the internet through a public bore.dev server (or self-hosted). Used for quick reverse tunnels.",
    "localtunnel":      "Exposes localhost to the internet via a public URL. Attacker usage: quick outbound tunnel through any firewall that allows HTTPS.",
    "ngrok":            "Tunnels local ports to public ngrok.io subdomains over HTTPS. Frequently abused to establish C2 over outbound HTTPS without opening inbound firewall holes.",
    "cloudflared":      "Cloudflare's tunnel daemon (cloudflared). Creates outbound-only tunnels to Cloudflare's edge, giving the attacker a persistent HTTPS endpoint with no inbound firewall exposure.",
    "pagekite":         "Reverse tunnel service that publishes local servers through the PageKite relay. Used to establish C2 channels that blend with HTTPS.",
    "wstunnel":         "Tunnels arbitrary TCP or UDP traffic inside WebSocket connections. Used to smuggle C2 traffic through web proxies that only allow WebSocket upgrades.",
    # VPN / mesh / anon
    "tor":              "Anonymity network that routes traffic through three encrypted relays to hide the origin. A HiddenServicePort entry in torrc exposes a service (e.g. SSH) as a .onion address, giving the attacker a covert, censor-resistant inbound channel.",
    "wireguard":        "Modern, minimal VPN using state-of-the-art cryptography. Attackers install it on a compromised host to create an encrypted tunnel back to their infrastructure, harder to detect than OpenVPN or IPSec.",
    "tailscale":        "Mesh VPN built on WireGuard that handles NAT traversal automatically. An attacker with a Tailscale auth key can join the compromised machine to their private mesh and access it from anywhere.",
    "zerotier":         "Software-defined mesh networking that connects devices into a virtual LAN regardless of NAT. Used by attackers to integrate a compromised host into their own virtual network.",
    "nebula":           "Overlay mesh VPN from Slack (open-sourced). Lightweight, certificate-based, and capable of NAT traversal — used for the same purpose as ZeroTier or Tailscale.",
    "openvpn":          "Mature SSL/TLS VPN. Found on compromised hosts when an attacker needs a traditional VPN client config to tunnel traffic to their own server.",
    "softether":        "Multi-protocol VPN server/client supporting L2TP, OpenVPN and SSTP. Its unusual protocols can bypass firewalls that block standard VPN ports.",
    "i2p":              "Invisible Internet Project — an anonymity network focused on internal services ('eepsites'). Less common than Tor but harder to detect and block.",
    # C2 / censorship-evasion
    "shadowsocks":      "Encrypted SOCKS5 proxy originally designed to bypass censorship. In intrusions it is used as a covert C2 transport because its traffic looks like random HTTPS to deep-packet inspection.",
    "v2ray":            "Modular proxy platform supporting VMess, VLESS, and many other protocols. Designed for censorship evasion but used by attackers because its traffic is nearly indistinguishable from normal HTTPS.",
    "xray":             "Fork of v2ray with additional protocols (XTLS). Same uses: covert C2 transport that defeats traffic analysis.",
    "trojan":           "Proxy protocol that masquerades as legitimate HTTPS traffic to a real TLS server, making it nearly impossible to distinguish from normal HTTPS without the key.",
    "hysteria":         "High-speed UDP-based proxy (QUIC) designed for censorship evasion. Attackers use it for fast covert channels that bypass TCP-focused firewalls.",
    "naiveproxy":       "Proxy that tunnels traffic inside standard HTTP/2 CONNECT to look exactly like browser traffic, even under active probing.",
    "gost-plugin":      "ShadowsocksR plugin that routes traffic through a GOST relay, adding another layer of obfuscation to already-encrypted C2 channels.",
    # DNS / ICMP tunnels
    "iodine":           "Tunnels IP traffic inside DNS queries and responses. Bypasses firewalls that only allow DNS out — the attacker controls the authoritative DNS server for a domain and reads data from the query names.",
    "dnscat2":          "Creates a C2 channel entirely inside DNS. The compromised host resolves attacker-controlled domain names; answers carry C2 instructions back. Encrypted and hard to detect without DNS inspection.",
    "dns2tcp":          "Relays TCP connections over DNS queries. Older but simple and effective for bypassing captive portals or firewalls that pass DNS.",
    "dnstt":            "Tunnels TCP over DNS or DoH (DNS-over-HTTPS). The DoH variant makes the traffic look like encrypted HTTPS, defeating DNS-inspection controls.",
    "ptunnel":          "Tunnels TCP connections inside ICMP echo (ping) packets. ICMP is often unrestricted across firewalls, making it an effective covert channel.",
    "icmpsh":           "Simple reverse shell that runs its command channel inside ICMP echo replies. Very lightweight, needs no listen port on the attacker's machine.",
    "hans":             "IP-over-ICMP tunnel: wraps full IP packets inside ICMP echo, creating a full VPN-like channel through firewalls that pass ping.",
    "icmptunnel":       "Similar to hans — tunnels IP packets over ICMP echo for covert communication through ICMP-permissive firewalls.",
    "pingtunnel":       "Relays TCP/UDP through ICMP echo with optional authentication and TLS. More feature-rich than basic ICMP shells.",
    "udp2raw":          "Wraps UDP packets inside raw TCP, ICMP or UDP with encryption, making them look like TCP SYN packets to bypass UDP-blocking firewalls.",
    "kcptun":           "Accelerates unreliable UDP connections using the KCP protocol, often layered under Shadowsocks or other proxies to improve throughput through lossy links.",
    # web tunnels
    "reGeorg":          "Web-based SOCKS tunnel: a server-side script (PHP, Python, .NET) receives HTTP requests from a client tool on the attacker's machine and proxies TCP connections through the web server, creating a SOCKS5 channel that appears to be normal web traffic.",
    "neo-reGeorg":      "Improved, encrypted reGeorg rewrite with better performance and detection evasion. Widely deployed via web shells to pivot through web servers.",
    "tunna":            "HTTP tunnel similar to reGeorg — deploys a web-server-side script that wraps arbitrary TCP connections inside HTTP POST requests.",
    "abptts":           "A Black Path Toward The Sun: HTTP/S tunnel using a server-side JSP/ASPX agent. Encrypts the tunnel traffic to avoid signature detection.",
    "pystinger":        "SOCKS4 proxy over webshell HTTP(S) requests. Lets tools like Metasploit route through a webshell as if it were a SOCKS proxy.",
    "suo5":             "High-performance HTTP/1.1 full-duplex tunnel using chunked transfer encoding. Designed to evade WAFs and proxy inspection.",
    "reDuh":            "One of the original HTTP tunnelling tools — converts HTTP POST requests into TCP connections through an uploaded server-side script.",
    # sniffer / MITM
    "tcpdump":          "Standard command-line packet capture tool. On a compromised host it captures all traffic the interface sees — credentials, session tokens, cleartext data.",
    "tshark":           "Command-line version of Wireshark. Full protocol dissection, filterable capture — used to extract credentials and session data from captured traffic.",
    "ngrep":            "Network grep: matches regex patterns against live network packets. Used to harvest credentials, tokens, and sensitive data from plaintext protocols in real time.",
    "netsniff-ng":      "High-performance Linux packet capture toolkit. Zero-copy capture with PCAP output — used when tcpdump performance is insufficient.",
    "dsniff":           "Suite of tools (dsniff, urlsnarf, mailsnarf, msgsnarf, filesnarf) for passively sniffing passwords and data from common protocols (FTP, HTTP, SMTP, IMAP, POP3, SMB). urlsnarf logs all URLs from HTTP traffic.",
    "ettercap":         "Network MITM and sniffing framework with ARP poisoning, DNS spoofing, SSL stripping and password dissection built in. Full GUI or text mode.",
    "bettercap":        "Modern, modular network attack and MITM framework. Supports ARP spoofing, DNS poisoning, 802.11 attacks, BLE sniffing, credential harvesting, and HTTP(S) interception.",
    "arpspoof":         "Sends forged ARP replies to redirect traffic through the attacker's machine (ARP poisoning / MITM). Part of the dsniff suite.",
    "responder":        "Poisons LLMNR, NBT-NS and MDNS name resolution to capture NTLM challenge-response hashes from Windows clients, which can then be cracked offline or relayed.",
    "mitm6":            "Abuses IPv6 router-advertisement messages to MITM IPv4 networks — makes Windows machines prefer the attacker as their IPv6 default gateway and DNS server.",
    "sslstrip":         "Downgrades HTTPS connections to HTTP by rewriting redirect responses in a MITM position, allowing cleartext interception of traffic the client thought was encrypted.",
    "sslsplit":         "Transparent SSL/TLS MITM proxy: intercepts and terminates encrypted connections using forged certificates, logging the plaintext.",
    "mitmproxy":        "Interactive HTTPS MITM proxy with a web UI. Full request/response inspection, modification and replay — used for credential harvesting and traffic manipulation.",
    "bdfproxy":         "Injects payloads (backdoors) into binaries as they are downloaded over HTTP in a MITM position. An attacker who controls the network can backdoor software updates silently.",
    "driftnet":         "Captures images from HTTP traffic in real time. Used to snoop on what users are browsing in a MITM position.",
    "singularity":      "DNS rebinding attack framework. Bypasses browser same-origin policy by rapidly changing a domain's DNS record to an internal IP, allowing JavaScript in the browser to reach internal services.",
    # scanners
    "nmap":             "The most widely used network scanner. Discovers live hosts, open ports, running services, OS version and can run scripted checks. Presence on a server it wasn't installed to administer is a strong indicator of reconnaissance.",
    "masscan":          "Internet-scale TCP port scanner capable of scanning the entire IPv4 address space in minutes. Extremely fast but noisy — used for large-scale host discovery.",
    "zmap":             "Similar to masscan: a single-packet network scanner designed to survey the entire internet. Used for finding vulnerable services at scale.",
    "rustscan":         "Rust-based fast port scanner that hands off to nmap for service detection. Scans all 65535 ports in seconds.",
    "naabu":            "Go-based port scanner from ProjectDiscovery. Fast, supports host discovery and integrates with nuclei for immediate vulnerability scanning.",
    "nuclei":           "Template-driven vulnerability scanner from ProjectDiscovery. Runs thousands of community-written templates against discovered services to find known vulnerabilities and misconfigurations.",
    "httpx":            "Fast HTTP probe that fingerprints web servers, checks for technologies, status codes and titles. Used to survey discovered web services before targeting them.",
    "zgrab":            "Application-layer banner grabber. Collects TLS certificates, HTTP headers and service banners at scale — commonly seen in attacker User-Agents in web logs.",
    "gobuster":         "Directory and DNS brute-forcer. Discovers hidden paths, subdomains and virtual hosts by trying wordlists against a target.",
    "ffuf":             "Fast web fuzzer for directory discovery, parameter fuzzing and virtual-host enumeration. Highly configurable and fast.",
    "feroxbuster":      "Rust-based recursive directory brute-forcer. Automatically follows redirects and recurses into discovered directories.",
    "dirsearch":        "Python-based web path discovery tool — enumerates files and directories using wordlists. Very common in web-application attacks.",
    "nikto":            "Web server vulnerability scanner that checks for thousands of known dangerous files, misconfigurations and outdated software.",
    "wpscan":           "Black-box WordPress security scanner — enumerates plugins, themes, users and known CVEs in WordPress installations.",
    "whatweb":          "Web technology fingerprinter: identifies CMS, frameworks, server software and versions from HTTP responses.",
    "arp-scan":         "Sends ARP requests to discover all live hosts on the local network segment. Very fast and reliable for local host discovery.",
    "netdiscover":      "Active/passive ARP-based host discovery tool. Captures ARP traffic to map the local network without sending its own packets.",
    "fscan":            "Chinese-developed internal network scanner that combines port scanning, service detection, web vulnerability checks and brute-forcing in a single binary.",
    "kscan":            "Similar to fscan: a comprehensive internal-network scanner with service fingerprinting and vulnerability checks in one tool.",
    # exploit / cracking
    "sqlmap":           "Automated SQL injection detection and exploitation framework. Extracts databases, escalates to OS command execution and can dump the entire database automatically.",
    "hydra":            "Parallelised network login brute-forcer supporting dozens of protocols (SSH, FTP, HTTP, SMB, SMTP, RDP, VNC, …). Used to guess credentials at high speed.",
    "medusa":           "Another fast parallel network brute-forcer, similar to Hydra. Supports many protocols and service modules.",
    "ncrack":           "Nmap project's network authentication cracker. Designed for reliability under high connection load.",
    "john":             "John the Ripper: offline password hash cracker supporting hundreds of hash types. Used to crack /etc/shadow hashes and other stolen password stores.",
    "hashcat":          "GPU-accelerated offline password hash cracker. Capable of billions of guesses per second against MD5, SHA-1, NTLM, bcrypt and many other hash types.",
    "crackmapexec":     "Post-exploitation Swiss army knife for Active Directory environments. Enumerates users, shares, logs, and runs commands across Windows hosts using SMB, WMI or WinRM.",
    "impacket":         "Python library and collection of tools (secretsdump.py, psexec.py, wmiexec.py, …) for working with Windows network protocols. Used to extract hashes, run remote commands and move laterally in Windows environments.",
    "metasploit":       "The most widely used exploitation framework. Provides hundreds of exploits, payloads (including Meterpreter), post-exploitation modules and auxiliary tools. Finding msfvenom-generated payloads or meterpreter shellcode is a strong indicator.",
    "sliver":           "Open-source adversary simulation framework (C2). Generates implants for Windows/Linux/macOS that communicate over mTLS, WireGuard, HTTP(S) or DNS. A direct competitor to Cobalt Strike.",
    "havoc":            "Modern post-exploitation C2 framework with an evasion-focused agent ('Demon'). Designed to bypass modern EDR solutions.",
    "villain":          "Framework that generates and manages reverse shells, integrates with multiple handlers, and supports shell sharing between operators.",
    "pwncat":           "Post-exploitation platform that enhances a reverse shell with file transfer, privilege escalation helpers, persistence setup and automated enumeration.",
    "evil-winrm":       "WinRM shell for Windows post-exploitation. Provides an interactive shell with file upload/download, in-memory .NET assembly loading, and Bypass-AMSI/Bypass-UAC helpers.",
    # post-exploitation
    "linpeas":          "Linux Privilege Escalation Awesome Script: an automated enumeration script that checks hundreds of misconfigurations, writable paths, SUID binaries, kernel exploits and credential files to find privilege escalation paths. Its output is a prioritised list of leads.",
    "linenum":          "Older Linux enumeration script that collects system information, user context, installed packages, writable directories and network configuration for manual review.",
    "les":              "Linux Exploit Suggester: analyses kernel version and installed packages to suggest applicable public kernel exploits. Outputs a ranked list of CVEs likely to work on the target.",
    "pspy":             "Unprivileged process monitor that watches /proc for new process creation without needing root. Used to discover cron jobs, triggered scripts and other processes running in the background — often used to find credentials passed on the command line.",
    "deepce":           "Docker and container enumeration/escape tool. Checks for container misconfigurations (privileged mode, mounted docker socket, exposed APIs) and attempts escapes.",
    "traitor":          "Automated Linux privilege escalation tool that tries known local-privilege-escalation techniques in sequence until one succeeds.",
    "mimipenguin":      "Dumps cleartext credentials from memory on Linux systems (extracts from gnome-keyring, sshd, vsftpd, Apache htdigest, and sudo password cache).",
    "lazagne":          "Retrieves stored passwords from dozens of applications (browsers, mail clients, SSH keys, database credentials, Wi-Fi passwords) on the local machine.",
    "gtfoblookup":      "Local lookup tool for GTFOBins — finds which installed system binaries can be abused to read files, write files, or escalate privileges.",
    # rootkits
    "diamorphine":      "LKM (loadable kernel module) rootkit for Linux. Hides processes, files and itself from the OS, provides a root backdoor, and can make a process invisible to ps and /proc. Loaded with insmod — evidence in audit logs and kern.log.",
    "reptile":          "LKM rootkit with a covert reverse shell and file-hiding capability. Harder to detect than diamorphine because it hides itself more thoroughly from kernel module lists.",
    "suterusu":         "LKM rootkit that hides processes and network connections. Hooks kernel syscalls to intercept and filter what the OS reports.",
    "azazel":           "Userland (LD_PRELOAD) rootkit that hides files, processes and network connections without needing a kernel module. Works by intercepting C library calls.",
    "jynx":             "LD_PRELOAD rootkit (Jynx2) that hides files and network connections and provides a covert PAM-based backdoor for SSH access with a hardcoded password.",
    "beurk":            "Userland rootkit using LD_PRELOAD hooks to hide files, processes and network sockets. Also includes a connect-back shell.",
    "bdvl":             "Bedevil: a highly configurable LD_PRELOAD rootkit generator. Hides arbitrary files, processes, ports and provides a covert shell.",
    "vlany":            "LD_PRELOAD rootkit designed for long-term persistence. Hides files, processes, sockets and itself from standard tools.",
    "libprocesshider":  "Simple LD_PRELOAD library that hides any process whose name matches a configured pattern. Often used to conceal miners or C2 agents.",
    "brokepkg":         "Bypasses dpkg/apt package verification to silently replace system binaries. Used to trojanise standard utilities (e.g. replacing /usr/bin/ls with a version that also runs a backdoor).",
    "symbiote":         "Sophisticated LD_PRELOAD rootkit that embeds inside all running processes. Hides files, processes and network traffic, and provides a backdoor accessible via a magic packet.",
    # miners
    "xmrig":            "The most common XMR (Monero) CPU and GPU miner. Installed by cryptojacking attacks to mine cryptocurrency using the victim machine's resources. Network connections to mining pools (typically port 3333, 5555, 14444) are a key indicator.",
    "xmr-stak":         "All-in-one Monero miner supporting CPU, AMD GPU and Nvidia GPU. Used in the same cryptojacking campaigns as xmrig.",
    "cpuminer":         "General-purpose CPU miner (minerd). Older and slower than xmrig but still found in automated compromise scripts.",
    "kinsing":          "Container-targeting malware that downloads and runs xmrig. Typically arrives via unauthenticated Redis, Docker or Kubernetes API exposure. Also deploys a backdoor and removes competing miners.",
    # offensive web middleware
    "rack-attack":      "Ruby Rack middleware for rate limiting and blocking. Legitimate use: protect a Rails/Sinatra app from brute force. Attacker use: added to a compromised web app to block security scanners and defenders while allowing the attacker's own IP through.",
}

# MITRE ATT&CK mapping — gives an investigator the tactic at a glance.
MITRE = {
    "tunnel/proxy": [("T1090", "Proxy"), ("T1572", "Protocol Tunneling")],
    "vpn/mesh/anon": [("T1572", "Protocol Tunneling"), ("T1090.003", "Multi-hop Proxy")],
    "censorship-evasion/C2 transport": [("T1572", "Protocol Tunneling"), ("T1095", "Non-Application Layer C2"), ("T1071", "Application Layer C2")],
    "dns/icmp tunnel": [("T1071.004", "DNS C2"), ("T1095", "Non-Application Layer C2"), ("T1048", "Exfiltration Over Alternative Protocol")],
    "web tunnel": [("T1090", "Proxy"), ("T1102", "Web Service"), ("T1071.001", "Web Protocols")],
    "sniffer/MITM": [("T1040", "Network Sniffing"), ("T1557", "Adversary-in-the-Middle"), ("T1056.001", "Credential Capture")],
    "scanner/recon": [("T1046", "Network Service Discovery"), ("T1595", "Active Scanning")],
    "exploit/cracking": [("T1190", "Exploit Public-Facing App"), ("T1110", "Brute Force"), ("T1212", "Exploitation for Credential Access")],
    "post-exploitation/privesc": [("T1068", "Privilege Escalation"), ("T1552", "Unsecured Credentials"), ("T1087", "Account Discovery")],
    "rootkit": [("T1014", "Rootkit"), ("T1562.001", "Disable or Modify Tools"), ("T1564", "Hide Artifacts")],
    "miner": [("T1496", "Resource Hijacking")],
    "offensive web middleware": [("T1190", "Exploit Public-Facing App")],
}

CAT_OF = {}
NAME_OF = {}
_WORDS = {}
for _cat, _tools in CATALOG.items():
    for _canon, _alts in _tools:
        CAT_OF[_canon] = _cat
        for _a in _alts:
            NAME_OF[_a.lower()] = _canon
            _WORDS.setdefault(_canon, set()).add(_a.lower())

# one regex that finds any catalogue name as a whole word (word chars, dots and hyphens around it)
_ALL = sorted({a for alts in _WORDS.values() for a in alts}, key=len, reverse=True)
_RX = re.compile(r"(?<![\w.-])(" + "|".join(re.escape(a) for a in _ALL) + r")(?![\w-])", re.I)

TOOL_RULE = {"tool_present": ("medium", "tooling", "Non-standard tool present (not part of base Debian)")}
az.RULE_INFO.update({k: {"severity": v[0], "category": v[1], "description": v[2]} for k, v in TOOL_RULE.items()})

BIN_DIRS = ("bin/", "sbin/", "usr/bin/", "usr/sbin/", "usr/local/bin/", "usr/local/sbin/", "usr/local/",
            "opt/", "snap/bin/")
# base-Debian names that happen to collide with catalogue fragments: ignore as bare mentions
STOPWORDS = {"tor", "nc", "ss", "lt", "cme", "agent", "proxy", "naive", "john", "hans", "les", "bore", "nps", "npc"}


# Fast gate before the anchored scan: split the line into word tokens and test set membership.
# This is far cheaper than an unanchored alternation and catches the same lines the real _RX will.
_NAME_SET = frozenset(_ALL)
_TOKEN = re.compile(r"[A-Za-z0-9][\w.-]*")


def quick_hint(text):
    if not text or len(text) > 8000:
        text = (text or "")[:8000]
    for tok in _TOKEN.findall(text.lower()):
        if tok in _NAME_SET:
            return True
        # names can be embedded (e.g. "neoreg.py", "frpc.ini"): check dotted/dashed splits cheaply
        if ("." in tok or "-" in tok):
            for part in re.split(r"[.-]", tok):
                if part in _NAME_SET:
                    return True
    return False


class ToolScan:
    """Accumulates breadcrumbs across the whole case. The indexer feeds it log/script lines via
    note_mention(); file- and package-level evidence is collected in finalize()."""

    def __init__(self):
        self.hits = defaultdict(lambda: {"mentions": 0, "where": {}, "first": None, "last": None,
                                         "binary": [], "package": [], "config": [], "sample": None})

    def note_mention(self, canon, rel, line_no, ts, text):
        h = self.hits[canon]
        h["mentions"] += 1
        w = h["where"].get(rel)
        if w is None:
            w = h["where"][rel] = {"n": 0, "lines": [], "first_line": line_no, "first_ts": ts, "sample": None}
        w["n"] += 1
        if len(w["lines"]) < 60 and line_no not in w["lines"]:
            w["lines"].append(line_no)
        if w["sample"] is None and text:
            w["sample"] = {"line": line_no, "ts": ts, "text": text.strip()[:220]}
        if ts:
            h["first"] = min(h["first"], ts) if h["first"] else ts
            h["last"] = max(h["last"] or "", ts)
        if h["sample"] is None and text:
            h["sample"] = {"rel": rel, "line": line_no, "ts": ts, "text": text[:200]}

    def scan_text(self, rel, line_no, ts, text):
        if not text or len(text) > 4000:
            text = (text or "")[:4000]
        for m in _RX.finditer(text):
            frag = m.group(1).lower()
            if frag in STOPWORDS:
                continue
            canon = NAME_OF.get(frag)
            if canon:
                self.note_mention(canon, rel, line_no, ts, text)


def _ns_ts(ns):
    return az.epoch_to_ts(ns / 1e9) if ns else None


def finalize(con, files, scan=None):
    """Find every breadcrumb and write facts + findings. Scans stored lines for mentions (so it is
    complete even on an incremental re-index), plus file-, package- and config-level evidence.
    Returns findings tuples (rule, file_id, line_no, ts, ts_end, snippet, detail)."""
    out = []
    import linux
    scan = scan or ToolScan()
    # mentions: scan the stored lines of files whose type can carry tool names (logs, history,
    # scripts, configs, decoded content), skipping large reference data.
    rel_by_id = {f["id"]: f["rel"] for f in files}
    text_ids = [f["id"] for f in files if not (f.get("magic") or "").startswith(("ELF", "pcap", "image"))]
    for fid in text_ids:
        rel = rel_by_id.get(fid, str(fid))
        for n, ts, text in con.execute("SELECT line_no, ts, text FROM lines WHERE file_id=?", (fid,)):
            if text and quick_hint(text):
                scan.scan_text(rel, n, ts, text)
    for fid, n, text in con.execute("SELECT d.file_id, d.line_no, d.text FROM decoded d"):
        if text and quick_hint(text):
            scan.scan_text(rel_by_id.get(fid, str(fid)), n, None, text)
    # bash completion scripts: the filename = the installed command, confirmed by Debian packaging
    # (each package installs its own completion file), so this is reliable hard evidence of presence.
    bash_comp_rels = [f for f in files
                      if linux.path_kind(f["rel"]) == "bash_completion"]
    for f in bash_comp_rels:
        cmd = f["rel"].rsplit("/", 1)[-1].lower()
        canon = NAME_OF.get(cmd) or NAME_OF.get(cmd.split(".")[0])
        if canon:
            h = scan.hits[canon]
            h["package"].append({"name": f"bash-completion/{cmd}", "ts": _ns_ts(f["mtime_ns"]),
                                  "file_id": f["id"], "line": 1,
                                  "by": "bash-completion package (completion script = installed command)"})

    # dpkg-owned paths, to tell a dropped binary from a packaged one
    owned = set()
    prefix = ""
    info = [r for r in con.execute("SELECT id, rel FROM files WHERE rel LIKE '%var/lib/dpkg/info/%.list' "
                                   "OR rel LIKE '%var/lib/dpkg/info/%.md5sums'")]
    if info:
        prefix = info[0]["rel"].split("var/lib/dpkg/info/")[0]
        for r in info:
            for l in con.execute("SELECT text FROM lines WHERE file_id=?", (r["id"],)):
                t = (l[0] or "").strip()
                if t.startswith("/"):
                    owned.add(prefix + t.lstrip("/"))
                elif t and len(t.split(None, 1)) == 2 and len(t.split(None, 1)[0]) == 32:
                    owned.add(prefix + t.split(None, 1)[1])

    # binaries and config files on disk
    for f in files:
        rel = f["rel"]
        base = rel.rsplit("/", 1)[-1].lower()
        canon = NAME_OF.get(base) or NAME_OF.get(base.split(".")[0])
        is_bin = any(("/" + rel).replace(prefix and "/" + prefix or "\0", "/").find("/" + d) >= 0 for d in BIN_DIRS) or \
                 rel.startswith(BIN_DIRS) or (f.get("magic") or "").startswith("ELF")
        if canon and (is_bin or (f.get("magic") or "").startswith(("ELF", "script"))):
            packaged = bool(owned) and rel in owned
            h = scan.hits[canon]
            h["binary"].append({"rel": rel, "file_id": f["id"], "ts": _ns_ts(f["mtime_ns"]), "packaged": packaged,
                                "elf": (f.get("magic") or "").startswith("ELF")})
        # config files handled by linux.path_kind == tunnel_config already; map them here too
        k = linux.path_kind(rel)
        if k == "tunnel_config":
            name = rel.rsplit("/", 1)[-1].lower()
            canon = next((NAME_OF[a] for a in NAME_OF if a in rel.lower()), None)
            if canon:
                scan.hits[canon]["config"].append({"rel": rel, "file_id": f["id"], "ts": _ns_ts(f["mtime_ns"])})

    # packages installed
    for r in con.execute("SELECT file_id, line_no, ts, subject, data FROM facts WHERE kind='package'"):
        d = json.loads(r["data"]) if r["data"] else {}
        canon = NAME_OF.get((r["subject"] or "").lower().split(":")[0])
        if canon and d.get("action") in ("install", "reinstall"):
            scan.hits[canon]["package"].append({"name": r["subject"], "ts": r["ts"], "file_id": r["file_id"],
                                                "line": r["line_no"], "by": d.get("requested_by")})

    # emit
    rel_to_id = {f["rel"]: f["id"] for f in files}
    for canon, h in scan.hits.items():
        if not (h["mentions"] or h["binary"] or h["package"] or h["config"]):
            continue
        cat = CAT_OF.get(canon, "tool")
        dropped = [b for b in h["binary"] if not b["packaged"]]
        where_files = len(h["where"]) + len({b["rel"] for b in h["binary"]}) + len(h["config"])
        kinds = []
        if dropped:
            kinds.append(f"{len(dropped)} dropped binary/ies")
        elif h["binary"]:
            kinds.append("installed as a package")
        if h["package"]:
            kinds.append("apt/dpkg install")
        if h["config"]:
            kinds.append(f"{len(h['config'])} config file(s)")
        if h["mentions"]:
            kinds.append(f"{h['mentions']} mention(s) in {len(h['where'])} file(s)")
        first = min([x for x in [h["first"]] + [b["ts"] for b in h["binary"]] + [p["ts"] for p in h["package"]]
                     + [c["ts"] for c in h["config"]] if x], default=None)
        last = max([x for x in [h["last"]] + [b["ts"] for b in h["binary"]] + [p["ts"] for p in h["package"]]
                   + [c["ts"] for c in h["config"]] if x], default=None)
        # every place this tool shows up, as clickable locations (file_id + line numbers)
        locations = []
        for b in h["binary"]:
            locations.append({"kind": "dropped binary" if not b["packaged"] else "packaged binary",
                              "rel": b["rel"], "file_id": b["file_id"], "line": 1, "lines": [],
                              "ts": b["ts"], "strong": not b["packaged"],
                              "detail": ("ELF program" if b["elf"] else "file") + (", not in any package" if not b["packaged"] else "")})
        for c in h["config"]:
            locations.append({"kind": "config file", "rel": c["rel"], "file_id": c["file_id"], "line": 1,
                              "lines": [], "ts": c["ts"], "strong": True, "detail": "configuration for this tool"})
        for p in h["package"]:
            kind = "bash completion script" if "bash-completion/" in (p.get("name") or "") else "package install"
            locations.append({"kind": kind, "rel": "apt/dpkg history" if kind == "package install" else p["name"],
                              "file_id": p["file_id"],
                              "line": p["line"], "lines": [p["line"]] if p["line"] else [], "ts": p["ts"],
                              "strong": True, "detail": f"{p['name']} installed" + (f" by {p['by']}" if p.get("by") else "")})
        for rel, w in sorted(h["where"].items(), key=lambda kv: -kv[1]["n"]):
            locations.append({"kind": "mention", "rel": rel, "file_id": rel_to_id.get(rel),
                              "line": w["first_line"], "lines": sorted(w["lines"]), "ts": w.get("first_ts"),
                              "count": w["n"], "strong": False,
                              "sample": w["sample"]["text"] if w.get("sample") else None})
        data = {"tool": canon, "category": cat, "mentions": h["mentions"], "files": where_files,
                "description": TOOL_DESC.get(canon, ""),
                "binaries": h["binary"][:20], "dropped": len(dropped), "packages": h["package"][:10],
                "configs": h["config"][:10], "locations": locations[:200], "location_total": len(locations),
                "sample": h["sample"], "first": first, "last": last, "kinds": kinds,
                "mitre": MITRE.get(cat, [])}
        anchor_fid = (dropped[0]["file_id"] if dropped else h["binary"][0]["file_id"] if h["binary"]
                      else h["config"][0]["file_id"] if h["config"] else h["package"][0]["file_id"] if h["package"]
                      else next((l["file_id"] for l in locations if l["file_id"]), None))
        anchor_line = (h["sample"] or {}).get("line")
        # Which IPs appear in the same files as this tool's evidence?
        assoc_fids = list({l["file_id"] for l in locations if l.get("file_id")})
        assoc_ips = []
        if assoc_fids:
            ph = ",".join("?" * len(assoc_fids))
            assoc_ips = [{"value": r[0], "meta": r[1], "hits": r[2]} for r in con.execute(
                f"SELECT e.value, e.meta, sum(ef.hits) hits FROM entities e "
                f"JOIN entity_files ef ON ef.entity_id=e.id "
                f"WHERE e.type='ipv4' AND ef.file_id IN ({ph}) "
                f"GROUP BY e.id ORDER BY hits DESC LIMIT 12", assoc_fids).fetchall()
            ]
        data["assoc_ips"] = assoc_ips
        con.execute("INSERT INTO facts(kind, scope, file_id, line_no, ts, subject, data) VALUES('tool_present','case',?,?,?,?,?)",
                    (anchor_fid, anchor_line, first, canon, json.dumps(data)))

        # finding? offensive always; dual-use only when it is a dropped binary / package / own config
        strong = cat in OFFENSIVE_CATS or dropped or h["package"] or h["config"]
        if cat in OFFENSIVE_CATS or (cat in DUALUSE_CATS and strong):
            sev = "high" if (cat in ("rootkit", "miner", "web tunnel", "dns/icmp tunnel", "exploit/cracking") or dropped) else "medium"
            snippet = f"{canon} ({cat}) — " + "; ".join(kinds)
            if h["sample"]:
                snippet += f"; e.g. {h['sample']['rel']}: {h['sample']['text'][:120]}"
            elif dropped:
                snippet += f"; e.g. {dropped[0]['rel']}"
            out.append(("tool_present", anchor_fid, anchor_line, first, last, snippet,
                        json.dumps({"tool": canon, "category": cat, "severity": sev})))
    return out


def _tool_hits(t):
    """Total incidence: mentions + binary presences + package installs + config files."""
    return (t.get("mentions") or 0) + len(t.get("binaries") or []) * 5 + len(t.get("packages") or []) * 10 + len(t.get("configs") or []) * 10


def all_tools(con):
    out = []
    for r in con.execute("SELECT data FROM facts WHERE kind='tool_present'"):
        d = json.loads(r[0])
        d["total_hits"] = _tool_hits(d)
        out.append(d)
    out.sort(key=lambda t: (-t["total_hits"], t.get("tool", "")))
    return out
