"""
Where did the logins come from?  Geolocation that works offline, plus a world map that needs no download.

Location sources, best first:
  1. An offline city database in MaxMind DB format (.mmdb) placed in the `geo/` folder next to app.py:
       - DB-IP "IP to City Lite"  (free, no account, CC BY 4.0: https://db-ip.com/db/download/ip-to-city-lite)
       - MaxMind GeoLite2-City    (free account)
     Read by a small built-in reader, so no extra Python package is needed.
  2. What threat-intel lookups already returned (Shodan coordinates or city, AbuseIPDB / VirusTotal country):
     those are placed at the city's coordinates when Shodan gave them, otherwise at the country's centre.
Private, loopback and link-local addresses are not placed on the map; they are listed as the internal network.

The map itself is a dotted world drawn from coarse built-in coastlines, rendered by the browser as SVG.
"""
import glob
import ipaddress
import json
import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
GEO_DIR = os.path.join(HERE, "geo")


# --------------------------------------------------------------------------- MaxMind DB (.mmdb) reader
class MMDB:
    """Minimal reader for the MaxMind DB format (spec v2): search tree + data section decoder."""
    META = b"\xab\xcd\xefMaxMind.com"

    def __init__(self, path):
        with open(path, "rb") as fh:
            self.buf = fh.read()
        i = self.buf.rfind(self.META, max(0, len(self.buf) - 128 * 1024))
        if i < 0:
            raise ValueError("not a MaxMind DB file")
        self.meta, _ = self._decode(i + len(self.META), i + len(self.META))
        self.nodes = self.meta["node_count"]
        self.rsize = self.meta["record_size"]
        self.ipver = self.meta["ip_version"]
        self.tree_size = (self.rsize * 2 // 8) * self.nodes
        self.data_start = self.tree_size + 16
        self.v4_start = 0
        if self.ipver == 6:
            n = 0
            for _ in range(96):
                if n >= self.nodes:
                    break
                n = self._record(n, 0)
            self.v4_start = n
        self.path = path
        self.name = self.meta.get("database_type", os.path.basename(path))

    def _record(self, node, bit):
        rs, b = self.rsize, self.buf
        if rs == 24:
            o = node * 6 + bit * 3
            return int.from_bytes(b[o:o + 3], "big")
        if rs == 28:
            o = node * 7
            if bit == 0:
                return ((b[o + 3] & 0xF0) << 20) | int.from_bytes(b[o:o + 3], "big")
            return ((b[o + 3] & 0x0F) << 24) | int.from_bytes(b[o + 4:o + 7], "big")
        if rs == 32:
            o = node * 8 + bit * 4
            return int.from_bytes(b[o:o + 4], "big")
        raise ValueError(f"unsupported record size {rs}")

    def lookup(self, ip):
        a = ipaddress.ip_address(ip)
        if a.version == 6 and self.ipver == 4:
            return None
        packed = a.packed
        node = self.v4_start if (a.version == 4 and self.ipver == 6) else 0
        bits = len(packed) * 8
        for i in range(bits):
            if node >= self.nodes:
                break
            node = self._record(node, (packed[i >> 3] >> (7 - (i & 7))) & 1)
        if node == self.nodes or node < self.nodes:
            return None
        off = node - self.nodes + self.tree_size
        val, _ = self._decode(off, self.data_start)
        return val

    def _size(self, ctrl, o):
        size = ctrl & 0x1F
        b = self.buf
        if size < 29:
            return size, o
        if size == 29:
            return 29 + b[o], o + 1
        if size == 30:
            return 285 + int.from_bytes(b[o:o + 2], "big"), o + 2
        return 65821 + int.from_bytes(b[o:o + 3], "big"), o + 3

    def _decode(self, o, base):
        b = self.buf
        ctrl = b[o]
        o += 1
        typ = ctrl >> 5
        if typ == 1:  # pointer
            ss, vvv = (ctrl >> 3) & 3, ctrl & 7
            if ss == 0:
                p, o = (vvv << 8) | b[o], o + 1
            elif ss == 1:
                p, o = ((vvv << 16) | int.from_bytes(b[o:o + 2], "big")) + 2048, o + 2
            elif ss == 2:
                p, o = ((vvv << 24) | int.from_bytes(b[o:o + 3], "big")) + 526336, o + 3
            else:
                p, o = int.from_bytes(b[o:o + 4], "big"), o + 4
            val, _ = self._decode(base + p, base)
            return val, o
        if typ == 0:
            typ = 7 + b[o]
            o += 1
        size, o = self._size(ctrl, o)
        if typ == 2:
            return b[o:o + size].decode("utf-8", "replace"), o + size
        if typ == 3:
            return struct.unpack(">d", b[o:o + 8])[0], o + 8
        if typ == 4:
            return bytes(b[o:o + size]), o + size
        if typ in (5, 6, 9, 10):
            return int.from_bytes(b[o:o + size], "big"), o + size
        if typ == 8:
            v = int.from_bytes(b[o:o + size], "big")
            return (v - (1 << 32) if size == 4 and v >> 31 else v), o + size
        if typ == 7:
            d = {}
            for _ in range(size):
                k, o = self._decode(o, base)
                v, o = self._decode(o, base)
                d[k] = v
            return d, o
        if typ == 11:
            arr = []
            for _ in range(size):
                v, o = self._decode(o, base)
                arr.append(v)
            return arr, o
        if typ == 14:
            return bool(size), o
        if typ == 15:
            return struct.unpack(">f", b[o:o + 4])[0], o + 4
        return None, o + size


_DB = {"key": None, "db": None, "error": None}


def database():
    """The offline city/country database, if one was placed in geo/ (re-checked when the folder changes)."""
    files = sorted(glob.glob(os.path.join(GEO_DIR, "*.mmdb")), key=lambda p: ("city" not in p.lower(), p))
    key = tuple((p, os.path.getmtime(p)) for p in files)
    if key != _DB["key"]:
        _DB.update(key=key, db=None, error=None)
        for p in files:
            try:
                _DB["db"] = MMDB(p)
                break
            except Exception as e:
                _DB["error"] = f"{os.path.basename(p)}: {e}"
    return _DB["db"]


# --------------------------------------------------------------------------- country centres
# ISO code: (name, latitude, longitude) - approximate centres, good enough to place a marker
COUNTRIES = {
    "AF": ("Afghanistan", 33.9, 67.7), "AL": ("Albania", 41.2, 20.2), "DZ": ("Algeria", 28.0, 1.7),
    "AD": ("Andorra", 42.5, 1.5), "AO": ("Angola", -11.2, 17.9), "AR": ("Argentina", -38.4, -63.6),
    "AM": ("Armenia", 40.1, 45.0), "AU": ("Australia", -25.3, 133.8), "AT": ("Austria", 47.5, 14.6),
    "AZ": ("Azerbaijan", 40.1, 47.6), "BS": ("Bahamas", 25.0, -77.4), "BH": ("Bahrain", 26.0, 50.6),
    "BD": ("Bangladesh", 23.7, 90.4), "BY": ("Belarus", 53.7, 28.0), "BE": ("Belgium", 50.5, 4.5),
    "BZ": ("Belize", 17.2, -88.5), "BJ": ("Benin", 9.3, 2.3), "BT": ("Bhutan", 27.5, 90.4),
    "BO": ("Bolivia", -16.3, -63.6), "BA": ("Bosnia and Herzegovina", 43.9, 17.7), "BW": ("Botswana", -22.3, 24.7),
    "BR": ("Brazil", -14.2, -51.9), "BN": ("Brunei", 4.5, 114.7), "BG": ("Bulgaria", 42.7, 25.5),
    "BF": ("Burkina Faso", 12.2, -1.6), "BI": ("Burundi", -3.4, 29.9), "KH": ("Cambodia", 12.6, 105.0),
    "CM": ("Cameroon", 7.4, 12.4), "CA": ("Canada", 56.1, -106.3), "CF": ("Central African Republic", 6.6, 20.9),
    "TD": ("Chad", 15.5, 18.7), "CL": ("Chile", -35.7, -71.5), "CN": ("China", 35.9, 104.2),
    "CO": ("Colombia", 4.6, -74.3), "CG": ("Congo", -0.2, 15.8), "CD": ("DR Congo", -4.0, 21.8),
    "CR": ("Costa Rica", 9.7, -83.8), "CI": ("Côte d'Ivoire", 7.5, -5.5), "HR": ("Croatia", 45.1, 15.2),
    "CU": ("Cuba", 21.5, -77.8), "CY": ("Cyprus", 35.1, 33.4), "CZ": ("Czechia", 49.8, 15.5),
    "DK": ("Denmark", 56.3, 9.5), "DJ": ("Djibouti", 11.8, 42.6), "DO": ("Dominican Republic", 18.7, -70.2),
    "EC": ("Ecuador", -1.8, -78.2), "EG": ("Egypt", 26.8, 30.8), "SV": ("El Salvador", 13.8, -88.9),
    "EE": ("Estonia", 58.6, 25.0), "ET": ("Ethiopia", 9.1, 40.5), "FI": ("Finland", 61.9, 25.7),
    "FR": ("France", 46.2, 2.2), "GA": ("Gabon", -0.8, 11.6), "GE": ("Georgia", 42.3, 43.4),
    "DE": ("Germany", 51.2, 10.5), "GH": ("Ghana", 7.9, -1.0), "GR": ("Greece", 39.1, 21.8),
    "GT": ("Guatemala", 15.8, -90.2), "GN": ("Guinea", 9.9, -9.7), "HT": ("Haiti", 19.0, -72.3),
    "HN": ("Honduras", 15.2, -86.2), "HK": ("Hong Kong", 22.3, 114.2), "HU": ("Hungary", 47.2, 19.5),
    "IS": ("Iceland", 64.9, -19.0), "IN": ("India", 20.6, 79.0), "ID": ("Indonesia", -0.8, 113.9),
    "IR": ("Iran", 32.4, 53.7), "IQ": ("Iraq", 33.2, 43.7), "IE": ("Ireland", 53.4, -8.2),
    "IL": ("Israel", 31.0, 34.9), "IT": ("Italy", 41.9, 12.6), "JM": ("Jamaica", 18.1, -77.3),
    "JP": ("Japan", 36.2, 138.3), "JO": ("Jordan", 30.6, 36.2), "KZ": ("Kazakhstan", 48.0, 66.9),
    "KE": ("Kenya", -0.0, 37.9), "KP": ("North Korea", 40.3, 127.5), "KR": ("South Korea", 35.9, 127.8),
    "KW": ("Kuwait", 29.3, 47.5), "KG": ("Kyrgyzstan", 41.2, 74.8), "LA": ("Laos", 19.9, 102.5),
    "LV": ("Latvia", 56.9, 24.6), "LB": ("Lebanon", 33.9, 35.9), "LY": ("Libya", 26.3, 17.2),
    "LI": ("Liechtenstein", 47.2, 9.6), "LT": ("Lithuania", 55.2, 23.9), "LU": ("Luxembourg", 49.8, 6.1),
    "MO": ("Macao", 22.2, 113.5), "MG": ("Madagascar", -18.8, 46.9), "MW": ("Malawi", -13.3, 34.3),
    "MY": ("Malaysia", 4.2, 102.0), "MV": ("Maldives", 3.2, 73.2), "ML": ("Mali", 17.6, -4.0),
    "MT": ("Malta", 35.9, 14.4), "MR": ("Mauritania", 21.0, -10.9), "MU": ("Mauritius", -20.3, 57.6),
    "MX": ("Mexico", 23.6, -102.6), "MD": ("Moldova", 47.4, 28.4), "MC": ("Monaco", 43.7, 7.4),
    "MN": ("Mongolia", 46.9, 103.8), "ME": ("Montenegro", 42.7, 19.4), "MA": ("Morocco", 31.8, -7.1),
    "MZ": ("Mozambique", -18.7, 35.5), "MM": ("Myanmar", 21.9, 95.96), "NA": ("Namibia", -22.96, 18.5),
    "NP": ("Nepal", 28.4, 84.1), "NL": ("Netherlands", 52.1, 5.3), "NZ": ("New Zealand", -40.9, 174.9),
    "NI": ("Nicaragua", 12.9, -85.2), "NE": ("Niger", 17.6, 8.1), "NG": ("Nigeria", 9.1, 8.7),
    "MK": ("North Macedonia", 41.6, 21.7), "NO": ("Norway", 60.5, 8.5), "OM": ("Oman", 21.5, 55.9),
    "PK": ("Pakistan", 30.4, 69.3), "PS": ("Palestine", 31.9, 35.2), "PA": ("Panama", 8.5, -80.8),
    "PG": ("Papua New Guinea", -6.3, 143.96), "PY": ("Paraguay", -23.4, -58.4), "PE": ("Peru", -9.2, -75.0),
    "PH": ("Philippines", 12.9, 121.8), "PL": ("Poland", 51.9, 19.1), "PT": ("Portugal", 39.4, -8.2),
    "PR": ("Puerto Rico", 18.2, -66.6), "QA": ("Qatar", 25.4, 51.2), "RO": ("Romania", 45.9, 25.0),
    "RU": ("Russia", 61.5, 105.3), "RW": ("Rwanda", -1.9, 29.9), "SA": ("Saudi Arabia", 23.9, 45.1),
    "SN": ("Senegal", 14.5, -14.5), "RS": ("Serbia", 44.0, 21.0), "SC": ("Seychelles", -4.7, 55.5),
    "SL": ("Sierra Leone", 8.5, -11.8), "SG": ("Singapore", 1.35, 103.8), "SK": ("Slovakia", 48.7, 19.7),
    "SI": ("Slovenia", 46.2, 15.0), "SO": ("Somalia", 5.2, 46.2), "ZA": ("South Africa", -30.6, 22.9),
    "SS": ("South Sudan", 6.9, 31.3), "ES": ("Spain", 40.5, -3.7), "LK": ("Sri Lanka", 7.9, 80.8),
    "SD": ("Sudan", 12.9, 30.2), "SR": ("Suriname", 3.9, -56.0), "SE": ("Sweden", 60.1, 18.6),
    "CH": ("Switzerland", 46.8, 8.2), "SY": ("Syria", 34.8, 39.0), "TW": ("Taiwan", 23.7, 121.0),
    "TJ": ("Tajikistan", 38.9, 71.3), "TZ": ("Tanzania", -6.4, 34.9), "TH": ("Thailand", 15.9, 101.0),
    "TG": ("Togo", 8.6, 0.8), "TT": ("Trinidad and Tobago", 10.7, -61.2), "TN": ("Tunisia", 33.9, 9.5),
    "TR": ("Türkiye", 39.0, 35.2), "TM": ("Turkmenistan", 38.97, 59.6), "UG": ("Uganda", 1.4, 32.3),
    "UA": ("Ukraine", 48.4, 31.2), "AE": ("United Arab Emirates", 23.4, 53.8), "GB": ("United Kingdom", 55.4, -3.4),
    "US": ("United States", 37.1, -95.7), "UY": ("Uruguay", -32.5, -55.8), "UZ": ("Uzbekistan", 41.4, 64.6),
    "VE": ("Venezuela", 6.4, -66.6), "VN": ("Vietnam", 14.1, 108.3), "YE": ("Yemen", 15.6, 48.5),
    "ZM": ("Zambia", -13.1, 27.8), "ZW": ("Zimbabwe", -19.0, 29.2), "XK": ("Kosovo", 42.6, 20.9),
    "CV": ("Cabo Verde", 16.0, -24.0), "GM": ("Gambia", 13.4, -15.3), "GW": ("Guinea-Bissau", 11.8, -15.2),
    "LR": ("Liberia", 6.4, -9.4), "ER": ("Eritrea", 15.2, 39.8), "LS": ("Lesotho", -29.6, 28.2),
    "SZ": ("Eswatini", -26.5, 31.5), "GQ": ("Equatorial Guinea", 1.65, 10.3), "FJ": ("Fiji", -17.7, 178.1),
    "GL": ("Greenland", 71.7, -42.6), "GY": ("Guyana", 4.9, -58.9), "BB": ("Barbados", 13.2, -59.5),
    "SM": ("San Marino", 43.9, 12.5), "VA": ("Vatican City", 41.9, 12.45), "GI": ("Gibraltar", 36.1, -5.35),
    "IM": ("Isle of Man", 54.2, -4.5), "JE": ("Jersey", 49.2, -2.1), "GG": ("Guernsey", 49.45, -2.6),
    "FO": ("Faroe Islands", 61.9, -6.9), "NC": ("New Caledonia", -20.9, 165.6), "PF": ("French Polynesia", -17.7, -149.4),
    "RE": ("Réunion", -21.1, 55.5), "KY": ("Cayman Islands", 19.3, -81.3), "BM": ("Bermuda", 32.3, -64.8),
    "VG": ("British Virgin Islands", 18.4, -64.6), "SB": ("Solomon Islands", -9.6, 160.2), "VU": ("Vanuatu", -15.4, 166.96),
    "WS": ("Samoa", -13.8, -172.1), "TO": ("Tonga", -21.2, -175.2), "KI": ("Kiribati", 1.9, -157.4),
    "TL": ("Timor-Leste", -8.9, 125.7), "AW": ("Aruba", 12.5, -69.97), "CW": ("Curaçao", 12.2, -69.0),
    "SX": ("Sint Maarten", 18.04, -63.05), "AG": ("Antigua and Barbuda", 17.1, -61.8), "DM": ("Dominica", 15.4, -61.4),
    "GD": ("Grenada", 12.1, -61.7), "KN": ("Saint Kitts and Nevis", 17.36, -62.8), "LC": ("Saint Lucia", 13.9, -60.98),
    "VC": ("Saint Vincent", 13.25, -61.2), "SH": ("Saint Helena", -15.97, -5.7), "ST": ("São Tomé and Príncipe", 0.2, 6.6),
    "KM": ("Comoros", -11.9, 43.9), "MH": ("Marshall Islands", 7.1, 171.2), "FM": ("Micronesia", 7.4, 150.6),
    "PW": ("Palau", 7.5, 134.6), "NR": ("Nauru", -0.5, 166.9), "TV": ("Tuvalu", -7.1, 177.6),
    "EU": ("Europe", 50.0, 10.0), "AP": ("Asia/Pacific", 15.0, 105.0),
}
_BY_NAME = {v[0].lower(): k for k, v in COUNTRIES.items()}
_BY_NAME.update({"united states of america": "US", "russian federation": "RU", "korea, republic of": "KR",
                 "republic of korea": "KR", "turkey": "TR", "czech republic": "CZ", "viet nam": "VN",
                 "iran, islamic republic of": "IR", "moldova, republic of": "MD", "the netherlands": "NL",
                 "great britain": "GB", "england": "GB", "hong kong sar": "HK", "taiwan, province of china": "TW"})


def country_code(v):
    if not v:
        return None
    v = str(v).strip()
    if len(v) == 2 and v.upper() in COUNTRIES:
        return v.upper()
    return _BY_NAME.get(v.lower())


# --------------------------------------------------------------------------- the world (dotted map)
# Coarse coastlines (longitude, latitude). Drawn as a dot grid, which is forgiving of the simplification.
_LAND = [
    # North America
    [(-168, 66), (-162, 70), (-156, 71.3), (-141, 69.6), (-128, 70), (-115, 68.5), (-95, 68), (-82, 69.5), (-82, 63),
     (-90, 57), (-94, 59), (-92, 57), (-85, 55), (-79, 51.5), (-77, 57), (-78, 62), (-72, 62), (-66, 58.5), (-61, 56),
     (-56, 52), (-59, 47.5), (-65, 47.5), (-64, 45), (-67, 44.5), (-70, 43), (-70.5, 41.5), (-74, 40.5), (-76, 37),
     (-75.5, 35.3), (-81, 31.5), (-80, 27), (-80.5, 25.2), (-82, 26.5), (-83, 29), (-85, 30), (-89, 30.3), (-90, 29),
     (-94, 29.7), (-97.2, 27.5), (-97.5, 24), (-97.8, 22), (-96, 19), (-94.5, 18.2), (-91, 18.6), (-90.5, 21), (-87, 21.5),
     (-88, 18), (-88.5, 16), (-84, 15.8), (-83.2, 15), (-83.6, 11), (-81.8, 9), (-79.5, 9.5), (-77.5, 8.5), (-78, 7.2),
     (-80, 7.5), (-81, 8), (-83.5, 8.3), (-85.7, 10), (-86, 11.5), (-87.5, 13), (-91.5, 13.9), (-94, 16), (-96.5, 15.7),
     (-99, 16.5), (-102, 17.8), (-105.5, 20), (-105.2, 21.5), (-106, 23), (-108.9, 25.5), (-111, 27.8), (-112.8, 31.3),
     (-114.7, 31.5), (-114.2, 29), (-112, 25.8), (-110, 23), (-109.5, 23.2), (-111.7, 26.3), (-113.3, 28.8), (-114.8, 30.5),
     (-115, 32), (-117.1, 32.5), (-118.5, 34), (-120.6, 34.6), (-122.4, 37.2), (-123.8, 39.8), (-124.3, 42), (-124, 46.2),
     (-124.7, 48.4), (-123, 49), (-126, 50), (-130, 54.5), (-133, 57.5), (-137, 59), (-140, 59.8), (-146, 60.6),
     (-151.5, 59.2), (-154, 58), (-158, 56.6), (-162, 55), (-164.8, 54.4), (-158, 58.6), (-162, 60), (-165.5, 62),
     (-164.5, 63.3), (-161, 64.5), (-166, 64.6)],
    [(-80, 63.5), (-77, 62.5), (-72, 62.8), (-65, 62), (-64, 66), (-62, 67), (-68, 70), (-73, 71.5), (-78, 72.8),
     (-85, 73.5), (-90, 71.5), (-85, 69.8), (-82, 67), (-85, 65.5)],
    [(-125, 72), (-115, 73.5), (-105, 73), (-100, 70), (-110, 68.5), (-118, 69.5)],
    [(-90, 76), (-80, 76.5), (-70, 78.5), (-62, 82), (-75, 83), (-90, 81.5), (-95, 78)],
    [(-100, 74), (-92, 74.5), (-90, 76), (-100, 77)],
    [(-73, 78), (-66, 76), (-58, 75.5), (-55, 71), (-53, 68), (-51, 64), (-48, 61), (-43, 60), (-41, 63), (-37, 65.5),
     (-32, 68), (-23, 70), (-22, 73), (-18, 76), (-18, 79.5), (-12, 81.5), (-25, 83.5), (-40, 83.6), (-60, 82), (-70, 80)],
    [(-24, 65.5), (-22, 66.4), (-17, 66.5), (-13.5, 65.2), (-15, 64.3), (-18.5, 63.4), (-22.5, 63.8)],
    [(-59.3, 47.6), (-55.5, 46.8), (-52.7, 47.5), (-53.5, 49.5), (-55.5, 51.6), (-57.5, 50.8)],
    [(-85, 21.9), (-82, 23.1), (-77.5, 22.5), (-74.2, 20.2), (-77.5, 19.9), (-80, 21.7)],
    [(-74.4, 19.8), (-70, 19.8), (-68.4, 18.6), (-71.5, 17.6), (-74.4, 18.4)],
    # South America
    [(-77.5, 8.5), (-75.5, 10.5), (-72, 12), (-71.4, 10.8), (-68, 10.6), (-63, 10.7), (-60, 8.5), (-57, 6), (-53, 5.5),
     (-51, 4), (-50, 1.8), (-48.5, -1), (-44.5, -2.5), (-40, -2.9), (-35.2, -5.5), (-34.8, -7.5), (-37, -11), (-39, -13.5),
     (-39, -17.6), (-40.8, -22), (-44, -23), (-48.5, -26), (-48.6, -28.5), (-53, -33.7), (-56, -34.8), (-58.4, -34.5),
     (-57, -36.5), (-58, -38.8), (-62.3, -38.8), (-65, -41), (-63.5, -42.6), (-65.5, -45), (-67.5, -46.5), (-66, -47.8),
     (-69, -50.5), (-68.3, -52.3), (-69.5, -52.6), (-71.5, -53.8), (-74, -52.5), (-75.5, -48.6), (-74, -44), (-73.7, -37.5),
     (-71.6, -33), (-71.4, -28), (-70.3, -18.4), (-75.2, -15.3), (-78.2, -10.5), (-81.2, -6), (-80.3, -3.4), (-80, -0.5),
     (-78.8, 1.5), (-77.5, 4), (-77.3, 7)],
    [(-68.6, -52.6), (-65, -55), (-70, -55.3), (-74, -53.5)],
    # Europe (to the Urals and the Caspian)
    [(-9.3, 43), (-8.8, 41.9), (-9.5, 38.8), (-8.9, 37), (-6.2, 36.6), (-5.4, 36), (-2, 36.7), (0.2, 38.8), (-0.3, 39.5),
     (0.9, 41), (3.2, 42), (3, 43.3), (4.8, 43.4), (7.5, 43.8), (8.8, 44.4), (10.5, 43), (12.3, 41.7), (15.5, 40),
     (16.2, 38.8), (15.7, 38), (16.6, 38.4), (17.2, 39.4), (16.5, 40.8), (18.5, 40.2), (17, 41.1), (14.2, 42.2), (12.4, 44.2),
     (12.3, 45.4), (13.7, 45.6), (15.2, 44.2), (17.5, 43), (19.4, 41.8), (19.4, 40.3), (21, 38.4), (21.6, 36.8), (23, 36.4),
     (23.2, 38.2), (24, 38), (22.5, 40.5), (24.5, 40.9), (26.1, 40.6), (28, 41), (29, 41.2), (28, 42), (28.6, 43.7),
     (29.7, 45.2), (30.7, 46.5), (33.5, 44.5), (36, 45.2), (35, 46.3), (38.5, 47.1), (39.7, 47.3), (38, 46.5), (37.4, 45.3),
     (39.5, 44), (41.5, 42), (46, 41.5), (49.5, 40.4), (47.5, 43.8), (47.2, 45.5), (49.5, 46.5), (52, 47), (53.5, 46.8),
     (58, 51), (60, 55), (60, 62), (65, 65), (68.5, 68.2), (66, 69.5), (60.5, 69.8), (55, 68.4), (53.5, 68.3), (44, 68.4),
     (43.5, 66.2), (41, 66.4), (40.5, 64.5), (37, 64.5), (35, 66), (33, 67), (41, 67.6), (41, 68.6), (36, 69.1), (33, 69.4),
     (28.5, 70.9), (25, 71.1), (21, 70.2), (16, 68.8), (13.5, 67.6), (12.2, 65.9), (10.5, 64.5), (8, 63), (5, 62), (5, 59),
     (6, 58), (7.5, 58), (10.5, 59.4), (11, 58.8), (12.4, 56.5), (12.9, 55.4), (14.4, 55.6), (16, 56.3), (16.7, 57.9),
     (16.5, 59.6), (18.5, 60.2), (17.4, 61.6), (17.7, 62.9), (21, 64.5), (21.5, 65.6), (24.5, 65.8), (25.4, 64.9),
     (21.4, 62.6), (21.5, 60.5), (23.5, 59.9), (26, 60.4), (28.8, 60.5), (28, 59.5), (23.5, 59.2), (23.5, 58), (24.3, 57.3),
     (21.4, 57.3), (21, 56), (21, 55.2), (19.8, 54.4), (18.5, 54.8), (16.5, 54.5), (14.3, 53.9), (11.5, 54.2), (10.9, 54.9),
     (9.9, 55), (10, 57), (10.6, 57.7), (8.6, 57.1), (8.2, 56.6), (8.6, 55.5), (8.9, 54.4), (8.3, 53.5), (7, 53.5),
     (5.5, 53.4), (4.6, 52.6), (3.5, 51.4), (2.5, 51.1), (1.6, 50.9), (1.4, 50.1), (0.1, 49.6), (-1.2, 49.4), (-1.9, 49.7),
     (-1.6, 48.6), (-4.6, 48.6), (-4.3, 47.8), (-2.5, 47.3), (-1.9, 46.8), (-1.2, 45.6), (-1.5, 43.4), (-4.5, 43.4), (-8, 43.7)],
    [(-5.7, 50), (1.4, 51.2), (1.7, 52.7), (0.2, 53.4), (-0.2, 54.2), (-1.6, 55.6), (-2, 57), (-1.8, 57.6), (-4, 57.6),
     (-3, 58.6), (-5, 58.6), (-6.2, 56.8), (-5.6, 55.3), (-4.6, 54.8), (-3, 54), (-3.1, 53.2), (-4.7, 52.8), (-5.2, 51.7),
     (-3.3, 51.4)],
    [(-6, 52.2), (-6.2, 53.9), (-5.5, 54.5), (-7.3, 55.3), (-8.4, 55.1), (-10, 54.2), (-9.9, 53), (-10.4, 51.8), (-8.5, 51.6)],
    [(12.4, 38), (15.6, 38.3), (15.1, 36.7)],
    [(8.4, 39), (9.6, 39.2), (9.7, 41), (9.4, 43), (8.6, 42.4), (8.2, 40.9)],
    [(11, 78.5), (16, 77), (22, 77.5), (27, 79.5), (20, 80.5), (11, 79.8)],
    [(52, 71.3), (55, 70.6), (57.5, 70.7), (56, 73), (60, 75.5), (68, 76.9), (62, 76.2), (55, 74.5)],
    # Africa
    [(-17.1, 14.7), (-16.7, 12.4), (-15, 10.9), (-13.3, 9), (-11.5, 6.9), (-7.5, 4.4), (-4, 5.2), (-1.9, 4.8), (1, 6),
     (3.5, 6.4), (5.5, 4.5), (7, 4.4), (8.5, 4.5), (9.7, 3), (9.5, 1), (9.3, -1.5), (11.8, -4.5), (12.3, -6.1), (13.4, -9.5),
     (13.5, -12.5), (11.8, -16.5), (12.5, -19), (14.5, -22.9), (15.2, -27), (16.5, -28.6), (18.4, -33.8), (18.8, -34.4),
     (20, -34.8), (22.5, -34), (25.6, -34), (27.5, -33.2), (30, -31), (32.5, -28.5), (32.9, -26), (35.5, -24), (35.3, -22),
     (34.7, -19.8), (36.8, -17.9), (40.5, -15.3), (40.5, -10.5), (39.2, -7), (39.3, -4.7), (41.5, -1.7), (43, 0.5),
     (46.5, 3.8), (49, 6.8), (51.2, 10.5), (51.3, 11.9), (48, 11.2), (44.5, 10.4), (43.2, 11.5), (42.5, 13.5), (39.5, 15.5),
     (38.5, 18), (37.2, 21), (36.8, 22.5), (35.5, 24), (33.8, 27.6), (32.6, 29.9), (32.3, 31.3), (29, 30.9), (25, 31.6),
     (20, 30.8), (19.5, 30.3), (15.5, 31.4), (11.5, 33.1), (10.2, 34.3), (11, 36.9), (9.5, 37.3), (5, 36.8), (1, 36.5),
     (-2, 35.1), (-5.9, 35.8), (-6.5, 34.5), (-9.6, 30.4), (-9.9, 29.4), (-13, 27.6), (-14.5, 26), (-16, 23.7), (-17, 21),
     (-16.2, 19), (-16.5, 16.4)],
    [(49.3, -12), (50.5, -15.5), (49.5, -17.5), (47.2, -24.8), (45, -25.5), (43.7, -23.5), (44.4, -19.8), (43.9, -17.5),
     (46.3, -15.8), (48, -13.5)],
    # Asia
    [(29, 41.2), (31, 41.1), (35, 42), (38, 41), (41.5, 41.5), (46, 41.5), (49.5, 40.4), (49, 38.5), (51, 36.8), (54, 37),
     (53.9, 39), (53, 41), (52.5, 42.5), (51, 44.5), (53.5, 46.8), (58, 51), (60, 55), (60, 62), (65, 65), (68.5, 68.2),
     (73, 68.5), (72.5, 71.5), (77, 72.5), (80, 73.5), (87, 74), (95, 76), (104, 77.7), (113, 73.7), (120, 73), (129, 72),
     (140, 72.5), (150, 71.5), (160, 69.7), (170, 70), (180, 69), (180, 65), (178, 64.5), (174, 61.8), (170, 60), (164, 60),
     (162, 58), (163, 56), (160, 53), (156.5, 51), (156, 57), (155, 59.5), (150, 59.5), (143, 59.3), (141, 57.5), (138, 54),
     (141, 52), (141, 48), (138, 46), (135, 43.5), (132, 43), (130, 42.5), (129.5, 40.5), (128, 38.6), (129.4, 36.8),
     (129, 35), (126.5, 34.4), (126.5, 37.5), (124.7, 39.7), (121.5, 39), (122, 40.5), (118, 39), (120.5, 37.5),
     (122.5, 37), (119, 35), (121, 32), (122, 30), (120, 26), (117, 23.5), (113, 22.2), (110, 21), (109.8, 18.5), (108, 21.6),
     (106, 20), (106.5, 18), (108.8, 15), (109.2, 11.5), (105, 8.6), (104.5, 10.5), (102.5, 12.5), (101, 13), (100, 12),
     (99.2, 10), (100.3, 8), (101.5, 6.8), (103.5, 4), (103.5, 1.4), (101, 2.8), (98.5, 8), (98.3, 11), (98.5, 13.5),
     (97.7, 16.5), (95, 15.8), (94.5, 18.5), (92.4, 21), (91.5, 22.6), (88.5, 21.7), (86.9, 20.5), (84.6, 19), (82, 17),
     (80.2, 15.5), (80.2, 13), (79.8, 10.3), (77.5, 8.1), (76.3, 9.5), (74.8, 12.8), (73.4, 16), (72.8, 19), (72.6, 21.4),
     (70.2, 20.8), (68.5, 23), (66.6, 25.4), (61.5, 25.2), (57.3, 25.8), (56.4, 27.1), (54, 26.7), (51.5, 27.9), (50.2, 30),
     (48.5, 29.9), (47.7, 28.5), (48.8, 27.5), (50.2, 25.7), (51.6, 24.3), (54, 24.2), (56, 26), (56.4, 24.8), (58.8, 23.5),
     (59.8, 22.4), (57.8, 19), (55.4, 17.5), (52.2, 15.6), (45, 12.8), (43.3, 12.7), (42.7, 15.7), (40, 20), (38.4, 24),
     (37, 25.9), (35, 28), (34.8, 29.5), (34.2, 31.3), (34.9, 32.8), (35.9, 35.4), (36.2, 36.6), (32.5, 36.1), (30.5, 36.3),
     (28.2, 36.7), (27.2, 37.5), (26.3, 38.8), (26.3, 40)],
    [(-180, 69), (-172, 64.5), (-176, 65.5), (-180, 65)],
    [(130, 31.2), (131.3, 31.5), (132, 33.8), (135.2, 33.7), (136.8, 34.3), (138.8, 34.7), (140, 35), (140.8, 36),
     (141, 38.2), (141.5, 40.5), (141.4, 41.4), (140.2, 41.2), (139.9, 40), (139.6, 38.4), (138.6, 37.3), (136.7, 37),
     (136, 35.7), (133, 35.5), (130.9, 34.4), (129.8, 33.2)],
    [(140, 41.5), (141.2, 41.8), (143.2, 42), (145.5, 43.3), (144.5, 44), (141.7, 45.4), (141.6, 43.4), (140, 42.9)],
    [(142, 46), (143.5, 46.8), (143.2, 49.2), (144.5, 49), (143, 53), (142.6, 54.3), (142, 52.5)],
    [(120.2, 22.5), (121, 21.9), (121.9, 24.5), (121.5, 25.3), (120.1, 23.5)],
    [(79.9, 6), (81.8, 7.2), (81.2, 8.7), (80, 9.8), (79.8, 7.8)],
    [(120, 18.5), (122.3, 18.5), (122.2, 16.5), (121.5, 15.2), (124, 13), (123, 13.5), (120.6, 14.2), (120, 16)],
    [(122, 7), (123.5, 8), (125.5, 9.5), (126.5, 7.5), (125.5, 6), (124, 6.3)],
    [(123, 10), (125, 11.5), (125.7, 10), (124, 9.5)],
    [(109, 1.5), (109.6, -1), (110.2, -2.9), (114.5, -3.8), (116.2, -3.5), (116.5, -1), (118, 1), (119, 5), (117.5, 6.9),
     (116, 6.9), (113, 3.1), (111, 1.8)],
    [(95.3, 5.6), (97.5, 5.2), (100.3, 2.5), (103.8, -1), (106, -3), (105.8, -5.8), (104.5, -5.9), (102.3, -4), (100.4, -1),
     (98.7, 1.7)],
    [(105.2, -6.8), (106, -5.9), (108.3, -6.3), (110.5, -6.5), (112.6, -6.9), (114.5, -7.7), (114.4, -8.7), (110, -8.1),
     (106.5, -7.4)],
    [(119.5, -5.5), (120.5, -5.6), (121, -2), (123.4, -0.9), (121, 0.5), (122.5, 1), (125, 1.5), (120.3, 0.5), (119.6, -2.5)],
    [(131, -1.3), (134, -0.8), (138, -1.5), (141, -2.6), (145.7, -4.6), (147.5, -6.1), (147.8, -8), (150.5, -10.5),
     (146, -8.1), (144, -7.8), (141, -9.1), (138, -8.4), (138.5, -6.8), (135, -4.4), (132.5, -4), (132, -2.8)],
    # Australia and New Zealand
    [(113.4, -22), (114.2, -26.3), (115, -30.5), (115, -33.6), (117.8, -35.1), (123.5, -33.9), (126, -32.3),
     (129.5, -31.6), (131.5, -31.5), (134.2, -32.7), (135.8, -34.8), (137.8, -32.7), (137.5, -35), (139.5, -35.7),
     (140.6, -38), (143.5, -38.8), (146.3, -39.1), (148, -37.8), (150, -37.4), (151.2, -33.9), (153, -31), (153.5, -28.2),
     (153, -25), (150.8, -22.6), (149, -20.3), (146.3, -18.9), (145.4, -15), (143.5, -14), (142.5, -10.7), (141.6, -13),
     (141.5, -17), (140, -17.7), (137, -15.9), (135.5, -14.7), (136.8, -12.2), (132.6, -11.5), (130, -13), (129.4, -14.9),
     (126.8, -13.8), (124.5, -16.4), (122.3, -17.9), (121, -19.5), (117, -20.6)],
    [(144.6, -40.7), (148.3, -40.9), (148, -43.2), (146, -43.6)],
    [(172.7, -34.4), (174.6, -36), (176, -37.6), (178.5, -37.7), (177, -39.2), (176.9, -40), (175.2, -41.6),
     (174.6, -40.9), (175, -39.8), (173.8, -39.2), (174.6, -37.5)],
    [(172.7, -40.5), (174.3, -41.7), (173.2, -43), (171.2, -44.4), (170.6, -45.9), (168.4, -46.6), (166.5, -45.8),
     (168.2, -44), (171.5, -41.8)],
]
LAT_TOP, LAT_BOTTOM = 84.0, -58.0


def _inside(lon, lat, poly):
    c, j = False, len(poly) - 1
    for i in range(len(poly)):
        xi, yi = poly[i]
        xj, yj = poly[j]
        if (yi > lat) != (yj > lat) and lon < (xj - xi) * (lat - yi) / ((yj - yi) or 1e-12) + xi:
            c = not c
        j = i
    return c


_DOTS = {}


def world_dots(step=2.0):
    """Land points on a regular grid: [[lon, lat], ...]."""
    if step not in _DOTS:
        boxes = [(min(p[0] for p in pl), max(p[0] for p in pl), min(p[1] for p in pl), max(p[1] for p in pl), pl)
                 for pl in _LAND]
        pts = []
        lat = LAT_TOP - step / 2
        while lat > LAT_BOTTOM:
            lon = -180 + step / 2
            while lon < 180:
                for x0, x1, y0, y1, pl in boxes:
                    if x0 <= lon <= x1 and y0 <= lat <= y1 and _inside(lon, lat, pl):
                        pts.append([round(lon, 2), round(lat, 2)])
                        break
                lon += step
            lat -= step
        _DOTS[step] = pts
    return _DOTS[step]


# --------------------------------------------------------------------------- locating addresses
def classify(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return "invalid"
    if a.is_loopback:
        return "loopback"
    if a.is_private or a.is_link_local or a.is_reserved or a.is_multicast or a.is_unspecified:
        return "internal"
    return "public"


def _from_db(db, ip):
    try:
        r = db.lookup(ip)
    except Exception:
        return None
    if not r:
        return None
    loc = r.get("location") or {}
    ctry = r.get("country") or r.get("registered_country") or {}
    cc = ctry.get("iso_code")
    name = (ctry.get("names") or {}).get("en") or (COUNTRIES.get(cc, (None,))[0] if cc else None)
    city = ((r.get("city") or {}).get("names") or {}).get("en")
    lat, lon = loc.get("latitude"), loc.get("longitude")
    precise = lat is not None and city is not None
    if lat is None and cc in COUNTRIES:
        _n, lat, lon = COUNTRIES[cc]
    if lat is None:
        return None
    return {"lat": lat, "lon": lon, "cc": cc, "country": name, "city": city, "precise": precise,
            "source": db.name}


def _from_intel(con, ip):
    rows = {}
    try:
        for r in con.execute("SELECT provider, data FROM intel_cache WHERE indicator=? AND ok=1", (ip,)):
            rows[r[0]] = json.loads(r[1]) if r[1] else {}
    except Exception:
        return None
    sh = rows.get("shodan") or {}
    if sh.get("latitude") is not None and sh.get("longitude") is not None:
        cc = country_code(sh.get("country_code") or sh.get("country"))
        return {"lat": sh["latitude"], "lon": sh["longitude"], "cc": cc, "country": sh.get("country"),
                "city": sh.get("city"), "precise": True, "source": "Shodan"}
    for prov, key in (("shodan", "country"), ("abuseipdb", "country"), ("virustotal", "country")):
        cc = country_code((rows.get(prov) or {}).get(key))
        if cc:
            name, lat, lon = COUNTRIES[cc]
            return {"lat": lat, "lon": lon, "cc": cc, "country": name,
                    "city": (rows.get("shodan") or {}).get("city") if prov == "shodan" else None,
                    "precise": False, "source": {"shodan": "Shodan", "abuseipdb": "AbuseIPDB",
                                                 "virustotal": "VirusTotal"}[prov] + " (country)"}
    return None


def locate(con, ip):
    db = database()
    return (_from_db(db, ip) if db else None) or _from_intel(con, ip)


def status():
    db = database()
    return {"database": os.path.basename(db.path) if db else None, "database_type": db.name if db else None,
            "error": _DB["error"], "folder": GEO_DIR}
