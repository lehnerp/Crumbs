"""
Threat-intelligence enrichment: file hashes to VirusTotal, public IPs to Shodan and AbuseIPDB.

Crumbs never calls out on its own. You add your own API keys in Settings (stored in this case's
database, never sent anywhere except the matching service), then enrich an indicator from its
detail panel or in bulk from the Triage / IOC view. Results are cached in the database with the
time they were fetched, so re-opening an indicator is instant and works offline afterwards.

Keys are free to obtain:
  * VirusTotal  - https://www.virustotal.com/gui/my-apikey  (free: 4 lookups/min, 500/day)
  * Shodan      - https://account.shodan.io                 (free/member key does host lookups)
  * AbuseIPDB   - https://www.abuseipdb.com/account/api      (free: 1000 checks/day)

The free VirusTotal tier is rate limited; bulk enrichment paces itself and stops cleanly if a
service answers "rate limited", keeping whatever it already fetched.
"""
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request

PROVIDERS = {
    "virustotal": {"label": "VirusTotal", "kinds": {"hash", "md5", "sha1", "sha256", "ip", "ipv4", "domain", "url"},
                   "key_hint": "VirusTotal API key (free tier works)"},
    "shodan": {"label": "Shodan", "kinds": {"ip", "ipv4"}, "key_hint": "Shodan API key"},
    "abuseipdb": {"label": "AbuseIPDB", "kinds": {"ip", "ipv4"}, "key_hint": "AbuseIPDB API key"},
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS intel_keys(provider TEXT PRIMARY KEY, api_key TEXT, added TEXT);
CREATE TABLE IF NOT EXISTS intel_cache(
    id INTEGER PRIMARY KEY, provider TEXT, indicator TEXT COLLATE NOCASE, kind TEXT,
    ok INTEGER, summary TEXT, data TEXT, fetched TEXT,
    UNIQUE(provider, indicator));
CREATE INDEX IF NOT EXISTS idx_intel_ind ON intel_cache(indicator);
"""


def ensure(con):
    con.executescript(SCHEMA)


def norm_kind(kind):
    k = (kind or "").lower()
    if k in ("md5", "sha1", "sha256"):
        return "hash"
    if k in ("ipv4", "ipv6"):
        return "ip"
    return k


def providers_for(kind):
    k = norm_kind(kind)
    return [p for p, info in PROVIDERS.items() if k in info["kinds"] or (k == "hash" and "hash" in info["kinds"])]


def get_keys(con):
    ensure(con)
    return {r[0]: bool(r[1]) for r in con.execute("SELECT provider, api_key FROM intel_keys")}


def set_key(con, provider, key):
    ensure(con)
    if provider not in PROVIDERS:
        raise ValueError("unknown provider")
    if key:
        con.execute("INSERT OR REPLACE INTO intel_keys(provider, api_key, added) VALUES(?,?,?)",
                    (provider, key.strip(), time.strftime("%Y-%m-%d %H:%M:%S")))
    else:
        con.execute("DELETE FROM intel_keys WHERE provider=?", (provider,))


def _key(con, provider):
    r = con.execute("SELECT api_key FROM intel_keys WHERE provider=?", (provider,)).fetchone()
    return r[0] if r else None


def cached(con, provider, indicator):
    ensure(con)
    r = con.execute("SELECT ok, summary, data, fetched FROM intel_cache WHERE provider=? AND indicator=?",
                    (provider, indicator)).fetchone()
    if r:
        return {"provider": provider, "indicator": indicator, "ok": bool(r[0]), "summary": r[1],
                "data": json.loads(r[2]) if r[2] else None, "fetched": r[3], "cached": True}
    return None


def all_cached(con, indicator):
    ensure(con)
    out = {}
    for r in con.execute("SELECT provider, ok, summary, data, fetched FROM intel_cache WHERE indicator=?", (indicator,)):
        out[r[0]] = {"ok": bool(r[1]), "summary": r[2], "data": json.loads(r[3]) if r[3] else None, "fetched": r[4]}
    return out


def _store(con, provider, indicator, kind, ok, summary, data):
    con.execute("INSERT OR REPLACE INTO intel_cache(provider, indicator, kind, ok, summary, data, fetched) "
                "VALUES(?,?,?,?,?,?,?)", (provider, indicator, norm_kind(kind), 1 if ok else 0, summary,
                                         json.dumps(data) if data is not None else None, time.strftime("%Y-%m-%d %H:%M:%S")))
    con.commit()


class RateLimited(Exception):
    pass


def _get(url, headers=None, timeout=15):
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        if e.code in (429, 403):
            body = e.read().decode("utf-8", "replace")[:200]
            raise RateLimited(f"{e.code} {body}") if e.code == 429 else _AuthError(f"{e.code} {body}")
        try:
            return e.code, json.loads(e.read().decode("utf-8", "replace"))
        except Exception:
            return e.code, None


class _AuthError(Exception):
    pass


# -------------------------------------------------------------- providers ---
def _vt(con, indicator, kind, key):
    k = norm_kind(kind)
    if k == "hash":
        path = "files/" + indicator
    elif k == "ip":
        path = "ip_addresses/" + indicator
    elif k == "domain":
        path = "domains/" + indicator
    elif k == "url":
        import base64
        path = "urls/" + base64.urlsafe_b64encode(indicator.encode()).decode().strip("=")
    else:
        return False, "VirusTotal does not take this kind", None
    status, body = _get("https://www.virustotal.com/api/v3/" + path, {"x-apikey": key})
    if status == 404:
        return True, "not seen by VirusTotal", {"found": False}
    if not body or "data" not in body:
        return False, f"VirusTotal error {status}", None
    attr = body["data"].get("attributes", {})
    stats = attr.get("last_analysis_stats", {})
    mal, susp = stats.get("malicious", 0), stats.get("suspicious", 0)
    total = sum(stats.values()) or 0
    names = attr.get("names") or ([attr.get("meaningful_name")] if attr.get("meaningful_name") else [])
    labels = (attr.get("popular_threat_classification", {}) or {}).get("suggested_threat_label")
    summary = f"{mal}/{total} engines flag this as malicious" + (f" ({labels})" if labels else "")
    if mal == 0 and susp == 0:
        summary = f"clean on VirusTotal (0/{total})"
    data = {"malicious": mal, "suspicious": susp, "total": total, "label": labels, "names": names[:5],
            "reputation": attr.get("reputation"), "type": attr.get("type_description"),
            "country": attr.get("country"), "as_owner": attr.get("as_owner"),
            "first_seen": attr.get("first_submission_date") or attr.get("creation_date"),
            "link": f"https://www.virustotal.com/gui/search/{urllib.parse.quote(indicator)}"}
    return True, summary, data


def _shodan(con, indicator, kind, key):
    status, body = _get(f"https://api.shodan.io/shodan/host/{indicator}?key={urllib.parse.quote(key)}")
    if status == 404:
        return True, "no Shodan data for this address", {"found": False}
    if not body or "ip_str" not in body:
        return False, f"Shodan error {status}", None
    ports = body.get("ports", [])
    tags = body.get("tags", [])
    vulns = list(body.get("vulns", []) or [])
    prods = []
    for svc in body.get("data", [])[:40]:
        p = svc.get("product")
        if p and p not in prods:
            prods.append(p)
    summary = (f"{len(ports)} open port(s): " + ", ".join(str(p) for p in sorted(ports)[:12])
               + (f"; {len(vulns)} known CVE(s)" if vulns else "") + (f"; tags: {', '.join(tags)}" if tags else ""))
    data = {"ports": sorted(ports), "tags": tags, "vulns": sorted(vulns)[:40], "products": prods[:12],
            "org": body.get("org"), "isp": body.get("isp"), "asn": body.get("asn"), "os": body.get("os"),
            "country": body.get("country_name"), "country_code": body.get("country_code"), "city": body.get("city"),
            "latitude": body.get("latitude"), "longitude": body.get("longitude"), "hostnames": body.get("hostnames", [])[:8],
            "last_update": body.get("last_update"), "link": f"https://www.shodan.io/host/{indicator}"}
    return True, summary, data


def _abuse(con, indicator, kind, key):
    url = "https://api.abuseipdb.com/api/v2/check?" + urllib.parse.urlencode({"ipAddress": indicator, "maxAgeInDays": 365, "verbose": ""})
    status, body = _get(url, {"Key": key, "Accept": "application/json"})
    if not body or "data" not in body:
        return False, f"AbuseIPDB error {status}", None
    d = body["data"]
    score = d.get("abuseConfidenceScore", 0)
    reports = d.get("totalReports", 0)
    summary = (f"abuse score {score}/100 from {reports} report(s)"
               + (f"; {d.get('usageType')}" if d.get("usageType") else "")
               + (" — on an allowlist" if d.get("isWhitelisted") else ""))
    cats = []
    for rep in (d.get("reports") or [])[:20]:
        for c in rep.get("categories", []):
            cats.append(c)
    data = {"score": score, "reports": reports, "last_reported": d.get("lastReportedAt"), "tor": d.get("isTor"),
            "usage": d.get("usageType"), "isp": d.get("isp"), "domain": d.get("domain"), "country": d.get("countryCode"),
            "whitelisted": d.get("isWhitelisted"), "categories": _abuse_cats(cats),
            "link": f"https://www.abuseipdb.com/check/{indicator}"}
    return True, summary, data


ABUSE_CATEGORIES = {3: "Fraud Orders", 4: "DDoS", 5: "FTP Brute-Force", 6: "Ping of Death", 7: "Phishing",
                    9: "Open Proxy", 10: "Web Spam", 11: "Email Spam", 14: "Port Scan", 15: "Hacking",
                    16: "SQL Injection", 17: "Spoofing", 18: "Brute-Force", 19: "Bad Web Bot", 20: "Exploited Host",
                    21: "Web App Attack", 22: "SSH", 23: "IoT Targeted"}


def _abuse_cats(nums):
    from collections import Counter
    c = Counter(nums)
    return [{"name": ABUSE_CATEGORIES.get(k, str(k)), "n": v} for k, v in c.most_common(8)]


_FUNCS = {"virustotal": _vt, "shodan": _shodan, "abuseipdb": _abuse}


def enrich(con, provider, indicator, kind, force=False):
    """One lookup. Uses the cache unless force. Returns a result dict, never raises for the caller."""
    ensure(con)
    indicator = indicator.strip()
    if provider not in _FUNCS:
        return {"provider": provider, "indicator": indicator, "ok": False, "summary": "unknown provider"}
    if not force:
        c = cached(con, provider, indicator)
        if c:
            return c
    key = _key(con, provider)
    if not key:
        return {"provider": provider, "indicator": indicator, "ok": False, "summary": f"no {PROVIDERS[provider]['label']} API key set", "need_key": True}
    try:
        ok, summary, data = _FUNCS[provider](con, indicator, kind, key)
    except RateLimited as e:
        return {"provider": provider, "indicator": indicator, "ok": False, "summary": "rate limited — try again shortly", "rate_limited": True, "detail": str(e)}
    except _AuthError as e:
        return {"provider": provider, "indicator": indicator, "ok": False, "summary": "API key rejected (403)", "bad_key": True, "detail": str(e)}
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return {"provider": provider, "indicator": indicator, "ok": False, "summary": f"could not reach {PROVIDERS[provider]['label']} ({e})", "offline": True}
    except (ValueError, KeyError, TypeError) as e:
        return {"provider": provider, "indicator": indicator, "ok": False, "summary": f"unexpected response ({e})"}
    _store(con, provider, indicator, kind, ok, summary, data)
    return {"provider": provider, "indicator": indicator, "ok": ok, "summary": summary, "data": data,
            "fetched": time.strftime("%Y-%m-%d %H:%M:%S"), "cached": False}


def enrich_all(con, indicator, kind, force=False):
    return {p: enrich(con, p, indicator, kind, force=force) for p in providers_for(kind)}


def verdict_hint(results):
    """Turn provider results into a one-line, colour-coded assessment for the UI."""
    bad, notes = 0, []
    vt = results.get("virustotal", {}).get("data")
    if vt and vt.get("malicious"):
        bad = max(bad, 2 if vt["malicious"] >= 3 else 1)
        notes.append(f"VT {vt['malicious']}/{vt.get('total', '?')}" + (f" {vt['label']}" if vt.get("label") else ""))
    ab = results.get("abuseipdb", {}).get("data")
    if ab:
        if ab.get("whitelisted"):
            notes.append("AbuseIPDB allowlisted")
        elif ab.get("score", 0) >= 50:
            bad = max(bad, 2)
            notes.append(f"abuse {ab['score']}/100")
        elif ab.get("score", 0) >= 15:
            bad = max(bad, 1)
            notes.append(f"abuse {ab['score']}/100")
        if ab.get("tor"):
            notes.append("Tor exit")
    sh = results.get("shodan", {}).get("data")
    if sh and sh.get("vulns"):
        bad = max(bad, 1)
        notes.append(f"{len(sh['vulns'])} CVEs")
    level = ["unknown", "suspicious", "malicious"][bad]
    return {"level": level, "notes": notes}
