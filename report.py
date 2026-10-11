"""
Investigation report.

Pulls together everything Crumbs worked out about a case into one Markdown document an investigator
can read, share or attach to a ticket: the headline story, how the attacker got in, the control
channels and tunnels, the attack episodes (floods, eavesdropping), the Debian baseline diff,
non-standard tools, confirmed and dismissed findings from Triage, confirmed IOCs with any threat
intel, and the open leads. It reflects your Triage verdicts: dismissed findings are left out, and
confirmed ones are highlighted.
"""
import json

import analyzers as az


def _facts(con, kind):
    for r in con.execute("SELECT data FROM facts WHERE kind=? ORDER BY ts IS NULL, ts", (kind,)):
        yield json.loads(r[0])


def _one(con, sql, p=()):
    r = con.execute(sql, p).fetchone()
    return r[0] if r else None


def build(con):
    import sqlite3
    con.row_factory = sqlite3.Row
    import triage
    L = []
    w = L.append
    root = _one(con, "SELECT value FROM meta WHERE key='root'") or "(unknown)"
    indexed = _one(con, "SELECT value FROM meta WHERE key='last_indexed'") or "(unknown)"
    host = {}
    for r in con.execute("SELECT subject, data FROM facts WHERE kind='host'"):
        try:
            host[r[0]] = json.loads(r[1]).get("value")
        except Exception:
            pass
    hostname = host.get("hostname") or "the host"
    w(f"# Crumbs investigation report — {hostname}")
    w("")
    w(f"*Evidence:* `{root}`  \n*Indexed:* {indexed}  \n*Report generated from the current analysis and your Triage verdicts.*")
    w("")

    # headline numbers
    files = _one(con, "SELECT count(*) FROM files") or 0
    lines = _one(con, "SELECT coalesce(sum(line_count),0) FROM files") or 0
    hi = _one(con, "SELECT count(*) FROM findings WHERE severity='high'") or 0
    med = _one(con, "SELECT count(*) FROM findings WHERE severity='medium'") or 0
    st = triage.stats(con)
    w("## Overview")
    w("")
    w(f"- Indexed **{files:,} files**, **{lines:,} lines**.")
    w(f"- **{hi:,} high** and **{med:,} medium** findings.")
    w(f"- Triage: **{st['valid']} confirmed valid**, {st['fp']} false positive, {st['unsure']} unsure, {st['unreviewed']} unreviewed.")
    cs = _one(con, "SELECT value FROM meta WHERE key='compromise_start'")
    if cs:
        w(f"- Earliest compromise activity: **{cs} UTC**.")
    if host.get("pretty_name"):
        w(f"- System: {host['pretty_name']}" + (f" (Debian {host['debian_version']})" if host.get("debian_version") else ""))
    if host.get("timezone"):
        w(f"- Time zone: {host['timezone']} — syslog-style logs are local time; wtmp, auditd, file times and decoded times are UTC.")
    w("")

    # how they got in
    ia = list(_facts(con, "initial_access"))
    if ia:
        w("## How they got in")
        w("")
        for h in ia:
            mark = " — **most likely foothold**" if h.get("likely") else (" (first successful step)" if h.get("earliest") else "")
            stg = " _(later stage)_" if h.get("stage") == "later" else ""
            w(f"- **{h['ts']}** · {h['kind']}{mark}{stg} · from `{h.get('ip') or '?'}` · {h.get('confidence', '')} confidence")
            for e in h.get("evidence", [])[:3]:
                w(f"    - {e}")
        w("")

    # control channels
    ch = list(_facts(con, "channel"))
    if ch:
        w("## Remote control & tunnels")
        w("")
        w("| Channel | From | To / through | Uses | First | Last | |")
        w("|---|---|---|---|---|---|---|")
        for c in ch:
            flag = "**INTERNAL**" if c.get("internal") else ""
            w(f"| {c['kind']} | `{c['source']}` | `{c['target']}` | {c.get('n', '')} | {c.get('first', '')} | {c.get('last', '')} | {flag} |")
        w("")
    tun = rows_findings(con, ("tunnel_installed", "covert_tunnel", "dns_tunnel", "icmp_tunnel", "suspicious_socket",
                              "beaconing", "http_tunnel"))
    if tun:
        w("### Tunnel / beacon / covert-channel evidence")
        w("")
        for t in tun[:40]:
            w(f"- **{t['rule'].replace('_', ' ')}** · {t['ts'] or ''} · `{(t['rel'] or '')}` — {t['snippet']}")
        w("")

    # episodes (floods, eavesdropping)
    eps = list(_facts(con, "episode"))
    if eps:
        w("## Attack episodes")
        w("")
        for e in sorted(eps, key=lambda e: e.get("n", 0)):
            when = f"{e.get('start', '')}" + (f" → {e['end']}" if e.get("end") else "")
            w(f"- **Episode #{e['n']}: {e['title']}** — {when}")
            w(f"    - {e.get('summary', '')}")
        w("")

    # debian baseline
    try:
        import baseline
        bl = baseline.report(con)
        if bl.get("available"):
            c = bl["counts"]
            w("## Debian baseline diff")
            w("")
            w(f"- {c['standard']:,} standard, **{c['modified']:,} modified**, **{c['unowned']:,} unowned**, {c['unverifiable']:,} unverifiable.")
            if bl.get("modified"):
                w("- Changed from their package:")
                for m in (bl.get("conffiles_changed", []) + bl["modified"])[:25]:
                    w(f"    - `{m['path']}` ({m.get('package', '')})" + (f" — modified {m['ts']}" if m.get("ts") else ""))
            if bl.get("unowned"):
                w("- Not installed by any package:")
                for u in bl["unowned"][:25]:
                    w(f"    - `{u['path']}`" + (" — in a program folder" if u.get("in_bin") else "") + (" (ELF)" if u.get("elf") else ""))
            if bl.get("extra_suspicious"):
                w("- Offensive / dual-use packages installed: " + ", ".join(f"`{p['package']}` {p.get('version', '')}" for p in bl["extra_suspicious"]))
            w("")
    except Exception:
        pass

    # whole-filesystem sweep (full dumps)
    try:
        r = con.execute("SELECT data FROM facts WHERE kind='fsweep'").fetchone()
        if r:
            import fsweep
            S = json.loads(r[0])
            w("## Filesystem: deletions and timestamp manipulation")
            w("")
            w(f"- {S.get('os') or 'Debian'}; installed around {S.get('os_install') or 'unknown'} UTC; "
              f"{S.get('files', 0):,} files checked against {S.get('packages', 0):,} packages "
              f"({'full filesystem' if S.get('complete') else 'partial collection'}).")
            w(f"- Inode change times {'look original' if S.get('ctime_reliable') else 'were reset by copying the evidence and were not used'}; "
              f"{round(S.get('subsecond_share', 0) * 100)}% of locally written files have sub-second times.")
            for n in S.get("notes", []):
                w(f"- _{n}_")
            groups = (("Deleted", ("deletion", "defense_evasion")), ("Timestamps changed", ("timestomp",)),
                      ("Hidden or planted", ("hiding", "rootkit", "execution", "log_tampering")))
            rules = list(fsweep.RULES)
            ph = ",".join("?" * len(rules))
            items = con.execute(f"SELECT rule, category, ts, snippet FROM findings WHERE rule IN ({ph}) "
                                f"ORDER BY ts IS NULL, ts", rules).fetchall()
            for title, cats in groups:
                xs = [x for x in items if x[1] in cats]
                if xs:
                    w(f"- **{title}** ({len(xs)}):")
                    for x in xs[:40]:
                        w(f"    - {x[2] or 'time unknown'} — {x[3]}")
            w("")
    except Exception:
        pass

    # non-standard tools
    tools = list(_facts(con, "tool_present"))
    if tools:
        w("## Non-standard tools")
        w("")
        for t in sorted(tools, key=lambda t: t.get("category", "")):
            tags = " ".join(f"[{m[0]}]" for m in t.get("mitre", []))
            desc = f" — {t['description']}" if t.get("description") else ""
            w(f"- **{t['tool']}** ({t['category']}) {tags}{desc}")
            w(f"  Evidence: " + "; ".join(t.get("kinds", [])))
            for l in (t.get("locations") or [])[:6]:
                where = f"`{l['rel']}`" + (f" lines {', '.join(str(x) for x in l['lines'][:8])}" if l.get("lines") else "")
                w(f"    - {l['kind']}: {where}" + (f" — {l['sample']}" if l.get("sample") else (f" — {l['detail']}" if l.get("detail") else "")))
        w("")

    # confirmed IOCs, with intel where present
    iocs = st.get("iocs", [])
    if iocs:
        w("## Confirmed indicators (IOCs)")
        w("")
        import intel
        for i in iocs:
            cache = intel.all_cached(con, i["value"])
            extra = ""
            if cache:
                asm = intel.verdict_hint(cache)
                if asm["notes"]:
                    extra = " — " + ", ".join(asm["notes"])
            w(f"- `{i['value']}` ({i['type']}) · {i.get('source', '')}{extra}")
        w("")

    # confirmed findings
    confirmed = rows_verdict(con, "valid")
    if confirmed:
        w("## Confirmed findings")
        w("")
        for r in confirmed[:100]:
            w(f"- **{r['severity']}** · {r['description']} · `{(r['rel'] or 'case-wide')}`"
              + (f":{r['line_no']}" if r['line_no'] else "") + (f" · {r['ts']}" if r['ts'] else ""))
            if r["snippet"]:
                w(f"    - {r['snippet'][:200]}")
        w("")

    # leads
    try:
        leads = triage.leads(con, fts=_one(con, "SELECT 1 FROM sqlite_master WHERE name='lines_fts'") is not None)
        open_leads = [l for l in leads if l.get("unreviewed_findings")]
        if open_leads:
            w("## Open leads")
            w("")
            w("Confirmed indicators that still have unreviewed findings or unexamined lines:")
            w("")
            for l in open_leads[:20]:
                w(f"- `{l['value']}` — {l['lines']} line(s) in {l['files']} file(s), {l['unreviewed_findings']} unreviewed finding(s)")
            w("")
    except Exception:
        pass

    w("---")
    w("")
    w("*Generated by Crumbs. Findings are leads, not verdicts — confirm each against the source line. "
      "Times are UTC unless a log is noted as local.*")
    return "\n".join(L)


def rows_findings(con, rules):
    ph = ",".join("?" * len(rules))
    out = []
    for r in con.execute(
            f"SELECT fi.rule, fi.severity, fi.ts, fi.snippet, fi.line_no, f.rel FROM findings fi "
            f"LEFT JOIN files f ON f.id = fi.file_id "
            f"WHERE fi.rule IN ({ph}) AND NOT EXISTS (SELECT 1 FROM finding_verdicts v WHERE v.finding_id=fi.id AND v.verdict='fp') "
            f"ORDER BY fi.ts IS NULL, fi.ts", rules):
        out.append(dict(r))
    return out


def rows_verdict(con, verdict):
    out = []
    for r in con.execute(
            "SELECT fi.rule, fi.severity, fi.ts, fi.snippet, fi.line_no, f.rel FROM finding_verdicts v "
            "JOIN findings fi ON fi.id=v.finding_id LEFT JOIN files f ON f.id=fi.file_id "
            "WHERE v.verdict=? ORDER BY CASE fi.severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END, fi.ts",
            (verdict,)):
        d = dict(r)
        d["description"] = az.RULE_INFO.get(d["rule"], {}).get("description", d["rule"])
        out.append(d)
    return out
