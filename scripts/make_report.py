#!/usr/bin/env python3
"""Skaner natijalarini (JSON) bitta tushunarli HTML hisobotga yig'adi."""
import datetime
import html
import json
import os
import re

REP = "reports"
RANK = {"CRITICAL": 0, "HIGH": 1, "?": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
COLORS = {"CRITICAL": "#82071e", "HIGH": "#cf222e", "?": "#cf222e",
          "MEDIUM": "#9a6700", "LOW": "#0969da", "INFO": "#57606a"}
findings = []
notes = []

HINTS = [
    (("b608", "sql"),
     "SQL so'rovini f-string bilan emas, parametr bilan yozing: "
     "conn.execute(\"SELECT * FROM users WHERE name = ?\", (name,))"),
    (("b307", "eval"),
     "eval() ni olib tashlang. Faqat literal kerak bo'lsa: ast.literal_eval(x)"),
    (("b104", "bind", "0.0.0.0"),
     "host=\"0.0.0.0\" o'rniga \"127.0.0.1\". Konteynerda ochiq bo'lishi uchun "
     "Dockerfile'da ENV HOST=0.0.0.0 va kodda os.environ.get(\"HOST\", \"127.0.0.1\")"),
    (("hardcoded", "secret", "aws", "password", "credential"),
     "Kalitni koddan olib tashlang: os.environ.get(\"AWS_KEY\"). Qiymatni "
     "GitHub Secrets'ga qo'ying, oshkor bo'lgan kalitni esa rotate qiling"),
    (("debug",), "debug=True ni o'chiring"),
]
HADOLINT = {
    "DL3042": "pip'ga --no-cache-dir qo'shing: RUN pip install --no-cache-dir -r requirements.txt",
    "DL3013": "pip paketlarini aniq versiya bilan pin qiling (==)",
}


def hint(*texts):
    t = " ".join(str(x) for x in texts).lower()
    for keys, text in HINTS:
        if any(k in t for k in keys):
            return text
    return ""


def norm(path):
    return re.sub(r"^\./", "", path or "")


def load(name):
    try:
        with open(os.path.join(REP, name), encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def src(path, line):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
        n = int(line)
        return "%d: %s" % (n, lines[n - 1].strip()) if 1 <= n <= len(lines) else ""
    except Exception:
        return ""


def add(sev, tool, file, line, title, fix="", code=None):
    if code is None:
        code = src(file, line) if (file and line) else ""
    findings.append(dict(sev=sev, tool=tool, file=file or "-", line=line or "",
                         title=title, fix=fix, code=code))


def vkey(v):
    return tuple(int(x) for x in re.findall(r"\d+", v))


def req_line(name):
    try:
        with open("app/requirements.txt", encoding="utf-8") as f:
            for n, text in enumerate(f, 1):
                if re.match(r"\s*%s\s*[=<>~!]" % re.escape(name), text, re.I):
                    return n
    except Exception:
        pass
    return ""


# --- Bandit
for r in (load("bandit.json") or {}).get("results", []):
    add(r["issue_severity"], "Bandit", norm(r["filename"]), r["line_number"],
        "%s: %s" % (r["test_id"], r["issue_text"]),
        hint(r["test_id"], r["test_name"], r["issue_text"]))

# --- Semgrep
SEMGREP_SEV = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}
for r in (load("semgrep.json") or {}).get("results", []):
    ex = r.get("extra", {})
    msg = " ".join(ex.get("message", r["check_id"]).split())[:300]
    add(SEMGREP_SEV.get(ex.get("severity"), "MEDIUM"), "Semgrep", norm(r["path"]),
        r["start"]["line"], msg, hint(r["check_id"], msg))

# --- Gitleaks (topilgan qiymat hisobotga yozilmaydi)
for r in load("gitleaks.json") or []:
    add("HIGH", "Gitleaks", norm(r.get("File")), r.get("StartLine"),
        "Secret topildi: %s" % r.get("Description"),
        hint("secret"), code="[yashirilgan]")

# --- pip-audit: har bir paket uchun BITTA qator
for dep in (load("pip-audit.json") or {}).get("dependencies", []):
    vulns = dep.get("vulns") or []
    if not vulns:
        continue
    ids, fixes = [], set()
    for v in vulns:
        for i in [v["id"]] + [a for a in v.get("aliases", []) if a.startswith("CVE-")]:
            if i not in ids:
                ids.append(i)
        fixes.update(v.get("fix_versions", []))
    rec = max(fixes, key=vkey) if fixes else None
    fix = ("Qatorni quyidagiga almashtiring: %s==%s" % (dep["name"], rec)) if rec \
        else "Tuzatilgan versiya yo'q: boshqa kutubxonaga o'ting"
    count = len(set(v["id"] for v in vulns))
    add("?", "pip-audit", "app/requirements.txt", req_line(dep["name"]),
        "%s %s: %d ta zaiflik (%s%s)" % (dep["name"], dep["version"], count,
                                       ", ".join(ids[:5]), " ..." if len(ids) > 5 else ""),
        fix)

# --- Hadolint
LEVEL = {"error": "HIGH", "warning": "MEDIUM", "info": "LOW", "style": "INFO"}
for r in load("hadolint.json") or []:
    add(LEVEL.get(r.get("level"), "LOW"), "Hadolint", "Dockerfile", r["line"],
        "%s: %s" % (r["code"], r["message"]),
        HADOLINT.get(r["code"], "https://github.com/hadolint/hadolint/wiki/" + r["code"]))

# --- Trivy config
for res in (load("trivy-config.json") or {}).get("Results", []):
    for m in res.get("Misconfigurations") or []:
        line = (m.get("CauseMetadata") or {}).get("StartLine") or ""
        add(m["Severity"], "Trivy config", res["Target"], line,
            "%s: %s" % (m["ID"], m["Title"]), m.get("Resolution", ""))

# --- Trivy image: paket bo'yicha guruhlab, eng og'irlari
groups = {}
for res in (load("trivy-image.json") or {}).get("Results", []):
    for v in res.get("Vulnerabilities") or []:
        key = (res.get("Class"), res["Target"], v["PkgName"],
               v["InstalledVersion"], v.get("FixedVersion", ""))
        g = groups.setdefault(key, {"sev": v["Severity"], "ids": []})
        g["ids"].append(v["VulnerabilityID"])
        if RANK.get(v["Severity"], 5) < RANK.get(g["sev"], 5):
            g["sev"] = v["Severity"]
items = sorted(groups.items(), key=lambda kv: (RANK.get(kv[1]["sev"], 5), kv[0][2]))
for (cls, target, pkg, ver, fixed), g in items[:25]:
    os_pkg = cls == "os-pkgs"
    fix = "%s %s -> %s" % (pkg, ver, fixed or "tuzatilgan versiya yo'q")
    if os_pkg:
        fix += ". Odatda base image'ni yangilash yetadi: FROM python:3.12-slim"
    add(g["sev"], "Trivy image", "Dockerfile" if os_pkg else target, 1 if os_pkg else "",
        "%s %s: %d ta zaiflik (%s)" % (pkg, ver, len(g["ids"]), ", ".join(g["ids"][:3])), fix)
if len(items) > 25:
    notes.append("Image skanida yana %d ta paket topilgan, bu yerda eng og'ir 25 tasi. "
                 "To'liq ro'yxat: report-image artifact'idagi trivy-image.json." % (len(items) - 25))

# --- Umumiy eslatmalar
try:
    with open("Dockerfile", encoding="utf-8") as f:
        first_from = next((l.strip() for l in f if l.strip().upper().startswith("FROM")), "")
except Exception:
    first_from = ""
if any(f["tool"] == "pip-audit" for f in findings) and re.search(r"python:3\.[0-8]\b", first_from):
    notes.append("Yangi kutubxona versiyalari Python 3.9+ talab qiladi, shuning uchun "
                 "Dockerfile'ning birinchi qatorini ham almashtiring: FROM python:3.12-slim")

# --- HTML
STATUS = [
    ("Gitleaks", "STATUS_SECRETS"), ("Bandit", "STATUS_SAST"), ("Semgrep", "STATUS_SAST"),
    ("pip-audit", "STATUS_SCA"), ("Hadolint", "STATUS_DOCKERFILE"),
    ("Trivy config", "STATUS_DOCKERFILE"), ("Trivy image", "STATUS_IMAGE"),
]


def esc(x):
    return html.escape(str(x))


def sort_key(f):
    ln = int(f["line"]) if str(f["line"]).isdigit() else 0
    return (RANK.get(f["sev"], 5), f["file"], ln)


findings.sort(key=sort_key)
out = ["<html><head><meta charset='utf-8'><style>",
       "@page{size:A4 landscape;margin:10mm}",
       "body{font-family:Arial,sans-serif;font-size:10px;color:#1f2328}",
       "h1{font-size:18px;margin:0 0 4px}h2{font-size:13px;margin:16px 0 6px}",
       "table{border-collapse:collapse;width:100%;table-layout:fixed}",
       "th,td{border:1px solid #d0d7de;padding:4px;vertical-align:top;word-wrap:break-word;overflow-wrap:anywhere}",
       "th{background:#f6f8fa;text-align:left}",
       "code{font-family:monospace;font-size:9px;background:#f6f8fa;padding:1px 3px}",
       ".b{color:#fff;padding:1px 5px;border-radius:3px;font-weight:bold;font-size:9px}",
       ".note{background:#fff8c5;border:1px solid #d4a72c;padding:6px;margin:6px 0}",
       "</style></head><body>",
       "<h1>DevSecOps hisobot: nimani, qayerda tuzatish kerak</h1>",
       "<p>Repo: %s &nbsp; Commit: %s &nbsp; Run: %s &nbsp; Sana: %s</p>" % (
           esc(os.environ.get("GITHUB_REPOSITORY", "")), esc(os.environ.get("GITHUB_SHA", "")[:12]),
           esc(os.environ.get("GITHUB_RUN_ID", "")),
           datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")),
       "<h2>Xulosa</h2><table><tr><th>Skaner</th><th>Job holati</th><th>Topilmalar</th></tr>"]
for tool, env in STATUS:
    st = os.environ.get(env, "unknown")
    col = "#1a7f37" if st == "success" else ("#cf222e" if st == "failure" else "#9a6700")
    n = sum(1 for f in findings if f["tool"] == tool)
    out.append("<tr><td>%s</td><td style='color:%s'><b>%s</b></td><td>%d</td></tr>"
               % (esc(tool), col, esc(st.upper()), n))
out.append("</table>")
for n in notes:
    out.append("<div class='note'><b>Muhim:</b> %s</div>" % esc(n))
out.append("<h2>Tuzatish ro'yxati (og'irlik bo'yicha)</h2>")
if findings:
    out.append("<table><tr><th style='width:3%'>#</th><th style='width:7%'>Daraja</th>"
               "<th style='width:8%'>Skaner</th><th style='width:13%'>Fayl:qator</th>"
               "<th style='width:23%'>Muammo</th><th style='width:16%'>Hozirgi kod</th>"
               "<th style='width:30%'>Qanday tuzatish</th></tr>")
    for i, f in enumerate(findings, 1):
        where = f["file"] + (":%s" % f["line"] if f["line"] != "" else "")
        label = "N/A" if f["sev"] == "?" else f["sev"]
        out.append("<tr><td>%d</td><td><span class='b' style='background:%s'>%s</span></td>"
                   "<td>%s</td><td><b>%s</b></td><td>%s</td><td><code>%s</code></td><td>%s</td></tr>"
                   % (i, COLORS.get(f["sev"], "#57606a"), esc(label), esc(f["tool"]), esc(where),
                      esc(f["title"]), esc(f["code"]), esc(f["fix"])))
    out.append("</table>")
else:
    out.append("<p>Hech qanday topilma yo'q.</p>")
out.append("<p>ZAP (DAST) hisoboti alohida fayl: reports/zap-report.html</p></body></html>")
with open("security-report.html", "w", encoding="utf-8") as fh:
    fh.write("\n".join(out))
print("findings:", len(findings))
