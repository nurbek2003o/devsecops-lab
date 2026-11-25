#!/usr/bin/env python3
"""Skaner natijalarini (JSON) yig'adi, GATE qoidalarini tekshiradi, HTML hisobot yozadi.

Pipeline o'tadimi yoki yo'qmi, QOIDALAR bilan hal qilinadi (R1..R5).
Reyting (0-5) faqat ma'lumot uchun ko'rsatiladi.
"""
import datetime
import html
import json
import os
import re

REP = "reports"
MAX_SCORE = 5.0

RANK = {"CRITICAL": 0, "HIGH": 1, "?": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def threshold(name, default):
    v = os.environ.get(name, default).upper()
    return v if v in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else default


# ---- GATE sozlamalari (workflow'dagi env orqali o'zgartiriladi) ----
SAST_FAIL_ON = threshold("SAST_FAIL_ON", "MEDIUM")    # R2: shu daraja va undan yuqori
IMAGE_FAIL_ON = threshold("IMAGE_FAIL_ON", "HIGH")    # R4: shu daraja va undan yuqori

RULES = [
    ("R1", "Secrets", "har qanday topilma"),
    ("R2", "SAST", "%s va undan yuqori" % SAST_FAIL_ON),
    ("R3", "SCA", "tuzatilgan versiyasi mavjud har qanday zaif paket"),
    ("R4", "Image", "%s va undan yuqori (faqat tuzatilgani bor)" % IMAGE_FAIL_ON),
    ("R5", "Dockerfile", "HIGH+ noto'g'ri sozlama (root user, latest tag...) yoki Hadolint error"),
]

COLORS = {"CRITICAL": "#82071e", "HIGH": "#cf222e", "?": "#cf222e",
          "MEDIUM": "#9a6700", "LOW": "#0969da", "INFO": "#57606a"}
PENALTY = {"CRITICAL": 1.5, "HIGH": 1.0, "?": 1.0, "MEDIUM": 0.5, "LOW": 0.1, "INFO": 0.0}
CATEGORY = {"Gitleaks": "Secrets", "Bandit": "SAST", "Semgrep": "SAST",
            "pip-audit": "SCA", "Hadolint": "Dockerfile", "Trivy config": "Dockerfile",
            "Trivy image": "Image"}
CATS = ["Secrets", "SAST", "SCA", "Dockerfile", "Image"]
JOBS = [("build", "STATUS_BUILD"), ("secrets", "STATUS_SECRETS"), ("sast", "STATUS_SAST"),
        ("sca", "STATUS_SCA"), ("dockerfile", "STATUS_DOCKERFILE"), ("image-scan", "STATUS_IMAGE")]

findings = []
notes = []
problems = []
violations = []

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


def at_least(sev, thr):
    return RANK.get(sev, 5) <= RANK[thr]


def violate(rule, where, detail):
    violations.append(dict(rule=rule, where=where, detail=detail))


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
        problems.append("%s topilmadi yoki o'qib bo'lmadi: skaner ishlamagan bo'lishi mumkin" % name)
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


# --- Bandit (R2)
for r in (load("bandit.json") or {}).get("results", []):
    where = "%s:%s" % (norm(r["filename"]), r["line_number"])
    add(r["issue_severity"], "Bandit", norm(r["filename"]), r["line_number"],
        "%s: %s" % (r["test_id"], r["issue_text"]),
        hint(r["test_id"], r["test_name"], r["issue_text"]))
    if at_least(r["issue_severity"], SAST_FAIL_ON):
        violate("R2", where, "Bandit %s (%s)" % (r["test_id"], r["issue_severity"]))

# --- Semgrep (R2)
SEMGREP_SEV = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}
for r in (load("semgrep.json") or {}).get("results", []):
    ex = r.get("extra", {})
    msg = " ".join(ex.get("message", r["check_id"]).split())[:300]
    sev = SEMGREP_SEV.get(ex.get("severity"), "MEDIUM")
    add(sev, "Semgrep", norm(r["path"]), r["start"]["line"], msg, hint(r["check_id"], msg))
    if at_least(sev, SAST_FAIL_ON):
        violate("R2", "%s:%s" % (norm(r["path"]), r["start"]["line"]),
                "Semgrep %s (%s)" % (r["check_id"].split(".")[-1], sev))

# --- Gitleaks (R1; topilgan qiymat hisobotga yozilmaydi)
for r in load("gitleaks.json") or []:
    add("HIGH", "Gitleaks", norm(r.get("File")), r.get("StartLine"),
        "Secret topildi: %s" % r.get("Description"),
        hint("secret"), code="[yashirilgan]")
    violate("R1", "%s:%s" % (norm(r.get("File")), r.get("StartLine")),
            "Secret topildi: %s" % r.get("Description"))

# --- pip-audit (R3): har bir paket uchun BITTA qator
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
    line = req_line(dep["name"])
    add("?", "pip-audit", "app/requirements.txt", line,
        "%s %s: %d ta zaiflik (%s%s)" % (dep["name"], dep["version"], count,
                                       ", ".join(ids[:5]), " ..." if len(ids) > 5 else ""),
        fix)
    if rec:
        violate("R3", "app/requirements.txt:%s" % line,
                "%s %s -> %s (%d ta zaiflik)" % (dep["name"], dep["version"], rec, count))

# --- Hadolint (R5: faqat error)
LEVEL = {"error": "HIGH", "warning": "MEDIUM", "info": "LOW", "style": "INFO"}
for r in load("hadolint.json") or []:
    sev = LEVEL.get(r.get("level"), "LOW")
    add(sev, "Hadolint", "Dockerfile", r["line"], "%s: %s" % (r["code"], r["message"]),
        HADOLINT.get(r["code"], "https://github.com/hadolint/hadolint/wiki/" + r["code"]))
    if sev == "HIGH":
        violate("R5", "Dockerfile:%s" % r["line"], "Hadolint %s" % r["code"])

# --- Trivy config (R5)
for res in (load("trivy-config.json") or {}).get("Results", []):
    for m in res.get("Misconfigurations") or []:
        line = (m.get("CauseMetadata") or {}).get("StartLine") or ""
        add(m["Severity"], "Trivy config", res["Target"], line,
            "%s: %s" % (m["ID"], m["Title"]), m.get("Resolution", ""))
        if at_least(m["Severity"], "HIGH"):
            violate("R5", res["Target"] + (":%s" % line if line != "" else ""),
                    "%s: %s" % (m["ID"], m["Title"]))

# --- Trivy image (R4): paket bo'yicha guruhlab; qoida HAMMASINI sanaydi, jadval 25 tasini ko'rsatadi
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
hit = [g for g in groups.values() if at_least(g["sev"], IMAGE_FAIL_ON)]
if hit:
    crit = sum(1 for g in hit if g["sev"] == "CRITICAL")
    violate("R4", "Dockerfile:1 (base image / paketlar)",
            "%d ta paket (CRITICAL %d, boshqalar %d), hammasining tuzatilgan versiyasi bor"
            % (len(hit), crit, len(hit) - crit))

# --- Umumiy eslatmalar
try:
    with open("Dockerfile", encoding="utf-8") as f:
        first_from = next((l.strip() for l in f if l.strip().upper().startswith("FROM")), "")
except Exception:
    first_from = ""
if any(f["tool"] == "pip-audit" for f in findings) and re.search(r"python:3\.[0-8]\b", first_from):
    notes.append("Yangi kutubxona versiyalari Python 3.9+ talab qiladi, shuning uchun "
                 "Dockerfile'ning birinchi qatorini ham almashtiring: FROM python:3.12-slim")

# --- Reyting (faqat ma'lumot uchun): kategoriya = 5 - jarimalar, umumiy = o'rtacha
scored = {}


def put(key, cat, p):
    if key not in scored or p > scored[key][1]:
        scored[key] = (cat, p)


for f in findings:
    if f["tool"] == "Trivy image":
        continue
    cat = CATEGORY[f["tool"]]
    put((cat, f["file"], f["line"] if f["line"] != "" else f["title"]), cat,
        PENALTY.get(f["sev"], 0.5))
for k, g in groups.items():
    put(("Image",) + k, "Image", PENALTY.get(g["sev"], 0.5))

cat_pen = dict((c, 0.0) for c in CATS)
cat_cnt = dict((c, 0) for c in CATS)
for cat, p in scored.values():
    cat_pen[cat] += p
    cat_cnt[cat] += 1
cat_score = dict((c, round(max(0.0, MAX_SCORE - cat_pen[c]), 1)) for c in CATS)
score = round(sum(max(0.0, MAX_SCORE - cat_pen[c]) for c in CATS) / len(CATS), 2)

bad_jobs = [name for name, env in JOBS if os.environ.get(env, "success") != "success"]
passed = not violations and not problems and not bad_jobs

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
box = "#1a7f37" if passed else "#cf222e"
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
       ".err{background:#ffebe9;border:1px solid #cf222e;padding:6px;margin:6px 0}",
       ".score{border:3px solid %s;padding:10px;margin:8px 0}" % box,
       ".score .n{font-size:24px;font-weight:bold;color:%s}" % box,
       "</style></head><body>",
       "<h1>DevSecOps hisobot: nimani, qayerda tuzatish kerak</h1>",
       "<p>Repo: %s &nbsp; Commit: %s &nbsp; Run: %s &nbsp; Sana: %s</p>" % (
           esc(os.environ.get("GITHUB_REPOSITORY", "")), esc(os.environ.get("GITHUB_SHA", "")[:12]),
           esc(os.environ.get("GITHUB_RUN_ID", "")),
           datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")),
       "<div class='score'><span class='n'>%s</span> &nbsp; Gate qoidalari buzilishi: <b>%d</b> "
       "&nbsp;|&nbsp; Reyting (faqat ma'lumot uchun): <b>%.2f / %.0f</b></div>" % (
           "PIPELINE O'TDI" if passed else "PIPELINE YIQILDI", len(violations), score, MAX_SCORE)]
if problems or bad_jobs:
    out.append("<div class='err'><b>Skaner xatolari (natijaga ishonib bo'lmaydi, pipeline yiqiladi):</b><br>%s</div>"
               % esc("; ".join(problems + ["job '%s' muvaffaqiyatsiz" % j for j in bad_jobs])))

out.append("<h2>Gate qoidalari</h2><table><tr><th style='width:6%'>Qoida</th><th style='width:12%'>Kategoriya</th>"
           "<th>Shart (shu bo'lsa pipeline yiqiladi)</th><th style='width:10%'>Buzilgan</th>"
           "<th style='width:10%'>Holat</th></tr>")
for rid, cat, cond in RULES:
    n = sum(1 for v in violations if v["rule"] == rid)
    out.append("<tr><td>%s</td><td>%s</td><td>%s</td><td>%d</td><td style='color:%s'><b>%s</b></td></tr>"
               % (rid, esc(cat), esc(cond), n, "#cf222e" if n else "#1a7f37", "BUZILGAN" if n else "OK"))
out.append("</table>")
if violations:
    out.append("<h2>Buzilishlar (pipeline'ni to'xtatayotgan topilmalar)</h2><table><tr><th style='width:6%'>Qoida</th>"
               "<th style='width:26%'>Joyi</th><th>Tafsilot</th></tr>")
    for v in violations:
        out.append("<tr><td>%s</td><td><b>%s</b></td><td>%s</td></tr>"
                   % (v["rule"], esc(v["where"]), esc(v["detail"])))
    out.append("</table>")

out.append("<h2>Kategoriyalar bo'yicha reyting (faqat ma'lumot uchun)</h2><table><tr><th>Kategoriya</th>"
           "<th>Reyting</th><th>Topilmalar</th><th>Jarima</th></tr>")
for c in CATS:
    out.append("<tr><td>%s</td><td><b>%.1f / %.0f</b></td><td>%d</td><td>-%.1f</td></tr>"
               % (esc(c), cat_score[c], MAX_SCORE, cat_cnt[c], min(cat_pen[c], MAX_SCORE)))
out.append("</table><p>Reyting: har bir kategoriya %.0f dan boshlanadi, jarima: CRITICAL -1.5, HIGH -1.0, "
           "MEDIUM -0.5, LOW -0.1. Umumiy = 5 kategoriya o'rtachasi. Pipeline'ni reyting emas, "
           "yuqoridagi qoidalar to'xtatadi.</p>" % MAX_SCORE)
out.append("<h2>Skanerlar</h2><table><tr><th>Skaner</th><th>Job holati</th><th>Topilmalar</th></tr>")
for tool, env in STATUS:
    st = os.environ.get(env, "success")
    col = "#1a7f37" if st == "success" else ("#cf222e" if st == "failure" else "#9a6700")
    n = sum(1 for f in findings if f["tool"] == tool)
    out.append("<tr><td>%s</td><td style='color:%s'><b>%s</b></td><td>%d</td></tr>"
               % (esc(tool), col, esc(st.upper()), n))
out.append("</table>")
for n in notes:
    out.append("<div class='note'><b>Muhim:</b> %s</div>" % esc(n))
out.append("<h2>Barcha topilmalar (og'irlik bo'yicha)</h2>")
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
out.append("<p>ZAP (DAST) hisoboti alohida fayl: reports/zap-report.html (informatsion, gate'ga ta'sir qilmaydi)</p>"
           "</body></html>")
with open("security-report.html", "w", encoding="utf-8") as fh:
    fh.write("\n".join(out))

# --- Gate natijasi (workflow oxirgi qadamda shuni o'qiydi) va run xulosasi
with open("gate.env", "w", encoding="utf-8") as fh:
    fh.write("PASSED=%s\nVIOLATIONS=%d\nSCORE=%.2f\n" % ("true" if passed else "false", len(violations), score))
summary = os.environ.get("GITHUB_STEP_SUMMARY")
if summary:
    with open(summary, "a", encoding="utf-8") as fh:
        fh.write("## Security gate: %s\n\nBuzilgan qoidalar: **%d** | Reyting (ma'lumot uchun): %.2f / %.0f\n\n"
                 % ("PASS" if passed else "FAIL", len(violations), score, MAX_SCORE))
        if violations:
            fh.write("| Qoida | Joyi | Tafsilot |\n|---|---|---|\n")
            for v in violations[:40]:
                fh.write("| %s | `%s` | %s |\n" % (v["rule"], v["where"], v["detail"].replace("|", "/")))
        for p in problems + bad_jobs:
            fh.write("\n:warning: %s\n" % p)
print("findings: %d | violations: %d | rating: %.2f / %.0f | passed: %s" %
      (len(findings), len(violations), score, MAX_SCORE, passed))
