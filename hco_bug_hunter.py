#!/usr/bin/env python3
"""
HCO BUG HUNTER
Advanced Web Security Assessment Assistant
Code by Azhar - HCO

Authorized-use security assessment tool.
Low-impact reconnaissance and defensive web-security checks only.
"""

import json, os, re, socket, ssl, sys, time, webbrowser
from datetime import datetime
from pathlib import Path
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen

APP="HCO BUG HUNTER"; VERSION="1.0.0"; AUTHOR="Azhar - HCO"
YOUTUBE="https://youtube.com/@hackers_colony_termux?si=gJj3pKGkPpk1Qkw"
WORKDIR=Path.home()/".hco_bug_hunter"; REPORT_DIR=WORKDIR/"reports"
RESET="\033[0m"; BOLD="\033[1m"; GREEN="\033[92m"; CYAN="\033[96m"
YELLOW="\033[93m"; RED="\033[91m"; MAGENTA="\033[95m"; WHITE="\033[97m"; DIM="\033[2m"
UA="HCO-Bug-Hunter/1.0 (authorized-security-assessment)"; TIMEOUT=8

def c(t,col=WHITE,bold=False): return f"{BOLD if bold else ''}{col}{t}{RESET}"
def clear(): os.system("clear" if os.name!="nt" else "cls")
def ensure_dirs(): REPORT_DIR.mkdir(parents=True,exist_ok=True)

def banner():
    print(c(r"""
╔══════════════════════════════════════════╗
║            HCO BUG HUNTER              ║
║      Advanced Web Security Tool        ║
║          Code by Azhar - HCO           ║
╚══════════════════════════════════════════╝
""",GREEN,True))
    print(c(f"Version {VERSION} | Authorized Security Assessment\n",DIM))

def lock_screen():
    clear(); banner()
    print(c("🔒 HCO BUG HUNTER",CYAN,True))
    print(c("Please support Hackers Colony on YouTube.",WHITE))
    print(c("Opening YouTube in:",YELLOW,True))
    for n in range(9,0,-1):
        print(f"\r{c(f'              {n}...',GREEN,True)}",end="",flush=True); time.sleep(1)
    print()
    try: webbrowser.open(YOUTUBE)
    except Exception: pass
    print(c("\nReturn to Termux after visiting the channel.",CYAN))
    input(c("Press ENTER to continue...",YELLOW,True))

def normalize_target(raw):
    raw=raw.strip()
    if not raw: return None
    if not re.match(r"^https?://",raw,re.I): raw="https://"+raw
    p=urlparse(raw)
    if not p.hostname or p.username or p.password: return None
    return p._replace(fragment="",query="").geturl().rstrip("/")

def in_scope(url,host):
    return (urlparse(url).hostname or "").lower().rstrip(".")==host.lower().rstrip(".")

def fetch(url,method="GET",max_bytes=512000):
    req=Request(url,headers={"User-Agent":UA,"Accept":"*/*"},method=method)
    try:
        with urlopen(req,timeout=TIMEOUT,context=ssl.create_default_context()) as r:
            return {"ok":True,"status":getattr(r,"status",200),"headers":dict(r.headers.items()),
                    "body":r.read(max_bytes),"url":r.geturl()}
    except Exception as e: return {"ok":False,"error":str(e),"url":url}

def dns_info(host):
    try:
        return {"host":host,"addresses":sorted({i[4][0] for i in socket.getaddrinfo(host,None)})}
    except Exception as e: return {"host":host,"addresses":[],"error":str(e)}

def tls_info(host,port=443):
    try:
        ctx=ssl.create_default_context()
        with socket.create_connection((host,port),timeout=TIMEOUT) as s:
            with ctx.wrap_socket(s,server_hostname=host) as ss:
                cert=ss.getpeercert()
                return {"host":host,"port":port,"tls_version":ss.version(),
                        "cipher":ss.cipher()[0] if ss.cipher() else None,
                        "subject":str(cert.get("subject","")),"issuer":str(cert.get("issuer","")),
                        "not_after":cert.get("notAfter")}
    except Exception as e: return {"host":host,"port":port,"error":str(e)}

def header_findings(headers):
    h={k.lower():v for k,v in headers.items()}; out=[]
    checks={
        "content-security-policy":"Consider a suitable Content-Security-Policy.",
        "strict-transport-security":"Consider HSTS after validating application behavior.",
        "x-content-type-options":"Consider X-Content-Type-Options: nosniff.",
        "referrer-policy":"Consider an explicit Referrer-Policy.",
        "permissions-policy":"Consider an appropriate Permissions-Policy."
    }
    for key,fix in checks.items():
        if key not in h:
            out.append({"type":"Security header not observed","severity":"INFO","confidence":"HIGH",
                        "evidence":f"Header not present: {key}",
                        "impact":"May reduce browser-side security hardening depending on context.",
                        "remediation":fix})
    if "server" in h:
        out.append({"type":"Server header disclosure","severity":"LOW","confidence":"HIGH",
                    "evidence":f"Observed Server header: {h['server'][:120]}",
                    "impact":"May reveal technology information useful for reconnaissance.",
                    "remediation":"Minimize unnecessary server identification where practical."})
    return out

def cookie_findings(headers):
    raw=headers.get("Set-Cookie",""); low=raw.lower(); out=[]
    if not raw: return out
    if "secure" not in low:
        out.append({"type":"Cookie Secure attribute not observed","severity":"LOW","confidence":"MEDIUM",
                    "evidence":"Observed Set-Cookie without an obvious Secure attribute.",
                    "impact":"Sensitive cookies may have increased exposure in some deployments.",
                    "remediation":"Use Secure for sensitive cookies when appropriate."})
    if "httponly" not in low:
        out.append({"type":"Cookie HttpOnly attribute not observed","severity":"LOW","confidence":"MEDIUM",
                    "evidence":"Observed Set-Cookie without an obvious HttpOnly attribute.",
                    "impact":"Client-side script access may increase exposure in some threat models.",
                    "remediation":"Use HttpOnly for cookies that do not need JavaScript access."})
    return out

def extract_links(base,body,limit=80):
    text=body.decode("utf-8",errors="ignore"); found=[]
    pattern=r"""(?:href|src|action)\s*=\s*["']([^"']+)["']"""
    for m in re.findall(pattern,text,re.I):
        u=urljoin(base,m)
        if urlparse(u).scheme in ("http","https"): found.append(u.split("#")[0])
    for m in re.findall(r"""["'](\/(?:api|graphql|v\d+)[^"']*)["']""",text,re.I):
        found.append(urljoin(base,m))
    return list(dict.fromkeys(found))[:limit]

def inspect_target(target):
    host=urlparse(target).hostname
    data={"target":target,"timestamp":datetime.utcnow().isoformat()+"Z","dns":dns_info(host),
          "tls":tls_info(host) if urlparse(target).scheme=="https" else {"note":"Target is not HTTPS."},
          "http":{},"discovered_urls":[],"findings":[],"public_resources":[]}
    r=fetch(target)
    if not r["ok"]: data["http"]=r; return data
    data["http"]={"status":r["status"],"final_url":r["url"],"headers":r["headers"]}
    data["findings"]+=header_findings(r["headers"])+cookie_findings(r["headers"])
    data["discovered_urls"]=[u for u in extract_links(r["url"],r["body"]) if in_scope(u,host)]
    for path in ("/robots.txt","/sitemap.xml"):
        u=urljoin(target+"/",path.lstrip("/")); x=fetch(u)
        if x["ok"]: data["public_resources"].append({"url":u,"status":x["status"]})
    return data

def rank(s): return {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}.get(s,5)

def render(data):
    print("\n"+c("═"*58,GREEN)); print(c("ASSESSMENT RESULTS",GREEN,True)); print(c("═"*58,GREEN))
    print(c(f"Target: {data['target']}",WHITE,True)); print(c(f"Time:   {data['timestamp']}",DIM))
    print("\n"+c("[+] DNS",CYAN,True)); print(c("    "+(", ".join(data["dns"].get("addresses",[])) or "No address resolved."),WHITE))
    tls=data["tls"]; print(c("\n[+] TLS",CYAN,True)); print(c(f"    {tls.get('tls_version',tls.get('note',tls.get('error','Unavailable')))}",WHITE))
    h=data["http"]; print(c("\n[+] HTTP",CYAN,True)); print(c(f"    Status: {h.get('status','Unavailable')}",WHITE))
    print(c(f"    Final URL: {h.get('final_url','Unavailable')}",WHITE))
    print(c(f"\n[+] In-scope URLs discovered: {len(data['discovered_urls'])}",CYAN,True))
    print("\n"+c("FINDINGS",MAGENTA,True))
    findings=sorted(data["findings"],key=lambda x:rank(x.get("severity")))
    if not findings: print(c("    No potential finding was detected by enabled checks.",GREEN))
    for i,f in enumerate(findings,1):
        col=RED if f["severity"] in ("CRITICAL","HIGH") else YELLOW if f["severity"]=="MEDIUM" else GREEN
        print(c(f"\n[{i}] {f['type']} — {f['severity']}",col,True))
        print(c(f"    Confidence: {f['confidence']}",WHITE))
        print(c(f"    Evidence: {f['evidence']}",WHITE))
        print(c(f"    Impact: {f['impact']}",WHITE)); print(c(f"    Fix: {f['remediation']}",WHITE))
    if not findings: print(c("\nNo confirmed vulnerability is claimed by this assessment.",GREEN,True))

def save_reports(data):
    ensure_dirs(); stamp=datetime.now().strftime("%Y%m%d_%H%M%S")
    host=re.sub(r"[^A-Za-z0-9_.-]","_",urlparse(data["target"]).hostname or "target")
    jp=REPORT_DIR/f"{host}_{stamp}.json"; mp=REPORT_DIR/f"{host}_{stamp}.md"
    jp.write_text(json.dumps(data,indent=2,ensure_ascii=False),encoding="utf-8")
    lines=["# HCO BUG HUNTER REPORT","",f"- Target: `{data['target']}`",
           f"- Generated: `{data['timestamp']}`","","## Findings",""]
    if not data["findings"]: lines.append("No potential finding was detected by enabled checks.")
    for i,f in enumerate(data["findings"],1):
        lines += [f"### {i}. {f['type']}",f"- Severity: **{f['severity']}**",
                  f"- Confidence: **{f['confidence']}**",f"- Evidence: {f['evidence']}",
                  f"- Impact: {f['impact']}",f"- Remediation: {f['remediation']}",""]
    mp.write_text("\n".join(lines),encoding="utf-8"); return jp,mp

def assessment():
    print(c("\nAUTHORIZED TARGET ONLY",YELLOW,True))
    raw=input(c("Target URL: ",CYAN,True)); target=normalize_target(raw)
    if not target: print(c("Invalid target URL.",RED)); input("Press ENTER..."); return
    host=urlparse(target).hostname
    ok=input(c(f"Confirm authorized scope for {host}? [yes/no]: ",YELLOW,True)).strip().lower()
    if ok!="yes": print(c("Assessment cancelled.",YELLOW)); input("Press ENTER..."); return
    print(c("\nStarting low-impact assessment...\n",GREEN,True))
    data=inspect_target(target); render(data); jp,mp=save_reports(data)
    print(c(f"\n[+] JSON report: {jp}",GREEN)); print(c(f"[+] Markdown report: {mp}",GREEN))
    input(c("\nPress ENTER to return to menu...",YELLOW))

def menu():
    while True:
        clear(); banner()
        print(c("1.",GREEN,True),"New Security Assessment")
        print(c("2.",GREEN,True),"Open Reports Folder")
        print(c("3.",GREEN,True),"About / Ethical Use")
        print(c("0.",RED,True),"Exit")
        ch=input(c("\nHCO> ",CYAN,True)).strip()
        if ch=="1": assessment()
        elif ch=="2":
            ensure_dirs(); print(c(f"\nReports: {REPORT_DIR}",GREEN))
            try: webbrowser.open(REPORT_DIR.as_uri())
            except Exception: pass
            input("\nPress ENTER...")
        elif ch=="3":
            print(c("\nUse only on systems you own or have explicit written permission to assess.",GREEN,True))
            print("Respect scope, rate limits and disclosure rules.")
            print("No unauthorized access, credential attacks, malware, data theft or disruption.")
            input("\nPress ENTER...")
        elif ch=="0": break
        else: print(c("Invalid option.",RED)); time.sleep(1)

if __name__=="__main__":
    ensure_dirs(); lock_screen(); menu()
