#!/usr/bin/env python3
"""HCO BUG HUNTER - Code by Azhar - HCO
Authorized, low-impact web security assessment assistant.
"""
import json, os, re, socket, ssl, time, webbrowser
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen

VERSION = "1.0.1"
YOUTUBE = "https://youtube.com/@hackers_colony_termux?si=gJjJ3pKGkPpk1Qkw"
WORKDIR = Path.home() / ".hco_bug_hunter"
REPORT_DIR = WORKDIR / "reports"
RESET="\033[0m"; BOLD="\033[1m"; GREEN="\033[92m"; CYAN="\033[96m"
YELLOW="\033[93m"; RED="\033[91m"; MAGENTA="\033[95m"; WHITE="\033[97m"; DIM="\033[2m"
UA="HCO-Bug-Hunter/1.0 (authorized-security-assessment)"; TIMEOUT=8

def c(t,col=WHITE,bold=False): return f"{BOLD if bold else ''}{col}{t}{RESET}"
def clear(): os.system("clear" if os.name != "nt" else "cls")
def ensure_dirs(): REPORT_DIR.mkdir(parents=True,exist_ok=True)

def banner():
    print(c(r'''\
╔══════════════════════════════════════════╗
║            HCO BUG HUNTER              ║
║      Advanced Web Security Tool        ║
║          Code by Azhar - HCO           ║
╚══════════════════════════════════════════╝
'''.lstrip("\\"),GREEN,True))
    print(c(f"Version {VERSION} | Authorized Security Assessment\n",DIM))

def open_youtube():
    try:
        return os.system('am start -a android.intent.action.VIEW -d "'+YOUTUBE+'" > /dev/null 2>&1') == 0
    except Exception:
        try: return bool(webbrowser.open(YOUTUBE))
        except Exception: return False

def lock_screen():
    clear(); banner(); print(c("🔒 HCO BUG HUNTER",CYAN,True)); print(c("Please support Hackers Colony on YouTube.",WHITE)); print(c("Opening YouTube in:",YELLOW,True))
    for n in range(9,0,-1): print(f"\r{c(f'              {n}...',GREEN,True)}",end="",flush=True); time.sleep(1)
    print()
    if open_youtube(): print(c("\n✓ YouTube launch request sent.",GREEN,True))
    else: print(c("\n⚠ Could not open YouTube automatically.",YELLOW,True)); print(YOUTUBE)
    print(c("\nReturn to Termux after visiting the channel.",CYAN)); input(c("Press ENTER to continue...",YELLOW,True))

def normalize_target(raw):
    raw=raw.strip()
    if not raw: return None
    if not re.match(r"^https?://",raw,re.I): raw="https://"+raw
    p=urlparse(raw)
    if not p.hostname or p.username or p.password: return None
    return p._replace(fragment="",query="").geturl().rstrip("/")

def in_scope(url,host): return (urlparse(url).hostname or "").lower().rstrip(".")==host.lower().rstrip(".")

def fetch(url,method="GET",max_bytes=512000):
    try:
        req=Request(url,headers={"User-Agent":UA,"Accept":"*/*"},method=method)
        with urlopen(req,timeout=TIMEOUT,context=ssl.create_default_context()) as r:
            return {"ok":True,"status":getattr(r,"status",200),"headers":dict(r.headers.items()),"body":r.read(max_bytes),"url":r.geturl()}
    except Exception as e: return {"ok":False,"error":str(e),"url":url}

def dns_info(host):
    try: return {"host":host,"addresses":sorted({i[4][0] for i in socket.getaddrinfo(host,None)})}
    except Exception as e: return {"host":host,"addresses":[],"error":str(e)}

def tls_info(host,port=443):
    try:
        ctx=ssl.create_default_context()
        with socket.create_connection((host,port),timeout=TIMEOUT) as s:
            with ctx.wrap_socket(s,server_hostname=host) as ss:
                cert=ss.getpeercert()
                return {"host":host,"port":port,"tls_version":ss.version(),"cipher":ss.cipher()[0] if ss.cipher() else None,"subject":str(cert.get("subject","")),"issuer":str(cert.get("issuer","")),"not_after":cert.get("notAfter")}
    except Exception as e: return {"host":host,"port":port,"error":str(e)}

def header_findings(headers):
    h={k.lower():v for k,v in headers.items()}; out=[]
    checks={"content-security-policy":"Consider a suitable Content-Security-Policy.","strict-transport-security":"Consider HSTS after validating application behavior.","x-content-type-options":"Consider X-Content-Type-Options: nosniff.","referrer-policy":"Consider an explicit Referrer-Policy.","permissions-policy":"Consider an appropriate Permissions-Policy."}
    for key,fix in checks.items():
        if key not in h: out.append({"type":"Security header not observed","severity":"INFO","confidence":"HIGH","evidence":f"Header not present: {key}","impact":"May reduce browser-side security hardening depending on context.","remediation":fix})
    if "server" in h: out.append({"type":"Server header disclosure","severity":"LOW","confidence":"HIGH","evidence":f"Observed Server header: {h['server'][:120]}","impact":"May reveal technology information useful for reconnaissance.","remediation":"Minimize unnecessary server identification where practical."})
    return out

def cookie_findings(headers):
    raw=headers.get("Set-Cookie","")
    if not raw: return []
    low=raw.lower(); out=[]
    if "secure" not in low: out.append({"type":"Cookie Secure attribute not observed","severity":"LOW","confidence":"MEDIUM","evidence":"Observed Set-Cookie without an obvious Secure attribute.","impact":"Sensitive cookies may have increased exposure in some deployments.","remediation":"Use Secure for sensitive cookies when appropriate."})
    if "httponly" not in low: out.append({"type":"Cookie HttpOnly attribute not observed","severity":"LOW","confidence":"MEDIUM","evidence":"Observed Set-Cookie without an obvious HttpOnly attribute.","impact":"Client-side script access may increase exposure in some threat models.","remediation":"Use HttpOnly for cookies that do not need JavaScript access."})
    return out

def extract_links(base,body,limit=80):
    text=body.decode("utf-8",errors="ignore"); found=[]
    for m in re.findall(r'''(?:href|src|action)\s*=\s*["']([^"']+)["']''',text,re.I):
        u=urljoin(base,m)
        if urlparse(u).scheme in ("http","https"): found.append(u.split("#")[0])
    for m in re.findall(r'''["'](\/(?:api|graphql|v\d+)[^"']*)["']''',text,re.I): found.append(urljoin(base,m))
    return list(dict.fromkeys(found))[:limit]

def inspect_target(target):
    p=urlparse(target); host=p.hostname
    data={"target":target,"timestamp":datetime.now(timezone.utc).isoformat(),"dns":dns_info(host),"tls":tls_info(host) if p.scheme=="https" else {"note":"Target is not HTTPS."},"http":{},"discovered_urls":[],"findings":[],"public_resources":[]}
    if not data["dns"].get("addresses"):
        data["assessment_status"]="DNS_FAILED"; data["assessment_error"]="Target hostname could not be resolved. No security tests were completed."; return data
    r=fetch(target)
    if not r["ok"]:
        data["http"]=r; data["assessment_status"]="HTTP_FAILED"; data["assessment_error"]="The target could not be fetched successfully. No vulnerability conclusion can be made."; return data
    data["http"]={"status":r["status"],"final_url":r["url"],"headers":r["headers"]}
    data["findings"]+=header_findings(r["headers"])+cookie_findings(r["headers"])
    data["discovered_urls"]=[u for u in extract_links(r["url"],r["body"]) if in_scope(u,host)]
    for path in ("/robots.txt","/sitemap.xml"):
        u=urljoin(target+"/",path.lstrip("/")); x=fetch(u)
        if x["ok"]: data["public_resources"].append({"url":u,"status":x["status"]})
    data["assessment_status"]="COMPLETED"; return data

def rank(s): return {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}.get(s,5)

def render(data):
    print("\n"+c("═"*58,GREEN)); print(c("ASSESSMENT RESULTS",GREEN,True)); print(c("═"*58,GREEN)); print(c(f"Target: {data['target']}",WHITE,True)); print(c(f"Time:   {data['timestamp']}",DIM))
    dns=data["dns"]; print("\n"+c("[+] DNS",CYAN,True)); print(c("    "+(", ".join(dns.get("addresses",[])) or "✗ Hostname could not be resolved."),RED if not dns.get("addresses") else WHITE,not bool(dns.get("addresses"))))
    tls=data["tls"]; print(c("\n[+] TLS",CYAN,True));
    if tls.get("tls_version"): print(c(f"    Version: {tls['tls_version']}",WHITE)); print(c(f"    Cipher:  {tls.get('cipher','Unavailable')}",WHITE))
    else: print(c(f"    ⚠ {tls.get('error',tls.get('note','Unavailable'))}",YELLOW))
    h=data["http"]; print(c("\n[+] HTTP",CYAN,True));
    if h.get("status"): print(c(f"    Status: {h['status']}",WHITE)); print(c(f"    Final URL: {h.get('final_url','Unavailable')}",WHITE))
    else: print(c("    ✗ HTTP assessment was not completed.",RED,True))
    print(c(f"\n[+] In-scope URLs discovered: {len(data['discovered_urls'])}",CYAN,True)); print("\n"+c("FINDINGS",MAGENTA,True))
    findings=sorted(data["findings"],key=lambda x:rank(x.get("severity")))
    if not findings: print(c("    No potential finding was detected by enabled checks.",GREEN))
    for i,f in enumerate(findings,1):
        col=RED if f["severity"] in ("CRITICAL","HIGH") else YELLOW if f["severity"]=="MEDIUM" else GREEN
        print(c(f"\n[{i}] {f['type']} — {f['severity']}",col,True)); print(c(f"    Confidence: {f['confidence']}",WHITE)); print(c(f"    Evidence: {f['evidence']}",WHITE)); print(c(f"    Impact: {f['impact']}",WHITE)); print(c(f"    Fix: {f['remediation']}",WHITE))
    if data.get("assessment_status")!="COMPLETED": print(c("\n⚠ Assessment was not completed.",YELLOW,True)); print(c(f"  {data.get('assessment_error','Unknown assessment error.')}",YELLOW)); print(c("\nNo vulnerability conclusion can be made from this run.",YELLOW,True))
    elif not findings: print(c("\nNo confirmed vulnerability is claimed by this assessment.",GREEN,True))

def save_reports(data):
    ensure_dirs(); stamp=datetime.now().strftime("%Y%m%d_%H%M%S"); host=re.sub(r"[^A-Za-z0-9_.-]","_",urlparse(data["target"]).hostname or "target")
    jp=REPORT_DIR/f"{host}_{stamp}.json"; mp=REPORT_DIR/f"{host}_{stamp}.md"; jp.write_text(json.dumps(data,indent=2,ensure_ascii=False),encoding="utf-8")
    lines=["# HCO BUG HUNTER REPORT","",f"- Target: `{data['target']}`",f"- Generated: `{data['timestamp']}`",f"- Assessment status: `{data.get('assessment_status','UNKNOWN')}`","","## Findings",""]
    if not data["findings"]: lines.append("No potential finding was detected by enabled checks.")
    for i,f in enumerate(data["findings"],1): lines += [f"### {i}. {f['type']}",f"- Severity: **{f['severity']}**",f"- Confidence: **{f['confidence']}**",f"- Evidence: {f['evidence']}",f"- Impact: {f['impact']}",f"- Remediation: {f['remediation']}",""]
    if data.get("assessment_error"): lines += ["## Assessment Note","",data["assessment_error"],""]
    mp.write_text("\n".join(lines),encoding="utf-8"); return jp,mp

def view_report(path):
    clear(); banner(); print(c(f"REPORT: {path.name}",CYAN,True)); print(c("═"*58,GREEN)); print(path.read_text(encoding="utf-8")); print(c("\n"+"═"*58,GREEN)); input(c("Press ENTER to return...",YELLOW,True))

def reports_menu():
    ensure_dirs()
    while True:
        clear(); banner(); print(c("SAVED REPORTS",CYAN,True)); print(c("═"*58,GREEN))
        files=sorted([p for p in REPORT_DIR.iterdir() if p.is_file() and p.suffix.lower() in (".json",".md")],key=lambda p:p.stat().st_mtime,reverse=True)
        if not files: print(c("\nNo reports found yet.",YELLOW)); input("\nPress ENTER to return..."); return
        for i,p in enumerate(files,1):
            size=p.stat().st_size; modified=datetime.fromtimestamp(p.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
            print(c(f"{i:2}.",GREEN,True),f"{p.name} {DIM}{size} bytes | {modified}{RESET}")
        print(c("\n0.",RED,True),"Back")
        choice=input(c("\nSelect report: ",CYAN,True)).strip()
        if choice=="0": return
        if not choice.isdigit() or not 1<=int(choice)<=len(files): print(c("Invalid report selection.",RED)); time.sleep(1); continue
        view_report(files[int(choice)-1])

def assessment():
    print(c("\nAUTHORIZED TARGET ONLY",YELLOW,True)); print(c("Use only a domain/asset you own or have explicit permission to assess.",WHITE))
    raw=input(c("Target URL: ",CYAN,True)); target=normalize_target(raw)
    if not target: print(c("Invalid target URL.",RED)); input("Press ENTER..."); return
    host=urlparse(target).hostname; ok=input(c(f"Confirm authorized scope for {host}? [yes/no]: ",YELLOW,True)).strip().lower()
    if ok!="yes": print(c("Assessment cancelled.",YELLOW)); input("Press ENTER..."); return
    print(c("\nStarting low-impact assessment...\n",GREEN,True)); data=inspect_target(target); render(data); jp,mp=save_reports(data); print(c(f"\n[+] JSON report saved: {jp}",GREEN)); print(c(f"[+] Markdown report saved: {mp}",GREEN)); input(c("\nPress ENTER to return to menu...",YELLOW,True))

def menu():
    while True:
        clear(); banner(); print(c("1.",GREEN,True),"New Security Assessment"); print(c("2.",GREEN,True),"View Saved Reports"); print(c("3.",GREEN,True),"About / Ethical Use"); print(c("0.",RED,True),"Exit")
        ch=input(c("\nHCO> ",CYAN,True)).strip()
        if ch=="1": assessment()
        elif ch=="2": reports_menu()
        elif ch=="3":
            clear(); banner(); print(c("AUTHORIZED SECURITY TESTING ONLY",GREEN,True)); print("\nUse only on systems you own or have explicit written permission to assess."); print("Respect scope, rate limits and responsible-disclosure rules."); print("No unauthorized access, credential attacks, malware, data theft or service disruption."); input("\nPress ENTER...")
        elif ch=="0": print(c("\nStay safe. Stay ethical. Keep learning. 🛡️",GREEN,True)); break
        else: print(c("Invalid option.",RED)); time.sleep(1)

if __name__=="__main__":
    ensure_dirs(); lock_screen(); menu()
