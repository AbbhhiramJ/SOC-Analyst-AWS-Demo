from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path
from datetime import datetime, timezone
import hashlib, json, re, sqlite3, urllib.request, urllib.error

ROOT = Path(__file__).resolve().parents[2]
DB = ROOT / "cai_demo.db"
FRONTEND = ROOT / "frontend" / "index.html"

app = FastAPI(title="CAI SOC Analyst", version="2.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

DEMO_REPORT = """Incident report: suspicious PowerShell execution from workstation 10.20.4.15.
The host contacted https://update-secure-example.com/download and resolved 185.199.108.153.
Observed SHA256 7d793037a0760186574b0282f2f435e7b9b8c5d7b4d1e0f9d3e5b21ac6d7e8f9.
The activity resembles T1059.001 PowerShell and T1105 Ingress Tool Transfer.
Credential access indicators were also observed. Severity: High."""

MITRE = [
 {"id":"T1059.001","name":"PowerShell","tactic":"Execution","description":"Adversaries may abuse PowerShell commands and scripts."},
 {"id":"T1105","name":"Ingress Tool Transfer","tactic":"Command and Control","description":"Adversaries may transfer tools or files into a compromised environment."},
 {"id":"T1555","name":"Credentials from Password Stores","tactic":"Credential Access","description":"Adversaries may search application password stores for credentials."},
 {"id":"T1071.001","name":"Web Protocols","tactic":"Command and Control","description":"Application layer protocol over common web protocols."},
 {"id":"T1053.005","name":"Scheduled Task/Job: Scheduled Task","tactic":"Persistence","description":"Adversaries may abuse scheduled tasks for execution."},
 {"id":"T1566.001","name":"Spearphishing Attachment","tactic":"Initial Access","description":"Malicious attachments may deliver payloads to targeted users."},
 {"id":"T1027","name":"Obfuscated Files or Information","tactic":"Defense Evasion","description":"Adversaries may obfuscate files or information."},
 {"id":"T1082","name":"System Information Discovery","tactic":"Discovery","description":"Adversaries may gather information about the operating system."}
]

IOC_PATTERNS = {
 "ipv4": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
 "urls": r"https?://[^\s<>\"']+",
 "sha256": r"\b[a-fA-F0-9]{64}\b",
 "sha1": r"\b[a-fA-F0-9]{40}\b",
 "md5": r"\b[a-fA-F0-9]{32}\b",
 "emails": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
 "domains": r"\b(?!(?:https?|www)\.)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z]{2,63})+\b"
}

def db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    c.execute("""CREATE TABLE IF NOT EXISTS investigations(
        id INTEGER PRIMARY KEY AUTOINCREMENT, filename TEXT, created_at TEXT,
        severity TEXT, risk_score INTEGER, summary TEXT, iocs TEXT, mitre TEXT,
        ai_assessment TEXT, retrieved_context TEXT)""")
    c.commit()
    return c

def extract_iocs(text):
    out = {}
    for kind, pattern in IOC_PATTERNS.items():
        vals = list(dict.fromkeys(re.findall(pattern, text, re.I)))
        if kind == "ipv4":
            vals = [x for x in vals if all(int(p) <= 255 for p in x.split("."))]
        out[kind] = vals
    return out

def map_mitre(text):
    rules = [
      ("powershell","T1059.001","PowerShell","Execution",0.97),
      ("ingress tool transfer","T1105","Ingress Tool Transfer","Command and Control",0.91),
      ("download","T1105","Ingress Tool Transfer","Command and Control",0.86),
      ("credential","T1555","Credentials from Password Stores","Credential Access",0.74),
      ("password","T1555","Credentials from Password Stores","Credential Access",0.74),
      ("scheduled task","T1053.005","Scheduled Task/Job: Scheduled Task","Persistence",0.82),
      ("spearphishing","T1566.001","Spearphishing Attachment","Initial Access",0.84),
      ("obfuscat","T1027","Obfuscated Files or Information","Defense Evasion",0.82),
      ("system information","T1082","System Information Discovery","Discovery",0.78),
      ("http","T1071.001","Web Protocols","Command and Control",0.68)
    ]
    low = text.lower(); found = {}
    for needle, tid, name, tactic, conf in rules:
        if needle in low: found[tid] = {"id":tid,"name":name,"tactic":tactic,"confidence":conf}
    return list(found.values())

def retrieve(text, top_k=4):
    sentences = re.split(r"(?<=[.!?])\s+", text.strip())
    keywords = set(re.findall(r"[a-zA-Z0-9_-]{4,}", text.lower()))
    scored=[]
    for s in sentences:
        words=set(re.findall(r"[a-zA-Z0-9_-]{4,}",s.lower()))
        score=len(words & keywords)
        if score: scored.append((score,s))
    return [s for _,s in sorted(scored, reverse=True)[:top_k]]

def risk(iocs, mitre, text):
    score = min(99, 20 + len(iocs["ipv4"])*8 + len(iocs["urls"])*8 + len(iocs["sha256"])*12 +
                len(iocs["sha1"])*8 + len(iocs["md5"])*6 + len(mitre)*9)
    if re.search(r"\b(critical|ransomware|credential theft|exfiltration)\b", text, re.I): score=min(99,score+12)
    severity = "Critical" if score >= 85 else "High" if score >= 65 else "Medium" if score >= 35 else "Low"
    return score, severity

def ollama_assess(text, iocs, mitre):
    prompt = f"""You are a defensive SOC analyst. Analyze this CTI evidence without inventing facts.
Return 3 short sections: Assessment, Risk signals, Next steps.
Evidence: {text[:5000]}
IoCs: {json.dumps(iocs)}
MITRE: {json.dumps(mitre)}"""
    req = urllib.request.Request("http://127.0.0.1:11434/api/generate",
        data=json.dumps({"model":"phi3","prompt":prompt,"stream":False}).encode(),
        headers={"Content-Type":"application/json"})
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            return json.loads(r.read().decode()).get("response","").strip()
    except Exception:
        return "Local AI unavailable; deterministic CTI + MITRE analysis was used. Start Ollama with model phi3 to enable optional LLM assessment."

def analyze(text, filename="manual-investigation.txt", use_ai=False):
    iocs=extract_iocs(text); mitre=map_mitre(text); score,severity=risk(iocs,mitre,text)
    context=retrieve(text)
    assessment = ollama_assess(text,iocs,mitre) if use_ai else "Deterministic analyst assessment: suspicious activity identified from the supplied evidence. IoCs and ATT&CK techniques are mapped directly from observable text."
    actions=["Isolate the affected endpoint if malicious activity is confirmed.",
             "Validate the parent/child process chain for suspicious execution.",
             "Block confirmed malicious domains/IPs after triage.",
             "Search endpoint and network telemetry for the mapped ATT&CK techniques.",
             "Preserve the source report and relevant logs for investigation."]
    if severity in ("Critical","High"): actions.insert(0,"Escalate the case to the incident-response queue and preserve evidence.")
    result={"id":0,"filename":filename,"created_at":datetime.now(timezone.utc).isoformat(),"severity":severity,
            "risk_score":score,"summary":f"{severity} risk assessment with {sum(map(len,iocs.values()))} indicators and {len(mitre)} ATT&CK mappings.",
            "iocs":iocs,"mitre":mitre,"recommended_actions":actions,"ai_assessment":assessment,
            "retrieved_context":context,"source_excerpt":text[:1600]}
    return result

def save(result):
    c=db()
    cur=c.execute("INSERT INTO investigations(filename,created_at,severity,risk_score,summary,iocs,mitre,ai_assessment,retrieved_context) VALUES(?,?,?,?,?,?,?,?,?)",
      (result["filename"],result["created_at"],result["severity"],result["risk_score"],result["summary"],
       json.dumps(result["iocs"]),json.dumps(result["mitre"]),result["ai_assessment"],json.dumps(result["retrieved_context"])))
    c.commit(); result["id"]=cur.lastrowid; c.close(); return result

@app.get("/")
def root(): return FileResponse(FRONTEND)

@app.get("/api/v1/health")
def health(): return {"status":"ok","service":"cai-soc-analyst","mode":"local-demo","version":"2.0.0"}

@app.get("/api/v1/dashboard")
def dashboard():
    c=db(); row=c.execute("SELECT COUNT(*) n, COALESCE(SUM(CASE WHEN severity='Critical' THEN 1 ELSE 0 END),0) critical, COALESCE(SUM(CASE WHEN severity IN ('Critical','High') THEN 1 ELSE 0 END),0) high FROM investigations").fetchone()
    return {"active_investigations":row["n"],"critical_alerts":row["critical"],"high_alerts":row["high"],
            "iocs_today":37 if row["n"]==0 else row["n"]*3,"mitre_matches":12 if row["n"]==0 else row["n"]*3,
            "system_status":"Operational","analysis_engine":"Deterministic CTI + MITRE + lightweight RAG","ai_available":ollama_available()}

def ollama_available():
    try:
        urllib.request.urlopen("http://127.0.0.1:11434/api/tags",timeout=1); return True
    except Exception: return False

@app.get("/api/v1/demo/report")
def demo_report(): return save(analyze(DEMO_REPORT,"demo-threat-report.txt",False))

@app.post("/api/v1/cti/analyze-text")
async def cti_text(payload:dict):
    text=str(payload.get("text","")).strip()
    if not text: raise HTTPException(400,"Text required")
    return save(analyze(text,"manual-investigation.txt",bool(payload.get("use_ai",False))))

@app.post("/api/v1/cti/analyze")
async def cti_analyze(file: UploadFile=File(...), use_ai: bool=False):
    raw=await file.read()
    if file.filename.lower().endswith(".pdf"):
        try:
            from pypdf import PdfReader
            import io
            reader=PdfReader(io.BytesIO(raw)); text="\n".join((p.extract_text() or "") for p in reader.pages)
        except Exception as e: raise HTTPException(400,f"PDF extraction failed: {e}")
    else:
        text=raw.decode("utf-8","ignore")
    if not text.strip(): raise HTTPException(400,"No readable text found")
    return save(analyze(text,file.filename or "uploaded-report.txt",use_ai))

@app.get("/api/v1/investigations")
def investigations():
    c=db(); rows=c.execute("SELECT * FROM investigations ORDER BY id DESC").fetchall(); c.close()
    items=[]
    for r in rows:
        items.append({"id":r["id"],"filename":r["filename"],"created_at":r["created_at"],"severity":r["severity"],
          "risk_score":r["risk_score"],"summary":r["summary"],"iocs":json.loads(r["iocs"]),"mitre":json.loads(r["mitre"]),
          "ai_assessment":r["ai_assessment"],"retrieved_context":json.loads(r["retrieved_context"])})
    return {"items":items,"count":len(items)}

@app.get("/api/v1/investigations/{id}")
def investigation(id:int):
    data=investigations()["items"]
    for x in data:
        if x["id"]==id: return x
    raise HTTPException(404,"Investigation not found")

@app.get("/api/v1/mitre/search")
def mitre_search(q:str="",limit:int=20):
    q=q.lower().strip()
    results=[x for x in MITRE if not q or q in " ".join(x.values()).lower()]
    return {"query":q,"results":results[:max(1,min(limit,50))]}

@app.get("/api/v1/mitre/catalog")
def mitre_catalog(): return {"results":MITRE,"count":len(MITRE)}

@app.get("/api/v1/export/{id}")
def export_case(id:int):
    case=investigation(id)
    return case
