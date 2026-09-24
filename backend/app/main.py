from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path
import re, datetime

ROOT = Path(__file__).resolve().parents[2]
app = FastAPI(title="CAI SOC Analyst Demo", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
DEMO_REPORT = """Incident report: suspicious PowerShell execution from workstation 10.20.4.15.
The host contacted hxxp://update-secure-example.com/download and resolved 185.199.108.153.
Observed SHA256: 7d793037a0760186574b0282f2f435e7b9b8c5d7b4d1e0f9d3e5b2a1c6d7e8f9.
The activity resembles T1059.001 PowerShell and T1105 Ingress Tool Transfer.
User account: analyst-demo@example.local. Severity: High."""
INVESTIGATIONS=[]
def extract_iocs(text):
    return {"ipv4":sorted(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b",text))),
            "urls":sorted(set(re.findall(r"https?://[^\s)]+|hxxps?://[^\s)]+",text,re.I))),
            "hashes":sorted(set(re.findall(r"\b[a-fA-F0-9]{64}\b",text))),
            "domains":sorted(set(re.findall(r"(?<![/\w])(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?![/\w])",text)))}
def mitre(text):
    out=[]
    if re.search("powershell",text,re.I): out.append({"id":"T1059.001","name":"PowerShell","tactic":"Execution","confidence":.97})
    if re.search("ingress|download|transfer",text,re.I): out.append({"id":"T1105","name":"Ingress Tool Transfer","tactic":"Command and Control","confidence":.91})
    if re.search("credential|password|token",text,re.I): out.append({"id":"T1555","name":"Credentials from Password Stores","tactic":"Credential Access","confidence":.74})
    return out
def analyze(text,filename):
    iocs=extract_iocs(text); techniques=mitre(text)
    return {"id":len(INVESTIGATIONS)+1,"filename":filename,"created_at":datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "severity":"High" if techniques else "Medium","summary":"Suspicious execution and external transfer indicators detected.",
            "iocs":iocs,"mitre":techniques,"risk_score":min(99,42+len(techniques)*18+len(iocs["ipv4"])*8+len(iocs["hashes"])*12),
            "recommended_actions":["Isolate the affected endpoint from the network.","Validate the PowerShell parent/child process chain.","Block confirmed malicious domains/IPs after triage.","Search enterprise telemetry for the mapped ATT&CK techniques."]}
@app.get("/")
def root(): return FileResponse(ROOT/"frontend"/"index.html")
@app.get("/api/v1/health")
def health(): return {"status":"ok","mode":"demo","service":"cai-soc-analyst","version":"1.0.0"}
@app.get("/api/v1/dashboard")
def dashboard(): return {"active_investigations":len(INVESTIGATIONS)+3,"critical_alerts":1,"high_alerts":4,"iocs_today":37,"mitre_matches":12,"system_status":"Operational"}
@app.get("/api/v1/demo/report")
def demo_report(): return analyze(DEMO_REPORT,"demo-threat-report.txt")
@app.post("/api/v1/cti/analyze")
async def cti_analyze(file:UploadFile=File(...)):
    raw=await file.read(); text=raw.decode("utf-8",errors="ignore") or DEMO_REPORT
    result=analyze(text,file.filename or "uploaded-report.txt"); INVESTIGATIONS.append(result); return result
@app.post("/api/v1/cti/analyze-text")
async def cti_text(payload:dict):
    text=str(payload.get("text","")).strip()
    if not text: raise HTTPException(400,"Text required")
    result=analyze(text,"manual-investigation.txt"); INVESTIGATIONS.append(result); return result
@app.get("/api/v1/investigations")
def investigations(): return {"items":list(reversed(INVESTIGATIONS)),"count":len(INVESTIGATIONS)}
@app.get("/api/v1/mitre/search")
def mitre_search(q:str=""):
    catalog=[{"id":"T1059.001","name":"PowerShell","tactic":"Execution","description":"Command and scripting interpreter using PowerShell."},
    {"id":"T1105","name":"Ingress Tool Transfer","tactic":"Command and Control","description":"Adversaries may transfer tools or files into a compromised environment."},
    {"id":"T1555","name":"Credentials from Password Stores","tactic":"Credential Access","description":"Adversaries may search for credentials stored by applications."},
    {"id":"T1071.001","name":"Web Protocols","tactic":"Command and Control","description":"Application layer protocol over common web protocols."}]
    q=q.lower(); return {"results":[x for x in catalog if not q or q in " ".join(map(str,x.values())).lower()]}
