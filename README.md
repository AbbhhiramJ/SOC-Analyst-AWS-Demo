# CAI SOC Analyst — Local Demo

A CPU-friendly presentation build of the CAI / AI-SOC-Analyst workflow.

## Included
- FastAPI analyst backend
- CTI text and PDF ingestion
- IPv4, URL, domain, MD5, SHA-1, SHA-256 and email extraction
- MITRE ATT&CK technique mapping
- Lightweight evidence retrieval (RAG-style)
- Risk scoring and response recommendations
- SQLite investigation persistence
- Investigation history and case detail
- Optional Ollama assessment when Ollama is available locally
- Responsive analyst dashboard
- Docker + GitHub Actions smoke tests

## Run locally

```bash
open -a Docker
git clone https://github.com/AbbhhiramJ/SOC-Analyst-AWS-Demo.git
cd SOC-Analyst-AWS-Demo
docker compose up -d --build
```

Open http://localhost

Health:
```bash
curl http://localhost/api/v1/health
```

## Demo sequence
1. Dashboard
2. Run demo investigation
3. Show IoCs and ATT&CK mappings
4. Show retrieved evidence and response actions
5. Upload a PDF or paste CTI
6. Open Investigation History
7. Search MITRE ATT&CK
8. Show Architecture

## Relationship to the original CAI
The original project uses FastAPI, React, CTI ingestion, IoC extraction, MITRE ATT&CK context, TF-IDF-style RAG and optional local Ollama analysis. This demo keeps those analyst workflows while using a compact single-container implementation suitable for a laptop or small EC2 instance.
