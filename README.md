# CAI SOC Analyst AWS Demo

Presentation-ready clone of the user's CAI / AI-SOC-Analyst workflow.

## Demo flow
1. Open the dashboard.
2. Show SOC metrics and system health.
3. Run the built-in suspicious PowerShell investigation.
4. Show extracted IPs, URLs and hashes.
5. Show MITRE ATT&CK mappings, risk score and recommended actions.
6. Open Investigation History.
7. Search MITRE ATT&CK.
8. Paste custom CTI text and analyze it.

## AWS deployment
Ubuntu EC2 + Docker + FastAPI. The app listens on port 80 through Docker and needs an EC2 security-group rule for TCP 80.

Commands:
git clone https://github.com/AbbhhiramJ/SOC-Analyst-AWS-Demo.git
cd SOC-Analyst-AWS-Demo
docker compose up -d --build

Then open http://YOUR_EC2_PUBLIC_IP

## Why demo mode
The original CAI uses FastAPI, React, CTI ingestion, IoC extraction, MITRE ATT&CK context, RAG and Ollama. This AWS demo keeps the analyst workflow but uses deterministic local analysis so a small EC2 instance can run it without a GPU, Ollama or an external AI API key.

## Architecture
Browser -> AWS EC2 -> FastAPI -> CTI extraction -> MITRE mapping -> risk scoring -> investigation history.

For a production AI version, the deterministic analysis layer can be replaced by the original RAG + Ollama/LLM services.
