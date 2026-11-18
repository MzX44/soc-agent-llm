# SOC Investigation Agent — CIS 4622 Assignment 3

AI-driven Tier-1 SOC investigation assistant (LangChain + gemini-3.5-flash-lite).
`python main.py TICKET_ID` retrieves a ticket, investigates it with the five SOC
services + VirusTotal + Tavily, streams the activity, and writes
`<TICKET_ID>.md`.

---

## Setup in VS Code (do this once)

### 1. Open the folder
VS Code → **File → Open Folder…** → select this `soc-agent` folder.
If prompted "Do you trust the authors," choose **Yes**.

### 2. Create a virtual environment
Open the terminal (**Terminal → New Terminal**) and run:

**macOS / Linux:**
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

**Windows (PowerShell):**
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

You should see `(venv)` at the start of the terminal prompt.

### 3. Select the interpreter
Press **Ctrl+Shift+P** → "Python: Select Interpreter" → choose the one inside
`./venv`. This makes VS Code use the venv for running and IntelliSense.

### 4. Add your API keys
1. Copy `.env.example` to `.env` (in VS Code, right-click `.env.example` → Copy,
   paste, rename to `.env`).
2. Open `.env` and paste your real keys after each `=` (no spaces, no quotes):
   ```
   GEMINI_API_KEY=AIza...
   VIRUSTOTAL_API_KEY=...
   TAVILY_API_KEY=tvly-...
   CASEBOARD_API_KEY=...
   ```
   - **Gemini**: https://aistudio.google.com/apikey (free tier)
   - **VirusTotal**: profile menu → API Key
   - **Tavily**: https://app.tavily.com dashboard
   - **Caseboard**: ticket platform → API keys → Create key (shown once)

> **Never commit or submit `.env`.** `.gitignore` already excludes it.

---

## Before your first real run (confirm the SOC endpoints)

The SOC endpoint paths in `main.py` (the `ENDPOINTS` dict near the top) were
confirmed against each service's `/docs`. If the lab changes, re-check them.

1. Connect to the course **OpenVPN**.
2. Run the helper:
   ```bash
   python discover_endpoints.py
   ```
   It prints the real routes each service exposes.
3. Open `main.py`, find the `ENDPOINTS = { ... }` block, and fix any path or
   parameter name that differs. **That block is the only place you need to
   edit.** (If a service uses GET-with-query-params instead of a POST body, or a
   different field name, adjust that one tool's request accordingly — the
   comments mark where.)

If `discover_endpoints.py` can't find an `/openapi.json`, open each service's
`/docs` page in a browser (e.g. `http://10.10.11.125:3023/docs`) and read the
routes there.

---

## Run it

VPN connected, `.env` filled in, endpoints confirmed:

```bash
python main.py <TICKET_ID>
```

- The console streams every agent message, tool call, and tool result.
- The final report is written to `<TICKET_ID>.md` in this folder.
- Run it on each of your two assigned tickets.

**Tip (free tier):** test a tool by itself before a full run, e.g. in a quick
Python shell import `main` and call `main.virustotal_domain_report.invoke({"domain": "example.com"})`.
Each run looks up each indicator once (VirusTotal allows 4/min, 500/day).

---

## Finish the submission

1. Paste each ticket's report + representative console output into the
   **Findings** sections of `Report.pdf` (they're marked `[FILL IN]`).
2. Make a **flat ZIP** with exactly two files at the top level — no enclosing
   folder, no `.env`, no `venv/`:
   - `main.py`
   - `Report.pdf`

```bash
# from inside this folder, after filling in Report.pdf:
zip submission.zip main.py Report.pdf
```

---

## Files in this project

| File | What it is |
|---|---|
| `main.py` | The agent. Edit only `.env` and the `ENDPOINTS` block. **Submit this.** |
| `Report.pdf` | Report; fill in the two Findings sections. **Submit this.** |
| `requirements.txt` | The four allowed packages. |
| `.env.example` | Template — copy to `.env` and add keys. |
| `discover_endpoints.py` | One-time helper to confirm SOC API routes. Not submitted. |
| `.gitignore` | Keeps `.env`, `venv/`, and generated `*.md` out of git. |
| `README.md` | This file. |
