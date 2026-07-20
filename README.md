# Shadow IT Detection Platform

A full-stack enterprise security demo: a React dashboard connected to a Flask REST API
that detects unauthorized ("Shadow IT") applications on employee devices, scores their
risk, raises real-time alerts, and includes a code-paste scanner that flags security
risks in pasted code and gives a heuristic best guess at which AI tool (ChatGPT, Gemini,
Claude, Copilot, or a human) likely wrote it.

Tested end-to-end with a real browser (Playwright): login → dashboard → scan → alerts →
applications → code scanner → reports, with zero console errors.

## Project structure

```
shadow-it-platform/
├── backend/          Flask REST API (JWT auth, SQLite, SQLAlchemy)
│   ├── app.py         All routes
│   ├── models.py       Database models
│   ├── code_analysis.py  Heuristic code risk/source analyzer
│   ├── config.py
│   └── requirements.txt
└── frontend/         React + Vite + Tailwind dashboard
    └── src/
        ├── api/client.js       Axios client (reads VITE_API_BASE_URL)
        ├── context/AuthContext.jsx
        ├── components/
        └── pages/
```

## 1. Run the backend

```bash
cd backend
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

The API starts at **http://localhost:5000**. On first run it creates `shadow_it.db`
(SQLite) and seeds demo users, devices, and applications automatically.

**Demo login:** `admin@company.com` / `admin123`

Health check: `curl http://localhost:5000/api/health`

### Optional: real email alerts
By default, email notifications are logged to the console instead of sent (so the
app runs without any mail server configured). To send real emails, set these
environment variables before running `python app.py`:
```bash
export MAIL_SERVER=smtp.yourprovider.com
export MAIL_USERNAME=you@company.com
export MAIL_PASSWORD=your-app-password
export ADMIN_EMAIL=admin@company.com
```

## 2. Run the frontend

In a **second terminal**:
```bash
cd frontend
npm install
npm run dev
```

The app opens at **http://localhost:5173** and is already configured (via `.env`) to
call the backend at `http://localhost:5000/api`. If you run the backend on a
different host/port, edit `frontend/.env`:
```
VITE_API_BASE_URL=http://your-backend-host:5000/api
```

## 3. Use it

1. Open http://localhost:5173, sign in with the demo admin account.
2. Click **Run Shadow IT Scan** on the dashboard to simulate a device scan — any
   unauthorized app found generates a real-time popup alert and (for High/Critical
   risk) an email notification.
3. **Alerts** — search/filter alert history, approve/block/ignore each one.
4. **Applications** — full inventory with risk level and status filters.
5. **Code Scanner** — paste any code snippet to get a security-risk scan (hardcoded
   secrets, `eval`/`exec`, shell injection, etc.) and a heuristic guess at its likely
   AI source. This is pattern-matching for triage, not a forensic guarantee — no tool
   can prove authorship with certainty, and the UI says so.
6. **Reports** — download CSV, Excel, or PDF exports of unauthorized apps + alerts.

## API endpoints

| Method | Endpoint             | Description                          |
|--------|-----------------------|---------------------------------------|
| POST   | /api/login            | Authenticate, returns JWT             |
| GET    | /api/me                | Current user profile                  |
| GET    | /api/dashboard         | Summary stats + chart data            |
| GET    | /api/users             | Employee list with risk scores        |
| GET    | /api/devices           | Enrolled devices                      |
| GET    | /api/applications      | Detected applications (filterable)    |
| POST   | /api/scan              | Simulate a device scan                |
| GET    | /api/alerts            | Alert history (search/filter)         |
| POST   | /api/approve           | Approve an alert/application          |
| POST   | /api/block             | Block an alert/application            |
| POST   | /api/ignore            | Ignore an alert                       |
| GET    | /api/risk              | Risk breakdown summary                |
| POST   | /api/analyze-code      | Analyze pasted code (risk + source)   |
| GET    | /api/reports?format=   | Export report (csv / excel / pdf)     |

All endpoints except `/api/login` and `/api/health` require `Authorization: Bearer <token>`.

## Notes on the "code source" feature

There is no reliable, general-purpose way to prove which AI assistant (or human)
wrote a given piece of code — that's true of any tool claiming to do this, not just
this demo. `analyze-code` uses transparent, weighted text-pattern matching (comment
style, phrasing, formatting habits) to produce a best-guess with a confidence score,
and always returns a note saying it's a heuristic. Treat it as a conversation-starter
for a security review, not a definitive verdict.
