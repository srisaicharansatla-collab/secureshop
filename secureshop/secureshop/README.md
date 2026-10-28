# SecureShop — Red Team / AppSec Lab Assignment

An intentionally vulnerable Flask e-commerce app, built for the
**Build → Attack → Identify → Fix → Retest** assignment. Two copies of the
app are included:

- `vulnerable_app/` — the lab target, with documented weaknesses. Runs on
  `http://127.0.0.1:8080`.
- `fixed_app/` — the remediated version, same feature set. Runs on
  `http://127.0.0.1:8081`.

**Only ever scan `127.0.0.1` / `localhost`.** Do not deploy either app to a
public host or scan anything other than your own local instance.

## 1. Setup

```bash
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# Vulnerable target
pip install -r vulnerable_app/requirements.txt
python vulnerable_app/app.py    # -> http://127.0.0.1:8080

# In a second terminal/venv: the fixed version
pip install -r fixed_app/requirements.txt
python fixed_app/app.py         # -> http://127.0.0.1:8081
```

Seed accounts (vulnerable app only — plaintext on purpose):
| username | password | role |
|---|---|---|
| admin | admin123 | admin |
| alice | alicepass | user |
| bob   | bobpass   | user |

The fixed app generates a random admin password at first run and prints it
once to the console (`[setup] generated admin password: ...`). Regular
users (`alice` / `bob`) keep the same passwords, now stored as hashes.

## 2. Seeded vulnerabilities (vulnerable_app only)

| OWASP Category | Where | Try it |
|---|---|---|
| A03 Injection (SQLi + auth bypass) | `/login` | username `admin' -- `, any password |
| A03 Injection (SQLi + reflected XSS) | `/search?q=` | `q=<script>alert(1)</script>`, or `q=%' UNION SELECT id,username,password,is_admin FROM users-- -` |
| A01 Broken Access Control (IDOR) | `/order/<id>` | log in as `alice`, then browse `/order/2` (belongs to `bob`) |
| A01 Broken Access Control | `/admin` | log in as `alice` (non-admin), browse to `/admin` directly |
| A05 Security Misconfiguration | whole app | `DEBUG=True`, hardcoded `secret_key`, default `admin/admin123`, verbose DB errors on `/search` |
| A06 Vulnerable/Outdated Component | `requirements.txt` | Flask 2.0.1 / Werkzeug 2.0.1 — see `vulnerable_app/requirements.txt` for the CVE reference |
| A07 Authentication weakness | `users` table | passwords stored in plaintext, no lockout, weak session cookie flags |
| A09 Logging/Monitoring failure | `/login` | no login attempt (success or failure) is ever logged |

## 3. Running the OWASP ZAP scan (Phase 2)

1. Install OWASP ZAP: <https://www.zaproxy.org/download/>
2. Start the **vulnerable_app** target (`http://127.0.0.1:8080`) — never
   scan the fixed app and call it the "before" result.
3. In ZAP: **Automated Scan** → Target URL `http://127.0.0.1:8080` →
   "Use traditional spider" + Active Scan → Attack.
4. Once finished, export the results: **Report → Generate Report** (HTML
   and/or PDF) and save it into `scan_results/before/`.
5. Stop `vulnerable_app`, start `fixed_app` on `http://127.0.0.1:8081`,
   repeat the same scan, and save the report into `scan_results/after/`.
6. Fill in `REPORT.md` with the actual alert counts/severities ZAP gives
   you for each run — the numbers in this repo are placeholders only,
   since ZAP has to be run on your machine against your running instance.

Record for each run: scan date, target URL, ZAP version, scan type,
number of alerts, severities, affected URLs, and evidence (screenshots or
the exported report) — see `REPORT.md` for the structured template.

## 4. Repo layout

```
secureshop/
├── README.md
├── REPORT.md                 <- fill this in after you run ZAP
├── vulnerable_app/
│   ├── app.py
│   └── requirements.txt      <- outdated, pinned on purpose
├── fixed_app/
│   ├── app.py
│   └── requirements.txt      <- patched
└── scan_results/
    ├── before/                <- put your ZAP export here
    └── after/                 <- put your ZAP export here
```

## 5. Scope reminder

This app is for local, isolated use only. Never point a scanner or this
code at a system you don't own or don't have explicit permission to test.
