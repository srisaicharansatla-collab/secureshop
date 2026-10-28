# Red Team / Application Security Assignment Report
### Company: SecureShop
**Author:** _[your name]_
**Date:** _[date]_
**Stack used:** Python 3 + Flask + SQLite

---

## 1. Problem Statement

SecureShop's internal e-commerce application was reportedly built with
outdated components and insecure development practices. This engagement
determines how vulnerable the application is and validates whether
remediation actually closes the identified gaps, following the
Build → Attack → Identify → Fix → Retest methodology.

## 2. Application Overview

The application (`vulnerable_app/`) implements:

- **Public:** home, login, registration, product listing, product search,
  product details.
- **Authenticated:** user profile, order history, cart.
- **Administrative:** admin login (shared with normal login), product/user
  management (user listing).

Stack: Flask 2.0.1, Werkzeug 2.0.1, SQLite, server-rendered HTML
templates. Full source in `vulnerable_app/app.py`.

## 3. Outdated Component (A06)

| Field | Value |
|---|---|
| Component | Flask (and its bundled Werkzeug) |
| Version used | Flask 2.0.1 / Werkzeug 2.0.1 |
| Current version at time of writing | Flask 3.x |
| Advisory | CVE-2023-30861 — affects Flask < 2.3.2 / 2.2.5: under certain deployment configurations a response's `Set-Cookie` header (including the session cookie) can be cached by a shared/intermediary cache and replayed to other clients, leading to session data disclosure. |
| Why it's risky | The app never received 2+ years of subsequent security and bug-fix releases; relying on an unsupported minor version means known, patched issues remain exploitable. |
| Fix applied | Upgraded to Flask ≥ 3.0.3 / Werkzeug ≥ 3.0.3 in `fixed_app/requirements.txt`. |

## 4. Seeded Vulnerabilities (minimum 4 categories)

| # | OWASP Category | Location | Description |
|---|---|---|---|
| 1 | A03 Injection | `/login` | Username/password concatenated directly into SQL string; allows authentication bypass. |
| 2 | A03 Injection / XSS | `/search` | Search term concatenated into SQL `LIKE` clause and reflected into HTML unescaped. |
| 3 | A01 Broken Access Control | `/order/<id>` | No ownership check — any logged-in user can view any order by ID (IDOR). |
| 4 | A01 Broken Access Control | `/admin` | Checks only "is a user logged in", not "is this user an admin". |
| 5 | A05 Security Misconfiguration | app-wide | `DEBUG=True`, hardcoded Flask `secret_key`, default admin credentials, verbose SQL errors returned to the client. |
| 6 | A06 Vulnerable/Outdated Component | `requirements.txt` | See Section 3. |
| 7 | A07 Authentication Failure | `users` table / sessions | Plaintext password storage, no account lockout, session cookie missing `HttpOnly`/`SameSite` hardening. |
| 8 | A09 Logging/Monitoring Failure | `/login` | No logging of successful or failed login attempts anywhere in the app. |

(8 implemented — exceeds the assignment's minimum of 4 across different
categories.)

## 5. Phase 2 — OWASP ZAP Scan

> Fill in after running ZAP against your own running instance of
> `vulnerable_app` on `http://127.0.0.1:8080`. Attach the exported
> HTML/PDF report under `scan_results/before/`.

| Field | Value |
|---|---|
| Scan date | _[fill in]_ |
| Target URL | http://127.0.0.1:8080 |
| ZAP version | _[fill in, e.g. 2.15.0]_ |
| Scan type | Automated Scan (Spider + Active Scan) |
| Total alerts | _[fill in]_ |
| High severity | _[fill in]_ |
| Medium severity | _[fill in]_ |
| Low / Informational | _[fill in]_ |

### Alert summary table

| Alert | Risk | Affected URL(s) | Confidence |
|---|---|---|---|
| _e.g. SQL Injection_ | High | /login, /search | _[fill in]_ |
| _e.g. Cross Site Scripting (Reflected)_ | High | /search | _[fill in]_ |
| _e.g. Vulnerable JS/Lib or Outdated framework hints_ | Medium | / | _[fill in]_ |
| _..._ | | | |

## 6. Phase 3 — Finding Investigation

Repeat this block for each significant ZAP alert.

### Finding: _[name]_
- **What?** _[what ZAP flagged]_
- **Where?** _[URL / parameter / header / component]_
- **Why?** _[root cause in the code — reference the file/line, e.g. `app.py`, `login()`, string-built SQL query]_
- **Impact?** _[what an attacker could realistically achieve — e.g. authenticate as any user, exfiltrate the users table, read other customers' orders]_
- **Evidence?** _[ZAP request/response pair, screenshot, or a manual curl/browser repro — e.g. `curl -X POST -d "username=admin' -- &password=x" http://127.0.0.1:8080/login`]_

_(duplicate the block above for every finding you investigate)_

## 7. Manual Validation (safe, non-weaponized)

Example validations performed against the lab instance only:

- **SQLi auth bypass:** submitted `username=admin' -- `, any password, to
  `/login` → authenticated as `admin` without knowing the real password.
- **Reflected XSS:** requested `/search?q=<script>alert(1)</script>` →
  script tag reflected unescaped in the response body.
- **IDOR:** logged in as `alice`, requested `/order/2` (an order belonging
  to `bob`) → order details returned without an ownership check.
- **Broken access control:** logged in as non-admin `alice`, browsed
  directly to `/admin` → full user list (including admin flag) displayed.

_(record your own actual commands/screenshots here)_

## 8. Remediation

Implemented in `fixed_app/app.py`:

| Finding | Fix |
|---|---|
| SQL injection | Replaced all string-built queries with parameterized queries (`?` placeholders). |
| Reflected XSS | All user-controlled values passed through `markupsafe.escape()` before being embedded in HTML. |
| IDOR on orders | `/order/<id>` now checks `order.user_id == session.user_id` (or admin) before returning data, else `403`. |
| Broken access control on `/admin` | Added explicit `is_admin` session check; non-admins are redirected instead of shown admin data. |
| Plaintext passwords | Switched to `werkzeug.security.generate_password_hash` / `check_password_hash`. |
| Hardcoded secret key / debug mode | Secret key now random per run (or from env var); `DEBUG=False`. |
| Default admin credentials | Admin password now randomly generated at setup and never hardcoded. |
| Verbose error disclosure | Removed the raw-query/error echo path that existed in the vulnerable search handler. |
| Missing logging | Added a `security.log` with structured login success/failure/lockout and access-control-denial events. |
| Outdated dependency | Upgraded Flask/Werkzeug to current stable releases (see Section 3). |
| Session cookie hardening | Set `SESSION_COOKIE_HTTPONLY` and `SESSION_COOKIE_SAMESITE`. |
| No account lockout | Added a simple failed-attempt counter with temporary lockout per (IP, username). |

## 9. Phase 4 — Retest

> Fill in after running the same ZAP scan against `fixed_app` on
> `http://127.0.0.1:8081`. Attach the exported report under
> `scan_results/after/`.

| Field | Before | After |
|---|---|---|
| Scan date | _[fill in]_ | _[fill in]_ |
| Total alerts | _[fill in]_ | _[fill in]_ |
| High severity | _[fill in]_ | _[fill in]_ |
| Medium severity | _[fill in]_ | _[fill in]_ |
| Low / Informational | _[fill in]_ | _[fill in]_ |

### Verification of each fix

| Finding | Before | After | Verified how |
|---|---|---|---|
| SQLi auth bypass | Bypassed login as admin | Payload returns "Invalid credentials" | Repeated the same `admin' -- ` payload against :8081 |
| Reflected XSS | `<script>` reflected raw | `<script>` HTML-escaped | Repeated the same `/search?q=` payload |
| IDOR | Order of another user returned | `403 Forbidden` | Repeated `/order/2` as `alice` against :8081 |
| Broken access control | Non-admin reached `/admin` data | Redirected to login | Repeated `/admin` as `alice` against :8081 |
| Outdated component | Flask 2.0.1 | Flask ≥3.0.3 | `pip show flask` in the fixed_app venv |

## 10. Conclusion

_[summarize overall risk reduction, residual risk/limitations of the lab
(e.g. in-memory lockout resets on restart, no HTTPS in this local lab),
and recommendations for a production deployment.]_
