# Architecture and design notes

## Components

| Service | Image | Role |
|---|---|---|
| `waf` | Python 3.12 alpine | reverse proxy on host port `${WAF_PORT:-8080}`; F5 ASM-style Referer-origin + User-Agent rules; only panel-facing surface |
| `panel` | Python 3.12 alpine | CampaignHub SPA + HTML Builder + session APIs + widget store |
| `attacker` | Python 3.12 alpine | static start page with an incomplete `postMessage` PoC; also serves `solution_poc.html` (copied from `solve/` at image build) |

**Running the lab** needs only Docker + Compose. Everything (panel, WAF,
attacker) runs in containers — no host Python or Node for `docker compose up`.

**Host tooling** is optional and only for operators/CI:

| Command | Needs on the host |
|---------|-------------------|
| `make up` / `docker compose up` | Docker Compose |
| `make test` → `tests/smoke.sh` | `bash`, `curl`, `python3` (JSON checks) |
| `make solve` → `solve/solve.py` | `python3` |
| CI (`.github/workflows/lab-ci.yml`) | provided by `ubuntu-latest` |

Players who only open `localhost:8000` / `localhost:8080` in a browser
need neither host Python nor Node.

```
browser
  │
  ├─ http://localhost:8000 (ATTACKER_PORT) ──► attacker
  │         │ postMessage — no origin check
  │         ▼
  └─ http://localhost:8080 (WAF_PORT) ──► waf ──► panel:3000
                                    │
                                    ├─ Referer origin ≠ panel origin → 403
                                    │    (e.g. http://localhost:8000 blocked;
                                    │     no Referer → allowed = bypass)
                                    └─ non-browser UA on /panel/* → 403
```

Default ports are 8080 / 8000; override with `WAF_PORT` / `ATTACKER_PORT`
in `.env`. The WAF Referer allow-list uses the published `WAF_PORT`.

## Vulnerable surfaces (intentional)

| Location | Flaw |
|---|---|
| `panel/www/html-builder/index.html` `message` handler | no `event.origin` allow-list |
| same file, `applyView()` | `range.createContextualFragment(view.html)` executes markup/scripts |
| same page headers | no `X-Frame-Options`, no CSP (frame-able) |
| Builder **Save** → `POST /panel/widget/save` | HTML stored without sanitization (any authenticated role, including `viewer`) |
| `GET /panel/widget/preview` | re-injects stored HTML with the same sink (no role check on read — victim session is whatever cookie the browser sends) |

## Request path through the WAF

1. **Referer present and origin ≠ panel origin** →
   `403 Request Rejected (F5…)`.
   Same host is not enough: `http://localhost:8000` (attacker) ≠
   `http://localhost:${WAF_PORT:-8080}` (panel) → blocked.
   Bypass that matches the scenario: iframe
   `referrerpolicy="no-referrer"` (no Referer header → rule never fires).
2. **`/panel/*` without a browser User-Agent** → `403`.
   curl needs `-A "Mozilla/5.0"` (or use a real browser).

## Single source for the solution PoC

Canonical file: **`solve/solution_poc.html`**.

The attacker image build copies it in:

```dockerfile
# attacker/Dockerfile (build context = repo root)
COPY solve/solution_poc.html /site/solution_poc.html
```

There is no second editable copy under `attacker/`. Edit `solve/` only,
then `docker compose up -d --build attacker`.

## Session model

- `POST /login` sets `panel_sid` **HttpOnly; SameSite=Lax**.
- `document.cookie` cannot read it (by design).
- XSS running under the panel origin uses
  `fetch(..., { credentials: 'include' })`; the browser attaches the cookie.
- Roles: `viewer` (403 on campaigns/audit; **can** Save widgets),
  `admin` (full lab APIs including preview-time audit read).

## Flags

| Flag | Where it lives | Stage |
|---|---|---|
| `FLAG1` | `localStorage.campaignhub_app_key` (seeded in builder/dashboard HTML) | 1 — DOM XSS proof |
| `FLAG2` | `GET /panel/v2/campaigns` → `export_token` (admin session) | 2 — session riding |
| `FLAG3` | `GET /panel/v2/audit/log` → `integrity_token` (admin session) | 3 — stored XSS target |

Values come from compose environment (see `.env.example`). They are also
visible in this repository; the point of the lab is the path, not the secret.

## Health

`GET /healthz` on the panel returns `ok` — used by compose `healthcheck`
and CI wait loops. WAF only starts after `panel` is healthy.

## Scenario context

Fully **fictional** educational reconstruction of a production-style
notification/HTML-builder panel: cross-origin `postMessage` into a
builder with no origin check, WAF Referer rule bypassed via
`no-referrer`, credentialed API abuse, plus a related unsanitized
widget save path. In the scenario notes the save→render chain was a
code-derived hypothesis that could not be verified end-to-end; this lab
implements it so the low-priv → admin story is runnable. Company names,
products, and identifiers are synthetic — not affiliated with any real
vendor.
