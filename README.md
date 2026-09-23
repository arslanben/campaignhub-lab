# CampaignHub — DOM XSS Lab

Single-host, Docker-based **fictional** lab that recreates a common
web bug-bounty class: a cross-origin **`postMessage` → DOM XSS** chain
against an HTML Builder, bypassing an F5-style Referer WAF, escalating
to **session riding**, then a related **stored XSS** via unsanitized
widget save. Company names, products, and data are synthetic.

> Flag values are visible in this repository; the point of the lab is the
> path, not the secret. If you publish a write-up, keep the process inside a
> spoiler section.

---

## Quick start

```bash
git clone <repo-url>
cd <repo-dir>
docker compose up -d --build
# or: make up
```

Requires **Docker + Compose only** to run the lab.  
Optional host tools for operators: `bash` + `curl` + `python3` (`make test`,
`make solve`). Players using a browser need neither.

| URL | Role |
|-----|------|
| http://localhost:8080 | Target panel (behind the WAF) |
| http://localhost:8000 | Attacker start page — incomplete PoC |

Ports are overridable via `.env` (copy from `.env.example`).

### Make targets

```bash
make up       # build and start
make ps       # service status
make logs     # follow logs
make test     # smoke tests
make solve    # reference solver (SPOILER)
make reset    # stop and clean up
make debug    # also publish panel:3000 for maintenance
```

### Accounts

| User | Password | Role |
|------|----------|------|
| `viewer` | `viewer123` | no campaigns/audit; **can** Save widgets |
| `admin` | `Admin!2024` | campaigns + audit |

---

## Target surface

| Path | Note |
|------|------|
| `GET /html-builder/` | no origin check on `postMessage`; `createContextualFragment` sink; frame-able |
| `POST /login` | sets HttpOnly `panel_sid` |
| `GET /panel/v2/user/status` | session probe (`{"result":false}` if anonymous) |
| `GET /panel/v2/campaigns` | admin only → flag2 (`export_token`) |
| `GET /panel/v2/audit/log` | admin only → flag3 (`integrity_token`) |
| `POST /panel/widget/save` | stores HTML **without sanitization** |
| `GET /panel/widget/preview?id=` | re-renders stored HTML (stored XSS) |
| WAF rules | Referer **origin** ≠ panel origin → 403 (incl. `localhost:8000`); no Referer → OK; non-browser UA on `/panel/*` → 403 |

**Stages**

1. **DOM XSS proof** — iframe + `referrerpolicy="no-referrer"` + crafted
   `NTM_HTML_BUILDER` message → `localStorage.campaignhub_app_key` (flag1)
2. **Session riding** — admin logged in, XSS calls
   `fetch('/panel/v2/campaigns', {credentials:'include'})` → flag2
3. **Stored XSS** — low-priv (`viewer`) saves payload, `admin` opens
   widget preview in a new tab → flag3  
   *(in the scenario write-up this save→render path was an unverified
   hypothesis; the lab makes it runnable)*

WAF: Referer **origin** must be the panel origin (`http://localhost:8080`).
Attacker origin `http://localhost:8000` → 403. No Referer
(`referrerpolicy="no-referrer"`) → allowed — that is the bypass.

CVSS reference (scenario template): **9.3**
(`AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N`)

---

## Hints and solution

Spoilers live in separate files — do not open them early.

- `HINTS.md` — progressive hint levels, each hidden behind a spoiler tag.
- `solve/WRITEUP.md` — full walkthrough with the payloads (**major spoiler**).
- `solve/solution_poc.html` — one-click browser exploit; while the lab is
  up also at `http://localhost:8000/solution_poc.html`.
- `solve/solve.py` — HTTP reference solver for CI / impatient operators.

**Impatient path:** start the lab, open
`http://localhost:8000/solution_poc.html`, click **Run all**.
Use `http://localhost` — not `127.0.0.1` (different site → cookies break).

---

## Architecture

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

```
browser → :8000 attacker ──postMessage──► :8080 waf → panel:3000
```

CI (`.github/workflows/lab-ci.yml`) builds the stack from scratch, waits
for `/healthz`, runs `tests/smoke.sh` and `solve/solve.py` on every push.

---

## Repository layout

```
.
├── docker-compose.yml          # panel + waf + attacker (+ healthcheck)
├── docker-compose.debug.yml    # optional: expose panel:3000
├── .env.example                # ports, flags, passwords
├── Makefile
├── HINTS.md                    # progressive spoilers
├── LICENSE                     # MIT
├── .github/workflows/lab-ci.yml
├── panel/                      # vulnerable CampaignHub
├── waf/                        # Referer + UA proxy
├── attacker/                   # start page; PoC copied in at image build
├── solve/
│   ├── WRITEUP.md              # SPOILER
│   ├── solution_poc.html       # SPOILER — single source for the PoC
│   └── solve.py                # SPOILER HTTP solver
├── tests/smoke.sh
└── docs/ARCHITECTURE.md
```

---

## Troubleshooting

- **Port busy** — set `WAF_PORT` / `ATTACKER_PORT` in `.env`, `docker compose up -d`.
- **403 on panel from curl** — WAF UA rule; add `-A "Mozilla/5.0"`.
- **403 when embedding with a normal iframe** — Referer is
  `http://localhost:8000` ≠ panel origin; set
  `referrerpolicy="no-referrer"`.
- **PoC finds 0 flags** — open via `http://localhost:...`, never `127.0.0.1`.
- **Builder shows nothing** — message needs `containerStyles`; check builder log pane.
- **Reset** — `make reset && make up`.

---

## License

MIT
