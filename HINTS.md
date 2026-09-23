# CampaignHub DOM XSS Lab — progressive hints

Three stages. Each hint is behind a spoiler tag — open them one at a time.
If you are still stuck, `solve/WRITEUP.md` has the full walkthrough and
`solve/solution_poc.html` is the ready-made browser exploit.

---

## Stage 1 — builder listens to everyone

<details>
<summary>Spoiler</summary>

Open DevTools → Network or just read
`panel/www/html-builder/index.html`. The `message` handler accepts
`NTM_HTML_BUILDER` and never checks `event.origin`.

The page also sends no `X-Frame-Options` / CSP, so any site can iframe it.

</details>

<details>
<summary>Spoiler (deeper)</summary>

1. Embed `http://localhost:8080/html-builder/` in an iframe with
   `referrerpolicy="no-referrer"` (otherwise the WAF returns 403).
2. On `load`, `postMessage` a message shaped like:

```js
{
  type: 'NTM_HTML_BUILDER',
  view: {
    html: '<img src=x onerror="…">',
    containerStyles: { width: '300px' }   // required or the builder throws
  },
  widgetType: 'FLOATING_BAR',
  platform: 'WEB'
}
```

3. `view.html` is injected with `range.createContextualFragment` — your
   `onerror` runs as `http://localhost:8080`.
4. Read `localStorage.getItem('campaignhub_app_key')` → flag1.

</details>

---

## Stage 2 — the victim is already logged in

<details>
<summary>Spoiler</summary>

Log into the panel as `admin` in the **same** browser profile, then open the
attacker page (`http://localhost:8000`). The session cookie is HttpOnly —
you cannot read it with `document.cookie`. You do not need to.

From the XSS (panel origin), call:

```js
fetch('/panel/v2/campaigns', { credentials: 'include' })
```

The browser attaches the cookie. Response field `export_token` → flag2.

`viewer` gets 403 — you need the admin role.

</details>

---

## Stage 3 — stored XSS (low-priv writes, admin opens)

<details>
<summary>Spoiler</summary>

Builder **Save** → `POST /panel/widget/save` stores canvas HTML with no
sanitization. **`viewer` is enough to save.**

1. Log in as `viewer`, put the payload on the builder canvas, click Save.
2. Log in as `admin` in the same profile (preview needs the admin session
   to read `/panel/v2/audit/log`).
3. Open `http://localhost:8080/panel/widget/preview?id=…` in a **new tab**
   — not from the attacker page. The same `createContextualFragment` sink
   runs your payload on a plain panel visit.

Payload should fetch `/panel/v2/audit/log` with `credentials: 'include'`
→ `integrity_token` → flag3.

In the scenario notes this save→render path was a hypothesis that could
not be verified live; the lab makes it runnable on purpose.

</details>

---

## Stuck on the message shape?

<details>
<summary>Spoiler</summary>

Working template: `attacker/index.html` already builds the outer message —
only `view.html` is empty. Fill that string. `containerStyles` is already
present; do not remove it.

One-click full chain (spoiler): `http://localhost:8000/solution_poc.html`
(canonical file in the repo: `solve/solution_poc.html`).

</details>
