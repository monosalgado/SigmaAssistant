# Live demo runbook — Sigma Assistant

Prepared 2026-09-27 for the demo on 2026-09-28. Both URLs below were run **live** through the web
app on 2026-09-27 (pipeline frozen at `a6e9157`), fetching the pages from the internet.

---

## 30 minutes before

1. **Plug in the charger.** Turn **OpenVPN off**; connect the **USF VPN** (GlobalProtect).
2. Start the app from the project folder (it opens the SSH tunnel to the Spark by itself):
   ```
   .venv/bin/python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
   ```
   Wait for `Sigma Agent Initialized`. If it says the port is busy, an earlier server is still
   running — stop it first. If the tunnel fails, run `ssh-add --apple-load-keychain` and restart.
3. Open **http://127.0.0.1:8000**. (If the old look with emojis appears, reload once — the new files are
   versioned, so a normal reload is enough.)
4. **Warm-up run:** run the backup URL once before the audience arrives — the first call loads the
   model on the Spark and is slower.

---

## The demo (~10 minutes)

**+ New analysis → paste the URL → Generate rules.** While it runs, explain each step as it is ticked off.

| Stage on screen | What to say |
|---|---|
| Preprocessing | It reads the whole report (up to 100,000 characters), not a snippet. |
| PoC analysis | If the report links exploit code, it reads that too and lists what it would do on a machine. |
| Attack vector | *How does the attack start and where would you see it?* — entry point, attacker input, patterns, and strings that belong to the researcher, not the attacker (kept out of rules). |
| Analysis | Indicators, ATT&CK techniques, and the **recommended log source**, chosen from a table generated from SigmaHQ's own rules. |
| Review & Confirm | **What the LLM understood** about the attack — this is where the analyst checks it (see "Be honest about"). |
| Generation → Review | Rules written, then checked by pySigma; errors go back for a rewrite. |
| Coverage check | Do the rules cover the attack vector? One retry if not. |

**Then walk through the Analysis panel on the right** — *what the model understood; check it against
the report*: the attack vector (how it starts, entry point, what the attacker controls, where it would be
seen) and each pattern with the model's basis for it; strings excluded as researcher-only; the
recommended log source (highlighted) with its reasoning; ATT&CK techniques and why; indicators by type;
the checks (coverage gaps, pySigma). Say that the basis lines are the model's own words — the analyst
confirms them against the report; confirm/correct buttons are the next step.

### Main URL — SharePoint "ToolShell" (CVE-2025-53770), recent and real
`https://research.eye.security/sharepoint-under-siege/` — **177 s live**. Attack vector:
deserialization over HTTP (confidence 90%); log source `webserver`; 5 valid rules (initial access
via the authentication bypass, execution via the deserialization RCE, credential dumping,
malicious ASPX file, …). Point out: the first rule is `category: webserver` with **no invented
product** — exactly how SigmaHQ writes web rules (Phase 2's work).
**Talking point for human verification:** one rule looks for `ysoserial.exe` running — but
ysoserial is usually run on the *attacker's* machine to build the payload, so it would rarely show
up on the victim's server. This is why an analyst has to verify what the model understood.

### Backup URL — sudo CVE-2019-14287, fast and easy to follow
`https://www.openwall.com/lists/oss-security/2019/10/14/1` — **89 s live**. Local privilege
escalation; log source `process_creation / linux`; 3 valid rules on the `sudo -u#-1` trick
(negative / very large user id); no coverage gaps.
**Caution — live output varies between runs.** In 2 of 3 live runs on 2026-09-27 the analysis recommended
`process_creation / windows` for this *Linux* bug (once with a final rule on `\sudo.exe`). Use it on
purpose as the **verification example**: the Analysis panel shows "Log source: process_creation /
windows 95%" right under an attack vector about `sudo` — the analyst catches it at a glance.

### If the live run fails
The runs are saved as chats in the list: "https://research.eye.security/…" (SharePoint, correct), and
three "https://www.openwall.com/lists…" — the **lowest** is the correct run (Linux rules); the two above
it recommended Windows (verification examples). Opening a saved chat also fills the Analysis panel. Say
plainly it was run earlier.
(The "Empty Chat" entries from testing can be deleted.)

---

## The results slide (Phase 2, measured)

On **60 held-out cases no change was designed on** (drawn by committed code before any run):
- the first rule's log source matches the human SigmaHQ rule in **25 of 55 = 45%** — chance level
  is 17% (p = 1.2 × 10⁻⁶);
- baseline v2 on the same cases: 10 of 50 → final pipeline **21 of 50** (p = 0.013);
- ATT&CK (S4) and detection fields (S5) did **not** change yet — the next phase.

---

## Be honest about

- **The "Review & Confirm" panel is informational today**: it shows the model's understanding but
  the analyst cannot yet correct it in the interface (the backend accepts corrections; the UI does
  not send them). Next step: the analyst confirms or corrects what the LLM understood before the
  rules are trusted.
- A URL takes about 1.5–3 minutes; if an answer runs away it is cut and retried (up to ~6 min).
- Everything runs locally (the Spark); web search is off.
- The numbers compare against human SigmaHQ rules; they do not show the rules fire on a real attack.

## Troubleshooting

- **Hangs at a stage for minutes:** the Spark may be busy (it is shared) — switch to the backup URL
  or a saved chat.
- **"Connection refused" / LLM errors:** the VPN dropped — reconnect, restart the app.
- **A page fails to load:** some sites block automated fetches — use the other URL.
