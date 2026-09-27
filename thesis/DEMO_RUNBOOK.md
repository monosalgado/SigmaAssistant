# Live demo runbook — Sigma Assistant

Prepared 2026-09-27 for the demo on 2026-09-28. Both URLs below were run **live** through the web
app on 2026-09-27 (pipeline frozen at `a6e9157`), fetching the pages from the internet.

> **This is the `analyst-review` branch's version (Change 34):** the run stops after the analysis
> and the analyst confirms or corrects it before the rules are written. To demo it, the project
> folder must be on this branch (`git checkout analyst-review`) *before* starting the app; on `main`
> the app runs straight through (the runbook on `main` describes that). Tested live twice (sudo).

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

**+ New analysis → paste the URL → Analyse.** While it runs (about a minute), explain each step as it is ticked off.
It **stops after the analysis**: the Analysis panel shows what the model understood, with a button on
every item. Review it (below), then **Generate rules** at the bottom of the panel (about a minute).

| Stage on screen | What to say |
|---|---|
| Preprocessing | It reads the whole report (up to 100,000 characters), not a snippet. |
| PoC analysis | If the report links exploit code, it reads that too and lists what it would do on a machine. |
| Attack vector | *How does the attack start and where would you see it?* — entry point, attacker input, patterns, and strings that belong to the researcher, not the attacker (kept out of rules). |
| Analysis | Indicators, ATT&CK techniques, and the **recommended log source**, chosen from a table generated from SigmaHQ's own rules. |
| *(stops)* Your review | **What the LLM understood** — the analyst confirms, rejects, or changes the log source, *before* any rule is written. |
| Generation → Review | Rules written from the analysis as reviewed (no second analysis), then checked by pySigma; errors go back for one rewrite. |
| Coverage check | Do the rules cover the attack vector? If they miss it, **one** regeneration with the gaps as feedback (fixed 2026-09-27 — before, the web app said "regenerating" but never did: defect 20). Remaining gaps are listed in the panel. |

**The review, in the Analysis panel** — *what the model understood; check it against the report*: the
attack vector and each pattern with the model's basis (**Confirm / Reject**); strings excluded as
researcher-only (**Restore**); the log source — **Use this** on a suggestion, or **choose any of the 125
log sources in SigmaHQ's rules**; ATT&CK techniques (**Confirm / Reject**); indicators; a note to the
rule writer. The bar at the bottom counts the decisions. Say it plainly: **rejected items are not given
to the rule writer, a chosen log source is given as the analyst's decision, confirmations are
recorded.** The basis lines are the model's own words, not quotes. After **Generate rules**, the panel
opens with **"Your review"** — what was decided, next to the rules that came out.

### Main URL — SharePoint "ToolShell" (CVE-2025-53770), recent and real
`https://research.eye.security/sharepoint-under-siege/` — **177 s live**. Attack vector:
deserialization over HTTP (confidence 90%); log source `webserver`; 5 valid rules (initial access
via the authentication bypass, execution via the deserialization RCE, credential dumping,
malicious ASPX file, …). Point out: the first rule is `category: webserver` with **no invented
product** — exactly how SigmaHQ writes web rules (Phase 2's work).
**Talking point for human verification:** the model proposes `ysoserial.exe` as a pattern — but
ysoserial is usually run on the *attacker's* machine to build the payload, so it would rarely show
up on the victim's server. This is why an analyst has to verify what the model understood.
**With the review (tested live 2026-09-27: analysis 113 s, generation 134 s):**
1. Log source: `webserver` is the model's first suggestion and right — **Use this**.
2. Attack patterns: **Reject** `ysoserial.exe` (say why, as above). The same value is also an
   indicator — reject it there too; rejecting a pattern does not reject it elsewhere (known gap).
3. ATT&CK: **Reject** T1566.002 (spearphishing) and T1204.002 (user execution) — neither fits a
   server exploit; **Confirm** T1190.
4. **Generate rules.** In the live test the first attempt missed 4 of 7 patterns; the app said
   "regenerating" and did (defect 20 fixed) → 1 of 7 missed. The rules came out `webserver` (one
   `process_creation / windows` for the ASPX file), tagged T1190, none of the rejected techniques;
   ysoserial appeared only in a description ("used to generate ViewState payloads"), not in a detection.

### Backup URL — sudo CVE-2019-14287, fast and easy to follow
`https://www.openwall.com/lists/oss-security/2019/10/14/1` — **89 s live**. Local privilege
escalation; log source `process_creation / linux`; 3 valid rules on the `sudo -u#-1` trick
(negative / very large user id); no coverage gaps.
**This is the verification example.** In 4 of 5 live runs on 2026-09-27 the analysis recommended
`process_creation / windows` for this *Linux* bug. Tested twice with the review:
1. The panel shows `process_creation / windows 95%` under an attack vector about `sudo`.
2. Choose **`process_creation / linux`** in "Or choose another" (the model did not suggest it).
3. Reject **T1548.004** "Elevated Execution with Prompt" (a macOS technique) and any too-broad pattern
   (the model has proposed a bare `sudo` or `root`).
4. **Generate rules** → the rules came out `process_creation / linux`, tagged only the techniques kept.
If the model happens to suggest Linux this time, confirm it with **Use this** and say that in most runs today it did not.

### If the live run fails
The runs are saved as chats in the list: "https://research.eye.security/…" (SharePoint, correct), and
several "https://www.openwall.com/lists…" — the two **newest** (top) are the reviewed runs: the panel
opens with "Your review" (Linux chosen by the analyst). Opening a saved chat fills the Analysis panel. A
chat whose analysis is still waiting for review reopens with the buttons. Say plainly it was run earlier.
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

- **The review is new (built 2026-09-27) and not measured**: tested live twice on one case.
  Confirming an item is recorded but does not change what the rule writer gets; a rule that departs
  from the analyst's log source is not yet caught automatically (next step). What confirmation is
  worth will be measured with a simulated analyst (the gold answer as the analyst's choice).
- A URL takes about 1.5–3 minutes; if an answer runs away it is cut and retried (up to ~6 min).
- Everything runs locally (the Spark); web search is off.
- The numbers compare against human SigmaHQ rules; they do not show the rules fire on a real attack.

## Troubleshooting

- **Hangs at a stage for minutes:** the Spark may be busy (it is shared) — switch to the backup URL
  or a saved chat.
- **"Connection refused" / LLM errors:** the VPN dropped — reconnect, restart the app.
- **A page fails to load:** some sites block automated fetches — use the other URL.
