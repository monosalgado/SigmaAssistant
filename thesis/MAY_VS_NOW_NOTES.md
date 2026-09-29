# May vs now — the prompts, the inputs, the outputs (notes for the professor's question)

**Question (professor, 2026-09-28, via the user):** some rules shown in May were good; rules
generated later were wrong. Why? How was the prompt then, what went in and what came out, and how
different is it now? These are notes; the user writes the prose. Tags as in the chapter notes.
First answer: CH6 §6.0c, log 2026-09-28. This file adds the May reconstruction.

## 0. What survives from May, and what does not

- **The May code:** commit `2ec05f6` (2026-05-14). Its prompts are identical to `f457855` (same
  day), the first commit of the work done from mid-April. `7b80426` (2026-04-12) is the version
  before the attack-vector stage. Any version's prompts: `git show 2ec05f6:backend/pipeline/prompts.py`.
- **The saved chats:** `data/sessions.json` — local user data, not in git. **20 answers with rules
  are dated 20 March – 23 April; none is dated in May**, and the next is 13 September. So the
  rules shown in May were written by 23 April, or were never saved. A chat has no timestamp: each
  answer is dated by its rules' `date:` field, which the generation prompt fills with the current
  date (since `7271080`, 2026-03-20).
- **The library:** `data/saved_rules.json` — rules saved on 7, 15 and 16 April (CH6 §6.0c).
- **Not recorded:** which model wrote each April rule; which prompt text was in use between two
  commits (15 April – 14 May had no commit); the web-search results. No evaluation run exists
  before September, so May cannot be rescored. `[DISCLOSE]`
- **Tools (committed, tests first, each seen to fail):** `eval/prompt_history.py` (prompts of two
  versions side by side, read from git, never run); `eval/old_sessions.py` (the chats as runs:
  date, pipeline version, each rule's log source, whether the rule is complete, whether its log
  source is one SigmaHQ's rules use; `--find` for strings; `--results` counts a result file the
  same way). The chat counts can be re-run only on this laptop, where the chats file is.
  `[DISCLOSE]`

## 1. The pipeline in May and now `[MEASURED]` (code) / `[UNMEASURED]` (model per chat)

| Stage | May (`2ec05f6`) | Now (`main`) |
|---|---|---|
| Web enrichment | **On**: code builds a search query (CVE IDs + page titles); Gemini searches Google. April chats carry **0–16 extra web sources** each | **Off**: the Gemini key was deleted; a local model cannot search (`model-plan`) |
| PoC analysis | qwen3-coder:30b · `POC_CODE_ANALYSIS` 2,169 chars | same prompt, same model |
| Attack vector | qwen3-coder:30b · 10,776 chars · worked examples **from the demo reports** (§3) | 11,855 chars · examples invented, values as `<placeholders>` (Change 27); host activity described as host telemetry |
| Analysis | qwen3-coder:30b · 4,358 chars · a **hand-written 13-row log-source table** (`process_creation \| windows/sysmon`, `webserver \| linux-windows/apache-iis`…) | 4,280 chars + **SigmaHQ's full table in Sigma's two forms**, filled in at run time (Changes 25, 28, 29); at most 10 techniques |
| **Rule writing** | **Gemini 2.5 Flash** (cloud, a thinking model) · 6,145 chars · answer in JSON | **qwen3-coder:30b** (local) · 7,100 chars · + the recommended log source for the first rule (Change 26) · answer as YAML blocks (Change 36) · SigmaHQ tag style |
| Review | qwen3-coder:30b · `COMBINED_REVIEW` 3,300 chars | same prompt, same model |
| Code checks after the model | hand-written YAML checks, the LLM review, a retry on review errors | pySigma validation (since 2026-08-06, `a1c4f37`), ids that are not UUIDs replaced (Change 9), placeholder values and unknown ATT&CK ids caught (Changes 30–33), the coverage retry made to run (defect 20) |
| Analyst | none | optional review of the log source and items (Changes 34–35) |

- **Prompts `[MEASURED]`** (`prompt_history.py 2ec05f6 HEAD`): of the 8 prompts the pipeline uses
  now, **5 are unchanged since May**; 3 changed (attack vector, analysis, rule writing). The rule
  writer's prompt changed little: one input added (`first_rule_logsource`), the output format, the
  tag style, one line on `product:`. The large change came **before** May: from `7b80426` to
  `2ec05f6` it grew from 2,449 to 6,145 characters and from 8 to 17 inputs, and the
  attack-vector, analysis and review prompts were new.
- **So the prompt text is not the main difference.** Three things are: the model that writes the
  rules, the web search, and what fills the prompts' slots (the log-source table, the first-rule
  recommendation, fixed defects).
- **Model routing `[DESIGN]`:** from the May code (`economy=True` on PoC, attack vector, analysis
  and review; generation on the primary tier) and the startup banner recorded on 2026-08-06 (log,
  "Baseline established": primary `gemini-2.5-flash`, fast `gemini-2.0-flash`, economy
  `qwen3-coder:30b`). **Which model wrote each April rule is not recorded** `[UNMEASURED]`: from
  12 April one setting could also run everything locally. Every September run checked called
  qwen3-coder:30b and nothing else (`--results`: baseline v1 321 calls, baseline v2 323, held-out
  338 and 320, `c36_yaml60` 330). **No measured run has Gemini writing the rules.**

## 2. What came out in April — the saved chats `[MEASURED]` (`old_sessions.py --since 2026-03-20 --until 2026-06-01`)

| Pipeline version (told apart by the stage results saved) | Answers | Rules | Complete | Log source SigmaHQ's rules use |
|---|---|---|---|---|
| No stage results saved (before 12 April) | 4 | 10 | 10 | 4 |
| `f41d0a5` pipeline (12–15 April) | 5 | 18 | 16 | 3 |
| Attack-vector pipeline, `f457855` (16–23 April) | 11 | 28 | 28 | **0** |
| **All** | **20** | **56** | **54** | **7** |

"Complete" = a `detection` block holding a `condition`. "Log source SigmaHQ's rules use" =
`sigma_logsource.on_table`, the check behind Changes 28–29.

- **Log sources SigmaHQ's rules do not use:** 49 of 56 April rules. Examples:
  `webserver/citrix/netscaler`, `webserver/nginx/nginx`, `webserver/linux-windows/apache-iis`,
  `webserver_access_log/apache/web`, `proxy/generic`, `process_creation/windows/sysmon`. Some
  come straight from the analysis prompt's own hand-written table: `linux-windows` (its product
  cell for `webserver`, not a Sigma product) is in **13 of the 20 April answers** (`--find
  linux-windows`). A rule like that looks right to a reader but may match nothing in a SIEM.
- **The same measure now** (`old_sessions.py --results`; September runs, other reports):

  | Run | Rules | Log source SigmaHQ's rules use |
  |---|---|---|
  | baseline v1 (09-19) | 196 | 103 |
  | baseline v2 (09-24) | 249 | 147 |
  | held-out, baseline v2 code | 208 | 105 |
  | held-out, final pipeline | 204 | 188 |
  | `c36_yaml60` (= `main`) | 250 | 236 |

  The held-out pair is the fair comparison (the same 60 reports): **105 of 208 → 188 of 204**.
  April's reports differ from the corpus, so April vs September is only indicative.
- **Repeats — the same report, again and again (15–23 April):**

  | Report | Runs | Different first-rule log sources |
  |---|---|---|
  | BeyondTrust CVE-2026-1731 (AttackerKB) | 5 | **5** |
  | SolarWinds WHD CVE-2025-40551 (Horizon3) | 3 | 3 |
  | nginx-ui CVE-2026-33032 (BleepingComputer) | 4 | 3 |
  | Citrix NetScaler CVE-2026-3055 (watchTowr) | 2 | 2 |
  | Follina CVE-2022-30190 (AttackerKB) | 2 | 1, but 0 of 2 rules complete on 12 April |

  In April the repeats are not a clean variance measure: the code and the prompts were being
  edited between runs, and each run's web search found different sources (from 0 to 16 for the
  BeyondTrust runs). The clean measure is September's: frozen code and pages, 16 of 60 cases
  disagree (CH6 §6.0c).
- **Follina, good then wrong:** on 7 April, two complete `process_creation` rules for msdt.exe
  (the library's Follina rule). On 12 April, the same URL gave rules tagged T1548.003 (sudo
  caching), a `registry_key` category, the condition outside `detection` (not valid Sigma), and
  the summary stage wrote that the text "provides a URL" and names no attack — the page's text
  never reached the stages. `[UNMEASURED]` 12 April is the day the local-model switch was committed; which model ran
  is not recorded. `[UNMEASURED]` Follina (2022) is in any model's training data, so a good
  Follina rule may come from the model's memory rather than the page.

## 3. One report, five runs: BeyondTrust CVE-2026-1731 `[MEASURED]`

| Date | Pipeline | What the stages concluded | First rule |
|---|---|---|---|
| 15 Apr | `f41d0a5`, 0 web sources | "does not describe any attack behavior": the page's text never reached the stages (cause not recorded) | **Visits to the report page** (`cs-host|contains: attackerkb.com`) — the library's rule |
| 15 Apr | `f41d0a5`, 10 web sources | Page used; summary about decrypting the **vendor's patch** with a hard-coded password | **Six auditd rules on the researchers' own patch-diffing** (`openssl`, `tar`): research workflow taken for attacker activity |
| 16 Apr | attack vector, 13 web sources | WebSocket `/nw`, command injection in `remoteVersion`; the patch file and its password listed as "not part of the attack" | WebSocket rule on `webserver/beyondtrust_remote_support/websocket` |
| 22 Apr | attack vector, 16 web sources | the same, **in the May prompt's own words** | WebSocket handshake to `/nw` on `webserver/apache-iis` |
| 22 Apr | attack vector, 12 web sources | the same | `webserver_access_log/apache-iis/webserver` |

- **The May prompt's worked examples are these reports.** Example A: an unauthenticated POST to
  `/saml/login`, leaked memory in the `NSC_TASS` cookie — the Citrix vulnerability. Example B: a
  WebSocket command injection in `remoteVersion`, the vendor patch `BT26-02-RS.nss`, the patch
  password — the BeyondTrust report. `--find` with those strings: **7 of the 20 April answers
  contain them, all about these two vulnerabilities** (Citrix 3, from two watchTowr articles;
  BeyondTrust 4). The 15 April BeyondTrust chat already holds the password, and its pipeline had no
  attack-vector stage yet: the report came first, the example after.
- **Word for word:** the example's sentence "vendor patch filename used during patch-diffing, not
  part of attack" is in 2 answers, both on 22 April. So by then at the latest the attack-vector
  prompt held this report's answer, and the model repeated it.
- **What this means `[DISCLOSE]`:** the April/May prompts were improved by running them on these
  reports and writing each fix back into the prompt as an example. That is ordinary prompt
  engineering, but it tunes the prompt to its test reports: the rules for them improve, and the
  improvement is not evidence about new reports. On 60 other reports in September, text from these
  two examples appeared in the attack-vector record of **10 of 60**, and 16 of 48 first rules for
  non-web gold went to web log sources (log 2026-09-26, Change 27: examples replaced by placeholders
  → 7 of 60 and 8 of 45).

## 4. The answer, by evidence

1. **The prompt was tuned on the demo reports** `[MEASURED]` (§3): the good-looking rules of late
   April came from a prompt that held those reports' answers. New reports did not get that help,
   and the examples pulled them toward web exploits.
2. **The system changed** `[MEASURED]` code / `[UNMEASURED]` effect: the rule writer was Gemini
   2.5 Flash with Google search (up to 16 extra sources per run); now qwen3-coder:30b without web
   search. Their effect on rule quality is unmeasured.
3. **Defects present in April** `[MEASURED]`: the page's text not reaching the stages (rules on
   visits to the report page; cause not recorded — a page that yields no text, defect 9, is still
   open; URL misrouting, defect 8, was fixed in September); invalid rules (condition outside
   `detection`); log sources SigmaHQ's rules do not use (49 of 56 April rules; held-out 105/208 → 188/204 after
   Changes 25–29).
4. **One run is one sample** `[MEASURED]` (CH6 §6.0c): with nothing changed, 16 of 60 cases
   disagree. A good rule in a demo and a wrong one the next day can both come from the same code.
5. **Inputs differ** `[MEASURED]` (log 2026-09-27): the analysis is right for web reports far more
   often than for host or service ones. April's reports were almost all web exploits.

## 5. The rerun: the May code against today's, same model, same pages `[MEASURED]` (2026-09-29)

The May code (`2ec05f6`) through today's harness (`run_eval.py --code`) and `main` (`8f6a91c`), 3 runs each
on the 60 held-out reports; qwen3-coder:30b for every stage in both; web search off; plan fixed before the
runs (log 2026-09-28), results in the log 2026-09-29 and CH6 §6.0d (`eval/compare_arms.py`).
- **Log source right** (a rule that does not parse counts as wrong): May 0.072, now 0.439, **+0.367
  [+0.250, +0.489]**. **Detection-field F1:** 0.171 → 0.330, **+0.158 [+0.096, +0.222]**. First rule
  parses: 0.711 → 0.950.
- **Same log source in all 3 runs:** May 18 of 60, now 43 of 60 (p = 1.1e-05). The May code's runs part at
  the rule writer (32.3 of 60 per pair), today's in 13.3.
- **So:** with the model held fixed, the code and prompt changes since May make better and steadier rules on
  reports neither version was written from. On such reports the May code (with qwen) is below chance on
  the log source. The good May rules came from the reports its prompt was tuned on, possibly from Gemini
  (`[UNMEASURED]`), and from picking good runs out of unsteady ones.
- **Not measured:** the May system itself (Gemini, web search, the May index) — CH7 item 53. Tuning leakage
  measured directly would need a gold rule for each April report; none is in the corpus.

## Reproduce

```
.venv/bin/python eval/compare_arms.py --a eval/results/may_heldout_r{1,2,3}.jsonl --b eval/results/main_heldout_r{1,2,3}.jsonl --label-a May --label-b main
.venv/bin/python eval/prompt_history.py 2ec05f6 HEAD
.venv/bin/python eval/prompt_history.py 7b80426 2ec05f6
.venv/bin/python eval/prompt_history.py 2ec05f6 HEAD --diff ATTACK_VECTOR_EXTRACTION
.venv/bin/python eval/old_sessions.py --since 2026-03-20 --until 2026-06-01
.venv/bin/python eval/old_sessions.py --since 2026-03-20 --until 2026-06-01 --find Bingb0ng BT26-02 remoteVersion thin-scc-wrapper NSC_TASS /saml/login
.venv/bin/python eval/old_sessions.py --results eval/results/heldout_v2_60.jsonl eval/results/heldout_final60.jsonl
```
