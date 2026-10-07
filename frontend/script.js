document.addEventListener('DOMContentLoaded', () => {
    // --- XSS-safe rendering helpers ---
    // Sanitize any HTML before assigning to innerHTML. Content may originate
    // from the LLM, web enrichment, or user input, so it is never trusted.
    function safeHTML(html) {
        return DOMPurify.sanitize(html);
    }
    // Render untrusted markdown (LLM/user text) to sanitized HTML.
    function renderMarkdown(text) {
        return DOMPurify.sanitize(marked.parse(text || ""));
    }

    // --- Elements ---
    // Navigation
    const navChat = document.getElementById('nav-chat');
    const navLibrary = document.getElementById('nav-library');
    const viewChat = document.getElementById('view-chat');
    const viewLibrary = document.getElementById('view-library');
    const chatSidebar = document.getElementById('chat-sidebar-content');
    const librarySidebar = document.getElementById('library-sidebar-content');

    // Chat
    const chatHistory = document.getElementById('chat-history');
    const userInput = document.getElementById('user-input');
    const sendBtn = document.getElementById('send-btn');
    const newChatBtn = document.getElementById('new-chat-btn');
    const sessionList = document.getElementById('session-list');
    const fileInput = document.getElementById('file-input');
    const attachBtn = document.getElementById('attach-btn');
    const filePreview = document.getElementById('file-preview');
    const fileNameSpan = document.getElementById('file-name');
    const removeFileBtn = document.getElementById('remove-file');

    // Library
    const ruleList = document.getElementById('rule-list');
    const newRuleBtn = document.getElementById('new-rule-btn');
    const ruleEditor = document.getElementById('rule-editor');
    const editorTitle = document.getElementById('editor-title');
    const saveRuleBtn = document.getElementById('save-rule-btn');
    const downloadRuleBtn = document.getElementById('download-rule-btn');
    const deleteRuleBtn = document.getElementById('delete-rule-btn');
    const translateBtn = document.getElementById('translate-btn');
    const translationOutput = document.getElementById('translation-output');
    const targetLangSelect = document.getElementById('target-lang');

    // State
    let currentSessionId = null;
    let selectedFile = null;
    let currentRuleId = null;

    // --- Pipeline Stage Definitions ---
    // The analysis stops for the analyst's review; generation starts from it.
    const ANALYSIS_STAGES = [
        { id: 'classification', label: 'Intent Classification' },
        { id: 'preprocessing', label: 'Preprocessing' },
        { id: 'poc_analysis', label: 'PoC Analysis' },
        { id: 'web_enrichment', label: 'Web Enrichment' },
        { id: 'attack_vector', label: 'Attack Vector Extraction' },
        { id: 'analysis', label: 'Threat Analysis' },
    ];
    const GENERATION_STAGES = [
        { id: 'generation', label: 'Rule Generation' },
        { id: 'review', label: 'Validation & Optimization' },
        { id: 'coverage_check', label: 'Coverage Gap Check' },
        { id: 'analyst_check', label: 'Check Against Your Review' },
    ];

    // --- Navigation Logic ---
    function switchView(view) {
        if (view === 'chat') {
            viewChat.style.display = 'flex';
            viewLibrary.style.display = 'none';
            chatSidebar.style.display = 'flex';
            librarySidebar.style.display = 'none';
            navChat.classList.add('active');
            navLibrary.classList.remove('active');
        } else {
            viewChat.style.display = 'none';
            viewLibrary.style.display = 'grid';
            chatSidebar.style.display = 'none';
            librarySidebar.style.display = 'flex';
            navChat.classList.remove('active');
            navLibrary.classList.add('active');
            loadRules();
        }
    }

    navChat.addEventListener('click', () => switchView('chat'));
    navLibrary.addEventListener('click', () => switchView('library'));


    // --- File Logic ---
    if (attachBtn && fileInput) {
        attachBtn.addEventListener('click', () => fileInput.click());
    }

    if (fileInput) {
        fileInput.addEventListener('change', (e) => {
            if (e.target.files.length > 0) {
                selectedFile = e.target.files[0];
                if (fileNameSpan) fileNameSpan.innerText = selectedFile.name;
                if (filePreview) filePreview.style.display = 'flex';
            }
        });
    }

    if (removeFileBtn) {
        removeFileBtn.addEventListener('click', () => {
            selectedFile = null;
            fileInput.value = '';
            filePreview.style.display = 'none';
        });
    }

    // --- Session Logic (Chat) ---
    async function initChat() {
        await loadSessions();
        if (!currentSessionId) {
            const res = await fetch('/sessions');
            const sessions = await res.json();
            if (sessions.length > 0) {
                await switchSession(sessions[sessions.length - 1].id);
            } else {
                await createSession();
            }
        }
    }

    async function loadSessions() {
        try {
            const res = await fetch('/sessions');
            const data = await res.json();
            renderSessionList(data);
        } catch (e) {
            console.error("Failed to load sessions", e);
        }
    }

    function renderSessionList(sessions) {
        if (!sessionList) return;
        sessionList.innerHTML = '';
        sessions.slice().reverse().forEach(s => {
            const item = document.createElement('div');
            item.className = `session-item ${s.id === currentSessionId ? 'active' : ''}`;
            const infoDiv = document.createElement('div');
            infoDiv.className = 'session-info';
            infoDiv.innerHTML = safeHTML(`<div class="session-preview">${s.preview || 'New Chat'}</div>`);
            infoDiv.onclick = () => switchSession(s.id);

            const delBtn = document.createElement('button');
            delBtn.className = 'delete-session-btn';
            delBtn.innerHTML = '<svg class="icon" viewBox="0 0 24 24"><path d="M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13"/></svg>';
            delBtn.title = 'Delete';
            delBtn.onclick = (e) => {
                e.stopPropagation();
                deleteSession(s.id);
            };

            item.appendChild(infoDiv);
            item.appendChild(delBtn);
            sessionList.appendChild(item);
        });
    }

    async function createSession() {
        const res = await fetch('/sessions', { method: 'POST' });
        const data = await res.json();
        currentSessionId = data.id;
        chatHistory.innerHTML = '';
        await loadSessions();
        await switchSession(data.id);
    }

    async function deleteSession(id) {
        if (!confirm('Delete this chat?')) return;
        await fetch(`/sessions/${id}`, { method: 'DELETE' });
        if (currentSessionId === id) {
            currentSessionId = null;
            chatHistory.innerHTML = '';
        }
        await initChat();
    }

    async function switchSession(id) {
        currentSessionId = id;
        const res = await fetch(`/sessions/${id}`);
        const msgs = await res.json();
        chatHistory.innerHTML = '';

        const contextDiv = document.getElementById('context-content');
        if (contextDiv) contextDiv.innerHTML = '';

        let last = null;
        let lastAnalysis = null;
        msgs.forEach(m => {
            if (m.status) lastAnalysis = m;
            if (m.status && !m.content) return;   // Change 46: the saved analysis has no chat text of its own
            if (m.version) appendVersionLabel(m.version, m.corrections);
            appendMessage(m.role, m.content);
            if (m.role === 'assistant' && m.context && Object.keys(m.context).length > 0) last = m;
        });
        review = null;
        if (lastAnalysis && lastAnalysis.status === 'awaiting_review') {
            await startReview(lastAnalysis.analysis_id, lastAnalysis.context, lastAnalysis.pipeline_metadata);
        } else if (lastAnalysis && lastAnalysis.status === 'generated' && last && last.analysis_id === lastAnalysis.analysis_id) {
            await startReview(lastAnalysis.analysis_id, last.context,
                panelMeta(last.pipeline_metadata, lastAnalysis.pipeline_metadata), true);
        } else {
            if (last) renderContext(last.context, last.pipeline_metadata || null);
            updateReviewBar();
        }
        loadSessions();
    }

    // --- Library Logic ---
    async function loadRules() {
        try {
            const res = await fetch('/rules');
            const rules = await res.json();
            renderRuleList(rules);
        } catch (e) {
            console.error("Failed to load rules", e);
        }
    }

    function renderRuleList(rules) {
        ruleList.innerHTML = '';
        rules.slice().reverse().forEach(r => {
            const item = document.createElement('div');
            item.className = `session-item ${r.id === currentRuleId ? 'active' : ''}`;
            item.innerHTML = safeHTML(`<div class="session-info">${r.title}</div>`);
            item.onclick = () => loadRuleIntoEditor(r);
            ruleList.appendChild(item);
        });
    }

    // Change 47: a rule's YAML is checked as it is edited - pySigma and SigmaHQ's log sources, no model.
    // A short pause after typing, then POST /validate_rule; the rule itself is never changed.
    function renderCheck(panel, out) {
        panel.replaceChildren();
        if (!out) return;
        const n = (k, w) => `${out[k]} ${w}${out[k] === 1 ? '' : 's'}`;
        panel.appendChild(out.valid
            ? el('div', 'check-ok', out.warnings ? `Valid Sigma rule · ${n('warnings', 'warning')}` : 'Valid Sigma rule')
            : el('div', 'check-bad', `Not valid · ${n('errors', 'error')}` + (out.warnings ? ` · ${n('warnings', 'warning')}` : '')));
        (out.issues || []).forEach(i => panel.appendChild(el('div', `check-issue is-${i.severity}`, i.message)));
    }

    function liveCheck(textarea, panel) {
        let timer = null;
        let latest = 0;
        const run = async () => {
            const asked = ++latest;
            panel.classList.add('is-checking');
            try {
                const res = await fetch('/validate_rule', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ content: textarea.value })
                });
                const out = await res.json();
                if (asked === latest) renderCheck(panel, out);   // an older answer never replaces a newer one
            } catch (e) {
                if (asked === latest) { panel.replaceChildren(); panel.appendChild(el('div', 'check-bad', `Could not check: ${e.message}`)); }
            } finally {
                if (asked === latest) panel.classList.remove('is-checking');
            }
        };
        textarea.addEventListener('input', () => { clearTimeout(timer); timer = setTimeout(run, 400); });
        return run;
    }

    const ruleCheckPanel = document.getElementById('rule-check');
    const checkLibraryRule = ruleEditor && ruleCheckPanel ? liveCheck(ruleEditor, ruleCheckPanel) : () => {};

    // Every generated rule can be edited under it, checked as it is typed, and saved to the library.
    function openRuleEditor(anchor, yaml) {
        const next = anchor.nextElementSibling;
        if (next && next.classList.contains('rule-edit')) { next.remove(); return; }
        const box = el('div', 'rule-edit');
        const area = document.createElement('textarea');
        area.className = 'rule-edit-text';
        area.spellcheck = false;
        area.value = yaml;
        area.rows = Math.min(30, Math.max(8, yaml.split('\n').length + 1));
        const panel = el('div', 'rule-check');
        panel.setAttribute('aria-live', 'polite');
        const bar = el('div', 'rule-edit-actions');
        const save = el('button', 'mini-btn', 'Save to library');
        const dl = el('button', 'mini-btn', 'Download .yml');
        const close = el('button', 'mini-btn', 'Close');
        const saved = el('span', 'rule-edit-saved', '');
        save.onclick = async () => {
            const title = (area.value.match(/^title:\s*(.+)$/m) || [])[1];
            const res = await fetch('/rules', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ content: area.value, title: title ? title.trim() : 'Edited rule' })
            });
            const rule = await res.json();
            const c = rule.check || {};
            saved.textContent = c.valid === false ? `Saved - not valid (${c.errors} error${c.errors === 1 ? '' : 's'})` : 'Saved to the library';
            loadRules();
        };
        dl.onclick = () => triggerYmlDownload(area.value);
        close.onclick = () => box.remove();
        [save, dl, close].forEach(b => { b.type = 'button'; bar.appendChild(b); });
        bar.appendChild(saved);
        box.append(area, panel, bar);
        anchor.after(box);
        liveCheck(area, panel)();
        area.focus();
    }

    function loadRuleIntoEditor(rule) {
        currentRuleId = rule.id;
        editorTitle.innerText = rule.title;
        ruleEditor.value = rule.content;
        translationOutput.value = '';
        checkLibraryRule();

        Array.from(ruleList.children).forEach(child => {
            child.classList.remove('active');
            if (child.innerText === rule.title) child.classList.add('active');
        });
    }

    async function createNewRule() {
        const defaultContent = `title: New Rule
id: ${crypto.randomUUID()}
date: ${new Date().toISOString().split('T')[0]}
author: You
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: 'test.exe'
    condition: selection
level: medium`;

        const res = await fetch('/rules', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ content: defaultContent, title: "New Rule" })
        });
        const rule = await res.json();
        await loadRules();
        loadRuleIntoEditor(rule);
    }

    async function saveCurrentRule() {
        if (!currentRuleId) {
            const content = ruleEditor.value;
            if (!content) return;
            const res = await fetch('/rules', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ content: content })
            });
            const rule = await res.json();
            await loadRules();
            loadRuleIntoEditor(rule);
            alert("Created new rule!");
        } else {
            const content = ruleEditor.value;
            const res = await fetch(`/rules/${currentRuleId}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ content: content })
            });
            const saved = await res.json();
            await loadRules();
            const c = saved.check || {};
            alert(c.valid === false ? `Saved - but not a valid Sigma rule (${c.errors} error${c.errors === 1 ? '' : 's'}).` : "Saved!");
        }
    }

    async function deleteCurrentRule() {
        if (!currentRuleId) return;
        if (!confirm("Delete this rule?")) return;
        await fetch(`/rules/${currentRuleId}`, { method: 'DELETE' });
        currentRuleId = null;
        editorTitle.innerText = "Select a Rule";
        ruleEditor.value = "";
        translationOutput.value = "";
        renderCheck(ruleCheckPanel, null);
        await loadRules();
    }

    async function translateRule() {
        const content = ruleEditor.value;
        if (!content) return;
        const target = targetLangSelect.value;

        translationOutput.value = "Translating...";

        try {
            const res = await fetch('/translate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ rule: content, target: target })
            });

            if (res.ok) {
                const data = await res.json();
                let output = data.query || "No query generated";

                if (data.log_set) {
                    output += `\n\n/* Log Set: ${data.log_set} */`;
                }
                if (data.confidence) {
                    output += `\n/* Confidence: ${data.confidence} */`;
                }
                if (data.explanation) {
                    output += `\n\n/* ${data.explanation} */`;
                }
                if (data.warnings && data.warnings.length > 0) {
                    output += `\n\n/* Warnings:\n${data.warnings.map(w => '   - ' + w).join('\n')}\n*/`;
                }

                translationOutput.value = output;
            } else {
                const err = await res.json();
                translationOutput.value = `Error: ${err.detail}`;
            }
        } catch (e) {
            translationOutput.value = `Error: ${e.message}`;
        }
    }

    // Bind Library Buttons
    if (newRuleBtn) newRuleBtn.addEventListener('click', createNewRule);
    if (saveRuleBtn) saveRuleBtn.addEventListener('click', saveCurrentRule);
    if (deleteRuleBtn) deleteRuleBtn.addEventListener('click', deleteCurrentRule);
    if (translateBtn) translateBtn.addEventListener('click', translateRule);
    if (downloadRuleBtn) downloadRuleBtn.addEventListener('click', () => {
        const content = ruleEditor.value;
        if (!content) { alert('No rule content to download.'); return; }
        triggerYmlDownload(content);
    });

    // --- Message Logic ---
    function appendMessage(role, text) {
        const msgDiv = document.createElement('div');
        msgDiv.className = `message ${role}`;

        const avatar = document.createElement('div');
        avatar.className = 'avatar';
        avatar.innerText = role === 'user' ? 'U' : 'AI';

        const content = document.createElement('div');
        content.className = 'content';

        if (role === 'assistant' && (text.includes('```yaml') || text.includes('```'))) {
            content.innerHTML = renderMarkdown(text);

            // Extract all YAML blocks from the message
            const yamlBlocks = extractAllYamlBlocks(text);

            if (yamlBlocks.length > 1) {
                // Multiple rules: show per-rule save/download buttons
                const rulesActionsDiv = document.createElement('div');
                rulesActionsDiv.className = 'msg-actions rules-picker';

                const label = document.createElement('span');
                label.className = 'rules-picker-label';
                label.innerText = `${yamlBlocks.length} rules generated:`;
                rulesActionsDiv.appendChild(label);

                yamlBlocks.forEach((yaml, idx) => {
                    const titleMatch = yaml.match(/^title:\s*(.+)$/m);
                    const ruleTitle = titleMatch ? titleMatch[1].trim() : `Rule ${idx + 1}`;

                    const ruleRow = document.createElement('div');
                    ruleRow.className = 'rule-pick-row';

                    const ruleLabel = document.createElement('span');
                    ruleLabel.className = 'rule-pick-name';
                    ruleLabel.innerText = ruleTitle;
                    ruleLabel.title = ruleTitle;   // the whole title on hover when the row shortens it
                    ruleRow.appendChild(ruleLabel);

                    const saveBtn = document.createElement('button');
                    saveBtn.innerText = 'Save';
                    saveBtn.className = 'mini-btn';
                    saveBtn.onclick = () => saveOneRule(yaml);
                    ruleRow.appendChild(saveBtn);

                    const dlBtn = document.createElement('button');
                    dlBtn.innerText = 'Download';
                    dlBtn.className = 'mini-btn';
                    dlBtn.onclick = () => triggerYmlDownload(yaml);
                    ruleRow.appendChild(dlBtn);

                    const editBtn = document.createElement('button');
                    editBtn.innerText = 'Edit';
                    editBtn.className = 'mini-btn';
                    editBtn.onclick = () => openRuleEditor(ruleRow, yaml);
                    ruleRow.appendChild(editBtn);

                    rulesActionsDiv.appendChild(ruleRow);
                });

                // Also add a "Save All" button
                const saveAllBtn = document.createElement('button');
                saveAllBtn.innerText = 'Save All to Library';
                saveAllBtn.className = 'mini-btn save-all-btn';
                saveAllBtn.onclick = () => saveAllRules(yamlBlocks);
                rulesActionsDiv.appendChild(saveAllBtn);

                content.appendChild(rulesActionsDiv);
            } else {
                // Single rule: simple save/download buttons
                const actionsDiv = document.createElement('div');
                actionsDiv.className = 'msg-actions';
                const saveBtn = document.createElement('button');
                saveBtn.innerText = 'Save to Library';
                saveBtn.className = 'mini-btn';
                saveBtn.onclick = () => saveRuleFromChat(text);
                actionsDiv.appendChild(saveBtn);

                const downloadBtn = document.createElement('button');
                downloadBtn.innerText = 'Download .yml';
                downloadBtn.className = 'mini-btn';
                downloadBtn.onclick = () => downloadRuleAsYml(text);
                actionsDiv.appendChild(downloadBtn);
                if (yamlBlocks.length === 1) {
                    const editBtn = document.createElement('button');
                    editBtn.innerText = 'Edit';
                    editBtn.className = 'mini-btn';
                    editBtn.onclick = () => openRuleEditor(actionsDiv, yamlBlocks[0]);
                    actionsDiv.appendChild(editBtn);
                }
                content.appendChild(actionsDiv);
            }

        } else {
            content.innerHTML = renderMarkdown(text);
        }

        if (role === 'user') {
            msgDiv.appendChild(content);
            msgDiv.appendChild(avatar);
        } else {
            msgDiv.appendChild(avatar);
            msgDiv.appendChild(content);
        }

        chatHistory.appendChild(msgDiv);
        chatHistory.scrollTop = chatHistory.scrollHeight;
    }

    function extractAllYamlBlocks(text) {
        const regex = /```yaml\n([\s\S]*?)\n```/g;
        const blocks = [];
        let m;
        while ((m = regex.exec(text)) !== null) {
            blocks.push(m[1]);
        }
        return blocks;
    }

    function downloadRuleAsYml(text) {
        const match = text.match(/```yaml\n([\s\S]*?)\n```/);
        if (match && match[1]) {
            triggerYmlDownload(match[1]);
        } else {
            alert("No valid YAML rule found in this message.");
        }
    }

    function triggerYmlDownload(yamlContent) {
        const titleMatch = yamlContent.match(/^title:\s*(.+)$/m);
        let filename = 'sigma_rule.yml';
        if (titleMatch && titleMatch[1]) {
            filename = titleMatch[1].trim()
                .toLowerCase()
                .replace(/[^a-z0-9]+/g, '_')
                .replace(/^_|_$/g, '') + '.yml';
        }

        const blob = new Blob([yamlContent], { type: 'application/x-yaml' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    async function saveRuleFromChat(text) {
        const match = text.match(/```yaml\n([\s\S]*?)\n```/);
        if (match && match[1]) {
            await saveOneRule(match[1]);
        } else {
            alert("No valid YAML rule found in this message.");
        }
    }

    async function saveOneRule(yamlContent) {
        const res = await fetch('/rules', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ content: yamlContent })
        });
        const rule = await res.json();
        const titleMatch = yamlContent.match(/^title:\s*(.+)$/m);
        const name = titleMatch ? titleMatch[1].trim() : 'Rule';
        if (confirm(`"${name}" saved! Switch to library to view it?`)) {
            switchView('library');
            await loadRules();
            loadRuleIntoEditor(rule);
        }
    }

    async function saveAllRules(yamlBlocks) {
        let savedCount = 0;
        let lastRule = null;
        for (const yaml of yamlBlocks) {
            try {
                const res = await fetch('/rules', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ content: yaml })
                });
                lastRule = await res.json();
                savedCount++;
            } catch (e) {
                console.error('Failed to save rule:', e);
            }
        }
        if (confirm(`${savedCount} rule(s) saved to library! Switch to library?`)) {
            switchView('library');
            await loadRules();
            if (lastRule) loadRuleIntoEditor(lastRule);
        }
    }

    // --- Pipeline Progress UI ---
    function createPipelineProgress(stages) {
        const wrapper = document.createElement('div');
        wrapper.className = 'message assistant';

        const avatar = document.createElement('div');
        avatar.className = 'avatar';
        avatar.innerText = 'AI';

        const content = document.createElement('div');
        content.className = 'content';

        const progressDiv = document.createElement('div');
        progressDiv.className = 'pipeline-progress';
        progressDiv.id = 'pipeline-progress';

        stages.forEach(stage => {
            const stageDiv = document.createElement('div');
            stageDiv.className = 'pipeline-stage pending';
            stageDiv.id = `stage-${stage.id}`;
            stageDiv.innerHTML = `
                <div class="stage-icon"></div>
                <span class="stage-label">${stage.label}</span>
                <span class="stage-detail"></span>
            `;
            progressDiv.appendChild(stageDiv);
        });

        content.appendChild(progressDiv);
        wrapper.appendChild(avatar);
        wrapper.appendChild(content);
        return wrapper;
    }

    function updatePipelineStage(stageId, status, detail) {
        const stageDiv = document.getElementById(`stage-${stageId}`);
        if (!stageDiv) return;

        stageDiv.className = `pipeline-stage ${status}`;
        const icon = stageDiv.querySelector('.stage-icon');
        const detailSpan = stageDiv.querySelector('.stage-detail');

        if (status === 'complete') {
            icon.innerHTML = '&#10003;';
        } else if (status === 'running') {
            icon.innerHTML = '';
        } else if (status === 'error') {
            icon.innerHTML = '&#10007;';
        }

        if (detail) {
            detailSpan.textContent = detail;
        }

        // Auto-scroll
        chatHistory.scrollTop = chatHistory.scrollHeight;
    }

    // --- handleSend with SSE Streaming ---
    async function handleSend() {
        const text = userInput.value.trim();
        if (!text && !selectedFile) return;

        let userDisplay = text;
        if (selectedFile) userDisplay += `\n[Attached: ${selectedFile.name}]`;

        appendMessage('user', userDisplay);
        userInput.value = '';
        if (selectedFile) filePreview.style.display = 'none';

        // For multimodal, fall back to non-streaming endpoint
        if (selectedFile) {
            const loadingDiv = document.createElement('div');
            loadingDiv.className = 'message assistant loading';
            loadingDiv.innerHTML = '<div class="avatar">AI</div><div class="content">Analysing... </div>';
            chatHistory.appendChild(loadingDiv);

            try {
                const formData = new FormData();
                formData.append('description', text || "Analyze this file");
                formData.append('session_id', currentSessionId);
                formData.append('file', selectedFile);
                const response = await fetch('/analyze_multimodal', { method: 'POST', body: formData });
                selectedFile = null;
                if (fileInput) fileInput.value = '';

                const data = await response.json();
                chatHistory.removeChild(loadingDiv);

                if (data.rule) {
                    appendMessage('assistant', data.rule);
                    if (data.context) renderContext(data.context, data.pipeline_metadata);
                    loadSessions();
                } else {
                    appendMessage('assistant', "I encountered an error analyzing that.");
                }
            } catch (error) {
                chatHistory.removeChild(loadingDiv);
                appendMessage('assistant', `Error: ${error.message}`);
            }
            return;
        }

        // Use SSE streaming for text-only requests. Change 46: the pipeline runs to the rules; the analyst's
        // corrections come after, from the saved analysis.
        const pipelineDiv = createPipelineProgress(ANALYSIS_STAGES.concat(GENERATION_STAGES));
        chatHistory.appendChild(pipelineDiv);
        chatHistory.scrollTop = chatHistory.scrollHeight;

        try {
            const response = await fetch('/analyze_stream', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ description: text, session_id: currentSessionId })
            });

            await readSSE(response, async (event, data) => {
                if (event === 'stage') {
                    updatePipelineStage(data.stage, data.status, data.detail);
                } else if (event === 'review') {
                    pipelineDiv.remove();
                    appendMessage('assistant', data.content);
                    if (data.session_id) currentSessionId = data.session_id;
                    await startReview(data.analysis_id, data.context, data.pipeline_metadata);
                    loadSessions();
                } else if (event === 'result') {
                    pipelineDiv.remove();
                    if (data.session_id) currentSessionId = data.session_id;
                    if (data.analysis_id) {
                        // Version 1, then the corrections against the saved analysis
                        appendVersionLabel(data.version, data.corrections);
                        appendMessage('assistant', data.rule || 'No rules were generated.');
                        await startReview(data.analysis_id, data.context,
                            panelMeta(data.pipeline_metadata, data.analysis_metadata), true);
                        loadSessions();
                    } else if (data.retry_analysis_id) {
                        // The analysis was saved but generation failed: it can be generated from again
                        appendMessage('assistant', data.rule);
                        await switchSession(currentSessionId);
                    } else if (data.rule) {
                        appendMessage('assistant', data.rule);
                        if (data.context) renderContext(data.context, data.pipeline_metadata);
                        loadSessions();
                    } else {
                        appendMessage('assistant', "I encountered an error analyzing that.");
                    }
                }
            });
        } catch (error) {
            // Remove pipeline progress on error
            if (pipelineDiv.parentNode) pipelineDiv.remove();
            appendMessage('assistant', `Error: ${error.message}`);
        }
    }

    // Read a Server-Sent Events response; events are separated by a blank line and may
    // arrive split across chunks.
    async function readSSE(response, onEvent) {
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = '';
        while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            buffer += decoder.decode(value, { stream: true });
            const parts = buffer.split('\n\n');
            buffer = parts.pop();
            for (const part of parts) {
                let event = 'message';
                let data = '';
                part.split('\n').forEach(line => {
                    if (line.startsWith('event: ')) event = line.substring(7).trim();
                    else if (line.startsWith('data: ')) data += line.substring(6);
                });
                if (!data) continue;
                let parsed;
                try {
                    parsed = JSON.parse(data);
                } catch (parseErr) {
                    console.error('SSE parse error:', parseErr);
                    continue;
                }
                await onEvent(event, parsed);
            }
        }
    }

    // --- The analyst's review: confirm or correct what the model understood ---
    // Decisions refer to the saved analysis by position. Rejected items are not given to
    // the rule writer; a chosen log source is given as the analyst's decision; confirmations
    // are recorded. Untouched items stay the model's suggestions.
    let review = null;
    let logsourceChoices = null;
    const DECIDE = [['confirmed', 'Confirm'], ['rejected', 'Reject']];
    const RESTORE = [['restored', 'Restore']];
    const KIND_LABELS = { patterns: 'Patterns', excluded: 'Excluded strings', techniques: 'Techniques', indicators: 'Indicators' };
    const STATUS_LABELS = { confirmed: 'confirmed', rejected: 'rejected', restored: 'restored', linked: 'rejected as copies' };
    // One decision per string: a rejected pattern or indicator takes its copies in the other list
    // with it, matched exactly (case and spacing aside) - the backend applies the same rule.
    const LINKED = ['patterns', 'indicators'];

    async function loadLogsourceChoices() {
        if (logsourceChoices) return logsourceChoices;
        try {
            const res = await fetch('/logsource_choices');
            logsourceChoices = await res.json();
        } catch (e) {
            console.error('Failed to load log sources', e);
            return [];
        }
        return logsourceChoices;
    }

    // Change 46: a version's panel shows the saved analysis's items (what the corrections refer to by position)
    // and that version's own record of the corrections and their check.
    const ANALYSIS_FIELDS = ['indicators', 'ttp_mappings', 'attack_vector', 'logsource_suggestions', 'logsource_primary',
        'suggested_log_sources'];

    function panelMeta(versionMeta, analysisMeta) {
        const out = Object.assign({}, versionMeta || {});
        ANALYSIS_FIELDS.forEach(f => { if (analysisMeta && f in analysisMeta) out[f] = analysisMeta[f]; });
        return out;
    }

    function appendVersionLabel(version, corrections) {
        if (!version) return;
        const label = el('div', 'version-label',
            version === 1 && !corrections ? 'Version 1 · automatic'
                : `Version ${version} · ${corrections ? 'with your corrections: ' + corrections : 'automatic'}`);
        chatHistory.appendChild(label);
    }

    async function startReview(analysisId, context, meta, after = false) {
        await loadLogsourceChoices();
        review = {
            analysisId, after, techniques: {}, indicators: {}, patterns: {}, excluded: {}, logsource: null, note: '',
            values: {
                patterns: ((meta && meta.attack_vector && meta.attack_vector.payload_signatures) || []).map(p => p.pattern),
                indicators: ((meta && meta.indicators) || []).map(i => i.value),
            },
        };
        renderContext(context, meta);
        updateReviewBar();
    }

    // Same rule as the backend: trimmed, lower case, placeholders absent.
    function clean(v) {
        const t = v === undefined || v === null ? '' : String(v).trim().toLowerCase();
        return ['', '-', 'none', 'n/a', 'null'].includes(t) ? null : t;
    }

    function asSource(ls) {
        return { category: clean(ls.category), product: clean(ls.product), service: clean(ls.service) };
    }

    function sameSource(a, b) {
        return !!a && !!b && ['category', 'product', 'service'].every(f => clean(a[f]) === clean(b[f]));
    }

    function onTable(ls) {
        return (logsourceChoices || []).some(c => sameSource(c, ls));
    }

    function sameString(v) {
        return String(v === undefined || v === null ? '' : v).split(/\s+/).filter(Boolean).join(' ').toLowerCase();
    }

    function rejectedStrings() {
        const out = new Set();
        LINKED.forEach(kind => Object.entries(review[kind]).forEach(([i, status]) => {
            if (status === 'rejected') out.add(sameString(review.values[kind][i]));
        }));
        out.delete('');
        return out;
    }

    function decisionButtons(item, kind, index, statuses, value) {
        item.dataset.kind = kind;
        item.dataset.index = String(index);
        if (LINKED.includes(kind)) item.dataset.link = sameString(value);
        const bar = el('div', 'an-actions');
        statuses.forEach(([status, label]) => {
            const b = el('button', 'an-act', label);
            b.type = 'button';
            b.dataset.status = status;
            b.onclick = () => {
                if (review[kind][index] === status) {
                    delete review[kind][index];
                } else {
                    review[kind][index] = status;
                    // A confirmed copy of a string rejected now goes with it.
                    if (status === 'rejected' && item.dataset.link) {
                        LINKED.forEach(k => Object.keys(review[k]).forEach(i => {
                            if (review[k][i] === 'confirmed' && sameString(review.values[k][i]) === item.dataset.link) delete review[k][i];
                        }));
                    }
                }
                paintDecisions();
                updateReviewBar();
            };
            bar.appendChild(b);
        });
        if (item.dataset.link !== undefined) {
            const note = el('span', 'an-linked-note', 'rejected with its copy in the other list');
            note.hidden = true;
            bar.appendChild(note);
        }
        return bar;
    }

    function paintDecisions() {
        if (!review) return;
        const rejected = rejectedStrings();
        document.querySelectorAll('#context-content .an-item[data-kind]').forEach(item => {
            const own = review[item.dataset.kind][item.dataset.index];
            const linked = !own && item.dataset.link !== undefined && rejected.has(item.dataset.link);
            const status = own || (linked ? 'rejected' : null);
            item.classList.remove('is-confirmed', 'is-rejected', 'is-restored');
            if (status) item.classList.add(`is-${status}`);
            item.classList.toggle('is-linked', linked);
            item.querySelectorAll('.an-act').forEach(b => {
                const on = b.dataset.status === status;
                b.classList.toggle('on', on);
                b.setAttribute('aria-pressed', on ? 'true' : 'false');
                b.disabled = linked;
            });
            const note = item.querySelector('.an-linked-note');
            if (note) note.hidden = !linked;
        });
    }

    function paintLogsource(section) {
        section.querySelectorAll('[data-ls-index]').forEach(item => {
            const chosen = sameSource(review.logsource, item.logsource);
            item.classList.toggle('is-chosen', chosen);
            const b = item.querySelector('.an-act');
            if (b) {
                b.classList.toggle('on', chosen);
                b.setAttribute('aria-pressed', chosen ? 'true' : 'false');
                b.textContent = chosen ? 'Chosen' : 'Use this';
            }
        });
        const select = section.querySelector('.an-select');
        if (select) {
            const i = (logsourceChoices || []).findIndex(c => sameSource(c, review.logsource));
            select.value = i >= 0 ? String(i) : '';
        }
        updateReviewBar();
    }

    function buildReview() {
        const out = {};
        ['techniques', 'indicators', 'patterns', 'excluded'].forEach(kind => {
            if (Object.keys(review[kind]).length) out[kind] = review[kind];
        });
        if (review.logsource) out.logsource = review.logsource;
        if (review.note.trim()) out.note = review.note.trim();
        return out;
    }

    function updateReviewBar() {
        const bar = document.getElementById('review-bar');
        if (!bar) return;
        bar.hidden = !review;
        if (!review) return;
        const counts = { confirmed: 0, rejected: 0, restored: 0 };
        ['techniques', 'indicators', 'patterns', 'excluded'].forEach(kind =>
            Object.values(review[kind]).forEach(status => { counts[status] += 1; }));
        const parts = Object.entries(counts).filter(([, n]) => n).map(([status, n]) => `${n} ${status}`);
        const copies = document.querySelectorAll('#context-content .an-item.is-linked').length;
        if (copies) parts.push(`${copies} cop${copies === 1 ? 'y' : 'ies'} rejected with them`);
        parts.push(review.logsource ? `log source: ${logsourceName(review.logsource)}` : "log source: the model's suggestion");
        document.getElementById('review-summary').textContent = parts.join(' · ');
        const btn = document.getElementById('generate-btn');
        btn.textContent = review.after ? 'Regenerate with my corrections' : 'Generate rules';
        btn.disabled = false;
    }

    async function generateFromReview() {
        if (!review) return;
        const btn = document.getElementById('generate-btn');
        btn.disabled = true;
        const progress = createPipelineProgress(GENERATION_STAGES);
        chatHistory.appendChild(progress);
        chatHistory.scrollTop = chatHistory.scrollHeight;
        try {
            const response = await fetch('/generate_stream', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ session_id: currentSessionId, analysis_id: review.analysisId, review: buildReview() })
            });
            if (!response.ok) {
                const err = await response.json().catch(() => ({}));
                progress.remove();
                appendMessage('assistant', `The rules were not generated: ${err.detail || response.status}`);
                btn.disabled = false;
                return;
            }
            await readSSE(response, (event, data) => {
                if (event === 'stage') {
                    updatePipelineStage(data.stage, data.status, data.detail);
                } else if (event === 'result') {
                    progress.remove();
                    if (data.retry_analysis_id) {   // the analysis is kept; the review stays open
                        appendMessage('assistant', data.rule || 'No rules were generated.');
                        return;
                    }
                    appendVersionLabel(data.version, data.corrections);
                    appendMessage('assistant', data.rule || 'No rules were generated.');
                    // Change 46: every version is kept; the analyst can correct again, from the saved analysis
                    startReview(review.analysisId, data.context, panelMeta(data.pipeline_metadata, data.analysis_metadata), true);
                    loadSessions();
                }
            });
        } catch (error) {
            if (progress.parentNode) progress.remove();
            appendMessage('assistant', `Error: ${error.message}`);
        }
        if (review) btn.disabled = false;
    }

    // --- Analysis panel: what the model understood, evidence first ---
    // With a review open, each item carries the analyst's controls.
    // Built with text nodes only, so nothing the model writes is interpreted as HTML.
    function el(tag, className, text) {
        const node = document.createElement(tag);
        if (className) node.className = className;
        if (text !== undefined && text !== null && text !== '') node.textContent = String(text);
        return node;
    }

    function add(parent, ...nodes) {
        nodes.forEach(n => { if (n) parent.appendChild(n); });
    }

    function panelSection(title, meta, open) {
        const details = el('details', 'an-section');
        details.open = !!open;
        const summary = el('summary', 'an-summary');
        add(summary, el('span', 'an-title', title), meta ? el('span', 'an-meta', meta) : null);
        const body = el('div', 'an-body');
        add(details, summary, body);
        return { details, body };
    }

    function kv(label, value, mono) {
        if (!value) return null;
        const row = el('div', 'an-kv');
        add(row, el('span', 'an-k', label), el('span', mono ? 'an-v mono' : 'an-v', value));
        return row;
    }

    function basis(text) {
        return text ? el('div', 'an-basis', text) : null;
    }

    function pct(x) {
        return typeof x === 'number' ? `${Math.round(x * 100)}%` : '';
    }

    function logsourceName(ls) {
        const absent = ['', '-', 'none', 'null', 'n/a'];
        return ['category', 'product', 'service']
            .map(f => ls[f])
            .filter(v => v && !absent.includes(String(v).trim().toLowerCase()))
            .join(' / ') || '?';
    }

    function renderContext(context, meta) {
        const root = document.getElementById('context-content');
        if (!root) return;
        root.innerHTML = '';
        context = context || {};
        meta = meta || {};
        const av = meta.attack_vector || {};

        if (review && review.after) {
            root.appendChild(el('p', 'an-review-intro',
                'The rules were written from what the pipeline understood, shown below. If something is wrong, ' +
                'correct it - reject what is wrong, restore a string that was wrongly excluded, change the log ' +
                'source - and regenerate. Only the rules are written again; the analysis stays. Every version is kept.'));
        } else if (review) {
            root.appendChild(el('p', 'an-review-intro',
                'Confirm what is right, reject what is wrong, and change the log source if needed - then ' +
                'generate. Rejected items are not given to the rule writer; a log source you choose is given as ' +
                'your decision. Confirmations are recorded. Untouched items stay the model\'s suggestions.'));
        }

        // 0. The analyst's review, as applied before these rules were written
        const rec = meta.analyst_review;
        if (rec) {
            const s = review && review.after
                ? panelSection('Your corrections', 'applied to the latest version', true)
                : panelSection('Your review', 'applied before the rules were written', true);
            if (rec.logsource) {
                const rank = rec.logsource.suggested_rank;
                add(s.body, kv('Log source', `${logsourceName(rec.logsource)} - ${rank ? `the model's suggestion #${rank}` : 'your choice'}`));
            }
            Object.entries(KIND_LABELS).forEach(([kind, label]) => {
                Object.entries(rec[kind] || {}).forEach(([status, items]) => {
                    if (items.length) add(s.body, kv(`${label} ${STATUS_LABELS[status] || status}`, items.join(', '), true));
                });
            });
            if (rec.note) add(s.body, kv('Your note', rec.note));
            // The rules checked against the review by code (design P4)
            const chk = meta.analyst_check;
            if (chk) {
                const line = d => `Rule ${d.rule} "${d.title}": ${d.message}`;
                const deps = chk.departures || [];
                const flagged = chk.flagged || [];
                if (chk.rewrite_failed) {
                    deps.forEach(d => add(s.body, el('div', 'an-warn', line(d))));
                    add(s.body, el('div', 'an-note', 'The rewrite gave no rules (its answer could not be read), so these ' +
                        'are the rules from before it. They were not edited - check them before use.'));
                } else if (deps.length) {
                    deps.forEach(d => add(s.body, el('div', 'an-warn', line(d))));
                    add(s.body, el('div', 'an-note', 'Still departing after one rewrite. The rules were not edited - check them before use.'));
                } else if (chk.rewritten) {
                    add(s.body, el('div', 'an-ok', 'Checked: the log source and techniques follow your review after one rewrite.'));
                    add(s.body, el('div', 'an-note', `Before the rewrite: ${(chk.departures_before || []).map(line).join('; ')}`));
                } else {
                    add(s.body, el('div', 'an-ok', 'Checked: the log source and techniques follow your review.'));
                }
                if (flagged.length) {
                    add(s.body, el('div', 'an-subhead', 'Rejected strings used in detection'));
                    flagged.forEach(d => add(s.body, el('div', 'an-warn', line(d))));
                    add(s.body, el('div', 'an-note', 'Shown, not rewritten: a rejected string can be right inside a larger ' +
                        'condition (the process is sudo AND the argument is -u#-1). Check whether each rule depends on it.'));
                }
            }
            if (s.body.children.length === 0) add(s.body, el('div', 'an-note', 'Generated without changes: every item stayed the model\'s suggestion.'));
            root.appendChild(s.details);
        }

        // 1. Attack vector — how the attack starts and where it would be seen
        const sigs = av.payload_signatures || [];
        if (av.initial_access_vector || av.entry_point || sigs.length) {
            const s = panelSection('Attack vector', av.confidence !== undefined ? `confidence ${pct(av.confidence)}` : '', true);
            add(s.body,
                el('p', 'an-lead', av.initial_access_vector),
                kv('Entry point', av.entry_point, true),
                kv('Attacker controls', av.attacker_controlled_input),
                kv('Type', [av.vuln_class, av.protocol, av.preconditions].filter(Boolean).join(' · ').replace(/_/g, ' ')),
                kv('Seen in', [av.primary_telemetry, ...(av.secondary_telemetry || [])].filter(Boolean).join(', '), true),
                kv('Kill chain', (av.kill_chain_stages || []).join(' → ').replace(/_/g, ' ')));
            if (sigs.length) {
                add(s.body, el('div', 'an-subhead', `Patterns to match (${sigs.length})`));
                sigs.forEach((sig, i) => {
                    const item = el('div', 'an-item');
                    const head = el('div', 'an-item-head');
                    add(head, el('code', 'an-code', sig.pattern), el('span', 'an-where', (sig.where || '').replace(/_/g, ' ')));
                    add(item, head, basis(sig.derived_from === 'inferred_from_class'
                        ? 'Inferred from the vulnerability class, not from the text'
                        : sig.derived_from));
                    if (review) add(item, decisionButtons(item, 'patterns', i, DECIDE, sig.pattern));
                    s.body.appendChild(item);
                });
            }
            if (av.reasoning) add(s.body, el('div', 'an-note', `Model's note: ${av.reasoning}`));
            root.appendChild(s.details);
        }

        // 2. Strings kept out of the rules (researcher / patch workflow)
        const inc = av.incidental_artifacts || [];
        if (inc.length) {
            const s = panelSection('Excluded from rules', `${inc.length} researcher-only`, !!review);
            inc.forEach((it, i) => {
                const item = el('div', 'an-item');
                add(item, el('code', 'an-code', typeof it === 'string' ? it : it.value), basis(it.reason));
                if (review) add(item, decisionButtons(item, 'excluded', i, RESTORE, typeof it === 'string' ? it : it.value));
                s.body.appendChild(item);
            });
            if (review) add(s.body, el('div', 'an-note', 'A restored string becomes a pattern the rules may match.'));
            root.appendChild(s.details);
        }

        // 3. Recommended log source (the first is the one recommended for the first rule)
        const sugs = meta.logsource_suggestions || [];
        if (sugs.length) {
            const s = panelSection('Log source', 'first = recommended for the first rule', true);
            sugs.forEach((ls, i) => {
                const item = el('div', i === 0 ? 'an-item an-primary' : 'an-item');
                const head = el('div', 'an-item-head');
                add(head, el('code', 'an-code', logsourceName(ls)), el('span', 'an-conf', pct(ls.confidence)));
                add(item, head, basis(ls.reasoning));
                if ((ls.relevant_fields || []).length) add(item, el('div', 'an-fields', ls.relevant_fields.join(', ')));
                if (review) {
                    item.dataset.lsIndex = String(i);
                    item.logsource = asSource(ls);
                    const bar = el('div', 'an-actions');
                    const b = el('button', 'an-act', 'Use this');
                    b.type = 'button';
                    b.dataset.status = 'chosen';
                    if (onTable(ls)) {
                        b.onclick = () => {
                            review.logsource = sameSource(review.logsource, item.logsource) ? null : item.logsource;
                            paintLogsource(s.details);
                        };
                    } else {
                        b.disabled = true;
                        b.title = "Not a log source in SigmaHQ's rules - choose one from the list below";
                    }
                    add(bar, b);
                    add(item, bar);
                }
                s.body.appendChild(item);
            });
            if (review) {
                add(s.body, el('div', 'an-subhead', 'Or choose another'));
                const select = el('select', 'an-select');
                select.setAttribute('aria-label', "Log source from SigmaHQ's rules");
                add(select, el('option', null, "- the model's suggestion -"));
                select.firstChild.value = '';
                const withCategory = el('optgroup');
                withCategory.label = 'By category';
                const withoutCategory = el('optgroup');
                withoutCategory.label = 'Product / service (no category)';
                (logsourceChoices || []).forEach((c, i) => {
                    const option = el('option', null, logsourceName(c));
                    option.value = String(i);
                    (c.category ? withCategory : withoutCategory).appendChild(option);
                });
                add(select, withCategory, withoutCategory);
                select.onchange = () => {
                    review.logsource = select.value === '' ? null : logsourceChoices[Number(select.value)];
                    paintLogsource(s.details);
                };
                add(s.body, select, el('div', 'an-note',
                    "Every log source in SigmaHQ's rules. Untouched, the first suggestion stays a recommendation " +
                    'the rule writer may depart from; a log source you choose is given to it as your decision.'));
            }
            root.appendChild(s.details);
            if (review) paintLogsource(s.details);
        }

        // 4. ATT&CK techniques
        const ttps = meta.ttp_mappings || [];
        const dropped = (meta.ttp_dropped_ids || []).filter(Boolean);
        if (ttps.length || dropped.length) {
            const s = panelSection('MITRE ATT&CK', `${ttps.length} technique${ttps.length === 1 ? '' : 's'}`, true);
            ttps.forEach((t, i) => {
                const item = el('div', 'an-item');
                const head = el('div', 'an-item-head');
                add(head, el('code', 'an-code', t.technique_id), el('span', 'an-name', t.technique_name),
                    t.severity ? el('span', `severity-badge ${t.severity}`, t.severity) : null);
                add(item, head, t.tactic ? el('div', 'an-fields', t.tactic) : null, basis(t.relevance));
                if (review) add(item, decisionButtons(item, 'techniques', i, DECIDE, t.technique_id));
                s.body.appendChild(item);
            });
            if (dropped.length) add(s.body, el('div', 'an-note', `Removed, not in ATT&CK: ${dropped.join(', ')}`));
            root.appendChild(s.details);
        }

        // 5. Indicators, grouped by type
        const inds = meta.indicators || [];
        if (inds.length) {
            const s = panelSection('Indicators', `${inds.length} extracted`, !!review);
            const groups = {};
            inds.forEach((ind, i) => {
                const type = ind.type || 'other';
                (groups[type] = groups[type] || []).push([ind, i]);
            });
            Object.entries(groups).sort((a, b) => b[1].length - a[1].length).forEach(([type, list]) => {
                add(s.body, el('div', 'an-subhead', `${type.replace(/_/g, ' ')} (${list.length})`));
                list.forEach(([ind, i]) => {
                    const item = el('div', 'an-item compact');
                    add(item, el('code', 'an-code', ind.value), basis(ind.context));
                    if (review) add(item, decisionButtons(item, 'indicators', i, DECIDE, ind.value));
                    s.body.appendChild(item);
                });
            });
            root.appendChild(s.details);
        }

        // 6. Exploit code the report linked to
        const pocFlow = meta.poc_attack_flow || '';
        const pocInd = meta.poc_behavioral_indicators || [];
        if (pocFlow || pocInd.length) {
            const n = meta.poc_snippets_found || 0;
            const s = panelSection('Exploit code (PoC)', `${n} snippet${n === 1 ? '' : 's'}`, false);
            add(s.body, el('p', 'an-lead', pocFlow));
            pocInd.forEach(ind => {
                const item = el('div', 'an-item compact');
                add(item, el('code', 'an-code', ind.value), basis(ind.context));
                s.body.appendChild(item);
            });
            root.appendChild(s.details);
        }

        // 7. Checks run on the rules
        const cov = meta.coverage_check || {};
        const warnings = cov.warnings || [];
        const issues = meta.validation_issues || [];
        if (warnings.length || issues.length || Object.keys(cov).length) {
            const s = panelSection('Checks', `${warnings.length} coverage · ${issues.length} pySigma`, warnings.length > 0);
            if (!warnings.length) add(s.body, el('div', 'an-ok', 'Coverage: no gaps detected'));
            warnings.forEach(w => add(s.body, el('div', 'an-warn', w)));
            issues.forEach(i => {
                const item = el('div', 'an-item compact an-issue');
                add(item, el('span', `an-sev ${i.severity || ''}`, i.severity), el('span', 'an-v', i.message));
                s.body.appendChild(item);
            });
            root.appendChild(s.details);
        }

        // 8. What the review step changed
        const changes = meta.optimization_changes || [];
        if (changes.length) {
            const s = panelSection('Changes made in review', String(changes.length), false);
            changes.forEach(c => add(s.body, el('div', 'an-item compact', c)));
            root.appendChild(s.details);
        }

        // 9. Documents retrieved for the model
        const refs = [['Similar SigmaHQ rules', context.sigma], ['ATT&CK', context.mitre], ['Sysmon', context.sysmon]];
        const total = refs.reduce((n, [, items]) => n + ((items || []).length), 0);
        if (total) {
            const s = panelSection('Retrieved references', String(total), false);
            refs.forEach(([title, items]) => {
                if (!items || !items.length) return;
                add(s.body, el('div', 'an-subhead', `${title} (${items.length})`));
                items.forEach(doc => {
                    const text = String(doc);
                    s.body.appendChild(el('pre', 'an-doc', text.length > 1200 ? `${text.slice(0, 1200)}\n…` : text));
                });
            });
            root.appendChild(s.details);
        }

        if (review) {
            const s = panelSection('Note to the rule writer', 'optional', true);
            const note = el('textarea', 'an-textarea');
            note.maxLength = 2000;
            note.placeholder = 'Anything the model got wrong that the buttons do not cover, e.g. "The target runs Linux only."';
            note.value = review.note;
            note.oninput = () => { review.note = note.value; };
            add(s.body, note);
            root.appendChild(s.details);
        }

        if (!root.children.length) root.appendChild(el('p', 'empty-state', 'No analysis was recorded for this answer.'));
        paintDecisions();
    }

    if (sendBtn) sendBtn.addEventListener('click', handleSend);
    const generateBtn = document.getElementById('generate-btn');
    if (generateBtn) generateBtn.addEventListener('click', generateFromReview);
    if (newChatBtn) newChatBtn.addEventListener('click', createSession);
    if (userInput) {
        userInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                handleSend();
            }
        });
    }

    // Start with chat
    initChat();
});
