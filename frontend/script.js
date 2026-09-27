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
    const PIPELINE_STAGES = [
        { id: 'classification', label: 'Intent Classification' },
        { id: 'preprocessing', label: 'Preprocessing' },
        { id: 'web_enrichment', label: 'Web Enrichment' },
        { id: 'poc_analysis', label: 'PoC Analysis' },
        { id: 'attack_vector', label: 'Attack Vector Extraction' },
        { id: 'analysis', label: 'Threat Analysis' },
        { id: 'feedback', label: 'Review & Confirm' },
        { id: 'generation', label: 'Rule Generation' },
        { id: 'review', label: 'Validation & Optimization' },
        { id: 'coverage_check', label: 'Coverage Gap Check' },
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

        let lastContext = null;
        let lastPipelineMeta = null;
        msgs.forEach(m => {
            appendMessage(m.role, m.content);
            if (m.role === 'assistant' && m.context && Object.keys(m.context).length > 0) {
                lastContext = m.context;
                lastPipelineMeta = m.pipeline_metadata || null;
            }
        });
        if (lastContext) renderContext(lastContext, lastPipelineMeta);
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

    function loadRuleIntoEditor(rule) {
        currentRuleId = rule.id;
        editorTitle.innerText = rule.title;
        ruleEditor.value = rule.content;
        translationOutput.value = '';

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
            await fetch(`/rules/${currentRuleId}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ content: content })
            });
            await loadRules();
            alert("Saved!");
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
    function createPipelineProgress() {
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

        PIPELINE_STAGES.forEach(stage => {
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

    // --- Feedback Preview Panel ---
    function showFeedbackPreview(data, pipelineDiv) {
        const feedbackDiv = document.createElement('div');
        feedbackDiv.className = 'feedback-preview';
        feedbackDiv.id = 'feedback-preview';

        let html = '<h4>Pipeline Preview — Review Before Generation</h4>';

        // Attack Summary
        if (data.attack_summary) {
            html += `<div class="feedback-section"><strong>Attack Summary:</strong> ${data.attack_summary}</div>`;
        }

        // Indicators
        const indicators = data.indicators || [];
        if (indicators.length > 0) {
            html += '<div class="feedback-section"><strong>Extracted Indicators:</strong><div class="indicator-chips">';
            indicators.forEach(ind => {
                html += `<span class="indicator-chip ${ind.type}" title="${ind.context || ''}">${ind.value}</span>`;
            });
            html += '</div></div>';
        }

        // TTP Mappings
        const ttps = data.ttp_mappings || [];
        if (ttps.length > 0) {
            html += '<div class="feedback-section"><strong>MITRE ATT&CK:</strong>';
            ttps.forEach(ttp => {
                html += `<div class="ttp-card-mini"><span class="ttp-id">${ttp.technique_id}</span> ${ttp.technique_name} <span class="severity-badge ${ttp.severity}">${ttp.severity}</span></div>`;
            });
            html += '</div>';
        }

        // Log Source Suggestions
        const logsources = data.logsource_suggestions || [];
        if (logsources.length > 0) {
            html += '<div class="feedback-section"><strong>Suggested Log Sources:</strong>';
            html += `<div class="logsource-primary">Primary: ${data.primary_logsource || 'N/A'}</div>`;
            logsources.forEach(ls => {
                const pct = Math.round((ls.confidence || 0) * 100);
                html += `<div class="logsource-item"><span class="logsource-cat">${ls.category}/${ls.product}</span> <span class="logsource-conf">${pct}%</span> — ${ls.reasoning || ''}</div>`;
            });
            html += '</div>';
        }

        html += '<div class="feedback-note">This preview is informational. The pipeline will continue automatically.</div>';

        feedbackDiv.innerHTML = safeHTML(html);

        // Insert after the pipeline progress inside the same wrapper
        const contentDiv = pipelineDiv.querySelector('.content');
        if (contentDiv) {
            contentDiv.appendChild(feedbackDiv);
        }
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

        // Use SSE streaming for text-only requests
        const pipelineDiv = createPipelineProgress();
        chatHistory.appendChild(pipelineDiv);
        chatHistory.scrollTop = chatHistory.scrollHeight;

        try {
            const response = await fetch('/analyze_stream', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ description: text, session_id: currentSessionId })
            });

            const reader = response.body.getReader();
            const decoder = new TextDecoder();
            let buffer = '';

            while (true) {
                const { done, value } = await reader.read();
                if (done) break;

                buffer += decoder.decode(value, { stream: true });

                // Parse SSE events from buffer
                const lines = buffer.split('\n');
                buffer = '';

                let currentEvent = null;
                let currentData = '';

                for (const line of lines) {
                    if (line.startsWith('event: ')) {
                        currentEvent = line.substring(7).trim();
                    } else if (line.startsWith('data: ')) {
                        currentData = line.substring(6);
                    } else if (line === '' && currentEvent && currentData) {
                        // Complete SSE event
                        try {
                            const data = JSON.parse(currentData);

                            if (currentEvent === 'stage') {
                                updatePipelineStage(data.stage, data.status, data.detail);
                            } else if (currentEvent === 'feedback_request') {
                                // Show feedback preview in the pipeline progress
                                updatePipelineStage('feedback', 'running', 'Review extracted data...');
                                showFeedbackPreview(data, pipelineDiv);
                            } else if (currentEvent === 'result') {
                                // Remove pipeline progress, show final message
                                chatHistory.removeChild(pipelineDiv);

                                if (data.rule) {
                                    appendMessage('assistant', data.rule);
                                    if (data.context) renderContext(data.context, data.pipeline_metadata);
                                    if (data.session_id) currentSessionId = data.session_id;
                                    loadSessions();
                                } else {
                                    appendMessage('assistant', "I encountered an error analyzing that.");
                                }
                            }
                        } catch (parseErr) {
                            console.error('SSE parse error:', parseErr);
                        }
                        currentEvent = null;
                        currentData = '';
                    } else if (line !== '') {
                        // Partial data, keep in buffer
                        buffer = line + '\n';
                    }
                }
            }
        } catch (error) {
            // Remove pipeline progress on error
            if (pipelineDiv.parentNode) {
                chatHistory.removeChild(pipelineDiv);
            }
            appendMessage('assistant', `Error: ${error.message}`);
        }
    }

    // --- Analysis panel: what the model understood, evidence first (read-only) ---
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
                sigs.forEach(sig => {
                    const item = el('div', 'an-item');
                    const head = el('div', 'an-item-head');
                    add(head, el('code', 'an-code', sig.pattern), el('span', 'an-where', (sig.where || '').replace(/_/g, ' ')));
                    add(item, head, basis(sig.derived_from === 'inferred_from_class'
                        ? 'Inferred from the vulnerability class, not from the text'
                        : sig.derived_from));
                    s.body.appendChild(item);
                });
            }
            if (av.reasoning) add(s.body, el('div', 'an-note', `Model's note: ${av.reasoning}`));
            root.appendChild(s.details);
        }

        // 2. Strings kept out of the rules (researcher / patch workflow)
        const inc = av.incidental_artifacts || [];
        if (inc.length) {
            const s = panelSection('Excluded from rules', `${inc.length} researcher-only`, false);
            inc.forEach(it => {
                const item = el('div', 'an-item');
                add(item, el('code', 'an-code', typeof it === 'string' ? it : it.value), basis(it.reason));
                s.body.appendChild(item);
            });
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
                s.body.appendChild(item);
            });
            root.appendChild(s.details);
        }

        // 4. ATT&CK techniques
        const ttps = meta.ttp_mappings || [];
        const dropped = (meta.ttp_dropped_ids || []).filter(Boolean);
        if (ttps.length || dropped.length) {
            const s = panelSection('MITRE ATT&CK', `${ttps.length} technique${ttps.length === 1 ? '' : 's'}`, true);
            ttps.forEach(t => {
                const item = el('div', 'an-item');
                const head = el('div', 'an-item-head');
                add(head, el('code', 'an-code', t.technique_id), el('span', 'an-name', t.technique_name),
                    t.severity ? el('span', `severity-badge ${t.severity}`, t.severity) : null);
                add(item, head, t.tactic ? el('div', 'an-fields', t.tactic) : null, basis(t.relevance));
                s.body.appendChild(item);
            });
            if (dropped.length) add(s.body, el('div', 'an-note', `Removed, not in ATT&CK: ${dropped.join(', ')}`));
            root.appendChild(s.details);
        }

        // 5. Indicators, grouped by type
        const inds = meta.indicators || [];
        if (inds.length) {
            const s = panelSection('Indicators', `${inds.length} extracted`, false);
            const groups = {};
            inds.forEach(ind => {
                const type = ind.type || 'other';
                (groups[type] = groups[type] || []).push(ind);
            });
            Object.entries(groups).sort((a, b) => b[1].length - a[1].length).forEach(([type, list]) => {
                add(s.body, el('div', 'an-subhead', `${type.replace(/_/g, ' ')} (${list.length})`));
                list.forEach(ind => {
                    const item = el('div', 'an-item compact');
                    add(item, el('code', 'an-code', ind.value), basis(ind.context));
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

        if (!root.children.length) root.appendChild(el('p', 'empty-state', 'No analysis was recorded for this answer.'));
    }

    if (sendBtn) sendBtn.addEventListener('click', handleSend);
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
