document.addEventListener('DOMContentLoaded', () => {
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
            infoDiv.innerHTML = `<div class="session-preview">${s.preview || 'New Chat'}</div>`;
            infoDiv.onclick = () => switchSession(s.id);

            const delBtn = document.createElement('button');
            delBtn.className = 'delete-session-btn';
            delBtn.innerHTML = '🗑️';
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
        if (contextDiv) contextDiv.innerHTML = '<p class="empty-state">No specific context found.</p>';

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
            item.innerHTML = `<div class="session-info">${r.title}</div>`;
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
            content.innerHTML = marked.parse(text);

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
            content.innerHTML = marked.parse(text || "");
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

        feedbackDiv.innerHTML = html;

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

    // --- Context Panel Rendering (Enhanced with Pipeline Metadata) ---
    function renderContext(context, pipelineMetadata) {
        const contextDiv = document.getElementById('context-content');
        if (!contextDiv) return;
        contextDiv.innerHTML = '';

        // Render pipeline metadata first (if available)
        if (pipelineMetadata) {
            // Extracted Indicators
            const indicators = pipelineMetadata.indicators || [];
            if (indicators.length > 0) {
                const section = document.createElement('div');
                section.className = 'context-section';
                const header = document.createElement('h4');
                header.textContent = 'Extracted Indicators';
                section.appendChild(header);

                const chipsDiv = document.createElement('div');
                chipsDiv.className = 'indicator-chips';
                indicators.forEach(ind => {
                    const chip = document.createElement('span');
                    chip.className = `indicator-chip ${ind.type}`;
                    chip.textContent = ind.value;
                    chip.title = `${ind.type} (${ind.confidence})`;
                    chipsDiv.appendChild(chip);
                });
                section.appendChild(chipsDiv);
                contextDiv.appendChild(section);
            }

            // TTP Mappings
            const ttps = pipelineMetadata.ttp_mappings || [];
            if (ttps.length > 0) {
                const section = document.createElement('div');
                section.className = 'context-section';
                const header = document.createElement('h4');
                header.textContent = 'MITRE ATT&CK Mappings';
                section.appendChild(header);

                ttps.forEach(ttp => {
                    const card = document.createElement('div');
                    card.className = 'ttp-card';
                    card.innerHTML = `
                        <span class="ttp-id">${ttp.technique_id}</span>
                        <span class="ttp-name">${ttp.technique_name}</span>
                        <span class="severity-badge ${ttp.severity || 'medium'}">${ttp.severity || 'medium'}</span>
                        <br><span class="ttp-tactic">${ttp.tactic}</span>
                    `;
                    section.appendChild(card);
                });
                contextDiv.appendChild(section);
            }

            // Validation Issues
            const issues = pipelineMetadata.validation_issues || [];
            if (issues.length > 0) {
                const section = document.createElement('div');
                section.className = 'context-section';
                const header = document.createElement('h4');
                header.textContent = 'Validation';
                section.appendChild(header);

                issues.forEach(issue => {
                    const card = document.createElement('div');
                    card.className = 'context-card';
                    const color = issue.severity === 'error' ? '#f85149' : issue.severity === 'warning' ? '#d29922' : '#8b949e';
                    card.innerHTML = `<span style="color:${color};font-weight:600">${issue.severity.toUpperCase()}</span> [${issue.field}]: ${issue.message}`;
                    section.appendChild(card);
                });
                contextDiv.appendChild(section);
            }

            // Enrichment Sources
            const enrichSources = pipelineMetadata.enrichment_sources || [];
            if (enrichSources.length > 0) {
                const section = document.createElement('div');
                section.className = 'context-section';
                const header = document.createElement('h4');
                header.textContent = 'Web Enrichment Sources';
                section.appendChild(header);

                enrichSources.forEach(src => {
                    const card = document.createElement('div');
                    card.className = 'context-card enrichment-source';
                    card.innerHTML = `<a href="${src.url}" target="_blank" class="enrich-link">${src.title || src.url}</a><p class="enrich-snippet">${src.snippet || ''}</p>`;
                    section.appendChild(card);
                });
                contextDiv.appendChild(section);
            }

            // PoC Analysis
            const pocFlow = pipelineMetadata.poc_attack_flow || '';
            const pocIndicators = pipelineMetadata.poc_behavioral_indicators || [];
            if (pocFlow || pocIndicators.length > 0) {
                const section = document.createElement('div');
                section.className = 'context-section';
                const header = document.createElement('h4');
                header.textContent = `PoC Analysis (${pipelineMetadata.poc_snippets_found || 0} snippets)`;
                section.appendChild(header);

                if (pocFlow) {
                    const flowCard = document.createElement('div');
                    flowCard.className = 'context-card';
                    flowCard.textContent = pocFlow;
                    section.appendChild(flowCard);
                }
                if (pocIndicators.length > 0) {
                    const chipsDiv = document.createElement('div');
                    chipsDiv.className = 'indicator-chips';
                    pocIndicators.forEach(ind => {
                        const chip = document.createElement('span');
                        chip.className = `indicator-chip ${ind.type || 'other'}`;
                        chip.textContent = ind.value;
                        chip.title = ind.context || '';
                        chipsDiv.appendChild(chip);
                    });
                    section.appendChild(chipsDiv);
                }
                contextDiv.appendChild(section);
            }

            // Log Source Suggestions
            const logsourceSugs = pipelineMetadata.logsource_suggestions || [];
            if (logsourceSugs.length > 0) {
                const section = document.createElement('div');
                section.className = 'context-section';
                const header = document.createElement('h4');
                header.textContent = 'Log Source Analysis';
                section.appendChild(header);

                if (pipelineMetadata.logsource_primary) {
                    const primaryDiv = document.createElement('div');
                    primaryDiv.className = 'logsource-primary-badge';
                    primaryDiv.textContent = `Primary: ${pipelineMetadata.logsource_primary}`;
                    section.appendChild(primaryDiv);
                }

                logsourceSugs.forEach(ls => {
                    const card = document.createElement('div');
                    card.className = 'context-card logsource-card';
                    const pct = Math.round((ls.confidence || 0) * 100);
                    card.innerHTML = `
                        <div class="logsource-header">
                            <strong>${ls.category || '?'}/${ls.product || '?'}</strong>
                            <span class="logsource-conf">${pct}%</span>
                        </div>
                        <div class="logsource-reason">${ls.reasoning || ''}</div>
                        <div class="logsource-fields">${(ls.relevant_fields || []).join(', ')}</div>
                    `;
                    section.appendChild(card);
                });
                contextDiv.appendChild(section);
            }

            // Optimization Changes
            const changes = pipelineMetadata.optimization_changes || [];
            if (changes.length > 0) {
                const section = document.createElement('div');
                section.className = 'context-section';
                const header = document.createElement('h4');
                header.textContent = 'Optimizations Applied';
                section.appendChild(header);

                changes.forEach(change => {
                    const card = document.createElement('div');
                    card.className = 'context-card';
                    card.textContent = change;
                    section.appendChild(card);
                });
                contextDiv.appendChild(section);
            }
        }

        // RAG Context (original behavior)
        const addSection = (title, items, icon) => {
            if (!items || items.length === 0) return;
            const section = document.createElement('div');
            section.className = 'context-section';
            const header = document.createElement('h4');
            header.innerHTML = `${icon} ${title}`;
            section.appendChild(header);
            items.forEach(item => {
                const card = document.createElement('div');
                card.className = 'context-card';
                if (item.length > 200) {
                    const shortText = item.substring(0, 200) + '...';
                    card.innerText = shortText;
                    const toggle = document.createElement('span');
                    toggle.innerText = ' [Expand]';
                    toggle.style.color = 'var(--accent)';
                    toggle.style.cursor = 'pointer';
                    toggle.onclick = (e) => {
                        e.stopPropagation();
                        if (card.getAttribute('data-expanded') === 'true') {
                            card.innerText = shortText;
                            toggle.innerText = ' [Expand]';
                            card.appendChild(toggle);
                            card.setAttribute('data-expanded', 'false');
                        } else {
                            card.innerText = item;
                            toggle.innerText = ' [Collapse]';
                            card.appendChild(toggle);
                            card.setAttribute('data-expanded', 'true');
                        }
                    };
                    card.appendChild(toggle);
                } else {
                    card.innerText = item;
                }
                section.appendChild(card);
            });
            contextDiv.appendChild(section);
        };
        addSection('Sigma Rules', context.sigma, '📜');
        addSection('MITRE ATT&CK', context.mitre, '🛡️');
        addSection('Sysmon Events', context.sysmon, '📝');
        if (contextDiv.innerHTML === '') contextDiv.innerHTML = '<p class="empty-state">No specific context found.</p>';
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
