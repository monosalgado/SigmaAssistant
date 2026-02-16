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
    const deleteRuleBtn = document.getElementById('delete-rule-btn');
    const translateBtn = document.getElementById('translate-btn');
    const translationOutput = document.getElementById('translation-output');
    const targetLangSelect = document.getElementById('target-lang');

    // State
    let currentSessionId = null;
    let selectedFile = null;
    let currentRuleId = null;

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
            viewLibrary.style.display = 'grid'; // Grid layout for library
            chatSidebar.style.display = 'none';
            librarySidebar.style.display = 'flex';
            navChat.classList.remove('active');
            navLibrary.classList.add('active');
            loadRules(); // Refresh rules when switching
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

        // Context reset
        const contextDiv = document.getElementById('context-content');
        if (contextDiv) contextDiv.innerHTML = '<p class="empty-state">No specific context found.</p>';

        let lastContext = null;
        msgs.forEach(m => {
            appendMessage(m.role, m.content);
            if (m.role === 'assistant' && m.context && Object.keys(m.context).length > 0) {
                lastContext = m.context;
            }
        });
        if (lastContext) renderContext(lastContext);
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
            item.className = `session-item ${r.id === currentRuleId ? 'active' : ''}`; // Reuse session-item style for now
            item.innerHTML = `<div class="session-info">${r.title}</div>`;
            item.onclick = () => loadRuleIntoEditor(r);
            ruleList.appendChild(item);
        });
    }

    function loadRuleIntoEditor(rule) {
        currentRuleId = rule.id;
        editorTitle.innerText = rule.title;
        ruleEditor.value = rule.content;
        translationOutput.value = ''; // Clear prev translation

        // Re-render list to show active state
        // In efficient app we just toggle class, but this is fine
        Array.from(ruleList.children).forEach(child => {
            // simplified logic: reload list is easiest or manually toggle
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
            // If no rule selected, create new one with editor content
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
            // Update
            const content = ruleEditor.value;
            await fetch(`/rules/${currentRuleId}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ content: content })
            });
            await loadRules(); // Reload to update title if changed
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
                translationOutput.value = data.query;
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

    // --- Message Logic ---
    function appendMessage(role, text) {
        const msgDiv = document.createElement('div');
        msgDiv.className = `message ${role}`;

        const avatar = document.createElement('div');
        avatar.className = 'avatar';
        avatar.innerText = role === 'user' ? 'U' : 'AI';

        const content = document.createElement('div');
        content.className = 'content';

        // Check for YAML/Code block to add "Save to Library" button
        if (role === 'assistant' && (text.includes('```yaml') || text.includes('```'))) {
            // Render text
            content.innerHTML = marked.parse(text);

            // Add Save Button
            const actionsDiv = document.createElement('div');
            actionsDiv.className = 'msg-actions';
            const saveBtn = document.createElement('button');
            saveBtn.innerText = '💾 Save to Library';
            saveBtn.className = 'mini-btn';
            saveBtn.onclick = () => saveRuleFromChat(text);
            actionsDiv.appendChild(saveBtn);
            content.appendChild(actionsDiv);

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

    async function saveRuleFromChat(text) {
        // Extract YAML block
        const match = text.match(/```yaml\n([\s\S]*?)\n```/);
        if (match && match[1]) {
            const ruleContent = match[1];
            const res = await fetch('/rules', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ content: ruleContent })
            });
            const rule = await res.json();
            alert("Rule saved to library!");
            // Switch to library view and load it?
            // Optional but good UX:
            if (confirm("Rule saved! Switch to library to view it?")) {
                switchView('library');
                await loadRules();
                loadRuleIntoEditor(rule);
            }
        } else {
            alert("No valid YAML rule found in this message.");
        }
    }

    async function handleSend() {
        const text = userInput.value.trim();
        if (!text && !selectedFile) return;

        let userDisplay = text;
        if (selectedFile) userDisplay += `\n[Attached: ${selectedFile.name}]`;

        appendMessage('user', userDisplay);
        userInput.value = '';
        if (selectedFile) filePreview.style.display = 'none';

        const loadingDiv = document.createElement('div');
        loadingDiv.className = 'message assistant loading';
        loadingDiv.innerHTML = '<div class="avatar">AI</div><div class="content">Analysing... ⏳</div>';
        chatHistory.appendChild(loadingDiv);

        try {
            let response;
            if (selectedFile) {
                const formData = new FormData();
                formData.append('description', text || "Analyze this file");
                formData.append('session_id', currentSessionId);
                formData.append('file', selectedFile);
                response = await fetch('/analyze_multimodal', { method: 'POST', body: formData });
                selectedFile = null;
                if (fileInput) fileInput.value = '';
            } else {
                response = await fetch('/analyze', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ description: text, session_id: currentSessionId })
                });
            }

            const data = await response.json();
            chatHistory.removeChild(loadingDiv);

            if (data.rule) {
                appendMessage('assistant', data.rule);
                if (data.context) renderContext(data.context);
                loadSessions();
            } else {
                appendMessage('assistant', "I encountered an error analyzing that.");
            }
        } catch (error) {
            chatHistory.removeChild(loadingDiv);
            appendMessage('assistant', `Error: ${error.message}`);
        }
    }

    function renderContext(context) {
        const contextDiv = document.getElementById('context-content');
        if (!contextDiv) return;
        contextDiv.innerHTML = '';
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
