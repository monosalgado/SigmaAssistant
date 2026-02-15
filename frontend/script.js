document.addEventListener('DOMContentLoaded', () => {
    const chatHistory = document.getElementById('chat-history');
    const userInput = document.getElementById('user-input');
    const sendBtn = document.getElementById('send-btn');
    const newChatBtn = document.getElementById('new-chat-btn');
    const sessionList = document.getElementById('session-list');

    // File Inputs
    const fileInput = document.getElementById('file-input');
    const attachBtn = document.getElementById('attach-btn');
    const filePreview = document.getElementById('file-preview');
    const fileNameSpan = document.getElementById('file-name');
    const removeFileBtn = document.getElementById('remove-file');

    let currentSessionId = null;
    let selectedFile = null;

    // --- File Logic ---
    if (attachBtn && fileInput) {
        attachBtn.addEventListener('click', () => {
            fileInput.click();
        });
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

    // --- Session Logic ---
    async function init() {
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

            // Info
            const infoDiv = document.createElement('div');
            infoDiv.className = 'session-info';
            // Removed message count as requested
            infoDiv.innerHTML = `<div class="session-preview">${s.preview || 'New Chat'}</div>`;
            infoDiv.onclick = () => switchSession(s.id);

            // Delete
            const delBtn = document.createElement('button');
            delBtn.className = 'delete-session-btn';
            delBtn.innerHTML = '🗑️';
            delBtn.title = 'Delete Chat';
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
        try {
            const res = await fetch('/sessions', { method: 'POST' });
            const data = await res.json();
            currentSessionId = data.id;
            chatHistory.innerHTML = '';
            await loadSessions();
            await switchSession(data.id);
        } catch (e) {
            console.error("Failed to create session", e);
        }
    }

    async function deleteSession(id) {
        if (!confirm('Delete this chat?')) return;
        try {
            await fetch(`/sessions/${id}`, { method: 'DELETE' });
            if (currentSessionId === id) {
                currentSessionId = null;
                chatHistory.innerHTML = '';
                // render empty or load another?
            }
            await init();
        } catch (e) {
            console.error("Failed to delete session", e);
        }
    }

    async function switchSession(id) {
        currentSessionId = id;
        try {
            const res = await fetch(`/sessions/${id}`);
            const msgs = await res.json();

            chatHistory.innerHTML = '';

            // Clear context initially
            const contextDiv = document.getElementById('context-content');
            if (contextDiv) contextDiv.innerHTML = '<p class="empty-state">No specific context found.</p>';

            let lastContext = null;

            msgs.forEach(m => {
                appendMessage(m.role, m.content);
                if (m.role === 'assistant' && m.context && Object.keys(m.context).length > 0) {
                    lastContext = m.context;
                }
            });

            // Only render the context of the LAST message that had one (or stay empty)
            if (lastContext) {
                renderContext(lastContext);
            }

            loadSessions();
        } catch (e) {
            console.error("Failed to switch session", e);
        }
    }

    // --- Message Logic ---

    function appendMessage(role, text) {
        const msgDiv = document.createElement('div');
        msgDiv.className = `message ${role}`;

        const avatar = document.createElement('div');
        avatar.className = 'avatar';
        avatar.innerText = role === 'user' ? 'U' : 'AI';

        const content = document.createElement('div');
        content.className = 'content';

        if (!text) text = "";

        // Markdown
        // Configure marked to handle potential HTML safely (optional, but good practice)
        // For now using default
        content.innerHTML = marked.parse(text);

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

    async function handleSend() {
        const text = userInput.value.trim();
        if (!text && !selectedFile) return;

        let userDisplay = text;
        if (selectedFile) {
            userDisplay += `\n[Attached: ${selectedFile.name}]`;
        }

        appendMessage('user', userDisplay);
        userInput.value = '';

        // Hide preview
        if (selectedFile) {
            filePreview.style.display = 'none';
        }

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

                response = await fetch('/analyze_multimodal', {
                    method: 'POST',
                    body: formData
                });

                selectedFile = null;
                if (fileInput) fileInput.value = '';

            } else {
                response = await fetch('/analyze', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        description: text,
                        session_id: currentSessionId
                    })
                });
            }

            const data = await response.json();

            chatHistory.removeChild(loadingDiv);

            if (data.rule) {
                appendMessage('assistant', data.rule);
                if (data.context) {
                    renderContext(data.context);
                }
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
                    toggle.style.fontSize = '0.75rem';

                    toggle.onclick = (e) => {
                        e.stopPropagation();
                        // Check if we are currently expanded or collapsed based on text length/content
                        // Simpler state tracking:
                        const isExpanded = card.getAttribute('data-expanded') === 'true';

                        if (isExpanded) {
                            card.innerText = shortText;
                            // Re-append toggle
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

        if (contextDiv.innerHTML === '') {
            contextDiv.innerHTML = '<p class="empty-state">No specific context found.</p>';
        }
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

    init();
});
