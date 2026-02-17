// ThreatAnalyzer - Client Side Logic (Mail.tm Integration)
let currentToken = '';
let currentEmail = '';
let currentTab = 'url';
let refreshInterval = null;

// Inicialización automática
window.addEventListener('load', () => {
    // Cargar estado del switch de caché
    fetch('/api/cache/status')
        .then(res => res.json())
        .then(data => {
            const cacheToggle = document.getElementById('cache-toggle');
            if (cacheToggle) {
                cacheToggle.checked = data.enabled;
            }
        })
        .catch(err => console.error('Error al cargar estado de caché:', err));

    // Manejar cambio del switch de caché
    const cacheToggle = document.getElementById('cache-toggle');
    if (cacheToggle) {
        cacheToggle.addEventListener('change', (e) => {
            fetch('/api/cache/toggle', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ enabled: e.target.checked })
            })
            .then(res => res.json())
            .then(data => {
                console.log(`Caché ${data.enabled ? 'activada' : 'desactivada'}`);
            })
            .catch(err => console.error('Error al cambiar estado de caché:', err));
        });
    }

    // Intentar generar email automáticamente en modo silencioso
    generateMailTM(true);
    startAutoRefresh();

    document.getElementById('gen-email-btn').addEventListener('click', () => generateMailTM(false));
    document.getElementById('refresh-inbox-btn').addEventListener('click', refreshInboxTM);

    // Botón URL
    document.getElementById('analyze-url-btn').addEventListener('click', () => {
        resetResults();
        analyzeURL();
    });
    document.getElementById('url-input').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            resetResults();
            analyzeURL();
        }
    });

    // Botón SMS
    document.getElementById('analyze-sms-btn').addEventListener('click', () => {
        resetResults();
        analyzeSMS();
    });

    // Botón de copiar
    document.getElementById('copy-email-btn').addEventListener('click', () => {
        if (!currentEmail || currentEmail === '...') return;
        navigator.clipboard.writeText(currentEmail).then(() => {
            const btn = document.getElementById('copy-email-btn');
            const oldText = btn.innerText;
            btn.innerText = '✅';
            setTimeout(() => btn.innerText = oldText, 1000);
        });
    });

    // Cambio de Pestañas Global
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            btn.classList.add('active');
            currentTab = btn.dataset.tab;
            document.getElementById(`${currentTab}-section`).classList.add('active');

            // LIMPIAR todo al cambiar
            resetResults();
        });
    });
});

function resetResults() {
    document.getElementById('results').classList.add('hidden');
    document.getElementById('risk-factors').innerHTML = '';

    // Limpiar contenido de tarjetas para evitar datos persistentes
    const ids = ['ssl-info', 'domain-age', 'email-info', 'vt-info', 'reputation-info', 'url-list-container'];
    ids.forEach(id => {
        const el = document.getElementById(id);
        if (el) el.innerHTML = '<p class="empty-msg">Preparado para análisis...</p>';
    });

    const sslStatus = document.getElementById('ssl-status');
    if (sslStatus) {
        sslStatus.innerText = 'Buscando...';
        sslStatus.className = 'status-badge';
    }
}

function startAutoRefresh() {
    if (!refreshInterval) {
        refreshInterval = setInterval(() => {
            // SOLO si estamos en la pestaña de emails y la ventana está visible
            if (currentTab === 'inbox' && !document.hidden) {
                refreshInboxTM();
            }
        }, 5000);
    }
}

function stopAutoRefresh() {
    clearInterval(refreshInterval);
    refreshInterval = null;
}

async function generateMailTM(silent = false) {
    try {
        const genBtn = document.getElementById('gen-email-btn');
        const emailDisplay = document.getElementById('temp-email-display');
        genBtn.disabled = true;
        genBtn.innerText = 'Generando...';
        emailDisplay.innerText = 'Generando...';
        emailDisplay.style.color = '';

        const domainsRes = await fetch('/proxy/mailtm/domains');
        if (!domainsRes.ok) {
            throw new Error(`Error al obtener dominios: ${domainsRes.status}`);
        }
        const domains = await domainsRes.json();

        if (domains.error) throw new Error(domains.error);

        // La API de Mail.tm puede devolver un array directo o un objeto con hydra:member
        let memberList = [];
        if (Array.isArray(domains)) {
            // Si es un array directo, usarlo directamente
            memberList = domains;
        } else if (domains['hydra:member']) {
            // Formato Hydra
            memberList = domains['hydra:member'];
        } else if (domains['member']) {
            // Formato alternativo
            memberList = domains['member'];
        } else if (domains && typeof domains === 'object' && !Array.isArray(domains)) {
            // Si es un objeto pero no tiene member, intentar convertirlo a array
            memberList = Object.values(domains).filter(item => item && typeof item === 'object' && item.domain);
        }

        if (!Array.isArray(memberList) || memberList.length === 0) {
            throw new Error('No hay dominios disponibles');
        }

        // Obtener el dominio del primer elemento
        const firstDomain = memberList[0];
        const domain = firstDomain.domain || firstDomain;
        
        if (!domain || typeof domain !== 'string') {
            console.error('Formato de dominio inválido:', firstDomain);
            throw new Error('Formato de dominio inválido');
        }

        const randomId = Math.random().toString(36).substring(2, 9);
        const address = `safe_${randomId}@${domain}`;
        const password = 'SafePassword123!';

        const createRes = await fetch('/proxy/mailtm/create-account', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ address, password })
        });

        const createData = await createRes.json();
        if (createRes.status !== 201) {
            const errorMsg = createData.message || createData['@type'] || 'Fallo al crear cuenta';
            throw new Error(`Error al crear cuenta: ${errorMsg}`);
        }

        const tokenRes = await fetch('/proxy/mailtm/token', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ address, password })
        });
        
        if (!tokenRes.ok) {
            const tokenError = await tokenRes.json().catch(() => ({}));
            throw new Error(`Error al obtener token: ${tokenError.message || tokenRes.status}`);
        }
        
        const tokenData = await tokenRes.json();
        if (!tokenData.token) {
            throw new Error('No se recibió token de autenticación');
        }
        
        currentToken = tokenData.token;
        currentEmail = address;
        
        console.log('Email generado:', currentEmail);
        console.log('Token guardado:', currentToken ? 'Sí (primeros 20 chars: ' + currentToken.substring(0, 20) + '...)' : 'No');

        emailDisplay.innerText = currentEmail;
        emailDisplay.style.color = 'var(--accent-primary)';
        genBtn.disabled = false;
        genBtn.innerText = 'Nueva Dirección';
        
        // Refrescar el inbox después de generar el email
        setTimeout(() => refreshInboxTM(), 1000);
    } catch (err) {
        const genBtn = document.getElementById('gen-email-btn');
        const emailDisplay = document.getElementById('temp-email-display');
        genBtn.disabled = false;
        genBtn.innerText = 'Generar Dirección';
        emailDisplay.innerText = 'Error: ' + err.message;
        emailDisplay.style.color = 'var(--danger)';
        console.error('Error con Mail.tm:', err);
        
        // Mostrar alerta al usuario solo si no es modo silencioso
        if (!silent) {
            alert('Error al generar email temporal: ' + err.message + '\n\nPor favor, intenta nuevamente o verifica tu conexión.');
        } else {
            // En modo silencioso, mostrar mensaje más amigable
            emailDisplay.innerText = 'Haz clic en "Generar Dirección" para crear un email temporal';
            emailDisplay.style.color = 'var(--text-dim)';
        }
        
        // Restaurar después de 5 segundos si no es modo silencioso
        if (!silent) {
            setTimeout(() => {
                if (emailDisplay.innerText.startsWith('Error:')) {
                    emailDisplay.innerText = 'Haz clic en "Generar Dirección"';
                    emailDisplay.style.color = 'var(--text-dim)';
                }
            }, 5000);
        }
    }
}

async function refreshInboxTM() {
    if (!currentToken) {
        const listEl = document.getElementById('inbox-list');
        if (listEl) {
            listEl.innerHTML = '<p class="empty-msg">No hay token de autenticación. Genera un email primero.</p>';
        }
        return;
    }
    const listEl = document.getElementById('inbox-list');
    if (!listEl) return;

    try {
        console.log('Refrescando inbox con token:', currentToken ? currentToken.substring(0, 20) + '...' : 'NO HAY TOKEN');
        
        const response = await fetch('/proxy/mailtm/messages', {
            headers: { 'Authorization': `Bearer ${currentToken}` }
        });
        
        console.log('Respuesta del servidor:', response.status, response.statusText);
        
        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            console.error('Error en respuesta:', errorData);
            throw new Error(errorData.error || `Error ${response.status}`);
        }
        
        const data = await response.json();
        console.log('Datos recibidos:', data);
        console.log('Tipo de datos:', typeof data, 'Es array:', Array.isArray(data));
        
        // Manejar diferentes formatos de respuesta (array directo o objeto con hydra:member)
        let messages = [];
        if (Array.isArray(data)) {
            messages = data;
            console.log('Usando array directo, mensajes encontrados:', messages.length);
        } else if (data['hydra:member'] && Array.isArray(data['hydra:member'])) {
            messages = data['hydra:member'];
            console.log('Usando hydra:member, mensajes encontrados:', messages.length);
        } else if (data['member'] && Array.isArray(data['member'])) {
            messages = data['member'];
            console.log('Usando member, mensajes encontrados:', messages.length);
        } else if (data.error) {
            throw new Error(data.error);
        } else {
            console.warn('Formato de respuesta no reconocido:', data);
        }

        if (messages.length === 0) {
            if (listEl.children.length <= 1) {
                listEl.innerHTML = '<p class="empty-msg">Esperando emails... (Refresco automático cada 5s)</p>';
            }
            return;
        }

        listEl.innerHTML = '';
        messages.forEach(msg => {
            // Verificar que el mensaje tenga la estructura esperada
            if (!msg || !msg.id) {
                console.warn('Mensaje con formato inesperado:', msg);
                return;
            }
            
            const div = document.createElement('div');
            div.className = 'inbox-item';
            
            // Manejar diferentes formatos de remitente
            const fromAddress = msg.from?.address || msg.from?.name || msg.from || '(Desconocido)';
            const subject = msg.subject || msg.title || '(Sin Asunto)';
            
            div.innerHTML = `
                <div class="meta">
                    <span class="subject">${subject}</span>
                    <span class="sender">De: ${fromAddress}</span>
                </div>
                <button class="mini-btn">ANALIZAR</button>
            `;
            div.onclick = () => readAndAnalyzeTM(msg.id);
            listEl.appendChild(div);
        });
    } catch (err) {
        console.error('Error al sincronizar mensajes:', err);
        if (listEl) {
            listEl.innerHTML = `<p class="empty-msg" style="color: var(--danger)">Error: ${err.message}</p>`;
        }
    }
}

async function readAndAnalyzeTM(msgId) {
    showLoading('Descargando y analizando contenido HTML de Mail.tm...');
    try {
        const response = await fetch(`/proxy/mailtm/read-message?id=${msgId}`, {
            headers: { 'Authorization': `Bearer ${currentToken}` }
        });
        const fullMsg = await response.json();
        const content = fullMsg.html ? fullMsg.html.join('') : (fullMsg.text || '');

        const analyzeRes = await fetch('/analyze-email', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ content: content })
        });
        const data = await analyzeRes.json();
        displayResults(data);
    } catch (err) { alert('Error en el análisis TM: ' + err.message); }
    finally { hideLoading(); }
}

async function analyzeURL() {
    const urlInput = document.getElementById('url-input').value.trim();
    if (!urlInput) return;
    showLoading('Escaneando el dominio en tiempo real...');
    try {
        const response = await fetch('/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: urlInput })
        });
        const data = await response.json();
        if (data.error) throw new Error(data.error);
        displayResults(data);
    } catch (err) { alert(err.message); }
    finally { hideLoading(); }
}

async function analyzeSMS() {
    const sender = document.getElementById('sms-sender').value.trim();
    const content = document.getElementById('sms-content').value.trim();
    if (!content) return;
    showLoading('Analizando reporte de Smishing...');
    try {
        const res = await fetch('/analyze-sms', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ sender, content })
        });
        const data = await res.json();
        displayResults(data);
    } catch (e) { alert(e.message); }
    finally { hideLoading(); }
}

function showLoading(text) {
    const loadingEl = document.getElementById('loading');
    if (loadingEl) {
        loadingEl.querySelector('p').innerText = text;
        loadingEl.classList.remove('hidden');
    }
    const resultsEl = document.getElementById('results');
    if (resultsEl) resultsEl.classList.add('hidden');
}

function hideLoading() {
    const loadingEl = document.getElementById('loading');
    if (loadingEl) loadingEl.classList.add('hidden');
}

function displayResults(data) {
    document.getElementById('results').classList.remove('hidden');
    const factorsList = document.getElementById('risk-factors');
    factorsList.innerHTML = '';

    // Referencias a todas las tarjetas
    const allCards = Array.from(document.querySelectorAll('.card'));
    const getCard = (text) => allCards.find(c => c.querySelector('h3')?.innerText.includes(text));

    const cards = {
        ssl: getCard('Certificado SSL'),
        domain: getCard('Propiedades del Dominio'),
        links: document.getElementById('url-list-card'),
        email: document.getElementById('email-details-card'),
        reputation: document.getElementById('reputation-card'),
        malware: getCard('Reputación & Malware'),
        ai: document.getElementById('ai-analysis-card')
    };

    // 1. Resetear visibilidad (ocultar todo por defecto) y estilos de grid
    Object.values(cards).forEach(c => { 
        if (c) {
            c.style.display = 'none';
            c.style.gridColumn = ''; // Resetear gridColumn
        }
    });

    // 2. Lógica de visibilidad inteligente
    const hasUrls = data.urls_found && data.urls_found.length > 0;

    if (data.type === 'email') {
        if (cards.reputation) cards.reputation.style.display = 'block';
        if (cards.email) cards.email.style.display = 'block';
        if (cards.links && hasUrls) cards.links.style.display = 'block';
        if (cards.ssl && hasUrls) cards.ssl.style.display = 'block';
        if (cards.malware && hasUrls) cards.malware.style.display = 'block';
        if (cards.ai && data.ai_analysis) {
            cards.ai.style.display = 'block';
            // En emails: ocupar el ancho restante (span 2 columnas)
            cards.ai.style.gridColumn = 'span 2';
        }

        renderReputation(data);
        renderEmailResults(data, factorsList);
        renderAIAnalysis(data.ai_analysis);
    } else if (data.type === 'sms') {
        if (cards.reputation) cards.reputation.style.display = 'block';
        if (cards.links && hasUrls) cards.links.style.display = 'block';
        if (cards.ssl && hasUrls) cards.ssl.style.display = 'block';
        if (cards.malware && hasUrls) cards.malware.style.display = 'block';
        if (cards.ai && data.ai_analysis) {
            cards.ai.style.display = 'block';
            // En SMS: mantener el tamaño normal (no cambiar)
            cards.ai.style.gridColumn = '';
        }

        renderReputation(data);
        renderSMSResults(data, factorsList);
        renderAIAnalysis(data.ai_analysis);
    } else {
        // Análisis de URL Individual
        if (cards.ssl) cards.ssl.style.display = 'block';
        if (cards.domain) cards.domain.style.display = 'block';
        if (cards.malware) cards.malware.style.display = 'block';
        if (cards.ai && data.ai_analysis) {
            cards.ai.style.display = 'block';
            // En URL: ocupar todo el ancho (nueva línea completa)
            cards.ai.style.gridColumn = '1 / -1';
        }
        renderURLResults(data, factorsList);
        renderAIAnalysis(data.ai_analysis);
    }
}

function renderReputation(data) {
    const target = data.sender_address || data.sender_phone || data.reputation_query;
    const infoDiv = document.getElementById('reputation-info');
    if (!infoDiv) return;

    if (!target) {
        infoDiv.innerHTML = '<p class="empty-msg">No se detectó remitente original.</p>';
        return;
    }

    const isEmail = target.includes('@');
    let html = `<p style="margin-bottom:15px; color:var(--accent-primary)">Análisis de reputación para: <strong>${target}</strong></p>`;

    // --- INTEGRACIÓN DE RESULTADOS LISTASPAM ENRIQUECIDOS ---
    if (data.phone_reputation) {
        const rep = data.phone_reputation;
        const statusLower = rep.status.toLowerCase();
        const color = (statusLower.includes('peligroso') || statusLower.includes('negativa')) ? 'var(--danger)' : 'var(--warning)';

        html += `
            <div style="background: rgba(255,255,255,0.05); padding: 18px; border-radius: 12px; margin-bottom: 20px; border-left: 4px solid ${color}">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
                    <span style="font-size: 1.2rem; font-weight: 700; color: ${color}; text-transform: uppercase;">${rep.status}</span>
                    <span style="font-size: 0.8rem; background: rgba(255,255,255,0.1); padding: 4px 10px; border-radius: 20px;">${rep.searches} búsquedas</span>
                </div>
                
                <div style="font-size: 0.95rem; margin-bottom: 12px;">Denuncias activas: <strong style="color: ${color}">${rep.reports}</strong></div>
                
                <div style="font-size: 0.8rem; border-top: 1px solid rgba(255,255,255,0.05); padding-top: 10px;">
                    <span style="color: var(--text-dim); display: block; margin-bottom: 5px;">Palabras clave detectadas:</span>
                    <div style="line-height:1.4; color: var(--accent-primary); font-style: italic;">${rep.tags}</div>
                </div>
            </div>
        `;
    }

    if (isEmail) {
        html += `
            <a href="https://www.google.com/search?q=%22${target}%22+scam+report" target="_blank" class="reputation-link">🔍 Buscar reportes de estafa en Google</a>
            <a href="https://scamsearch.io/search?q=${target}" target="_blank" class="reputation-link">🛡️ Consultar en ScamSearch.io</a>
            <a href="https://haveibeenpwned.com/unifiedsearch/${target}" target="_blank" class="reputation-link">🔑 Buscar en HaveIBeenPwned</a>
        `;
    } else {
        html += `
            <a href="https://www.tellows.es/num/${target}" target="_blank" class="reputation-link">☎️ Consultar reputación en Tellows</a>
            <a href="https://www.listaspam.com/busca.php?Telefono=${target}" target="_blank" class="reputation-link">🚫 Ver detalles en ListaSpam</a>
            <a href="https://www.google.com/search?q=quien+llama+${target}" target="_blank" class="reputation-link">🔍 Buscar en Google "Quién Llama"</a>
        `;
    }
    infoDiv.innerHTML = html;
}

function renderSMSResults(data, factorsList) {
    updateRiskMeter(data.risk_score);
    factorsList.innerHTML = '';

    if (data.risk_factors && data.risk_factors.length > 0) {
        data.risk_factors.forEach(f => {
            const li = document.createElement('li');
            li.innerText = f;
            factorsList.appendChild(li);
        });
    } else {
        factorsList.innerHTML = '<li style="color: var(--success)">Contenido aparentemente limpio.</li>';
    }

    if (data.urls_found.length > 0) {
        const worst = data.urls_found.reduce((a, b) => a.risk_score > b.risk_score ? a : b);
        renderSingleURLDetails(worst);

        const urlContainer = document.getElementById('url-list-container');
        if (urlContainer) {
            document.getElementById('url-list-card').style.display = 'block';
            urlContainer.innerHTML = '';
            data.urls_found.forEach(res => {
                const div = document.createElement('div');
                div.className = 'url-item';
                const riskColor = res.risk_score > 50 ? 'var(--danger)' : (res.risk_score > 20 ? 'var(--warning)' : 'var(--success)');
                
                // Verificar si hay resultados en VirusTotal para mostrar el botón MÁS
                const hasVTResults = res.virustotal && 
                                    (res.virustotal.malicious > 0 || res.virustotal.suspicious > 0);
                
                div.innerHTML = `
                    <div style="display: flex; justify-content: space-between; align-items: flex-start;">
                        <div><strong style="color:${riskColor}">${res.risk_score}%</strong> <span>${res.domain}</span></div>
                        ${hasVTResults ? '<button class="mini-btn">MÁS</button>' : ''}
                    </div>
                `;
                if (hasVTResults) {
                    div.querySelector('button').onclick = (e) => {
                        e.stopPropagation();
                        displaySingleFromList(res);
                    };
                }
                urlContainer.appendChild(div);
            });
        }
    }
}

function renderAIAnalysis(aiData) {
    const aiInfoDiv = document.getElementById('ai-analysis-info');
    if (!aiInfoDiv) return;

    if (!aiData) {
        aiInfoDiv.innerHTML = '<p class="empty-msg">Análisis de IA no disponible.</p>';
        return;
    }

    if (!aiData.enabled) {
        const message = aiData.analysis || 'Análisis de IA no disponible.';
        aiInfoDiv.innerHTML = `<p class="empty-msg">${message}</p>`;
        return;
    }

    const riskScore = aiData.risk_score || 0;
    const riskLevel = aiData.risk_level || 'medio';
    const analysis = aiData.analysis || 'Sin análisis disponible';
    const reasoning = aiData.reasoning || '';
    const confidence = aiData.confidence || 0;

    // Determinar color según el nivel de riesgo
    let riskColor = 'var(--success)';
    if (riskScore >= 70) {
        riskColor = 'var(--danger)';
    } else if (riskScore >= 40) {
        riskColor = 'var(--warning)';
    }

    // Determinar color del nivel de riesgo
    let levelColor = 'var(--success)';
    let levelText = 'BAJO';
    if (riskLevel === 'alto' || riskLevel === 'high') {
        levelColor = 'var(--danger)';
        levelText = 'ALTO';
    } else if (riskLevel === 'medio' || riskLevel === 'medium') {
        levelColor = 'var(--warning)';
        levelText = 'MEDIO';
    }

    let html = `
        <div style="background: rgba(255,255,255,0.05); padding: 18px; border-radius: 12px; margin-bottom: 15px; border-left: 4px solid ${riskColor}">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
                <div>
                    <span style="font-size: 1.2rem; font-weight: 700; color: ${riskColor};">${riskScore}%</span>
                    <span style="font-size: 0.9rem; color: var(--text-dim); margin-left: 10px;">Riesgo</span>
                </div>
                <span style="font-size: 0.9rem; background: ${levelColor}; padding: 4px 12px; border-radius: 20px; font-weight: 600;">${levelText}</span>
            </div>
            
            <div style="font-size: 0.95rem; margin-bottom: 12px; color: var(--text-primary);">
                <strong>Análisis:</strong> ${analysis}
            </div>
            
            ${reasoning ? `
            <div style="font-size: 0.85rem; border-top: 1px solid rgba(255,255,255,0.05); padding-top: 12px; color: var(--text-dim); line-height: 1.6;">
                <strong style="color: var(--accent-primary);">Razonamiento:</strong><br>
                ${reasoning}
            </div>
            ` : ''}
            
            <div style="font-size: 0.8rem; margin-top: 12px; color: var(--text-dim);">
                Confianza: <strong style="color: var(--accent-primary);">${confidence}%</strong>
            </div>
        </div>
    `;

    // Añadir línea en el risk meter global
    const factorsList = document.getElementById('risk-factors');
    if (factorsList) {
        const aiFactor = document.createElement('li');
        aiFactor.style.color = riskColor;
        aiFactor.innerHTML = `🤖 <strong>Análisis de IA:</strong> ${riskScore}% de riesgo (${levelText.toLowerCase()}) - Confianza: ${confidence}%`;
        factorsList.appendChild(aiFactor);
    }

    aiInfoDiv.innerHTML = html;
}

function renderURLResults(data, factorsList) {
    updateRiskMeter(data.risk_score);

    if (factorsList) {
        if (data.risk_factors && data.risk_factors.length === 0) {
            factorsList.innerHTML = '<li style="color: var(--success); font-weight: 400;">No se detectaron factores de riesgo inmediatos.</li>';
        } else if (data.risk_factors) {
            data.risk_factors.forEach(f => {
                const li = document.createElement('li');
                li.innerText = f;
                factorsList.appendChild(li);
            });
        }
    }

    const sslStatus = document.getElementById('ssl-status');
    if (sslStatus && data.ssl) {
        sslStatus.innerText = data.ssl.status || 'N/A';
        sslStatus.className = 'status-badge ' + (data.ssl.status === 'Secure' ? 'status-safe' : 'status-danger');
    }

    const sslInfo = document.getElementById('ssl-info');
    if (sslInfo && data.ssl) {
        sslInfo.innerHTML = `
            <div class="info-item"><span class="info-label">Emisor</span><span class="info-val">${data.ssl.issuer || 'N/A'}</span></div>
            <div class="info-item"><span class="info-label">Caducidad</span><span class="info-val">${data.ssl.valid_to || 'N/A'}</span></div>
        `;
    }

    const domainAge = document.getElementById('domain-age');
    if (domainAge && data.whois) {
        domainAge.innerHTML = `
            <div class="info-item"><span class="info-label">Antigüedad</span><span class="info-val">${data.whois.age_years || 0}a ${data.whois.age_months || 0}m</span></div>
            <div class="info-item"><span class="info-label">Reciente</span><span class="info-val">${data.whois.is_recent ? 'Sí' : 'No'}</span></div>
        `;
    }

    if (data.virustotal) renderVT(data.virustotal);
    const urlListCard = document.getElementById('url-list-card');
    if (urlListCard) urlListCard.style.display = 'none';
}

function renderEmailResults(data, factorsList) {
    updateRiskMeter(data.email_risk_score);

    if (factorsList) {
        if (data.email_factors && data.email_factors.length === 0) {
            factorsList.innerHTML = '<li style="color: var(--success); font-weight: 400;">Contenido aparentemente limpio.</li>';
        } else if (data.email_factors) {
            data.email_factors.forEach(f => {
                const li = document.createElement('li');
                li.innerText = f;
                factorsList.appendChild(li);
            });
        }
    }

    const emailInfo = document.getElementById('email-info');
    if (emailInfo) {
        emailInfo.innerHTML = `
            <div class="info-item"><span class="info-label">URLs encontradas</span><span class="info-val">${data.urls_found ? data.urls_found.length : 0}</span></div>
            <div class="info-item"><span class="info-label">Palabras sospechosas</span><span class="info-val">${data.keywords_found ? data.keywords_found.length : 0}</span></div>
            <div class="info-item"><span class="info-label">Faltas ortografía</span><span class="info-val">${data.spelling ? data.spelling.misspelled_count : 0}</span></div>
            <div class="info-item" style="flex-direction: column; align-items: flex-start;">
                <span class="info-label">Ejemplos ortografía:</span>
                <span class="info-val" style="text-align: left; max-width: 100%; font-size: 0.8rem; color: var(--warning)">${(data.spelling && data.spelling.misspelled_examples) ? data.spelling.misspelled_examples.join(', ') : 'Ninguna'}</span>
            </div>
        `;
    }

    const urlContainer = document.getElementById('url-list-container');
    const urlListCard = document.getElementById('url-list-card');
    if (urlListCard) urlListCard.style.display = 'block';

    if (urlContainer) {
        urlContainer.innerHTML = '';
        if (!data.urls_found || data.urls_found.length === 0) {
            urlContainer.innerHTML = '<p class="empty-msg">No se detectaron enlaces.</p>';
        } else {
            // Filtrar por URL completa o hostname completo, no solo por dominio base
            const uniqueUrls = [];
            const seenUrls = new Set();
            data.urls_found.forEach(res => {
                // Usar hostname completo si está disponible, sino usar domain, sino usar URL
                const uniqueKey = res.hostname || res.domain || res.url;
                if (!seenUrls.has(uniqueKey)) {
                    uniqueUrls.push(res);
                    seenUrls.add(uniqueKey);
                }
            });

            uniqueUrls.forEach(res => {
                const div = document.createElement('div');
                div.className = 'url-item';
                const riskColor = res.risk_score > 50 ? 'var(--danger)' : (res.risk_score > 20 ? 'var(--warning)' : 'var(--success)');
                // Mostrar hostname completo si está disponible, sino mostrar domain
                const displayDomain = res.hostname || res.domain;
                
                // Verificar si hay resultados en VirusTotal para mostrar el botón MÁS
                const hasVTResults = res.virustotal && 
                                    (res.virustotal.malicious > 0 || res.virustotal.suspicious > 0);
                
                div.innerHTML = `
                    <div style="display: flex; justify-content: space-between; align-items: flex-start;">
                        <div style="overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 80%;">
                            <strong style="color: ${riskColor}">${res.risk_score}%</strong> 
                            <span>${displayDomain}</span>
                        </div>
                        ${hasVTResults ? '<button class="mini-btn">MÁS</button>' : ''}
                    </div>
                    ${res.is_redirected ? `<div class="redirect-info">↳ ${displayDomain} (vía tracker)</div>` : ''}
                `;
                if (hasVTResults) {
                    div.querySelector('button').onclick = (e) => {
                        e.stopPropagation();
                        displaySingleFromList(res);
                    };
                }
                urlContainer.appendChild(div);
            });
        }
    }

    if (data.urls_found && data.urls_found.length > 0) {
        const worstUrl = data.urls_found.reduce((prev, current) => (prev.risk_score > current.risk_score) ? prev : current);
        renderSingleURLDetails(worstUrl);
    }
}

function displaySingleFromList(res) {
    renderSingleURLDetails(res);
    document.querySelector('.grid').scrollIntoView({ behavior: 'smooth' });
}

function renderSingleURLDetails(data) {
    if (!data) return;
    const sslStatus = document.getElementById('ssl-status');
    if (sslStatus && data.ssl) {
        sslStatus.innerText = data.ssl.status || 'N/A';
        sslStatus.className = 'status-badge ' + (data.ssl.status === 'Secure' ? 'status-safe' : 'status-danger');
    }

    const sslInfo = document.getElementById('ssl-info');
    if (sslInfo && data.ssl) {
        sslInfo.innerHTML = `
            <div class="info-item"><span class="info-label">Emisor</span><span class="info-val">${data.ssl.issuer || 'N/A'}</span></div>
            <div class="info-item"><span class="info-label">Caducidad</span><span class="info-val">${data.ssl.valid_to || 'N/A'}</span></div>
        `;
    }

    const domainAge = document.getElementById('domain-age');
    if (domainAge && data.whois) {
        domainAge.innerHTML = `
            <div class="info-item"><span class="info-label">Antigüedad</span><span class="info-val">${data.whois.age_years || 0}a ${data.whois.age_months || 0}m</span></div>
            <div class="info-item"><span class="info-label">Reciente</span><span class="info-val">${data.whois.is_recent ? 'Sí' : 'No'}</span></div>
        `;
    }
    if (data.virustotal) renderVT(data.virustotal);
}

function updateRiskMeter(score) {
    const scoreEl = document.getElementById('risk-score');
    if (scoreEl) scoreEl.innerText = score + '%';
    const gaugePath = document.getElementById('gauge-path');
    if (gaugePath) {
        const circumference = 125.6;
        const offset = circumference - (score / 100) * circumference;
        gaugePath.style.strokeDashoffset = offset;
    }
}

function renderVT(vt) {
    const vtInfo = document.getElementById('vt-info');
    if (!vtInfo) return;
    if (vt.message === 'API Key not configured') {
        vtInfo.innerHTML = '<p style="font-size: 0.7rem; color: var(--text-dim)">VT API Key no configurada.</p>';
    } else if (vt.error) {
        vtInfo.innerHTML = `<p style="color: var(--danger)">${vt.error}</p>`;
    } else {
        let html = `
            <div class="info-item"><span class="info-label">Malicioso</span><span class="info-val" style="color: var(--danger)">${vt.malicious || 0}</span></div>
            <div class="info-item"><span class="info-label">Sospechoso</span><span class="info-val" style="color: var(--warning)">${vt.suspicious || 0}</span></div>
        `;
        
        // Mostrar listado de detecciones si hay
        if (vt.detections && vt.detections.length > 0) {
            html += `<div style="margin-top: 15px; border-top: 1px solid rgba(255,255,255,0.1); padding-top: 15px;">`;
            html += `<div style="font-size: 0.85rem; font-weight: 600; margin-bottom: 10px; color: var(--accent-primary)">Detecciones encontradas:</div>`;
            html += `<div style="max-height: 200px; overflow-y: auto; font-size: 0.8rem;">`;
            
            vt.detections.forEach((det, idx) => {
                const isMalicious = det.result && det.result.toLowerCase().includes('malicious');
                const color = isMalicious ? 'var(--danger)' : 'var(--warning)';
                html += `
                    <div style="padding: 8px; margin-bottom: 6px; background: rgba(255,255,255,0.03); border-radius: 6px; border-left: 3px solid ${color}">
                        <div style="font-weight: 600; color: ${color}">${det.engine || 'Unknown'}</div>
                        <div style="font-size: 0.75rem; color: var(--text-dim); margin-top: 4px;">
                            ${det.result || 'Detected'}${det.method ? ` (${det.method})` : ''}
                        </div>
                    </div>
                `;
            });
            
            if (vt.detections.length >= 20) {
                html += `<div style="font-size: 0.7rem; color: var(--text-dim); margin-top: 8px; font-style: italic;">Mostrando primeras 20 detecciones...</div>`;
            }
            
            html += `</div></div>`;
        }
        
        if (vt.message) {
            html += `<p style="font-size: 0.75rem; color: var(--text-dim); margin-top: 10px; border-top: 1px solid rgba(255,255,255,0.05); padding-top: 10px;">${vt.message}</p>`;
        }
        vtInfo.innerHTML = html;
    }
}
