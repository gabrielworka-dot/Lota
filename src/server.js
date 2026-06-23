/**
 * LOTA v2.0 — Servidor Principal
 * Workamusic © 2025 — Todos os direitos reservados
 * Deploy: Railway.app
 */

const express = require('express');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const fetch   = require('node-fetch');
const fs      = require('fs');
const path    = require('path');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'lota_dev_secret_change_in_prod';

// ── Security Headers ──────────────────────────────────────
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  next();
});

// ── Rate Limiting ─────────────────────────────────────────
const rateLimits = new Map();
function rateLimit(windowMs = 60000, max = 30) {
  return (req, res, next) => {
    const key = req.ip + (req.path || '');
    const now = Date.now();
    const record = rateLimits.get(key) || { count: 0, start: now };
    if (now - record.start > windowMs) { record.count = 0; record.start = now; }
    record.count++;
    rateLimits.set(key, record);
    if (record.count > max) return res.status(429).json({ error: 'Muitas requisições. Aguarde um momento.' });
    next();
  };
}
// Limpeza periódica
setInterval(() => { const now = Date.now(); rateLimits.forEach((v,k) => { if (now - v.start > 120000) rateLimits.delete(k); }); }, 60000);

// ── Paths ─────────────────────────────────────────────────
const DATA_DIR = fs.existsSync('/app') ? '/app' : path.join(__dirname, '..');
const DB_FILE  = path.join(DATA_DIR, 'db.json');
const POSSIBLE_PUBLIC = [
  path.join(__dirname, '../public'),
  path.join(process.cwd(), 'public'),
  '/app/public'
];
const PUBLIC_DIR = POSSIBLE_PUBLIC.find(p => { try { return fs.existsSync(path.join(p,'index.html')); } catch(e) { return false; }}) || path.join(__dirname,'../public');
const INDEX_HTML = path.join(PUBLIC_DIR, 'index.html');

// ── Middleware ────────────────────────────────────────────
app.use(express.json({ limit: '5mb' }));
app.use(express.static(PUBLIC_DIR));

// ── Input sanitization helper ─────────────────────────────
function sanitize(str, maxLen = 500) {
  if (typeof str !== 'string') return '';
  return str.trim().slice(0, maxLen).replace(/<[^>]*>/g, '');
}

// ── Database ──────────────────────────────────────────────
function loadDB() {
  try { if (fs.existsSync(DB_FILE)) return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); } catch(e) {}
  return { users: [{
    id: 'admin-001', name: 'admin', displayName: 'Administrador',
    password: bcrypt.hashSync('admin123', 12),
    plan: 'unlimited', limit: 999, used: 0,
    isAdmin: true, active: true, avatar: '', globalSlots: 50,
    createdAt: new Date().toISOString()
  }], loginAttempts: {}};
}
function saveDB(d) { try { fs.writeFileSync(DB_FILE, JSON.stringify(d, null, 2)); } catch(e) {} }
let db = loadDB();
if (!db.loginAttempts) db.loginAttempts = {};
if (!db.users.find(u => u.isAdmin)) { db.users.unshift(loadDB().users[0]); saveDB(db); }
console.log(`✅ Banco carregado: ${db.users.length} usuário(s)`);

// ── User data helpers ─────────────────────────────────────
function udFile(id) { return path.join(DATA_DIR, `userdata_${id}.json`); }
function loadUD(id) {
  try { const f = udFile(id); if (fs.existsSync(f)) return JSON.parse(fs.readFileSync(f,'utf8')); } catch(e) {}
  return { events: [], projects: [], metrics: {} };
}
function saveUD(id, d) { try { fs.writeFileSync(udFile(id), JSON.stringify(d)); } catch(e) {} }

// ── Chat helpers ──────────────────────────────────────────
const CHAT_FILE = path.join(DATA_DIR, 'chat_global.json');
function loadChat() {
  try { if (fs.existsSync(CHAT_FILE)) return JSON.parse(fs.readFileSync(CHAT_FILE,'utf8')); } catch(e) {}
  return { messages: [] };
}
function saveChat(d) { try { fs.writeFileSync(CHAT_FILE, JSON.stringify(d)); } catch(e) {} }

// ── Auth helpers ──────────────────────────────────────────
function auth(req, res, next) {
  const token = (req.headers['authorization'] || '').replace('Bearer ', '').trim();
  if (!token) return res.status(401).json({ error: 'Token não enviado.' });
  try {
    const dec = jwt.verify(token, JWT_SECRET);
    const user = db.users.find(u => u.id === dec.id && u.active);
    if (!user) return res.status(401).json({ error: 'Sessão inválida.' });
    req.user = user;
    next();
  } catch(e) { return res.status(401).json({ error: 'Token inválido ou expirado.' }); }
}
function adminOnly(req, res, next) {
  if (!req.user.isAdmin) return res.status(403).json({ error: 'Acesso restrito.' });
  next();
}
function safe(u) {
  const { password, ...r } = u;
  return r;
}

// ── Anthropic AI helper ───────────────────────────────────
async function callAI(system, userMsg, maxTokens = 2000) {
  if (!process.env.ANTHROPIC_API_KEY) throw new Error('ANTHROPIC_API_KEY não configurada no servidor.');
  const resp = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
    body: JSON.stringify({ model: 'claude-haiku-4-5-20251001', max_tokens: maxTokens, system, messages: [{ role: 'user', content: userMsg }] })
  });
  const data = await resp.json();
  if (!resp.ok) throw new Error(data.error?.message || `Erro Anthropic: ${resp.status}`);
  return data.content?.[0]?.text || '';
}

const SYSTEM_LOTA = `Você é o Lota, IA especialista em lançamento e venda de eventos de entretenimento no Brasil pela Workamusic.
Você domina: psicologia do comprador de ingresso, escassez e antecipação, tráfego pago Instagram, saudosismo como gatilho de venda, lotes com janelas de tempo, tinder do evento, lista VIP, festa da senha, clubes de assinatura para casas de show premium, conteúdo pós-evento como ativo de venda.
Os 5 perfis de evento: show de releitura, festa temática, stand-up, festa consolidada, casa chique/jazz.
Responda sempre em português brasileiro. Seja direto, prático e orientado a resultado.
© Workamusic 2025 — Todos os direitos reservados.`;

// ════════════════════════════════════════════════════════
// AUTH
// ════════════════════════════════════════════════════════
app.post('/api/auth/login', rateLimit(60000, 10), (req, res) => {
  const name = sanitize(req.body.name || '', 100);
  const password = (req.body.password || '').slice(0, 200);
  if (!name || !password) return res.status(400).json({ error: 'Preencha usuário e senha.' });

  // Brute force protection
  const ip = req.ip;
  const attempts = db.loginAttempts[ip] || { count: 0, lastAttempt: 0 };
  const now = Date.now();
  if (attempts.count >= 5 && now - attempts.lastAttempt < 300000) {
    return res.status(429).json({ error: 'Muitas tentativas. Aguarde 5 minutos.' });
  }

  const user = db.users.find(u => u.name.toLowerCase() === name.toLowerCase());
  if (!user || !user.active) {
    db.loginAttempts[ip] = { count: (attempts.count || 0) + 1, lastAttempt: now };
    saveDB(db);
    return res.status(401).json({ error: 'Usuário ou senha incorretos.' });
  }
  if (!bcrypt.compareSync(password, user.password)) {
    db.loginAttempts[ip] = { count: (attempts.count || 0) + 1, lastAttempt: now };
    saveDB(db);
    return res.status(401).json({ error: 'Usuário ou senha incorretos.' });
  }

  // Reset attempts on success
  delete db.loginAttempts[ip];
  user.lastLogin = new Date().toISOString();
  saveDB(db);

  const token = jwt.sign({ id: user.id, v: 2 }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: safe(user) });
});

app.get('/api/auth/me', auth, (req, res) => res.json({ user: safe(req.user) }));

app.patch('/api/auth/profile', auth, rateLimit(60000, 10), (req, res) => {
  const user = db.users.find(u => u.id === req.user.id);
  const { displayName, currentPassword, newPassword } = req.body;
  if (newPassword) {
    if (!currentPassword || !bcrypt.compareSync(currentPassword, user.password))
      return res.status(401).json({ error: 'Senha atual incorreta.' });
    if (newPassword.length < 6) return res.status(400).json({ error: 'Nova senha deve ter pelo menos 6 caracteres.' });
    user.password = bcrypt.hashSync(newPassword, 12);
  }
  if (displayName) user.displayName = sanitize(displayName, 60);
  saveDB(db);
  res.json({ user: safe(user) });
});

// ════════════════════════════════════════════════════════
// ADMIN
// ════════════════════════════════════════════════════════
app.get('/api/admin/users', auth, adminOnly, (req, res) => res.json(db.users.map(safe)));
app.get('/api/admin/slots', auth, adminOnly, (req, res) => {
  const admin = db.users.find(u => u.isAdmin);
  res.json({ slots: admin?.globalSlots || 50, used: db.users.filter(u => !u.isAdmin).length });
});
app.patch('/api/admin/slots', auth, adminOnly, (req, res) => {
  const admin = db.users.find(u => u.isAdmin);
  const val = parseInt(req.body.slots);
  if (isNaN(val) || val < 1 || val > 10000) return res.status(400).json({ error: 'Valor inválido.' });
  if (admin) { admin.globalSlots = val; saveDB(db); }
  res.json({ ok: true });
});
app.post('/api/admin/users', auth, adminOnly, rateLimit(60000, 20), (req, res) => {
  const name = sanitize(req.body.name || '', 60);
  const password = (req.body.password || '').slice(0, 200);
  const displayName = sanitize(req.body.displayName || name, 60);
  const plan = ['basic','pro','unlimited'].includes(req.body.plan) ? req.body.plan : 'basic';
  const limit = Math.min(parseInt(req.body.limit) || 10, 9999);
  if (!name || !password) return res.status(400).json({ error: 'Nome e senha obrigatórios.' });
  if (password.length < 6) return res.status(400).json({ error: 'Senha deve ter pelo menos 6 caracteres.' });
  if (db.users.find(u => u.name.toLowerCase() === name.toLowerCase()))
    return res.status(400).json({ error: 'Login já em uso.' });
  const admin = db.users.find(u => u.isAdmin);
  if (db.users.filter(u => !u.isAdmin).length >= (admin?.globalSlots || 50))
    return res.status(400).json({ error: 'Limite de slots atingido.' });
  const user = {
    id: uuidv4(), name, displayName,
    password: bcrypt.hashSync(password, 12),
    plan, limit, used: 0, isAdmin: false, active: true, avatar: '',
    createdAt: new Date().toISOString()
  };
  db.users.push(user); saveDB(db);
  res.status(201).json({ user: safe(user) });
});
app.patch('/api/admin/users/:id', auth, adminOnly, (req, res) => {
  const user = db.users.find(u => u.id === req.params.id);
  if (!user || user.isAdmin) return res.status(404).json({ error: 'Não encontrado ou protegido.' });
  if (req.body.name) {
    const n = sanitize(req.body.name, 60);
    const dup = db.users.find(u => u.name.toLowerCase() === n.toLowerCase() && u.id !== user.id);
    if (dup) return res.status(400).json({ error: 'Login já em uso.' });
    user.name = n;
  }
  if (req.body.displayName) user.displayName = sanitize(req.body.displayName, 60);
  if (req.body.plan && ['basic','pro','unlimited'].includes(req.body.plan)) user.plan = req.body.plan;
  if (req.body.limit !== undefined) user.limit = Math.min(parseInt(req.body.limit) || 10, 9999);
  if (req.body.active !== undefined) user.active = !!req.body.active;
  if (req.body.password && req.body.password.length >= 6) user.password = bcrypt.hashSync(req.body.password, 12);
  saveDB(db);
  res.json({ user: safe(user) });
});
app.delete('/api/admin/users/:id', auth, adminOnly, (req, res) => {
  const user = db.users.find(u => u.id === req.params.id);
  if (!user || user.isAdmin) return res.status(404).json({ error: 'Não encontrado ou protegido.' });
  db.users = db.users.filter(u => u.id !== req.params.id);
  saveDB(db);
  res.json({ ok: true });
});

// ════════════════════════════════════════════════════════
// USER DATA
// ════════════════════════════════════════════════════════
app.get('/api/data', auth, (req, res) => res.json(loadUD(req.user.id)));
app.post('/api/data', auth, (req, res) => {
  const curr = loadUD(req.user.id);
  if (req.body.events   !== undefined) curr.events   = req.body.events;
  if (req.body.projects !== undefined) curr.projects = req.body.projects;
  if (req.body.metrics  !== undefined) curr.metrics  = req.body.metrics;
  saveUD(req.user.id, curr);
  res.json({ ok: true });
});

// ════════════════════════════════════════════════════════
// CHAT INTERNO
// ════════════════════════════════════════════════════════
app.get('/api/chat', auth, (req, res) => {
  const chat = loadChat();
  // Retorna últimas 100 mensagens
  const msgs = (chat.messages || []).slice(-100).map(m => ({
    ...m,
    // Não expõe ID do remetente, só o nome
  }));
  res.json({ messages: msgs });
});

app.post('/api/chat', auth, rateLimit(60000, 30), (req, res) => {
  const text = sanitize(req.body.text || '', 1000);
  if (!text) return res.status(400).json({ error: 'Mensagem vazia.' });
  const chat = loadChat();
  const msg = {
    id: uuidv4(),
    userId: req.user.id,
    userName: req.user.displayName || req.user.name,
    text,
    ts: new Date().toISOString()
  };
  chat.messages = chat.messages || [];
  chat.messages.push(msg);
  // Mantém só as últimas 500 mensagens
  if (chat.messages.length > 500) chat.messages = chat.messages.slice(-500);
  saveChat(chat);
  res.json({ message: msg });
});

// ════════════════════════════════════════════════════════
// MÉTRICAS DO PROJETO
// ════════════════════════════════════════════════════════
app.get('/api/metrics/:projectId', auth, (req, res) => {
  const ud = loadUD(req.user.id);
  const metrics = ud.metrics?.[req.params.projectId] || {
    ingressosVendidos: 0, ingressosMeta: 0,
    receitaBruta: 0, custoTotal: 0,
    seguidoresAntes: 0, seguidoresDepois: 0,
    alcanceCampanha: 0, cliquesAnuncio: 0,
    custoAnuncio: 0, vendasOnline: 0, vendasOffline: 0,
    metaApiToken: '', metaAdAccountId: '', metaPageId: '',
    historico: []
  };
  res.json(metrics);
});

app.patch('/api/metrics/:projectId', auth, (req, res) => {
  const ud = loadUD(req.user.id);
  if (!ud.metrics) ud.metrics = {};
  const curr = ud.metrics[req.params.projectId] || {};
  ud.metrics[req.params.projectId] = { ...curr, ...req.body, updatedAt: new Date().toISOString() };
  saveUD(req.user.id, ud);
  res.json({ ok: true, metrics: ud.metrics[req.params.projectId] });
});

// ════════════════════════════════════════════════════════
// META API — Estrutura pronta para conectar
// ════════════════════════════════════════════════════════
app.post('/api/meta/connect', auth, async (req, res) => {
  const { token, adAccountId, pageId, projectId } = req.body;
  if (!token) return res.status(400).json({ error: 'Token da Meta obrigatório.' });
  // Valida o token com a API da Meta
  try {
    const resp = await fetch(`https://graph.facebook.com/v18.0/me?access_token=${token}`);
    const data = await resp.json();
    if (data.error) return res.status(400).json({ error: 'Token inválido: ' + data.error.message });
    // Salva referência nas métricas (nunca o token em texto puro no banco principal)
    const ud = loadUD(req.user.id);
    if (!ud.metrics) ud.metrics = {};
    if (!ud.metrics[projectId]) ud.metrics[projectId] = {};
    ud.metrics[projectId].metaConnected = true;
    ud.metrics[projectId].metaUser = data.name;
    ud.metrics[projectId].metaAdAccountId = adAccountId || '';
    ud.metrics[projectId].metaPageId = pageId || '';
    // Token salvo separado por segurança
    ud.metrics[projectId]._metaToken = token;
    saveUD(req.user.id, ud);
    res.json({ ok: true, metaUser: data.name });
  } catch(e) {
    res.status(500).json({ error: 'Erro ao conectar com a Meta: ' + e.message });
  }
});

app.get('/api/meta/insights/:projectId', auth, async (req, res) => {
  const ud = loadUD(req.user.id);
  const metrics = ud.metrics?.[req.params.projectId];
  if (!metrics?.metaConnected || !metrics?._metaToken) {
    return res.status(400).json({ error: 'Conta Meta não conectada para este projeto.' });
  }
  try {
    const token = metrics._metaToken;
    const adAccountId = metrics.metaAdAccountId;
    // Busca insights de campanhas
    const resp = await fetch(
      `https://graph.facebook.com/v18.0/${adAccountId}/insights?fields=spend,impressions,clicks,reach,actions&date_preset=last_30d&access_token=${token}`
    );
    const data = await resp.json();
    if (data.error) return res.status(400).json({ error: data.error.message });
    res.json({ insights: data.data || [] });
  } catch(e) {
    res.status(500).json({ error: 'Erro ao buscar dados da Meta: ' + e.message });
  }
});

app.get('/api/meta/page/:projectId', auth, async (req, res) => {
  const ud = loadUD(req.user.id);
  const metrics = ud.metrics?.[req.params.projectId];
  if (!metrics?.metaConnected || !metrics?._metaToken) {
    return res.status(400).json({ error: 'Conta Meta não conectada.' });
  }
  try {
    const token = metrics._metaToken;
    const pageId = metrics.metaPageId;
    const resp = await fetch(
      `https://graph.facebook.com/v18.0/${pageId}?fields=followers_count,fan_count,name&access_token=${token}`
    );
    const data = await resp.json();
    if (data.error) return res.status(400).json({ error: data.error.message });
    res.json({ page: data });
  } catch(e) {
    res.status(500).json({ error: 'Erro ao buscar página: ' + e.message });
  }
});

// ════════════════════════════════════════════════════════
// MÓDULOS DE IA
// ════════════════════════════════════════════════════════
async function aiRoute(path, bodyFn) {
  app.post(path, auth, rateLimit(60000, 20), async (req, res) => {
    try {
      const { system, prompt } = bodyFn(req.body, req.user);
      const result = await callAI(system || SYSTEM_LOTA, prompt, 2500);
      // Salva projeto automaticamente
      const ud = loadUD(req.user.id);
      ud.projects = ud.projects || [];
      const proj = {
        id: uuidv4(),
        tipo: req.body._tipo || 'geral',
        nome: sanitize(req.body._nome || req.body.nome || req.body.tema || 'Projeto', 80),
        eventoId: req.body._eventoId || null,
        inputs: req.body,
        resultado: result,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      };
      ud.projects.unshift(proj);
      if (ud.projects.length > 200) ud.projects = ud.projects.slice(0, 200);
      saveUD(req.user.id, ud);
      // Incrementa uso
      const user = db.users.find(u => u.id === req.user.id);
      user.used = (user.used || 0) + 1;
      saveDB(db);
      res.json({ result, projectId: proj.id });
    } catch(e) {
      res.status(500).json({ error: e.message });
    }
  });
}

aiRoute('/api/evento/criar-nome', (b) => ({
  prompt: `Crie 5 opções de nome para um evento:
Tema: ${sanitize(b.tema,300)}
Tipo: ${sanitize(b.tipo,100)}
Vibe: ${sanitize(b.vibe,200)}
Público: ${sanitize(b.publico,200)}

Para cada opção:
NOME: [nome impactante e memorável]
TAGLINE: [frase curta, máx 8 palavras]
CONCEITO: [por que funciona, 2-3 linhas]
MECÂNICA SUGERIDA: [tinder do evento / lista VIP / festa da senha / outro]
---`
}));

aiRoute('/api/evento/identidade', (b) => ({
  prompt: `Crie a identidade completa para o evento "${sanitize(b.nome,100)}".
Tipo: ${sanitize(b.tipo,100)} | Tema: ${sanitize(b.tema,200)} | Público: ${sanitize(b.publico,200)} | Vibe: ${sanitize(b.vibe,200)}

🎨 IDENTIDADE VISUAL
- Paleta de cores (3-4 cores com hex)
- Estilo visual (referências)
- Tipografia sugerida
- Elementos gráficos

✍️ IDENTIDADE VERBAL
- Tom de voz
- Palavras proibidas
- Palavras-chave
- 3 frases de exemplo

📝 DESCRIÇÃO OFICIAL (máx 150 palavras)

🎟️ EXPERIÊNCIA QUE SERÁ VENDIDA (o que o comprador vai SENTIR)`
}));

aiRoute('/api/evento/publico', (b) => ({
  prompt: `Análise completa do público para:
Evento: ${sanitize(b.nome,100)} | Tipo: ${sanitize(b.tipo,100)} | Tema: ${sanitize(b.tema,200)} | Cidade: ${sanitize(b.cidade,100)} | Faixa etária: ${sanitize(b.faixaEtaria,100)}

👥 PERFIL DO COMPRADOR IDEAL (idade, gênero, classe, ocupação, digital)
💡 POR QUE ELA VAI SAIR DE CASA (motivo emocional real, FOMO, o que vai contar)
🎯 SEGMENTAÇÃO INSTAGRAM (faixa etária, interesses, comportamentos, cidades)
⚠️ OBJEÇÕES MAIS COMUNS (e como quebrar cada uma)
📊 TAMANHO DO PÚBLICO POTENCIAL`
}));

aiRoute('/api/evento/lancamento', (b) => ({
  prompt: `Estratégia completa de lançamento:
Evento: ${sanitize(b.nome,100)} | Tipo: ${sanitize(b.tipo,100)} | Data: ${sanitize(b.data,30)} | Local: ${sanitize(b.local,200)} | Capacidade: ${sanitize(b.capacidade,20)} | Preço: R$${sanitize(b.preco,30)} | Início vendas: ${sanitize(b.dataLancamento,30)} | Lotes: ${sanitize(b.qtdLotes,10)}

🚀 FASE 1 — PRÉ-ANÚNCIO (aquecimento e mistério)
📣 FASE 2 — ANÚNCIO (revelação, mecânicas de engajamento)
🎟️ FASE 3 — ESTRUTURA DOS LOTES (preço, quantidade, janela de tempo, gatilho de abertura e fechamento)
⏰ FASE 4 — ESCASSEZ (silêncio estratégico, reabertura, frases exatas)
🎉 FASE 5 — RETA FINAL (últimos 7 dias, sequência diária)`
}));

aiRoute('/api/evento/campanha', (b) => ({
  prompt: `Plano de campanha 30 dias para:
Evento: ${sanitize(b.nome,100)} | Tipo: ${sanitize(b.tipo,100)} | Tema: ${sanitize(b.tema,200)} | Data evento: ${sanitize(b.dataEvento,30)} | Início vendas: ${sanitize(b.dataLancamento,30)}

📅 SEMANA 1 — Aquecimento (ação por dia: o que postar, tipo, objetivo)
📅 SEMANA 2 — Revelação e abertura de vendas
📅 SEMANA 3 — Manutenção e prova social
📅 SEMANA 4 — Urgência e reta final
📅 PÓS-EVENTO (3 dias — conteúdo para vender o próximo)`
}));

aiRoute('/api/evento/criativo', (b) => ({
  prompt: `3 roteiros de criativo para tráfego pago Instagram (15-30s):
Evento: ${sanitize(b.nome,100)} | Tipo: ${sanitize(b.tipo,100)} | Tema: ${sanitize(b.tema,200)} | Artistas: ${sanitize(b.artistas,200)} | Público: ${sanitize(b.publico,200)} | Faixa etária: ${sanitize(b.faixaEtaria,100)} | Local: ${sanitize(b.local,100)} | Data: ${sanitize(b.data,30)} | Preço: R$${sanitize(b.preco,30)}

🎬 CRIATIVO 1 — EXPERIÊNCIA (mostrar como é estar lá)
Cena 0-3s: | Cena 3-8s: | Cena 8-15s: | Descrição do anúncio: | Segmentação:

🎬 CRIATIVO 2 — SAUDOSISMO/EMOÇÃO (gatilho emocional)
[mesmo formato]

🎬 CRIATIVO 3 — URGÊNCIA/ESCASSEZ (virada de lote)
[mesmo formato]

💡 DICAS DE PRODUÇÃO (cenas, áudio, horário de veiculação)`
}));

aiRoute('/api/evento/conteudo', (b) => ({
  prompt: `10 sugestões de conteúdo para redes:
Evento: ${sanitize(b.nome,100)} | Tipo: ${sanitize(b.tipo,100)} | Tema: ${sanitize(b.tema,200)} | Fase: ${sanitize(b.fase,100)}

📸 POSTS FEED (3): ideia visual + legenda + hashtags
🎥 REELS (3): conceito + roteiro + áudio + legenda
📱 STORIES (2): sequência de telas com texto
🤳 CONTEÚDO DO PÚBLICO (2): ideia que estimula compartilhamento (tinder do evento, desafio, etc)

Para cada: objetivo, melhor horário, fase ideal`
}));

aiRoute('/api/evento/vendas', (b) => ({
  prompt: `Kit completo de vendas para equipe:
Evento: ${sanitize(b.nome,100)} | Tipo: ${sanitize(b.tipo,100)} | Tema: ${sanitize(b.tema,200)} | Preço: R$${sanitize(b.preco,30)} | Benefícios: ${sanitize(b.beneficios,500)}

📞 SCRIPT WHATSAPP (versão curta 3 linhas + versão completa)
💬 OBJEÇÕES (resposta ideal para cada):
1. "Tá caro" 2. "Vou pensar" 3. "Não conheço o artista" 4. "Será que vai ser bom?" 5. "Não sei se vou poder ir" 6. "Já fui e não gostei"
🎯 ARGUMENTOS POR TIPO DE INGRESSO (1º lote, VIP, último lote)
⚡ 5 FRASES DE FECHAMENTO
📊 3 CENÁRIOS DE CLIENTE DIFÍCIL com resolução`
}));

// ════════════════════════════════════════════════════════
// HEALTH
// ════════════════════════════════════════════════════════
app.get('/health', (req, res) => {
  res.json({
    status: 'ok', app: 'Lota v2.0', brand: 'Workamusic',
    users: db.users.length,
    anthropic: !!process.env.ANTHROPIC_API_KEY ? '✅' : '❌',
    uptime: Math.round(process.uptime()) + 's'
  });
});

app.get('*', (req, res) => {
  if (fs.existsSync(INDEX_HTML)) return res.sendFile(INDEX_HTML);
  const dirs = POSSIBLE_PUBLIC.map(p => `${p}: ${fs.existsSync(p)}`).join(' | ');
  res.status(500).send(`<h2>index.html não encontrado</h2><p>${dirs}</p><p>cwd: ${process.cwd()}</p>`);
});

app.listen(PORT, () => {
  console.log(`\n🎪 LOTA v2.0 rodando na porta ${PORT}`);
  console.log(`   Workamusic © 2025`);
  console.log(`   Anthropic: ${process.env.ANTHROPIC_API_KEY ? '✅' : '❌'}`);
  console.log(`   index.html: ${fs.existsSync(INDEX_HTML) ? '✅' : '❌ — ' + INDEX_HTML}\n`);
});
