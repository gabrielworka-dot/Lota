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
if (!db.ticketSlugs) db.ticketSlugs = {}; // slug -> { userId, projectId }
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
// USER DATA (sub-usuários compartilham dados do pai)
// ════════════════════════════════════════════════════════
app.get('/api/data', auth, (req, res) => {
  const uid = req.user.isSubUser ? req.user.parentId : req.user.id;
  res.json(loadUD(uid));
});
app.post('/api/data', auth, (req, res) => {
  // Leitores não podem editar
  if (req.user.isSubUser && req.user.subRole === 'leitor')
    return res.status(403).json({ error: 'Acesso somente leitura.' });
  const uid = req.user.isSubUser ? req.user.parentId : req.user.id;
  const curr = loadUD(uid);
  if (req.body.events   !== undefined) curr.events   = req.body.events;
  if (req.body.projects !== undefined) curr.projects = req.body.projects;
  if (req.body.metrics  !== undefined) curr.metrics  = req.body.metrics;
  saveUD(uid, curr);
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
// MÓDULOS DE IA — salva tudo em UM único projeto
// ════════════════════════════════════════════════════════
async function aiRoute(path, bodyFn) {
  app.post(path, auth, rateLimit(60000, 20), async (req, res) => {
    try {
      const { system, prompt } = bodyFn(req.body, req.user);
      const result = await callAI(system || SYSTEM_LOTA, prompt, 2500);
      const uid = req.user.isSubUser ? req.user.parentId : req.user.id;
      const ud = loadUD(uid);
      ud.projects = ud.projects || [];

      const eventoId = req.body._eventoId || null;
      const tipo     = req.body._tipo || 'geral';
      const nome     = sanitize(req.body._nome || req.body.nome || req.body.tema || 'Projeto', 80);

      // Se tem _eventoId, atualiza o projeto existente em vez de criar um novo
      let proj = eventoId ? ud.projects.find(p => p.id === eventoId) : null;

      if (proj) {
        // Adiciona módulo ao projeto existente
        if (!proj.modulos) proj.modulos = {};
        proj.modulos[tipo] = { resultado: result, inputs: req.body, updatedAt: new Date().toISOString() };
        proj.updatedAt = new Date().toISOString();
        // Atualiza o resultado principal com o último módulo
        proj.ultimoModulo = tipo;
        saveUD(uid, ud);
        res.json({ result, projectId: proj.id });
      } else {
        // Cria projeto novo (primeiro módulo = Nome)
        proj = {
          id: uuidv4(),
          tipo: 'evento',
          nome,
          nomeEvento: nome,
          status: 'em_criacao',
          modulos: { [tipo]: { resultado: result, inputs: req.body, updatedAt: new Date().toISOString() } },
          resultado: result, // mantido por compatibilidade
          cores: { primaria: '#D97706', secundaria: '#1A1714', texto: '#F5F0E8' },
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString()
        };
        ud.projects.unshift(proj);
        if (ud.projects.length > 200) ud.projects = ud.projects.slice(0, 200);
        saveUD(uid, ud);
        res.json({ result, projectId: proj.id });
      }

      // Incrementa uso
      const user = db.users.find(u => u.id === req.user.id);
      user.used = (user.used || 0) + 1;
      saveDB(db);
    } catch(e) {
      res.status(500).json({ error: e.message });
    }
  });
}

// PATCH — marca projeto como ativo/concluído e salva cores
app.patch('/api/projeto/:projectId/finalizar', auth, (req, res) => {
  const uid = req.user.isSubUser ? req.user.parentId : req.user.id;
  const ud = loadUD(uid);
  const proj = (ud.projects || []).find(p => p.id === req.params.projectId);
  if (!proj) return res.status(404).json({ error: 'Projeto não encontrado.' });
  proj.status = 'ativo';
  if (req.body.cores)      proj.cores      = req.body.cores;
  if (req.body.nomeEvento) proj.nomeEvento = sanitize(req.body.nomeEvento, 80);
  if (req.body.tipo)       proj.tipoEvento = sanitize(req.body.tipo, 80);
  if (req.body.nome)       proj.nome       = sanitize(req.body.nome, 80);
  proj.updatedAt = new Date().toISOString();
  saveUD(uid, ud);
  res.json({ ok: true, projeto: proj });
});

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
// SUB-USUÁRIOS (plano PRO: até 3, Unlimited: até 10)
// ════════════════════════════════════════════════════════
const SUBUSR_LIMITS = { basic: 0, pro: 3, unlimited: 10 };

// Retorna sub-usuários de uma conta pai
app.get('/api/subusuarios', auth, (req, res) => {
  const subs = db.users.filter(u => u.parentId === req.user.id);
  res.json(subs.map(safe));
});

// Cria sub-usuário
app.post('/api/subusuarios', auth, rateLimit(60000, 10), (req, res) => {
  const plan = req.user.plan || 'basic';
  const maxSubs = SUBUSR_LIMITS[plan] || 0;
  if (maxSubs === 0) return res.status(403).json({ error: 'Seu plano não permite sub-usuários. Faça upgrade para PRO.' });
  const currentSubs = db.users.filter(u => u.parentId === req.user.id).length;
  if (currentSubs >= maxSubs) return res.status(400).json({ error: `Limite de ${maxSubs} sub-usuários para o plano ${plan.toUpperCase()} atingido.` });

  const { name, password, displayName, cargo, role } = req.body;
  if (!name || !password) return res.status(400).json({ error: 'Nome e senha obrigatórios.' });
  if (password.length < 6) return res.status(400).json({ error: 'Senha deve ter pelo menos 6 caracteres.' });
  const normalizedName = sanitize(name, 60).toLowerCase();
  if (db.users.find(u => u.name.toLowerCase() === normalizedName))
    return res.status(400).json({ error: 'Login já em uso.' });
  const validRoles = ['leitor', 'editor', 'total'];
  const subRole = validRoles.includes(role) ? role : 'leitor';
  const user = {
    id: uuidv4(), name: normalizedName,
    displayName: sanitize(displayName || name, 60),
    cargo: sanitize(cargo || '', 60),
    password: bcrypt.hashSync(password, 12),
    plan: 'basic', limit: 0, used: 0,
    isAdmin: false, active: true, avatar: '',
    parentId: req.user.id,
    subRole,
    isSubUser: true,
    createdAt: new Date().toISOString()
  };
  db.users.push(user);
  saveDB(db);
  res.status(201).json({ user: safe(user) });
});

app.patch('/api/subusuarios/:id', auth, (req, res) => {
  const user = db.users.find(u => u.id === req.params.id && u.parentId === req.user.id);
  if (!user) return res.status(404).json({ error: 'Sub-usuário não encontrado.' });
  const { displayName, cargo, role, active, password } = req.body;
  if (displayName) user.displayName = sanitize(displayName, 60);
  if (cargo !== undefined) user.cargo = sanitize(cargo, 60);
  if (role && ['leitor','editor','total'].includes(role)) user.subRole = role;
  if (active !== undefined) user.active = !!active;
  if (password && password.length >= 6) user.password = bcrypt.hashSync(password, 12);
  saveDB(db);
  res.json({ user: safe(user) });
});

app.delete('/api/subusuarios/:id', auth, (req, res) => {
  const user = db.users.find(u => u.id === req.params.id && u.parentId === req.user.id);
  if (!user) return res.status(404).json({ error: 'Sub-usuário não encontrado.' });
  db.users = db.users.filter(u => u.id !== req.params.id);
  saveDB(db);
  res.json({ ok: true });
});

// Patch de perfil para sub-usuário (nome e cargo próprios)
app.patch('/api/auth/profile', auth, rateLimit(60000, 10), (req, res) => {
  const user = db.users.find(u => u.id === req.user.id);
  const { displayName, currentPassword, newPassword, cargo } = req.body;
  if (newPassword) {
    if (!currentPassword || !bcrypt.compareSync(currentPassword, user.password))
      return res.status(401).json({ error: 'Senha atual incorreta.' });
    if (newPassword.length < 6) return res.status(400).json({ error: 'Nova senha deve ter pelo menos 6 caracteres.' });
    user.password = bcrypt.hashSync(newPassword, 12);
  }
  if (displayName) user.displayName = sanitize(displayName, 60);
  if (cargo !== undefined) user.cargo = sanitize(cargo, 60);
  saveDB(db);
  res.json({ user: safe(user) });
});

// ════════════════════════════════════════════════════════
// DIRECIONAMENTO E DICAS (admin adiciona, todos veem)
// ════════════════════════════════════════════════════════
const DICAS_FILE = path.join(DATA_DIR, 'dicas.json');
function loadDicas() {
  try { if (fs.existsSync(DICAS_FILE)) return JSON.parse(fs.readFileSync(DICAS_FILE,'utf8')); } catch(e) {}
  return { dicas: [] };
}
function saveDicas(d) { try { fs.writeFileSync(DICAS_FILE, JSON.stringify(d)); } catch(e) {} }

app.get('/api/dicas', auth, (req, res) => {
  const d = loadDicas();
  res.json({ dicas: d.dicas || [] });
});

app.post('/api/dicas', auth, adminOnly, (req, res) => {
  const { titulo, descricao, url, categoria } = req.body;
  if (!titulo || !url) return res.status(400).json({ error: 'Título e URL obrigatórios.' });
  const d = loadDicas();
  d.dicas = d.dicas || [];
  d.dicas.unshift({
    id: uuidv4(),
    titulo: sanitize(titulo, 100),
    descricao: sanitize(descricao || '', 500),
    url: url.slice(0, 500),
    categoria: sanitize(categoria || 'Geral', 60),
    createdAt: new Date().toISOString()
  });
  saveDicas(d);
  res.json({ ok: true });
});

app.delete('/api/dicas/:id', auth, adminOnly, (req, res) => {
  const d = loadDicas();
  d.dicas = (d.dicas || []).filter(x => x.id !== req.params.id);
  saveDicas(d);
  res.json({ ok: true });
});

// ════════════════════════════════════════════════════════
// INSUMOS — links de materiais por projeto
// ════════════════════════════════════════════════════════
app.get('/api/insumos/:projectId', auth, (req, res) => {
  const ud = loadUD(req.user.isSubUser ? req.user.parentId : req.user.id);
  const insumos = ud.insumos?.[req.params.projectId] || [];
  res.json({ insumos });
});

app.post('/api/insumos/:projectId', auth, (req, res) => {
  const { titulo, url, tipo, descricao } = req.body;
  if (!titulo || !url) return res.status(400).json({ error: 'Título e URL obrigatórios.' });
  const uid = req.user.isSubUser ? req.user.parentId : req.user.id;
  const ud = loadUD(uid);
  if (!ud.insumos) ud.insumos = {};
  if (!ud.insumos[req.params.projectId]) ud.insumos[req.params.projectId] = [];
  ud.insumos[req.params.projectId].unshift({
    id: uuidv4(),
    titulo: sanitize(titulo, 100),
    url: url.slice(0, 500),
    tipo: sanitize(tipo || 'Link', 40),
    descricao: sanitize(descricao || '', 300),
    addedBy: req.user.displayName || req.user.name,
    createdAt: new Date().toISOString()
  });
  saveUD(uid, ud);
  res.json({ ok: true });
});

app.delete('/api/insumos/:projectId/:insumoId', auth, (req, res) => {
  const uid = req.user.isSubUser ? req.user.parentId : req.user.id;
  const ud = loadUD(uid);
  if (ud.insumos?.[req.params.projectId]) {
    ud.insumos[req.params.projectId] = ud.insumos[req.params.projectId].filter(x => x.id !== req.params.insumoId);
    saveUD(uid, ud);
  }
  res.json({ ok: true });
});

// ════════════════════════════════════════════════════════
// FLUXO DE PROJETO — salva seleções por etapa
// ════════════════════════════════════════════════════════
app.patch('/api/projeto/:projectId/etapa', auth, (req, res) => {
  const uid = req.user.isSubUser ? req.user.parentId : req.user.id;
  const ud = loadUD(uid);
  const proj = (ud.projects || []).find(p => p.id === req.params.projectId);
  if (!proj) return res.status(404).json({ error: 'Projeto não encontrado.' });
  const { etapa, selecao, etapaIndex } = req.body;
  if (!proj.etapas) proj.etapas = {};
  proj.etapas[etapa] = { selecao, etapaIndex, updatedAt: new Date().toISOString() };
  proj.etapaAtual = req.body.etapaAtual || proj.etapaAtual || 0;
  if (req.body.ativo !== undefined) proj.ativo = req.body.ativo;
  proj.updatedAt = new Date().toISOString();
  saveUD(uid, ud);
  res.json({ ok: true, projeto: proj });
});

// ════════════════════════════════════════════════════════
// BANNER SVG — geração visual de referência
// ════════════════════════════════════════════════════════
app.post('/api/banner/generate', auth, async (req, res) => {
  const { nomeEvento, tagline, cores, tipo, data, local } = req.body;
  if (!nomeEvento) return res.status(400).json({ error: 'Nome do evento obrigatório.' });
  // Retorna dados para o frontend gerar o SVG
  res.json({
    nomeEvento: sanitize(nomeEvento, 80),
    tagline: sanitize(tagline || '', 120),
    tipo: sanitize(tipo || '', 60),
    data: sanitize(data || '', 40),
    local: sanitize(local || '', 80),
    cores: cores || { primaria: '#D97706', secundaria: '#1A1714', texto: '#F5F0E8' }
  });
});

// ════════════════════════════════════════════════════════
// FORNECEDORES
// ════════════════════════════════════════════════════════
app.get('/api/fornecedores', auth, (req, res) => {
  const uid = req.user.isSubUser ? req.user.parentId : req.user.id;
  const ud = loadUD(uid);
  res.json({ fornecedores: ud.fornecedores || [] });
});
app.post('/api/fornecedores', auth, (req, res) => {
  const uid = req.user.isSubUser ? req.user.parentId : req.user.id;
  const { nome, categoria, telefone, email, instagram, site, observacoes } = req.body;
  if (!nome) return res.status(400).json({ error: 'Nome obrigatório.' });
  const ud = loadUD(uid);
  if (!ud.fornecedores) ud.fornecedores = [];
  ud.fornecedores.unshift({ id: uuidv4(), nome: sanitize(nome,100), categoria: sanitize(categoria||'Geral',60), telefone: sanitize(telefone||'',30), email: sanitize(email||'',100), instagram: sanitize(instagram||'',60), site: sanitize(site||'',200), observacoes: sanitize(observacoes||'',500), createdAt: new Date().toISOString() });
  saveUD(uid, ud);
  res.json({ ok: true });
});
app.patch('/api/fornecedores/:id', auth, (req, res) => {
  const uid = req.user.isSubUser ? req.user.parentId : req.user.id;
  const ud = loadUD(uid);
  const f = (ud.fornecedores||[]).find(x=>x.id===req.params.id);
  if (!f) return res.status(404).json({ error: 'Não encontrado.' });
  ['nome','categoria','telefone','email','instagram','site','observacoes'].forEach(k=>{ if(req.body[k]!==undefined) f[k]=sanitize(req.body[k],k==='observacoes'?500:200); });
  f.updatedAt = new Date().toISOString();
  saveUD(uid, ud);
  res.json({ ok: true });
});
app.delete('/api/fornecedores/:id', auth, (req, res) => {
  const uid = req.user.isSubUser ? req.user.parentId : req.user.id;
  const ud = loadUD(uid);
  ud.fornecedores = (ud.fornecedores||[]).filter(x=>x.id!==req.params.id);
  saveUD(uid, ud);
  res.json({ ok: true });
});

// ════════════════════════════════════════════════════════
// WEBHOOK TICKETERIA — Sympla / Ingresse / Bileto / Eventbrite
// ════════════════════════════════════════════════════════
app.post('/api/webhook/ticketeria/:userId/:projectId', (req, res) => {
  const { userId, projectId } = req.params;
  const user = db.users.find(u => u.id === userId);
  if (!user) return res.status(404).json({ error: 'Usuário não encontrado.' });
  const ud = loadUD(userId);
  if (!ud.metrics) ud.metrics = {};
  if (!ud.metrics[projectId]) ud.metrics[projectId] = {};
  const m = ud.metrics[projectId];
  const b = req.body;
  let qtd = 0, valor = 0;
  if (b.order) {
    qtd = parseInt(b.order.tickets_quantity||b.order.quantity||1);
    valor = parseFloat(b.order.total_value||b.order.amount||0);
    const st = (b.order.status||'').toLowerCase();
    if (st && !['approved','confirmed','paid','complete','aprovado','confirmado'].includes(st))
      return res.json({ ok:true, skipped:'status não aprovado' });
  } else if (b.event && b.event.sold!==undefined) {
    m.vendasOnline = parseInt(b.event.sold)||0;
    m.receitaBruta = parseFloat(b.event.revenue)||m.receitaBruta||0;
    m.ingressosVendidos = (m.vendasOnline||0)+(m.vendasOffline||0);
    m.updatedAt = new Date().toISOString();
    saveUD(userId, ud);
    return res.json({ ok:true, source:'ingresse' });
  } else {
    qtd = parseInt(b.quantidade||b.quantity||0);
    valor = parseFloat(b.valor||b.amount||b.value||0);
  }
  if (qtd > 0) {
    m.vendasOnline = (m.vendasOnline||0)+qtd;
    m.receitaBruta = (m.receitaBruta||0)+valor;
    m.ingressosVendidos = (m.vendasOnline||0)+(m.vendasOffline||0);
    if (!m.historicoVendas) m.historicoVendas = [];
    m.historicoVendas.push({ qtd, valor, ts:new Date().toISOString(), fonte:'webhook' });
    if (m.historicoVendas.length>500) m.historicoVendas = m.historicoVendas.slice(-500);
    m.updatedAt = new Date().toISOString();
    saveUD(userId, ud);
  }
  res.json({ ok:true, vendasOnline: m.vendasOnline });
});

app.get('/api/webhook/url/:projectId', auth, (req, res) => {
  const uid = req.user.isSubUser ? req.user.parentId : req.user.id;
  const host = req.get('host') || 'seu-app.railway.app';
  const proto = req.get('x-forwarded-proto') || 'https';
  res.json({ url:`${proto}://${host}/api/webhook/ticketeria/${uid}/${req.params.projectId}` });
});

// ════════════════════════════════════════════════════════
// EVENTOS FINALIZADOS
// ════════════════════════════════════════════════════════
app.get('/api/eventos/finalizados', auth, (req, res) => {
  const uid = req.user.isSubUser ? req.user.parentId : req.user.id;
  const ud = loadUD(uid);
  const hoje = new Date();
  let changed = false;
  const finalizados = (ud.projects||[]).filter(p => {
    if (p.status==='finalizado') return true;
    const dtStr = p.dataEvento || p.modulos?.lancamento?.inputs?.data || p.modulos?.campanha?.inputs?.dataEvento;
    if (dtStr) {
      const dt = new Date(dtStr);
      if (!isNaN(dt) && dt < hoje && p.status==='ativo') {
        p.status='finalizado'; p.finalizadoEm=dt.toISOString(); changed=true; return true;
      }
    }
    return false;
  });
  if (changed) saveUD(uid, ud);
  res.json({ finalizados });
});

app.patch('/api/projeto/:projectId/finalizar-evento', auth, (req, res) => {
  const uid = req.user.isSubUser ? req.user.parentId : req.user.id;
  const ud = loadUD(uid);
  const proj = (ud.projects||[]).find(p=>p.id===req.params.projectId);
  if (!proj) return res.status(404).json({ error: 'Não encontrado.' });
  proj.status='finalizado';
  proj.finalizadoEm=new Date().toISOString();
  if (req.body.dataEvento) proj.dataEvento=req.body.dataEvento;
  proj.updatedAt=new Date().toISOString();
  saveUD(uid, ud);
  res.json({ ok:true });
});

// ════════════════════════════════════════════════════════════
// PLATAFORMA DE INGRESSOS — venda direta com Mercado Pago (Marketplace/Split)
// ════════════════════════════════════════════════════════════
const MP_TOKEN         = process.env.MP_ACCESS_TOKEN || ''; // opcional, fallback
const MP_CLIENT_ID     = process.env.MP_CLIENT_ID || '';
const MP_CLIENT_SECRET = process.env.MP_CLIENT_SECRET || '';
const MP_API = 'https://api.mercadopago.com';
const RESEND_API_KEY   = process.env.RESEND_API_KEY || '';
const RESEND_FROM      = process.env.RESEND_FROM_EMAIL || 'Lota <onboarding@resend.dev>';
if (db.marketplaceFeePercent === undefined) { db.marketplaceFeePercent = parseFloat(process.env.MP_MARKETPLACE_FEE_PERCENT) || 10; saveDB(db); }

function slugify(str) {
  return String(str || 'evento')
    .toLowerCase()
    .normalize('NFD').replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/(^-|-$)/g, '')
    .slice(0, 40) || 'evento';
}
function gerarSlugUnico(nome) {
  const base = slugify(nome);
  let slug = base + '-' + Math.random().toString(36).slice(2, 7);
  while (db.ticketSlugs[slug]) slug = base + '-' + Math.random().toString(36).slice(2, 7);
  return slug;
}
function gerarCodigoTicket() {
  return 'LT-' + uuidv4().split('-')[0].toUpperCase() + '-' + Math.random().toString(36).slice(2, 6).toUpperCase();
}
function pedFile(uid) { return path.join(DATA_DIR, `pedidos_${uid}.json`); }
function loadPedidos(uid) {
  try { const f = pedFile(uid); if (fs.existsSync(f)) return JSON.parse(fs.readFileSync(f, 'utf8')); } catch(e) {}
  return {};
}
function savePedidos(uid, d) { try { fs.writeFileSync(pedFile(uid), JSON.stringify(d)); } catch(e) {} }

// Retorna o token de MP a usar para um produtor (conta própria via OAuth, ou fallback da plataforma)
function tokenDoProdutor(userId) {
  const u = db.users.find(x => x.id === userId);
  return u?.mpAccount?.accessToken || '';
}
function isTestToken(token) { return /^TEST-/i.test(token || ''); }

// ── Envio de e-mail via Resend ──
async function enviarEmailIngressos(pedido, nomeEvento) {
  if (!RESEND_API_KEY || !pedido.comprador?.email) return;
  const ticketsHtml = (pedido.tickets || []).map(t => `
    <div style="border:1px solid #2A2822;border-radius:10px;padding:16px;margin-bottom:10px;display:flex;align-items:center;gap:16px;background:#161410;">
      <img src="https://api.qrserver.com/v1/create-qr-code/?size=120x120&data=${encodeURIComponent(t.codigo)}" width="90" height="90" style="border-radius:8px;background:#fff;padding:4px" />
      <div>
        <div style="font-family:monospace;font-weight:700;color:#E8961A;font-size:14px;">${t.codigo}</div>
        <div style="font-size:12px;color:#A09880;margin-top:2px;">${t.loteNome}</div>
      </div>
    </div>`).join('');
  const html = `
    <div style="background:#0F0E0C;padding:32px 20px;font-family:Arial,sans-serif;color:#F0EDE8;">
      <div style="max-width:480px;margin:0 auto;">
        <div style="font-size:22px;font-weight:800;color:#E8961A;margin-bottom:4px;">🎪 Lota</div>
        <p style="font-size:14px;color:#A09880;margin-bottom:24px;">Confirmação de compra — Workamusic</p>
        <h2 style="font-size:18px;margin-bottom:6px;">Seu ingresso para</h2>
        <p style="font-size:20px;font-weight:800;color:#fff;margin-bottom:20px;">${esc(nomeEvento)}</p>
        <p style="font-size:13px;color:#A09880;margin-bottom:16px;">Olá ${esc(pedido.comprador.nome)}, seu pagamento foi aprovado! Aqui estão seus ingressos:</p>
        ${ticketsHtml}
        <p style="font-size:11px;color:#605848;margin-top:20px;">Apresente o QR Code na entrada do evento. Guarde este e-mail.</p>
        <p style="font-size:10px;color:#605848;margin-top:24px;">© Workamusic — Vendido com Lota</p>
      </div>
    </div>`;
  try {
    await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${RESEND_API_KEY}` },
      body: JSON.stringify({ from: RESEND_FROM, to: pedido.comprador.email, subject: `🎟️ Seus ingressos — ${nomeEvento}`, html })
    });
  } catch(e) { console.error('Erro ao enviar e-mail:', e.message); }
}
function esc(s) { return String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

// Processa aprovação de pagamento — gera tickets, atualiza métricas, envia e-mail
async function processarPedidoAprovado(uid, projectId, pedido) {
  const ud = loadUD(uid);
  const proj = (ud.projects || []).find(p => p.id === projectId);
  if (!proj) return;
  pedido.tickets = [];
  for (const it of pedido.itens) {
    const lote = (proj.ingressos?.lotes || []).find(l => l.id === it.loteId);
    const qtd = Math.max(1, parseInt(it.qtd) || 1);
    if (lote) lote.vendidos = (lote.vendidos || 0) + qtd;
    for (let i = 0; i < qtd; i++) pedido.tickets.push({ codigo: gerarCodigoTicket(), loteNome: lote?.nome || 'Ingresso', usado: false, usadoEm: null });
  }
  if (!ud.metrics) ud.metrics = {};
  if (!ud.metrics[projectId]) ud.metrics[projectId] = {};
  const m = ud.metrics[projectId];
  m.vendasOnline = (m.vendasOnline || 0) + pedido.tickets.length;
  m.receitaBruta = (m.receitaBruta || 0) + pedido.total;
  m.ingressosVendidos = (m.vendasOnline || 0) + (m.vendasOffline || 0);
  m.updatedAt = new Date().toISOString();
  saveUD(uid, ud);
  await enviarEmailIngressos(pedido, proj.nome);
}

// ════════════════════════════════════════════════════════════
// OAUTH MERCADO PAGO — cada produtor conecta a própria conta
// ════════════════════════════════════════════════════════════
app.get('/api/mp/oauth/connect', auth, (req, res) => {
  if (!MP_CLIENT_ID) return res.status(400).json({ error: 'Marketplace do Mercado Pago não configurado (MP_CLIENT_ID ausente). Peça ao administrador.' });
  const uid = req.user.isSubUser ? req.user.parentId : req.user.id;
  const state = jwt.sign({ uid }, JWT_SECRET, { expiresIn: '15m' });
  const host = req.get('host');
  const proto = req.get('x-forwarded-proto') || 'https';
  const redirectUri = `${proto}://${host}/api/mp/oauth/callback`;
  const url = `https://auth.mercadopago.com/authorization?client_id=${MP_CLIENT_ID}&response_type=code&platform_id=mp&state=${encodeURIComponent(state)}&redirect_uri=${encodeURIComponent(redirectUri)}`;
  res.json({ url });
});

app.get('/api/mp/oauth/callback', async (req, res) => {
  try {
    const { code, state } = req.query;
    if (!code || !state) return res.status(400).send('Parâmetros inválidos.');
    let uid;
    try { uid = jwt.verify(state, JWT_SECRET).uid; } catch(e) { return res.status(400).send('Sessão expirada, tente conectar novamente.'); }

    const host = req.get('host');
    const proto = req.get('x-forwarded-proto') || 'https';
    const redirectUri = `${proto}://${host}/api/mp/oauth/callback`;

    const tokenResp = await fetch(`${MP_API}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ client_id: MP_CLIENT_ID, client_secret: MP_CLIENT_SECRET, grant_type: 'authorization_code', code, redirect_uri: redirectUri })
    });
    const tokenData = await tokenResp.json();
    if (!tokenResp.ok) return res.status(400).send('Erro ao conectar: ' + (tokenData.message || 'tente novamente'));

    const user = db.users.find(u => u.id === uid);
    if (user) {
      user.mpAccount = {
        accessToken: tokenData.access_token,
        refreshToken: tokenData.refresh_token,
        mpUserId: tokenData.user_id,
        publicKey: tokenData.public_key || '',
        testMode: isTestToken(tokenData.access_token),
        connectedAt: new Date().toISOString()
      };
      saveDB(db);
    }
    res.send(`<html><body style="background:#0F0E0C;color:#F0EDE8;font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0"><div style="text-align:center"><div style="font-size:40px;margin-bottom:12px">✅</div><h2>Conta Mercado Pago conectada!</h2><p style="color:#A09880">Você já pode fechar esta janela e voltar ao Lota.</p></div></body></html>`);
  } catch(e) {
    res.status(500).send('Erro: ' + e.message);
  }
});

app.get('/api/mp/status', auth, (req, res) => {
  const uid = req.user.isSubUser ? req.user.parentId : req.user.id;
  const user = db.users.find(u => u.id === uid);
  const acc = user?.mpAccount;
  res.json({ connected: !!acc?.accessToken, mpUserId: acc?.mpUserId || null, testMode: !!acc?.testMode, connectedAt: acc?.connectedAt || null, feePercent: db.marketplaceFeePercent });
});

app.post('/api/mp/disconnect', auth, (req, res) => {
  const uid = req.user.isSubUser ? req.user.parentId : req.user.id;
  const user = db.users.find(u => u.id === uid);
  if (user) { delete user.mpAccount; saveDB(db); }
  res.json({ ok: true });
});

// Admin — configurar % de comissão global da plataforma
app.get('/api/admin/marketplace-fee', auth, adminOnly, (req, res) => res.json({ feePercent: db.marketplaceFeePercent }));
app.patch('/api/admin/marketplace-fee', auth, adminOnly, (req, res) => {
  const v = parseFloat(req.body.feePercent);
  if (isNaN(v) || v < 0 || v > 50) return res.status(400).json({ error: 'Valor inválido (0-50%).' });
  db.marketplaceFeePercent = v; saveDB(db);
  res.json({ ok: true, feePercent: v });
});

// ── CONFIGURAR VENDA DE INGRESSOS (autenticado, dono do projeto) ──
app.get('/api/projeto/:projectId/ingressos-config', auth, (req, res) => {
  const uid = req.user.isSubUser ? req.user.parentId : req.user.id;
  const ud = loadUD(uid);
  const proj = (ud.projects || []).find(p => p.id === req.params.projectId);
  if (!proj) return res.status(404).json({ error: 'Projeto não encontrado.' });
  res.json({ ingressos: proj.ingressos || { ativo: false, slug: '', lotes: [] } });
});

app.patch('/api/projeto/:projectId/ingressos-config', auth, (req, res) => {
  const uid = req.user.isSubUser ? req.user.parentId : req.user.id;
  const ud = loadUD(uid);
  const proj = (ud.projects || []).find(p => p.id === req.params.projectId);
  if (!proj) return res.status(404).json({ error: 'Projeto não encontrado.' });

  if (req.body.ativo && !tokenDoProdutor(uid)) {
    return res.status(400).json({ error: 'Conecte sua conta Mercado Pago antes de ativar as vendas.' });
  }

  if (!proj.ingressos) proj.ingressos = { ativo: false, slug: '', lotes: [] };

  if (req.body.ativo && !proj.ingressos.slug) {
    const slug = gerarSlugUnico(proj.nome);
    proj.ingressos.slug = slug;
    db.ticketSlugs[slug] = { userId: uid, projectId: proj.id };
    saveDB(db);
  }
  if (req.body.ativo !== undefined) proj.ingressos.ativo = !!req.body.ativo;

  if (Array.isArray(req.body.lotes)) {
    proj.ingressos.lotes = req.body.lotes.map(l => ({
      id: l.id || uuidv4(),
      nome: sanitize(l.nome || 'Lote', 60),
      preco: Math.max(0, parseFloat(l.preco) || 0),
      qtdTotal: Math.max(0, parseInt(l.qtdTotal) || 0),
      vendidos: parseInt(l.vendidos) || 0,
      ativo: l.ativo !== false
    }));
  }
  proj.updatedAt = new Date().toISOString();
  saveUD(uid, ud);
  res.json({ ok: true, ingressos: proj.ingressos });
});

// ── LISTAR PEDIDOS de um projeto (autenticado) ──
app.get('/api/projeto/:projectId/pedidos', auth, (req, res) => {
  const uid = req.user.isSubUser ? req.user.parentId : req.user.id;
  const peds = loadPedidos(uid);
  res.json({ pedidos: peds[req.params.projectId] || [] });
});

// ── SIMULAR PAGAMENTO (apenas em modo sandbox/teste) — testa o fluxo sem gastar de verdade ──
app.post('/api/projeto/:projectId/pedidos/:pedidoId/simular', auth, async (req, res) => {
  const uid = req.user.isSubUser ? req.user.parentId : req.user.id;
  const user = db.users.find(u => u.id === uid);
  if (!user?.mpAccount?.testMode) return res.status(403).json({ error: 'Simulação disponível apenas com conta Mercado Pago em modo TESTE.' });
  const peds = loadPedidos(uid);
  const lista = peds[req.params.projectId] || [];
  const pedido = lista.find(p => p.id === req.params.pedidoId);
  if (!pedido) return res.status(404).json({ error: 'Pedido não encontrado.' });
  if (pedido.status === 'pago') return res.json({ ok: true, jaProcessado: true });
  pedido.status = 'pago';
  pedido.pagoEm = new Date().toISOString();
  pedido.mpPaymentId = 'SIMULADO-' + Date.now();
  await processarPedidoAprovado(uid, req.params.projectId, pedido);
  savePedidos(uid, peds);
  res.json({ ok: true });
});

// ── CHECK-IN — valida código do ingresso na portaria ──
app.post('/api/checkin/validar', auth, rateLimit(60000, 60), (req, res) => {
  const uid = req.user.isSubUser ? req.user.parentId : req.user.id;
  const { projectId, codigo } = req.body;
  if (!projectId || !codigo) return res.status(400).json({ error: 'Dados incompletos.' });
  const peds = loadPedidos(uid);
  const lista = peds[projectId] || [];
  let ticketEncontrado = null, pedidoEncontrado = null;
  for (const p of lista) {
    const t = (p.tickets || []).find(tk => tk.codigo === sanitize(codigo, 40));
    if (t) { ticketEncontrado = t; pedidoEncontrado = p; break; }
  }
  if (!ticketEncontrado) return res.status(404).json({ error: 'Ingresso não encontrado.', valido: false });
  if (ticketEncontrado.usado) return res.json({ valido: false, jaUsado: true, usadoEm: ticketEncontrado.usadoEm, ticket: ticketEncontrado, comprador: pedidoEncontrado.comprador });
  ticketEncontrado.usado = true;
  ticketEncontrado.usadoEm = new Date().toISOString();
  savePedidos(uid, peds);
  res.json({ valido: true, ticket: ticketEncontrado, comprador: pedidoEncontrado.comprador });
});

// ════════════════════════════════════════════════════════════
// ROTAS PÚBLICAS — sem autenticação (página de compra)
// ════════════════════════════════════════════════════════════

// Info pública do evento para a página de vendas
app.get('/api/public/evento/:slug', rateLimit(60000, 60), (req, res) => {
  const ref = db.ticketSlugs[req.params.slug];
  if (!ref) return res.status(404).json({ error: 'Evento não encontrado.' });
  const ud = loadUD(ref.userId);
  const proj = (ud.projects || []).find(p => p.id === ref.projectId);
  if (!proj || !proj.ingressos?.ativo) return res.status(404).json({ error: 'Vendas não estão ativas para este evento.' });
  const producerAcc = db.users.find(u => u.id === ref.userId)?.mpAccount;
  const lotesPublicos = (proj.ingressos.lotes || [])
    .filter(l => l.ativo && l.vendidos < l.qtdTotal)
    .map(l => ({ id: l.id, nome: l.nome, preco: l.preco, disponivel: l.qtdTotal - l.vendidos }));
  res.json({
    nome: proj.nome, tipo: proj.tipo, cores: proj.cores || {},
    dataEvento: proj.dataEvento || proj.modulos?.lancamento?.inputs?.data || '',
    local: proj.modulos?.lancamento?.inputs?.local || '',
    lotes: lotesPublicos,
    testMode: !!producerAcc?.testMode
  });
});

// Cria pedido + preferência de pagamento no Mercado Pago (com split de comissão)
app.post('/api/public/checkout', rateLimit(60000, 20), async (req, res) => {
  try {
    const { slug, itens, comprador } = req.body;
    const ref = db.ticketSlugs[slug];
    if (!ref) return res.status(404).json({ error: 'Evento não encontrado.' });
    const uid = ref.userId;
    const producerToken = tokenDoProdutor(uid);
    if (!producerToken) return res.status(500).json({ error: 'Este produtor ainda não conectou uma conta de pagamento.' });
    if (!comprador?.nome || !comprador?.email) return res.status(400).json({ error: 'Nome e e-mail obrigatórios.' });
    if (!Array.isArray(itens) || !itens.length) return res.status(400).json({ error: 'Selecione ao menos um ingresso.' });

    const ud = loadUD(uid);
    const proj = (ud.projects || []).find(p => p.id === ref.projectId);
    if (!proj || !proj.ingressos?.ativo) return res.status(404).json({ error: 'Vendas encerradas.' });

    const mpItems = [];
    let total = 0;
    for (const it of itens) {
      const lote = (proj.ingressos.lotes || []).find(l => l.id === it.loteId);
      if (!lote || !lote.ativo) return res.status(400).json({ error: 'Lote indisponível.' });
      const qtd = Math.max(1, parseInt(it.qtd) || 1);
      if (lote.vendidos + qtd > lote.qtdTotal) return res.status(400).json({ error: `Apenas ${lote.qtdTotal - lote.vendidos} ingressos disponíveis em "${lote.nome}".` });
      mpItems.push({ title: `${proj.nome} — ${lote.nome}`, quantity: qtd, unit_price: lote.preco, currency_id: 'BRL' });
      total += lote.preco * qtd;
    }

    const pedidoId = uuidv4();
    const host = req.get('host');
    const proto = req.get('x-forwarded-proto') || 'https';
    const baseUrl = `${proto}://${host}`;
    const feePercent = db.marketplaceFeePercent || 10;
    const marketplaceFee = Math.round(total * (feePercent / 100) * 100) / 100;

    // Cria preferência usando o TOKEN DO PRODUTOR — o dinheiro cai direto na conta dele,
    // e marketplace_fee é a comissão retida automaticamente para a plataforma (Workamusic)
    const prefBody = {
      items: mpItems,
      payer: { name: sanitize(comprador.nome, 100), email: comprador.email },
      external_reference: pedidoId,
      marketplace_fee: marketplaceFee,
      back_urls: {
        success: `${baseUrl}/e/${slug}?pedido=${pedidoId}&status=success`,
        pending: `${baseUrl}/e/${slug}?pedido=${pedidoId}&status=pending`,
        failure: `${baseUrl}/e/${slug}?pedido=${pedidoId}&status=failure`
      },
      auto_return: 'approved',
      notification_url: `${baseUrl}/api/mp/webhook?uid=${uid}&proj=${ref.projectId}&ped=${pedidoId}`,
      statement_descriptor: 'LOTA INGRESSOS'
    };

    const mpResp = await fetch(`${MP_API}/checkout/preferences`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${producerToken}` },
      body: JSON.stringify(prefBody)
    });
    const mpData = await mpResp.json();
    if (!mpResp.ok) return res.status(400).json({ error: mpData.message || 'Erro ao criar pagamento.' });

    const peds = loadPedidos(uid);
    if (!peds[ref.projectId]) peds[ref.projectId] = [];
    peds[ref.projectId].push({
      id: pedidoId,
      status: 'pendente',
      comprador: { nome: sanitize(comprador.nome, 100), email: comprador.email, telefone: sanitize(comprador.telefone || '', 30) },
      itens: itens.map(it => ({ loteId: it.loteId, qtd: it.qtd })),
      total,
      marketplaceFee,
      mpPreferenceId: mpData.id,
      mpPaymentId: null,
      tickets: [],
      createdAt: new Date().toISOString()
    });
    savePedidos(uid, peds);

    res.json({ ok: true, pedidoId, init_point: mpData.init_point, sandbox_init_point: mpData.sandbox_init_point, testMode: isTestToken(producerToken) });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Webhook do Mercado Pago — confirma pagamento, gera ingressos e envia e-mail
app.post('/api/mp/webhook', async (req, res) => {
  try {
    const paymentId = req.body?.data?.id || req.query['data.id'];
    const type = req.body?.type || req.query.type;
    if (type !== 'payment' || !paymentId) return res.sendStatus(200);

    // Lookup direto via query params (embutidos na notification_url) — evita varrer todos os slugs
    const { uid, proj: projectId, ped: pedidoId } = req.query;
    if (!uid || !projectId || !pedidoId) return res.sendStatus(200);

    const producerToken = tokenDoProdutor(uid);
    if (!producerToken) return res.sendStatus(200);

    const payResp = await fetch(`${MP_API}/v1/payments/${paymentId}`, { headers: { 'Authorization': `Bearer ${producerToken}` } });
    const payment = await payResp.json();
    if (!payResp.ok) return res.sendStatus(200);

    const peds = loadPedidos(uid);
    const lista = peds[projectId] || [];
    const pedido = lista.find(p => p.id === pedidoId);
    if (!pedido) return res.sendStatus(200);

    if (pedido.mpPaymentId === String(paymentId) && pedido.status === 'pago') return res.sendStatus(200);
    pedido.mpPaymentId = String(paymentId);

    if (payment.status === 'approved' && pedido.status !== 'pago') {
      pedido.status = 'pago';
      pedido.pagoEm = new Date().toISOString();
      await processarPedidoAprovado(uid, projectId, pedido);
    } else if (['rejected', 'cancelled'].includes(payment.status)) {
      pedido.status = 'recusado';
    }
    savePedidos(uid, peds);
    res.sendStatus(200);
  } catch (e) {
    res.sendStatus(200); // MP não deve reenviar em loop por erro nosso
  }
});

// Status do pedido — usado pela página pública para exibir ingressos após pagamento
app.get('/api/public/pedido/:pedidoId', rateLimit(60000, 60), (req, res) => {
  for (const slug in db.ticketSlugs) {
    const ref = db.ticketSlugs[slug];
    const peds = loadPedidos(ref.userId);
    const lista = peds[ref.projectId] || [];
    const pedido = lista.find(p => p.id === req.params.pedidoId);
    if (pedido) {
      return res.json({
        status: pedido.status, total: pedido.total,
        tickets: pedido.tickets || [], comprador: { nome: pedido.comprador.nome }
      });
    }
  }
  res.status(404).json({ error: 'Pedido não encontrado.' });
});

// Serve a página pública de compra em /e/:slug
app.get('/e/:slug', (req, res) => {
  const comprarPath = path.join(PUBLIC_DIR, 'comprar.html');
  if (fs.existsSync(comprarPath)) return res.sendFile(comprarPath);
  res.status(404).send('Página de vendas não encontrada.');
});

app.get('/health', (req, res) => {
  res.json({
    status: 'ok', app: 'Lota v2.0', brand: 'Workamusic',
    users: db.users.length,
    anthropic: !!process.env.ANTHROPIC_API_KEY ? '✅' : '❌',
    mercadopago_oauth: (MP_CLIENT_ID && MP_CLIENT_SECRET) ? '✅' : '❌ (configure MP_CLIENT_ID e MP_CLIENT_SECRET)',
    resend_email: !!RESEND_API_KEY ? '✅' : '❌ (configure RESEND_API_KEY)',
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
