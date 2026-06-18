/**
 * LOTA — Servidor v1.0
 * Inteligência de eventos. Do lançamento ao sold out.
 * Express + JWT + bcrypt + Anthropic
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
const JWT_SECRET = process.env.JWT_SECRET || 'lota_dev_secret';

// ── Paths ─────────────────────────────────────────────────
const DATA_DIR   = fs.existsSync('/app') ? '/app' : path.join(__dirname, '..');
const DB_FILE    = path.join(DATA_DIR, 'db.json');
const PUBLIC_DIR = path.join(__dirname, '../public');
const INDEX_HTML = path.join(PUBLIC_DIR, 'index.html');

app.use(express.json({ limit: '10mb' }));
app.use(express.static(PUBLIC_DIR));

// ── Database ──────────────────────────────────────────────
function loadDB() {
  try { if (fs.existsSync(DB_FILE)) return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); } catch(e) {}
  return { users: [{
    id: 'admin-001', name: 'admin', displayName: 'Administrador',
    password: bcrypt.hashSync('admin123', 10),
    plan: 'unlimited', limit: 999, used: 0,
    isAdmin: true, active: true, avatar: '', globalSlots: 50,
    createdAt: new Date().toISOString()
  }]};
}
function saveDB(d) { try { fs.writeFileSync(DB_FILE, JSON.stringify(d, null, 2)); } catch(e) {} }
let db = loadDB();
if (!db.users.find(u => u.isAdmin)) { db.users.unshift(loadDB().users[0]); saveDB(db); }
console.log(`✅ Banco carregado: ${db.users.length} usuário(s)`);

function udFile(id) { return path.join(DATA_DIR, `userdata_${id}.json`); }
function loadUD(id) {
  try { const f = udFile(id); if (fs.existsSync(f)) return JSON.parse(fs.readFileSync(f, 'utf8')); } catch(e) {}
  return { events: [], projects: [] };
}
function saveUD(id, d) { try { fs.writeFileSync(udFile(id), JSON.stringify(d)); } catch(e) {} }

// ── Auth ──────────────────────────────────────────────────
function auth(req, res, next) {
  const token = (req.headers['authorization'] || '').replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Token não enviado.' });
  try {
    const dec = jwt.verify(token, JWT_SECRET);
    const user = db.users.find(u => u.id === dec.id && u.active);
    if (!user) return res.status(401).json({ error: 'Usuário não encontrado ou desativado.' });
    req.user = user;
    next();
  } catch(e) { return res.status(401).json({ error: 'Token inválido.' }); }
}
function adminOnly(req, res, next) {
  if (!req.user.isAdmin) return res.status(403).json({ error: 'Acesso restrito.' });
  next();
}
function safe(u) { const { password, ...r } = u; return r; }

// ── Anthropic ─────────────────────────────────────────────
async function callAI(system, userMsg, maxTokens = 2000) {
  const resp = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
    body: JSON.stringify({ model: 'claude-haiku-4-5-20251001', max_tokens: maxTokens, system, messages: [{ role: 'user', content: userMsg }] })
  });
  const data = await resp.json();
  if (!resp.ok) throw new Error(data.error?.message || 'Erro na API.');
  return data.content?.[0]?.text || '';
}

// ═══════════════════════════════════════════════════════════
// AUTH ROUTES
// ═══════════════════════════════════════════════════════════
app.post('/api/auth/login', (req, res) => {
  const { name, password } = req.body;
  if (!name || !password) return res.status(400).json({ error: 'Preencha usuário e senha.' });
  const user = db.users.find(u => u.name.toLowerCase() === name.trim().toLowerCase());
  if (!user) return res.status(401).json({ error: 'Usuário não encontrado.' });
  if (!user.active) return res.status(401).json({ error: 'Conta desativada.' });
  if (!bcrypt.compareSync(password, user.password)) return res.status(401).json({ error: 'Senha incorreta.' });
  user.lastLogin = new Date().toISOString();
  saveDB(db);
  const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: safe(user) });
});

app.get('/api/auth/me', auth, (req, res) => res.json({ user: safe(req.user) }));

app.patch('/api/auth/profile', auth, (req, res) => {
  const user = db.users.find(u => u.id === req.user.id);
  const { displayName, currentPassword, newPassword } = req.body;
  if (newPassword) {
    if (!bcrypt.compareSync(currentPassword, user.password)) return res.status(401).json({ error: 'Senha atual incorreta.' });
    user.password = bcrypt.hashSync(newPassword, 10);
  }
  if (displayName) user.displayName = displayName.trim();
  saveDB(db);
  res.json({ user: safe(user) });
});

// ═══════════════════════════════════════════════════════════
// ADMIN ROUTES
// ═══════════════════════════════════════════════════════════
app.get('/api/admin/users', auth, adminOnly, (req, res) => res.json(db.users.map(safe)));
app.get('/api/admin/slots', auth, adminOnly, (req, res) => {
  const admin = db.users.find(u => u.isAdmin);
  res.json({ slots: admin?.globalSlots || 50, used: db.users.filter(u => !u.isAdmin).length });
});
app.patch('/api/admin/slots', auth, adminOnly, (req, res) => {
  const admin = db.users.find(u => u.isAdmin);
  const val = parseInt(req.body.slots);
  if (isNaN(val) || val < 1) return res.status(400).json({ error: 'Valor inválido.' });
  if (admin) { admin.globalSlots = val; saveDB(db); }
  res.json({ ok: true });
});
app.post('/api/admin/users', auth, adminOnly, (req, res) => {
  const { name, password, displayName, plan, limit } = req.body;
  if (!name || !password) return res.status(400).json({ error: 'Nome e senha obrigatórios.' });
  if (db.users.find(u => u.name.toLowerCase() === name.toLowerCase())) return res.status(400).json({ error: 'Login já em uso.' });
  const admin = db.users.find(u => u.isAdmin);
  if (db.users.filter(u => !u.isAdmin).length >= (admin?.globalSlots || 50)) return res.status(400).json({ error: 'Limite de slots atingido.' });
  const user = {
    id: uuidv4(), name: name.trim(), displayName: (displayName || name).trim(),
    password: bcrypt.hashSync(password, 10), plan: plan || 'basic',
    limit: parseInt(limit) || 10, used: 0, isAdmin: false, active: true, avatar: '',
    createdAt: new Date().toISOString()
  };
  db.users.push(user); saveDB(db);
  res.status(201).json({ user: safe(user) });
});
app.patch('/api/admin/users/:id', auth, adminOnly, (req, res) => {
  const user = db.users.find(u => u.id === req.params.id);
  if (!user || user.isAdmin) return res.status(404).json({ error: 'Não encontrado ou protegido.' });
  const { name, password, displayName, plan, limit, active } = req.body;
  if (name) user.name = name.trim();
  if (displayName) user.displayName = displayName.trim();
  if (plan) user.plan = plan;
  if (limit !== undefined) user.limit = parseInt(limit);
  if (active !== undefined) user.active = !!active;
  if (password) user.password = bcrypt.hashSync(password, 10);
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

// ═══════════════════════════════════════════════════════════
// USER DATA
// ═══════════════════════════════════════════════════════════
app.get('/api/data', auth, (req, res) => res.json(loadUD(req.user.id)));
app.post('/api/data', auth, (req, res) => {
  const curr = loadUD(req.user.id);
  const { events, projects } = req.body;
  if (events   !== undefined) curr.events   = events;
  if (projects !== undefined) curr.projects = projects;
  saveUD(req.user.id, curr);
  res.json({ ok: true });
});

// ═══════════════════════════════════════════════════════════
// MÓDULO 1 & 8 — CRIAÇÃO DO EVENTO (Briefing + Nome + Identidade)
// ═══════════════════════════════════════════════════════════
const SYSTEM_LOTA = `Você é o Lota, uma IA especialista em lançamento e venda de eventos de entretenimento no Brasil. 
Você domina profundamente:
- Psicologia do comprador de ingresso (por que as pessoas saem de casa)
- Estratégias de escassez, antecipação e gatilhos de urgência
- Tráfego pago para venda de ingressos (especialmente Instagram)
- Criação de hype para público frio (que não conhece o artista)
- Lotes de ingresso com preço crescente e janelas de escassez por tempo
- O saudosismo como gatilho de venda para shows de releitura
- Tinder do evento, lista de presença VIP, festa da senha, fila premiada
- Clubes de assinatura para casas de show premium (jazz, MPB ao vivo)
- Conteúdo pós-evento como ativo de venda do próximo
- Os 5 perfis de evento: show de releitura, festa temática, stand-up, festa consolidada, casa chique/jazz

Responda sempre em português brasileiro. Seja direto, prático e orientado a resultado.`;

app.post('/api/evento/criar-nome', auth, async (req, res) => {
  const { tema, tipo, vibe, publico } = req.body;
  if (!tema) return res.status(400).json({ error: 'Tema obrigatório.' });
  try {
    const text = await callAI(SYSTEM_LOTA, `Crie 5 opções de nome para um evento com as seguintes características:

Tema/Ideia: ${tema}
Tipo de evento: ${tipo || 'Não especificado'}
Vibe desejada: ${vibe || 'Não especificada'}
Público-alvo: ${publico || 'Geral'}

Para cada opção, entregue:
1. NOME DO EVENTO (impactante, memorável, que carrega o tema)
2. TAGLINE (frase curta de apoio, máximo 8 palavras)
3. CONCEITO (explicação em 2-3 linhas do porquê funciona)
4. MECÂNICA SUGERIDA (qual estratégia de antecipação combina com esse nome — tinder do evento, festa da senha, lista VIP, etc)

Formato:
---
OPÇÃO 1
Nome: [nome]
Tagline: [tagline]
Conceito: [conceito]
Mecânica: [mecânica]
---`, 1800);
    res.json({ result: text });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/evento/identidade', auth, async (req, res) => {
  const { nome, tipo, tema, publico, vibe } = req.body;
  if (!nome) return res.status(400).json({ error: 'Nome do evento obrigatório.' });
  try {
    const text = await callAI(SYSTEM_LOTA, `Crie a identidade completa para o evento "${nome}".

Tipo: ${tipo || 'Show/Festa'}
Tema: ${tema || nome}
Público: ${publico || 'Geral'}
Vibe: ${vibe || 'Não especificada'}

Entregue:

🎨 IDENTIDADE VISUAL
- Paleta de cores (3-4 cores com hex e nome)
- Estilo visual (referências: anos 80 neon, minimalismo luxo, rock vintage, samba colorido, etc)
- Tipografia sugerida (estilo de fonte para o nome do evento)
- Elementos gráficos (ícones, texturas, símbolos que representam o evento)

✍️ IDENTIDADE VERBAL  
- Tom de voz (como o evento fala com o público)
- Palavras proibidas (o que NÃO usar na comunicação)
- Palavras-chave (o que sempre usar)
- 3 frases de exemplo para stories/posts

📝 DESCRIÇÃO OFICIAL DO EVENTO
(Texto completo para usar no site, Sympla, Ingresse — máx 150 palavras)

🎟️ EXPERIÊNCIA QUE SERÁ VENDIDA
(O que o comprador vai SENTIR — não o que vai acontecer)`, 2000);
    res.json({ result: text });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ═══════════════════════════════════════════════════════════
// MÓDULO 2 — ANÁLISE DE PÚBLICO
// ═══════════════════════════════════════════════════════════
app.post('/api/evento/publico', auth, async (req, res) => {
  const { nome, tipo, tema, cidade, faixaEtaria, generoMusical } = req.body;
  if (!tipo) return res.status(400).json({ error: 'Tipo de evento obrigatório.' });
  try {
    const text = await callAI(SYSTEM_LOTA, `Faça uma análise completa do público para o seguinte evento:

Nome: ${nome || 'Não definido'}
Tipo: ${tipo}
Tema/Gênero: ${tema || generoMusical || 'Não especificado'}
Cidade: ${cidade || 'Brasil'}
Faixa etária estimada: ${faixaEtaria || 'A definir'}

Entregue:

👥 PERFIL DO COMPRADOR IDEAL
- Idade, gênero, classe social, ocupação
- Onde essa pessoa está no digital (Instagram, TikTok, Facebook)
- Comportamento de compra de ingresso (compra com antecedência ou na hora?)
- O que ela consome no dia a dia

💡 POR QUE ELA VAI SAIR DE CASA
(O motivo emocional real — não "para ver o show")
- Desejo principal
- Medo de perder (FOMO)
- O que ela vai contar para os amigos depois

🎯 SEGMENTAÇÃO PARA TRÁFEGO PAGO (Instagram)
- Faixa etária para segmentar
- Interesses para usar no gerenciador de anúncios
- Comportamentos que indicam intenção de compra
- Cidades e regiões prioritárias

⚠️ OBJEÇÕES MAIS COMUNS
(O que impede a compra e como quebrar cada uma)

📊 TAMANHO DO PÚBLICO POTENCIAL
(Estimativa de quantas pessoas na cidade podem comprar ingresso)`, 2000);
    res.json({ result: text });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ═══════════════════════════════════════════════════════════
// MÓDULO 3 — ESTRATÉGIA DE LANÇAMENTO
// ═══════════════════════════════════════════════════════════
app.post('/api/evento/lancamento', auth, async (req, res) => {
  const { nome, tipo, data, local, capacidade, preco, dataLancamento, qtdLotes } = req.body;
  if (!tipo || !data) return res.status(400).json({ error: 'Tipo e data do evento são obrigatórios.' });
  try {
    const text = await callAI(SYSTEM_LOTA, `Crie a estratégia completa de lançamento para:

Evento: ${nome || 'Sem nome ainda'}
Tipo: ${tipo}
Data do evento: ${data}
Local/Cidade: ${local || 'A definir'}
Capacidade: ${capacidade || 'Não informada'} pessoas
Faixa de preço: R$ ${preco || 'A definir'}
Data de início das vendas: ${dataLancamento || 'A definir'}
Número de lotes desejados: ${qtdLotes || '3-4'}

Entregue:

🚀 FASE 1 — PRÉ-ANÚNCIO (Aquecimento)
- Quanto tempo antes do anúncio começar a criar expectativa
- O que fazer nas redes ANTES de revelar o evento
- Como criar mistério e antecipação sem revelar nada
- Conteúdo específico para essa fase

📣 FASE 2 — ANÚNCIO DO EVENTO
- Quando e como fazer a revelação
- Roteiro do post/stories de anúncio
- Mecânica de engajamento (tinder do evento, lista VIP, etc)
- Meta de engajamento antes de abrir as vendas

🎟️ FASE 3 — ESTRUTURA DOS LOTES
Para cada lote:
- LOTE X: preço, quantidade, período de vendas (horas/dias), gatilho de abertura e fechamento
(Usar janelas de tempo, não só quantidade — ex: "aberto por 48h")

⏰ FASE 4 — ESCASSEZ E URGÊNCIA
- Como anunciar o fechamento de cada lote
- Silêncio estratégico entre lotes
- Quando e como reabrir
- Frases exatas para usar nos posts de escassez

🎉 FASE 5 — RETA FINAL (últimos 7 dias)
- Sequência de ações diárias
- Como usar o conteúdo de quem já comprou
- Última chamada e urgência final`, 2500);
    res.json({ result: text });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ═══════════════════════════════════════════════════════════
// MÓDULO 4 — CAMPANHA DIA A DIA
// ═══════════════════════════════════════════════════════════
app.post('/api/evento/campanha', auth, async (req, res) => {
  const { nome, tipo, dataEvento, dataLancamento, tema } = req.body;
  if (!dataEvento) return res.status(400).json({ error: 'Data do evento obrigatória.' });
  try {
    const text = await callAI(SYSTEM_LOTA, `Crie o plano de campanha dia a dia para:

Evento: ${nome || 'Sem nome'}
Tipo: ${tipo || 'Show/Festa'}
Tema: ${tema || 'Não especificado'}
Data do evento: ${dataEvento}
Início das vendas: ${dataLancamento || '30 dias antes'}

Monte um calendário de 30 dias com ações específicas para cada semana:

📅 SEMANA 1 — Aquecimento e Mistério
(Ações para cada dia: o que postar, que tipo de conteúdo, objetivo)

📅 SEMANA 2 — Revelação e Abertura de Vendas  
(Ações para cada dia: revelação, mecânicas de engajamento, abertura do 1º lote)

📅 SEMANA 3 — Manutenção e Prova Social
(Ações para cada dia: conteúdo de quem comprou, contagem regressiva, virada de lote)

📅 SEMANA 4 — Urgência e Reta Final
(Ações para cada dia: fechamento de lotes, última chamada, D-day)

📅 PÓS-EVENTO (3 dias depois)
(Como usar o conteúdo pós-evento para já vender o próximo)

Para cada ação indique:
- Tipo de conteúdo (stories, feed, reels, WhatsApp)
- Texto/legenda sugerida
- Objetivo do dia`, 2500);
    res.json({ result: text });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ═══════════════════════════════════════════════════════════
// MÓDULO 5 — CRIATIVO PARA TRÁFEGO PAGO
// ═══════════════════════════════════════════════════════════
app.post('/api/evento/criativo', auth, async (req, res) => {
  const { nome, tipo, tema, publico, faixaEtaria, generoMusical, artistas, preco, local, data } = req.body;
  if (!tipo) return res.status(400).json({ error: 'Tipo de evento obrigatório.' });
  try {
    const text = await callAI(SYSTEM_LOTA, `Crie roteiros de criativos para tráfego pago no Instagram para:

Evento: ${nome || 'Sem nome'}
Tipo: ${tipo}
Tema/Gênero: ${tema || generoMusical || 'Não especificado'}
Artistas/Atrações: ${artistas || 'A definir'}
Público-alvo: ${publico || 'Geral'} — faixa etária: ${faixaEtaria || 'A definir'}
Cidade/Local: ${local || 'A definir'}
Data: ${data || 'A definir'}
Faixa de preço: R$ ${preco || 'A definir'}

Crie 3 roteiros de vídeo (15-30 segundos cada) para Instagram:

🎬 CRIATIVO 1 — EXPERIÊNCIA (mostrar como é estar lá)
Cena 0-3s: [descrição exata do que aparece na tela e o áudio]
Cena 3-8s: [...]
Cena 8-15s: [...]
Texto da descrição do anúncio: [texto completo]
Segmentação sugerida: [faixa etária, interesses, localização]
Objetivo: [awareness ou conversão]

🎬 CRIATIVO 2 — SAUDOSISMO/EMOÇÃO (gatilho emocional)
[mesmo formato]

🎬 CRIATIVO 3 — URGÊNCIA/ESCASSEZ (virada de lote ou reta final)
[mesmo formato]

💡 DICAS DE PRODUÇÃO
- Que tipo de cenas filmar dentro do evento/local
- Qual áudio usar em cada criativo
- Melhor horário para rodar os anúncios para esse público`, 2500);
    res.json({ result: text });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ═══════════════════════════════════════════════════════════
// MÓDULO 6 — CONTEÚDO PARA REDES
// ═══════════════════════════════════════════════════════════
app.post('/api/evento/conteudo', auth, async (req, res) => {
  const { nome, tipo, tema, artistas, fase } = req.body;
  if (!tipo) return res.status(400).json({ error: 'Tipo obrigatório.' });
  try {
    const text = await callAI(SYSTEM_LOTA, `Crie sugestões de conteúdo para redes sociais para:

Evento: ${nome || 'Sem nome'}
Tipo: ${tipo}
Tema: ${tema || 'Não especificado'}
Artistas/Atrações: ${artistas || 'A definir'}
Fase atual: ${fase || 'Aquecimento'}

Entregue 10 sugestões de conteúdo organizadas por tipo:

📸 POSTS DE FEED (3 sugestões)
- Ideia visual + legenda completa + hashtags

🎥 REELS/VÍDEOS (3 sugestões)
- Conceito + roteiro resumido + áudio sugerido + legenda

📱 STORIES (2 sugestões)
- Sequência de stories com texto de cada tela

🤳 CONTEÚDO GERADO PELO PÚBLICO (2 sugestões)
- Ideia de post que estimula o público a criar e compartilhar
(Ex: tinder do evento, "marque quem vai com você", desafio relacionado ao tema)

Para cada sugestão indique:
- Objetivo (engajamento, vendas, prova social, FOMO)
- Melhor horário para postar
- Se é para antes, durante ou depois da compra do ingresso`, 2000);
    res.json({ result: text });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ═══════════════════════════════════════════════════════════
// MÓDULO 7 — CENTRAL DE VENDAS (Scripts da Equipe)
// ═══════════════════════════════════════════════════════════
app.post('/api/evento/vendas', auth, async (req, res) => {
  const { nome, tipo, tema, preco, beneficios } = req.body;
  if (!tipo) return res.status(400).json({ error: 'Tipo obrigatório.' });
  try {
    const text = await callAI(SYSTEM_LOTA, `Crie o kit completo de vendas para a equipe do evento:

Evento: ${nome || 'Sem nome'}
Tipo: ${tipo}
Tema: ${tema || 'Não especificado'}
Preço dos ingressos: R$ ${preco || 'A definir'}
Benefícios/diferenciais: ${beneficios || 'A definir'}

Entregue:

📞 SCRIPT DE ABORDAGEM INICIAL (WhatsApp)
(Mensagem para quem demonstrou interesse mas não comprou)
- Versão curta (até 3 linhas)
- Versão completa (com todos os argumentos)

💬 RESPOSTAS PARA OBJEÇÕES
Para cada objeção, entregue a resposta ideal:
1. "Tá caro" / "Não tenho grana agora"
2. "Vou pensar e te aviso"
3. "Não conheço o artista"
4. "Será que vai ser bom mesmo?"
5. "Não sei se vou poder ir nessa data"
6. "Já fui num evento assim e não gostei"

🎯 ARGUMENTOS POR TIPO DE INGRESSO
- Ingresso 1º lote (preço mais baixo): argumentos de antecipação
- Ingresso VIP: argumentos de exclusividade e experiência
- Ingresso último lote: argumentos de urgência

⚡ FRASES DE FECHAMENTO
(5 frases para usar no momento decisivo)

📊 SIMULADOR DE ATENDIMENTO
Crie 3 cenários de conversa com cliente difícil e como resolver cada um.`, 2500);
    res.json({ result: text });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ═══════════════════════════════════════════════════════════
// HEALTH
// ═══════════════════════════════════════════════════════════
app.get('/health', (req, res) => res.json({
  status: 'ok', app: 'Lota',
  users: db.users.length,
  anthropic: !!process.env.ANTHROPIC_API_KEY ? '✅' : '❌',
  uptime: Math.round(process.uptime()) + 's'
}));

app.get('*', (req, res) => {
  if (fs.existsSync(INDEX_HTML)) res.sendFile(INDEX_HTML);
  else res.status(500).send(`<h2>index.html não encontrado</h2><p>Pasta: ${PUBLIC_DIR}</p>`);
});

app.listen(PORT, () => {
  console.log(`\n🎪 LOTA rodando na porta ${PORT}`);
  console.log(`   Anthropic: ${process.env.ANTHROPIC_API_KEY ? '✅' : '❌'}`);
  console.log(`   JWT: ${process.env.JWT_SECRET ? '✅' : '⚠️  padrão'}`);
  console.log(`   index.html: ${fs.existsSync(INDEX_HTML) ? '✅' : '❌'}\n`);
});
