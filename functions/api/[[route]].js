// Board to Notes: Cloudflare Worker backend
// Routes: /api/* handled here, everything else served from public/ (the app).

const MODELS = ['gemini-3.8-flash', 'gemini-3.7-flash', 'gemini-3.5-flash-lite'];
const SESSION_DAYS = 30;
const MAX_IMAGE_CHARS = 1800000;
const MODEL_TIMEOUT_MS = 28000;
const DAILY_LIMIT = 10;   // AI summaries per user per day (UTC). Set to 0 to turn the limit off.

const READ_PROMPT = `You are an expert note-taker. You are given a photo of a classroom board or notebook page (it may be handwritten, tilted, blurry or shadowed). Turn it into clear, well-organised STUDY NOTES that a student can revise from, without needing to look at the photo.

Return ONLY a JSON object (no other text) with this shape:
{
  "transcription": "all readable text on the board, line by line",
  "title": "the main heading of the board",
  "subject": "one of: Computer Science, Mathematics, Physics, Chemistry, Biology, English, Urdu, History, Islamiyat, Pakistan Studies, Economics, General",
  "summary": "2-3 sentences: what this board teaches, in plain words",
  "sections": [
    { "heading": "short topic heading", "bullets": ["a complete, easy-to-understand note", "..."] }
  ],
  "points": ["5-8 key takeaways for quick revision, one short sentence each"],
  "definitions": [{"term": "...", "def": "..."}],
  "figures": [
    {
      "title": "short name, e.g. 'Mind map of network types' or 'Graph: speed vs time'",
      "type": "diagram | flowchart | mind map | graph | chart | table | formula | drawing",
      "explanation": "explain the figure in words so the notes make sense without the picture: every label, box, arrow and what it points to, axes and units, curve shape, trends, values, rows and columns",
      "box_2d": [ymin, xmin, ymax, xmax]
    }
  ]
}

Rules:
- Follow the structure of the board: each topic, branch of a mind map, step of a flowchart or numbered item becomes a section with bullets. Put related ideas together; do not just copy lines in the order you see them.
- Write bullets as complete notes. You may connect ideas with a few clarifying words, but never add facts that are not on the board.
- EVERY diagram, mind map, flowchart, graph, chart, table, circuit or drawing on the board must appear in "figures". "box_2d" is a tight box around that drawing, with coordinates normalised to 0-1000 (ymin, xmin, ymax, xmax, origin at the top-left of the photo). If there are none, return an empty list.
- Also mention each figure inside the matching section, for example "See Figure 1: ...".
- Write formulas and maths in plain text, e.g. F = m x a, x^2 + 3x = 0.
- Write unreadable words as [unclear]. Put key terms and their meanings in "definitions", not in "points".
- Use the same language as the board (Urdu, Roman Urdu or English).`;

const enc = new TextEncoder();
const hex = buf => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
const unhex = h => Uint8Array.from(h.match(/../g).map(x => parseInt(x, 16)));
const json = (data, status = 200) =>
  new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json' } });
const sha256 = async s => hex(await crypto.subtle.digest('SHA-256', enc.encode(s)));
const todayStr = () => new Date().toISOString().slice(0, 10);
const clip = (v, fallback, max) => String(v ?? '').trim().slice(0, max) || fallback;
const strList = a => (Array.isArray(a) ? a : []).map(s => String(s).trim()).filter(Boolean).slice(0, 50);
const defList = a => (Array.isArray(a) ? a : [])
  .filter(d => d && d.def)
  .map(d => ({ term: String(d.term || '').slice(0, 100), def: String(d.def).slice(0, 1000) }))
  .slice(0, 50);
const secList = a => (Array.isArray(a) ? a : [])
  .map(x => ({ heading: clip(x && x.heading, 'Notes', 120), bullets: strList(x && x.bullets).slice(0, 30) }))
  .filter(x => x.bullets.length)
  .slice(0, 20);
const boxOk = b => Array.isArray(b) && b.length === 4 && b.every(n => Number.isFinite(Number(n)));
const figList = a => (Array.isArray(a) ? a : [])
  .filter(f => f && (f.title || f.explanation))
  .map(f => {
    let box = null;
    if (boxOk(f.box || f.box_2d)) {
      const [y1, x1, y2, x2] = (f.box || f.box_2d).map(n => Math.max(0, Math.min(1000, Math.round(Number(n)))));
      if (y2 - y1 > 20 && x2 - x1 > 20) box = [y1, x1, y2, x2];
    }
    return { title: clip(f.title, 'Figure', 120), type: clip(f.type, 'diagram', 30),
             explanation: clip(f.explanation, '', 2000), box };
  })
  .slice(0, 8);
const safeJSON = (t, fb) => { try { return JSON.parse(t); } catch { return fb; } };
const cleanExtra = b => JSON.stringify({
  summary: clip(b.summary, '', 2000), sections: secList(b.sections), figures: figList(b.figures)
});

let schemaReady = false;
async function ensureSchema(env) {
  if (schemaReady) return;
  try { await env.DB.prepare("ALTER TABLE notes ADD COLUMN extra TEXT NOT NULL DEFAULT '{}'").run(); }
  catch { /* column already exists */ }
  try {
    await env.DB.prepare('CREATE TABLE IF NOT EXISTS usage (user_id TEXT NOT NULL, day TEXT NOT NULL, n INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (user_id, day))').run();
  } catch (e) { console.error('usage table', e); }
  schemaReady = true;
}

async function hashPassword(password, saltHex) {
  const salt = saltHex ? unhex(saltHex) : crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, key, 256);
  return { hash: hex(bits), salt: hex(salt) };
}

async function currentUser(req, env) {
  const auth = req.headers.get('authorization') || '';
  if (!auth.startsWith('Bearer ')) return null;
  return env.DB.prepare(
    'SELECT u.id, u.email FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ? AND s.expires_at > ?'
  ).bind(await sha256(auth.slice(7)), Date.now()).first();
}

export async function onRequest(context) {
  const req = context.request;
  const env = context.env;
  const url = new URL(req.url);
  try {
    await ensureSchema(env);
    return await route(req, env, url.pathname);
  } catch (err) {
    console.error(err);
    return json({ error: "Server error. Please try again." }, 500);
  }
}

async function route(req, env, p) {
  const m = req.method;

  // public / admin routes
  if (p === '/api/login' && m === 'POST') return login(req, env);
  if (p === '/api/signup' && m === 'POST') return signup(req, env);
  if (p === '/api/admin/users' && m === 'POST') return createUser(req, env);

  // everything below needs a logged-in user
  const user = await currentUser(req, env);
  if (!user) return json({ error: 'Please log in again.' }, 401);

  if (p === '/api/logout' && m === 'POST') return logout(req, env);
  if (p === '/api/password' && m === 'POST') return changePassword(req, env, user);
  if (p === '/api/me' && m === 'GET') return json({ email: user.email });
  if (p === '/api/summarize' && m === 'POST') return summarize(req, env, user);
  if (p === '/api/notes' && m === 'GET') return listNotes(env, user);
  if (p === '/api/notes' && m === 'POST') return createNote(req, env, user);

  const match = p.match(/^\/api\/notes\/([\w-]+)(\/image)?$/);
  if (match) {
    const [, id, isImage] = match;
    if (isImage && m === 'GET') return getImage(env, user, id);
    if (!isImage && m === 'PUT') return updateNote(req, env, user, id);
    if (!isImage && m === 'DELETE') return deleteNote(env, user, id);
  }
  return json({ error: 'Not found' }, 404);
}

async function login(req, env) {
  const body = await req.json().catch(() => ({}));
  const email = String(body.email || '').trim().toLowerCase();
  const password = String(body.password || '');
  const fail = () => json({ error: 'Wrong email or password.' }, 401);

  const row = await env.DB.prepare('SELECT id, pass_hash, salt FROM users WHERE email = ?').bind(email).first();
  if (!row) return fail();
  const { hash } = await hashPassword(password, row.salt);
  if (hash !== row.pass_hash) return fail();

  return json({ token: await newSession(env, row.id), email });
}

async function newSession(env, userId) {
  const token = hex(crypto.getRandomValues(new Uint8Array(32)));
  const now = Date.now();
  await env.DB.prepare('INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)')
    .bind(await sha256(token), userId, now, now + SESSION_DAYS * 864e5).run();
  return token;
}

// Open sign-up: anyone can make an account (each user is limited by DAILY_LIMIT)
async function signup(req, env) {
  const body = await req.json().catch(() => ({}));
  const email = String(body.email || '').trim().toLowerCase();
  const password = String(body.password || '');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 200) {
    return json({ error: 'Enter a valid email address.' }, 400);
  }
  if (password.length < 8 || password.length > 200) {
    return json({ error: 'Password must be at least 8 characters.' }, 400);
  }
  const { hash, salt } = await hashPassword(password);
  const id = crypto.randomUUID();
  try {
    await env.DB.prepare('INSERT INTO users (id, email, pass_hash, salt, created_at) VALUES (?, ?, ?, ?, ?)')
      .bind(id, email, hash, salt, Date.now()).run();
  } catch {
    return json({ error: 'That email already has an account. Please log in.' }, 409);
  }
  return json({ token: await newSession(env, id), email }, 201);
}

async function changePassword(req, env, user) {
  const body = await req.json().catch(() => ({}));
  const current = String(body.current || ''), next = String(body.next || '');
  if (next.length < 8 || next.length > 200) return json({ error: 'New password must be at least 8 characters.' }, 400);
  const row = await env.DB.prepare('SELECT pass_hash, salt FROM users WHERE id = ?').bind(user.id).first();
  if (!row || (await hashPassword(current, row.salt)).hash !== row.pass_hash) {
    return json({ error: 'Current password is wrong.' }, 403);
  }
  const { hash, salt } = await hashPassword(next);
  const keep = await sha256(req.headers.get('authorization').slice(7));
  await env.DB.batch([
    env.DB.prepare('UPDATE users SET pass_hash = ?, salt = ? WHERE id = ?').bind(hash, salt, user.id),
    env.DB.prepare('DELETE FROM sessions WHERE user_id = ? AND token_hash != ?').bind(user.id, keep)   // log out other devices
  ]);
  return json({ ok: true });
}

async function logout(req, env) {
  await env.DB.prepare('DELETE FROM sessions WHERE token_hash = ?')
    .bind(await sha256(req.headers.get('authorization').slice(7))).run();
  return json({ ok: true });
}

// Admin creates accounts with: POST /api/admin/users + header x-admin-token
async function createUser(req, env) {
  if (!env.ADMIN_TOKEN || req.headers.get('x-admin-token') !== env.ADMIN_TOKEN) {
    return json({ error: 'Forbidden' }, 403);
  }
  const body = await req.json().catch(() => ({}));
  const email = String(body.email || '').trim().toLowerCase();
  const password = String(body.password || '');
  if (!email.includes('@') || password.length < 8) {
    return json({ error: 'Need a valid email and a password of at least 8 characters.' }, 400);
  }
  const { hash, salt } = await hashPassword(password);
  try {
    await env.DB.prepare('INSERT INTO users (id, email, pass_hash, salt, created_at) VALUES (?, ?, ?, ?, ?)')
      .bind(crypto.randomUUID(), email, hash, salt, Date.now()).run();
  } catch {
    return json({ error: 'That email already exists.' }, 409);
  }
  return json({ ok: true, email }, 201);
}

function parseReply(text) {
  const j = JSON.parse(text.slice(text.indexOf('{'), text.lastIndexOf('}') + 1));
  const sections = secList(j.sections);
  const points = strList(j.points);
  const fallback = sections.length ? [] : strList(j.transcription ? String(j.transcription).split('\n') : []).slice(0, 12);
  return {
    title: clip(j.title, 'Board Notes', 120),
    subject: clip(j.subject, 'General', 60),
    summary: clip(j.summary, '', 2000),
    sections,
    points: points.length ? points : (fallback.length ? fallback : ['No readable text found. Add your points manually.']),
    definitions: defList(j.definitions).slice(0, 12),
    figures: figList(j.figures),
    transcription: String(j.transcription || '').slice(0, 20000)
  };
}

async function summarize(req, env, user) {
  const { image } = await req.json().catch(() => ({}));
  if (typeof image !== 'string' || !image.startsWith('data:image/')) {
    return json({ error: 'Send a valid image.' }, 400);
  }
  if (image.length > MAX_IMAGE_CHARS) return json({ error: 'Image is too large.' }, 413);
  if (!env.GEMINI_API_KEY) return json({ error: 'Server AI key is not set.' }, 500);

  // per-user daily limit (counted up front, refunded if the AI call fails)
  const day = todayStr();
  if (DAILY_LIMIT > 0) {
    const used = (await env.DB.prepare('SELECT n FROM usage WHERE user_id = ? AND day = ?').bind(user.id, day).first())?.n || 0;
    if (used >= DAILY_LIMIT) {
      return json({ error: `Daily limit reached (${DAILY_LIMIT} summaries per day). Try again tomorrow.` }, 429);
    }
    await env.DB.prepare('INSERT INTO usage (user_id, day, n) VALUES (?, ?, 1) ON CONFLICT(user_id, day) DO UPDATE SET n = n + 1').bind(user.id, day).run();
  }
  const refund = () => DAILY_LIMIT > 0
    ? env.DB.prepare('UPDATE usage SET n = MAX(n - 1, 0) WHERE user_id = ? AND day = ?').bind(user.id, day).run().catch(() => {})
    : null;

  const data = image.split(',')[1];
  const mime = (image.match(/^data:(image\/[\w.+-]+);/) || [])[1] || 'image/jpeg';
  const key = String(env.GEMINI_API_KEY).trim().replace(/^["']|["']$/g, '');
  // Ask every model at the same time; the first good answer wins and the rest are cancelled.
  // This keeps the wait short even when one model is overloaded.
  let lastErr = 'No model responded';
  const controllers = [];
  const body = JSON.stringify({
    contents: [{ parts: [{ inline_data: { mime_type: mime, data } }, { text: READ_PROMPT }] }],
    generationConfig: { responseMimeType: 'application/json', thinkingConfig: { thinkingLevel: 'low' } }
  });
  const askModel = async model => {
    const c = new AbortController();
    controllers.push(c);
    const timer = setTimeout(() => c.abort(), MODEL_TIMEOUT_MS);
    let res;
    try {
      res = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`, {
        method: 'POST',
        signal: c.signal,
        headers: { 'content-type': 'application/json', 'x-goog-api-key': key },
        body
      });
    } finally {
      clearTimeout(timer);
    }
    if (!res.ok) {
      const raw = await res.text();
      let msg = raw;
      try { msg = JSON.parse(raw).error.message || raw; } catch {}
      console.error('Gemini error', model, res.status, raw.slice(0, 300));
      throw new Error(`Gemini ${res.status} (${model}): ${msg.replace(/\s+/g, ' ').slice(0, 160)}`);
    }
    const d = await res.json();
    const text = (d.candidates?.[0]?.content?.parts || []).filter(p => !p.thought).map(p => p.text || '').join('');
    return parseReply(text);   // throws if the reply is not readable JSON
  };

  try {
    const reply = await Promise.any(MODELS.map(askModel));
    controllers.forEach(c => c.abort());
    return json(reply);
  } catch (err) {
    controllers.forEach(c => c.abort());
    const errors = err.errors || [err];
    lastErr = errors.map(e => (e && e.name === 'AbortError' ? 'Gemini did not respond in time' : e?.message || String(e))).join(' | ').slice(0, 400);
    console.error('summarize failed:', lastErr);
  }
  await refund();
  return json({ error: lastErr || 'AI is busy right now. Please try again.' }, 502);
}

async function listNotes(env, user) {
  const { results } = await env.DB.prepare(
    'SELECT id, title, subject, date, points, definitions, raw_text, extra, created_at FROM notes WHERE user_id = ? ORDER BY created_at DESC'
  ).bind(user.id).all();
  return json({
    notes: results.map(r => {
      const ex = safeJSON(r.extra, {});
      return {
        id: r.id, title: r.title, subject: r.subject, date: r.date,
        points: JSON.parse(r.points), definitions: JSON.parse(r.definitions),
        summary: ex.summary || '', sections: ex.sections || [], figures: ex.figures || [],
        rawText: r.raw_text, createdAt: r.created_at
      };
    })
  });
}

async function createNote(req, env, user) {
  const b = await req.json().catch(() => ({}));
  if (typeof b.image !== 'string' || !b.image.startsWith('data:image/')) {
    return json({ error: 'Image is missing.' }, 400);
  }
  if (b.image.length > MAX_IMAGE_CHARS) return json({ error: 'Image is too large.' }, 413);

  const id = crypto.randomUUID();
  const now = Date.now();
  await env.DB.batch([
    env.DB.prepare(`INSERT INTO notes (id, user_id, title, subject, date, points, definitions, raw_text, extra, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .bind(id, user.id, clip(b.title, 'Untitled', 200), clip(b.subject, 'General', 60),
            clip(b.date, todayStr(), 20), JSON.stringify(strList(b.points)),
            JSON.stringify(defList(b.definitions)), String(b.rawText || '').slice(0, 20000),
            cleanExtra(b), now, now),
    env.DB.prepare('INSERT INTO images (note_id, data) VALUES (?, ?)').bind(id, b.image)
  ]);
  return json({ id }, 201);
}

async function updateNote(req, env, user, id) {
  const b = await req.json().catch(() => ({}));
  const r = await env.DB.prepare(
    'UPDATE notes SET title = ?, subject = ?, date = ?, points = ?, definitions = ?, extra = ?, updated_at = ? WHERE id = ? AND user_id = ?'
  ).bind(clip(b.title, 'Untitled', 200), clip(b.subject, 'General', 60), clip(b.date, todayStr(), 20),
         JSON.stringify(strList(b.points)), JSON.stringify(defList(b.definitions)), cleanExtra(b), Date.now(), id, user.id).run();
  if (!r.meta.changes) return json({ error: 'Not found' }, 404);
  return json({ ok: true });
}

async function deleteNote(env, user, id) {
  const r = await env.DB.batch([
    env.DB.prepare('DELETE FROM images WHERE note_id = ? AND note_id IN (SELECT id FROM notes WHERE user_id = ?)')
      .bind(id, user.id),
    env.DB.prepare('DELETE FROM notes WHERE id = ? AND user_id = ?').bind(id, user.id)
  ]);
  if (!r[1].meta.changes) return json({ error: 'Not found' }, 404);
  return json({ ok: true });
}

async function getImage(env, user, id) {
  const row = await env.DB.prepare(
    'SELECT i.data FROM images i JOIN notes n ON n.id = i.note_id WHERE i.note_id = ? AND n.user_id = ?'
  ).bind(id, user.id).first();
  if (!row) return json({ error: 'Not found' }, 404);
  return json({ image: row.data });
}