// Board to Notes: Cloudflare Worker backend
// Routes: /api/* handled here, everything else served from public/ (the app).

const MODELS = ['gemini-3.8-flash', 'gemini-3.5-flash-lite'];
const SESSION_DAYS = 30;
const MAX_IMAGE_CHARS = 900000;

const READ_PROMPT = `You are reading a photo of a classroom board or notebook page. It may be handwritten, tilted, blurry or shadowed. Read it carefully, then return ONLY a JSON object (no other text) with this shape:
{
  "transcription": "all readable text, line by line",
  "title": "the main heading, e.g. 'CH #6: Application and Impact of Computing'",
  "subject": "one of: Computer Science, Mathematics, Physics, Chemistry, Biology, English, Urdu, History, Islamiyat, Pakistan Studies, Economics, General",
  "points": ["main points as short sentences, in the same language as the board"],
  "definitions": [{"term": "...", "def": "..."}]
}
Rules: Use only what is visible on the board. Do not invent facts. Keep each point short. Write words you cannot read as [unclear]. Put key terms and their meanings in definitions, not in points.`;

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

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (!url.pathname.startsWith('/api/')) return env.ASSETS.fetch(req);
    try {
      return await route(req, env, url.pathname);
    } catch (err) {
      console.error(err);
      return json({ error: 'Server error. Please try again.' }, 500);
    }
  }
};

async function route(req, env, p) {
  const m = req.method;

  // public / admin routes
  if (p === '/api/login' && m === 'POST') return login(req, env);
  if (p === '/api/admin/users' && m === 'POST') return createUser(req, env);

  // everything below needs a logged-in user
  const user = await currentUser(req, env);
  if (!user) return json({ error: 'Please log in again.' }, 401);

  if (p === '/api/logout' && m === 'POST') return logout(req, env);
  if (p === '/api/me' && m === 'GET') return json({ email: user.email });
  if (p === '/api/summarize' && m === 'POST') return summarize(req, env);
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

  const token = hex(crypto.getRandomValues(new Uint8Array(32)));
  const now = Date.now();
  await env.DB.prepare('INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)')
    .bind(await sha256(token), row.id, now, now + SESSION_DAYS * 864e5).run();
  return json({ token, email });
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
  const points = strList(j.points);
  return {
    title: clip(j.title, 'Board Notes', 120),
    subject: clip(j.subject, 'General', 60),
    points: points.length ? points : ['No readable text found. Add your points manually.'],
    definitions: defList(j.definitions).slice(0, 12),
    transcription: String(j.transcription || '').slice(0, 20000)
  };
}

async function summarize(req, env) {
  const { image } = await req.json().catch(() => ({}));
  if (typeof image !== 'string' || !image.startsWith('data:image/')) {
    return json({ error: 'Send a valid image.' }, 400);
  }
  if (image.length > MAX_IMAGE_CHARS) return json({ error: 'Image is too large.' }, 413);
  if (!env.GEMINI_API_KEY) return json({ error: 'Server AI key is not set.' }, 500);

  const data = image.split(',')[1];
  let lastErr = 'No model responded';
  for (const model of MODELS) {
    const res = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-goog-api-key': env.GEMINI_API_KEY },
      body: JSON.stringify({
        contents: [{ parts: [{ inline_data: { mime_type: 'image/jpeg', data } }, { text: READ_PROMPT }] }],
        generationConfig: { responseMimeType: 'application/json', temperature: 0.2 }
      })
    });
    if (res.ok) {
      const d = await res.json();
      const text = (d.candidates?.[0]?.content?.parts || []).map(p => p.text || '').join('');
      try {
        return json(parseReply(text));
      } catch {
        return json({ error: 'AI reply could not be read. Please try again.' }, 502);
      }
    }
    lastErr = `Gemini ${res.status}: ${(await res.text()).slice(0, 120)}`;
    // try the next model only for limit / unavailable errors
    if (![429, 404, 503].includes(res.status)) break;
  }
  return json({ error: lastErr }, 502);
}

async function listNotes(env, user) {
  const { results } = await env.DB.prepare(
    'SELECT id, title, subject, date, points, definitions, raw_text, created_at FROM notes WHERE user_id = ? ORDER BY created_at DESC'
  ).bind(user.id).all();
  return json({
    notes: results.map(r => ({
      id: r.id, title: r.title, subject: r.subject, date: r.date,
      points: JSON.parse(r.points), definitions: JSON.parse(r.definitions),
      rawText: r.raw_text, createdAt: r.created_at
    }))
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
    env.DB.prepare(`INSERT INTO notes (id, user_id, title, subject, date, points, definitions, raw_text, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .bind(id, user.id, clip(b.title, 'Untitled', 200), clip(b.subject, 'General', 60),
            clip(b.date, todayStr(), 20), JSON.stringify(strList(b.points)),
            JSON.stringify(defList(b.definitions)), String(b.rawText || '').slice(0, 20000), now, now),
    env.DB.prepare('INSERT INTO images (note_id, data) VALUES (?, ?)').bind(id, b.image)
  ]);
  return json({ id }, 201);
}

async function updateNote(req, env, user, id) {
  const b = await req.json().catch(() => ({}));
  const r = await env.DB.prepare(
    'UPDATE notes SET title = ?, subject = ?, date = ?, points = ?, definitions = ?, updated_at = ? WHERE id = ? AND user_id = ?'
  ).bind(clip(b.title, 'Untitled', 200), clip(b.subject, 'General', 60), clip(b.date, todayStr(), 20),
         JSON.stringify(strList(b.points)), JSON.stringify(defList(b.definitions)), Date.now(), id, user.id).run();
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