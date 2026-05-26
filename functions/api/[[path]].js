// functions/api/[[path]].js
// Cloudflare Pages Function — handles all /api/* routes.
// Env variables needed:
//   BUCKET          — R2 binding
//   ADMIN_PASSWORD  — secret: your admin password
//   SESSION_SECRET  — secret: random 32+ char string for signing tokens
//   GROQ_API_KEY    — secret: for AI features (Groq)

// ── In-memory rate limiter (5 attempts / 15 min per IP) ─────────────────────
const loginAttempts = new Map();
function getRateEntry(ip) {
  const now = Date.now();
  let e = loginAttempts.get(ip) || { count: 0, resetAt: now + 900000 };
  if (now > e.resetAt) { e = { count: 0, resetAt: now + 900000 }; }
  return e;
}

// ── Token helpers (HS256 JWT-style) ─────────────────────────────────────────
async function signToken(secret, payload) {
  const enc = s => btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
  const header = enc(JSON.stringify({ alg:'HS256' }));
  const body   = enc(JSON.stringify(payload));
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret),
    { name:'HMAC', hash:'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(`${header}.${body}`));
  return `${header}.${body}.${enc(String.fromCharCode(...new Uint8Array(sig)))}`;
}

async function verifyToken(secret, token) {
  try {
    const [h, b, s] = token.split('.');
    if (!h || !b || !s) return false;
    const key = await crypto.subtle.importKey(
      'raw', new TextEncoder().encode(secret),
      { name:'HMAC', hash:'SHA-256' }, false, ['verify']
    );
    const dec = t => t.replace(/-/g,'+').replace(/_/g,'/');
    const sigBytes = Uint8Array.from(atob(dec(s)), c => c.charCodeAt(0));
    const valid = await crypto.subtle.verify('HMAC', key, sigBytes, new TextEncoder().encode(`${h}.${b}`));
    if (!valid) return false;
    const payload = JSON.parse(atob(dec(b)));
    return payload.exp > Date.now();
  } catch { return false; }
}

async function requireAuth(request, env) {
  if (!env.SESSION_SECRET) return true; // dev mode: no secret = open
  const auth = request.headers.get('Authorization') || '';
  return verifyToken(env.SESSION_SECRET, auth.replace(/^Bearer\s+/, ''));
}

// ── TOTP helpers (RFC 6238 / Google Authenticator compatible) ────────────────
function base32ToBytes(s) {
  const abc = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const clean = s.toUpperCase().replace(/=+$/, '');
  let bits = 0, val = 0;
  const out = [];
  for (const c of clean) {
    const i = abc.indexOf(c);
    if (i < 0) continue;
    val = (val << 5) | i; bits += 5;
    if (bits >= 8) { out.push((val >>> (bits - 8)) & 0xff); bits -= 8; }
  }
  return new Uint8Array(out);
}

function generateBase32(len = 20) {
  const abc = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const bytes = crypto.getRandomValues(new Uint8Array(len));
  let r = '', buf = 0, bits = 0;
  for (const b of bytes) {
    buf = (buf << 8) | b; bits += 8;
    while (bits >= 5) { bits -= 5; r += abc[(buf >>> bits) & 31]; }
  }
  return r;
}

async function computeTOTP(base32Secret, unixSec) {
  const counter = Math.floor(unixSec / 30);
  const cb = new Uint8Array(8);
  let c = counter;
  for (let i = 7; i >= 0; i--) { cb[i] = c & 0xff; c = Math.floor(c / 256); }
  const key = await crypto.subtle.importKey(
    'raw', base32ToBytes(base32Secret),
    { name:'HMAC', hash:'SHA-1' }, false, ['sign']
  );
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', key, cb));
  const off = sig[19] & 0xf;
  const code = (((sig[off]&0x7f)<<24)|((sig[off+1]&0xff)<<16)|((sig[off+2]&0xff)<<8)|(sig[off+3]&0xff)) % 1000000;
  return String(code).padStart(6, '0');
}

async function verifyTOTP(secret, code) {
  const t = Math.floor(Date.now() / 1000);
  for (const d of [-1, 0, 1]) {
    if (await computeTOTP(secret, t + d * 30) === String(code).trim()) return true;
  }
  return false;
}

// ── Main handler ─────────────────────────────────────────────────────────────
export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const BUCKET = env.BUCKET;
  const NO_CACHE = { 'Cache-Control': 'no-store, no-cache, must-revalidate', 'Pragma': 'no-cache' };
  const json = (data, status = 200) => new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json' } });

  if (!BUCKET) return json({ error: 'R2 Bucket not bound. Check Pages → Settings → Functions → R2 Bindings.' }, 500);

  // ── POST /api/admin/login ──────────────────────────────────────────────────
  if (request.method === 'POST' && url.pathname === '/api/admin/login') {
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    const entry = getRateEntry(ip);

    if (entry.count >= 5) {
      const wait = Math.ceil((entry.resetAt - Date.now()) / 60000);
      return json({ error: `Too many attempts. Try again in ${wait} minute${wait !== 1 ? 's' : ''}.` }, 429);
    }

    try {
      const { password, totp } = await request.json();
      const correctPw = env.ADMIN_PASSWORD || 'marble123';

      if (password !== correctPw) {
        entry.count++;
        loginAttempts.set(ip, entry);
        const left = 5 - entry.count;
        return json({ error: `Wrong password. ${left} attempt${left !== 1 ? 's' : ''} remaining.` }, 401);
      }

      // Check TOTP
      const cfgObj = await BUCKET.get('admin_config.json').catch(() => null);
      const cfg = cfgObj ? JSON.parse(await cfgObj.text()) : {};

      if (cfg.totpEnabled && cfg.totpSecret) {
        if (!totp) return json({ requireTotp: true });
        const ok = await verifyTOTP(cfg.totpSecret, totp);
        if (!ok) {
          entry.count++;
          loginAttempts.set(ip, entry);
          return json({ error: 'Invalid authenticator code.' }, 401);
        }
      }

      // Issue token
      entry.count = 0;
      loginAttempts.set(ip, entry);

      if (!env.SESSION_SECRET) {
        return json({ token: 'dev-unsigned', warning: 'Set SESSION_SECRET for secure tokens.' });
      }
      const token = await signToken(env.SESSION_SECRET, {
        sub: 'admin',
        exp: Date.now() + 8 * 3600 * 1000,
        jti: crypto.randomUUID()
      });
      return json({ token });
    } catch (e) { return json({ error: e.message }, 500); }
  }

  // ── POST /api/admin/setup-totp ─────────────────────────────────────────────
  if (request.method === 'POST' && url.pathname === '/api/admin/setup-totp') {
    if (!await requireAuth(request, env)) return json({ error: 'Unauthorized' }, 401);
    try {
      const secret = generateBase32();
      const shopName = encodeURIComponent('Jainson Marble Admin');
      const uri = `otpauth://totp/${shopName}?secret=${secret}&issuer=JainsonMarble&algorithm=SHA1&digits=6&period=30`;
      // Don't enable yet — just return the secret for verification
      return json({ secret, uri });
    } catch (e) { return json({ error: e.message }, 500); }
  }

  // ── POST /api/admin/confirm-totp ───────────────────────────────────────────
  // Verify user scanned correctly before enabling
  if (request.method === 'POST' && url.pathname === '/api/admin/confirm-totp') {
    if (!await requireAuth(request, env)) return json({ error: 'Unauthorized' }, 401);
    try {
      const { secret, code } = await request.json();
      if (!await verifyTOTP(secret, code)) return json({ error: 'Code incorrect — check your app and try again.' }, 400);
      await BUCKET.put('admin_config.json', JSON.stringify({ totpEnabled: true, totpSecret: secret }));
      return json({ success: true });
    } catch (e) { return json({ error: e.message }, 500); }
  }

  // ── POST /api/admin/disable-totp ───────────────────────────────────────────
  if (request.method === 'POST' && url.pathname === '/api/admin/disable-totp') {
    if (!await requireAuth(request, env)) return json({ error: 'Unauthorized' }, 401);
    try {
      await BUCKET.put('admin_config.json', JSON.stringify({ totpEnabled: false, totpSecret: null }));
      return json({ success: true });
    } catch (e) { return json({ error: e.message }, 500); }
  }

  // ── GET /api/admin/totp-status ─────────────────────────────────────────────
  if (request.method === 'GET' && url.pathname === '/api/admin/totp-status') {
    if (!await requireAuth(request, env)) return json({ error: 'Unauthorized' }, 401);
    const cfgObj = await BUCKET.get('admin_config.json').catch(() => null);
    const cfg = cfgObj ? JSON.parse(await cfgObj.text()) : {};
    return new Response(JSON.stringify({ totpEnabled: !!cfg.totpEnabled }), {
      headers: { 'Content-Type': 'application/json', ...NO_CACHE }
    });
  }

  // ── GET /api/state ─────────────────────────────────────────────────────────
  if (request.method === 'GET' && url.pathname === '/api/state') {
    try {
      const object = await BUCKET.get('app_state.json');
      if (!object) return new Response(JSON.stringify({ products: [], settings: {} }), { headers: { 'Content-Type': 'application/json', ...NO_CACHE } });
      return new Response(object.body, { headers: { 'Content-Type': 'application/json', ...NO_CACHE } });
    } catch (e) { return json({ error: e.message }, 500); }
  }

  // ── POST /api/state  (auth required) ──────────────────────────────────────
  if (request.method === 'POST' && url.pathname === '/api/state') {
    if (!await requireAuth(request, env)) return json({ error: 'Unauthorized' }, 401);
    try {
      const body = await request.text();
      // Strip password from state before storing — password lives in env now
      const parsed = JSON.parse(body);
      if (parsed.settings) delete parsed.settings.password;
      await BUCKET.put('app_state.json', JSON.stringify(parsed));
      return json({ success: true });
    } catch (e) { return json({ error: e.message }, 500); }
  }

  // ── POST /api/upload  (auth required) ─────────────────────────────────────
  if (request.method === 'POST' && url.pathname === '/api/upload') {
    if (!await requireAuth(request, env)) return json({ error: 'Unauthorized' }, 401);
    try {
      const formData = await request.formData();
      const file = formData.get('file');
      if (!file) return json({ error: 'No file provided' }, 400);
      const safeName = (file.name || 'image.jpg').replace(/[^a-zA-Z0-9._-]/g, '_').replace(/_{2,}/g, '_').toLowerCase();
      const key = `uploads/${Date.now()}-${safeName}`;
      await BUCKET.put(key, await file.arrayBuffer(), { httpMetadata: { contentType: file.type || 'image/jpeg' } });
      return json({ url: `/${key}` });
    } catch (e) { return json({ error: e.message }, 500); }
  }

  // ── POST /api/ai/describe  (auth required) ─────────────────────────────────
  if (request.method === 'POST' && url.pathname === '/api/ai/describe') {
    if (!await requireAuth(request, env)) return json({ error: 'Unauthorized' }, 401);
    if (!env.GROQ_API_KEY) return json({ error: 'GROQ_API_KEY not set' }, 500);
    try {
      const { imageUrl } = await request.json();
      const aiRes = await fetch('https://api.groq.com/openai/v1/chat/completions', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json', 
          'Authorization': `Bearer ${env.GROQ_API_KEY}`
        },
        body: JSON.stringify({
          model: 'llama-2-90b-vision', 
          max_tokens: 400,
          messages: [{ 
            role: 'user', 
            content: [
              { type: 'image_url', image_url: { url: imageUrl } },
              { type: 'text', text: 'This is a product photo for an Indian marble temple and murti shop. Analyse it.\nRespond ONLY with valid JSON, no markdown:\n{"name":"short product name","category":"Marble Temple OR Murti OR Idol OR Custom","material":"Marble OR Corian OR Stone OR Mixed","desc":"2-3 sentence product description"}' }
            ]
          }]
        })
      });
      const d = await aiRes.json();
      const clean = (d.choices?.[0]?.message?.content || '{}').replace(/```json|```/g, '').trim();
      return json(JSON.parse(clean));
    } catch (e) { return json({ error: e.message }, 500); }
  }

  // ── POST /api/ai/chat  (public for customer widget, auth for admin tasks) ──
  if (request.method === 'POST' && url.pathname === '/api/ai/chat') {
    if (!env.GROQ_API_KEY) return json({ error: 'GROQ_API_KEY not set' }, 500);
    try {
      const body = await request.json();

      if (body.task === 'describe') {
        if (!await requireAuth(request, env)) return json({ error: 'Unauthorized' }, 401);
        const { name, category, material, size } = body;
        const aiRes = await fetch('https://api.groq.com/openai/v1/chat/completions', {
          method: 'POST',
          headers: { 
            'Content-Type': 'application/json', 
            'Authorization': `Bearer ${env.GROQ_API_KEY}`
          },
          body: JSON.stringify({
            model: 'mixtral-8x7b-32768', 
            max_tokens: 200,
            messages: [{ role: 'user', content: `Write a 2-3 sentence product description for an Indian marble shop listing.\nProduct: ${name || 'Marble item'}\nCategory: ${category || 'Temple'}\nMaterial: ${material || 'Marble'}\nSize: ${size || 'Custom'}\nWarm, devotional, specific. Plain text only.` }]
          })
        });
        const d = await aiRes.json();
        return json({ text: d.choices?.[0]?.message?.content || '' });
      }

      // Customer chat (public)
      const { message, history, catalogue } = body;
      const systemPrompt = `You are a helpful, warm assistant for Jainson Marble, a shop selling marble temples (mandirs) and devotional murtis in Delhi. Help customers find products, answer pricing and availability questions, and guide them toward making an enquiry.\n\nCurrent catalogue (name | category | material | size | price):\n${catalogue || 'No catalogue data'}\n\nKeep responses concise (2-4 sentences). Suggest WhatsApp enquiry for custom orders.`;
      const aiRes = await fetch('https://api.groq.com/openai/v1/chat/completions', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json', 
          'Authorization': `Bearer ${env.GROQ_API_KEY}`
        },
        body: JSON.stringify({
          model: 'mixtral-8x7b-32768', 
          max_tokens: 300, 
          system: systemPrompt,
          messages: [...(Array.isArray(history) ? history.slice(-10) : []), { role: 'user', content: message }]
        })
      });
      const d = await aiRes.json();
      return json({ text: d.choices?.[0]?.message?.content || 'Sorry, unable to respond right now.' });
    } catch (e) { return json({ error: e.message }, 500); }
  }

  return new Response('Not found', { status: 404 });
}