// functions/api/[[path]].js
// Cloudflare Pages Function — handles all /api/* and /uploads/* routes.
// Place this file at: functions/api/[[path]].js in your Pages project.

export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const BUCKET = env.BUCKET;

  const NO_CACHE = {
    "Cache-Control": "no-store, no-cache, must-revalidate",
    "Pragma": "no-cache"
  };

  if (!BUCKET) {
    return new Response(JSON.stringify({ error: "R2 Bucket not bound. Check Pages → Settings → Functions → R2 Bindings." }), {
      status: 500,
      headers: { "Content-Type": "application/json" }
    });
  }

  // ── GET /api/state ──────────────────────────────────────────────────────────
  if (request.method === 'GET' && url.pathname === '/api/state') {
    try {
      const object = await BUCKET.get("app_state.json");
      if (!object) {
        return new Response(JSON.stringify({ products: [], settings: {} }), {
          headers: { "Content-Type": "application/json", ...NO_CACHE }
        });
      }
      return new Response(object.body, {
        headers: { "Content-Type": "application/json", ...NO_CACHE }
      });
    } catch (error) {
      return new Response(JSON.stringify({ error: error.message }), {
        status: 500, headers: { "Content-Type": "application/json" }
      });
    }
  }

  // ── POST /api/state ─────────────────────────────────────────────────────────
  if (request.method === 'POST' && url.pathname === '/api/state') {
    try {
      const body = await request.text();
      await BUCKET.put("app_state.json", body);
      return new Response(JSON.stringify({ success: true }), {
        headers: { "Content-Type": "application/json" }
      });
    } catch (error) {
      return new Response(JSON.stringify({ error: error.message }), {
        status: 500, headers: { "Content-Type": "application/json" }
      });
    }
  }

  // ── POST /api/upload ────────────────────────────────────────────────────────
  if (request.method === 'POST' && url.pathname === '/api/upload') {
    try {
      const formData = await request.formData();
      const file = formData.get("file");
      if (!file) {
        return new Response(JSON.stringify({ error: "No file provided" }), {
          status: 400, headers: { "Content-Type": "application/json" }
        });
      }
      const safeName = (file.name || "image.jpg")
        .replace(/[^a-zA-Z0-9._-]/g, "_")
        .replace(/_{2,}/g, "_")
        .toLowerCase();
      const key = `uploads/${Date.now()}-${safeName}`;
      const arrayBuffer = await file.arrayBuffer();
      await BUCKET.put(key, arrayBuffer, {
        httpMetadata: { contentType: file.type || "image/jpeg" }
      });
      return new Response(JSON.stringify({ url: `/${key}` }), {
        headers: { "Content-Type": "application/json" }
      });
    } catch (error) {
      return new Response(JSON.stringify({ error: error.message }), {
        status: 500, headers: { "Content-Type": "application/json" }
      });
    }
  }

  // ── GET /uploads/* ──────────────────────────────────────────────────────────
  if (request.method === 'GET' && url.pathname.startsWith('/uploads/')) {
    try {
      const key = url.pathname.slice(1);
      const object = await BUCKET.get(key);
      if (!object) return new Response("Not found", { status: 404 });
      const headers = new Headers();
      object.writeHttpMetadata(headers);
      headers.set("Cache-Control", "public, max-age=31536000, immutable");
      return new Response(object.body, { headers });
    } catch (error) {
      return new Response("Error fetching image", { status: 500 });
    }
  }

  // Fallthrough — should not normally be reached under /api/*
  return new Response("Not found", { status: 404 });
}
