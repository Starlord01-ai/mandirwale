export async function onRequest(context) {
  const { request, env } = context;
  if (!env.BUCKET) return new Response("R2 bucket not bound", { status: 500 });

  try {
    // 1. Grab raw URL path (e.g., "/uploads/123.png")
    // 2. Slice off the first slash (e.g., "uploads/123.png")
    // 3. Decode any weird URL characters the browser added
    const key = decodeURIComponent(new URL(request.url).pathname.slice(1));
    
    const object = await env.BUCKET.get(key);
    
    if (!object) {
      // IF IT FAILS, IT WILL NOW PRINT EXACTLY WHAT IT SEARCHED FOR
      return new Response(`DEBUG ERROR: Image not found. The code searched the R2 bucket for exactly: [${key}]`, { status: 404 });
    }
    
    const headers = new Headers();
    object.writeHttpMetadata(headers);
    headers.set("Cache-Control", "public, max-age=31536000, immutable");
    return new Response(object.body, { headers });
    
  } catch (error) {
    return new Response("Server Error: " + error.message, { status: 500 });
  }
}
