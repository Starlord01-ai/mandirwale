export async function onRequest(context) {
  const { request, env } = context;
  const BUCKET = env.BUCKET;

  if (!BUCKET) {
    return new Response("R2 bucket not bound", { status: 500 });
  }

  try {
    // This perfectly rebuilds the key to match your R2 bucket exactly
    const key = 'uploads/' + context.params.file.join('/');
    
    const object = await BUCKET.get(key);
    
    if (!object) {
      return new Response("Image not found", { status: 404 });
    }
    
    const headers = new Headers();
    object.writeHttpMetadata(headers);
    headers.set("Cache-Control", "public, max-age=31536000, immutable");
    return new Response(object.body, { headers });
    
  } catch (error) {
    return new Response("Error fetching image", { status: 500 });
  }
}
