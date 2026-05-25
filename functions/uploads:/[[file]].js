// functions/uploads/[[file]].js
// Serves uploaded images stored in R2.
// Place this file at: functions/uploads/[[file]].js in your Pages project.

export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const BUCKET = env.BUCKET;

  if (!BUCKET) {
    return new Response("R2 bucket not bound", { status: 500 });
  }

  try {
    const key = url.pathname.slice(1); // e.g. "uploads/1234-temple.jpg"
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
