const MAX_BODY = 16_000;
const RATE_LIMIT = 5;
const RATE_WINDOW_MS = 60 * 60 * 1000;
const CCW_CHOICES = new Set(["Yes", "No", "Prefer not to say"]);

const PAGE_STYLE = `
  * { box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    line-height: 1.5; max-width: 700px; margin: 0 auto; padding: 16px;
    background: #ffffff; color: #000000;
  }
  .card { background: #ffffff; border: 2px solid #000000; border-radius: 10px; padding: 20px; }
  h1 { font-size: 1.5rem; margin: 0 0 12px 0; }
  a { color: #0066cc; }
`;

export default {
  async fetch(request, env) {
    try {
      return await route(request, env);
    } catch (error) {
      console.error(JSON.stringify({
        message: "request failed",
        error: error instanceof Error ? error.message : "unknown",
      }));
      return page("Something went wrong. Please try again in a moment.", 500);
    }
  },
};

async function route(request, env) {
  const url = new URL(request.url);
  if (url.pathname === "/api/sign") {
    if (request.method !== "POST") return text("Method not allowed", 405);
    return sign(request, env);
  }
  if (url.pathname.startsWith("/api/")) return text("Not found", 404);
  return env.ASSETS.fetch(request);
}

async function sign(request, env) {
  if (!sameOrigin(request)) return page("This form can only be submitted from this site.", 403);

  const length = Number(request.headers.get("content-length") || "0");
  if (!Number.isFinite(length) || length <= 0 || length > MAX_BODY) {
    return page("That submission could not be read.", 413);
  }

  const type = request.headers.get("content-type") || "";
  if (!type.includes("application/x-www-form-urlencoded") && !type.includes("multipart/form-data")) {
    return page("Submit the form from the petition page.", 415);
  }

  const form = await request.formData();
  if (String(form.get("_gotcha") || "").trim() !== "") {
    return Response.redirect(new URL("/thanks", request.url), 303);
  }

  const parsed = parseSignature(form);
  if (parsed.error) return page(parsed.error, 400);

  const now = new Date();
  const createdAt = now.toISOString();
  const ipHash = await sha256Hex(request.headers.get("CF-Connecting-IP") || "unknown");
  const windowStart = new Date(now.getTime() - RATE_WINDOW_MS).toISOString();

  await env.DB.prepare("DELETE FROM submit_log WHERE created_at < ?")
    .bind(new Date(now.getTime() - 24 * 60 * 60 * 1000).toISOString())
    .run();

  const recent = await env.DB.prepare(
    "SELECT COUNT(*) AS n FROM submit_log WHERE ip_hash = ? AND created_at > ?",
  ).bind(ipHash, windowStart).first();
  if (Number(recent?.n || 0) >= RATE_LIMIT) {
    return page("Too many signatures from this network. Please try again later.", 429);
  }

  const signature = parsed.value;
  const existing = await env.DB.prepare("SELECT id FROM signatures WHERE email = ?")
    .bind(signature.email)
    .first();
  if (existing) return Response.redirect(new URL("/already", request.url), 303);

  const id = crypto.randomUUID();
  try {
    await env.DB.prepare(
      `INSERT INTO signatures
        (id, created_at, name, email, city, county, zip, ccw_holder, comment)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).bind(
      id,
      createdAt,
      signature.name,
      signature.email,
      signature.city,
      signature.county,
      signature.zip,
      signature.ccw_holder,
      signature.comment,
    ).run();
  } catch (error) {
    const message = error instanceof Error ? error.message : "";
    if (message.includes("UNIQUE")) {
      return Response.redirect(new URL("/already", request.url), 303);
    }
    throw error;
  }

  await env.DB.prepare("INSERT INTO submit_log (ip_hash, created_at) VALUES (?, ?)")
    .bind(ipHash, createdAt)
    .run();

  console.log(JSON.stringify({ message: "signature stored", id }));
  return Response.redirect(new URL("/thanks", request.url), 303);
}

function parseSignature(form) {
  const name = clean(form.get("name"), 120);
  const email = clean(form.get("email"), 200).toLowerCase();
  const city = clean(form.get("city"), 80);
  const county = clean(form.get("county"), 80);
  const zip = clean(form.get("zip"), 5);
  const ccw = clean(form.get("ccw_holder"), 32);
  const comment = clean(form.get("comment"), 2000);

  if (name.length < 2) return { error: "Enter your full name." };
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return { error: "Enter a valid email address." };
  if (city.length < 1) return { error: "Enter your city." };
  if (county.length < 1) return { error: "Enter your county." };
  if (zip !== "" && !/^[0-9]{5}$/.test(zip)) return { error: "ZIP code must be 5 digits, or leave it blank." };
  if (!CCW_CHOICES.has(ccw)) return { error: "Choose whether you hold a California CCW license." };

  return { value: { name, email, city, county, zip, ccw_holder: ccw, comment } };
}

function clean(value, max) {
  return String(value ?? "").replace(/[\u0000-\u001F\u007F]/g, "").trim().slice(0, max);
}

function sameOrigin(request) {
  const origin = request.headers.get("Origin");
  if (!origin) return false;
  try {
    return new URL(origin).host === new URL(request.url).host;
  } catch {
    return false;
  }
}

async function sha256Hex(text) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function page(message, status) {
  const body = `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Petition</title><style>${PAGE_STYLE}</style></head>
<body><div class="card"><h1>Could not record the signature</h1><p>${escapeHtml(message)}</p>
<p><a href="/">Back to the petition</a></p></div></body></html>`;
  return new Response(body, {
    status,
    headers: { "Content-Type": "text/html; charset=UTF-8", "Cache-Control": "no-store" },
  });
}

function text(message, status) {
  return new Response(message, { status, headers: { "Cache-Control": "no-store" } });
}

function escapeHtml(value) {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}
