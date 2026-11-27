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
  if (url.pathname === "/api/export") {
    if (request.method !== "GET") return text("Method not allowed", 405);
    return exportSignatures(request, env);
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

  const keyBytes = decodeKey(env.ENCRYPTION_KEY);
  const now = new Date();
  const createdAt = now.toISOString();
  const ipHash = await hmacHex(keyBytes, request.headers.get("CF-Connecting-IP") || "unknown");
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

  const emailHash = await hmacHex(keyBytes, parsed.value.email);
  const existing = await env.DB.prepare(
    "SELECT id FROM signatures WHERE email_hash = ?",
  ).bind(emailHash).first();
  if (existing) return Response.redirect(new URL("/already", request.url), 303);

  const sealed = await encryptJson(keyBytes, parsed.value);
  const id = crypto.randomUUID();
  try {
    await env.DB.prepare(
      "INSERT INTO signatures (id, created_at, email_hash, iv, payload) VALUES (?, ?, ?, ?, ?)",
    ).bind(id, createdAt, emailHash, sealed.iv, sealed.payload).run();
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

async function exportSignatures(request, env) {
  const header = request.headers.get("Authorization") || "";
  const presented = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (!env.ADMIN_TOKEN || !timingSafeEqual(presented, env.ADMIN_TOKEN)) {
    return text("Unauthorized", 401);
  }

  const keyBytes = decodeKey(env.ENCRYPTION_KEY);
  const rows = await env.DB.prepare(
    "SELECT id, created_at, iv, payload FROM signatures ORDER BY created_at ASC",
  ).all();

  const signatures = [];
  for (const row of rows.results || []) {
    const fields = await decryptJson(keyBytes, row.iv, row.payload);
    signatures.push({ id: row.id, created_at: row.created_at, ...fields });
  }

  return Response.json(
    { count: signatures.length, signatures },
    { headers: { "Cache-Control": "no-store" } },
  );
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

function decodeKey(secret) {
  const bytes = b64ToBytes(secret || "");
  if (bytes.byteLength !== 32) throw new Error("encryption key is not 32 bytes");
  return bytes;
}

async function encryptJson(keyBytes, value) {
  const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const cipher = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    new TextEncoder().encode(JSON.stringify(value)),
  );
  return { iv: bytesToB64(iv), payload: bytesToB64(new Uint8Array(cipher)) };
}

async function decryptJson(keyBytes, iv, payload) {
  const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["decrypt"]);
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: b64ToBytes(iv) },
    key,
    b64ToBytes(payload),
  );
  return JSON.parse(new TextDecoder().decode(plain));
}

async function hmacHex(keyBytes, text) {
  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const mac = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(text));
  return [...new Uint8Array(mac)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function timingSafeEqual(left, right) {
  const a = new TextEncoder().encode(left);
  const b = new TextEncoder().encode(right);
  if (a.byteLength !== b.byteLength || a.byteLength === 0) return false;
  return crypto.subtle.timingSafeEqual(a, b);
}

function bytesToB64(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function b64ToBytes(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
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
