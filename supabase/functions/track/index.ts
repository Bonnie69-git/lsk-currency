// track: события мини-аппа LSK Currency для /stats в боте.
// POST {e, uid, from, to} (можно text/plain — так шлёт navigator.sendBeacon).
// Пишет в public.events через service_role (ключ Supabase сам кладёт в env
// функции, в коде его нет). Принимает только события из белого списка.
// uid берётся из Telegram на стороне клиента и не проверяется — для
// статистики этого достаточно, ни на что другое он не влияет.
const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "authorization, apikey, content-type, x-client-info",
};
const EVENTS = new Set(["app_open", "app_transfer", "app_partner_click"]);
const TAG = /^[A-Za-z0-9 ()_.-]{1,24}$/;

// Простой лимит на IP, чтобы таблицу нельзя было завалить мусором
const hits = new Map<string, { t: number; n: number }>();
function limited(ip: string): boolean {
  const now = Date.now();
  const h = hits.get(ip);
  if (!h || now - h.t > 60_000) {
    hits.set(ip, { t: now, n: 1 });
    if (hits.size > 5000) hits.clear();
    return false;
  }
  return ++h.n > 30;
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: CORS });
  if (req.method !== "POST") return new Response("method", { status: 405, headers: CORS });
  const ip = (req.headers.get("x-forwarded-for") || "").split(",")[0].trim() || "?";
  if (limited(ip)) return new Response(null, { status: 204, headers: CORS });

  let body: any;
  try {
    body = JSON.parse((await req.text()).slice(0, 2000));
  } catch {
    return new Response("bad", { status: 400, headers: CORS });
  }
  const e = String(body?.e || "");
  if (!EVENTS.has(e)) return new Response("bad", { status: 400, headers: CORS });
  const uid = Number(body?.uid);
  const tag = (v: unknown) => (typeof v === "string" && TAG.test(v) ? v : null);
  const row = {
    user_id: Number.isSafeInteger(uid) && uid > 0 ? uid : 0,
    event_type: e,
    from_cur: tag(body?.from),
    to_cur: tag(body?.to),
    chat_type: "miniapp",
  };

  const url = Deno.env.get("SUPABASE_URL")!;
  const key = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
  const r = await fetch(`${url}/rest/v1/events`, {
    method: "POST",
    headers: { apikey: key, Authorization: `Bearer ${key}`, "Content-Type": "application/json", Prefer: "return=minimal" },
    body: JSON.stringify(row),
  }).catch(() => null);
  if (!r?.ok) console.error("insert failed", r?.status, await r?.text().catch(() => ""));
  return new Response(null, { status: 204, headers: CORS });
});
