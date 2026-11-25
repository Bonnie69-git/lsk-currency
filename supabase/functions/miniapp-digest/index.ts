// miniapp-digest: настройка ежедневной сводки из мини-аппа LSK Currency.
// Подпись Telegram (initData) проверяется так же, как в miniapp-alerts.
// Пишет в ту же таблицу subscriptions, что /subscribe в боте; сводку шлёт бот.
// Своя сводка: chat_id = id пользователя. Сводка группы (?chat=-100…): только
// если бот недавно отметил этого человека админом группы — отметку
// dgadm:<chat>:<user> бот ставит в app_config, когда админ открывает панель
// сводки в группе.
const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "authorization, apikey, content-type, x-client-info, x-init-data",
};
const TG_PUBLIC_KEY = "e7bf03a2fa4602af4580703d88dda5bb59f32ed8b02a56c187fe7d34caed242d";
const MAX_AGE_SEC = 48 * 3600;
const GRANT_TTL_SEC = 48 * 3600;
const MAX_CODES = 16;
const TZ_MIN = 100, TZ_MAX = 113; // TZ_ZONE_BASE + индекс TZ_ZONES в боте
// Всё, что бот умеет показывать в сводке (как SUPPORTED в miniapp-alerts)
const ALLOWED = new Set("ADA AED ALL AMD ARS ATOM AUD AVAX AZN BBD BCH BDT BGN BHD BNB BOB BRL BSD BTC BWP BYN BZD CAD CHF CLP CNY COP CRC CUP CZK DKK DOGE DOP DOT DZD EGP ETB ETH EUR FJD GBP GEL GHS GTQ HKD HNL HUF IDR ILS INR IQD IRR ISK JMD JOD JPY KES KHR KPW KRW KWD KZT LAK LBP LINK LKR LTC MAD MDL MKD MMK MNT MUR MXN MYR MZN NAD NGN NIO NOK NPR NZD OMR PAB PEN PGK PHP PKR PLN PYG QAR RON RSD RUB SAR SCR SEK SGD SOL THB TND TON TOP TRX TRY TTD TWD TZS UAH UGX UNI USD USDC USDT UYU UZS VND VUV WST XAF XAG XAU XLM XOF XPD XPT XRP YER ZAR ZMW".split(" "));

const SB_URL = Deno.env.get("SUPABASE_URL")!;
const SB_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const sbHeaders = { apikey: SB_KEY, Authorization: `Bearer ${SB_KEY}`, "Content-Type": "application/json" };
const sb = (path: string, init: RequestInit = {}) =>
  fetch(`${SB_URL}/rest/v1/${path}`, { ...init, headers: { ...sbHeaders, ...(init.headers || {}) }, signal: AbortSignal.timeout(8000) });
const json = (body: unknown, status = 200) => Response.json(body, { status, headers: CORS });

let botId: string | null = null;
async function getBotId(): Promise<string | null> {
  if (botId) return botId;
  const r = await sb("app_config?key=eq.bot_id&select=value");
  const rows = r.ok ? await r.json() : [];
  botId = rows[0]?.value || null;
  return botId;
}

let pubKey: CryptoKey | null = null;
const hex = (h: string) => new Uint8Array(h.match(/../g)!.map((b) => parseInt(b, 16)));
const b64url = (s: string) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4)), (c) => c.charCodeAt(0));

async function verifyInitData(initData: string, bot: string, key: CryptoKey, now = Date.now() / 1000) {
  const p = new URLSearchParams(initData);
  const sig = p.get("signature");
  if (!sig) return null;
  const pairs: string[] = [];
  for (const [k, v] of p) if (k !== "hash" && k !== "signature") pairs.push(`${k}=${v}`);
  pairs.sort();
  const data = new TextEncoder().encode(`${bot}:WebAppData\n${pairs.join("\n")}`);
  let ok = false;
  try { ok = await crypto.subtle.verify("Ed25519", key, b64url(sig), data); } catch { ok = false; }
  if (!ok) return null;
  const authDate = Number(p.get("auth_date") || 0);
  if (!authDate || now - authDate > MAX_AGE_SEC) return null;
  try { const u = JSON.parse(p.get("user") || "null"); return u?.id ? u : null; } catch { return null; }
}

async function isGroupAdmin(chat: number, uid: number): Promise<boolean> {
  const r = await sb(`app_config?key=eq.${encodeURIComponent(`dgadm:${chat}:${uid}`)}&select=value`);
  const rows = r.ok ? await r.json() : [];
  const ts = Number(rows[0]?.value || 0);
  return ts > 0 && Date.now() / 1000 - ts < GRANT_TTL_SEC;
}

async function readSub(chat: number) {
  const r = await sb(`subscriptions?chat_id=eq.${chat}&select=id,send_hour,send_minute,currencies,tz_offset&order=id.asc`);
  if (!r.ok) return { ok: false, rows: [] as any[] };
  return { ok: true, rows: await r.json() as any[] };
}
const shape = (s: any) => s ? { h: s.send_hour ?? 9, m: s.send_minute ?? 0, currencies: s.currencies || "", tz: s.tz_offset ?? 0 } : null;

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: CORS });
  const initData = req.headers.get("x-init-data") || "";
  const bot = await getBotId().catch(() => null);
  if (!bot) return json({ error: "not_ready" }, 503);
  pubKey ??= await crypto.subtle.importKey("raw", hex(TG_PUBLIC_KEY), { name: "Ed25519" }, false, ["verify"]);
  const user = initData ? await verifyInitData(initData, bot, pubKey) : null;
  if (!user) return json({ error: "unauthorized" }, 401);
  const uid = Number(user.id);

  const chatParam = new URL(req.url).searchParams.get("chat");
  let chat = uid, title = "";
  if (chatParam) {
    chat = Number(chatParam);
    if (!Number.isSafeInteger(chat) || chat >= 0) return json({ error: "bad_params" }, 400);
    if (!(await isGroupAdmin(chat, uid))) return json({ error: "not_admin" }, 403);
    const t = await sb(`chat_settings?chat_id=eq.${chat}&select=title`).catch(() => null);
    title = t?.ok ? ((await t.json())[0]?.title || "") : "";
  }

  const cur = await readSub(chat);
  if (!cur.ok) return json({ error: "db" }, 502);

  if (req.method === "GET") return json({ sub: shape(cur.rows[0]), title });

  if (req.method === "DELETE") {
    const r = await sb(`subscriptions?chat_id=eq.${chat}`, { method: "DELETE" });
    return r.ok ? json({ ok: true, sub: null }) : json({ error: "db" }, 502);
  }

  if (req.method === "POST") {
    const b = await req.json().catch(() => ({}));
    const h = Number(b.h), m = Number(b.m), tz = Number(b.tz);
    if (!Number.isInteger(h) || h < 0 || h > 23 || !Number.isInteger(m) || m < 0 || m > 59) return json({ error: "bad_time" }, 400);
    // Пояс: зона из списка бота или старый фиксированный сдвиг, который уже был у этой сводки
    const oldTz = cur.rows[0]?.tz_offset;
    if (!Number.isInteger(tz) || !((tz >= TZ_MIN && tz <= TZ_MAX) || tz === oldTz)) return json({ error: "bad_tz" }, 400);
    const codes = [...new Set((Array.isArray(b.currencies) ? b.currencies : []).map((c: unknown) => String(c).toUpperCase()))]
      .filter((c) => ALLOWED.has(c as string)).slice(0, MAX_CODES);
    if (!codes.length) return json({ error: "empty" }, 400);
    const row = { send_hour: h, send_minute: m, tz_offset: tz, currencies: codes.join(","), user_id: uid };
    let r: Response;
    if (cur.rows.length) {
      r = await sb(`subscriptions?chat_id=eq.${chat}`, { method: "PATCH", headers: { Prefer: "return=minimal" }, body: JSON.stringify(row) });
      // одна сводка на чат: лишние строки (старая логика) убираем
      if (r.ok && cur.rows.length > 1) {
        const extra = cur.rows.slice(1).map((x: any) => x.id).join(",");
        await sb(`subscriptions?id=in.(${extra})`, { method: "DELETE" }).catch(() => null);
      }
    } else {
      r = await sb("subscriptions", { method: "POST", headers: { Prefer: "return=minimal" }, body: JSON.stringify({ ...row, chat_id: chat }) });
    }
    if (!r.ok) return json({ error: "db" }, 502);
    const lang = b.lang === "ru" ? "ru" : "en";
    await Promise.all([
      chat === uid ? sb("user_lang?on_conflict=user_id", {
        method: "POST", headers: { Prefer: "resolution=ignore-duplicates,return=minimal" },
        body: JSON.stringify({ user_id: uid, lang }),
      }).catch(() => null) : null,
      sb("events", {
        method: "POST", headers: { Prefer: "return=minimal" },
        body: JSON.stringify({ user_id: uid, event_type: "subscribe", chat_type: "miniapp" }),
      }).catch(() => null),
    ]);
    const after = await readSub(chat);
    return json({ ok: true, sub: shape(after.rows[0]) });
  }
  return json({ error: "method" }, 405);
});
