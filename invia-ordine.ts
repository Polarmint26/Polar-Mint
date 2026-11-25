// =====================================================================
//  POLAR MINT · GESTIONALE · Funzione "invia-ordine"
//  Invia l'ordine a fornitore da ordini@polarmint.it (server Aruba),
//  con il PDF allegato, e ne salva una copia nella "Posta inviata".
//  Segreti richiesti (Supabase › Edge Functions › Secrets):
//    SMTP_USER = ordini@polarmint.it
//    SMTP_PASS = password della casella
//  Facoltativi: SMTP_HOST (smtps.aruba.it), SMTP_PORT (465),
//               IMAP_HOST (imaps.aruba.it), IMAP_PORT (993),
//               MAIL_FROM_NAME (Polar Mint), SENT_FOLDER (es. INBOX.Sent)
// =====================================================================

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, apikey, content-type, x-client-info",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const env = (k: string, d = "") => (Deno.env.get(k) ?? d).trim();
const json = (o: unknown, status = 200) =>
  new Response(JSON.stringify(o), { status, headers: { ...CORS, "Content-Type": "application/json" } });

const enc = new TextEncoder();
const dec = new TextDecoder();
const b64 = (s: string | Uint8Array) => {
  const u = typeof s === "string" ? enc.encode(s) : s;
  let bin = "";
  for (let i = 0; i < u.length; i += 0x8000) bin += String.fromCharCode(...u.subarray(i, i + 0x8000));
  return btoa(bin);
};
const wrap76 = (s: string) => s.replace(/(.{76})/g, "$1\r\n");
const hdrEnc = (s: string) => (/^[\x20-\x7e]*$/.test(s) ? s : "=?UTF-8?B?" + b64(s) + "?=");
const addr = (s: string) => String(s || "").trim();
const isEmail = (s: string) => /^[^\s@<>,;"]+@[^\s@<>,;"]+\.[^\s@<>,;"]+$/.test(s);

// ---------- connessione riga per riga ----------
class Line {
  buf = new Uint8Array(0);
  constructor(public conn: Deno.TlsConn) {}
  async line(): Promise<string> {
    while (true) {
      const i = this.buf.indexOf(10);
      if (i >= 0) {
        const l = dec.decode(this.buf.subarray(0, i)).replace(/\r$/, "");
        this.buf = this.buf.subarray(i + 1);
        return l;
      }
      const chunk = new Uint8Array(16384);
      const n = await this.conn.read(chunk);
      if (n === null) throw new Error("connessione chiusa dal server");
      const nb = new Uint8Array(this.buf.length + n);
      nb.set(this.buf);
      nb.set(chunk.subarray(0, n), this.buf.length);
      this.buf = nb;
    }
  }
  async write(s: string | Uint8Array) {
    let u = typeof s === "string" ? enc.encode(s) : s;
    while (u.length) {
      const n = await this.conn.write(u);
      u = u.subarray(n);
    }
  }
}

// ---------- SMTP ----------
async function smtpReply(c: Line) {
  let l = await c.line(), all = l;
  while (/^\d{3}-/.test(l)) { l = await c.line(); all += "\n" + l; }
  return { code: +l.slice(0, 3), text: all };
}
async function smtpCmd(c: Line, cmd: string, ok: number[], show = cmd) {
  await c.write(cmd + "\r\n");
  const r = await smtpReply(c);
  if (!ok.includes(r.code)) throw new Error(`SMTP ${show.split(" ")[0]}: ${r.text}`);
  return r;
}
async function smtpSend(o: { from: string; rcpt: string[]; raw: string }) {
  const host = env("SMTP_HOST", "smtps.aruba.it"), port = +env("SMTP_PORT", "465");
  const conn = await Deno.connectTls({ hostname: host, port });
  const c = new Line(conn);
  try {
    let r = await smtpReply(c);
    if (r.code !== 220) throw new Error("SMTP: " + r.text);
    await smtpCmd(c, "EHLO polarmint.it", [250]);
    await smtpCmd(c, "AUTH LOGIN", [334]);
    await smtpCmd(c, b64(env("SMTP_USER")), [334], "AUTH utente");
    await smtpCmd(c, b64(env("SMTP_PASS")), [235], "AUTH password");
    await smtpCmd(c, `MAIL FROM:<${o.from}>`, [250]);
    for (const t of o.rcpt) await smtpCmd(c, `RCPT TO:<${t}>`, [250, 251]);
    await smtpCmd(c, "DATA", [354]);
    const body = o.raw.replace(/\r?\n/g, "\r\n").replace(/^\./gm, "..");
    await c.write(body + (body.endsWith("\r\n") ? "" : "\r\n") + ".\r\n");
    r = await smtpReply(c);
    if (r.code !== 250) throw new Error("SMTP DATA: " + r.text);
    try { await c.write("QUIT\r\n"); } catch (_) { /* */ }
  } finally {
    try { conn.close(); } catch (_) { /* */ }
  }
}

// ---------- IMAP: copia nella Posta inviata ----------
async function imapUntil(c: Line, tag: string) {
  const lines: string[] = [];
  while (true) {
    const l = await c.line();
    lines.push(l);
    if (l.startsWith(tag + " ")) {
      if (!/^\S+ OK/i.test(l)) throw new Error("IMAP: " + l);
      return lines;
    }
  }
}
const q = (s: string) => '"' + s.replace(/\\/g, "\\\\").replace(/"/g, '\\"') + '"';
async function imapSaveSent(raw: string) {
  const host = env("IMAP_HOST", "imaps.aruba.it"), port = +env("IMAP_PORT", "993");
  const conn = await Deno.connectTls({ hostname: host, port });
  const c = new Line(conn);
  try {
    const g = await c.line();
    if (!/^\* (OK|PREAUTH)/i.test(g)) throw new Error("IMAP: " + g);
    await c.write(`a1 LOGIN ${q(env("SMTP_USER"))} ${q(env("SMTP_PASS"))}\r\n`);
    await imapUntil(c, "a1");
    let folder = env("SENT_FOLDER");
    if (!folder) {
      await c.write('a2 LIST "" "*"\r\n');
      const ls = (await imapUntil(c, "a2")).filter((l) => l.startsWith("* LIST"));
      const parse = (l: string) => {
        const m = l.match(/^\* LIST \(([^)]*)\) (?:"[^"]*"|NIL) (.+)$/i);
        if (!m) return null;
        let n = m[2].trim();
        if (n.startsWith('"')) n = n.slice(1, -1).replace(/\\(.)/g, "$1");
        return { flags: m[1], name: n };
      };
      const all = ls.map(parse).filter(Boolean) as { flags: string; name: string }[];
      const pick = all.find((f) => /\\Sent\b/i.test(f.flags)) ||
        all.find((f) => /(^|[./])(sent|sent items|sent messages|posta inviata|inviata|inviati)$/i.test(f.name));
      folder = pick ? pick.name : "INBOX.Sent";
    }
    const data = enc.encode(raw.replace(/\r?\n/g, "\r\n"));
    await c.write(`a3 APPEND ${q(folder)} (\\Seen) {${data.length}}\r\n`);
    const cont = await c.line();
    if (!cont.startsWith("+")) throw new Error("IMAP APPEND: " + cont);
    await c.write(data);
    await c.write("\r\n");
    await imapUntil(c, "a3");
    try { await c.write("a4 LOGOUT\r\n"); } catch (_) { /* */ }
    return folder;
  } finally {
    try { conn.close(); } catch (_) { /* */ }
  }
}

// ---------- messaggio ----------
function buildMime(o: { from: string; fromName: string; to: string[]; replyTo: string[]; subject: string; text: string; pdf?: string; filename?: string }) {
  const bnd = "pm-" + crypto.randomUUID();
  const date = new Date().toUTCString().replace("GMT", "+0000");
  const h = [
    `From: ${hdrEnc(o.fromName)} <${o.from}>`,
    `To: ${o.to.join(", ")}`,
    ...(o.replyTo.length ? [`Reply-To: ${o.replyTo.join(", ")}`] : []),
    `Subject: ${hdrEnc(o.subject)}`,
    `Date: ${date}`,
    `Message-ID: <${crypto.randomUUID()}@polarmint.it>`,
    "MIME-Version: 1.0",
    `Content-Type: multipart/mixed; boundary="${bnd}"`,
  ];
  const parts = [
    `--${bnd}\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n${wrap76(b64(o.text))}`,
  ];
  if (o.pdf) {
    const fn = (o.filename || "ordine.pdf").replace(/[^\w.\- ]/g, "_");
    parts.push(`--${bnd}\r\nContent-Type: application/pdf; name="${fn}"\r\nContent-Disposition: attachment; filename="${fn}"\r\nContent-Transfer-Encoding: base64\r\n\r\n${wrap76(o.pdf.replace(/\s/g, ""))}`);
  }
  return h.join("\r\n") + "\r\n\r\n" + parts.join("\r\n") + `\r\n--${bnd}--\r\n`;
}

// ---------- utente collegato ----------
async function checkUser(req: Request) {
  const auth = req.headers.get("Authorization") || "";
  const url = env("SUPABASE_URL"), key = req.headers.get("apikey") || env("SUPABASE_ANON_KEY");
  if (!auth.startsWith("Bearer ")) throw { status: 401, msg: "Accesso non valido" };
  const u = await fetch(url + "/auth/v1/user", { headers: { Authorization: auth, apikey: key } });
  if (!u.ok) throw { status: 401, msg: "Sessione scaduta: esci e rientra nel gestionale" };
  const user = await u.json();
  const r = await fetch(url + "/rest/v1/app_users?select=role,perms&user_id=eq." + user.id, { headers: { Authorization: auth, apikey: key } });
  const row = r.ok ? (await r.json())[0] : null;
  if (!row) throw { status: 403, msg: "Utente non abilitato al gestionale" };
  const ok = row.role === "admin" || row.role === "editor" || row.role === "operatore" || +(row.perms?.purch ?? 0) >= 2;
  if (!ok) throw { status: 403, msg: "Non hai il permesso di inviare ordini a fornitore" };
  return user.email as string;
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: CORS });
  if (req.method !== "POST") return json({ error: "Metodo non consentito" }, 405);
  let who = "";
  try { who = await checkUser(req); } catch (e) { return json({ error: (e as any).msg || String(e) }, (e as any).status || 401); }
  if (!env("SMTP_USER") || !env("SMTP_PASS")) return json({ error: "Invio non configurato: mancano SMTP_USER / SMTP_PASS nei Secrets di Supabase" }, 500);
  let b: any;
  try { b = await req.json(); } catch (_) { return json({ error: "Richiesta non valida" }, 400); }
  const to = (Array.isArray(b.to) ? b.to : [b.to]).map(addr).filter(Boolean);
  const replyTo = [...new Set((b.replyTo || []).map(addr).filter(isEmail))] as string[];
  if (!to.length || !to.every(isEmail)) return json({ error: "Indirizzo del fornitore non valido: " + to.join(", ") }, 400);
  if (!b.subject || !b.text) return json({ error: "Oggetto o testo mancanti" }, 400);
  if (b.pdf && b.pdf.length > 14_000_000) return json({ error: "PDF troppo grande" }, 400);
  const from = env("SMTP_USER");
  const raw = buildMime({ from, fromName: env("MAIL_FROM_NAME", "Polar Mint"), to, replyTo, subject: String(b.subject), text: String(b.text), pdf: b.pdf, filename: b.filename });
  try {
    await smtpSend({ from, rcpt: to, raw });
  } catch (e) {
    const m = String((e as Error).message || e);
    return json({ error: /535|auth/i.test(m) ? "Il server Aruba ha rifiutato email o password di " + from + " (controlla SMTP_PASS)" : "Invio non riuscito: " + m }, 502);
  }
  let sent = "", warn = "";
  try { sent = await imapSaveSent(raw); } catch (e) { warn = "Email inviata, ma non sono riuscito a salvarne la copia nella Posta inviata: " + String((e as Error).message || e); }
  return json({ ok: true, from, to, replyTo, sentFolder: sent, warn, by: who });
});
