import express from "express";
import dns from "node:dns/promises";
import net from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";
import crypto from "node:crypto";

const { VT_API_KEY: VT_KEY, SB_API_KEY: SB_KEY, PORT = 3000 } = process.env;
const sleep = ms => new Promise(r => setTimeout(r, ms));
const app = express();
app.use(express.json({ limit: "10kb" }));
   const __dirname = path.dirname(fileURLToPath(import.meta.url));
   app.use(express.static(path.join(__dirname, "public")));

/* ---------- tiny rate limiter (per IP) + cache ---------- */
const hits = new Map();
function limited(ip) {
  const now = Date.now(), arr = (hits.get(ip) || []).filter(t => now - t < 60000);
  arr.push(now); hits.set(ip, arr); return arr.length > 15;
}
const cache = new Map(); // url -> {t, data}
const TTL = 60 * 60 * 1000;

/* ---------- SSRF-safe page metadata fetch ---------- */
function isPrivate(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split(".").map(Number);
    return a === 0 || a === 10 || a === 127 || a >= 224 || (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127);
  }
  const l = ip.toLowerCase();
  if (l.startsWith("::ffff:")) return isPrivate(l.slice(7));
  return l === "::1" || l === "::" || /^(fc|fd|fe[89ab])/.test(l);
}
async function assertPublic(u) {
  const host = u.hostname.replace(/^\[|\]$/g, "");
  const ips = net.isIP(host) ? [host] : (await dns.lookup(host, { all: true })).map(a => a.address);
  if (!ips.length || ips.some(isPrivate)) throw new Error("blocked address");
}
const decode = s => s.replace(/&amp;/g, "&").replace(/&quot;/g, '"').replace(/&#39;|&apos;/g, "'").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/\s+/g, " ").trim();
async function pageMeta(url) {
  let cur = new URL(url);
  for (let hop = 0; hop < 4; hop++) {
    await assertPublic(cur);
    const res = await fetch(cur, { redirect: "manual", signal: AbortSignal.timeout(5000),
      headers: { "user-agent": "LFY-LinkChecker/1.0", accept: "text/html" } });
    if (res.status >= 300 && res.status < 400 && res.headers.get("location")) {
      cur = new URL(res.headers.get("location"), cur);
      if (!/^https?:$/.test(cur.protocol)) throw new Error("bad redirect");
      continue;
    }
    if (!/text\/html/i.test(res.headers.get("content-type") || "")) return { finalUrl: cur.href, status: res.status };
    let html = "", size = 0;
    for await (const chunk of res.body) {
      size += chunk.length; html += Buffer.from(chunk).toString("utf8");
      if (size > 200000 || /<\/head>/i.test(html)) break;
    }
    const pick = re => { const m = html.match(re); return m ? decode(m[1]) : ""; };
    const og = n => pick(new RegExp(`<meta[^>]+(?:property|name)=["']${n}["'][^>]*content=["']([^"']*)["']`, "i")) ||
                    pick(new RegExp(`<meta[^>]+content=["']([^"']*)["'][^>]*(?:property|name)=["']${n}["']`, "i"));
    return {
      finalUrl: cur.href, status: res.status, redirected: cur.href !== url,
      title: (og("og:site_name") || pick(/<title[^>]*>([^<]*)<\/title>/i)).slice(0, 120),
      description: (og("og:description") || og("description")).slice(0, 300)
    };
  }
  throw new Error("too many redirects");
}

/* ---------- VirusTotal v3 ---------- */
function parseVT(stats = {}, results = {}) {
  const flaggedBy = Object.entries(results)
    .filter(([, v]) => v.category === "malicious" || v.category === "suspicious")
    .map(([k, v]) => `${k} (${v.result || v.category})`);
  return { malicious: stats.malicious || 0, suspicious: stats.suspicious || 0,
    harmless: stats.harmless || 0, undetected: stats.undetected || 0, flaggedBy };
}
async function virusTotal(url) {
  if (!VT_KEY) return null;
  const h = { "x-apikey": VT_KEY };
  const id = Buffer.from(url).toString("base64url");
  const link = "https://www.virustotal.com/gui/url/" + crypto.createHash("sha256").update(url).digest("hex");
  const r = await fetch(`https://www.virustotal.com/api/v3/urls/${id}`, { headers: h, signal: AbortSignal.timeout(10000) });
  if (r.ok) { const a = (await r.json()).data.attributes; return { ...parseVT(a.last_analysis_stats, a.last_analysis_results), link }; }
  if (r.status !== 404) throw new Error("VirusTotal " + r.status);
  const p = await fetch("https://www.virustotal.com/api/v3/urls", { method: "POST", signal: AbortSignal.timeout(10000),
    headers: { ...h, "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ url }) });
  if (!p.ok) throw new Error("VirusTotal submit " + p.status);
  const aid = (await p.json()).data.id;
  for (let i = 0; i < 6; i++) {
    await sleep(3000);
    const a = await fetch(`https://www.virustotal.com/api/v3/analyses/${aid}`, { headers: h, signal: AbortSignal.timeout(10000) });
    if (!a.ok) continue;
    const at = (await a.json()).data.attributes;
    if (at.status === "completed") return { ...parseVT(at.stats, at.results), link };
  }
  return { pending: true, link };
}

/* ---------- Google Safe Browsing v4 ---------- */
async function safeBrowsing(url) {
  if (!SB_KEY) return null;
  const r = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${SB_KEY}`, {
    method: "POST", headers: { "content-type": "application/json" }, signal: AbortSignal.timeout(8000),
    body: JSON.stringify({ client: { clientId: "lfy", clientVersion: "1.0" }, threatInfo: {
      threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
      platformTypes: ["ANY_PLATFORM"], threatEntryTypes: ["URL"], threatEntries: [{ url }] } })
  });
  if (!r.ok) throw new Error("Safe Browsing " + r.status);
  const j = await r.json();
  return { threats: [...new Set((j.matches || []).map(m => m.threatType))] };
}

/* ---------- API ---------- */
app.post("/api/check", async (req, res) => {
  if (limited(req.ip)) return res.status(429).json({ error: "Too many checks. Wait a minute." });
  let u;
  try { u = new URL(String(req.body?.url || "").slice(0, 2048)); if (!/^https?:$/.test(u.protocol)) throw 0; }
  catch { return res.status(400).json({ error: "Invalid URL" }); }
  const url = u.href;
  const hit = cache.get(url);
  if (hit && Date.now() - hit.t < TTL) return res.json(hit.data);

  const [vt, sb, meta] = await Promise.allSettled([virusTotal(url), safeBrowsing(url), pageMeta(url)]);
  const val = x => (x.status === "fulfilled" ? x.value : null);
  const data = {
    vt: val(vt), sb: val(sb), meta: val(meta),
    configured: { vt: !!VT_KEY, sb: !!SB_KEY },
    errors: [vt, sb].filter(x => x.status === "rejected").map(x => String(x.reason?.message || x.reason))
  };
  if (data.errors.length) console.warn(url, data.errors);
  else cache.set(url, { t: Date.now(), data });
  res.json(data);
});

app.listen(PORT, () => console.log(`LFY running on http://localhost:${PORT}`));
