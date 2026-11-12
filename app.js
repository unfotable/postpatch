(() => {
'use strict';
/* ===================== UTILS ===================== */
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const reduce = matchMedia('(prefers-reduced-motion: reduce)');
const EASE = 'cubic-bezier(0.22, 1, 0.36, 1)';
let toastTimer;
function toast(msg) {
  const t = $('#toast'); t.textContent = msg; t.classList.add('show');
  clearTimeout(toastTimer); toastTimer = setTimeout(() => t.classList.remove('show'), 2600);
}
const LS = {
  get(k, d = null) { try { const v = localStorage.getItem(k); return v === null ? d : JSON.parse(v); } catch { return d; } },
  set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch { /* storage blocked */ } },
  del(k) { try { localStorage.removeItem(k); } catch { /* ignore */ } },
};
const b64e = u8 => btoa(String.fromCharCode(...u8)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const b64d = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
const randomToken = () => b64e(crypto.getRandomValues(new Uint8Array(16)));
const canvasBlob = (c, type = 'image/png') => new Promise((res, rej) => c.toBlob(b => b ? res(b) : rej(new Error('encode')), type));
function postmarkOf(iso) {
  const d = new Date(iso + 'T12:00:00');
  return `${String(d.getDate()).padStart(2, '0')} ${d.toLocaleString('en-GB', { month: 'short' }).toUpperCase().replace('.', '')} ${d.getFullYear()}`;
}
const todayISO = () => { const d = new Date(); return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`; };
function enter(el) {
  if (reduce.matches || !el.animate) return;
  el.animate([{ opacity: 0, transform: 'translateY(12px)' }, { opacity: 1, transform: 'none' }], { duration: 300, easing: EASE });
}

/* ===================== STORAGE (IndexedDB for stamps) ===================== */
let dbp;
const openDB = () => dbp ||= new Promise((res, rej) => {
  const r = indexedDB.open('postpatch', 1);
  r.onupgradeneeded = () => {
    const s = r.result.createObjectStore('stamps', { keyPath: 'id', autoIncrement: true });
    s.createIndex('owner', 'owner'); s.createIndex('token', 'token', { unique: true });
  };
  r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error);
});
const reqP = r => new Promise((res, rej) => { r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); });
const store = async mode => (await openDB()).transaction('stamps', mode).objectStore('stamps');
const dbAll = async owner => reqP((await store('readonly')).index('owner').getAll(owner));
const dbAdd = async rec => reqP((await store('readwrite')).add(rec));
const dbPut = async rec => reqP((await store('readwrite')).put(rec));
const dbDel = async id => reqP((await store('readwrite')).delete(id));
const dbGet = async id => reqP((await store('readonly')).get(id));
const dbByToken = async t => reqP((await store('readonly')).index('token').get(t));

/* ===================== ACCOUNTS: public ID + password =====================
   Same mechanism as the chat app:
   - an ID is 3-14 letters/numbers, public and unique across the network
   - the network (public MQTT broker) holds a RETAINED profile {id, name, salt, hash}
     where hash = SHA-256(salt:password); the password itself is never sent anywhere
   - creating checks the network first, so a taken ID is refused
   - this device keeps a vault (keyring) of every ID it created or signed into,
     so signing in again works instantly and offline
   - signing in on a new device chases the ID across two brokers + a live handshake */
const ROOT = 'postpatch/v1/';
const topic = (...p) => ROOT + p.join('/');
const MQTT_URL = 'wss://broker.hivemq.com:8884/mqtt';
const BROKERS = [MQTT_URL, 'wss://broker.emqx.io:8084/mqtt'];
const CODE_ABC = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
const uid = () => Math.random().toString(36).slice(2, 10);
const normId = s => String(s || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
const chunkId = c => String(c || '').replace(/(.{4})(?=.)/g, '$1-');
const randomId = () => Array.from({ length: 8 }, () => CODE_ABC[Math.floor(Math.random() * CODE_ABC.length)]).join('');
const idFromName = nm => { // "Meera" -> MEE482, ITSME7739, MECHAT42 ...
  const base = normId(nm); if (base.length < 2) return randomId();
  const digs = n => Array.from({ length: n }, () => Math.floor(Math.random() * 10)).join('');
  const r = n => Math.floor(Math.random() * n);
  return [() => base.slice(0, 3 + r(3)) + digs(2 + r(3)), () => 'ITS' + base.slice(0, 2 + r(2)) + digs(2 + r(3)), () => base.slice(0, 2) + 'CHAT' + digs(1 + r(3))][r(3)]();
};
const session = () => LS.get('pp_session');

/* device vault */
const vaultAll = () => { const v = LS.get('pp_vault', {}); return v && typeof v === 'object' && !Array.isArray(v) ? v : {}; };
const vaultGet = id => vaultAll()[normId(id)] || null;
const vaultPut = entry => { const all = vaultAll(); all[entry.id] = { ...(all[entry.id] || {}), ...entry, savedAt: Date.now() }; LS.set('pp_vault', all); };

/* SHA-256 hex: WebCrypto when available, pure-JS fallback otherwise (identical output either way) */
function sha256Hex(str) {
  const maxWord = Math.pow(2, 32); let ascii;
  try { ascii = encodeURIComponent(String(str)).replace(/%([0-9A-F]{2})/g, (m, p) => String.fromCharCode(parseInt(p, 16))); } catch { ascii = String(str); }
  const words = [], asciiBitLength = ascii.length * 8, hash = [], k = [], isComposite = {}; let primeCounter = 0;
  for (let candidate = 2; primeCounter < 64; candidate++) {
    if (!isComposite[candidate]) {
      for (let i = 0; i < 313; i += candidate) isComposite[i] = candidate;
      hash[primeCounter] = (Math.pow(candidate, .5) * maxWord) | 0; k[primeCounter++] = (Math.pow(candidate, 1 / 3) * maxWord) | 0;
    }
  }
  ascii += '\x80'; while (ascii.length % 64 - 56) ascii += '\x00';
  for (let i = 0; i < ascii.length; i++) { const j = ascii.charCodeAt(i); if (j >> 8) return ''; words[i >> 2] |= j << ((3 - i) % 4) * 8; }
  words[words.length] = (asciiBitLength / maxWord) | 0; words[words.length] = asciiBitLength;
  const rr = (v, a) => (v >>> a) | (v << (32 - a));
  for (let j0 = 0; j0 < words.length;) {
    const w = words.slice(j0, j0 += 16), oldHash = hash.slice(0), hh = hash.slice(0, 8);
    for (let i = 0; i < 64; i++) {
      const w15 = w[i - 15], w2 = w[i - 2], a = hh[0], e = hh[4];
      const temp1 = hh[7] + (rr(e, 6) ^ rr(e, 11) ^ rr(e, 25)) + ((e & hh[5]) ^ ((~e) & hh[6])) + k[i]
        + (w[i] = (i < 16) ? w[i] : (w[i - 16] + (rr(w15, 7) ^ rr(w15, 18) ^ (w15 >>> 3)) + w[i - 7] + (rr(w2, 17) ^ rr(w2, 19) ^ (w2 >>> 10))) | 0);
      const temp2 = (rr(a, 2) ^ rr(a, 13) ^ rr(a, 22)) + ((a & hh[1]) ^ (a & hh[2]) ^ (hh[1] & hh[2]));
      hh.unshift((temp1 + temp2) | 0); hh[4] = (hh[4] + temp1) | 0;
    }
    for (let i = 0; i < 8; i++) hash[i] = (hh[i] + oldHash[i]) | 0;
  }
  let result = '';
  for (let i = 0; i < 8; i++) for (let j = 3; j + 1; j--) { const b = (hash[i] >> (j * 8)) & 255; result += ((b < 16) ? 0 : '') + b.toString(16); }
  return result;
}
const sha256 = async s => {
  try {
    if (crypto?.subtle?.digest) {
      const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(String(s)));
      return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
    }
  } catch { /* fall through */ }
  return sha256Hex(s);
};
const pwHash = (salt, pw) => sha256(salt + ':' + pw);

/* one retained-message pull; resolves { data, connected } so "offline" differs from "not there" */
function pullRetained(t, match, opts = {}) {
  return new Promise(resolve => {
    if (typeof mqtt === 'undefined') return resolve({ data: null, connected: false });
    let c; try { c = mqtt.connect(opts.url || MQTT_URL, { clientId: 'ppp-' + uid(), keepalive: 20, reconnectPeriod: 0, connectTimeout: 6000 }); } catch { return resolve({ data: null, connected: false }); }
    let done = false, sawConn = false, to, fast;
    const finish = v => { if (done) return; done = true; clearTimeout(to); clearTimeout(fast); try { c.end(true); } catch { /* ignore */ } resolve(v); };
    to = setTimeout(() => finish({ data: null, connected: sawConn }), opts.timeout || 5000);
    c.on('connect', () => { sawConn = true; try { c.subscribe(t, { qos: 0 }); } catch { /* ignore */ } fast = setTimeout(() => finish({ data: null, connected: true }), opts.fastMs || 2600); });
    c.on('message', (_t, payload) => { const s = payload.toString(); if (!s) return finish({ data: null, connected: true }); try { const d = JSON.parse(s); if (match(d)) finish({ data: d, connected: true }); } catch { /* ignore */ } });
    c.on('error', () => finish({ data: null, connected: sawConn }));
    c.on('close', () => { if (!done && sawConn) finish({ data: null, connected: true }); });
  });
}
const profileMatch = id => d => d && d.app === 'postpatch' && d.profile && d.profile.id === id;
const fetchProfile = (id, timeout) => pullRetained(topic('profile', id), profileMatch(id), { timeout: timeout || 4500, fastMs: 2400 });

/* live handshake: any ONLINE device that owns the ID answers a ping on need/<ID> with its profile */
function lookupLive(id, timeout) {
  return new Promise(resolve => {
    if (typeof mqtt === 'undefined') return resolve({ data: null, connected: false });
    let c; try { c = mqtt.connect(MQTT_URL, { clientId: 'ppn-' + uid(), keepalive: 20, reconnectPeriod: 0, connectTimeout: 6000 }); } catch { return resolve({ data: null, connected: false }); }
    let done = false, sawConn = false, to, r1, r2;
    const finish = v => { if (done) return; done = true; clearTimeout(to); clearTimeout(r1); clearTimeout(r2); try { c.end(true); } catch { /* ignore */ } resolve(v); };
    to = setTimeout(() => finish({ data: null, connected: sawConn }), timeout || 4200);
    c.on('connect', () => {
      sawConn = true; try { c.subscribe(topic('profile', id), { qos: 0 }); } catch { /* ignore */ }
      const ping = () => { try { c.publish(topic('need', id), JSON.stringify({ app: 'postpatch', type: 'need', id, t: Date.now() }), { qos: 0 }); } catch { /* ignore */ } };
      ping(); r1 = setTimeout(ping, 900); r2 = setTimeout(ping, 2000);
    });
    c.on('message', (_t, payload) => { const s = payload.toString(); if (!s) return; try { const d = JSON.parse(s); if (profileMatch(id)(d)) finish({ data: d, connected: true }); } catch { /* ignore */ } });
    c.on('error', () => finish({ data: null, connected: sawConn }));
  });
}
/* sign-in chase: broker 1, broker 2, then a live handshake, before ever saying "not found" */
async function lookupIdentity(id, onStep) {
  const tries = [{ url: BROKERS[0] }, { url: BROKERS[1] }, { live: true }];
  let connected = false, profile = null;
  for (let i = 0; i < tries.length && !profile; i++) {
    onStep?.(tries[i].live ? 'live' : 'lookup');
    const r = tries[i].live ? await lookupLive(id, 4200) : await pullRetained(topic('profile', id), profileMatch(id), { url: tries[i].url, timeout: i === 0 ? 6000 : 4600, fastMs: i === 0 ? 2600 : 2200 });
    if (r.connected) connected = true;
    if (r.data) profile = r.data.profile;
  }
  return { profile, connected };
}
/* publish a retained profile (best effort, resolves true when the broker acknowledged it) */
function publishProfile(p, url) {
  return new Promise(resolve => {
    if (typeof mqtt === 'undefined') return resolve(false);
    let c; try { c = mqtt.connect(url || MQTT_URL, { clientId: 'ppw-' + uid(), reconnectPeriod: 0, connectTimeout: 6000 }); } catch { return resolve(false); }
    let done = false; const fin = v => { if (done) return; done = true; try { c.end(true); } catch { /* ignore */ } resolve(v); };
    setTimeout(() => fin(false), 7000);
    c.on('connect', () => c.publish(topic('profile', p.id), JSON.stringify({ app: 'postpatch', type: 'profile', profile: { id: p.id, name: p.name, salt: p.salt, hash: p.hash }, updatedAt: Date.now() }), { qos: 1, retain: true }, err => fin(!err)));
    c.on('error', () => fin(false));
  });
}
/* while signed in, stay online: keep the profile registered and answer other devices' sign-in pings */
let presence = null;
function stopPresence() { try { presence?.end(true); } catch { /* ignore */ } presence = null; }
function startPresence() {
  stopPresence();
  const id = session(), v = id && vaultGet(id); if (!v || typeof mqtt === 'undefined') return;
  try {
    const c = mqtt.connect(MQTT_URL, { clientId: 'ppo-' + uid(), keepalive: 30, reconnectPeriod: 5000, connectTimeout: 6000 });
    const body = () => JSON.stringify({ app: 'postpatch', type: 'profile', profile: { id: v.id, name: v.name, salt: v.salt, hash: v.hash }, updatedAt: Date.now() });
    c.on('connect', () => { c.subscribe(topic('need', id)); c.publish(topic('profile', id), body(), { qos: 1, retain: true }); });
    c.on('message', t => { if (t === topic('need', id)) c.publish(topic('profile', id), body(), { qos: 0 }); });
    c.on('error', () => { /* retries on its own */ });
    presence = c;
  } catch { /* offline: the vault still signs us in */ }
}

/* ===================== PRIVACY: metadata scan, seal, verify ===================== */
const OWNER_ID = 'DEVANSHU';
/* Pin your inbox public key here (paste the JSON from the owner dashboard) so nobody can swap it on the public broker. */
const OWNER_PUB = null;
const emailOk = e => /^[^\s@]{1,64}@[^\s@]+\.[^\s@]{2,}$/.test(e) && e.length <= 120;
function ask(t, p, labels) {
  return new Promise(res => {
    const d = $('#ask'); $('#ask-t').textContent = t; $('#ask-p').textContent = p;
    $('#ask-b').replaceChildren(...labels.map((l, i) => { const b = document.createElement('button'); b.type = 'button'; b.className = 'btn ' + (i ? 'btn--secondary' : 'btn--primary'); b.textContent = l; b.onclick = () => { d.close(); res(i); }; return b; }));
    d.addEventListener('close', () => res(-1), { once: true }); d.showModal();
  });
}
/* reads what the ORIGINAL photo file carried (the stamp itself is always re-drawn from pixels) */
async function scanMeta(file) {
  const out = { gps: false, device: '', time: false, other: false };
  try {
    const buf = await file.slice(0, 262144).arrayBuffer(), b = new DataView(buf);
    if (file.type === 'image/jpeg') {
      let o = 2;
      while (o < b.byteLength - 4 && b.getUint8(o) === 255) {
        const m = b.getUint8(o + 1), len = b.getUint16(o + 2);
        if (m === 0xE1) {
          if (String.fromCharCode(...new Uint8Array(buf, o + 4, 4)) === 'Exif') {
            const t = o + 10, L = b.getUint16(t) === 0x4949, u16 = p => b.getUint16(p, L), u32 = p => b.getUint32(p, L), ifd = t + u32(t + 4), n = u16(ifd);
            for (let i = 0; i < n; i++) {
              const e = ifd + 2 + i * 12, tag = u16(e);
              if (tag === 0x8825) out.gps = true; if (tag === 0x0132) out.time = true;
              if (tag === 0x0110) { const c = u32(e + 4), q = c > 4 ? t + u32(e + 8) : e + 8; out.device = String.fromCharCode(...new Uint8Array(buf, q, Math.min(c, 40))).replace(/\0.*/, ''); }
            }
          } else out.other = true;
        }
        if (m === 0xDA) break; o += 2 + len;
      }
    } else out.other = /Exif|eXIf|XML:com\.adobe/.test(new TextDecoder('latin1').decode(buf.slice(0, 65536)));
  } catch { /* unreadable: treat as unknown */ }
  return out;
}
const crcT = (() => { const t = []; for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xEDB88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0; } return t; })();
const crc32 = u => { let c = -1; for (const b of u) c = crcT[(c ^ b) & 255] ^ (c >>> 8); return (c ^ -1) >>> 0; };
async function addText(blob, kv) { // optional tEXt chunks, inserted right after IHDR
  const u = new Uint8Array(await blob.arrayBuffer()), enc = new TextEncoder(), parts = [];
  for (const [k, v] of kv) {
    const d = enc.encode(k + '\0' + String(v).replace(/[^\x20-\x7e]/g, '?')), c = new Uint8Array(12 + d.length), dv = new DataView(c.buffer);
    dv.setUint32(0, d.length); c.set(enc.encode('tEXt'), 4); c.set(d, 8); dv.setUint32(8 + d.length, crc32(c.subarray(4, 8 + d.length))); parts.push(c);
  }
  return new Blob([u.subarray(0, 33), ...parts, u.subarray(33)], { type: 'image/png' });
}
/* invisible seal: 32-bit ID spread over every pixel as +-4 noise; found again by correlation, survives lossless copies and mild compression */
const AMP = 4;
function rng(s) { return () => { s = (s + 0x6D2B79F5) | 0; let t = Math.imul(s ^ (s >>> 15), 1 | s); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return (t ^ (t >>> 14)) >>> 0; }; }
function applySeal(cv, hex) {
  const g = cv.getContext('2d'), im = g.getImageData(0, 0, cv.width, cv.height), d = im.data, r = rng(0x5EA1), n = parseInt(hex, 16);
  const bits = Array.from({ length: 32 }, (_, i) => (n >>> (31 - i)) & 1);
  for (let p = 0; p < d.length; p += 4) { const v = r(), dl = ((v >>> 5) & 1 ? 1 : -1) * (bits[v & 31] ? AMP : -AMP); if (d[p + 3] === 255) { d[p] += dl; d[p + 1] += dl; d[p + 2] += dl; } }
  g.putImageData(im, 0, 0);
}
function readSeal(cv) {
  const W = cv.width, H = cv.height, d = cv.getContext('2d').getImageData(0, 0, W, H).data, r = rng(0x5EA1), cor = new Float64Array(32), cnt = new Float64Array(32);
  for (let y = 0; y < H; y++) for (let x = 0; x < W; x++) {
    const p = (y * W + x) * 4, v = r(); if (x < 1 || y < 1 || x > W - 2 || y > H - 2 || d[p + 3] < 255) continue;
    const hp = d[p + 1] - (d[p - 3] + d[p + 5] + d[p - W * 4 + 1] + d[p + W * 4 + 1]) / 4, b = v & 31; cor[b] += hp * ((v >>> 5) & 1 ? 1 : -1); cnt[b]++;
  }
  let id = 0, str = 0;
  for (let i = 0; i < 32; i++) { const m = cor[i] / ((cnt[i] * AMP) || 1); str += Math.abs(m); if (m > 0) id |= 1 << (31 - i); }
  return { found: str / 32 > 0.1, id: (id >>> 0).toString(16).padStart(8, '0') };
}
async function pixHash(cv) { // fingerprint of opaque pixels only, so PNG decode rounding at perforation edges can't matter
  const d = new Uint8Array(cv.getContext('2d').getImageData(0, 0, cv.width, cv.height).data);
  for (let i = 0; i < d.length; i += 4) if (d[i + 3] !== 255) d[i] = d[i + 1] = d[i + 2] = d[i + 3] = 0;
  try { return [...new Uint8Array(await crypto.subtle.digest('SHA-256', d))].map(b => b.toString(16).padStart(2, '0')).join(''); }
  catch { let h = 2166136261; for (let i = 0; i < d.length; i += 7) h = Math.imul(h ^ d[i], 16777619); return 'f' + (h >>> 0).toString(16); }
}
$('#seal-toggle').addEventListener('click', e => { const b = e.currentTarget; b.setAttribute('aria-checked', b.getAttribute('aria-checked') !== 'true'); });
$('#verify-btn').addEventListener('click', () => $('#vfile').click());
$('#vfile').addEventListener('change', async e => {
  const f = e.target.files[0]; e.target.value = ''; if (!f) return;
  try {
    const bmp = await createImageBitmap(f).catch(() => loadImg(f)), cv = document.createElement('canvas'); cv.width = 989; cv.height = 1200;
    cv.getContext('2d').drawImage(bmp, 0, 0, 989, 1200);
    const exact = bmp.width === 989 && bmp.height === 1200, s = readSeal(cv); let msg;
    if (!s.found) msg = 'No Postpatch seal found. This is not a sealed Postpatch stamp, or editing wiped the seal.';
    else {
      const mine = (await dbAll(session())).find(r => r.seal === s.id);
      if (!mine) msg = `A Postpatch seal (${s.id}) is present, but it is not from this album.`;
      else msg = `Seal matches your stamp from ${postmarkOf(mine.takenAt)}. ` + (exact && await pixHash(cv) === mine.px ? 'Pixels are identical: this is the untouched original.' : 'The pixels differ, so it was resized, compressed or edited.');
    }
    await ask('Verification', msg, ['Done']);
  } catch { toast('We couldn\'t read that image.'); }
});

/* ===================== OWNER INBOX: emails are encrypted in the visitor's browser (RSA-OAEP + AES-GCM) ===================== */
const LK = 'pp_leads', KK = 'pp_owner_key', RSA = { name: 'RSA-OAEP', hash: 'SHA-256' };
const leads = () => LS.get(LK, {});
const pub1 = (t, obj) => new Promise(res => {
  if (typeof mqtt === 'undefined') return res(false);
  let c; try { c = mqtt.connect(MQTT_URL, { clientId: 'ppl-' + uid(), reconnectPeriod: 0, connectTimeout: 6000 }); } catch { return res(false); }
  const fin = v => { try { c.end(true); } catch { /* ignore */ } res(v); }; setTimeout(() => fin(false), 7000);
  c.on('connect', () => c.publish(t, JSON.stringify(obj), { qos: 1, retain: true }, err => fin(!err))); c.on('error', () => fin(false));
});
async function sendLead(email) {
  try {
    const r = OWNER_PUB ? { data: { jwk: OWNER_PUB } } : await pullRetained(topic('owner', OWNER_ID, 'pub'), d => d && d.jwk, { timeout: 5000, fastMs: 2800 });
    if (!r.data) throw 0;
    const pk = await crypto.subtle.importKey('jwk', r.data.jwk, RSA, false, ['encrypt']);
    const k = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']), iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, k, new TextEncoder().encode(JSON.stringify({ email, t: Date.now() })));
    const wk = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, pk, await crypto.subtle.exportKey('raw', k));
    if (!await pub1(topic('owner', OWNER_ID, 'lead', randomToken()), { app: 'postpatch', type: 'lead', wk: b64e(new Uint8Array(wk)), iv: b64e(iv), ct: b64e(new Uint8Array(ct)) })) throw 0;
    LS.del('pp_lead_pending');
  } catch { LS.set('pp_lead_pending', email); } // retried on the next visit
}
async function openLead(d, jwk) {
  const pk = await crypto.subtle.importKey('jwk', jwk, RSA, false, ['decrypt']);
  const k = await crypto.subtle.importKey('raw', await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, pk, b64d(d.wk)), 'AES-GCM', false, ['decrypt']);
  return JSON.parse(new TextDecoder().decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64d(d.iv) }, k, b64d(d.ct))));
}
let ownerConn = null;
const setLive = on => { const el = $('#o-live'); el.classList.toggle('on', on); el.textContent = on ? 'Inbox live' : 'Reconnecting'; };
function stopOwner() { try { ownerConn?.end(true); } catch { /* ignore */ } ownerConn = null; }
function startOwner() {
  stopOwner(); if (typeof mqtt === 'undefined') return;
  const c = mqtt.connect(BROKERS[0], { clientId: 'ppd-' + uid(), keepalive: 30, reconnectPeriod: 5000, connectTimeout: 6000 });
  c.on('connect', () => { c.subscribe(topic('owner', OWNER_ID, 'lead', '+'), { qos: 1 }); setLive(true); });
  c.on('close', () => setLive(false)); c.on('error', () => { /* retries */ });
  c.on('message', async (t, p) => {
    const id = t.split('/').pop(), k = LS.get(KK); if (!k || !p.length || leads()[id]) return;
    try { const d = JSON.parse(p.toString()), v = await openLead(d, k.priv); if (d.type === 'lead' && typeof v.email === 'string' && emailOk(v.email)) { const all = leads(); all[id] = { email: v.email, t: +v.t || Date.now() }; LS.set(LK, all); ownerRender(); } } catch { /* not for this key */ }
  });
  ownerConn = c;
}
const dayKey = t => new Date(t).toDateString();
function ownerRender() {
  const all = Object.values(leads()).sort((a, b) => b.t - a.t), now = Date.now(), D = 864e5, q = $('#o-q').value.trim().toLowerCase();
  $('#o-stats').innerHTML = [['Emails collected', all.length, 1], ['Today', all.filter(l => dayKey(l.t) === dayKey(now)).length], ['Last 7 days', all.filter(l => now - l.t < 7 * D).length], ['Email domains', new Set(all.map(l => l.email.split('@')[1])).size]]
    .map(([k, v, dark]) => `<div class="stat card ${dark ? 'card--dark' : ''}"><span class="caption">${k}</span><b>${v}</b></div>`).join('');
  const days = Array.from({ length: 14 }, (_, i) => { const d = new Date(now - (13 - i) * D); return { k: dayKey(d), n: 0, l: d.toLocaleDateString('en-GB', { day: 'numeric', month: 'short' }) }; });
  all.forEach(l => { const x = days.find(d => d.k === dayKey(l.t)); if (x) x.n++; });
  const mx = Math.max(1, ...days.map(d => d.n));
  $('#o-bars').replaceChildren(...days.map(d => { const i = document.createElement('i'); i.style.height = Math.max(4, d.n / mx * 100) + '%'; i.title = `${d.l}: ${d.n}`; return i; }));
  const rows = all.filter(l => l.email.toLowerCase().includes(q)).map(l => {
    const r = document.createElement('div'), a = document.createElement('div'), s = document.createElement('span'), c = document.createElement('small');
    r.className = 'lead'; a.className = 'avatar'; c.className = 'caption'; a.textContent = l.email[0].toUpperCase(); s.textContent = l.email; // textContent: decrypted data is never trusted as HTML
    c.textContent = new Date(l.t).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' }); r.append(a, s, c); return r;
  });
  const empty = document.createElement('p'); empty.className = 'body-quiet'; empty.textContent = all.length ? 'No matches.' : 'No sign-ups yet. They land here when someone adds an email on the welcome cards.';
  $('#o-list').replaceChildren(...(rows.length ? rows : [empty]));
  $('#o-key').innerHTML = LS.get(KK)
    ? '<h2 class="title">Inbox key active</h2><p class="body-quiet">Pin it: copy the public key into OWNER_PUB in the code, so nobody can swap it on the public broker. Keep a backup, because emails can only be opened with this key.</p><button class="btn btn--secondary" data-act="pub" type="button">Copy public key</button><button class="btn btn--secondary" data-act="bak" type="button">Download key backup</button><button class="btn-text" data-act="res" type="button" style="color:var(--cream-text)">Restore from backup</button>'
    : '<h2 class="title">Create your inbox key</h2><p class="body-quiet">Emails are encrypted on the visitor\'s device, so only a key kept in this browser can open them. Create it to start receiving.</p><button class="btn btn--primary" data-act="gen" type="button">Create key</button><button class="btn-text" data-act="res" type="button" style="color:var(--cream-text)">Restore from backup</button>';
}
function showOwner() { show('v-owner'); $('#o-title').textContent = `Hello, ${(vaultGet(session()) || {}).name || 'owner'}.`; ownerRender(); startOwner(); }
$('#o-q').addEventListener('input', ownerRender);
$('#o-copy').addEventListener('click', async () => { try { await navigator.clipboard.writeText(Object.values(leads()).map(l => l.email).join('\n')); toast('Emails copied.'); } catch { toast('Copy was blocked by the browser.'); } });
$('#o-csv').addEventListener('click', () => {
  const q = x => '"' + String(x).replace(/^[=+\-@]/, "'$&").replace(/"/g, '""') + '"';
  const csv = [['email', 'received'], ...Object.values(leads()).sort((a, b) => b.t - a.t).map(l => [l.email, new Date(l.t).toISOString()])].map(r => r.map(q).join(',')).join('\n');
  const u = URL.createObjectURL(new Blob([csv], { type: 'text/csv' })), a = document.createElement('a'); a.href = u; a.download = 'postpatch-signups.csv'; a.click(); setTimeout(() => URL.revokeObjectURL(u), 1000);
});
$('#o-key').addEventListener('click', async e => {
  const act = e.target.closest('[data-act]')?.dataset.act; if (!act) return;
  if (act === 'gen') {
    const kp = await crypto.subtle.generateKey({ name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['encrypt', 'decrypt']);
    const k = { pub: await crypto.subtle.exportKey('jwk', kp.publicKey), priv: await crypto.subtle.exportKey('jwk', kp.privateKey) };
    LS.set(KK, k); pub1(topic('owner', OWNER_ID, 'pub'), { jwk: k.pub }); startOwner(); ownerRender(); toast('Inbox key created.');
  }
  if (act === 'pub') { try { await navigator.clipboard.writeText(JSON.stringify(LS.get(KK).pub)); toast('Public key copied.'); } catch { toast('Copy was blocked by the browser.'); } }
  if (act === 'bak') { const u = URL.createObjectURL(new Blob([JSON.stringify(LS.get(KK))], { type: 'application/json' })), a = document.createElement('a'); a.href = u; a.download = 'postpatch-owner-key.json'; a.click(); setTimeout(() => URL.revokeObjectURL(u), 1000); }
  if (act === 'res') $('#o-restore').click();
});
$('#o-restore').addEventListener('change', async e => {
  const f = e.target.files[0]; e.target.value = ''; if (!f) return;
  try { const k = JSON.parse(await f.text()); if (!k.pub || !k.priv) throw 0; LS.set(KK, k); startOwner(); ownerRender(); toast('Key restored.'); } catch { toast('That isn\'t a valid key file.'); }
});

/* ===================== STAMP RENDERING ===================== */
const PAPER = '#FDFDEA';
function geometry(L) {
  const border = Math.round(L * 0.06), ph = L - 2 * border, pw = Math.round(ph * 0.8);
  return { W: pw + 2 * border, H: L, border, pw, ph };
}
/* Raw photo, center-cropped to 4:5. Flat paper border. Transparent semicircle perforations. No filters. */
function renderStamp(src, L, holeScale = 1) {
  const { W, H, border, pw, ph } = geometry(L);
  const c = document.createElement('canvas'); c.width = W; c.height = H;
  const g = c.getContext('2d');
  g.fillStyle = PAPER; g.fillRect(0, 0, W, H);
  const sw = src.width || src.videoWidth, sh = src.height || src.videoHeight;
  let cw = sw, ch = sh;
  if (sw / sh > 0.8) cw = Math.round(sh * 0.8); else ch = Math.round(sw / 0.8);
  g.imageSmoothingEnabled = true; g.imageSmoothingQuality = 'high';
  g.drawImage(src, (sw - cw) / 2, (sh - ch) / 2, cw, ch, border, border, pw, ph);
  const r = L * 14 / 1200 * holeScale, pitch = L * 42 / 1200;
  const nx = Math.max(2, Math.round(W / pitch)), ny = Math.max(2, Math.round(H / pitch));
  g.globalCompositeOperation = 'destination-out'; g.fillStyle = '#000'; g.beginPath();
  for (let i = 0; i <= nx; i++) { const x = i * W / nx; g.moveTo(x + r, 0); g.arc(x, 0, r, 0, 7); g.moveTo(x + r, H); g.arc(x, H, r, 0, 7); }
  for (let j = 0; j <= ny; j++) { const y = j * H / ny; g.moveTo(r, y); g.arc(0, y, r, 0, 7); g.moveTo(W + r, y); g.arc(W, y, r, 0, 7); }
  g.fill();
  return c;
}

/* ===================== ROUTER ===================== */
const state = { photo: null, camStream: null, facing: 'environment', newId: null, openId: null };
const views = $$('.view');
function show(id) {
  views.forEach(v => v.classList.toggle('active', v.id === id));
  const app = ['v-camera', 'v-preview', 'v-album', 'v-owner'].includes(id);
  $('#topbar').hidden = !app;
  if (app) { const u = vaultGet(session()); $('#who').textContent = u ? `${u.name} · ${chunkId(u.id)}` : ''; }
  $('#nav-camera').toggleAttribute('aria-current', id === 'v-camera' || id === 'v-preview');
  $('#nav-album').toggleAttribute('aria-current', id === 'v-album');
  $('#nav-owner').hidden = session() !== OWNER_ID; $('#nav-owner').toggleAttribute('aria-current', id === 'v-owner');
  $$('.chip[aria-current]').forEach(c => c.setAttribute('aria-current', 'page'));
  const v = $('#' + id); enter($('.page, .onb, .public', v) || v);
  window.scrollTo(0, 0);
}
const go = path => { location.hash = path; };
function route() {
  const h = location.hash.replace(/^#/, '') || '/';
  const user = session();
  if (user && !presence) startPresence(); if (!user) stopPresence();
  if (h !== '/camera') stopCamera();
  if (h !== '/owner') stopOwner();
  if (h.startsWith('/s/')) return publicPage(h.slice(3));
  if (h === '/') {
    if (user) return go('/camera');
    if (LS.get('pp_onboarded') && !location.search.includes('tour')) return go('/login');
    setStep(1); return show('v-onboarding');
  }
  if (h === '/login' || h === '/signup') { if (user) return go('/camera'); return showAuth(h.slice(1)); }
  if (!user) return go('/login');
  if (h === '/camera') return showCamera();
  if (h === '/preview') { if (!state.photo) return go('/camera'); return showPreview(); }
  if (h === '/owner') { if (user !== OWNER_ID) return go('/camera'); return showOwner(); }
  if (h === '/album') return showAlbum();
  go('/');
}
window.addEventListener('hashchange', route);

/* ===================== ONBOARDING ===================== */
const slides = $$('#onb .slide'), segFills = $$('#onb-progress .seg i');
let onbStep = 1;
function drawSwirl(slide) {
  const p = $('.swirl path', slide);
  p.style.strokeDasharray = '1';
  p.getAnimations().forEach(a => a.cancel());
  if (reduce.matches || !p.animate) { p.style.strokeDashoffset = '0'; return; }
  p.animate([{ strokeDashoffset: 1 }, { strokeDashoffset: 0 }], { duration: 1200, delay: 150, easing: EASE, fill: 'both' });
}
function setStep(n) {
  onbStep = Math.max(1, Math.min(5, n));
  slides.forEach(s => s.classList.toggle('active', +s.dataset.step === onbStep));
  segFills.forEach((el, i) => { el.style.width = (i < onbStep - 1 ? 100 : i === onbStep - 1 ? (onbStep === 5 ? 100 : 12) : 0) + '%'; });
  $('#onb-progress').setAttribute('aria-valuenow', onbStep === 5 ? 100 : Math.round(((onbStep - 1) + 0.12) / 5 * 100));
  $('#onb-back').hidden = onbStep === 1;
  $('#onb-skip').hidden = onbStep === 5;
  $('#onb-login').hidden = onbStep !== 5;
  $('#onb-next').textContent = onbStep === 5 ? 'Create account' : 'Next';
  drawSwirl(slides[onbStep - 1]);
}
function finishOnboarding(withMail) {
  const el = $('#ob-mail'), email = el.value.trim();
  if (withMail && email) { if (!emailOk(email)) { $('#ob-mail-err').textContent = 'That email doesn\'t look right.'; el.focus(); return; } sendLead(email); }
  LS.set('pp_onboarded', true); go('/signup');
}
$('#onb-next').addEventListener('click', () => onbStep === 5 ? finishOnboarding(true) : setStep(onbStep + 1));
$('#onb-back').addEventListener('click', () => setStep(onbStep - 1));
$('#onb-skip').addEventListener('click', () => finishOnboarding(false));
$('#onb-login').addEventListener('click', () => LS.set('pp_onboarded', true));
let sx = 0, sy = 0;
$('#onb').addEventListener('pointerdown', e => { sx = e.clientX; sy = e.clientY; });
$('#onb').addEventListener('pointerup', e => {
  const dx = e.clientX - sx, dy = e.clientY - sy;
  if (Math.abs(dx) > 50 && Math.abs(dx) > Math.abs(dy) * 1.5) setStep(onbStep + (dx < 0 ? 1 : -1));
});
document.addEventListener('keydown', e => {
  if (!$('#v-onboarding').classList.contains('active') || e.target.closest('a,input')) return;
  if (e.key === 'ArrowRight') setStep(onbStep + 1); if (e.key === 'ArrowLeft') setStep(onbStep - 1);
});

/* ===================== AUTH ===================== */
let authMode = 'signup';
const nameEl = $('#name'), idEl = $('#uid'), pwEl = $('#password'), pw2El = $('#password2');
function fieldErr(input, errEl, msg) { errEl.textContent = msg || ''; input.setAttribute('aria-invalid', msg ? 'true' : 'false'); return !msg; }
const idOk = v => v.length >= 3 && v.length <= 14;
const checkName = () => fieldErr(nameEl, $('#name-err'), nameEl.value.trim() ? '' : 'Tell us what to call you.');
const checkId = () => fieldErr(idEl, $('#id-err'), idOk(normId(idEl.value)) ? '' : 'Use 3 to 14 letters or numbers.');
const checkPw = () => fieldErr(pwEl, $('#pw-err'), pwEl.value.length >= 4 ? '' : 'Use at least 4 characters.');
const checkPw2 = () => fieldErr(pw2El, $('#pw2-err'), pw2El.value === pwEl.value ? '' : 'Passwords don\'t match yet.');

/* live "is this ID free?" check while typing (sign-up only) */
let idTimer, idSeq = 0, idState = 'idle';
function setIdStatus(s, id) {
  idState = s; const el = $('#id-status'), c = chunkId(id);
  const text = {
    idle: '3 to 14 letters or numbers. The dice builds one from your name.',
    checking: `Checking ${c}…`, free: `${c} is free. Grab it!`, taken: `${c} is already taken. Try another.`,
    offline: `${c} looks free. You're offline, so we'll register it when you're back.`,
  }[s];
  el.textContent = authMode === 'signup' ? text : '';
  el.style.color = s === 'taken' ? 'var(--error)' : s === 'free' ? 'var(--blue)' : '';
}
function scheduleIdCheck() {
  clearTimeout(idTimer); if (authMode !== 'signup') return;
  const id = normId(idEl.value);
  if (!idOk(id)) { idSeq++; return setIdStatus('idle', id); }
  setIdStatus('checking', id); const seq = ++idSeq;
  idTimer = setTimeout(async () => {
    if (vaultGet(id)) { if (seq === idSeq) setIdStatus('taken', id); return; }
    const r = await fetchProfile(id);
    if (seq === idSeq) setIdStatus(r.data ? 'taken' : r.connected ? 'free' : 'offline', id);
  }, 600);
}

function showAuth(mode) {
  authMode = mode; const signup = mode === 'signup';
  $('#auth-title').textContent = signup ? 'Start your album.' : 'Welcome back.';
  $('#auth-sub').textContent = signup ? 'Pick an ID and a password. Your stamps follow your ID.' : 'Use your ID and password to pick up where you left off.';
  $('#auth-submit').textContent = signup ? 'Create my ID' : 'Log in';
  $('#f-name').hidden = !signup; $('#f-pw2').hidden = !signup; $('#id-dice').hidden = !signup;
  pwEl.autocomplete = signup ? 'new-password' : 'current-password';
  const sw = $('#auth-switch'); sw.textContent = signup ? 'Already have an ID? ' : 'New here? ';
  const a = document.createElement('a'); a.href = signup ? '#/login' : '#/signup'; a.textContent = signup ? 'Log in' : 'Start one'; sw.append(a);
  pwEl.value = ''; pw2El.value = '';
  ['#form-err', '#name-err', '#id-err', '#pw-err', '#pw2-err'].forEach(s => { $(s).textContent = ''; });
  [nameEl, idEl, pwEl, pw2El].forEach(i => i.setAttribute('aria-invalid', 'false'));
  setIdStatus('idle', ''); if (signup) scheduleIdCheck();
  show('v-auth');
}
nameEl.addEventListener('blur', () => nameEl.value && checkName());
idEl.addEventListener('input', () => { idEl.value = normId(idEl.value); if (idEl.getAttribute('aria-invalid') === 'true') checkId(); scheduleIdCheck(); });
idEl.addEventListener('blur', () => idEl.value && checkId());
pwEl.addEventListener('blur', () => authMode === 'signup' && pwEl.value && checkPw());
pwEl.addEventListener('input', () => pwEl.getAttribute('aria-invalid') === 'true' && checkPw());
pw2El.addEventListener('input', () => (pw2El.getAttribute('aria-invalid') === 'true' || pw2El.value.length >= pwEl.value.length) && checkPw2());
$('#id-dice').addEventListener('click', () => { idEl.value = idFromName(nameEl.value); fieldErr(idEl, $('#id-err'), ''); scheduleIdCheck(); idEl.focus(); });
$('#pw-toggle').addEventListener('click', e => {
  const btn = e.currentTarget, showing = pwEl.type === 'password';
  pwEl.type = showing ? 'text' : 'password'; pw2El.type = pwEl.type;
  btn.setAttribute('aria-pressed', showing); btn.setAttribute('aria-label', showing ? 'Hide password' : 'Show password');
  $('use', btn).setAttribute('href', showing ? '#i-eye-off' : '#i-eye');
});

/* create: the network is asked first, so a taken ID is refused; the password is stored only as salt + SHA-256 hash */
async function createAccount(id, name, pw) {
  if (vaultGet(id)) throw { code: 'taken' };
  const r = await fetchProfile(id); if (r.data) throw { code: 'taken' };
  const salt = uid() + uid(), hash = await pwHash(salt, pw);
  const entry = { id, name, salt, hash, created: Date.now() };
  vaultPut(entry); LS.set('pp_session', id);
  publishProfile(entry); publishProfile(entry, BROKERS[1]); // best effort; presence re-registers it if we were offline
  return { registered: r.connected, name };
}
/* sign in: this device's vault first (instant, offline-proof), then chase the ID across the network */
async function signIn(id, pw, onStep) {
  const v = vaultGet(id);
  if (v) { if (await pwHash(v.salt, pw) === v.hash) { LS.set('pp_session', id); return v; } throw { code: 'badpw' }; }
  const { profile, connected } = await lookupIdentity(id, onStep);
  if (!profile) throw { code: connected ? 'notfound' : 'offline' };
  if (await pwHash(profile.salt, pw) !== profile.hash) throw { code: 'badpw' };
  vaultPut({ id, name: profile.name, salt: profile.salt, hash: profile.hash }); LS.set('pp_session', id);
  return profile;
}
$('#auth-form').addEventListener('submit', async e => {
  e.preventDefault();
  const signup = authMode === 'signup';
  if (![signup ? checkName() : true, checkId(), checkPw(), signup ? checkPw2() : true].every(Boolean)) return;
  if (signup && idState === 'taken') { fieldErr(idEl, $('#id-err'), 'That ID is already taken. Try another.'); return; }
  const id = normId(idEl.value), pw = pwEl.value, btn = $('#auth-submit'), label = btn.textContent;
  btn.disabled = true; btn.textContent = signup ? 'Creating your ID…' : 'One moment…'; $('#form-err').textContent = '';
  try {
    let res;
    if (signup) res = await createAccount(id, nameEl.value.trim().slice(0, 24), pw);
    else res = await signIn(id, pw, s => { btn.textContent = s === 'live' ? 'Asking your other devices…' : 'Looking up your ID…'; });
    LS.set('pp_onboarded', true); pwEl.value = ''; pw2El.value = '';
    startPresence(); go('/camera');
    if (signup) toast(res.registered ? `Welcome, ${res.name}. Your ID is ${chunkId(id)}.` : 'ID saved on this device. We\'ll register it once you\'re online.');
  } catch (err) {
    const code = err && err.code;
    if (code === 'taken') { fieldErr(idEl, $('#id-err'), 'That ID is already taken. Try another.'); setIdStatus('taken', id); }
    else if (code === 'badpw') $('#form-err').textContent = 'That ID and password don\'t match. Try again?';
    else if (code === 'notfound') $('#form-err').textContent = 'We can\'t find that ID. Check the spelling, or start an album.';
    else if (code === 'offline') $('#form-err').textContent = 'We can\'t reach the network to look that ID up. Check your connection and try again.';
    else $('#form-err').textContent = 'Something went sideways. Please try again.';
  } finally { btn.disabled = false; btn.textContent = label; }
});
$('#logout').addEventListener('click', () => { stopPresence(); LS.del('pp_session'); state.photo = null; go('/login'); });

/* ===================== CAMERA ===================== */
function prep(src) { // cap the working copy; never alters pixels beyond downscale
  const w = src.width || src.videoWidth, h = src.height || src.videoHeight, k = Math.min(1, 2400 / Math.max(w, h));
  const c = document.createElement('canvas'); c.width = Math.round(w * k); c.height = Math.round(h * k);
  const g = c.getContext('2d'); g.imageSmoothingQuality = 'high'; g.drawImage(src, 0, 0, c.width, c.height); return c;
}
function stopCamera() {
  state.camStream?.getTracks().forEach(t => t.stop()); state.camStream = null;
  const v = $('#video'); v.srcObject = null; v.hidden = true;
  $('#cam-pre').hidden = false; $('#cam-bar').hidden = true; $('#cam-hint').hidden = true;
}
async function startCamera() {
  const err = $('#cam-err'); err.textContent = '';
  if (!navigator.mediaDevices?.getUserMedia) {
    err.textContent = 'The camera isn\'t available here. It needs https or localhost. You can choose a photo instead.'; return;
  }
  try {
    state.camStream?.getTracks().forEach(t => t.stop());
    const stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: { ideal: state.facing }, width: { ideal: 2048 }, height: { ideal: 2048 } }, audio: false });
    state.camStream = stream;
    const v = $('#video'); v.srcObject = stream; v.hidden = false; await v.play().catch(() => {});
    $('#cam-pre').hidden = true; $('#cam-bar').hidden = false; $('#cam-hint').hidden = false;
  } catch (e) {
    err.textContent = e.name === 'NotAllowedError' ? 'Camera access is blocked. Allow it in your browser settings, or choose a photo instead.'
      : e.name === 'NotFoundError' ? 'No camera found. You can choose a photo instead.'
      : 'We couldn\'t start the camera. You can choose a photo instead.';
  }
}
async function showCamera() {
  show('v-camera');
  if (state.camStream) return;
  try { const p = await navigator.permissions?.query({ name: 'camera' }); if (p?.state === 'granted') startCamera(); } catch { /* not supported */ }
}
$('#cam-allow').addEventListener('click', startCamera);
$('#flip').addEventListener('click', () => { state.facing = state.facing === 'user' ? 'environment' : 'user'; startCamera(); });
$('#shutter').addEventListener('click', () => {
  const v = $('#video'); if (!v.videoWidth) return;
  if (!reduce.matches) $('#ring').animate([{ opacity: .9, transform: 'scale(1)' }, { opacity: 0, transform: 'scale(1.5)' }], { duration: 500, easing: EASE });
  state.meta = null; state.photo = prep(v);
  setTimeout(() => go('/preview'), reduce.matches ? 0 : 160);
});
const loadImg = file => new Promise((res, rej) => {
  const url = URL.createObjectURL(file), im = new Image();
  im.onload = () => { URL.revokeObjectURL(url); res(im); }; im.onerror = () => { URL.revokeObjectURL(url); rej(new Error('decode')); }; im.src = url;
});
async function handleFile(file) {
  if (!file) return;
  if (!['image/jpeg', 'image/png', 'image/webp'].includes(file.type) || file.size > 8 * 1024 * 1024) { toast('Please use a JPEG, PNG or WebP photo under 8 MB.'); return; }
  try {
    let bmp; try { bmp = await createImageBitmap(file, { imageOrientation: 'from-image' }); } catch { bmp = await loadImg(file); }
    if (Math.min(bmp.width, bmp.height) < 200) { toast('That photo is a bit too small. Try a bigger one.'); return; }
    state.meta = await scanMeta(file); state.photo = prep(bmp); go('/preview');
  } catch { toast('We couldn\'t read that photo. Try another.'); }
}
$('#cam-upload-alt').addEventListener('click', () => $('#file').click());
$('#cam-pick').addEventListener('click', () => $('#file').click());
$('#file').addEventListener('change', e => { handleFile(e.target.files[0]); e.target.value = ''; });

/* ===================== PREVIEW ===================== */
function showPreview() {
  show('v-preview'); state.takenAt = todayISO();
  $('#note').value = ''; $('#pv-note').textContent = ''; $('#save-err').textContent = '';
  $('#pv-postmark').textContent = postmarkOf(state.takenAt);
  const cv = $('#pv-canvas'), ctx = cv.getContext('2d');
  const draw = s => { ctx.clearRect(0, 0, cv.width, cv.height); ctx.drawImage(renderStamp(state.photo, 1200, s), 0, 0); };
  if (reduce.matches) return draw(1);
  const t0 = performance.now(), D = 800;
  const tick = now => { const t = Math.min(1, (now - t0) / D); draw(1 - Math.pow(1 - t, 4)); if (t < 1) requestAnimationFrame(tick); };
  requestAnimationFrame(tick);
  cv.animate([{ opacity: 0, transform: 'scale(.94) translateY(12px)' }, { opacity: 1, transform: 'none' }], { duration: 800, easing: EASE });
}
$('#note').addEventListener('input', e => { $('#pv-note').textContent = e.target.value; });
$('#retake').addEventListener('click', () => { state.photo = null; go('/camera'); });
$('#save-stamp').addEventListener('click', async e => {
  const btn = e.currentTarget; btn.disabled = true; btn.textContent = 'Saving…'; $('#save-err').textContent = '';
  try {
    const m = state.meta, found = m ? [m.gps && 'location (GPS)', m.device && `camera (${m.device})`, m.time && 'date and time', m.other && 'extra embedded data'].filter(Boolean) : [];
    const choice = await ask('Remove photo metadata?', found.length ? `Your original photo carried hidden details: ${found.join(', ')}. Removing makes sure none of it travels with the stamp.` : 'Photo files can hide location, camera and time. Removing keeps the stamp file clean.', ['Remove metadata', 'Keep stamp details (date, note)']);
    if (choice < 0) return;
    const token = randomToken(), note = $('#note').value.trim().slice(0, 40), big = renderStamp(state.photo, 1200);
    let seal = ''; if ($('#seal-toggle').getAttribute('aria-checked') === 'true') { seal = (await sha256(session() + ':' + token)).slice(0, 8); applySeal(big, seal); }
    const px = await pixHash(big); let stamp = await canvasBlob(big);
    if (choice === 1) stamp = await addText(stamp, [['Software', 'Postpatch'], ['Creation Time', state.takenAt], ['Description', note], ['Copyright', `Postpatch stamp by ${session()}. Not for AI training or synthetic media.`]]);
    const thumb = await canvasBlob(renderStamp(state.photo, 400));
    state.newId = await dbAdd({ owner: session(), stamp, thumb, note, takenAt: state.takenAt, isPublic: false, token, seal, px, created: Date.now() });
    state.photo = null; toast('Saved to your album.'); go('/album');
  } catch { $('#save-err').textContent = 'We couldn\'t save that stamp. Please try again.'; }
  finally { btn.disabled = false; btn.textContent = 'Save stamp'; }
});

/* ===================== ALBUM ===================== */
const urlCache = new Map();
function urlsFor(rec) {
  if (!urlCache.has(rec.id)) urlCache.set(rec.id, { stamp: URL.createObjectURL(rec.stamp), thumb: URL.createObjectURL(rec.thumb) });
  return urlCache.get(rec.id);
}
const altFor = rec => `Stamp postmarked ${postmarkOf(rec.takenAt)}${rec.note ? ': ' + rec.note : ''}`;
const albumEl = $('#album');
function setAlbumState(s) {
  $('#album-loading').hidden = s !== 'loading'; $('#album-empty').hidden = s !== 'empty';
  $('#album-error').hidden = s !== 'error'; albumEl.hidden = s !== 'list';
}
function tile(rec, i) {
  const b = document.createElement('button'); b.type = 'button';
  const isNew = rec.id === state.newId;
  b.className = 'tile ' + (isNew ? 'drop' : 'fade'); b.style.animationDelay = isNew ? '0ms' : `${i * 40}ms`;
  const img = new Image(); img.width = 330; img.height = 400; img.loading = 'lazy'; img.decoding = 'async'; img.alt = altFor(rec); img.src = urlsFor(rec).thumb;
  const s = document.createElement('span'); s.textContent = postmarkOf(rec.takenAt);
  b.append(img, s); b.addEventListener('click', () => openViewer(rec.id)); return b;
}
async function showAlbum() {
  show('v-album'); setAlbumState('loading');
  try {
    const list = (await dbAll(session())).sort((a, b) => b.created - a.created);
    $('#album-count').textContent = list.length ? `${list.length} stamp${list.length === 1 ? '' : 's'}` : '';
    if (!list.length) return setAlbumState('empty');
    albumEl.replaceChildren(...list.map(tile)); setAlbumState('list'); state.newId = null;
  } catch { setAlbumState('error'); }
}
$('#album-retry').addEventListener('click', showAlbum);

const viewer = $('#viewer'), confirmDlg = $('#confirm');
const shareURL = t => location.href.split('#')[0] + '#/s/' + t;
function syncShare(rec) {
  $('#share-toggle').setAttribute('aria-checked', rec.isPublic);
  $('#share-row').hidden = !rec.isPublic;
  $('#share-state').textContent = rec.isPublic ? 'Anyone with the link can see it.' : 'Only you can see this stamp.';
  $('#share-url').value = shareURL(rec.token);
}
async function openViewer(id) {
  const rec = await dbGet(id); if (!rec) return; state.openId = id;
  const img = $('#viewer-img'); img.src = urlsFor(rec).stamp; img.alt = altFor(rec);
  $('#viewer-postmark').textContent = postmarkOf(rec.takenAt); $('#viewer-note').textContent = rec.note;
  syncShare(rec); viewer.showModal();
}
$('#viewer-close').addEventListener('click', () => viewer.close());
viewer.addEventListener('click', e => { if (e.target === viewer) viewer.close(); });
$('#viewer-download').addEventListener('click', async () => {
  const rec = await dbGet(state.openId); if (!rec) return;
  const a = document.createElement('a'); a.href = urlsFor(rec).stamp; a.download = `postpatch-${rec.takenAt}.png`; document.body.append(a); a.click(); a.remove();
});
$('#share-toggle').addEventListener('click', async () => {
  const rec = await dbGet(state.openId); if (!rec) return;
  if (rec.isPublic) rec.token = randomToken(); // revoking rotates the token; the old link dies
  rec.isPublic = !rec.isPublic; await dbPut(rec); syncShare(rec);
  toast(rec.isPublic ? 'Public link is on.' : 'Link turned off.');
});
$('#share-copy').addEventListener('click', async () => {
  const input = $('#share-url');
  try { await navigator.clipboard.writeText(input.value); } catch { input.select(); document.execCommand('copy'); }
  toast('Link copied.');
});
$('#viewer-delete').addEventListener('click', () => confirmDlg.showModal());
$('#confirm-no').addEventListener('click', () => confirmDlg.close());
$('#confirm-yes').addEventListener('click', async () => {
  const id = state.openId; await dbDel(id);
  const u = urlCache.get(id); if (u) { URL.revokeObjectURL(u.stamp); URL.revokeObjectURL(u.thumb); urlCache.delete(id); }
  confirmDlg.close(); viewer.close(); toast('Stamp deleted.'); showAlbum();
});

/* ===================== PUBLIC STAMP ===================== */
async function publicPage(token) {
  show('v-public');
  const body = $('#public-body'); body.replaceChildren();
  const msg = (h, p) => { const a = document.createElement('h1'); a.className = 'title'; a.textContent = h; const b = document.createElement('p'); b.className = 'body-quiet'; b.textContent = p; body.append(a, b); };
  try {
    const rec = await dbByToken(token);
    if (!rec || !rec.isPublic) return msg('Nothing here.', 'This stamp isn\'t shared, or the link was turned off.');
    const img = new Image(); img.className = 'stamp-img reveal'; img.width = 989; img.height = 1200; img.alt = altFor(rec); img.src = urlsFor(rec).stamp;
    const pm = document.createElement('p'); pm.className = 'postmark'; pm.textContent = postmarkOf(rec.takenAt);
    const n = document.createElement('p'); n.className = 'note-line'; n.textContent = rec.note;
    body.append(img, pm, n);
  } catch { msg('Something went sideways.', 'We couldn\'t open that stamp. Try again in a moment.'); }
}

/* ===================== START ===================== */
route();
const pend = LS.get('pp_lead_pending'); if (pend) sendLead(pend);

})();
