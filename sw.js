/*
 * rd-lock service worker (format 1). Published in plaintext next to the login page; holds no paths, names or keys.
 * With a valid key (a non-extractable AES-GCM CryptoKey in IndexedDB, saved by the login page) it serves the site
 * from the encrypted blobs in c/: fetch → decrypt chunk by chunk → (gunzip) → Response with the real Content-Type and
 * Content-Length. Without a key it passes everything through, so the login page shows. Scheme: lock/README.md.
 * Decrypted content and the index live only in this worker's memory; nothing is written to Cache Storage.
 */
'use strict';

const PREFIX = new TextEncoder().encode('rd-lock/1\u0000');
const CHECK_TEXT = 'rd-lock check v1';
const MAX_AGE = 30 * 24 * 3600 * 1000;
const CLOCK_SKEW = 24 * 3600 * 1000;
const SCOPE = new URL(self.registration.scope);
const BASE = SCOPE.pathname; // ends with '/'
const DB_NAME = 'rd-lock:' + BASE; // site-specific: every Pages project site of the account shares the origin
const NO_KEY = 'no-key';

/** null = unknown (worker just started), NO_KEY, or { key, created, salt, check, build, app, appHeaders, files }. */
let state = null;
let loading = null;

self.addEventListener('install', (event) => {
  event.waitUntil(self.skipWaiting());
});

self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (url.origin !== SCOPE.origin || !url.pathname.startsWith(BASE)) return;
  let rel;
  try {
    rel = decodeURIComponent(url.pathname.slice(BASE.length));
  } catch {
    return;
  }
  if (rel === 'sw.js' || rel === 'lock.json' || rel.startsWith('c/')) return;
  const nav = req.mode === 'navigate';
  if (!nav) {
    if (state === NO_KEY) return;
    if (state) {
      const entry = state.files.get(rel);
      if (entry) event.respondWith(serve(event, state, entry, false, url.searchParams.has('pobierz')));
      return;
    }
  }
  event.respondWith(handle(event, req, url, rel, nav));
});

// Note: Chromium sends <a download> requests past the service worker, so links to encrypted files must be plain
// links (navigations). A link with ?pobierz gets Content-Disposition: attachment (e.g. a PDF meant as a download).
async function handle(event, req, url, rel, nav) {
  if (nav && url.searchParams.has('wyloguj')) {
    await forget(null).catch(() => {});
    return fetch(req);
  }
  let st = null;
  try {
    st = await getState(nav);
  } catch {
    st = null;
  }
  if (!st) return fetch(req);
  let entry;
  if (nav && (rel === '' || rel === 'index.html')) entry = st.files.get(st.app);
  else entry = st.files.get(rel);
  if (!entry) return fetch(req);
  return serve(event, st, entry, entry.path === st.app, url.searchParams.has('pobierz'), nav);
}

// ------------------------------------------------------------------------------------------------ key + index state

function getState(fresh) {
  if (!fresh && state && state !== NO_KEY) return Promise.resolve(state);
  if (!loading) loading = loadState().finally(() => (loading = null));
  return loading;
}

async function loadState() {
  const rec = await idb('readonly', (s) => s.get('key'));
  if (!rec || !rec.key || typeof rec.created !== 'number') {
    state = NO_KEY;
    return null;
  }
  const age = Date.now() - rec.created;
  if (!(age >= -CLOCK_SKEW && age <= MAX_AGE)) {
    await forget('expired');
    return null;
  }
  const previous = state && state !== NO_KEY && state.created === rec.created ? state : null;
  let lock;
  try {
    lock = await fetchLock('no-store');
  } catch {
    // Offline or a failed request: keep serving the index already in memory for this key, if any.
    return previous;
  }
  if (!lock || lock.format !== 1 || !lock.kdf || typeof lock.check !== 'string') return null;
  if (previous && previous.salt === lock.kdf.salt && previous.check === lock.check && previous.build === lock.build) {
    return previous;
  }
  if (rec.salt !== lock.kdf.salt || !(await checkKey(rec.key, lock.check))) {
    await forget('changed'); // password (and salt) changed since this device logged in
    return null;
  }
  let index = null;
  try {
    index = await loadIndex(rec.key, lock);
  } catch {
    // The check blob has just proved the key, so a failing index is a publish in progress (the CDN serving lock.json
    // and the blobs of different builds), never a changed password: retry once with lock.json reloaded, then keep
    // the key and serve the build already in memory, or let the login page say the site is being updated (L01).
    try {
      const fresh = await fetchLock('reload');
      if (fresh && fresh.kdf && fresh.kdf.salt === rec.salt && fresh.check === lock.check) {
        index = await loadIndex(rec.key, fresh);
        lock = fresh;
      }
    } catch {
      index = null;
    }
    if (!index) {
      if (previous) return previous;
      await idb('readwrite', (s) => {
        s.put('updating', 'reason');
      }).catch(() => {});
      return null;
    }
  }
  await idb('readwrite', (s) => {
    const q = s.get('reason');
    q.onsuccess = () => {
      if (q.result === 'updating') s.delete('reason');
    };
  }).catch(() => {});
  const files = new Map();
  for (const [path, e] of Object.entries(index.files)) {
    files.set(path, { ...e, path, idBytes: hex(e.id), tagBytes: hex(e.tag) });
  }
  state = {
    key: rec.key,
    created: rec.created,
    salt: lock.kdf.salt,
    check: lock.check,
    build: lock.build,
    app: index.app,
    chunk: index.chunk,
    appHeaders: index.appHeaders || {},
    files,
  };
  return state;
}

async function fetchLock(cache) {
  const res = await fetch(new URL('lock.json', SCOPE), { cache, credentials: 'same-origin' });
  if (!res.ok) throw new Error('lock.json ' + res.status);
  return res.json();
}

async function loadIndex(key, lock) {
  const entry = { id: lock.index, tag: lock.build, idBytes: hex(lock.index), tagBytes: hex(lock.build), chunks: 1 };
  let lastErr = null;
  for (const cache of ['default', 'reload']) {
    try {
      const res = await fetch(blobUrl(entry), { cache, credentials: 'same-origin' });
      if (!res.ok) throw new Error('index ' + res.status);
      const rec = new Uint8Array(await res.arrayBuffer());
      const pt = await decryptRecord(key, entry, 0, rec);
      const index = JSON.parse(new TextDecoder().decode(pt));
      if (!index || index.format !== 1 || typeof index.files !== 'object') throw new Error('index format');
      return index;
    } catch (err) {
      lastErr = err;
    }
  }
  throw lastErr;
}

async function checkKey(key, checkB64) {
  try {
    const blob = b64(checkB64);
    const pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: blob.subarray(0, 12), additionalData: concat(PREFIX, new TextEncoder().encode('check')), tagLength: 128 },
      key,
      blob.subarray(12),
    );
    return new TextDecoder().decode(pt) === CHECK_TEXT;
  } catch {
    return false;
  }
}

/** Delete the key (and remember why, for the login page); the next navigation shows the login page. */
async function forget(reason) {
  state = NO_KEY;
  await idb('readwrite', (s) => {
    s.delete('key');
    if (reason) s.put(reason, 'reason');
    else s.delete('reason');
  });
}

// ------------------------------------------------------------------------------------------------ serving a file

/** c/<id>-<first 16 hex of the tag>: one name per version of a file (lock/crypto.mjs blobName). */
function blobUrl(entry) {
  return new URL('c/' + entry.id + '-' + entry.tag.slice(0, 16), SCOPE);
}

/** A navigation whose blob cannot be served (a PDF or RVT link) gets a short Polish page instead of a blank one. */
function failedPage(status) {
  const html =
    '<!doctype html><html lang="pl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">' +
    '<meta name="robots" content="noindex,nofollow"><title>Nie udało się otworzyć pliku</title>' +
    '<style>body{margin:40px;font:16px/1.5 system-ui,sans-serif;color:#1a1a1a;background:#fff}a{color:#1a1a1a}</style></head>' +
    '<body><p>Nie udało się otworzyć pliku. Odśwież stronę.</p><p><a href="' + BASE + '">Przejdź do strony głównej</a></p></body></html>';
  return new Response(html, {
    status,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
      'X-Content-Type-Options': 'nosniff',
    },
  });
}

function recordLength(entry, i, chunk) {
  return (i < entry.chunks - 1 ? chunk : entry.stored - chunk * (entry.chunks - 1)) + 28;
}

function attachment(entry) {
  if (entry.disp) return entry.disp.replace(/^inline/, 'attachment');
  const name = entry.path.split('/').pop();
  const ascii = name.normalize('NFKD').replace(/[^\x20-\x7e]/g, '').replace(/["\\]/g, '_') || 'file';
  const ext = encodeURIComponent(name).replace(/['()*!]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase());
  return `attachment; filename="${ascii}"; filename*=UTF-8''${ext}`;
}

async function serve(event, st, entry, isApp, download, nav) {
  let finish;
  event.waitUntil(new Promise((resolve) => (finish = resolve))); // keep the worker alive while the body streams
  let src;
  try {
    src = await openBlob(st, entry);
  } catch (err) {
    finish();
    const status = err && err.status === 404 ? 404 : 502;
    return nav ? failedPage(status) : new Response(null, { status });
  }
  const { reader, first } = src;
  let i = 1;
  const body = new ReadableStream(
    {
      async start(c) {
        c.enqueue(first);
        if (entry.chunks > 1) return;
        try {
          await reader.end();
          c.close();
        } catch (err) {
          c.error(err);
          reader.cancel();
        }
        finish();
      },
      async pull(c) {
        try {
          const rec = await reader.take(recordLength(entry, i, st.chunk));
          c.enqueue(await decryptRecord(st.key, entry, i, rec));
          i++;
          if (i === entry.chunks) {
            await reader.end();
            c.close();
            finish();
          }
        } catch (err) {
          c.error(err);
          reader.cancel();
          finish();
        }
      },
      cancel() {
        reader.cancel();
        finish();
      },
    },
    { highWaterMark: 1 },
  );
  const headers = new Headers();
  headers.set('Content-Type', entry.type);
  headers.set('Content-Length', String(entry.size));
  headers.set('X-Content-Type-Options', 'nosniff');
  if (download) headers.set('Content-Disposition', attachment(entry));
  else if (entry.disp) headers.set('Content-Disposition', entry.disp);
  if (isApp) for (const [k, v] of Object.entries(st.appHeaders)) if (v) headers.set(k, v);
  const out = entry.gz ? body.pipeThrough(new DecompressionStream('gzip')) : body;
  return new Response(out, { status: 200, headers });
}

/** Fetch the blob (normal HTTP cache) and decrypt its first record; on any failure retry once bypassing the cache. */
async function openBlob(st, entry) {
  let lastErr = null;
  for (const cache of ['default', 'reload']) {
    let reader = null;
    try {
      const res = await fetch(blobUrl(entry), { cache, credentials: 'same-origin' });
      if (!res.ok || !res.body) throw Object.assign(new Error('blob ' + res.status), { status: res.status });
      reader = new RecordReader(res.body.getReader());
      const first = await decryptRecord(st.key, entry, 0, await reader.take(recordLength(entry, 0, st.chunk)));
      return { reader, first };
    } catch (err) {
      if (reader) reader.cancel();
      lastErr = err;
    }
  }
  throw lastErr;
}

async function decryptRecord(key, entry, i, rec) {
  const last = i === entry.chunks - 1 ? 1 : 0;
  const aad = concat(PREFIX, entry.idBytes, entry.tagBytes, u32(i), Uint8Array.of(last));
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: rec.subarray(0, 12), additionalData: aad, tagLength: 128 }, key, rec.subarray(12));
  return new Uint8Array(pt);
}

/** Reads exact byte counts from a network stream without holding more than one record. */
class RecordReader {
  constructor(reader) {
    this.reader = reader;
    this.bufs = [];
    this.have = 0;
  }
  async take(n) {
    while (this.have < n) {
      const { done, value } = await this.reader.read();
      if (done) throw new Error('truncated blob');
      this.bufs.push(value);
      this.have += value.byteLength;
    }
    const out = new Uint8Array(n);
    let o = 0;
    while (o < n) {
      const b = this.bufs[0];
      const k = Math.min(b.byteLength, n - o);
      out.set(b.subarray(0, k), o);
      o += k;
      if (k === b.byteLength) this.bufs.shift();
      else this.bufs[0] = b.subarray(k);
    }
    this.have -= n;
    return out;
  }
  async end() {
    if (this.have > 0) throw new Error('trailing bytes');
    const { done, value } = await this.reader.read();
    if (!done && value && value.byteLength) throw new Error('trailing bytes');
  }
  cancel() {
    this.reader.cancel().catch(() => {});
  }
}

// ------------------------------------------------------------------------------------------------ helpers

function idb(mode, fn) {
  return new Promise((resolve, reject) => {
    const open = indexedDB.open(DB_NAME, 1);
    open.onupgradeneeded = () => open.result.createObjectStore('kv');
    open.onerror = () => reject(open.error);
    open.onsuccess = () => {
      const db = open.result;
      const tx = db.transaction('kv', mode);
      const req = fn(tx.objectStore('kv'));
      let result;
      if (req && 'onsuccess' in req) req.onsuccess = () => (result = req.result);
      tx.oncomplete = () => {
        db.close();
        resolve(result);
      };
      tx.onerror = tx.onabort = () => {
        db.close();
        reject(tx.error);
      };
    };
  });
}

function hex(s) {
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function b64(s) {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function u32(n) {
  return Uint8Array.of(n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255);
}

function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.byteLength, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.byteLength;
  }
  return out;
}
