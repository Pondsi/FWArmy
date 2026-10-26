/**
 * FWArmy 中转服务器（独立程序）—— 撮合 + 转发，**不存消息**。
 *
 * 产品名：FWArmy（用户也会写成 FWAmry / fwamry，均指同一程序；目录固定为 fwarmy/）。
 * 本文件既是 `node server.mjs` 的源运行入口，也会被打包进单文件 `FWArmy.exe`（Node SEA）。
 *
 * 管理面（只允许本机回环访问，打开即用、无需登录）：
 *   GET  / 或 /admin                    自包含管理页（无外部资源）
 *   GET  /api/admin/stats               总统计 + 按凭据统计（日/月/年/速度/峰值）
 *   GET  /api/admin/credentials         凭据列表
 *   POST /api/admin/credentials         新建凭据 {name, limits?}
 *   POST /api/admin/credential-update   改名/停用/改限额 {id, name?, disabled?, limits?}
 *   POST /api/admin/credential-revoke   停用（兼容旧名）{id}
 *   POST /api/admin/credential-delete   删除 {id, confirmName}
 *   POST /api/admin/config              全局默认限流/开关/队列/TTL
 *   GET  /api/admin/first-credential    首次启动自动生成的凭据（只在本机显示）
 *   POST /api/admin/first-credential-ack 我已保存，删除明文引导文件
 *   GET  /api/admin/log?tail=200        最近日志（不含消息/凭据明文）
 *   POST /api/admin/public-ip           探测公网 IP
 *   GET  /api/admin/security            重放/黑名单/来源密钥固定策略
 *   GET/POST /api/admin/tls             TLS 证书策略（改动需重启）
 *   GET/POST /api/admin/reach           公网可达性（NAT-PMP 只读探针 / 显式映射 / STUN）
 *   POST /api/admin/shutdown            关闭服务器
 *
 * 业务面（都必须带 `Authorization: Bearer <凭据>`）：
 *   register / lookup / relay / poll / bye / heartbeat / presence/batch（协议同 SERVER-RELAY.md）
 *
 * 硬边界：
 *  · 消息只在内存队列（TTL 30s），进程退出即消失；不写任何消息日志/消息文件。
 *  · 磁盘只有：credentials.json（凭据 sha256 + 名称 + 限额）、config.json、expand.json（被扩网凭据只存 sha256；
 *    出网凭据 AES-256-GCM 加密）、stats.json（计数/字节数）、security.json（消息 ID 哈希/黑名单/来源公钥）、
 *    tls/（自签证书与私钥，0600）、secret.key（仅本机加密密钥，0600；可用 FWARMY_MASTER_KEY 替代）、
 *    server.log（运行日志，不含消息/凭据明文）、server.pid、instance.json、first-credential.enc
 *    （首次凭据加密保存，确认后删除；旧版 .txt 明文会在启动时迁移并删除）。
 *  · 自签私钥 tls/key.pem 也经 secret.key 加密；用户证书模式的 keyFile 由用户自己保管（文档写明）。
 *  · 统计按本机时区的日/月/年累计；字节口径 = 信封字节（上行入队 + 下行取走），不含 HTTP 头开销。
 *  · TLS 默认自签 + 指纹固定；明文仅在回环或显式 allowPlaintext=true 时接受（否未知来源直接 426）。
 */

import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import tls from 'node:tls';
import dgram from 'node:dgram';
import dns from 'node:dns';
import os from 'node:os';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { promisify } from 'node:util';

/** 源码是 ESM、SEA 里是 CJS；import.meta.url 在 CJS 下为空，createRequire 改用 __filename/argv 兜底。 */
const REQ_BASE = (() => {
  if (typeof __filename !== 'undefined' && __filename) return __filename;
  if (process.argv[1]) return path.resolve(process.argv[1]);
  return path.join(process.cwd(), 'fwarmy.js');
})();
const require = createRequire(REQ_BASE);
let SEA = null;
try { SEA = require('node:sea'); } catch { /* Node < 20.12 没有 node:sea；源运行不需要 */ }
const IS_SEA = !!(SEA && typeof SEA.isSea === 'function' && SEA.isSea());
/** 打包成 CJS（SEA）后 import.meta.url 不存在；这里必须容错，否则单文件启动即崩。 */
const SELF_FILE = (() => {
  try { return fileURLToPath(import.meta.url); } catch { return ''; }
})();
const HERE = SELF_FILE ? path.dirname(SELF_FILE) : (IS_SEA ? path.dirname(process.execPath) : process.cwd());
/** 单文件运行时，数据目录跟随可执行文件；源码运行时跟随本文件。 */
const APP_DIR = IS_SEA ? path.dirname(process.execPath) : HERE;
export const VERSION = '0.5.1';
export const PRODUCT = 'FWArmy';

const TTL_MS = 30_000;
/** 上游一次投递的总预算：超过 8 秒即判失败，只在内存里试下一个网关，不落盘、不排队重试。 */
export const UPSTREAM_TIMEOUT_MS = 8_000;
/** 同一 messageId 在 24h 内最多被本实例转发/投递 2 次；第 3 次与超 24h 都进黑名单。 */
export const MESSAGE_WINDOW_MS = 24 * 60 * 60 * 1000;
/** 黑名单条目 30 天没有再次出现就自动清理。 */
export const BLACKLIST_TTL_MS = 30 * 24 * 60 * 60 * 1000;
export const MAX_FORWARDS = 2;
/** 不设业务跳数上限；route 只作为环路证据，长度上限仅防超大报文（默认 128，可调）。 */
export const MAX_ROUTE = 128;
const MAX_REPLAY_ENTRIES = 50_000;
const MAX_BLACKLIST_ENTRIES = 50_000;
/** 一条消息每次请求最多试 3 个上游，避免“一个请求放大成 N 次外呼”。 */
const MAX_FORWARD_PEERS = 3;
const MAX_MSG_ID = 128;
/** 单条被扩网凭据的入站速率上限（防放大/洪泛）；只影响扩网 ingress，不影响普通业务凭据。 */
const INBOUND_RATE_PER_MIN = 240;
const INBOUND_BYTES_PER_MIN = 20 * 1024 * 1024;
const LIMIT_KEYS = ['ratePerMin', 'bytesPerMin', 'dailyRequests', 'dailyBytes', 'monthlyRequests', 'monthlyBytes', 'totalRequests', 'totalBytes', 'yearlyBytes'];
const DEFAULTS = {
  ratePerMin: 120,
  bytesPerMin: 10 * 1024 * 1024,
  dailyRequests: 0,
  dailyBytes: 50 * 1024 * 1024,
  monthlyRequests: 0,
  monthlyBytes: 1024 * 1024 * 1024,
  totalRequests: 0,
  totalBytes: 0,
  yearlyBytes: 10 * 1024 * 1024 * 1024,
  maxEnvelope: 64 * 1024,
  queuePerUser: 50,
  presenceTtlMs: 60_000,
  accepting: true,
  /**
   * 证书策略（默认自签 + 指纹固定）：
   *  self-signed  首次启动生成 P-256 自签证书，客户端必须固定 fingerprint（不校验证书链/域名）
   *  user-cert    用户提供 certFile/keyFile，客户端按系统 CA 校验证书链与 hostname
   *  off          明文 HTTP（只在用户显式确认后允许）
   * allowPlaintext=false 时，非回环来源的明文业务请求一律 426；回环始终允许（本机管理/ctl）。
   */
  tls: { mode: 'self-signed', allowPlaintext: false, certFile: '', keyFile: '', hostnames: [] },
};
const CONFIG_RANGES = {
  ratePerMin: [1, 1_000_000],
  bytesPerMin: [1, 10 * 1024 * 1024 * 1024],
  dailyRequests: [0, Number.MAX_SAFE_INTEGER],
  monthlyRequests: [0, Number.MAX_SAFE_INTEGER],
  totalRequests: [0, Number.MAX_SAFE_INTEGER],
  dailyBytes: [0, 1024 * 1024 * 1024 * 1024],
  monthlyBytes: [0, 10 * 1024 * 1024 * 1024 * 1024],
  totalBytes: [0, Number.MAX_SAFE_INTEGER],
  yearlyBytes: [0, 100 * 1024 * 1024 * 1024 * 1024],
  maxEnvelope: [1024, 16 * 1024 * 1024],
  queuePerUser: [1, 10_000],
  presenceTtlMs: [100, 24 * 3600 * 1000],
};
const validLimit = (k, v) => typeof v === 'number' && Number.isSafeInteger(v)
  && v >= CONFIG_RANGES[k][0] && v <= CONFIG_RANGES[k][1];
function parseLimits(raw = {}, current = {}) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error('bad-limits');
  const next = { ...current };
  for (const k of Object.keys(raw)) {
    if (!LIMIT_KEYS.includes(k)) throw new Error('bad-limit:' + k);
    const v = raw[k];
    if (v !== null && !validLimit(k, v)) throw new Error('bad-limit:' + k);
    next[k] = v; // null 仅表示继承；分钟继承值也必须大于零
  }
  return Object.fromEntries(LIMIT_KEYS.map((k) => [k, next[k] ?? null]));
}
const ED_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const X_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');
const edPub = (b64) => crypto.createPublicKey({ key: Buffer.concat([ED_PREFIX, Buffer.from(String(b64), 'base64')]), format: 'der', type: 'spki' });
const xPub = (b64) => crypto.createPublicKey({ key: Buffer.concat([X_PREFIX, Buffer.from(String(b64), 'base64')]), format: 'der', type: 'spki' });
const sha = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');
const b64u = (b) => b.toString('base64url');
const pad2 = (n) => String(n).padStart(2, '0');
const dayKey = (d = new Date()) => `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())}`;
const monthKey = (d = new Date()) => `${d.getFullYear()}-${pad2(d.getMonth() + 1)}`;
const yearKey = (d = new Date()) => String(d.getFullYear());
const minuteKey = (d = new Date()) => `${dayKey(d)}T${pad2(d.getHours())}:${pad2(d.getMinutes())}`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const lookup = promisify(dns.lookup);
const isIp = (h) => net.isIP(String(h || '')) !== 0;
const isPrivateIpv4 = (h) => {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(String(h || ''));
  if (!m) return false;
  const a = Number(m[1]), b = Number(m[2]);
  return a === 10 || a === 127 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
};

/* ── 消息身份 ─────────────────────────────────────────────────────── */
/** 消息签名覆盖：ID、来源实例、收件人、创建时间、信封哈希。中间跳只搬运，不能改任何一项。 */
export function messageCanonical({ msgId, origin, to, createdAt, envelope }) {
  return `fwarmy-msg|v1|${msgId}|${origin}|${to}|${createdAt}|${sha(envelope)}`;
}
export function isMessageId(v) {
  return typeof v === 'string' && v.length >= 8 && v.length <= MAX_MSG_ID && /^[A-Za-z0-9_.:-]+$/.test(v);
}
const msgKey = (msgId) => sha('msg|' + msgId).slice(0, 32);

/* ── 落盘密钥（AES-256-GCM）──────────────────────────────────────── */
/**
 * 本机数据目录里的 secret.key 只解决“凭据不落明文”，不是硬件密钥库：
 * 拿到这台机器的文件系统（或备份）仍可解密。更强的方式是设 FWARMY_MASTER_KEY（不落盘），
 * 或用系统盘加密；两种都在文档里写明最坏情况。
 */
function createSecretBox(dir) {
  let key = null;
  const env = process.env.FWARMY_MASTER_KEY || '';
  if (env) {
    key = crypto.scryptSync(env, 'fwarmy-secret-v1', 32);
  } else {
    const f = path.join(dir, 'secret.key');
    try {
      const b = fs.readFileSync(f);
      if (b.length === 32) key = b;
    } catch { /* 首次生成 */ }
    if (!key) {
      key = crypto.randomBytes(32);
      try { fs.writeFileSync(f, key, { mode: 0o600 }); } catch { /* 无权限时仍可在内存工作 */ }
    }
  }
  const seal = (plain, aad = '') => {
    const iv = crypto.randomBytes(12);
    const c = crypto.createCipheriv('aes-256-gcm', key, iv);
    c.setAAD(Buffer.from(String(aad)));
    const ct = Buffer.concat([c.update(Buffer.from(String(plain), 'utf8')), c.final()]);
    return `enc:v1:${iv.toString('base64')}:${c.getAuthTag().toString('base64')}:${ct.toString('base64')}`;
  };
  const open = (blob, aad = '') => {
    const s = String(blob || '');
    if (!s.startsWith('enc:v1:')) return s; // 旧明文：交给调用方迁移
    const p = s.split(':');
    if (p.length !== 5) return '';
    try {
      const d = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(p[2], 'base64'));
      d.setAAD(Buffer.from(String(aad)));
      d.setAuthTag(Buffer.from(p[3], 'base64'));
      return Buffer.concat([d.update(Buffer.from(p[4], 'base64')), d.final()]).toString('utf8');
    } catch { return ''; }
  };
  return { seal, open, encrypted: (s) => String(s || '').startsWith('enc:v1:') };
}

/* ── 最小 DER/X.509（自签证书，零依赖）────────────────────────────── */
function derLen(n) {
  if (n < 0x80) return Buffer.from([n]);
  const a = [];
  while (n > 0) { a.unshift(n & 0xff); n = Math.floor(n / 256); }
  return Buffer.from([0x80 | a.length, ...a]);
}
const derTlv = (tag, ...c) => { const b = Buffer.concat(c); return Buffer.concat([Buffer.from([tag]), derLen(b.length), b]); };
const derSeq = (...c) => derTlv(0x30, ...c);
const derSet = (...c) => derTlv(0x31, ...c);
const derInt = (v) => {
  let b;
  if (Buffer.isBuffer(v)) b = v;
  else {
    const a = []; let x = BigInt(v);
    if (x === 0n) a.push(0);
    while (x > 0n) { a.unshift(Number(x & 255n)); x >>= 8n; }
    b = Buffer.from(a);
  }
  while (b.length > 1 && b[0] === 0 && (b[1] & 0x80) === 0) b = b.subarray(1);
  if (b[0] & 0x80) b = Buffer.concat([Buffer.from([0]), b]);
  return derTlv(0x02, b);
};
const derOid = (s) => {
  const p = String(s).split('.').map(Number);
  const a = [40 * p[0] + p[1]];
  for (let i = 2; i < p.length; i++) {
    let v = p[i]; const tmp = [v & 0x7f];
    while ((v = Math.floor(v / 128)) > 0) tmp.unshift((v & 0x7f) | 0x80);
    a.push(...tmp);
  }
  return derTlv(0x06, Buffer.from(a));
};
const derUtf8 = (s) => derTlv(0x0c, Buffer.from(String(s), 'utf8'));
const derUtc = (d) => derTlv(0x17, Buffer.from(d.toISOString().replace(/[-:T]/g, '').slice(2, 14) + 'Z'));
const derBits = (b) => derTlv(0x03, Buffer.from([0]), b);
const derOct = (b) => derTlv(0x04, b);
const derCtx = (n, ...c) => derTlv(0xa0 + n, ...c);
const derName = (cn) => derSeq(derSet(derSeq(derOid('2.5.4.3'), derUtf8(cn))));
const derExt = (id, critical, value) => derSeq(derOid(id), ...(critical ? [derTlv(0x01, Buffer.from([0xff]))] : []), derOct(value));

/** P-256 自签证书；SAN 覆盖 localhost、回环与当前本机 IPv4/主机名。 */
export function generateSelfSignedCert({ commonName = 'FWArmy', hostnames = [], ips = [] } = {}) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  const now = Date.now();
  const alg = derSeq(derOid('1.2.840.10045.4.3.2'));
  const nm = derName(commonName);
  const san = [];
  const dnsNames = [...new Set(['localhost', ...hostnames].filter(Boolean))].slice(0, 16);
  for (const h of dnsNames) san.push(derTlv(0x82, Buffer.from(h)));
  const ipList = [...new Set(['127.0.0.1', '::1', ...ips].filter(Boolean))].slice(0, 16);
  for (const ip of ipList) {
    const fam = net.isIP(ip);
    if (fam === 4) san.push(derTlv(0x87, Buffer.from(ip.split('.').map(Number))));
    else if (fam === 6) {
      try {
        const x = new Uint8Array(16);
        const [head, tail] = ip.split('::');
        const h = head ? head.split(':') : [];
        const t = tail ? tail.split(':') : [];
        const parts = [];
        if (ip.includes('::')) {
          const need = 8 - h.length - t.length;
          parts.push(...h); for (let i = 0; i < Math.max(0, need); i++) parts.push('0'); parts.push(...t);
        } else parts.push(...ip.split(':'));
        if (parts.length === 8) {
          for (let i = 0; i < 8; i++) { const v = parseInt(parts[i] || '0', 16); x[i * 2] = (v >> 8) & 0xff; x[i * 2 + 1] = v & 0xff; }
          san.push(derTlv(0x87, Buffer.from(x)));
        }
      } catch { /* 跳过坏 IPv6 */ }
    }
  }
  const exts = derSeq(
    derExt('2.5.29.19', true, derSeq()), // CA:FALSE
    derExt('2.5.29.15', true, derBits(Buffer.from([0x80]))), // digitalSignature
    derExt('2.5.29.37', false, derSeq(derOid('1.3.6.1.5.5.7.3.1'))), // serverAuth
    ...(san.length ? [derExt('2.5.29.17', false, derSeq(...san))] : []),
  );
  const tbs = derSeq(
    derCtx(0, derInt(2)),
    derInt(crypto.randomBytes(16)),
    alg,
    nm,
    derSeq(derUtc(new Date(now - 86400000)), derUtc(new Date(now + 3650 * 86400000))),
    nm,
    spki,
    derCtx(3, exts),
  );
  const sig = crypto.sign('sha256', tbs, privateKey);
  const cert = derSeq(tbs, alg, derBits(sig));
  const certPem = `-----BEGIN CERTIFICATE-----\n${cert.toString('base64').match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----\n`;
  const keyPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const fingerprint = crypto.createHash('sha256').update(cert).digest('hex');
  return { certPem, keyPem, fingerprint };
}
function certFingerprint(pem) {
  try { return crypto.createHash('sha256').update(new crypto.X509Certificate(pem).raw).digest('hex'); } catch { return ''; }
}

/* ── 固定指纹的 HTTPS 客户端（先握手验指纹，再发任何字节/凭据）───── */
/**
 * 不用全局 fetch：自签模式必须“指纹吻合后才发送 Authorization”。
 * 返回 {status, headers, text, json, fingerprint, secure, ms}。
 */
async function rawHttpRequest(o) {
  const t0 = Date.now();
  const host = String(o.host || '');
  const port = Number(o.port) || 80;
  const timeoutMs = Math.max(100, Number(o.timeoutMs) || UPSTREAM_TIMEOUT_MS);
  const body = Buffer.from(String(o.body ?? ''), 'utf8');
  const headers = { host: `${host.includes(':') ? `[${host}]` : host}:${port}`, 'content-type': 'application/json', 'content-length': String(body.length), connection: 'close', ...(o.headers || {}) };
  const mode = o.tls && o.tls.mode ? o.tls.mode : 'off';
  let socket;
  let fingerprint = '';
  const secure = mode !== 'off';
  if (secure) {
    const opt = {
      host, port, minVersion: 'TLSv1.2',
      rejectUnauthorized: mode === 'verify',
      servername: isIp(host) ? undefined : host,
    };
    if (o.tls && o.tls.caFile) { try { opt.ca = fs.readFileSync(o.tls.caFile); } catch { /* 无 CA 文件按系统 CA */ } }
    if (o.tls && o.tls.servername) opt.servername = String(o.tls.servername);
    socket = tls.connect(opt);
  } else {
    socket = net.connect({ host, port });
  }
  return await new Promise((resolve, reject) => {
    let done = false;
    const finish = (err, val) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      try { socket.destroy(); } catch { /* noop */ }
      if (err) reject(err); else resolve(val);
    };
    const timer = setTimeout(() => finish(new Error('timeout')), timeoutMs);
    socket.once('error', (e) => finish(e));
    if (!secure) socket.once('connect', sendRequest);
    else socket.once('secureConnect', () => {
      try {
        const peer = socket.getPeerCertificate();
        fingerprint = peer && peer.raw ? crypto.createHash('sha256').update(peer.raw).digest('hex') : '';
        if (mode === 'pin') {
          const want = String(o.tls.fingerprint || '').toLowerCase();
          if (!want) return finish(new Error('fingerprint-required'));
          if (fingerprint !== want) return finish(new Error('fingerprint-mismatch'));
        }
      } catch (e) { return finish(e); }
      sendRequest();
    });
    function sendRequest() {
      const head = `${o.method || 'GET'} ${o.path || '/'} HTTP/1.1\r\n`
        + Object.entries(headers).map(([k, v]) => `${k}: ${v}`).join('\r\n') + '\r\n\r\n';
      try { socket.write(head); if (body.length) socket.write(body); } catch (e) { return finish(e); }
      const chunks = [];
      let n = 0;
      socket.on('data', (d) => {
        n += d.length;
        if (n > 512 * 1024) return finish(new Error('response-too-large'));
        chunks.push(d);
      });
      socket.on('end', () => {
        const all = Buffer.concat(chunks);
        const i = all.indexOf('\r\n\r\n');
        if (i < 0) return finish(new Error('bad-response'));
        const headText = all.subarray(0, i).toString('utf8');
        const lines = headText.split('\r\n');
        const status = Number((lines[0] || '').split(' ')[1]) || 0;
        const hdrs = {};
        for (const line of lines.slice(1)) {
          const k = line.indexOf(':');
          if (k > 0) hdrs[line.slice(0, k).trim().toLowerCase()] = line.slice(k + 1).trim();
        }
        let buf = all.subarray(i + 4);
        if (/chunked/i.test(hdrs['transfer-encoding'] || '')) buf = dechunk(buf);
        else if (hdrs['content-length']) buf = buf.subarray(0, Number(hdrs['content-length']) || buf.length);
        const text = buf.toString('utf8');
        let json = null;
        try { json = JSON.parse(text); } catch { /* 非 JSON */ }
        finish(null, { status, headers: hdrs, text, json, fingerprint, secure, ms: Date.now() - t0 });
      });
    }
  });
}
function dechunk(buf) {
  const out = [];
  let p = 0;
  while (p < buf.length) {
    const e = buf.indexOf('\r\n', p);
    if (e < 0) break;
    const n = parseInt(buf.subarray(p, e).toString('ascii').trim(), 16);
    if (!Number.isFinite(n) || n <= 0) break;
    out.push(buf.subarray(e + 2, e + 2 + n));
    p = e + 2 + n + 2;
  }
  return Buffer.concat(out);
}

/* ── STUN / NAT-PMP（纯 UDP，不内置任何公网服务器）───────────────── */
const STUN_MAGIC = 0x2112a442;
function stunRequest(software = 'FWArmy/1') {
  const tid = crypto.randomBytes(12);
  const val = Buffer.from(String(software).slice(0, 32), 'utf8');
  const pad = (4 - (val.length % 4)) % 4;
  const a = Buffer.alloc(4 + val.length + pad);
  a.writeUInt16BE(0x0013, 0); a.writeUInt16BE(val.length, 2); val.copy(a, 4);
  const head = Buffer.alloc(20);
  head.writeUInt16BE(0x0001, 0);
  head.writeUInt16BE(a.length, 2);
  head.writeUInt32BE(STUN_MAGIC, 4);
  tid.copy(head, 8);
  return { buf: Buffer.concat([head, a]), tid };
}
function parseStun(buf) {
  if (!buf || buf.length < 20) return null;
  if (buf.readUInt16BE(0) !== 0x0101) return null;
  const len = buf.readUInt16BE(2);
  const tid = buf.subarray(8, 20);
  const out = { tid, mapped: null };
  let p = 20;
  const end = Math.min(buf.length, 20 + len);
  while (p + 4 <= end) {
    const t = buf.readUInt16BE(p), l = buf.readUInt16BE(p + 2);
    const v = buf.subarray(p + 4, p + 4 + l);
    if (t === 0x0020 && l >= 8 && v[1] === 1) {
      const port = v.readUInt16BE(2) ^ (STUN_MAGIC >>> 16);
      const ip = (v.readUInt32BE(4) ^ STUN_MAGIC) >>> 0;
      out.mapped = { host: `${ip >>> 24}.${(ip >>> 16) & 255}.${(ip >>> 8) & 255}.${ip & 255}`, port };
    } else if (t === 0x0001 && l >= 8 && v[1] === 1) {
      out.mapped = { host: `${v[4]}.${v[5]}.${v[6]}.${v[7]}`, port: v.readUInt16BE(2) };
    }
    p += 4 + l + ((4 - (l % 4)) % 4);
  }
  return out;
}
async function stunUdp(pkt, addr, timeoutMs) {
  return await new Promise((resolve) => {
    const sock = dgram.createSocket('udp4');
    let done = false;
    const fin = (v) => { if (done) return; done = true; clearTimeout(t); try { sock.close(); } catch { /* noop */ } resolve(v); };
    const t = setTimeout(() => fin(null), Math.max(100, timeoutMs));
    sock.on('message', (m) => fin(m));
    sock.on('error', () => fin(null));
    try { sock.send(pkt, addr.port, addr.host, (e) => { if (e) fin(null); }); } catch { fin(null); }
  });
}
/** 问 STUN 自己的公网映射；servers 为空就如实返回 no-server（隐私默认）。 */
export async function stunBinding({ servers = [], timeoutMs = 1500, send = null } = {}) {
  const t0 = Date.now();
  const attempts = [];
  const list = (servers || []).map((s) => String(s || '').trim()).filter(Boolean);
  if (!list.length) return { ok: false, reason: 'no-server', detail: '未配置 STUN 服务器（不内置公网服务器）', attempts, ms: 0 };
  const { buf, tid } = stunRequest();
  for (const raw of list) {
    const ta = Date.now();
    let host = raw.replace(/^stuns?:\/\//i, '').split('?')[0];
    let port = 3478;
    const m = /^\[([^\]]+)\](?::(\d+))?$/.exec(host);
    if (m) { host = m[1]; if (m[2]) port = Number(m[2]); }
    else if (host.split(':').length === 2) { const [h, pp] = host.split(':'); host = h; port = Number(pp) || 3478; }
    try {
      // 注入 send 的门禁不解析 DNS：离线 mock 不需要真实域名。
      if (!send && !isIp(host)) host = (await lookup(host)).address;
      const resp = send ? await send(buf, { host, port }, timeoutMs) : await stunUdp(buf, { host, port }, timeoutMs);
      if (!resp) { attempts.push({ server: raw, ok: false, reason: 'timeout', ms: Date.now() - ta }); continue; }
      const j = parseStun(resp);
      if (!j || !j.tid.equals(tid)) { attempts.push({ server: raw, ok: false, reason: 'bad-response', ms: Date.now() - ta }); continue; }
      if (!j.mapped) { attempts.push({ server: raw, ok: false, reason: 'no-mapped', ms: Date.now() - ta }); continue; }
      attempts.push({ server: raw, ok: true, reason: 'ok', ms: Date.now() - ta });
      return { ok: true, publicAddress: j.mapped, via: raw, reason: 'resolved', attempts, ms: Date.now() - t0 };
    } catch (e) {
      attempts.push({ server: raw, ok: false, reason: 'network', ms: Date.now() - ta });
      void e;
    }
  }
  return { ok: false, reason: 'timeout', attempts, ms: Date.now() - t0 };
}

const NATPMP_PORT = 5351;
const NATPMP_TEXT = { 0: 'ok', 1: 'unsupported-version', 2: 'unauthorized', 3: 'not-a-gateway', 4: 'external-only-support', 5: 'gateway-unavailable', 6: 'no-memory-resources', 7: 'no-port-resources' };
async function natpmpUdp(pkt, gateway, timeoutMs) {
  return await new Promise((resolve) => {
    const sock = dgram.createSocket('udp4');
    let done = false;
    const fin = (v) => { if (done) return; done = true; clearTimeout(t); try { sock.close(); } catch { /* noop */ } resolve(v); };
    const t = setTimeout(() => fin(null), Math.max(100, timeoutMs));
    sock.on('message', (m) => fin(m));
    sock.on('error', () => fin(null));
    try { sock.send(pkt, NATPMP_PORT, gateway, (e) => { if (e) fin(null); }); } catch { fin(null); }
  });
}
/** 只读探针：version=1 会被路由器回 UNSUPPORTED_VERSION，不会创建任何映射。 */
export async function natpmpProbe({ gateways = [], timeoutMs = 1200, request = null } = {}) {
  const t0 = Date.now();
  const attempts = [];
  const gws = (gateways.length ? gateways : gatewayCandidates()).filter(Boolean);
  if (!gws.length) return { alive: false, detail: '没有私有网关候选（可能直连公网或没有 IPv4 网卡）', attempts, ms: 0 };
  const pkt = Buffer.alloc(16); pkt[0] = 1;
  for (const gw of gws) {
    if (!isPrivateIpv4(gw)) { attempts.push({ gateway: gw, ok: false, reason: 'bad-gateway' }); continue; }
    const resp = request ? await request(pkt, gw, timeoutMs) : await natpmpUdp(pkt, gw, timeoutMs);
    if (!resp) { attempts.push({ gateway: gw, ok: false, reason: 'timeout' }); continue; }
    const result = resp.length >= 4 && resp[1] === 128 ? resp.readUInt16BE(2) : null;
    const txt = result === null ? 'responded' : (NATPMP_TEXT[result] || `result-${result}`);
    attempts.push({ gateway: gw, ok: true, reason: txt });
    return { alive: true, gateway: gw, detail: `网关 ${gw} 应答 NAT-PMP（${txt}）`, attempts, ms: Date.now() - t0 };
  }
  return { alive: false, detail: `${gws.length} 个网关候选都没应答 5351/UDP（不支持或被挡）`, attempts, ms: Date.now() - t0 };
}
/**
 * 申请/取消映射（会改路由器状态，必须显式调用）。externalPort=0 让路由器挑；
 * leaseSec=0 + 同内部端口即删除。
 */
export async function natpmpMap({ gateway, internalPort, externalPort = 0, leaseSec = 7200, protocol = 'tcp', timeoutMs = 1500, request = null }) {
  const gw = String(gateway || '');
  if (!isPrivateIpv4(gw)) return { ok: false, reason: 'bad-gateway', detail: '只允许向私有/链路本地网关申请映射' };
  const explicit = Number(externalPort) > 0;
  const pkt = Buffer.alloc(16);
  pkt[0] = 0;
  pkt[1] = protocol === 'tcp' ? (explicit ? 3 : 1) : (explicit ? 2 : 0);
  if (explicit) pkt.writeUInt16BE(Number(externalPort), 2);
  pkt.writeUInt16BE(Number(internalPort) & 0xffff, 4);
  pkt.writeUInt16BE(Number(externalPort) || 0, 8);
  pkt.writeUInt32BE(Math.max(0, Math.min(0xffffffff, Math.trunc(Number(leaseSec) || 0))), 12);
  const resp = request ? await request(pkt, gw, timeoutMs) : await natpmpUdp(pkt, gw, timeoutMs);
  if (!resp) return { ok: false, reason: 'timeout', gateway: gw };
  if (resp.length < 16 || resp[1] < 128) return { ok: false, reason: 'bad-response', gateway: gw };
  const result = resp.readUInt16BE(2);
  if (result !== 0) return { ok: false, reason: NATPMP_TEXT[result] || 'router-refused', gateway: gw, result };
  return {
    ok: true, gateway: gw, reason: 'router-ok',
    internalPort: resp.readUInt16BE(8), externalPort: resp.readUInt16BE(10), lifetime: resp.readUInt32BE(12),
  };
}
function gatewayCandidates() {
  const out = [];
  for (const list of Object.values(os.networkInterfaces())) {
    for (const it of list || []) {
      if (it.family !== 'IPv4' || it.internal || !isPrivateIpv4(it.address)) continue;
      const base = it.address.split('.').slice(0, 3).join('.') + '.';
      for (const tail of ['1', '254']) { const g = base + tail; if (g !== it.address && !out.includes(g)) out.push(g); }
    }
  }
  return out;
}
function localAddresses() {
  const out = [];
  for (const [iface, list] of Object.entries(os.networkInterfaces())) {
    for (const it of list || []) {
      if (!it.address) continue;
      out.push({ iface, address: it.address, family: it.family, internal: !!it.internal, private: it.family === 'IPv4' ? isPrivateIpv4(it.address) : /^fe80:/i.test(it.address) });
    }
  }
  return out;
}

/**
 * 解析命令行。单文件 SEA 的 process.argv 会把 exe 路径重复一次，调用方统一传“真正的参数”。
 */
export function parseArgs(argv = []) {
  const o = { port: 8787, host: '0.0.0.0', open: null, data: '', quiet: false, logFile: '' };
  for (const a of argv) {
    if (a.startsWith('--port=')) o.port = Number(a.slice(7));
    else if (a.startsWith('--host=')) o.host = a.slice(7) || '0.0.0.0';
    else if (a.startsWith('--data=')) o.data = a.slice(7);
    else if (a.startsWith('--log-file=')) o.logFile = a.slice(11);
    else if (a === '--open') o.open = true;
    else if (a === '--no-open' || a === '--headless') o.open = false;
    else if (a === '--quiet') o.quiet = true;
  }
  if (!Number.isFinite(o.port) || o.port < 1 || o.port > 65535) o.port = 8787;
  return o;
}

function resolveDataDir(optData) {
  if (optData) return path.resolve(optData);
  const env = process.env.FWARMY_DATA || process.env.WARMY_RELAY_DATA; // WARMY_RELAY_DATA 为旧名兼容
  if (env) return path.resolve(env);
  return path.join(APP_DIR, 'data');
}

function writeJsonAtomic(file, obj, mode = 0o600) {
  const tmp = `${file}.${process.pid}.${crypto.randomBytes(3).toString('hex')}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(obj, null, 2), { encoding: 'utf8', mode });
  try {
    fs.renameSync(tmp, file);
  } catch (e) {
    try { fs.rmSync(file, { force: true }); fs.renameSync(tmp, file); } catch { throw e; }
  }
}

function emptyAgg() {
  return { requests: 0, bytesIn: 0, bytesOut: 0, relayed: 0, delivered: 0, rejected: 0, offline: 0 };
}
function normAgg(b) {
  const o = emptyAgg();
  if (b && typeof b === 'object') for (const k of Object.keys(o)) o[k] = Number(b[k]) || 0;
  return o;
}
function emptyStats() {
  return {
    v: 1,
    since: new Date().toISOString(),
    credentials: {},
    unauthorized: 0,
    peakPerMin: 0,
    peakAt: 0,
    minute: { key: '', n: 0 },
  };
}
function normMap(m) {
  const out = {};
  if (m && typeof m === 'object') for (const [k, v] of Object.entries(m)) out[k] = normAgg(v);
  return out;
}
function normCredStats(c, id) {
  return {
    id,
    name: String(c && c.name || ''),
    createdAt: String(c && c.createdAt || ''),
    deletedAt: Number(c && c.deletedAt) || 0,
    total: normAgg(c && c.total),
    days: normMap(c && c.days),
    months: normMap(c && c.months),
    years: normMap(c && c.years),
    peakPerMin: Number(c && c.peakPerMin) || 0,
    peakAt: Number(c && c.peakAt) || 0,
    lastMinute: { key: String(c && c.lastMinute && c.lastMinute.key || ''), n: Number(c && c.lastMinute && c.lastMinute.n) || 0 },
    lastUsed: Number(c && c.lastUsed) || 0,
  };
}
function normStats(raw) {
  const out = emptyStats();
  if (!raw || typeof raw !== 'object') return out;
  out.since = String(raw.since || out.since);
  out.unauthorized = Number(raw.unauthorized) || 0;
  out.peakPerMin = Number(raw.peakPerMin) || 0;
  out.peakAt = Number(raw.peakAt) || 0;
  out.minute = { key: String(raw.minute && raw.minute.key || ''), n: Number(raw.minute && raw.minute.n) || 0 };
  for (const [id, c] of Object.entries(raw.credentials || {})) out.credentials[id] = normCredStats(c, id);
  return out;
}
function pruneMap(m, keep) {
  const keys = Object.keys(m).sort().reverse();
  for (const k of keys.slice(keep)) delete m[k];
}

/* ── 扩网 / 被扩网（多个 FWArmy 之间转发） ─────────────────────────── */
function emptySide() {
  return { total: emptyAgg(), days: {}, months: {}, lastAt: 0, lastResult: '' };
}
function normSide(raw) {
  const o = emptySide();
  if (raw && typeof raw === 'object') {
    o.total = normAgg(raw.total);
    o.days = normMap(raw.days);
    o.months = normMap(raw.months);
    o.lastAt = Number(raw.lastAt) || 0;
    o.lastResult = String(raw.lastResult || '').slice(0, 120);
  }
  return o;
}
function normTlsPeer(raw) {
  const t = raw && typeof raw === 'object' ? raw : {};
  const mode = t.mode === 'off' || t.mode === 'verify' ? t.mode : 'pin';
  const fp = String(t.fingerprint || '').toLowerCase().replace(/[^0-9a-f]/g, '');
  return {
    mode,
    fingerprint: fp.length === 64 ? fp : '',
    servername: String(t.servername || '').slice(0, 253),
    caFile: String(t.caFile || '').slice(0, 500),
  };
}
function emptyExpand() {
  return {
    v: 2,
    instanceId: crypto.randomBytes(8).toString('hex'),
    identity: { pub: '', priv: '' },
    inbound: [],
    outbound: [],
    natpmp: null,
    stats: { inbound: emptySide(), outbound: emptySide(), perOutbound: {}, perSource: {}, perInbound: {} },
  };
}
function normInbound(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const hash = String(raw.hash || raw.tokenHash || '');
  if (!/^[0-9a-f]{64}$/.test(hash)) return null;
  return {
    id: String(raw.id || crypto.randomUUID()),
    name: String(raw.name || '接入凭据').slice(0, 40),
    hash,
    prefix: String(raw.prefix || '').slice(0, 24),
    createdAt: Number(raw.createdAt) || 0,
    lastAt: Number(raw.lastAt) || 0,
    lastResult: String(raw.lastResult || '').slice(0, 120),
    disabled: raw.disabled === true,
  };
}
function normOutbound(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const host = String(raw.host || '').trim();
  const port = Number(raw.port);
  if (!host || !Number.isInteger(port) || port < 1 || port > 65535) return null;
  return {
    id: String(raw.id || crypto.randomUUID()),
    name: String(raw.name || host).slice(0, 40),
    host, port,
    credential: String(raw.credential || ''),
    tls: normTlsPeer(raw.tls),
    enabled: raw.enabled !== false,
    createdAt: Number(raw.createdAt) || Date.now(),
    lastTest: Number(raw.lastTest) || 0,
    lastTestOk: raw.lastTestOk === true,
  };
}
function normExpand(raw) {
  const o = emptyExpand();
  if (!raw || typeof raw !== 'object') return o;
  o.instanceId = String(raw.instanceId || o.instanceId).slice(0, 64);
  const idn = raw.identity && typeof raw.identity === 'object' ? raw.identity : {};
  o.identity = { pub: String(idn.pub || ''), priv: String(idn.priv || '') };
  if (Array.isArray(raw.inbound)) o.inbound = raw.inbound.map(normInbound).filter(Boolean);
  else {
    const one = normInbound(raw.inbound);
    if (one) { one.name = '旧版接入凭据'; one.createdAt = one.createdAt || Date.now(); o.inbound = [one]; }
  }
  o.outbound = Array.isArray(raw.outbound) ? raw.outbound.map(normOutbound).filter(Boolean) : [];
  const nm = raw.natpmp && typeof raw.natpmp === 'object' ? raw.natpmp : null;
  o.natpmp = nm && Number(nm.externalPort) > 0 ? {
    gateway: String(nm.gateway || ''), internalPort: Number(nm.internalPort) || 0,
    externalPort: Number(nm.externalPort) || 0, lifetimeSec: Number(nm.lifetimeSec) || 0,
    mappedAt: Number(nm.mappedAt) || 0, protocol: nm.protocol === 'udp' ? 'udp' : 'tcp',
  } : null;
  const st = raw.stats && typeof raw.stats === 'object' ? raw.stats : {};
  o.stats.inbound = normSide(st.inbound);
  o.stats.outbound = normSide(st.outbound);
  for (const [k, v] of Object.entries(st.perOutbound || {})) o.stats.perOutbound[k] = normSide(v);
  for (const [k, v] of Object.entries(st.perSource || {})) o.stats.perSource[String(k)] = normSide(v);
  for (const [k, v] of Object.entries(st.perInbound || {})) o.stats.perInbound[String(k)] = normSide(v);
  return o;
}
function normTlsCfg(raw) {
  const d = DEFAULTS.tls;
  const t = raw && typeof raw === 'object' ? raw : {};
  const mode = t.mode === 'off' || t.mode === 'user-cert' ? t.mode : 'self-signed';
  return {
    mode,
    allowPlaintext: t.allowPlaintext === true,
    certFile: String(t.certFile || '').slice(0, 500),
    keyFile: String(t.keyFile || '').slice(0, 500),
    hostnames: Array.isArray(t.hostnames) ? t.hostnames.map((x) => String(x).slice(0, 253)).filter(Boolean).slice(0, 16) : d.hostnames,
  };
}
/** 地址：IP 或域名；不写端口默认 59599；可写 host:port / [v6]:port / http(s)://host:port。 */
export function parseExpandAddress(raw) {
  let s = String(raw || '').trim();
  if (!s) throw new Error('bad-address');
  s = s.replace(/^https?:\/\//i, '').replace(/\/.*$/, '');
  let host = '';
  let port = 59599;
  if (s.startsWith('[')) {
    const m = /^\[([^\]]+)\](?::(\d+))?$/.exec(s);
    if (!m) throw new Error('bad-address');
    host = m[1];
    if (m[2]) port = Number(m[2]);
  } else {
    const i = s.lastIndexOf(':');
    if (i > 0 && s.indexOf(':') === i) {
      host = s.slice(0, i);
      port = Number(s.slice(i + 1));
    } else host = s;
  }
  host = host.trim();
  if (!host || /[\s/?#]/.test(host)) throw new Error('bad-address');
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('bad-port');
  return { host, port };
}
export function expandBaseUrl(p) {
  return `http://${String(p.host).includes(':') ? `[${p.host}]` : p.host}:${p.port}`;
}
function peerTls(p) { return normTlsPeer(p && p.tls); }
function peerScheme(p) { return peerTls(p).mode === 'off' ? 'http' : 'https'; }
function peerUrl(p) { return `${peerScheme(p)}://${String(p.host).includes(':') ? `[${p.host}]` : p.host}:${p.port}`; }
function aggAdd(target, add) {
  for (const k of Object.keys(emptyAgg())) target[k] += Number(add[k]) || 0;
}

/** 中日韩/全角字符按 2 列计算，供控制台表格对齐。 */
export function displayWidth(s) {
  let n = 0;
  for (const ch of String(s)) {
    const cp = ch.codePointAt(0) || 0;
    const wide = (cp >= 0x1100 && cp <= 0x115f) || (cp >= 0x2e80 && cp <= 0xa4cf)
      || (cp >= 0xac00 && cp <= 0xd7a3) || (cp >= 0xf900 && cp <= 0xfaff)
      || (cp >= 0xfe10 && cp <= 0xfe6f) || (cp >= 0xff00 && cp <= 0xff60)
      || (cp >= 0xffe0 && cp <= 0xffe6) || (cp >= 0x1f300 && cp <= 0x1faff)
      || (cp >= 0x20000 && cp <= 0x3fffd);
    n += wide ? 2 : 1;
  }
  return n;
}
export function padCell(s, width, right = false) {
  const t = String(s == null ? '' : s);
  const fill = ' '.repeat(Math.max(0, width - displayWidth(t)));
  return right ? fill + t : t + fill;
}
export function renderTable(headers, rows, aligns = []) {
  const widths = headers.map((h, i) => Math.max(displayWidth(h), ...rows.map((r) => displayWidth(r[i] == null ? '' : r[i]))));
  const line = (cells) => cells.map((c, i) => padCell(c, widths[i], aligns[i] === 'right')).join('  ');
  return [line(headers), widths.map((w) => '-'.repeat(w)).join('  '), ...rows.map(line)].join('\n');
}

/**
 * @param {{argv?: string[], data?: string, port?: number, host?: string, open?: boolean}} options
 */
export async function startServer(options = {}) {
  const opt = parseArgs(options.argv || []);
  if (options.port) opt.port = options.port;
  if (options.host) opt.host = options.host;
  if (options.open !== undefined) opt.open = options.open;
  const DATA = resolveDataDir(options.data || opt.data);
  const CK = path.join(DATA, 'credentials.json');
  const CFG_FILE = path.join(DATA, 'config.json');
  const STATS_FILE = path.join(DATA, 'stats.json');
  const LOG = opt.logFile ? path.resolve(opt.logFile) : path.join(DATA, 'server.log');
  const PID_FILE = path.join(DATA, 'server.pid');
  const INSTANCE = path.join(DATA, 'instance.json');
  const FIRST_CRED = path.join(DATA, 'first-credential.txt');
  const FIRST_CRED_ENC = path.join(DATA, 'first-credential.enc');
  const EXPAND_FILE = path.join(DATA, 'expand.json');
  const SECURITY_FILE = path.join(DATA, 'security.json');
  const UPDATE_FILE = path.join(DATA, 'update.json');
  const TLS_DIR = path.join(DATA, 'tls');
  const STARTED = Date.now();
  let actualPort = 0;
  /** 安全判定（24h 窗口/30 天黑名单）用可注入时钟，门禁才能跑“一天后/三十天后”；队列 TTL 仍用真实时间。 */
  const now = () => (typeof options.clock === 'function' ? Number(options.clock()) : Date.now());

  fs.mkdirSync(DATA, { recursive: true });
  fs.mkdirSync(path.dirname(LOG), { recursive: true });

  // ── 日志（写文件 + 终端；绝不写消息明文/凭据明文）──
  let logStream = null;
  let logLines = 0;
  function rotateLog() {
    try {
      if (!fs.existsSync(LOG)) return;
      if (fs.statSync(LOG).size < 5 * 1024 * 1024) return;
      const old = LOG + '.1';
      try { fs.rmSync(old, { force: true }); } catch { /* noop */ }
      fs.renameSync(LOG, old);
    } catch { /* 日志问题不挡启动 */ }
  }
  rotateLog();
  try { logStream = fs.createWriteStream(LOG, { flags: 'a', mode: 0o600 }); } catch { logStream = null; }
  function log(level, msg) {
    const line = `${new Date().toISOString()} ${String(level).padEnd(5)} ${msg}\n`;
    if (!opt.quiet) { try { process.stdout.write(line); } catch { /* noop */ } }
    if (logStream) {
      try { logStream.write(line); logLines++; } catch { /* noop */ }
    }
  }
  try { process.stdout.on('error', () => { /* 管道关闭不影响服务 */ }); } catch { /* noop */ }

  // ── 凭据 ──
  let creds = {};
  try {
    const raw = JSON.parse(fs.readFileSync(CK, 'utf8'));
    creds = raw && raw.items && typeof raw.items === 'object' ? raw.items : {};
  } catch (e) {
    if (e && e.code !== 'ENOENT') {
      try { fs.renameSync(CK, `${CK}.corrupt-${Date.now()}`); } catch { /* noop */ }
      log('WARN', 'credentials.json 损坏，按空表启动（原文件已改名保留）');
    }
    creds = {};
  }
  function normLimits(raw, legacy = {}) {
    const out = {};
    for (const k of LIMIT_KEYS) {
      const v = raw && raw[k] !== undefined ? raw[k] : legacy[k];
      if (v === undefined || v === null || v === '') { out[k] = null; continue; }
      const n = Number(v);
      out[k] = validLimit(k, n) ? n : null; // 旧分钟 0/非法值迁移为非零全局默认
    }
    return out;
  }
  let migrated = false;
  for (const [id, raw] of Object.entries(creds)) {
    const c = raw && typeof raw === 'object' ? raw : {};
    c.id = String(c.id || id);
    c.name = String(c.name || '未命名').slice(0, 40) || '未命名';
    c.hash = String(c.hash || '');
    c.hash8 = String(c.hash8 || c.hash.slice(0, 8));
    c.createdAt = String(c.createdAt || new Date().toISOString());
    // 旧字段 revoked → disabled；旧单凭据限额 → limits（不再丢弃）
    c.disabled = !!(c.disabled || c.revoked);
    c.limits = normLimits(c.limits, { ratePerMin: c.ratePerMin, dailyBytes: c.dailyBytes });
    c.lastUsed = Number(c.lastUsed) || 0;
    // 旧计数器仅用于一次性迁移到 stats；迁移后不再写入凭据文件
    c.__legacyRequests = Number(c.requests) || 0;
    c.__legacyBytes = Number(c.bytes) || 0;
    delete c.revoked; delete c.ratePerMin; delete c.dailyBytes; delete c.requests; delete c.bytes;
    creds[id] = c;
    migrated = true;
  }
  function saveCreds() {
    try {
      writeJsonAtomic(CK, { items: creds });
    } catch (e) { log('WARN', '写 credentials.json 失败：' + (e && e.message || e)); }
  }
  if (migrated) saveCreds();

  let hashIndex = new Map();
  function rebuildIndex() {
    hashIndex = new Map();
    for (const c of Object.values(creds)) if (c.hash) hashIndex.set(c.hash, c);
  }
  rebuildIndex();

  // ── 配置（旧 config 字段原样兼容）──
  let cfg = { ...DEFAULTS };
  let cfgRaw = null;
  try {
    const raw = JSON.parse(fs.readFileSync(CFG_FILE, 'utf8'));
    if (raw && typeof raw === 'object') { cfgRaw = raw; cfg = { ...cfg, ...raw }; }
  } catch { /* 用默认 */ }
  for (const k of Object.keys(CONFIG_RANGES)) {
    const n = Number(cfg[k]);
    cfg[k] = validLimit(k, n) ? n : DEFAULTS[k];
  }
  cfg.accepting = cfg.accepting !== false;
  cfg.tls = normTlsCfg(cfgRaw && cfgRaw.tls);
  if (cfg.tls.mode === 'off') log('WARN', 'TLS 已关闭：业务凭据会以明文跨网传输，只建议在回环/VPN 内使用');
  const secret = createSecretBox(DATA);
  /** 旧版 first-credential.txt 是明文秘密：启动时改存 AES-GCM（.enc）并删除明文。 */
  function migrateFirstCredential() {
    try {
      if (!fs.existsSync(FIRST_CRED)) return;
      const token = fs.readFileSync(FIRST_CRED, 'utf8').trim();
      if (token) fs.writeFileSync(FIRST_CRED_ENC, secret.seal(token, 'first-credential'), { mode: 0o600 });
      fs.rmSync(FIRST_CRED, { force: true });
      log('INFO', '首次凭据已从明文文件迁移为加密文件（first-credential.enc）');
    } catch (e) { log('WARN', '首次凭据明文迁移失败：' + String(e && e.message || e).slice(0, 120)); }
  }
  migrateFirstCredential();
  function readFirstCredential() {
    try { if (fs.existsSync(FIRST_CRED_ENC)) return secret.open(fs.readFileSync(FIRST_CRED_ENC, 'utf8').trim(), 'first-credential'); } catch { /* noop */ }
    try { return fs.readFileSync(FIRST_CRED, 'utf8').trim(); } catch { return ''; }
  }
  function clearFirstCredential() {
    try { fs.rmSync(FIRST_CRED_ENC, { force: true }); } catch { /* noop */ }
    try { fs.rmSync(FIRST_CRED, { force: true }); } catch { /* noop */ }
  }
  function saveCfg() {
    try { writeJsonAtomic(CFG_FILE, cfg); } catch (e) { log('WARN', '写 config.json 失败：' + (e && e.message || e)); }
  }
  saveCfg();

  // ── 统计（损坏按空表处理，不挡启动）──
  let stats = emptyStats();
  try {
    const raw = fs.readFileSync(STATS_FILE, 'utf8');
    stats = normStats(JSON.parse(raw));
  } catch (e) {
    if (e && e.code !== 'ENOENT') {
      try { fs.renameSync(STATS_FILE, `${STATS_FILE}.corrupt-${Date.now()}`); } catch { /* noop */ }
      log('WARN', 'stats.json 损坏，按空表启动（原文件已改名保留）：' + (e && e.message || e));
    }
  }
  let legacyCleared = false;
  for (const c of Object.values(creds)) {
    const s = stats.credentials[c.id] || (stats.credentials[c.id] = normCredStats({ name: c.name, createdAt: c.createdAt }, c.id));
    if (s.total.requests === 0 && s.total.bytesIn === 0 && (c.__legacyRequests || c.__legacyBytes)) {
      s.total.requests = c.__legacyRequests || 0;
      s.total.bytesIn = c.__legacyBytes || 0; // 旧数据没有方向拆分，统一记入上行
    }
    if (!s.name) s.name = c.name;
    pruneMap(s.days, 400); pruneMap(s.months, 36); pruneMap(s.years, 10);
    if (c.__legacyRequests || c.__legacyBytes) { delete c.__legacyRequests; delete c.__legacyBytes; legacyCleared = true; }
  }
  if (legacyCleared) saveCreds();
  let statsDirty = false;
  let statsTimer = null;
  function flushStats(force = false) {
    if (!statsDirty && !force) return;
    statsDirty = false;
    // 长期运行也要有界：只保留约 400 天 / 36 月 / 10 年
    for (const s of Object.values(stats.credentials)) {
      pruneMap(s.days, 400); pruneMap(s.months, 36); pruneMap(s.years, 10);
    }
    try { writeJsonAtomic(STATS_FILE, stats); } catch (e) { log('WARN', '写 stats.json 失败：' + (e && e.message || e)); }
  }
  function markStatsDirty() {
    statsDirty = true;
    if (statsTimer) return;
    statsTimer = setTimeout(() => { statsTimer = null; flushStats(); }, 3000);
    if (statsTimer.unref) statsTimer.unref();
  }
  const statsInterval = setInterval(() => flushStats(), 10_000);
  statsInterval.unref();
  saveCreds();

  // ── 扩网 / 被扩网状态 ──
  let expand = emptyExpand();
  try {
    expand = normExpand(JSON.parse(fs.readFileSync(EXPAND_FILE, 'utf8')));
  } catch (e) {
    if (e && e.code !== 'ENOENT') {
      try { fs.renameSync(EXPAND_FILE, `${EXPAND_FILE}.corrupt-${Date.now()}`); } catch { /* noop */ }
      log('WARN', 'expand.json 损坏，按空表启动（原文件已改名保留）');
    }
  }
  let tlsInfo = null;
  let expandDirty = false;
  let expandTimer = null;
  function saveExpand() {
    expandDirty = false;
    try { writeJsonAtomic(EXPAND_FILE, expand); }
    catch (e) { log('WARN', '写 expand.json 失败：' + (e && e.message || e)); }
  }
  function markExpandDirty() {
    expandDirty = true;
    if (expandTimer) return;
    expandTimer = setTimeout(() => { expandTimer = null; saveExpand(); }, 1200);
    if (expandTimer.unref) expandTimer.unref();
  }
  // 实例身份：起源签名用 Ed25519 私钥；私钥 AES-GCM 落盘，公钥明文。
  let identityKey = null;
  function ensureIdentity() {
    let dirty = false;
    if (!expand.identity.pub || !expand.identity.priv) {
      const kp = crypto.generateKeyPairSync('ed25519');
      const pub = kp.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32).toString('base64');
      expand.identity = { pub, priv: secret.seal(kp.privateKey.export({ type: 'pkcs8', format: 'pem' }), 'expand.identity') };
      dirty = true;
    } else if (!secret.encrypted(expand.identity.priv)) {
      expand.identity.priv = secret.seal(expand.identity.priv, 'expand.identity');
      dirty = true;
    }
    const pem = secret.open(expand.identity.priv, 'expand.identity');
    try { identityKey = pem ? crypto.createPrivateKey(pem) : null; } catch { identityKey = null; }
    if (!identityKey) {
      log('ERROR', '实例签名私钥无法解密（secret.key 变了？），来源签名将不可用；请让对端重新固定本实例公钥');
    }
    if (dirty) saveExpand();
  }
  ensureIdentity();
  // 旧版出网凭据是明文：加载时原地重封，之后任何日志/接口都不返回明文。
  let credMigrated = false;
  for (const p of expand.outbound) {
    if (p.credential && !secret.encrypted(p.credential)) {
      p.hint = p.credential.slice(-4);
      p.credential = secret.seal(p.credential, 'expand.credential.' + p.id);
      credMigrated = true;
    }
  }
  if (credMigrated) saveExpand();

  function sideWithBytes(b) {
    const o = { ...normAgg(b) };
    o.bytes = (o.bytesIn || 0) + (o.bytesOut || 0);
    return o;
  }
  function sideView(s) {
    return {
      total: sideWithBytes(s.total),
      today: sideWithBytes(s.days[dayKey()] || emptyAgg()),
      month: sideWithBytes(s.months[monthKey()] || emptyAgg()),
      lastAt: s.lastAt,
      lastResult: s.lastResult,
    };
  }
  function recordExpand(side, key, delta, result, credId = '') {
    const at = now();
    const date = new Date(at);
    const dk = dayKey(date), mk = monthKey(date);
    const root = side === 'inbound' ? expand.stats.inbound : expand.stats.outbound;
    const map = side === 'inbound' ? expand.stats.perSource : expand.stats.perOutbound;
    const k = String(key || 'unknown').slice(0, 80);
    const item = map[k] || (map[k] = emptySide());
    const maps = [root, item];
    if (side === 'inbound' && credId) maps.push(expand.stats.perInbound[credId] || (expand.stats.perInbound[credId] = emptySide()));
    for (const s of maps) {
      aggAdd(s.total, delta);
      aggAdd(s.days[dk] || (s.days[dk] = emptyAgg()), delta);
      aggAdd(s.months[mk] || (s.months[mk] = emptyAgg()), delta);
      s.lastAt = at;
      s.lastResult = String(result || '').slice(0, 120);
    }
    markExpandDirty();
  }
  function tlsPublicView() {
    return tlsInfo ? {
      mode: cfg.tls.mode, secure: true, fingerprint: tlsInfo.fingerprint,
      certPath: tlsInfo.certPath, keyEncrypted: cfg.tls.mode === 'self-signed',
      allowPlaintext: !!cfg.tls.allowPlaintext,
      notAfter: tlsInfo.notAfter,
    } : {
      mode: 'off', secure: false, fingerprint: '', certPath: '', keyEncrypted: false,
      allowPlaintext: true, notAfter: '',
    };
  }
  function expandView() {
    const perOutbound = {};
    for (const p of expand.outbound) perOutbound[p.id] = sideView(expand.stats.perOutbound[p.id] || emptySide());
    const perSource = {};
    for (const [k, s] of Object.entries(expand.stats.perSource)) perSource[k] = sideView(s);
    const inboundStats = sideView(expand.stats.inbound);
    const creds = expand.inbound.map((c) => ({
      id: c.id, name: c.name, prefix: c.prefix, createdAt: c.createdAt, lastAt: c.lastAt,
      lastResult: c.lastResult, disabled: c.disabled,
      stats: sideView(expand.stats.perInbound[c.id] || emptySide()),
    }));
    return {
      ok: true,
      instanceId: expand.instanceId,
      identityPub: expand.identity.pub,
      port: boundPort || opt.port,
      tls: tlsPublicView(),
      inbound: {
        configured: creds.some((c) => !c.disabled),
        count: creds.length,
        prefix: creds[0] ? creds[0].prefix : '',
        createdAt: creds[0] ? creds[0].createdAt : 0,
        lastAt: inboundStats.lastAt,
        credentials: creds,
        stats: inboundStats,
        sources: perSource,
      },
      outbound: expand.outbound.map((p) => {
        const t = peerTls(p);
        return {
          id: p.id, name: p.name, host: p.host, port: p.port, enabled: p.enabled,
          tls: { mode: t.mode, fingerprint: t.fingerprint, servername: t.servername, caFile: t.caFile },
          trusted: t.mode !== 'pin' || t.fingerprint.length === 64,
          createdAt: p.createdAt, lastTest: p.lastTest, lastTestOk: p.lastTestOk,
          credentialMasked: p.credential ? ('••••' + String(p.hint || '')) : '',
          stats: perOutbound[p.id] || sideView(emptySide()),
        };
      }),
      stats: { inbound: inboundStats, outbound: sideView(expand.stats.outbound), perOutbound, perSource },
    };
  }
  function generateInboundToken(name = '') {
    const token = 'fwnexp_' + crypto.randomBytes(24).toString('base64url');
    const item = {
      id: crypto.randomUUID(), name: String(name || '').trim().slice(0, 40) || ('接入凭据 ' + (expand.inbound.length + 1)),
      hash: sha(token), prefix: token.slice(0, 13) + '…',
      createdAt: now(), lastAt: 0, lastResult: '', disabled: false,
    };
    expand.inbound.push(item);
    saveExpand();
    // 明文只返回这一次；expand.json 只有 sha256。
    return { token, item };
  }
  function expandCred(req) {
    const t = String(req.headers.authorization || '').replace(/^Bearer\s+/i, '');
    if (!t) return null;
    const h = Buffer.from(sha(t), 'hex');
    let hit = null;
    for (const c of expand.inbound) {
      if (c.disabled || !c.hash) continue;
      const want = Buffer.from(c.hash, 'hex');
      if (want.length === h.length && crypto.timingSafeEqual(want, h)) hit = c;
    }
    return hit;
  }

  /* ── 重放窗口 / 黑名单 / 来源公钥固定（security.json，同步落盘）── */
  function emptySecurity() {
    return { v: 1, replay: {}, blacklist: {}, origins: {}, violations: { originMismatch: 0, signatureBad: 0, loop: 0, routeTooLong: 0, replayRejected: 0 }, lastInbound: { at: 0, from: '' } };
  }
  function normSecurity(raw) {
    const o = emptySecurity();
    if (!raw || typeof raw !== 'object') return o;
    for (const [k, v] of Object.entries(raw.replay || {})) {
      if (!v || typeof v !== 'object') continue;
      const first = Number(v.first) || 0, last = Number(v.last) || 0;
      if (!first) continue;
      o.replay[k] = { first, last: last || first, count: Math.max(0, Number(v.count) || 0), origin: String(v.origin || '').slice(0, 64) };
    }
    for (const [k, v] of Object.entries(raw.blacklist || {})) {
      if (!v || typeof v !== 'object') continue;
      const firstAt = Number(v.firstAt) || 0, lastAt = Number(v.lastAt) || firstAt;
      if (!firstAt) continue;
      o.blacklist[k] = { reason: String(v.reason || 'unknown').slice(0, 40), firstAt, lastAt, hits: Math.max(1, Number(v.hits) || 1), origin: String(v.origin || '').slice(0, 64) };
    }
    for (const [k, v] of Object.entries(raw.origins || {})) {
      if (!v || typeof v !== 'object' || !v.pub) continue;
      o.origins[String(k).slice(0, 64)] = { pub: String(v.pub).slice(0, 80), firstAt: Number(v.firstAt) || 0, lastAt: Number(v.lastAt) || 0 };
    }
    if (raw.violations && typeof raw.violations === 'object') {
      for (const k of Object.keys(o.violations)) o.violations[k] = Math.max(0, Number(raw.violations[k]) || 0);
    }
    if (raw.lastInbound && typeof raw.lastInbound === 'object') {
      o.lastInbound = { at: Number(raw.lastInbound.at) || 0, from: String(raw.lastInbound.from || '').slice(0, 80) };
    }
    return o;
  }
  let security = emptySecurity();
  try {
    security = normSecurity(JSON.parse(fs.readFileSync(SECURITY_FILE, 'utf8')));
  } catch (e) {
    if (e && e.code !== 'ENOENT') {
      try { fs.renameSync(SECURITY_FILE, `${SECURITY_FILE}.corrupt-${Date.now()}`); } catch { /* noop */ }
      log('WARN', 'security.json 损坏，按空表启动（原文件已改名保留）');
    }
  }
  let securityTimer = null;
  function saveSecurity() {
    if (securityTimer) { clearTimeout(securityTimer); securityTimer = null; }
    try { writeJsonAtomic(SECURITY_FILE, security); } catch (e) { log('WARN', '写 security.json 失败：' + (e && e.message || e)); }
  }
  /** 普通计数攒 250ms 写一次（每秒最多 4 次请求也不至于每包重写全表）；黑名单/固定公钥立即写。 */
  function markSecurityDirty() {
    if (securityTimer) return;
    securityTimer = setTimeout(() => { securityTimer = null; saveSecurity(); }, 2000);
    if (securityTimer.unref) securityTimer.unref();
  }
  function pruneMapSize(map, max) {
    const keys = Object.keys(map);
    if (keys.length <= max) return 0;
    keys.sort((a, b) => (Number(map[a].lastAt || map[a].last || 0)) - (Number(map[b].lastAt || map[b].last || 0)));
    let n = 0;
    for (const k of keys.slice(0, keys.length - max)) { delete map[k]; n++; }
    return n;
  }
  /** 24h 窗口条目保留 30 天（否则重启后无法识别“25 小时前的重复”）；黑名单 30 天未再出现即删。 */
  function pruneSecurity(at = now()) {
    let r = 0, b = 0;
    for (const [k, v] of Object.entries(security.replay)) {
      if (at - (v.last || v.first) > BLACKLIST_TTL_MS) { delete security.replay[k]; r++; }
    }
    for (const [k, v] of Object.entries(security.blacklist)) {
      if (at - (v.lastAt || v.firstAt) > BLACKLIST_TTL_MS) { delete security.blacklist[k]; b++; }
    }
    const ev1 = pruneMapSize(security.replay, MAX_REPLAY_ENTRIES);
    const ev2 = pruneMapSize(security.blacklist, MAX_BLACKLIST_ENTRIES);
    return { replayRemoved: r + ev1, blacklistRemoved: b + ev2, replaySize: Object.keys(security.replay).length, blacklistSize: Object.keys(security.blacklist).length };
  }
  pruneSecurity(now());
  saveSecurity();
  function blacklistMessage(key, reason, at, origin) {
    const cur = security.blacklist[key];
    if (cur) { cur.hits++; cur.lastAt = at; cur.reason = reason; }
    else security.blacklist[key] = { reason, firstAt: at, lastAt: at, hits: 1, origin: String(origin || '').slice(0, 64) };
    saveSecurity();
    log('WARN', `安全：消息 ${key.slice(0, 12)}… 已加入黑名单（${reason}）`);
  }
  /**
   * 重放闸：同一 messageId 在本实例 24h 内最多放行 2 次。
   * 第 3 次 / 首次出现已超过 24h ⇒ 丢弃 + 写黑名单（重启后仍生效）。
   * 返回 {ok, reason, count}；黑名单每次再出现会刷新 lastAt（30 天计时从最后一次出现算）。
   */
  function noteMessage(msgId, origin = '') {
    const key = msgKey(msgId);
    const at = now();
    const b = security.blacklist[key];
    if (b) {
      b.hits++; b.lastAt = at;
      security.violations.replayRejected++;
      markSecurityDirty();
      return { ok: false, reason: 'blacklisted', detail: b.reason, count: 0 };
    }
    let e = security.replay[key];
    if (!e) { e = { first: at, last: at, count: 0, origin: String(origin || '').slice(0, 64) }; security.replay[key] = e; }
    if (at - e.first > MESSAGE_WINDOW_MS) {
      security.violations.replayRejected++;
      blacklistMessage(key, 'older-than-24h', at, origin);
      return { ok: false, reason: 'older-than-24h', count: e.count };
    }
    if (e.count >= MAX_FORWARDS) {
      security.violations.replayRejected++;
      blacklistMessage(key, 'forward-limit', at, origin);
      return { ok: false, reason: 'forward-limit', count: e.count };
    }
    e.count++;
    e.last = at;
    if (origin) e.origin = String(origin).slice(0, 64);
    // 到上限必须立即落盘，避免重启把“已用满 2 次”忘掉；普通第一次攒批写。
    if (e.count >= MAX_FORWARDS) saveSecurity(); else markSecurityDirty();
    return { ok: true, count: e.count };
  }
  function pinOrigin(origin, pub) {
    const cur = security.origins[origin];
    if (cur) {
      if (cur.pub !== pub) {
        security.violations.originMismatch++;
        saveSecurity();
        return { ok: false, reason: 'origin-key-mismatch' };
      }
      cur.lastAt = now();
      return { ok: true };
    }
    security.origins[origin] = { pub, firstAt: now(), lastAt: now() };
    saveSecurity();
    return { ok: true };
  }
  function verifyOrigin({ msgId, origin, originPub, originSig, to, createdAt, envelope }) {
    if (!origin || !originPub || !originSig) return { ok: false, reason: 'origin-signature-required' };
    if (!/^[A-Za-z0-9_-]{6,64}$/.test(origin)) return { ok: false, reason: 'bad-origin' };
    if (origin === expand.instanceId) return { ok: false, reason: 'loop' };
    let pub;
    try { pub = edPub(originPub); } catch { return { ok: false, reason: 'bad-origin-key' }; }
    const pin = pinOrigin(origin, originPub);
    if (!pin.ok) return pin;
    const msg = messageCanonical({ msgId, origin, to, createdAt, envelope });
    let ok = false;
    try { ok = crypto.verify(null, Buffer.from(msg, 'utf8'), pub, Buffer.from(String(originSig), 'base64')); } catch { ok = false; }
    if (!ok) { security.violations.signatureBad++; saveSecurity(); return { ok: false, reason: 'bad-origin-signature' }; }
    return { ok: true };
  }
  function signAsSelf(msgId, to, createdAt, envelope) {
    if (!identityKey) return null;
    const msg = messageCanonical({ msgId, origin: expand.instanceId, to, createdAt, envelope });
    return {
      origin: expand.instanceId, originPub: expand.identity.pub,
      originSig: crypto.sign(null, Buffer.from(msg, 'utf8'), identityKey).toString('base64'),
    };
  }
  function securityView() {
    const bl = Object.entries(security.blacklist)
      .sort((a, b) => (b[1].lastAt || 0) - (a[1].lastAt || 0)).slice(0, 20)
      .map(([k, v]) => ({ key: k.slice(0, 12), reason: v.reason, firstAt: v.firstAt, lastAt: v.lastAt, hits: v.hits, origin: v.origin }));
    const origins = Object.entries(security.origins).map(([id, v]) => ({ instanceId: id, pub: v.pub, firstAt: v.firstAt, lastAt: v.lastAt }));
    return {
      ok: true,
      policy: {
        windowMs: MESSAGE_WINDOW_MS, maxForwards: MAX_FORWARDS, blacklistTtlMs: BLACKLIST_TTL_MS,
        maxRoute: MAX_ROUTE, maxEnvelope: cfg.maxEnvelope, upstreamTimeoutMs: UPSTREAM_TIMEOUT_MS,
        maxReplay: MAX_REPLAY_ENTRIES, maxBlacklist: MAX_BLACKLIST_ENTRIES,
      },
      replay: { count: Object.keys(security.replay).length },
      blacklist: { count: Object.keys(security.blacklist).length, recent: bl },
      origins: { count: origins.length, items: origins },
      violations: security.violations,
      lastInbound: security.lastInbound,
    };
  }

  /* ── 公网可达性：只报证据，不把“发过包/有映射”说成“已打通”────── */
  let lastNatpmp = null;
  let lastStun = null;
  function mappingValid() {
    const m = expand.natpmp;
    if (!m || !m.externalPort) return false;
    return now() < m.mappedAt + Math.max(0, m.lifetimeSec * 1000) - 60_000;
  }
  function reachView() {
    const local = localAddresses();
    const inbound = security.lastInbound;
    const fromRemote = !!inbound.from && !/^(::1|::ffff:127\.0\.0\.1|127\.)/.test(inbound.from);
    const m = expand.natpmp;
    const mv = mappingValid();
    const advertised = [];
    if (lastStun && lastStun.ok && lastStun.publicAddress) advertised.push(`${scheme || 'https'}://${lastStun.publicAddress.host}:${boundPort || opt.port}`);
    if (mv) advertised.push(`${scheme || 'https'}://<公网IP>:${m.externalPort}`);
    for (const a of local.filter((x) => !x.internal && x.family === 'IPv4')) advertised.push(`${scheme || 'https'}://${a.address}:${boundPort || opt.port}`);
    let verdict = 'lan-only';
    if (fromRemote && now() - inbound.at < 7 * 86400000) verdict = 'confirmed-inbound';
    else if (mv) verdict = 'mapped';
    else if (lastStun && lastStun.ok) verdict = 'stun-visible';
    else if (!local.some((x) => !x.internal)) verdict = 'unknown';
    return {
      ok: true,
      listening: { host: opt.host, port: boundPort || opt.port, scheme: scheme || (tlsInfo ? 'https' : 'http'), tls: tlsPublicView() },
      local,
      natpmp: lastNatpmp,
      mapping: m ? { ...m, valid: mv, expiresAt: m.mappedAt + Math.max(0, m.lifetimeSec * 1000) } : null,
      stun: lastStun,
      evidence: inbound,
      advertised,
      verdict,
      // confirmed-inbound 只来自“确实有外部实例连进来过”；mapped/stun-visible 仍需对端实测。
      hints: verdict === 'confirmed-inbound'
        ? ['最近 7 天有非回环来源成功抵达本机（来自被扩网请求）']
        : verdict === 'mapped'
          ? ['已拿到 NAT-PMP 外部端口；公网 IP 仍需 STUN 或对端实测，不能仅凭映射宣称可达']
          : verdict === 'stun-visible'
            ? ['STUN 报告了公网映射地址；请用另一台 FWArmy 实测 /api/expand/ping']
            : ['目前只有本机/局域网地址；需要端口映射、公网 IPv6 或 VPN'],
    };
  }

  /* ── TLS（默认自签 + 指纹固定；用户证书；显式关闭）──────────────── */
  function loadOrCreateTls() {
    if (cfg.tls.mode === 'off') return null;
    let certPem = '', keyPem = '', certPath = '';
    if (cfg.tls.mode === 'user-cert') {
      if (!cfg.tls.certFile || !cfg.tls.keyFile) throw new Error('user-cert 需要同时配置 certFile 与 keyFile');
      certPath = path.resolve(cfg.tls.certFile);
      certPem = fs.readFileSync(certPath, 'utf8');
      keyPem = fs.readFileSync(path.resolve(cfg.tls.keyFile), 'utf8');
    } else {
      fs.mkdirSync(TLS_DIR, { recursive: true });
      certPath = path.join(TLS_DIR, 'cert.pem');
      const keyPath = path.join(TLS_DIR, 'key.pem');
      let reuse = false;
      try {
        const c = new crypto.X509Certificate(fs.readFileSync(certPath, 'utf8'));
        const raw = fs.readFileSync(keyPath, 'utf8');
        const k = raw.startsWith('enc:v1:') ? secret.open(raw, 'tls.key') : raw;
        if (new Date(c.validTo).getTime() > Date.now() + 7 * 86400000 && k.includes('PRIVATE KEY')) {
          tls.createSecureContext({ cert: c.toString(), key: k }); // 证书与私钥必须匹配
          certPem = c.toString(); keyPem = k; reuse = true;
          if (!raw.startsWith('enc:v1:')) fs.writeFileSync(keyPath, secret.seal(k, 'tls.key'), { mode: 0o600 });
        }
      } catch { /* 重新生成 */ }
      if (!reuse) {
        const local = localAddresses().filter((x) => !x.internal).map((x) => x.address);
        const gen = generateSelfSignedCert({
          commonName: `FWArmy-${expand.instanceId.slice(0, 8)}`,
          hostnames: cfg.tls.hostnames,
          ips: local,
        });
        certPem = gen.certPem; keyPem = gen.keyPem;
        fs.writeFileSync(certPath, certPem, { mode: 0o600 });
        // 服务端私钥也加密落盘（secret.key 或 FWARMY_MASTER_KEY）；启动时解密。
        fs.writeFileSync(keyPath, secret.seal(keyPem, 'tls.key'), { mode: 0o600 });
        log('INFO', `TLS：已生成自签证书 ${certPath}（指纹 ${gen.fingerprint.slice(0, 16)}…）`);
      }
    }
    // 明确校验证书与私钥匹配；不匹配就拒绝启动，而不是悄悄降级为 HTTP。
    tls.createSecureContext({ cert: certPem, key: keyPem });
    const x = new crypto.X509Certificate(certPem);
    return {
      certPem, keyPem, certPath,
      fingerprint: crypto.createHash('sha256').update(x.raw).digest('hex'),
      notAfter: x.validTo,
    };
  }
  try {
    tlsInfo = loadOrCreateTls();
  } catch (e) {
    log('ERROR', 'TLS 初始化失败（拒绝以明文降级）：' + String(e && e.message || e).slice(0, 300));
    throw e;
  }
  if (tlsInfo) log('INFO', `TLS：${cfg.tls.mode} 已启用，证书指纹 sha256:${tlsInfo.fingerprint}`);
  else log('WARN', 'TLS：已按配置关闭（仅回环/VPN 场景可接受）');

  function credStat(c) {
    let s = stats.credentials[c.id];
    if (!s) { s = normCredStats({ name: c.name, createdAt: c.createdAt }, c.id); stats.credentials[c.id] = s; }
    if (c.name && s.name !== c.name) s.name = c.name;
    return s;
  }

  // ── 最近 60 秒速度（内存窗口，不落盘）──
  const inboundRecent = new Map(); // 被扩网凭据 id → Map(sec → {r,b})
  function inboundRateCheck(id, bytes, at = Date.now()) {
    const sec = Math.floor(at / 1000);
    let m = inboundRecent.get(id);
    if (!m) { m = new Map(); inboundRecent.set(id, m); }
    let r = 0, b = 0;
    for (const [s, v] of m) {
      if (s <= sec - 60) m.delete(s); else { r += v.r; b += v.b; }
    }
    if (r + 1 > INBOUND_RATE_PER_MIN || b + bytes > INBOUND_BYTES_PER_MIN) return false;
    const cur = m.get(sec) || { r: 0, b: 0 };
    cur.r++; cur.b += bytes;
    m.set(sec, cur);
    return true;
  }
  const recent = new Map(); // cid → Map(sec → {r,b})
  function speedAdd(cid, requests, bytes, now) {
    const sec = Math.floor(now / 1000);
    let m = recent.get(cid);
    if (!m) { m = new Map(); recent.set(cid, m); }
    const b = m.get(sec) || { r: 0, b: 0 };
    b.r += requests; b.b += bytes;
    m.set(sec, b);
  }
  function speedFor(cid, at = Date.now()) {
    const now = Math.floor(at / 1000);
    let r = 0, b = 0;
    const m = recent.get(cid);
    if (m) for (const [sec, v] of m) if (sec > now - 60) { r += v.r; b += v.b; }
    return { reqPerMin: r, bytesPerMin: b };
  }
  function totalSpeed() {
    const now = Math.floor(Date.now() / 1000);
    let r = 0, b = 0;
    for (const m of recent.values()) for (const [sec, v] of m) if (sec > now - 60) { r += v.r; b += v.b; }
    return { reqPerMin: r, bytesPerMin: b };
  }
  const pruneTimer = setInterval(() => {
    const cutoff = Math.floor(Date.now() / 1000) - 90;
    for (const [cid, m] of recent) {
      for (const sec of m.keys()) if (sec < cutoff) m.delete(sec);
      if (!m.size) recent.delete(cid);
    }
    for (const [cid, m] of inboundRecent) {
      for (const sec of m.keys()) if (sec < cutoff) m.delete(sec);
      if (!m.size) inboundRecent.delete(cid);
    }
  }, 15_000);
  pruneTimer.unref();

  function record(c, p = {}) {
    const now = Date.now(), date = new Date(now);
    const s = credStat(c);
    const dk = dayKey(date), mk = monthKey(date), yk = yearKey(date);
    const req = p.requests === undefined ? 1 : Number(p.requests) || 0;
    const add = {
      requests: req,
      bytesIn: Number(p.bytesIn) || 0,
      bytesOut: Number(p.bytesOut) || 0,
      relayed: Number(p.relayed) || 0,
      delivered: Number(p.delivered) || 0,
      rejected: Number(p.rejected) || 0,
      offline: Number(p.offline) || 0,
    };
    const maps = [[s.total], [s.days[dk] || (s.days[dk] = emptyAgg())], [s.months[mk] || (s.months[mk] = emptyAgg())], [s.years[yk] || (s.years[yk] = emptyAgg())]];
    for (const [b] of maps) for (const k of Object.keys(add)) b[k] += add[k];
    const mkey = minuteKey(date);
    if (s.lastMinute.key !== mkey) s.lastMinute = { key: mkey, n: 0 };
    s.lastMinute.n += req;
    if (s.lastMinute.n > s.peakPerMin) { s.peakPerMin = s.lastMinute.n; s.peakAt = now; }
    if (stats.minute.key !== mkey) stats.minute = { key: mkey, n: 0 };
    stats.minute.n += req;
    if (stats.minute.n > stats.peakPerMin) { stats.peakPerMin = stats.minute.n; stats.peakAt = now; }
    s.lastUsed = now;
    c.lastUsed = now;
    speedAdd(c.id, req, add.bytesIn + add.bytesOut, now);
    markStatsDirty();
  }

  function eff(c) {
    const out = {};
    for (const k of LIMIT_KEYS) {
      const v = c.limits ? c.limits[k] : null;
      out[k] = v === null || v === undefined ? cfg[k] : Number(v);
    }
    return out;
  }
  function usageOf(c) {
    const s = credStat(c);
    const tot = (b) => (b ? (b.bytesIn || 0) + (b.bytesOut || 0) : 0);
    return {
      day: tot(s.days[dayKey()]),
      month: tot(s.months[monthKey()]),
      year: tot(s.years[yearKey()]),
      total: tot(s.total),
    };
  }
  /** 只核预算，不预扣：所有窗口与 stats 共用 record，失败次数也计入，字节只计实际入队/取走。
   * 分钟采用与速度统计一致的最近 60 秒（按秒聚合、有界内存），无需 Redis。
   * 核验到队列变更及 record 之间没有 await；并发请求不能穿透剩余额度。
   */
  function gate(c, costBytes = 0, now = Date.now()) {
    const lim = eff(c), s = credStat(c), date = new Date(now);
    const reject = (error, scope, limit, used) => ({ ok: false, code: 429, error, scope, limit, used });
    for (const [scope, bucket] of [['daily', s.days[dayKey(date)]], ['monthly', s.months[monthKey(date)]], ['total', s.total], ['yearly', s.years[yearKey(date)]]]) {
      const requests = bucket?.requests || 0, bytes = (bucket?.bytesIn || 0) + (bucket?.bytesOut || 0);
      const rq = lim[scope + 'Requests'], bq = lim[scope + 'Bytes'];
      if (rq > 0 && requests + 1 > rq) return reject(scope + '-requests-quota', scope, rq, requests);
      if (costBytes > 0 && bq > 0 && bytes + costBytes > bq) return reject(scope + '-quota', scope, bq, bytes);
    }
    const speed = speedFor(c.id, now);
    if (speed.reqPerMin + 1 > lim.ratePerMin) return reject('rate-limit', 'rate', lim.ratePerMin, speed.reqPerMin);
    if (costBytes > 0 && speed.bytesPerMin + costBytes > lim.bytesPerMin) return reject('bytes-rate-limit', 'rate', lim.bytesPerMin, speed.bytesPerMin);
    return { ok: true };
  }

  // 仅兼容旧版遗留的待保存凭据；首次空表启动不创建任何凭据/明文文件。
  function firstRunPending() { return fs.existsSync(FIRST_CRED_ENC) || fs.existsSync(FIRST_CRED); }

  // ── 在线状态（内存）──
  const ren = new Map(); // did → { boxPub, lastSeen, queue: [{id, env, exp}] }
  const zaiXianTtl = () => Math.max(100, Number(cfg.presenceTtlMs) || 60_000);
  const shiJianOk = (ts) => { const n = Number(ts || 0); return !!n && Math.abs(Date.now() - n) <= 5 * 60_000; };
  const yanQianMing = (did, msg, sig) => {
    try { return crypto.verify(null, Buffer.from(msg, 'utf8'), edPub(did), Buffer.from(String(sig || ''), 'base64')); } catch { return false; }
  };
  const queueClean = setInterval(() => {
    const now = Date.now();
    for (const [did, v] of ren) {
      const q = v.queue.filter((x) => x.exp > now);
      if (q.length !== v.queue.length) v.queue = q;
      if (!q.length && now - v.lastSeen > 10 * 60_000) ren.delete(did);
    }
  }, 15_000);
  queueClean.unref();
  // 30 天黑名单清理也按注入时钟走；每小时一次，重启时还会再清一次。
  const securityGc = setInterval(() => { pruneSecurity(now()); saveSecurity(); }, 3600_000);
  securityGc.unref();

  function enqueueLocal(to, env, now = Date.now()) {
    const y = ren.get(to);
    if (!y || now - y.lastSeen >= zaiXianTtl()) return { ok: false, code: 'offline', body: { ok: false, offline: true }, offline: 1 };
    const queue = y.queue.filter((x) => x.exp > now);
    if (queue.length >= cfg.queuePerUser) return { ok: false, code: 'queue-full', body: { ok: false, error: 'queue-full' }, rejected: 1 };
    const id = crypto.randomUUID();
    queue.push({ id, env, exp: now + TTL_MS });
    y.queue = queue;
    y.lastSeen = now;
    return { ok: true, id, body: { ok: true, queued: true }, bytesIn: Buffer.byteLength(env, 'utf8'), relayed: 1 };
  }

  function peerCredential(p) {
    return p && p.credential ? secret.open(p.credential, 'expand.credential.' + p.id) : '';
  }
  function setPeerCredential(p, plain) {
    const v = String(plain || '').trim();
    p.credential = v ? secret.seal(v, 'expand.credential.' + p.id) : '';
    p.hint = v ? v.slice(-4) : '';
  }
  function tlsFromInput(raw, cur) {
    const base = normTlsPeer(cur);
    if (raw === undefined) return { ok: true, tls: base };
    if (typeof raw === 'string') {
      if (!['pin', 'verify', 'off'].includes(raw)) return { ok: false, error: 'bad-tls-mode' };
      base.mode = raw;
    } else if (raw && typeof raw === 'object') {
      if (raw.mode !== undefined) {
        if (!['pin', 'verify', 'off'].includes(raw.mode)) return { ok: false, error: 'bad-tls-mode' };
        base.mode = raw.mode;
      }
      if (raw.fingerprint !== undefined) {
        const fp = String(raw.fingerprint || '').toLowerCase().replace(/[^0-9a-f]/g, '');
        if (fp && fp.length !== 64) return { ok: false, error: 'bad-fingerprint' };
        base.fingerprint = fp;
      }
      if (raw.servername !== undefined) base.servername = String(raw.servername || '').slice(0, 253);
      if (raw.caFile !== undefined) base.caFile = String(raw.caFile || '').slice(0, 500);
    } else return { ok: false, error: 'bad-tls' };
    if (base.mode === 'pin' && base.fingerprint && base.fingerprint.length !== 64) return { ok: false, error: 'bad-fingerprint' };
    return { ok: true, tls: base };
  }
  async function peerCall(p, pth, { method = 'GET', payload, timeoutMs = UPSTREAM_TIMEOUT_MS, auth = true, tlsOverride = null, credential } = {}) {
    const t = tlsOverride || peerTls(p);
    const headers = {};
    const cred = credential !== undefined ? credential : peerCredential(p);
    if (auth) {
      if (!cred) throw new Error('credential-unreadable');
      headers.authorization = 'Bearer ' + cred;
    }
    return await rawHttpRequest({
      host: p.host, port: p.port, path: pth, method, tls: t, headers,
      body: payload === undefined ? '' : JSON.stringify(payload), timeoutMs,
    });
  }

  /**
   * 扩网：把本机无法投递的信封按顺序转给上游 FWArmy。
   * 8 秒是**整次投递**的预算（不是每个上游 8 秒）；超时只记失败，不落盘、不排队重试。
   * 同一 messageId 最多试 3 个上游，避免一个请求放大成 N 次外呼。
   */
  async function forwardToPeers(to, env, msgId, meta, route) {
    const attempts = [];
    const bytes = Buffer.byteLength(env, 'utf8');
    const deadline = Date.now() + UPSTREAM_TIMEOUT_MS;
    let tried = 0;
    for (const p of expand.outbound.filter((x) => x.enabled)) {
      if (tried >= MAX_FORWARD_PEERS) break;
      const t = peerTls(p);
      if (t.mode === 'pin' && t.fingerprint.length !== 64) {
        attempts.push({ id: p.id, name: p.name, ok: false, ms: 0, error: 'needs-trust' });
        recordExpand('outbound', p.id, { requests: 1, rejected: 1 }, 'needs-trust');
        continue;
      }
      const remain = deadline - Date.now();
      if (remain <= 50) { attempts.push({ id: p.id, name: p.name, ok: false, ms: 0, error: 'timeout' }); break; }
      tried++;
      const body = {
        msgId, to, envelope: env,
        origin: meta.origin, originPub: meta.originPub, originSig: meta.originSig, createdAt: meta.createdAt,
        route: [...route, expand.instanceId], source: expand.instanceId,
      };
      const t0 = Date.now();
      let resultText = '';
      try {
        const r = await peerCall(p, '/api/expand/relay', { method: 'POST', payload: body, timeoutMs: Math.min(remain, UPSTREAM_TIMEOUT_MS) });
        const j = r.json || {};
        const ok = r.status === 200 && j.ok === true;
        resultText = ok ? 'queued' : (j.error || ('http:' + r.status));
        recordExpand('outbound', p.id, {
          requests: 1, bytesIn: bytes, relayed: 1,
          delivered: ok ? 1 : 0, rejected: ok ? 0 : 1,
        }, resultText);
        attempts.push({ id: p.id, name: p.name, ok, status: r.status, ms: Date.now() - t0, result: { ok: !!j.ok, error: j.error || '', forwarded: !!j.forwarded } });
        if (ok) return { ok: true, via: p, result: j, attempts };
        // 环路/黑名单/TLS 要求是“这条消息/这个地址不可再用”，不再换下一个上游。
        if (r.status === 409 || r.status === 426) return { ok: false, attempts };
      } catch (e) {
        const msg = String((e && e.message) || e);
        resultText = msg === 'timeout' ? 'upstream-timeout' : (msg === 'fingerprint-mismatch' ? 'tls-fingerprint-mismatch' : 'net-error');
        recordExpand('outbound', p.id, { requests: 1, bytesIn: bytes, relayed: 1, rejected: 1 }, resultText);
        attempts.push({ id: p.id, name: p.name, ok: false, ms: Date.now() - t0, error: resultText });
      }
    }
    return { ok: false, attempts };
  }

  function relayRoute(j) {
    const route = Array.isArray(j.route) ? j.route.map((x) => String(x)) : [];
    if (route.length > MAX_ROUTE || route.some((x) => x.length > 64 || !/^[A-Za-z0-9_-]+$/.test(x))) {
      return { ok: false, error: 'route-too-long' };
    }
    if (route.includes(expand.instanceId)) return { ok: false, error: 'loop' };
    return { ok: true, route };
  }

  /** 被扩网：别的 FWArmy 用我们生成的凭据把信封交过来；本机尝试投递并如实返回结果。 */
  async function handleExpandRelay(req, res) {
    const cred = expandCred(req);
    if (!cred) return send(res, 401, { ok: false, error: 'expand-credential-required' });
    // 只有通过凭据认证的入站才算“外部可达”的证据。
    security.lastInbound = { at: now(), from: String(req.socket.remoteAddress || '').slice(0, 80) };
    markSecurityDirty();
    let j;
    try { j = await body(req, cfg.maxEnvelope + 8192); }
    catch { return send(res, 400, { ok: false, error: 'bad-json' }); }
    const to = String(j.to || '').slice(0, 200);
    const env = String(j.envelope || '');
    const bytes = Buffer.byteLength(env, 'utf8');
    const source = String(j.source || req.socket.remoteAddress || 'unknown').slice(0, 80);
    const msgId = String(j.msgId || '');
    const createdAt = Number(j.createdAt);
    const routeJ = relayRoute(j);
    const fail = (status, error, extra = {}) => {
      recordExpand('inbound', source, { requests: 1, bytesIn: bytes, rejected: 1 }, error, cred.id);
      cred.lastAt = now(); cred.lastResult = error; markExpandDirty();
      return send(res, status, { ok: false, error, instanceId: expand.instanceId, ...extra });
    };
    if (!isMessageId(msgId)) return fail(400, 'bad-msg-id');
    if (!to || !bytes || bytes > cfg.maxEnvelope) return fail(400, 'bad-envelope');
    if (!Number.isFinite(createdAt) || Math.abs(now() - createdAt) > MESSAGE_WINDOW_MS) return fail(400, 'bad-created-at');
    if (!routeJ.ok) {
      if (routeJ.error === 'loop') security.violations.loop++; else security.violations.routeTooLong++;
      saveSecurity();
      return fail(409, routeJ.error);
    }
    if (!inboundRateCheck(cred.id, bytes)) return fail(429, 'rate-limit');
    const vo = verifyOrigin({ msgId, origin: String(j.origin || ''), originPub: String(j.originPub || ''), originSig: String(j.originSig || ''), to, createdAt, envelope: env });
    if (!vo.ok) return fail(vo.reason === 'loop' ? 409 : 403, vo.reason);
    const note = noteMessage(msgId, String(j.origin || ''));
    if (!note.ok) return fail(409, note.reason === 'blacklisted' ? 'message-blacklisted' : 'duplicate-message', { reason: note.detail || note.reason, count: note.count });

    const local = enqueueLocal(to, env);
    if (local.ok) {
      recordExpand('inbound', source, { requests: 1, bytesIn: bytes, relayed: 1, delivered: 1 }, 'queued', cred.id);
      cred.lastAt = now(); cred.lastResult = 'queued';
      return send(res, 200, { ok: true, queued: true, msgId, instanceId: expand.instanceId });
    }
    // 本机确实送不到：带着原来源签名继续转发（中间跳不能改任何签名覆盖字段）。
    const fwd = await forwardToPeers(to, env, msgId, {
      origin: String(j.origin), originPub: String(j.originPub), originSig: String(j.originSig), createdAt,
    }, routeJ.route);
    const ok = fwd.ok;
    recordExpand('inbound', source, {
      requests: 1, bytesIn: bytes, relayed: 1,
      delivered: ok ? 1 : 0,
      rejected: ok ? 0 : (local.code === 'queue-full' ? 1 : 0),
      offline: ok ? 0 : (local.offline ? 1 : 0),
    }, ok ? 'forwarded' : local.code, cred.id);
    cred.lastAt = now(); cred.lastResult = ok ? 'forwarded' : local.code;
    if (ok) return send(res, 200, { ok: true, queued: true, forwarded: true, via: fwd.via.name, msgId, instanceId: expand.instanceId });
    return send(res, local.code === 'queue-full' ? 429 : 200, {
      ok: false, error: local.code, offline: !!local.offline, forwarded: false, attempts: fwd.attempts,
      msgId, instanceId: expand.instanceId,
    });
  }
  function handleExpandPing(req, res) {
    const c = expandCred(req);
    if (!c) return send(res, 401, { ok: false, error: 'expand-credential-required' });
    return send(res, 200, {
      ok: true, instanceId: expand.instanceId, product: PRODUCT, version: VERSION,
      port: boundPort || opt.port, tls: tlsPublicView(), msgPolicy: { maxForwards: MAX_FORWARDS, windowMs: MESSAGE_WINDOW_MS },
    });
  }
  /** 不鉴权的指纹引导端点：只给实例 ID/版本/证书指纹，不含任何凭据或消息。 */
  function handleExpandIdentify(req, res) {
    return send(res, 200, {
      ok: true, instanceId: expand.instanceId, product: PRODUCT, version: VERSION,
      port: boundPort || opt.port, tls: tlsPublicView(), identityPub: expand.identity.pub,
      msgPolicy: { maxForwards: MAX_FORWARDS, windowMs: MESSAGE_WINDOW_MS, maxRoute: MAX_ROUTE },
    });
  }

  // ── 本机管理面边界：回环直连 + Host 回环名 + 同源/无 Origin + JSON ──
  const isLoopback = (req) => {
    const a = String(req.socket.remoteAddress || '');
    return a.startsWith('127.') || a === '::1' || a === '::ffff:127.0.0.1';
  };
  const isLocalHostHeader = (req) => {
    const h = String(req.headers.host || '').toLowerCase().replace(/:\d+$/, '');
    return h === '127.0.0.1' || h === 'localhost' || h === '[::1]' || h === '::1';
  };
  const isSameOriginOrNoOrigin = (req) => {
    const o = String(req.headers.origin || '');
    if (!o) return true;
    try { return new URL(o).host.toLowerCase() === String(req.headers.host || '').toLowerCase(); } catch { return false; }
  };
  const isAdminRequest = (req) => {
    if (!isLoopback(req) || !isLocalHostHeader(req) || !isSameOriginOrNoOrigin(req)) return false;
    if (String(req.headers['sec-fetch-site'] || '') === 'cross-site') return false;
    if (req.method === 'POST' && !/^application\/json\b/i.test(String(req.headers['content-type'] || ''))) return false;
    return true;
  };

  function send(res, code, obj) {
    const b = Buffer.from(JSON.stringify(obj));
    res.writeHead(code, { 'content-type': 'application/json; charset=utf-8', 'content-length': b.length, 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' });
    res.end(b);
  }
  function sendHtml(res, code, html) {
    const b = Buffer.from(html, 'utf8');
    res.writeHead(code, {
      'content-type': 'text/html; charset=utf-8',
      'content-length': b.length,
      'cache-control': 'no-store',
      'content-security-policy': "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
      'x-frame-options': 'DENY',
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'no-referrer',
    });
    res.end(b);
  }
  async function body(req, max = 1024 * 1024) {
    const bu = []; let n = 0;
    for await (const c of req) { n += c.length; if (n > max) throw new Error('too-large'); bu.push(c); }
    let j;
    try { j = JSON.parse(Buffer.concat(bu).toString('utf8') || '{}'); } catch { throw new Error('bad-json'); }
    if (!j || typeof j !== 'object' || Array.isArray(j)) throw new Error('bad-json-object');
    return j;
  }
  let ADMIN_HTML = '';
  function adminHtml() {
    if (ADMIN_HTML) return ADMIN_HTML;
    try {
      if (IS_SEA && SEA && typeof SEA.getAsset === 'function') ADMIN_HTML = SEA.getAsset('admin.html', 'utf8');
    } catch { ADMIN_HTML = ''; }
    if (!ADMIN_HTML) {
      try { ADMIN_HTML = fs.readFileSync(path.join(HERE, 'admin.html'), 'utf8'); } catch { /* fallback */ }
    }
    if (!ADMIN_HTML) ADMIN_HTML = '<!doctype html><meta charset="utf-8"><title>FWArmy</title><h1>FWArmy</h1><p>管理页文件 admin.html 缺失；请重新构建或使用完整目录。</p>';
    return ADMIN_HTML;
  }

  function sendLogo(res) {
    const svg = IS_SEA && SEA ? Buffer.from(SEA.getAsset('logo.svg')) : fs.readFileSync(path.join(HERE, 'assets', 'logo.svg'));
    res.writeHead(200, { 'content-type': 'image/svg+xml', 'content-length': svg.length,
      'cache-control': 'no-cache', 'x-content-type-options': 'nosniff',
      'content-security-policy': "default-src 'none'; sandbox" });
    res.end(svg);
  }

  function findCred(idOrHash) {
    const k = String(idOrHash || '');
    if (creds[k]) return creds[k];
    return Object.values(creds).find((c) => c.hash8 && c.hash8 === k) || null;
  }
  function cred(req) {
    const t = String(req.headers.authorization || '').replace(/^Bearer\s+/i, '');
    if (!t) return null;
    const c = hashIndex.get(sha(t));
    return c && !c.disabled ? c : null;
  }

  function aggTotal(list) {
    const o = emptyAgg();
    for (const b of list) if (b) for (const k of Object.keys(o)) o[k] += Number(b[k]) || 0;
    return o;
  }
  function viewCred(c) {
    const s = credStat(c);
    const total = s.total;
    const today = s.days[dayKey()] || emptyAgg();
    const month = s.months[monthKey()] || emptyAgg();
    const year = s.years[yearKey()] || emptyAgg();
    const withBytes = (b) => ({ ...b, bytes: (b.bytesIn || 0) + (b.bytesOut || 0) });
    return {
      id: c.id,
      name: c.name,
      hash8: c.hash8,
      createdAt: c.createdAt,
      disabled: !!c.disabled,
      limits: c.limits,
      effective: eff(c),
      total: withBytes(total),
      today: withBytes(today),
      month: withBytes(month),
      year: withBytes(year),
      usage: usageOf(c),
      speed: speedFor(c.id),
      peakPerMin: s.peakPerMin,
      peakAt: s.peakAt,
      lastUsed: c.lastUsed || s.lastUsed || 0,
    };
  }
  function buildStats() {
    const now = Date.now();
    const list = Object.values(creds).map(viewCred);
    const all = Object.values(stats.credentials);
    const total = aggTotal(all.map((s) => s.total));
    const today = aggTotal(all.map((s) => s.days[dayKey()]));
    const month = aggTotal(all.map((s) => s.months[monthKey()]));
    const year = aggTotal(all.map((s) => s.years[yearKey()]));
    const withBytes = (b) => ({ ...b, bytes: (b.bytesIn || 0) + (b.bytesOut || 0) });
    const peak = Math.max(stats.peakPerMin, ...all.map((s) => s.peakPerMin || 0));
    return {
      ok: true,
      server: 'fwarmy-relay',
      product: PRODUCT,
      version: VERSION,
      uptimeSec: Math.round((Date.now() - STARTED) / 1000),
      accepting: !!cfg.accepting,
      users: [...ren.values()].filter((v) => now - v.lastSeen < zaiXianTtl()).length,
      queued: [...ren.values()].reduce((n, v) => n + v.queue.filter((x) => x.exp > now).length, 0),
      config: cfg,
      totals: { ...withBytes(total), today: withBytes(today), month: withBytes(month), year: withBytes(year), speed: totalSpeed(), peakPerMin: peak, peakAt: stats.peakAt },
      perCredential: list,
      unauthorized: stats.unauthorized,
      firstRunPending: firstRunPending(),
      dataDir: DATA,
      tls: tlsPublicView(),
      security: {
        replay: Object.keys(security.replay).length,
        blacklist: Object.keys(security.blacklist).length,
        origins: Object.keys(security.origins).length,
        lastInbound: security.lastInbound,
      },
      update: updateSummary(),
    };
  }

  // ── 自动更新（只在单文件运行时可执行替换；源码运行只允许检查）──
  function emptyUpdate() {
    return { auto: 'check', intervalHours: 6, lastCheck: 0, latest: null, lastError: '', lastInstall: null, triedVersion: '' };
  }
  function normUpdate(raw) {
    const o = emptyUpdate();
    if (!raw || typeof raw !== 'object') return o;
    if (['off', 'check', 'install'].includes(raw.auto)) o.auto = raw.auto;
    const h = Number(raw.intervalHours);
    if (Number.isFinite(h) && h >= 1 && h <= 168) o.intervalHours = Math.round(h);
    o.lastCheck = Number(raw.lastCheck) || 0;
    o.lastError = String(raw.lastError || '').slice(0, 400);
    o.triedVersion = String(raw.triedVersion || '');
    if (raw.lastInstall && typeof raw.lastInstall === 'object') {
      o.lastInstall = {
        version: String(raw.lastInstall.version || ''), at: Number(raw.lastInstall.at) || 0,
        ok: !!raw.lastInstall.ok, error: String(raw.lastInstall.error || '').slice(0, 300),
      };
    }
    if (raw.latest && typeof raw.latest === 'object') {
      const a = raw.latest.asset && typeof raw.latest.asset === 'object' ? raw.latest.asset : null;
      o.latest = {
        version: String(raw.latest.version || ''), tag: String(raw.latest.tag || ''),
        name: String(raw.latest.name || '').slice(0, 160), publishedAt: String(raw.latest.publishedAt || ''),
        notes: String(raw.latest.notes || '').slice(0, 6000), url: String(raw.latest.url || ''),
        sumsUrl: String(raw.latest.sumsUrl || ''),
        asset: a ? {
          name: String(a.name || ''), size: Number(a.size) || 0, url: String(a.url || ''),
          sha256: String(a.sha256 || '').toLowerCase().replace(/^sha256:/, ''),
        } : null,
      };
    }
    return o;
  }
  let upd = emptyUpdate();
  try { upd = normUpdate(JSON.parse(fs.readFileSync(UPDATE_FILE, 'utf8'))); }
  catch (e) {
    if (e && e.code !== 'ENOENT') {
      try { fs.renameSync(UPDATE_FILE, `${UPDATE_FILE}.corrupt-${Date.now()}`); } catch { /* noop */ }
      log('WARN', 'update.json 损坏，按默认设置启动（原文件已改名保留）');
    }
  }
  let updateTimer = null;
  let updateRetryTimer = null;
  let updateChecking = false;
  let updateInstalling = false;
  let updateClosed = false;
  let pendingUpdatePath = '';
  function saveUpdate() {
    try { writeJsonAtomic(UPDATE_FILE, upd); }
    catch (e) { log('WARN', '写 update.json 失败：' + (e && e.message || e)); }
  }
  function updatePlatform() {
    if (process.platform === 'win32' && process.arch === 'x64') return 'win-x64';
    if (process.platform === 'darwin' && (process.arch === 'x64' || process.arch === 'arm64')) return 'macos-' + process.arch;
    if (process.platform === 'linux' && process.arch === 'x64') return 'linux-x64';
    return '';
  }
  function verParts(v) {
    return String(v || '').replace(/^v/i, '').split(/[.+-]/).map((x) => (/^\d+$/.test(x) ? Number(x) : x));
  }
  function compareVersion(a, b) {
    const A = verParts(a), B = verParts(b);
    for (let i = 0; i < Math.max(A.length, B.length); i++) {
      const x = A[i], y = B[i];
      if (x === undefined) return -1;
      if (y === undefined) return 1;
      if (typeof x === 'number' && typeof y === 'number') { if (x !== y) return x < y ? -1 : 1; continue; }
      const sx = String(x), sy = String(y);
      if (sx !== sy) return sx < sy ? -1 : 1;
    }
    return 0;
  }
  function queuedTotal() {
    const t = Date.now();
    let n = 0;
    for (const v of ren.values()) n += v.queue.filter((x) => x.exp > t).length;
    return n;
  }
  function updateSummary() {
    const latest = upd.latest;
    return {
      available: !!(latest && compareVersion(latest.version, VERSION) > 0),
      latest: latest ? latest.version : '',
      auto: upd.auto,
      lastCheck: upd.lastCheck,
      lastError: upd.lastError,
    };
  }
  function updateView() {
    const latest = upd.latest;
    const available = !!(latest && compareVersion(latest.version, VERSION) > 0);
    const platform = updatePlatform();
    const assetOk = !!(latest && latest.asset && latest.asset.name && latest.asset.url);
    const staged = IS_SEA && pendingUpdatePath && fs.existsSync(pendingUpdatePath);
    return {
      ok: true,
      current: VERSION,
      platform,
      singleFile: IS_SEA,
      auto: upd.auto,
      intervalHours: upd.intervalHours,
      lastCheck: upd.lastCheck,
      lastError: upd.lastError,
      latest,
      updateAvailable: available,
      canInstall: !!(IS_SEA && platform && available && assetOk && !updateInstalling),
      installing: updateInstalling,
      checking: updateChecking,
      staged: !!staged,
      queue: queuedTotal(),
      lastInstall: upd.lastInstall,
    };
  }
  function allowedUpdateUrl(raw) {
    try {
      const u = new URL(String(raw));
      if (process.env.FWARMY_UPDATE_TEST === '1') return u.protocol === 'http:' || u.protocol === 'https:';
      return u.protocol === 'https:' && u.hostname === 'github.com';
    } catch { return false; }
  }
  async function fetchText(url, timeout = 15_000) {
    if (!allowedUpdateUrl(url)) throw new Error('update-url-not-allowed');
    const r = await fetch(url, {
      headers: { 'user-agent': `FWArmy/${VERSION}`, accept: 'application/vnd.github+json' },
      signal: AbortSignal.timeout(timeout),
    });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    return await r.text();
  }
  async function fetchToFile(url, dest) {
    if (!allowedUpdateUrl(url)) throw new Error('update-url-not-allowed');
    const r = await fetch(url, {
      headers: { 'user-agent': `FWArmy/${VERSION}` },
      signal: AbortSignal.timeout(10 * 60_000),
    });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    if (!r.body) {
      fs.writeFileSync(dest, Buffer.from(await r.arrayBuffer()));
      return;
    }
    await pipeline(Readable.fromWeb(r.body), fs.createWriteStream(dest));
  }
  function hashFile(file) {
    return new Promise((resolve, reject) => {
      const h = crypto.createHash('sha256');
      const s = fs.createReadStream(file);
      s.on('error', reject);
      s.on('data', (d) => h.update(d));
      s.on('end', () => resolve(h.digest('hex')));
    });
  }
  function probeLocalHealth(port, timeout = 700) {
    return new Promise((resolve) => {
      const req = http.get({ host: '127.0.0.1', port, path: '/api/health', timeout }, (res) => {
        res.resume();
        resolve(res.statusCode === 200);
      });
      req.on('timeout', () => { try { req.destroy(); } catch { /* noop */ } resolve(false); });
      req.on('error', () => resolve(false));
    });
  }
  function findUpdateBinary(dir, name, depth = 0) {
    let ents = [];
    try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch { return ''; }
    for (const e of ents) if (e.isFile() && e.name === name) return path.join(dir, e.name);
    if (depth >= 3) return '';
    for (const e of ents) {
      if (!e.isDirectory()) continue;
      const hit = findUpdateBinary(path.join(dir, e.name), name, depth + 1);
      if (hit) return hit;
    }
    return '';
  }
  async function checkUpdate(manual = false, allowAuto = true) {
    if (updateChecking || updateClosed) return updateView();
    updateChecking = true;
    try {
      const apiBase = String(process.env.FWARMY_UPDATE_API || 'https://api.github.com/repos/Pondsi/FWArmy').replace(/\/+$/, '');
      if (process.env.FWARMY_UPDATE_TEST !== '1' && apiBase !== 'https://api.github.com/repos/Pondsi/FWArmy') {
        throw new Error('update-api-not-allowed');
      }
      const r = await fetch(`${apiBase}/releases/latest`, {
        headers: { 'user-agent': `FWArmy/${VERSION}`, accept: 'application/vnd.github+json' },
        signal: AbortSignal.timeout(15_000),
      });
      if (!r.ok) throw new Error('HTTP ' + r.status + (r.status === 403 ? '（GitHub 限流，稍后再试）' : ''));
      const j = await r.json();
      const tag = String(j.tag_name || '').trim();
      const version = tag.replace(/^v/i, '');
      if (!version) throw new Error('release 没有 tag_name');
      const platform = updatePlatform();
      const suffix = platform === 'win-x64' ? `-${platform}.zip` : (platform ? `-${platform}.tar.gz` : '');
      const assets = Array.isArray(j.assets) ? j.assets : [];
      const asset = suffix ? assets.find((a) => String(a.name || '').endsWith(suffix)) : null;
      const sums = assets.find((a) => String(a.name || '') === 'SHA256SUMS');
      upd.latest = {
        version, tag,
        name: String(j.name || '').slice(0, 160),
        publishedAt: String(j.published_at || ''),
        notes: String(j.body || '').slice(0, 6000),
        url: String(j.html_url || ''),
        sumsUrl: sums ? String(sums.browser_download_url || '') : '',
        asset: asset ? {
          name: String(asset.name || ''), size: Number(asset.size) || 0,
          url: String(asset.browser_download_url || ''),
          sha256: String(asset.digest || '').replace(/^sha256:/i, '').toLowerCase(),
        } : null,
      };
      upd.lastCheck = Date.now();
      upd.lastError = '';
      saveUpdate();
      const available = compareVersion(version, VERSION) > 0;
      log('INFO', `更新检查：当前 ${VERSION}，最新 ${version}${available ? '（有新版本）' : ''}${manual ? '（手动）' : ''}`);
      if (allowAuto && upd.auto === 'install' && available && upd.triedVersion !== version && !updateInstalling) {
        if (queuedTotal() === 0) {
          upd.triedVersion = version;
          saveUpdate();
          setImmediate(() => installUpdate(false).catch((e) => log('WARN', '自动更新失败：' + String(e && e.message || e).slice(0, 200))));
        } else {
          log('INFO', '自动更新暂缓：队列还有消息，60 秒后重试');
          if (updateRetryTimer) clearTimeout(updateRetryTimer);
          updateRetryTimer = setTimeout(() => {
            updateRetryTimer = null;
            if (!updateClosed && upd.auto === 'install') checkUpdate(false);
          }, 60_000);
          updateRetryTimer.unref?.();
        }
      }
    } catch (e) {
      upd.lastCheck = Date.now();
      upd.lastError = String(e && e.message || e).slice(0, 300);
      saveUpdate();
      log('WARN', '更新检查失败：' + upd.lastError);
    } finally {
      updateChecking = false;
    }
    return updateView();
  }
  function scheduleUpdateCheck(delayMs) {
    if (updateTimer) { clearTimeout(updateTimer); updateTimer = null; }
    if (updateClosed || upd.auto === 'off') return;
    updateTimer = setTimeout(() => {
      updateTimer = null;
      checkUpdate(false).finally(() => scheduleUpdateCheck(upd.intervalHours * 3600_000));
    }, Math.max(1000, Number(delayMs) || 0));
    updateTimer.unref?.();
  }
  async function installUpdate(force = false) {
    if (updateInstalling) throw new Error('update-in-progress');
    if (!IS_SEA) throw new Error('not-single-file');
    const platform = updatePlatform();
    if (!platform) throw new Error('unsupported-platform');
    if (!upd.latest || !upd.latest.asset) await checkUpdate(true, false);
    const latest = upd.latest;
    if (!latest || !latest.asset) throw new Error('no-update-asset');
    if (process.env.FWARMY_UPDATE_TEST !== '1' && compareVersion(latest.version, VERSION) <= 0) throw new Error('already-latest');
    if (!force && queuedTotal() > 0) throw new Error('queue-not-empty');
    updateInstalling = true;
    upd.lastError = '';
    saveUpdate();
    const work = path.join(DATA, 'updates', latest.version.replace(/[^0-9A-Za-z._-]/g, '_'));
    try {
      fs.rmSync(work, { recursive: true, force: true });
      fs.mkdirSync(work, { recursive: true });
      const archive = path.join(work, String(latest.asset.name).replace(/[\\/:*?"<>|]/g, '_'));
      log('INFO', `更新：下载 ${latest.version} ${latest.asset.name}`);
      await fetchToFile(latest.asset.url, archive);
      if (latest.asset.size && fs.statSync(archive).size !== latest.asset.size) throw new Error('size-mismatch');
      let want = String(latest.asset.sha256 || '').toLowerCase();
      if (!want && latest.sumsUrl) {
        const sums = await fetchText(latest.sumsUrl);
        const line = String(sums).split(/\r?\n/).find((x) => x.trim().split(/\s+/)[1] === latest.asset.name);
        if (line) want = line.trim().split(/\s+/)[0].toLowerCase();
      }
      if (!want) throw new Error('sha256-missing');
      const got = await hashFile(archive);
      if (got !== want) throw new Error('sha256-mismatch');
      const extract = path.join(work, 'extract');
      fs.mkdirSync(extract, { recursive: true });
      let x;
      if (process.platform === 'win32') {
        const tarExe = path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'tar.exe');
        if (fs.existsSync(tarExe)) x = spawnSync(tarExe, ['-xf', archive, '-C', extract], { timeout: 120_000, encoding: 'utf8' });
        if (!x || x.status !== 0) {
          const q = (s) => String(s).replace(/'/g, "''");
          x = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', `Expand-Archive -LiteralPath '${q(archive)}' -DestinationPath '${q(extract)}' -Force`], { timeout: 120_000, encoding: 'utf8' });
        }
      } else {
        x = spawnSync('tar', ['-xzf', archive, '-C', extract], { timeout: 120_000, encoding: 'utf8' });
      }
      if (!x || x.status !== 0) throw new Error('extract-failed: ' + String((x && (x.stderr || x.stdout)) || '').slice(0, 120));
      const binName = process.platform === 'win32' ? 'FWArmy.exe' : 'FWArmy';
      const found = findUpdateBinary(extract, binName);
      if (!found) throw new Error('binary-not-found');
      if (process.platform !== 'win32') fs.chmodSync(found, 0o755);
      const newVer = spawnSync(found, ['--version'], { timeout: 30_000, encoding: 'utf8', windowsHide: true });
      if (newVer.status !== 0 || !/FWArmy/.test(String(newVer.stdout))) throw new Error('new-binary-cannot-run');
      if (process.env.FWARMY_UPDATE_TEST !== '1' && !String(newVer.stdout).includes(`FWArmy ${latest.version}`)) {
        throw new Error('new-binary-version-mismatch');
      }
      const staged = path.join(work, binName + '.new');
      fs.rmSync(staged, { force: true });
      fs.copyFileSync(found, staged);
      if (process.platform !== 'win32') fs.chmodSync(staged, 0o755);
      pendingUpdatePath = staged;
      log('INFO', `更新：已暂存 ${staged} exists=${fs.existsSync(staged)} size=${fs.existsSync(staged) ? fs.statSync(staged).size : 0}`);
      upd.lastInstall = { version: latest.version, at: Date.now(), ok: true, error: '' };
      upd.lastError = '';
      saveUpdate();
      log('INFO', `更新：${latest.version} 已下载并校验，准备重启`);
      setTimeout(() => { applyUpdate(staged).catch((e) => log('ERROR', '重启应用更新失败：' + String(e && e.message || e).slice(0, 200))); }, 500).unref?.();
      return updateView();
    } catch (e) {
      const msg = String(e && e.message || e).slice(0, 300);
      upd.lastError = msg;
      upd.lastInstall = { version: latest.version, at: Date.now(), ok: false, error: msg };
      saveUpdate();
      log('WARN', '更新失败：' + msg);
      throw e;
    } finally {
      updateInstalling = false;
    }
  }
  async function applyUpdate(stagedPath = '') {
    if (!IS_SEA) return;
    const current = process.execPath;
    const staged = stagedPath || pendingUpdatePath || (current + '.new');
    log('INFO', `更新：检查待替换文件 ${staged} exists=${fs.existsSync(staged)}`);
    if (!fs.existsSync(staged)) {
      upd.lastError = 'staged-missing';
      upd.lastInstall = { version: upd.latest ? upd.latest.version : '', at: Date.now(), ok: false, error: 'staged-missing' };
      saveUpdate();
      log('WARN', '更新：找不到待替换文件，保留当前程序');
      return;
    }
    const args = ['--server', `--port=${actualPort || opt.port}`, `--host=${opt.host}`, `--data=${DATA}`, '--no-open'];
    if (opt.quiet) args.push('--quiet');
    if (opt.logFile) args.push(`--log-file=${opt.logFile}`);
    const old = `${current}.old-${Date.now()}`;
    log('INFO', `更新：关闭服务并重启以应用 ${upd.latest ? upd.latest.version : '新版本'}`);
    try { await close(); } catch { /* noop */ }
    let movedOld = false, movedNew = false, copyFallback = false;
    try {
      fs.renameSync(current, old); movedOld = true;
      try { fs.renameSync(staged, current); }
      catch (e) {
        if (!e || e.code !== 'EXDEV') throw e;
        fs.copyFileSync(staged, current);
        if (process.platform !== 'win32') fs.chmodSync(current, 0o755);
        copyFallback = true;
      }
      movedNew = true;
      const child = spawn(current, args, { detached: true, stdio: 'ignore', cwd: path.dirname(current), windowsHide: true });
      if (!child.pid) throw new Error('spawn-failed');
      child.on('error', (e) => log('ERROR', '新版本启动失败：' + String(e && e.message || e).slice(0, 200)));
      child.unref();
      log('INFO', `更新：新进程已启动 pid=${child.pid}，等待健康检查`);
      /** 等新进程真的能服务再退出；否则回滚到旧文件，避免“更新完服务没了”。 */
      let healthy = false;
      for (let i = 0; i < 120; i++) {
        await sleep(250);
        if (await probeLocalHealth(actualPort || opt.port)) { healthy = true; break; }
      }
      if (!healthy) {
        try { child.kill(); } catch { /* noop */ }
        throw new Error('new-server-not-healthy');
      }
      log('INFO', '更新：新进程健康，旧进程退出');
      setTimeout(() => process.exit(0), 100);
    } catch (e) {
      try {
        if (movedNew) {
          if (copyFallback) {
            fs.copyFileSync(current, staged);
            fs.rmSync(current, { force: true });
          } else {
            fs.renameSync(current, staged);
          }
          movedNew = false;
        }
        if (movedOld) { fs.renameSync(old, current); movedOld = false; }
      } catch { /* noop */ }
      upd.lastError = 'restart-failed: ' + String(e && e.message || e).slice(0, 200);
      upd.lastInstall = { version: upd.latest ? upd.latest.version : '', at: Date.now(), ok: false, error: upd.lastError };
      saveUpdate();
      log('ERROR', '更新替换失败：' + upd.lastError);
      try { spawn(current, args, { detached: true, stdio: 'ignore', cwd: path.dirname(current), windowsHide: true }).unref(); } catch { /* noop */ }
      setTimeout(() => process.exit(1), 500);
    }
  }

  async function adminApi(req, res, u) {
    const p = u.pathname;
    if (req.method === 'GET' && p === '/api/admin/stats') return send(res, 200, buildStats());
    if (req.method === 'GET' && p === '/api/admin/update') return send(res, 200, updateView());
    if (req.method === 'POST' && p === '/api/admin/update-check') {
      await checkUpdate(true);
      return send(res, 200, updateView());
    }
    if (req.method === 'POST' && p === '/api/admin/update-config') {
      const j = await body(req);
      if (j.auto !== undefined) {
        if (!['off', 'check', 'install'].includes(j.auto)) return send(res, 400, { ok: false, error: 'bad-update-auto' });
        upd.auto = j.auto;
      }
      if (j.intervalHours !== undefined) {
        const h = Number(j.intervalHours);
        if (!Number.isFinite(h) || h < 1 || h > 168) return send(res, 400, { ok: false, error: 'bad-update-interval' });
        upd.intervalHours = Math.round(h);
      }
      upd.triedVersion = '';
      saveUpdate();
      scheduleUpdateCheck(upd.auto === 'off' ? 0 : 5000);
      log('INFO', `更新设置：auto=${upd.auto} interval=${upd.intervalHours}h`);
      return send(res, 200, { ok: true, update: updateView() });
    }
    if (req.method === 'POST' && p === '/api/admin/update-install') {
      const j = await body(req);
      try {
        const view = await installUpdate(j && j.force === true);
        return send(res, 200, { ok: true, restarting: true, update: view });
      } catch (e) {
        return send(res, 400, { ok: false, error: String(e && e.message || e).slice(0, 200), update: updateView() });
      }
    }
    if (req.method === 'GET' && p === '/api/admin/expand') return send(res, 200, expandView());
    if (req.method === 'POST' && p === '/api/admin/expand-inbound') {
      const j = await body(req);
      const { token, item } = generateInboundToken(j.name);
      log('INFO', `被扩网：已生成新的接入凭据 #${expand.inbound.length}（只显示一次）`);
      return send(res, 200, { ok: true, token, item: { id: item.id, name: item.name, prefix: item.prefix }, inbound: expandView().inbound });
    }
    if (req.method === 'POST' && p === '/api/admin/expand-inbound-update') {
      const j = await body(req);
      const item = expand.inbound.find((x) => x.id === String(j.id || ''));
      if (!item) return send(res, 404, { ok: false, error: 'not-found' });
      if (j.name !== undefined) {
        const name = String(j.name || '').trim().slice(0, 40);
        if (!name) return send(res, 400, { ok: false, error: 'bad-name' });
        item.name = name;
      }
      if (j.disabled !== undefined) {
        if (typeof j.disabled !== 'boolean') return send(res, 400, { ok: false, error: 'bad-disabled' });
        item.disabled = j.disabled;
      }
      saveExpand();
      log('INFO', `被扩网：凭据 ${item.id.slice(0, 8)} ${item.disabled ? '停用' : '启用'}`);
      return send(res, 200, { ok: true, item: expandView().inbound.credentials.find((x) => x.id === item.id) });
    }
    if (req.method === 'POST' && p === '/api/admin/expand-inbound-remove') {
      const j = await body(req);
      const i = expand.inbound.findIndex((x) => x.id === String(j.id || ''));
      if (i < 0) return send(res, 404, { ok: false, error: 'not-found' });
      const [removed] = expand.inbound.splice(i, 1);
      delete expand.stats.perInbound[removed.id];
      saveExpand();
      log('INFO', `被扩网：删除接入凭据 ${removed.id.slice(0, 8)}`);
      return send(res, 200, { ok: true });
    }
    if (req.method === 'POST' && p === '/api/admin/expand-outbound') {
      const j = await body(req);
      let addr;
      try { addr = parseExpandAddress(j.address); }
      catch (e) { return send(res, 400, { ok: false, error: String(e.message || 'bad-address') }); }
      const credential = String(j.credential || '').trim();
      if (!credential) return send(res, 400, { ok: false, error: 'credential-required' });
      const ts = tlsFromInput(j.tls, null);
      if (!ts.ok) return send(res, 400, { ok: false, error: ts.error });
      const name = String(j.name || '').trim().slice(0, 40) || (addr.host + ':' + addr.port);
      const item = {
        id: crypto.randomUUID(), name, host: addr.host, port: addr.port,
        credential: '', hint: '', tls: ts.tls,
        enabled: true, createdAt: Date.now(), lastTest: 0, lastTestOk: false,
      };
      setPeerCredential(item, credential);
      expand.outbound.push(item);
      saveExpand();
      log('INFO', `扩网：添加 ${name} → ${addr.host}:${addr.port}（TLS ${ts.tls.mode}）`);
      return send(res, 200, { ok: true, item: expandView().outbound.find((x) => x.id === item.id) });
    }
    if (req.method === 'POST' && p === '/api/admin/expand-update') {
      const j = await body(req);
      const item = expand.outbound.find((x) => x.id === String(j.id || ''));
      if (!item) return send(res, 404, { ok: false, error: 'not-found' });
      if (j.name !== undefined) {
        const name = String(j.name || '').trim().slice(0, 40);
        if (!name) return send(res, 400, { ok: false, error: 'bad-name' });
        item.name = name;
      }
      if (j.address !== undefined) {
        let addr;
        try { addr = parseExpandAddress(j.address); }
        catch (e) { return send(res, 400, { ok: false, error: String(e.message || 'bad-address') }); }
        item.host = addr.host; item.port = addr.port;
      }
      if (j.credential !== undefined) {
        const credential = String(j.credential || '').trim();
        if (!credential) return send(res, 400, { ok: false, error: 'credential-required' });
        setPeerCredential(item, credential);
      }
      if (j.tls !== undefined) {
        const ts = tlsFromInput(j.tls, item.tls);
        if (!ts.ok) return send(res, 400, { ok: false, error: ts.error });
        item.tls = ts.tls;
      }
      if (j.enabled !== undefined) {
        if (typeof j.enabled !== 'boolean') return send(res, 400, { ok: false, error: 'bad-enabled' });
        item.enabled = j.enabled;
      }
      saveExpand();
      return send(res, 200, { ok: true, item: expandView().outbound.find((x) => x.id === item.id) });
    }
    if (req.method === 'POST' && p === '/api/admin/expand-remove') {
      const j = await body(req);
      const i = expand.outbound.findIndex((x) => x.id === String(j.id || ''));
      if (i < 0) return send(res, 404, { ok: false, error: 'not-found' });
      const [removed] = expand.outbound.splice(i, 1);
      saveExpand();
      log('INFO', `扩网：移除 ${removed.name || removed.host}`);
      return send(res, 200, { ok: true });
    }
    if (req.method === 'POST' && p === '/api/admin/expand-identify') {
      const j = await body(req);
      const item = expand.outbound.find((x) => x.id === String(j.id || ''));
      if (!item) return send(res, 404, { ok: false, error: 'not-found' });
      try {
        const r = await peerCall(item, '/api/expand/identify', { auth: false, timeoutMs: 6000, tlsOverride: { ...peerTls(item), mode: 'inspect' } });
        const out = r.json || {};
        item.lastTest = Date.now();
        item.lastTestOk = r.status === 200 && out.ok === true;
        saveExpand();
        return send(res, 200, {
          ok: true, status: r.status, ms: r.ms,
          instanceId: out.instanceId || '', fingerprint: r.fingerprint || (out.tls && out.tls.fingerprint) || '',
          tls: out.tls || null, product: out.product || '', version: out.version || '',
        });
      } catch (e) {
        return send(res, 200, { ok: true, reachable: false, error: String((e && e.message) || e).slice(0, 160) });
      }
    }
    if (req.method === 'POST' && p === '/api/admin/expand-trust') {
      const j = await body(req);
      const item = expand.outbound.find((x) => x.id === String(j.id || ''));
      if (!item) return send(res, 404, { ok: false, error: 'not-found' });
      const fp = String(j.fingerprint || '').toLowerCase().replace(/[^0-9a-f]/g, '');
      if (fp.length !== 64) return send(res, 400, { ok: false, error: 'bad-fingerprint' });
      item.tls = { ...peerTls(item), mode: 'pin', fingerprint: fp };
      saveExpand();
      log('INFO', `扩网：固定 ${item.name} 的证书指纹 ${fp.slice(0, 16)}…`);
      return send(res, 200, { ok: true, item: expandView().outbound.find((x) => x.id === item.id) });
    }
    if (req.method === 'POST' && p === '/api/admin/expand-test') {
      const j = await body(req);
      const item = expand.outbound.find((x) => x.id === String(j.id || ''));
      if (!item) return send(res, 404, { ok: false, error: 'not-found' });
      const t = peerTls(item);
      if (t.mode === 'pin' && t.fingerprint.length !== 64) {
        // 未固定指纹时先只做 identify（不发凭据）；用户确认后才允许发 Authorization。
        try {
          const r = await peerCall(item, '/api/expand/identify', { auth: false, timeoutMs: 6000, tlsOverride: { ...t, mode: 'inspect' } });
          return send(res, 200, {
            ok: true, reachable: false, needsTrust: true, status: r.status, ms: r.ms,
            fingerprint: r.fingerprint, instanceId: (r.json && r.json.instanceId) || '',
          });
        } catch (e) {
          return send(res, 200, { ok: true, reachable: false, needsTrust: true, error: String((e && e.message) || e).slice(0, 160) });
        }
      }
      const t0 = Date.now();
      try {
        const r = await peerCall(item, '/api/expand/ping', { timeoutMs: 6000 });
        const out = r.json || {};
        item.lastTest = Date.now();
        item.lastTestOk = r.status === 200 && out.ok === true;
        saveExpand();
        return send(res, 200, {
          ok: true, reachable: item.lastTestOk, status: r.status, ms: Date.now() - t0,
          fingerprint: r.fingerprint, result: out,
        });
      } catch (e) {
        item.lastTest = Date.now();
        item.lastTestOk = false;
        saveExpand();
        const msg = String((e && e.message) || e);
        return send(res, 200, {
          ok: true, reachable: false, ms: Date.now() - t0,
          error: msg === 'timeout' ? 'timeout' : (msg === 'fingerprint-mismatch' ? 'tls-fingerprint-mismatch' : msg.slice(0, 160)),
        });
      }
    }
    if (req.method === 'GET' && p === '/api/admin/security') return send(res, 200, securityView());
    if (req.method === 'POST' && p === '/api/admin/security-gc') {
      const r = pruneSecurity(now());
      saveSecurity();
      return send(res, 200, { ok: true, ...r });
    }
    if (req.method === 'POST' && p === '/api/admin/security-clear-blacklist') {
      const j = await body(req);
      if (j.confirm !== true) return send(res, 400, { ok: false, error: 'confirm-required' });
      security.blacklist = {};
      saveSecurity();
      log('WARN', '管理员清空消息黑名单');
      return send(res, 200, { ok: true });
    }
    if (req.method === 'GET' && p === '/api/admin/reach') return send(res, 200, reachView());
    if (req.method === 'POST' && p === '/api/admin/reach') {
      const j = await body(req);
      const action = String(j.action || '');
      if (action === 'natpmp-probe') {
        lastNatpmp = await natpmpProbe({ gateways: Array.isArray(j.gateways) ? j.gateways.map(String).slice(0, 8) : [] });
        return send(res, 200, { ok: true, natpmp: lastNatpmp, view: reachView() });
      }
      if (action === 'stun') {
        const servers = Array.isArray(j.servers) ? j.servers.map((x) => String(x).slice(0, 253)).filter(Boolean).slice(0, 8) : [];
        lastStun = await stunBinding({ servers, timeoutMs: 1800 });
        return send(res, 200, { ok: true, stun: lastStun, view: reachView() });
      }
      if (action === 'natpmp-map') {
        if (j.confirm !== true) return send(res, 400, { ok: false, error: 'confirm-required' });
        const gw = String(j.gateway || (lastNatpmp && lastNatpmp.gateway) || (gatewayCandidates()[0] || ''));
        const r = await natpmpMap({ gateway: gw, internalPort: boundPort || opt.port, externalPort: Number(j.externalPort) || 0, leaseSec: Math.max(60, Math.min(86400, Number(j.leaseSec) || 7200)), protocol: 'tcp' });
        if (!r.ok) return send(res, 200, { ok: true, mapped: false, result: r });
        expand.natpmp = {
          gateway: gw, internalPort: r.internalPort, externalPort: r.externalPort,
          lifetimeSec: r.lifetime, mappedAt: Date.now(), protocol: 'tcp',
        };
        saveExpand();
        log('INFO', `NAT-PMP：TCP ${r.internalPort} → 外部 ${r.externalPort}（租期 ${r.lifetime}s）`);
        return send(res, 200, { ok: true, mapped: true, result: r, view: reachView() });
      }
      if (action === 'natpmp-unmap') {
        const m = expand.natpmp;
        if (!m) return send(res, 200, { ok: true, unmapped: false, error: 'no-mapping' });
        const r = await natpmpMap({ gateway: m.gateway, internalPort: m.internalPort, externalPort: 0, leaseSec: 0, protocol: 'tcp' });
        if (r.ok) { expand.natpmp = null; saveExpand(); }
        return send(res, 200, { ok: true, unmapped: r.ok, result: r, view: reachView() });
      }
      return send(res, 400, { ok: false, error: 'bad-action' });
    }
    if (req.method === 'GET' && p === '/api/admin/tls') return send(res, 200, { ok: true, tls: tlsPublicView(), config: cfg.tls });
    if (req.method === 'POST' && p === '/api/admin/tls') {
      const j = await body(req);
      const next = normTlsCfg({ ...cfg.tls, ...j });
      if (next.mode === 'off' && j.confirmInsecure !== true) return send(res, 400, { ok: false, error: 'confirm-insecure-required' });
      if (next.mode === 'user-cert') {
        if (!next.certFile || !next.keyFile) return send(res, 400, { ok: false, error: 'cert-and-key-required' });
        try { tls.createSecureContext({ cert: fs.readFileSync(path.resolve(next.certFile), 'utf8'), key: fs.readFileSync(path.resolve(next.keyFile), 'utf8') }); }
        catch (e) { return send(res, 400, { ok: false, error: 'bad-cert-or-key:' + String(e && e.message || e).slice(0, 80) }); }
      }
      cfg.tls = next;
      saveCfg();
      log('INFO', `TLS 配置已保存 mode=${next.mode} allowPlaintext=${next.allowPlaintext}（需重启生效）`);
      return send(res, 200, { ok: true, tls: tlsPublicView(), restartRequired: true });
    }
    if (req.method === 'GET' && p === '/api/admin/credentials') {
      return send(res, 200, { ok: true, items: Object.values(creds).map(viewCred) });
    }
    if (req.method === 'POST' && p === '/api/admin/credentials') {
      const j = await body(req);
      const name = String(j.name || '').trim().slice(0, 40) || '未命名';
      const limits = parseLimits(j.limits);
      const token = b64u(crypto.randomBytes(32));
      const id = crypto.randomUUID();
      creds[id] = {
        id, name, hash: sha(token), hash8: sha(token).slice(0, 8),
        createdAt: new Date().toISOString(), disabled: false, limits, lastUsed: 0,
      };
      rebuildIndex(); saveCreds();
      log('INFO', `新建凭据 id=${id} name=${JSON.stringify(name)}`);
      return send(res, 200, { ok: true, id, name, token, credential: viewCred(creds[id]) });
    }
    if (req.method === 'POST' && p === '/api/admin/credential-update') {
      const j = await body(req);
      const c = findCred(j.id);
      if (!c) return send(res, 404, { ok: false, error: 'not-found' });
      const name = j.name === undefined ? c.name : String(j.name || '').trim().slice(0, 40);
      if (!name) return send(res, 400, { ok: false, error: 'bad-name' });
      if (j.disabled !== undefined && typeof j.disabled !== 'boolean') return send(res, 400, { ok: false, error: 'bad-disabled' });
      const limits = parseLimits(j.limits, c.limits);
      // 全部字段通过后一次提交，非法限额不能顺带改名/停用。
      c.name = name;
      c.disabled = j.disabled === undefined ? c.disabled : j.disabled;
      c.limits = limits;
      credStat(c).name = name;
      saveCreds(); markStatsDirty();
      log('INFO', `更新凭据 id=${c.id} disabled=${c.disabled}`);
      return send(res, 200, { ok: true, credential: viewCred(c) });
    }
    if (req.method === 'POST' && (p === '/api/admin/credential-revoke' || p === '/api/admin/credential-disable')) {
      const j = await body(req);
      const c = findCred(j.id);
      if (!c) return send(res, 404, { ok: false, error: 'not-found' });
      c.disabled = j.disabled === undefined ? true : !!j.disabled;
      saveCreds();
      log('INFO', `凭据 ${c.disabled ? '停用' : '启用'} id=${c.id}`);
      return send(res, 200, { ok: true, credential: viewCred(c) });
    }
    if (req.method === 'POST' && p === '/api/admin/credential-delete') {
      const j = await body(req);
      const c = findCred(j.id);
      if (!c) return send(res, 404, { ok: false, error: 'not-found' });
      if (String(j.confirmName || '') !== c.name) return send(res, 400, { ok: false, error: 'confirm-name-mismatch' });
      delete creds[c.id];
      const s = credStat(c); s.deletedAt = Date.now();
      rebuildIndex(); saveCreds(); markStatsDirty();
      // 删的正好是首次引导凭据 ⇒ 明文文件也一起删，别留下一个已失效但仍是秘密的 token
      if (firstRunPending()) {
        try { if (sha(readFirstCredential()) === c.hash) clearFirstCredential(); } catch { /* noop */ }
      }
      log('INFO', `删除凭据 id=${c.id}`);
      return send(res, 200, { ok: true });
    }
    if (req.method === 'POST' && p === '/api/admin/config') {
      const j = await body(req);
      if (!j || typeof j !== 'object' || Array.isArray(j)) return send(res, 400, { ok: false, error: 'bad-config' });
      const next = { ...cfg };
      for (const [k, v] of Object.entries(j)) {
        if (k === 'accepting' ? typeof v !== 'boolean' : !Object.hasOwn(CONFIG_RANGES, k) || !validLimit(k, v)) {
          return send(res, 400, { ok: false, error: 'bad-config:' + k });
        }
        next[k] = v;
      }
      cfg = next; // 不清用量：新限额立刻作用于已有统计，避免改设置刷新预算。
      saveCfg();
      log('INFO', `更新全局配置 accepting=${cfg.accepting} ratePerMin=${cfg.ratePerMin}`);
      return send(res, 200, { ok: true, config: cfg });
    }
    if (req.method === 'GET' && p === '/api/admin/first-credential') {
      const token = readFirstCredential();
      return send(res, 200, { ok: true, pending: !!token, token, name: '默认凭据' });
    }
    if (req.method === 'POST' && p === '/api/admin/first-credential-ack') {
      clearFirstCredential();
      log('INFO', '首次凭据已确认保存，删除本机加密引导文件');
      return send(res, 200, { ok: true });
    }
    if (req.method === 'GET' && p === '/api/admin/log') {
      const tail = Math.min(500, Math.max(20, Number(u.searchParams.get('tail')) || 200));
      let text = '';
      try {
        const st = fs.statSync(LOG);
        const start = Math.max(0, st.size - 128 * 1024);
        const fd = fs.openSync(LOG, 'r');
        const buf = Buffer.alloc(Math.min(st.size - start, 128 * 1024));
        fs.readSync(fd, buf, 0, buf.length, start);
        fs.closeSync(fd);
        text = buf.toString('utf8');
      } catch { text = ''; }
      const lines = text.split(/\r?\n/).filter(Boolean).slice(-tail);
      return send(res, 200, { ok: true, lines, file: path.basename(LOG) });
    }
    if (req.method === 'POST' && p === '/api/admin/public-ip') {
      const pu = await (async () => {
        try {
          const r = await fetch('https://api.ipify.org?format=json', { signal: AbortSignal.timeout(4000) });
          const j = await r.json();
          return String(j.ip || '');
        } catch { return ''; }
      })();
      const hou = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim() || String(req.socket.remoteAddress || '');
      return send(res, 200, { ok: true, publicIp: pu || hou, via: pu ? 'ipify' : 'peer-address' });
    }
    if (req.method === 'POST' && p === '/api/admin/shutdown') {
      send(res, 200, { ok: true, bye: true });
      setTimeout(() => shutdown('admin'), 200);
      return;
    }
    return send(res, 404, { ok: false, error: 'not-found' });
  }

  const requestListener = async (req, res) => {
    const t0 = Date.now();
    let u;
    try { u = new URL(req.url || '/', 'http://x'); } catch { return send(res, 400, { ok: false, error: 'bad-url' }); }
    let c = null, recorded = false;
    const reply = (code, obj, usage = {}) => {
      if (c && !recorded) { record(c, usage); recorded = true; }
      return send(res, code, obj);
    };
    const fail = (code, error, extra = {}) => reply(code, { ok: false, error, ...extra }, { rejected: 1 });
    res.on('finish', () => {
      // 只记路径，不记 query/正文（query 里有 did/签名，正文可能有信封）
      log('INFO', `req ${req.method} ${u.pathname} ${res.statusCode} ${Date.now() - t0}ms cred=${c ? c.hash8 : '-'}`);
    });
    try {
      const logoLu = ['/assets/logo.svg', '/logo.svg', '/favicon.svg', '/favicon.ico'].includes(u.pathname);
      const adminLu = logoLu || u.pathname === '/' || u.pathname === '/admin' || u.pathname.startsWith('/api/admin/');
      if (adminLu && !isAdminRequest(req)) return send(res, 403, { ok: false, error: 'admin-local-only' });
      if (req.method === 'GET' && logoLu) return sendLogo(res);
      if (req.method === 'GET' && (u.pathname === '/' || u.pathname === '/admin')) return sendHtml(res, 200, adminHtml());
      if (u.pathname.startsWith('/api/admin/')) return await adminApi(req, res, u);

      // 健康检查在业务凭据之前：ctl stop 用它确认端口上是不是我们的服务；无敏感信息
      if (req.method === 'GET' && u.pathname === '/api/health') {
        return send(res, 200, {
          ok: true, server: 'fwarmy-relay', product: PRODUCT, version: VERSION, accepting: cfg.accepting,
          presenceTtlMs: cfg.presenceTtlMs, secure: !!req.socket.encrypted, tls: tlsPublicView(),
        });
      }
      // 指纹引导：不鉴权、不返回凭据；客户端先拿到指纹，用户确认后才发 Authorization。
      if (req.method === 'GET' && u.pathname === '/api/expand/identify') return handleExpandIdentify(req, res);

      // 明文防线：默认只允许回环明文；其它来源必须 TLS（防止凭据/信封被嗅探）。
      if (!req.socket.encrypted && !isLoopback(req) && !cfg.tls.allowPlaintext) {
        return send(res, 426, {
          ok: false, error: 'tls-required',
          tls: { mode: cfg.tls.mode, fingerprint: tlsInfo ? tlsInfo.fingerprint : '' },
          hint: '本服务器要求 TLS；用 https 并核对证书指纹，或在 config.json 显式 allowPlaintext=true（不建议）',
        });
      }

      // 扩网端点用自己的「被扩网凭据」，不使用普通业务凭据。
      if (req.method === 'POST' && u.pathname === '/api/expand/relay') return await handleExpandRelay(req, res);
      if (req.method === 'GET' && u.pathname === '/api/expand/ping') return handleExpandPing(req, res);

      c = cred(req);
      if (!c) {
        stats.unauthorized++;
        markStatsDirty();
        return send(res, 401, { ok: false, error: 'credential-required' });
      }
      const j = req.method === 'POST' ? await body(req, cfg.maxEnvelope + 8192) : {};
      // 读请求体期间可能发生管理修改，异步点后重新核验停用/删除/暂停及预算。
      if (c.disabled || creds[c.id] !== c) {
        c = null; stats.unauthorized++; markStatsDirty();
        return send(res, 401, { ok: false, error: 'credential-required' });
      }
      if (!cfg.accepting) return fail(503, 'not-accepting');
      const g0 = gate(c);
      if (!g0.ok) return fail(g0.code, g0.error, { scope: g0.scope, limit: g0.limit, used: g0.used });

      if (req.method === 'GET' && u.pathname === '/api/lookup') {
        const v = ren.get(String(u.searchParams.get('did') || ''));
        return reply(200, { ok: true, online: !!(v && Date.now() - v.lastSeen < zaiXianTtl()), boxPub: v ? v.boxPub : '', lastSeen: v ? v.lastSeen : 0 });
      }

      if (req.method === 'GET' && u.pathname === '/api/poll') {
        const did = String(u.searchParams.get('did') || '');
        const ts = u.searchParams.get('ts'), sig = u.searchParams.get('sig');
        if (!did || !shiJianOk(ts) || !yanQianMing(did, `poll|${did}|${ts}`, sig)) return fail(401, 'bad-signature');
        const v = ren.get(did);
        if (!v) return fail(404, 'unknown-did');
        if (Date.now() - v.lastSeen >= zaiXianTtl()) return reply(410, { ok: false, error: 'offline' }, { offline: 1 });
        const now = Date.now();
        const yi = v.queue.filter((x) => x.exp > now).slice(0, 50);
        const outBytes = yi.reduce((n, x) => n + Buffer.byteLength(x.env, 'utf8'), 0);
        const g = gate(c, outBytes, now);
        if (!g.ok) return fail(g.code, g.error, { scope: g.scope, limit: g.limit, used: g.used });
        v.lastSeen = now;
        v.queue = v.queue.filter((x) => !yi.includes(x));
        return reply(200, { ok: true, envelopes: yi.map((x) => x.env) }, { delivered: yi.length, bytesOut: outBytes });
      }

      if (req.method === 'POST' && u.pathname === '/api/register') {
        const did = String(j.did || ''), boxPub = String(j.boxPub || ''), ts = Number(j.ts || 0);
        if (!did || !boxPub || !shiJianOk(ts)) return fail(400, 'bad-register');
        if (!yanQianMing(did, `register|${did}|${boxPub}|${ts}`, j.sig)) return fail(401, 'bad-signature');
        try { xPub(boxPub); } catch { return fail(400, 'bad-box-key'); }
        const jiu = ren.get(did);
        ren.set(did, { boxPub, lastSeen: Date.now(), queue: jiu ? jiu.queue : [] });
        return reply(200, { ok: true, online: true });
      }
      if (req.method === 'POST' && u.pathname === '/api/bye') {
        const did = String(j.did || ''), ts = Number(j.ts || 0);
        if (!did || !shiJianOk(ts) || !yanQianMing(did, `bye|${did}|${ts}`, j.sig)) return fail(401, 'bad-signature');
        const v = ren.get(did); if (v) v.lastSeen = 0;
        return reply(200, { ok: true });
      }
      if (req.method === 'POST' && u.pathname === '/api/relay') {
        const to = String(j.to || '').slice(0, 200), env = String(j.envelope || '');
        const bytes = Buffer.byteLength(env, 'utf8');
        if (!to || !bytes || bytes > cfg.maxEnvelope) return fail(400, 'bad-envelope');
        // 客户端没带 messageId 时用信封哈希兜底：完全相同的信封会被当成同一条消息。
        const msgId = j.msgId === undefined || j.msgId === '' ? ('sha256:' + sha(env).slice(0, 32)) : String(j.msgId);
        if (!isMessageId(msgId)) return fail(400, 'bad-msg-id');
        const at = Date.now();
        const createdAt = at;
        const local = enqueueLocal(to, env, at);
        if (local.ok) {
          const g = gate(c, bytes, at);
          if (!g.ok) {
            const y = ren.get(to);
            if (y) y.queue = y.queue.filter((x) => x.id !== local.id);
            return fail(g.code, g.error, { scope: g.scope, limit: g.limit, used: g.used });
          }
          const note = noteMessage(msgId, expand.instanceId);
          if (!note.ok) {
            const y = ren.get(to);
            if (y) y.queue = y.queue.filter((x) => x.id !== local.id);
            return fail(409, note.reason === 'blacklisted' ? 'message-blacklisted' : 'duplicate-message', { reason: note.detail || note.reason, count: note.count });
          }
          return reply(200, { ...local.body, msgId }, { bytesIn: local.bytesIn, relayed: 1 });
        }
        // 本机送不到（离线 / 队列满）⇒ 尝试扩网转发；结果如实回给原发送方。
        const note = noteMessage(msgId, expand.instanceId);
        if (!note.ok) return fail(409, note.reason === 'blacklisted' ? 'message-blacklisted' : 'duplicate-message', { reason: note.detail || note.reason, count: note.count });
        const meta = { ...(signAsSelf(msgId, to, createdAt, env) || {}), createdAt };
        if (!meta.originSig) {
          return reply(200, { ...local.body, forwarded: false, error: 'signing-unavailable' }, local.offline ? { offline: 1 } : { rejected: 1 });
        }
        const fwd = await forwardToPeers(to, env, msgId, meta, []);
        if (fwd.ok) {
          return reply(200, { ok: true, queued: true, forwarded: true, via: fwd.via.name, msgId },
            { bytesIn: bytes, relayed: 1 });
        }
        return reply(local.code === 'queue-full' ? 429 : 200, {
          ...local.body, forwarded: false, attempts: fwd.attempts, msgId,
        }, local.offline ? { offline: 1 } : { rejected: 1 });
      }
      if (req.method === 'POST' && u.pathname === '/api/heartbeat') {
        const did = String(j.did || ''), ts = Number(j.ts || 0);
        if (!did || !shiJianOk(ts) || !yanQianMing(did, `heartbeat|${did}|${ts}`, j.sig)) return fail(401, 'bad-signature');
        const v = ren.get(did);
        if (v) v.lastSeen = Date.now();
        return reply(200, { ok: true, online: !!v, serverTime: Date.now() });
      }
      if (req.method === 'POST' && u.pathname === '/api/presence/batch') {
        const dids = Array.isArray(j.dids) ? j.dids.map(String).slice(0, 500) : [];
        const out = {};
        for (const d of dids) {
          const v = ren.get(d);
          out[d] = { online: !!(v && Date.now() - v.lastSeen < zaiXianTtl()), lastSeen: v ? v.lastSeen : 0 };
        }
        return reply(200, { ok: true, presence: out, serverTime: Date.now() });
      }
      return fail(404, 'not-found');
    } catch (e) {
      const msg = String((e && e.message) || e).slice(0, 120);
      try { log('WARN', `请求处理失败 ${req.method} ${u ? u.pathname : '?'}: ${msg}`); } catch { /* noop */ }
      return fail(400, msg);
    }
  };
  const httpSrv = http.createServer(requestListener);
  const httpsSrv = tlsInfo
    ? https.createServer({ key: tlsInfo.keyPem, cert: tlsInfo.certPem, minVersion: 'TLSv1.2' }, requestListener)
    : null;
  /**
   * 同一端口按首字节分流（0x16=TLS），这样管理页/旧客户端仍能走回环 HTTP，
   * 而公网来源的明文会在请求层被 426 拒绝。注意 resume 必须放到 nextTick，
   * 否则 TLS server 还没挂好监听就被恢复流动，握手会超时。
   */
  const srv = net.createServer((socket) => {
    socket.on('error', () => { /* 连接级错误不影响服务 */ });
    socket.once('data', (buf) => {
      if (!buf || !buf.length) { socket.destroy(); return; }
      socket.pause();
      socket.unshift(buf);
      const target = buf[0] === 0x16 && httpsSrv ? httpsSrv : httpSrv;
      target.emit('connection', socket);
      process.nextTick(() => { try { socket.resume(); } catch { /* noop */ } });
    });
  });

  // ── 单实例：已有同数据目录的服务就只打开管理页 ──
  async function probe(port) {
    for (const t of [{ mode: 'inspect' }, { mode: 'off' }]) {
      try {
        const r = await rawHttpRequest({ host: '127.0.0.1', port, path: '/api/health', tls: t, timeoutMs: 1200 });
        if (r.json && r.json.ok) return r.json;
      } catch { /* 换下一种 */ }
    }
    return null;
  }
  function readInstance() {
    try { return JSON.parse(fs.readFileSync(INSTANCE, 'utf8')); } catch { return null; }
  }
  const inst = readInstance();
  if (inst && inst.port) {
    const alive = await probe(inst.port);
    if (alive && (alive.server === 'fwarmy-relay' || alive.server === 'warmy-relay')) {
      log('INFO', `已有 FWArmy 在运行 pid=${inst.pid || '?'} port=${inst.port}；本次只打开管理页`);
      finishAlreadyRunning(`${tlsInfo ? 'https' : 'http'}://127.0.0.1:${inst.port}/`);
      return { alreadyRunning: true, port: inst.port, dataDir: DATA };
    }
  }

  let port = opt.port;
  let boundPort = 0;
  for (let i = 0; i < 20 && !boundPort; i++) {
    const tryPort = port + i;
    try {
      await new Promise((resolve, reject) => {
        const onErr = (e) => { srv.off('listening', onOk); reject(e); };
        const onOk = () => { srv.off('error', onErr); resolve(); };
        srv.once('error', onErr);
        srv.once('listening', onOk);
        srv.listen(tryPort, opt.host);
      });
      boundPort = tryPort;
    } catch (e) {
      if (e && e.code === 'EADDRINUSE') {
        const h = await probe(tryPort);
        if (h && (h.server === 'fwarmy-relay' || h.server === 'warmy-relay')) {
          log('INFO', `端口 ${tryPort} 上已有 FWArmy；本次只打开管理页`);
          finishAlreadyRunning(`${tlsInfo ? 'https' : 'http'}://127.0.0.1:${tryPort}/`);
          return { alreadyRunning: true, port: tryPort, dataDir: DATA };
        }
        log('WARN', `端口 ${tryPort} 被其它程序占用，尝试 ${tryPort + 1}`);
      } else throw e;
    }
  }
  if (!boundPort) throw new Error('找不到可用端口（8787 起试了 20 个）');
  port = boundPort;
  actualPort = boundPort;

  const scheme = tlsInfo ? 'https' : 'http';
  try {
    writeJsonAtomic(INSTANCE, {
      pid: process.pid, port, host: opt.host, scheme,
      startedAt: new Date().toISOString(), version: VERSION,
      tls: { mode: cfg.tls.mode, fingerprint: tlsInfo ? tlsInfo.fingerprint : '' },
    });
  } catch { /* noop */ }
  try { fs.writeFileSync(PID_FILE, String(process.pid), { encoding: 'utf8', mode: 0o600 }); } catch { /* noop */ }

  const adminUrl = `${scheme}://127.0.0.1:${port}/`;
  log('INFO', `[fwarmy] ${PRODUCT} ${VERSION} 已启动 ${scheme}://${opt.host}:${port}  管理页 ${adminUrl}（本机直接打开，无需密钥）`);
  log('INFO', `[fwarmy] 数据目录 ${DATA}；只存凭据哈希/配置/统计/消息ID哈希，不存消息；队列 TTL ${TTL_MS / 1000}s`);
  if (firstRunPending()) log('INFO', '[fwarmy] 首次启动凭据待保存：打开管理页查看（不会写进日志）');
  /** 上一版更新留下的 .old/.new：新进程稳定后清掉；Windows 上旧进程退出前文件仍被锁，失败就下次再清。 */
  if (IS_SEA) {
    setTimeout(() => {
      try {
        const dir = path.dirname(process.execPath);
        const base = path.basename(process.execPath);
        for (const f of fs.readdirSync(dir)) {
          if (f === base + '.new' || f.startsWith(base + '.old-')) {
            try { fs.rmSync(path.join(dir, f), { force: true }); } catch { /* 下次再清 */ }
          }
        }
      } catch { /* noop */ }
    }, 15_000).unref();
  }
  scheduleUpdateCheck(60_000);

  function openBrowser(url) {
    try {
      if (process.platform === 'win32') spawnDetached('cmd', ['/c', 'start', '', url]);
      else if (process.platform === 'darwin') spawnDetached('open', [url]);
      else spawnDetached('xdg-open', [url]);
    } catch { log('WARN', '无法自动打开浏览器，请手动打开 ' + url); }
  }
  function spawnDetached(cmd, args) {
    const { spawn } = require('node:child_process');
    const child = spawn(cmd, args, { detached: true, stdio: 'ignore', windowsHide: true });
    child.on('error', () => { /* Linux 没有 xdg-open 时不要因为未处理的 error 崩服务 */ });
    child.unref();
  }
  /** 第二个实例只打开管理页就退出；先关掉日志流，否则 Windows 上可能一直挂着。 */
  function finishAlreadyRunning(url) {
    if (url && opt.open !== false) openBrowser(url);
    try { if (logStream) { logStream.end(); logStream = null; } } catch { /* noop */ }
  }
  if (opt.open !== false) openBrowser(adminUrl);

  let stopping = false;
  function cleanupFiles() {
    try {
      const cur = readInstance();
      if (!cur || Number(cur.pid) === process.pid) fs.rmSync(INSTANCE, { force: true });
    } catch { /* noop */ }
    try {
      if (Number(fs.readFileSync(PID_FILE, 'utf8')) === process.pid) fs.rmSync(PID_FILE, { force: true });
    } catch { /* noop */ }
  }
  /** 门禁/嵌入用：停监听、清定时器、落盘，但**不**结束进程（shutdown 才 exit）。 */
  async function close() {
    updateClosed = true;
    if (updateTimer) { clearTimeout(updateTimer); updateTimer = null; }
    if (updateRetryTimer) { clearTimeout(updateRetryTimer); updateRetryTimer = null; }
    clearInterval(statsInterval);
    clearInterval(pruneTimer);
    clearInterval(queueClean);
    clearInterval(securityGc);
    if (statsTimer) clearTimeout(statsTimer);
    if (expandTimer) clearTimeout(expandTimer);
    try { flushStats(true); } catch { /* noop */ }
    try { saveCreds(); } catch { /* noop */ }
    try { saveExpand(); } catch { /* noop */ }
    try { saveSecurity(); } catch { /* noop */ }
    try { httpSrv.close(); } catch { /* noop */ }
    try { if (httpsSrv) httpsSrv.close(); } catch { /* noop */ }
    try { httpSrv.closeAllConnections && httpSrv.closeAllConnections(); } catch { /* noop */ }
    try { if (httpsSrv && httpsSrv.closeAllConnections) httpsSrv.closeAllConnections(); } catch { /* noop */ }
    await new Promise((resolve) => {
      let done = false;
      const fin = () => { if (!done) { done = true; resolve(); } };
      try { srv.close(fin); } catch { fin(); }
      setTimeout(fin, 1500).unref();
    });
    try { if (logStream) { logStream.end(); logStream = null; } } catch { /* noop */ }
  }
  function shutdown(reason) {
    if (stopping) return;
    stopping = true;
    log('INFO', `收到关闭请求（${reason}），正在停止…`);
    cleanupFiles();
    close().finally(() => setTimeout(() => process.exit(0), 50).unref());
    setTimeout(() => process.exit(0), 2000).unref();
  }
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGHUP', () => shutdown('SIGHUP'));
  process.on('exit', () => { try { flushStats(true); } catch { /* noop */ } try { saveExpand(); } catch { /* noop */ } try { saveSecurity(); } catch { /* noop */ } cleanupFiles(); });
  process.on('uncaughtException', (e) => { log('ERROR', '未捕获异常：' + String(e && e.stack || e).slice(0, 500)); });
  process.on('unhandledRejection', (e) => { log('ERROR', '未处理 Promise：' + String(e && e.stack || e).slice(0, 500)); });

  return { srv, port, dataDir: DATA, stats: () => buildStats(), shutdown, close };
}

/** 源运行时：`node server.mjs` 直接启动。单文件由 sea-main.mjs 调用 startServer，不能在这里重复启动。 */
const isMain = !IS_SEA && !!SELF_FILE && !!process.argv[1] && path.resolve(process.argv[1]) === path.resolve(SELF_FILE);
if (isMain) {
  startServer({ argv: process.argv.slice(2) }).catch((e) => {
    console.error('FWArmy 启动失败：', e && e.stack || e);
    process.exit(1);
  });
}
