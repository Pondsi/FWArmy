/**
 * FWArmy 中转服务器（独立程序）—— 撮合 + 转发，**不存消息**。
 *
 * 产品名：FWArmy（用户也会写成 FWAmry / fwamry，均指同一程序；目录固定为 fwarmy/）。
 * 本文件既是 `node server.mjs` 的源运行入口，也会被打包进单文件 `FWArmy.exe`（Node SEA）。
 *
 * 管理面（只允许本机回环访问，打开即用、无需登录）：
 *   GET  / 或 /admin                    自包含管理页（无外部资源）
 *   GET  /api/admin/stats[?limit=&offset=]   总统计 + 按凭据统计（日/月/年/速度/峰值；凭据分页默认 200/页、上限 5000、新凭据在前）
 *   GET  /api/admin/credentials[?limit=&offset=]   凭据列表（分页同上）
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
import { Readable, Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { promisify } from 'node:util';
import {
  DhtJieDian,
  DHT_PROTOCOL,
  DEFAULT_DHT_PORT,
  DEFAULT_RECORD_TTL_MS,
  DHT_REFRESH_MS,
  PUBLIC_DISCOVERY_KEY,
  base32,
  guiFanAnChors,
  jieXiDhtDiZhi,
  jiLuJian,
  warmyZhiWen,
} from './dht.mjs';

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
export const VERSION = '0.7.32';

/** R153：内置公用中继凭据——所有 FWArmy 出厂默认携带，明文显示在管理页（点击可查看完整/复制）；其余自创凭据仍只存 sha256 不可回看。 */
const BUILTIN_CREDENTIALS = [
  { name: '公用', token: 'KuEfbuByYXqyXARdlPyiFL1K_GXPy7PvAeJtUYdOLdM' },
  { name: '公用1', token: 'wdSmhiYs_d89z3l5HU1kj5q2qqsQsKTCrJAngl5Bafc' },
];
export const PRODUCT = 'FWArmy';

const TTL_MS = 30_000;
/** 上游一次投递的总预算：超过 8 秒即判失败，只在内存里试下一个网关，不落盘、不排队重试。 */
export const UPSTREAM_TIMEOUT_MS = 8_000;
/** 同一 messageId 在 24h 内最多被本实例转发/投递 2 次；第 3 次与超 24h 都进黑名单。 */
export const MESSAGE_WINDOW_MS = 24 * 60 * 60 * 1000;
/** 黑名单条目 30 天没有再次出现就自动清理。 */
export const BLACKLIST_TTL_MS = 30 * 24 * 60 * 60 * 1000;
/**
 * 重放闸/转圈防护（用户拍板口径，R123）：
 * 同一 messageId（消息头）24h 内最多放行 2 次（第 1 次正常投递 + 第 2 次容忍重复/补发/首轮转圈）；
 * 第 3 次出现 ⇒ 直接丢弃并**写黑名单**——黑名单键就是该消息（msgId 哈希），不是来源/IP；
 * 只要 msgId 相同即视为同一条消息；拉黑后 30 天内该消息直接拒绝（重启仍生效）。
 * 首次出现已超过 24h ⇒ 老消息重放，同样丢弃 + 写黑名单。
 * 不限制转发跳数（防环靠本闸 + route 含本站即 409；MAX_ROUTE 只是报文尺寸上限）。
 */
export const REPLAY_MAX_PASSES = 2;
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
/** F中继（被扩网）凭据默认端口（R133 用户拍板：扩网默认 58588）。 */
const EXPAND_DEFAULT_PORT = 58588;
/** 中继页业务凭据默认端口（R133 用户拍板：中继默认 59599）。 */
const CRED_DEFAULT_PORT = 59599;
/** 默认业务监听端口列表（R147：管理入口 8787 + 中继 59599 + 扩网 58588——R142 曾加 TCP 443/62666，用户拍板移除：443 TCP 通常被占且无业务必要，62666 只需 UDP DHT）。 */
const DEFAULT_PORTS = [8787, CRED_DEFAULT_PORT, EXPAND_DEFAULT_PORT];
/** R142 的过渡默认（含 TCP 443/62666）：恰等于它的配置自动回退到 3 个默认端口（用户自定义过的端口列表不动）。 */
const R142_DEFAULT_PORTS = [8787, CRED_DEFAULT_PORT, EXPAND_DEFAULT_PORT, 443, 62666];
/** 内置引导锚点（R151 用户拍板：dht/dht2.numumu.com × 443/62666 共 4 个；443 为默认端口可省略；剥协议取主机）。 */
const DEFAULT_ANCHORS = ['dht.numumu.com', 'dht.numumu.com:62666', 'dht2.numumu.com', 'dht2.numumu.com:62666'];
/** 管理页语言白名单（R138：与 admin.html LANGS 27 项一致；选择持久化到 config.json.lang）。 */
const UI_LANGS = ['zh-CN', 'zh-TW', 'en-US', 'ja', 'ko', 'ru', 'es', 'fr', 'pt', 'eo', 'de', 'it', 'nl', 'pl', 'sv', 'cs', 'hu', 'da', 'nb', 'tr', 'uk', 'id', 'vi', 'th', 'hi', 'ar', 'fa'];
/** 手动对外地址的验证周期：验证通过才用于宣告，失效自动回退自动推断。 */
const MANUAL_ADDR_CHECK_MS = 5 * 60_000;
/** 无凭据来源（未配对）的 /api/expand/relay 请求按来源 IP 限速（防滥用 §9：直接丢弃 + 限速）。 */
const UNAUTH_RATE_PER_MIN = 30;
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
  /**
   * DHT 发现（默认强制开启，只做设备发现，消息仍走凭据通道）：
   *  - udpPorts 监听端口列表（默认 443 与 62666；测试可用 FWARMY_DHT_PORTS 覆盖）；
   *  - addresses 手动对外地址列表 [{host, port, enabled}]（每条验证通过才宣告，失效自动回退）；
   *  - anchors 引导节点列表（默认内置 6 个：DHT/DHT2/numumu × 443/62666；可手动追加）；
   *  - routeByDht：投递失败时用 DHT 定位目标所在中继站，优先转发给已配置互信的匹配 peer；
   *  - retryBaseMs 为内部字段（config.json 可写，管理页不暴露）：锚点引导失败后的退避基值。
   */
  dht: { enabled: true, udpPorts: [443, 62666], addresses: [], anchors: [], routeByDht: true, retryBaseMs: 1000 },
  ports: DEFAULT_PORTS, // R133 多业务端口：默认监听 59599（中继）+ 58588（扩网）；不再自动顺延
  // R135g 附加内容库（会话提示消息）：最多 1000 条纯文字；每条中继凭据可绑定模式（关/随机/顺序/按比例）
  addition: { texts: [] },
  // 自动重启定时器：到点自动重启进程；重启后按 intervalHours 重算下次时间（nextAt = epoch ms，0=未设置）
  autorestart: { enabled: false, intervalHours: 24, nextAt: 0 },
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
/** R162：Ed25519 公钥对象缓存——poll/register/heartbeat/来源验签每请求 createPublicKey 解析公钥，
 * 高频轮询下是热路径；公钥是公开数据、KeyObject 不可变，缓存无安全影响；上限淘汰最旧防内存无界。 */
const ED_PUB_CACHE = new Map();
const ED_PUB_CACHE_MAX = 50_000;
const edPub = (b64) => {
  const k = String(b64 || '');
  let o = ED_PUB_CACHE.get(k);
  if (!o) {
    o = crypto.createPublicKey({ key: Buffer.concat([ED_PREFIX, Buffer.from(k, 'base64')]), format: 'der', type: 'spki' });
    if (ED_PUB_CACHE.size >= ED_PUB_CACHE_MAX) {
      const oldest = ED_PUB_CACHE.keys().next().value;
      if (oldest !== undefined) ED_PUB_CACHE.delete(oldest);
    }
    ED_PUB_CACHE.set(k, o);
  }
  return o;
};
const xPub = (b64) => crypto.createPublicKey({ key: Buffer.concat([X_PREFIX, Buffer.from(String(b64), 'base64')]), format: 'der', type: 'spki' });
const sha = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');
/** Buffer/字符串 → sha256 hex（哈希链审计用）。 */
const sha256Hex = (s) => crypto.createHash('sha256').update(s).digest('hex');
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
 * R162：off/verify/inspect 走 http(s).request + keepAlive agent 池（复用 TCP+TLS 连接）；
 * **pin 模式走 rawHttpPin（每次新连接，TLS 握手后校验指纹再发送）**——实测 Node 在
 * rejectUnauthorized=false 时完全不调用 checkServerIdentity，若 pin 也用 agent 池会复用连接跳过校验（安全回归）。
 * 返回 {status, headers, text, json, fingerprint, secure, ms}。
 */
const OUTBOUND_AGENTS = new Map(); // key → { agent, fingerprint }
const OUTBOUND_AGENT_MAX = 32;
const OUTBOUND_CA_CACHE = new Map(); // caFile 路径 → Buffer | null
function outboundAgentKey(o) {
  const t = o.tls || {};
  return `${t.mode || 'off'}|${Number(o.port) || 80}|${String(o.host)}|${t.servername || ''}|${t.caFile || ''}`;
}
async function rawHttpRequest(o) {
  const mode = o.tls && o.tls.mode ? o.tls.mode : 'off';
  if (mode === 'pin') return rawHttpPin(o);
  return rawHttpPool(o);
}
/** pin 模式：每次新连接——TLS 握手完成、指纹吻合后才发送任何字节（含 Authorization）。 */
async function rawHttpPin(o) {
  const t0 = Date.now();
  const host = String(o.host || '');
  const port = Number(o.port) || 80;
  const timeoutMs = Math.max(100, Number(o.timeoutMs) || UPSTREAM_TIMEOUT_MS);
  const body = Buffer.from(String(o.body ?? ''), 'utf8');
  const headers = { host: `${host.includes(':') ? `[${host}]` : host}:${port}`, 'content-type': 'application/json', 'content-length': String(body.length), connection: 'close', ...(o.headers || {}) };
  const want = String(o.tls.fingerprint || '').toLowerCase();
  let fingerprint = '';
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
    const opt = {
      host, port, minVersion: 'TLSv1.2', rejectUnauthorized: false,
      servername: (o.tls && o.tls.servername) || (isIp(host) ? undefined : host),
    };
    if (o.tls && o.tls.caFile) {
      let ca = OUTBOUND_CA_CACHE.get(o.tls.caFile);
      if (ca === undefined) { try { ca = fs.readFileSync(o.tls.caFile); } catch { ca = null; } OUTBOUND_CA_CACHE.set(o.tls.caFile, ca); }
      if (ca) opt.ca = ca;
    }
    const socket = tls.connect(opt);
    socket.once('error', (e) => finish(e));
    socket.once('secureConnect', () => {
      try {
        const peer = socket.getPeerCertificate();
        fingerprint = peer && peer.raw ? crypto.createHash('sha256').update(peer.raw).digest('hex') : '';
        if (!want) return finish(new Error('fingerprint-required'));
        if (fingerprint !== want) return finish(new Error('fingerprint-mismatch'));
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
        finish(null, { status, headers: hdrs, text, json, fingerprint, secure: true, ms: Date.now() - t0 });
      });
    }
  });
}
/** off/verify/inspect 模式：http(s).request + keepAlive agent 池（Node 系统 CA 校验，复用安全）。 */
async function rawHttpPool(o) {
  const t0 = Date.now();
  const host = String(o.host || '');
  const port = Number(o.port) || 80;
  const timeoutMs = Math.max(100, Number(o.timeoutMs) || UPSTREAM_TIMEOUT_MS);
  const body = Buffer.from(String(o.body ?? ''), 'utf8');
  const headers = { host: `${host.includes(':') ? `[${host}]` : host}:${port}`, 'content-type': 'application/json', 'content-length': String(body.length), ...(o.headers || {}) };
  const mode = o.tls && o.tls.mode ? o.tls.mode : 'off';
  const secure = mode !== 'off';
  const key = outboundAgentKey(o);
  let ent = OUTBOUND_AGENTS.get(key);
  if (!ent) {
    const agentOpts = { keepAlive: true, maxSockets: 8, maxTotalSockets: 64, keepAliveMsecs: 2000 };
    const agent = secure ? new https.Agent(agentOpts) : new http.Agent(agentOpts);
    if (OUTBOUND_AGENTS.size >= OUTBOUND_AGENT_MAX) {
      const k0 = OUTBOUND_AGENTS.keys().next().value;
      if (k0 !== undefined) OUTBOUND_AGENTS.delete(k0);
    }
    ent = { agent, fingerprint: '' };
    OUTBOUND_AGENTS.set(key, ent);
  }
  const lib = secure ? https : http;
  return await new Promise((resolve, reject) => {
    let fp = ent.fingerprint;
    const reqOpts = {
      host, port, method: o.method || 'GET', path: o.path || '/', headers, agent: ent.agent, timeout: timeoutMs,
    };
    if (secure) {
      reqOpts.minVersion = 'TLSv1.2';
      reqOpts.rejectUnauthorized = mode === 'verify';
      reqOpts.servername = (o.tls && o.tls.servername) || (isIp(host) ? undefined : host);
      if (o.tls && o.tls.caFile) {
        let ca = OUTBOUND_CA_CACHE.get(o.tls.caFile);
        if (ca === undefined) { try { ca = fs.readFileSync(o.tls.caFile); } catch { ca = null; } OUTBOUND_CA_CACHE.set(o.tls.caFile, ca); }
        if (ca) reqOpts.ca = ca;
      }
    }
    const req = lib.request(reqOpts, (res) => {
      const bu = []; let n = 0;
      res.on('data', (d) => {
        n += d.length;
        if (n > 512 * 1024) { req.destroy(new Error('response-too-large')); return; }
        bu.push(d);
      });
      res.on('end', () => {
        ent.fingerprint = fp || ent.fingerprint;
        const text = Buffer.concat(bu).toString('utf8');
        let json = null;
        try { json = JSON.parse(text); } catch { /* 非 JSON */ }
        resolve({ status: res.statusCode, headers: res.headers, text, json, fingerprint: fp, secure, ms: Date.now() - t0 });
      });
    });
    if (secure) {
      req.on('socket', (sock) => {
        if (sock && sock.encrypted) sock.once('secureConnect', () => {
          try { fp = crypto.createHash('sha256').update(sock.getPeerCertificate().raw).digest('hex'); } catch { /* noop */ }
        });
      });
    }
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', (e) => reject(e));
    if (body.length) req.write(body);
    req.end();
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
  const o = { port: 8787, host: '0.0.0.0', open: null, data: '', quiet: false, logFile: '', portExplicit: false, noTray: false };
  for (const a of argv) {
    if (a.startsWith('--port=')) { o.port = Number(a.slice(7)); o.portExplicit = true; }
    else if (a.startsWith('--host=')) o.host = a.slice(7) || '0.0.0.0';
    else if (a.startsWith('--data=')) o.data = a.slice(7);
    else if (a.startsWith('--log-file=')) o.logFile = a.slice(11);
    else if (a === '--open') o.open = true;
    else if (a === '--no-open' || a === '--headless') o.open = false;
    else if (a === '--quiet') o.quiet = true;
    else if (a === '--no-tray') o.noTray = true; // R135y：禁用系统托盘（无桌面/CI/服务场景）
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

function writeJsonAtomic(file, obj, mode = 0o600, compact = false) {
  const tmp = `${file}.${process.pid}.${crypto.randomBytes(3).toString('hex')}.tmp`;
  fs.writeFileSync(tmp, compact ? JSON.stringify(obj) : JSON.stringify(obj, null, 2), { encoding: 'utf8', mode });
  try {
    fs.renameSync(tmp, file);
  } catch (e) {
    // 失败绝不删除唯一旧副本：清掉临时文件并如实抛错，旧配置/凭据保持可读。
    try { fs.rmSync(tmp, { force: true }); } catch { /* noop */ }
    throw e;
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
    stats: { inbound: emptySide(), outbound: emptySide(), perOutbound: {}, perSource: {}, perInbound: {} },
  };
}
function normInbound(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const hash = String(raw.hash || raw.tokenHash || '');
  if (!/^[0-9a-f]{64}$/.test(hash)) return null;
  const port = Number(raw.port);
  const tail5 = String(raw.tail5 || '').slice(0, 5);
  return {
    id: String(raw.id || crypto.randomUUID()),
    name: String(raw.name || '接入凭据').slice(0, 40),
    hash,
    tail5, // R150：明文末尾 5 位（人可对账）；旧数据无则回退哈希尾 5
    masked: tail5 ? '…' + tail5 : ('…' + hash.slice(30, 35) + '…' + hash.slice(-5)),
    port: Number.isInteger(port) && port >= 1 && port <= 65535 ? port : 0,
    addr: String(raw.addr || '').slice(0, 253),
    createdAt: Number(raw.createdAt) || 0,
    lastAt: Number(raw.lastAt) || 0,
    lastResult: String(raw.lastResult || '').slice(0, 120),
    disabled: raw.disabled === true,
    limits: raw.limits && typeof raw.limits === 'object' ? normLimitsStored(raw.limits) : null,
    expiresAt: Number(raw.expiresAt) > 0 ? Number(raw.expiresAt) : 0,
  };
}
function normLimitsStored(raw) {
  const out = {};
  for (const k of LIMIT_KEYS) {
    const v = raw[k];
    out[k] = v === null || v === undefined ? null : (typeof v === 'number' && validLimit(k, v) ? v : null);
  }
  return out;
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
/** 端口列表归一化：去重/去非法/上限；空列表回默认。用于业务监听端口与 DHT UDP 端口。 */
function normPorts(raw, def = DEFAULT_PORTS, max = 16) {
  const list = Array.isArray(raw) ? raw : [];
  const out = [];
  const seen = new Set();
  for (const p of list) {
    const n = Math.floor(Number(p));
    if (!Number.isInteger(n) || n < 1 || n > 65535 || seen.has(n)) continue;
    seen.add(n);
    out.push(n);
    if (out.length >= max) break;
  }
  return out.length ? out : [...def];
}
/** 手动对外地址列表归一化：{host, port, enabled}；兼容 'host:port' 字符串（管理页 UI 提交格式）；去重/去非法/上限 16。 */
function normAddrList(raw) {
  const list = Array.isArray(raw) ? raw : [];
  const out = [];
  const seen = new Set();
  for (const x of list) {
    let o = x;
    if (typeof x === 'string') {
      const s = String(x).trim();
      const i = s.lastIndexOf(':');
      if (i <= 0 || !/^\d{1,5}$/.test(s.slice(i + 1)) || /[\s/?#]/.test(s.slice(0, i))) continue;
      o = { host: s.slice(0, i), port: Number(s.slice(i + 1)) };
    }
    const obj = o && typeof o === 'object' ? o : {};
    const host = String(obj.host || '').trim().slice(0, 253);
    const port = Math.floor(Number(obj.port));
    if (!host || /[\s/?#]/.test(host) || !Number.isInteger(port) || port < 1 || port > 65535) continue;
    const key = `${host}|${port}`.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ host, port, enabled: obj.enabled !== false, manual: true });
    if (out.length >= 16) break;
  }
  return out;
}

/* ── R135g 附加内容（会话提示消息）：纯文字校验 / 库归一化 / 凭证级模式 ── */
const ADDITION_MAX_TEXTS = 1000;
const ADDITION_MAX_BYTES = 120; // R135t：按 WArmy 一行参考收紧（CJK≈30 字 / Latin≈60 字符，120B 覆盖两者）
/** 附加内容必须纯文字：可打印文本、无控制字符（允许 \t）、无 HTML 特殊字符、长度 ≤ 512 字节（一行）。 */
function validAdditionText(s) {
  if (typeof s !== 'string') return false;
  if (Buffer.byteLength(s, 'utf8') > ADDITION_MAX_BYTES) return false;
  if (/[\x00-\x08\x0A-\x1F\x7F]/.test(s)) return false; // 控制字符（\t=\x09 允许，换行/回车不允许）
  if (/[<>&"']/.test(s)) return false; // HTML 特殊字符（渲染层无法被利用）
  return s.trim().length > 0;
}
/** UTF-8 字节安全截断（不切半个多字节字符；尾部替换符清掉）。 */
function truncateUtf8Bytes(s, maxBytes) {
  const buf = Buffer.from(String(s), 'utf8');
  if (buf.length <= maxBytes) return String(s);
  return buf.subarray(0, maxBytes).toString('utf8').replace(/[\uFFFD]+$/, '') || '';
}
/** 附加内容库归一化：超长强制截断到 120 字节（R135v，不再丢弃），HTML/控制字符仍过滤，去重，上限 1000。 */
function normAdditionTexts(raw) {
  const list = Array.isArray(raw) ? raw : [];
  const out = [];
  const seen = new Set();
  for (const x of list) {
    let s = String(x || '').trim().slice(0, ADDITION_MAX_BYTES + 16);
    if (Buffer.byteLength(s, 'utf8') > ADDITION_MAX_BYTES) s = truncateUtf8Bytes(s, ADDITION_MAX_BYTES).trim();
    if (!validAdditionText(s) || seen.has(s)) continue;
    seen.add(s);
    out.push(s);
    if (out.length >= ADDITION_MAX_TEXTS) break;
  }
  return out;
}
/** 全角数字/标点 → 半角（中文用户输入兼容：１２３ → 123，：，； → :,;） */
function toHalfWidth(s) {
  return String(s || '')
    .replace(/[０-９]/g, (c) => String.fromCharCode(c.charCodeAt(0) - 0xFEE0))
    .replace(/[：]/g, ':').replace(/[，；]/g, ',');
}
/** 凭证级附加内容配置：{mode: off|random|sequence|weighted, weights: {序号: 权重}}；weights 空 = 全部条目等权；有权重表时仅列出的条目参与（未列出 = 不使用）。 */
function normCredAddition(raw) {
  if (raw === undefined || raw === null) return null;
  const o = raw && typeof raw === 'object' && !Array.isArray(raw) ? raw : {};
  const mode = ['off', 'random', 'sequence', 'weighted'].includes(o.mode) ? o.mode : 'off';
  const weights = {};
  if (o.weights && typeof o.weights === 'object' && !Array.isArray(o.weights)) {
    for (const k of Object.keys(o.weights)) {
      const key = toHalfWidth(k);
      const idx = Math.floor(Number(key));
      const w = Number(toHalfWidth(o.weights[k]));
      if (/^\d+$/.test(key.trim()) && Number.isInteger(idx) && idx >= 1 && idx <= ADDITION_MAX_TEXTS && Number.isFinite(w) && w >= 0) weights[String(idx)] = Math.floor(w);
    }
  }
  return { mode, weights };
}
function normDhtCfg(raw) {
  const d = DEFAULTS.dht;
  const t = raw && typeof raw === 'object' ? raw : {};
  let udpPorts = normPorts(t.udpPorts, d.udpPorts, 8);
  if (!Array.isArray(t.udpPorts) || !t.udpPorts.length) {
    // config 未显式配置时，允许环境变量覆盖（测试/特殊环境）
    const envPorts = String(process.env.FWARMY_DHT_PORTS || '').split(/[, ]+/).map(Number)
      .filter((x) => Number.isInteger(x) && x >= 1 && x <= 65535);
    if (envPorts.length) udpPorts = envPorts;
  }
  return {
    enabled: true, // R129 拍板：DHT 强制开启（使用 FWArmy 就必须进网），配置不再接受关闭
    udpPorts,
    pausedUdpPorts: normPorts(t.pausedUdpPorts, [], 8), // R135：暂停的 UDP 端口仍保留配置，只停监听
    addresses: normAddrList(t.addresses),
    pausedAuto: Array.isArray(t.pausedAuto)
      ? [...new Set(t.pausedAuto.map((x) => String(x || '').trim()).filter((s) => /^(IPv4|IPv6)\|\d+$/.test(s)))]
      : [], // R135：暂停的自动兜底维度（如 'IPv6|59599'），全停后定时自检自启
    anchors: guiFanAnChors(t.anchors),
    routeByDht: t.routeByDht !== false,
    retryBaseMs: Math.max(200, Math.min(60_000, Number(t.retryBaseMs) || d.retryBaseMs)),
  };
}
export function expandBaseUrl(p) {
  return `http://${String(p.host).includes(':') ? `[${p.host}]` : p.host}:${p.port}`;
}
/**
 * 凭证 v2 自带地址：fwnexp_v2_<b64url(JSON{h,p,r})>，拿到凭证即可连接，无需再填域名/端口。
 * 旧格式（fwnexp_<随机>）不带地址，仍可验证，但添加扩网时需手填地址。
 */
export function parseExpandToken(token) {
  const t = String(token || '').trim();
  if (!t.startsWith('fwnexp_v2_')) return null;
  try {
    const j = JSON.parse(Buffer.from(t.slice('fwnexp_v2_'.length), 'base64url').toString('utf8'));
    const host = String(j.h || '').trim();
    const port = Number(j.p);
    if (!host || /[\s/?#]/.test(host) || !Number.isInteger(port) || port < 1 || port > 65535) return null;
    return { host, port };
  } catch { return null; }
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

/** R160：IPv4/IPv6 字面量校验与文本提取（公网 IP 探测用；模块级便于门禁单测）。 */
export const isV4 = (s) => { const p = String(s).split('.'); return p.length === 4 && p.every((x) => x !== '' && !isNaN(Number(x)) && Number(x) >= 0 && Number(x) <= 255); };
export const isV6 = (s) => /^[0-9a-fA-F:]+$/.test(String(s)) && String(s).includes(':') && !isV4(s);
export function extractIpFromText(txt, family) {
  const s = String(txt || '');
  if (family === 4) {
    const m = s.match(/(\d{1,3}(?:\.\d{1,3}){3})/);
    return m && isV4(m[1]) ? m[1] : '';
  }
  const m = s.match(/([0-9a-fA-F]{1,4}:){2,}[0-9a-fA-F]{1,4}/);
  return m && isV6(m[0]) ? m[0] : '';
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
  const IMPORT_CRED_FILE = path.join(DATA, 'import-credentials.txt'); // R153：每行一个 token，启动自动导入并删除
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
  if (options.port) opt.portExplicit = true;
  /** 安全判定（24h 窗口/30 天黑名单）用可注入时钟，门禁才能跑“一天后/三十天后”；队列 TTL 仍用真实时间。 */
  const now = () => (typeof options.clock === 'function' ? Number(options.clock()) : Date.now());

  fs.mkdirSync(DATA, { recursive: true });
  fs.mkdirSync(path.dirname(LOG), { recursive: true });
  // 先声明日志句柄（真正打开在拿到锁之后），锁失败路径才能安全收尾。
  let logStream = null;
  let logLines = 0;

  // ── 数据目录级原子单实例锁：必须在任何数据文件写入之前拿到（F07）。──
  const LOCK = path.join(DATA, 'fwarmy.lock');
  const dataDirHash = (() => {
    try { return crypto.createHash('sha256').update(fs.realpathSync(DATA)).digest('hex').slice(0, 16); }
    catch { return crypto.createHash('sha256').update(DATA).digest('hex').slice(0, 16); }
  })();
  function procAlive(pid) {
    const n = Number(pid) || 0;
    if (!n) return false;
    if (n === process.pid) return true;
    try { process.kill(n, 0); return true; } catch (e) { return !!(e && e.code === 'EPERM'); }
  }
  function readLock() { try { return JSON.parse(fs.readFileSync(LOCK, 'utf8')); } catch { return null; } }
  let lockOwned = false;
  function releaseLock() {
    if (!lockOwned) return;
    lockOwned = false;
    try {
      const cur = readLock();
      if (!cur || Number(cur.pid) === process.pid) fs.rmSync(LOCK, { force: true });
    } catch { /* noop */ }
  }
  function acquireLock() {
    for (let i = 0; i < 2; i++) {
      try {
        const fd = fs.openSync(LOCK, 'wx');
        fs.writeSync(fd, JSON.stringify({ pid: process.pid, startedAt: Date.now(), dataDirHash }));
        fs.closeSync(fd);
        lockOwned = true;
        return true;
      } catch (e) {
        if (!e || e.code !== 'EEXIST') return false;
        const cur = readLock();
        if (cur && procAlive(cur.pid) && Number(cur.pid) !== process.pid) return false;
        try { fs.rmSync(LOCK, { force: true }); } catch { /* 再试一次 */ }
      }
    }
    return false;
  }
  /** 记录启动前已有文件；启动失败时只清掉本轮新建的，绝不碰既有数据。 */
  const preExisting = new Set(fs.existsSync(DATA) ? fs.readdirSync(DATA) : []);
  function cleanupNewFiles() {
    try { if (logStream) { logStream.end(); logStream = null; } } catch { /* noop */ }
    try {
      for (const name of fs.readdirSync(DATA)) {
        if (preExisting.has(name)) continue;
        try { fs.rmSync(path.join(DATA, name), { recursive: true, force: true }); } catch { /* noop */ }
      }
    } catch { /* noop */ }
    releaseLock();
  }
  /** 端口上的 FWArmy 是否就是本数据目录的实例（F07 边角：陈旧 instance.json 不能把别人的实例当成自己的）。 */
  const isSameInstance = (h, instRec) => {
    if (!h || (h.server !== 'fwarmy-relay' && h.server !== 'warmy-relay')) return false;
    if (h.dataDirHash) return h.dataDirHash === dataDirHash;
    // 旧版健康响应没有 dataDirHash：只有本目录 instance.json 也无记录时按升级兼容信任
    return !(instRec && instRec.dataDirHash);
  };
  if (!acquireLock()) {
    const cur = readLock();
    const inst0 = (() => { try { return JSON.parse(fs.readFileSync(INSTANCE, 'utf8')); } catch { return null; } })();
    if (inst0 && inst0.port) {
      const alive0 = await probe(inst0.port);
      if (isSameInstance(alive0, inst0)) {
        const scheme0 = inst0.scheme || (alive0.secure ? 'https' : 'http');
        process.stdout.write(`已有 FWArmy 在运行 pid=${inst0.pid || '?'} port=${inst0.port}；本次只打开管理页\n`);
        finishAlreadyRunning(`${scheme0}://127.0.0.1:${inst0.port}/`);
        return { alreadyRunning: true, port: inst0.port, dataDir: DATA };
      }
    }
    throw new Error(`数据目录 ${DATA} 的单实例锁被进程 ${cur && cur.pid || '?'} 占用，但探不到健康服务；等它退出或删除 fwarmy.lock 后重试`);
  }

  // ── 日志（写文件 + 终端；绝不写消息明文/凭据明文）──
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
  if (logStream) logStream.on('error', () => { try { logStream && logStream.end(); } catch { /* noop */ } logStream = null; });
  let logDropped = 0;
  function log(level, msg) {
    const line = `${new Date().toISOString()} ${String(level).padEnd(5)} ${msg}\n`;
    if (!opt.quiet) { try { process.stdout.write(line); } catch { /* noop */ } }
    if (logStream) {
      try {
        if (logLines % 256 === 0) rotateLog(); // 运行中轮转（每 256 行查一次大小，避免每行 stat）
        if (logStream.writableLength > 4 * 1024 * 1024) { logDropped++; return; } // 背压：丢弃并计数，防内存无界
        logStream.write(line);
        logLines++;
      } catch { /* noop */ }
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
  /** 返回是否落盘成功；失败只记日志、不抛出（后台调用点安全），管理接口必须检查返回值。 */
  /** R161：聚合缓存（buildStats 用；结构性变更 saveCreds/saveCfg 时失效——声明在二者之前避免 TDZ）。 */
  let statsAggCache = new Map(); // "offset:limit" → { at, out }
  function saveCreds() {
    statsAggCache.clear();
    try {
      writeJsonAtomic(CK, { items: creds });
      return true;
    } catch (e) { log('WARN', '写 credentials.json 失败：' + (e && e.message || e)); return false; }
  }
  if (migrated) saveCreds();

  let hashIndex = new Map();
  function rebuildIndex() {
    hashIndex = new Map();
    for (const c of Object.values(creds)) if (c.hash) hashIndex.set(c.hash, c);
  }
  rebuildIndex();

  // ── R153：内置公用凭据（出厂默认携带；明文展示；名称按首次创建时的界面语言生成，之后固定）──
  /** 语言 → 公用/公用1 名称（首次创建时按当前界面语言生成；之后更换语言不再变）。 */
  const BUILTIN_NAMES = {
    'zh-CN': ['公用', '公用1'], 'zh-TW': ['公用', '公用1'], 'en-US': ['Public', 'Public 1'],
    ja: ['パブリック', 'パブリック 1'], ko: ['공용', '공용 1'], ru: ['Общий', 'Общий 1'],
    es: ['Público', 'Público 1'], fr: ['Public', 'Public 1'], pt: ['Público', 'Público 1'],
    eo: ['Publika', 'Publika 1'], de: ['Gemeinsam', 'Gemeinsam 1'], it: ['Pubblico', 'Pubblico 1'],
    nl: ['Openbaar', 'Openbaar 1'], pl: ['Publiczny', 'Publiczny 1'], sv: ['Gemensam', 'Gemensam 1'],
    cs: ['Veřejný', 'Veřejný 1'], hu: ['Közös', 'Közös 1'], da: ['Fælles', 'Fælles 1'],
    nb: ['Felles', 'Felles 1'], tr: ['Ortak', 'Ortak 1'], uk: ['Загальний', 'Загальний 1'],
    id: ['Publik', 'Publik 1'], vi: ['Chung', 'Chung 1'], th: ['สาธารณะ', 'สาธารณะ 1'],
    hi: ['साझा', 'साझा 1'], ar: ['عام', 'عام 1'], fa: ['عمومی', 'عمومی 1'],
  };
  function builtinNamesFor(lang) {
    const list = BUILTIN_NAMES[String(lang || '')] || BUILTIN_NAMES['zh-CN'];
    return list;
  }
  /** 确保内置公用凭据存在（按首次创建时的语言生成名称，之后不因换语言改名）。
   * R154b：内置带端点（默认本机公网 IP:59599）与保守限速限量；已存在的旧内置条目补齐缺字段。 */
  const BUILTIN_LIMITS = {
    ratePerMin: 60, bytesPerMin: 10 * 1048576,       // 每分钟 60 次 / 10MB
    dailyRequests: 5000, dailyBytes: 500 * 1048576,  // 每日 5000 次 / 500MB
    monthlyRequests: 50000, monthlyBytes: 5 * 1073741824, // 每月 5 万次 / 5GB
    totalRequests: null, totalBytes: null, yearlyBytes: 50 * 1073741824, // 总量不限；每年 50GB
  };
  function ensureBuiltinCredentials(langHint) {
    let changed = false;
    const names = builtinNamesFor(langHint || cfg.lang);
    let host = '';
    try { host = activeExternalAddr().host; } catch { host = ''; }
    // R157：判断地址是否本机网卡地址（创建时探测未完成会填本地 IP，探测完成后修正为公网）
    const isLocalAddr = (h) => {
      try { return localAddresses().some((a) => String(a.address).toLowerCase() === String(h || '').toLowerCase()); } catch { return false; }
    };
    for (let i = 0; i < BUILTIN_CREDENTIALS.length; i++) {
      const b = BUILTIN_CREDENTIALS[i];
      const hash = sha(b.token);
      const existing = hashIndex.get(hash);
      if (existing) {
        // R154b：升级兼容——已存在的内置条目补齐端点/限额（首次创建时可能没有这些字段）
        if (!existing.host || !existing.port || !existing.limits) {
          existing.host = existing.host || host;
          existing.port = existing.port || CRED_DEFAULT_PORT;
          existing.limits = existing.limits || { ...BUILTIN_LIMITS };
          changed = true;
          log('INFO', `内置公用凭据已补齐端点/限额：${existing.name} → ${existing.host}:${existing.port}`);
        } else if (existing.host && isLocalAddr(existing.host) && host && !isLocalAddr(host)) {
          // R157：端点修正——创建时公网探测未完成填了本机网卡 IP；探测完成后自动刷成公网 IP
          const old = existing.host;
          existing.host = host;
          changed = true;
          log('INFO', `内置公用凭据端点已修正：${existing.name} ${old} → ${host}（探测完成后自动刷新）`);
        }
        continue;
      }
      const id = crypto.randomUUID();
      creds[id] = {
        id, name: names[i] || b.name, hash, hash8: hash.slice(0, 8),
        tail5: b.token.slice(-5), public: true, publicToken: b.token, // 内置公用：明文展示（点击可查看完整/复制）
        host, port: CRED_DEFAULT_PORT, limits: { ...BUILTIN_LIMITS }, // R154b：端点（默认本机 IP:59599）+ 保守限额
        createdAt: new Date().toISOString(), disabled: false, lastUsed: 0,
      };
      changed = true;
      log('INFO', `内置公用凭据已添加：${names[i] || b.name}（语言 ${langHint || cfg.lang || 'zh-CN'}，端点 ${host || '自动'}:${CRED_DEFAULT_PORT}）`);
    }
    if (changed) { rebuildIndex(); saveCreds(); }
    return changed;
  }
  // ── R153：import-credentials.txt 导入（每行一个 token，导入后删除文件）──
  function importCredentialsFile() {
    try {
      if (!fs.existsSync(IMPORT_CRED_FILE)) return;
      const raw = fs.readFileSync(IMPORT_CRED_FILE, 'utf8');
      const tokens = String(raw).split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
      let added = 0, skipped = 0;
      for (const t of tokens) {
        if (!/^[A-Za-z0-9_-]{32,64}$/.test(t)) { skipped++; continue; }
        const hash = sha(t);
        if (hashIndex.has(hash)) { skipped++; continue; }
        const id = crypto.randomUUID();
        creds[id] = {
          id, name: '导入凭据', hash, hash8: hash.slice(0, 8),
          tail5: t.slice(-5), createdAt: new Date().toISOString(), disabled: false, limits: null, lastUsed: 0,
        };
        added++;
      }
      if (added) { rebuildIndex(); saveCreds(); }
      fs.rmSync(IMPORT_CRED_FILE, { force: true });
      log(`INFO`, `导入凭据文件：新增 ${added} 条，跳过 ${skipped} 条（文件已删除）`);
    } catch (e) { log('WARN', '导入凭据文件失败：' + String(e && e.message || e).slice(0, 120)); }
  }
  importCredentialsFile();

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
  cfg.dht = normDhtCfg(cfgRaw && cfgRaw.dht);
  // 自动重启配置规范化（intervalHours 1–100000 小时；nextAt 非未来时间戳清零）
  const arRaw = (cfgRaw && cfgRaw.autorestart) || {};
  const arH = Number(arRaw.intervalHours);
  cfg.autorestart = {
    enabled: !!arRaw.enabled,
    intervalHours: Number.isFinite(arH) && arH > 0 && arH <= 100000 ? arH : 24,
    nextAt: Number.isFinite(Number(arRaw.nextAt)) && Number(arRaw.nextAt) > 0 ? Number(arRaw.nextAt) : 0,
  };
  // R142 曾把 TCP 443/62666 加入默认业务端口；R147 用户拍板移除——配置恰等于 R142 迁移结果时自动回退到 3 个默认端口
  if (JSON.stringify(cfg.ports) === JSON.stringify(R142_DEFAULT_PORTS)) cfg.ports = [...DEFAULT_PORTS];
  cfg.ports = normPorts(cfg.ports);
  // R166 自愈：旧版更新（applyUpdate 曾强制带 --port=8787，显式模式覆盖 cfg.ports 并落盘）会把
  // 默认业务端口 59599/58588 从 config.json 抹掉——启动时自动补回缺失的默认业务端口（入口 8787 尊重"入口可改"语义）
  {
    const missingDefaults = DEFAULT_PORTS.filter((dp) => dp !== 8787 && !cfg.ports.includes(dp));
    if (missingDefaults.length) {
      cfg.ports = normPorts([...cfg.ports, ...missingDefaults]);
      if (!saveCfg()) log('WARN', '端口自愈：补回默认端口后保存 config.json 失败');
      log('WARN', `端口自愈：检测到默认端口缺失（${missingDefaults.join(', ')}，通常由旧版更新/--port 覆盖导致），已自动补回：${cfg.ports.join(', ')}`);
    }
  }
  // R138：语言选择服务端持久化——null 表示从未选择（前端据此决定首启弹窗）；换端口/换浏览器/重启都记住。
  cfg.lang = (cfgRaw && typeof cfgRaw.lang === 'string' && UI_LANGS.includes(cfgRaw.lang)) ? cfgRaw.lang : null;
  // R148：首启弹窗是否已展示过（托盘/无痕浏览器打开不再每次弹）
  cfg.langAsked = !!(cfgRaw && cfgRaw.langAsked === true);
  // R153b：语言未定（首启弹窗未选）时不在启动创建内置公用凭据——等用户选定语言后再建（名称跟随首次语言）；
  // 老实例（cfg.lang 已有值）启动即建，名称 = 已选语言；已建后不因换语言改名。
  if (cfg.lang) ensureBuiltinCredentials(cfg.lang);
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
    statsAggCache.clear(); // R161：配置变更使聚合缓存失效（管理页立即看到新值）
    try { writeJsonAtomic(CFG_FILE, cfg); return true; } catch (e) { log('WARN', '写 config.json 失败：' + (e && e.message || e)); return false; }
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
  /** R162：全局统计聚合（增量维护 O(1)/请求）——record 时同步累加，buildStats 直接读，
   * 100k 凭据表不再每次全量遍历聚合（首次重算 ~170ms → ~10ms）；启动/每小时校准重建自动修复漂移。 */
  let aggTotals = { total: emptyAgg(), days: {}, months: {}, years: {} };
  function aggAddInto(bucket, add) {
    for (const k of Object.keys(add)) bucket[k] += Number(add[k]) || 0;
  }
  function aggTotalsAdd(add, date) {
    aggAddInto(aggTotals.total, add);
    const dk = dayKey(date), mk = monthKey(date), yk = yearKey(date);
    aggAddInto(aggTotals.days[dk] || (aggTotals.days[dk] = emptyAgg()), add);
    aggAddInto(aggTotals.months[mk] || (aggTotals.months[mk] = emptyAgg()), add);
    aggAddInto(aggTotals.years[yk] || (aggTotals.years[yk] = emptyAgg()), add);
  }
  function aggTotalsRebuild() {
    const t = { total: emptyAgg(), days: {}, months: {}, years: {} };
    for (const s of Object.values(stats.credentials)) {
      aggAddInto(t.total, s.total);
      for (const [k, b] of Object.entries(s.days)) aggAddInto(t.days[k] || (t.days[k] = emptyAgg()), b);
      for (const [k, b] of Object.entries(s.months)) aggAddInto(t.months[k] || (t.months[k] = emptyAgg()), b);
      for (const [k, b] of Object.entries(s.years)) aggAddInto(t.years[k] || (t.years[k] = emptyAgg()), b);
    }
    aggTotals = t;
  }
  aggTotalsRebuild(); // 启动校准（含 legacy 迁移后的值）
  let statsDirty = false;
  let statsTimer = null;
  function flushStats(force = false) {
    if (!statsDirty && !force) return;
    // R161：统计桶 prune 已移出落盘路径（见 pruneStatsTimer）——100k 表全量 prune 每次数百 ms 阻塞
    try { writeJsonAtomic(STATS_FILE, stats, 0o600, true); statsDirty = false; return true; }
    catch (e) { log('WARN', '写 stats.json 失败：' + (e && e.message || e)); return false; } // 失败保留脏标记，下次再试
  }
  function markStatsDirty() {
    statsDirty = true;
    if (statsTimer) return;
    // R161：落盘防抖 3s → 15s——高 QPS 下每 3s 全量写大表是 IO 风暴；崩溃最多丢 15s 展示性统计
    statsTimer = setTimeout(() => { statsTimer = null; flushStats(); }, 15_000);
    if (statsTimer.unref) statsTimer.unref();
  }
  const statsInterval = setInterval(() => flushStats(), 30_000);
  statsInterval.unref();
  /** R161：统计桶有界化（400 天 / 36 月 / 10 年）——独立低频执行，不再在每次落盘时全量遍历。 */
  function pruneStatsBuckets() {
    for (const s of Object.values(stats.credentials)) {
      pruneMap(s.days, 400); pruneMap(s.months, 36); pruneMap(s.years, 10);
    }
    aggTotalsRebuild(); // R162：每小时校准（清理聚合中的超期桶 + 自动修复增量漂移）
    markStatsDirty();
  }
  const pruneStatsTimer = setInterval(() => { try { pruneStatsBuckets(); } catch { /* noop */ } }, 3600_000);
  pruneStatsTimer.unref();
  saveCreds();

  // ── 扩网 / 被扩网状态 ──
  let expand = emptyExpand();

  /* ── R135g 附加内容（会话提示消息）：凭证级选择 + 哈希链审计 + DHT 签名检查点 ── */
  const additionSeq = new Map(); // credId → 顺序模式计数器（内存，重启归零）
  const ADDITION_AUDIT_FILE = path.join(DATA, 'addition-audit.log');
  const ADDITION_AUDIT_MAX_LINES = 200_000; // 超出从头部截断并重置链根（截断是可审计事件：gen++）
  let additionAudit = { gen: 0, head: '', count: 0, lastSignedAt: 0, lastSignedHead: '' };
  function loadAdditionAudit() {
    try {
      const lines = fs.readFileSync(ADDITION_AUDIT_FILE, 'utf8').split(/\r?\n/).filter(Boolean);
      if (!lines.length) return;
      let gen = 0, head = '', count = 0;
      for (const line of lines) {
        try {
          const e = JSON.parse(line);
          if (e.t === 'gen') { gen = e.gen; head = ''; count = 0; continue; }
          if (!e.h || !e.m) continue;
          head = e.h; count++;
        } catch { /* 跳过坏行（不阻止加载） */ }
      }
      additionAudit = { gen, head, count, lastSignedAt: 0, lastSignedHead: '' };
    } catch { /* 无审计文件 */ }
  }
  function auditAppend(msgId, addition) {
    const m = sha256Hex(String(msgId || '')).slice(0, 16);
    const a = sha256Hex(String(addition || '')).slice(0, 16);
    const prev = additionAudit.head || `gen${additionAudit.gen}`;
    const h = sha256Hex(prev + '|' + m + '|' + a);
    additionAudit.head = h;
    additionAudit.count++;
    let line;
    try { line = JSON.stringify({ t: 1, at: Date.now(), m, a, h }) + '\n'; fs.appendFileSync(ADDITION_AUDIT_FILE, line); } catch { /* 审计写盘失败不阻断业务 */ }
    if (additionAudit.count > ADDITION_AUDIT_MAX_LINES) {
      additionAudit.gen++;
      additionAudit.head = '';
      additionAudit.count = 0;
      try {
        fs.appendFileSync(ADDITION_AUDIT_FILE, JSON.stringify({ t: 'gen', gen: additionAudit.gen, at: Date.now() }) + '\n');
      } catch { /* noop */ }
    }
  }
  /** 附加内容选择：按凭证配置（关/随机/顺序/按比例）从库中选一条；未配置/库空 → null。 */
  function pickAddition(c) {
    if (!c || !c.addition || c.addition.mode === 'off') return null;
    const texts = cfg.addition && Array.isArray(cfg.addition.texts) ? cfg.addition.texts : [];
    if (!texts.length) return null;
    const w = c.addition.weights || {};
    const hasWeights = Object.keys(w).length > 0;
    // R135o：有权重表时仅列出的条目参与（未列出 = 不使用）；留空 = 全部等权
    const pool = texts.map((t, i) => ({ t, i: i + 1, w: hasWeights ? (w[String(i + 1)] || 0) : 1 })).filter((x) => x.w > 0);
    if (!pool.length) return null;
    const mode = c.addition.mode;
    if (mode === 'sequence') {
      const idx = (additionSeq.get(c.id) || 0) % pool.length;
      additionSeq.set(c.id, idx + 1);
      return pool[idx].t;
    }
    if (mode === 'weighted') {
      const total = pool.reduce((s, x) => s + x.w, 0);
      let r = Math.random() * total;
      for (const x of pool) { r -= x.w; if (r <= 0) return x.t; }
      return pool[pool.length - 1].t;
    }
    return pool[Math.floor(Math.random() * pool.length)].t; // random
  }
  /** 审计检查点指纹（独立键，不覆盖本站服务记录）：sha256(本站指纹|addition-audit) → base32。 */
  function dhtAuditZhiWen() {
    return warmyZhiWen(sha256Hex(Buffer.from(`${dhtZhiWen || ''}|addition-audit`, 'utf8')));
  }
  /** 周期签名检查点：把审计链根签名发布到 DHT（组密钥加密 + 验签 + 防回滚 seq），改造站无法抹掉历史。 */
  async function dhtPublishAudit() {
    if (!dhtZhiWen || !cfg.dht.enabled) return { ok: false, error: 'dht-disabled' };
    if (!additionAudit || !additionAudit.count || !additionAudit.head) return { ok: false, error: 'empty-audit' };
    const r = await dhtPublishRecord({
      zhiWen: dhtAuditZhiWen(),
      record: {
        fp: dhtAuditZhiWen(), host: activeExternalAddr().host, port: activeExternalAddr().port,
        scope: 'relay', announcedAt: Date.now(), bieMing: expand.instanceId,
        extra: {
          kind: 'fwarmy-addition-audit', instanceId: expand.instanceId,
          head: additionAudit.head, count: additionAudit.count, gen: additionAudit.gen, version: VERSION,
        },
      },
    });
    if (r.ok) { additionAudit.lastSignedAt = Date.now(); additionAudit.lastSignedHead = additionAudit.head; }
    return r;
  }
  loadAdditionAudit();
  const auditTimer = setInterval(() => { void dhtPublishAudit(); }, MANUAL_ADDR_CHECK_MS); // 与对外地址复查同周期（5 分钟）
  auditTimer.unref();

  /** 公网 IP 探测缓存（R131：启动自动探测 + 30 分钟定时 + 手动刷新；顶部常驻显示 IPv4/IPv6）。 */
  let lastPub = { ipv4: '', ipv6: '', at: 0, via: 'none' };
  /** R153b：强制指定 family 出口请求（dns 解析该族记录后向对应 IP 发 HTTPS，SNI 保持域名）——
   * 机器有 IPv6 出口时普通 fetch 会走 IPv6，导致「IPv4 探测」实际拿的是 IPv6 或失败显示【无】。 */
  function httpsGetFixedFamily(host, path, family, timeoutMs = 4000) {
    return new Promise((resolve) => {
      dns.lookup(host, { family }, (err, addr) => {
        if (err || !addr) return resolve('');
        const opts = {
          host: String(addr), port: 443, path, method: 'GET', agent: false,
          headers: { host, 'user-agent': `FWArmy/${VERSION}` },
          servername: host, timeout: timeoutMs,
        };
        const req = https.request(opts, (res) => {
          const bu = [];
          res.on('data', (c) => bu.push(c));
          res.on('end', () => resolve(Buffer.concat(bu).toString('utf8')));
        });
        req.on('error', () => resolve(''));
        req.on('timeout', () => { req.destroy(); resolve(''); });
        req.end();
      });
    });
  }
  /** R160：系统栈 HTTPS 兜底（替代 fetch）——https.request agent:false 不留连接池（进程可干净退出），
   * 对纯 A/纯 AAAA 域名系统栈解析只能走对应族，行为与 fetch 一致但可控。 */
  function httpsGetSystemStack(host, path, timeoutMs = 5000) {
    return new Promise((resolve) => {
      const opts = {
        host, port: 443, path, method: 'GET', agent: false, timeout: timeoutMs,
        headers: { host, 'user-agent': `FWArmy/${VERSION}`, connection: 'close' },
      };
      const req = https.request(opts, (res) => {
        const bu = [];
        res.on('data', (c) => bu.push(c));
        res.on('end', () => resolve(Buffer.concat(bu).toString('utf8')));
      });
      req.on('error', () => resolve(''));
      req.on('timeout', () => { req.destroy(); resolve(''); });
      req.end();
    });
  }
  /** R160：手写 DNS 报文查询（零依赖）。myip.opendns.com 的 A/AAAA 记录即「该 family 出口地址」
   *（OpenDNS 特有服务）；dgram socket 创建时固定协议族，双栈机器上出口必然走对应 family，
   * 这是 HTTPS 端点全灭（境外服务被阻断/直连超时）时的保底路径（public-ip 同款方案）。 */
  function udpDnsQuery(family, server, name, wantType, timeoutMs = 4000) {
    return new Promise((resolve) => {
      let done = false;
      const sock = dgram.createSocket(family === 4 ? 'udp4' : 'udp6');
      const finish = (v) => {
        if (done) return; done = true; clearTimeout(timer);
        try { sock.close(); } catch { /* noop */ } resolve(v);
      };
      const timer = setTimeout(() => finish(''), timeoutMs);
      if (timer.unref) timer.unref();
      const q = Buffer.alloc(12 + name.length + 6);
      q.writeUInt16BE(Date.now() & 0xffff, 0); q.writeUInt16BE(0x0100, 2); q.writeUInt16BE(1, 4); q.writeUInt16BE(0, 6);
      let off = 12;
      for (const label of name.split('.')) { q[off++] = label.length; q.write(label, off, 'ascii'); off += label.length; }
      q[off++] = 0;
      q.writeUInt16BE(wantType, off); q.writeUInt16BE(1, off + 2);
      sock.on('message', (msg) => {
        if (done) return;
        let ans = '';
        try { ans = parseDnsAnswers(msg, wantType); } catch { /* noop */ }
        finish(ans);
      });
      sock.on('error', () => finish(''));
      sock.send(q, 53, server, (e) => { if (e) finish(''); });
    });
  }
  function parseDnsAnswers(buf, wantType) {
    let off = 12;
    while (off < buf.length && buf[off] !== 0) off += buf[off] + 1; // question name（未压缩）
    off += 5; // 结尾 0 + QTYPE + QCLASS
    const ancount = buf.readUInt16BE(6);
    const res = [];
    for (let i = 0; i < ancount && off + 10 <= buf.length; i++) {
      if ((buf[off] & 0xc0) === 0xc0) off += 2; else { while (off < buf.length && buf[off] !== 0) off += buf[off] + 1; off += 1; }
      const type = buf.readUInt16BE(off);
      const rdlen = buf.readUInt16BE(off + 8);
      off += 10;
      if (type === wantType && rdlen === (wantType === 1 ? 4 : 16) && off + rdlen <= buf.length) {
        if (wantType === 1) res.push(`${buf[off]}.${buf[off + 1]}.${buf[off + 2]}.${buf[off + 3]}`);
        else { const p = []; for (let j = 0; j < 16; j += 2) p.push(buf.toString('hex', off + j, off + j + 2)); res.push(p.join(':')); }
      }
      off += rdlen;
    }
    return res.join(',');
  }
  async function udpProbePublicIp(family) {
    const cfg = family === 4
      ? [['208.67.222.222', 'myip.opendns.com', 1], ['208.67.220.220', 'myip.opendns.com', 1],
         ['208.67.222.220', 'myip.opendns.com', 1], ['208.67.220.222', 'myip.opendns.com', 1]]
      : [['2620:0:ccc::2', 'myip.opendns.com', 28], ['2620:0:ccd::2', 'myip.opendns.com', 28]];
    for (const [server, name, type] of cfg) {
      const raw = await udpDnsQuery(family, server, name, type);
      const ip = String(raw).split(',').find((x) => (family === 4 ? isV4(x) : isV6(x))) || '';
      if (ip) return ip;
    }
    return '';
  }
  /** R160：端点表。fetch 兜底只对「纯 A/纯 AAAA」域名开启——此类域名无对族记录，系统栈 fetch 也只能走对应族；
   * 双栈域名（api.ipify.org/myip.ipip.net/icanhazip.com）关掉 fetch（系统栈可能走错族返回被过滤，白等超时），
   * 只走强制 family 直连。ipify 直连优先（本机实测最稳），ipip 中文文本经 extractIpFromText 提取。 */
  const IPV4_ENDPOINTS = [
    { host: 'api4.ipify.org', path: '/?format=json', json: true, fetch: true },
    { host: 'ipv4.icanhazip.com', path: '/', json: false, fetch: true },
    { host: 'api.ipify.org', path: '/?format=json', json: true, fetch: false },
    { host: 'myip.ipip.net', path: '/', json: false, fetch: false },
  ];
  const IPV6_ENDPOINTS = [
    { host: 'api6.ipify.org', path: '/?format=json', json: true, fetch: true },
    { host: 'ipv6.icanhazip.com', path: '/', json: false, fetch: true },
    { host: 'icanhazip.com', path: '/', json: false, fetch: false },
  ];
  /** R158：单端点探测——强制 family 直连与系统栈 https（agent:false）并行竞速（任一成功即用）。
   * R159：严格按 family 过滤返回 IP——系统栈可能走错 family（连 api4 却经 IPv6 返回 v6），旧逻辑未校验导致
   * 「双栈时只显示 v6、v4 显示无」。R160：双栈域名不再启用系统栈兜底；逐端点记录结果与耗时。 */
  async function probeOne(ep, family) {
    const { host, path, json: parseJson, fetch: useFetch } = ep;
    const t0 = Date.now();
    const pick = (txt) => {
      if (!String(txt || '').trim()) return '';
      let ip = '';
      if (parseJson) { try { ip = String((JSON.parse(txt) || {}).ip || '').trim(); } catch { ip = ''; } }
      if (!ip) ip = extractIpFromText(txt, family);
      return (family === 4 && isV4(ip)) || (family === 6 && isV6(ip)) ? ip : '';
    };
    const results = await Promise.all([
      httpsGetFixedFamily(host, path, family, 5000)
        .then((txt) => ({ src: 'direct', txt, ms: Date.now() - t0 }))
        .catch(() => ({ src: 'direct', txt: '', ms: Date.now() - t0 })),
      useFetch
        ? httpsGetSystemStack(host, path, 5000)
          .then((txt) => ({ src: 'fetch', txt, ms: Date.now() - t0 }))
          .catch(() => ({ src: 'fetch', txt: '', ms: Date.now() - t0 }))
        : Promise.resolve(null),
    ]);
    for (const r of results) {
      if (!r) continue;
      const ip = pick(r.txt);
      if (ip) {
        log('INFO', `[fwarmy] 公网 IP 探测 ${family === 4 ? 'IPv4' : 'IPv6'} ${host}：${r.src}=${ip}（${r.ms}ms）`);
        return ip;
      }
    }
    log('INFO', `[fwarmy] 公网 IP 探测 ${family === 4 ? 'IPv4' : 'IPv6'} ${host}：未命中（${results.filter(Boolean).map((r) => `${r.src}=${r.ms}ms`).join(' / ')}）`);
    return '';
  }
  async function probePublicIp() {
    // R160 测试钩子：跳过 HTTPS 只走 UDP 兜底（verify 用，验证 socket 固定 family 的全链路）
    if (process.env.FWARMY_PROBE_FORCE_UDP === '1') {
      const f4 = await udpProbePublicIp(4);
      const f6 = await udpProbePublicIp(6);
      lastPub = { ipv4: isV4(f4) ? f4 : '', ipv6: isV6(f6) ? f6 : '', at: Date.now(), via: f4 ? 'udp' : (f6 ? 'udp' : 'none') };
      try { syncAddrStates(); } catch { /* noop */ }
      log('INFO', `[fwarmy] 公网 IP 自动探测（强制 UDP）：IPv4=${lastPub.ipv4 || '无'} IPv6=${lastPub.ipv6 || '无'}`);
      return { ...lastPub, defaultHost: lastPub.ipv4 || lastPub.ipv6 };
    }
    // IPv4：纯 A 域名（直连+fetch 竞速）优先 → 双栈域名仅直连 → UDP4 DNS 兜底
    let v4 = '', v4via = 'https';
    for (const ep of IPV4_ENDPOINTS) {
      const ip = await probeOne(ep, 4);
      if (isV4(ip)) { v4 = ip; break; }
    }
    if (!v4) { v4 = await udpProbePublicIp(4); if (isV4(v4)) v4via = 'udp'; }
    // IPv6：纯 AAAA 域名优先 → 双栈域名仅直连 → UDP6 DNS 兜底（国内多数网络 UDP6 不通，仅作保底）
    let v6 = '', v6via = 'https';
    for (const ep of IPV6_ENDPOINTS) {
      const ip = await probeOne(ep, 6);
      if (isV6(ip)) { v6 = ip; break; }
    }
    if (!v6) { v6 = await udpProbePublicIp(6); if (isV6(v6)) v6via = 'udp'; }
    const v4b = v4 || v6; // 只有 v6 时也让默认地址可用
    lastPub = { ipv4: v4, ipv6: v6, at: Date.now(), via: v4 || v6 ? (v4via === 'udp' || v6via === 'udp' ? 'udp+https' : 'https') : 'none' };
    // R157：探测完成后立即刷新对外地址缓存——否则 activeExternalAddr/内置凭据端点
    // 会一直用探测前生成的本机网卡 IP（addrSelfHeal 5 分钟才同步一次，太晚）
    try { syncAddrStates(); } catch { /* noop */ }
    log('INFO', `[fwarmy] 公网 IP 自动探测：IPv4=${v4 || '无'}（${v4via}） IPv6=${v6 || '无'}（${v6via}）`);
    return { ...lastPub, defaultHost: v4b };
  }
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
    try { writeJsonAtomic(EXPAND_FILE, expand); expandDirty = false; return true; }
    catch (e) { log('WARN', '写 expand.json 失败：' + (e && e.message || e)); return false; } // 失败保留脏标记
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
      id: c.id, name: c.name, masked: c.tail5 ? '…' + c.tail5 : (c.masked || '—'), addr: c.addr || '', host: c.host || '', createdAt: c.createdAt, lastAt: c.lastAt,
      lastResult: c.lastResult, disabled: c.disabled, limits: c.limits || null, expiresAt: c.expiresAt || 0,
      port: c.port || 0, portOk: listeningPorts().includes(Number(c.port) || 0), // R133：凭据端口须在监听集合
      effective: eff(c),
      stats: sideView(expand.stats.perInbound[c.id] || emptySide()),
    }));
    return {
      ok: true,
      instanceId: expand.instanceId,
      identityPub: expand.identity.pub,
      port: boundPort || opt.port,
      listeningPorts: listeningPorts(), // R133 多业务端口
      publicIp: { ...lastPub }, // R130/R131：探测结果缓存（生成凭据默认地址 + 顶部常驻显示）
      defaultAdvHost: activeExternalAddr().host,
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
          addrFrom: p.addrFrom || 'manual', // 'credential' = 地址来自凭证；'manual' = 手填
          createdAt: p.createdAt, lastTest: p.lastTest, lastTestOk: p.lastTestOk,
          credentialMasked: p.credential ? ('••••' + String(p.hint || '')) : '',
          stats: perOutbound[p.id] || sideView(emptySide()),
        };
      }),
      stats: { inbound: inboundStats, outbound: sideView(expand.stats.outbound), perOutbound, perSource },
    };
  }
  function generateInboundToken(name = '', portRaw, hostRaw, limits = null, expiresAt = 0) {
    // R149：F中继凭证不再内嵌地址（与中继 token 一致）——地址可能变化，凭证带地址会造成「凭据有效但地址失效」的矛盾；
    // 条目仍保存 host/port 供管理页展示与端口管理，可事后修改；对方添加扩网时需另填地址（或用旧版 v2 凭证自动解析）。
    const host = String(hostRaw || '').trim() || activeExternalAddr().host;
    let port = Math.floor(Number(portRaw));
    if (!Number.isInteger(port) || port < 1 || port > 65535) port = EXPAND_DEFAULT_PORT;
    const token = b64u(crypto.randomBytes(32));
    const hash = sha(token);
    const tail5 = token.slice(-5); // R150：标识列显示明文末尾 5 位（人可对账；≈30bit 熵 + 来源限速，无实质风险）
    const item = {
      id: crypto.randomUUID(), name: uniqueInboundName(name), tail5,
      hash, masked: '…' + tail5, // 前缀无意义：只显示末尾 5 个（R150；R132 曾用哈希中段，人无法核对）
      host, port, addr: host + ':' + port, createdAt: now(), lastAt: 0, lastResult: '', disabled: false,
      limits: limits || null, expiresAt: Number(expiresAt) || 0, // R129：可管理（改名/流量/速度/有效期）；R135p：生成时即可设置
    };
    expand.inbound.push(item);
    saveExpand();
    // 明文只返回这一次；expand.json 只有 sha256 + tail5。
    return { token, item };
  }
  /** R150：名称必须唯一（人类只靠名称区分凭据）——重名拒绝；默认名自动避让。 */
  function uniqueInboundName(name) {
    const raw = String(name || '').trim().slice(0, 40);
    const taken = new Set(expand.inbound.map((c) => c.name));
    if (raw && taken.has(raw)) throw new Error('name-conflict');
    if (raw) return raw;
    for (let i = expand.inbound.length + 1; ; i++) {
      const cand = '接入凭据 ' + i;
      if (!taken.has(cand)) return cand;
    }
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
  /** R133：凭据端口必须在本机监听端口集合中（多端口体系）；否则强制禁止。 */
  function credPortUnavailable(c) {
    const lp = listeningPorts();
    return lp.length > 0 && !lp.includes(Number(c.port) || 0);
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
    try { writeJsonAtomic(SECURITY_FILE, security); return true; } catch (e) { log('WARN', '写 security.json 失败：' + (e && e.message || e)); return false; }
  }
  /** 普通计数攒 250ms 写一次（每秒最多 4 次请求也不至于每包重写全表）；黑名单/固定公钥立即写。 */
  function markSecurityDirty() {
    if (securityTimer) return;
    securityTimer = setTimeout(() => { securityTimer = null; saveSecurity(); }, 2000);
    if (securityTimer.unref) securityTimer.unref();
  }
  /** R161：重放计数到上限的落盘 300ms 防抖（与 markSecurityDirty 共用 securityTimer）——高频重复消息下
   * 每次全量写盘是 IO 热点；优雅关闭 close() 同步 saveSecurity()，崩溃最多丢 300ms 计数（24h 窗口内多放行 ≤1 次）。 */
  function scheduleSecurityFlush() {
    if (securityTimer) { clearTimeout(securityTimer); securityTimer = null; }
    securityTimer = setTimeout(() => { securityTimer = null; saveSecurity(); }, 300);
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
   * 重放闸/转圈防护：同一 messageId 24h 内最多放行 2 次（第 1 次正常投递 + 第 2 次容忍重复/补发/首轮转圈）。
   * 第 3 次出现 ⇒ 直接丢弃并写黑名单——黑名单键 = 该消息（msgId 哈希），不是来源/IP；
   * 只要 msgId 相同即同一消息。首次出现已超过 24h ⇒ 老消息重放，同样丢弃 + 写黑名单（重启后仍生效）。
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
    if (e.count >= REPLAY_MAX_PASSES) {
      security.violations.replayRejected++;
      blacklistMessage(key, 'already-seen', at, origin);
      return { ok: false, reason: 'already-seen', count: e.count };
    }
    e.count++;
    e.last = at;
    if (origin) e.origin = String(origin).slice(0, 64);
    // 到上限必须立即落盘，避免重启把“已放行 2 次”忘掉（环形转圈不会因重启被重置）；普通第一次攒批写。
    // R161：到上限的落盘改 300ms 防抖（优雅关闭时 close() 同步落盘兜底）。
    if (e.count >= REPLAY_MAX_PASSES) scheduleSecurityFlush(); else markSecurityDirty();
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
  /** R133/R134：端口管理视图（TCP 业务端口 + UDP DHT 端口；状态 + 凭据引用）。 */
  function portsView() {
    const credsUse = (port) => Object.values(creds).filter((c) => (c.port || 0) === port).length
      + expand.inbound.filter((c) => (c.port || 0) === port).length;
    // R166：视图与实际监听一致——显式 --port 时只看该端口（cfg.ports 保持持久化配置，不被运行参数覆盖）
    const tcpItems = viewPorts.map((port) => {
      const st = portStates.get(port) || { status: 'error', error: 'unknown' };
      return {
        port, protocol: 'tcp', status: st.status, error: st.error || '',
        creds: credsUse(port), main: port === viewPorts[0],
      };
    });
    const udpItems = cfg.dht.udpPorts.map((port) => {
      if (cfg.dht.pausedUdpPorts.includes(port)) {
        return { port, protocol: 'udp', status: 'paused', error: '', creds: 0, main: false }; // R135：暂停保留配置
      }
      const up = dhtNodes.some((n) => n.listening && n.address.port === port);
      return {
        port, protocol: 'udp', status: up ? 'listening' : 'error',
        error: up ? '' : 'udp-bind-failed', creds: 0, main: false,
      };
    });
    return {
      ok: true,
      defaultCredPort: CRED_DEFAULT_PORT,
      defaultExpandPort: EXPAND_DEFAULT_PORT,
      entryPort: viewPorts[0],
      mainPort: boundPort || opt.port,
      items: [...tcpItems, ...udpItems],
    };
  }
  function findListeningPid(port) {
    return new Promise((resolve) => {
      const cp = require('node:child_process');
      if (process.platform === 'win32') {
        cp.execFile('netstat', ['-ano', '-p', 'tcp'], { windowsHide: true, timeout: 5000 }, (err, stdout) => {
          if (err) return resolve(0);
          for (const line of String(stdout).split(/\r?\n/)) {
            const m = /TCP\s+[\d.:\[\]]+:(\d+)\s+[\d.:\[\]]+:0\s+LISTENING\s+(\d+)/.exec(line);
            if (m && Number(m[1]) === port) return resolve(Number(m[2]));
          }
          resolve(0);
        });
      } else {
        cp.execFile('lsof', ['-t', '-iTCP:' + port, '-sTCP:LISTEN'], { timeout: 5000 }, (err, stdout) => {
          const pid = Number(String(stdout || '').trim().split(/\s+/)[0]);
          resolve(err || !pid ? 0 : pid);
        });
      }
    });
  }
  /** 强制结束占用指定 TCP 端口的进程（本机端口管理，用户显式操作才调用）。 */
  async function forceKillPort(port) {
    const pid = await findListeningPid(port);
    if (!pid) return { ok: true, killed: false };
    if (pid === process.pid) return { ok: false, error: 'cannot-kill-self' };
    try {
      const cp = require('node:child_process');
      if (process.platform === 'win32') cp.spawnSync('taskkill', ['/F', '/PID', String(pid)], { windowsHide: true });
      else cp.spawnSync('kill', ['-9', String(pid)]);
    } catch { /* 尽力 */ }
    for (let i = 0; i < 20; i++) {
      if (!(await findListeningPid(port))) return { ok: true, killed: true, pid };
      await new Promise((r) => setTimeout(r, 100));
    }
    return { ok: false, error: '进程未退出（pid=' + pid + '），端口仍未释放' };
  }
  function securityView() {
    const bl = Object.entries(security.blacklist)
      .sort((a, b) => (b[1].lastAt || 0) - (a[1].lastAt || 0)).slice(0, 20)
      .map(([k, v]) => ({ key: k.slice(0, 12), reason: v.reason, firstAt: v.firstAt, lastAt: v.lastAt, hits: v.hits, origin: v.origin }));
    const origins = Object.entries(security.origins).map(([id, v]) => ({ instanceId: id, pub: v.pub, firstAt: v.firstAt, lastAt: v.lastAt }));
    return {
      ok: true,
      policy: {
        windowMs: MESSAGE_WINDOW_MS, replayMaxPasses: REPLAY_MAX_PASSES, blacklistTtlMs: BLACKLIST_TTL_MS,
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


  /* ── DHT 发现层（默认强制开启；只做设备发现，消息仍走凭据通道）──── */
  let dhtNodes = [];
  let dhtZhiWen = '';
  let dhtRetryDelayMs = cfg.dht.retryBaseMs;
  let dhtState = { lastPublishAt: 0, lastPublishSeq: 0, lastStoredOn: [], lastError: '', lastYindao: null, selfPublishes: 0 };
  const didLastPub = new Map(); // did → 上次代发布定位记录的时间
  /** 自动推断 IP：探测到的公网 IP（ipify）优先（R155：IPv4 优先，无 IPv4 才用 IPv6——用户拍板覆盖 R135 的 IPv6 优先），其次本机非回环 IPv4 > IPv6 > 回环（R139：移除 STUN/NAT-PMP 优先级）。 */
  function autoAdvIp() {
    if (lastPub && (lastPub.ipv4 || lastPub.ipv6)) return lastPub.ipv4 || lastPub.ipv6;
    for (const a of localAddresses()) {
      if (!a.internal && a.family === 'IPv4' && !/^fe80:/i.test(a.address) && !a.address.includes('%')) return a.address;
    }
    for (const a of localAddresses()) if (!a.internal && a.family === 'IPv6') return a.address;
    return '127.0.0.1';
  }
  /**
   * 自动兜底投递端口（R135q）：对外地址宣告 = 投递地址，走 TCP 业务端口——
   * 取当前监听的业务端口（优先非入口，最多 2 个）；UDP 443/62666 是引导端口，
   * 不再作为投递宣告（否则别人按记录投递 TCP 到 UDP 端口必然不通）。
   */
  function autoAddrPorts() {
    try {
      const lp = listeningPorts(); // 端口表初始化后：实际监听集合（仅 TCP 业务端口）
      const pref = lp.filter((p) => p !== (cfg.ports[0] || 0));
      const picked = (pref.length ? pref : lp).slice(0, 2);
      if (picked.length) return picked;
    } catch { /* 启动早期端口表未初始化（TDZ），回退配置端口 */ }
    const cp = Array.isArray(cfg.ports) ? [...cfg.ports] : [];
    return cp.slice(0, 2).length ? cp.slice(0, 2) : [59599];
  }
  /** R135：自动兜底地址维度 = 探测到的公网 IP（R155：IPv4 优先，无 IPv4 用 IPv6；ipify 全失败时用推断 IP），最多 2 维 × 业务端口。 */
  function autoAddrHosts() {
    if (lastPub && (lastPub.ipv4 || lastPub.ipv6)) {
      const out = [];
      if (lastPub.ipv4) out.push({ host: lastPub.ipv4, family: 'IPv4' });
      if (lastPub.ipv6) out.push({ host: lastPub.ipv6, family: 'IPv6' });
      return out;
    }
    const ip = autoAdvIp();
    return [{ host: ip, family: ip.includes(':') ? 'IPv6' : 'IPv4' }];
  }
  function autoAddrKey(a) { return `${a.family}|${a.port}`; }
  /** 对外地址状态表：手动条目（cfg.dht.addresses 派生）+ 自动兜底条目（公网 IPv4/IPv6 × 业务端口）。 */
  let addrStates = [];
  function syncAddrStates() {
    const manual = cfg.dht.addresses.map((a) => {
      const prev = addrStates.find((x) => x.manual && x.host === a.host && x.port === a.port);
      return { ...a, valid: prev ? prev.valid : false, lastCheckAt: prev ? prev.lastCheckAt : 0, lastError: prev ? prev.lastError : '' };
    });
    const auto = [];
    for (const h of autoAddrHosts()) {
      for (const port of autoAddrPorts()) {
        const prev = addrStates.find((x) => !x.manual && x.family === h.family && x.port === port);
        const key = `${h.family}|${port}`;
        auto.push({
          host: h.host, port, family: h.family, manual: false,
          enabled: prev ? prev.enabled : !cfg.dht.pausedAuto.includes(key),
          valid: true, lastCheckAt: 0, lastError: '',
          label: `自动兜底 · 公网 ${h.family} · ${port}（投递 TCP）`,
        });
      }
    }
    addrStates = [...manual, ...auto];
  }
  /** 是否有任何生效的对外地址（手动 = 启用且验证通过；兜底 = 启用）。 */
  function anyActiveExternalAddr() {
    return addrStates.some((a) => (a.manual ? a.enabled && a.valid : a.enabled));
  }
  /** R135h：对外地址预检——host 必须指向本机（本机网卡 IP / 探测公网 IP / 回环），域名须解析到其中；否则该地址宣告出去对方连不到本机。 */
  function hostPointsToSelf(host) {
    const mine = new Set();
    for (const a of localAddresses()) {
      const ad = String(a.address || '');
      if (ad && !ad.includes('%')) mine.add(ad.toLowerCase());
    }
    if (lastPub && lastPub.ipv4) mine.add(lastPub.ipv4.toLowerCase());
    if (lastPub && lastPub.ipv6) mine.add(lastPub.ipv6.toLowerCase());
    const selfIp = (h) => /^127\./.test(h) || h === '::1' || mine.has(h.toLowerCase());
    return new Promise((resolve) => {
      if (net.isIP(host)) {
        const h = String(host).toLowerCase();
        return resolve({ ok: selfIp(h), reason: selfIp(h) ? '' : 'not-self', ips: [host], mine: [...mine] });
      }
      dns.lookup(host, { all: true }, (err, addrs) => {
        if (err || !Array.isArray(addrs) || !addrs.length) return resolve({ ok: false, reason: 'dns-empty', ips: [], mine: [...mine] });
        const ips = addrs.map((x) => x.address);
        const ok = ips.some((x) => selfIp(x));
        resolve({ ok, reason: ok ? '' : 'not-self', ips, mine: [...mine] });
      });
    });
  }
  syncAddrStates();
  /** 生效的对外地址：第一个启用且验证通过的手动条目；否则第一个启用的自动兜底。 */
  function activeExternalAddr() {
    const m = addrStates.find((a) => a.manual && a.enabled && a.valid);
    if (m) return { host: m.host, port: m.port };
    const a = addrStates.find((x) => !x.manual && x.enabled);
    return { host: a ? a.host : autoAdvIp(), port: a ? a.port : autoAddrPorts()[0] };
  }
  async function probeOwnAddress(host, port) {
    const t0 = Date.now();
    const once = (secure) => new Promise((resolve) => {
      const mod = secure ? https : http;
      const req = mod.request({
        host, port, path: '/api/expand/identify', method: 'GET',
        ...(secure ? { rejectUnauthorized: false } : {}), agent: false, timeout: 5000,
      }, (res) => {
        const bu = [];
        res.on('data', (d) => bu.push(d));
        res.on('end', () => {
          let j = null;
          try { j = JSON.parse(Buffer.concat(bu).toString('utf8')); } catch { /* noop */ }
          resolve(j && String(j.identityPub || '') === expand.identity.pub
            ? { ok: true, ms: Date.now() - t0 }
            : { ok: false, error: 'identify 不匹配（不是本实例）', ms: Date.now() - t0 });
        });
      });
      req.on('error', (e) => resolve({ ok: false, error: String((e && e.message) || e).slice(0, 60), ms: Date.now() - t0 }));
      req.setTimeout(5000, () => { req.destroy(new Error('timeout')); resolve({ ok: false, error: '超时', ms: Date.now() - t0 }); });
      req.end();
    });
    const r1 = await once(true);
    if (r1.ok) return r1;
    const r2 = await once(false);
    if (r2.ok) return r2;
    return r1.error && r1.error.includes('identify') ? r1 : r2;
  }
  /** 验证所有启用的手动对外地址：通过才用于宣告；失效自动回退自动兜底（R133 定时复查）。 */
  async function checkExternalAddrs() {
    for (const a of addrStates) {
      if (!a.manual || !a.enabled) continue;
      const r = await probeOwnAddress(a.host, a.port);
      a.valid = r.ok;
      a.lastCheckAt = Date.now();
      a.lastError = r.ok ? '' : r.error;
      log(r.ok ? 'INFO' : 'WARN', `[dht] 对外地址 ${a.host}:${a.port} ${r.ok ? '验证通过，宣告优先使用' : '验证失败（' + r.error + '）'}`);
    }
  }
  /** R135 定时自检：没有任何生效的对外地址（手动全失效/暂停 + 自动兜底全暂停）时，自动恢复启用全部兜底；随后复查手动地址。 */
  async function addrSelfHeal() {
    syncAddrStates();
    if (!anyActiveExternalAddr() && cfg.dht.pausedAuto.length) {
      cfg.dht = { ...cfg.dht, pausedAuto: [] };
      if (!saveCfg()) log('WARN', '[dht] 自动恢复兜底时保存配置失败');
      log('WARN', '[dht] 对外地址全部失效，已自动启用全部自动兜底');
      syncAddrStates();
    }
    await checkExternalAddrs();
  }
  const addrCheckTimer = setInterval(() => { void addrSelfHeal(); }, MANUAL_ADDR_CHECK_MS);
  addrCheckTimer.unref();
  const udpRetryTimers = new Map(); // R135z：启动瞬间绑定失败（Windows UDP 释放延迟）→ 延迟自动补绑
  async function dhtStop() {
    const list = dhtNodes;
    dhtNodes = [];
    for (const [port, t] of udpRetryTimers) { clearTimeout(t); log('INFO', `[dht] 取消端口 ${port} 的延迟补绑`); }
    udpRetryTimers.clear();
    for (const n of list) { try { await n.stop(); } catch { /* noop */ } }
    log('INFO', '[dht] 节点已停止');
    return { ok: true };
  }
  /** 启动 DHT 节点（R133）：cfg.dht.udpPorts（默认 443、62666）各一个节点，同一身份；端口占用即失败。 */
  async function bindUdpNode(udpPort) {
    const rawPub = Buffer.from(String(expand.identity.pub || ''), 'base64');
    const adv = activeExternalAddr();
    const node = new DhtJieDian({
      zhiWen: dhtZhiWen,
      publicKeyRaw: rawPub,
      sign: (msg) => crypto.sign(null, msg, identityKey),
      nodeId: expand.instanceId,
      host: '::', // udp6 双栈：IPv6 直连支持
      advertiseHost: adv.host,
      port: 0,
      tcpPort: adv.port, // 宣告的业务端口 = 生效对外地址的端口
      groupKeys: [PUBLIC_DISCOVERY_KEY()],
      onEvent: (e) => {
        if (e.type === 'error') log('WARN', `[dht] ${e.detail || ''}`);
        else log('INFO', `[dht] ${e.type}${e.detail ? ' ' + e.detail : ''}`);
      },
    });
    let bound = null;
    for (let attempt = 1; attempt <= 5 && !bound; attempt++) {
      try { bound = await node.start({ port: udpPort }); }
      catch (e) {
        // R135h/z：Windows UDP 端口释放延迟/瞬时占用——退避重试（400/800/1600/3200ms），5 次仍失败才放弃
        if (attempt === 5) {
          dhtState.lastError = `UDP 端口 ${udpPort} 绑定失败：` + String((e && e.message) || e).slice(0, 200);
          log('ERROR', '[dht] ' + dhtState.lastError);
        } else await sleep(400 * attempt);
      }
    }
    return bound ? node : null;
  }
  function scheduleUdpRetry(udpPort, n = 1) {
    if (n > 3) return; // 10s / 30s / 60s 三次自动补绑，仍失败就等用户处理（端口页会显示异常）
    if (udpRetryTimers.has(udpPort)) return;
    const t = setTimeout(async () => {
      udpRetryTimers.delete(udpPort);
      if (!cfg.dht.enabled || cfg.dht.pausedUdpPorts.includes(udpPort)) return;
      try {
        const node = await bindUdpNode(udpPort);
        if (node) {
          dhtNodes.push(node);
          dhtState.lastError = '';
          log('INFO', `[dht] 端口 ${udpPort} 延迟绑定成功（自动恢复）`);
        } else scheduleUdpRetry(udpPort, n + 1);
      } catch { scheduleUdpRetry(udpPort, n + 1); }
    }, 10_000 * n);
    t.unref?.();
    udpRetryTimers.set(udpPort, t);
  }
  async function dhtStart() {
    if (dhtNodes.length) await dhtStop();
    if (!cfg.dht.enabled) { dhtState.lastError = ''; return { ok: false, error: 'disabled' }; }
    let rawPub = null;
    try { rawPub = Buffer.from(String(expand.identity.pub || ''), 'base64'); } catch { rawPub = null; }
    if (!rawPub || rawPub.length !== 32 || !identityKey) {
      dhtState.lastError = '实例 Ed25519 身份不可用（expand.identity 缺失或私钥无法解密）';
      log('ERROR', '[dht] ' + dhtState.lastError);
      return { ok: false, error: dhtState.lastError };
    }
    dhtZhiWen = warmyZhiWen(rawPub);
    const list = [];
    for (const udpPort of cfg.dht.udpPorts) {
      if (cfg.dht.pausedUdpPorts.includes(udpPort)) continue; // R135：暂停的 UDP 端口不启动监听（配置保留）
      const node = await bindUdpNode(udpPort);
      if (!node) {
        scheduleUdpRetry(udpPort); // R135z：启动瞬间绑定失败自动补绑，无需手动点
        continue;
      }
      list.push(node);
      log('INFO', `[dht] 节点已启动 udp=${node.address ? node.address.host + ':' + node.address.port : udpPort} 指纹=${dhtZhiWen.slice(0, 16)}… 锚点=${yindaoSeeds().length}`);
    }
    if (!list.length) return { ok: false, error: dhtState.lastError };
    dhtNodes = list;
    dhtState.lastError = '';
    dhtRetryDelayMs = cfg.dht.retryBaseMs;
    for (const node of dhtNodes) void dhtYindaoLoop(node);
    return { ok: true };
  }
  /** 引导种子 = 默认锚点（与 WArmy 对齐，自动生效）+ 手动锚点。 */
  function yindaoSeeds() {
    const def = process.env.FWARMY_DISABLE_DEFAULT_ANCHOR === '1' ? [] : guiFanAnChors(DEFAULT_ANCHORS);
    return [...def, ...cfg.dht.anchors];
  }
  /** 锚点引导：至少一个成功即发布本站记录并收工（之后靠 DHT 迭代查询自持）；全部失败则指数退避重试（可恢复）。 */
  async function dhtYindaoLoop(node) {
    for (;;) {
      if (!node.listening || !cfg.dht.enabled || !dhtNodes.includes(node)) return;
      const seeds = yindaoSeeds();
      if (!seeds.length) {
        dhtState.lastYindao = { ok: 0, failed: 0, at: Date.now(), detail: 'no-anchors' };
        // R135：无锚点也自发布（记录存本机 store + 发给路由表已学节点），
        // 使「以本机为锚点引导入网」的设备能立即反向发现本机的服务记录（双向可发现）。
        void dhtPublishSelf();
        return;
      }
      const r = await node.yindao(seeds);
      dhtState.lastYindao = { ok: r.ok, failed: r.failed, at: Date.now() };
      if (r.ok > 0) {
        log('INFO', `[dht] 锚点引导成功 ${r.ok}/${seeds.length}，路由表 ${node.contactCount}；发布本站记录`);
        void dhtPublishSelf();
        return;
      }
      log('WARN', `[dht] 锚点全部不可达（${seeds.length} 个），${dhtRetryDelayMs}ms 后重试`);
      await sleep(dhtRetryDelayMs);
      dhtRetryDelayMs = Math.min(dhtRetryDelayMs * 2, 60_000);
    }
  }
  async function dhtPublishRecord({ zhiWen, record }) {
    const node = dhtNodes[0];
    if (!node || !node.listening) return { ok: false, error: 'dht-not-running' };
    try {
      const r = await node.publish({ zhiWen, record });
      dhtState.lastPublishAt = Date.now();
      dhtState.lastPublishSeq = r.seq;
      dhtState.lastStoredOn = r.storedOn;
      dhtState.lastError = '';
      dhtState.selfPublishes += 1;
      return { ok: true, key: r.key, seq: r.seq, storedOn: r.storedOn };
    } catch (e) {
      dhtState.lastError = String((e && e.message) || e).slice(0, 200);
      log('WARN', `[dht] 发布失败：${dhtState.lastError}`);
      return { ok: false, error: dhtState.lastError };
    }
  }
  /** 本站服务记录：别人据此发现「这台中继站」，含身份公钥与 TLS 指纹用于核对互信；R135n 追加 UDP 端口宣告（发现即引导）。 */
  function dhtSelfRecord() {
    const adv = activeExternalAddr();
    return {
      fp: dhtZhiWen,
      host: adv.host,
      port: adv.port,
      scope: 'relay',
      announcedAt: Date.now(),
      bieMing: expand.instanceId,
      extra: {
        kind: 'fwarmy-relay', instanceId: expand.instanceId,
        identityPub: expand.identity.pub,
        tlsFingerprint: tlsInfo ? tlsInfo.fingerprint : '',
        version: VERSION,
        udpPorts: cfg.dht.udpPorts.filter((p) => !cfg.dht.pausedUdpPorts.includes(p)), // 引导端口（UDP），发现本机后可据此引导
      },
    };
  }
  /** 客户端定位记录：did 当前所在中继站 = 本站（注册/心跳保鲜，离线 30 分钟后自然过期）。 */
  function dhtLocatorRecord(did) {
    let raw;
    try { raw = Buffer.from(String(did), 'base64'); } catch { return null; }
    if (raw.length !== 32) return null;
    const didWen = warmyZhiWen(raw);
    return {
      zhiWen: didWen,
      record: {
        fp: didWen,
        host: activeExternalAddr().host,
        port: activeExternalAddr().port,
        scope: 'relay',
        announcedAt: Date.now(),
        bieMing: expand.instanceId,
        extra: {
          kind: 'fwarmy-client-locator', relay: expand.instanceId,
          relayFingerprint: dhtZhiWen,
          tlsFingerprint: tlsInfo ? tlsInfo.fingerprint : '',
          udpPorts: cfg.dht.udpPorts.filter((p) => !cfg.dht.pausedUdpPorts.includes(p)),
        },
      },
    };
  }
  async function dhtPublishSelf() {
    if (!dhtZhiWen) return { ok: false, error: 'no-identity' };
    return dhtPublishRecord({ zhiWen: dhtZhiWen, record: dhtSelfRecord() });
  }
  async function dhtPublishLocator(did) {
    const loc = dhtLocatorRecord(did);
    if (!loc) return { ok: false, error: 'bad-did' };
    const r = await dhtPublishRecord({ zhiWen: loc.zhiWen, record: loc.record });
    if (r.ok) didLastPub.set(String(did), Date.now());
    return r;
  }
  /** 10 分钟保鲜：重发本站记录与「接近过期」的在线客户端定位记录（每轮最多 200 个，最旧优先）。 */
  async function dhtRefreshLoop() {
    const node = dhtNodes[0];
    if (!cfg.dht.enabled || !node || !node.listening) return;
    await dhtPublishSelf();
    const nowMs = Date.now();
    const online = [];
    for (const [did, v] of ren) {
      if (nowMs - v.lastSeen < zaiXianTtl()) online.push(did);
    }
    online.sort((a, b) => (didLastPub.get(a) || 0) - (didLastPub.get(b) || 0));
    for (const did of online.slice(0, 200)) {
      const last = didLastPub.get(did) || 0;
      if (nowMs - last < DHT_REFRESH_MS) continue;
      await dhtPublishLocator(did);
    }
  }
  const dhtRefreshTimer = setInterval(() => { void dhtRefreshLoop(); }, DHT_REFRESH_MS);
  dhtRefreshTimer.unref();
  /** 投递失败时定位目标：查 DHT 得到目标所在中继站的地址/身份；查不到返回 null，不阻塞原转发路径。 */
  async function dhtRouteTarget(to) {
    const node = dhtNodes[0];
    if (!node || !node.listening || !cfg.dht.routeByDht) return null;
    const loc = dhtLocatorRecord(to);
    if (!loc) return null;
    const r = await node.query(loc.zhiWen, { requireDecrypt: true }).catch(() => null);
    if (!r || !r.ok || !r.record) return null;
    const rec = r.record;
    return {
      host: rec.host, port: rec.port,
      instanceId: (rec.extra && rec.extra.relay) || rec.bieMing || '',
      tlsFingerprint: (rec.extra && rec.extra.tlsFingerprint) || '',
      scope: rec.scope || '',
    };
  }
  function dhtPublicView() {
    const node = dhtNodes[0];
    const adv = activeExternalAddr();
    return {
      ok: true,
      protocol: DHT_PROTOCOL,
      enabled: cfg.dht.enabled,
      running: !!(node && node.listening),
      udps: dhtNodes.filter((n) => n.listening).map((n) => n.address),
      udp: node ? node.address : null,
      advertised: { host: adv.host, port: adv.port, source: addrStates.some((a) => a.manual && a.enabled && a.valid) ? 'manual' : 'auto' },
      addresses: addrStates.map((a) => ({
        host: a.host, port: a.port, manual: a.manual, enabled: a.enabled,
        valid: a.valid, lastCheckAt: a.lastCheckAt, lastError: a.lastError || '', label: a.label || '',
        ...(a.family ? { family: a.family, key: `${a.family}|${a.port}` } : {}),
      })),
      instanceId: expand.instanceId,
      fingerprint: dhtZhiWen,
      nodeIdHex: node ? node.id.toString('hex') : '',
      contacts: node ? node.contactCount : 0,
      contactsList: node ? node.contacts.slice(0, 20) : [],
      stats: node ? node.statsSnapshot : null,
      lastPublishAt: dhtState.lastPublishAt || 0,
      lastPublishSeq: dhtState.lastPublishSeq || 0,
      lastStoredOn: dhtState.lastStoredOn || [],
      lastError: dhtState.lastError || '',
      lastYindao: dhtState.lastYindao,
      selfPublishes: dhtState.selfPublishes,
      anchors: cfg.dht.anchors,
      defaultAnchors: process.env.FWARMY_DISABLE_DEFAULT_ANCHOR === '1' ? [] : guiFanAnChors(DEFAULT_ANCHORS),
      config: {
        enabled: cfg.dht.enabled, udpPorts: cfg.dht.udpPorts, pausedUdpPorts: cfg.dht.pausedUdpPorts,
        addresses: cfg.dht.addresses, pausedAuto: cfg.dht.pausedAuto, anchors: cfg.dht.anchors,
        routeByDht: cfg.dht.routeByDht,
      },
      refreshMs: DHT_REFRESH_MS,
      ttlMs: DEFAULT_RECORD_TTL_MS,
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
  const inboundRecent = new Map(); // 被扩网凭据 id → { newest, sum:{r,b}, buckets:Map(sec→{r,b}) }（R162 O(1) 滑动和）
  function advanceInboundWindow(m, sec) {
    for (let s = m.newest + 1; s <= sec; s++) {
      const old = m.buckets.get(s - 60);
      if (old) { m.sum.r -= old.r; m.sum.b -= old.b; m.buckets.delete(s - 60); }
    }
    m.newest = sec;
  }
  function inboundRateCheck(id, bytes, at = Date.now()) {
    const sec = Math.floor(at / 1000);
    let m = inboundRecent.get(id);
    if (!m) { m = { newest: sec, sum: { r: 0, b: 0 }, buckets: new Map() }; inboundRecent.set(id, m); }
    if (sec > m.newest) advanceInboundWindow(m, sec);
    if (m.sum.r + 1 > INBOUND_RATE_PER_MIN || m.sum.b + bytes > INBOUND_BYTES_PER_MIN) return false;
    const cur = m.buckets.get(sec) || { r: 0, b: 0 };
    cur.r++; cur.b += bytes;
    m.buckets.set(sec, cur);
    m.sum.r++; m.sum.b += bytes;
    return true;
  }
  function inboundSpeedFor(id, at = Date.now()) {
    const sec = Math.floor(at / 1000);
    const m = inboundRecent.get(id);
    if (!m) return { reqPerMin: 0, bytesPerMin: 0 };
    if (sec > m.newest) advanceInboundWindow(m, sec);
    return { reqPerMin: m.sum.r, bytesPerMin: m.sum.b };
  }
  /** 被扩网凭据限额（R129）：速度/日/月/总次数与流量，缺省继承全局默认；只核预算不预扣（同 gate）。 */
  function inboundGate(c, costBytes = 0, at = Date.now()) {
    if (!c.limits) return { ok: true };
    const lim = eff(c), s = expand.stats.perInbound[c.id] || (expand.stats.perInbound[c.id] = emptySide());
    const date = new Date(at);
    const reject = (error, scope, limit, used) => ({ ok: false, code: 429, error, scope, limit, used });
    for (const [scope, bucket] of [['daily', s.days[dayKey(date)]], ['monthly', s.months[monthKey(date)]], ['total', s.total]]) {
      const requests = bucket?.requests || 0, bytes = (bucket?.bytesIn || 0) + (bucket?.bytesOut || 0);
      const rq = lim[scope + 'Requests'], bq = lim[scope + 'Bytes'];
      if (rq > 0 && requests + 1 > rq) return reject(scope + '-requests-quota', scope, rq, requests);
      if (costBytes > 0 && bq > 0 && bytes + costBytes > bq) return reject(scope + '-quota', scope, bq, bytes);
    }
    const speed = inboundSpeedFor(c.id, at);
    if (speed.reqPerMin + 1 > lim.ratePerMin) return reject('rate-limit', 'rate', lim.ratePerMin, speed.reqPerMin);
    if (costBytes > 0 && speed.bytesPerMin + costBytes > lim.bytesPerMin) return reject('bytes-rate-limit', 'rate', lim.bytesPerMin, speed.bytesPerMin);
    return { ok: true };
  }
  // 无凭据（未配对）来源按 IP 限速：直接丢弃 + 限速（防滥用 §9.1/§9.2）。
  const unauthRecent = new Map(); // ip → { newest, sum, buckets:Map(sec→n) }（R162 O(1)）
  function unauthRateOk(ip, at = Date.now()) {
    if (!ip) return false;
    const sec = Math.floor(at / 1000);
    let m = unauthRecent.get(ip);
    if (!m) { m = { newest: sec, sum: 0, buckets: new Map() }; unauthRecent.set(ip, m); }
    if (sec > m.newest) {
      for (let s = m.newest + 1; s <= sec; s++) {
        const old = m.buckets.get(s - 60);
        if (old) { m.sum -= old; m.buckets.delete(s - 60); }
      }
      m.newest = sec;
    }
    if (m.sum + 1 > UNAUTH_RATE_PER_MIN) return false;
    m.buckets.set(sec, (m.buckets.get(sec) || 0) + 1);
    m.sum += 1;
    return true;
  }
  const recent = new Map(); // cid → Map(sec → {r,b})
  /** R161：限速滑动窗口（Redis「主循环只做 O(1) 内存操作」实践）。
   * recent: Map<cid, { newest, sum:{r,b}, buckets:Map<sec,{r,b}> }> —— sum 为 60s 窗口内总和，
   * speedAdd 按秒推进窗口并扣减刚过期桶，speedFor 读 sum（O(1)）；时间回拨不推进窗口（sum 偏大=保守限速）。 */
  function advanceSpeedWindow(m, sec) {
    for (let s = m.newest + 1; s <= sec; s++) {
      const old = m.buckets.get(s - 60);
      if (old) { m.sum.r -= old.r; m.sum.b -= old.b; m.buckets.delete(s - 60); }
    }
    m.newest = sec;
  }
  function speedAdd(cid, requests, bytes, now) {
    const sec = Math.floor(now / 1000);
    let m = recent.get(cid);
    if (!m) { m = { newest: sec, sum: { r: 0, b: 0 }, buckets: new Map() }; recent.set(cid, m); }
    if (sec > m.newest) advanceSpeedWindow(m, sec);
    const b = m.buckets.get(sec) || { r: 0, b: 0 };
    b.r += requests; b.b += bytes;
    m.buckets.set(sec, b);
    m.sum.r += requests; m.sum.b += bytes;
  }
  function speedFor(cid, at = Date.now()) {
    const now = Math.floor(at / 1000);
    const m = recent.get(cid);
    if (!m) return { reqPerMin: 0, bytesPerMin: 0 };
    if (now > m.newest) advanceSpeedWindow(m, now);
    return { reqPerMin: m.sum.r, bytesPerMin: m.sum.b };
  }
  function totalSpeed() {
    const now = Math.floor(Date.now() / 1000);
    let r = 0, b = 0;
    for (const m of recent.values()) for (const [sec, v] of m.buckets) if (sec > now - 60) { r += v.r; b += v.b; }
    return { reqPerMin: r, bytesPerMin: b };
  }
  const pruneTimer = setInterval(() => {
    const cutoff = Math.floor(Date.now() / 1000) - 90;
    for (const [cid, m] of recent) {
      for (const [sec, v] of m.buckets) if (sec < cutoff) { m.sum.r -= v.r; m.sum.b -= v.b; m.buckets.delete(sec); }
      if (!m.buckets.size) recent.delete(cid);
    }
    for (const [cid, m] of inboundRecent) {
      for (const [sec, v] of m.buckets) if (sec < cutoff) { m.sum.r -= v.r; m.sum.b -= v.b; m.buckets.delete(sec); }
      if (!m.buckets.size) inboundRecent.delete(cid);
    }
    for (const [ip, m] of unauthRecent) {
      for (const [sec, n] of m.buckets) if (sec < cutoff) { m.sum -= n; m.buckets.delete(sec); }
      if (!m.buckets.size) unauthRecent.delete(ip);
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
    aggTotalsAdd(add, date); // R162：全局聚合增量维护（O(1)）
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
    queuedBytes = queuedBytesSum(); // 自愈：与真实队列对账，防止计数漂移
  }, 5_000);
  queueClean.unref();
  // 30 天黑名单清理也按注入时钟走；每小时一次，重启时还会再清一次。
  const securityGc = setInterval(() => { pruneSecurity(now()); saveSecurity(); }, 3600_000);
  securityGc.unref();

  /** 实例级队列总字节预算（F13）：多用户大信封时内存有上限；超预算拒收 queue-full，不静默丢。 */
  const QUEUE_BYTE_BUDGET = 64 * 1024 * 1024;
  let queuedBytes = 0;
  function queuedBytesSum() {
    let n = 0;
    for (const v of ren.values()) for (const x of v.queue) n += Buffer.byteLength(x.env, 'utf8');
    return n;
  }
  function enqueueLocal(to, env, now = Date.now(), addition = null) {
    // 防御性暂停门（入口层已拦）：暂停期间绝不产生新队列条目。
    if (!cfg.accepting) return { ok: false, code: 'not-accepting', body: { ok: false, error: 'not-accepting' }, rejected: 1 };
    const y = ren.get(to);
    if (!y || now - y.lastSeen >= zaiXianTtl()) return { ok: false, code: 'offline', body: { ok: false, offline: true }, offline: 1 };
    const queue = y.queue;
    // R161：惰性清理——exp 随 now 单调，队首最早过期，只 shift 队首（原 filter 全队列扫描是 O(n) 算法 DoS 面）；
    // 时钟回拨乱序时由 queueClean 5s 全量兜底。
    while (queue.length && queue[0].exp <= now) {
      queuedBytes = Math.max(0, queuedBytes - Buffer.byteLength(queue[0].env, 'utf8'));
      queue.shift();
    }
    if (queue.length >= cfg.queuePerUser) return { ok: false, code: 'queue-full', body: { ok: false, error: 'queue-full' }, rejected: 1 };
    const envBytes = Buffer.byteLength(env, 'utf8');
    if (queuedBytes + envBytes > QUEUE_BYTE_BUDGET) return { ok: false, code: 'queue-full', body: { ok: false, error: 'queue-full', budgetExceeded: true }, rejected: 1 };
    const id = crypto.randomUUID();
    queue.push({ id, env, addition: addition || null, exp: now + TTL_MS }); // R135g：附加内容随队列条目存储，poll 同序返回
    y.queue = queue;
    queuedBytes += envBytes;
    // 在线状态只由 register/heartbeat/poll/bye 刷新：发送方持续发消息不能替收件人续在线（F13）。
    return { ok: true, id, body: { ok: true, queued: true }, bytesIn: envBytes, relayed: 1 };
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
   * prefer（DHT 定位到的目标所在中继站）：匹配的 peer 排最前优先尝试；
   * 转发仍只走已配置互信（凭据 + TLS 指纹固定）的 peer，DHT 不做无凭据投递。
   */
  async function forwardToPeers(to, env, msgId, meta, route, prefer = null, addition = null) {
    const attempts = [];
    const bytes = Buffer.byteLength(env, 'utf8');
    const deadline = Date.now() + UPSTREAM_TIMEOUT_MS;
    let list = expand.outbound.filter((x) => x.enabled);
    if (prefer) {
      const hit = list.find((p) => {
        const t = peerTls(p);
        if (prefer.tlsFingerprint && t.fingerprint && t.fingerprint === prefer.tlsFingerprint) return true;
        return p.host === prefer.host && p.port === prefer.port;
      });
      if (hit) list = [hit, ...list.filter((p) => p.id !== hit.id)];
    }
    let tried = 0;
    for (const p of list) {
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
        // R135g：转出必带附加内容或密封标记——接收站（F中继）见 addition 或 additionLocked 一律不再添加
        ...(addition ? { addition } : { additionLocked: true }),
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
    if (!cred) {
      // 未配对请求直接丢弃（401），并按来源 IP 限速，防止陌生人打满资源。
      const ip = String(req.socket.remoteAddress || '').slice(0, 80);
      if (!unauthRateOk(ip)) return send(res, 429, { ok: false, error: 'rate-limit', instanceId: expand.instanceId });
      return send(res, 401, { ok: false, error: 'expand-credential-required' });
    }
    if (cred.expiresAt && now() > cred.expiresAt) {
      cred.lastAt = now(); cred.lastResult = 'expired'; markExpandDirty();
      return send(res, 401, { ok: false, error: 'credential-expired', instanceId: expand.instanceId });
    }
    if (credPortUnavailable(cred)) {
      cred.lastAt = now(); cred.lastResult = 'port-unavailable'; markExpandDirty();
      return send(res, 401, { ok: false, error: 'credential-port-unavailable', instanceId: expand.instanceId, boundPort: boundPort || opt.port });
    }
    // 暂停 truth table：新投递入口（relay、expand relay）一律 503，不入队。
    if (!cfg.accepting) return send(res, 503, { ok: false, error: 'not-accepting', instanceId: expand.instanceId });
    if (updateFreeze) return send(res, 503, { ok: false, error: 'updating', instanceId: expand.instanceId });
    // 只有通过凭据认证的入站才算“外部可达”的证据。
    security.lastInbound = { at: now(), from: String(req.socket.remoteAddress || '').slice(0, 80) };
    markSecurityDirty();
    let j;
    try { j = await body(req, cfg.maxEnvelope + 8192); }
    catch { return send(res, 400, { ok: false, error: 'bad-json' }); }
    // 读慢正文期间凭据可能被停用/删除/过期/端口失效：复核后才继续。
    if (cred.disabled || !expand.inbound.includes(cred) || (cred.expiresAt && now() > cred.expiresAt) || credPortUnavailable(cred)) {
      return send(res, 401, { ok: false, error: 'expand-credential-required' });
    }
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
    // R135g F中继完整性检查：转来的报文必须已带附加内容或密封标记（否则 = 旧版本/被改造上游，直接丢弃）；F中继任何情况不添加。
    const jAddition = typeof j.addition === 'string' && j.addition ? j.addition : null;
    if (jAddition === null && j.additionLocked !== true) return fail(400, 'addition-required');
    if (jAddition !== null && !validAdditionText(jAddition)) return fail(400, 'bad-addition');
    if (!routeJ.ok) {
      if (routeJ.error === 'loop') security.violations.loop++; else security.violations.routeTooLong++;
      saveSecurity();
      return fail(409, routeJ.error);
    }
    if (!inboundRateCheck(cred.id, bytes)) return fail(429, 'rate-limit');
    const ig = inboundGate(cred, bytes);
    if (!ig.ok) return fail(429, ig.error);
    const vo = verifyOrigin({ msgId, origin: String(j.origin || ''), originPub: String(j.originPub || ''), originSig: String(j.originSig || ''), to, createdAt, envelope: env });
    if (!vo.ok) return fail(vo.reason === 'loop' ? 409 : 403, vo.reason);
    const note = noteMessage(msgId, String(j.origin || ''));
    if (!note.ok) return fail(409, note.reason === 'blacklisted' ? 'message-blacklisted' : 'duplicate-message', { reason: note.detail || note.reason, count: note.count });

    const local = enqueueLocal(to, env, Date.now(), jAddition); // 注：用真实时间（与 relay 入口一致；注入时钟只影响 noteMessage 窗口）
    if (local.ok) {
      recordExpand('inbound', source, { requests: 1, bytesIn: bytes, relayed: 1, delivered: 1 }, 'queued', cred.id);
      cred.lastAt = now(); cred.lastResult = 'queued';
      return send(res, 200, { ok: true, queued: true, msgId, instanceId: expand.instanceId });
    }
    // 本机确实送不到：带着原来源签名继续转发（中间跳不能改任何签名覆盖字段）。
    const fwd = await forwardToPeers(to, env, msgId, {
      origin: String(j.origin), originPub: String(j.originPub), originSig: String(j.originSig), createdAt,
    }, routeJ.route, cfg.dht.routeByDht ? (await dhtRouteTarget(to)) : null, jAddition);
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
    if (c.expiresAt && now() > c.expiresAt) {
      c.lastAt = now(); c.lastResult = 'expired'; markExpandDirty();
      return send(res, 401, { ok: false, error: 'credential-expired' });
    }
    if (credPortUnavailable(c)) {
      c.lastAt = now(); c.lastResult = 'port-unavailable'; markExpandDirty();
      return send(res, 401, { ok: false, error: 'credential-port-unavailable', boundPort: boundPort || opt.port });
    }
    return send(res, 200, {
      ok: true, instanceId: expand.instanceId, product: PRODUCT, version: VERSION,
      port: boundPort || opt.port, tls: tlsPublicView(), msgPolicy: { replayMaxPasses: REPLAY_MAX_PASSES, windowMs: MESSAGE_WINDOW_MS },
    });
  }
  /** 不鉴权的指纹引导端点：只给实例 ID/版本/证书指纹，不含任何凭据或消息。 */
  function handleExpandIdentify(req, res) {
    return send(res, 200, {
      ok: true, instanceId: expand.instanceId, product: PRODUCT, version: VERSION,
      port: boundPort || opt.port, tls: tlsPublicView(), identityPub: expand.identity.pub,
      msgPolicy: { replayMaxPasses: REPLAY_MAX_PASSES, windowMs: MESSAGE_WINDOW_MS, maxRoute: MAX_ROUTE },
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
    // R162：content-length 已知时预分配单缓冲直写（免分块数组 + Buffer.concat 二次拷贝）；声明与实收不一致拒绝
    const clen = Number(req.headers['content-length']);
    if (Number.isInteger(clen) && clen > 0 && clen <= max) {
      const buf = Buffer.allocUnsafe(clen);
      let off = 0;
      for await (const c of req) {
        if (off + c.length > clen) throw new Error('too-large');
        c.copy(buf, off);
        off += c.length;
      }
      if (off !== clen) throw new Error('too-large');
      let j;
      try { j = JSON.parse(buf.toString('utf8') || '{}'); } catch { throw new Error('bad-json'); }
      if (!j || typeof j !== 'object' || Array.isArray(j)) throw new Error('bad-json-object');
      return j;
    }
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

  /* ── R135k 帮助文档：内嵌（SEA asset 或源码文件）→ 导出到数据目录 → 返回本地绝对路径（file:// 打开，不写死路径） ── */
  function helpHtml() {
    if (IS_SEA && SEA) {
      try { return SEA.getAsset('help.html', 'utf8'); } catch { /* fallback */ }
    }
    try { return fs.readFileSync(path.join(HERE, 'help.html'), 'utf8'); } catch { return null; }
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
      masked: c.tail5 ? '…' + c.tail5 : (c.hash ? '…' + String(c.hash).slice(-5) : ''), // R150：明文末尾 5 位（人可对账）；旧数据无 tail5 回退哈希尾 5
      public: c.public === true, publicToken: c.public === true ? String(c.publicToken || '') : '', // R153：内置公用明文展示
      createdAt: c.createdAt,
      disabled: !!c.disabled,
      limits: c.limits,
      effective: eff(c),
      endpoint: c.host ? { host: c.host, port: c.port || CRED_DEFAULT_PORT } : null,
      total: withBytes(total),
      today: withBytes(today),
      month: withBytes(month),
      year: withBytes(year),
      usage: usageOf(c),
      speed: speedFor(c.id),
      peakPerMin: s.peakPerMin,
      peakAt: s.peakAt,
      lastUsed: c.lastUsed || s.lastUsed || 0,
      addition: c.addition || null, // R135g：凭证级附加内容配置
    };
  }
  /** 管理面列表分页：limit 默认 200、上限 5000；offset 默认 0；非法值回退默认。 */
  function adminPage(u) {
    let limit = Math.floor(Number(u && u.searchParams.get('limit')));
    if (!Number.isFinite(limit) || limit <= 0) limit = 200;
    limit = Math.min(5000, limit);
    let offset = Math.floor(Number(u && u.searchParams.get('offset')));
    if (!Number.isFinite(offset) || offset < 0) offset = 0;
    return { limit, offset };
  }
  /** 凭据按创建时间倒序（新凭据排第一页，创建后刷新立即可见；同毫秒保持插入序）。 */
  function credsNewestFirst() {
    return Object.values(creds).sort((a, b) => (a.createdAt === b.createdAt ? 0 : a.createdAt < b.createdAt ? 1 : -1));
  }
  function buildStats(u) {
    // R153b：兜底——内置公用凭据惰性确保。仅在「语言已选定」或「首启弹窗已展示（含跳过）」后创建：
    // 名称按创建时刻语言（cfg.lang || zh-CN），创建后不因换语言改名。首启弹窗未展示前不创建（等用户选定语言，
    // 名称跟随所选语言）。
    if (cfg.lang || cfg.langAsked) ensureBuiltinCredentials(cfg.lang || 'zh-CN');
    const page = adminPage(u);
    // R161：聚合缓存——record() 使全部失效；同分页 15s 窗口内重复查询直接返回（100k 表从 ~170ms → ~0ms）。
    const nowMs = Date.now();
    const ck = page.offset + ':' + page.limit;
    const hit = statsAggCache.get(ck);
    if (hit && nowMs - hit.at < 15_000) return hit.out;
    const now = Date.now();
    const all = Object.values(creds);
    const list = credsNewestFirst().slice(page.offset, page.offset + page.limit).map(viewCred);
    // R162：totals 直接读增量聚合（O(1)），不再遍历 100k 凭据
    const total = aggTotals.total;
    const today = aggTotals.days[dayKey()] || emptyAgg();
    const month = aggTotals.months[monthKey()] || emptyAgg();
    const year = aggTotals.years[yearKey()] || emptyAgg();
    const withBytes = (b) => ({ ...b, bytes: (b.bytesIn || 0) + (b.bytesOut || 0) });
    // 全局峰值 = 所有凭据计数之和的峰值，恒 ≥ 任何单凭据峰值 → 直接读 stats.peakPerMin（O(1)）
    const peak = stats.peakPerMin;
    const out = {
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
      credTotal: all.length,
      credEnabled: all.reduce((n, c) => n + (c.disabled ? 0 : 1), 0),
      credOffset: page.offset,
      credLimit: page.limit,
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
      publicIp: { ...lastPub },
      listeningPorts: listeningPorts(),
      entryPort: cfg.ports[0],
      update: updateSummary(),
    };
    statsAggCache.set(ck, { at: nowMs, out });
    return out;
  }

  // ── 自动更新（只在单文件运行时可执行替换；源码运行只允许检查）──
  function emptyUpdate() {
    return { auto: 'check', intervalHours: 6, lastCheck: 0, latest: null, lastError: '', lastInstall: null, triedVersion: '', triedAt: 0, progress: null };
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
    o.triedAt = Number(raw.triedAt) || 0;
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
  /** 更新替换期间冻结新投递（允许 poll 排空）；交接后禁止旧进程再写共享状态（F04）。 */
  let updateFreeze = false;
  let sharedStateFrozen = false;
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
    // 更新交接后旧进程会把最终 lastInstall 写盘；新进程合并磁盘上更新的记录，避免内存暂存标记盖住结果（F04）。
    try {
      const disk = normUpdate(JSON.parse(fs.readFileSync(UPDATE_FILE, 'utf8')));
      if (disk.lastInstall && (!upd.lastInstall || disk.lastInstall.at >= upd.lastInstall.at)) upd.lastInstall = disk.lastInstall;
    } catch { /* noop */ }
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
      canInstall: !!(IS_SEA && platform && available && assetOk && !updateInstalling && !staged), // R135w：等待重启（staged）期间不可再点
      installing: updateInstalling,
      checking: updateChecking,
      staged: !!staged,
      queue: queuedTotal(),
      lastInstall: upd.lastInstall,
      progress: upd.progress || null, // R158：下载/安装进度（前端进度条轮询）
    };
  }
  /** 更新源白名单：初始 URL 与每一跳重定向都必须过（F12）。Release 资产会 302 到 GitHub CDN。 */
  function allowedUpdateUrl(raw) {
    try {
      const u = new URL(String(raw));
      if (process.env.FWARMY_UPDATE_TEST === '1') return u.protocol === 'http:' || u.protocol === 'https:';
      if (u.protocol !== 'https:') return false;
      const host = u.hostname.toLowerCase();
      return host === 'github.com' || host.endsWith('.github.com') || host.endsWith('.githubusercontent.com');
    } catch { return false; }
  }
  /** 手动跟随有限跳重定向：逐跳校验协议/主机，拒绝循环与 https→http 降级。 */
  async function fetchWithHops(url, { headers = {}, timeoutMs = 15_000, maxHops = 5 } = {}) {
    let cur = String(url);
    const seen = new Set();
    for (let hop = 0; hop <= maxHops; hop++) {
      if (!allowedUpdateUrl(cur)) throw new Error('update-url-not-allowed');
      if (seen.has(cur)) throw new Error('update-redirect-loop');
      seen.add(cur);
      const r = await fetch(cur, { headers, redirect: 'manual', signal: AbortSignal.timeout(timeoutMs) });
      if ([301, 302, 303, 307, 308].includes(r.status)) {
        const loc = r.headers.get('location') || '';
        if (!loc) throw new Error('update-redirect-no-location');
        const next = new URL(loc, cur).toString();
        if (cur.startsWith('https:') && !next.startsWith('https:') && process.env.FWARMY_UPDATE_TEST !== '1') {
          throw new Error('update-redirect-downgrade');
        }
        cur = next;
        continue;
      }
      return r;
    }
    throw new Error('update-redirect-too-many');
  }
  async function fetchText(url, timeout = 15_000) {
    const r = await fetchWithHops(url, {
      headers: { 'user-agent': `FWArmy/${VERSION}`, accept: 'application/vnd.github+json' },
      timeoutMs: timeout,
    });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    return await r.text();
  }
  async function fetchToFile(url, dest) {
    // R152：下载失败自动重试 3 次（网络瞬断/GitHub CDN 抖动常见；指数退避 2s/4s）
    // R158：流式下载并更新 upd.progress（前端进度条轮询展示）
    let lastErr = null;
    for (let attempt = 1; attempt <= 3; attempt++) {
      try {
        const r = await fetchWithHops(url, {
          headers: { 'user-agent': `FWArmy/${VERSION}` },
          timeoutMs: 10 * 60_000,
        });
        if (!r.ok) throw new Error('HTTP ' + r.status);
        const total = Number(r.headers.get('content-length')) || 0;
        upd.progress = { phase: 'download', pct: 5, got: 0, total, detail: '下载中…' };
        if (!r.body) {
          fs.writeFileSync(dest, Buffer.from(await r.arrayBuffer()));
          upd.progress = null;
          return;
        }
        // R158：进度统计用 Transform 中间件（pipeline 单消费者，避免 on('data') 双消费竞争导致写入不完整）
        const ws = fs.createWriteStream(dest);
        const fmtB = (n) => (n >= 1048576 ? (n / 1048576).toFixed(1) + 'MB' : Math.round(n / 1024) + 'KB');
        let got = 0;
        const counter = new Transform({
          transform(chunk, _enc, cb) {
            got += chunk.length;
            if (total > 0 && got % (1 << 20) < 65536) {
              upd.progress = { phase: 'download', pct: Math.min(80, 5 + Math.round((got / total) * 75)), got, total, detail: `下载中… ${fmtB(got)} / ${fmtB(total)}` };
            }
            cb(null, chunk);
          },
        });
        await pipeline(Readable.fromWeb(r.body), counter, ws);
        upd.progress = null;
        return;
      } catch (e) {
        lastErr = e;
        upd.progress = null;
        if (attempt < 3) {
          log('WARN', `更新：下载第 ${attempt} 次失败（${String(e && e.message || e).slice(0, 120)}），${attempt * 2}s 后重试`);
          await sleep(attempt * 2000);
        }
      }
    }
    throw lastErr || new Error('download-failed');
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
  /** 更新后的健康判定：HTTP 200 + FWArmy 产品 + 目标版本 + 同数据目录身份（F04）。 */
  function probeLocalIdentity(port, expect = null, timeout = 700) {
    return new Promise((resolve) => {
      const req = http.get({ host: '127.0.0.1', port, path: '/api/health', timeout }, (res) => {
        const chunks = [];
        res.on('data', (d) => chunks.push(d));
        res.on('end', () => {
          let j = null;
          try { j = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { /* noop */ }
          if (!j || res.statusCode !== 200) return resolve(null);
          if (j.server !== 'fwarmy-relay' && j.server !== 'warmy-relay') return resolve(null);
          if (j.product !== PRODUCT) return resolve(null);
          if (expect && expect.version && j.version !== expect.version) return resolve(null);
          if (expect && expect.dataDirHash && j.dataDirHash && j.dataDirHash !== expect.dataDirHash) return resolve(null);
          resolve(j);
        });
      });
      req.on('timeout', () => { try { req.destroy(); } catch { /* noop */ } resolve(null); });
      req.on('error', () => resolve(null));
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
      const r = await fetchWithHops(`${apiBase}/releases/latest`, {
        headers: { 'user-agent': `FWArmy/${VERSION}`, accept: 'application/vnd.github+json' },
        timeoutMs: 15_000,
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
      // 同版本失败后 6 小时内不自动重试；之后有界退避重试，而不是永久跳过（F04）。
      const triedRecently = upd.triedVersion === version && Date.now() - (upd.triedAt || 0) < 6 * 3600_000;
      if (allowAuto && upd.auto === 'install' && available && !triedRecently && !updateInstalling) {
        if (queuedTotal() === 0) {
          upd.triedVersion = version;
          upd.triedAt = Date.now();
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
    if (IS_SEA && pendingUpdatePath && fs.existsSync(pendingUpdatePath)) throw new Error('update-pending-restart'); // R135w：等待重启期间拒绝重复安装（防竞态）
    if (!IS_SEA) throw new Error('not-single-file');
    const platform = updatePlatform();
    if (!platform) throw new Error('unsupported-platform');
    if (!upd.latest || !upd.latest.asset) await checkUpdate(true, false);
    const latest = upd.latest;
    if (!latest || !latest.asset) throw new Error('no-update-asset');
    if (process.env.FWARMY_UPDATE_TEST !== '1' && compareVersion(latest.version, VERSION) <= 0) throw new Error('already-latest');
    if (!force && queuedTotal() > 0) throw new Error('queue-not-empty');
    updateInstalling = true;
    updateFreeze = true; // F04：下载/校验期间停止新投递，poll 仍可排空
    upd.lastError = '';
    saveUpdate();
    const work = path.join(DATA, 'updates', latest.version.replace(/[^0-9A-Za-z._-]/g, '_'));
    try {
      fs.rmSync(work, { recursive: true, force: true });
      fs.mkdirSync(work, { recursive: true });
      const archive = path.join(work, String(latest.asset.name).replace(/[\\/:*?"<>|]/g, '_'));
      log('INFO', `更新：下载 ${latest.version} ${latest.asset.name}`);
      upd.progress = { phase: 'download', pct: 2, got: 0, total: 0, detail: '连接下载…' };
      await fetchToFile(latest.asset.url, archive);
      upd.progress = { phase: 'verify', pct: 85, detail: '校验 SHA-256…' };
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
      upd.progress = { phase: 'extract', pct: 90, detail: '解压安装包…' };
      const extract = path.join(work, 'extract');
      fs.mkdirSync(extract, { recursive: true });
      // F12：解压前先列条目——拒绝绝对路径/盘符/上级逃逸/条目数爆炸（可离线用合成恶意包测试）。
      {
        const listTar = process.platform === 'win32'
          ? path.join(process.env.SystemRoot || 'C:\Windows', 'System32', 'tar.exe')
          : 'tar';
        const canList = process.platform !== 'win32' || fs.existsSync(listTar);
        if (canList) {
          const lx = spawnSync(listTar, ['-tf', archive], { timeout: 60_000, encoding: 'utf8' });
          if (lx.status !== 0) throw new Error('archive-list-failed');
          const entries = String(lx.stdout || '').split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
          if (entries.length > 2000) throw new Error('archive-too-many-entries');
          for (const en of entries) {
            const norm = en.replace(/\\/g, '/');
            if (norm.startsWith('/') || /^[A-Za-z]:/.test(norm) || norm.split('/').includes('..')) {
              throw new Error('archive-entry-path-not-allowed');
            }
          }
        }
      }
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
      // F12：解压后清点产物——拒绝符号链接与超量解压；预期单文件程序之外只允许有限伴随文件。
      {
        const budget = 512 * 1024 * 1024;
        let total = 0;
        const walk = (dir, depth = 0) => {
          if (depth > 4) return;
          for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
            const p = path.join(dir, e.name);
            if (e.isSymbolicLink()) throw new Error('extract-symlink-not-allowed');
            if (e.isDirectory()) walk(p, depth + 1);
            else if (e.isFile()) total += fs.statSync(p).size;
            if (total > budget) throw new Error('extract-size-exceeded');
          }
        };
        walk(extract);
      }
      const binName = process.platform === 'win32' ? 'FWArmy.exe' : 'FWArmy';
      const found = findUpdateBinary(extract, binName);
      if (!found) throw new Error('binary-not-found');
      if (process.platform !== 'win32') fs.chmodSync(found, 0o755);
      const newVer = spawnSync(found, ['--version'], { timeout: 30_000, encoding: 'utf8', windowsHide: true });
      if (newVer.status !== 0 || !/FWArmy/.test(String(newVer.stdout))) throw new Error('new-binary-cannot-run');
      if (process.env.FWARMY_UPDATE_TEST !== '1' && !String(newVer.stdout).includes(`FWArmy ${latest.version}`)) {
        throw new Error('new-binary-version-mismatch');
      }
      upd.progress = { phase: 'stage', pct: 95, detail: '暂存新程序…' };
      const staged = path.join(work, binName + '.new');
      fs.rmSync(staged, { force: true });
      fs.copyFileSync(found, staged);
      if (process.platform !== 'win32') fs.chmodSync(staged, 0o755);
      pendingUpdatePath = staged;
      log('INFO', `更新：已暂存 ${staged} exists=${fs.existsSync(staged)} size=${fs.existsSync(staged) ? fs.statSync(staged).size : 0}`);
      // F04：替换前排空队列并再次核对；成功标记只在新进程真正健康后由 applyUpdate 写。
      upd.progress = { phase: 'restart', pct: 98, detail: '排空队列，准备重启…' };
      const drainDeadline = Date.now() + 35_000;
      while (queuedTotal() > 0 && Date.now() < drainDeadline) await sleep(500);
      if (!force && queuedTotal() > 0) throw new Error('queue-not-empty');
      upd.lastInstall = { version: latest.version, at: Date.now(), ok: false, error: '' };
      upd.lastError = '';
      saveUpdate();
      log('INFO', `更新：${latest.version} 已下载并校验（队列 ${queuedTotal()}），准备重启`);
      setTimeout(() => { applyUpdate(staged).catch((e) => log('ERROR', '重启应用更新失败：' + String(e && e.message || e).slice(0, 200))); }, 500).unref?.();
      return updateView();
    } catch (e) {
      const msg = String(e && e.message || e).slice(0, 300);
      updateFreeze = false;
      upd.lastError = msg;
      upd.lastInstall = { version: latest.version, at: Date.now(), ok: false, error: msg };
      upd.progress = null; // R158：失败清除进度
      saveUpdate();
      log('WARN', '更新失败：' + msg);
      throw e;
    } finally {
      updateInstalling = false;
    }
  }
  async function applyUpdate(stagedPath = '') {
    if (!IS_SEA) return;
    // R146：服务器已关闭（管理员点「停止」）时取消待执行的更新重启——否则 update 计时器会竞态拉起新进程
    if (updateClosed) {
      log('WARN', '更新已取消：服务器处于关闭流程');
      return;
    }
    const current = process.execPath;
    const staged = stagedPath || pendingUpdatePath || (current + '.new');
    log('INFO', `更新：检查待替换文件 ${staged} exists=${fs.existsSync(staged)}`);
    if (!fs.existsSync(staged)) {
      pendingUpdatePath = ''; // R135w：staged 缺失是异常态，清掉待重启标记以允许重试
      updateFreeze = false;
      upd.lastError = 'staged-missing';
      upd.lastInstall = { version: upd.latest ? upd.latest.version : '', at: Date.now(), ok: false, error: 'staged-missing' };
      saveUpdate();
      log('WARN', '更新：找不到待替换文件，保留当前程序');
      return;
    }
    // R166：更新重启沿用原启动方式——显式 --port 才带 --port（保持单端口语义）；默认配置模式不带，
    // 否则新进程被 --port 钉成单端口，cfg.ports 里的默认端口（59599/58588）不再监听（默认端口丢失根因）
    const args = ['--server', `--host=${opt.host}`, `--data=${DATA}`, '--no-open'];
    if (opt.portExplicit) args.push(`--port=${actualPort || opt.port}`);
    if (opt.quiet) args.push('--quiet');
    if (opt.noTray) args.push('--no-tray'); // R135y：更新重启保留托盘开关
    if (opt.logFile) args.push(`--log-file=${opt.logFile}`);
    const old = `${current}.old-${Date.now()}`;
    log('INFO', `更新：关闭服务并重启以应用 ${upd.latest ? upd.latest.version : '新版本'}`);
    try { await close(); } catch { /* noop */ }
    sharedStateFrozen = true; // 交接后旧进程不再写 stats/expand/security/update
    releaseLock(); // 锁交接：新进程要拿同一数据目录的单实例锁，旧进程先放（F04/F07）
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
      // R136：自动更新除替换 exe 外，同步白名单伴随文件（托盘脚本/启动脚本/图标等）——
      // 旧目录（无这些文件）自动更新上来也能获得完整功能；data/ 一律不碰。
      try {
        const workDir = path.join(DATA, 'updates', upd.latest ? String(upd.latest.version).replace(/[^0-9A-Za-z._-]/g, '_') : '');
        const extractDir = path.join(workDir, 'extract');
        const COMPANION_FILES = ['fwarmy-tray.ps1', 'start.bat', 'stop.bat', 'fwarmy-headless.bat', 'fwarmy-console.bat', 'set-folder-icon.bat', 'install.ps1', 'assets/fwarmy.ico', 'assets/logo.svg'];
        // R137：归档顶层带版本目录（Compress-Archive 压入 stage 目录名），扁平直取会全部落空——
        // 必须与 findUpdateBinary 同模式递归查找，旧目录自动更新才能补齐伴随文件。
        const findCompanion = (dir, base, depth = 0) => {
          let ents = [];
          try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch { return ''; }
          for (const e of ents) if (e.isFile() && e.name === base) return path.join(dir, e.name);
          if (depth >= 3) return '';
          for (const e of ents) {
            if (!e.isDirectory()) continue;
            const hit = findCompanion(path.join(dir, e.name), base, depth + 1);
            if (hit) return hit;
          }
          return '';
        };
        for (const f of COMPANION_FILES) {
          const src = findCompanion(extractDir, path.basename(f));
          if (!src) { log('WARN', `更新：归档中未找到伴随文件 ${f}（跳过）`); continue; }
          const dst = path.join(path.dirname(current), f);
          try {
            fs.mkdirSync(path.dirname(dst), { recursive: true });
            fs.copyFileSync(src, dst);
            log('INFO', `更新：同步伴随文件 ${f}`);
          } catch { /* 单个文件失败不影响主替换 */ }
        }
      } catch { /* 伴随文件同步失败不影响主替换 */ }
      const childEnv = { ...process.env };
      // 测试模式下给新进程标注目标版本，跨版本夹具才能验证健康判定（生产不设置）。
      if (process.env.FWARMY_UPDATE_TEST === '1' && upd.latest && upd.latest.version) {
        childEnv.FWARMY_FAKE_VERSION = upd.latest.version;
      }
      const child = spawn(current, args, { detached: true, stdio: 'ignore', cwd: path.dirname(current), windowsHide: true, env: childEnv });
      if (!child.pid) throw new Error('spawn-failed');
      child.on('error', (e) => log('ERROR', '新版本启动失败：' + String(e && e.message || e).slice(0, 200)));
      child.unref();
      log('INFO', `更新：新进程已启动 pid=${child.pid}，等待健康检查`);
      /** 等新进程真的能服务再退出；健康判定带产品/版本/数据目录身份，否则回滚（F04）。 */
      const expect = { version: upd.latest ? upd.latest.version : '', dataDirHash };
      let healthy = false;
      for (let i = 0; i < 120; i++) {
        await sleep(250);
        if (await probeLocalIdentity(actualPort || opt.port, expect)) { healthy = true; break; }
      }
      if (!healthy) {
        try { child.kill(); } catch { /* noop */ }
        throw new Error('new-server-not-healthy');
      }
      upd.lastInstall = { version: expect.version, at: Date.now(), ok: true, error: '' };
      upd.lastError = '';
      try { writeJsonAtomic(UPDATE_FILE, upd); } catch { /* noop */ }
      log('INFO', '更新：新进程健康（产品/版本/数据目录核对通过），旧进程退出');
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

  /* ── 自动重启定时器（R165）：到点重启自身；重启后按 intervalHours 重算下次 ── */
  let autoRestartTimer = null;
  function autorestartView() {
    const ar = cfg.autorestart;
    return { enabled: !!ar.enabled, intervalHours: ar.intervalHours, nextAt: ar.nextAt || 0, approxDays: ar.intervalHours / 24 };
  }
  function scheduleAutoRestart() {
    if (autoRestartTimer) { clearTimeout(autoRestartTimer); autoRestartTimer = null; }
    const ar = cfg.autorestart;
    if (!ar || !ar.enabled) return;
    let wait = (ar.nextAt || 0) - Date.now();
    if (wait <= 0) {
      // 重启后 / 错过时间：按间隔从当前重算下次（用户设置的间隔驱动滚动）
      ar.nextAt = Date.now() + ar.intervalHours * 3600_000;
      if (!saveCfg()) log('WARN', '自动重启：写下次重启时间到 config.json 失败');
      wait = ar.nextAt - Date.now();
    }
    autoRestartTimer = setTimeout(() => void doAutoRestart(), wait);
    if (autoRestartTimer.unref) autoRestartTimer.unref();
    log('INFO', `自动重启：已安排，下次重启时间 ${new Date(ar.nextAt).toLocaleString()}（${ar.intervalHours}h 间隔）`);
  }
  async function doAutoRestart() {
    if (updateClosed || stopping || !cfg.autorestart || !cfg.autorestart.enabled) return;
    log('INFO', '自动重启：到达计划时间，开始重启');
    // 交接前先把下次时间按间隔算好（新进程启动时读取 config.json 就会是未来时间）
    cfg.autorestart.nextAt = Date.now() + cfg.autorestart.intervalHours * 3600_000;
    if (!saveCfg()) log('WARN', '自动重启：保存下次重启时间失败');
    const args = ['--server', `--host=${opt.host}`, `--data=${DATA}`, '--no-open'];
    if (opt.portExplicit) args.push(`--port=${actualPort || opt.port}`); // R166：同更新重启——显式才钉端口
    if (opt.quiet) args.push('--quiet');
    if (opt.noTray) args.push('--no-tray');
    if (opt.logFile) args.push(`--log-file=${opt.logFile}`);
    const current = process.execPath;
    try { await close(); } catch { /* noop */ }
    sharedStateFrozen = true; // 旧进程不再写共享状态，交给新进程
    releaseLock();
    // SEA：直接重启 exe；源码：node server.mjs <参数>（SELF_FILE 为本文件绝对路径）
    const launch = IS_SEA
      ? { cmd: current, args }
      : { cmd: current, args: [SELF_FILE || path.join(HERE, 'server.mjs'), ...args] };
    const child = spawn(launch.cmd, launch.args, { detached: true, stdio: 'ignore', cwd: IS_SEA ? path.dirname(current) : HERE, windowsHide: true });
    if (!child.pid) {
      log('ERROR', '自动重启：spawn 失败');
      autoRestartTimer = setTimeout(() => void doAutoRestart(), 60_000);
      if (autoRestartTimer.unref) autoRestartTimer.unref();
      return;
    }
    child.on('error', (e) => log('ERROR', '自动重启：新进程启动失败 ' + String(e && e.message || e).slice(0, 200)));
    child.unref();
    log('INFO', `自动重启：新进程已启动 pid=${child.pid}，等待健康检查`);
    const expect = { version: VERSION, dataDirHash };
    let healthy = false;
    for (let i = 0; i < 120; i++) {
      await sleep(250);
      if (await probeLocalIdentity(actualPort || opt.port, expect)) { healthy = true; break; }
    }
    if (!healthy) {
      log('ERROR', '自动重启：新进程健康检查未通过（保留当前进程继续运行）');
      return;
    }
    log('INFO', '自动重启：新进程健康（产品/版本/数据目录核对通过），旧进程退出');
    setTimeout(() => process.exit(0), 100);
  }

  async function adminApi(req, res, u) {
    const p = u.pathname;
    if (req.method === 'GET' && p === '/api/admin/stats') return send(res, 200, buildStats(u));
    if (req.method === 'GET' && p === '/api/admin/lang') return send(res, 200, { ok: true, lang: cfg.lang, asked: cfg.langAsked }); // R138：语言持久化（null=未选过）；R148：asked=首启弹窗已展示过（托盘/无痕浏览器不再每次弹）
    if (req.method === 'POST' && p === '/api/admin/lang') {
      const j = await body(req);
      // R138：lang=null 表示清除选择（回到首启询问，asked 一并重置）；非白名单字符串一律 400；只传 asked 时不校验 lang
      if (j.lang !== undefined && j.lang !== null && (typeof j.lang !== 'string' || !UI_LANGS.includes(j.lang))) return send(res, 400, { ok: false, error: 'bad-lang' });
      if (j.lang === null) cfg.langAsked = false; else cfg.langAsked = true;
      if (j.asked === true && j.lang === undefined) cfg.langAsked = true; // R148：仅标记「已展示首启弹窗」，不改语言
      if (j.lang !== undefined) cfg.lang = j.lang === null ? null : j.lang;
      if (!saveCfg()) return send(res, 500, { ok: false, error: 'persist-failed' });
      // R153b：首次选定语言时创建内置公用凭据（名称跟随该语言；之后换语言不再变）
      if (cfg.lang) ensureBuiltinCredentials(cfg.lang);
      log('INFO', '界面语言已保存：' + String(cfg.lang) + ' asked=' + cfg.langAsked);
      return send(res, 200, { ok: true, lang: cfg.lang, asked: cfg.langAsked });
    }
    if (req.method === 'GET' && p === '/api/admin/export-config') {
      // R153：一键导出全部配置为 .nm 包（JSON）：config / credentials（sha256 + 内置公用明文）/ expand / addition / security。
      // 不含：TLS 私钥与用户证书（机器敏感、不可跨机搬移）、outbound 明文出网凭据（本机 AES 加密串原样导出——跨机导入后
      // 若本机 master key 不同则该扩网对端需重新填凭据）。
      const pkg = {
        format: 'fwarmy-config', v: 1, exportedAt: Date.now(), version: VERSION,
        config: cfg,
        credentials: { items: creds },
        expand,
        addition: { texts: (cfg.addition && Array.isArray(cfg.addition.texts) ? cfg.addition.texts : []) },
        security,
      };
      return send(res, 200, { ok: true, package: pkg, filename: 'fwarmy-config.nm' });
    }
    if (req.method === 'POST' && p === '/api/admin/import-config') {
      // R153：导入 .nm 包并替换当前全部配置（凭证/扩网/附加内容/全局配置/安全表）。管理面本机回环专属操作。
      const j = await body(req, 16 * 1024 * 1024);
      const pkg = j && typeof j.package === 'object' ? j.package : (j && typeof j === 'object' && j.format ? j : null);
      if (!pkg || pkg.format !== 'fwarmy-config') return send(res, 400, { ok: false, error: 'bad-package', hint: '不是 FWArmy 配置包（.nm）' });
      if (pkg.v !== 1) return send(res, 400, { ok: false, error: 'bad-package-version', hint: '配置包版本不支持：' + String(pkg.v) });
      try {
        // 1) 凭据：替换全表（含内置公用与自创；哈希一致才有效）
        const newCreds = {};
        for (const [id, raw] of Object.entries(pkg.credentials && pkg.credentials.items || {})) {
          const c = raw && typeof raw === 'object' ? { ...raw } : {};
          if (!c.hash || !/^[0-9a-f]{64}$/.test(String(c.hash))) continue;
          c.id = String(c.id || id); c.name = String(c.name || '未命名').slice(0, 40);
          c.hash8 = String(c.hash8 || String(c.hash).slice(0, 8));
          c.createdAt = String(c.createdAt || new Date().toISOString());
          c.disabled = c.disabled === true; c.lastUsed = Number(c.lastUsed) || 0;
          c.limits = normLimits(c.limits || null, {});
          c.tail5 = String(c.tail5 || '').slice(0, 5);
          c.public = c.public === true; c.publicToken = c.public ? String(c.publicToken || '').slice(0, 64) : '';
          newCreds[c.id] = c;
        }
        creds = newCreds; rebuildIndex(); saveCreds();
        // 2) 扩网（inbound/outbound/identity/stats）
        if (pkg.expand && typeof pkg.expand === 'object') {
          const ne = normExpand(pkg.expand);
          if (ne && ne.identity && ne.identity.pub) { expand = ne; saveExpand(); }
        }
        // 3) 附加内容库
        if (pkg.addition && Array.isArray(pkg.addition.texts)) {
          cfg.addition = { texts: pkg.addition.texts.map((t) => String(t).slice(0, ADDITION_MAX_BYTES)).slice(0, ADDITION_MAX_TEXTS) };
        }
        // 4) 全局配置（合并，保留本机 TLS 模式与端口监听相关关键项——密钥/证书路径不可搬移）
        if (pkg.config && typeof pkg.config === 'object') {
          const prevTls = cfg.tls;
          const prevPorts = cfg.ports;
          const prevLang = cfg.lang; const prevLangAsked = cfg.langAsked;
          cfg = { ...DEFAULTS, ...cfg, ...pkg.config };
          cfg.tls = prevTls; // 本机 TLS 证书/模式不随包搬移
          cfg.ports = prevPorts; // 监听端口不随包搬移（避免覆盖本机端口占用）
          cfg.lang = prevLang; cfg.langAsked = prevLangAsked;
          for (const k of Object.keys(CONFIG_RANGES)) {
            const n = Number(cfg[k]);
            cfg[k] = validLimit(k, n) ? n : DEFAULTS[k];
          }
          cfg.accepting = cfg.accepting !== false;
        }
        // 5) 安全表（黑名单/重放/固定公钥）
        if (pkg.security && typeof pkg.security === 'object') {
          security = normSecurity(pkg.security); saveSecurity();
        }
        if (!saveCfg()) return send(res, 500, { ok: false, error: 'persist-failed' });
        scheduleAutoRestart(); // 导入包可能携带自动重启配置，重排定时器
        // 6) 内置公用凭据保证（若包内没有，按当前语言补回）
        ensureBuiltinCredentials(cfg.lang);
        log('INFO', '配置包导入完成（.nm）：凭据/扩网/附加内容/全局/安全表已替换');
        return send(res, 200, { ok: true, creds: Object.keys(creds).length, expand: expand.inbound.length + expand.outbound.length, addition: (cfg.addition || { texts: [] }).texts.length });
      } catch (e) {
        return send(res, 400, { ok: false, error: 'import-failed', hint: String(e && e.message || e).slice(0, 200) });
      }
    }
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
    if (req.method === 'GET' && p === '/api/admin/autorestart') {
      return send(res, 200, { ok: true, autorestart: autorestartView() });
    }
    if (req.method === 'POST' && p === '/api/admin/autorestart') {
      const j = await body(req);
      if (typeof j.enabled !== 'boolean') return send(res, 400, { ok: false, error: 'bad-ar-config', hint: 'enabled 必须是布尔值' });
      const ih = Number(j.intervalHours);
      if (!Number.isFinite(ih) || ih <= 0 || ih > 100000) return send(res, 400, { ok: false, error: 'bad-ar-interval', hint: '间隔时间需为 1–100000 小时' });
      let nextAt = 0;
      if (j.nextAt !== undefined && j.nextAt !== null && j.nextAt !== '' && Number(j.nextAt) !== 0) {
        const n = Number(j.nextAt);
        if (!Number.isFinite(n) || n <= Date.now()) return send(res, 400, { ok: false, error: 'bad-ar-next', hint: '下次重启时间必须是未来时间' });
        nextAt = n;
      }
      cfg.autorestart = { enabled: j.enabled, intervalHours: ih, nextAt: j.enabled ? (nextAt || Date.now() + ih * 3600_000) : 0 };
      if (!saveCfg()) return send(res, 500, { ok: false, error: 'save-failed' });
      scheduleAutoRestart();
      return send(res, 200, { ok: true, autorestart: autorestartView() });
    }
    if (req.method === 'GET' && p === '/api/admin/expand') return send(res, 200, expandView());
    if (req.method === 'POST' && p === '/api/admin/expand-inbound') {
      const j = await body(req);
      if (j.host !== undefined) {
        const h = String(j.host || '').trim();
        const isV6 = h.includes(':') && (h.includes('::') || h.split(':').length > 2);
        if (!h || /[\s/?#]/.test(h) || h.length > 253 || (h.includes(':') && !isV6)) {
          return send(res, 400, { ok: false, error: 'bad-host', hint: '域名或 IP 不能为空，不能含空格/斜杠/问号/井号；不要在这里写端口（端口请填到端口输入框），IPv6 地址除外' });
        }
      }
      // R135p：生成时即可设置限额与有效期（弹窗填写，与中继凭据一致）
      let limits = null;
      if (j.limits !== undefined) {
        try { limits = parseLimits(j.limits, {}); }
        catch (e) { return send(res, 400, { ok: false, error: String(e.message || 'bad-limits') }); }
      }
      let expiresAt = 0;
      if (j.expiresDays !== undefined) {
        const d = Math.floor(Number(j.expiresDays));
        if (!Number.isFinite(d) || d < 0 || d > 36500) return send(res, 400, { ok: false, error: 'bad-expires-days' });
        if (d > 0) expiresAt = now() + d * 86400000;
      }
      // R142：凭据端口不在监听集 → 自动添加并监听（业务端口默认打开策略）
      if (j.port !== undefined) {
        const inPort = Math.floor(Number(j.port));
        if (Number.isInteger(inPort) && inPort >= 1 && inPort <= 65535) {
          const ep = await ensureCredPort(inPort);
          if (!ep.ok) return send(res, 401, { ok: false, error: 'credential-port-unavailable', hint: ep.error || '' });
        }
      }
      let generated;
      try { generated = generateInboundToken(j.name, j.port, j.host, limits, expiresAt); }
      catch (e) {
        if (String(e && e.message) === 'name-conflict') {
          return send(res, 400, { ok: false, error: 'name-conflict', hint: '已存在同名凭据；名称必须唯一，请换一个名称' });
        }
        throw e;
      }
      const { token, item } = generated;
      log('INFO', `被扩网：已生成新的接入凭据 #${expand.inbound.length}（地址 ${item.addr}，只显示一次）`);
      return send(res, 200, { ok: true, token, item: { id: item.id, name: item.name, masked: item.masked }, inbound: expandView().inbound });
    }
    if (req.method === 'POST' && p === '/api/admin/expand-inbound-update') {
      const j = await body(req);
      const item = expand.inbound.find((x) => x.id === String(j.id || ''));
      if (!item) return send(res, 404, { ok: false, error: 'not-found' });
      if (j.name !== undefined) {
        const name = String(j.name || '').trim().slice(0, 40);
        if (!name) return send(res, 400, { ok: false, error: 'bad-name' });
        if (expand.inbound.some((x) => x.id !== item.id && x.name === name)) {
          return send(res, 400, { ok: false, error: 'name-conflict', hint: '已存在同名凭据；名称必须唯一，请换一个名称' });
        }
        item.name = name;
      }
      if (j.disabled !== undefined) {
        if (typeof j.disabled !== 'boolean') return send(res, 400, { ok: false, error: 'bad-disabled' });
        item.disabled = j.disabled;
      }
      if (j.limits !== undefined) {
        let lim;
        try { lim = parseLimits(j.limits, item.limits || {}); }
        catch (e) { return send(res, 400, { ok: false, error: String(e.message || 'bad-limits') }); }
        item.limits = lim;
      }
      if (j.expiresAt !== undefined) {
        const exp = Number(j.expiresAt);
        if (!Number.isInteger(exp) || exp < 0) return send(res, 400, { ok: false, error: 'bad-expires-at' });
        item.expiresAt = exp;
      }
      // R149：条目地址/端口可改（凭证不再内嵌地址；改后管理页展示与端口检查随之更新）
      if (j.host !== undefined || j.port !== undefined) {
        const h = j.host !== undefined ? String(j.host || '').trim().slice(0, 253) : (item.host || '');
        const isV6 = h.includes(':') && (h.includes('::') || h.split(':').length > 2);
        if (!h || /[\s/?#]/.test(h) || (h.includes(':') && !isV6)) {
          return send(res, 400, { ok: false, error: 'bad-host', hint: '域名或 IP 不能为空，不能含空格/斜杠/问号/井号；不要在这里写端口（端口请填到端口输入框），IPv6 地址除外' });
        }
        const port = j.port !== undefined ? Math.floor(Number(j.port)) : Number(item.port || EXPAND_DEFAULT_PORT);
        if (!Number.isInteger(port) || port < 1 || port > 65535) {
          return send(res, 400, { ok: false, error: 'bad-port', hint: '端口必须是 1–65535 的整数' });
        }
        item.host = h; item.port = port; item.addr = h + ':' + port;
      }
      if (!saveExpand()) return send(res, 500, { ok: false, error: 'persist-failed' });
      log('INFO', `被扩网：凭据 ${item.id.slice(0, 8)} 已更新（名称/停用/限额/有效期）`);
      return send(res, 200, { ok: true, item: expandView().inbound.credentials.find((x) => x.id === item.id) });
    }
    if (req.method === 'POST' && p === '/api/admin/expand-inbound-remove') {
      const j = await body(req);
      const i = expand.inbound.findIndex((x) => x.id === String(j.id || ''));
      if (i < 0) return send(res, 404, { ok: false, error: 'not-found' });
      const [removed] = expand.inbound.splice(i, 1);
      delete expand.stats.perInbound[removed.id];
      if (!saveExpand()) return send(res, 500, { ok: false, error: 'persist-failed' });
      log('INFO', `被扩网：删除接入凭据 ${removed.id.slice(0, 8)}`);
      return send(res, 200, { ok: true });
    }
    if (req.method === 'POST' && p === '/api/admin/expand-outbound') {
      const j = await body(req);
      const credential = String(j.credential || '').trim();
      if (!credential) return send(res, 400, { ok: false, error: 'credential-required' });
      // R149：地址来源 = ① 旧版 v2 凭证内嵌（fwnexp_v2_ 自带 host:port，兼容既有对端）；② 手动填写的 host/port（新凭证不带地址）。
      const tok = parseExpandToken(credential);
      const hostRaw = String(j.host || j.address || '').trim();
      let host = '', port = 0;
      if (hostRaw) {
        const hs = hostRaw.lastIndexOf(':');
        if (hs > 0 && /^\d{1,5}$/.test(hostRaw.slice(hs + 1)) && !hostRaw.slice(0, hs).includes(':')) {
          host = hostRaw.slice(0, hs); port = Number(hostRaw.slice(hs + 1));
        } else {
          host = hostRaw; port = Math.floor(Number(j.port));
        }
        if (/[\s/?#]/.test(host)) return send(res, 400, { ok: false, error: 'bad-address', hint: '地址 host 不能含空格/斜杠/问号/井号' });
      }
      if (!host && tok) { host = tok.host; port = tok.port; }
      if (j.port !== undefined && !port) {
        port = Math.floor(Number(j.port));
      }
      if (!host || !Number.isInteger(port) || port < 1 || port > 65535) {
        return send(res, 400, { ok: false, error: 'address-required', hint: '新凭证不带地址；请填写对方的域名/IP 与端口（旧版 fwnexp_v2_ 凭证可不填，自动解析）' });
      }
      const ts = tlsFromInput(j.tls, null);
      if (!ts.ok) return send(res, 400, { ok: false, error: ts.error });
      const name = String(j.name || '').trim().slice(0, 40) || (host + ':' + port);
      const item = {
        id: crypto.randomUUID(), name, host, port,
        credential: '', hint: '', tls: ts.tls, addrFrom: tok ? 'credential' : 'manual',
        enabled: true, createdAt: Date.now(), lastTest: 0, lastTestOk: false,
      };
      setPeerCredential(item, credential);
      expand.outbound.push(item);
      if (!saveExpand()) return send(res, 500, { ok: false, error: 'persist-failed' });
      log('INFO', `扩网：添加 ${name} → ${host}:${port}（TLS ${ts.tls.mode}，地址来自${tok ? '凭证' : '手动'}）`);
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
      if (j.credential !== undefined) {
        const credential = String(j.credential || '').trim();
        if (!credential) return send(res, 400, { ok: false, error: 'credential-required' });
        const tok = parseExpandToken(credential);
        setPeerCredential(item, credential);
        if (tok) { item.host = tok.host; item.port = tok.port; item.addrFrom = 'credential'; }
        else item.addrFrom = 'manual'; // R149：新凭证不带地址，沿用条目现有地址（可在前端另改）
      }
      if (j.host !== undefined || j.port !== undefined) {
        const host = j.host !== undefined ? String(j.host || '').trim() : item.host;
        const port = j.port !== undefined ? Math.floor(Number(j.port)) : item.port;
        if (!host || /[\s/?#]/.test(host) || !Number.isInteger(port) || port < 1 || port > 65535) {
          return send(res, 400, { ok: false, error: 'bad-address', hint: '地址 host 不能含空格/斜杠/问号/井号，端口须为 1–65535' });
        }
        item.host = host; item.port = port; item.addrFrom = 'manual';
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
      if (!saveExpand()) return send(res, 500, { ok: false, error: 'persist-failed' });
      return send(res, 200, { ok: true, item: expandView().outbound.find((x) => x.id === item.id) });
    }
    if (req.method === 'POST' && p === '/api/admin/expand-remove') {
      const j = await body(req);
      const i = expand.outbound.findIndex((x) => x.id === String(j.id || ''));
      if (i < 0) return send(res, 404, { ok: false, error: 'not-found' });
      const [removed] = expand.outbound.splice(i, 1);
      if (!saveExpand()) return send(res, 500, { ok: false, error: 'persist-failed' });
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
        if (!saveExpand()) return send(res, 500, { ok: false, error: 'persist-failed' });
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
      if (!saveExpand()) return send(res, 500, { ok: false, error: 'persist-failed' });
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
        if (!saveExpand()) return send(res, 500, { ok: false, error: 'persist-failed' });
        return send(res, 200, {
          ok: true, reachable: item.lastTestOk, status: r.status, ms: Date.now() - t0,
          fingerprint: r.fingerprint, result: out,
        });
      } catch (e) {
        item.lastTest = Date.now();
        item.lastTestOk = false;
        if (!saveExpand()) return send(res, 500, { ok: false, error: 'persist-failed' });
        const msg = String((e && e.message) || e);
        return send(res, 200, {
          ok: true, reachable: false, ms: Date.now() - t0,
          error: msg === 'timeout' ? 'timeout' : (msg === 'fingerprint-mismatch' ? 'tls-fingerprint-mismatch' : msg.slice(0, 160)),
        });
      }
    }
    /* ── R133 端口管理：多业务端口（监听/暂停/异常/占用强制启用/删除/添加）── */
    if (req.method === 'GET' && p === '/api/admin/ports') return send(res, 200, portsView());
    if (req.method === 'POST' && p === '/api/admin/ports') {
      const j = await body(req);
      const action = String(j.action || '');
      const port = Math.floor(Number(j.port));
      if (!Number.isInteger(port) || port < 1 || port > 65535) return send(res, 400, { ok: false, error: 'bad-port' });
      // R134：UDP（DHT 监听端口）走 dht.udpPorts；TCP 走业务端口
      if (j.protocol === 'udp') {
        if (action === 'pause') {
          if (!cfg.dht.udpPorts.includes(port)) return send(res, 400, { ok: false, error: 'not-managed' });
          if (cfg.dht.pausedUdpPorts.includes(port)) return send(res, 200, { ok: true, ports: portsView() }); // 幂等
          const remaining = cfg.dht.udpPorts.filter((x) => x !== port && !cfg.dht.pausedUdpPorts.includes(x));
          if (!remaining.length) return send(res, 400, { ok: false, error: 'udp-port-required', hint: 'DHT 至少保留一个未暂停的 UDP 端口' });
          cfg.dht = { ...cfg.dht, pausedUdpPorts: normPorts([...cfg.dht.pausedUdpPorts, port], [], 8) };
          if (!saveCfg()) return send(res, 500, { ok: false, error: 'persist-failed' });
          await dhtStart();
          return send(res, 200, { ok: true, ports: portsView() });
        }
        if (action === 'remove') {
          if (!cfg.dht.udpPorts.includes(port)) return send(res, 400, { ok: false, error: 'not-managed' });
          const remaining = cfg.dht.udpPorts.filter((x) => x !== port && !cfg.dht.pausedUdpPorts.includes(x));
          if (!remaining.length) return send(res, 400, { ok: false, error: 'udp-port-required', hint: 'DHT 至少保留一个 UDP 端口' });
          cfg.dht = { ...cfg.dht, udpPorts: cfg.dht.udpPorts.filter((x) => x !== port), pausedUdpPorts: cfg.dht.pausedUdpPorts.filter((x) => x !== port) };
          if (!saveCfg()) return send(res, 500, { ok: false, error: 'persist-failed' });
          await dhtStart();
          return send(res, 200, { ok: true, ports: portsView() });
        }
        if (action === 'resume') {
          if (!cfg.dht.udpPorts.includes(port)) return send(res, 400, { ok: false, error: 'not-managed' });
          if (!cfg.dht.pausedUdpPorts.includes(port)) return send(res, 200, { ok: true, ports: portsView() }); // 幂等
          cfg.dht = { ...cfg.dht, pausedUdpPorts: cfg.dht.pausedUdpPorts.filter((x) => x !== port) };
          if (!saveCfg()) return send(res, 500, { ok: false, error: 'persist-failed' });
          const r = await dhtStart();
          return send(res, 200, { ok: true, start: r, ports: portsView() });
        }
        if (action === 'add') {
          if (!cfg.dht.udpPorts.includes(port)) {
            cfg.dht = { ...cfg.dht, udpPorts: normPorts([...cfg.dht.udpPorts, port], cfg.dht.udpPorts, 8), pausedUdpPorts: cfg.dht.pausedUdpPorts.filter((x) => x !== port) };
            if (!saveCfg()) return send(res, 500, { ok: false, error: 'persist-failed' });
          } else if (cfg.dht.pausedUdpPorts.includes(port)) {
            cfg.dht = { ...cfg.dht, pausedUdpPorts: cfg.dht.pausedUdpPorts.filter((x) => x !== port) };
            if (!saveCfg()) return send(res, 500, { ok: false, error: 'persist-failed' });
          }
          const r = await dhtStart();
          return send(res, 200, { ok: true, start: r, ports: portsView() });
        }
        return send(res, 400, { ok: false, error: 'bad-action' });
      }
      // R135：管理入口端口（cfg.ports[0]）不可暂停/删除/强制启用，只能更改为其它端口（action=entry）
      if (cfg.ports[0] === port && action !== 'entry') {
        return send(res, 400, { ok: false, error: 'entry-port-fixed', hint: '管理入口端口不可暂停/删除，只能在「端口」页更改端口号' });
      }
      // R134：管理入口端口修改（移到列表首位并启用）
      if (action === 'entry') {
        cfg.ports = normPorts([port, ...cfg.ports.filter((x) => x !== port)]);
        if (opt.portExplicit) viewPorts = [port, ...viewPorts.filter((x) => x !== port)];
        if (!saveCfg()) return send(res, 500, { ok: false, error: 'persist-failed' });
        const r = await startPort(port);
        if (!r.ok && r.error === 'occupied') {
          const k = await forceKillPort(port);
          if (k.ok) { const r2 = await startPort(port); return send(res, 200, { ok: true, entryPort: port, start: r2, killed: k.killed, ports: portsView() }); }
          return send(res, 400, { ok: false, error: 'occupied', hint: '端口被占用，强制启用失败' });
        }
        log('INFO', `端口管理：管理入口改为 ${port}`);
        return send(res, 200, { ok: true, entryPort: port, start: r, ports: portsView() });
      }
      if (action === 'add') {
        if (cfg.ports.includes(port)) return send(res, 400, { ok: false, error: 'port-exists' });
        cfg.ports = normPorts([...cfg.ports, port]);
        if (opt.portExplicit && !viewPorts.includes(port)) viewPorts.push(port); // R166：显式模式视图跟随本次实际监听
        if (!saveCfg()) return send(res, 500, { ok: false, error: 'persist-failed' });
        const r = await startPort(port);
        log('INFO', `端口管理：添加 ${port}（${r.ok ? '监听中' : r.error}）`);
        return send(res, 200, { ok: true, start: r, ports: portsView() });
      }
      if (action === 'pause') {
        if (!cfg.ports.includes(port)) return send(res, 400, { ok: false, error: 'not-managed' });
        pausePort(port);
        log('INFO', `端口管理：暂停 ${port}`);
        return send(res, 200, { ok: true, ports: portsView() });
      }
      if (action === 'resume' || action === 'force') {
        if (!cfg.ports.includes(port)) return send(res, 400, { ok: false, error: 'not-managed' });
        let killed = false;
        if (action === 'force') {
          const k = await forceKillPort(port);
          if (!k.ok) return send(res, 400, { ok: false, error: k.error });
          killed = k.killed;
        }
        const r = await startPort(port);
        return send(res, 200, { ok: true, start: r, killed, ports: portsView() });
      }
      if (action === 'remove') {
        if (!cfg.ports.includes(port)) return send(res, 400, { ok: false, error: 'not-managed' });
        pausePort(port);
        cfg.ports = cfg.ports.filter((x) => x !== port);
        if (opt.portExplicit) viewPorts = viewPorts.filter((x) => x !== port); // R166：显式模式视图同步移除
        if (!cfg.ports.length) cfg.ports = [...DEFAULT_PORTS];
        if (!saveCfg()) return send(res, 500, { ok: false, error: 'persist-failed' });
        log('INFO', `端口管理：删除 ${port}`);
        return send(res, 200, { ok: true, ports: portsView() });
      }
      return send(res, 400, { ok: false, error: 'bad-action' });
    }
    if (req.method === 'GET' && p === '/api/admin/help') {
      const html = helpHtml();
      if (!html) return send(res, 404, { ok: false, error: 'help-missing' });
      const out = path.join(DATA, 'help.html');
      try { fs.writeFileSync(out, html, 'utf8'); }
      catch (e) { return send(res, 500, { ok: false, error: 'help-export-failed', hint: String((e && e.message) || e) }); }
      // 本地绝对路径（file:// 打开用）：统一正斜杠（file:///C:/Users/...）
      const fileUrl = 'file:///' + out.split(/[\\/]+/).join('/');
      return send(res, 200, { ok: true, file: fileUrl });
    }
    if (req.method === 'POST' && p === '/api/admin/help-open') {
      // R135k：浏览器跨协议拦截 http→file:// 弹窗；改为本机服务器用系统命令打开帮助文档（file 路径由程序生成，不写死）
      const html = helpHtml();
      if (!html) return send(res, 404, { ok: false, error: 'help-missing' });
      const out = path.join(DATA, 'help.html');
      try { fs.writeFileSync(out, html, 'utf8'); } catch { /* 已存在也可打开 */ }
      const fileUrl = 'file:///' + out.split(/[\\/]+/).join('/');
      const cp = require('node:child_process');
      let opened = false;
      try {
        if (process.platform === 'win32') {
          cp.spawn('cmd', ['/c', 'start', '', fileUrl], { windowsHide: true, detached: true }).unref();
        } else if (process.platform === 'darwin') {
          cp.spawn('open', [fileUrl], { detached: true }).unref();
        } else {
          cp.spawn('xdg-open', [fileUrl], { detached: true }).unref();
        }
        opened = true;
      } catch { /* 打开失败如实返回 */ }
      log('INFO', `帮助文档已导出 ${out}（${opened ? '已在浏览器打开' : '打开失败'}）`);
      return send(res, 200, { ok: true, opened, file: fileUrl });
    }
    if (req.method === 'GET' && p === '/api/admin/security') return send(res, 200, securityView());    if (req.method === 'GET' && p === '/api/admin/dht') return send(res, 200, dhtPublicView());
    if (req.method === 'POST' && p === '/api/admin/dht-config') {
      const j = await body(req);
      if (j.enabled === false) return send(res, 400, { ok: false, error: 'dht-always-on', hint: 'DHT 发现层强制开启，不可关闭' });
      // R135：暂停自动兜底——仅当暂停后仍有其它生效的对外地址才允许（否则 400，防止全部兜底被停导致无地址宣告）
      if (j.pausedAuto !== undefined) {
        const list = Array.isArray(j.pausedAuto) ? j.pausedAuto : [];
        // R135q：暂停校验与状态表条目一致（端口 = 当前实际自动兜底条目端口）
        const autoPorts = [...new Set(addrStates.filter((a) => !a.manual).map((a) => a.port))];
        const norm = [...new Set(list.map((x) => String(x || '').trim()).filter((s) => /^(IPv4|IPv6)\|(\d+)$/.test(s) && autoPorts.includes(Number(s.split('|')[1]))))];
        const probeAuto = autoAddrHosts().flatMap((h) => autoPorts.map((port) => ({ family: h.family, port, enabled: !norm.includes(`${h.family}|${port}`) })));
        const stillActive = addrStates.some((a) => a.manual && a.enabled && a.valid) || probeAuto.some((a) => a.enabled);
        if (!stillActive) return send(res, 400, { ok: false, error: 'auto-fallback-required', hint: '至少保留一个生效的对外地址：自动兜底全部暂停需先有其它生效地址（手动地址验证通过或其它兜底未暂停）' });
        j.pausedAuto = norm;
      }
      const next = normDhtCfg({ ...cfg.dht, ...j });
      // R135h/r：对外地址预检——域名解析或 IP 必须指向本机（本机网卡/探测公网 IP/回环），否则拒绝添加（宣告出去对方连不到本机）；兼容字符串与对象
      if (j.addresses !== undefined) {
        const list = Array.isArray(j.addresses) ? j.addresses : [];
        for (const a of list) {
          const host = typeof a === 'string'
            ? String(a).slice(0, String(a).lastIndexOf(':')).trim()
            : String(a && a.host || '').trim();
          if (!host) continue;
          const chk = await hostPointsToSelf(host);
          if (!chk.ok) {
            const why = chk.reason === 'dns-empty' ? '域名无法解析'
              : `解析到 ${chk.ips.join('、')}，而本机是 ${chk.mine.join('、') || '（未探测到公网 IP）'}`;
            return send(res, 400, { ok: false, error: 'bad-address', hint: `${host}：${why}——对外地址必须是本机的公网 IP 或解析指向本机的域名（解析指向本机才能被对方连到）` });
          }
        }
      }
      if (j.anchors !== undefined) {
        const list = Array.isArray(j.anchors) ? j.anchors : String(j.anchors || '').split(/[\r\n,]+/);
        next.anchors = guiFanAnChors(list);
      }
      const prev = cfg.dht;
      cfg.dht = next;
      if (!saveCfg()) { cfg.dht = prev; return send(res, 500, { ok: false, error: 'persist-failed' }); }
      log('INFO', `DHT 配置已保存 udpPorts=${next.udpPorts.join(',')} addresses=${next.addresses.length} anchors=${next.anchors.length} routeByDht=${next.routeByDht}`);
      syncAddrStates();
      const r = await dhtStart();
      if (j.addresses !== undefined) void checkExternalAddrs();
      return send(res, 200, { ok: true, restart: r.ok ? 'started' : r.error || 'failed', dht: dhtPublicView() });
    }
    if (req.method === 'POST' && p === '/api/admin/dht-publish') {
      const r = await dhtPublishSelf();
      return send(res, 200, { ok: true, publish: r, dht: dhtPublicView() });
    }
    if (req.method === 'POST' && p === '/api/admin/dht-query') {
      const j = await body(req);
      const fp = String(j.fingerprint || '').trim();
      if (!fp || !/^[A-Z2-7]{40,60}$/.test(fp)) return send(res, 400, { ok: false, error: 'bad-fingerprint' });
      const node = dhtNodes[0];
      if (!node || !node.listening) {
        return send(res, 200, { ok: true, found: false, error: 'dht-not-running', dht: dhtPublicView() });
      }
      const r = await node.query(fp, { requireDecrypt: true }).catch((e) => ({ ok: false, error: String((e && e.message) || e) }));
      return send(res, 200, {
        ok: true, found: r.ok === true, record: r.record || null,
        attempts: r.attempts || [], rejected: r.rejected || [], error: r.error || '',
        dht: dhtPublicView(),
      });
    }
    /* ── R135c：一键变成锚点——生成可分享的锚点地址（本机 UDP 监听端口 × 公网 IP/域名），不改任何配置 ── */
    if (req.method === 'POST' && p === '/api/admin/dht-anchor') {
      const j = await body(req).catch(() => ({}));
      const domain = String(j.domain || '').trim().slice(0, 253);
      if (domain && /[\s/?#]/.test(domain)) return send(res, 400, { ok: false, error: 'bad-domain' });
      let udpPorts = [...new Set(dhtNodes.filter((n) => n.listening && n.address && n.address.port).map((n) => n.address.port))];
      if (!udpPorts.length) udpPorts = cfg.dht.udpPorts.filter((p) => !cfg.dht.pausedUdpPorts.includes(p));
      if (!lastPub || !lastPub.at) await probePublicIp().catch(() => {});
      const pub = { ipv4: lastPub.ipv4 || '', ipv6: lastPub.ipv6 || '' };
      let dnsCheck = { status: 'none', ips: [] };
      if (domain) {
        const ips = await new Promise((resolve) => {
          dns.lookup(domain, { all: true }, (err, addrs) => {
            if (err || !Array.isArray(addrs) || !addrs.length) return resolve([]);
            resolve(addrs.map((a) => a.address));
          });
        });
        const mine = [pub.ipv6, pub.ipv4].filter(Boolean);
        const hit = mine.some((x) => ips.includes(x));
        dnsCheck = { status: !ips.length ? 'no-record' : (hit ? 'match' : 'mismatch'), ips };
      }
      const hosts = domain ? [domain] : [...new Set([pub.ipv4 || pub.ipv6, pub.ipv6].filter(Boolean))]; // R155：IPv4 优先
      const addrs = hosts.flatMap((h) => udpPorts.map((port) => ({
        host: h, port,
        kind: domain ? 'domain' : (h.includes(':') ? 'ipv6' : 'ipv4'),
      })));
      log('INFO', `[dht] 一键变成锚点：${addrs.map((a) => `${a.host}:${a.port}`).join('、') || '（无可用 UDP 端口）'} 域名校验=${dnsCheck.status}`);
      return send(res, 200, {
        ok: true, addrs, udpPorts,
        publicIp: pub, dns: dnsCheck,
        note: '锚点无需凭证：其他 FWArmy 在「手动锚点」里添加任一地址即可引导到本机（发现≠授权，消息仍走凭据通道）；本机仍是完整服务器（中继/F中继照常）。',
      });
    }
    if (req.method === 'POST' && p === '/api/admin/security-gc') {
      const r = pruneSecurity(now());
      if (!saveSecurity()) return send(res, 500, { ok: false, error: 'persist-failed' });
      return send(res, 200, { ok: true, ...r });
    }
    if (req.method === 'POST' && p === '/api/admin/security-clear-blacklist') {
      const j = await body(req);
      if (j.confirm !== true) return send(res, 400, { ok: false, error: 'confirm-required' });
      security.blacklist = {};
      if (!saveSecurity()) return send(res, 500, { ok: false, error: 'persist-failed' });
      log('WARN', '管理员清空消息黑名单');
      return send(res, 200, { ok: true });
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
      const prevTls = cfg.tls;
      cfg.tls = next;
      if (!saveCfg()) { cfg.tls = prevTls; return send(res, 500, { ok: false, error: 'persist-failed' }); }
      log('INFO', `TLS 配置已保存 mode=${next.mode} allowPlaintext=${next.allowPlaintext}（需重启生效）`);
      return send(res, 200, { ok: true, tls: tlsPublicView(), restartRequired: true });
    }
    if (req.method === 'GET' && p === '/api/admin/credentials') {
      const page = adminPage(u);
      const all = credsNewestFirst();
      return send(res, 200, {
        ok: true,
        items: all.slice(page.offset, page.offset + page.limit).map(viewCred),
        total: all.length,
        offset: page.offset,
        limit: page.limit,
      });
    }
    if (req.method === 'POST' && p === '/api/admin/credentials') {
      const j = await body(req);
      const name = String(j.name || '').trim().slice(0, 40) || '未命名';
      const limits = parseLimits(j.limits);
      // R132：业务凭据可选带端点（域名/IP + 端口，不填端口默认 8787）；token 结构不变（协议兼容，供客户端参考）。
      const host = String(j.host || '').trim().slice(0, 253);
      if (host && /[\s/?#]/.test(host)) return send(res, 400, { ok: false, error: 'bad-host' });
      let port = Number(j.port);
      if (host && (!Number.isInteger(port) || port < 1 || port > 65535)) port = CRED_DEFAULT_PORT; // R133：中继凭据默认 59599
      if (host) { // R142：凭据端口不在监听集 → 自动添加并监听（业务端口默认打开策略）
        const ep = await ensureCredPort(port);
        if (!ep.ok) return send(res, 401, { ok: false, error: 'credential-port-unavailable', hint: ep.error || '' });
      }
      const token = b64u(crypto.randomBytes(32));
      const id = crypto.randomUUID();
      // R150：名称必须唯一（人类只靠名称区分凭据）——重名拒绝
      if (Object.values(creds).some((c) => c.name === name)) {
        return send(res, 400, { ok: false, error: 'name-conflict', hint: '已存在同名凭据；名称必须唯一，请换一个名称' });
      }
      creds[id] = {
        id, name, hash: sha(token), hash8: sha(token).slice(0, 8),
        tail5: token.slice(-5), // R150：标识列显示明文末尾 5 位（人可对账；≈30bit 熵 + 来源限速，无实质风险）
        createdAt: new Date().toISOString(), disabled: false, limits, lastUsed: 0,
        host, port: host ? port : 0,
        addition: normCredAddition(j.addition), // R135g：凭证级附加内容配置（关/随机/顺序/按比例）
      };
      rebuildIndex(); if (!saveCreds()) return send(res, 500, { ok: false, error: 'persist-failed' });
      log('INFO', `新建凭据 id=${id} name=${JSON.stringify(name)}${host ? ` endpoint=${host}:${port}` : ''}`);
      return send(res, 200, { ok: true, id, name, token, credential: viewCred(creds[id]) });
    }
    if (req.method === 'POST' && p === '/api/admin/credential-update') {
      const j = await body(req);
      const c = findCred(j.id);
      if (!c) return send(res, 404, { ok: false, error: 'not-found' });
      const name = j.name === undefined ? c.name : String(j.name || '').trim().slice(0, 40);
      if (!name) return send(res, 400, { ok: false, error: 'bad-name' });
      if (j.name !== undefined && Object.values(creds).some((x) => x.id !== c.id && x.name === name)) {
        return send(res, 400, { ok: false, error: 'name-conflict', hint: '已存在同名凭据；名称必须唯一，请换一个名称' });
      }
      if (j.disabled !== undefined && typeof j.disabled !== 'boolean') return send(res, 400, { ok: false, error: 'bad-disabled' });
      const limits = parseLimits(j.limits, c.limits);
      // 全部字段通过后一次提交，非法限额不能顺带改名/停用。
      c.name = name;
      c.disabled = j.disabled === undefined ? c.disabled : j.disabled;
      c.limits = limits;
      if (j.host !== undefined || j.port !== undefined) {
        const h = j.host !== undefined ? String(j.host || '').trim().slice(0, 253) : (c.host || '');
        if (h && /[\s/?#]/.test(h)) return send(res, 400, { ok: false, error: 'bad-host' });
        const isV6 = h.includes(':') && (h.includes('::') || h.split(':').length > 2);
        if (h && h.includes(':') && !isV6) return send(res, 400, { ok: false, error: 'bad-host', hint: '不要在这里写端口（端口请填到端口输入框），IPv6 地址除外' });
        let port = j.port !== undefined ? Number(j.port) : (c.port || 0);
        if (h && (!Number.isInteger(port) || port < 1 || port > 65535)) port = CRED_DEFAULT_PORT;
        if (!h) port = 0;
        c.host = h; c.port = port;
      }
      // R135g：凭证级附加内容配置（mode=off 或权重表同时清空）
      if (j.addition !== undefined) {
        const na = normCredAddition(j.addition);
        if (na.mode === 'off') { c.addition = null; additionSeq.delete(c.id); }
        else c.addition = na;
      }
      credStat(c).name = name;
      if (!saveCreds()) return send(res, 500, { ok: false, error: 'persist-failed' });
      markStatsDirty();
      log('INFO', `更新凭据 id=${c.id} disabled=${c.disabled}`);
      return send(res, 200, { ok: true, credential: viewCred(c) });
    }
    if (req.method === 'POST' && (p === '/api/admin/credential-revoke' || p === '/api/admin/credential-disable')) {
      const j = await body(req);
      const c = findCred(j.id);
      if (!c) return send(res, 404, { ok: false, error: 'not-found' });
      c.disabled = j.disabled === undefined ? true : !!j.disabled;
      if (!saveCreds()) return send(res, 500, { ok: false, error: 'persist-failed' });
      log('INFO', `凭据 ${c.disabled ? '停用' : '启用'} id=${c.id}`);
      return send(res, 200, { ok: true, credential: viewCred(c) });
    }
    if (req.method === 'POST' && p === '/api/admin/credential-delete') {
      const j = await body(req);
      const c = findCred(j.id);
      if (!c) return send(res, 404, { ok: false, error: 'not-found' });
      if (String(j.confirmName || '') !== c.name) return send(res, 400, { ok: false, error: 'confirm-name-mismatch' });
      delete creds[c.id];
      additionSeq.delete(c.id);
      const s = credStat(c); s.deletedAt = Date.now();
      rebuildIndex(); if (!saveCreds()) return send(res, 500, { ok: false, error: 'persist-failed' });
      markStatsDirty();
      // 删的正好是首次引导凭据 ⇒ 明文文件也一起删，别留下一个已失效但仍是秘密的 token
      if (firstRunPending()) {
        try { if (sha(readFirstCredential()) === c.hash) clearFirstCredential(); } catch { /* noop */ }
      }
      log('INFO', `删除凭据 id=${c.id}`);
      return send(res, 200, { ok: true });
    }
    /* ── R135g 附加内容：库配置 + 审计检查点查看 ── */
    if (req.method === 'GET' && p === '/api/admin/addition-config') {
      const cfgAdd = cfg.addition || { texts: [] };
      return send(res, 200, { ok: true, texts: Array.isArray(cfgAdd.texts) ? cfgAdd.texts : [], max: ADDITION_MAX_TEXTS, maxBytes: ADDITION_MAX_BYTES });
    }
    if (req.method === 'POST' && p === '/api/admin/addition-config') {
      const j = await body(req);
      const texts = normAdditionTexts(j.texts);
      if (j.texts !== undefined && !Array.isArray(j.texts)) return send(res, 400, { ok: false, error: 'bad-texts' });
      const prev = cfg.addition || { texts: [] };
      cfg.addition = { texts };
      if (!saveCfg()) { cfg.addition = prev; return send(res, 500, { ok: false, error: 'persist-failed' }); }
      log('INFO', `附加内容库已保存：${texts.length} 条（上限 ${ADDITION_MAX_TEXTS}）`);
      return send(res, 200, { ok: true, texts, max: ADDITION_MAX_TEXTS });
    }
    if (req.method === 'GET' && p === '/api/admin/addition-audit') {
      return send(res, 200, {
        ok: true,
        gen: additionAudit.gen,
        count: additionAudit.count,
        head: additionAudit.head,
        lastSignedAt: additionAudit.lastSignedAt,
        lastSignedHead: additionAudit.lastSignedHead,
        texts: (cfg.addition && Array.isArray(cfg.addition.texts) ? cfg.addition.texts : []).length,
        enabledCreds: Object.values(creds).filter((c) => c.addition && c.addition.mode !== 'off').length,
        file: ADDITION_AUDIT_FILE,
      });
    }
    if (req.method === 'POST' && p === '/api/admin/addition-audit-publish') {
      const r = await dhtPublishAudit();
      return send(res, 200, { ok: true, publish: r, audit: {
        gen: additionAudit.gen, count: additionAudit.count, head: additionAudit.head,
        lastSignedAt: additionAudit.lastSignedAt, lastSignedHead: additionAudit.lastSignedHead,
      } });
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
      const prevCfg = cfg;
      cfg = next; // 不清用量：新限额立刻作用于已有统计，避免改设置刷新预算。
      if (!saveCfg()) { cfg = prevCfg; return send(res, 500, { ok: false, error: 'persist-failed' }); }
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
      const r = await probePublicIp();
      return send(res, 200, { ok: true, ...r });
    }
    if (req.method === 'POST' && p === '/api/admin/shutdown') {
      send(res, 200, { ok: true, bye: true });
      setTimeout(() => shutdown('admin'), 200);
      return;
    }
    return send(res, 404, { ok: false, error: 'not-found' });
  }

  /** R161：请求日志批量落盘（250ms 合并写，行格式与 log() 一致）——高 QPS 下逐条 write 是 IO 热点。 */
  const reqLogBuf = [];
  let reqLogTimer = null;
  function flushReqLog() {
    reqLogTimer = null;
    const lines = reqLogBuf.splice(0);
    if (!lines.length) return;
    const chunk = lines.join('');
    if (!opt.quiet) { try { process.stdout.write(chunk); } catch { /* noop */ } }
    if (logStream) {
      try {
        if (logLines % 256 === 0) rotateLog();
        if (logStream.writableLength > 4 * 1024 * 1024) { logDropped += lines.length; return; } // 背压：丢弃并计数
        logStream.write(chunk);
        logLines += lines.length;
      } catch { /* noop */ }
    }
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
      reqLogBuf.push(`${new Date().toISOString()} INFO req ${req.method} ${u.pathname} ${res.statusCode} ${Date.now() - t0}ms cred=${c ? c.hash8 : '-'}\n`);
      if (!reqLogTimer) reqLogTimer = setTimeout(flushReqLog, 250);
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
          ok: true, server: 'fwarmy-relay', product: PRODUCT,
          version: (process.env.FWARMY_UPDATE_TEST === '1' && process.env.FWARMY_FAKE_VERSION) ? process.env.FWARMY_FAKE_VERSION : VERSION,
          accepting: cfg.accepting, instanceId: expand.instanceId, dataDirHash,
          presenceTtlMs: cfg.presenceTtlMs, secure: !!req.socket.encrypted, tls: tlsPublicView(),
          tray: trayStatus(), // R146：托盘状态（fwarmy-tray.ps1 写入 tray-state.json），诊断「看不到图标」的原因
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
        const q = v.queue;
        // R161：惰性清理队首过期（exp 单调有序）；原 filter+slice 每次 O(队列长)
        while (q.length && q[0].exp <= now) { queuedBytes = Math.max(0, queuedBytes - Buffer.byteLength(q[0].env, 'utf8')); q.shift(); }
        const cand = q.slice(0, 50);
        if (!cand.length) {
          v.lastSeen = now;
          return reply(200, { ok: true, envelopes: [] }, {});
        }
        // F13：按剩余额度取有界前缀——只剩 1 条额度时也要能取走 1 条，而不是整批 429。
        const yi = [];
        let outBytes = 0;
        let lastGate = null;
        for (const x of cand) {
          const b = Buffer.byteLength(x.env, 'utf8');
          const g = gate(c, outBytes + b, now);
          if (!g.ok) { lastGate = g; break; }
          yi.push(x);
          outBytes += b;
        }
        if (!yi.length) {
          const g = lastGate || { code: 429, error: 'quota-exceeded' };
          return fail(g.code, g.error, { scope: g.scope, limit: g.limit, used: g.used });
        }
        v.lastSeen = now;
        q.splice(0, yi.length); // R161：yi 是 q 的连续前缀，直接删队首（原 includes 式 filter 是 O(n×m)）
        queuedBytes = Math.max(0, queuedBytes - outBytes);
        // R135g：附加内容与信封同序返回（无附加 = null），WArmy 客户端据此渲染提示消息
        return reply(200, { ok: true, envelopes: yi.map((x) => x.env), additions: yi.map((x) => x.addition || null) }, { delivered: yi.length, bytesOut: outBytes });
      }

      if (req.method === 'POST' && u.pathname === '/api/register') {
        const did = String(j.did || ''), boxPub = String(j.boxPub || ''), ts = Number(j.ts || 0);
        if (!did || !boxPub || !shiJianOk(ts)) return fail(400, 'bad-register');
        if (!yanQianMing(did, `register|${did}|${boxPub}|${ts}`, j.sig)) return fail(401, 'bad-signature');
        try { xPub(boxPub); } catch { return fail(400, 'bad-box-key'); }
        const jiu = ren.get(did);
        ren.set(did, { boxPub, lastSeen: Date.now(), queue: jiu ? jiu.queue : [] });
        // DHT 发现：注册即把「该客户端当前所在中继站 = 本站」签入 DHT（异步，失败只记日志）。
        if (cfg.dht.enabled && dhtNodes[0]) void dhtPublishLocator(did);
        return reply(200, { ok: true, online: true });
      }
      if (req.method === 'POST' && u.pathname === '/api/bye') {
        const did = String(j.did || ''), ts = Number(j.ts || 0);
        if (!did || !shiJianOk(ts) || !yanQianMing(did, `bye|${did}|${ts}`, j.sig)) return fail(401, 'bad-signature');
        const v = ren.get(did); if (v) v.lastSeen = 0;
        return reply(200, { ok: true });
      }
      if (req.method === 'POST' && u.pathname === '/api/relay') {
        // 暂停 truth table：relay 是新投递入口，暂停即 503（poll/lookup/心跳等控制面不受影响）。
        if (!cfg.accepting) return fail(503, 'not-accepting');
        if (updateFreeze) return fail(503, 'updating');
        const to = String(j.to || '').slice(0, 200), env = String(j.envelope || '');
        const bytes = Buffer.byteLength(env, 'utf8');
        if (!to || !bytes || bytes > cfg.maxEnvelope) return fail(400, 'bad-envelope');
        // R135g：客户端方向不允许携带附加内容/密封字段（异常即弃，防注入）
        if (j.addition !== undefined || j.additionLocked !== undefined) return fail(400, 'addition-not-allowed');
        // 消息身份必须由客户端显式给出：不带 msgId（缺失/空串）视为不合规消息，直接丢弃，不做信封哈希兜底。
        const msgId = String(j.msgId || '');
        if (!isMessageId(msgId)) return fail(400, 'bad-msg-id');
        const at = Date.now();
        const createdAt = at;
        // R135g：按该请求凭据的附加内容配置选一条（未配置/库空 = null，转出时补密封标记）
        const addition = pickAddition(c);
        if (addition) auditAppend(msgId, addition);
        const local = enqueueLocal(to, env, at, addition);
        if (local.ok) {
          const g = gate(c, bytes, at);
          if (!g.ok) {
            const y = ren.get(to);
            if (y) y.queue = y.queue.filter((x) => x.id !== local.id);
            queuedBytes = Math.max(0, queuedBytes - (local.bytesIn || 0));
            return fail(g.code, g.error, { scope: g.scope, limit: g.limit, used: g.used });
          }
          const note = noteMessage(msgId, expand.instanceId);
          if (!note.ok) {
            const y = ren.get(to);
            if (y) y.queue = y.queue.filter((x) => x.id !== local.id);
            queuedBytes = Math.max(0, queuedBytes - (local.bytesIn || 0));
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
        const fwd = await forwardToPeers(to, env, msgId, meta, [], cfg.dht.routeByDht ? (await dhtRouteTarget(to)) : null, addition);
        if (fwd.ok) {
          return reply(200, { ok: true, queued: true, forwarded: true, via: fwd.via.name, msgId },
            { bytesIn: bytes, relayed: 1 });
        }
        return reply(local.code === 'queue-full' ? 429 : 200, {
          ...local.body, forwarded: false, attempts: fwd.attempts, msgId,
          error: local.code, // 明确失败码：'offline' / 'queue-full' / 'not-accepting'
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
  // R161：连接硬上限 + 完整请求超时（NATS max_connections / write_deadline 防滥用实践；
  // 慢客户端把请求体挂死连接由 requestTimeout 兜底；超限拒绝新连接，超限日志 10s 节流）
  const MAX_CONNECTIONS = 4096;
  let connWarnAt = 0;
  function guardServer(s) {
    s.maxConnections = MAX_CONNECTIONS;
    s.requestTimeout = 60_000;
    s.on('connection', () => {
      if (s.connections >= MAX_CONNECTIONS && Date.now() - connWarnAt > 10_000) {
        connWarnAt = Date.now();
        log('WARN', `连接数达上限 ${MAX_CONNECTIONS}，新连接将被拒绝`);
      }
    });
  }
  // R162：TLS 会话票据密钥持久化——重启后客户端仍可恢复会话（免完整握手）；删除 tls/ticket-keys 即重置（无损）
  const TICKET_FILE = path.join(TLS_DIR, 'ticket-keys');
  let ticketKeys = null;
  try {
    const raw = fs.readFileSync(TICKET_FILE);
    if (raw && raw.length === 48) ticketKeys = raw;
  } catch { /* 首次生成 */ }
  if (!ticketKeys) {
    ticketKeys = crypto.randomBytes(48);
    try { fs.mkdirSync(TLS_DIR, { recursive: true }); fs.writeFileSync(TICKET_FILE, ticketKeys, { mode: 0o600 }); } catch { /* 写失败用内存随机（重启后客户端重新握手，功能无损） */ }
  }
  const httpSrv = http.createServer(requestListener);
  const httpsSrv = tlsInfo
    ? https.createServer({ key: tlsInfo.keyPem, cert: tlsInfo.certPem, minVersion: 'TLSv1.2', ticketKeys, sessionTimeout: 3600 }, requestListener)
    : null;
  // R135f：keep-alive 超时调大（Node 默认 5s 与管理页 5s 轮询撞车 → 连接刚被关闭就被复用 → ECONNRESET → 管理页「端口读取失败: Failed to fetch」）
  for (const s of [httpSrv, httpsSrv]) {
    if (!s) continue;
    s.keepAliveTimeout = 30_000;
    s.headersTimeout = 31_000;
    guardServer(s);
  }
  /**
   * 同一端口按首字节分流（0x16=TLS），这样管理页/旧客户端仍能走回环 HTTP，
   * 而公网来源的明文会在请求层被 426 拒绝。注意 resume 必须放到 nextTick，
   * 否则 TLS server 还没挂好监听就被恢复流动，握手会超时。
   */
  /** R162：显式跟踪分流器 accept 的全部连接——Node 的 server.closeAllConnections 覆盖不到「注入」连接，
   * 否则 keep-alive 连接在 close() 后仍活着，同数据目录重启会被 probe 误判「已有实例在运行」。 */
  const liveConns = new Set();
  function makeSrv() {
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
    srv.on('connection', (s) => { liveConns.add(s); s.once('close', () => liveConns.delete(s)); });
    guardServer(srv);
    return srv;
  }
  /** R133 多业务端口：每端口一个分流器；状态 listening/paused/error（occupied）。 */
  const portStates = new Map(); // port → { srv, status, error }
  /** R142：凭据端口不在监听集合时自动添加（配置 + 尝试监听）——业务端口默认打开策略；监听失败仅记录（端口页可处理），不拒绝凭据。 */
  async function ensureCredPort(port) {
    const p = Number(port);
    if (!Number.isInteger(p) || p < 1 || p > 65535) return { ok: false, error: 'bad-port' };
    let added = false;
    if (!cfg.ports.includes(p)) {
      cfg.ports = normPorts([...cfg.ports, p]);
      if (opt.portExplicit && !viewPorts.includes(p)) viewPorts.push(p); // R166：显式模式视图同步（凭据端口自动添加）
      if (!saveCfg()) return { ok: false, error: 'persist-failed' };
      added = true;
    }
    const st = portStates.get(p);
    if (!st || !st.srv) {
      const r = await startPort(p);
      if (!r.ok) log('WARN', `凭据端口 ${p} 已加入配置但监听失败（端口页可处理）：` + (r.error || ''));
    }
    const after = portStates.get(p);
    return { ok: true, added, listening: !!(after && after.srv) };
  }
  async function startPort(port) {
    const cur = portStates.get(port);
    if (cur && cur.srv) { try { cur.srv.close(); } catch { /* noop */ } }
    const srv = makeSrv();
    const r = await new Promise((resolve) => {
      const onErr = (e) => { srv.off('listening', onOk); resolve({ ok: false, code: e && e.code, msg: String((e && e.message) || e) }); };
      const onOk = () => { srv.off('error', onErr); resolve({ ok: true }); };
      srv.once('error', onErr);
      srv.once('listening', onOk);
      srv.listen(port, opt.host);
    });
    if (r.ok) { portStates.set(port, { srv, status: 'listening', error: '' }); syncAddrStates(); return { ok: true }; }
    try { srv.close(); } catch { /* noop */ }
    const occupied = r.code === 'EADDRINUSE';
    portStates.set(port, { srv: null, status: 'error', error: occupied ? 'occupied' : r.msg.slice(0, 120) });
    syncAddrStates();
    return { ok: false, error: occupied ? 'occupied' : r.msg.slice(0, 120) };
  }
  function pausePort(port) {
    const cur = portStates.get(port);
    if (!cur) return { ok: false, error: 'not-managed' };
    if (cur.srv) { try { cur.srv.close(); } catch { /* noop */ } }
    portStates.set(port, { srv: null, status: 'paused', error: '' });
    syncAddrStates(); // R135q：端口变化立即刷新对外地址状态（自动兜底端口随监听集合）
    return { ok: true };
  }
  const listeningPorts = () => [...portStates.keys()].filter((p) => portStates.get(p).status === 'listening');

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
    // 必须核对数据目录身份：陈旧 instance.json 的端口可能已被另一个数据目录的实例接管。
    if (isSameInstance(alive, inst)) {
      log('INFO', `已有 FWArmy 在运行 pid=${inst.pid || '?'} port=${inst.port}；本次只打开管理页`);
      cleanupNewFiles();
      finishAlreadyRunning(`${inst.scheme || (alive.secure ? 'https' : 'http')}://127.0.0.1:${inst.port}/`);
      return { alreadyRunning: true, port: inst.port, dataDir: DATA };
    }
  }

  // ── R133 多业务端口启动：显式 --port 固定单端口；否则监听 cfg.ports（默认 59599+58588），被占标记异常不再顺延 ──
  let port = opt.port;
  let boundPort = 0;
  const wantPorts = opt.portExplicit ? [opt.port] : cfg.ports;
  // R166：显式 --port 是运行参数，只影响本次监听与视图；不再覆盖 cfg.ports（否则后续 saveCfg 会把默认端口 59599/58588 从 config.json 抹掉——更新重启带 --port 导致默认端口丢失的根因）。
  // viewPorts = 本次进程端口视图：显式模式从 [opt.port] 起，随端口管理操作（add/entry/remove/凭据端口自动加）同步；
  // 默认模式直接引用 cfg.ports（持久化配置即视图）。
  let viewPorts = opt.portExplicit ? [opt.port] : cfg.ports;
  const syncViewPorts = () => { if (opt.portExplicit) viewPorts = [...new Set(viewPorts)]; };
  const finishIfOurs = async (p) => {
    const h = await probe(p);
    const sameOurs = h && (h.server === 'fwarmy-relay' || h.server === 'warmy-relay') && h.dataDirHash === dataDirHash;
    if (sameOurs) {
      log('INFO', `端口 ${p} 上已有本数据目录的 FWArmy；本次只打开管理页`);
      cleanupNewFiles();
      finishAlreadyRunning(`${tlsInfo ? 'https' : 'http'}://127.0.0.1:${p}/`);
      return true;
    }
    return false;
  };
  for (const p of wantPorts) {
    const r = await startPort(p);
    if (r.ok) {
      if (!boundPort) boundPort = p;
      continue;
    }
    if (opt.portExplicit && p === opt.port) {
      if (await finishIfOurs(p)) return { alreadyRunning: true, port: p, dataDir: DATA };
      const h = await probe(p);
      const who = h && (h.server === 'fwarmy-relay' || h.server === 'warmy-relay')
        ? `被另一个 FWArmy 实例占用（数据目录标识 ${h.dataDirHash || '未知'}，不是本数据目录）`
        : '被其它程序占用';
      cleanupNewFiles();
      throw new Error(`显式端口 ${p} ${who}；显式 --port 固定端口不会自动换端口`);
    }
    log('WARN', `端口 ${p} 未能监听（${r.error}），已标记异常；可在「端口」页处理占用后启用`);
  }
  if (!boundPort) {
    if (await finishIfOurs(wantPorts[0])) return { alreadyRunning: true, port: wantPorts[0], dataDir: DATA };
    cleanupNewFiles();
    throw new Error(`没有可监听的端口（${wantPorts.join(', ')} 均被占用或失败）；请在管理页「端口」处理占用后重启`);
  }
  port = boundPort;
  actualPort = boundPort;

  const scheme = tlsInfo ? 'https' : 'http';
  try {
    writeJsonAtomic(INSTANCE, {
      pid: process.pid, port, host: opt.host, scheme,
      startedAt: new Date().toISOString(), version: VERSION,
      dataDirHash, instanceId: expand.instanceId,
      tls: { mode: cfg.tls.mode, fingerprint: tlsInfo ? tlsInfo.fingerprint : '' },
    });
  } catch { /* noop */ }
  try { fs.writeFileSync(PID_FILE, String(process.pid), { encoding: 'utf8', mode: 0o600 }); } catch { /* noop */ }

  const adminUrl = `${scheme}://127.0.0.1:${port}/`;
  log('INFO', `[fwarmy] ${PRODUCT} ${VERSION} 已启动 ${scheme}://${opt.host}:${port}  管理页 ${adminUrl}（本机直接打开，无需密钥）`);
  log('INFO', `[fwarmy] 数据目录 ${DATA}；只存凭据哈希/配置/统计/消息ID哈希，不存消息；队列 TTL ${TTL_MS / 1000}s`);
  if (firstRunPending()) log('INFO', '[fwarmy] 首次启动凭据待保存：打开管理页查看（不会写进日志）');
  // R135y：Windows 系统托盘（logo 图标 / 双击开管理页 / 右键退出）；--no-tray 或非交互会话禁用
  if (process.platform === 'win32' && !opt.noTray) setTimeout(() => startTray(port), 1200);
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
  scheduleAutoRestart(); // 自动重启定时器（到点重启自身；配置启用且 nextAt 有效才安排）
  // 公网 IP 自动探测（R131）：启动即探测，之后每 30 分钟刷新；页面点击可手动刷新。
  void probePublicIp();
  setInterval(() => void probePublicIp(), 30 * 60_000).unref();
  // 先验证手动对外地址再启动节点：首次发布的记录就用最终宣告地址（避免先用自动地址发布后被手动覆盖）。
  void (async () => {
    syncAddrStates();
    await checkExternalAddrs();
    const r = await dhtStart();
    if (!r.ok) log('WARN', '[dht] 启动失败：' + (r.error || ''));
  })();

  function openBrowser(url) {
    try {
      if (process.platform === 'win32') spawnDetached('cmd', ['/c', 'start', '', url]);
      else if (process.platform === 'darwin') spawnDetached('open', [url]);
      else spawnDetached('xdg-open', [url]);
    } catch { log('WARN', '无法自动打开浏览器，请手动打开 ' + url); }
  }
  function spawnDetached(cmd, args) {
    const { spawn } = require('node:child_process');
    // R146：detached:true 在本机/部分受管环境不可靠（进程退出但命令未执行——WDAC/策略拦截）——
    // 托盘脚本与打开浏览器不需要独立进程组，去掉 detached 保证命令真正执行（GUI 程序无控制台，父退出不影响子进程）。
    const child = spawn(cmd, args, { stdio: 'ignore', windowsHide: true });
    child.on('error', () => { /* Linux 没有 xdg-open 时不要因为未处理的 error 崩服务 */ });
    child.unref();
    return child;
  }
  /** R135y：启动系统托盘（fwarmy-tray.ps1，与 exe 同目录分发）；R145：每次启动都用内嵌 asset 覆盖磁盘脚本——旧目录残留的 $Pid 冲突版脚本会静默失败，覆盖后保证脚本与 exe 版本一致。 */
  function startTray(entryPort) {
    try {
      const trayPath = path.join(HERE, 'fwarmy-tray.ps1');
      if (IS_SEA && SEA && typeof SEA.getAsset === 'function') {
        try {
          // getAsset 无 encoding 时返回 ArrayBuffer（无 .length）——必须 Buffer.from 再判长，且保留 UTF-8 BOM
          const raw = SEA.getAsset('fwarmy-tray.ps1');
          if (raw) {
            const bytes = Buffer.from(raw);
            if (bytes.length) {
              fs.writeFileSync(trayPath, bytes);
              log('INFO', '[fwarmy] 托盘脚本已与程序版本同步（内嵌资源）');
            }
          }
        } catch (e) {
          log('WARN', '同步托盘脚本失败：' + String((e && e.message) || e).slice(0, 120));
        }
      }
      if (!fs.existsSync(trayPath)) return;
      spawnDetached('powershell.exe', ['-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden', '-ExecutionPolicy', 'Bypass', '-File', trayPath, '-Port', String(entryPort), '-MainPid', String(process.pid), '-Data', DATA]);
      log('INFO', `[fwarmy] 系统托盘已启动（管理页 http://127.0.0.1:${entryPort}/）`);
    } catch (e) {
      log('WARN', '托盘启动失败：' + String((e && e.message) || e).slice(0, 120));
    }
  }
  /** 第二个实例只打开管理页就退出；先关掉日志流，否则 Windows 上可能一直挂着。 */
  /** R146：读托盘状态文件（fwarmy-tray.ps1 写），供管理页/health 显示诊断信息。PS 5.1 的 Set-Content -Encoding UTF8 带 BOM——读取时剥掉。 */
  let trayCache = null; // R161：托盘状态 2s 缓存——health 热路径每请求同步读盘会阻塞事件循环（并发时放大）
  function trayStatus() {
    const now = Date.now();
    if (trayCache && now - trayCache.at < 2000) return trayCache.val;
    let val = { status: 'unknown', error: '' };
    try {
      const f = path.join(DATA, 'tray-state.json');
      if (fs.existsSync(f)) {
        const j = JSON.parse(fs.readFileSync(f, 'utf8').replace(/^\uFEFF/, ''));
        if (j && typeof j === 'object') val = { status: String(j.status || 'unknown'), error: String(j.error || ''), at: Number(j.at) ? String(j.at) : '' };
      }
    } catch { /* noop */ }
    trayCache = { at: now, val };
    return val;
  }
  function finishAlreadyRunning(url) {
    if (url && opt.open !== false) openBrowser(url);
    try { if (logStream) { logStream.end(); logStream = null; } } catch { /* noop */ }
  }
  if (opt.open !== false) openBrowser(adminUrl);

  let stopping = false;
  function cleanupFiles() {
    releaseLock();
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
    removeProcessHandlers();
    if (updateTimer) { clearTimeout(updateTimer); updateTimer = null; }
    if (updateRetryTimer) { clearTimeout(updateRetryTimer); updateRetryTimer = null; }
    if (autoRestartTimer) { clearTimeout(autoRestartTimer); autoRestartTimer = null; }
    clearInterval(statsInterval);
    clearInterval(pruneTimer);
    clearInterval(queueClean);
    clearInterval(securityGc);
    clearInterval(dhtRefreshTimer);
    if (statsTimer) clearTimeout(statsTimer);
    if (expandTimer) clearTimeout(expandTimer);
    await dhtStop();
    try { flushStats(true); } catch { /* noop */ }
    try { saveCreds(); } catch { /* noop */ }
    try { saveExpand(); } catch { /* noop */ }
    try { saveSecurity(); } catch { /* noop */ }
    try { httpSrv.close(); } catch { /* noop */ }
    try { if (httpsSrv) httpsSrv.close(); } catch { /* noop */ }
    try { httpSrv.closeAllConnections && httpSrv.closeAllConnections(); } catch { /* noop */ }
    try { if (httpsSrv && httpsSrv.closeAllConnections) httpsSrv.closeAllConnections(); } catch { /* noop */ }
    await Promise.all([...portStates.values()].map((st) => new Promise((resolve) => {
      const fin = () => resolve();
      if (st.srv) { try { st.srv.close(fin); } catch { fin(); } } else fin();
      setTimeout(fin, 1500).unref();
    })));
    for (const s of liveConns) { try { s.destroy(); } catch { /* noop */ } }
    liveConns.clear();
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
  // F13：监听器保存句柄，close() 时移除；嵌入/门禁多次启动不再累积 listener。
  const sigHandlers = [
    ['SIGINT', () => shutdown('SIGINT')],
    ['SIGTERM', () => shutdown('SIGTERM')],
    ['SIGHUP', () => shutdown('SIGHUP')],
  ];
  for (const [ev, fn] of sigHandlers) process.on(ev, fn);
  const exitHandler = () => {
    if (sharedStateFrozen) return; // 更新交接后新进程已接管共享状态，旧进程再写会覆盖（F04）
    try { flushStats(true); } catch { /* noop */ }
    try { saveExpand(); } catch { /* noop */ }
    try { saveSecurity(); } catch { /* noop */ }
    cleanupFiles();
  };
  const uncaughtHandler = (e) => { log('ERROR', '未捕获异常：' + String(e && e.stack || e).slice(0, 500)); };
  const unhandledHandler = (e) => { log('ERROR', '未处理 Promise：' + String(e && e.stack || e).slice(0, 500)); };
  process.on('exit', exitHandler);
  process.on('uncaughtException', uncaughtHandler);
  process.on('unhandledRejection', unhandledHandler);
  function removeProcessHandlers() {
    for (const [ev, fn] of sigHandlers) { try { process.off(ev, fn); } catch { /* noop */ } }
    try { process.off('exit', exitHandler); } catch { /* noop */ }
    try { process.off('uncaughtException', uncaughtHandler); } catch { /* noop */ }
    try { process.off('unhandledRejection', unhandledHandler); } catch { /* noop */ }
  }

  return { port, dataDir: DATA, stats: () => buildStats(), shutdown, close };
}

/** 源运行时：`node server.mjs` 直接启动。单文件由 sea-main.mjs 调用 startServer，不能在这里重复启动。 */
const isMain = !IS_SEA && !!SELF_FILE && !!process.argv[1] && path.resolve(process.argv[1]) === path.resolve(SELF_FILE);
if (isMain) {
  startServer({ argv: process.argv.slice(2) }).catch((e) => {
    console.error('FWArmy 启动失败：', e && e.stack || e);
    process.exit(1);
  });
}
