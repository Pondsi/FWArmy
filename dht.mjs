/**
 * dht —— FWArmy 内置 DHT 发现层（UDP）。
 *
 * 与 WArmy `@warmy/sync-protocol` 的 DHT 层**协议互认**（等价实现，非依赖）：
 *  - 线格式：单个 UDP 报文一段 JSON（base64url 承载二进制），k=8、alpha=3；
 *  - 节点 ID = sha256('warmy-dht/1|node-id|指纹')；记录键 = sha256hex('warmy-dht/1|record|指纹')；
 *  - 记录信封 {v,k,s,t,sg,pk,sl,sig}：内容用群密钥 AES-256-GCM 加密（AAD 绑定信封头），
 *    头部用 Ed25519 签名（transcript 为长度前缀字段拼接），可验签不解密（存储方）；
 *  - 指纹 = RFC 4648 base32(sha256(公钥))，52 字符无填充大写。
 *
 * 职责边界：DHT 只做**发现**（服务记录 / 客户端所在中继站的定位记录），
 * 消息投递仍走 FWArmy 既有凭据通道（expand 凭据 + TLS 指纹固定），本模块不承载业务消息。
 *
 * 诚实标注：与 WArmy 相同，这是可用最小子集（PING/FIND_NODE/STORE/GET、迭代查询、
 * k 桶 LRU），不做节点超时驱逐的严格收敛、不做 FIND_VALUE 缓存、不做节点 ID 工作量证明。
 */
import dgram from 'node:dgram';
import net from 'node:net';
import dns from 'node:dns';
import crypto from 'node:crypto';

export const DHT_PROTOCOL = 'warmy-dht/1';
export const DHT_ID_LENGTH = 32;
export const DEFAULT_K = 8;
export const DEFAULT_ALPHA = 3;
export const DEFAULT_RPC_TIMEOUT_MS = 1500;
export const RECORD_VERSION = 1;
/** 记录新鲜度上限：超过这个年龄的记录视为过期（不接受、不返回） */
export const DEFAULT_RECORD_TTL_MS = 30 * 60_000;
/** 公开发现记录的固定群密钥（与 WArmy public-discovery 相同：所有人可解，记录本身仍必须签名） */
export const PUBLIC_DISCOVERY_KEY = () => sha256(Buffer.from('warmy-public-discovery/1', 'utf8'));
export const DEFAULT_DHT_PORT = 443; // R133 拍板：DHT/锚点默认端口 443（另配 62666）
/** 记录 TTL 30 分钟 ⇒ 每 10 分钟重发一次保鲜 */
export const DHT_REFRESH_MS = 10 * 60_000;
/* ── 防滥用边界（DHT 发现层自身的 DoS 防护；不参与协议语义） ── */
/** 单报文上限：记录 + 节点列表 + 信封远小于此；超限直接丢弃（防超大 JSON 解析/内存占用） */
export const MAX_DGRAM_BYTES = 16 * 1024;
/** 每来源 IP 入站限速（60 次/分钟，突发 20）：压平 find_node 反射放大的利用（UDP 放大） */
export const DHT_PEER_RATE_PER_MIN = 60;
export const DHT_PEER_BURST = 20;
/** 存储上限：条目数与总字节（网络侧）；本机自发布（from=null）豁免 */
export const MAX_STORE_KEYS = 512;
export const MAX_STORE_BYTES = 4 * 1024 * 1024;

/* ────────────────────────────── 编解码 ────────────────────────────── */

export function b64u(b) { return Buffer.from(b).toString('base64url'); }
export function fromB64u(s) { return Buffer.from(String(s), 'base64url'); }
export function sha256(...parts) {
  const h = crypto.createHash('sha256');
  for (const p of parts) h.update(p instanceof Buffer ? p : Buffer.from(p));
  return h.digest();
}
export function sha256Hex(...parts) { return sha256(...parts).toString('hex'); }
/** RFC 4648 base32（无填充、大写），与 WArmy 指纹推导一致 */
export function base32(buf) {
  const b = Buffer.from(buf);
  let wei = 0, value = 0, out = '';
  for (const zijie of b) {
    value = (value << 8) | zijie;
    wei += 8;
    while (wei >= 5) { out += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.charAt((value >>> (wei - 5)) & 31); wei -= 5; }
  }
  if (wei > 0) out += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.charAt((value << (5 - wei)) & 31);
  return out;
}
/** 无歧义的字段拼接（长度前缀），供签名 transcript 使用 —— 与 WArmy pinJieZiduan 一致 */
export function pinJieZiduan(fields) {
  return fields
    .map((f) => {
      const s = f === null || f === undefined ? '' : String(f);
      return `${Buffer.byteLength(s, 'utf8')}:${s}`;
    })
    .join('|');
}
/** 指纹推导：base32(sha256(公钥 raw 32B)) */
export function warmyZhiWen(publicKeyRaw) { return base32(sha256(publicKeyRaw)); }
/** 节点 ID 由指纹推出（身份即路由身份） */
export function youZhiWenQuDhtId(zhiWen) {
  return sha256(Buffer.from(`${DHT_PROTOCOL}|node-id|${zhiWen}`, 'utf8'));
}
/** 记录键：由被宣告者指纹推出，DHT 上看不到明文指纹 */
export function jiLuJian(zhiWen) {
  return sha256Hex(Buffer.from(`${DHT_PROTOCOL}|record|${zhiWen}`, 'utf8'));
}
export function yihuoJuli(a, b) {
  const ba = Buffer.from(a), bb = Buffer.from(b);
  const out = Buffer.alloc(Math.min(ba.length, bb.length));
  for (let i = 0; i < out.length; i++) out[i] = ba[i] ^ bb[i];
  return out;
}
/** common prefix length（0..256），用于 k 桶划分 */
export function gongGongQianZhui(a, b) {
  const ba = Buffer.from(a), bb = Buffer.from(b);
  let wei = 0;
  for (let i = 0; i < Math.min(ba.length, bb.length); i++) {
    const x = ba[i] ^ bb[i];
    if (x === 0) { wei += 8; continue; }
    for (let bit = 7; bit >= 0; bit--) if ((x >> bit) & 1) return wei + (7 - bit);
  }
  return wei;
}

/* ── AES-256-GCM（记录内容加密；AAD 绑定信封头） ── */
export function gcmSeal(key, plaintext, aad) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  c.setAAD(Buffer.from(aad));
  return { iv, ct: Buffer.concat([c.update(Buffer.from(plaintext)), c.final(), c.getAuthTag()]) };
}
export function gcmOpen(key, iv, ct, aad) {
  const tag = ct.subarray(ct.length - 16);
  const body = ct.subarray(0, ct.length - 16);
  const d = crypto.createDecipheriv('aes-256-gcm', key, iv);
  d.setAAD(Buffer.from(aad));
  d.setAuthTag(tag);
  return Buffer.concat([d.update(body), d.final()]);
}

/* ────────────────────────────── 地址解析 ────────────────────────────── */

/** 解析 `host` / `host:port` / `[::1]:port`；不合法返回 null（不猜、不静默兜底） */

/** R132：域名解析优先 IPv6（IPv6 不可达回退 IPv4）；IP 字面量原样返回；解析失败返回 ''（调用方快速失败，绝不对域名发包——dgram 对域名 send 会触发 socket error 置空）。 */
export function resolve6First(host) {
  const h = String(host || '');
  if (net.isIP(h)) return Promise.resolve(h);
  return new Promise((resolve) => {
    dns.lookup(h, { all: true }, (err, addrs) => {
      if (err || !Array.isArray(addrs) || !addrs.length) return resolve('');
      const v6 = addrs.find((a) => a.family === 6);
      const v4 = addrs.find((a) => a.family === 4);
      resolve((v6 || v4 || addrs[0]).address);
    });
  });
}
export function jieXiDhtDiZhi(raw, defaultPort = DEFAULT_DHT_PORT) {
  const s = String(raw || '').trim();
  if (!s) return null;
  let host = s;
  let port = defaultPort;
  if (s.startsWith('[')) {
    const end = s.indexOf(']');
    if (end < 0) return null;
    host = s.slice(1, end);
    const rest = s.slice(end + 1);
    if (rest) {
      if (!rest.startsWith(':')) return null;
      port = Number(rest.slice(1));
    }
  } else {
    const colons = s.split(':').length - 1;
    if (colons > 1) return null;
    if (colons === 1) {
      const parts = s.split(':');
      host = parts[0] || '';
      port = Number(parts[1]);
    }
  }
  if (!host || !Number.isInteger(port) || port <= 0 || port > 65535) return null;
  if (!/^[A-Za-z0-9._-]+$/.test(host) && !/^[0-9a-fA-F:]+$/.test(host)) return null;
  return { host, port };
}
/** 归一化锚点列表：去重、去空、上限 16 个；非法项如实丢弃 */
export function guiFanAnChors(anchors, defaultPort = DEFAULT_DHT_PORT) {
  const list = Array.isArray(anchors) ? anchors : [];
  const out = [];
  const seen = new Set();
  for (const x of list) {
    const a = jieXiDhtDiZhi(String(x || ''), defaultPort);
    if (!a) continue;
    const key = `${a.host}|${a.port}`.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(a);
    if (out.length >= 16) break;
  }
  return out;
}

/* ────────────────────────────── 路由表（k-bucket） ────────────────────────────── */

export class LuyouBiao {
  constructor(selfId, k = DEFAULT_K) {
    this.selfId = selfId;
    this.k = k;
    this.buckets = new Map();
  }
  get size() {
    let n = 0;
    for (const b of this.buckets.values()) n += b.length;
    return n;
  }
  list() { return [...this.buckets.values()].flat(); }
  /** 加入/更新；桶满时淘汰最久未见（LRU） */
  add(contact) {
    if (contact.id.equals(this.selfId)) return;
    const idx = gongGongQianZhui(this.selfId, contact.id);
    let tong = this.buckets.get(idx);
    if (!tong) { tong = []; this.buckets.set(idx, tong); }
    const cur = tong.find((c) => c.id.equals(contact.id));
    if (cur) {
      cur.host = contact.host;
      cur.port = contact.port;
      cur.lastSeen = contact.lastSeen;
      if (contact.zhiWen) cur.zhiWen = contact.zhiWen;
      return;
    }
    if (tong.length >= this.k) {
      tong.sort((a, b) => a.lastSeen - b.lastSeen);
      tong.shift();
    }
    tong.push({ ...contact });
  }
  remove(id) {
    const idx = gongGongQianZhui(this.selfId, id);
    const tong = this.buckets.get(idx);
    if (!tong) return;
    this.buckets.set(idx, tong.filter((c) => !c.id.equals(id)));
  }
  /** 距离 target 最近的 n 个联系人 */
  closest(target, n = this.k) {
    return this.list()
      .sort((a, b) => Buffer.compare(yihuoJuli(a.id, target), yihuoJuli(b.id, target)))
      .slice(0, n);
  }
}

/* ────────────────────────────── 记录（签名 + 群密钥加密） ────────────────────────────── */

export function jiluQianmingJiaoyi(env) {
  return pinJieZiduan([DHT_PROTOCOL, 'RECORD', env.v, env.k, env.s, env.t, env.sg, env.pk, env.sl]);
}
export function jiluAad(env) {
  return pinJieZiduan([DHT_PROTOCOL, 'RECORD-AAD', env.v, env.k, env.s, env.t, env.sg, env.pk]);
}

/**
 * 组装记录信封：内容加密（群密钥）+ 头部签名（Ed25519）。
 * @param {object} o { zhiWen, publicKeyRaw, sign(msg)->Buffer, groupKey, key, record, seq, ts }
 */
export function qianMingJiLuFeng(o) {
  const pk = Buffer.from(o.publicKeyRaw);
  const ts = o.ts ?? Date.now();
  const touBu = {
    v: RECORD_VERSION, k: o.key, s: o.seq, t: ts,
    sg: o.zhiWen, pk: b64u(pk), sl: '', sig: '',
  };
  const sealed = gcmSeal(o.groupKey, Buffer.from(JSON.stringify(o.record), 'utf8'), jiluAad(touBu));
  touBu.sl = b64u(Buffer.concat([sealed.iv, sealed.ct]));
  touBu.sig = b64u(o.sign(Buffer.from(jiluQianmingJiaoyi(touBu), 'utf8')));
  return touBu;
}

export const JILU_JUJUE = {
  'bad-version': 'bad-version', 'key-mismatch': 'key-mismatch', 'signer-mismatch': 'signer-mismatch',
  'signature-invalid': 'signature-invalid', 'stale-seq': 'stale-seq', 'decrypt-failed': 'decrypt-failed',
  malformed: 'malformed',
};

/**
 * 校验记录：版本 → 键 → 签名者指纹↔公钥 → 签名 → seq 回滚 → 时间容差 → 解密。
 * @param {object} opts { expectKey, lastSeq, groupKeys: Buffer[], requireDecrypt, now, tsToleranceMs }
 */
export function yanZhengJiLuFeng(env, opts = {}) {
  const now = opts.now ?? (() => Date.now());
  const fail = (reason, detail) => ({ ok: false, reason, detail, signer: env && env.sg });
  if (!env || typeof env !== 'object') return fail(JILU_JUJUE.malformed, '信封不是对象');
  if (env.v !== RECORD_VERSION) return fail(JILU_JUJUE['bad-version'], `版本 ${env.v}`);
  if (typeof env.k !== 'string' || typeof env.sl !== 'string' || typeof env.sig !== 'string') {
    return fail(JILU_JUJUE.malformed, '缺少必要字段');
  }
  if (opts.expectKey && env.k !== opts.expectKey) {
    return fail(JILU_JUJUE['key-mismatch'], `记录键 ${env.k} ≠ 期望 ${opts.expectKey}`);
  }
  if (!Number.isSafeInteger(env.s) || env.s <= 0) return fail(JILU_JUJUE.malformed, `seq 非法：${env.s}`);
  let pk;
  try { pk = fromB64u(env.pk); } catch { pk = null; }
  if (!pk || pk.length !== 32) return fail(JILU_JUJUE.malformed, '签名公钥长度非法');
  if (warmyZhiWen(pk) !== env.sg) {
    return fail(JILU_JUJUE['signer-mismatch'], `签名者指纹 ${env.sg} 与公钥推出不符`);
  }
  const transcript = Buffer.from(jiluQianmingJiaoyi(env), 'utf8');
  let sigOk = false;
  try {
    sigOk = crypto.verify(null, transcript, crypto.createPublicKey({
      key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), pk]), format: 'der', type: 'spki',
    }), fromB64u(env.sig));
  } catch { sigOk = false; }
  if (!sigOk) return fail(JILU_JUJUE['signature-invalid'], '签名校验失败');
  if (typeof opts.lastSeq === 'number' && env.s <= opts.lastSeq) {
    return fail(JILU_JUJUE['stale-seq'], `记录 seq ${env.s} <= 已见 ${opts.lastSeq}`);
  }
  const rongcha = opts.tsToleranceMs ?? 10 * 60_000;
  if (Math.abs(now() - env.t) > rongcha) return fail(JILU_JUJUE.malformed, `记录时间戳超出容差：${env.t}`);
  const keys = Array.isArray(opts.groupKeys) ? opts.groupKeys : [];
  let jiLu = null;
  if (keys.length) {
    let sl;
    try { sl = fromB64u(env.sl); } catch { sl = null; }
    if (sl && sl.length > 16) {
      const iv = sl.subarray(0, 12);
      const ct = sl.subarray(12);
      for (const key of keys) {
        try {
          jiLu = JSON.parse(gcmOpen(key, iv, ct, jiluAad(env)).toString('utf8'));
          if (jiLu && typeof jiLu.fp === 'string' && typeof jiLu.host === 'string') break;
          jiLu = null;
        } catch { /* 试下一把 */ }
      }
    }
  }
  if (!jiLu) {
    if (opts.requireDecrypt) return fail(JILU_JUJUE['decrypt-failed'], '无群组密钥或内容被篡改，无法解密');
    return { ok: true, signer: env.sg, envelope: env };
  }
  return { ok: true, signer: env.sg, record: jiLu, envelope: env };
}

/* ────────────────────────────── 节点 ────────────────────────────── */

/**
 * @param {object} opts {
 *   zhiWen, publicKeyRaw, sign(msg)->Buffer,   // 身份（Ed25519，identity 模式签名）
 *   nodeId,                                     // 别名（记录 bieMing）
 *   host, advertiseHost, port, tcpPort,
 *   groupKeys: Buffer[],                        // 群密钥环，[0] 活跃（发布用）
 *   k, alpha, rpcTimeoutMs, now, onEvent, onRecord }
 */
export class DhtJieDian {
  constructor(opts) {
    this.opts = opts;
    this.k = opts.k ?? DEFAULT_K;
    this.alpha = opts.alpha ?? DEFAULT_ALPHA;
    this.rpcTimeoutMs = opts.rpcTimeoutMs ?? DEFAULT_RPC_TIMEOUT_MS;
    this.now = opts.now ?? (() => Date.now());
    this.tcpPort = opts.tcpPort ?? 0;
    this.id = youZhiWenQuDhtId(opts.zhiWen);
    this.table = new LuyouBiao(this.id, this.k);
    this.socket = null;
    this.bound = { host: opts.host ?? '::', port: 0 };
    this.store = new Map();        // keyHex → env
    this.storeBytes = 0;
    this.seqSeen = new Map();      // keyHex → 已见最大 seq
    this.seqLocal = new Map();     // keyHex → 本地发布 seq
    this.pending = new Map();      // rid → {resolve,reject,timer,replyType,target}
    this.watchers = new Map();     // keyHex → [cb]（'*' = 全部）
    this.ipRecent = new Map();     // 来源 IP → 时间窗口计数（入站限速，防反射放大）
    this.stats = { rpcSent: 0, rpcRecv: 0, rpcFailed: 0, rpcTimeout: 0, nodesLearned: 0, storesAccepted: 0, storesRejected: 0, recordsStored: 0, dgramDropped: 0, dgramRateLimited: 0 };
  }

  get zhiWen() { return this.opts.zhiWen; }
  get address() { return { ...this.bound }; }
  get listening() { return !!this.socket; }
  get contactCount() { return this.table.size; }
  get contacts() { return this.table.list().map((c) => ({ id: b64u(c.id), host: c.host, port: c.port, lastSeen: c.lastSeen, zhiWen: c.zhiWen || '' })); }
  get statsSnapshot() { return { ...this.stats }; }
  get groupKeys() { return this.opts.groupKeys ?? []; }

  setTcpPort(port) { this.tcpPort = port; }
  get advertisedTcpPort() { return this.tcpPort; }

  /** 订阅某个记录键（hex）；'*' 订阅全部 */
  watch(keyHex, cb) {
    const list = this.watchers.get(keyHex) ?? [];
    list.push(cb);
    this.watchers.set(keyHex, list);
    return () => {
      const cur = this.watchers.get(keyHex) ?? [];
      this.watchers.set(keyHex, cur.filter((f) => f !== cb));
    };
  }

  /** 启动 UDP 监听。port=0 随机端口（测试用）；显式传 port 覆盖构造选项。 */
  start(opts = {}) {
    return new Promise((resolve, reject) => {
      const host = this.opts.host ?? '::';
      this.isV6 = String(host).includes(':') || host === '::';
      const sock = dgram.createSocket({ type: this.isV6 ? 'udp6' : 'udp4', reuseAddr: true });
      this.socket = sock;
      sock.on('error', (e) => {
        this.emit('error', String(e.message ?? e));
        if (this.socket === sock) this.socket = null;
        reject(e);
      });
      sock.on('message', (msg, rinfo) => { void this.handleDatagram(msg, rinfo.address, rinfo.port); });
      sock.bind({ port: opts.port ?? this.opts.port ?? 0, address: host }, () => {
        const a = sock.address();
        this.bound = { host, port: a.port };
        resolve(this.address);
      });
    });
  }

  /** 归一化 IPv4-mapped 地址（::ffff:1.2.3.4 → 1.2.3.4），用于显示与比较 */
  normHost(h) { return String(h).startsWith('::ffff:') ? String(h).slice(7) : String(h); }
  /**
   * 统一发包。Windows 上 udp6 socket 向 IPv4 字面量地址 send 会 EINVAL，
   * 必须映射为 IPv4-mapped（::ffff:x.x.x.x）；纯 IPv6 与 mapped 地址原样发送。
   */
  sendTo(host, port, payload) {
    let h = String(host);
    if (this.isV6 && net.isIP(h) === 4) h = `::ffff:${h}`;
    this.socket.send(payload, port, h);
  }

  stop() {
    return new Promise((resolve) => {
      for (const p of this.pending.values()) { clearTimeout(p.timer); p.reject(new Error('node stopped')); }
      this.pending.clear();
      if (!this.socket) return resolve();
      const s = this.socket;
      this.socket = null;
      s.close(() => resolve());
    });
  }

  /** 引导：PING + FIND_NODE(self) 播种路由表；每个种子独立成败。 */
  async yindao(seeds) {
    let ok = 0, failed = 0;
    for (const seed of seeds) {
      try {
        await this.ping(seed);
        await this.findNode(seed, this.id);
        ok += 1;
      } catch { failed += 1; }
    }
    return { ok, failed };
  }

  /* ── 基础 RPC ── */

  contactFromWire(v) {
    if (typeof v !== 'object' || v === null) return null;
    const o = v;
    if (typeof o.id !== 'string' || typeof o.port !== 'number') return null;
    let id;
    try { id = fromB64u(o.id); } catch { return null; }
    if (id.length !== DHT_ID_LENGTH) return null;
    return {
      id, host: typeof o.host === 'string' && o.host.length > 0 ? o.host : '',
      port: o.port, lastSeen: this.now(),
      zhiWen: typeof o.fp === 'string' ? o.fp : undefined,
    };
  }

  /** 发送一条 RPC 并等待回复（单次，超时即失败；不重试）。R132：域名解析优先 IPv6，解析失败快速失败。 */
  async call(addr, xiaoXi, replyType, timeoutMs = this.rpcTimeoutMs) {
    if (!this.socket) return Promise.reject(new Error('DhtNode 未启动'));
    const host = await resolve6First(addr.host);
    if (!host) return Promise.reject(new Error(`RPC ${replyType} 无法解析 ${addr.host}`));
    const rid = crypto.randomBytes(6).toString('hex');
    const payload = Buffer.from(JSON.stringify({ ...xiaoXi, id: b64u(this.id), rid, reply: replyType }), 'utf8');
    this.stats.rpcSent += 1;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(rid);
        this.stats.rpcFailed += 1;
        this.stats.rpcTimeout += 1;
        this.emit('rpc-failed', `${replyType} → ${addr.host}:${addr.port} 超时`);
        reject(new Error(`RPC ${replyType} 超时`));
      }, timeoutMs);
      this.pending.set(rid, { resolve, reject, timer, replyType, target: { host: addr.host, port: addr.port } });
      try {
        this.sendTo(host, addr.port, payload);
      } catch (e) {
        clearTimeout(timer);
        this.pending.delete(rid);
        this.stats.rpcFailed += 1;
        reject(e);
      }
    }).finally(() => this.emit('rpc-sent', `${replyType} → ${addr.host}:${addr.port}`));
  }

  async ping(addr) {
    const res = await this.call(addr, { t: 'ping' }, 'pong');
    const from = this.contactFromWire(res.from);
    if (from) this.learn(from, addr);
    return from;
  }

  async findNode(addr, target) {
    const res = await this.call(addr, { t: 'find_node', target: b64u(target) }, 'nodes');
    const out = [];
    const arr = Array.isArray(res.nodes) ? res.nodes : [];
    for (const n of arr) {
      const c = this.contactFromWire(n);
      if (c) { out.push(c); this.learn(c, addr); }
    }
    return out;
  }

  learn(contact, observedAddr) {
    const before = this.table.size;
    const host = contact.host && contact.host !== '0.0.0.0' ? contact.host : observedAddr.host;
    this.table.add({ ...contact, host, port: contact.port || observedAddr.port, lastSeen: this.now() });
    if (this.table.size > before) this.stats.nodesLearned += 1;
  }

  /** 迭代 FIND_NODE（alpha 并行，非阻塞收敛） */
  async iterativeLookup(target, maxRpc = 48) {
    const shortlist = new Map();
    const asked = new Set();
    for (const c of this.table.closest(target, this.k)) shortlist.set(b64u(c.id), c);
    let rpcCount = 0;
    for (;;) {
      const candidates = [...shortlist.values()]
        .filter((c) => !asked.has(b64u(c.id)))
        .sort((a, b) => Buffer.compare(yihuoJuli(a.id, target), yihuoJuli(b.id, target)))
        .slice(0, this.alpha);
      if (candidates.length === 0 || rpcCount >= maxRpc) break;
      const results = await Promise.all(candidates.map(async (c) => {
        asked.add(b64u(c.id));
        rpcCount += 1;
        try { return await this.findNode({ host: c.host, port: c.port }, target); }
        catch { this.table.remove(c.id); return []; }
      }));
      for (const list of results) {
        for (const c of list) {
          const key = b64u(c.id);
          if (!shortlist.has(key)) shortlist.set(key, c);
        }
      }
    }
    return [...shortlist.values()]
      .sort((a, b) => Buffer.compare(yihuoJuli(a.id, target), yihuoJuli(b.id, target)))
      .slice(0, this.k);
  }

  /* ── 发布 / 查询 ── */

  localRecord(keyHex) { return this.store.get(keyHex) ?? null; }
  seenSeq(keyHex) { return this.seqSeen.get(keyHex) ?? 0; }
  /** 本端下一序列号（严格递增：本地计数与已见最大值的较大者 + 1） */
  nextSeq(keyHex, seenFromNetwork = this.seenSeq(keyHex)) {
    const local = this.seqLocal.get(keyHex) ?? 0;
    const next = Math.max(local, seenFromNetwork, this.seqSeen.get(keyHex) ?? 0) + 1;
    this.seqLocal.set(keyHex, next);
    return next;
  }

  /** 发布：内容加密 + 签名 → 本机存一份 → PUT 给距离最近的 k 个节点 */
  async publish(args) {
    const key = jiLuJian(args.zhiWen);
    const groupKey = this.groupKeys[0];
    if (!groupKey) throw new Error('发布记录需要群组密钥');
    const record = args.record ?? {
      fp: args.zhiWen,
      host: this.selfHost(),
      port: this.tcpPort,
      scope: 'relay',
      announcedAt: this.now(),
      bieMing: this.opts.nodeId,
    };
    const seq = args.seq ?? this.nextSeq(key);
    const env = qianMingJiLuFeng({
      zhiWen: this.opts.zhiWen, publicKeyRaw: this.opts.publicKeyRaw, sign: this.opts.sign,
      groupKey, key, record, seq, ts: this.now(),
    });
    this.acceptRecord(env, null);
    const target = youZhiWenQuDhtId(args.zhiWen);
    const closest = (await this.iterativeLookup(target)).filter((c) => !c.id.equals(this.id));
    const storedOn = [];
    for (const c of closest.slice(0, this.k)) {
      try {
        await this.call({ host: c.host, port: c.port }, { t: 'store', key, env }, 'stored');
        storedOn.push({ host: c.host, port: c.port });
      } catch { this.table.remove(c.id); }
    }
    this.emit('record-received', `本机发布 ${key.slice(0, 12)} seq=${seq}`);
    return { key, seq, storedOn, envelope: env };
  }

  /**
   * 查询：迭代查询最近的 k 个节点 → GET → 逐个验签/解密，返回 seq 最高的合法记录。
   */
  async query(zhiWen, opts = {}) {
    const key = jiLuJian(zhiWen);
    const attempts = [];
    const rejected = [];
    const target = youZhiWenQuDhtId(zhiWen);
    const candidates = await this.iterativeLookup(target);
    const zuiJia = { env: null, record: undefined, signer: undefined, from: undefined, seq: 0 };

    const kaoLv = async (env, addr) => {
      const result = yanZhengJiLuFeng(env, {
        expectKey: key, groupKeys: this.groupKeys,
        requireDecrypt: opts.requireDecrypt ?? true, now: this.now,
      });
      if (!result.ok) {
        attempts.push({ addr, status: 'reject', reason: result.reason });
        rejected.push({ addr, reason: result.reason ?? 'unknown', detail: result.detail });
        return;
      }
      if (env.s > zuiJia.seq) {
        zuiJia.env = env; zuiJia.record = result.record;
        zuiJia.signer = result.signer; zuiJia.from = addr; zuiJia.seq = env.s;
      }
      attempts.push({ addr, status: 'ok', seq: env.s });
    };

    const local = this.store.get(key);
    if (local) await kaoLv(local, { host: this.bound.host, port: this.bound.port });

    for (const c of candidates) {
      const addr = { host: c.host, port: c.port };
      if (c.id.equals(this.id)) continue;
      try {
        const res = await this.call(addr, { t: 'get', key }, 'found');
        const envs = Array.isArray(res.envs) ? res.envs : [];
        if (envs.length === 0) { attempts.push({ addr, status: 'empty' }); continue; }
        for (const env of envs) await kaoLv(env, addr);
      } catch (e) {
        attempts.push({ addr, status: 'rpc-failed', reason: String((e && e.message) || e) });
        this.table.remove(c.id);
      }
    }

    if (!zuiJia.env) return { ok: false, key, attempts, rejected };
    this.learnSeen(key, zuiJia.seq);
    return { ok: true, key, record: zuiJia.record, envelope: zuiJia.env, signer: zuiJia.signer, from: zuiJia.from, attempts, rejected };
  }

  learnSeen(keyHex, seq) {
    const cur = this.seqSeen.get(keyHex) ?? 0;
    if (seq > cur) this.seqSeen.set(keyHex, seq);
  }

  /** 接受一条记录（来自网络或本机）：防回滚，然后回调订阅者 */
  acceptRecord(env, from) {
    const seen = this.seqSeen.get(env.k) ?? 0;
    if (env.s <= seen) {
      this.stats.storesRejected += 1;
      return { accepted: false, reason: `stale-seq（${env.s} <= ${seen}）` };
    }
    // 容量边界：网络侧存储上限（防恶意 store 填满内存）；本机自发布（from=null）豁免。
    const isLocal = from === null;
    const isNew = !this.store.has(env.k);
    if (isNew && !isLocal) {
      if (this.store.size >= MAX_STORE_KEYS) {
        this.stats.storesRejected += 1;
        return { accepted: false, reason: 'store-full' };
      }
      const bytes = Buffer.byteLength(JSON.stringify(env), 'utf8');
      if (this.storeBytes + bytes > MAX_STORE_BYTES) {
        this.stats.storesRejected += 1;
        return { accepted: false, reason: 'store-bytes-exceeded' };
      }
      this.storeBytes += bytes;
    }
    this.store.set(env.k, env);
    this.learnSeen(env.k, env.s);
    if (env.s > (this.seqLocal.get(env.k) ?? 0)) this.seqLocal.set(env.k, env.s);
    this.stats.storesAccepted += 1;
    this.stats.recordsStored += 1;
    this.notifyWatchers(env, from);
    this.opts.onRecord?.(env, from);
    return { accepted: true };
  }

  /** 每来源 IP 的入站限速（滑动 60 秒窗口）；超限丢弃，压平反射放大/洪泛。 */
  rateOk(ip, at = this.now()) {
    const sec = Math.floor(at / 1000);
    let m = this.ipRecent.get(ip);
    if (!m) { m = new Map(); this.ipRecent.set(ip, m); }
    let n = 0;
    for (const [s, v] of m) { if (s <= sec - 60) m.delete(s); else n += v; }
    if (n >= DHT_PEER_RATE_PER_MIN) return false;
    if (m.size >= DHT_PEER_BURST + 2) { for (const [s] of m) if (s <= sec) m.delete(s); }
    m.set(sec, (m.get(sec) || 0) + 1);
    return true;
  }

  notifyWatchers(env, from) {
    for (const [key, list] of this.watchers) {
      if (key !== '*' && key !== env.k) continue;
      for (const cb of list) { try { cb(env, from); } catch { /* 订阅者异常不影响节点 */ } }
    }
  }

  /* ── 收包处理 ── */

  async handleDatagram(raw, host, port) {
    // 防滥用入口：报文大小上限 + 每来源 IP 限速（超限静默丢弃，只记账）。
    if (raw.length > MAX_DGRAM_BYTES) { this.stats.dgramDropped += 1; return; }
    if (!this.rateOk(this.normHost(host))) { this.stats.dgramRateLimited += 1; return; }
    let xiaoXi;
    try { xiaoXi = JSON.parse(raw.toString('utf8')); } catch { return; }
    if (!xiaoXi || typeof xiaoXi !== 'object') return;
    this.stats.rpcRecv += 1;
    const t = typeof xiaoXi.t === 'string' ? xiaoXi.t : '';
    const rid = typeof xiaoXi.rid === 'string' ? xiaoXi.rid : '';
    const peer = { host: this.normHost(host), port };
    const sender = this.contactFromWire({ id: xiaoXi.id, host: peer.host, port });
    if (sender) this.learn(sender, peer);

    // 0) 这是我发出的某条 RPC 的回包？直接结算（带 rid + 目标地址匹配 + 不是请求）
    const p = rid ? this.pending.get(rid) : undefined;
    const shiFouQingQiu = Object.prototype.hasOwnProperty.call(xiaoXi, 'reply');
    if (rid && p && !shiFouQingQiu && (t === p.replyType || t === 'error')
      && this.normHost(p.target.host) === peer.host && p.target.port === peer.port) {
      this.resolvePending(rid, xiaoXi);
      return;
    }

    // 1) 内置 RPC
    switch (t) {
      case 'ping':
        this.reply(port, host, rid, 'pong', { from: this.selfWireContact() });
        return;
      case 'find_node': {
        let target = this.id;
        try {
          const b = fromB64u(String(xiaoXi.target || ''));
          if (b.length === DHT_ID_LENGTH) target = b;
        } catch { /* 默认自己 */ }
        const nodes = this.table.closest(target, this.k).map((c) => this.contactOf(c));
        if (!nodes.some((n) => n.id === b64u(this.id))) nodes.push(this.selfWireContact());
        this.reply(port, host, rid, 'nodes', { nodes: nodes.slice(0, this.k) });
        return;
      }
      case 'store': {
        const env = xiaoXi.env;
        const key = typeof xiaoXi.key === 'string' ? xiaoXi.key : '';
        // 键一致性：请求 key 必须与信封内记录键一致（防错位存储/投毒路由键）。
        if (!env || typeof env !== 'object' || !key || env.k !== key) {
          this.reply(port, host, rid, 'error', { reason: 'key-mismatch' });
          return;
        }
        const yiYanZheng = yanZhengJiLuFeng(env, {
          expectKey: key,
          groupKeys: null, // 存储方无需群密钥：只验签，不解密
          requireDecrypt: false, now: this.now,
        });
        if (!yiYanZheng.ok) {
          this.stats.storesRejected += 1;
          this.emit('error', `拒绝记录：${yiYanZheng.reason} ${yiYanZheng.detail ?? ''}`);
          this.reply(port, host, rid, 'error', { reason: yiYanZheng.reason });
          return;
        }
        const accepted = this.acceptRecord(env, peer);
        if (!accepted.accepted) { this.reply(port, host, rid, 'error', { reason: accepted.reason }); return; }
        this.emit('stored', `接受 ${env.k.slice(0, 12)} seq=${env.s}`);
        this.reply(port, host, rid, 'stored', { key: env.k });
        return;
      }
      case 'get': {
        const key = typeof xiaoXi.key === 'string' ? xiaoXi.key : '';
        const env = this.store.get(key);
        this.reply(port, host, rid, 'found', { key, envs: env ? [env] : [] });
        return;
      }
      default:
        if (rid) this.reply(port, host, rid, 'error', { reason: `unknown-rpc:${t}` });
        return;
    }
  }

  /** 本节点在别人路由表里的样子：advertiseHost 显式给出时用显式值，否则如实上报绑定地址 */
  selfWireContact() {
    const host = (this.opts.advertiseHost && String(this.opts.advertiseHost).trim())
      || (this.bound.host === '0.0.0.0' || this.bound.host === '::' ? '127.0.0.1' : this.bound.host);
    return { id: b64u(this.id), host, port: this.bound.port, fp: this.opts.zhiWen };
  }

  selfHost() {
    const adv = this.opts.advertiseHost && String(this.opts.advertiseHost).trim();
    if (adv) return adv;
    return (this.bound.host === '0.0.0.0' || this.bound.host === '::') ? '127.0.0.1' : this.bound.host;
  }

  contactOf(contact) {
    return { id: b64u(contact.id), host: contact.host, port: contact.port };
  }

  reply(port, host, rid, type, ti) {
    if (!rid) return;
    try {
      this.sendTo(host, port, Buffer.from(JSON.stringify({ t: type, rid, id: b64u(this.id), ...ti }), 'utf8'));
    } catch { /* ignore */ }
  }

  emit(type, detail, peer) {
    this.opts.onEvent?.({ type, detail, peer, ts: this.now() });
  }

  resolvePending(rid, reply) {
    const p = this.pending.get(rid);
    if (!p) return;
    clearTimeout(p.timer);
    this.pending.delete(rid);
    if (reply.t === 'error') { p.reject(new Error(`RPC ${p.replyType} 被拒绝：${JSON.stringify(reply)}`)); return; }
    p.resolve(reply);
  }

  /** 通用：把一条原始报文喂给节点（测试用） */
  async feedDatagram(raw, host, port) {
    await this.handleDatagram(Buffer.from(raw), host, port);
  }
}

/** 判断记录里的地址是否与本地地址相同（地址变了要重新宣告） */
export function tongYiDiZhi(a, b) {
  return a && b && a.host === b.host && a.port === b.port;
}
