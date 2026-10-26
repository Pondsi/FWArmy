/**
 * FWArmy 扩网 / 被扩网 / 安全门禁（不依赖 Electron，进程内起多台真实服务器）。
 *
 * 覆盖第 11 项：
 *  · TLS 自签握手、客户端指纹固定（错指纹必须拒绝，且拒绝发生在发凭据之前）
 *  · 回环双服务器、三台多跳（A→B→C）
 *  · 每条消息唯一 ID + 来源实例 Ed25519 签名（改信封/换来源公钥都拒绝）
 *  · 同一消息 24h 内最多 2 次，第 3 次丢弃并写黑名单；超过 24h 也写黑名单
 *  · 重启后黑名单仍在；30 天未再出现自动清理（可注入时钟）
 *  · 上游 8 秒超时 = 失败，不落盘、不排队重试
 *  · 每实例多个被扩网凭据（可单独停用/删除）
 *  · 防环路/放大/伪造：route 环路、route 过长、报文大小、来源签名
 *  · NAT-PMP 只读探针/映射与 STUN 解析（离线 mock，不访问公网）
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import tls from 'node:tls';
import http from 'node:http';
import https from 'node:https';
import crypto from 'node:crypto';
import { pathToFileURL, fileURLToPath } from 'node:url';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const mod = await import(pathToFileURL(path.join(ROOT, 'server.mjs')).href);
const {
  parseExpandAddress, startServer, stunBinding, natpmpProbe, natpmpMap, generateSelfSignedCert,
  messageCanonical, MAX_FORWARDS, MESSAGE_WINDOW_MS, BLACKLIST_TTL_MS, MAX_ROUTE, UPSTREAM_TIMEOUT_MS,
} = mod;

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'fwarmy-expand-gate-'));
const freePort = () => new Promise((resolve) => {
  const s = net.createServer();
  s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); });
});
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let ok = 0, bad = 0;
const jian = (name, pass, detail) => {
  if (pass) { ok++; console.log('  ok  ' + name); }
  else { bad++; console.log('  FAIL ' + name + (detail !== undefined ? ' ← ' + JSON.stringify(detail).slice(0, 500) : '')); }
};
const sha = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');

function httpsJson(inst, p, { method = 'GET', body, token, timeout = 12000 } = {}) {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? '' : JSON.stringify(body);
    const req = https.request({
      host: '127.0.0.1', port: inst.port, path: p, method,
      rejectUnauthorized: false, agent: false,
      headers: {
        ...(payload ? { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload) } : {}),
        ...(token ? { authorization: 'Bearer ' + token } : {}),
        connection: 'close',
      },
    }, (res) => {
      const bu = [];
      res.on('data', (d) => bu.push(d));
      res.on('end', () => {
        const text = Buffer.concat(bu).toString('utf8');
        let json = null;
        try { json = JSON.parse(text); } catch { /* noop */ }
        resolve({ status: res.statusCode, json, text });
      });
    });
    req.setTimeout(timeout, () => req.destroy(new Error('timeout')));
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}
const admin = (inst, p, body) => httpsJson(inst, p, { method: body === undefined ? 'GET' : 'POST', body });
function httpJson(host, port, p, { method = 'GET', body } = {}) {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? '' : JSON.stringify(body);
    const req = http.request({
      host, port, path: p, method, agent: false,
      headers: { ...(payload ? { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload) } : {}), connection: 'close' },
    }, (res) => {
      const bu = []; res.on('data', (d) => bu.push(d));
      res.on('end', () => { let j = null; try { j = JSON.parse(Buffer.concat(bu).toString('utf8')); } catch { /* noop */ } resolve({ status: res.statusCode, json: j }); });
    });
    req.setTimeout(4000, () => req.destroy(new Error('timeout')));
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

async function boot(name, port, clock) {
  const data = path.join(tmp, name);
  const inst = await startServer({ port: port || (await freePort()), host: '127.0.0.1', data, open: false, argv: ['--quiet'], ...(clock ? { clock } : {}) });
  return inst;
}
async function createCred(inst, name) {
  const r = await admin(inst, '/api/admin/credentials', { name });
  return r.json.token;
}
async function inboundTok(inst, name) {
  const r = await admin(inst, '/api/admin/expand-inbound', { name });
  return { token: r.json.token, id: r.json.item.id };
}
async function addPeer(inst, name, host, port, credential) {
  const r = await admin(inst, '/api/admin/expand-outbound', { name, address: `${host}:${port}`, credential, tls: { mode: 'pin' } });
  return r.json.item;
}
async function trustPeer(inst, id) {
  const idn = await admin(inst, '/api/admin/expand-identify', { id });
  if (!idn.json || !idn.json.fingerprint) return { ok: false, idn: idn.json };
  const tr = await admin(inst, '/api/admin/expand-trust', { id, fingerprint: idn.json.fingerprint });
  return { ok: tr.json.ok === true, fingerprint: idn.json.fingerprint, idn: idn.json };
}
function makeOrigin(originId) {
  const kp = crypto.generateKeyPairSync('ed25519');
  const pub = kp.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32).toString('base64');
  return { originId, kp, pub };
}
function signedRelayBody(o, { msgId, to, envelope, createdAt, route = [] }) {
  const msg = messageCanonical({ msgId, origin: o.originId, to, createdAt, envelope });
  return {
    msgId, to, envelope, createdAt, route, source: o.originId,
    origin: o.originId, originPub: o.pub,
    originSig: crypto.sign(null, Buffer.from(msg), o.kp.privateKey).toString('base64'),
  };
}
function registerRecipient(inst, token) {
  const didKp = crypto.generateKeyPairSync('ed25519');
  const boxKp = crypto.generateKeyPairSync('x25519');
  const did = didKp.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32).toString('base64');
  const boxPub = boxKp.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32).toString('base64');
  const ts = Date.now();
  const sig = crypto.sign(null, Buffer.from(`register|${did}|${boxPub}|${ts}`), didKp.privateKey).toString('base64');
  return { did, boxPub, ts, sig, didKp, token };
}
async function poll(inst, rec, token) {
  const ts = Date.now();
  const sig = crypto.sign(null, Buffer.from(`poll|${rec.did}|${ts}`), rec.didKp.privateKey).toString('base64');
  return await httpsJson(inst, `/api/poll?did=${encodeURIComponent(rec.did)}&ts=${ts}&sig=${encodeURIComponent(sig)}`, { token });
}
async function restart(inst, clock) {
  const port = inst.port, data = inst.dataDir;
  await inst.close();
  return await startServer({ port, host: '127.0.0.1', data, open: false, argv: ['--quiet'], ...(clock ? { clock } : {}) });
}

const A = { inst: null }, B = { inst: null }, C = { inst: null }, D = { inst: null };
let clockC = Date.now();
try {
  A.inst = await boot('a');
  B.inst = await boot('b');
  C.inst = await boot('c', null, () => clockC);
  D.inst = await boot('d');

  const page = (await httpsJson(A.inst, '/')).text;
  jian('管理页有「扩网」标签，且在总览与日志之间',
    /data-tab="overview"[\s\S]{0,200}data-tab="expand"[\s\S]{0,200}data-tab="logs"/.test(page));
  jian('扩网页包含扩网与被扩网两块，并保留地址/凭据/生成按钮',
    /id="tab-expand"/.test(page) && /扩网 · 我连接别人/.test(page) && /被扩网 · 别人连接我/.test(page)
    && /id="exAddr"/.test(page) && /id="exCred"/.test(page) && /id="exGen"/.test(page)
    && /id="exInTokenBox" class="tokenbox" hidden/.test(page));
  jian('地址提示仍是：不填端口默认 59599',
    /不填端口就是默认 59599/.test(page) && /:端口/.test(page));

  jian('地址解析：不写端口默认 59599',
    parseExpandAddress('example.com').port === 59599 && parseExpandAddress('1.2.3.4').port === 59599);
  jian('地址解析：域名/IP 后可指定端口',
    parseExpandAddress('example.com:60000').port === 60000
    && parseExpandAddress('[::1]:60001').port === 60001
    && parseExpandAddress('http://x.test:59599/').host === 'x.test');

  /* ── TLS ── */
  const tlsView = (await admin(A.inst, '/api/admin/tls')).json.tls;
  const handshake = await new Promise((resolve) => {
    const s = tls.connect({ host: '127.0.0.1', port: A.inst.port, rejectUnauthorized: false });
    s.once('secureConnect', () => {
      const fp = crypto.createHash('sha256').update(s.getPeerCertificate().raw).digest('hex');
      resolve({ ok: true, fp, protocol: s.getProtocol() });
      s.destroy();
    });
    s.once('error', (e) => resolve({ ok: false, error: e.message }));
  });
  jian('TLS 握手成功，证书指纹与管理页一致', handshake.ok && handshake.fp === tlsView.fingerprint && /TLS/.test(handshake.protocol || ''), handshake);
  jian('TLS 默认自签 + 不明文放行远端', tlsView.mode === 'self-signed' && tlsView.allowPlaintext === false, tlsView);
  const keyOnDisk = fs.readFileSync(path.join(A.inst.dataDir, 'tls', 'key.pem'), 'utf8');
  jian('自签私钥不以明文落盘（secret.key 加密）', keyOnDisk.startsWith('enc:v1:') && !keyOnDisk.includes('PRIVATE KEY'));

  // 用户证书模式：用户给 cert/key，客户端按 CA 链校验（这里只验证服务器能用该证书握手）。
  const uc = generateSelfSignedCert({ commonName: 'fwarmy-user-cert', hostnames: ['localhost'], ips: ['127.0.0.1'] });
  const ucCert = path.join(tmp, 'user-cert.pem');
  const ucKey = path.join(tmp, 'user-key.pem');
  fs.writeFileSync(ucCert, uc.certPem);
  fs.writeFileSync(ucKey, uc.keyPem);
  const H = { inst: null, data: path.join(tmp, 'h') };
  fs.mkdirSync(H.data, { recursive: true });
  fs.writeFileSync(path.join(H.data, 'config.json'), JSON.stringify({ tls: { mode: 'user-cert', certFile: ucCert, keyFile: ucKey } }));
  H.inst = await startServer({ port: await freePort(), host: '127.0.0.1', data: H.data, open: false, argv: ['--quiet'] });
  const hHand = await new Promise((resolve) => {
    const s = tls.connect({ host: '127.0.0.1', port: H.inst.port, rejectUnauthorized: false });
    s.once('secureConnect', () => { resolve(crypto.createHash('sha256').update(s.getPeerCertificate().raw).digest('hex')); s.destroy(); });
    s.once('error', () => resolve(''));
  });
  jian('用户证书模式可用，指纹等于提供的证书', hHand === uc.fingerprint);
  await H.inst.close();
  const badData = path.join(tmp, 'bad-cert');
  fs.mkdirSync(badData, { recursive: true });
  fs.writeFileSync(path.join(badData, 'config.json'), JSON.stringify({ tls: { mode: 'user-cert', certFile: path.join(tmp, 'nope.pem'), keyFile: path.join(tmp, 'nope.key') } }));
  let badStart = false;
  try { const x = await startServer({ port: await freePort(), host: '127.0.0.1', data: badData, open: false, argv: ['--quiet'] }); await x.close(); }
  catch { badStart = true; }
  jian('用户证书缺失时拒绝启动，不静默降级为明文', badStart === true);

  // 明文防线：绑 0.0.0.0 后从 127.0.0.2（不是回环白名单里的 127.0.0.1）访问，应 426。
  const G = {
    inst: await startServer({
      port: await freePort(), host: '0.0.0.0', data: path.join(tmp, 'g'), open: false, argv: ['--quiet'],
    }),
  };
  try {
    const lan = Object.values(os.networkInterfaces()).flat().find((x) => x.family === 'IPv4' && !x.internal && x.address);
    if (!lan) jian('非回环来源的明文业务请求被 426 拒绝（跳过：没有非回环 IPv4）', true);
    else {
      const plain = await httpJson(lan.address, G.inst.port, '/api/relay', { method: 'POST', body: { to: 'x', envelope: '{}' } });
      jian('非回环来源的明文业务请求被 426 拒绝', plain.status === 426 && plain.json.error === 'tls-required', plain);
    }
  } catch (e) {
    jian('非回环来源的明文业务请求被 426 拒绝', false, String(e && e.message || e));
  } finally {
    try { await G.inst.close(); } catch { /* noop */ }
  }

  /* ── 双向凭据 / 多被扩网凭据 ── */
  const ka = await createCred(A.inst, 'A-client');
  const kb = await createCred(B.inst, 'B-client');
  const kc = await createCred(C.inst, 'C-client');
  const kd = await createCred(D.inst, 'D-client');
  jian('三端业务凭据可创建', !!ka && !!kb && !!kc);

  const inB1 = await inboundTok(B.inst, 'from-A');
  const inB2 = await inboundTok(B.inst, 'second');
  const inC = await inboundTok(C.inst, 'from-B');
  jian('被扩网：可生成多个独立凭据', inB1.token !== inB2.token && /^fwnexp_/.test(inB1.token));

  const pingB1 = await httpsJson(B.inst, '/api/expand/ping', { token: inB1.token });
  const pingB2 = await httpsJson(B.inst, '/api/expand/ping', { token: inB2.token });
  jian('两个被扩网凭据都可单独使用', pingB1.status === 200 && pingB2.status === 200);
  await admin(B.inst, '/api/admin/expand-inbound-update', { id: inB2.id, disabled: true });
  const pingB2b = await httpsJson(B.inst, '/api/expand/ping', { token: inB2.token });
  const pingB1b = await httpsJson(B.inst, '/api/expand/ping', { token: inB1.token });
  jian('停用其中一个不影响另一个', pingB2b.status === 401 && pingB1b.status === 200, { a: pingB2b.status, b: pingB1b.status });
  await admin(B.inst, '/api/admin/expand-inbound-update', { id: inB2.id, disabled: false });
  const delB2 = await admin(B.inst, '/api/admin/expand-inbound-remove', { id: inB2.id });
  const pingB2c = await httpsJson(B.inst, '/api/expand/ping', { token: inB2.token });
  const pingB1c = await httpsJson(B.inst, '/api/expand/ping', { token: inB1.token });
  jian('删除一条凭据后它立即失效，其余不受影响', delB2.json.ok === true && pingB2c.status === 401 && pingB1c.status === 200);

  /* ── 多跳 A→B→C ── */
  const pAB = await addPeer(A.inst, 'B', '127.0.0.1', B.inst.port, inB1.token);
  const tAB = await trustPeer(A.inst, pAB.id);
  const pBC = await addPeer(B.inst, 'C', '127.0.0.1', C.inst.port, inC.token);
  const tBC = await trustPeer(B.inst, pBC.id);
  jian('扩网：识别并固定对端证书指纹', tAB.ok && tBC.ok && /^[0-9a-f]{64}$/.test(tAB.fingerprint));

  const testA = await admin(A.inst, '/api/admin/expand-test', { id: pAB.id });
  jian('扩网连通测试在指纹固定后可达', testA.json.reachable === true, testA.json);

  let rec = registerRecipient(C.inst, kc);
  const reg = await httpsJson(C.inst, '/api/register', { method: 'POST', token: kc, body: { did: rec.did, boxPub: rec.boxPub, ts: rec.ts, sig: rec.sig } });
  jian('C 上收件人注册成功', reg.status === 200 && reg.json.ok === true, reg.json);

  const env1 = JSON.stringify({ hello: 'multi-hop', n: 1 });
  const r1 = await httpsJson(A.inst, '/api/relay', { method: 'POST', token: ka, body: { to: rec.did, envelope: env1 }, timeout: 15000 });
  jian('A 本机离线 → B → C 三台多跳成功', r1.status === 200 && r1.json.ok === true && r1.json.forwarded === true, r1.json);
  const poll1 = await poll(C.inst, rec, kc);
  jian('C 真的收到多跳信封', poll1.status === 200 && (poll1.json.envelopes || []).includes(env1), poll1.json);

  const aExp = (await admin(A.inst, '/api/admin/expand')).json;
  const cExp = (await admin(C.inst, '/api/admin/expand')).json;
  jian('A 记到成功转发 / C 记到成功投递',
    aExp.stats.outbound.total.delivered >= 1 && cExp.stats.inbound.total.delivered >= 1,
    { a: aExp.stats.outbound.total, c: cExp.stats.inbound.total });

  /* ── 凭据不落明文 ── */
  const aRaw = fs.readFileSync(path.join(A.inst.dataDir, 'expand.json'), 'utf8');
  const bRaw = fs.readFileSync(path.join(B.inst.dataDir, 'expand.json'), 'utf8');
  jian('出网凭据不以明文落盘，入网凭据只存 sha256',
    !aRaw.includes(inB1.token) && !aRaw.includes('fwnexp_') && aRaw.includes('enc:v1:')
    && !bRaw.includes(inB1.token) && bRaw.includes(inB1.token ? sha(inB1.token) : 'x'), { aEnc: aRaw.includes('enc:v1:') });

  /* ── 重复消息：2 次后第 3 次丢弃并黑名单 ── */
  const o1 = makeOrigin('origin-dup-1');
  const baseC = clockC;
  const dup = async (msgId, at, o = o1, route = []) => httpsJson(C.inst, '/api/expand/relay', {
    method: 'POST', token: inC.token,
    body: signedRelayBody(o, { msgId, to: rec.did, envelope: JSON.stringify({ dup: msgId, at }), createdAt: at, route }),
  });
  const d1 = await dup('dup-msg-0001', baseC);
  const d2 = await dup('dup-msg-0001', baseC + 1000);
  const d3 = await dup('dup-msg-0001', baseC + 2000);
  const d4 = await dup('dup-msg-0001', baseC + 3000);
  jian('同一消息前 2 次允许，第 3 次丢弃', d1.json.ok === true && d2.json.ok === true && d3.status === 409 && d3.json.ok === false, { d1: d1.json, d3: d3.json });
  jian('第 3 次写入黑名单，第 4 次直接拒绝', d4.status === 409 && d4.json.error === 'message-blacklisted', d4.json);
  const sec1 = (await admin(C.inst, '/api/admin/security')).json;
  jian('安全面板能看到黑名单条目', sec1.blacklist.count >= 1 && sec1.policy.maxForwards === MAX_FORWARDS, sec1.blacklist);

  /* ── 24h 边界 ── */
  const o2 = makeOrigin('origin-24h-2');
  const m2 = 'boundary-msg-0024';
  const b1 = await dup(m2, baseC, o2);
  clockC = baseC + 23 * 3600 * 1000;
  const b2 = await dup(m2, clockC, o2);
  clockC = baseC + MESSAGE_WINDOW_MS + 1;
  const b3 = await dup(m2, clockC, o2);
  jian('24h 内第二次仍允许，超过 24h 立即丢弃并黑名单',
    b1.json.ok === true && b2.json.ok === true && b3.status === 409 && /24h|duplicate/.test(String(b3.json.error) + (b3.json.reason || '')), { b1: b1.json, b2: b2.json, b3: b3.json });

  /* ── 重启后黑名单仍在 ── */
  C.inst = await restart(C.inst, () => clockC);
  rec = registerRecipient(C.inst, kc);
  await httpsJson(C.inst, '/api/register', { method: 'POST', token: kc, body: { did: rec.did, boxPub: rec.boxPub, ts: rec.ts, sig: rec.sig } });
  const afterRestart = await dup('dup-msg-0001', clockC);
  const afterRestart2 = await dup(m2, clockC);
  jian('重启后原黑名单仍生效', afterRestart.status === 409 && afterRestart.json.error === 'message-blacklisted'
    && afterRestart2.status === 409, { a: afterRestart.json, b: afterRestart2.json });

  /* ── 30 天清理 ── */
  clockC = clockC + BLACKLIST_TTL_MS + 86400000;
  C.inst = await restart(C.inst, () => clockC);
  rec = registerRecipient(C.inst, kc);
  await httpsJson(C.inst, '/api/register', { method: 'POST', token: kc, body: { did: rec.did, boxPub: rec.boxPub, ts: rec.ts, sig: rec.sig } });
  const sec2 = (await admin(C.inst, '/api/admin/security')).json;
  const after30 = await dup('dup-msg-0001', clockC);
  jian('30 天未再出现后黑名单自动清理', sec2.blacklist.count === 0 && after30.json.ok === true, { count: sec2.blacklist.count, r: after30.json });

  /* ── 防伪造 / 环路 / 超长 route ── */
  const forged = signedRelayBody(o2, { msgId: 'forged-msg-01', to: rec.did, envelope: JSON.stringify({ ok: true }), createdAt: clockC });
  forged.envelope = JSON.stringify({ ok: false });
  const fr = await httpsJson(C.inst, '/api/expand/relay', { method: 'POST', token: inC.token, body: forged });
  jian('改信封后来源签名失效（防伪造）', fr.status === 403 && fr.json.error === 'bad-origin-signature', fr.json);

  const o3 = makeOrigin('origin-mismatch-3');
  const mm = signedRelayBody(o3, { msgId: 'mismatch-msg-01', to: rec.did, envelope: '{}', createdAt: clockC });
  mm.originPub = makeOrigin('x').pub;
  const mmr = await httpsJson(C.inst, '/api/expand/relay', { method: 'POST', token: inC.token, body: mm });
  jian('换来源公钥被拒绝（防冒充）', mmr.status === 403 || mmr.status === 409, mmr.json);

  const cid = (await admin(C.inst, '/api/admin/expand')).json.instanceId;
  const loop = await httpsJson(C.inst, '/api/expand/relay', {
    method: 'POST', token: inC.token,
    body: signedRelayBody(o2, { msgId: 'loop-msg-0001', to: rec.did, envelope: '{}', createdAt: clockC, route: [cid] }),
  });
  jian('route 里出现本实例即拒绝（防环路）', loop.status === 409 && loop.json.error === 'loop', loop.json);

  const longRoute = Array.from({ length: MAX_ROUTE + 1 }, (_, i) => 'r' + i);
  const lr = await httpsJson(C.inst, '/api/expand/relay', {
    method: 'POST', token: inC.token,
    body: signedRelayBody(o2, { msgId: 'route-long-01', to: rec.did, envelope: '{}', createdAt: clockC, route: longRoute }),
  });
  jian('route 超长直接拒绝（限制报文大小）', lr.status === 409 && lr.json.error === 'route-too-long', lr.json);

  /* ── 上游 8 秒超时 ── */
  const blackhole = net.createServer((s) => { s.on('data', () => { /* 永不回包 */ }); s.on('error', () => {}); });
  const bhPort = await freePort();
  await new Promise((r) => blackhole.listen(bhPort, '127.0.0.1', r));
  const pTimeout = await addPeer(D.inst, 'blackhole', '127.0.0.1', bhPort, 'fwnexp_fake_for_timeout');
  await admin(D.inst, '/api/admin/expand-update', { id: pTimeout.id, tls: { mode: 'off' }, enabled: true });
  const t0 = Date.now();
  const to = await httpsJson(D.inst, '/api/relay', { method: 'POST', token: kd, body: { to: 'nobody', envelope: '{"timeout":1}' }, timeout: 15000 });
  const elapsed = Date.now() - t0;
  const dExp = (await admin(D.inst, '/api/admin/expand')).json;
  const peerStat = dExp.outbound.find((x) => x.id === pTimeout.id);
  jian('上游 8 秒超时即判失败（不无限等）', elapsed >= 7200 && elapsed <= 11000
    && to.json.ok === false && (to.json.attempts || []).some((x) => x.error === 'upstream-timeout'),
    { elapsed, body: to.json });
  jian('超时写入统计，且没有落盘重试队列', peerStat && peerStat.stats.lastResult === 'upstream-timeout'
    && !fs.readdirSync(D.inst.dataDir).some((f) => /retry|queue/i.test(f)), { stat: peerStat && peerStat.stats.lastResult, files: fs.readdirSync(D.inst.dataDir) });
  jian('默认超时常量为 8000ms', UPSTREAM_TIMEOUT_MS === 8000);
  blackhole.close();

  /* ── NAT-PMP / STUN 离线 mock ── */
  const probe = await natpmpProbe({ gateways: ['192.168.1.1'], request: async () => Buffer.from([0, 128, 0, 1]) });
  jian('NAT-PMP 只读探针：网关应答即视为支持（不建映射）', probe.alive === true && probe.gateway === '192.168.1.1', probe);
  const mapped = await natpmpMap({
    gateway: '192.168.1.1', internalPort: 59599,
    request: async () => {
      const b = Buffer.alloc(16); b[0] = 0; b[1] = 129; b.writeUInt16BE(0, 2); b.writeUInt16BE(59599, 8); b.writeUInt16BE(40123, 10); b.writeUInt32BE(7200, 12); return b;
    },
  });
  jian('NAT-PMP 映射解析出外部端口', mapped.ok === true && mapped.externalPort === 40123, mapped);

  const stun = await stunBinding({
    servers: ['stun.invalid:3478'],
    send: async (pkt) => {
      const tid = pkt.subarray(8, 20);
      const val = Buffer.alloc(8); val[1] = 1;
      val.writeUInt16BE((40123 ^ 0x2112) & 0xffff, 2);
      const ip = (0x0a000001 ^ 0x2112a442) >>> 0;
      val.writeUInt32BE(ip, 4);
      const attr = Buffer.alloc(12); attr.writeUInt16BE(0x0020, 0); attr.writeUInt16BE(8, 2); val.copy(attr, 4);
      const head = Buffer.alloc(20); head.writeUInt16BE(0x0101, 0); head.writeUInt16BE(attr.length, 2); head.writeUInt32BE(0x2112a442, 4); tid.copy(head, 8);
      return Buffer.concat([head, attr]);
    },
  });
  jian('STUN Binding 解析出公网映射地址', stun.ok === true && stun.publicAddress.host === '10.0.0.1' && stun.publicAddress.port === 40123, stun);

  const reach = (await admin(C.inst, '/api/admin/reach')).json;
  jian('可达性页面给出证据与判决（不谎称已打通）', reach.ok === true && ['confirmed-inbound', 'mapped', 'stun-visible', 'lan-only'].includes(reach.verdict)
    && reach.hints.length > 0, reach);

  /* ── 错指纹必须拒绝 ── */
  const pBad = await addPeer(D.inst, 'wrong-pin', '127.0.0.1', B.inst.port, inB1.token);
  await admin(D.inst, '/api/admin/expand-update', { id: pBad.id, tls: { mode: 'pin', fingerprint: '00'.repeat(32) } });
  const badTest = await admin(D.inst, '/api/admin/expand-test', { id: pBad.id });
  jian('客户端指纹不匹配时拒绝连接（不发凭据）', badTest.json.reachable === false && /fingerprint/.test(String(badTest.json.error || '')), badTest.json);

  console.log(`\n==== FWArmy 扩网/安全门禁：${ok} ok / ${bad} FAIL ====`);
} catch (e) {
  bad++;
  console.log('  FAIL 未捕获异常 ← ' + String((e && e.stack) || e).slice(0, 800));
  console.log(`\n==== FWArmy 扩网/安全门禁：${ok} ok / ${bad} FAIL ====`);
} finally {
  for (const x of [A, B, C, D]) {
    try { if (x.inst && x.inst.close) await x.inst.close(); } catch { /* noop */ }
  }
  await sleep(200);
  try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* noop */ }
}
process.exitCode = bad ? 1 : 0;
