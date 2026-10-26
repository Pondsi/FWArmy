/**
 * 单文件验收（三平台同一套）：
 *   node verify-binary.mjs dist/FWArmy.exe
 *
 * 不 import 源码，只把构建出来的可执行文件当成黑盒：
 * 启动、健康检查、管理页/图标、首次凭据、业务签名、转发/轮询、TLS 指纹、扩网端点、
 * Host/Origin/表单边界、table/stop/shutdown。
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import http from 'node:http';
import https from 'node:https';
import crypto from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const BIN = path.resolve(process.argv[2] || path.join(ROOT, 'dist', process.platform === 'win32' ? 'FWArmy.exe' : 'FWArmy'));
const VERSION = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8')).version;

let okN = 0;
let failN = 0;
const jian = (label, pass, detail = '') => {
  if (pass) { okN++; console.log('  ok  ' + label); }
  else { failN++; console.log('  FAIL ' + label + (detail ? ' ← ' + String(detail).slice(0, 220) : '')); }
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const freePort = () => new Promise((resolve) => {
  const s = net.createServer();
  s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); });
});

function ed() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const raw = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
  return { pub: raw.toString('base64'), priv: privateKey };
}
function x25519() {
  const { publicKey } = crypto.generateKeyPairSync('x25519');
  return publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('base64');
}
const sign = (priv, msg) => crypto.sign(null, Buffer.from(msg, 'utf8'), priv).toString('base64');

async function getJson(url, headers = {}) {
  const r = await fetch(url, { headers });
  const text = await r.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* non-json */ }
  return { status: r.status, json, text };
}
async function postJson(url, body, headers = {}) {
  const r = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body: JSON.stringify(body),
  });
  const text = await r.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* non-json */ }
  return { status: r.status, json, text };
}
function rawStatus(port, pathname, headers) {
  return new Promise((resolve) => {
    const req = http.request({ host: '127.0.0.1', port, path: pathname, method: 'GET', headers }, (res) => {
      res.resume();
      resolve(res.statusCode || 0);
    });
    req.on('error', () => resolve(0));
    req.end();
  });
}
function httpsGet(port, pathname, headers) {
  return new Promise((resolve, reject) => {
    const req = https.request({
      host: '127.0.0.1', port, path: pathname, method: 'GET', headers,
      rejectUnauthorized: false, checkServerIdentity: () => undefined,
    }, (res) => {
      const cert = res.socket && res.socket.getPeerCertificate ? res.socket.getPeerCertificate() : null;
      const fp = cert && cert.raw ? crypto.createHash('sha256').update(cert.raw).digest('hex') : '';
      let text = '';
      res.setEncoding('utf8');
      res.on('data', (d) => { text += d; });
      res.on('end', () => {
        let json = null;
        try { json = JSON.parse(text); } catch { /* non-json */ }
        resolve({ status: res.statusCode, json, text, fingerprint: fp });
      });
    });
    req.on('error', reject);
    req.end();
  });
}

function startServer(port, data) {
  const child = spawn(BIN, ['--server', `--port=${port}`, '--host=127.0.0.1', `--data=${data}`, '--no-open'], {
    stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true,
  });
  child.__out = '';
  child.__err = '';
  child.stdout.on('data', (b) => { child.__out += String(b); });
  child.stderr.on('data', (b) => { child.__err += String(b); });
  return child;
}
async function waitHealth(port, child, timeoutMs = 60_000) {
  const t0 = Date.now();
  while (Date.now() - t0 < timeoutMs) {
    if (child.exitCode !== null) throw new Error(`服务提前退出 code=${child.exitCode} err=${child.__err}`);
    try {
      const r = await fetch(`http://127.0.0.1:${port}/api/health`, { signal: AbortSignal.timeout(800) });
      if (r.ok) return await r.json();
    } catch { /* retry */ }
    await sleep(100);
  }
  throw new Error('等待健康检查超时 err=' + child.__err);
}
async function waitExit(child, timeoutMs = 15_000) {
  if (child.exitCode !== null) return child.exitCode;
  return Promise.race([
    new Promise((resolve) => child.once('exit', (code, sig) => resolve(code === null ? `signal:${sig}` : code))),
    sleep(timeoutMs).then(() => null),
  ]);
}
async function stopChild(child) {
  if (child.exitCode !== null) return;
  try { child.kill(); } catch { /* noop */ }
  await waitExit(child, 3000);
}

const tmpDirs = [];
const mkTmp = (tag) => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), `fwarmy-bin-${tag}-`));
  tmpDirs.push(d);
  return d;
};

try {
  console.log(`FWArmy 单文件验收：${BIN}`);
  jian('单文件存在', fs.existsSync(BIN), BIN);
  if (!fs.existsSync(BIN)) throw new Error('binary not found');
  if (process.platform !== 'win32') {
    try { fs.chmodSync(BIN, 0o755); } catch { /* noop */ }
  }

  const ver = spawnSync(BIN, ['--version'], { encoding: 'utf8', timeout: 30_000, windowsHide: true });
  jian('--version 可执行且报出产品名/版本', ver.status === 0 && /FWArmy/.test(String(ver.stdout)) && String(ver.stdout).includes(VERSION), `${ver.status} ${ver.stdout} ${ver.stderr}`);

  // ── 第一段：完整 HTTP/TLS 业务 + 管理页关闭 ──
  const port1 = await freePort();
  const data1 = mkTmp('one');
  const base1 = `http://127.0.0.1:${port1}`;
  const srv1 = startServer(port1, data1);
  try {
    const health = await waitHealth(port1, srv1);
    jian('健康检查：认出 fwarmy-relay / FWArmy', health.ok === true && health.server === 'fwarmy-relay' && health.product === 'FWArmy', JSON.stringify(health));

    const page = await fetch(base1 + '/');
    const html = await page.text();
    jian('管理页可打开且内嵌完整界面', page.status === 200 && /FWArmy/.test(html) && /id=["']?credTable/.test(html), String(page.status));

    const logo = await fetch(base1 + '/assets/logo.svg');
    const logoSvg = await logo.text();
    jian('内嵌 logo.svg 可取（单文件不依赖外部目录）', logo.status === 200 && /<svg/i.test(logoSvg), String(logo.status));

    const first = await getJson(base1 + '/api/admin/first-credential');
    jian('首次启动不自动生成凭据（pending=false）', first.status === 200 && first.json && first.json.pending === false && !first.json.token, JSON.stringify(first.json));

    const mk = await postJson(base1 + '/api/admin/credentials', { name: 'binary-gate', limits: { ratePerMin: 1200 } });
    const cred = mk.json && mk.json.token;
    jian('本机管理面可生成凭据', mk.status === 200 && !!cred && mk.json.name === 'binary-gate', JSON.stringify(mk.json));
    if (!cred) throw new Error('credential not created');

    const noAuth = await getJson(base1 + '/api/lookup?did=x');
    jian('业务面无凭据 ⇒ 401', noAuth.status === 401, String(noAuth.status));

    const A = ed(); A.box = x25519();
    const B = ed(); B.box = x25519();
    const auth = { authorization: 'Bearer ' + cred };

    const tsA = Date.now();
    const regA2 = await postJson(base1 + '/api/register', {
      did: A.pub, boxPub: A.box, ts: tsA, sig: sign(A.priv, `register|${A.pub}|${A.box}|${tsA}`),
    }, auth);
    const tsB = Date.now();
    const regB = await postJson(base1 + '/api/register', {
      did: B.pub, boxPub: B.box, ts: tsB, sig: sign(B.priv, `register|${B.pub}|${B.box}|${tsB}`),
    }, auth);
    jian('Ed25519 身份注册成功（A/B）', regA2.status === 200 && regA2.json?.ok === true && regB.status === 200 && regB.json?.ok === true, `${regA2.status}/${regB.status}`);

    const lookB = await getJson(base1 + '/api/lookup?did=' + encodeURIComponent(B.pub), auth);
    jian('在线查询：B 已上线', lookB.status === 200 && lookB.json?.online === true, JSON.stringify(lookB.json));

    const hbTs = Date.now();
    const hb = await postJson(base1 + '/api/heartbeat', { did: A.pub, ts: hbTs, sig: sign(A.priv, `heartbeat|${A.pub}|${hbTs}`) }, auth);
    jian('心跳签名通过', hb.status === 200 && hb.json?.ok === true, JSON.stringify(hb.json));

    const batch = await postJson(base1 + '/api/presence/batch', { dids: [A.pub, B.pub] }, auth);
    jian('批量在线：A/B 都在线', batch.status === 200 && batch.json?.presence?.[A.pub]?.online === true && batch.json?.presence?.[B.pub]?.online === true, JSON.stringify(batch.json));

    const msgId = 'binary-gate-' + Date.now() + '-' + crypto.randomBytes(3).toString('hex');
    const envelope = JSON.stringify({ ct: 'hello-binary', n: 1 });
    const relay = await postJson(base1 + '/api/relay', { to: B.pub, envelope, msgId }, auth);
    jian('A 发给 B：服务器入队成功', relay.status === 200 && relay.json?.ok === true, JSON.stringify(relay.json));

    const dup2 = await postJson(base1 + '/api/relay', { to: B.pub, envelope, msgId }, auth);
    jian('同一 messageId 第二次仍在允许窗口内（最多 2 次）', dup2.status === 200 && dup2.json?.ok === true, `${dup2.status} ${JSON.stringify(dup2.json)}`);
    const dup3 = await postJson(base1 + '/api/relay', { to: B.pub, envelope, msgId }, auth);
    jian('同一 messageId 第三次 ⇒ 409 duplicate-message', dup3.status === 409 && dup3.json?.error === 'duplicate-message', `${dup3.status} ${JSON.stringify(dup3.json)}`);

    const pollTs = Date.now();
    const poll = await getJson(base1 + '/api/poll?did=' + encodeURIComponent(B.pub) + '&ts=' + pollTs + '&sig=' + encodeURIComponent(sign(B.priv, `poll|${B.pub}|${pollTs}`)), auth);
    jian('B 轮询取到 2 个信封（前两次投递）且内容一致', poll.status === 200 && Array.isArray(poll.json?.envelopes) && poll.json.envelopes.length === 2 && poll.json.envelopes.every((x) => x === envelope), JSON.stringify(poll.json));

    const pollTs2 = Date.now();
    const poll2 = await getJson(base1 + '/api/poll?did=' + encodeURIComponent(B.pub) + '&ts=' + pollTs2 + '&sig=' + encodeURIComponent(sign(B.priv, `poll|${B.pub}|${pollTs2}`)), auth);
    jian('取走后不重复投递', poll2.status === 200 && poll2.json?.envelopes?.length === 0, JSON.stringify(poll2.json));

    const byeTs = Date.now();
    const bye = await postJson(base1 + '/api/bye', { did: A.pub, ts: byeTs, sig: sign(A.priv, `bye|${A.pub}|${byeTs}`) }, auth);
    const lookA = await getJson(base1 + '/api/lookup?did=' + encodeURIComponent(A.pub), auth);
    jian('bye 后 A 判离线', bye.status === 200 && lookA.json?.online === false, `${bye.status} ${JSON.stringify(lookA.json)}`);

    const tls = await getJson(base1 + '/api/admin/tls');
    const fp = tls.json?.tls?.fingerprint || '';
    jian('管理面给出 64 位证书指纹', /^[0-9a-f]{64}$/i.test(fp), fp);
    const tlsLook = await httpsGet(port1, '/api/lookup?did=' + encodeURIComponent(B.pub), auth);
    jian('同端口 TLS 握手可取业务数据', tlsLook.status === 200 && tlsLook.json?.online === true, `${tlsLook.status} ${JSON.stringify(tlsLook.json)}`);
    jian('TLS 对端证书指纹与公告一致（可固定）', tlsLook.fingerprint.toLowerCase() === fp.toLowerCase(), `${tlsLook.fingerprint} vs ${fp}`);

    const badHost = await rawStatus(port1, '/api/admin/stats', { host: 'evil.example' });
    jian('Host 非回环名 ⇒ 403（防 DNS rebinding）', badHost === 403, String(badHost));
    const cross = await fetch(base1 + '/api/admin/config', {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: 'https://evil.example' },
      body: JSON.stringify({ accepting: true }),
    });
    jian('跨站 Origin ⇒ 403', cross.status === 403, String(cross.status));
    const form = await fetch(base1 + '/api/admin/config', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: 'accepting=true',
    });
    jian('管理写操作必须是 JSON ⇒ 表单被挡', form.status === 403, String(form.status));

    const inb = await postJson(base1 + '/api/admin/expand-inbound', { name: 'binary-gate-inbound' });
    const inbToken = inb.json?.token;
    jian('可生成被扩网凭据（只显示一次）', inb.status === 200 && !!inbToken, JSON.stringify(inb.json));
    const ping = await getJson(base1 + '/api/expand/ping', { authorization: 'Bearer ' + inbToken });
    jian('扩网 ping 走真实凭据并返回实例信息', ping.status === 200 && ping.json?.ok === true && ping.json?.product === 'FWArmy' && ping.json?.version === VERSION, JSON.stringify(ping.json));

    const uv = await getJson(base1 + '/api/admin/update');
    jian('更新状态：单文件/当前版本/平台可读', uv.status === 200 && uv.json?.ok === true && uv.json.current === VERSION && uv.json.singleFile === true && !!uv.json.platform, JSON.stringify({ current: uv.json?.current, singleFile: uv.json?.singleFile, platform: uv.json?.platform }));
    const uc = await postJson(base1 + '/api/admin/update-config', { auto: 'check', intervalHours: 6 });
    jian('更新设置：auto/interval 可保存', uc.status === 200 && uc.json?.update?.auto === 'check' && uc.json?.update?.intervalHours === 6, JSON.stringify(uc.json?.update));
    jian('管理页带「更新」标签与容器', /data-tab=["']?update/.test(html) && /id=["']?updCards/.test(html));

    const table = spawnSync(BIN, ['table', `--data=${data1}`], { encoding: 'utf8', timeout: 30_000, windowsHide: true });
    jian('CLI table 能读出刚建的凭据', table.status === 0 && /binary-gate/.test(String(table.stdout)), `${table.status} ${table.stdout} ${table.stderr}`);

    const shut = await postJson(base1 + '/api/admin/shutdown', {});
    const code1 = await waitExit(srv1, 15_000);
    jian('管理面 shutdown ⇒ 进程正常退出', shut.status === 200 && code1 === 0, `${shut.status} code=${code1}`);
  } finally {
    await stopChild(srv1);
  }

  // ── 第二段：CLI stop ──
  const port2 = await freePort();
  const data2 = mkTmp('two');
  const srv2 = startServer(port2, data2);
  try {
    const h2 = await waitHealth(port2, srv2);
    jian('第二次启动仍正常', h2.ok === true && h2.server === 'fwarmy-relay', JSON.stringify(h2));
    const stop = spawnSync(BIN, ['stop', `--data=${data2}`], { encoding: 'utf8', timeout: 30_000, windowsHide: true });
    const code2 = await waitExit(srv2, 15_000);
    jian('CLI stop 能停掉进程', stop.status === 0 && (code2 === 0 || (process.platform === 'win32' && code2 === 1)), `${stop.status} code=${code2} ${stop.stdout} ${stop.stderr}`);
    let dead = false;
    try { await fetch(`http://127.0.0.1:${port2}/api/health`, { signal: AbortSignal.timeout(500) }); }
    catch { dead = true; }
    jian('停掉后端口不再服务', dead);
  } finally {
    await stopChild(srv2);
  }
} catch (e) {
  failN++;
  console.log('  FAIL 未捕获异常 ← ' + String(e && e.stack || e).slice(0, 500));
} finally {
  for (const d of tmpDirs) { try { fs.rmSync(d, { recursive: true, force: true }); } catch { /* noop */ } }
}

console.log(`\n==== verify-binary: ${okN} ok / ${failN} FAIL ====`);
process.exit(failN ? 1 : 0);
