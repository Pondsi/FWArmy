/**
 * 自动更新门禁（四平台同一套）：
 *   node verify-update.mjs dist/FWArmy.exe out/FWArmy-0.5.1-win-x64.zip
 *
 * 本地 mock 更新源，不访问 GitHub：
 *  · 检查更新能识别更高版本与平台产物
 *  · 错误 SHA256 ⇒ 安装失败且服务器继续运行
 *  · 正确 SHA256 ⇒ 下载/解压/校验/替换/重启，重启后版本与 lastInstall 正确
 *  · 更新设置 auto/interval 可保存
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import http from 'node:http';
import crypto from 'node:crypto';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const VERSION = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8')).version;
const BIN = path.resolve(process.argv[2] || path.join(ROOT, 'dist', process.platform === 'win32' ? 'FWArmy.exe' : 'FWArmy'));
const ARCHIVE = path.resolve(process.argv[3] || '');
const MOCK_VERSION = '9.9.9';
const isWin = process.platform === 'win32';
const platform = process.platform === 'win32' ? 'win-x64'
  : process.platform === 'darwin' ? 'macos-' + process.arch
    : 'linux-x64';

let okN = 0, failN = 0;
const jian = (label, pass, detail = '') => {
  if (pass) { okN++; console.log('  ok  ' + label); }
  else { failN++; console.log('  FAIL ' + label + (detail ? ' ← ' + String(detail).slice(0, 240) : '')); }
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const freePort = () => new Promise((resolve) => {
  const s = net.createServer();
  s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); });
});
const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest('hex');
const fileHash = (f) => sha256(fs.readFileSync(f));

async function getJson(url, init) {
  const r = await fetch(url, init);
  const text = await r.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* non-json */ }
  return { status: r.status, json, text };
}
const postJson = (url, body) => getJson(url, {
  method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
});

const tmpDirs = [];
const mkTmp = (tag) => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), `fwarmy-update-${tag}-`));
  tmpDirs.push(d);
  return d;
};
const data = mkTmp('data');
const archiveBuf = fs.readFileSync(ARCHIVE);
const archiveHash = sha256(archiveBuf);
const assetName = path.basename(ARCHIVE);
let mode = 'bad';
let mockPort = 0;
const mock = http.createServer((req, res) => {
  const u = new URL(req.url, `http://127.0.0.1:${mockPort}`);
  if (u.pathname === '/api/releases/latest') {
    const digest = mode === 'bad' ? '0'.repeat(64) : archiveHash;
    const body = JSON.stringify({
      tag_name: 'v' + MOCK_VERSION,
      name: 'FWArmy ' + MOCK_VERSION + ' update-gate',
      published_at: new Date().toISOString(),
      body: '自动更新门禁用的发布说明。',
      html_url: 'https://github.com/Pondsi/FWArmy/releases/tag/v' + MOCK_VERSION,
      assets: [
        {
          name: assetName,
          size: archiveBuf.length,
          browser_download_url: `http://127.0.0.1:${mockPort}/asset`,
          digest: 'sha256:' + digest,
        },
        { name: 'SHA256SUMS', size: 0, browser_download_url: `http://127.0.0.1:${mockPort}/SHA256SUMS`, digest: '' },
      ],
    });
    res.writeHead(200, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) });
    return res.end(body);
  }
  if (u.pathname === '/asset') {
    res.writeHead(200, { 'content-type': 'application/octet-stream', 'content-length': archiveBuf.length });
    return res.end(archiveBuf);
  }
  if (u.pathname === '/SHA256SUMS') {
    const body = archiveHash + '  ' + assetName + '\n';
    res.writeHead(200, { 'content-type': 'text/plain', 'content-length': Buffer.byteLength(body) });
    return res.end(body);
  }
  res.writeHead(404); res.end('not found');
});

await new Promise((resolve) => mock.listen(0, '127.0.0.1', () => { mockPort = mock.address().port; resolve(); }));
const port = await freePort();
const base = `http://127.0.0.1:${port}`;
let child = null;
let current = '';

function start() {
  child = spawn(BIN, ['--server', `--port=${port}`, '--host=127.0.0.1', `--data=${data}`, '--no-open'], {
    stdio: ['ignore', 'pipe', 'pipe'],
    windowsHide: true,
    env: { ...process.env, FWARMY_UPDATE_TEST: '1', FWARMY_UPDATE_API: `http://127.0.0.1:${mockPort}/api` },
  });
  child.__err = '';
  child.stderr.on('data', (b) => { child.__err += String(b); });
}
async function waitHealth(ms = 60_000) {
  const t0 = Date.now();
  while (Date.now() - t0 < ms) {
    try {
      const r = await fetch(base + '/api/health', { signal: AbortSignal.timeout(800) });
      if (r.ok) return await r.json();
    } catch { /* retry */ }
    await sleep(150);
  }
  return null;
}
async function waitExit(c, ms = 20_000) {
  if (!c || c.exitCode !== null) return c ? c.exitCode : null;
  return Promise.race([
    new Promise((r) => c.once('exit', (code) => r(code))),
    sleep(ms).then(() => null),
  ]);
}
async function stopCurrent() {
  try { await postJson(base + '/api/admin/shutdown', {}); } catch { /* noop */ }
  await waitExit(child, 10_000);
  if (child && child.exitCode === null) { try { child.kill(); } catch { /* noop */ } }
}

try {
  console.log(`FWArmy 自动更新门禁：${BIN}`);
  console.log(`平台 ${platform} · 归档 ${assetName} · 当前 ${VERSION} · mock 最新 ${MOCK_VERSION}`);
  jian('单文件与归档存在', fs.existsSync(BIN) && fs.existsSync(ARCHIVE));
  jian('mock 更新服务已启动', mockPort > 0);

  start();
  const h = await waitHealth();
  jian('服务器启动并健康', h && h.version === VERSION, JSON.stringify(h));
  const beforeHash = fileHash(BIN);

  let r = await postJson(base + '/api/admin/update-check', {});
  jian('检查更新：识别 mock 最新版本与本平台产物', r.status === 200 && r.json?.latest?.version === MOCK_VERSION && r.json?.latest?.asset?.name === assetName && r.json?.updateAvailable === true, JSON.stringify(r.json && { latest: r.json.latest && r.json.latest.version, asset: r.json.latest && r.json.latest.asset && r.json.latest.asset.name, available: r.json.updateAvailable }));

  r = await postJson(base + '/api/admin/update-install', { force: true });
  jian('错误 SHA256 ⇒ 安装被拒绝', r.status === 400 && /sha256-mismatch/.test(String(r.json?.error)), `${r.status} ${r.json?.error}`);
  const alive = await fetch(base + '/api/health', { signal: AbortSignal.timeout(1000) }).then((x) => x.ok).catch(() => false);
  jian('失败后服务器仍在运行', alive === true);

  mode = 'good';
  r = await postJson(base + '/api/admin/update-check', {});
  jian('复检成功（正确 SHA256）', r.status === 200 && r.json?.latest?.version === MOCK_VERSION, `${r.status}`);
  const oldChild = child;
  r = await postJson(base + '/api/admin/update-install', { force: true });
  jian('提交安装并返回 restarting', r.status === 200 && r.json?.restarting === true, `${r.status} ${JSON.stringify(r.json && { error: r.json.error, restarting: r.json.restarting })}`);
  const oldCode = await waitExit(oldChild, 90_000);
  jian('旧进程退出', oldCode === 0, 'code=' + oldCode);
  child = null;
  const h2 = await waitHealth(120_000);
  jian('新进程接管同一端口', !!h2 && h2.version === VERSION, JSON.stringify(h2));
  const afterHash = fs.existsSync(BIN) ? fileHash(BIN) : '';
  jian('二进制已被归档内容替换（哈希一致）', afterHash === beforeHash, `${afterHash.slice(0, 12)} vs ${beforeHash.slice(0, 12)}`);
  const uv = await getJson(base + '/api/admin/update');
  jian('更新记录：lastInstall 版本/成功', uv.status === 200 && uv.json?.lastInstall?.version === MOCK_VERSION && uv.json?.lastInstall?.ok === true, JSON.stringify(uv.json && uv.json.lastInstall));
  jian('重启后不再残留 .new', uv.status === 200 && uv.json?.staged === false, JSON.stringify(uv.json && { staged: uv.json.staged }));

  r = await postJson(base + '/api/admin/update-config', { auto: 'check', intervalHours: 12 });
  jian('更新设置 auto/interval 保存', r.status === 200 && r.json?.update?.auto === 'check' && r.json?.update?.intervalHours === 12, JSON.stringify(r.json?.update));
} catch (e) {
  failN++;
  console.log('  FAIL 未捕获异常 ← ' + String(e && e.stack || e).slice(0, 600));
  try {
    const log = fs.readFileSync(path.join(data, 'server.log'), 'utf8').split(/\r?\n/).slice(-15).join('\n');
    console.log('--- server.log tail ---\n' + log);
  } catch { /* noop */ }
} finally {
  await stopCurrent();
  try { mock.close(); } catch { /* noop */ }
  if (failN) {
    try {
      const log = fs.readFileSync(path.join(data, 'server.log'), 'utf8').split(/\r?\n/).slice(-30).join('\n');
      console.log('--- server.log tail ---\n' + log);
    } catch { /* noop */ }
  }
  for (const d of tmpDirs) { try { fs.rmSync(d, { recursive: true, force: true }); } catch { /* noop */ } }
}

console.log(`\n==== verify-update: ${okN} ok / ${failN} FAIL ====`);
process.exit(failN ? 1 : 0);
