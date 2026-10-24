/**
 * FWArmy 控制台（源运行 `node ctl.mjs ...`，单文件 `FWArmy.exe ...` 同一套命令）。
 *
 *   start [--open] [--port=8787] [--host=0.0.0.0] [--data=目录]
 *   stop [--force] | status | open | table | console [--watch] [--show-token]
 *   cred-new <名称> [--rate=] [--bytes-rate=] [--daily=] [--monthly=] [--yearly=]  （用量单位 MB）
 *   cred-list | cred-update <id|哈希前缀> [--name=] [--rate=] [--daily=] [--disable|--enable]
 *   cred-disable <id> | cred-enable <id> | cred-revoke <id> | cred-delete <id> --yes
 *   cred-default [--show] | stats | ip | switch | version
 *
 * 说明：start 以**分离进程**跑 server.mjs（单文件时跑自己），PID 写 data/server.pid；
 * stop 先用 /api/health 确认端口上真的是 FWArmy，再杀这个 PID。管理面本机打开即用，无需管理密钥。
 * 日志不含消息明文/凭据明文；`cred-default` 是唯一会打印首次凭据明文的命令（需显式调用）。
 */
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import https from 'node:https';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { startServer, parseArgs, displayWidth, padCell, renderTable, VERSION, PRODUCT } from './server.mjs';

/** 源码是 ESM、SEA 里是 CJS；import.meta.url 在 CJS 下为空，createRequire 改用 __filename/argv 兜底。 */
const REQ_BASE = (() => {
  if (typeof __filename !== 'undefined' && __filename) return __filename;
  if (process.argv[1]) return path.resolve(process.argv[1]);
  return path.join(process.cwd(), 'fwarmy.js');
})();
const require = createRequire(REQ_BASE);
let SEA = null;
try { SEA = require('node:sea'); } catch { /* 源运行 */ }
const IS_SEA = !!(SEA && typeof SEA.isSea === 'function' && SEA.isSea());
const SELF_FILE = (() => { try { return fileURLToPath(import.meta.url); } catch { return ''; } })();
const HERE = SELF_FILE ? path.dirname(SELF_FILE) : (IS_SEA ? path.dirname(process.execPath) : process.cwd());
const APP_DIR = IS_SEA ? path.dirname(process.execPath) : HERE;

export const CLI_COMMANDS = new Set([
  'start', 'stop', 'status', 'open', 'table', 'console', 'cred-new', 'cred-list', 'cred-update',
  'cred-disable', 'cred-enable', 'cred-revoke', 'cred-delete', 'cred-default', 'stats', 'ip', 'switch', 'version', 'help',
]);

const flag = (argv, name, d = '') => {
  const hit = argv.find((x) => x === '--' + name || x.startsWith('--' + name + '='));
  if (!hit) return d;
  if (hit.includes('=')) return hit.split('=').slice(1).join('=');
  return true;
};
const has = (argv, name) => argv.some((x) => x === '--' + name || x.startsWith('--' + name + '='));
function dataDir(argv) {
  const d = flag(argv, 'data', '');
  if (d && d !== true) return path.resolve(String(d));
  const env = process.env.FWARMY_DATA || process.env.WARMY_RELAY_DATA;
  return env ? path.resolve(env) : path.join(APP_DIR, 'data');
}
function readInstance(dir) {
  try { return JSON.parse(fs.readFileSync(path.join(dir, 'instance.json'), 'utf8')); } catch { return null; }
}
function readPid(dir) {
  try { return Number(fs.readFileSync(path.join(dir, 'server.pid'), 'utf8')) || 0; } catch { return 0; }
}
function resolveBase(argv) {
  const p = Number(flag(argv, 'port', 0));
  if (p) return { port: p, base: `https://127.0.0.1:${p}` };
  const inst = readInstance(dataDir(argv));
  if (inst && inst.port) {
    const scheme = inst.scheme || (inst.tls && inst.tls.mode && inst.tls.mode !== 'off' ? 'https' : 'http');
    return { port: Number(inst.port), base: `${scheme}://127.0.0.1:${inst.port}` };
  }
  return { port: 8787, base: 'https://127.0.0.1:8787' };
}
/** 本机回环 HTTPS 用自签证书：只在本机管理面跳过链校验（业务面仍走指纹固定）。 */
function requestOnce(base, p, body, timeout = 4000) {
  return new Promise((resolve, reject) => {
    const u = new URL(base + p);
    const lib = u.protocol === 'https:' ? https : http;
    const payload = body === undefined ? '' : JSON.stringify(body);
    const req = lib.request({
      hostname: u.hostname, port: u.port, path: u.pathname + u.search,
      method: body === undefined ? 'GET' : 'POST',
      rejectUnauthorized: false, agent: false,
      headers: { ...(payload ? { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload) } : {}), connection: 'close' },
    }, (res) => {
      const bu = [];
      res.on('data', (d) => bu.push(d));
      res.on('end', () => {
        let j = null;
        try { j = JSON.parse(Buffer.concat(bu).toString('utf8')); } catch { /* noop */ }
        if (!j) return reject(new Error(`HTTP ${res.statusCode}（不是 JSON）`));
        resolve(j);
      });
    });
    req.setTimeout(timeout, () => req.destroy(new Error('timeout')));
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}
async function request(base, p, body) {
  try { return await requestOnce(base, p, body); }
  catch (e) {
    // 旧实例是纯 HTTP（或 TLS 关闭）：回退一次；连接失败时请求体尚未被处理，不会重复写。
    if (/^https:/.test(base)) return await requestOnce(base.replace(/^https:/, 'http:'), p, body);
    throw e;
  }
}
async function api(argv, p, body) {
  const { base } = resolveBase(argv);
  const j = await request(base, p, body);
  if (!j.ok) throw new Error(j.error || '请求失败');
  return j;
}
function openUrl(url) {
  const cmd = process.platform === 'win32' ? ['cmd', ['/c', 'start', '', url]]
    : process.platform === 'darwin' ? ['open', [url]] : ['xdg-open', [url]];
  try {
    spawn(cmd[0], cmd[1], { detached: true, stdio: 'ignore', windowsHide: true }).unref();
    console.log('已打开管理页：' + url);
  } catch { console.log('请手动打开：' + url); }
}
async function health(port, timeout = 1200) {
  for (const scheme of ['https', 'http']) {
    try {
      const j = await requestOnce(`${scheme}://127.0.0.1:${port}`, '/api/health', undefined, timeout);
      if (j && j.ok) return j;
    } catch { /* 换下一种 */ }
  }
  return null;
}
function localBase(port, h) {
  return `${h && h.secure ? 'https' : 'http'}://127.0.0.1:${port}`;
}
async function waitHealth(port, ms = 10000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    const h = await health(port);
    if (h && (h.server === 'fwarmy-relay' || h.server === 'warmy-relay')) return h;
    await new Promise((r) => setTimeout(r, 150));
  }
  return null;
}
function tailLog(dir, n = 12) {
  try {
    const f = path.join(dir, 'server.log');
    const st = fs.statSync(f);
    const start = Math.max(0, st.size - 64 * 1024);
    const fd = fs.openSync(f, 'r');
    const buf = Buffer.alloc(st.size - start);
    fs.readSync(fd, buf, 0, buf.length, start);
    fs.closeSync(fd);
    return buf.toString('utf8').split(/\r?\n/).filter(Boolean).slice(-n).join('\n');
  } catch { return ''; }
}
function serverArgs(argv) {
  const out = [];
  const port = flag(argv, 'port', '');
  const host = flag(argv, 'host', '');
  const data = flag(argv, 'data', '');
  const log = flag(argv, 'log-file', '');
  if (port && port !== true) out.push('--port=' + port);
  if (host && host !== true) out.push('--host=' + host);
  if (data && data !== true) out.push('--data=' + path.resolve(String(data)));
  if (log && log !== true) out.push('--log-file=' + path.resolve(String(log)));
  out.push('--no-open');
  return out;
}

function cmdStart(argv) {
  const dir = dataDir(argv);
  const inst = readInstance(dir);
  return (async () => {
    if (inst && inst.port) {
      const h = await health(Number(inst.port));
      if (h && (h.server === 'fwarmy-relay' || h.server === 'warmy-relay')) {
        console.log(`FWArmy 已在运行 pid=${inst.pid || '?'} port=${inst.port}`);
        const base = localBase(Number(inst.port), h);
        console.log(`管理页：${base}/（本机直接打开，无需密钥${h && h.secure ? '；自签证书需在浏览器确认一次' : ''}）`);
        if (has(argv, 'open')) openUrl(`${base}/`);
        return 0;
      }
    }
    const { port } = resolveBase(argv);
    const args = serverArgs(argv);
    const child = IS_SEA
      ? spawn(process.execPath, ['--server', ...args], { detached: true, stdio: 'ignore', windowsHide: true })
      : spawn(process.execPath, [path.join(HERE, 'server.mjs'), ...args], { detached: true, stdio: 'ignore', windowsHide: true });
    let exited = null;
    child.once('exit', (code) => { exited = code; });
    child.unref();
    try { fs.writeFileSync(path.join(dir, 'server.pid'), String(child.pid), { encoding: 'utf8', mode: 0o600 }); } catch { /* 服务自己也会写 */ }
    /** 端口被占用时服务会自动 +1；等 instance.json 出现或健康检查通过，别死等用户给的端口。 */
    let actualPort = 0;
    const end = Date.now() + 12000;
    while (Date.now() < end && !actualPort) {
      const cur = readInstance(dir);
      if (cur && Number(cur.pid) === child.pid && cur.port) {
        const h = await waitHealth(Number(cur.port), 1500);
        if (h) { actualPort = Number(cur.port); break; }
      }
      const h = await health(port, 500);
      if (h && (h.server === 'fwarmy-relay' || h.server === 'warmy-relay')) { actualPort = port; break; }
      await new Promise((r) => setTimeout(r, 200));
    }
    if (!actualPort) {
      console.error(`启动失败：没有等到 FWArmy 健康检查${exited === null ? '' : `（子进程退出码 ${exited}）`}`);
      const t = tailLog(dir);
      if (t) console.error('最近日志：\n' + t);
      return 1;
    }
    const h = await health(actualPort, 1500);
    const base = localBase(actualPort, h);
    console.log(`FWArmy 已启动 pid=${child.pid} port=${actualPort}`);
    console.log(`管理页：${base}/（本机直接打开，无需密钥${h && h.secure ? '；自签证书需在浏览器确认一次' : ''}）`);
    console.log(`数据目录：${dir}`);
    if (h && h.server !== 'fwarmy-relay') console.log('注意：健康检查返回的是旧版 warmy-relay 标识。');
    const fr = await request(base, '/api/admin/first-credential').catch(() => null);
    if (fr && fr.pending) console.log('首次凭据待保存：打开管理页查看；或在控制台执行 cred-default（会打印明文）。');
    if (has(argv, 'open')) openUrl(`${base}/`);
    return 0;
  })();
}

function cmdStop(argv) {
  return (async () => {
    const dir = dataDir(argv);
    const inst = readInstance(dir);
    const port = Number(flag(argv, 'port', inst && inst.port ? inst.port : 0)) || 8787;
    const pid = Number(inst && inst.pid) || readPid(dir);
    const h = await health(port);
    const shiWoMen = !!(h && (h.server === 'fwarmy-relay' || h.server === 'warmy-relay'));
    if (!pid) {
      console.log(shiWoMen ? `端口 ${port} 上有 FWArmy，但没有 PID 文件；为安全起见不杀未知进程。` : '没有发现运行中的 FWArmy。');
      return 0;
    }
    if (!shiWoMen && !has(argv, 'force')) {
      console.log(`拒绝停止：PID ${pid} 对应的端口 ${port} 没有回应 FWArmy 健康检查（可能是失效 PID 或被复用）。`);
      console.log('确认这是挂死的旧服务、仍要强杀时：FWArmy stop --force');
      return 1;
    }
    try { process.kill(pid, 'SIGTERM'); } catch (e) { console.log('发送停止信号失败：' + String(e).slice(0, 120)); }
    for (let i = 0; i < 50; i++) {
      const still = await health(port, 300);
      if (!still) break;
      await new Promise((r) => setTimeout(r, 150));
    }
    const still = await health(port, 300);
    if (still && has(argv, 'force')) {
      try { process.kill(pid, 'SIGKILL'); } catch { /* noop */ }
      await new Promise((r) => setTimeout(r, 300));
    }
    try { fs.rmSync(path.join(dir, 'server.pid'), { force: true }); } catch { /* noop */ }
    try { fs.rmSync(path.join(dir, 'instance.json'), { force: true }); } catch { /* noop */ }
    console.log((await health(port, 300)) ? `已发送停止信号 pid=${pid}，但端口仍有响应；请查看 data/server.log。` : `已停止 pid=${pid}`);
    return 0;
  })();
}

const fmtB = (n) => {
  n = Number(n) || 0;
  if (n < 1024) return n + ' B';
  const u = ['KB', 'MB', 'GB', 'TB'];
  let i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
  return n.toFixed(n >= 100 ? 0 : n >= 10 ? 1 : 2) + ' ' + u[i];
};
const fmtN = (n) => Number(n || 0).toLocaleString('en-US');
const fmtDur = (sec) => {
  sec = Math.max(0, Math.floor(Number(sec) || 0));
  const d = Math.floor(sec / 86400), h = Math.floor((sec % 86400) / 3600), m = Math.floor((sec % 3600) / 60), s = sec % 60;
  return d ? `${d}d ${h}h` : h ? `${h}h ${m}m` : m ? `${m}m ${s}s` : `${s}s`;
};
const fmtT = (ms) => {
  if (!ms) return '-';
  const d = new Date(Number(ms));
  if (Number.isNaN(d.getTime())) return '-';
  const p = (x) => String(x).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
};
const limText = (c) => {
  const e = c.effective, l = c.limits;
  const f = (k, unit) => (l[k] === null || l[k] === undefined ? '继承' : e[k] ? `${fmtN(e[k])}${unit}` : '不限');
  const rate = f('ratePerMin', '/m');
  const bytes = f('bytesPerMin', '/m');
  return `${rate} ${bytes} ${f('dailyBytes', '/d')} ${f('monthlyBytes', '/mo')} ${f('yearlyBytes', '/y')}`;
};
function useCell(b) { return `${fmtN(b.requests)} 次 / ${fmtB(b.bytes)}`; }

function tableText(S) {
  const t = S.totals;
  const out = [];
  out.push(`${PRODUCT} ${S.version} · 中转服务器状态`);
  out.push(renderTable(['项目', '值'], [
    ['运行时长', fmtDur(S.uptimeSec)],
    ['接客', S.accepting ? '开' : '关'],
    ['在线 / 队列', `${S.users} / ${S.queued}`],
    ['当前速度（60s）', `${S.totals.speed.reqPerMin} 次/分 · ${fmtB(S.totals.speed.bytesPerMin)}/分`],
    ['峰值（每分钟）', `${S.totals.peakPerMin} 次 · ${fmtT(S.totals.peakAt)}`],
    ['今日 / 本月 / 今年', `${fmtN(t.today.requests)} 次 / ${fmtN(t.month.requests)} 次 / ${fmtN(t.year.requests)} 次`],
    ['累计请求 / 流量', `${fmtN(t.requests)} 次 / ${fmtB(t.bytes)}`],
    ['未授权尝试', String(S.unauthorized)],
    ['数据目录', S.dataDir || '-'],
  ]));
  out.push('');
  out.push('凭据用量（日 / 月 / 年）');
  out.push(renderTable(
    ['名称', '状态', '今日', '本月', '今年', '累计', '峰值/分', '最近使用'],
    S.perCredential.map((c) => [c.name, c.disabled ? '停用' : '有效', useCell(c.today), useCell(c.month), useCell(c.year), useCell(c.total), String(c.peakPerMin), fmtT(c.lastUsed)]),
    ['left', 'left', 'right', 'right', 'right', 'right', 'right', 'left'],
  ));
  out.push('');
  out.push('凭据限额（继承 = 跟随全局；不限 = 0）');
  out.push(renderTable(
    ['名称', '限速', '流量速度', '日', '月', '年'],
    S.perCredential.map((c) => {
      const e = c.effective, l = c.limits;
      const g = (k) => (l[k] === null || l[k] === undefined ? '继承' : e[k] ? fmtB(e[k]) : '不限');
      return [c.name, l.ratePerMin === null ? '继承' : (e.ratePerMin ? `${fmtN(e.ratePerMin)}/m` : '不限'), fmtB(e.bytesPerMin) + '/m', g('dailyBytes'), g('monthlyBytes'), g('yearlyBytes')];
    }),
    ['left', 'right', 'right', 'right', 'right', 'right'],
  ));
  return out.join('\n');
}

function cmdTable(argv) {
  return (async () => {
    const S = await api(argv, '/api/admin/stats');
    console.log(tableText(S));
    return 0;
  })();
}

async function cmdConsole(argv) {
  const watch = has(argv, 'watch');
  const once = async () => {
    const S = await api(argv, '/api/admin/stats');
    // 旧版 cmd.exe 不认 ANSI 清屏；Windows Terminal / Unix 终端才清，避免满屏 ←[2J
    const canClear = process.stdout.isTTY && (process.platform !== 'win32' || process.env.WT_SESSION || process.env.TERM_PROGRAM);
    if (watch && canClear) process.stdout.write('\x1b[2J\x1b[H');
    console.log(tableText(S));
    if (has(argv, 'show-token')) {
      const fr = await api(argv, '/api/admin/first-credential');
      if (fr.pending) console.log(`\n首次凭据（明文，只在本机显示）：\n${fr.token}\n`);
    } else if (S.firstRunPending) {
      console.log('\n首次凭据待保存：打开管理页查看，或运行 `FWArmy cred-default` 显示明文。');
    }
    console.log(`\n${new Date().toLocaleString()}  ·  按 Ctrl+C 退出${watch ? '（每 2 秒刷新）' : ''}`);
  };
  await once();
  if (!watch) return 0;
  await new Promise(() => setInterval(() => once().catch((e) => console.error('刷新失败：' + e.message)), 2000));
  return 0;
}

function limitBody(argv) {
  const body = {};
  const rate = flag(argv, 'rate', undefined);
  const br = flag(argv, 'bytes-rate', undefined);
  const d = flag(argv, 'daily', undefined);
  const m = flag(argv, 'monthly', undefined);
  const y = flag(argv, 'yearly', undefined);
  const toBytes = (v) => {
    if (v === undefined || v === '' || v === true) return undefined;
    const n = Number(v);
    if (!Number.isFinite(n) || n < 0) throw new Error('用量必须是 ≥0 的数字（单位 MB）');
    return n === 0 ? 0 : Math.round(n * 1048576);
  };
  if (rate !== undefined && rate !== '' && rate !== true) body.ratePerMin = Math.round(Number(rate));
  const b = toBytes(br); if (b !== undefined) body.bytesPerMin = b;
  const dd = toBytes(d); if (dd !== undefined) body.dailyBytes = dd;
  const mm = toBytes(m); if (mm !== undefined) body.monthlyBytes = mm;
  const yy = toBytes(y); if (yy !== undefined) body.yearlyBytes = yy;
  for (const k of Object.keys(body)) if (!Number.isFinite(body[k]) || body[k] < 0) throw new Error('限额必须是 ≥0 的数字：' + k);
  return body;
}

async function resolveCred(argv, key) {
  const j = await api(argv, '/api/admin/credentials');
  const hit = (j.items || []).find((c) => c.id === key || c.hash8 === key);
  if (!hit) throw new Error('找不到凭据：' + key);
  return hit;
}

async function runCredCommand(cmd, argv) {
  if (cmd === 'cred-new') {
    const name = String(argv[1] || '').trim();
    if (!name) throw new Error('用法：cred-new <名称> [--rate=] [--daily=] ...');
    const limits = limitBody(argv);
    const r = await api(argv, '/api/admin/credentials', { name, limits });
    console.log(`凭据「${r.name}」已生成（明文只显示这一次）：\n${r.token}`);
    return 0;
  }
  if (cmd === 'cred-list') {
    const S = await api(argv, '/api/admin/stats');
    console.log(renderTable(
      ['名称', '状态', '今日', '本月', '今年', '累计', '限额'],
      S.perCredential.map((c) => [c.name, c.disabled ? '停用' : '有效', useCell(c.today), useCell(c.month), useCell(c.year), useCell(c.total), limText(c)]),
      ['left', 'left', 'right', 'right', 'right', 'right', 'left'],
    ));
    return 0;
  }
  if (cmd === 'cred-update') {
    const key = String(argv[1] || '');
    if (!key) throw new Error('用法：cred-update <id|哈希前缀> [--name=] [--rate=] [--daily=] [--disable|--enable]');
    const c = await resolveCred(argv, key);
    const body = { id: c.id };
    const name = flag(argv, 'name', undefined);
    if (name !== undefined && name !== '' && name !== true) body.name = String(name);
    if (has(argv, 'disable')) body.disabled = true;
    if (has(argv, 'enable')) body.disabled = false;
    const lim = limitBody(argv);
    if (Object.keys(lim).length) body.limits = lim;
    const r = await api(argv, '/api/admin/credential-update', body);
    console.log(`已更新「${r.credential.name}」：${r.credential.disabled ? '停用' : '有效'}`);
    return 0;
  }
  if (cmd === 'cred-disable' || cmd === 'cred-enable' || cmd === 'cred-revoke') {
    const key = String(argv[1] || '');
    if (!key) throw new Error(`用法：${cmd} <id|哈希前缀>`);
    const c = await resolveCred(argv, key);
    const r = await api(argv, '/api/admin/credential-update', { id: c.id, disabled: cmd !== 'cred-enable' });
    console.log(`「${r.credential.name}」已${r.credential.disabled ? '停用' : '启用'}`);
    return 0;
  }
  if (cmd === 'cred-delete') {
    const key = String(argv[1] || '');
    if (!key) throw new Error('用法：cred-delete <id|哈希前缀> --yes');
    if (!has(argv, 'yes')) {
      const c = await resolveCred(argv, key);
      console.log(`将永久删除「${c.name}」。确认请再执行：cred-delete ${key} --yes`);
      return 1;
    }
    const c = await resolveCred(argv, key);
    await api(argv, '/api/admin/credential-delete', { id: c.id, confirmName: c.name });
    console.log(`已删除「${c.name}」`);
    return 0;
  }
  if (cmd === 'cred-default') {
    const fr = await api(argv, '/api/admin/first-credential');
    if (!fr.pending) { console.log('没有待保存的首次凭据（可能已确认或已删除）。'); return 0; }
    console.log(`首次凭据（明文，只在本机显示）：\n${fr.token}\n\n保存后请打开管理页点“我已保存”，或运行 cred-default --yes 删除明文文件。`);
    if (has(argv, 'yes')) {
      await api(argv, '/api/admin/first-credential-ack', {});
      console.log('已删除本机明文引导文件。');
    }
    return 0;
  }
  return -1;
}

export async function runCli(argv) {
  const cmd = String(argv[0] || '').toLowerCase();
  try {
    if (!cmd || cmd === 'help' || cmd === '-h' || cmd === '--help') {
      console.log(`FWArmy ${VERSION} · 中转服务器控制台\n` +
        '用法：FWArmy <命令> [参数]\n' +
        '  start [--open] [--port=8787] [--host=0.0.0.0]   启动（分离进程，写 data/server.log）\n' +
        '  stop [--force] | status | open | table | console [--watch] [--show-token]\n' +
        '  cred-new <名称> [--rate=] [--bytes-rate=] [--daily=] [--monthly=] [--yearly=]（用量单位 MB）\n' +
        '  cred-list | cred-update <id|哈希前缀> [--name=] [--rate=] [--daily=] [--disable|--enable]\n' +
        '  cred-disable <id> | cred-enable <id> | cred-delete <id> --yes | cred-default\n' +
        '  stats | ip | switch | version\n' +
        '\n数据目录：--data=<目录> 或环境变量 FWARMY_DATA（兼容旧名 WARMY_RELAY_DATA），默认是程序旁的 data/。');
      return 0;
    }
    if (cmd === 'version' || cmd === '--version' || cmd === '-v') { console.log(`${PRODUCT} ${VERSION}`); return 0; }
    if (cmd === 'start') return await cmdStart(argv);
    if (cmd === 'stop') return await cmdStop(argv);
    if (cmd === 'open') {
      const { port } = resolveBase(argv);
      const h = await health(port);
      openUrl(localBase(port, h) + '/');
      return 0;
    }
    if (cmd === 'status') {
      const j = await api(argv, '/api/admin/stats');
      console.log(JSON.stringify(j, null, 2));
      return 0;
    }
    if (cmd === 'table') return await cmdTable(argv);
    if (cmd === 'console') return await cmdConsole(argv);
    if (cmd.startsWith('cred-')) return await runCredCommand(cmd, argv);
    if (cmd === 'stats') {
      console.log(JSON.stringify(await api(argv, '/api/admin/stats'), null, 2));
      return 0;
    }
    if (cmd === 'ip') {
      console.log(JSON.stringify(await api(argv, '/api/admin/public-ip', {}), null, 2));
      return 0;
    }
    if (cmd === 'switch') {
      const st = await api(argv, '/api/admin/stats');
      const r = await api(argv, '/api/admin/config', { accepting: !st.accepting });
      console.log(`接客已${r.config.accepting ? '打开' : '暂停'}`);
      return 0;
    }
    console.error('未知命令：' + cmd + '（运行 FWArmy help 查看用法）');
    return 1;
  } catch (e) {
    console.error('错误：' + String(e && e.message || e));
    return 1;
  }
}

/** 供单文件入口判断：没有参数时启动服务，不当作 CLI。 */
export async function runServerFromCli(argv = []) {
  const r = await startServer({ argv });
  return r;
}

const isMain = !IS_SEA && !!SELF_FILE && !!process.argv[1] && path.resolve(process.argv[1]) === path.resolve(SELF_FILE);
if (isMain) {
  runCli(process.argv.slice(2)).then((code) => process.exit(code));
}
