/**
 * 构建单文件 FWArmy（Node SEA）。
 *
 * 用法（在 fwarmy/ 下）：
 *   node build-sea.mjs              # 构建到 dist/ 并做一次启动冒烟
 *   node build-sea.mjs --skip-smoke # 只构建
 *   node build-sea.mjs --out=目录    # 指定输出目录
 *
 * 为什么必须“在目标系统上构建”：
 *   SEA 的做法是把一段 blob 注入到**当前 Node 可执行文件**里，所以 Windows 上只能产出 .exe，
 *   macOS 上只能产出 Mach-O，Linux 上只能产出 ELF；没有可靠的跨平台交叉注入。
 *   本脚本在 win32/darwin/linux 上都能跑；macOS 会自动 ad-hoc 签名（codesign --sign -）。
 *
 * 构建期需要联网下载两个构建工具（运行期完全不需要）：
 *   esbuild（把 ESM 打成 CJS 单文件）+ postject（把 blob 注入 Node 可执行文件）。
 * 版本固定，避免“今天能构建、明天不能”。
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const BUILD = path.join(ROOT, '.build');
const OUT = path.resolve(ROOT, (process.argv.find((a) => a.startsWith('--out=')) || '').slice(6) || 'dist');
const SKIP_SMOKE = process.argv.includes('--skip-smoke');
const ESBUILD = 'esbuild@0.25.10';
const POSTJECT = 'postject@1.0.0-alpha.6';
const FUSE = 'NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2';
const EXE = process.platform === 'win32' ? 'FWArmy.exe' : 'FWArmy';

const NPX = process.platform === 'win32' ? 'npx.cmd' : 'npx';
function run(cmd, args, opts = {}) {
  // 只有 .cmd 需要 shell；node/codesign 直接用绝对路径 spawn，避免 "C:\Program Files" 被空格拆开
  const needShell = process.platform === 'win32' && /\.(cmd|bat)$/i.test(cmd);
  const r = spawnSync(cmd, args, { cwd: ROOT, stdio: 'inherit', shell: needShell, ...opts });
  if (r.error) throw r.error;
  if (r.status !== 0) throw new Error(`${cmd} ${args.join(' ')} 失败（退出码 ${r.status}）`);
}
function npx(pkg, args) {
  run(NPX, ['--yes', pkg, ...args]);
}
function sha256(file) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}
function freePort() {
  return new Promise((resolve) => {
    const net = require('node:net');
    const s = net.createServer();
    s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); });
  });
}
const require = (await import('node:module')).createRequire(import.meta.url);

fs.rmSync(BUILD, { recursive: true, force: true });
fs.mkdirSync(BUILD, { recursive: true });
fs.mkdirSync(OUT, { recursive: true });

console.log('[1/5] 打包 ESM → CJS（esbuild）');
npx(ESBUILD, ['sea-main.mjs', '--bundle', '--platform=node', '--format=cjs', '--target=node20', `--outfile=${path.join(BUILD, 'sea-main.cjs')}`, '--log-level=warning']);
if (!fs.existsSync(path.join(BUILD, 'sea-main.cjs'))) throw new Error('esbuild 没有产出 sea-main.cjs');

console.log('[2/5] 生成 SEA blob');
const seaConfig = {
  main: '.build/sea-main.cjs',
  mainFormat: 'commonjs',
  output: '.build/sea-prep.blob',
  disableExperimentalSEAWarning: true,
  useSnapshot: false,
  useCodeCache: false,
  assets: { 'admin.html': 'admin.html' },
};
fs.writeFileSync(path.join(BUILD, 'sea-config.json'), JSON.stringify(seaConfig, null, 2));
run(process.execPath, ['--experimental-sea-config', path.join(BUILD, 'sea-config.json')]);
const blobPath = path.join(ROOT, seaConfig.output);
if (!fs.existsSync(blobPath)) throw new Error('没有产出 sea-prep.blob');

console.log('[3/5] 复制 Node 可执行文件并注入 blob');
const outExe = path.join(OUT, EXE);
fs.rmSync(outExe, { force: true });
fs.copyFileSync(process.execPath, outExe);
if (process.platform === 'darwin') {
  try { run('codesign', ['--remove-signature', outExe]); } catch { /* 未签名时忽略 */ }
}
const postArgs = [outExe, 'NODE_SEA_BLOB', blobPath, '--sentinel-fuse', FUSE];
if (process.platform === 'darwin') postArgs.push('--macho-segment-name', 'NODE_SEA');
npx(POSTJECT, postArgs);
if (process.platform === 'darwin') run('codesign', ['--sign', '-', outExe]);
if (process.platform !== 'win32') fs.chmodSync(outExe, 0o755);

console.log('[4/5] 组装便携目录（启动脚本/说明）');
for (const f of ['admin.html', 'README.md', 'start.bat', 'start.sh', 'stop.bat', 'stop.sh', 'fwarmy-headless.bat', 'fwarmy-console.bat', 'fwarmy-headless.sh', 'fwarmy-console.sh']) {
  const src = path.join(ROOT, f);
  if (fs.existsSync(src)) {
    const dst = path.join(OUT, f);
    fs.copyFileSync(src, dst);
    if (process.platform !== 'win32' && f.endsWith('.sh')) fs.chmodSync(dst, 0o755);
  }
}
const info = [
  `${'FWArmy'} ${JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8')).version}`,
  `builtAt=${new Date().toISOString()}`,
  `node=${process.version}`,
  `platform=${process.platform}-${process.arch}`,
  `exe=${EXE}`,
  `size=${fs.statSync(outExe).size}`,
  `sha256=${sha256(outExe)}`,
].join('\n') + '\n';
fs.writeFileSync(path.join(OUT, 'BUILD-INFO.txt'), info, 'utf8');
console.log(info.trim());

if (!SKIP_SMOKE) {
  console.log('[5/5] 冒烟：--version + 启动/健康检查/关闭');
  const v = spawnSync(outExe, ['--version'], { encoding: 'utf8', windowsHide: true });
  if (v.status !== 0 || !/FWArmy/.test(String(v.stdout))) throw new Error('冒烟失败：--version 输出不对：' + String(v.stdout) + String(v.stderr));
  const port = await freePort();
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'fwarmy-sea-'));
  const child = (await import('node:child_process')).spawn(outExe, ['--server', '--port=' + port, '--host=127.0.0.1', '--data=' + tmp, '--no-open'], { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
  let exited = false;
  child.once('exit', () => { exited = true; });
  try {
    let h = null;
    for (let i = 0; i < 80 && !h && !exited; i++) {
      await new Promise((r) => setTimeout(r, 100));
      try { h = await (await fetch(`http://127.0.0.1:${port}/api/health`, { signal: AbortSignal.timeout(500) })).json(); } catch { /* retry */ }
    }
    if (!h || h.server !== 'fwarmy-relay') throw new Error('冒烟失败：单文件没有起来或健康检查不对');
    const page = await (await fetch(`http://127.0.0.1:${port}/`)).text();
    if (!/FWArmy/.test(page) || !/id="credTable"/.test(page)) throw new Error('冒烟失败：管理页没有正确内嵌');
    /** 第 65 轮用户口径：首次启动**不自动生成**凭据，由管理页手动生成 */
    const fr = await (await fetch(`http://127.0.0.1:${port}/api/admin/first-credential`)).json();
    if (!fr.ok || fr.pending !== false || fr.token) throw new Error('冒烟失败：首次启动不应自动生成凭据');
    const mk = await (await fetch(`http://127.0.0.1:${port}/api/admin/credentials`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ name: '冒烟凭据', limits: { ratePerMin: 120, dailyRequests: 10, totalBytes: 1048576 } }),
    })).json();
    if (!mk.ok || !mk.token || mk.credential?.limits?.dailyRequests !== 10 || mk.credential?.limits?.totalBytes !== 1048576) {
      throw new Error('冒烟失败：手动生成凭据/新限额字段不生效');
    }
    await fetch(`http://127.0.0.1:${port}/api/admin/shutdown`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
    for (let i = 0; i < 50 && !exited; i++) await new Promise((r) => setTimeout(r, 100));
  } finally {
    if (!exited) { try { child.kill(); } catch { /* noop */ } }
    fs.rmSync(tmp, { recursive: true, force: true });
  }
  console.log('冒烟通过：单文件启动、管理页、手动凭据（新限额字段）、关闭均正常');
}
if (!process.argv.includes('--keep-build')) { try { fs.rmSync(BUILD, { recursive: true, force: true }); } catch { /* noop */ } }
console.log(`完成：${outExe}`);
