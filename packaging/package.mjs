/**
 * 把 dist/ 组装成可发布的平台包：
 *   node packaging/package.mjs --platform=win-x64 --dist=dist --out=out
 *
 * 只收程序文件，绝不收 data/（凭据/统计/日志）。产出：
 *   out/FWArmy-<version>-<platform>/
 *   out/FWArmy-<version>-<platform>.zip | .tar.gz
 *   out/FWArmy-<version>-<platform>.zip.sha256 | .tar.gz.sha256
 */
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const arg = (name, def) => {
  const hit = process.argv.find((a) => a === '--' + name || a.startsWith('--' + name + '='));
  if (!hit) return def;
  return hit.includes('=') ? hit.slice(hit.indexOf('=') + 1) : true;
};
const PLATFORM = String(arg('platform', ''));
const DIST = path.resolve(ROOT, String(arg('dist', 'dist')));
const OUT = path.resolve(ROOT, String(arg('out', 'out')));
const VERSION = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8')).version;
const NAME = `FWArmy-${VERSION}-${PLATFORM}`;

if (!/^(win-x64|macos-x64|macos-arm64|linux-x64)$/.test(PLATFORM)) {
  console.error('用法：node packaging/package.mjs --platform=win-x64|macos-x64|macos-arm64|linux-x64');
  process.exit(2);
}
if (!fs.existsSync(DIST)) {
  console.error('dist 不存在：' + DIST);
  process.exit(2);
}

const common = ['README.md', 'install.sh', 'install.ps1', 'BUILD-INFO.txt'];
const byPlatform = {
  'win-x64': ['FWArmy.exe', 'start.bat', 'stop.bat', 'fwarmy-headless.bat', 'fwarmy-console.bat'],
  'macos-x64': ['FWArmy', 'FWArmy.command', 'start.sh', 'stop.sh', 'fwarmy-headless.sh', 'fwarmy-console.sh'],
  'macos-arm64': ['FWArmy', 'FWArmy.command', 'start.sh', 'stop.sh', 'fwarmy-headless.sh', 'fwarmy-console.sh'],
  'linux-x64': ['FWArmy', 'FWArmy.desktop', 'start.sh', 'stop.sh', 'fwarmy-headless.sh', 'fwarmy-console.sh'],
};
const files = [...common, ...byPlatform[PLATFORM]];

fs.mkdirSync(OUT, { recursive: true });
const stage = path.join(OUT, NAME);
fs.rmSync(stage, { recursive: true, force: true });
fs.mkdirSync(stage, { recursive: true });

for (const f of files) {
  const src = path.join(DIST, f);
  if (!fs.existsSync(src)) {
    console.error('缺少文件：' + src);
    process.exit(1);
  }
  fs.copyFileSync(src, path.join(stage, f));
}
const logo = path.join(DIST, 'assets', 'logo.svg');
if (!fs.existsSync(logo)) {
  console.error('缺少文件：' + logo);
  process.exit(1);
}
fs.mkdirSync(path.join(stage, 'assets'), { recursive: true });
fs.copyFileSync(logo, path.join(stage, 'assets', 'logo.svg'));

if (!PLATFORM.startsWith('win')) {
  fs.chmodSync(path.join(stage, 'FWArmy'), 0o755);
  for (const f of ['start.sh', 'stop.sh', 'fwarmy-headless.sh', 'fwarmy-console.sh', 'FWArmy.command', 'install.sh']) {
    const p = path.join(stage, f);
    if (fs.existsSync(p)) fs.chmodSync(p, 0o755);
  }
}

const isWin = PLATFORM.startsWith('win');
const archive = path.join(OUT, NAME + (isWin ? '.zip' : '.tar.gz'));
fs.rmSync(archive, { force: true });
let r;
if (isWin) {
  const cmd = `Compress-Archive -Path '${stage.replace(/'/g, "''")}' -DestinationPath '${archive.replace(/'/g, "''")}' -Force`;
  r = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', cmd], { stdio: 'inherit' });
} else {
  r = spawnSync('tar', ['-czf', archive, '-C', OUT, NAME], { stdio: 'inherit' });
}
if (r.error) throw r.error;
if (r.status !== 0) throw new Error('打包失败（退出码 ' + r.status + '）');

const hash = crypto.createHash('sha256').update(fs.readFileSync(archive)).digest('hex');
const size = fs.statSync(archive).size;
fs.writeFileSync(archive + '.sha256', `${hash}  ${path.basename(archive)}\n`, 'utf8');
console.log(JSON.stringify({ archive: path.basename(archive), size, sha256: hash }));
