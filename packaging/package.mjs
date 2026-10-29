/**
 * 把 dist/ 组装成可发布的平台包：
 *   node packaging/package.mjs --platform=win-x64 --dist=dist --out=out
 *
 * 只收程序文件与文档，绝不收 data/（凭据/统计/日志/secret.key）。产出：
 *   out/FWArmy-<version>-<platform>/
 *   out/FWArmy-<version>-<platform>.zip | .tar.gz
 *   out/FWArmy-<version>-<platform>.zip.sha256 | .tar.gz.sha256
 *   out/SHA256SUMS   （每种平台产物一行：<sha256>  <文件名>）
 *
 * 打包前强制校验（任何不一致直接报错退出，防止旧 dist 冒充新版本包）：
 *   package.json.version == dist/BUILD-INFO.txt 版本 == 二进制 --version
 *   dist/BUILD-INFO.txt 的 sha256 == 当前二进制实际哈希
 * 并从最终二进制重新生成/校验 BUILD-INFO（staging 内写入准确副本）。
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

const EXE = PLATFORM.startsWith('win') ? 'FWArmy.exe' : 'FWArmy';
const BIN = path.join(DIST, EXE);

const die = (msg) => {
  console.error('打包拒绝：' + msg);
  process.exit(1);
};

const sha256File = (file) => crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');

// ── 干净 staging：dist/data、server.log、secret.key 一律禁止 ──────────────
if (fs.existsSync(path.join(DIST, 'data'))) {
  die(`发现 ${path.join(DIST, 'data')}（运行时数据）。打包禁止携带 data/；请先删除 dist/data 再打包。`);
}
for (const forbidden of ['server.log', 'secret.key', 'credentials.json', 'config.json', 'stats.json', 'expand.json', 'security.json']) {
  if (fs.existsSync(path.join(DIST, forbidden))) {
    die(`发现禁止打包的文件：${path.join(DIST, forbidden)}`);
  }
}

// ── 强制校验版本 / BUILD-INFO / 二进制哈希 ─────────────────────────────
if (!fs.existsSync(BIN)) die('缺少二进制：' + BIN);
const binHash = sha256File(BIN);

const buildInfoPath = path.join(DIST, 'BUILD-INFO.txt');
if (!fs.existsSync(buildInfoPath)) die('缺少 BUILD-INFO.txt（应由 build-sea.mjs 生成）：' + buildInfoPath);
const buildInfoRaw = fs.readFileSync(buildInfoPath, 'utf8');
const infoLines = buildInfoRaw.split(/\r?\n/).filter((l) => l.trim() && !l.startsWith('#'));
const infoMap = {};
let infoVersion = '';
for (const line of infoLines) {
  const m = /^([A-Za-z0-9_]+)=(.*)$/.exec(line.trim());
  if (m) infoMap[m[1]] = m[2].trim();
  else if (/^FWArmy\s+/.test(line.trim())) infoVersion = line.trim().replace(/^FWArmy\s+/, '').trim();
}
if (!infoVersion) die('BUILD-INFO.txt 缺少首行版本（FWArmy <version>）');
if (infoVersion !== VERSION) {
  die(`版本不一致：package.json=${VERSION}，BUILD-INFO.txt=${infoVersion}。请重新运行 node build-sea.mjs（它会更新 BUILD-INFO）。`);
}
const infoHash = String(infoMap.sha256 || '').toLowerCase();
if (!infoHash) die('BUILD-INFO.txt 缺少 sha256=');
if (infoHash !== binHash) {
  die(`BUILD-INFO 的 sha256 与当前二进制不符：BUILD-INFO=${infoHash}，实际=${binHash}。旧 dist 不能冒充新版本包；请重新运行 node build-sea.mjs。`);
}

// 二进制 --version 必须可执行且版本一致（打包必须在目标平台上做）
const ver = spawnSync(BIN, ['--version'], { encoding: 'utf8', windowsHide: true, timeout: 30000 });
if (ver.error) die('无法执行二进制 --version：' + String(ver.error.message || ver.error));
const verText = String(ver.stdout || '') + String(ver.stderr || '');
if (ver.status !== 0) die(`二进制 --version 退出码 ${ver.status}：${verText.trim()}`);
if (!verText.includes(VERSION)) {
  die(`二进制 --version 输出不含版本 ${VERSION}：${verText.trim()}`);
}

console.log(JSON.stringify({
  ok: true,
  version: VERSION,
  platform: PLATFORM,
  binary: EXE,
  sha256: binHash,
  buildInfo: 'consistent',
}));

// ── 组装白名单 ────────────────────────────────────────────────────────
const common = [
  'README.md',
  'install.sh',
  'install.ps1',
  'BUILD-INFO.txt',
];
const docs = [
  'docs/INSTALL-3-PLATFORMS.md',
  'docs/USAGE-3-PLATFORMS.md',
  'docs/SERVER-RELAY.md',
];
const byPlatform = {
  'win-x64': ['FWArmy.exe', 'start.bat', 'stop.bat', 'fwarmy-headless.bat', 'fwarmy-console.bat'],
  'macos-x64': ['FWArmy', 'FWArmy.command', 'start.sh', 'stop.sh', 'fwarmy-headless.sh', 'fwarmy-console.sh'],
  'macos-arm64': ['FWArmy', 'FWArmy.command', 'start.sh', 'stop.sh', 'fwarmy-headless.sh', 'fwarmy-console.sh'],
  'linux-x64': ['FWArmy', 'FWArmy.desktop', 'start.sh', 'stop.sh', 'fwarmy-headless.sh', 'fwarmy-console.sh'],
};
const required = [...common, ...byPlatform[PLATFORM]];
const optional = [...docs]; // 文档随发行树而定：完整树有 docs/，精简源码树没有——缺省跳过而不是失败
const files = [...required, ...optional];

// 打包禁止携带的路径片段（staging 后再断言一次）
const FORBIDDEN_NAME = /(^|[/\\])(data|server\.log|secret\.key|credentials\.json)$/i;

fs.mkdirSync(OUT, { recursive: true });
const stage = path.join(OUT, NAME);
fs.rmSync(stage, { recursive: true, force: true });
fs.mkdirSync(stage, { recursive: true });

for (const f of files) {
  const src = path.join(DIST, f);
  if (!fs.existsSync(src)) {
    if (optional.includes(f)) { console.warn('跳过缺失的可选文档：' + f); continue; }
    console.error('缺少文件：' + src);
    process.exit(1);
  }
  const dst = path.join(stage, f);
  fs.mkdirSync(path.dirname(dst), { recursive: true });
  fs.copyFileSync(src, dst);
}
const logo = path.join(DIST, 'assets', 'logo.svg');
if (!fs.existsSync(logo)) {
  console.error('缺少文件：' + logo);
  process.exit(1);
}
fs.mkdirSync(path.join(stage, 'assets'), { recursive: true });
fs.copyFileSync(logo, path.join(stage, 'assets', 'logo.svg'));

// 从最终二进制重新写一份准确的 BUILD-INFO（staging 内；数值与二进制一致）
const rebuiltInfo = [
  `# BUILD-INFO 由 build-sea.mjs 生成/更新；packaging/package.mjs 打包前强制校验并在此重写。`,
  `# 版本必须等于 package.json 与二进制 --version；sha256 必须等于二进制实际哈希。`,
  `FWArmy ${VERSION}`,
  `builtAt=${infoMap.builtAt || new Date().toISOString()}`,
  `node=${infoMap.node || process.version}`,
  `platform=${infoMap.platform || `${process.platform}-${process.arch}`}`,
  `exe=${EXE}`,
  `size=${fs.statSync(BIN).size}`,
  `sha256=${binHash}`,
].join('\n') + '\n';
fs.writeFileSync(path.join(stage, 'BUILD-INFO.txt'), rebuiltInfo, 'utf8');

// staging 干净断言：不得出现 data/、server.log、secret.key 等
(function assertClean(dir) {
  for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, ent.name);
    const rel = path.relative(stage, p);
    if (FORBIDDEN_NAME.test(rel) || FORBIDDEN_NAME.test(ent.name)) {
      die('staging 中出现禁止打包的路径：' + rel);
    }
    if (ent.isDirectory()) assertClean(p);
  }
})(stage);

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

const hash = sha256File(archive);
const size = fs.statSync(archive).size;
const base = path.basename(archive);
fs.writeFileSync(archive + '.sha256', `${hash}  ${base}\n`, 'utf8');

// SHA256SUMS：与最终包一致，每种平台产物一行 <sha256>  <文件名>
const sumsPath = path.join(OUT, 'SHA256SUMS');
let sums = new Map();
if (fs.existsSync(sumsPath)) {
  for (const line of fs.readFileSync(sumsPath, 'utf8').split(/\r?\n/)) {
    const m = /^([0-9a-fA-F]{64})\s\s(\S+)$/.exec(line.trim());
    if (m) sums.set(m[2], m[1].toLowerCase());
  }
}
sums.set(base, hash);
const body = [...sums.entries()].map(([name, h]) => `${h}  ${name}`).join('\n') + '\n';
fs.writeFileSync(sumsPath, body, 'utf8');

console.log(JSON.stringify({ archive: base, size, sha256: hash, sha256sums: path.basename(sumsPath) }));
