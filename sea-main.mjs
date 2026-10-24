/**
 * 单文件入口（Node SEA）：
 *   FWArmy.exe                      → 启动服务器并打开管理页
 *   FWArmy.exe --no-open            → 启动服务器，不打开浏览器（headless/脚本）
 *   FWArmy.exe --server ...         → 强制以服务模式启动（ctl start 内部使用）
 *   FWArmy.exe table|status|stop... → 控制台命令（见 ctl.mjs）
 *
 * 注意：Node SEA 的 process.argv 在部分版本会把 exe 路径重复一次（argv[0]、argv[1] 都是 exe），
 * 所以用户参数统一从 argv.slice(2) 取。源码运行时由 server.mjs / ctl.mjs 自己判断入口。
 */
import path from 'node:path';
import { startServer } from './server.mjs';
import { runCli, CLI_COMMANDS } from './ctl.mjs';

/**
 * Node SEA 的 argv 形态在不同版本里不完全一样：24.x 是 [exe, exe, ...args]，
 * 旧版/未来版可能变成 [exe, ...args]。这里先去掉重复的 exe，再取用户参数。
 */
const rawArgs = process.argv.slice(1);
const args = (rawArgs[0] && path.resolve(rawArgs[0]) === path.resolve(process.execPath))
  ? rawArgs.slice(1)
  : rawArgs;
const first = String(args[0] || '').toLowerCase();
const isCli = CLI_COMMANDS.has(first) || first === '--version' || first === '-v' || first === '--help' || first === '-h';
const forceServer = args.includes('--server');

if (forceServer || !isCli) {
  const clean = args.filter((a) => a !== '--server');
  startServer({ argv: clean }).catch((e) => {
    console.error('FWArmy 启动失败：', (e && e.stack) || e);
    process.exit(1);
  });
} else {
  runCli(args).then((code) => process.exit(code));
}
