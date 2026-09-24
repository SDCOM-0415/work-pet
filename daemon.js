#!/usr/bin/env node
'use strict';
/**
 * TraeWork 签到宠物 daemon
 *
 * 为 TraeWork 提供 CDP 注入与签到机制，只保留三个能力：
 *
 * 注意：客户端安装目录会改名（TRAE SOLO CN → TraeWork CN），因此本文件一律不写死
 * 品牌名做路径/进程匹配，统一按 TRAEWORK_NAME_RE「含 trae 且含 solo/work」动态探测
 * （见 findTraeExecutable / findTraeDataDir / TRAE_PROCESS_ERE）。
 * 普通版 Trae（Trae CN / Trae）是另一个产品，不在适配范围内，需排除。
 *   1) 桌面宠物机器人   —— 注入到 TraeWork 窗口内的 SVG 动画宠物
 *   2) 每日签到         —— 调用官方 checkin_credits/status + claim 接口
 *   3) 签到过期显示     —— 距下次签到倒计时 + 本次/累计积分与到期信息
 *
 * 职责：
 *   - 解密 storage.json 里的登录态（还原自 main.js 的 smart-secret AES）
 *   - 拉起 / 复用带 --remote-debugging-port 的 TraeWork，经 CDP 注入 inject.js
 *   - 本地 HTTP API 供注入的宠物面板调用（签到状态、签到、健康检查）
 *   - watchdog：CDP 掉线自动重连、页面重载自动补种
 */
const fs = require('fs');
const path = require('path');
const os = require('os');
const http = require('http');
const crypto = require('crypto');
const { spawn, execFileSync } = require('child_process');

const isMac = process.platform === 'darwin';

const APP_BRAND = 'TraeWork';
const DAEMON_VERSION = '1.0.5';
const APP_VERSION = DAEMON_VERSION;
const HOST = '127.0.0.1';

// 自身脚本指纹：进程启动时读一次并缓存，随 /api/health 上报，供桌面端判断
// 「47921 端口上那个常驻进程，是不是本安装包里的这份 daemon.js」。
//
// 为什么需要它：桌面端原本只比对版本号（DAEMON_VERSION vs app 版本），但同一版本号
// 重新构建（本地修 bug 重打包、版本号没 bump）时版本号是一致的，于是旧常驻进程会被
// 判定为「本包的」而一直被复用 —— 表现为换了 node 和 daemon.js，跑的还是旧逻辑
// （例如内置 Node 已升 24，进程里却仍是 Node 20，CDP 全部失效）。
//
// 必须「启动时」读取并缓存：进程跑起来之后安装包可能已把 daemon.js 覆盖，
// 那时再 statSync 拿到的是新文件，无法反映本进程实际加载的版本。
const SELF_FINGERPRINT = (() => {
  try {
    const st = fs.statSync(__filename);
    // 只用「字节数 + 整秒 mtime」，避免浮点毫秒在 JS/Rust 两侧的取整差异
    return `${st.size}-${Math.floor(st.mtimeMs / 1000)}`;
  } catch (_) { return ''; }
})();

// 语义化版本比较：a>b 返回正数，a<b 返回负数，相等返回 0（支持 v 前缀；
// 预发布后缀按 semver 规则处理：同为 1.0.3 时 1.0.3 > 1.0.3-beta.3，正式版发布后测试版能收到更新提示）
function compareSemver(a, b) {
  const norm = (s) => {
    const m = String(s).trim().replace(/^v/i, '').split('-');
    return { core: (m[0] || '').split('.').map(n => parseInt(n, 10) || 0), pre: m.slice(1).join('-') || null };
  };
  const A = norm(a), B = norm(b);
  for (let i = 0; i < 3; i++) {
    const d = (A.core[i] || 0) - (B.core[i] || 0);
    if (d) return d;
  }
  if (A.pre && !B.pre) return -1;
  if (!A.pre && B.pre) return 1;
  return 0;
}

// ---------------- WorkBuddy / CodeBuddy / AutoClaw Token 用量统计（扫描本机会话日志，数据不出本机） ----------------
// 数据源：~/.workbuddy/projects、~/.codebuddy/projects 下的 **/*.jsonl（providerData.rawUsage/usage），
// ~/.openclaw-autoclaw/agents 下的 */sessions/*.jsonl（message.usage，文件名即 sessionId），均为请求级真实 usage
const CLIENT_USAGE_DIRS = {
  wb: path.join(os.homedir(), '.workbuddy', 'projects'),
  cb: path.join(os.homedir(), '.codebuddy', 'projects'),
  ac: path.join(os.homedir(), '.openclaw-autoclaw', 'agents'),
};
const clientUsageCaches = {}; // kind -> { at, data }（各端独立 60s 缓存）

function wbListJsonl(dir, out) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch (_) { return; }
  for (const e of entries) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) wbListJsonl(p, out);
    else if (e.isFile() && e.name.endsWith('.jsonl')) out.push(p);
  }
}

function wbLocalDay(d) {
  return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0');
}

function wbExtractUsage(rec) {
  // OpenClaw/AutoClaw 格式：rec.message.usage = { input, output, cacheRead, cacheWrite, totalTokens, ... }
  // 必须校验 input 为数字：cb 的 message.usage 是 snake_case（input_tokens），不能误入此分支
  const oc = rec.message && rec.message.usage;
  if (oc && typeof oc === 'object' && typeof oc.input === 'number') {
    const input = Number(oc.input || 0);
    const output = Number(oc.output || 0);
    if (!input && !output) return null;
    return {
      input,
      output,
      cached: Number(oc.cacheRead || 0) + Number(oc.cacheWrite || 0),
      total: Number(oc.totalTokens || input + output),
    };
  }
  // WorkBuddy / CodeBuddy 格式：providerData.rawUsage/usage 或顶层 usage。
  // 新格式（CodeBuddy CLI / WorkBuddy 5.6+）：rawUsage 为 OpenAI 风格 snake_case；
  // providerData.usage 为聚合驼峰（inputTokens/outputTokens/totalTokens）——
  // 两键可能同时存在，rawUsage 优先、每记录只取一份，避免重复计数。
  const pd = rec.providerData;
  const u = (pd && (pd.rawUsage || pd.usage)) || rec.usage;
  if (!u || typeof u !== 'object') return null;
  const input = Number(u.prompt_tokens ?? u.inputTokens ?? 0);
  const output = Number(u.completion_tokens ?? u.outputTokens ?? 0);
  if (!input && !output) return null;
  const cached = Number(
    u.prompt_cache_hit_tokens ??
    (u.prompt_tokens_details && u.prompt_tokens_details.cached_tokens) ??
    u.cache_read_input_tokens ??
    (Array.isArray(u.inputTokensDetails) && u.inputTokensDetails[0] && u.inputTokensDetails[0].cached_tokens) ??
    0
  );
  return { input, output, cached, total: Number(u.total_tokens ?? u.totalTokens ?? input + output) };
}

function scanClientTokenUsage(kind) {
  const now = Date.now();
  const cache = clientUsageCaches[kind] || (clientUsageCaches[kind] = { at: 0, data: null });
  if (cache.data && now - cache.at < 60_000) return cache.data;
  const byDay = Object.create(null);
  const sessions = new Set();
  let requests = 0;
  const files = [];
  wbListJsonl(CLIENT_USAGE_DIRS[kind] || '', files);
  for (const f of files) {
    let text;
    try { text = fs.readFileSync(f, 'utf8'); } catch (_) { continue; }
    const fileSession = path.basename(f, path.extname(f)); // 兜底：AutoClaw 文件名即 sessionId
    for (const line of text.split('\n')) {
      const s = line.trim();
      if (s.length < 2) continue;
      let rec;
      try { rec = JSON.parse(s); } catch (_) { continue; }
      const u = wbExtractUsage(rec);
      if (!u) continue;
      requests++;
      const sid = rec.sessionId != null ? rec.sessionId : fileSession;
      if (sid) sessions.add(String(sid));
      // 优先 message.timestamp（AutoClaw 毫秒数字，避免其顶层 "MM/DD/YYYY" 字符串的月日歧义），回退顶层 timestamp
      const ts = (rec.message && rec.message.timestamp) ?? rec.timestamp;
      const d = ts ? new Date(ts) : new Date();
      const day = wbLocalDay(isNaN(d.getTime()) ? new Date() : d);
      const agg = (byDay[day] = byDay[day] || { input: 0, output: 0, cached: 0, total: 0, requests: 0 });
      agg.input += u.input; agg.output += u.output; agg.cached += u.cached; agg.total += u.total; agg.requests++;
    }
  }
  const data = { at: now, byDay, requests, sessions: sessions.size };
  clientUsageCaches[kind] = { at: now, data };
  return data;
}

function clientUsageSummary(kind) {
  const scan = scanClientTokenUsage(kind);
  const empty = () => ({ input: 0, output: 0, cached: 0, total: 0, requests: 0 });
  const sumRange = (fromDay, toDay) => {
    const s = empty();
    for (const day of Object.keys(scan.byDay)) {
      if (day >= fromDay && day <= toDay) {
        const a = scan.byDay[day];
        s.input += a.input; s.output += a.output; s.cached += a.cached; s.total += a.total; s.requests += a.requests;
      }
    }
    return s;
  };
  const today = wbLocalDay(new Date());
  const daysAgo = (n) => wbLocalDay(new Date(Date.now() - n * 86_400_000));
  const byDay = Object.keys(scan.byDay).sort().slice(-30).map((day) => ({ day, ...scan.byDay[day] }));
  return {
    today: sumRange(today, today),
    days7: sumRange(daysAgo(6), today),
    days30: sumRange(daysAgo(29), today),
    all: sumRange('0000-00-00', '9999-99-99'),
    allSessions: scan.sessions,
    allRequests: scan.requests,
    byDay,
    scannedAt: scan.at,
  };
}
const CDP_PORT = 9222;
const UI_PORT = parseInt(process.env.TRAEWORK_UI_PORT || '47921', 10);
const CDP_STARTUP_TIMEOUT_MS = 60000;

// 签到接口按官方 iCubeEntitlement 的实现：POST，body "{}"，多域名兜底（www.trae.cn 是官网非 API，不参与）
const CHECKIN_HOSTS = ['https://api.trae.cn', 'https://trae-api-cn.mchost.guru'];
const CHECKIN_PATH = '/trae/api/v2/ug/checkin_credits/';
const CHECKIN_REQUEST_TIMEOUT_MS = 12000;

// ---------------- 路径探测 ----------------
const USER_DATA_ROOT = isMac
  ? path.join(os.homedir(), 'Library', 'Application Support')
  : path.join(os.homedir(), 'AppData', 'Roaming');

// TraeWork 的安装目录/包名历经改名：TRAE SOLO CN → TraeWork CN。
// 普通版 Trae（"Trae CN" / "Trae"）是另一个产品，不在本项目适配范围内，必须排除：
// 否则会拉起错误的客户端、或读到别家产品的登录态。
// 判定依据：名称含 trae，且同时含 solo 或 work。
// 匹配：TRAE SOLO CN / TRAE SOLO / TraeWork CN / TraeWork
// 排除：Trae CN / Trae
const TRAEWORK_NAME_RE = /trae.*(solo|work)/i;

const EXE_CANDIDATES = isMac
  ? [
      '/Applications/TraeWork CN.app/Contents/MacOS/TraeWork CN',
      '/Applications/TRAE SOLO CN.app/Contents/MacOS/TRAE SOLO CN',
      '/Applications/TraeWork.app/Contents/MacOS/TraeWork',
      path.join(
        os.homedir(),
        'Applications',
        'TraeWork CN.app',
        'Contents',
        'MacOS',
        'TraeWork CN'
      ),
      path.join(
        os.homedir(),
        'Applications',
        'TRAE SOLO CN.app',
        'Contents',
        'MacOS',
        'TRAE SOLO CN'
      ),
      path.join(
        os.homedir(),
        'Applications',
        'TraeWork.app',
        'Contents',
        'MacOS',
        'TraeWork'
      ),
    ]
  : [
      'D:/Program Files/TRAE SOLO CN/TRAE SOLO CN.exe',
      path.join(
        process.env.ProgramFiles || 'C:/Program Files',
        'TRAE SOLO CN',
        'TRAE SOLO CN.exe'
      ),
      path.join(
        process.env['ProgramFiles(x86)'] || 'C:/Program Files (x86)',
        'TRAE SOLO CN',
        'TRAE SOLO CN.exe'
      ),
      path.join(
        process.env.LOCALAPPDATA || '',
        'Programs',
        'TRAE SOLO CN',
        'TRAE SOLO CN.exe'
      ),
    ];

const DATA_DIR_CANDIDATES = [
  'TraeWork CN',
  'TRAE SOLO CN',
  'TraeWork',
].map((name) => path.join(USER_DATA_ROOT, name));

function findTraeExecutable() {
  const direct = EXE_CANDIDATES.find((f) => f && fs.existsSync(f));
  if (direct) return direct;

  if (!isMac) return '';

  // macOS 兜底：
  // 扫描 /Applications 与 ~/Applications 中的 TraeWork.app（排除普通版 Trae）。
  for (const root of [
    '/Applications',
    path.join(os.homedir(), 'Applications'),
  ]) {
    let apps = [];

    try {
      apps = fs
        .readdirSync(root)
        .filter((name) => TRAEWORK_NAME_RE.test(name) && name.endsWith('.app'));
    } catch (_) {}

    for (const app of apps) {
      const macosDir = path.join(root, app, 'Contents', 'MacOS');

      let bins = [];
      try {
        bins = fs.readdirSync(macosDir);
      } catch (_) {}

      for (const bin of bins) {
        const full = path.join(macosDir, bin);

        try {
          if (fs.statSync(full).isFile()) return full;
        } catch (_) {}
      }
    }
  }

  return '';
}

function findTraeDataDir() {
  // 保留上游 v1.0.2 的逻辑：
  // 多个 Trae 客户端并存时，优先选择 storage.json 中
  // 真正含 iCubeAuthInfo 登录态的目录。
  const scanDirs = [...DATA_DIR_CANDIDATES];

  try {
    for (const name of fs.readdirSync(USER_DATA_ROOT)) {
      if (!TRAEWORK_NAME_RE.test(name)) continue;

      const dir = path.join(USER_DATA_ROOT, name);

      if (!scanDirs.includes(dir)) {
        scanDirs.push(dir);
      }
    }
  } catch (_) {}

  for (const dir of scanDirs) {
    if (!dir || !fs.existsSync(dir)) continue;

    const storage = path.join(
      dir,
      'User',
      'globalStorage',
      'storage.json'
    );

    if (!fs.existsSync(storage)) continue;

    try {
      if (
        fs
          .readFileSync(storage, 'utf8')
          .includes('iCubeAuthInfo://')
      ) {
        return dir;
      }
    } catch (_) {}
  }

  // 都没有有效登录态时，回退到第一个实际存在的数据目录。
  for (const dir of scanDirs) {
    if (dir && fs.existsSync(dir)) return dir;
  }

  return '';
}

function detectPaths() {
  return {
    exe: findTraeExecutable(),
    dataDir: findTraeDataDir(),
  };
}

let CFG = { exe: '', dataDir: '' };
function storageFile() { return path.join(CFG.dataDir, 'User', 'globalStorage', 'storage.json'); }

function log(...args) {
  const line = `[traework] ${new Date().toISOString()} ${args.join(' ')}\n`;
  try { process.stdout.write(line); } catch (_) {}
  try { fs.appendFileSync(path.join(__dirname, 'traework.log'), line); } catch (_) {}
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------------- 登录态解密（还原自 main.js 的 KUe/GGe） ----------------
const vh = 64, pv = 32, TO = 64, qm = 6;
const Ioe = Uint8Array.from([82,9,106,213,48,54,165,56,191,64,163,158,129,243,215,251,124,227,57,130,155,47,255,135,52,142,67,68,196,222,233,203,84,123,148,50,166,194,35,61,238,76,149,11,66,250,195,78,8,46,161,102,40,217,36,178,118,91,162,73,109,139,209,37]);
const Poe = Uint8Array.from([31,221,168,51,136,7,199,49,177,18,16,89,39,128,236,95,96,81,127,169,25,181,74,13,45,229,122,159,147,201,156,239,160,224,59,77,174,42,245,176,200,235,187,60,131,83,153,97,23,43,4,126,186,119,214,38,225,105,20,99,85,33,12,125]);
const sha512 = (u8) => new Uint8Array(crypto.createHash('sha512').update(Buffer.from(u8)).digest());

/** 解密 iCubeAuthInfo 值（base64 → Uint8Array → 明文 JSON buffer） */
function KUe(t) {
  const key = t.slice(qm, qm + pv);
  if (key.length !== pv) return null;
  const o = sha512(key);
  const a = new Uint8Array(TO);
  for (let i = 0; i < TO; i++) a[i] = Ioe[i] ^ Poe[i];
  const n = new Uint8Array(vh + TO);
  n.set(o, 0); n.set(a, vh);
  n.set(sha512(n), 0);
  const aesKey = n.slice(0, 16), iv = n.slice(16, 32);
  const d = crypto.createDecipheriv('aes-128-cbc', Buffer.from(aesKey), Buffer.from(iv));
  const pt = Buffer.concat([d.update(Buffer.from(t.slice(pv + qm))), d.final()]);
  const l = sha512(pt.slice(vh));
  for (let i = 0; i < vh; i++) if (l[i] !== pt[i]) return null;
  return pt.slice(vh);
}

/** 读取并解密登录态，返回 { token, userId, account, deviceId, raw }。
 *  任何失败都只返回 { error }，绝不抛异常：/api/health 会调用本函数，
 *  一旦抛出（如未安装 TraeWork 时 storageFile() 退化为相对路径导致 ENOENT），
 *  健康检查返回 500，桌面端据此误判 daemon 版本不匹配，最终误报「后台服务启动超时」。 */
function getAuth() {
  if (!CFG.dataDir) return { error: '未找到 TraeWork 数据目录（TraeWork 未安装或未登录）' };
  let json;
  try {
    json = JSON.parse(fs.readFileSync(storageFile(), 'utf8'));
  } catch (e) {
    return { error: '读取 storage.json 失败: ' + e.message };
  }
  const deviceId = json['telemetry.devDeviceId'] || '';
  const secret = json['iCubeAuthInfo://icube.cloudide'];
  if (!secret) return { error: '未找到 iCubeAuthInfo://icube.cloudide' };
  const buf = KUe(new Uint8Array(Buffer.from(secret, 'base64')));
  if (!buf) return { error: '登录态解密失败（校验和不通过）' };
  let info;
  try { info = JSON.parse(Buffer.from(buf).toString('utf8')); } catch (e) { return { error: '登录态解析失败: ' + e.message }; }
  return { token: info.token || '', userId: info.userId || '', account: info.account || {}, deviceId, info };
}

// ---------------- 便携数据目录 ----------------
// 账号备份/设置/积分缓存全部存放在数据目录（默认与 daemon.js 同目录）；
// Windows 继续使用便携目录；macOS 由桌面端指定到 ~/Library/Application Support/WorkPet。
// 目录不可写时回退到平台标准用户数据目录。
let DATA_ROOT =
  (process.env.WORKPET_DATA_DIR && fs.existsSync(process.env.WORKPET_DATA_DIR))
    ? process.env.WORKPET_DATA_DIR
    : __dirname;
const FALLBACK_DATA_DIR = path.join(
  isMac
    ? path.join(os.homedir(), 'Library', 'Application Support')
    : (process.env.APPDATA || path.join(os.homedir(), 'AppData', 'Roaming')),
  'WorkPet'
);
try {
  fs.mkdirSync(path.join(DATA_ROOT, 'accounts'), { recursive: true });
  fs.accessSync(path.join(DATA_ROOT, 'accounts'), fs.constants.W_OK);
} catch (e) {
  log('[data] 目录不可写，回退到: ' + FALLBACK_DATA_DIR + ' (' + e.message + ')');
  DATA_ROOT = FALLBACK_DATA_DIR;
  try { fs.mkdirSync(path.join(DATA_ROOT, 'accounts'), { recursive: true }); } catch (_) {}
}

// ---------------- 多账号管理（备份/列表/切换/删除） ----------------
// 登录态密文保存在 storage.json 的 iCubeAuthInfo://icube.cloudide 键里（自研 smart-secret AES）。
// 每个账号按 <userId>.json 备份到数据目录 accounts/ 下，
// 备份里保存「原始密文字符串 + 展示字段」；切换时把密文原样写回 storage.json 即可（解密是纯函数）。
const BACKUP_DIR = path.join(DATA_ROOT, 'accounts'); // 备份快照目录：WorkPet-accounts-<时间戳>.json
// 单一账号库：三端所有账号都在这一个文件里（WorkPet 自有格式）
const STORE_FILE = path.join(DATA_ROOT, 'WorkPet-accounts.json');
function loadStore() {
  const st = readJsonOrNull(STORE_FILE) || {};
  return {
    app: 'WorkPet', schema: 1, updatedAt: st.updatedAt || null,
    traework: Object.assign({ currentSecret: null, deviceId: null, accounts: [] }, st.traework),
    workbuddy: Object.assign({ current: null, accounts: [] }, st.workbuddy),
    codebuddy: Object.assign({ current: null, accounts: [] }, st.codebuddy),
    ac: Object.assign({ current: null, accounts: [] }, st.ac),
    codearts: Object.assign({ current: null, accounts: [] }, st.codearts),
    as: Object.assign({ current: null, accounts: [] }, st.as),
    zc: Object.assign({ current: null, accounts: [] }, st.zc),
  };
}
function saveStore(store) {
  store.updatedAt = new Date().toISOString();
  const tmp = STORE_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(store, null, 2));
  fs.renameSync(tmp, STORE_FILE);
}
// 一次性迁移：旧版平铺/traework 子目录的账号并入单文件账号库，然后删除旧目录
(function migrateToSingleStore() {
  try {
    const store = loadStore();
    const have = new Set(store.traework.accounts.map((a) => String(a.uid)));
    let moved = false;
    const legacyDirs = [path.join(BACKUP_DIR, 'traework'), BACKUP_DIR];
    for (const dir of legacyDirs) {
      let files = [];
      try { files = fs.readdirSync(dir).filter((f) => f.endsWith('.json')); } catch (_) {}
      for (const f of files) {
        const j = readJsonOrNull(path.join(dir, f));
        if (!j || !j.uid || !j.secret) continue;
        if (!have.has(String(j.uid))) { store.traework.accounts.push(j); have.add(String(j.uid)); moved = true; }
      }
    }
    if (moved) saveStore(store);
    try { fs.rmSync(path.join(BACKUP_DIR, 'traework'), { recursive: true, force: true }); } catch (_) {}
    try {
      // 只清理旧版平铺的 uid 数字命名文件，不动用户放入的任何其他文件
      for (const f of fs.readdirSync(BACKUP_DIR)) {
        if (/^\d+\.json$/.test(f)) { try { fs.unlinkSync(path.join(BACKUP_DIR, f)); } catch (_) {} }
      }
    } catch (_) {}
  } catch (_) {}
})();

function decodeSecret(secret) {
  const buf = KUe(new Uint8Array(Buffer.from(String(secret || ''), 'base64')));
  if (!buf) return null;
  try { return JSON.parse(Buffer.from(buf).toString('utf8')); } catch (_) { return null; }
}

/** 从解密信息抽取展示字段；secret 仅落盘备份用，不对外暴露 */
function accountMetaFromInfo(info) {
  const acct = (info && info.account) || {};
  return {
    uid: String(info.userId || ''),
    nickname: String(acct.username || ''),
    mobile: String(acct.nonPlainTextMobile || ''),
    avatarUrl: String(acct.avatar_url || ''),
    expiredAt: info.expiredAt || null,
    refreshExpiredAt: info.refreshExpiredAt || null,
    scope: String(acct.scope || ''),
  };
}

/** 当前登录账号（不含 token/secret） */
function readCurrentAccount() {
  const auth = getAuth();
  if (auth.error) return null;
  return accountMetaFromInfo(auth.info);
}

/** 备份当前登录账号：解密 → 连同密文写入 accounts/<uid>.json（原子写） */
function backupCurrentAccount() {
  const auth = getAuth();
  if (auth.error) throw new Error(auth.error);
  const raw = fs.readFileSync(storageFile(), 'utf8');
  const json = JSON.parse(raw);
  const secret = json['iCubeAuthInfo://icube.cloudide'];
  if (!secret) throw new Error('storage.json 中缺少 iCubeAuthInfo://icube.cloudide');
  const meta = accountMetaFromInfo(auth.info);
  if (!meta.uid) throw new Error('无法识别当前账号');
  const store = loadStore();
  const record = Object.assign({ schema: 1, backedUpAt: Date.now(), secret }, meta);
  const idx = store.traework.accounts.findIndex((a) => String(a.uid) === String(meta.uid));
  if (idx >= 0) store.traework.accounts[idx] = Object.assign({}, store.traework.accounts[idx], record);
  else store.traework.accounts.push(record);
  store.traework.currentSecret = secret;
  saveStore(store);
  return { uid: meta.uid, nickname: meta.nickname };
}

/**
 * 跨客户端收集：扫描 Roaming 下所有 TraeWork 客户端（TRAE SOLO CN / TraeWork CN /
 * TraeWork，不含普通版 Trae）的已登录账号，把有可用登录态的都并入备份库，实现「登录过的账号
 * 都能显示」。只读别的客户端 storage，绝不写回别人。
 */
function collectAllTraeAccounts() {
  const roam = USER_DATA_ROOT;
  let dirs = [];
  try { dirs = fs.readdirSync(roam).filter((n) => TRAEWORK_NAME_RE.test(n)); } catch (_) {}
  const saved = [];
  const store = loadStore();
  for (const name of dirs) {
    const storage = path.join(roam, name, 'User', 'globalStorage', 'storage.json');
    if (!fs.existsSync(storage)) continue;
    try {
      const json = JSON.parse(fs.readFileSync(storage, 'utf8'));
      const secret = json['iCubeAuthInfo://icube.cloudide'];
      if (!secret) continue;
      const info = decodeSecret(secret);
      if (!info || !info.userId) continue;
      const meta = accountMetaFromInfo(info);
      if (!meta.uid) continue;
      const record = Object.assign({ schema: 1, backedUpAt: Date.now(), secret, src: name }, meta);
      const idx = store.traework.accounts.findIndex((a) => String(a.uid) === String(meta.uid));
      if (idx >= 0) store.traework.accounts[idx] = Object.assign({}, store.traework.accounts[idx], record);
      else store.traework.accounts.push(record);
      saved.push((meta.nickname || meta.uid) + ':' + name);
    } catch (_) { /* 该客户端无有效登录态则跳过 */ }
  }
  if (saved.length) saveStore(store);
  return saved;
}

/** 列出所有已备份账号（不含 secret），按备份时间倒序 */
function listAccounts() {
  const store = loadStore();
  const list = store.traework.accounts
    .filter((rec) => rec && rec.uid)
    .map((rec) => ({
      uid: rec.uid, nickname: rec.nickname || '', mobile: rec.mobile || '',
      avatarUrl: rec.avatarUrl || '', expiredAt: rec.expiredAt || null,
      refreshExpiredAt: rec.refreshExpiredAt || null, scope: rec.scope || '',
      backedUpAt: rec.backedUpAt || null,
    }));
  list.sort((a, b) => (b.backedUpAt || 0) - (a.backedUpAt || 0));
  return list;
}

/** 读取某账号备份并校验：备份里存的密文必须能解密出相同 uid */
function readAccountSecret(uid) {
  const store = loadStore();
  const rec = store.traework.accounts.find((a) => String(a.uid) === String(uid));
  if (!rec) throw new Error('未找到账号 ' + uid + ' 的备份');
  if (String(rec.uid) !== String(uid)) throw new Error('备份 uid 不匹配');
  const info = decodeSecret(rec.secret);
  if (!info) throw new Error('备份密文无法解密');
  if (String(info.userId) !== String(uid)) throw new Error('备份校验失败：解密 userId 与 uid 不匹配');
  return { secret: rec.secret, info };
}

/** 把指定密文写回 storage.json（保留其它键；切换前必须先停宿主，防其覆盖） */
function writeAuthSecret(secret) {
  const file = storageFile();
  const json = JSON.parse(fs.readFileSync(file, 'utf8'));
  json['iCubeAuthInfo://icube.cloudide'] = secret;
  const tmp = file + '.twswitch.tmp';
  fs.writeFileSync(tmp, JSON.stringify(json, null, 2));
  fs.renameSync(tmp, file);
}

/** 删除账号备份文件（不影响当前登录） */
function deleteAccountBackup(uid) {
  const store = loadStore();
  const before = store.traework.accounts.length;
  store.traework.accounts = store.traework.accounts.filter((a) => String(a.uid) !== String(uid));
  saveStore(store);
  return store.traework.accounts.length < before;
}

/** 切换账号：停宿主 → 写回密文 → 以 CDP 模式重启 → 自动重注入 */
async function switchToAccount(uid) {
  const { secret, info } = readAccountSecret(uid);
  const nickname = ((info.account && info.account.username) || uid);
  log('[switch] 切换账号 -> ' + nickname + ' (' + uid + ')');
  killTraeWork(); // 先停宿主，避免其把内存身份写回 storage.json 覆盖切换
  await sleep(1500);
  writeAuthSecret(secret);
  log('[switch] 已写回登录态到 storage.json');
  statusCache.at = 0; statusCache.data = null;
  entCache.at = 0; entCache.data = null;
  await ensureTraeWorkWithCdp(); // 重启 TraeWork 使切换生效；桌面版不再注入
  log('[switch] 已切换账号: ' + nickname);
  // 切换后重备份一次：宿主重启时可能已刷新登录态（新 token/新有效期），
  // 把最新的 Cookie 时限同步进账号库，避免面板显示过期日期。
  try {
    const r = backupCurrentAccount();
    log('[switch] 已刷新账号备份 ' + r.nickname + ' (' + r.uid + ')');
  } catch (e) { log('[switch] 切换后备份失败: ' + e.message); }
  return { uid, nickname };
}

// ---------------- 签到 API ----------------
function postJson(url, body, headers) {
  return new Promise((resolve, reject) => {
    const mod = url.startsWith('https:') ? require('https') : require('http');
    const data = body != null ? Buffer.from(typeof body === 'string' ? body : JSON.stringify(body)) : null;
    const u = new URL(url);
    const req = mod.request({
      hostname: u.hostname,
      port: u.port || (u.protocol === 'https:' ? 443 : 80),
      path: u.pathname + u.search,
      method: 'POST',
      headers: Object.assign(
        { 'Content-Type': 'application/json', Accept: 'application/json' },
        data ? { 'Content-Length': data.length } : {},
        headers || {}
      ),
      timeout: CHECKIN_REQUEST_TIMEOUT_MS,
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let obj = {};
        try { obj = JSON.parse(text); } catch (_) { obj = { code: -1, message: text.slice(0, 300) }; }
        resolve({ status: res.statusCode, body: obj, text });
      });
    });
    req.on('timeout', () => req.destroy(new Error('请求超时')));
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

function getJson(url, headers, redirects) {
  return new Promise((resolve, reject) => {
    const mod = url.startsWith('https:') ? require('https') : require('http');
    const u = new URL(url);
    const req = mod.request({
      hostname: u.hostname,
      port: u.port || (u.protocol === 'https:' ? 443 : 80),
      path: u.pathname + u.search,
      method: 'GET',
      headers: Object.assign({ Accept: 'application/json', 'User-Agent': 'WorkPet-Desktop' }, headers || {}),
      timeout: 8000,
    }, (res) => {
      // 跟随 3xx 重定向（GitHub 仓库改名的 301 会指向新地址），最多 5 跳
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers && res.headers.location) {
        res.destroy(new Error('redirect'));
        if ((redirects || 0) >= 5) return reject(new Error('重定向次数过多'));
        return resolve(getJson(new URL(res.headers.location, url).toString(), headers, (redirects || 0) + 1));
      }
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let obj = null;
        try { obj = JSON.parse(text); } catch (_) {}
        resolve({ status: res.statusCode, body: obj, text });
      });
    });
    req.on('timeout', () => req.destroy(new Error('请求超时')));
    req.on('error', reject);
    req.end();
  });
}

function checkinHeaders(auth) {
  return {
    'Authorization': 'Cloud-IDE-JWT ' + auth.token,
    'x-device-id': auth.deviceId,
    'Origin': 'vscode-file://vscode-app',
    'User-Agent': 'TRAE SOLO CN',
  };
}

/** 带多域名兜底的签到请求：action = 'status' | 'claim' */
async function checkinRequest(action, auth) {
  let lastErr = null;
  for (const host of CHECKIN_HOSTS) {
    const url = host + CHECKIN_PATH + action;
    const t0 = Date.now();
    try {
      const r = await postJson(url, {}, checkinHeaders(auth));
      const body = r.body || {};
      const hasCode = typeof body.code === 'number';
      // 每次尝试都留痕，便于排查「签到失败」的真实服务端原因
      log(`[checkin/${action}] ${host} HTTP ${r.status} code=${body.code} msg=${body.message || body.msg || ''} checked_in=${body.checked_in} (${Date.now() - t0}ms)`);
      // 200 且返回了合法 JSON（带 code 字段）= 服务端的确定结果：
      // 无论 code 是否为 0 都直接返回，避免误落到返回 HTML 的错误 host 上。
      if (r.status === 200 && hasCode) {
        const ok = body.code === 0 || body.code === undefined || body.code === null;
        return { ok, status: r.status, body, host };
      }
      // 4xx/5xx（非 404）也视为确定失败
      if (r.status >= 400 && r.status < 500 && r.status !== 404) {
        return { ok: false, status: r.status, body, host };
      }
      lastErr = 'HTTP ' + r.status + ' ' + (body.message || body.msg || '');
    } catch (e) {
      log(`[checkin/${action}] ${host} 请求失败: ${e.message} (${Date.now() - t0}ms)`);
      lastErr = e.message;
    }
  }
  return { ok: false, status: 0, body: {}, host: CHECKIN_HOSTS[0], error: lastErr };
}

// ---------------- 设置（持久化到数据目录 config.json） ----------------
const CONFIG_DIR = DATA_ROOT;
const CONFIG_FILE = path.join(CONFIG_DIR, 'config.json');
const SETTING_DEFAULTS = { launchHostOnStart: false, wbLaunchOnStart: false, cbLaunchOnStart: false, acLaunchOnStart: isMac, caLaunchOnStart: false, asLaunchOnStart: false, zcLaunchOnStart: false, showPhone: false, fontScale: 1, tabOrder: ['wb', 'cb', 'ac', 'ca', 'as', 'zc', 'tw'], tabShowText: false, hidePet: true };
// 旧配置兼容：TraeWork Tab 的 key 原为 'accounts'，v1.0.2 起统一为 'tw'。
// 新增客户端（如 as）后，老配置里缺失的 Tab 追加到末尾而不是整表重置，避免用户自定义顺序被清掉。
function normalizeTabOrder(v) {
  if (!Array.isArray(v)) return null;
  const mapped = v.map((t) => (t === 'accounts' ? 'tw' : String(t)));
  const known = ['wb', 'cb', 'ac', 'ca', 'as', 'zc', 'tw'];
  const uniq = Array.from(new Set(mapped)).filter((t) => known.includes(t));
  for (const k of known) if (!uniq.includes(k)) uniq.push(k);
  return uniq;
}
function loadSettings() {
  try {
    return Object.assign({}, SETTING_DEFAULTS, JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8')));
  } catch (_) { return Object.assign({}, SETTING_DEFAULTS); }
}
function saveSettings(patch) {
  const next = Object.assign({}, loadSettings(), patch);
  fs.mkdirSync(CONFIG_DIR, { recursive: true });
  const tmp = CONFIG_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(next, null, 2));
  fs.renameSync(tmp, CONFIG_FILE);
  return next;
}

// ---------------- 全账号轮换（批量签到 + 每账号积分缓存） ----------------
// 签到/查积分接口只认 storage.json 里的登录态（getAuth 是纯读文件），因此批量
// 操作不需要逐个重启宿主：停宿主 → 依次写回各账号密文并查询/签到 → 恢复原账号。
// 顺带把每个账号的权益包数据缓存到 credits.json，供面板显示非当前账号的剩余积分。
let claimAllJob = { running: false, total: 0, done: 0, results: [], startedAt: 0, finishedAt: 0 };

const CREDITS_FILE = path.join(CONFIG_DIR, 'credits.json');
function loadCreditsStore() {
  try { return JSON.parse(fs.readFileSync(CREDITS_FILE, 'utf8')); } catch (_) { return {}; }
}
function saveCreditsStore(store) {
  fs.mkdirSync(CONFIG_DIR, { recursive: true });
  const tmp = CREDITS_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(store, null, 2));
  fs.renameSync(tmp, CREDITS_FILE);
}
let creditsStore = loadCreditsStore();

// 「设备签到名额」按天记忆：Trae 限制每台设备每日只能一个账号领签到积分。
// 一旦确认本设备今日名额已用（某账号签到成功 / 服务端返回「设备已签到」），
// 当天其余账号直接跳过宿主 IPC 签到，避免每次打开 Pet 都无意义地拉起 TraeWork。
function todayStrLocal() {
  const d = new Date();
  const z = (n) => String(n).padStart(2, '0');
  return d.getFullYear() + '-' + z(d.getMonth() + 1) + '-' + z(d.getDate());
}
function markDeviceClaimedToday() {
  if (creditsStore.deviceClaimDate === todayStrLocal()) return;
  creditsStore.deviceClaimDate = todayStrLocal();
  saveCreditsStore(creditsStore);
}
function isDeviceClaimedToday() {
  return creditsStore.deviceClaimDate === todayStrLocal();
}

/**
 * 依次把每个账号的登录态写回 storage.json 并执行 fn；结束后恢复原账号。
 * fn 收到当前账号，返回 { ok, already, checkedIn, packs, remaining, msg }。
 * claim=true 时对未签到账号执行签到（含限流自动重试）。
 */
// ---------------- 经宿主官方 IPC 签到（CDP） ----------------
// 实测：Trae 服务端对非 TTNet 客户端的直连 HTTP claim 一律返回 9074「当前参与用户太多」
// （换 UA / 设备指纹头 / req_source / curl(Schannel) 均被拒，凭证本身有效——status 正常）。
// 但宿主主进程经 TTNet 发出的同一请求可以成功。因此退化为：带 CDP 拉起宿主，
// 经 window.vscode.ipcRenderer.invoke 调用官方「签到按钮」完全相同的 IPC 通道。
async function claimViaApp(timeoutMs = 150000) {
  const started = await ensureTraeWorkWithCdp();
  if (started.error) {
    // 拉起失败时清理宿主，避免留下一个没开 CDP、无法签到的 TraeWork 窗口
    try { killTraeWork(); await sleep(1000); } catch (_) {}
    return { ok: false, error: started.error };
  }
  const deadline = Date.now() + timeoutMs;
  let lastErr = 'unknown';
  while (Date.now() < deadline) {
    const target = await getPageTarget(CDP_PORT).catch(() => null);
    if (!target) { await sleep(2000); lastErr = '未找到 TraeWork 页面目标'; continue; }
    const raw = await new Promise((resolve) => {
      let ws = null;
      const finish = (v) => { clearTimeout(timer); try { ws && ws.close(); } catch (_) {} resolve(v); };
      const timer = setTimeout(() => finish(null), 25000);
      try { ws = new WebSocket(target.webSocketDebuggerUrl); } catch (e) { return finish(null); }
      ws.onopen = () => {
        const expr = `(async () => {
          try {
            if (!window.vscode || !window.vscode.ipcRenderer) return JSON.stringify({ err: 'no vscode bridge' });
            const r = await window.vscode.ipcRenderer.invoke('vscode:sandbox::main-invoke-claimCheckinCredits');
            const st = await window.vscode.ipcRenderer.invoke('vscode:sandbox::main-invoke-fetchCheckinCreditsStatus').catch(() => null);
            return JSON.stringify({ claim: r, status: st && st.data });
          } catch (e) { return JSON.stringify({ err: String(e && e.message || e) }); }
        })()`;
        ws.send(JSON.stringify({ id: 1, method: 'Runtime.evaluate', params: { expression: expr, awaitPromise: true, returnByValue: true } }));
      };
      ws.onmessage = (ev) => {
        try {
          const d = JSON.parse(ev.data);
          if (d.id === 1) finish(d.result && d.result.result && d.result.result.value);
        } catch (_) {}
      };
      ws.onerror = () => finish(null);
    });
    if (raw) {
      let o = {};
      try { o = JSON.parse(raw); } catch (_) {}
      // 无论结果如何，先退出宿主：防止其在后续账号轮换时覆盖 storage.json 中的登录态
      try { killTraeWork(); await sleep(1500); } catch (_) {}
      if (o.err) { lastErr = o.err; }
      else {
        const claimData = (o.claim && o.claim.data) || {};
        const stData = o.status || {};
        const claimed = stData.checked_in === true;
        const ok = o.claim && o.claim.status === 200 && (claimData.code === 0 || claimData.code === undefined || claimData.code === null);
        if (ok || claimed) {
          statusCache.at = 0; statusCache.data = null; entCache.at = 0; entCache.data = null;
          return { ok: true, data: claimData, checkedIn: true, via: 'app-ipc' };
        }
        lastErr = claimData.message || claimData.msg || ('code=' + claimData.code);
        // 明确的业务失败（非限流）直接返回，避免无意义重试
        return { ok: false, error: lastErr, data: claimData };
      }
    }
    await sleep(2500);
  }
  try { killTraeWork(); await sleep(1000); } catch (_) {}
  return { ok: false, error: lastErr };
}

// ---------------- 全账号单文件备份/恢复（WorkPet 自有格式，跨电脑迁移） ----------------
// 导出为一个 WorkPet-accounts-<时间戳>.json，包含三端全部账号：
//   traework  当前登录密文 + 全部账号备份（accounts/*.json）
//   workbuddy 当前登录文件 + 全部账号备份（clients/accounts/*.info）
//   codebuddy 当前登录文件 + 全部账号备份（clients/profiles/codebuddy-cn/accounts/*.info）
// 恢复时写回各自位置即可在新电脑上使用。
// WB/CB 账号备份目录：WorkPet 自有目录。旧版曾借用 WorkDaddy 目录存放，
// 首次运行把旧目录文件搬迁过来（只读复制，旧目录原样保留）。
const APP_DATA_ROOT = isMac
  ? path.join(os.homedir(), 'Library', 'Application Support')
  : (process.env.APPDATA || path.join(os.homedir(), 'AppData', 'Roaming'));
const LOCAL_DATA_ROOT = isMac
  ? path.join(os.homedir(), 'Library', 'Application Support')
  : (process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local'));
const SHARED_DATA_DIR = path.join(APP_DATA_ROOT, 'WorkPet', 'clients');
const WB_ACCOUNTS_DIR = path.join(SHARED_DATA_DIR, 'accounts');
const CB_ACCOUNTS_DIR = path.join(SHARED_DATA_DIR, 'profiles', 'codebuddy-cn', 'accounts');
const LEGACY_SHARED_DIR = path.join(APP_DATA_ROOT, 'WorkDaddy');
function migrateLegacySharedDir(rel) {
  try {
    const dstDir = path.join(SHARED_DATA_DIR, rel);
    const srcDir = path.join(LEGACY_SHARED_DIR, rel);
    fs.mkdirSync(dstDir, { recursive: true });
    if (!fs.existsSync(srcDir)) return;
    for (const f of fs.readdirSync(srcDir)) {
      const dst = path.join(dstDir, f);
      const src = path.join(srcDir, f);
      if (!fs.existsSync(dst) && fs.statSync(src).isFile()) fs.copyFileSync(src, dst);
    }
  } catch (_) {}
}
migrateLegacySharedDir('accounts');
migrateLegacySharedDir(path.join('profiles', 'codebuddy-cn', 'accounts'));
const EXT_AUTH_DIR = path.join(LOCAL_DATA_ROOT, 'CodeBuddyExtension', 'Data', 'Public', 'auth');
const WB_AUTH_FILE = path.join(EXT_AUTH_DIR, 'workbuddy-desktop.info');
const CB_AUTH_FILE = path.join(EXT_AUTH_DIR, 'Tencent-Cloud.coding-copilot.info');

function readJsonOrNull(file) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch (_) { return null; }
}

function collectExportAccounts() {
  // TraeWork：直接取自单文件账号库
  const store = loadStore();
  const traeworkAccounts = store.traework.accounts;
  // WorkBuddy / CodeBuddy：账号备份为原始登录文件内容，uid 取自 account.uid
  const collectInfoFiles = (dir) => {
    const out = [];
    try {
      for (const f of fs.readdirSync(dir).filter((f) => f.endsWith('.info') && !f.endsWith('.tmp') && !f.includes('.logged-out'))) {
        const j = readJsonOrNull(path.join(dir, f));
        const uid = j && j.account && j.account.uid;
        if (j && uid) out.push(j);
      }
    } catch (_) {}
    return out;
  };
  const out = {
    traework: {
      currentSecret: (() => {
        try { return JSON.parse(fs.readFileSync(storageFile(), 'utf8'))['iCubeAuthInfo://icube.cloudide'] || store.traework.currentSecret || null; } catch (_) { return store.traework.currentSecret || null; }
      })(),
      deviceId: (() => {
        try { return JSON.parse(fs.readFileSync(storageFile(), 'utf8'))['telemetry.devDeviceId'] || null; } catch (_) { return null; }
      })(),
      accounts: traeworkAccounts,
    },
    workbuddy: {
      current: readJsonOrNull(WB_AUTH_FILE),
      accounts: collectInfoFiles(WB_ACCOUNTS_DIR),
    },
    codebuddy: {
      current: readJsonOrNull(CB_AUTH_FILE),
      accounts: collectInfoFiles(CB_ACCOUNTS_DIR),
    },
    autoclaw: {
      current: clientReadAuth('ac'),
      accounts: (store.ac && store.ac.accounts) || [],
    },
    codearts: {
      current: (store.codearts && store.codearts.current) || null, // 保持已有 current，不因导出而清空
      accounts: (store.codearts && store.codearts.accounts) || [],
    },
    astudio: (() => {
      // AStudio：导出前先把本机最新登录态（明文 session）并入账号库，保证 WorkPet-accounts.json 完整
      try { if (asReadSession()) clientSyncStore('as'); } catch (_) {}
      const s2 = loadStore();
      return { current: (s2.as && s2.as.current) || null, accounts: (s2.as && s2.as.accounts) || [] };
    })(),
    zcode: (() => {
      // ZCode：先把本机最新凭据文件并入账号库，保证 WorkPet-accounts.json 完整
      try { zcSyncStore(); } catch (_) {}
      const s2 = loadStore();
      return { current: (s2.zc && s2.zc.current) || null, accounts: (s2.zc && s2.zc.accounts) || [] };
    })(),
  };
  // 把引擎目录的最新账号状态同步回单文件账号库，保证 WorkPet-accounts.json 始终完整
  store.traework.currentSecret = out.traework.currentSecret;
  store.traework.deviceId = out.traework.deviceId;
  store.workbuddy = { current: out.workbuddy.current, accounts: out.workbuddy.accounts };
  store.codebuddy = { current: out.codebuddy.current, accounts: out.codebuddy.accounts };
  store.ac = { current: out.autoclaw.current, accounts: out.autoclaw.accounts };
  store.codearts = { current: out.codearts.current, accounts: out.codearts.accounts };
  store.as = { current: out.astudio.current, accounts: out.astudio.accounts };
  store.zc = { current: out.zcode.current, accounts: out.zcode.accounts };
  saveStore(store);
  return out;
}

function exportBackupFile() {
  const data = {
    app: 'WorkPet', schema: 1, exportedAt: new Date().toISOString(),
    ...collectExportAccounts(),
  };
  const d = new Date();
  const pad = (n) => String(n).padStart(2, '0');
  const name = `WorkPet-accounts-${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}-${pad(d.getHours())}${pad(d.getMinutes())}${pad(d.getSeconds())}.json`;
  const file = path.join(BACKUP_DIR, name);
  const tmp = file + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2));
  fs.renameSync(tmp, file);
  return {
    file: name,
    counts: {
      traework: data.traework.accounts.length,
      workbuddy: data.workbuddy.accounts.length,
      codebuddy: data.codebuddy.accounts.length,
      autoclaw: (data.autoclaw.accounts || []).length,
      codearts: (data.codearts.accounts || []).length,
      astudio: (data.astudio.accounts || []).length,
      zcode: (data.zcode.accounts || []).length,
    },
  };
}

function listBackupFiles() {
  try {
    return fs.readdirSync(BACKUP_DIR)
      .filter((f) => /^WorkPet-accounts-\d{8}-\d{6}\.json$/.test(f))
      .sort()
      .reverse();
  } catch (_) { return []; }
}

async function restoreBackupData(data) {
  if (!data || data.app !== 'WorkPet') throw new Error('不是有效的 WorkPet 备份文件');
  const counts = { traework: 0, workbuddy: 0, codebuddy: 0, autoclaw: 0, codearts: 0, astudio: 0, zcode: 0 };
  const atomicWrite = (file, content) => {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    const tmp = file + '.tmp';
    fs.writeFileSync(tmp, content);
    fs.renameSync(tmp, file);
  };
  // TraeWork：先停宿主（运行中的实例退出时会用内存中的旧登录覆盖 storage.json）
  if (isProcessRunning()) { try { killTraeWork(); await sleep(1500); } catch (_) {} }
  // 账号并入单文件账号库 + 当前登录密文写回 storage.json（保留本机 deviceId）
  const store = loadStore();
  if (data.traework) {
    for (const a of data.traework.accounts || []) {
      if (!a.uid || !a.secret) continue;
      const idx = store.traework.accounts.findIndex((x) => String(x.uid) === String(a.uid));
      if (idx >= 0) store.traework.accounts[idx] = Object.assign({}, store.traework.accounts[idx], a, { backedUpAt: Date.now() });
      else store.traework.accounts.push(Object.assign({ backedUpAt: Date.now() }, a));
      counts.traework++;
    }
    if (data.traework.currentSecret) {
      store.traework.currentSecret = data.traework.currentSecret;
      writeAuthSecret(data.traework.currentSecret);
    }
  }
  // WorkBuddy：账号写回 accounts；当前登录写回扩展 auth 文件
  if (data.workbuddy) {
    for (const a of data.workbuddy.accounts || []) {
      const uid = a && a.account && a.account.uid;
      if (!uid) continue;
      atomicWrite(path.join(WB_ACCOUNTS_DIR, `${uid}.info`), JSON.stringify(a, null, 2));
      counts.workbuddy++;
    }
    if (data.workbuddy.current) atomicWrite(WB_AUTH_FILE, JSON.stringify(data.workbuddy.current, null, 2));
    store.workbuddy = { current: data.workbuddy.current || null, accounts: data.workbuddy.accounts || [] };
  }
  // CodeBuddy：同上（独立 profile）
  if (data.codebuddy) {
    for (const a of data.codebuddy.accounts || []) {
      const uid = a && a.account && a.account.uid;
      if (!uid) continue;
      atomicWrite(path.join(CB_ACCOUNTS_DIR, `${uid}.info`), JSON.stringify(a, null, 2));
      counts.codebuddy++;
    }
    if (data.codebuddy.current) atomicWrite(CB_AUTH_FILE, JSON.stringify(data.codebuddy.current, null, 2));
    store.codebuddy = { current: data.codebuddy.current || null, accounts: data.codebuddy.accounts || [] };
  }
  // AutoClaw：仅并入账号库（不回写 auth.json —— 跨机恢复需本机 DPAPI 重加密，无意义）
  if (data.autoclaw) {
    for (const a of data.autoclaw.accounts || []) {
      const uid = a && a.uid;
      if (!uid) continue;
      const idx = store.ac.accounts.findIndex((x) => x && String(x.uid) === String(uid));
      if (idx >= 0) store.ac.accounts[idx] = Object.assign({}, store.ac.accounts[idx], a, { backedUpAt: Date.now() });
      else store.ac.accounts.push(Object.assign({ backedUpAt: Date.now() }, a));
      counts.autoclaw = (counts.autoclaw || 0) + 1;
    }
  }
  // CodeArts Agent：仅并入账号库（不回写 vscdb —— 切换时优先用本机可解的 secretRaw，
  // 跨机备份则用 secretPlain 以本机 safeStorage key 重加密，见 caSwitchToAccount）
  if (data.codearts) {
    for (const a of data.codearts.accounts || []) {
      const uid = a && a.uid;
      if (!uid || (!a.secretRaw && !a.secretPlain)) continue;
      const idx = store.codearts.accounts.findIndex((x) => x && String(x.uid) === String(uid));
      if (idx >= 0) store.codearts.accounts[idx] = Object.assign({}, store.codearts.accounts[idx], a, { backedUpAt: Date.now() });
      else store.codearts.accounts.push(Object.assign({ backedUpAt: Date.now() }, a));
      counts.codearts = (counts.codearts || 0) + 1;
    }
  }
  // AStudio：仅并入账号库（不自动写回本机 astron-session.json —— 登录态是明文，
  // 跨机导入后可直接切换；是否切换由用户点按钮决定）
  if (data.astudio) {
    for (const a of data.astudio.accounts || []) {
      const uid = a && a.uid;
      if (!uid || !a.session) continue;
      const idx = store.as.accounts.findIndex((x) => x && String(x.uid) === String(uid));
      if (idx >= 0) store.as.accounts[idx] = Object.assign({}, store.as.accounts[idx], a, { backedUpAt: Date.now() });
      else store.as.accounts.push(Object.assign({ backedUpAt: Date.now() }, a));
      counts.astudio = (counts.astudio || 0) + 1;
    }
  }
  // ZCode：仅并入账号库（不回写 credentials.json —— 凭据用本机派生 key 加密，
  // 跨机恢复的备份无法在本机解密，切换时会自检拒绝；是否切换由用户点按钮决定）
  if (data.zcode) {
    for (const a of data.zcode.accounts || []) {
      const uid = a && a.uid;
      if (!uid || !a.cred) continue;
      const idx = store.zc.accounts.findIndex((x) => x && String(x.uid) === String(uid));
      if (idx >= 0) store.zc.accounts[idx] = Object.assign({}, store.zc.accounts[idx], a, { backedUpAt: Date.now() });
      else store.zc.accounts.push(Object.assign({ backedUpAt: Date.now() }, a));
      counts.zcode = (counts.zcode || 0) + 1;
    }
  }
  saveStore(store);
  return counts;
}


// ================= WB/CB 客户端支持（原生实现，替代外部引擎） =================
// WorkBuddy / CodeBuddy 的账号备份、切换、签到、积分查询全部由本 daemon 原生完成：
// 登录态 = CodeBuddyExtension 扩展 auth 文件（两个客户端各一条独立通道）；
// 账号库 = WorkPet-accounts.json 的 workbuddy/codebuddy 段；
// 签到/积分 = 各端 apiHost 的 HTTP 接口（Bearer accessToken）。

const { extractCreditSegments, sortCreditSegments, mergeCreditSegments } = require('./credit-segments.js');

// ---------------- AutoClaw（智谱 AutoGLM 桌面端，独立账号体系） ----------------
// 登录态 = %APPDATA%/autoclaw/auth.json（token/refreshToken 为 Electron safeStorage "enc:v10" 加密，
//   密钥在 Local State 的 os_crypt.encrypted_key —— DPAPI 包裹的 AES-256-GCM key，与浏览器同构）。
// 签到 = POST /autoclaw-proxy/proxy/autoclaw-task-complete { task_id: 'daily_signin' }（任务中心任务，
//   实测 daily_signin 的 reward_points 为 400，不写死数字，一律以服务端返回为准）。
// 积分 = GET /agent-assetmgr/api/v1/points/expiring?biz_app_id=autoclaw（total_points / expiring_points）。
// 签名头 = X-Auth-Appid/X-Auth-TimeStamp/X-Auth-Sign（md5(appid&ts&appkey)），token 走 Authorization Bearer。
// Cookie 时限 = JWT exp（access_token 是 JWT，24h）；refresh 走 /userapi/v1/refresh（refresh_token 轮换，回写 auth.json）。
// macOS：Electron safeStorage 密钥在登录钥匙串（service "autoclaw Safe Storage"，密码经 PBKDF2 派生 AES key）
const AC_DATA_DIR = isMac
  ? path.join(os.homedir(), 'Library', 'Application Support', 'autoclaw')
  : path.join(process.env.APPDATA || path.join(os.homedir(), 'AppData', 'Roaming'), 'autoclaw');
const AC_AUTH_FILE = path.join(AC_DATA_DIR, 'auth.json');
const AC_LOCAL_STATE = path.join(AC_DATA_DIR, 'Local State');

// ---------------- AutoClaw2（zwork v2，智谱）：全新数据布局 ----------------
// 数据目录迁移到 %APPDATA%/AutoClaw-official；账号改为原生多账号：
//   accounts/<accountKey>/account-profile.json（明文：accountId/phone/numericUserId/lastLoginAt）
//   accounts/<accountKey>/account-credentials.enc（safeStorage v10，密钥为 app-bound 加密，
//     普通 DPAPI 解不开 —— 实测 "The data is invalid"，因此 token 外部拿不到）
// 当前账号 = device/active-product-account.json 的 accountKey 指针。
// 积分/会员只能经 CDP 调渲染进程的 window.zworkAuth（getCreditsBalance/getCreditsLedgers）；
// 新版无每日签到（账本里的「每日签到」是历史记录，zworkAuth 无签到方法）。
const AC2_DATA_DIR = path.join(process.env.APPDATA || path.join(os.homedir(), 'AppData', 'Roaming'), 'AutoClaw-official');
const AC2_ACCOUNTS_DIR = path.join(AC2_DATA_DIR, 'accounts');
const AC2_ACTIVE_FILE = path.join(AC2_DATA_DIR, 'device', 'active-product-account.json');

/** 是否为新版布局（AutoClaw-official/accounts 存在且非空） */
function ac2IsNewLayout() {
  try {
    return fs.existsSync(AC2_ACCOUNTS_DIR) && fs.readdirSync(AC2_ACCOUNTS_DIR).length > 0;
  } catch (_) { return false; }
}

/** 当前账号指针（accountKey = accounts/ 下的目录名） */
function ac2ReadActiveKey() {
  const j = readJsonOrNull(AC2_ACTIVE_FILE);
  return j && j.accountKey ? String(j.accountKey) : null;
}

/** 全部账号 profile（明文；含 accountKey 便于定位目录） */
function ac2ReadProfiles() {
  const out = [];
  try {
    for (const key of fs.readdirSync(AC2_ACCOUNTS_DIR)) {
      const p = readJsonOrNull(path.join(AC2_ACCOUNTS_DIR, key, 'account-profile.json'));
      if (p && p.profile && p.profile.accountId) out.push(Object.assign({ accountKey: key }, p.profile));
    }
  } catch (_) {}
  return out;
}

/** AutoClaw2 渲染进程 eval（页面 = zwork.html；window.zworkAuth 提供积分/会员 API） */
async function ac2CdpEval(jsExpr) {
  let list;
  try {
    const r = await fetch('http://127.0.0.1:' + CLIENT_PROFILES.ac.cdpPort + '/json/list', { signal: AbortSignal.timeout(1500) });
    list = await r.json();
  } catch (_) { return null; } // 未运行 / 未开调试端口
  const pages = (Array.isArray(list) ? list : []).filter((t) => t.type === 'page' && t.webSocketDebuggerUrl);
  const page = pages.find((t) => /zwork|autoclaw/i.test(String(t.url || '') + ' ' + String(t.title || '')));
  if (!page) return null;
  return cdpEvalOnWs(page.webSocketDebuggerUrl, jsExpr, 15000);
}

/** AutoClaw2 积分：余额 + 账本（含每笔过期时间）→ segments。
 *  账本 income（amount>0 且未过期）按过期时间升序构成积分包；
 *  消耗不按包摊销，差额并入最后一段，保证总额与 UI 一致。 */
/** AutoClaw2 账号列表：accounts/<key>/account-profile.json 全量（明文，免启动）；
 *  当前账号 = 指针指向的那个，排最前。AutoClaw2 无每日签到 → checkin 恒为 null。 */
function ac2ListAccounts() {
  const activeKey = ac2ReadActiveKey();
  const profiles = ac2ReadProfiles();
  const active = profiles.find((p) => p.accountKey === activeKey) || null;
  const currentUid = active ? String(active.accountId) : null;
  const sorted = profiles.slice().sort((a, b) => {
    const an = a.accountKey === activeKey ? -1 : 0;
    const bn = b.accountKey === activeKey ? -1 : 0;
    return (an - bn) || (Number(b.lastLoginAt || 0) - Number(a.lastLoginAt || 0));
  });
  return {
    currentUid,
    accounts: sorted.map((p) => ({
      uid: String(p.accountId),
      nickname: p.displayName || p.phone || String(p.numericUserId || ''),
      phone: p.phone || '',
      uin: p.numericUserId != null ? String(p.numericUserId) : '',
      loginMethod: '',
      tokenExpiresAt: null,
      refreshExpiresAt: null,
      lastRefreshTime: p.lastLoginAt ? p.lastLoginAt * 1000 : null,
      checkin: null,
    })),
  };
}

/** AutoClaw2 主进程是否在运行（tasklist 按新 exe 名） */
function ac2IsRunning() {
  if (isMac) return false;
  try {
    const out = execFileSync('tasklist', ['/FI', 'IMAGENAME eq AutoClaw2.exe', '/FO', 'CSV', '/NH'],
      { encoding: 'utf8', windowsHide: true });
    return out.includes('AutoClaw2.exe');
  } catch (_) { return false; }
}

/** AutoClaw2 切换账号：改 active-product-account.json 指针 + 重启客户端。
 *  凭据由 AutoClaw2 自己解密载入（app-bound，外部解不开），WorkPet 只翻指针。 */
async function ac2SwitchToAccount(uid) {
  const profiles = ac2ReadProfiles();
  const target = profiles.find((p) => String(p.accountId) === String(uid));
  if (!target) throw new Error('AutoClaw2 账号不存在');
  const activeKey = ac2ReadActiveKey();
  if (activeKey === target.accountKey) {
    return { uid, nickname: target.displayName || target.phone || uid, alreadyCurrent: true };
  }
  fs.mkdirSync(path.dirname(AC2_ACTIVE_FILE), { recursive: true });
  const tmp = AC2_ACTIVE_FILE + '.workpet-tmp';
  fs.writeFileSync(tmp, JSON.stringify({ schemaVersion: 1, accountKey: target.accountKey }, null, 2));
  fs.renameSync(tmp, AC2_ACTIVE_FILE);
  log('[client:ac] 已切换活跃账号指针 -> ' + target.accountKey.slice(0, 12) + '…');
  let relaunched = false;
  if (ac2IsRunning()) {
    killAutoClaw(); // 新旧 exe 名都会尝试
    for (let i = 0; i < 10 && ac2IsRunning(); i++) await sleep(500);
    try { const r = await acLaunchBinary(); relaunched = (r === 'launched' || r === 'reuse'); } catch (_) {}
    log('[client:ac] 切换前客户端在运行，已自动重启' + (relaunched ? '' : '（重启失败）'));
  }
  return { uid, nickname: target.displayName || target.phone || uid, relaunched };
}

/** AutoClaw2 积分：CDP 渲染进程 zworkAuth（余额 + 账本 → 含过期的 segments） */
async function ac2FetchCreditsViaCdp() {
  const expr = `(async () => {
    const a = window.zworkAuth;
    if (!a || typeof a.getCreditsBalance !== 'function') return { error: 'no-zworkAuth' };
    const balance = await a.getCreditsBalance();
    let ledgers = null;
    try { ledgers = await a.getCreditsLedgers({ flowDirection: 'all' }); } catch (e) { ledgers = null; }
    return { balance, ledgers };
  })()`;
  const r = await ac2CdpEval(expr);
  if (!r) throw new Error('AutoClaw2 未运行或未开启调试端口（请先点「启动 AutoClaw」）');
  if (r.error) throw new Error('AutoClaw2 渲染进程读取失败: ' + r.error);
  return ac2Segments(r.balance, r.ledgers);
}

function ac2Segments(balance, ledgers) {
  const total = Number((balance && balance.totalPoints) || 0);
  const nowSec = Math.floor(Date.now() / 1000);
  const entries = (ledgers && ledgers.entries) || [];
  const seg = [];
  for (const e of entries) {
    const amt = Number(e.amount || 0);
    const exp = Number(e.expiresAt || 0);
    if (amt > 0 && exp > nowSec) seg.push({ remaining: amt, total: amt, expiresAt: exp * 1000, source: e.description || '积分' });
  }
  seg.sort((a, b) => (a.expiresAt || 0) - (b.expiresAt || 0));
  const visible = seg.reduce((s, x) => s + x.remaining, 0);
  if (total > visible + 0.01) {
    if (seg.length) {
      seg[seg.length - 1].remaining += total - visible;
      seg[seg.length - 1].total += total - visible;
    } else {
      seg.push({ remaining: total, total, expiresAt: null, source: '积分' });
    }
  }
  if (!seg.length && total > 0) seg.push({ remaining: total, total, expiresAt: null, source: '积分' });
  return { credits: total, segments: seg, count: seg.length };
}
const AC_API_HOST = 'https://autoglm-acceleration-api.zhipuai.cn';
const AC_APP_ID = '100003';
const AC_APP_KEY = '38d2391985e2369a5fb8227d8e6cd5e5';

// ---------------- CodeArts Agent（华为云 CodeArts IDE 客户端，独立账号体系） ----------------
// 无签到：额度按官方政策自动发放（不写死任何数字）。WorkPet 只做「多账号登录态管理 + 一键切换」。
// 登录态 = VSCode 系数据目录 User/globalStorage/state.vscdb（SQLite ItemTable）里的两个键：
//   1) secret://{"extensionId":"huaweicloud.authentication","key":"HuaweiCloudSession"}
//      值为 {"type":"Buffer","data":[...]} 包装的 Electron safeStorage v10 密文，
//      密钥获取按平台分（与 AutoClaw 同构）：
//        Windows：AES-256-GCM，key 在数据目录 Local State 的 os_crypt.encrypted_key（DPAPI 包裹）；
//        macOS：AES-128-CBC（IV 固定 16 空格），key = PBKDF2(钥匙串随机密码, 'saltysalt', 1003 次, 16B, sha1)，
//          钥匙串条目 service "CodeArts Agent Safe Storage" / account "CodeArts Agent"（实测确认）。
//      明文含 refresh_token（长期）+ 临时 IAM 凭证 expires_at（约 1h，客户端运行期间自动续）；
//   2) huaweicloud.codearts-snap 键内含 userInfoKey（账号 id / 华为账号用户名 / 临时凭证快照）。
// 切换 = 停客户端（IDE 会持有/回写 vscdb）→ 备份库密文写回 vscdb（同机原样写回；跨机导入的备份
//   用 secretPlain 以本机 key 重加密）→ 同步内核侧 .codeartsdoer 的 userInfo.json → 按需重启客户端。
const CA_SECRET_KEY_DEFAULT = 'secret://{"extensionId":"huaweicloud.authentication","key":"HuaweiCloudSession"}';
const CA_SNAP_KEY = 'huaweicloud.codearts-snap';
const CA_IDE_EXE = 'codearts-agent.exe';
// Electron safeStorage 在 macOS 把随机密码存进登录钥匙串（与 AutoClaw 同构）。
// 实测：-w 读密码必须同时带 -a，只给 -s 会报条目不存在。
const CA_MAC_KEYCHAIN_SERVICE = 'CodeArts Agent Safe Storage';
const CA_MAC_KEYCHAIN_ACCOUNT = 'CodeArts Agent';
const CA_MAC_PBKDF2_SALT = Buffer.from('saltysalt', 'utf8');
const CA_MAC_PBKDF2_ITERS = 1003;
// macOS 主进程识别：路径形如 …/CodeArts Agent.app/Contents/MacOS/Electron（CFBundleExecutable
// 固定为 "Electron"），Helper 子进程路径不含该子串，不会误伤。
// 实测坑：Electron 主进程的 argv 区会被框架改写，pgrep/pkill -f 读不到它（Helper 却正常），
// 进程检测/终止一律走 ps 全量枚举 + kill，绝不能用 pgrep/pkill。
const CA_MAC_PROCESS_RE = /CodeArts[ _-]?Agent\.app\/Contents\/MacOS\/Electron(?: |$)/;
// macOS AgentKernel 内核进程（路径形如 ~/.codeartsdoer/CodeArts_Agent/AgentKernel_*，名字带版本号）
const CA_MAC_KERNEL_RE = /CodeArts_Agent\/AgentKernel_/;
function detectCodeArtsDataDir() {
  if (process.env.WORKPET_CODEARTS_DIR) {
    const d = process.env.WORKPET_CODEARTS_DIR;
    if (fs.existsSync(path.join(d, 'User', 'globalStorage', 'state.vscdb'))) return d;
  }
  // macOS: ~/Library/Application Support；Windows: %APPDATA%（目录名两平台都形如 "CodeArts Agent"）
  const roots = isMac
    ? [path.join(os.homedir(), 'Library', 'Application Support')]
    : [process.env.APPDATA || path.join(os.homedir(), 'AppData', 'Roaming')];
  for (const root of roots) {
    let names = [];
    try { names = fs.readdirSync(root).filter((n) => /^codearts[-_ ]?agent$/i.test(n)); } catch (_) {}
    for (const n of names) {
      const d = path.join(root, n);
      if (fs.existsSync(path.join(d, 'User', 'globalStorage', 'state.vscdb'))) return d;
    }
  }
  return null;
}
const CA_DATA_DIR = detectCodeArtsDataDir();
const CA_VSCDB = CA_DATA_DIR ? path.join(CA_DATA_DIR, 'User', 'globalStorage', 'state.vscdb') : null;
const CA_LOCAL_STATE = CA_DATA_DIR ? path.join(CA_DATA_DIR, 'Local State') : null;
// CodeArts Agent（Doer 内核）侧的用户身份文件：切换账号时一并换回，保持内核会话一致
const CA_DOER_USERINFO = path.join(os.homedir(), '.codeartsdoer', 'codearts-data', 'storage', 'userInfo.json');
// macOS 主二进制名固定为 "Electron"，且安装位置不限于 /Applications（找不到时 caFindExe 会从运行中进程反查）
const CA_MAC_EXE_CANDIDATES = [
  '/Applications/CodeArts Agent.app/Contents/MacOS/Electron',
  path.join(os.homedir(), 'Applications', 'CodeArts Agent.app', 'Contents', 'MacOS', 'Electron'),
];
const CA_EXE_CANDIDATES = (process.env.WORKPET_CODEARTS_BIN ? [process.env.WORKPET_CODEARTS_BIN] : []).concat(isMac ? CA_MAC_EXE_CANDIDATES : [
  'D:/Program Files/CodeArts Agent/' + CA_IDE_EXE,
  path.join(process.env.ProgramFiles || 'C:/Program Files', 'CodeArts Agent', CA_IDE_EXE),
  path.join(process.env['ProgramFiles(x86)'] || 'C:/Program Files (x86)', 'CodeArts Agent', CA_IDE_EXE),
  path.join(process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local'), 'Programs', 'CodeArts Agent', CA_IDE_EXE),
]);

// ---------------- AStudio（AStudio 桌面端，Electron，独立账号体系） ----------------
// 登录态 = <数据目录>/userdata/astron-session.json（纯明文 JSON：accountId/uid/token/
//   ssoSessionId/banned/modelBearerToken/loginMethod/loggedInAt/nickname/mobile）。
// 业务数据 = AStudio 本地 HTTP 服务（端口每次启动随机，记在 userdata/server-runtime.json），
//   鉴权 token 只存在于渲染进程内存，由 window.desktopBridge.getWsUrl() 暴露
//   （形如 ws://127.0.0.1:<port>/?token=<localToken>），因此一律经 CDP 在渲染进程内 fetch
//   —— 与 wb 经 CDP 取明文 token 是同一思路，且完全不触碰 app.asar。
// 签到 = 推广弹窗系统：GET /api/astron-client-popups/pending，命中
//   componentType==='DAILY_REWARD_DIALOG' 且 popupId 为正整数后
//   POST /api/astron-client-popups/complete {popupId, instanceKey}
//   （注意：/claim 是一次性「客户端下载奖励」claimAstronClientDownloadReward，不是每日积分；
//     另需过滤 popupId 为负、instanceKey==='DEV_PREVIEW' 的客户端预览夹具）
// 切换 = 停客户端（并等 state.sqlite.lifecycle-lock 释放）→ 写 astron-session.json →
//   同步所有 config.toml 的 [model_providers.astron-spark]（experimental_bearer_token + uid）
//   → 原样带 CDP 重启。与官方 persistAstronAuthState 的落盘路径一致。
const AS_DATA_DIR_NAME = 'AStudio Data';
const AS_EXE_NAME = 'AStudio.exe';
const AS_CDP_PORT = 9230; // 必须与 CLIENT_PROFILES.as.cdpPort 一致
const AS_PROVIDER_SECTION = '[model_providers.astron-spark]';
const AS_PROVIDER_NAME = 'Astron Spark';
const AS_PROVIDER_TOKEN_KEY = 'experimental_bearer_token';
const AS_PROVIDER_UID_KEY = 'uid';

/** Windows 常见安装根目录（多盘符/多 Program Files 并列搜索）：
 *  环境变量优先（Program Files → x86 → ProgramW6432 → LOCALAPPDATA\Programs → LOCALAPPDATA），
 *  最后兜底常见字面路径（部分机器装在 D 盘且未改环境变量）。不与任何单一绝对路径绑定。 */
function winProgramRoots() {
  const out = [];
  const add = (p) => { if (p && !out.includes(p)) out.push(p); };
  add(process.env.ProgramFiles);
  add(process.env['ProgramFiles(x86)']);
  add(process.env.ProgramW6432);
  const lad = process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local');
  add(path.join(lad, 'Programs'));
  add(lad);
  add('C:/Program Files');
  add('C:/Program Files (x86)');
  add('D:/Program Files');
  return out;
}

const AS_EXE_CANDIDATES = (process.env.WORKPET_ASTUDIO_BIN ? [process.env.WORKPET_ASTUDIO_BIN] : []).concat(isMac ? [
  '/Applications/AStudio.app/Contents/MacOS/AStudio',
] : winProgramRoots().map((root) => path.join(root, 'AStudio', AS_EXE_NAME)));

function detectAstudioExe() {
  for (const p of AS_EXE_CANDIDATES) {
    try { if (fs.existsSync(p) && fs.statSync(p).isFile()) return p; } catch (_) {}
  }
  return null;
}

/** 便携数据目录：与安装目录同级的「AStudio Data」（安装到哪就在其上级目录旁）。
 *  多根搜索：env 覆盖 → 安装位置同级 → 各常见 Program Files / 用户目录（含 x86 与 LOCALAPPDATA\Programs）。
 *  用 3 个标记文件判定；装在任何盘符/目录都能找到，找不到返回 null。 */
function detectAstudioDataDir() {
  const env = process.env.WORKPET_ASTUDIO_DIR;
  if (env && fs.existsSync(env)) return env;
  const cands = [];
  // 1) 由检测到的安装位置推导（覆盖自定义安装目录，如 D:\Apps\AStudio\）
  const exe = detectAstudioExe();
  if (exe) cands.push(path.join(path.dirname(path.dirname(exe)), AS_DATA_DIR_NAME));
  // 2) 多根目录并列搜索（C/D 盘 Program Files、x86、LOCALAPPDATA 及其 Programs 都在列）
  for (const root of winProgramRoots()) cands.push(path.join(root, AS_DATA_DIR_NAME));
  for (const d of cands) {
    try {
      if (fs.existsSync(path.join(d, 'userdata', 'astron-session.json'))
        || fs.existsSync(path.join(d, 'acode-home-overlay', 'config.toml'))
        || fs.existsSync(path.join(d, 'userdata', 'state.sqlite'))) return d;
    } catch (_) {}
  }
  return env || null; // 未安装 AStudio：as 全部能力安全降级为空
}

const AS_DATA_DIR = detectAstudioDataDir();
const AS_SESSION_FILE = AS_DATA_DIR ? path.join(AS_DATA_DIR, 'userdata', 'astron-session.json') : null;
const AS_LOCK_FILE = AS_DATA_DIR ? path.join(AS_DATA_DIR, 'userdata', 'state.sqlite.lifecycle-lock', 'owner.json') : null;
// config.toml 有两份（acode-home-overlay 与内核 runtime/acode-home），都含同一段 model_providers
const AS_CONFIG_FILES = AS_DATA_DIR ? [
  path.join(AS_DATA_DIR, 'acode-home-overlay', 'config.toml'),
  path.join(AS_DATA_DIR, 'runtime', 'acode-home', 'config.toml'),
].filter((p) => { try { return fs.existsSync(p); } catch (_) { return false; } }) : [];
let asSwitching = false; // 切换过程中挂起 watcher 同步，避免读到中间态

/** 读取 astron-session.json（纯明文；缺失/损坏返回 null） */
function asReadSession() {
  if (!AS_SESSION_FILE) return null;
  const raw = readJsonOrNull(AS_SESSION_FILE);
  return raw && raw.uid ? raw : null;
}

/** 原子写回登录态（与官方一致写整个 session 对象） */
function asWriteSession(session) {
  if (!AS_SESSION_FILE) throw new Error('未找到 AStudio 数据目录（请先安装并登录一次）');
  fs.mkdirSync(path.dirname(AS_SESSION_FILE), { recursive: true });
  const tmp = AS_SESSION_FILE + '.workpet-tmp';
  fs.writeFileSync(tmp, JSON.stringify(session, null, 2));
  fs.renameSync(tmp, AS_SESSION_FILE);
}

/** config.toml 的 [model_providers.astron-spark] 段手术（无 TOML 库，纯字符串处理）。
 *  行为对齐官方 updateAcodeToken：定位段头 → 只在段内替换两个键 → 缺失则插到段尾 →
 *  整段缺失则创建；值一律 JSON.stringify 加双引号。 */
function asPatchProviderConfig(text, token, uid) {
  const lines = String(text || '').split('\n');
  const q = (v) => JSON.stringify(String(v));
  const tokenRe = new RegExp('^\\s*' + AS_PROVIDER_TOKEN_KEY + '\\s*=');
  const uidRe = new RegExp('^\\s*' + AS_PROVIDER_UID_KEY + '\\s*=');
  const head = lines.findIndex((l) => l.trim() === AS_PROVIDER_SECTION);
  if (head < 0) {
    if (!token && !uid) return text;
    if (lines.length && lines[lines.length - 1].trim()) lines.push('');
    lines.push(AS_PROVIDER_SECTION, 'name = ' + q(AS_PROVIDER_NAME));
    if (token) lines.push(AS_PROVIDER_TOKEN_KEY + ' = ' + q(token));
    if (uid) lines.push(AS_PROVIDER_UID_KEY + ' = ' + q(uid));
    lines.push('');
    return lines.join('\n');
  }
  let end = lines.length;
  for (let i = head + 1; i < lines.length; i++) {
    if (/^\s*\[/.test(lines[i])) { end = i; break; }
  }
  const apply = (re, key, val) => {
    if (!val) return;
    const i = lines.findIndex((l, idx) => idx > head && idx < end && re.test(l));
    if (i >= 0) lines[i] = key + ' = ' + q(val);
    else { lines.splice(end, 0, key + ' = ' + q(val)); end++; }
  };
  apply(tokenRe, AS_PROVIDER_TOKEN_KEY, token);
  apply(uidRe, AS_PROVIDER_UID_KEY, uid);
  return lines.join('\n');
}

/** 把 uid/modelBearerToken 同步进所有 config.toml；返回改动的文件数 */
function asWriteProviderConfig(uid, modelBearerToken) {
  let changed = 0;
  for (const file of AS_CONFIG_FILES) {
    try {
      const prev = fs.readFileSync(file, 'utf8');
      const next = asPatchProviderConfig(prev, modelBearerToken, uid);
      if (next !== prev) {
        const tmp = file + '.workpet-tmp';
        fs.writeFileSync(tmp, next);
        fs.renameSync(tmp, file);
        changed++;
      }
    } catch (e) { log('[client:as] 写 config.toml 失败 ' + file + ': ' + e.message); }
  }
  return changed;
}

// ---------------- AStudio 云端直连（无需启动 AStudio） ----------------
// 逆向自 AStudio 3.4.1（app.asar astronAccountGateway / buildAstronCookieHeader），
// 并已实测：agent.xfyun.cn/xingchen-studio/* 接受「Cookie + clientType + studioVersion」。
// 鉴权四件套全部来自明文 astron-session.json，因此积分查询与每日积分签到都可以免启动。
const AS_CLOUD_BASE = 'https://agent.xfyun.cn';
const AS_CLIENT_TYPE = isMac ? '22' : '21'; // resolveAstronStudioClientType: win32=21 / darwin=22

let asAppVersionCache = null;
function asResolveAppVersion() {
  if (asAppVersionCache) return asAppVersionCache;
  try {
    const exe = detectAstudioExe();
    if (exe) {
      const v = fs.readFileSync(path.join(path.dirname(exe), 'version'), 'utf8').trim();
      if (v) { asAppVersionCache = v.split('-', 1)[0] || v; return asAppVersionCache; }
    }
  } catch (_) {}
  asAppVersionCache = '3.4.1'; // 兜底：读不到安装目录 version 文件时用已知近期版本
  return asAppVersionCache;
}

function asCloudHeaders(session) {
  return {
    accept: 'application/json',
    cookie: [
      session.ssoSessionId ? `ssoSessionId=${session.ssoSessionId}` : null,
      session.ssoSessionId ? `sso_sessionid=${session.ssoSessionId}` : null,
      `account_id=${session.accountId}`,
      `token=${session.token}`,
    ].filter(Boolean).join('; '),
    clienttype: AS_CLIENT_TYPE,
    studioversion: asResolveAppVersion(),
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) AStudio/3.4.1 Chrome/144.0.7559.236 Electron/40.10.6 Safari/537.36',
  };
}

/** 云端请求（不经 AStudio 本地服务）：返回 envelope.data；业务失败抛错。
 *  响应契约：{flag:true, code:0, data} = 成功；flag=false 时 desc 为可读错误。 */
async function asCloudRequest(pathName, init) {
  const session = asReadSession();
  if (!session || !session.uid || !session.ssoSessionId) {
    throw new Error('AStudio 未登录或登录态不完整（astron-session.json）');
  }
  const qs = 'ssoSessionId=' + encodeURIComponent(String(session.ssoSessionId))
    + '&account_id=' + encodeURIComponent(String(session.accountId || session.uid));
  const r = await fetch(AS_CLOUD_BASE + pathName + '?' + qs, Object.assign({
    headers: asCloudHeaders(session),
    signal: AbortSignal.timeout(10000),
  }, init || {}));
  const raw = await r.text();
  let env;
  try { env = JSON.parse(raw); } catch (_) { throw new Error('云端响应解析失败 (HTTP ' + r.status + '): ' + raw.slice(0, 100)); }
  if (!r.ok || !env || env.flag !== true || env.code !== 0) {
    const desc = String((env && env.desc) || raw.slice(0, 80) || ('HTTP ' + r.status));
    if (r.status === 401 || /失效|过期|重新登录|未登录|signed/i.test(desc)) {
      throw new Error('AStudio 登录态已失效，请打开 AStudio 重新登录');
    }
    throw new Error('云端接口失败: ' + desc);
  }
  return env.data;
}

/** AStudio 主进程是否在运行 */
function asIsRunning() {
  if (isMac) return false;
  try {
    const out = execFileSync('tasklist', ['/FI', 'IMAGENAME eq ' + AS_EXE_NAME, '/FO', 'CSV', '/NH'],
      { encoding: 'utf8', windowsHide: true });
    return out.includes(AS_EXE_NAME);
  } catch (_) { return false; }
}

/** 单实例锁是否仍被持有（owner.json 里的 pid 还活着）——AStudio 启动时会检查该锁 */
function asLockHeld() {
  if (!AS_LOCK_FILE) return false;
  const o = readJsonOrNull(AS_LOCK_FILE);
  if (!o || !o.pid) return false;
  const pid = Number(o.pid);
  if (!pid) return false;
  try {
    if (process.platform === 'win32') {
      const out = execFileSync('tasklist', ['/FI', 'PID eq ' + pid, '/FO', 'CSV', '/NH'],
        { encoding: 'utf8', windowsHide: true });
      return new RegExp('\\b' + pid + '\\b').test(out);
    }
    process.kill(pid, 0);
    return true;
  } catch (_) { return false; }
}

/** 停 AStudio：先优雅关（/T），等不到再强杀，最后等单实例锁释放 */
async function asKillApp() {
  if (isMac || !detectAstudioExe()) return;
  try { execFileSync('taskkill', ['/IM', AS_EXE_NAME, '/T'], { stdio: 'ignore', windowsHide: true }); } catch (_) {}
  for (let i = 0; i < 8 && asIsRunning(); i++) await sleep(1000);
  if (asIsRunning()) {
    try { execFileSync('taskkill', ['/IM', AS_EXE_NAME, '/F', '/T'], { stdio: 'ignore', windowsHide: true }); } catch (_) {}
    for (let i = 0; i < 4 && asIsRunning(); i++) await sleep(500);
  }
  for (let i = 0; i < 16 && asLockHeld(); i++) await sleep(500);
  if (asLockHeld()) log('[client:as] 警告：lifecycle-lock 仍未释放，AStudio 可能拒绝启动');
}

/** 带 CDP 调试端口拉起 AStudio（daemon 侧；UI 按钮走 Rust 的 launch_astudio） */
function asLaunchApp() {
  const exe = detectAstudioExe();
  if (!exe) return false;
  try {
    spawn(exe, ['--remote-debugging-port=' + AS_CDP_PORT], { detached: true, stdio: 'ignore', windowsHide: true }).unref();
    return true;
  } catch (_) { return false; }
}

/** 在 AStudio 渲染进程里执行 JS（页面 target = acode://app/index.html…） */
async function asCdpEval(jsExpr) {
  if (!AS_DATA_DIR) return null;
  let list;
  try {
    const r = await fetch('http://127.0.0.1:' + AS_CDP_PORT + '/json/list', { signal: AbortSignal.timeout(1500) });
    list = await r.json();
  } catch (_) { return null; } // 未运行 / 未开调试端口
  const pages = (Array.isArray(list) ? list : []).filter((t) => t.type === 'page' && t.webSocketDebuggerUrl);
  const page = pages.find((t) => /^acode:\/\/app\//i.test(String(t.url || '')))
    || pages.find((t) => /acode|astudio/i.test(String(t.url || '') + ' ' + String(t.title || '')));
  if (!page) return null;
  return cdpEvalOnWs(page.webSocketDebuggerUrl, jsExpr, 15000);
}

/**
 * ⚠️ 本函数体经 fn.toString() 送进 AStudio 渲染进程执行
 * （'(' + asApiImpl.toString() + ')("xxx")' → CDP Runtime.evaluate returnByValue+awaitPromise）。
 * 因此：1) 绝不可引用本文件内的任何外部变量；2) 参数与返回值必须可 JSON 序列化。
 * action: 'session' | 'points' | 'daily'
 */
async function asApiImpl(action) {
  const b = window.desktopBridge;
  if (!b || typeof b.getWsUrl !== 'function') return { error: 'no-desktopBridge' };
  let wsUrl;
  try { wsUrl = String(await b.getWsUrl()); } catch (e) { return { error: 'getWsUrl-failed:' + ((e && e.message) || e) }; }
  let u;
  try { u = new URL(wsUrl); } catch (e) { return { error: 'bad-ws-url:' + wsUrl }; }
  const origin = 'http://' + u.host;
  const tok = u.searchParams.get('token') || '';
  const withTok = (p) => origin + p + '?token=' + encodeURIComponent(tok);
  const call = (p, init) => fetch(withTok(p), init)
    .then((r) => r.json().then((j) => ({ status: r.status, body: j })).catch(() => ({ status: r.status, body: null })))
    .catch((e) => ({ status: 0, body: null, error: String((e && e.message) || e) }));
  const get = (p) => call(p, { method: 'GET' });
  const post = (p, body) => call(p, {
    method: 'POST',
    headers: body === undefined ? undefined : { 'content-type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const pick = (r) => (r && r.body) || null;
  const port = u.port || '';
  // 客户端预览夹具（popupId 为负 / instanceKey=DEV_PREVIEW）必须排除，否则会误判为真实每日奖励
  const isRealPopup = (p) => !!(p && Number.isSafeInteger(p.popupId) && p.popupId > 0
    && p.instanceKey && p.instanceKey !== 'DEV_PREVIEW');
  const dailies = (list) => (Array.isArray(list) ? list : []).filter((p) => p && p.componentType === 'DAILY_REWARD_DIALOG' && isRealPopup(p));

  if (action === 'session') {
    const profile = await get('/api/astron-auth/user-profile');
    return { port: port, profile: pick(profile) };
  }
  if (action === 'points') {
    const bal = await get('/api/astron-auth/points-balance');
    const mem = await get('/api/astron-auth/membership');
    const sum = await get('/api/astron-client-popups/points-summary');
    return { port: port, balance: pick(bal), membership: pick(mem), summary: pick(sum) };
  }
  if (action === 'daily') {
    const before = pick(await get('/api/astron-client-popups/pending'));
    const list = (before && Array.isArray(before.popups)) ? before.popups : [];
    const daily = dailies(list)[0] || null;
    if (!daily) {
      return { port: port, pending: list.length, daily: false, already: true, balance: pick(await get('/api/astron-auth/points-balance')) };
    }
    const c = await post('/api/astron-client-popups/complete', { popupId: daily.popupId, instanceKey: daily.instanceKey });
    const after = pick(await get('/api/astron-client-popups/pending'));
    const list2 = (after && Array.isArray(after.popups)) ? after.popups : [];
    return {
      port: port, pending: list.length, daily: true,
      popupCode: daily.popupCode || null,
      points: (daily.payload && daily.payload.points) || null,
      completeStatus: c.status,
      completeError: (c.body && (c.body.error || c.body.desc || c.body.message)) || c.error || null,
      completed: dailies(list2).length === 0,
      remaining: list2.length,
      balance: pick(await get('/api/astron-auth/points-balance')),
    };
  }
  return { error: 'bad-action:' + action };
}

/** 刷新当前账号（昵称/手机号）：云端 userInfo 优先（免启动），CDP user-profile 兜底。
 *  记录始终以「本机 session 文件的 uid」为准 —— 那才是这份登录态真正属于的账号；
 *  云端/CDP 只刷新显示字段，uid 不一致时不合并（避免把别人的 session 记到别的账号上）。
 *  失败由调用方静默（仍返回账号库备份）。 */
async function asRefreshCurrentAccount() {
  const session = asReadSession();
  if (!session || !session.uid) throw new Error('AStudio 未登录（astron-session.json 缺失）');
  const uid = String(session.uid);
  let nickname = session.nickname || uid;
  let phone = session.mobile || '';
  // 云端 userInfo（免启动；只刷新显示字段）
  try {
    const d = await asCloudRequest('/xingchen-studio/userInfo');
    const u = (d && d.userInfo) || {};
    if (String(u.uid || '') === uid) {
      nickname = u.nickname || nickname;
      phone = u.login || phone;
    }
  } catch (_) {
    // CDP 兜底（AStudio 以调试模式运行时可用）
    try {
      const obj = await asCdpEval('(' + asApiImpl.toString() + ')("session")');
      const sess = obj && obj.profile && obj.profile.session;
      if (sess && String(sess.uid) === uid) {
        nickname = sess.nickname || nickname;
        phone = sess.mobile || phone;
      }
    } catch (_) {}
  }
  const store = loadStore();
  const rec = {
    uid,
    nickname,
    phone,
    loginMethod: session.loginMethod || '',
    session, // 完整登录态快照（切换时整文件写回）
    tokenExpiresAt: null,
    backedUpAt: Date.now(),
  };
  const i = store.as.accounts.findIndex((x) => x && String(x.uid) === uid);
  if (i >= 0) store.as.accounts[i] = Object.assign({}, store.as.accounts[i], rec);
  else store.as.accounts.push(rec);
  store.as.current = Object.assign({}, store.as.accounts[i >= 0 ? i : store.as.accounts.length - 1]);
  saveStore(store);
  return { uid, nickname };
}

/** 列出 AStudio 全部账号（当前登录 + 账号库；记录形如 ac 的扁平结构） */
function asListAccounts() {
  clientSyncStore('as');
  const store = loadStore();
  const currentRaw = clientReadAuth('as');
  const currentUid = currentRaw && currentRaw.account ? String(currentRaw.account.uid) : null;
  const seen = new Set();
  const list = [];
  const push = (raw) => {
    if (!raw || !raw.uid) return;
    const uid = String(raw.uid);
    if (seen.has(uid)) return;
    seen.add(uid);
    list.push({
      uid,
      nickname: wbStr(raw.nickname) || uid,
      phone: wbStr(raw.phone) || '',
      uin: '',
      loginMethod: raw.loginMethod || '',
      tokenExpiresAt: null,   // astron-session.json 无到期字段，只有 loggedInAt
      refreshExpiresAt: null,
      lastRefreshTime: null,
    });
  };
  if (currentRaw) {
    push({
      uid: currentRaw.account.uid,
      nickname: currentRaw.account.nickname,
      phone: currentRaw.account.phoneNumber,
      loginMethod: (currentRaw.session && currentRaw.session.loginMethod) || '',
    });
  }
  for (const a of store.as.accounts) push(a);
  list.sort((a, b) => (a.uid === currentUid ? -1 : b.uid === currentUid ? 1 : 0));
  const cache = clientLoadCheckinCache('as');
  const today = todayStrLocal();
  return {
    currentUid,
    accounts: list.map((a) => Object.assign(a, {
      checkin: cache[a.uid] && cache[a.uid].date === today && !clientCheckinState.as.inFlight
        ? { ok: !!cache[a.uid].ok, already: !!cache[a.uid].already, code: cache[a.uid].code, message: cache[a.uid].message }
        : null,
    })),
  };
}

/** points-balance 的 activity/member/buy 三个桶 → 前端积分段 */
function asSegments(balance) {
  const b = balance || {};
  const seg = [];
  const push = (rem, tot, source) => {
    const r = Number(rem || 0);
    if (r > 0) seg.push({ remaining: r, total: Number(tot || r), expiresAt: null, source });
  };
  push(b.activityBalance, b.activityTotal, '活动积分');
  push(b.memberBalance, b.memberTotal, '会员积分');
  push(b.buyBalance, b.buyTotal, '购买积分');
  const total = Number(b.totalBalance != null ? b.totalBalance : (b.totalAmount || 0));
  const visible = seg.reduce((s, x) => s + x.remaining, 0);
  if (total > visible + 0.01) seg.push({ remaining: total - visible, total: total - visible, expiresAt: null, source: '其他积分' });
  if (!seg.length && total > 0) seg.push({ remaining: total, total, expiresAt: null, source: '积分' });
  return { credits: total, segments: seg, count: seg.length };
}

/** 每日积分（签到）：云端直连优先（免启动，pending → complete）；失败回落 CDP。
 *  ⚠️ 只认 popupId 为正整数且非 DEV_PREVIEW 的真实弹窗（客户端预览夹具不能回传）。 */
function asPickDailyPopup(list) {
  return (Array.isArray(list) ? list : []).find((p) => p && p.componentType === 'DAILY_REWARD_DIALOG'
    && Number.isSafeInteger(p.popupId) && p.popupId > 0
    && p.instanceKey && p.instanceKey !== 'DEV_PREVIEW') || null;
}

async function asDailyCheckin() {
  // —— 云端直连（无需启动 AStudio）——
  try {
    const pending = await asCloudRequest('/xingchen-studio/client-popups/pending');
    const daily = asPickDailyPopup(pending);
    if (!daily) return { ok: true, already: true, code: 0, message: '今日无每日积分弹窗' };
    await asCloudRequest('/xingchen-studio/client-popups/complete', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ popupId: daily.popupId, instanceKey: daily.instanceKey }),
    });
    return { ok: true, already: false, code: 0, message: '每日积分已领取' + ((daily.payload && daily.payload.points) ? ' +' + daily.payload.points : '') };
  } catch (cloudErr) {
    // —— 回落：CDP（AStudio 以调试模式运行时走本地服务）——
    const r = await asCdpEval('(' + asApiImpl.toString() + ')("daily")').catch(() => null);
    if (r && !r.error) {
      if (!r.daily) return { ok: true, already: true, code: 0, message: '今日无每日积分弹窗' };
      if (r.completed) return { ok: true, already: false, code: 0, message: '每日积分已领取' + (r.points ? ' +' + r.points : '') };
      return { ok: false, code: -1, message: '每日积分领取失败: ' + (r.completeError || ('HTTP ' + r.completeStatus)) };
    }
    return { ok: false, code: -1, message: '签到失败: ' + cloudErr.message };
  }
}

/** AStudio 积分查询：云端直连优先（免启动）；失败回落 CDP */
async function asFetchCredits() {
  let cloudErr = null;
  try {
    const b = await asCloudRequest('/xingchen-studio/points/balance');
    return asSegments(b);
  } catch (e) { cloudErr = e; }
  // 回落：CDP（AStudio 以调试模式运行时可用；云端失败多半是登录态问题，App 侧可续期）
  const r = await asCdpEval('(' + asApiImpl.toString() + ')("points")').catch(() => null);
  if (r && !r.error && r.balance) return asSegments(r.balance);
  throw cloudErr || new Error('AStudio 未运行或未开启调试端口（请先点「启动 AStudio」）');
}

/** AStudio 一键切换：停客户端（等单实例锁释放）→ 写 astron-session.json →
 *  同步所有 config.toml → 原本在运行则带 CDP 重启。 */
async function asSwitchToAccount(uid) {
  const store = loadStore();
  const idx = store.as.accounts.findIndex((x) => x && String(x.uid) === String(uid));
  if (idx < 0) throw new Error('账号备份不存在');
  const rec = store.as.accounts[idx];
  if (!rec.session || !rec.session.uid) throw new Error('该备份缺少登录态（session），无法切换');
  if (!AS_SESSION_FILE) throw new Error('未找到 AStudio 数据目录（请先安装并登录一次）');
  // 目标就是当前登录账号 → 直接返回。既避免无谓地杀进程/重启，
  // 也避免用可能已过期的备份 session（token 轮换过）覆盖本机新鲜登录态。
  const live = asReadSession();
  if (live && String(live.uid) === String(uid)) {
    return { uid, nickname: rec.nickname || uid, relaunched: false, alreadyCurrent: true, configFiles: 0 };
  }
  const wasRunning = asIsRunning();
  asSwitching = true;
  try {
    if (wasRunning) { log('[client:as] 停止 AStudio 以写入登录态…'); await asKillApp(); }
    asWriteSession(rec.session);
    const n = asWriteProviderConfig(rec.session.uid, rec.session.modelBearerToken || '');
    log('[client:as] 已写回 astron-session.json；config.toml 更新 ' + n + '/' + AS_CONFIG_FILES.length + ' 处');
    const st2 = loadStore();
    const i2 = st2.as.accounts.findIndex((x) => x && String(x.uid) === String(uid));
    if (i2 >= 0) st2.as.current = Object.assign({}, st2.as.accounts[i2]);
    saveStore(st2);
    let relaunched = false;
    if (wasRunning) {
      relaunched = asLaunchApp();
      log('[client:as] 切换前客户端在运行，已自动重启' + (relaunched ? '' : '（重启失败）'));
    }
    return { uid, nickname: rec.nickname || uid, relaunched, configFiles: n };
  } finally {
    asSwitching = false;
  }
}

// ---------------- ZCode（Z.ai Coding Plan 客户端）：账号备份/切换（无签到） ----------------
// 登录态：~/.zcode/v2/credentials.json（自定义 enc:v1: AES-256-GCM，key = sha256(secret)，
// secret = env.ZCODE_CREDENTIAL_SECRET || `zcode-credential-fallback:${platform}:${homedir}:${username}`）。
// 账号切换 = 整文件快照写回 + 重启 ZCode（与 AStudio 同思路）；本客户端无每日签到/无积分接口。
const ZC_HOME_DIR = path.join(os.homedir(), '.zcode');
const ZC_EXE_NAME = 'ZCode.exe';
// 多根搜索（C/D 盘 Program Files、x86、LOCALAPPDATA 及其 Programs），另带 Preview 版
const ZC_EXE_CANDIDATES = (process.env.WORKPET_ZCODE_BIN ? [process.env.WORKPET_ZCODE_BIN] : []).concat(isMac ? [
  '/Applications/ZCode.app/Contents/MacOS/ZCode',
] : winProgramRoots().map((root) => path.join(root, 'zcode', ZC_EXE_NAME)).concat([
  path.join(process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local'), 'Programs', 'ZCode Preview', 'ZCode Preview.exe'),
]));
// Preview 版进程名是 'ZCode Preview.exe'；kill 时两种名字都试
const ZC_KILL_NAMES = ['ZCode.exe', 'ZCode Preview.exe'];

function detectZcodeExe() {
  for (const p of ZC_EXE_CANDIDATES) {
    try { if (fs.existsSync(p) && fs.statSync(p).isFile()) return p; } catch (_) {}
  }
  return null;
}

/** 定位凭据文件：~/.zcode 下 vN 目录里的 credentials.json（取最近修改的一份）；未安装/未登录返回 null */
function detectZcodeCredFile() {
  const env = process.env.WORKPET_ZCODE_CRED_FILE;
  if (env && fs.existsSync(env)) return env;
  try {
    const cands = fs.readdirSync(ZC_HOME_DIR, { withFileTypes: true })
      .filter((e) => e.isDirectory() && /^v\d+$/.test(e.name))
      .map((e) => path.join(ZC_HOME_DIR, e.name, 'credentials.json'))
      .filter((f) => { try { return fs.existsSync(f); } catch (_) { return false; } });
    if (cands.length) {
      cands.sort((a, b) => { try { return fs.statSync(b).mtimeMs - fs.statSync(a).mtimeMs; } catch (_) { return 0; } });
      return cands[0];
    }
  } catch (_) {}
  return null;
}
let ZC_CRED_FILE = detectZcodeCredFile();

/** 凭据文件路径（懒探测：daemon 先于 ZCode 启动也能在安装/登录后被识别） */
function zcCredFilePath() {
  if (!ZC_CRED_FILE || !fs.existsSync(ZC_CRED_FILE)) ZC_CRED_FILE = detectZcodeCredFile();
  return ZC_CRED_FILE;
}

function zcSecret() {
  if (process.env.ZCODE_CREDENTIAL_SECRET) return process.env.ZCODE_CREDENTIAL_SECRET;
  let user = 'unknown';
  try { user = os.userInfo().username; } catch (_) {}
  return 'zcode-credential-fallback:' + process.platform + ':' + os.homedir() + ':' + user;
}
function zcCipherKey() {
  return crypto.createHash('sha256').update(zcSecret()).digest();
}
/** 解密 enc:v1:<iv>.<tag>.<ciphertext>（base64url，aes-256-gcm） */
function zcDecryptValue(v) {
  if (typeof v !== 'string' || !v.startsWith('enc:v1:')) return v;
  const parts = v.slice(7).split('.');
  if (parts.length !== 3) throw new Error('凭据密文格式异常');
  const dec = crypto.createDecipheriv('aes-256-gcm', zcCipherKey(), Buffer.from(parts[0], 'base64url'));
  dec.setAuthTag(Buffer.from(parts[1], 'base64url'));
  return dec.update(Buffer.from(parts[2], 'base64url')).toString('utf8') + dec.final('utf8');
}
/** 加密成与 ZCode 一致的 enc:v1 格式（切换写回时用） */
function zcEncryptValue(plain) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', zcCipherKey(), iv);
  const ct = Buffer.concat([c.update(String(plain), 'utf8'), c.final()]);
  return 'enc:v1:' + iv.toString('base64url') + '.' + c.getAuthTag().toString('base64url') + '.' + ct.toString('base64url');
}
let zcSwitching = false; // 切换写入过程中挂起 watcher 同步，避免读到中间态

/** 读取当前凭据文件原始对象（密文形态；缺失/损坏返回 null） */
function zcReadCreds() {
  const f = zcCredFilePath();
  if (!f) return null;
  const j = readJsonOrNull(f);
  return j ? { file: f, creds: j } : null;
}

/** 当前激活的 provider id（zai / bigmodel …）：优先 oauth:active_provider，回退扫 oauth:<id>:user_info 键 */
function zcActiveProvider(creds) {
  let prov = null;
  try { prov = String(zcDecryptValue(creds['oauth:active_provider']) || ''); } catch (_) {}
  if (prov && creds['oauth:' + prov + ':user_info']) return prov;
  const m = Object.keys(creds).find((k) => /^oauth:[^:]+:user_info$/.test(k));
  return m ? m.split(':')[1] : null;
}

/** 从凭据对象解出账号信息 { uid, nickname, ident, email, username }；解不开（外部 secret 等）返回 null。
 *  兼容两种 provider：zai（国际版，user_info 里 name/email）与 bigmodel（智谱，displayName/username/rawProfile）。 */
function zcUserInfoFrom(creds) {
  if (!creds || typeof creds !== 'object') return null;
  try {
    const prov = zcActiveProvider(creds);
    if (!prov) return null;
    const info = JSON.parse(zcDecryptValue(creds['oauth:' + prov + ':user_info']));
    const raw = (info && info.rawProfile) || {};
    const uid = String(info.user_id || info.id || raw.user_id || '');
    if (!uid) return null;
    const email = String(info.email || raw.email || '');
    const username = String(info.username || raw.username || info.login || '');
    const nickname = String(info.displayName || raw.displayName || info.name || raw.name || username || email || uid);
    // 卡片展示用的账号标识：邮箱优先（zai），无邮箱则用户名（bigmodel）
    const ident = email || username;
    return { uid, nickname, ident, email, username, provider: prov };
  } catch (_) { return null; }
}

/** 把当前登录快照并入账号库（watcher 变化时调用）；整文件快照凭据原样保存。
 *  幂等：内容未变化时不写盘（前端轮询会频繁触发本函数）。 */
function zcSyncStore() {
  if (zcSwitching) return;
  const live = zcReadCreds();
  if (!live) return;
  const info = zcUserInfoFrom(live.creds);
  if (!info) return;
  const store = loadStore();
  const prev = store.zc.accounts.find((x) => x && String(x.uid) === info.uid) || null;
  const credJson = JSON.stringify(live.creds);
  const curUid = store.zc.current && store.zc.current.uid ? String(store.zc.current.uid) : null;
  const unchanged = prev
    && JSON.stringify(prev.cred) === credJson
    && prev.nickname === info.nickname
    && (prev.email || '') === info.email
    && (prev.username || '') === info.username
    && curUid === info.uid;
  if (unchanged) return;
  const rec = {
    uid: info.uid,
    nickname: info.nickname,
    email: info.email,
    username: info.username,
    provider: info.provider,
    ident: info.ident,
    cred: live.creds, // 整文件快照（密文原样，切换时写回）
    tokenExpiresAt: null, // ZCode 登录 token 无 exp（长效，不登出即有效）→ 不显示 Cookie 时限
    backedUpAt: Date.now(),
  };
  const i = store.zc.accounts.findIndex((x) => x && String(x.uid) === info.uid);
  if (i >= 0) store.zc.accounts[i] = Object.assign({}, store.zc.accounts[i], rec);
  else store.zc.accounts.push(rec);
  store.zc.current = Object.assign({}, store.zc.accounts[i >= 0 ? i : store.zc.accounts.length - 1]);
  saveStore(store);
}

/** 账号列表：当前登录（凭据文件）排最前 + 账号库备份；ZCode 无每日签到 → checkin 恒为 null */
function zcListAccounts() {
  const store = loadStore();
  const live = zcReadCreds();
  const liveInfo = live ? zcUserInfoFrom(live.creds) : null;
  const currentUid = liveInfo ? liveInfo.uid : null;
  const seen = new Set();
  const list = [];
  const push = (uid, nickname, ident, lastRefreshTime) => {
    uid = String(uid || '');
    if (!uid || seen.has(uid)) return;
    seen.add(uid);
    list.push({
      uid,
      nickname: nickname || uid,
      phone: ident || '',
      uin: '',
      tokenExpiresAt: null, // ZCode 登录 token 无 exp（长效）→ 不显示 Cookie 时限
      refreshExpiresAt: null,
      lastRefreshTime: lastRefreshTime || null,
      checkin: null, // ZCode 无每日签到
    });
  };
  if (liveInfo) push(liveInfo.uid, liveInfo.nickname, liveInfo.ident, Date.now());
  for (const a of store.zc.accounts || []) push(a.uid, a.nickname, a.ident || a.email || a.username, a.backedUpAt);
  list.sort((a, b) => (a.uid === currentUid ? -1 : b.uid === currentUid ? 1 : 0));
  return { currentUid, accounts: list };
}

/** ZCode 主进程是否在运行 */
function zcIsRunning() {
  if (isMac) return false;
  for (const name of ZC_KILL_NAMES) {
    try {
      const out = execFileSync('tasklist', ['/FI', 'IMAGENAME eq ' + name, '/FO', 'CSV', '/NH'],
        { encoding: 'utf8', windowsHide: true });
      if (out.includes(name)) return true;
    } catch (_) {}
  }
  return false;
}

/** 停 ZCode：直接强杀（切换后必然带新登录态重启，无需优雅退出；先停干净再写，
 *  避免客户端退出时把内存里的旧凭据回写覆盖）。强杀后等进程退出 —— Electron 单实例锁
 *  要释放才能重启，最多 ~3.5s。旧实现用优雅关闭（taskkill /T 不带 /F）在多进程下
 *  每个进程都要等窗口响应，整轮实测 ~23s，超过前端 12s 超时 → 表现为「不关闭 ZCode 就切换失败」。 */
async function zcKillApp() {
  if (isMac || !detectZcodeExe()) return;
  for (const name of ZC_KILL_NAMES) {
    try { execFileSync('taskkill', ['/IM', name, '/F', '/T'], { stdio: 'ignore', windowsHide: true }); } catch (_) {}
  }
  for (let i = 0; i < 14 && zcIsRunning(); i++) await sleep(250);
  if (zcIsRunning()) log('[client:zc] 警告：ZCode 进程仍在退出中，重启可能被单实例锁挡下');
}

/** 拉起 ZCode（daemon 侧；UI 按钮走 Rust 的 launch_zcode）。正常启动即可，无需调试端口 */
function zcLaunchApp() {
  const exe = detectZcodeExe();
  if (!exe) return false;
  try {
    spawn(exe, [], { detached: true, stdio: 'ignore', windowsHide: true }).unref();
    return true;
  } catch (_) { return false; }
}

/** ZCode 切换账号：停客户端 → 写回备份凭据整文件 → 重启。
 *  写入前先校验备份可解密（防 secret 不一致写坏登录态），写入后再读校验 uid。
 *  串行化：连续点击/重试排队执行，避免并发杀进程与相互覆盖写文件。 */
let zcSwitchChain = Promise.resolve();
function zcSwitchToAccount(uid) {
  const run = () => zcSwitchToAccountImpl(uid);
  const p = zcSwitchChain.then(run, run);
  zcSwitchChain = p.then(() => {}, () => {});
  return p;
}
async function zcSwitchToAccountImpl(uid) {
  const store = loadStore();
  const rec = store.zc.accounts.find((x) => x && String(x.uid) === String(uid));
  if (!rec || !rec.cred) throw new Error('账号备份不存在或缺少登录态');
  const f = zcCredFilePath();
  if (!f) throw new Error('未找到 ZCode 凭据文件（请先安装并登录一次）');
  const live = zcReadCreds();
  const liveInfo = live ? zcUserInfoFrom(live.creds) : null;
  if (liveInfo && String(liveInfo.uid) === String(uid)) {
    return { uid, nickname: rec.nickname || uid, relaunched: false, alreadyCurrent: true };
  }
  if (!zcUserInfoFrom(rec.cred)) throw new Error('备份登录态无法解密，无法切换');
  const wasRunning = zcIsRunning();
  zcSwitching = true;
  try {
    if (wasRunning) { log('[client:zc] 停止 ZCode 以写入登录态…'); await zcKillApp(); }
    fs.mkdirSync(path.dirname(f), { recursive: true });
    const tmp = f + '.workpet-tmp';
    fs.writeFileSync(tmp, JSON.stringify(rec.cred, null, 2));
    fs.renameSync(tmp, f);
    const check = zcUserInfoFrom(readJsonOrNull(f));
    if (!check || String(check.uid) !== String(uid)) throw new Error('登录态写入校验失败');
    log('[client:zc] 已写回 credentials.json（' + (rec.nickname || uid) + '）');
    const st2 = loadStore();
    const i2 = st2.zc.accounts.findIndex((x) => x && String(x.uid) === String(uid));
    if (i2 >= 0) st2.zc.current = Object.assign({}, st2.zc.accounts[i2]);
    saveStore(st2);
    let relaunched = false;
    if (wasRunning) {
      relaunched = zcLaunchApp();
      log('[client:zc] 切换前客户端在运行，已自动重启' + (relaunched ? '' : '（重启失败）'));
    }
    return { uid, nickname: rec.nickname || uid, relaunched };
  } finally {
    zcSwitching = false;
  }
}

const CLIENT_PROFILES = {
  wb: {
    id: 'wb', name: 'WorkBuddy',
    authFile: WB_AUTH_FILE,
    apiHost: 'https://www.workbuddy.cn',
    checkinHosts: ['https://www.workbuddy.cn', 'https://www.codebuddy.cn'],
    cdpPort: 9222,
  },
  cb: {
    id: 'cb', name: 'CodeBuddy',
    authFile: CB_AUTH_FILE,
    apiHost: 'https://www.codebuddy.cn',
    checkinHosts: ['https://www.codebuddy.cn'],
    cdpPort: 9224,
  },
  ac: {
    id: 'ac', name: 'AutoClaw',
    authFile: AC_AUTH_FILE,
    apiHost: AC_API_HOST,
    checkinHosts: [AC_API_HOST],
    cdpPort: 9226,
  },
  ca: {
    id: 'ca', name: 'CodeArts Agent',
    authFile: CA_VSCDB, // 仅作路径展示用；ca 登录态在 SQLite 里，读写全部走专用函数
    apiHost: '',
    checkinHosts: [],
    cdpPort: 9228,
  },
  as: {
    id: 'as', name: 'AStudio',
    authFile: AS_SESSION_FILE, // 明文 JSON；读写见 asReadSession/asWriteSession
    apiHost: '',               // 业务接口在本地随机端口，只能经 CDP 在渲染进程内调用
    checkinHosts: [],
    cdpPort: AS_CDP_PORT,
  },
  zc: {
    id: 'zc', name: 'ZCode',
    authFile: ZC_CRED_FILE,    // ~/.zcode/v*/credentials.json；读写见 zcReadCreds/zcSwitchToAccount
    apiHost: '',               // 无签到/积分接口，仅账号备份与切换
    checkinHosts: [],
    cdpPort: 0,                // 无需调试端口
  },
};

// ---------------- AutoClaw 登录态解密（DPAPI + AES-256-GCM） ----------------
// Node 无内置 DPAPI，解 Local State 的 key 需要拉起 powershell。
// 绝不能像旧实现那样用 execFileSync 同步等它：powershell 一旦卡死（曾实测挂死数分钟），
// 整个 daemon 事件循环被堵住，HTTP 全部无响应，前端就报「后台服务未运行」。
// 因此这里统一为：异步 spawn + 12s 硬超时（按进程树强杀）+ AES key 只解一次并缓存。
const AC_KEY_PENDING = Symbol('ac-key-pending');
let acKeyCache = null;    // 已解出的 AES-256 key（Buffer），只解密一次
let acKeyPromise = null;  // 进行中的异步解密（并发共享）

/** 仅当 win-dpapi 原生模块可用时同步解密；不可用返回 null（走 powershell） */
function acDpapiNative(data) {
  try {
    const { CryptUnprotectData } = (() => { try { return require('win-dpapi'); } catch (_) { return {}; } })();
    if (CryptUnprotectData) return CryptUnprotectData(Buffer.from(data));
  } catch (_) {}
  return null;
}

/** 异步跑一次 powershell Unprotect；12s 未完成则按进程树强杀，绝不悬挂 */
function acDpapiViaPowershell(data) {
  return new Promise((resolve, reject) => {
    const inB64 = Buffer.from(data).toString('base64');
    const ps = `$ProgressPreference='SilentlyContinue'; Add-Type -AssemblyName System.Security; [Convert]::ToBase64String([Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String('${inB64}'), $null, [Security.Cryptography.DataProtectionScope]::CurrentUser))`;
    const encCmd = Buffer.from(ps, 'utf16le').toString('base64');
    const child = spawn('powershell', ['-NoProfile', '-EncodedCommand', encCmd], { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      // 只杀 powershell 不够（其子进程可能还握着 stdout 管道）；按进程树强杀
      try { spawn('taskkill', ['/PID', String(child.pid), '/T', '/F'], { windowsHide: true, stdio: 'ignore' }); } catch (_) {}
      reject(new Error('DPAPI 解密超时（已强杀 powershell 进程树）'));
    }, 12000);
    child.stdout.on('data', (d) => { out += d.toString(); });
    child.stderr.on('data', () => {});
    child.on('error', (e) => { clearTimeout(timer); reject(new Error('DPAPI powershell 启动失败: ' + e.message)); });
    child.on('close', (code) => {
      clearTimeout(timer);
      if (timedOut) return;
      if (code !== 0) { reject(new Error('DPAPI powershell 退出码 ' + code)); return; }
      try {
        // PowerShell 5 会在 stdout 前打 CLIXML 进度块，去掉到 </Objs> 之后的部分
        const idx = out.lastIndexOf('</Objs>');
        const clean = (idx >= 0 ? out.slice(idx + 7) : out).trim();
        const key = Buffer.from(clean, 'base64');
        if (!key.length) throw new Error('解密结果为空');
        resolve(key);
      } catch (e) { reject(new Error('DPAPI 解密结果解析失败: ' + e.message)); }
    });
  });
}

// ---------------- macOS：从登录钥匙串读取 safeStorage 密码并派生 AES key ----------------
// Electron safeStorage 在 macOS 上把随机密码存进登录钥匙串（service "<AppName> Safe Storage"，
// account "<AppName>"），AES key = PBKDF2-HMAC-SHA1(password, salt="saltysalt", 1003 次, 16B)。
// 与 Windows 的 Local State + DPAPI 完全不同的路径；首次读取会弹钥匙串授权框，用户点允许后记住。
const AC_KEYCHAIN_SERVICE = 'autoclaw Safe Storage';
const AC_KEYCHAIN_ACCOUNT = 'autoclaw';
const AC_MAC_PBKDF2_SALT = Buffer.from('saltysalt', 'utf8');
const AC_MAC_PBKDF2_ITERS = 1003;

function acMacDeriveKey(keychainPassword) {
  return crypto.pbkdf2Sync(keychainPassword, AC_MAC_PBKDF2_SALT, AC_MAC_PBKDF2_ITERS, 16, 'sha1');
}

/** 异步读钥匙串密码（spawn security；15s 超时，不阻塞事件循环，与 Windows powershell 路径同理） */
function acMacReadPasswordAsync() {
  return new Promise((resolve, reject) => {
    const child = spawn('security', ['find-generic-password', '-s', AC_KEYCHAIN_SERVICE, '-a', AC_KEYCHAIN_ACCOUNT, '-w'], { stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      try { child.kill(); } catch (_) {}
      reject(new Error('AutoClaw 钥匙串读取超时（15s）'));
    }, 15000);
    child.stdout.on('data', (d) => { out += d.toString(); });
    child.stderr.on('data', () => {});
    child.on('error', (e) => { clearTimeout(timer); reject(new Error('AutoClaw 钥匙串启动失败: ' + e.message)); });
    child.on('close', (code) => {
      clearTimeout(timer);
      if (timedOut) return;
      if (code !== 0) { reject(new Error('AutoClaw 钥匙串读取失败(exit ' + code + ')')); return; }
      const pw = out.trim();
      if (!pw) { reject(new Error('AutoClaw 钥匙串密码为空')); return; }
      resolve(acMacDeriveKey(pw));
    });
  });
}

/** 获取 AutoClaw AES key：只解一次并缓存；并发调用共享同一个 Promise */
function acRequestKey() {
  if (acKeyCache) return Promise.resolve(acKeyCache);
  if (!acKeyPromise) {
    acKeyPromise = (isMac
      ? acMacReadPasswordAsync()
      : (async () => {
          const ls = readJsonOrNull(AC_LOCAL_STATE);
          const enc = ls && ls.os_crypt && ls.os_crypt.encrypted_key;
          if (!enc) throw new Error('AutoClaw Local State 无 os_crypt.encrypted_key');
          const raw = Buffer.from(enc, 'base64');
          if (raw.slice(0, 5).toString() !== 'DPAPI') return raw;
          const viaNative = acDpapiNative(raw.slice(5));
          if (viaNative) return viaNative;
          return await acDpapiViaPowershell(raw.slice(5));
        })()
    ).then((k) => { acKeyCache = k; acKeyPromise = null; return k; })
      .catch((e) => { acKeyPromise = null; throw e; });
  }
  return acKeyPromise;
}

/** 后台预热 key（静默失败；daemon 启动时调用，让首次读账号前已就绪） */
function acWarmKey() {
  acRequestKey().catch((e) => log('[client:ac] AES key 预取失败: ' + e.message));
}

/** 同步取 key：已缓存直接返回；未就绪抛 AC_KEY_PENDING（调用方快速失败，绝不阻塞） */
function acKeySync() {
  if (acKeyCache) return acKeyCache;
  throw AC_KEY_PENDING;
}

/** 纯 AES 解密单个 token；key 可显式传入（异步路径）或走缓存（同步路径）。
 *  Windows: v10 + nonce(12) + ciphertext + tag(16)，AES-256-GCM，key 来自 DPAPI。
 *  macOS:   v10 + ciphertext，AES-128-CBC（IV 固定 16 空格，PKCS7），key 来自钥匙串 PBKDF2 派生。 */
function acDecryptToken(encStr, key) {
  if (!encStr) return '';
  if (!encStr.startsWith('enc:')) return encStr.replace(/^Bearer\s+/, '');
  const raw = Buffer.from(encStr.slice(4), 'base64');
  if (raw.slice(0, 3).toString() !== 'v10') return encStr.replace(/^Bearer\s+/, '');
  const k = key || acKeySync(); // 同步路径未就绪时抛 AC_KEY_PENDING
  let pt;
  if (isMac) {
    const dec = crypto.createDecipheriv('aes-128-cbc', k, Buffer.alloc(16, 0x20));
    pt = Buffer.concat([dec.update(raw.slice(3)), dec.final()]);
  } else {
    const nonce = raw.slice(3, 15), ct = raw.slice(15);
    const tag = ct.slice(ct.length - 16), body = ct.slice(0, ct.length - 16);
    const dec = crypto.createDecipheriv('aes-256-gcm', k, nonce);
    dec.setAuthTag(tag);
    pt = Buffer.concat([dec.update(body), dec.final()]);
  }
  return pt.toString('utf8').replace(/^Bearer\s+/, '');
}

/** 异步解密单 token（等待/触发 key 就绪后再解） */
async function acDecryptTokenAsync(encStr) {
  if (!encStr || !encStr.startsWith('enc:')) return acDecryptToken(encStr);
  return acDecryptToken(encStr, await acRequestKey());
}

/** 读取 AutoClaw 登录态（解密后），返回 { token, refreshToken, userId, phone, deviceId, raw } 或 { error } */
function acReadAuth() {
  if (ac2IsNewLayout()) {
    // AutoClaw2：账号在 AutoClaw-official/accounts/<key>/（profile 明文，凭据 app-bound 加密）。
    // token 外部拿不到 —— 积分走 CDP 渲染进程（zworkAuth），这里只提供账号身份。
    const activeKey = ac2ReadActiveKey();
    const profiles = ac2ReadProfiles();
    const active = profiles.find((p) => p.accountKey === activeKey) || profiles[0] || null;
    if (!active) return null;
    return {
      account: {
        uid: String(active.accountId),
        nickname: active.displayName || active.phone || String(active.numericUserId || ''),
        phoneNumber: active.phone || '',
      },
      auth: {
        accessToken: '',
        refreshToken: '',
        expiresAt: null,
        lastRefreshTime: active.lastLoginAt ? active.lastLoginAt * 1000 : null,
      },
      ac2: active,
    };
  }
  const raw = readJsonOrNull(AC_AUTH_FILE);
  if (!raw || !raw.token) return null;
  try {
    const key = acKeySync();
    const token = acDecryptToken(raw.token, key);
    const refreshToken = acDecryptToken(raw.refreshToken || '', key);
    return acBuildAuth(raw, token, refreshToken);
  } catch (e) {
    // key 未就绪（AC_KEY_PENDING）或解密失败：快速返回错误，绝不阻塞等待 powershell
    return { error: e === AC_KEY_PENDING ? 'AutoClaw 登录态解密未就绪（稍后自动重试）' : 'AutoClaw 登录态解密失败: ' + e.message };
  }
}

/** 异步版 acReadAuth：先确保 AES key 就绪（内部 12s 硬超时+树杀），再同步解密 */
async function acReadAuthAsync() {
  const raw = readJsonOrNull(AC_AUTH_FILE);
  if (!raw || !raw.token) return null;
  try {
    const key = await acRequestKey();
    const token = acDecryptToken(raw.token, key);
    const refreshToken = acDecryptToken(raw.refreshToken || '', key);
    return acBuildAuth(raw, token, refreshToken);
  } catch (e) {
    return { error: 'AutoClaw 登录态解密失败: ' + e.message };
  }
}

/** 由明文 token/refreshToken 组装统一形状 */
function acBuildAuth(raw, token, refreshToken) {
  let jwt = {};
  try {
    const p = token.split('.')[1];
    if (p) jwt = JSON.parse(Buffer.from(p.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8'));
  } catch (_) {}
  return {
    token,
    refreshToken,
    userId: (jwt.user_id || raw.userInfo && raw.userInfo.user_id || ''),
    phone: (raw.userInfo && (raw.userInfo.user_phone || raw.userInfo.phone)) || '',
    deviceId: raw.deviceId || '',
    jwtExp: jwt.exp ? jwt.exp * 1000 : null,
    raw,
  };
}

function acSignHeaders(extra) {
  const ts = String(Math.floor(Date.now() / 1000));
  const sign = crypto.createHash('md5').update(`${AC_APP_ID}&${ts}&${AC_APP_KEY}`).digest('hex');
  return Object.assign({
    accept: '*/*',
    'x-version': '1.0.0',
    'x-tm': 'win',
    'x-product': 'autoclaw',
    'x-auth-appid': AC_APP_ID,
    'x-auth-timestamp': ts,
    'x-auth-sign': sign,
    'x-trace-id': crypto.randomUUID(),
    'user-agent': 'autoclaw/1.0',
  }, extra || {});
}

/** AutoClaw refresh：refresh_token 轮换，成功后回写 auth.json（加密格式保持原样：只换 token 字段） */
async function acRefreshToken() {
  const auth = await acReadAuthAsync();
  if (!auth || auth.error || !auth.refreshToken) throw new Error('AutoClaw 无 refresh_token');
  const body = JSON.stringify({ source_id: 'autoclaw', device_id: auth.deviceId, refresh_token: auth.refreshToken });
  const r = await fetch(AC_API_HOST + '/userapi/v1/refresh', {
    method: 'POST',
    headers: acSignHeaders({ 'content-type': 'application/json' }),
    body,
    signal: AbortSignal.timeout(12000),
  });
  const o = await r.json().catch(() => ({}));
  if (o.code !== 0 || !o.data || !o.data.access_token) throw new Error('refresh 失败: ' + (o.msg || ('HTTP ' + r.status)));
  return { accessToken: String(o.data.access_token), refreshToken: String(o.data.refresh_token || auth.refreshToken), jwtExp: null };
}

/** 解析 JWT exp（毫秒） */
function acJwtExpMs(token) {
  try {
    const p = token.split('.')[1];
    if (!p) return null;
    const j = JSON.parse(Buffer.from(p.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8'));
    return j.exp ? j.exp * 1000 : null;
  } catch (_) { return null; }
}

/** 把刷新后的 token 写回 auth.json（保持 enc:v10 加密格式：重新加密需要 DPAPI，这里只在能加密时回写，否则不动文件） */
async function acPersistRefreshedToken(newAccess, newRefresh) {
  try {
    const raw = readJsonOrNull(AC_AUTH_FILE);
    if (!raw) return false;
    // 尝试用同 key 重新加密（保持各平台 Electron safeStorage 原生格式，AutoClaw 自身可读回）
    const key = await acRequestKey();
    const enc = (plain) => {
      if (isMac) {
        // macOS：enc: + base64(v10 + AES-128-CBC 密文)，IV 固定 16 空格
        const cipher = crypto.createCipheriv('aes-128-cbc', key, Buffer.alloc(16, 0x20));
        const ct = Buffer.concat([cipher.update(Buffer.from(plain, 'utf8')), cipher.final()]);
        return 'enc:' + Buffer.concat([Buffer.from('v10', 'utf8'), ct]).toString('base64');
      }
      // Windows：v10 + nonce(12) + ciphertext + tag(16)，AES-256-GCM
      const nonce = crypto.randomBytes(12);
      const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
      const ct = Buffer.concat([cipher.update(Buffer.from(plain, 'utf8')), cipher.final()]);
      const tag = cipher.getAuthTag();
      return 'enc:v10' + Buffer.concat([nonce, ct, tag]).toString('base64');
    };
    const next = Object.assign({}, raw, {
      token: enc('Bearer ' + newAccess.replace(/^Bearer\s+/, '')),
      refreshToken: enc('Bearer ' + newRefresh.replace(/^Bearer\s+/, '')),
      updatedAt: String(Date.now()),
    });
    const tmp = AC_AUTH_FILE + '.workpet-tmp';
    fs.writeFileSync(tmp, JSON.stringify(next, null, 2));
    fs.renameSync(tmp, AC_AUTH_FILE);
    return true;
  } catch (e) {
    log('[client:ac] 回写 auth.json 失败（不影响签到）: ' + e.message);
    return false;
  }
}

/** refresh 成功后同步进账号库（ac 段） */
function acSyncStoreAfterRefresh(accessToken, refreshToken, jwtExp) {
  try {
    const store = loadStore();
    if (!store.ac) store.ac = { current: null, accounts: [] };
    let uid = '';
    try {
      const p = accessToken.split('.')[1];
      if (p) uid = String(JSON.parse(Buffer.from(p.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8')).user_id || '');
    } catch (_) {}
    const rec0 = store.ac.current || store.ac.accounts[0];
    uid = uid || (rec0 && rec0.uid) || '';
    if (!uid) return;
    const idx = store.ac.accounts.findIndex((x) => x && String(x.uid) === uid);
    if (idx < 0) return;
    store.ac.accounts[idx] = Object.assign({}, store.ac.accounts[idx], {
      accessToken, refreshToken, tokenExpiresAt: jwtExp || null, lastRefreshTime: Date.now(),
    });
    if (store.ac.current && String(store.ac.current.uid) === uid) store.ac.current = store.ac.accounts[idx];
    saveStore(store);
  } catch (_) {}
}

// ---------------- CodeArts Agent 登录态（safeStorage 解密 + state.vscdb 读写） ----------------
// 与 AutoClaw 同构的 Electron safeStorage v10。key 获取按平台分：
//   Windows：DPAPI 解 Local State 的 key，再 AES-256-GCM；
//   macOS：登录钥匙串读随机密码 → PBKDF2 派生，再 AES-128-CBC。
// CodeArts 的 key 缓存与 AC 分开维护。

const CA_KEY_PENDING = Symbol('ca-key-pending');
let caKeyCache = null;    // 已解出的 CodeArts AES key（Windows 32B / macOS 16B）
let caKeyPromise = null;  // 进行中的异步解密（并发共享）

/** macOS：从登录钥匙串读 safeStorage 随机密码（异步 spawn + 15s 硬超时，绝不阻塞事件循环）。
 *  首次访问若系统弹钥匙串授权框，用户点「始终允许」后不会再问（README 有说明）。 */
function caMacReadKeychainPasswordAsync() {
  return new Promise((resolve, reject) => {
    const child = spawn('security', ['find-generic-password', '-s', CA_MAC_KEYCHAIN_SERVICE, '-a', CA_MAC_KEYCHAIN_ACCOUNT, '-w'], { stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '', err = '', done = false;
    const t = setTimeout(() => {
      if (done) return; done = true;
      try { child.kill('SIGKILL'); } catch (_) {}
      reject(new Error('security 读取钥匙串超时'));
    }, 15000);
    child.stdout.on('data', (d) => { out += d; });
    child.stderr.on('data', (d) => { err += d; });
    child.on('error', (e) => { if (!done) { done = true; clearTimeout(t); reject(e); } });
    child.on('close', (code) => {
      if (done) return; done = true; clearTimeout(t);
      const pw = String(out || '').trim();
      if (code === 0 && pw) resolve(pw);
      else reject(new Error('读取钥匙串失败(code=' + code + '): ' + (String(err || '').trim() || '无输出')));
    });
  });
}

/** macOS：钥匙串随机密码 → PBKDF2-HMAC-SHA1 派生 16B AES key（Electron/Chromium 固定参数） */
function caMacDeriveKey(keychainPassword) {
  return crypto.pbkdf2Sync(keychainPassword, CA_MAC_PBKDF2_SALT, CA_MAC_PBKDF2_ITERS, 16, 'sha1');
}

/** 获取 CodeArts safeStorage AES key：只解一次并缓存（Windows 复用 AC 的 DPAPI 实现，入参即密文） */
function caRequestKey() {
  if (caKeyCache) return Promise.resolve(caKeyCache);
  if (!caKeyPromise) {
    caKeyPromise = (async () => {
      if (isMac) return caMacDeriveKey(await caMacReadKeychainPasswordAsync());
      const ls = readJsonOrNull(CA_LOCAL_STATE);
      const enc = ls && ls.os_crypt && ls.os_crypt.encrypted_key;
      if (!enc) throw new Error('CodeArts Local State 无 os_crypt.encrypted_key');
      const raw = Buffer.from(enc, 'base64');
      if (raw.slice(0, 5).toString() !== 'DPAPI') return raw;
      const viaNative = acDpapiNative(raw.slice(5));
      if (viaNative) return viaNative;
      return await acDpapiViaPowershell(raw.slice(5));
    })().then((k) => { caKeyCache = k; caKeyPromise = null; return k; })
      .catch((e) => { caKeyPromise = null; throw e; });
  }
  return caKeyPromise;
}

/** 后台预热（daemon 启动时调用，静默失败） */
function caWarmKey() {
  if (!CA_VSCDB) return;
  caRequestKey().catch((e) => log('[client:ca] AES key 预取失败: ' + e.message));
}

/** node:sqlite 惰性加载（需 Node 22+；缺失时给出明确错误而不是崩溃） */
let CaSqliteModule = undefined; // undefined=未探测 / null=不可用
function caSqlite() {
  if (CaSqliteModule !== undefined) return CaSqliteModule;
  try { CaSqliteModule = require('node:sqlite'); }
  catch (_) { CaSqliteModule = null; }
  return CaSqliteModule;
}

/** 打开 vscdb（读路径优先只读；readOnly 选项在不支持的 Node 版本上自动降级） */
function caOpenDb(file, readOnly) {
  const sqlite = caSqlite();
  if (!sqlite) throw new Error('当前 Node 运行时无 node:sqlite（切换 CodeArts 账号需 Node 22+）');
  if (readOnly) {
    try { return new sqlite.DatabaseSync(file, { readOnly: true }); } catch (_) {}
  }
  return new sqlite.DatabaseSync(file);
}

/**
 * 读取 state.vscdb 里的两个登录键（只读，带重试：客户端运行期间可能瞬时持锁）。
 * 返回 { secretKey, secretRaw, snapState }；无数据目录/无登录返回 null；不可用返回 { error }。
 */
function caReadDb(retries) {
  if (!CA_VSCDB || !fs.existsSync(CA_VSCDB)) return null;
  if (!caSqlite()) return { error: '当前 Node 运行时无 node:sqlite（需 Node 22+，请更新 Work Pet 安装包）' };
  const n = retries || 3;
  for (let i = 0; i < n; i++) {
    let db = null;
    try {
      db = caOpenDb(CA_VSCDB, true);
      const srow = db.prepare("SELECT key, value FROM ItemTable WHERE key LIKE 'secret://%' AND key LIKE '%HuaweiCloudSession%'").get();
      const snapRow = db.prepare('SELECT value FROM ItemTable WHERE key = ?').get(CA_SNAP_KEY);
      return {
        secretKey: srow ? String(srow.key) : CA_SECRET_KEY_DEFAULT,
        secretRaw: srow ? String(srow.value) : null,
        snapState: snapRow ? String(snapRow.value) : null,
      };
    } catch (e) {
      if (i >= n - 1) return { error: '读取 CodeArts 登录库失败: ' + e.message };
    } finally {
      try { if (db) db.close(); } catch (_) {}
    }
  }
  return null;
}

/** 解密 vscdb 的 secret 值（{"type":"Buffer","data":[...]} → v10 → 平台分支 → 明文 JSON 字符串） */
function caDecryptVscSecret(vscValue, key) {
  const s = String(vscValue || '');
  let bytes;
  if (s.startsWith('{"type":"Buffer"')) bytes = Buffer.from(JSON.parse(s).data);
  else bytes = Buffer.from(s, 'latin1'); // 兼容旧形态
  if (bytes.slice(0, 3).toString('latin1') !== 'v10') throw new Error('非 safeStorage v10 格式');
  if (isMac) {
    // macOS：v10 + ciphertext，AES-128-CBC（IV 固定 16 空格 0x20，PKCS7）
    const dec = crypto.createDecipheriv('aes-128-cbc', key, Buffer.alloc(16, 0x20));
    return Buffer.concat([dec.update(bytes.slice(3)), dec.final()]).toString('utf8');
  }
  const nonce = bytes.slice(3, 15), ct = bytes.slice(15);
  const tag = ct.slice(ct.length - 16), body = ct.slice(0, ct.length - 16);
  const dec = crypto.createDecipheriv('aes-256-gcm', key, nonce);
  dec.setAuthTag(tag);
  return Buffer.concat([dec.update(body), dec.final()]).toString('utf8');
}

/** 用本机 key 把明文会话 JSON 重新加密成 vscdb 的 secret 值（跨机器恢复用） */
function caEncryptVscSecret(plain, key) {
  if (isMac) {
    const cipher = crypto.createCipheriv('aes-128-cbc', key, Buffer.alloc(16, 0x20));
    const ct = Buffer.concat([cipher.update(Buffer.from(plain, 'utf8')), cipher.final()]);
    const bytes = Buffer.concat([Buffer.from('v10', 'latin1'), ct]);
    return JSON.stringify({ type: 'Buffer', data: Array.from(bytes) });
  }
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
  const ct = Buffer.concat([cipher.update(Buffer.from(plain, 'utf8')), cipher.final()]);
  const bytes = Buffer.concat([Buffer.from('v10', 'latin1'), nonce, ct, cipher.getAuthTag()]);
  return JSON.stringify({ type: 'Buffer', data: Array.from(bytes) });
}

/** 读取并解密当前登录态 → { uid, nickname, sessionExp, refreshTokenExp, secretRaw, secretPlain, snapState, userInfoJson } */
async function caReadAuthAsync() {
  const dbv = caReadDb();
  if (!dbv || dbv.error) return dbv && dbv.error ? { error: dbv.error } : null;
  if (!dbv.secretRaw) return null; // 从未登录过
  const key = await caRequestKey();
  const secretPlain = caDecryptVscSecret(dbv.secretRaw, key); // 解密失败会抛出（key 不匹配/数据损坏）
  let j = null;
  try { j = JSON.parse(secretPlain); } catch (e) { throw new Error('会话明文解析失败: ' + e.message); }
  let snap = null;
  try { snap = dbv.snapState ? JSON.parse(dbv.snapState) : null; } catch (_) {}
  const info = (snap && snap.userInfoKey) || {};
  const uid = String((j.account && j.account.id) || info.id || '');
  if (!uid) return null;
  const nickname = String((j.account && j.account.label) || info.name || uid);
  return {
    uid, nickname,
    sessionExp: j.expires_at ? Date.parse(j.expires_at) : null,
    refreshTokenExp: acJwtExpMs(j.refresh_token || ''),
    secretRaw: dbv.secretRaw,
    secretPlain,
    snapState: dbv.snapState || null,
    userInfoJson: (() => { try { return fs.readFileSync(CA_DOER_USERINFO, 'utf8'); } catch (_) { return null; } })(),
  };
}

/** 把当前登录同步进账号库 codearts 段（登录库变化时调用；仅在内容变化时落盘） */
let caSwitching = false; // 切换过程中挂起同步，防止读到中间态
async function caSyncStore() {
  if (caSwitching || !CA_VSCDB) return null;
  const a = await caReadAuthAsync();
  if (!a || a.error || !a.uid) return a || null;
  const store = loadStore();
  const rec = {
    uid: a.uid,
    nickname: a.nickname,
    sessionExpiresAt: a.sessionExp,
    tokenExpiresAt: a.refreshTokenExp || a.sessionExp, // 卡片「Cookie 时限」= refresh_token 有效期
    secretRaw: a.secretRaw,
    secretPlain: a.secretPlain,
    snapState: a.snapState,
    userInfoJson: a.userInfoJson,
    backedUpAt: Date.now(),
  };
  const idx = store.codearts.accounts.findIndex((x) => x && String(x.uid) === String(a.uid));
  const prev = idx >= 0 ? store.codearts.accounts[idx] : null;
  const changed = !prev
    || prev.secretRaw !== rec.secretRaw || prev.snapState !== rec.snapState
    || prev.nickname !== rec.nickname || prev.tokenExpiresAt !== rec.tokenExpiresAt
    || prev.sessionExpiresAt !== rec.sessionExpiresAt || prev.userInfoJson !== rec.userInfoJson;
  if (idx >= 0) store.codearts.accounts[idx] = Object.assign({}, prev, rec);
  else store.codearts.accounts.push(rec);
  store.codearts.current = store.codearts.accounts[idx >= 0 ? idx : store.codearts.accounts.length - 1];
  if (changed) saveStore(store);
  return a;
}

/** 列出 CodeArts 全部账号（供 /api/client/ca/accounts） */
function caListAccounts() {
  const store = loadStore();
  const cur = store.codearts.current;
  const curUid = cur ? String(cur.uid) : null;
  const seen = new Set();
  const list = [];
  const push = (r) => {
    if (!r || !r.uid || seen.has(String(r.uid))) return;
    seen.add(String(r.uid));
    list.push({
      uid: String(r.uid),
      nickname: r.nickname || String(r.uid),
      phone: '',
      tokenExpiresAt: r.tokenExpiresAt || null,
      sessionExpiresAt: r.sessionExpiresAt || null,
      checkin: null, // CodeArts 无签到
    });
  };
  if (cur) push(cur);
  for (const r of store.codearts.accounts) push(r);
  list.sort((a, b) => (a.uid === curUid ? -1 : b.uid === curUid ? 1 : 0));
  return { currentUid: curUid, accounts: list };
}

// ---------------- CodeArts 进程管理 ----------------

/** macOS：ps 全量枚举 CodeArts 主进程。
 *  实测 Electron 主进程 argv 区被框架改写，pgrep/pkill -f 读不到它（Helper 却正常），
 *  ps 的 command 列稳定可见，进程检测与终止都必须走这条路。返回 [{ pid, argv0 }]。 */
function caMacListIdeProcs() {
  try {
    const out = execFileSync('ps', ['-axo', 'pid=,command='], { encoding: 'utf8' });
    const list = [];
    for (const line of String(out).split(/\r?\n/)) {
      const m = line.match(/^\s*(\d+)\s+(.+)$/);
      if (!m) continue;
      const am = m[2].match(/(?:^|\s)(\S*CodeArts[ _-]?Agent\.app\/Contents\/MacOS\/Electron)(?: |$)/);
      if (am) list.push({ pid: Number(m[1]), argv0: am[1] });
    }
    return list;
  } catch (_) { return []; }
}

/** macOS：ps 全量枚举 AgentKernel 内核进程（路径 ~/.codeartsdoer/CodeArts_Agent/AgentKernel_*） */
function caMacListKernelProcs() {
  try {
    const out = execFileSync('ps', ['-axo', 'pid=,command='], { encoding: 'utf8' });
    const list = [];
    for (const line of String(out).split(/\r?\n/)) {
      const m = line.match(/^\s*(\d+)\s+(.+)$/);
      if (m && CA_MAC_KERNEL_RE.test(m[2])) list.push({ pid: Number(m[1]) });
    }
    return list;
  } catch (_) { return []; }
}

function caIsIdeRunning() {
  if (isMac) return caMacListIdeProcs().length > 0;
  try {
    const out = execFileSync('tasklist', ['/FI', 'IMAGENAME eq ' + CA_IDE_EXE, '/FO', 'CSV', '/NH'], { encoding: 'utf8', windowsHide: true });
    return out.includes(CA_IDE_EXE);
  } catch (_) { return false; }
}

/** 停 CodeArts Agent：先优雅关闭（给 IDE 保存未保存编辑的机会），等不到再强杀；
 *  最后清理 AgentKernel 内核进程（名字带版本号，按路径匹配后逐个杀）。 */
async function caKillIde() {
  if (isMac) {
    const procs = caMacListIdeProcs();
    if (procs.length) {
      try { execFileSync('osascript', ['-e', 'tell application "CodeArts Agent" to quit'], { stdio: 'ignore' }); } catch (_) {}
      for (let i = 0; i < 6; i++) {
        if (!caMacListIdeProcs().length) break;
        await sleep(1000);
      }
      for (const p of caMacListIdeProcs()) { try { process.kill(p.pid, 'SIGTERM'); } catch (_) {} }
      for (let i = 0; i < 5; i++) {
        if (!caMacListIdeProcs().length) break;
        await sleep(1000);
      }
      for (const p of caMacListIdeProcs()) { try { process.kill(p.pid, 'SIGKILL'); } catch (_) {} }
    }
    // 主进程退出会连带 Helper；再清理 AgentKernel 内核进程（路径 ~/.codeartsdoer/CodeArts_Agent/AgentKernel_*）
    for (const p of caMacListKernelProcs()) { try { process.kill(p.pid, 'SIGKILL'); } catch (_) {} }
    return;
  }
  try { execFileSync('taskkill', ['/IM', CA_IDE_EXE, '/T'], { stdio: 'ignore', windowsHide: true }); } catch (_) {}
  for (let i = 0; i < 6; i++) {
    if (!caIsIdeRunning()) break;
    await sleep(1000);
  }
  if (caIsIdeRunning()) {
    try { execFileSync('taskkill', ['/IM', CA_IDE_EXE, '/F', '/T'], { stdio: 'ignore', windowsHide: true }); } catch (_) {}
  }
  try {
    const out = execFileSync('tasklist', ['/FO', 'CSV', '/NH'], { encoding: 'utf8', windowsHide: true });
    const kernels = new Set();
    for (const line of String(out).split(/\r?\n/)) {
      const m = line.match(/^"([^"]+\.exe)"/i);
      if (m && /^AgentKernel_/i.test(m[1])) kernels.add(m[1]);
    }
    for (const k of kernels) {
      try { execFileSync('taskkill', ['/IM', k, '/F', '/T'], { stdio: 'ignore', windowsHide: true }); } catch (_) {}
    }
  } catch (_) {}
}

/** 定位 CodeArts Agent 可执行文件（切换后重启 / 启动设置用）。
 *  macOS 上 App 可装在任意目录：候选路径找不到时从运行中的主进程反查安装位置。 */
function caFindExe() {
  const found = CA_EXE_CANDIDATES.find((p) => { try { return fs.existsSync(p); } catch (_) { return false; } });
  if (found) return found;
  if (!isMac) return null;
  const proc = caMacListIdeProcs()[0];
  return (proc && proc.argv0 && fs.existsSync(proc.argv0)) ? proc.argv0 : null;
}

function caLaunchIde() {
  const exe = caFindExe();
  if (!exe) return false;
  try { spawn(exe, [], { detached: true, stdio: 'ignore', windowsHide: true }).unref(); return true; } catch (_) { return false; }
}

/**
 * CodeArts Agent 一键切换账号：
 * 停客户端（vscdb 被 IDE 持有，且防其退出时回写旧会话）→ 备份库密文写回 vscdb
 * （本机备份原样写回；跨机导入的备份用明文以本机 key 重加密）→ 同步 .backup 副本
 * 与内核侧 userInfo.json → 原来在运行则重启客户端。
 */
async function caSwitchToAccount(uid) {
  const store = loadStore();
  const rec = store.codearts.accounts.find((x) => x && String(x.uid) === String(uid));
  if (!rec) throw new Error('账号备份不存在');
  if (!rec.secretRaw && !rec.secretPlain) throw new Error('该备份缺少登录态数据');
  if (!CA_VSCDB || !fs.existsSync(CA_VSCDB)) throw new Error('未找到 CodeArts Agent 数据目录（请先安装并登录一次）');
  const wasRunning = caIsIdeRunning();
  caSwitching = true;
  try {
    if (wasRunning || caIsIdeRunning()) {
      log('[client:ca] 停止 CodeArts Agent 以写入登录态…');
      await caKillIde();
      for (let i = 0; i < 10 && caIsIdeRunning(); i++) await sleep(1000);
      await sleep(800);
    }
    // 决定写入的密文：本机备份（能被本机 key 解开）原样写回，字节级一致最稳；
    // 解不开（跨机导入）则用明文本机重加密。
    let secretValue = rec.secretRaw || null;
    const key = await caRequestKey();
    if (secretValue) {
      try { caDecryptVscSecret(secretValue, key); } catch (_) { secretValue = null; }
    }
    if (!secretValue) {
      if (!rec.secretPlain) throw new Error('备份无可用登录态（既无本机密文也无明文）');
      log('[client:ca] 备份来自其他电脑，用本机密钥重新加密会话');
      secretValue = caEncryptVscSecret(rec.secretPlain, key);
    }
    // 写 vscdb（读一次真实 secret 键名，缺行则按默认键名插入）
    const dbv = caReadDb() || {};
    const secretKey = dbv.secretKey || CA_SECRET_KEY_DEFAULT;
    let db = null;
    try {
      db = caOpenDb(CA_VSCDB, false);
      db.exec('PRAGMA busy_timeout = 3000');
      db.prepare('INSERT OR REPLACE INTO ItemTable (key, value) VALUES (?, ?)').run(secretKey, secretValue);
      if (rec.snapState) db.prepare('INSERT OR REPLACE INTO ItemTable (key, value) VALUES (?, ?)').run(CA_SNAP_KEY, rec.snapState);
    } finally {
      try { if (db) db.close(); } catch (_) {}
    }
    // VSCode 保有 state.vscdb.backup 兜底副本（打开异常时会回退到它），同步覆盖防止旧会话复活
    try { fs.copyFileSync(CA_VSCDB, CA_VSCDB + '.backup'); } catch (_) {}
    // 内核侧 userInfo.json 一并换回（若备份里带）
    if (rec.userInfoJson) {
      try {
        fs.mkdirSync(path.dirname(CA_DOER_USERINFO), { recursive: true });
        const tmp = CA_DOER_USERINFO + '.workpet-tmp';
        fs.writeFileSync(tmp, rec.userInfoJson);
        fs.renameSync(tmp, CA_DOER_USERINFO);
      } catch (e) { log('[client:ca] 回写 userInfo.json 失败（不影响登录态）: ' + e.message); }
    }
    // 账号库：当前账号指向切换后的记录
    const st2 = loadStore();
    const idx = st2.codearts.accounts.findIndex((x) => x && String(x.uid) === String(uid));
    if (idx >= 0) st2.codearts.current = st2.codearts.accounts[idx];
    saveStore(st2);
    log('[client:ca] 已切换账号 -> ' + (rec.nickname || uid));
    let relaunched = false;
    if (wasRunning) {
      relaunched = caLaunchIde();
      log('[client:ca] 切换前客户端在运行，已自动重启');
    }
    return { uid, nickname: rec.nickname || uid, relaunched };
  } finally {
    caSwitching = false;
  }
}

const CLIENT_CHECKIN_CACHE_FILE = path.join(DATA_ROOT, 'client-checkin-cache.json');
const clientCheckinState = {
  wb: { inFlight: false, running: false, total: 0, done: 0, startedAt: 0, finishedAt: 0 },
  cb: { inFlight: false, running: false, total: 0, done: 0, startedAt: 0, finishedAt: 0 },
  ac: { inFlight: false, running: false, total: 0, done: 0, startedAt: 0, finishedAt: 0 },
  ca: { inFlight: false, running: false, total: 0, done: 0, startedAt: 0, finishedAt: 0 },
  as: { inFlight: false, running: false, total: 0, done: 0, startedAt: 0, finishedAt: 0 },
  zc: { inFlight: false, running: false, total: 0, done: 0, startedAt: 0, finishedAt: 0 },
};
// WB/CB 账号体系互通：同一账号在两端并发签到会被服务端以「请求处理中」拒绝，
// 因此签到全局串行（一次只跑一个 profile 的签到轮）
let clientClaimGlobalLock = false;

function clientLoadCheckinCache(profileId) {
  try {
    const all = JSON.parse(fs.readFileSync(CLIENT_CHECKIN_CACHE_FILE, 'utf8'));
    return all[profileId] || {};
  } catch (_) { return {}; }
}
function clientSaveCheckinCache(profileId, cache) {
  try {
    let all = {};
    try { all = JSON.parse(fs.readFileSync(CLIENT_CHECKIN_CACHE_FILE, 'utf8')); } catch (_) {}
    all[profileId] = cache;
    const tmp = CLIENT_CHECKIN_CACHE_FILE + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(all, null, 2));
    fs.renameSync(tmp, CLIENT_CHECKIN_CACHE_FILE);
  } catch (_) {}
}

/** 读取客户端当前登录（auth 文件为唯一真相） */
function clientReadAuth(profileId) {
  if (profileId === 'ac') {
    // AutoClaw：解密 auth.json，归一化成 { account, auth } 形状供下游统一消费
    const a = acReadAuth();
    if (!a || a.error || !a.userId) return null;
    return {
      account: { uid: String(a.userId), nickname: a.phone || String(a.userId), phoneNumber: a.phone || '' },
      auth: {
        accessToken: a.token,
        refreshToken: a.refreshToken || '',
        expiresAt: a.jwtExp || null,
        lastRefreshTime: Date.now(),
      },
    };
  }
  if (profileId === 'as') {
    // AStudio：登录态是明文 JSON，无加密；归一化成 { account, auth, session } 供下游统一消费
    const s = asReadSession();
    if (!s) return null;
    return {
      account: { uid: String(s.uid), nickname: s.nickname || String(s.uid), phoneNumber: s.mobile || '' },
      auth: { accessToken: String(s.token || ''), refreshToken: '', expiresAt: null, lastRefreshTime: null },
      session: s, // 原样保留，切换时整文件写回
    };
  }
  if (profileId === 'zc') {
    // ZCode：凭据文件为 enc:v1 密文；归一化成 { account, auth, cred }（cred 供切换整文件写回）
    const live = zcReadCreds();
    if (!live) return null;
    const info = zcUserInfoFrom(live.creds);
    if (!info) return null;
    return {
      account: { uid: info.uid, nickname: info.nickname, phoneNumber: info.email },
      auth: { accessToken: '', refreshToken: '', expiresAt: info.jwtExp || null, lastRefreshTime: null },
      cred: live.creds, // 原样保留，切换时整文件写回
    };
  }
  const raw = readJsonOrNull(CLIENT_PROFILES[profileId].authFile);
  if (!raw || !raw.account || !raw.account.uid) return null;
  return raw;
}

/** 把当前登录同步进账号库（登录文件变化时调用）；CodeArts 走异步解密，单独实现 */
function clientSyncStore(profileId) {
  if (profileId === 'ca') return; // ca 由 caSyncStore（异步）维护，不走 auth 文件路径
  if (profileId === 'zc') { try { zcSyncStore(); } catch (e) { log('[client:zc] 同步账号库失败: ' + e.message); } return; }
  const raw = clientReadAuth(profileId);
  if (!raw) return;
  const store = loadStore();
  const uid = String(raw.account.uid);
  if (profileId === 'as') {
    // as 段：扁平记录 + 完整 session 快照（切换账号时整文件写回 astron-session.json）。
    // 必须先于下面的 sec 三元返回，否则会落进 ac 段（三元默认分支是 'ac'）。
    if (asSwitching) return; // 切换写入过程中别把中间态覆盖回账号库
    const rec = {
      uid,
      nickname: wbStr(raw.account.nickname) || uid,
      phone: wbStr(raw.account.phoneNumber) || '',
      loginMethod: (raw.session && raw.session.loginMethod) || '',
      session: raw.session,
      tokenExpiresAt: null,
      backedUpAt: Date.now(),
    };
    const i = store.as.accounts.findIndex((x) => x && String(x.uid) === uid);
    if (i >= 0) store.as.accounts[i] = Object.assign({}, store.as.accounts[i], rec);
    else store.as.accounts.push(rec);
    store.as.current = Object.assign({}, store.as.accounts[i >= 0 ? i : store.as.accounts.length - 1]);
    saveStore(store);
    return;
  }
  const sec = store[profileId === 'wb' ? 'workbuddy' : profileId === 'cb' ? 'codebuddy' : 'ac'];
  if (profileId === 'ac') {
    // ac 段存扁平记录（uid/accessToken/tokenExpiresAt），与 wb/cb 的 { account, auth } 结构不同
    const rec = {
      uid,
      nickname: raw.account.nickname || uid,
      phone: raw.account.phoneNumber || '',
      tokenExpiresAt: raw.auth.expiresAt || null,
      accessToken: raw.auth.accessToken,
      refreshToken: raw.auth.refreshToken || '',
      lastRefreshTime: raw.auth.lastRefreshTime || Date.now(),
    };
    const i = sec.accounts.findIndex((x) => x && String(x.uid) === uid);
    if (i >= 0) sec.accounts[i] = Object.assign({}, sec.accounts[i], rec);
    else sec.accounts.push(rec);
    sec.current = sec.accounts[i >= 0 ? i : sec.accounts.length - 1];
    saveStore(store);
    return;
  }
  const idx = sec.accounts.findIndex((a) => a && a.account && String(a.account.uid) === uid);
  if (idx >= 0) sec.accounts[idx] = raw;
  else sec.accounts.push(raw);
  sec.current = raw;
  saveStore(store);
}

/**
 * WorkBuddy 5.6 起 `nickname` / `phoneNumber` / `accessToken` / `refreshToken` 等字段会被写成
 * `{$wbEncrypted, envelope}` 加密信封对象（同一机器 keyblob 下由 WorkBuddy 自身解密）。
 * 这里不解密，只做「取用安全」处理：信封一律视为「无可用明文值」。否则对象会漏进前端
 * 渲染成 [object Object]，或被当 Bearer token 拼成 "Bearer [object Object]" 导致签到/积分全挂。
 */
function wbIsEnvelope(v) {
  return !!(v && typeof v === 'object' && !Array.isArray(v) && v.$wbEncrypted);
}
// 取字段的「明文字符串」：字符串原样返回；信封/其它类型返回 null。
function wbStr(v) {
  return typeof v === 'string' && v.length ? v : null;
}

/** 列出客户端全部账号 + 当前登录（当前以 auth 文件为准）；CodeArts 单独实现 */
function clientListAccounts(profileId) {
  if (profileId === 'ca') return caListAccounts();
  if (profileId === 'as') return asListAccounts();
  if (profileId === 'zc') return zcListAccounts();
  if (profileId === 'ac' && ac2IsNewLayout()) return ac2ListAccounts();
  clientSyncStore(profileId);
  const store = loadStore();
  const sec = store[profileId === 'wb' ? 'workbuddy' : profileId === 'cb' ? 'codebuddy' : 'ac'];
  const currentRaw = clientReadAuth(profileId);
  const currentUid = currentRaw && currentRaw.account ? String(currentRaw.account.uid) : null;
  const seen = new Set();
  const list = [];
  const push = (raw) => {
    if (profileId === 'ac') {
      // ac 段扁平记录
      if (!raw || !raw.uid) return;
      const uid2 = String(raw.uid);
      if (seen.has(uid2)) return;
      seen.add(uid2);
      list.push({
        uid: uid2,
        nickname: wbStr(raw.nickname) || String(uid2),
        phone: wbStr(raw.phone) || '',
        uin: '',
        tokenExpiresAt: raw.tokenExpiresAt || null,
        refreshExpiresAt: null,
        lastRefreshTime: raw.lastRefreshTime || null,
      });
      return;
    }
    if (!raw || !raw.account) return;
    const uid = String(raw.account.uid);
    if (seen.has(uid)) return;
    seen.add(uid);
    const auth = raw.auth || {};
      list.push({
        uid,
        // nickname 加密时为信封对象 → 回落到明文 uin（账号数字 id），再回落 uid，避免 [object Object]
        nickname: wbStr(raw.account.nickname) || raw.account.uin || String(uid),
        // phoneNumber 加密时为信封对象 → 回落空串，前端显示 "-"
        phone: wbStr(raw.account.phoneNumber) || '',
        uin: raw.account.uin || '',
        tokenExpiresAt: auth.expiresAt || null,
        refreshExpiresAt: auth.refreshExpiresAt || null,
        lastRefreshTime: auth.lastRefreshTime || null,
      });
  };
  if (currentRaw) push(currentRaw);
  for (const a of sec.accounts) push(a);
  list.sort((a, b) => (a.uid === currentUid ? -1 : b.uid === currentUid ? 1 : 0));
  const cache = clientLoadCheckinCache(profileId);
  const today = todayStrLocal();
  return {
    currentUid,
    accounts: list.map((a) => {
      const rec = cache[a.uid];
      return Object.assign(a, {
        // 已有「今日 ok」缓存的账号即使在批量进行中也照常显示（否则加入旅行循环后
        // 批量变慢，UI 每 3s 的拉取几乎总落在 inFlight 窗口内，徽章会整体消失）
        checkin: rec && rec.date === today && (!clientCheckinState[profileId].inFlight || rec.ok)
          ? { ok: !!rec.ok, already: !!rec.already, code: rec.code, message: rec.message }
          : null,
        // WorkBuddy 成长空间自动旅行状态（旅行中倒计时/归来收益；其它端恒为 null）
        travel: profileId === 'wb' ? (wbTravelState[a.uid] || null) : null,
      });
    }),
  };
}

// ---------------- WorkBuddy 经 CDP 提取明文 token ----------------
// WorkBuddy 5.6 起 accessToken 是加密信封（{$wbEncrypted, envelope}），文件里的 token 不可用。
// 但 WorkBuddy 是 Electron 应用，被 WorkPet 以 --remote-debugging-port 拉起后，其渲染进程里
// 持有解密后的明文 token（localStorage / sessionStorage，或 window.electronAPI）。这里经 CDP
// 进渲染进程把它读出来，仅「当前登录账号」可获取（运行中的 app 只持有当前账号的 token）。
// 注意：WorkBuddy 与 TraeWork 共用 9222 调试端口，仅先拉起的一方有 CDP；且必须经 WorkPet 的
// 「启动 WorkBuddy（CDP 注入）」按钮拉起（带 --remote-debugging-port），手动打开的实例无端口。

/** 在指定 CDP WebSocket 上执行一段 JS，返回 returnByValue 的结果（失败/超时返回 null）。 */
async function cdpEvalOnWs(wsUrl, jsExpr, timeoutMs = 8000) {
  return new Promise((resolve) => {
    let ws;
    try { ws = new WebSocket(wsUrl); } catch (e) { return resolve(null); }
    const timer = setTimeout(() => { try { ws.close(); } catch (_) {} resolve(null); }, timeoutMs);
    let id = 0; const pend = new Map();
    ws.onopen = () => {
      const i = ++id;
      pend.set(i, true);
      ws.send(JSON.stringify({
        id: i, method: 'Runtime.evaluate',
        params: { expression: jsExpr, returnByValue: true, awaitPromise: true, scriptTimeout: Math.max(1000, timeoutMs - 1000) },
      }));
    };
    ws.onmessage = (ev) => {
      try {
        const m = JSON.parse(ev.data);
        if (m.id && pend.has(m.id)) {
          pend.delete(m.id);
          clearTimeout(timer);
          try { ws.close(); } catch (_) {}
          // CDP 响应结构是 {id, result:{result:{value}}}。这里 resolve 的是整条消息，
          // 必须取 m.result.result.value；写成 m.result.value 会永远拿到 undefined
          // （曾导致 WorkBuddy 的 CDP 取明文 token 静默失效，一直回落到文件 token）。
          const rv = m.result && (m.result.result ? m.result.result.value : m.result.value);
          resolve(m.error ? null : rv);
        }
      } catch (_) {}
    };
    ws.onerror = () => { clearTimeout(timer); resolve(null); };
    ws.onclose = () => { clearTimeout(timer); };
  });
}

/** 连接 WorkBuddy 的 CDP 端口，定位其渲染页（按标题/url 含 workbuddy，避开 TraeWork 的 workbench），执行 JS。 */
async function wbCdpEval(jsExpr) {
  const port = CLIENT_PROFILES.wb.cdpPort;
  let list;
  try {
    const r = await fetch(`http://127.0.0.1:${port}/json/list`, { signal: AbortSignal.timeout(1500) });
    list = await r.json();
  } catch (_) { return null; }
  const targets = Array.isArray(list) ? list : [];
  const page = targets.find((t) => t.type === 'page' && /workbuddy/i.test(String(t.title || '') + ' ' + String(t.url || '')))
    || targets.find((t) => t.type === 'page' && !/workbench|vscode-file/i.test(String(t.url || '')));
  if (!page || !page.webSocketDebuggerUrl) return null;
  return cdpEvalOnWs(page.webSocketDebuggerUrl, jsExpr);
}

// 渲染进程内执行的提取逻辑：扫 localStorage/sessionStorage 与 window.electronAPI，收集所有 JWT 形态的 token。
async function wbExtractTokenImpl() {
  try {
    const jwtRe = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
    const pick = (o) => {
      if (!o) return null;
      if (typeof o === 'string') { const s = o.replace(/^Bearer\s+/i, '').trim(); return jwtRe.test(s) ? s : null; }
      const flat = JSON.stringify(o);
      const m = flat.match(/"([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)"/);
      return m ? m[1] : null;
    };
    const scan = (store) => {
      const out = [];
      if (!store || !store.length) return out;
      for (let i = 0; i < store.length; i++) {
        const k = store.key(i);
        let v = null;
        try { v = store.getItem(k); } catch (e) { continue; }
        const t = pick(v);
        if (t) out.push(t);
      }
      return out;
    };
    let found = [];
    try { found = found.concat(scan(window.localStorage)); } catch (e) {}
    try { found = found.concat(scan(window.sessionStorage)); } catch (e) {}
    const api = window.electronAPI;
    if (api && typeof api === 'object') {
      const cands = ['getToken', 'getAccessToken', 'getTokenCache', 'getAuth', 'accessToken', 'token'];
      for (const m of cands) {
        try {
          const fn = api[m];
          if (typeof fn === 'function') { const r = await fn.call(api); const t = pick(r); if (t) found.push(t); }
          else if (typeof fn === 'string') { const t = pick(fn); if (t) found.push(t); }
        } catch (e) {}
      }
    }
    return { found: found, hasApi: !!api };
  } catch (e) { return { found: [], error: String(e) }; }
}

/** 经 CDP 取当前 WorkBuddy 账号的明文 token；5 分钟缓存，过期或失效再拉。返回 {token,uid,exp} 或 null。 */
let wbTokenCache = { token: null, uid: null, exp: 0, at: 0 };
async function wbExtractToken() {
  const now = Date.now();
  if (wbTokenCache.token && now - wbTokenCache.at < 5 * 60 * 1000 && wbTokenCache.exp > now) return wbTokenCache;
  const obj = await wbCdpEval('(' + wbExtractTokenImpl.toString() + ')()').catch(() => null);
  if (!obj || !Array.isArray(obj.found) || !obj.found.length) return null;
  for (const t of obj.found) {
    try {
      const parts = String(t).split('.');
      if (parts.length !== 3) continue;
      const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
      const uid = String(payload.user_id || payload.uid || payload.sub || payload.phone || payload.jti || '');
      const exp = payload.exp ? payload.exp * 1000 : 0;
      if (exp && exp <= now) continue; // 过期 token 跳过
      wbTokenCache = { token: t, uid, exp, at: now };
      return wbTokenCache;
    } catch (_) {}
  }
  return null;
}

async function clientTokenFor(profileId, uid) {
  if (profileId === 'ca') return null; // CodeArts 无签到/积分，不需要取 token
  if (profileId === 'zc') return null; // ZCode 无签到/积分，不需要取 token
  if (profileId === 'as') {
    // AStudio 的本地服务只服务「当前登录账号」→ 非当前账号返回 null（静默跳过签到/积分）。
    // 这里返回的是 session.token（UUID，非 JWT），仅作为「该账号可查询」的凭据标记；
    // 真正的本地 API 鉴权 token 在渲染进程内存里，由 CDP 流程自行解析。
    const cur = clientReadAuth('as');
    if (!cur || !cur.account) return null;
    return String(cur.account.uid) === String(uid) ? (wbStr(cur.auth && cur.auth.accessToken) || 'current') : null;
  }
  if (profileId === 'ac' && ac2IsNewLayout()) {
    // AutoClaw2：token 锁在 app-bound 加密凭据里（外部解不开），积分经 CDP 渲染进程取。
    // 仅当前活跃账号可查询；其余备份账号返回 null（静默跳过）。
    const activeKey = ac2ReadActiveKey();
    const act = ac2ReadProfiles().find((p) => p.accountKey === activeKey) || null;
    return act && String(act.accountId) === String(uid) ? 'current' : null;
  }
  // WorkBuddy 5.6+：accessToken 是加密信封（{$wbEncrypted, envelope}），文件里的 token 不可用。
  // 但 WorkBuddy 是 Electron 应用，被 WorkPet 以 --remote-debugging-port 拉起后，其渲染进程里
  // 持有解密后的明文 token。这里优先经 CDP 取「当前登录（运行中）账号」的明文 token。
  // 仅运行中的那一个账号能取到；其它账号回落到文件里的明文/信封（信封→null，禁用其签到/积分）。
  if (profileId === 'wb') {
    try {
      const cdp = await wbExtractToken();
      if (cdp && cdp.token) {
        const cur = clientReadAuth('wb');
        const curUid = cur && cur.account ? String(cur.account.uid) : null;
        // 请求的账号即当前（运行中的）账号 → 直接用 CDP 取到的明文 token
        if (String(uid) === String(curUid)) return cdp.token;
        // 否则若 token 自带的 uid 也能对上请求的账号，也用
        if (cdp.uid && String(cdp.uid) === String(uid)) return cdp.token;
      }
    } catch (e) {
      log('[client:wb] CDP 取 token 失败: ' + e.message);
    }
  }
  const raw = clientReadAuth(profileId);
  // WorkBuddy 5.6：accessToken 可能是 {$wbEncrypted, envelope} 信封对象，必须拦下，
  // 否则会被拼成 "Bearer [object Object]" 发给官方接口。信封需由 WorkBuddy 自身解密。
  if (raw && String(raw.account.uid) === String(uid)) return wbStr(raw.auth && raw.auth.accessToken);
  const store = loadStore();
  const sec = store[profileId === 'wb' ? 'workbuddy' : profileId === 'cb' ? 'codebuddy' : 'ac'];
  const rec = sec.accounts.find((a) => a && (a.account ? String(a.account.uid) === String(uid) : String(a.uid) === String(uid)));
  if (!rec) return null;
  if (rec.auth) return wbStr(rec.auth.accessToken);
  return wbStr(rec.accessToken); // ac 段账号记录直接存 accessToken
}

/** AutoClaw 调试端口（CDP）是否已在监听（复用中，无需重复拉起） */
async function isAcCdpUp(port) {
  try {
    const r = await fetch(`http://127.0.0.1:${port}/json/version`, { signal: AbortSignal.timeout(800) });
    if (!r.ok) return false;
    const o = await r.json().catch(() => ({}));
    return !!(o && o.webSocketDebuggerUrl);
  } catch (_) { return false; }
}

/** 启动 AutoClaw（带 --remote-debugging-port，供 CDP 签到所用）；不做 download 等待，只需拉起 */
function acLaunchBinary() {
  const port = CLIENT_PROFILES.ac.cdpPort;
  // 复用已运行的调试实例
  return isAcCdpUp(port).then((up) => {
    if (up) { log('[client:ac] CDP 已在监听，复用现有 AutoClaw'); return 'reuse'; }
    const exe = isMac
      ? '/Applications/AutoClaw.app/Contents/MacOS/AutoClaw'
      : ['D:/Program Files/AutoClaw2/AutoClaw2.exe', // 新版：安装目录与 exe 都改名 AutoClaw2
         'D:/Program Files/AutoClaw/AutoClaw.exe',
         path.join(process.env.ProgramFiles || 'C:/Program Files', 'AutoClaw2', 'AutoClaw2.exe'),
         path.join(process.env.ProgramFiles || 'C:/Program Files', 'AutoClaw', 'AutoClaw.exe'),
         path.join(process.env.LOCALAPPDATA || '', 'Programs', 'AutoClaw2', 'AutoClaw2.exe'),
         path.join(process.env.LOCALAPPDATA || '', 'Programs', 'AutoClaw', 'AutoClaw.exe')]
        .find((p) => { try { return fs.existsSync(p); } catch (_) { return false; } });
    if (!exe) throw new Error('未找到 AutoClaw 可执行文件');
    if (isMac && (() => { try { return !fs.existsSync(exe); } catch (_) { return true; } })()) {
      throw new Error('未找到 AutoClaw 可执行文件（' + exe + '）');
    }
    const args = ['--remote-debugging-port=' + port];
    if (isMac) {
      // 拉起前先杀旧实例：用户已开 / 上次拉起的实例都会带 single-instance-lock，
      // 不杀干净，新进程会立刻退出 → CDP 端口永远不开 → 反复拉起。
      // 最多两轮，每轮都重新杀 + 等退出 + spawn
      return acLaunchMacWithRetry(exe, args, port, 2);
    }
    spawn(exe, args, { detached: true, stdio: 'ignore', windowsHide: true }).unref();
    log(`[client:ac] 已拉起 AutoClaw (--remote-debugging-port=${port})`);
    return Promise.resolve('launched');
  });
}

/** macOS 上带「杀旧实例 + 等退出 + spawn + 端口就绪检测」重试逻辑的拉起 */
async function acLaunchMacWithRetry(exe, args, port, maxAttempts) {
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    killAutoClaw();
    const gone = await waitProcessGone(exe, 5000);
    if (!gone) log(`[client:ac] 旧实例未在 5s 内退出（第 ${attempt} 次）`);
    // spawn 的 ENOENT 等错误经异步 'error' 事件抛出，不监听会整个进程崩溃（unhandled 'error'）
    const ch = spawn(exe, args, { stdio: 'ignore', detached: true });
    ch.on('error', (e) => log(`[client:ac] 拉起 AutoClaw 失败: ${e.message}`));
    ch.unref();
    log(`[client:ac] 已拉起 AutoClaw (--remote-debugging-port=${port}) 第 ${attempt} 次`);
    // 轮询端口就绪（最坏 15s）
    const dl = Date.now() + 15000;
    while (Date.now() < dl) {
      if (await isAcCdpUp(port)) return 'launched';
      await sleep(400);
    }
    log(`[client:ac] 第 ${attempt} 次拉起后 CDP 端口未就绪`);
  }
  throw new Error('AutoClaw CDP 端口在 2 次拉起后仍未就绪（单实例锁可能未释放）');
}

/** 等指定进程完全退出（macOS 强杀后旧 lock 文件可能残留） */
async function waitProcessGone(exe, timeoutMs) {
  const name = path.basename(exe);
  const dl = Date.now() + timeoutMs;
  while (Date.now() < dl) {
    try {
      const out = execFileSync('pgrep', ['-x', name], { encoding: 'utf8' });
      if (!out.trim()) return true;
    } catch (_) { return true; } // pgrep 找不到进程 = 退出码 1
    await sleep(300);
  }
  return false;
}

/**
 * AutoClaw CDP 点击签到（方案1，macOS 优先）：当 AutoClaw 正以 --remote-debugging-port 运行时，
 * 经 CDP 找到「每日签到」按钮点击，让 AutoClaw 用自己内存中的登录态完成签到，
 * 从而完全绕开 auth.json 的 AES key 解密（macOS 上钥匙串密码与实际 key 不匹配的坑）。
 *
 * 仅在界面可见「签到」且未显示「已完成/已签到」时触发；成功返回 { cdp: true, already }。
 */
async function acCdpClickSignin() {
  const ports = [9226, 9225, 9224, 9223, 9222, 9227, 9228];
  let lastErr = null;
  for (const port of ports) {
    let ws = null;
    try {
      const list = await fetch(`http://127.0.0.1:${port}/json/list`, { signal: AbortSignal.timeout(1200) }).then(r => r.json()).catch(() => null);
      if (!Array.isArray(list)) { lastErr = `port${port}不可达`; continue; }
      const target = list.find(t => t.type === 'page' && t.webSocketDebuggerUrl && /AutoClaw|autoclaw/i.test(t.title || ''));
      if (!target) { lastErr = `port${port}无AutoClaw页面`; continue; }
      ws = new WebSocket(target.webSocketDebuggerUrl);
      await new Promise((res, rej) => { ws.onopen = res; ws.onerror = () => rej(new Error('ws连接失败')); });
      let id = 0; const pend = new Map();
      ws.onmessage = (ev) => { try { const m = JSON.parse(ev.data); if (m.id && pend.has(m.id)) { const { res, rej } = pend.get(m.id); pend.delete(m.id); m.error ? rej(new Error(m.error.message)) : res(m.result); } } catch (_) {} };
      const send = (method, params = {}) => new Promise((res, rej) => { const i = ++id; pend.set(i, { res, rej }); ws.send(JSON.stringify({ id: i, method, params })); });
      const evalJs = (expression) => send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true }).then(r => r.result && r.result.value);
      // 检查签到区状态
      const state = await evalJs(`(() => { const t = (document.body && document.body.innerText) || '';
        const doneBtn = [...document.querySelectorAll('button')].some(b => /已.?完成|已签.{1,3}天/i.test((b.textContent||'').trim()));
        return { textHasDone: /已.?完成|已签.{1,3}天/i.test(t) }; })()`);
      if (state && state.textHasDone) {
        log('[client:ac] CDP 检查：今日已签到（界面显示已完成），跳过');
        return { cdp: true, already: true };
      }
      // 点击「签到」按钮（避免点到「去邀请」「已完成」等）
      const clicked = await evalJs(`(() => { const btns = [...document.querySelectorAll('button')];
        const b = btns.find(x => /^签到$|^签\s*到$/.test((x.textContent||'').trim()));
        if (b) { b.click(); return 'clicked'; }
        return 'notfound'; })()`);
      if (clicked !== 'clicked') { lastErr = '未找到「签到」按钮'; continue; }
      log('[client:ac] CDP 已点击「签到」按钮，等待 AutoClaw 自行完成...');
      await new Promise(r => setTimeout(r, 6000));
      // 回读结果（界面是否变为已完成/已签）
      const after = await evalJs(`(() => { const t = (document.body && document.body.innerText) || '';
        return { done: /已.?完成|已签.{1,3}天/i.test(t), around: (t.match(/每日签到得[\\s\\S]{0,120}/) || [])[0] || '' }; })()`);
      return { cdp: true, already: false, message: '已触发 AutoClaw 自己签到', body: { after } };
    } catch (e) {
      lastErr = e.message;
    } finally {
      if (ws) { try { ws.close(); } catch (_) {} }
    }
  }
  throw new Error('CDP 点击签到失败: ' + lastErr);
}

/**
 * 通用：在 AutoClaw 的 CDP 渲染进程执行一段 JS，返回 returnByValue 结果。
 * 遍历常见调试端口，命中 AutoClaw 页面即执行；全部失败则 throw。
 */
async function acCdpEvalOnce(jsExpr) {
  const ports = [9226, 9225, 9224, 9223, 9222, 9227, 9228];
  let lastErr = null;
  // 只保留最后一个端口的错误会掩盖真实原因：AutoClaw 实际监听 9226，而列表末尾的 9228
  // 通常压根没监听，于是 9226 上的真实失败（ws 连接失败 / 页面内 JS 报错）会被
  // "port9228不可达" 覆盖掉，日志里看不到任何有效线索。这里同时记住首个错误。
  let firstErr = null;
  const note = (m) => { if (firstErr === null) firstErr = m; lastErr = m; };
  for (const port of ports) {
    let ws = null;
    try {
      const list = await fetch(`http://127.0.0.1:${port}/json/list`, { signal: AbortSignal.timeout(1500) }).then(r => r.json()).catch(() => null);
      if (!Array.isArray(list)) { note(`port${port}不可达`); continue; }
      const target = list.find(t => t.type === 'page' && t.webSocketDebuggerUrl && /AutoClaw|autoclaw/i.test(t.title || ''));
      if (!target) { note(`port${port}无AutoClaw页面`); continue; }
      ws = new WebSocket(target.webSocketDebuggerUrl);
      await new Promise((res, rej) => { ws.onopen = res; ws.onerror = () => rej(new Error('ws连接失败')); });
      let id = 0; const pend = new Map();
      ws.onmessage = (ev) => { try { const m = JSON.parse(ev.data); if (m.id && pend.has(m.id)) { const { res, rej } = pend.get(m.id); pend.delete(m.id); m.error ? rej(new Error(m.error.message)) : res(m.result); } } catch (_) {} };
      const send = (method, params = {}) => new Promise((res, rej) => { const i = ++id; pend.set(i, { res, rej }); ws.send(JSON.stringify({ id: i, method, params })); });
      const r = await send('Runtime.evaluate', { expression: jsExpr, returnByValue: true, awaitPromise: true, scriptTimeout: 8000 });
      return r.result && r.result.value;
    } catch (e) {
      note(e.message);
    } finally {
      if (ws) { try { ws.close(); } catch (_) {} }
    }
  }
  throw new Error('CDP 不可用: ' + (firstErr === lastErr ? String(lastErr) : `${firstErr} … ${lastErr}`));
}

/**
 * macOS 专属：经 CDP 从 AutoClaw 渲染进程的 electronAPI.auth 读取登录态与积分，
 * 完全绕开 auth.json 的 AES 钥匙串解密（macOS 上钥匙串密码与实际 key 不匹配的坑）。
 * 成功写入 store 的 ac 段（扁平记录），并返回 { raw, points }。
 */
async function acEnsureAuthViaCdp() {
  if (!isMac) return null;
  const obj = await acCdpEvalOnce(`(async () => {
    const auth = window.electronAPI && window.electronAPI.auth;
    if (!auth) return { error: 'no-auth-api' };
    try {
      const uc = await auth.getUserCache();
      const tc = await auth.getTokenCache();
      let pts = null, exp = null;
      try { pts = await auth.getPoints(); } catch (e) {}
      try { exp = await auth.getExpiringPoints(); } catch (e) {}
      return {
        userCache: uc || null,
        tokenCache: tc || null,
        points: (pts && pts.ok) ? pts : null,
        expiring: (exp && exp.ok) ? exp : null,
      };
    } catch (e) { return { error: 'call-fail: ' + (e && e.message) }; }
  })()`);
  if (!obj || obj.error || !obj.tokenCache || !obj.tokenCache.token) {
    throw new Error('CDP 读取 AutoClaw 登录态失败: ' + (obj && obj.error));
  }
  const tc = obj.tokenCache;
  const uc = obj.userCache || {};
  const rawToken = String(tc.token).replace(/^Bearer\s+/i, '');
  // jwt payload（未验证签名，仅解析字段）；tc 本身无 jwt 字段，需自行解码
  let jwtPayload = {};
  try {
    const p = rawToken.split('.');
    if (p[1]) jwtPayload = JSON.parse(Buffer.from(p[1], 'base64url').toString('utf8'));
  } catch (_) {}
  const token = rawToken;
  const uid = String(jwtPayload.user_id || uc.userId || tc.userId || '');
  // 手机号优先取 tokenCache.user.phone；否则退而用 email（jwt jti 形如 xxx@gmail.com）
  const email = jwtPayload.jti || '';
  const store = loadStore();
  const tab = store.ac;
  const rec = {
    uid,
    nickname: uc.userName || uc.nickname || uid,
    phone: (tc.user && tc.user.phone) || uc.phone || (email || ''),
    tokenExpiresAt: (jwtPayload.exp ? jwtPayload.exp * 1000 : null) || tc.expiresAt || null,
    lastRefreshTime: Date.now(),
    accessToken: token,
  };
  // 加分字段不污染账号记录：积分类单独缓存
  acCdpPointsCache = { points: (obj.points && obj.points.points) || null, expiring: (obj.expiring && obj.expiring.expiringPoints) || null, ts: Date.now() };
  const i = tab.accounts.findIndex((x) => x && String(x.uid) === String(uid));
  if (i >= 0) tab.accounts[i] = Object.assign({}, tab.accounts[i], rec);
  else tab.accounts.push(rec);
  tab.current = Object.assign({}, tab.accounts[i >= 0 ? i : tab.accounts.length - 1], rec);
  saveStore(store);
  log('[client:ac] CDP 已从 AutoClaw 读取登录态: ' + uid + ' (' + (rec.nickname || '') + ') 积分=' + (acCdpPointsCache.points));
  return { raw: { token, uid, nickname: rec.nickname, phone: rec.phone }, points: acCdpPointsCache };
}

/** AutoClaw 经 CDP 读取的积分缓存（{ points, expiring, ts }） */
let acCdpPointsCache = null;

/**
 * macOS 专属：经 CDP 调用 AutoClaw 的 electronAPI.auth 完成任务中心签到。
 * 使用 getTaskList 判断 daily_signin 状态，未完成才调用 completeClientTask 执行签到；
 * 幂等返回 { already }，完全绕开 HTTP 接口（macOS token 无法经 HTTP 认证的坑）。
 */
async function acCdpSignin() {
  const r = await acCdpEvalOnce(`(async () => {
    const auth = window.electronAPI && window.electronAPI.auth;
    if (!auth) return { error: 'no-auth-api' };
    try {
      const tl = await auth.getTaskList();
      const task = (tl && tl.data || []).find((x) => x.task_id === 'daily_signin');
      if (task && task.status === 'completed') {
        return { already: true, day: task.status_description || '' };
      }
      const done = await auth.completeClientTask({ task_id: 'daily_signin' });
      return { already: !!(done && done.data && done.data.already_completed), resp: done };
    } catch (e) { return { error: 'call-fail: ' + (e && e.message) }; }
  })()`);
  if (!r || r.error) throw new Error('CDP 任务签到失败: ' + (r && r.error));
  return { cdp: true, already: !!r.already };
}

/** AutoClaw 签到 = 任务中心 daily_signin 任务完成（每日 200 分）；响应 data.already_completed = 已签 */
async function acDailyCheckin(accessToken) {
  // 方案1（macOS 优先，临启即关，对齐 TraeWork）：签到时自动启动 AutoClaw（CDP 模式），
  // 经应用内任务 API 自行签到（绕开 HTTP token 认证坑），签到完成后自动关闭 AutoClaw。
  if (isMac) {
    // 记录是否由本进程临时拉起 AutoClaw：仅「临时拉起」场景签到后自动关闭，
    // 若复用用户已运行的实例则不关闭，避免打扰用户正在使用的客户端。
    try {
      const how = await acLaunchBinary(); // 'reuse' 复用现有实例，'launched' 本次临时拉起
      // acLaunchBinary 内部已确保 9226 端口就绪
      const r = await acCdpSignin();
      if (how === 'launched') {
        try { killAutoClaw(); log('[client:ac] CDP 签到完成，已自动关闭临时拉起的 AutoClaw'); } catch (_) {}
      } else {
        log('[client:ac] CDP 签到完成（复用已运行实例，保持 AutoClaw 不关闭）');
      }
      return { ok: true, ...r, code: 0 };
    } catch (e) { log('[client:ac] CDP 签到失败: ' + e.message + ' → 回退 API 方式'); }
  }
  let lastErr = null;
  for (let attempt = 0; attempt < 3; attempt++) {
    if (attempt > 0) await sleep(2000);
    try {
      const r = await fetch(AC_API_HOST + '/autoclaw-proxy/proxy/autoclaw-task-complete', {
        method: 'POST',
        headers: acSignHeaders({ 'content-type': 'application/json', authorization: 'Bearer ' + accessToken }),
        body: JSON.stringify({ task_id: 'daily_signin' }),
        signal: AbortSignal.timeout(12000),
      });
      const o = await r.json().catch(() => ({}));
      const code = o.code;
      const already = !!(o.data && o.data.already_completed);
      if (code === 0 || already) {
        return { ok: true, already, code, message: o.msg || 'ok', body: o, reward: (o.data && o.data.reward_points) || 0 };
      }
      if (code === 410000 || r.status === 401) return { ok: false, code, message: '登录身份过期', body: o };
      lastErr = o.msg || ('HTTP ' + r.status);
    } catch (e) {
      lastErr = e.message;
    }
  }
  return { ok: false, message: lastErr || '签到失败' };
}

/** AutoClaw 积分查询：GET /agent-assetmgr/api/v1/points/expiring?biz_app_id=autoclaw */
async function acFetchCredits(accessToken) {
  // macOS 优先：用 CDP 从 AutoClaw 应用内读取积分（electronAPI.auth.getPoints），
  // 完全绕开 HTTP 接口对 auth.json 解密的依赖；缓存不过期则直接用。
  if (isMac && acCdpPointsCache && acCdpPointsCache.points != null) {
    const { points, expiring } = acCdpPointsCache;
    const segments = [];
    const exp = Number(expiring) || 0;
    const tot = Number(points) || 0;
    if (exp > 0) segments.push({ remaining: exp, total: exp, expiresAt: null, source: exp + ' 积分即将过期' });
    if (tot - exp > 0) segments.push({ remaining: tot - exp, total: tot - exp, expiresAt: null, source: '长期积分' });
    return { credits: tot, count: segments.length, totalDosage: 0, segments };
  }
  let lastErr = null;
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      const r = await fetch(AC_API_HOST + '/agent-assetmgr/api/v1/points/expiring?biz_app_id=autoclaw', {
        method: 'GET',
        headers: acSignHeaders({ authorization: 'Bearer ' + accessToken }),
        signal: AbortSignal.timeout(12000),
      });
      const o = await r.json().catch(() => ({}));
      if (o.code !== 0) throw new Error(o.msg || ('code=' + o.code));
      const total = Number(o.data && o.data.total_points) || 0;
      const expiring = Number(o.data && o.data.expiring_points) || 0;
      const expireText = String((o.data && o.data.expiring_points_text) || '');
      const segments = [];
      if (expiring > 0) {
        segments.push({ remaining: expiring, total: expiring, expiresAt: null, source: expireText || '即将过期' });
      }
      if (total - expiring > 0) {
        segments.push({ remaining: total - expiring, total: total - expiring, expiresAt: null, source: '长期积分' });
      }
      return { credits: total, count: segments.length, totalDosage: 0, segments };
    } catch (e) {
      lastErr = e;
      if (attempt < 3) await sleep(300 * attempt);
    }
  }
  throw lastErr || new Error('积分查询失败');
}

async function clientDailyCheckin(profileId, accessToken) {
  if (profileId === 'ca') return { ok: false, message: 'CodeArts Agent 无签到（额度按官方政策自动发放）' };
  if (profileId === 'zc') return { ok: false, message: 'ZCode 无每日签到' };
  if (profileId === 'as') return asDailyCheckin(); // AStudio 每日积分：云端直连优先，CDP 兜底
  if (profileId === 'ac') {
    if (ac2IsNewLayout()) return { ok: false, message: 'AutoClaw2 无每日签到' };
    return acDailyCheckin(accessToken);
  }
  const profile = CLIENT_PROFILES[profileId];
  let lastErr = null;
  for (let attempt = 0; attempt < 3; attempt++) {
  if (attempt > 0) await sleep(2000);
  for (const host of profile.checkinHosts) {
    for (const cpath of ['/billing/meter/daily-checkin', '/v2/billing/meter/daily-checkin']) {
      try {
        const r = await fetch(host + cpath, {
          method: 'POST',
          headers: {
            accept: 'application/json, text/plain, */*',
            'content-type': 'application/json',
            'x-client-platform': 'web',
            origin: profile.apiHost,
            referer: profile.apiHost + '/profile/plans-usage',
            authorization: 'Bearer ' + accessToken,
            'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36',
          },
          body: '{}',
          signal: AbortSignal.timeout(12000),
        });
        const text = await r.text();
        let o = {};
        try { o = JSON.parse(text); } catch (_) {}
        const code = o.code;
        const already = code === 10001;
        const deviceLimit = /已经签到/.test(o.msg || o.message || '');
        if (already || deviceLimit || (r.ok && (code === 0 || code === undefined))) {
          return { ok: true, already, deviceLimit, code, message: o.msg || o.message || 'ok', body: o };
        }
        if (r.status === 401) return { ok: false, code, message: '登录身份过期', body: o };
        const busy = /请求处理中|重复操作|请稍后再试/.test(o.msg || o.message || '');
        if (busy) { lastErr = o.msg || o.message; break; }
        if (r.status >= 400 && r.status !== 404) return { ok: false, code, message: 'HTTP ' + r.status, body: o };
        lastErr = o.msg || o.message || ('HTTP ' + r.status);
      } catch (e) {
        lastErr = e.message;
      }
    }
  }
  }
  return { ok: false, message: lastErr || '签到失败' };
}

/**
 * 签到后同步账号的 Cookie 时限（tokenExpiresAt）进账号库：
 * - 当前登录账号：auth 文件是唯一真相（客户端刷新 token 时会重写该文件），
 *   立即把 auth.expiresAt / refreshExpiresAt / lastRefreshTime 同步进记录，
 *   不等 5s 的 watchFile 轮询，切换走之后记录也不会残留旧有效期。
 * - 其他账号：登录态只有备份库里一份，仅当签到响应明确带「刷新 token + 有效期」
 *   时才兜底更新，否则保持原值（不臆造有效期）。
 * 只更新有效期元数据，绝不改写 accessToken，避免写坏登录态。
 */
function clientSyncTokenExpiryAfterCheckin(profileId, uid, respBody) {
  if (profileId === 'ca') return; // CodeArts 无签到，有效期由 caSyncStore 维护
  if (profileId === 'zc') return; // ZCode 无签到；有效期展示取 zcodejwttoken 的 exp
  if (profileId === 'as') return; // AStudio 会话无到期字段（只有 loggedInAt），且下方 sec 三元会落到 ac 段
  // 各种形态 → 毫秒时间戳（数字秒/毫秒、数字字符串、ISO 日期字符串）
  const asMs = (v) => {
    if (v == null) return null;
    if (typeof v === 'number') {
      if (!Number.isFinite(v) || v <= 0) return null;
      return v > 1e12 ? v : v * 1000; // 秒 → 毫秒
    }
    if (typeof v === 'string') {
      const s = v.trim();
      if (!s) return null;
      if (/^\d+(\.\d+)?$/.test(s)) {
        const n = Number(s);
        if (!Number.isFinite(n) || n <= 0) return null;
        return n > 1e12 ? n : n * 1000;
      }
      const ms = Date.parse(s);
      return Number.isFinite(ms) && ms > 0 ? ms : null;
    }
    return null;
  };

  const store = loadStore();
  const sec = store[profileId === 'wb' ? 'workbuddy' : profileId === 'cb' ? 'codebuddy' : 'ac'];
  const idx = sec.accounts.findIndex((x) => x && (x.account ? String(x.account.uid) === String(uid) : String(x.uid) === String(uid)));
  if (idx < 0) return;
  const rec = sec.accounts[idx];

  // AutoClaw：账号记录是扁平结构（uid/accessToken/tokenExpiresAt），JWT exp 即 Cookie 时限
  if (profileId === 'ac') {
    const fileAuth = clientReadAuth('ac');
    const fileExp = fileAuth && fileAuth.auth ? fileAuth.auth.expiresAt : null;
    const prevExp = rec.tokenExpiresAt || null;
    const nextExp = fileExp != null ? fileExp : prevExp;
    if (nextExp !== prevExp && nextExp != null) {
      sec.accounts[idx] = Object.assign({}, rec, { tokenExpiresAt: nextExp, lastRefreshTime: Date.now() });
      if (sec.current && String(sec.current.uid) === String(uid)) sec.current = sec.accounts[idx];
      saveStore(store);
      log('[client:ac] ' + (rec.nickname || uid) + ' Cookie 时限已同步 -> ' + new Date(nextExp).toISOString());
    }
    return;
  }

  const prevAuth = rec.auth || {};
  const nextAuth = Object.assign({}, prevAuth);

  // 当前登录账号：以 auth 文件为准
  const fileRaw = clientReadAuth(profileId);
  if (fileRaw && fileRaw.auth && String(fileRaw.account.uid) === String(uid)) {
    const fe = asMs(fileRaw.auth.expiresAt);
    const fr = asMs(fileRaw.auth.refreshExpiresAt);
    const fl = asMs(fileRaw.auth.lastRefreshTime);
    if (fe != null) nextAuth.expiresAt = fe;
    if (fr != null) nextAuth.refreshExpiresAt = fr;
    if (fl != null) nextAuth.lastRefreshTime = fl;
  }

  // 签到响应若带刷新后的 token 及其有效期则兜底更新：
  // 只认明确的 token 对象（data.token / data.tokenInfo / data.auth，或顶层带 accessToken），
  // 避免把积分包到期时间之类的字段误当成 Cookie 时限。
  if (respBody && typeof respBody === 'object') {
    const d = (respBody.data && typeof respBody.data === 'object') ? respBody.data : {};
    const tokenObjs = [d.token, d.tokenInfo, d.auth].filter((t) => t && typeof t === 'object');
    if (respBody.accessToken || respBody.token) tokenObjs.push(respBody);
    let exp = null;
    for (const t of tokenObjs) {
      exp = asMs(t.expiresAt) ?? asMs(t.expireTime) ?? asMs(t.expiredAt);
      if (exp != null) break;
    }
    if (exp != null && exp > Date.now() && asMs(nextAuth.expiresAt) !== exp) nextAuth.expiresAt = exp;
  }

  const changed = nextAuth.expiresAt !== prevAuth.expiresAt
    || nextAuth.refreshExpiresAt !== prevAuth.refreshExpiresAt
    || nextAuth.lastRefreshTime !== prevAuth.lastRefreshTime;
  if (!changed) return;
  sec.accounts[idx] = Object.assign({}, rec, { auth: nextAuth });
  if (sec.current && sec.current.account && String(sec.current.account.uid) === String(uid)) {
    sec.current = sec.accounts[idx];
  }
  saveStore(store);
  log('[client:' + profileId + '] ' + (rec.account.nickname || uid) + ' Cookie 时限已同步 -> '
    + (nextAuth.expiresAt ? new Date(nextAuth.expiresAt).toISOString() : '(无)'));
}

// ---------------- WorkBuddy 自动旅行（成长中心「派猫猫旅行」） ----------------
// 规则（官方 ToS + 抓包实测）：每日 1 次（自然日重置），时长随机 1~4h，奖励 5~10 积分；
// 到家后须在「下一次出发前」领取，逾期作废。4 个地点奖励完全相同 → 随机选。
// API 逆向自 usercenter web（/activity/growth/buddy/travel/*），鉴权同签到（Bearer accessToken）。
// 免启动（纯云端调用，不需要 WorkBuddy 客户端运行）。
const WB_TRAVEL_BASE = 'https://www.workbuddy.cn';
const WB_TRAVEL_RUN_INTERVAL_MS = 10 * 60 * 1000; // 节流：最多 10 分钟跑一轮（到点领取的精度足够）
let wbTravelLastRunAt = 0;

function wbTravelHeaders(token) {
  return {
    accept: 'application/json, text/plain, */*',
    authorization: 'Bearer ' + token,
    origin: 'https://www.workbuddy.cn',
    referer: 'https://www.workbuddy.cn/profile/growth-center',
    'content-type': 'application/json',
    'x-client-platform': 'web',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/151.0.0.0 Safari/537.36',
  };
}

async function wbTravelGet(token, pathName) {
  const r = await fetch(WB_TRAVEL_BASE + pathName, { headers: wbTravelHeaders(token), signal: AbortSignal.timeout(10000) });
  const t = await r.text();
  let o;
  try { o = JSON.parse(t); } catch (_) { throw new Error('旅行接口响应解析失败 (HTTP ' + r.status + ')'); }
  if (!r.ok || (o.code !== 0 && o.code !== undefined)) throw new Error(o.msg || ('HTTP ' + r.status));
  return o.data || {};
}

/** 单账号旅行状态机：idle → 出发；traveling 且已到点 → 领取；其余跳过。
 *  不做本地缓存 —— 旅行状态以服务端为准，每轮只多 1 个 GET。 */
async function wbTravelAutomation(uid, nickname, token) {
  const st = await wbTravelGet(token, '/activity/growth/buddy/travel/status');
  const nowSec = Number(st.server_now || Math.floor(Date.now() / 1000));
  const state = String(st.state || '');
  const arriveAt = Number(st.arrive_at || 0);
  const who = nickname || String(uid).slice(0, 8);
  if (state === 'traveling' || state === 'completed') {
    if (!arriveAt || arriveAt > nowSec) return; // 还在路上
    const c = await fetch(WB_TRAVEL_BASE + '/activity/growth/buddy/travel/claim', {
      method: 'POST', headers: wbTravelHeaders(token), body: '{}', signal: AbortSignal.timeout(10000),
    });
    const o = await c.json().catch(() => ({}));
    if (c.ok && (o.code === 0 || o.code === undefined)) {
      const reward = o.data && (o.data.reward_credit ?? o.data.credits);
      log('[client:wb] 旅行奖励已领取（' + who + '）：+' + (reward != null ? reward : '?') + ' 积分');
    } else {
      log('[client:wb] 旅行奖励领取失败（' + who + '）：' + (o.msg || ('HTTP ' + c.status)));
    }
    return;
  }
  if (st.daily_limit_reached) return; // 今日已旅行（含已领取），明天再来
  if (state !== 'idle') return; // 其他状态（如未接受活动协议）不自动处理
  let locations = [];
  try { locations = (await wbTravelGet(token, '/activity/growth/buddy/travel/config')).locations || []; } catch (_) {}
  const loc = locations.length ? locations[Math.floor(Math.random() * locations.length)] : { id: 1, name: '咖啡馆' };
  const d = await fetch(WB_TRAVEL_BASE + '/activity/growth/buddy/travel/depart', {
    method: 'POST', headers: wbTravelHeaders(token), body: JSON.stringify({ location_id: loc.id }), signal: AbortSignal.timeout(10000),
  });
  const o = await d.json().catch(() => ({}));
  if (!d.ok || o.code !== 0) { log('[client:wb] 派旅行失败（' + who + '）：' + (o.msg || ('HTTP ' + d.status))); return; }
  const dur = (o.data && (o.data.duration_hours || (o.data.location && o.data.location.duration_hours))) || '?';
  log('[client:wb] 已派 Buddy 旅行（' + who + '）：' + (loc.name || '') + '，时长 ' + dur + 'h，预计 +5~10 积分');
}

// ---------------- WorkBuddy 成长空间：自动旅行（云端直连，免启动客户端） ----------------
// 逆向自 usercenter 前端 growthSpace 分包。旅行 = 伙伴（buddy）外出 1-4 小时，到达后
// 领取积分（5-10/次，每日上限 3 次），不消耗体力（体力用于开蛋/抽卡，不在本功能范围）。
// 鉴权与 wb 签到一致：Bearer accessToken。全部是 www.workbuddy.cn 的云端调用 —— 免启动。
const WB_GROWTH_BASE = 'https://www.workbuddy.cn';
const wbTravelState = Object.create(null); // uid → 最近一次旅行循环结果（内存，仅供账号列表展示）

function wbGrowthHeaders(accessToken) {
  return {
    accept: 'application/json',
    authorization: 'Bearer ' + accessToken,
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36',
  };
}

async function wbGrowthGet(pathName, accessToken) {
  const r = await fetch(WB_GROWTH_BASE + pathName, { headers: wbGrowthHeaders(accessToken), signal: AbortSignal.timeout(10000) });
  const j = await r.json().catch(() => null);
  if (!r.ok || !j || j.code !== 0) {
    throw new Error('成长空间接口失败 (HTTP ' + r.status + '): ' + String((j && j.msg) || '').slice(0, 80));
  }
  return j.data || {};
}

async function wbGrowthPost(pathName, body, accessToken) {
  const r = await fetch(WB_GROWTH_BASE + pathName, {
    method: 'POST',
    headers: Object.assign({}, wbGrowthHeaders(accessToken), { 'content-type': 'application/json' }),
    body: JSON.stringify(body === undefined ? {} : body),
    signal: AbortSignal.timeout(10000),
  });
  const j = await r.json().catch(() => null);
  if (!r.ok || !j || j.code !== 0) {
    throw new Error('成长空间接口失败 (HTTP ' + r.status + '): ' + String((j && j.msg) || '').slice(0, 80));
  }
  return j.data || {};
}

/** 单次旅行循环：到达→领取（空 body，服务端按登录态找未领记录）；
 *  未达每日上限→随机选地点出发；旅行中→返回倒计时信息。 */
async function wbTravelCycle(accessToken) {
  const st = await wbGrowthGet('/activity/growth/buddy/travel/status', accessToken);
  const now = Number(st.server_now || Math.floor(Date.now() / 1000));
  const arrive = Number(st.arrive_at || 0);
  const locName = (st.location && st.location.name) || '';
  // 1) 旅行中且未到达 → 只报状态
  if (st.state === 'traveling' && arrive > now) {
    return {
      state: 'traveling', locationName: locName, arriveInSec: arrive - now,
      rewardCredit: Number(st.reward_credit || 0), dailyLimitReached: !!st.daily_limit_reached,
      recordId: Number(st.record_id || 0), // UI 据此识别「新出发」并提示
    };
  }
  // 2) 已到达（state=arrived 或旅行时间已过）→ 领取（claim 空 body）
  let claimed = 0;
  if (st.state === 'arrived' || (st.record_id && arrive && arrive <= now)) {
    await wbGrowthPost('/activity/growth/buddy/travel/claim', {}, accessToken);
    claimed = Number(st.reward_credit || 0);
  }
  // 3) 今日次数已用完 → 不再出发；拉旅行记录取「最近一次已领取的奖励」供徽章展示
  if (st.daily_limit_reached) {
    let credited = claimed;
    let lastLoc = locName;
    try {
      const recs = ((await wbGrowthGet('/activity/growth/buddy/travel/records?page=1&page_size=3', accessToken)).records) || [];
      const lastRec = recs.find((x) => x.claimed_at) || recs[0] || null;
      if (lastRec) {
        credited = Number(lastRec.reward_credit || 0) || credited;
        lastLoc = (lastRec.location && lastRec.location.name) || lastLoc;
      }
    } catch (_) {}
    return { state: 'idle', dailyLimitReached: true, claimedCredit: credited, locationName: lastLoc };
  }
  // 4) 随机选一个地点出发
  const cfg = await wbGrowthGet('/activity/growth/buddy/travel/config', accessToken);
  const locs = cfg.locations || [];
  if (!locs.length) return { state: 'idle', dailyLimitReached: !!st.daily_limit_reached, claimedCredit: claimed };
  const loc = locs[Math.floor(Math.random() * locs.length)];
  await wbGrowthPost('/activity/growth/buddy/travel/depart', { location_id: loc.id }, accessToken);
  return {
    state: 'traveling', locationName: loc.name,
    arriveInSec: (loc.duration_hours || 1) * 3600, rewardCredit: Number(loc.reward_credit_min || 0),
    claimedCredit: claimed, departNow: true,
  };
}

/** 为单个账号跑旅行循环（取 token → 循环 → 记录状态），异常只记日志不抛出。
 *  60 秒节流：账号列表每次刷新都会触发批量，避免每个账号每轮打 1-4 次云端。 */
async function wbTravelCycleFor(profileId, uid, nickname, tkHint) {
  if (profileId !== 'wb') return;
  const last = wbTravelState[uid];
  if (last && last.checkedAt && Date.now() - last.checkedAt < 60_000 && !last.error) return;
  try {
    const tk = tkHint || (await clientTokenFor(profileId, uid));
    if (!tk) { wbTravelState[uid] = { error: '无 accessToken', checkedAt: Date.now() }; return; }
    const tr = await wbTravelCycle(tk);
    const prev = wbTravelState[uid] || {};
    wbTravelState[uid] = Object.assign({ checkedAt: Date.now() }, tr, {
      // 保留上次领取额：idle（今日已领完）状态下徽章要显示「已到账 +N」
      claimedCredit: tr.claimedCredit || prev.claimedCredit || 0,
    });
    if (tr.claimedCredit) log('[client:wb] ' + (nickname || uid) + ' 旅行归来 +' + tr.claimedCredit + ' 积分');
    else if (tr.departNow) log('[client:wb] ' + (nickname || uid) + ' 已出发旅行 → ' + (tr.locationName || '') + '（奖励约 ' + tr.rewardCredit + ' 积分）');
  } catch (e) {
    wbTravelState[uid] = { error: e.message, checkedAt: Date.now() };
    log('[client:wb] ' + (nickname || uid) + ' 自动旅行失败: ' + e.message);
  }
}

async function clientClaimDailyForAll(profileId) {
  if (profileId === 'ca') return { skipped: true, reason: 'no-checkin' }; // CodeArts 无签到，不进入签到轮
  if (profileId === 'zc') return { skipped: true, reason: 'no-checkin' }; // ZCode 无签到，仅账号备份/切换
  if (profileId === 'ac' && ac2IsNewLayout()) return { skipped: true, reason: 'no-checkin' }; // AutoClaw2 无每日签到
  const st = clientCheckinState[profileId];
  if (st.inFlight || clientClaimGlobalLock) return { skipped: true, reason: 'in-flight' };
  // AutoClaw 首次读账号前确保 AES key 已就绪（异步，12s 硬超时；失败则本轮按无 key 处理）
  if (profileId === 'ac') { try { await acRequestKey(); } catch (_) {} }
  const accounts = clientListAccounts(profileId).accounts;
  if (!accounts.length) return { skipped: true, reason: 'no-accounts' };
  st.inFlight = true;
  clientClaimGlobalLock = true;
  st.running = true;
  st.total = accounts.length;
  st.done = 0;
  st.startedAt = Date.now();
  st.finishedAt = 0;
  const cache = clientLoadCheckinCache(profileId);
  const today = todayStrLocal();
  const results = [];
  try {
    for (const a of accounts) {
      const hit = cache[a.uid];
      if (hit && hit.date === today && hit.ok) {
        st.done++;
        results.push({ uid: a.uid, nickname: a.nickname || a.uid, ok: true, already: !!hit.already, msg: hit.message || '今日已签' });
        // 已签到的账号也要跑旅行循环（到达自动领取 / 未达上限自动再出发）
        await wbTravelCycleFor(profileId, a.uid, a.nickname);
        continue;
      }
      const tk = await clientTokenFor(profileId, a.uid);
      if (!tk && profileId === 'as') {
        // AStudio 本地服务只服务当前登录账号：其余备份账号静默跳过。
        // 不写签到缓存（否则卡片会被标成「未签」），故下一轮会再试一次，代价仅一次文件读取。
        st.done++;
        results.push({ uid: a.uid, nickname: a.nickname || a.uid, ok: false, already: false, skipped: true, msg: '仅当前登录账号可签到' });
        continue;
      }
      let rec;
      let respBody = null;
      if (!tk) rec = { date: today, ok: false, code: -1, message: '无 accessToken' };
      else {
        const r = await clientDailyCheckin(profileId, tk);
        respBody = r.body;
        rec = { date: today, ok: !!r.ok, already: !!r.already, deviceLimit: !!r.deviceLimit, code: r.code, message: r.message || '' };
      }
      cache[a.uid] = rec;
      clientSaveCheckinCache(profileId, cache);
      // 签到后同步该账号的 Cookie 时限（tokenExpiresAt）：当前登录账号以 auth 文件为准，
      // 响应带刷新 token 的有效期则兜底更新，账号库不再残留旧的有效期
      try { clientSyncTokenExpiryAfterCheckin(profileId, a.uid, respBody); } catch (_) {}
      // AutoClaw：token 是 24h JWT，签到时若快过期（<2h）自动 refresh 并回写 auth.json，
      // 让「Cookie 时限」跟随签到保持即时续期（与用户需求：签到即同步 Cookie 时限一致）
      if (profileId === 'ac' && rec.ok) {
        try {
          const cur = clientReadAuth('ac');
          const exp = cur && cur.auth ? cur.auth.expiresAt : null;
          if (exp != null && exp - Date.now() < 2 * 3600 * 1000) {
            const r2 = await acRefreshToken();
            const newExp = acJwtExpMs(r2.accessToken);
            await acPersistRefreshedToken(r2.accessToken, r2.refreshToken);
            acSyncStoreAfterRefresh(r2.accessToken, r2.refreshToken, newExp);
            log('[client:ac] token 快过期，已 refresh 并回写，新时限 -> ' + (newExp ? new Date(newExp).toISOString() : '(无)'));
          }
        } catch (e) {
          log('[client:ac] token refresh 失败（不影响本次签到）: ' + e.message);
        }
      }
      st.done++;
      results.push({ uid: a.uid, nickname: a.nickname || a.uid, ok: !!rec.ok, already: !!rec.already, msg: rec.message || '' });
      log('[client:' + profileId + '] ' + a.nickname + ' 签到: ' + (rec.ok ? (rec.already ? '已签' : '成功') : rec.message));
      // WorkBuddy 成长空间：自动旅行（到达领取 → 未达上限自动出发；云端免启动）
      if (profileId === 'wb') await wbTravelCycleFor(profileId, a.uid, a.nickname, tk);
      await sleep(500);
    }
    // WorkBuddy 自动旅行：每账号每天 1 次出发 + 到点自动领取。
    // 10 分钟节流 —— 签到轮会被 /accounts 轮询频繁触发，旅行状态以服务端为准，无需本地缓存。
    if (profileId === 'wb' && Date.now() - wbTravelLastRunAt > WB_TRAVEL_RUN_INTERVAL_MS) {
      wbTravelLastRunAt = Date.now();
      for (const a of accounts) {
        try {
          const tk = await clientTokenFor(profileId, a.uid);
          if (!tk) continue; // 无可用 token（5.6+ 信封等）→ 跳过该账号的旅行
          await wbTravelAutomation(a.uid, a.nickname, tk);
          await sleep(300);
        } catch (e) {
          log('[client:wb] 旅行自动化失败 ' + (a.nickname || a.uid) + ': ' + e.message);
        }
      }
    }
  } finally {
    st.inFlight = false;
    st.running = false;
    st.finishedAt = Date.now();
    clientClaimGlobalLock = false;
  }
  return { total: st.total, done: st.done, results };
}

/** 积分查询（credit-resource-queries + fetchResource） */
function clientBuildResourceBody(now) {
  now = now || new Date();
  const end = new Date(now.getTime());
  end.setFullYear(end.getFullYear() + 101);
  const pad = (v) => String(v).padStart(2, '0');
  const f = (d) => d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) + ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds());
  return {
    PageNumber: 1, PageSize: 100, ProductCode: 'p_tcaca', Status: [0, 3],
    PackageEndTimeRangeBegin: f(now), PackageEndTimeRangeEnd: f(end),
  };
}

async function clientFetchCredits(profileId, accessToken) {
  if (profileId === 'ca') throw new Error('CodeArts Agent 额度按官方政策自动发放，无积分查询接口');
  if (profileId === 'zc') throw new Error('ZCode 无积分查询接口（仅账号备份/切换）');
  if (profileId === 'as') return asFetchCredits(); // AStudio 积分：云端直连优先，CDP 兜底
  if (profileId === 'ac') {
    if (ac2IsNewLayout()) return ac2FetchCreditsViaCdp(); // AutoClaw2：CDP 渲染进程 zworkAuth
    return acFetchCredits(accessToken); // 旧版 AutoClaw：HTTP + 解密 token
  }
  const profile = CLIENT_PROFILES[profileId];
  let lastErr = null;
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      const r = await fetch(profile.apiHost + '/v2/billing/meter/get-user-resource', {
        method: 'POST',
        headers: {
          accept: 'application/json, text/plain, */*',
          'content-type': 'application/json',
          'x-client-platform': 'web',
          origin: profile.apiHost,
          referer: profile.apiHost + '/profile/plans-usage',
          authorization: 'Bearer ' + accessToken,
          'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36',
        },
        body: JSON.stringify(clientBuildResourceBody()),
        signal: AbortSignal.timeout(12000),
      });
      const text = await r.text();
      let o;
      try { o = JSON.parse(text); } catch (e) { throw new Error('解析积分响应失败: ' + e.message); }
      if (!r.ok) throw new Error('积分接口 HTTP ' + r.status + ': ' + text.slice(0, 120));
      if (o.code !== 0 && o.code !== undefined) throw new Error(o.msg || ('积分接口返回 code=' + o.code));
      const data = (o.data && o.data.Response && o.data.Response.Data) ||
        (o.data && o.data.data && o.data.data.Response && o.data.data.Response.Data) || null;
      const accounts = (data && Array.isArray(data.Accounts) ? data.Accounts : null) ||
        (o.data && Array.isArray(o.data.accounts) ? o.data.accounts : null) ||
        (o.data && o.data.data && Array.isArray(o.data.data.accounts) ? o.data.data.accounts : null) || [];
      if (accounts.length === 0 && attempt < 3) { await sleep(300 * attempt); continue; }
      let credits = 0;
      for (const a of accounts) {
        // 剩余字段优先「周期剩余」(CycleCapacityRemainPrecise)：月度包用完时 CapacityRemainPrecise
        // 仍是满额，必须用周期剩余才算对。所有包组的剩余求和 = 总积分。
        const cands = [a.CycleCapacityRemainPrecise, a.CycleCapacityRemain, a.CapacityRemainPrecise, a.CapacityRemain];
        let v = NaN;
        for (const c of cands) {
          if (c === undefined || c === null || c === '') continue;
          const n = parseFloat(c);
          if (!Number.isNaN(n)) { v = n; break; }
        }
        if (!Number.isNaN(v)) credits += v;
      }
      let segments = sortCreditSegments(mergeCreditSegments(extractCreditSegments(accounts, '积分')));
      const visible = segments.reduce((sum, x) => sum + x.remaining, 0);
      if (credits > visible + 0.01) {
        segments = sortCreditSegments([
          ...segments,
          { remaining: credits - visible, total: credits - visible, expiresAt: null, source: '其他积分' },
        ]);
      }
      return { credits: parseFloat(credits.toFixed(2)), count: accounts.length, totalDosage: 0, segments: segments };
    } catch (e) {
      lastErr = e;
      if (attempt < 3) await sleep(300 * attempt);
    }
  }
  throw lastErr || new Error('积分查询失败');
}

/** CDP 刷新客户端页面（客户端以调试模式运行时） */
async function clientReloadViaCdp(profileId) {
  const profile = CLIENT_PROFILES[profileId];
  let list;
  try {
    const r = await fetch('http://127.0.0.1:' + profile.cdpPort + '/json/list', { signal: AbortSignal.timeout(2000) });
    list = await r.json();
  } catch (_) { return false; }
  const page = (Array.isArray(list) ? list : []).find(
    (t) => t.type === 'page' && /workbench(\.html)?|vscode-file/i.test(String(t.url || ''))
  );
  if (!page || !page.webSocketDebuggerUrl) return false;
  return new Promise((resolve) => {
    let ws = null;
    const finish = (v) => { clearTimeout(timer); try { ws && ws.close(); } catch (_) {} resolve(v); };
    const timer = setTimeout(() => finish(false), 6000);
    try { ws = new WebSocket(page.webSocketDebuggerUrl); } catch (e) { return finish(false); }
    ws.onopen = () => ws.send(JSON.stringify({ id: 1, method: 'Page.reload', params: {} }));
    ws.onmessage = (ev) => {
      try {
        const d = JSON.parse(ev.data);
        if (d.id === 1) finish(true);
      } catch (_) {}
    };
    ws.onerror = () => finish(false);
  });
}

// 登录文件变化 → 同步进账号库（每次打开/切换客户端都会重写 auth 文件）
// AutoClaw 的同步要先异步解密（key 缓存+树杀超时），不能同步阻塞事件循环
for (const pid of ['wb', 'cb', 'ac', 'as', 'zc']) {
  try {
    const authFile = pid === 'zc' ? zcCredFilePath() : CLIENT_PROFILES[pid].authFile;
    if (!authFile) continue; // AStudio 未安装 / ZCode 未登录时 authFile 为 null
    fs.watchFile(authFile, { interval: 5000 }, (cur, prev) => {
      if (!fs.existsSync(authFile)) return;
      if (cur.mtimeMs !== prev.mtimeMs) {
        const sync = () => { try { clientSyncStore(pid); log('[client:' + pid + '] 登录文件变化，已同步账号库'); } catch (_) {} };
        if (pid === 'ac') acRequestKey().then(sync).catch(() => {});
        else sync();
      }
    });
  } catch (_) {}
}
// 启动即预热 AutoClaw AES key（后台异步，不阻塞；避免首次读账号时等解密）
try { if (fs.existsSync(AC_AUTH_FILE)) acWarmKey(); } catch (_) {}

// CodeArts Agent：启动即预热 key + 备份当前登录；之后监听 state.vscdb 变化
// （客户端运行期间约每小时自动续期会话，续期后备份要跟着刷新，保证切换用的
//   refresh_token 始终新鲜）。文件变化频繁但仅在内容真正变化时才落盘。
try {
  if (CA_VSCDB && fs.existsSync(CA_VSCDB)) {
    caWarmKey();
    caRequestKey()
      .then(() => caSyncStore())
      .then((a) => { if (a && a.uid) log('[client:ca] 已备份当前账号 ' + (a.nickname || a.uid)); })
      .catch((e) => log('[client:ca] 启动备份失败: ' + e.message));
    fs.watchFile(CA_VSCDB, { interval: 5000 }, (cur, prev) => {
      if (!fs.existsSync(CA_VSCDB) || cur.mtimeMs === prev.mtimeMs || caSwitching) return;
      caRequestKey().then(() => caSyncStore()).catch(() => {});
    });
  }
} catch (_) {}


async function rotateAllAccounts({ claim }) {
  // 收集所有客户端登录态 + 备份当前账号，保证账号库完整
  try { collectAllTraeAccounts(); } catch (_) {}
  try { backupCurrentAccount(); } catch (_) {}
  const all = listAccounts();
  // Trae 限制每台设备每日只能一个账号领签到积分 → 按天轮换签到顺序，
  // 多账号隔天轮流领取（今天的 dayIdx 决定谁排在最前）
  const dayIdx = Math.floor(Date.now() / 86400000);
  const accounts = all.length > 1
    ? all.map((_, i) => all[(i + dayIdx) % all.length])
    : all;

  const originSecret = (() => {
    try {
      const json = JSON.parse(fs.readFileSync(storageFile(), 'utf8'));
      return json['iCubeAuthInfo://icube.cloudide'] || null;
    } catch (_) { return null; }
  })();
  // 仅当宿主本来就在运行时才停掉（防其覆盖登录态），结束后按原状恢复
  const hostWasRunning = isProcessRunning();
  if (hostWasRunning) {
    killTraeWork();
    await sleep(1500);
  }

  const results = [];
  for (const a of accounts) {
    const item = {
      uid: a.uid, nickname: a.nickname || a.uid,
      ok: false, already: false, checkedIn: false,
      packs: [], remaining: null, msg: '',
    };
    try {
      const rec = readAccountSecret(a.uid);
      writeAuthSecret(rec.secret);
      statusCache.at = 0; statusCache.data = null;
      entCache.at = 0; entCache.data = null;
      const st = await fetchStatus();
      const body = (st && st.data) || {};
      item.checkedIn = !!(st.ok && body.checked_in === true);

      // 权益包（剩余/总额/到期）→ 面板显示每账号剩余积分与积分点
      const ent = await fetchEntitlements();
      if (ent && ent.ok && ent.data && Array.isArray(ent.data.packs)) {
        item.packs = ent.data.packs.map((p) => ({
          name: p.name, limit: p.limit, remaining: p.remaining, expire_sec: p.expireTime,
        }));
        item.remaining = item.packs.reduce((s, p) => s + (p.remaining || 0), 0);
      }

      if (!claim) {
        item.ok = st.ok;
        item.msg = item.checkedIn ? '今日已签到' : '未签到（仅刷新积分）';
      } else if (item.checkedIn) {
        item.ok = true; item.already = true; item.msg = '今日已签到';
        markDeviceClaimedToday();
      } else {
        // 先尝试直连 HTTP 签到；被服务端拒绝（9074 等）时，自动经宿主官方 IPC
        // 签到（CDP 拉起宿主→走官方「签到按钮」同款通道→退出宿主），全程无需用户操作。
        let r = await doClaim();
        if (!r.ok) {
          await sleep(800);
          const re = await fetchStatus();
          item.checkedIn = !!(re.ok && re.data && re.data.checked_in === true);
        }
        if (item.checkedIn) {
          markDeviceClaimedToday();
          item.ok = true; item.msg = '签到成功';
        } else if (isDeviceClaimedToday()) {
          // 今日设备名额已被其他账号占用：设备已完成签到，不再拉起 TraeWork，
          // 状态按"已签"处理（Trae 按设备计算签到，名额被领 = 本设备今日已签）。
          // r.ok 必须同步置真，否则下方通用收尾会把 ok/msg 覆盖回失败。
          item.ok = true;
          item.already = true;
          item.msg = '本设备已有其他账号签到';
          r = { ok: true };
          log(`[claim_all] ${item.nickname} 跳过宿主 IPC 签到：设备今日名额已用（按已签计）`);
        } else if (r && r.retryable) {
          log(`[claim_all] ${item.nickname} HTTP 签到被服务端拒绝，改走宿主 IPC 签到（自动拉起/关闭 TraeWork）`);
          const viaApp = await claimViaApp();
          if (viaApp.ok) {
            item.checkedIn = true;
            r = { ok: true };
            markDeviceClaimedToday();
            log(`[claim_all] ${item.nickname} 宿主 IPC 签到成功`);
          } else {
            r = { ok: false, error: viaApp.error || '宿主 IPC 签到失败' };
            if (/已经签到/.test(viaApp.error || '')) markDeviceClaimedToday();
            log(`[claim_all] ${item.nickname} 宿主 IPC 签到失败: ${viaApp.error}`);
          }
        }
        if (!item.checkedIn) {
          item.ok = !!(r && r.ok);
          if (!item.ok) {
            item.msg = (r && (r.error || (r.data && (r.data.message || r.data.msg)))) || '签到失败';
          }
        }
      }

      // 签到时同步该账号的最新 Cookie 时限：若宿主在 IPC 签到期间刷新过登录态，
      // storage.json 里的密文会比备份库里的新——连同有效期一并写回账号库，
      // 保证面板上的「Cookie 时限」始终反映签到那一刻的真实有效期。
      try {
        let liveSecret = rec.secret;
        try {
          const cur = JSON.parse(fs.readFileSync(storageFile(), 'utf8'))['iCubeAuthInfo://icube.cloudide'];
          const curInfo = cur ? decodeSecret(cur) : null;
          if (curInfo && String(curInfo.userId) === String(a.uid)) liveSecret = cur;
        } catch (_) {}
        const liveInfo = decodeSecret(liveSecret);
        if (liveInfo && String(liveInfo.userId) === String(a.uid)) {
          const meta = accountMetaFromInfo(liveInfo);
          const store = loadStore();
          const idx = store.traework.accounts.findIndex((x) => String(x.uid) === String(a.uid));
          if (idx >= 0) {
            const prev = store.traework.accounts[idx];
            const secretChanged = prev.secret !== liveSecret;
            const metaChanged = prev.expiredAt !== meta.expiredAt || prev.refreshExpiredAt !== meta.refreshExpiredAt
              || (prev.nickname || '') !== meta.nickname || (prev.mobile || '') !== meta.mobile;
            if (secretChanged || metaChanged) {
              store.traework.accounts[idx] = Object.assign({}, prev, meta, { secret: liveSecret });
              if (secretChanged) store.traework.accounts[idx].backedUpAt = Date.now();
              saveStore(store);
              if (meta.expiredAt !== prev.expiredAt) {
                log(`[rotate] ${item.nickname}: Cookie 时限已同步 -> ${meta.expiredAt || '(无)'}${secretChanged ? '（登录态已刷新）' : ''}`);
              }
            }
          }
        }
      } catch (_) { /* 同步失败不影响签到结果 */ }
    } catch (e) { item.msg = e.message || String(e); }

    results.push(item);
    // 写入每账号积分缓存（含权益包明细），面板据此显示非当前账号的剩余积分
    creditsStore[item.uid] = {
      remaining: item.remaining,
      checkedIn: item.checkedIn,
      packs: item.packs,
      claimedOk: claim ? !!item.ok : (creditsStore[item.uid]?.claimedOk ?? null),
      at: Date.now(),
    };
    saveCreditsStore(creditsStore);
    log(`[rotate] ${item.nickname}: 剩余=${item.remaining ?? '?'} 已签=${item.checkedIn}${claim ? ' claim=' + (item.ok ? '成功' : item.msg) : ''}`);
  }

  // 恢复原账号登录态；宿主只在「轮换前就在运行」时才按原状重启
  if (originSecret) {
    try { writeAuthSecret(originSecret); } catch (e) { log('[rotate] 恢复原账号失败: ' + e.message); }
  }
  if (hostWasRunning) {
    try { await ensureTraeWorkWithCdp(); } catch (_) {}
  }
  statusCache.at = 0; statusCache.data = null;
  entCache.at = 0; entCache.data = null;
  return results;
}

async function runClaimAll() {
  if (claimAllJob.running) return;
  claimAllJob = { running: true, total: 0, done: 0, results: [], startedAt: Date.now(), finishedAt: 0 };
  log('[claim_all] 开始全账号自动签到');
  try {
    const accounts = listAccounts();
    claimAllJob.total = accounts.length;
    const results = await rotateAllAccounts({ claim: true });
    claimAllJob.results = results;
    claimAllJob.done = results.length;
    // AutoClaw：独立账号体系，一并签到（每日 daily_signin 任务，与 Trae 轮换互不影响）；
    // 结果并入 claimAllJob（total/results/done），前端「全部签到」进度和完成提示一起统计
    try {
      const acRes = await clientClaimDailyForAll('ac');
      if (!acRes.skipped) {
        claimAllJob.total += acRes.total || 0;
        claimAllJob.results = claimAllJob.results.concat(acRes.results || []);
        claimAllJob.done = claimAllJob.results.length;
      }
    } catch (e) {
      log('[claim_all] AutoClaw 签到异常: ' + e.message);
    }
  } catch (e) {
    log('[claim_all] 异常: ' + e.message);
  } finally {
    claimAllJob.running = false;
    claimAllJob.finishedAt = Date.now();
    log('[claim_all] 结束，用时 ' + Math.round((claimAllJob.finishedAt - claimAllJob.startedAt) / 1000) + 's');
    scheduleClaimCatchUp();
  }
}

// 有界补签：早高峰 Trae 服务端限流（9074「参与用户太多」）时，每 10 分钟补签一轮，
// 最多 6 轮；全部签成即停。不是常驻循环——当天签完或轮次用尽后不再触发。
let claimCatchUpCount = 0;
function scheduleClaimCatchUp() {
  // 「设备今日已签到」是 Trae 的按设备每日一次限制，无法通过重试解决，不算可补签失败
  const failed = (claimAllJob.results || []).some((r) => !r.ok && !/已经签到|已有其他账号签到/.test(r.msg || ''));
  if (!failed) { claimCatchUpCount = 0; return; }
  if (claimCatchUpCount >= 6) {
    log('[claim_all] 补签轮次已达上限（6 轮），今日停止补签');
    return;
  }
  claimCatchUpCount += 1;
  const n = claimCatchUpCount;
  log(`[claim_all] 有账号未签成，10 分钟后自动补签（第 ${n}/6 轮）`);
  setTimeout(() => {
    log(`[claim_all] 补签第 ${n} 轮开始`);
    runClaimAll();
  }, 10 * 60 * 1000);
}

/// 仅刷新各账号积分/签到状态（不签到）。宿主运行时不轮换（避免打断），直接返回。
async function refreshCreditsOnly() {
  if (claimAllJob.running) return { refreshed: false, reason: '任务进行中' };
  if (isProcessRunning()) return { refreshed: false, reason: 'TraeWork 正在运行' };
  log('[credits] 开始刷新各账号积分');
  const results = await rotateAllAccounts({ claim: false });
  return { refreshed: true, results };
}

// ---------------- 本地 HTTP API（供注入的宠物面板调用） ----------------
const statusCache = { at: 0, data: null };
function cachedStatus() {
  if (statusCache.data && Date.now() - statusCache.at < 30000) return statusCache.data;
  return null;
}

async function fetchStatus() {
  const hit = cachedStatus();
  if (hit) return hit;
  const auth = getAuth();
  if (auth.error) return { ok: false, error: auth.error };
  const r = await checkinRequest('status', auth);
  const out = { ok: r.ok, status: r.status, data: Object.assign({}, r.body), host: r.host, error: r.error };
  if (r.ok) { statusCache.at = Date.now(); statusCache.data = out; }
  return out;
}

/** 判断签到失败是否「临时性、可自动重试」：高峰期限流/5xx/网络抖动都算 */
function isTransientClaimFailure(r, data) {
  const code = data && data.code;
  if (code === 9074) return true;            // 当前参与用户太多，请稍后再试
  if (code === -1 || code === 500 || code === 502 || code === 503) return true; // 服务端限流/繁忙
  if (r.status === 429 || (r.status >= 500 && r.status < 600)) return true;
  if (!r.ok && !r.status) return true;       // 网络错误/超时
  return false;
}

let claimInFlight = false;
async function doClaim() {
  if (claimInFlight) return { ok: false, error: '签到进行中，请稍候' };
  claimInFlight = true;
  try {
    const auth = getAuth();
    if (auth.error) return { ok: false, error: auth.error };
    const r = await checkinRequest('claim', auth);
    const data = r.body || {};
    // claim 请求出错（超时/网络抖动/5xx）时，服务端可能已受理：
    // 回查一次状态，若 checked_in 已为 true，按「已签到成功」处理，避免误报失败。
    let claimedAnyway = false;
    if (!r.ok) {
      try {
        const s = await checkinRequest('status', auth);
        if (s.ok && s.body && s.body.checked_in === true) claimedAnyway = true;
      } catch (_) {}
    }
    // claim 成功后刷新状态缓存，让面板立即反映
    statusCache.at = 0; statusCache.data = null;
    entCache.at = 0; entCache.data = null;
    if (claimedAnyway) {
      log('[claim] 请求报错但状态显示已签到（服务端已受理），按成功处理');
      return { ok: true, status: 200, data: { code: 0, message: '已签到' }, claimedAnyway: true, error: r.error };
    }
    return { ok: r.ok, status: r.status, data, retryable: !r.ok && isTransientClaimFailure(r, data), error: r.error };
  } finally {
    claimInFlight = false;
  }
}

// ---------------- 权益额度（对齐 Trae 用量管理页） ----------------
// 用官方 ide_user_ent_usage 接口返回每个积分额度包（邀请奖励/每月登录赠送/签到奖励等）
// 的 剩余/总额 + 到期时间，供桌面端按用量页样式展示。
const entCache = { at: 0, data: null };
const ENT_USAGE_PATH = '/trae/api/v2/pay/ide_user_ent_usage';
function cachedEntitlements() {
  if (entCache.data && Date.now() - entCache.at < 30000) return entCache.data;
  return null;
}
async function fetchEntitlements() {
  const hit = cachedEntitlements();
  if (hit) return hit;
  const auth = getAuth();
  if (auth.error) return { ok: false, error: auth.error };
  let lastErr = null;
  for (const host of CHECKIN_HOSTS) {
    try {
      const r = await postJson(host + ENT_USAGE_PATH, {}, checkinHeaders(auth));
      const body = r.body || {};
      // 该接口成功码也为 code===0 或缺失 code
      const ok = r.status === 200 && (body.code === 0 || body.code === undefined || body.code === null);
      if (ok) {
        const packs = ((body.user_entitlement_pack_list) || [])
          .filter((p) => p && p.is_hide !== true)
          .map((p) => {
            const base = p.entitlement_base_info || {};
            const pq = (base.product_extra && base.product_extra.package_extra) || {};
            const limit = base.quota && typeof base.quota.credits_limit === 'number' ? base.quota.credits_limit : 0;
            const used = (p.usage && typeof p.usage.credits_amount === 'number')
              ? Math.max(0, p.usage.credits_amount) : 0;
            return {
              name: p.display_desc || p.group_name || '权益',
              groupType: p.group_type != null ? p.group_type : null,
              limit,
              used,
              remaining: limit > 0 ? Math.max(0, limit - used) : null,
              expireTime: (p.expire_time && p.expire_time > 0) ? p.expire_time
                : ((base.end_time && base.end_time > 0) ? base.end_time : 0),
              sourceType: pq.package_source_type != null ? pq.package_source_type : null,
              productType: base.product_type != null ? base.product_type : null,
            };
          })
          .filter((p) => p.limit > 0 && p.remaining !== null); // 只保留有积分配额的奖励桶
        const out = { ok: true, data: { usage_summary: body.usage_summary || null, packs } };
        entCache.at = Date.now(); entCache.data = out;
        return out;
      }
      lastErr = 'HTTP ' + r.status + ' ' + (body.message || body.msg || '');
    } catch (e) { lastErr = e.message; }
  }
  return { ok: false, error: lastErr };
}

/** 仅回显可信来源的 Origin；绝不用 *（避免恶意网页读到账号/会话响应）。
 *  允许：无 Origin（本地 CLI/curl）、'null'（Electron file:// renderer）、
 *  vscode-file://（TraeWork 注入页）、loopback。 */
function isAllowedApiOrigin(origin) {
  if (!origin) return true;
  if (origin === 'null') return true;
  try {
    const u = new URL(origin);
    if (u.protocol === 'vscode-file:') return true; // TraeWork 注入页
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return false;
    const host = String(u.hostname || '').toLowerCase();
    return host === 'localhost' || host === '127.0.0.1' || host === '[::1]';
  } catch (_) { return false; }
}

function corsOrigin(req) {
  const origin = String(req.headers.origin || '');
  return isAllowedApiOrigin(origin) ? origin : null;
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      let obj = {};
      try { obj = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'); } catch (_) {}
      resolve(obj);
    });
    req.on('error', reject);
  });
}

function sendJson(res, code, obj) {
  const text = JSON.stringify(obj);
  const headers = { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' };
  const origin = res.__twCorsOrigin;
  if (origin) { headers['Access-Control-Allow-Origin'] = origin; headers.Vary = 'Origin'; }
  res.writeHead(code, headers);
  res.end(text);
}

// 本地 API 鉴权：桌面端（Rust）会附带 X-WorkPet-Token；浏览器网页无法得知该值，
// 防止恶意页面跨域调用本机 API（切换/删除账号、导入备份等）。
const API_TOKEN = (() => {
  try {
    const t = fs.readFileSync(path.join(DATA_ROOT, '.api-token'), 'utf8').trim();
    if (t) return t;
  } catch (_) {}
  const t = crypto.randomBytes(32).toString('hex');
  try { fs.writeFileSync(path.join(DATA_ROOT, '.api-token'), t, { mode: 0o600 }); } catch (_) {}
  return t;
})();

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://' + HOST + ':' + UI_PORT);
  if (url.pathname.startsWith('/api/') && req.headers['x-workpet-token'] !== API_TOKEN) {
    return sendJson(res, 401, { ok: false, error: 'unauthorized' });
  }
  res.__twCorsOrigin = corsOrigin(req); // 传给 sendJson 回显
  // 预检：注入页可能带 CORS preflight
  if (req.method === 'OPTIONS') {
    const origin = res.__twCorsOrigin;
    res.writeHead(204, {
      'Access-Control-Allow-Origin': origin || '',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
      'Access-Control-Max-Age': '600',
    });
    return res.end();
  }
  try {
    if (req.method === 'GET' && url.pathname === '/api/health') {
      // 健康检查永远返回 200：桌面端靠 version/fingerprint 判断 daemon 就绪，
      // 此处一旦 500 会被误判为「版本不匹配」，误报「后台服务启动超时」。
      let authed = false;
      try { authed = !getAuth().error; } catch (_) {}
      return sendJson(res, 200, {
        ok: true, app: APP_BRAND, version: DAEMON_VERSION, ts: Date.now(), authed,
        // 脚本指纹 + 运行时 node 版本：桌面端据此识别「同版本号重新构建」导致的旧进程残留
        fingerprint: SELF_FINGERPRINT, node: process.version,
      });
    }
    if (req.method === 'GET' && url.pathname === '/api/checkin/status') {
      const r = await fetchStatus();
      return sendJson(res, r.ok ? 200 : 502, { ok: r.ok, ...r });
    }
    if (req.method === 'GET' && url.pathname === '/api/checkin/entitlements') {
      const r = await fetchEntitlements();
      return sendJson(res, r.ok ? 200 : 502, r);
    }
    if (req.method === 'POST' && url.pathname === '/api/checkin/claim') {
      const r = await doClaim();
      return sendJson(res, r.ok ? 200 : 502, { ok: r.ok, ...r });
    }
    if (req.method === 'POST' && url.pathname === '/api/checkin/claim_all') {
      if (!claimAllJob.running) void runClaimAll();
      return sendJson(res, 200, { ok: true, running: claimAllJob.running, done: claimAllJob.done, total: claimAllJob.total });
    }
    if (req.method === 'GET' && url.pathname === '/api/checkin/claim_all') {
      return sendJson(res, 200, { ok: true, ...claimAllJob });
    }
    if (req.method === 'POST' && url.pathname === '/api/credits/refresh') {
      const r = await refreshCreditsOnly();
      return sendJson(res, 200, { ok: true, ...r });
    }
    if (req.method === 'GET' && url.pathname === '/api/accounts') {
      const current = readCurrentAccount();
      const store = loadCreditsStore();
      const accounts = listAccounts().map((a) => ({
        ...a,
        // 每账号积分缓存（轮换时抓取），供面板显示非当前账号的剩余积分
        credits: store[a.uid]
          ? {
              remaining: store[a.uid].remaining,
              checkedIn: !!store[a.uid].checkedIn,
              claimedOk: store[a.uid].claimedOk ?? null,
              packs: Array.isArray(store[a.uid].packs) ? store[a.uid].packs : [],
              at: store[a.uid].at || 0,
            }
          : null,
      }));
      return sendJson(res, 200, { ok: true, current, accounts, deviceClaimDate: store.deviceClaimDate || null });
    }
    if (req.method === 'GET' && url.pathname.startsWith('/api/client/')) {
      const parts = url.pathname.split('/');
      const pid = parts[3];
      if (!CLIENT_PROFILES[pid]) return sendJson(res, 404, { ok: false, error: 'unknown client' });
      if (parts[4] === 'status') {
        const st = clientCheckinState[pid];
        let cdpConnected = false;
        if (CLIENT_PROFILES[pid].cdpPort) {
          try {
            const r = await fetch('http://127.0.0.1:' + CLIENT_PROFILES[pid].cdpPort + '/json/version', { signal: AbortSignal.timeout(1500) });
            cdpConnected = r.ok;
          } catch (_) {}
        }
        return sendJson(res, 200, {
          ok: true,
          profile: { id: pid, name: CLIENT_PROFILES[pid].name },
          batch: { running: st.running, total: st.total, done: st.done },
          cdp: { connected: cdpConnected },
        });
      }
      if (parts[4] === 'accounts') {
        clientClaimDailyForAll(pid).catch((e) => log('[client:' + pid + '] 自动签到失败: ' + e.message));
        // AutoClaw 账号列表：macOS 优先经 CDP 从 AutoClaw 应用内读登录态/积分（绕开 auth.json 钥匙串解密坑）；
        // CDP 不可用或读取失败再回退请求密钥做 auth.json 解密。
        if (pid === 'ac') {
          if (isMac) {
            try { await acEnsureAuthViaCdp(); }
            catch (e) { log('[client:ac] CDP 读登录态不可用，回退 auth.json 解密: ' + e.message); try { await acRequestKey(); } catch (_) {} }
          } else {
            try { await acRequestKey(); } catch (_) {}
          }
        }
        // CodeArts：登录态在 SQLite 且需解密，异步同步后返回（拉取同时即完成当前账号备份）
        if (pid === 'ca') {
          try { await caRequestKey(); await caSyncStore(); } catch (e) { log('[client:ca] 同步登录态失败: ' + e.message); }
          const list2 = caListAccounts();
          return sendJson(res, 200, { ok: true, ...list2, batch: clientCheckinState.ca });
        }
        if (pid === 'as') {
          // 刷新当前账号信息：云端直连优先（无需启动 AStudio），CDP 兜底；
          // 失败只记日志，仍返回账号库备份
          try { await asRefreshCurrentAccount(); }
          catch (e) { log('[client:as] 刷新当前账号不可用（仅展示账号库备份）: ' + e.message); }
          return sendJson(res, 200, { ok: true, ...asListAccounts(), batch: clientCheckinState.as });
        }
        if (pid === 'zc') {
          // ZCode：先把凭据文件当前登录并入账号库（拉取同时即完成备份），再返回列表
          try { zcSyncStore(); } catch (e) { log('[client:zc] 同步登录态失败: ' + e.message); }
          return sendJson(res, 200, { ok: true, ...zcListAccounts(), batch: clientCheckinState.zc });
        }
        const list = clientListAccounts(pid);
        return sendJson(res, 200, { ok: true, ...list, batch: clientCheckinState[pid] });
      }
      if (parts[4] === 'token-usage') {
        // WorkBuddy / CodeBuddy / AutoClaw Token 用量：扫描本机会话日志统计（60s 缓存）
        if (pid !== 'wb' && pid !== 'cb' && pid !== 'ac') return sendJson(res, 404, { ok: false, error: 'token usage only available for wb/cb/ac' });
        return sendJson(res, 200, { ok: true, ...clientUsageSummary(pid) });
      }
      return sendJson(res, 404, { ok: false, error: 'not found' });
    }
    if (req.method === 'POST' && url.pathname.startsWith('/api/client/')) {
      const parts = url.pathname.split('/');
      const pid = parts[3];
      if (!CLIENT_PROFILES[pid]) return sendJson(res, 404, { ok: false, error: 'unknown client' });
      const body = await readBody(req);
      if (parts[4] === 'credits') {
        if (pid === 'ca') return sendJson(res, 400, { ok: false, error: 'CodeArts Agent 额度按官方政策自动发放，无积分查询接口' });
        if (pid === 'zc') return sendJson(res, 400, { ok: false, error: 'ZCode 无积分查询接口（仅账号备份/切换）' });
        const uid = (body.uid || '').trim();
        const tk = await clientTokenFor(pid, uid);
        if (!tk) return sendJson(res, 404, { ok: false, error: '账号备份不存在或无 accessToken' });
        try {
          const r = await clientFetchCredits(pid, tk);
          return sendJson(res, 200, { ok: true, uid, credits: r.credits, count: r.count, segments: r.segments });
        } catch (e) {
          log('[client:' + pid + '] 积分查询失败 ' + uid + ': ' + e.message);
          return sendJson(res, 500, { ok: false, error: e.message });
        }
      }
      if (parts[4] === 'switch') {
        const uid = (body.uid || '').trim();
        // CodeArts：vscdb 写回 + 客户端重启，专用流程
        if (pid === 'ca') {
          try {
            const r = await caSwitchToAccount(uid);
            return sendJson(res, 200, { ok: true, uid, nickname: r.nickname, hint: r.relaunched ? '已切换并重启 CodeArts Agent' : '已切换；下次启动 CodeArts Agent 时生效' });
          } catch (e) {
            log('[client:ca] 切换失败: ' + e.message);
            return sendJson(res, 500, { ok: false, error: e.message });
          }
        }
        if (pid === 'as') {
          // AStudio：停客户端 → 写 astron-session.json + 两份 config.toml → 带 CDP 重启
          try {
            const r = await asSwitchToAccount(uid);
            return sendJson(res, 200, {
              ok: true, uid, nickname: r.nickname, reloaded: !!r.relaunched, alreadyCurrent: !!r.alreadyCurrent,
              hint: r.alreadyCurrent ? '该账号已是当前登录账号'
                : r.relaunched ? '已切换并重启 AStudio' : '已切换到该账号；下次启动 AStudio 时生效',
            });
          } catch (e) {
            log('[client:as] 切换失败: ' + e.message);
            return sendJson(res, 500, { ok: false, error: e.message });
          }
        }
        if (pid === 'zc') {
          // ZCode：停客户端 → 写回备份凭据整文件 → 重启（凭据加密可在 Node 内完整还原）
          try {
            const r = await zcSwitchToAccount(uid);
            return sendJson(res, 200, {
              ok: true, uid, nickname: r.nickname, reloaded: !!r.relaunched, alreadyCurrent: !!r.alreadyCurrent,
              hint: r.alreadyCurrent ? '该账号已是当前登录账号'
                : r.relaunched ? '已切换并重启 ZCode' : '已切换到该账号；下次启动 ZCode 时生效',
            });
          } catch (e) {
            log('[client:zc] 切换失败: ' + e.message);
            return sendJson(res, 500, { ok: false, error: e.message });
          }
        }
        const store = loadStore();
        const sec = store[pid === 'wb' ? 'workbuddy' : pid === 'cb' ? 'codebuddy' : 'ac'];
        if (pid === 'ac' && ac2IsNewLayout()) {
          // AutoClaw2：原生多账号（accounts/<key>/），切换 = 翻 active-product-account.json
          // 指针 + 重启客户端（凭据由它自己解密载入，app-bound 外部解不开）
          try {
            const r = await ac2SwitchToAccount(uid);
            return sendJson(res, 200, {
              ok: true, uid, nickname: r.nickname, reloaded: !!r.relaunched, alreadyCurrent: !!r.alreadyCurrent,
              hint: r.alreadyCurrent ? '该账号已是当前登录账号'
                : r.relaunched ? '已切换并重启 AutoClaw2' : '已切换到该账号；下次启动 AutoClaw2 时生效',
            });
          } catch (e) {
            log('[client:ac] 切换失败: ' + e.message);
            return sendJson(res, 500, { ok: false, error: e.message });
          }
        }
        if (pid === 'ac') {
          // 旧版 AutoClaw：登录态只有本机一份（auth.json），无多账号文件可切换；
          // 备份库里的其他账号只有 accessToken，回写会破坏 safeStorage 加密一致性，不支持
          return sendJson(res, 400, { ok: false, error: 'AutoClaw 暂不支持多账号切换（登录态由 AutoClaw 客户端管理）' });
        }
        const raw = sec.accounts.find((a) => a && a.account && String(a.account.uid) === String(uid));
        if (!raw) return sendJson(res, 404, { ok: false, error: '账号备份不存在' });
        try {
          const tmp = CLIENT_PROFILES[pid].authFile + '.tmp';
          fs.writeFileSync(tmp, JSON.stringify(raw, null, 2));
          fs.renameSync(tmp, CLIENT_PROFILES[pid].authFile);
          clientSyncStore(pid);
          const reloaded = await clientReloadViaCdp(pid);
          log('[client:' + pid + '] 已切换账号 ' + (raw.account.nickname || uid) + (reloaded ? '（CDP 已刷新）' : ''));
          return sendJson(res, 200, { ok: true, uid, reloaded, hint: reloaded ? '已切换并刷新窗口' : '登录文件已切换，重启客户端后生效' });
        } catch (e) {
          return sendJson(res, 500, { ok: false, error: e.message });
        }
      }
      if (parts[4] === 'delete') {
        const uid = (body.uid || '').trim();
        const store = loadStore();
        const sec = pid === 'ca' ? store.codearts : pid === 'as' ? store.as : pid === 'zc' ? store.zc : store[pid === 'wb' ? 'workbuddy' : pid === 'cb' ? 'codebuddy' : 'ac'];
        const before = sec.accounts.length;
        if (pid === 'ac' || pid === 'ca' || pid === 'as' || pid === 'zc') {
          sec.accounts = sec.accounts.filter((a) => a && String(a.uid) !== String(uid));
        } else {
          sec.accounts = sec.accounts.filter((a) => a && a.account && String(a.account.uid) !== String(uid));
        }
        saveStore(store);
        return sendJson(res, 200, { ok: true, deleted: before - sec.accounts.length });
      }
      return sendJson(res, 404, { ok: false, error: 'not found' });
    }
    if (req.method === 'POST' && url.pathname === '/api/backup/export') {
      try {
        const r = exportBackupFile();
        log('[backup] 已导出全部账号: ' + r.file);
        return sendJson(res, 200, { ok: true, ...r });
      } catch (e) {
        return sendJson(res, 500, { ok: false, error: e.message });
      }
    }
    if (req.method === 'GET' && url.pathname === '/api/backup/list') {
      return sendJson(res, 200, { ok: true, files: listBackupFiles() });
    }
    if (req.method === 'POST' && url.pathname === '/api/backup/import') {
      const body = await readBody(req);
      try {
        // 支持两种来源：直接传入文件内容 data，或传入导出文件名 name（数据目录内）
        let data = body.data;
        if (!data) {
          if (!/^WorkPet-accounts-\d{8}-\d{6}\.json$/.test(String(body.name || ''))) throw new Error('非法的备份文件名');
          data = readJsonOrNull(path.join(BACKUP_DIR, body.name));
        }
        const counts = await restoreBackupData(data);
        log('[backup] 已恢复账号: ' + JSON.stringify(counts));
        statusCache.at = 0; statusCache.data = null; entCache.at = 0; entCache.data = null;
        return sendJson(res, 200, { ok: true, counts });
      } catch (e) {
        return sendJson(res, 500, { ok: false, error: e.message });
      }
    }
    if (req.method === 'POST' && url.pathname === '/api/accounts/backup_all') {
      // 备份所有账号：跨客户端收集全部登录 + 备份当前登录（历史备份自动保留）
      try {
        const collected = collectAllTraeAccounts();
        let current = null;
        try { current = backupCurrentAccount(); } catch (_) {}
        const total = listAccounts().length;
        log('[backup_all] 收集 ' + collected.length + ' 个客户端登录，备份当前 ' + (current ? current.nickname : '无') + '，账号库共 ' + total + ' 个');
        return sendJson(res, 200, { ok: true, collected: collected.length, current, total });
      } catch (e) {
        return sendJson(res, 500, { ok: false, error: e.message });
      }
    }
    if (req.method === 'POST' && url.pathname === '/api/accounts/backup') {
      try {
        const r = backupCurrentAccount();
        return sendJson(res, 200, { ok: true, ...r });
      } catch (e) {
        return sendJson(res, 500, { ok: false, error: e.message });
      }
    }
    if (req.method === 'POST' && url.pathname === '/api/accounts/switch') {
      const body = await readBody(req);
      const uid = String((body && body.uid) || '').trim();
      if (!uid) return sendJson(res, 400, { ok: false, error: '缺少 uid' });
      try {
        const r = await switchToAccount(uid);
        return sendJson(res, 200, { ok: true, ...r });
      } catch (e) {
        return sendJson(res, 500, { ok: false, error: e.message });
      }
    }
    if (req.method === 'POST' && url.pathname === '/api/accounts/delete') {
      const body = await readBody(req);
      const uid = String((body && body.uid) || '').trim();
      if (!uid) return sendJson(res, 400, { ok: false, error: '缺少 uid' });
      const cur = readCurrentAccount();
      if (cur && cur.uid === uid) return sendJson(res, 400, { ok: false, error: '不能删除当前登录账号' });
      const deleted = deleteAccountBackup(uid);
      return sendJson(res, 200, { ok: true, deleted, uid });
    }
    if (req.method === 'GET' && url.pathname === '/api/config') {
      const s = loadSettings();
      return sendJson(res, 200, { ok: true, launchHostOnStart: !!s.launchHostOnStart, wbLaunchOnStart: !!s.wbLaunchOnStart, showPhone: !!s.showPhone, fontScale: Number(s.fontScale ?? 1), cbLaunchOnStart: !!s.cbLaunchOnStart, acLaunchOnStart: !!s.acLaunchOnStart, caLaunchOnStart: !!s.caLaunchOnStart, asLaunchOnStart: !!s.asLaunchOnStart, zcLaunchOnStart: !!s.zcLaunchOnStart, hidePet: !!s.hidePet, tabShowText: !!s.tabShowText, tabOrder: normalizeTabOrder(s.tabOrder) || ['wb', 'cb', 'ac', 'ca', 'as', 'zc', 'tw'] });
    }
    if (req.method === 'POST' && url.pathname === '/api/config') {
      const body = await readBody(req);
      const patch = {};
      if (typeof body.launchHostOnStart === 'boolean') patch.launchHostOnStart = body.launchHostOnStart;
      if (typeof body.wbLaunchOnStart === 'boolean') patch.wbLaunchOnStart = body.wbLaunchOnStart;
      if (typeof body.showPhone === 'boolean') patch.showPhone = body.showPhone;
      if (typeof body.fontScale === 'number' && body.fontScale >= 0.8 && body.fontScale <= 1.5) patch.fontScale = body.fontScale;
      if (typeof body.cbLaunchOnStart === 'boolean') patch.cbLaunchOnStart = body.cbLaunchOnStart;
      if (typeof body.acLaunchOnStart === 'boolean') patch.acLaunchOnStart = body.acLaunchOnStart;
      if (typeof body.caLaunchOnStart === 'boolean') patch.caLaunchOnStart = body.caLaunchOnStart;
      if (typeof body.asLaunchOnStart === 'boolean') patch.asLaunchOnStart = body.asLaunchOnStart;
      if (typeof body.zcLaunchOnStart === 'boolean') patch.zcLaunchOnStart = body.zcLaunchOnStart;
      if (typeof body.hidePet === 'boolean') patch.hidePet = body.hidePet;
      if (typeof body.tabShowText === 'boolean') patch.tabShowText = body.tabShowText;
      if (Array.isArray(body.tabOrder)) {
        const order = normalizeTabOrder(body.tabOrder);
        if (order) patch.tabOrder = order;
      }
      const s = saveSettings(patch);
      log('[config] 已保存设置: ' + JSON.stringify(patch));
      return sendJson(res, 200, { ok: true, launchHostOnStart: !!s.launchHostOnStart, wbLaunchOnStart: !!s.wbLaunchOnStart, showPhone: !!s.showPhone, fontScale: Number(s.fontScale ?? 1), cbLaunchOnStart: !!s.cbLaunchOnStart, acLaunchOnStart: !!s.acLaunchOnStart, caLaunchOnStart: !!s.caLaunchOnStart, asLaunchOnStart: !!s.asLaunchOnStart, zcLaunchOnStart: !!s.zcLaunchOnStart, hidePet: !!s.hidePet, tabShowText: !!s.tabShowText, tabOrder: normalizeTabOrder(s.tabOrder) || ['wb', 'cb', 'ac', 'ca', 'as', 'zc', 'tw'] });
    }
    if (req.method === 'GET' && url.pathname === '/api/check-update') {
      try {
        const gh = await getJson('https://api.github.com/repos/connoryang331/workpet/releases/latest');
        if (gh.status === 200 && gh.body) {
          const latestTag = String(gh.body.tag_name || '').trim();
          const currentTag = 'v' + APP_VERSION;
          // 仅当远端版本严格大于当前版本时才提示更新，避免本地 dev 版领先于已发布版本时误报
          const hasUpdate = Boolean(latestTag && compareSemver(latestTag, currentTag) > 0);
          return sendJson(res, 200, {
            ok: true,
            hasUpdate,
            currentVersion: currentTag,
            latestVersion: latestTag || currentTag,
            title: gh.body.name || latestTag,
            url: gh.body.html_url || 'https://github.com/connoryang331/workpet/releases/latest',
            publishedAt: gh.body.published_at || '',
          });
        }
        return sendJson(res, 200, { ok: true, hasUpdate: false, currentVersion: 'v' + APP_VERSION, error: 'GitHub API ' + gh.status });
      } catch (err) {
        return sendJson(res, 200, { ok: true, hasUpdate: false, currentVersion: 'v' + APP_VERSION, error: err.message });
      }
    }
    if (req.method === 'POST' && url.pathname === '/api/shutdown') {
      sendJson(res, 200, { ok: true, message: 'shutting down' });
      setTimeout(() => {
        log('[daemon] 收到退出请求，正在终止 daemon 进程');
        process.exit(0);
      }, 300);
      return;
    }
    return sendJson(res, 404, { ok: false, error: 'not found' });
  } catch (e) {
    log('[api] error ' + url.pathname + ': ' + e.message);
    return sendJson(res, 500, { ok: false, error: e.message });
  }
});

// ---------------- CDP ----------------
const cdp = { port: 0, ws: null, connected: false, error: null, targetUrl: '', id: 0, pending: new Map() };

function cdpSend(method, params = {}) {
  if (!cdp.ws || cdp.ws.readyState !== 1) return Promise.reject(new Error('CDP 未连接'));
  const id = ++cdp.id;
  return new Promise((resolve, reject) => {
    cdp.pending.set(id, { resolve, reject });
    cdp.ws.send(JSON.stringify({ id, method, params }));
  });
}

async function readCdpTargets(port) {
  const r = await fetch(`http://127.0.0.1:${port}/json/list`, { signal: AbortSignal.timeout(1500) });
  const list = await r.json();
  return Array.isArray(list) ? list : [];
}

function isTraeWorkPageTarget(t) {
  if (!t || t.type !== 'page' || !t.webSocketDebuggerUrl) return false;
  const u = String(t.url || '');
  // 主工作台页面：workbench.html；兜底 vscode-file / electron-browser 页面
  if (/workbench(\.html)?/i.test(u)) return true;
  if (/vscode-file:\/\/vscode-app\//i.test(u)) return true;
  if (/out\/vs\/code\/electron-browser\//i.test(u)) return true;
  return false;
}

async function getPageTarget(port) {
  const list = await readCdpTargets(port).catch(() => []);
  return list.find(isTraeWorkPageTarget) || null;
}

async function findCdpEndpoint() {
  try {
    const list = await readCdpTargets(CDP_PORT);
    if (list.some(isTraeWorkPageTarget)) return CDP_PORT;
  } catch (_) {}
  return 0;
}

async function connectCdp() {
  const port = await findCdpEndpoint();
  if (!port) {
    cdp.connected = false;
    cdp.error = '未发现 TraeWork 的 CDP 端口';
    return false;
  }
  const target = await getPageTarget(port).catch(() => null);
  if (!target) {
    cdp.connected = false;
    cdp.error = `端口 ${port} 上没有 TraeWork 页面目标`;
    return false;
  }
  if (cdp.ws) { try { cdp.ws.close(); } catch (_) {} }
  cdp.port = port;
  return new Promise((resolve) => {
    const ws = new WebSocket(target.webSocketDebuggerUrl);
    ws.onopen = () => {
      cdp.ws = ws;
      cdp.connected = true;
      cdp.error = null;
      cdp.targetUrl = target.url || '';
      log('[cdp] 已连接: ' + cdp.targetUrl.slice(0, 120));
      // 页面重载后自动补种
      try {
        ws.onmessage = (ev) => {
          try {
            const msg = JSON.parse(ev.data);
            if (msg.id && cdp.pending.has(msg.id)) {
              const p = cdp.pending.get(msg.id);
              cdp.pending.delete(msg.id);
              if (msg.error) p.reject(new Error(msg.error.message || msg.error));
              else p.resolve(msg.result);
            }
          } catch (_) {}
        };
      } catch (_) {}
      resolve(true);
    };
    ws.onerror = () => { cdp.connected = false; cdp.ws = null; resolve(false); };
    ws.onclose = () => { cdp.connected = false; cdp.ws = null; };
  });
}

let lastInjectAt = 0;
async function injectWidget(reason) {
  if (!cdp.connected) return Promise.reject(new Error('CDP 未连接'));
  if (reason !== 'manual' && Date.now() - lastInjectAt < 1000) return;
  lastInjectAt = Date.now();
  let script;
  try { script = fs.readFileSync(path.join(__dirname, 'inject.js'), 'utf8'); }
  catch (e) { return Promise.reject(new Error('读取 inject.js 失败: ' + e.message)); }
  script = script.replace(/__TW_API__/g, `http://${HOST}:${UI_PORT}`);
  script = script.replace(/__TW_VERSION__/g, DAEMON_VERSION);
  log(`[cdp] 注入宠物组件 (${reason})`);
  const cleanup = 'try{if(window.__twPet&&typeof window.__twPet.destroy==="function"){window.__twPet.destroy();}}catch(e){}';
  try { await cdpSend('Runtime.evaluate', { expression: cleanup }); } catch (_) {}
  const r = await cdpSend('Runtime.evaluate', { expression: script }).catch((e) => ({ error: e.message }));
  if (r && r.error) { log('[cdp] 注入失败: ' + r.error); return { mounted: false }; }
  if (r && r.exceptionDetails) {
    const ex = r.exceptionDetails.exception;
    log('[cdp] 注入脚本页面抛错: ' + String((ex && (ex.description || ex.value)) || r.exceptionDetails.text || '').slice(0, 400));
    return { mounted: false };
  }
  // 校验挂载
  for (let i = 0; i < 5; i++) {
    await sleep(i === 0 ? 150 : 300);
    try {
      const check = await cdpSend('Runtime.evaluate', {
        expression: '({root:!!document.querySelector(".tw-pet-root"), widget:!!window.__twPet})',
        returnByValue: true,
      });
      const st = check && check.result && check.result.value;
      if (st && st.root && st.widget) {
        log('[cdp] 注入确认(' + reason + '): root=true widget=true');
        return { mounted: true };
      }
    } catch (_) {}
  }
  log('[cdp] 注入后未检测到组件(' + reason + ')');
  return { mounted: false };
}

// ---------------- 进程管理（确保 TraeWork 以 CDP 模式运行） ----------------
const EXE_NAME = isMac
  ? path.basename(CFG.exe || 'TRAE SOLO CN')
  : path.basename(CFG.exe || 'TRAE SOLO CN.exe');

// pgrep -f 走 ERE 正则，这里有两个必须避开的坑：
//
// 1) 绝不能写成 '(\s|$)' —— JS 单引号字符串里 \s 不是合法转义，会被原样吞成 's'，
//    实际生效的模式是 "(s|$)"；而真实命令行形如
//    /Applications/XXX.app/Contents/MacOS/Electron，应用名后紧跟的是 '.' 而非 's'，
//    于是 pgrep 永远无匹配 → isProcessRunning() 在 macOS 上恒为 false：
//      · ensureTraeWorkWithCdp() 刚 spawn 完就判定「进程已退出」而 break，不再等 CDP 端口就绪
//      · 两轮拉起都秒退 →「等待 TraeWork CDP 端口超时」，宿主 IPC 签到永远走不通。
//
// 2) 不要写死品牌名。安装目录已由 "TRAE SOLO CN" 改为 "TraeWork CN"，任何固定名称都会在
//    下一次改名后再次失效。这里只约束「含 trae 且含 solo/work 的 .app 包内的
//    Contents/MacOS/」——额外要求 solo/work 是为了排除普通版 Trae（"Trae CN" / "Trae"），
//    那是另一个产品，不在本项目适配范围内（见 TRAEWORK_NAME_RE）。
//    匹配：TRAE SOLO CN.app / TraeWork CN.app / TraeWork.app
//    排除：Trae CN.app / Trae.app
//    注意 ERE 不支持 (?i)，用字符类 [Tt][Rr][Aa][Ee] 等代替忽略大小写。
const TRAE_PROCESS_ERE =
  '/[Tt][Rr][Aa][Ee][^/]*([Ss][Oo][Ll][Oo]|[Ww][Oo][Rr][Kk])[^/]*\\.app/Contents/MacOS/';

function isProcessRunning() {
  if (isMac) {
    try {
      const out = execFileSync('pgrep', ['-f', TRAE_PROCESS_ERE], { encoding: 'utf8' });
      return Boolean(out.trim());
    } catch (_) { return false; }
  }
  try {
    const out = execFileSync('tasklist', ['/FI', 'IMAGENAME eq ' + EXE_NAME, '/FO', 'CSV', '/NH'], { encoding: 'utf8', windowsHide: true });
    return out.includes(EXE_NAME);
  } catch (_) { return false; }
}

function killTraeWork() {
  if (isMac) {
    // 先按已探测到的可执行路径结束，再按通用路径模式兜底。
    // 不再用写死的 app 名列表去 osascript quit：客户端已多次改名
    // （TRAE SOLO CN → Trae CN → TraeWork CN），固定名称撑不过下一次改名。
    if (CFG.exe) {
      try { execFileSync('pkill', ['-f', CFG.exe], { stdio: 'ignore' }); } catch (_) {}
    }
    try { execFileSync('pkill', ['-f', TRAE_PROCESS_ERE], { stdio: 'ignore' }); } catch (_) {}
  } else {
    try { execFileSync('taskkill', ['/IM', EXE_NAME, '/F', '/T'], { stdio: 'ignore', windowsHide: true }); } catch (_) {}
  }
}

/** 退出 AutoClaw（macOS 与 Windows），用于「签到后自动关闭」的临启即关场景 */
function killAutoClaw() {
  if (isMac) {
    // 先 SIGKILL 强杀（杀主进程与所有子进程），避免 osascript 走优雅退出要等用户确认；
    // 杀完再用 osascript 兜底处理 dock 图标残留。
    try { execFileSync('pkill', ['-9', '-x', 'AutoClaw'], { stdio: 'ignore' }); } catch (_) {}
    try { execFileSync('pkill', ['-9', '-f', 'AutoClaw Helper'], { stdio: 'ignore' }); } catch (_) {}
    try { execFileSync('osascript', ['-e', 'tell application "AutoClaw" to quit'], { stdio: 'ignore' }); } catch (_) {}
  } else {
    // AutoClaw2（新版 exe 改名 AutoClaw2.exe）与旧版 AutoClaw.exe 都尝试关掉
    try { execFileSync('taskkill', ['/IM', 'AutoClaw2.exe', '/F', '/T'], { stdio: 'ignore', windowsHide: true }); } catch (_) {}
    try { execFileSync('taskkill', ['/IM', 'AutoClaw.exe', '/F', '/T'], { stdio: 'ignore', windowsHide: true }); } catch (_) {}
  }
}

async function ensureTraeWorkWithCdp() {
  if (await findCdpEndpoint()) return { started: false, reused: true };
  if (!CFG.exe) return { started: false, error: '未找到 TraeWork 安装目录' };
  log('[proc] 需要以 CDP 模式启动 TraeWork');
  if (isProcessRunning()) {
    log('[proc] 正在退出已运行的 TraeWork（需带 --remote-debugging-port 重启）');
    killTraeWork();
    // 等到进程彻底退出：旧实例的单实例锁会让新进程静默退出，导致 CDP 永远不开
    for (let i = 0; i < 10 && isProcessRunning(); i++) await sleep(1000);
    await sleep(800);
  }
  // 最多两轮拉起：进程中途退出（单实例锁残留）时自动重试一次
  for (let attempt = 1; attempt <= 2; attempt++) {
    // 每次拉起前再次确认旧实例已退出（包括上一轮拉起的失败进程）
    killTraeWork();
    for (let i = 0; i < 10 && isProcessRunning(); i++) await sleep(1000);
    await sleep(800);
    log(`[proc] 启动: ${CFG.exe} --remote-debugging-port=${CDP_PORT} (第 ${attempt} 次)`);
    if (isMac) {
      // 直接启动 .app 内真实可执行文件，参数可稳定传给 Electron 主进程。
      spawn(CFG.exe, ['--remote-debugging-port=' + CDP_PORT], { stdio: 'ignore', detached: true });
    } else {
      spawn(CFG.exe, ['--remote-debugging-port=' + CDP_PORT], { stdio: 'ignore', detached: true });
    }
    const deadline = Date.now() + CDP_STARTUP_TIMEOUT_MS;
    while (Date.now() < deadline) {
      const port = await findCdpEndpoint().catch(() => 0);
      if (port) return { started: true, reused: false, port };
      if (!isProcessRunning()) break; // 进程退出了 → 直接重试
      await sleep(1000);
    }
    if (await findCdpEndpoint().catch(() => 0)) return { started: true, reused: false, port };
  }
  return { started: false, error: '等待 TraeWork CDP 端口超时' };
}

// ---------------- 主流程 ----------------
async function main() {
  CFG = detectPaths();
  if (!CFG.dataDir) {
    // WorkPet 还承载 WorkBuddy / CodeBuddy；没有安装或登录 TraeWork 时也必须启动本地 API。
    log('警告：未找到 TraeWork 数据目录，TraeWork 功能暂不可用（WorkBuddy / CodeBuddy 仍可使用）');
  }
  if (!CFG.exe) log('警告：未找到 TraeWork 可执行文件（仅本地 API 和其它客户端功能可用）');
  log('dataDir=' + (CFG.dataDir || '(未找到)') + ' exe=' + (CFG.exe || '(未找到)'));

  if (CFG.dataDir) {
    try {
      const auth = getAuth();
      if (auth.error) log('[auth] ' + auth.error);
      else log('[auth] user=' + auth.userId + ' scope=' + ((auth.account && auth.account.scope) || '?') + ' deviceId=' + auth.deviceId);
    } catch (e) {
      log('[auth] 读取 TraeWork 登录态失败: ' + e.message);
    }
    // 每次启动自动备份当前登录账号，保证多账号列表始终包含正在用的账号
    try {
      const r = backupCurrentAccount();
      log('[accounts] 已备份当前账号 ' + r.nickname + ' (' + r.uid + ')');
    } catch (e) {
      log('[accounts] 备份当前账号失败: ' + e.message);
    }
    try {
      const extra = collectAllTraeAccounts();
      if (extra.length) log('[accounts] 跨客户端收集账号: ' + extra.join(', '));
    } catch (e) {
      log('[accounts] 跨客户端收集失败: ' + e.message);
    }
  }

  server.on('error', (e) => {
    if (e && e.code === 'EADDRINUSE') {
      log('[api] 端口 ' + UI_PORT + ' 已被占用，说明已有 Work Pet daemon 在运行，本实例退出。');
      process.exit(0);
    }
    log('[api] 本地服务启动失败: ' + e.message);
    process.exit(1);
  });
  server.listen(UI_PORT, HOST, () => log('[api] 本地 API 已启动 http://' + HOST + ':' + UI_PORT));

  // 设置项：打开 Pet 时同时启动 TraeWork（默认关闭；签到不需要 TraeWork 运行）
  const settings = loadSettings();
  if (settings.launchHostOnStart) {
    log('[proc] 设置项开启：启动时拉起 TraeWork（CDP 模式）');
    ensureTraeWorkWithCdp()
      .then((r) => { if (r.error) log('[proc] 拉起 TraeWork 失败: ' + r.error); })
      .catch((e) => log('[proc] 拉起 TraeWork 异常: ' + e.message));
  }

  // 每 30 分钟刷新一次各账号积分/签到状态（仅在 TraeWork 未运行时轮换，避免打断）；
  // 轮换时顺带把各账号最新的 Cookie 时限同步进账号库（rotateAllAccounts 内实现）。
  setInterval(() => {
    if (claimAllJob.running || isProcessRunning()) return;
    log('[credits] 定时刷新各账号积分');
    void refreshCreditsOnly().catch((e) => log('[credits] 刷新异常: ' + e.message));
  }, 30 * 60 * 1000).unref();

  // 每 5 分钟把 storage.json 里当前登录的 Cookie 时限同步进账号库（仅更新元数据，
  // 不写登录文件、不碰宿主），让「Cookie 时限」跟随宿主自动续期保持新鲜。
  setInterval(() => {
    if (claimAllJob.running || isProcessRunning()) return; // 宿主运行中不写库，防竞态覆盖
    try {
      const auth = getAuth();
      if (auth.error) return;
      const meta = accountMetaFromInfo(auth.info);
      if (!meta.uid) return;
      const store = loadStore();
      const idx = store.traework.accounts.findIndex((x) => String(x.uid) === String(meta.uid));
      if (idx < 0) return; // 只更新已备份账号，不新增
      const prev = store.traework.accounts[idx];
      const changed = prev.expiredAt !== meta.expiredAt || prev.refreshExpiredAt !== meta.refreshExpiredAt
        || (prev.nickname || '') !== meta.nickname || (prev.mobile || '') !== meta.mobile;
      if (changed) {
        store.traework.accounts[idx] = Object.assign({}, prev, meta);
        saveStore(store);
        log('[accounts] Cookie 时限已同步 ' + (meta.nickname || meta.uid) + ' -> ' + (meta.expiredAt || '(无)'));
      }
    } catch (_) {}
  }, 5 * 60 * 1000).unref();

  // AutoClaw：每 5 分钟把 auth.json 里最新的 JWT exp（Cookie 时限）同步进账号库 ac 段；
  // token 快过期（<2h）时自动 refresh 并回写 auth.json，时限跟随签到/刷新即时续期。
  // 解密走异步 acReadAuthAsync（key 缓存 + 12s 硬超时树杀），不阻塞事件循环。
  setInterval(() => {
    if (claimAllJob.running || clientClaimGlobalLock) return;
    (async () => {
      try {
        const a = await acReadAuthAsync();
        if (!a || a.error || !a.token) return;
        acSyncStore(a);
        const exp = a.jwtExp || acJwtExpMs(a.token);
        if (exp != null && exp - Date.now() < 2 * 3600 * 1000 && a.refreshToken) {
          log('[client:ac] token 快过期，自动 refresh');
          acRefreshToken()
            .then(async (r) => {
              const newExp = acJwtExpMs(r.accessToken);
              await acPersistRefreshedToken(r.accessToken, r.refreshToken);
              acSyncStoreAfterRefresh(r.accessToken, r.refreshToken, newExp);
              log('[client:ac] refresh 完成，新时限 -> ' + (newExp ? new Date(newExp).toISOString() : '(无)'));
            })
            .catch((e) => log('[client:ac] 自动 refresh 失败: ' + e.message));
        }
      } catch (_) {}
    })();
  }, 5 * 60 * 1000).unref();

  // AutoClaw：仅按设置 acLaunchOnStart 拉起（默认关闭，与 Trae 一致）；签到走「临时拉起→签完即关」，
  // 不再启动时常驻，避免 AutoClaw 一直占用资源。macOS 读登录态依赖 AutoClaw 运行时（CDP），
  // 若未运行则账号显示「暂无登录态」。
  if (settings.acLaunchOnStart) {
    log('[proc] 设置项开启：启动时拉起 AutoClaw（供账号显示）');
    acLaunchBinary()
      .then((how) => log('[proc] AutoClaw 拉起结果: ' + how))
      .catch((e) => log('[proc] 拉起 AutoClaw 异常: ' + e.message));
  }

  // 设置项：打开 Pet 时同时启动 CodeArts Agent（默认关闭）
  if (settings.caLaunchOnStart) {
    log('[proc] 设置项开启：启动时拉起 CodeArts Agent');
    try {
      if (caIsIdeRunning()) log('[proc] CodeArts Agent 已在运行，跳过拉起');
      else if (caLaunchIde()) log('[proc] 已拉起 CodeArts Agent');
      else log('[proc] 未找到 CodeArts Agent 可执行文件，跳过拉起');
    } catch (e) {
      log('[proc] 拉起 CodeArts Agent 异常: ' + e.message);
    }
  }

  // 桌面版：宠物/面板由 Rust 桌面客户端承载，不再向 TraeWork 注入 JS。
  // 仅保留 TraeWork 进程管理（账号切换时重启以生效），避免开机自动拉起。
  log('[proc] 桌面版模式：跳过 JS 注入（宠物面板由 Rust 客户端显示）');
}

main().catch((e) => { log('[fatal] ' + e.stack || e.message); process.exit(1); });
