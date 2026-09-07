#!/usr/bin/env node
'use strict';
/**
 * TraeWork 签到宠物 daemon
 *
 * 为 TraeWork（品牌名 TraeWork CN / TRAE Work，安装目录沿用旧名 "TRAE SOLO CN"）
 * 提供 CDP 注入与签到机制，只保留三个能力：
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
const { spawn } = require('child_process');

const APP_BRAND = 'TraeWork';
const DAEMON_VERSION = '1.0.0';
const HOST = '127.0.0.1';
const CDP_PORT = 9222;
const UI_PORT = parseInt(process.env.TRAEWORK_UI_PORT || '47921', 10);
const CDP_STARTUP_TIMEOUT_MS = 60000;

// 签到接口按官方 iCubeEntitlement 的实现：POST，body "{}"，多域名兜底（www.trae.cn 是官网非 API，不参与）
const CHECKIN_HOSTS = ['https://api.trae.cn', 'https://trae-api-cn.mchost.guru'];
const CHECKIN_PATH = '/trae/api/v2/ug/checkin_credits/';
const CHECKIN_REQUEST_TIMEOUT_MS = 12000;

// ---------------- 路径探测 ----------------
const EXE_CANDIDATES = [
  'D:/Program Files/TRAE SOLO CN/TRAE SOLO CN.exe',
  path.join(process.env.ProgramFiles || 'C:/Program Files', 'TRAE SOLO CN', 'TRAE SOLO CN.exe'),
  path.join(process.env['ProgramFiles(x86)'] || 'C:/Program Files (x86)', 'TRAE SOLO CN', 'TRAE SOLO CN.exe'),
  path.join(process.env.LOCALAPPDATA || '', 'Programs', 'TRAE SOLO CN', 'TRAE SOLO CN.exe'),
];
const DATA_DIR_CANDIDATES = [
  path.join(os.homedir(), 'AppData', 'Roaming', 'TRAE SOLO CN'),
  path.join(os.homedir(), 'AppData', 'Roaming', 'TraeWork'),
];

function detectPaths() {
  const exe = EXE_CANDIDATES.find((f) => f && fs.existsSync(f)) || '';
  let dataDir = DATA_DIR_CANDIDATES.find((d) => d && fs.existsSync(d)) || '';
  if (!dataDir) {
    // 兜底：在 Roaming 下找含 storage.json 且带 iCubeAuthInfo 的 Trae 目录
    const roam = path.join(os.homedir(), 'AppData', 'Roaming');
    try {
      for (const name of fs.readdirSync(roam)) {
        if (!/trae/i.test(name)) continue;
        const storage = path.join(roam, name, 'User', 'globalStorage', 'storage.json');
        if (!fs.existsSync(storage)) continue;
        try {
          const raw = fs.readFileSync(storage, 'utf8');
          if (raw.includes('iCubeAuthInfo://')) { dataDir = path.join(roam, name); break; }
        } catch (_) {}
      }
    } catch (_) {}
  }
  return { exe, dataDir };
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

/** 读取并解密登录态，返回 { token, userId, account, deviceId, raw } */
function getAuth() {
  const raw = fs.readFileSync(storageFile(), 'utf8');
  const json = JSON.parse(raw);
  const deviceId = json['telemetry.devDeviceId'] || '';
  const secret = json['iCubeAuthInfo://icube.cloudide'];
  if (!secret) return { error: '未找到 iCubeAuthInfo://icube.cloudide' };
  const buf = KUe(new Uint8Array(Buffer.from(secret, 'base64')));
  if (!buf) return { error: '登录态解密失败（校验和不通过）' };
  let info;
  try { info = JSON.parse(Buffer.from(buf).toString('utf8')); } catch (e) { return { error: '登录态解析失败: ' + e.message }; }
  return { token: info.token || '', userId: info.userId || '', account: info.account || {}, deviceId, info };
}

// 便携数据目录：账号备份/设置/积分缓存全部存放在数据目录（默认与 daemon.js 同目录）；
// 由 pet 启动时通过环境变量指定为 exe 同目录，不写系统 AppData/Application Support。
// 目录不可写时回退到平台标准路径。
let DATA_ROOT =
  (process.env.WORKPET_DATA_DIR && fs.existsSync(process.env.WORKPET_DATA_DIR))
    ? process.env.WORKPET_DATA_DIR
    : __dirname;
// 数据目录不可写时回退到平台标准用户数据目录
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
 * 跨客户端收集：扫描 Roaming 下所有 Trae 系列客户端（TRAE SOLO CN / Trae CN /
 * TraeWork 等）的已登录账号，把有可用登录态的都并入备份库，实现「登录过的账号
 * 都能显示」。只读别的客户端 storage，绝不写回别人。
 */
function collectAllTraeAccounts() {
  const roam = path.join(os.homedir(), 'AppData', 'Roaming');
  let dirs = [];
  try { dirs = fs.readdirSync(roam).filter((n) => /trae/i.test(n)); } catch (_) {}
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
  await ensureTraeWorkWithCdp(); // 重启 TraeWork 使切换生效；桌面版不再注入
  log('[switch] 已切换账号: ' + nickname);
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

function getJson(url, headers) {
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
const SETTING_DEFAULTS = { launchHostOnStart: false, wbLaunchOnStart: false, cbLaunchOnStart: false, showPhone: false, fontScale: 1, tabOrder: ['wb', 'cb', 'accounts'] };
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
const SHARED_DATA_DIR = path.join(process.env.APPDATA || path.join(os.homedir(), 'AppData', 'Roaming'), 'WorkPet', 'clients');
const WB_ACCOUNTS_DIR = path.join(SHARED_DATA_DIR, 'accounts');
const CB_ACCOUNTS_DIR = path.join(SHARED_DATA_DIR, 'profiles', 'codebuddy-cn', 'accounts');
const LEGACY_SHARED_DIR = path.join(process.env.APPDATA || path.join(os.homedir(), 'AppData', 'Roaming'), 'WorkDaddy');
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
const EXT_AUTH_DIR = path.join(process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local'), 'CodeBuddyExtension', 'Data', 'Public', 'auth');
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
  };
  // 把引擎目录的最新账号状态同步回单文件账号库，保证 WorkPet-accounts.json 始终完整
  store.traework.currentSecret = out.traework.currentSecret;
  store.traework.deviceId = out.traework.deviceId;
  store.workbuddy = { current: out.workbuddy.current, accounts: out.workbuddy.accounts };
  store.codebuddy = { current: out.codebuddy.current, accounts: out.codebuddy.accounts };
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
  const counts = { traework: 0, workbuddy: 0, codebuddy: 0 };
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
  saveStore(store);
  return counts;
}


// ================= WB/CB 客户端支持（原生实现，替代外部引擎） =================
// WorkBuddy / CodeBuddy 的账号备份、切换、签到、积分查询全部由本 daemon 原生完成：
// 登录态 = CodeBuddyExtension 扩展 auth 文件（两个客户端各一条独立通道）；
// 账号库 = WorkPet-accounts.json 的 workbuddy/codebuddy 段；
// 签到/积分 = 各端 apiHost 的 HTTP 接口（Bearer accessToken）。

const { extractCreditSegments, sortCreditSegments, mergeCreditSegments } = require('./credit-segments.js');

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
};
const CLIENT_CHECKIN_CACHE_FILE = path.join(DATA_ROOT, 'client-checkin-cache.json');
const clientCheckinState = {
  wb: { inFlight: false, running: false, total: 0, done: 0, startedAt: 0, finishedAt: 0 },
  cb: { inFlight: false, running: false, total: 0, done: 0, startedAt: 0, finishedAt: 0 },
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
  const raw = readJsonOrNull(CLIENT_PROFILES[profileId].authFile);
  if (!raw || !raw.account || !raw.account.uid) return null;
  return raw;
}

/** 把当前登录同步进账号库（登录文件变化时调用） */
function clientSyncStore(profileId) {
  const raw = clientReadAuth(profileId);
  if (!raw) return;
  const store = loadStore();
  const sec = store[profileId === 'wb' ? 'workbuddy' : 'codebuddy'];
  const uid = String(raw.account.uid);
  const idx = sec.accounts.findIndex((a) => a && a.account && String(a.account.uid) === uid);
  if (idx >= 0) sec.accounts[idx] = raw;
  else sec.accounts.push(raw);
  sec.current = raw;
  saveStore(store);
}

/** 列出客户端全部账号 + 当前登录（当前以 auth 文件为准） */
function clientListAccounts(profileId) {
  clientSyncStore(profileId);
  const store = loadStore();
  const sec = store[profileId === 'wb' ? 'workbuddy' : 'codebuddy'];
  const currentRaw = clientReadAuth(profileId);
  const currentUid = currentRaw && currentRaw.account ? String(currentRaw.account.uid) : null;
  const seen = new Set();
  const list = [];
  const push = (raw) => {
    if (!raw || !raw.account) return;
    const uid = String(raw.account.uid);
    if (seen.has(uid)) return;
    seen.add(uid);
    const auth = raw.auth || {};
    list.push({
      uid,
      nickname: raw.account.nickname || '',
      phone: raw.account.phoneNumber || '',
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
        checkin: rec && rec.date === today && !clientCheckinState[profileId].inFlight
          ? { ok: !!rec.ok, already: !!rec.already, code: rec.code, message: rec.message }
          : null,
      });
    }),
  };
}

function clientTokenFor(profileId, uid) {
  const raw = clientReadAuth(profileId);
  if (raw && String(raw.account.uid) === String(uid)) return raw.auth && raw.auth.accessToken;
  const store = loadStore();
  const sec = store[profileId === 'wb' ? 'workbuddy' : 'codebuddy'];
  const rec = sec.accounts.find((a) => a && a.account && String(a.account.uid) === String(uid));
  return rec && rec.auth ? rec.auth.accessToken : null;
}

async function clientDailyCheckin(profileId, accessToken) {
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
          return { ok: true, already, deviceLimit, code, message: o.msg || o.message || 'ok' };
        }
        if (r.status === 401) return { ok: false, code, message: '登录身份过期' };
        const busy = /请求处理中|重复操作|请稍后再试/.test(o.msg || o.message || '');
        if (busy) { lastErr = o.msg || o.message; break; }
        if (r.status >= 400 && r.status !== 404) return { ok: false, code, message: 'HTTP ' + r.status };
        lastErr = o.msg || o.message || ('HTTP ' + r.status);
      } catch (e) {
        lastErr = e.message;
      }
    }
  }
  }
  return { ok: false, message: lastErr || '签到失败' };
}

async function clientClaimDailyForAll(profileId) {
  const st = clientCheckinState[profileId];
  if (st.inFlight || clientClaimGlobalLock) return { skipped: true, reason: 'in-flight' };
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
  try {
    for (const a of accounts) {
      const hit = cache[a.uid];
      if (hit && hit.date === today && hit.ok) { st.done++; continue; }
      const tk = clientTokenFor(profileId, a.uid);
      let rec;
      if (!tk) rec = { date: today, ok: false, code: -1, message: '无 accessToken' };
      else {
        const r = await clientDailyCheckin(profileId, tk);
        rec = { date: today, ok: !!r.ok, already: !!r.already, deviceLimit: !!r.deviceLimit, code: r.code, message: r.message || '' };
      }
      cache[a.uid] = rec;
      clientSaveCheckinCache(profileId, cache);
      st.done++;
      log('[client:' + profileId + '] ' + a.nickname + ' 签到: ' + (rec.ok ? (rec.already ? '已签' : '成功') : rec.message));
      await sleep(500);
    }
  } finally {
    st.inFlight = false;
    st.running = false;
    st.finishedAt = Date.now();
    clientClaimGlobalLock = false;
  }
  return { total: st.total, done: st.done };
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
for (const pid of ['wb', 'cb']) {
  try {
    fs.watchFile(CLIENT_PROFILES[pid].authFile, { interval: 5000 }, (cur, prev) => {
      if (!fs.existsSync(CLIENT_PROFILES[pid].authFile)) return;
      if (cur.mtimeMs !== prev.mtimeMs) {
        try { clientSyncStore(pid); log('[client:' + pid + '] 登录文件变化，已同步账号库'); } catch (_) {}
      }
    });
  } catch (_) {}
}


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
      const auth = getAuth();
      return sendJson(res, 200, { ok: true, app: APP_BRAND, version: DAEMON_VERSION, ts: Date.now(), authed: !auth.error });
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
        try {
          const r = await fetch('http://127.0.0.1:' + CLIENT_PROFILES[pid].cdpPort + '/json/version', { signal: AbortSignal.timeout(1500) });
          cdpConnected = r.ok;
        } catch (_) {}
        return sendJson(res, 200, {
          ok: true,
          profile: { id: pid, name: CLIENT_PROFILES[pid].name },
          batch: { running: st.running, total: st.total, done: st.done },
          cdp: { connected: cdpConnected },
        });
      }
      if (parts[4] === 'accounts') {
        clientClaimDailyForAll(pid).catch((e) => log('[client:' + pid + '] 自动签到失败: ' + e.message));
        const list = clientListAccounts(pid);
        return sendJson(res, 200, { ok: true, ...list, batch: clientCheckinState[pid] });
      }
      return sendJson(res, 404, { ok: false, error: 'not found' });
    }
    if (req.method === 'POST' && url.pathname.startsWith('/api/client/')) {
      const parts = url.pathname.split('/');
      const pid = parts[3];
      if (!CLIENT_PROFILES[pid]) return sendJson(res, 404, { ok: false, error: 'unknown client' });
      const body = await readBody(req);
      if (parts[4] === 'credits') {
        const uid = (body.uid || '').trim();
        const tk = clientTokenFor(pid, uid);
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
        const store = loadStore();
        const sec = store[pid === 'wb' ? 'workbuddy' : 'codebuddy'];
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
        const sec = store[pid === 'wb' ? 'workbuddy' : 'codebuddy'];
        const before = sec.accounts.length;
        sec.accounts = sec.accounts.filter((a) => a && a.account && String(a.account.uid) !== String(uid));
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
      return sendJson(res, 200, { ok: true, launchHostOnStart: !!s.launchHostOnStart, wbLaunchOnStart: !!s.wbLaunchOnStart, showPhone: !!s.showPhone, fontScale: Number(s.fontScale ?? 1), cbLaunchOnStart: !!s.cbLaunchOnStart, hidePet: !!s.hidePet, tabOrder: Array.isArray(s.tabOrder) && s.tabOrder.length === 3 ? s.tabOrder : ['wb', 'cb', 'accounts'] });
    }
    if (req.method === 'POST' && url.pathname === '/api/config') {
      const body = await readBody(req);
      const patch = {};
      if (typeof body.launchHostOnStart === 'boolean') patch.launchHostOnStart = body.launchHostOnStart;
      if (typeof body.wbLaunchOnStart === 'boolean') patch.wbLaunchOnStart = body.wbLaunchOnStart;
      if (typeof body.showPhone === 'boolean') patch.showPhone = body.showPhone;
      if (typeof body.fontScale === 'number' && body.fontScale >= 0.8 && body.fontScale <= 1.5) patch.fontScale = body.fontScale;
      if (typeof body.cbLaunchOnStart === 'boolean') patch.cbLaunchOnStart = body.cbLaunchOnStart;
      if (typeof body.hidePet === 'boolean') patch.hidePet = body.hidePet;
      if (Array.isArray(body.tabOrder)) {
        const known = ['wb', 'cb', 'accounts'];
        const order = Array.from(new Set(body.tabOrder.map((t) => String(t))).values()).filter((t) => known.includes(t));
        if (order.length === known.length) patch.tabOrder = order;
      }
      const s = saveSettings(patch);
      log('[config] 已保存设置: ' + JSON.stringify(patch));
      return sendJson(res, 200, { ok: true, launchHostOnStart: !!s.launchHostOnStart, wbLaunchOnStart: !!s.wbLaunchOnStart, showPhone: !!s.showPhone, fontScale: Number(s.fontScale ?? 1), cbLaunchOnStart: !!s.cbLaunchOnStart, hidePet: !!s.hidePet, tabOrder: Array.isArray(s.tabOrder) && s.tabOrder.length === 3 ? s.tabOrder : ['wb', 'cb', 'accounts'] });
    }
    if (req.method === 'GET' && url.pathname === '/api/check-update') {
      try {
        const gh = await getJson('https://api.github.com/repos/connoryang331/work-pet/releases/latest');
        if (gh.status === 200 && gh.body) {
          const latestTag = String(gh.body.tag_name || '').trim();
          const currentTag = 'v1.0.0';
          const hasUpdate = Boolean(latestTag && latestTag !== currentTag);
          return sendJson(res, 200, {
            ok: true,
            hasUpdate,
            currentVersion: currentTag,
            latestVersion: latestTag || currentTag,
            title: gh.body.name || latestTag,
            url: gh.body.html_url || 'https://github.com/connoryang331/work-pet/releases/latest',
            publishedAt: gh.body.published_at || '',
          });
        }
        return sendJson(res, 200, { ok: true, hasUpdate: false, currentVersion: 'v1.0.0', error: 'GitHub API ' + gh.status });
      } catch (err) {
        return sendJson(res, 200, { ok: true, hasUpdate: false, currentVersion: 'v1.0.0', error: err.message });
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
  ? (CFG.exe ? path.basename(CFG.exe).replace(/\.app\/Contents\/MacOS\/.*$/, '').trim() || 'TRAE SOLO CN' : 'TRAE SOLO CN')
  : path.basename(CFG.exe || 'TRAE SOLO CN.exe');

function isProcessRunning() {
  if (isMac) {
    try {
      const out = execSync(['pgrep', '-x', 'Electron']);
      if (!out.trim()) return false;
      for (const pid of out.trim().split(/\s+/)) {
        try {
          const args = execSync(['ps', '-p', pid.trim(), '-o', 'command=']);
          if (args.includes('TRAE SOLO CN') || args.includes('Trae CN') || args.includes('TraeWork')) return true;
        } catch (_) {}
      }
      return false;
    } catch (_) { return false; }
  }
  try {
    const out = execSync(['tasklist', '/FI', 'IMAGENAME eq ' + EXE_NAME, '/FO', 'CSV', '/NH'], { encoding: 'utf8' });
    return out.includes(EXE_NAME);
  } catch (_) { return false; }
}

function killTraeWork() {
  if (isMac) {
    try { execSync(['osascript', '-e', 'quit app "TRAE SOLO CN"']); } catch (_) {}
    try { execSync(['osascript', '-e', 'quit app "Trae CN"']); } catch (_) {}
  } else {
    try { execSync(['taskkill', '/IM', EXE_NAME, '/F', '/T'], { stdio: 'ignore' }); } catch (_) {}
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
    log(`[proc] 启动: ${CFG.exe} --remote-debugging-port=${CDP_PORT} (第 ${attempt} 次)`);
    if (isMac) {
      const appname = CFG.exe ? path.basename(CFG.exe).replace(/\.app\/Contents\/MacOS\/.*$/, '').trim() : 'TRAE SOLO CN';
      spawn('open', ['-g', '-a', appname, '--args', '--remote-debugging-port=' + CDP_PORT], { stdio: 'ignore', detached: true });
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
  if (!CFG.dataDir) { log('未找到 TraeWork 数据目录，退出'); process.exit(1); }
  if (!CFG.exe) log('警告：未找到 TraeWork 可执行文件（仅本地 API 可用）');
  log('dataDir=' + CFG.dataDir + ' exe=' + (CFG.exe || '(未找到)'));
  const auth = getAuth();
  if (auth.error) log('[auth] ' + auth.error);
  else log('[auth] user=' + auth.userId + ' scope=' + ((auth.account && auth.account.scope) || '?') + ' deviceId=' + auth.deviceId);
  // 每次启动自动备份当前登录账号，保证多账号列表始终包含正在用的账号
  try {
    const r = backupCurrentAccount();
    log('[accounts] 已备份当前账号 ' + r.nickname + ' (' + r.uid + ')');
  } catch (e) {
    log('[accounts] 备份当前账号失败: ' + e.message);
  }
  // 跨客户端收集：把其它 Trae 客户端（如 Trae CN）里已登录的账号也并入备份库
  try {
    const extra = collectAllTraeAccounts();
    if (extra.length) log('[accounts] 跨客户端收集账号: ' + extra.join(', '));
  } catch (e) {
    log('[accounts] 跨客户端收集失败: ' + e.message);
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

  // 每 30 分钟刷新一次各账号积分/签到状态（仅在 TraeWork 未运行时轮换，避免打断）
  setInterval(() => {
    if (claimAllJob.running || isProcessRunning()) return;
    log('[credits] 定时刷新各账号积分');
    void refreshCreditsOnly().catch((e) => log('[credits] 刷新异常: ' + e.message));
  }, 30 * 60 * 1000).unref();

  // 桌面版：宠物/面板由 Rust 桌面客户端承载，不再向 TraeWork 注入 JS。
  // 仅保留 TraeWork 进程管理（账号切换时重启以生效），避免开机自动拉起。
  log('[proc] 桌面版模式：跳过 JS 注入（宠物面板由 Rust 客户端显示）');
}

main().catch((e) => { log('[fatal] ' + e.stack || e.message); process.exit(1); });
