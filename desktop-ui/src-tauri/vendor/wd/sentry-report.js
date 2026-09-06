#!/usr/bin/env node
/**
 * Small Sentry envelope client used by the Node/shell/PowerShell entry points.
 * It intentionally has no npm dependency: installers must be able to report
 * before the Electron shell or a package manager is available.
 */
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const https = require('https');
const crypto = require('crypto');

const DEFAULT_DSN = 'https://6cc1bae83102c222717df3b6e74ae9d4@o4511947624939520.ingest.us.sentry.io/4511947692572672';
const CLIENT = 'workdaddy-sentry/1';
const HOME = os.homedir();
const IS_WIN = process.platform === 'win32';
const PROFILE_ID = String(process.env.WBSWITCH_PROFILE || 'workbuddy-cn').trim().toLowerCase();
const CLIENT_VARIANT = PROFILE_ID === 'workbuddy-ai' ? 'workbuddy-ai'
  : PROFILE_ID === 'codebuddy-cn' ? 'codebuddy-cn'
    : PROFILE_ID === 'codebuddy-intl' ? 'codebuddy-intl' : 'workbuddy';
const CLIENT_NAME = CLIENT_VARIANT === 'workbuddy-ai' ? 'WorkBuddy AI'
  : CLIENT_VARIANT === 'codebuddy-cn' ? 'CodeBuddy CN'
    : CLIENT_VARIANT === 'codebuddy-intl' ? 'CodeBuddy' : 'WorkBuddy';
const SHARED_DATA_DIR = IS_WIN
  ? path.join(process.env.APPDATA || path.join(HOME, 'AppData', 'Roaming'), 'WorkDaddy')
  : path.join(HOME, 'Library', 'Application Support', 'WorkDaddy');
const DATA_DIR = process.env.WBSWITCH_DATA_DIR || (PROFILE_ID === 'workbuddy-cn'
  ? SHARED_DATA_DIR : path.join(SHARED_DATA_DIR, 'profiles', PROFILE_ID));
const OUTBOX_DIR = path.join(DATA_DIR, 'telemetry', 'outbox');
const MAX_OUTBOX_FILES = 50;
const MAX_FLUSH_FILES = 1;
const REQUEST_TIMEOUT_MS = 3000;
const MAX_TEXT = 6000;

function readVersion() {
  try {
    const source = fs.readFileSync(path.join(__dirname, 'daemon.js'), 'utf8');
    const match = source.match(/DAEMON_VERSION\s*=\s*'([^']+)'/);
    return match ? match[1] : 'unknown';
  } catch (_) {
    return 'unknown';
  }
}

function redactText(value) {
  return String(value == null ? '' : value)
    .replaceAll(HOME, '<HOME>')
    .replace(/(authorization\s*[:=]\s*bearer\s+)[^\s"']+/ig, '$1<redacted>')
    .replace(/(["']?(?:accessToken|refreshToken|idToken|token|cookie|password|secret|apiKey|authorization)["']?\s*[:=]\s*["']?)[^"'\s,}]+/ig, '$1<redacted>')
    .replace(/(https?:\/\/[^\s"']+)[?&](?:token|access_token|refresh_token)=[^&\s"']+/ig, '$1<redacted>')
    .slice(0, MAX_TEXT);
}

function sanitize(value, depth = 0) {
  if (depth > 4) return '<depth-limit>';
  if (typeof value === 'string') return redactText(value);
  if (value == null || typeof value === 'number' || typeof value === 'boolean') return value;
  if (Array.isArray(value)) return value.slice(0, 50).map((item) => sanitize(item, depth + 1));
  if (typeof value === 'object') {
    const result = {};
    for (const [key, item] of Object.entries(value)) {
      if (/token|secret|password|cookie|authorization|credential|private.?key/i.test(key)) {
        result[key] = '<redacted>';
      } else {
        result[key] = sanitize(item, depth + 1);
      }
    }
    return result;
  }
  return redactText(value);
}

function parseDsn(dsn) {
  const url = new URL(dsn);
  const projectId = url.pathname.split('/').filter(Boolean).pop();
  if (!url.username || !projectId || !/^https?:$/.test(url.protocol)) {
    throw new Error('invalid Sentry DSN');
  }
  const endpoint = new URL(`${url.protocol}//${url.host}/api/${projectId}/envelope/`);
  endpoint.searchParams.set('sentry_version', '7');
  endpoint.searchParams.set('sentry_key', decodeURIComponent(url.username));
  endpoint.searchParams.set('sentry_client', CLIENT);
  return endpoint;
}

function eventEnvelope(event) {
  const header = JSON.stringify({ event_id: event.event_id, sent_at: new Date().toISOString() });
  const itemHeader = JSON.stringify({ type: 'event', content_type: 'application/json' });
  return `${header}\n${itemHeader}\n${JSON.stringify(event)}\n`;
}

function sendEvent(event) {
  return new Promise((resolve, reject) => {
    let endpoint;
    try { endpoint = parseDsn(process.env.WORKDADDY_SENTRY_DSN || DEFAULT_DSN); } catch (error) { reject(error); return; }
    const body = eventEnvelope(event);
    const request = https.request({
      method: 'POST',
      hostname: endpoint.hostname,
      port: endpoint.port || 443,
      path: `${endpoint.pathname}${endpoint.search}`,
      timeout: REQUEST_TIMEOUT_MS,
      headers: {
        'content-type': 'application/x-sentry-envelope',
        'content-length': Buffer.byteLength(body),
      },
    }, (response) => {
      response.resume();
      response.on('end', () => {
        if (response.statusCode >= 200 && response.statusCode < 300) resolve();
        else reject(new Error(`Sentry HTTP ${response.statusCode}`));
      });
    });
    request.on('timeout', () => request.destroy(new Error('Sentry request timeout')));
    request.on('error', reject);
    request.end(body);
  });
}

function queueEvent(event) {
  try {
    fs.mkdirSync(OUTBOX_DIR, { recursive: true, mode: 0o700 });
    const file = path.join(OUTBOX_DIR, `${event.event_id}.json`);
    fs.writeFileSync(file, JSON.stringify(event), { mode: 0o600 });
    const files = fs.readdirSync(OUTBOX_DIR).filter((name) => name.endsWith('.json')).sort();
    for (const old of files.slice(0, Math.max(0, files.length - MAX_OUTBOX_FILES))) {
      try { fs.unlinkSync(path.join(OUTBOX_DIR, old)); } catch (_) {}
    }
  } catch (_) {
    // Telemetry must never make installation or startup fail.
  }
}

async function flushOutbox() {
  if (process.env.WORKDADDY_TELEMETRY === '0') return;
  let files;
  try { files = fs.readdirSync(OUTBOX_DIR).filter((name) => name.endsWith('.json')).sort(); } catch (_) { return; }
  for (const name of files.slice(0, MAX_FLUSH_FILES)) {
    const file = path.join(OUTBOX_DIR, name);
    try {
      const event = JSON.parse(fs.readFileSync(file, 'utf8'));
      await sendEvent(event);
      fs.unlinkSync(file);
    } catch (_) {
      break;
    }
  }
}

function makeEvent({ stage, message, level = 'error', tags = {}, extra = {}, exception = null }) {
  const version = readVersion();
  const event = {
    event_id: crypto.randomUUID().replaceAll('-', ''),
    timestamp: Date.now() / 1000,
    platform: 'node',
    level,
    message: redactText(message || 'WorkDaddy telemetry event'),
    logger: 'workdaddy',
    release: `workdaddy@${version}`,
    tags: sanitize({
      source: 'workdaddy',
      stage: stage || 'unknown',
      client: CLIENT_VARIANT,
      client_name: CLIENT_NAME,
      workbuddy_variant: CLIENT_VARIANT === 'workbuddy-ai' ? 'workbuddy-ai' : CLIENT_VARIANT === 'workbuddy' ? 'workbuddy' : 'other',
      os: process.platform,
      arch: process.arch,
      workdaddy_version: version,
      ...tags,
    }),
    contexts: {
      runtime: { name: 'node', version: process.version },
      os: { name: process.platform, version: os.release() },
      client: { name: CLIENT_NAME, profile: PROFILE_ID, variant: CLIENT_VARIANT },
    },
    extra: sanitize(extra),
  };
  if (exception) {
    const error = exception instanceof Error ? exception : new Error(String(exception));
    event.exception = { values: [{ type: error.name || 'Error', value: redactText(error.message), stacktrace: { frames: [] } }] };
    if (error.stack) event.extra.stack = redactText(error.stack);
  }
  return event;
}

async function captureEvent(event) {
  if (process.env.WORKDADDY_TELEMETRY === '0') return { disabled: true };
  await flushOutbox();
  try {
    await sendEvent(event);
    return { sent: true, eventId: event.event_id };
  } catch (_) {
    queueEvent(event);
    return { queued: true, eventId: event.event_id };
  }
}

function captureMessage(message, options = {}) {
  return captureEvent(makeEvent({ ...options, message }));
}

function captureException(error, options = {}) {
  const message = error && error.message ? error.message : String(error || 'Unknown error');
  return captureEvent(makeEvent({ ...options, message, exception: error }));
}

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (!arg.startsWith('--')) continue;
    const key = arg.slice(2);
    if (key === 'dry-run') { args.dryRun = true; continue; }
    args[key] = argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[++i] : '';
  }
  return args;
}

async function cli() {
  const args = parseArgs(process.argv.slice(2));
  let message = args.message || '';
  if (args['message-file']) {
    try { message = fs.readFileSync(path.resolve(args['message-file']), 'utf8'); } catch (_) {}
  }
  let extra = {};
  let tags = {};
  try { if (args['extra-json']) extra = JSON.parse(args['extra-json']); } catch (_) {}
  try { if (args['tags-json']) tags = JSON.parse(args['tags-json']); } catch (_) {}
  const event = makeEvent({ stage: args.stage || 'manual', message, level: args.level || 'error', extra, tags });
  if (args.dryRun) {
    process.stdout.write(JSON.stringify(event, null, 2) + '\n');
    return;
  }
  const result = await captureEvent(event);
  process.stdout.write(JSON.stringify(result) + '\n');
}

module.exports = { captureMessage, captureException, flushOutbox, makeEvent };

if (require.main === module) {
  cli().catch(() => { process.exitCode = 0; });
}
