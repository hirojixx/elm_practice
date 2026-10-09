# elm_practice
elm練習用

#!/usr/bin/env node
/**
 * Kubernetes / Rancher configuration comparison — standalone TypeScript.
 * Node.js 24.12+; no npm install, build step, package.json, or sibling .ts files.
 * Collection requires kubectl. --helm requires Helm. Optional SSH node-file
 * collection requires ssh locally and Node.js 18+ on the selected remote nodes.
 *
 * Quick start (replace prod/stg with your kubeconfig context names):
 *   node k8s_rancher_compare.ts run --prod-context prod --stg-context stg --helm --out result
 *   node k8s_rancher_compare.ts --help
 *
 * Exit status: 0 = complete/equal; 1 = complete/differences; 2 = incomplete/error.
 * Output directories must not already exist. See result/report.md and report.json.
 * Secret bytes are HMACed before writing. ConfigMaps and arbitrary custom
 * resources can contain plaintext credentials: treat all output as confidential.
 * Read-only collection; this sanitized output is not a restorable backup.
 *
 * Optional rule file (--rules rules.json), for example:
 * {"namespace_map":{"prod":{"app-prod":"app"},"stg":{"app-stg":"app"}}}
 * Optional JSON files are user selections, not runtime source dependencies.
 * Schema 2 is unchanged from the modular TypeScript version.
 */

import * as fs from 'node:fs';
import {writeFileSync} from 'node:fs';
import * as path from 'node:path';
import {join} from 'node:path';
import {createHash, createHmac, randomBytes} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {TextDecoder, parseArgs} from 'node:util';

// -----------------------------------------------------------------------------
// types
// -----------------------------------------------------------------------------
/** Kubernetes/CRD payloads have schemas discovered at runtime. */
export type JsonObject = Record<string, any>;
export type Side = 'prod' | 'stg';
export interface CollectionOptions {
  kubeconfig?: string;
  timeout: number;
  helm: boolean;
  helmValuesPlain: boolean;
  nodeFiles?: string;
}
export interface Entry {
  source: string;
  resource: string;
  namespaced: boolean;
  object: JsonObject;
  node_name?: string;
}
export interface Coverage {
  source: string;
  resource: string;
  state: 'ok' | 'failed';
  namespaced?: boolean;
  count?: number;
  error?: string;
  finished_at?: string;
  details?: JsonObject;
}
export interface SourceInfo {
  context?: string;
  discovery?: {namespaced: boolean; cluster: boolean};
  version?: unknown;
  listed?: boolean;
  configured?: boolean;
}
export interface Snapshot {
  schema_version: number;
  tool_version: string;
  started_at: string;
  finished_at?: string;
  hmac_key_id: string;
  objects: Record<string, Entry>;
  coverage: Coverage[];
  errors: Coverage[];
  sources: Record<string, SourceInfo>;
  secret_policy: string;
  helm_values_policy: 'plain' | 'hmac';
  complete: boolean;
}
export interface Selector {
  source?: string;
  resource?: string;
  namespace?: string;
  name?: string;
  reason?: string;
}
export interface IgnoreRule extends Selector {paths: string[]; reason: string}
export interface Rules {
  namespace_map: Record<Side, Record<string, string>>;
  value_map: Record<Side, Record<string, string>>;
  ignore_paths: IgnoreRule[];
  exclude_objects: (Selector & {reason: string})[];
  include_objects: Record<Side, Selector[]>;
}
export type Category = 'same' | 'different' | 'only_prod' | 'only_stg' | 'unknown' | 'ignored';

// -----------------------------------------------------------------------------
// common
// -----------------------------------------------------------------------------
export const VERSION = '2.0.0';
export const SCHEMA = 2;
export const LAST_APPLIED = 'kubectl.kubernetes.io/last-applied-configuration';
export const AUTO_META = new Set(['uid', 'resourceVersion', 'creationTimestamp', 'managedFields',
  'generation', 'deletionTimestamp', 'deletionGracePeriodSeconds', 'selfLink']);
export class CompareError extends Error {
  constructor(message: string) { super(message); this.name = 'CompareError'; }
}
export const now = (): string => new Date().toISOString();

function sortedJson(value: any): any {
  if (Array.isArray(value)) return value.map(sortedJson);
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map(k => [k, sortedJson(value[k])]));
  }
  return value;
}
export function canonical(value: unknown): Buffer {
  const text = JSON.stringify(sortedJson(value));
  if (text === undefined) throw new CompareError('invalid_json_value');
  return Buffer.from(text, 'utf8');
}
export function digest(key: Buffer, value: Buffer): string {
  return 'hmac-sha256:' + createHmac('sha256', key).update(value).digest('hex');
}
export function hashLeaves(value: any, key: Buffer): any {
  if (Array.isArray(value)) return value.map(x => hashLeaves(x, key));
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, hashLeaves(v, key)]));
  }
  return digest(key, canonical(value));
}
export function decodeBase64Strict(value: unknown): Buffer {
  if (typeof value !== 'string' || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw new CompareError('invalid_base64');
  }
  const bytes = Buffer.from(value, 'base64');
  if (bytes.toString('base64') !== value) throw new CompareError('invalid_base64');
  return bytes;
}

// Compare the exact decimal tokens to avoid accepting two distinct JSON numbers
// which JavaScript would round to the same Number. No payload appears in errors.
function decimalKey(token: string): string {
  const m = /^(-?)(\d+)(?:\.(\d+))?(?:[eE]([+-]?\d+))?$/.exec(token);
  if (!m) throw new CompareError('invalid_json_number');
  let digits = (m[2]! + (m[3] ?? '')).replace(/^0+/, '');
  if (!digits) return '0';
  let exponent = BigInt(m[4] ?? '0') - BigInt((m[3] ?? '').length);
  while (digits.endsWith('0')) { digits = digits.slice(0, -1); exponent++; }
  return m[1] + digits + 'e' + exponent.toString();
}
export function parseJson(text: string): any {
  try {
    return JSON.parse(text, function (_key: string, value: any, ...extra: unknown[]): any {
      if (typeof value === 'number') {
        const context = extra[0] as {source?: string} | undefined;
        if (!Number.isFinite(value) || (Number.isInteger(value) && !Number.isSafeInteger(value))) {
          throw new CompareError('unsafe_json_number');
        }
        if (!context?.source || decimalKey(context.source) !== decimalKey(String(value))) {
          throw new CompareError('unsafe_json_number');
        }
      }
      return value;
    });
  } catch (e) {
    if (e instanceof CompareError) throw e;
    throw new CompareError('invalid_json');
  }
}
export function readJson(file: string): any {
  try { return parseJson(fs.readFileSync(file, 'utf8')); }
  catch (e) {
    if (e instanceof CompareError) throw e;
    throw new CompareError('JSONファイルを読み込めません。');
  }
}
export function writeJson(file: string, value: unknown): void {
  fs.mkdirSync(path.dirname(file), {recursive: true, mode: 0o700});
  fs.writeFileSync(file, JSON.stringify(sortedJson(value), null, 2) + '\n', {flag: 'wx', mode: 0o600});
}
export function newDir(file: string): string {
  try {
    const result = path.resolve(file);
    fs.mkdirSync(path.dirname(result), {recursive: true, mode: 0o700});
    fs.mkdirSync(result, {mode: 0o700});
    return result;
  } catch { throw new CompareError('出力先を新規作成できません。既存ディレクトリは上書きしません。'); }
}
export function loadKey(file: string): Buffer {
  try {
    const stat = fs.lstatSync(file);
    if (!stat.isFile() || stat.isSymbolicLink()) throw new CompareError('比較鍵は通常ファイルを指定してください。');
    if (process.platform !== 'win32' && (stat.mode & 0o077) !== 0) throw new CompareError('比較鍵の権限を600にしてください。');
    const data = fs.readFileSync(file);
    if (data.length !== 32) throw new CompareError('比較鍵はkeygenで作成した32バイトのファイルを指定してください。');
    return data;
  } catch (e) {
    if (e instanceof CompareError) throw e;
    throw new CompareError('比較鍵を読み込めません。');
  }
}
function errorKind(stderr: Buffer): string {
  const message = stderr.toString('utf8').toLowerCase();
  if (message.includes('forbidden')) return 'forbidden';
  if (message.includes('unauthorized') || message.includes('provide credentials')) return 'unauthorized';
  if (message.includes('notfound') || message.includes('not found')) return 'not_found';
  if (message.includes('timeout') || message.includes('deadline exceeded')) return 'timeout';
  return 'command_failed';
}
export function execute(cmd: string[], timeout: number, input?: Buffer): Buffer {
  if (!cmd.length) throw new CompareError('empty_command');
  // No shell, no argv or stderr logging. A failed/partial response is discarded.
  const result = spawnSync(cmd[0]!, cmd.slice(1), {
    input, stdio: ['pipe', 'pipe', 'pipe'], timeout: timeout * 1000,
    killSignal: 'SIGKILL', maxBuffer: 256 * 1024 * 1024, windowsHide: true,
  });
  if (result.error) {
    const code = (result.error as NodeJS.ErrnoException).code;
    throw new CompareError(code === 'ETIMEDOUT' ? 'timeout' : code === 'ENOBUFS' ? 'response_too_large' : 'executable_failed');
  }
  if (result.status !== 0) throw new CompareError(errorKind(result.stderr ?? Buffer.alloc(0)));
  return result.stdout ?? Buffer.alloc(0);
}
export function executeJson(cmd: string[], timeout: number): any {
  const data = execute(cmd, timeout);
  let text: string;
  try { text = new TextDecoder('utf-8', {fatal: true}).decode(data); }
  catch { throw new CompareError('invalid_encoding'); }
  return parseJson(text);
}
export function requireExecutable(command: string): void {
  const ext = process.platform === 'win32' ? ['', ...(process.env.PATHEXT ?? '.EXE;.CMD').split(';')] : [''];
  const found = (process.env.PATH ?? '').split(path.delimiter).some(dir => ext.some(suffix => {
    try {
      const name = path.join(dir || '.', command + suffix);
      return fs.statSync(name).isFile() && (fs.accessSync(name, process.platform === 'win32' ? fs.constants.F_OK : fs.constants.X_OK), true);
    } catch { return false; }
  }));
  if (!found) throw new CompareError(command + 'がPATHにありません。');
}
export function problem(snapshot: Snapshot, source: string, resource: string, message: string, namespaced?: boolean): void {
  const record: Coverage = {source, resource, state: 'failed', error: message};
  if (namespaced !== undefined) record.namespaced = namespaced;
  snapshot.coverage.push(record);
  snapshot.errors.push({...record});
  snapshot.complete = false;
}

function encodeComponent(value: string): string {
  if (value === '.' || value === '..') return value.replaceAll('.', '%2E');
  return encodeURIComponent(value).replace(/[!'()*]/g, c => '%' + c.charCodeAt(0).toString(16).toUpperCase());
}
export function objectId(source: string, obj: JsonObject): string {
  const meta = obj.metadata ?? {};
  const api = obj.apiVersion;
  if (typeof api !== 'string' || !api) throw new CompareError('invalid_object_identity');
  const group = api.includes('/') ? api.split('/')[0] : 'core';
  const namespace = meta.namespace;
  const parts = [source, namespace ? 'namespaces' : 'cluster', namespace || '_', group, obj.kind, meta.name];
  if (parts.some(x => typeof x !== 'string' || !x)) throw new CompareError('invalid_object_identity');
  return (parts as string[]).map(encodeComponent).join('/');
}
export function objectFile(root: string, ident: string, suffix = '.json'): string {
  const bounded = (s: string): string => Buffer.byteLength(s) > 180
    ? s.slice(0, 80) + '--' + createHash('sha256').update(s).digest('hex') : s;
  const parts = ident.split('/').map(bounded);
  if (parts.some(s => s === '.' || s === '..' || s.includes('\\') || !s)) throw new CompareError('invalid_artifact_path');
  parts[parts.length - 1] += suffix;
  return path.join(root, ...parts);
}
export function extractConfigmap(root: string, ident: string, obj: JsonObject): void {
  if (obj.kind !== 'ConfigMap' || obj.apiVersion !== 'v1') return;
  for (const field of ['data', 'binaryData']) {
    for (const [key, value] of Object.entries(obj[field] ?? {})) {
      if (typeof value !== 'string') throw new CompareError('invalid_configmap_value');
      const bytes = field === 'data' ? Buffer.from(value, 'utf8') : decodeBase64Strict(value);
      const target = objectFile(root, ident + '/' + field + '/' + encodeComponent(key), '');
      fs.mkdirSync(path.dirname(target), {recursive: true, mode: 0o700});
      fs.writeFileSync(target, bytes, {flag: 'wx', mode: 0o600});
    }
  }
}

export function globMatch(pattern: string, value: string): boolean {
  // Python fnmatch-style glob: * and ? can span '/' here. Node paths use
  // nodePathMatches below to impose component and hidden-file boundaries.
  let out = '^';
  const literal = (c: string): string => c.replace(/[\\^$.*+?()[\]{}|]/g, '\\$&');
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i]!;
    if (c === '*') { out += '[\\s\\S]*'; continue; }
    if (c === '?') { out += '[\\s\\S]'; continue; }
    if (c === '[') {
      let end = i + 1;
      if (pattern[end] === '!') end++;
      if (pattern[end] === ']') end++;
      while (end < pattern.length && pattern[end] !== ']') end++;
      if (end < pattern.length) {
        let body = pattern.slice(i + 1, end);
        const negated = body.startsWith('!');
        if (negated) body = body.slice(1);
        body = body.replaceAll('\\', '\\\\').replaceAll(']', '\\]');
        if (body.startsWith('^')) body = '\\' + body;
        out += '[' + (negated ? '^' : '') + body + ']';
        i = end;
        continue;
      }
    }
    out += literal(c);
  }
  try { return new RegExp(out + '$', 'u').test(value); }
  catch { throw new CompareError('invalid_glob_pattern'); }
}
export function nodePathMatches(file: string, pattern: string): boolean {
  const parts = file.split('/').filter(Boolean);
  const patterns = pattern.split('/').filter(Boolean);
  if (parts.length !== patterns.length) return false;
  return parts.every((part, i) => {
    const rule = patterns[i]!;
    return !(/[*?[]/.test(rule) && part.startsWith('.') && !rule.startsWith('.')) && globMatch(rule, part);
  });
}
export function mdText(value: unknown): string {
  return String(value).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;')
    .replaceAll('|', '\\|').replaceAll('\n', ' ').replaceAll('`', "'");
}

// -----------------------------------------------------------------------------
// collector
// -----------------------------------------------------------------------------
const SENSITIVE_RESOURCES = new Set([
  'tokens.management.cattle.io', 'users.management.cattle.io',
  'userattributes.management.cattle.io', 'authconfigs.management.cattle.io',
  'cloudcredentials.management.cattle.io', 'clusterregistrationtokens.management.cattle.io',
]);

function isRecord(value: unknown): value is JsonObject {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function optionalMap(value: unknown, error: string): JsonObject {
  if (value === undefined || value === null) return Object.create(null);
  if (!isRecord(value)) throw new CompareError(error);
  return value;
}

/** Last-applied annotations can contain original Secret bytes, at any nesting level. */
function cleanAnnotations(value: unknown): any {
  if (Array.isArray(value)) return value.map(cleanAnnotations);
  if (isRecord(value)) {
    return Object.fromEntries(Object.entries(value)
      .filter(([key]) => key !== LAST_APPLIED)
      .map(([key, child]) => [key, cleanAnnotations(child)]));
  }
  return value;
}

export function sanitize(input: JsonObject, key: Buffer, resource: string): JsonObject {
  const obj = cleanAnnotations(input) as JsonObject;
  if (obj.kind === 'Secret' && obj.apiVersion === 'v1') {
    const meta = optionalMap(obj.metadata, 'invalid_secret_metadata');
    const keep = new Set(['name', 'namespace', 'ownerReferences', 'finalizers', 'generateName', ...AUTO_META]);
    const safeMeta = Object.fromEntries(Object.entries(meta).filter(([name]) => keep.has(name)));
    for (const name of ['labels', 'annotations']) {
      if (meta[name] !== undefined && meta[name] !== null) {
        const entries = optionalMap(meta[name], 'invalid_secret_metadata');
        if (Object.keys(entries).length) safeMeta[name] = hashLeaves(entries, key);
      }
    }
    const data: Record<string, string> = Object.create(null);
    for (const [name, value] of Object.entries(optionalMap(obj.data, 'invalid_secret_data'))) {
      data[name] = digest(key, decodeBase64Strict(value));
    }
    for (const [name, value] of Object.entries(optionalMap(obj.stringData, 'invalid_secret_stringData'))) {
      if (typeof value !== 'string') throw new CompareError('invalid_secret_stringData');
      // Kubernetes stringData has precedence over data for a duplicate key.
      data[name] = digest(key, Buffer.from(value, 'utf8'));
    }
    if (obj.type !== undefined && obj.type !== null && typeof obj.type !== 'string') {
      throw new CompareError('invalid_secret_type');
    }
    if (obj.immutable !== undefined && obj.immutable !== null && typeof obj.immutable !== 'boolean') {
      throw new CompareError('invalid_secret_immutable');
    }
    return {
      apiVersion: 'v1', kind: 'Secret', metadata: safeMeta,
      type: obj.type || 'Opaque', immutable: obj.immutable === true, data,
    };
  }

  // These Rancher objects contain credentials without being Kubernetes Secrets.
  if (SENSITIVE_RESOURCES.has(resource)) {
    const safe: JsonObject = Object.create(null);
    const safeMetaNames = new Set(['name', 'namespace', ...AUTO_META]);
    for (const [name, value] of Object.entries(obj)) {
      if (name === 'kind' || name === 'apiVersion') safe[name] = value;
      else if (name === 'metadata') {
        safe[name] = Object.fromEntries(Object.entries(optionalMap(value, 'invalid_sensitive_metadata'))
          .map(([metaName, child]) => [metaName, safeMetaNames.has(metaName) ? child : hashLeaves(child, key)]));
      } else if (name !== 'status') safe[name] = hashLeaves(value, key);
    }
    return safe;
  }

  function nested(value: any): any {
    if (Array.isArray(value)) return value.map(nested);
    if (isRecord(value)) {
      if (value.kind === 'Secret' && value.apiVersion === 'v1') return sanitize(value, key, 'secrets');
      return Object.fromEntries(Object.entries(value).map(([name, child]) => [name, nested(child)]));
    }
    return value;
  }
  return nested(obj);
}

export function createSnapshot(options: CollectionOptions, key: Buffer): Snapshot {
  return {
    schema_version: SCHEMA, tool_version: VERSION, started_at: now(),
    hmac_key_id: createHash('sha256').update(key).digest('hex'),
    objects: Object.create(null), coverage: [], errors: [], sources: Object.create(null),
    secret_policy: 'HMAC-SHA256 of decoded bytes; no Secret values saved',
    helm_values_policy: options.helmValuesPlain ? 'plain' : 'hmac', complete: true,
  };
}

function kubectlBase(options: CollectionOptions, context: string): string[] {
  const base = ['kubectl', '--context', context, `--request-timeout=${options.timeout}s`];
  if (options.kubeconfig) base.push('--kubeconfig', options.kubeconfig);
  return base;
}

function errorMessage(error: unknown): string {
  if (error instanceof CompareError) return error.message;
  // Do not expose raw API data, command arguments, or unexpected exception messages.
  return 'collection_failed';
}

export function collectCluster(
  snapshot: Snapshot, options: CollectionOptions, key: Buffer, context: string, source: string,
): void {
  const base = kubectlBase(options, context);
  const info: SourceInfo = { context, discovery: { namespaced: false, cluster: false } };
  snapshot.sources[source] = info;
  try {
    info.version = executeJson([...base, 'version', '-o', 'json'], options.timeout + 10);
  } catch (error) {
    problem(snapshot, source, '@version', errorMessage(error));
  }
  for (const namespaced of [true, false]) {
    const scope = namespaced ? 'namespaced' : 'cluster';
    let resources: string[];
    try {
      const raw = execute([...base, 'api-resources', '--verbs=list', `--namespaced=${namespaced}`, '-o', 'name'], options.timeout + 10);
      let decoded: string;
      try { decoded = new TextDecoder('utf-8', { fatal: true }).decode(raw); }
      catch { throw new CompareError('invalid_encoding'); }
      resources = [...new Set(decoded.split(/\s+/).filter(Boolean))].sort();
      if (resources.some(resource => !/^[a-z0-9][a-z0-9.-]*$/.test(resource))) {
        throw new CompareError('invalid_discovery_output');
      }
      if (resources.length === 0) throw new CompareError('empty_discovery');
      info.discovery![scope] = true;
    } catch (error) {
      problem(snapshot, source, `@discovery/${scope}`, errorMessage(error), namespaced);
      continue;
    }
    for (const [index, resource] of resources.entries()) {
      if (index === 0 || (index + 1) % 25 === 0) {
        process.stdout.write(`  ${source}/${scope}: ${index + 1}/${resources.length} resource types\n`);
      }
      const args = [...base, 'get', resource];
      if (namespaced) args.push('-A');
      args.push('-o', 'json', '--chunk-size=200');
      try {
        const result = executeJson(args, options.timeout + 10);
        if (!isRecord(result) || !Array.isArray(result.items)) throw new CompareError('invalid_list_response');
        // An invalid final item must not leave a deceptively complete partial list.
        const staged: Record<string, Entry> = Object.create(null);
        for (const obj of result.items) {
          if (!isRecord(obj)) throw new CompareError('invalid_object');
          const ident = objectId(source, obj);
          if (Object.hasOwn(staged, ident) || Object.hasOwn(snapshot.objects, ident)) {
            throw new CompareError('duplicate_object_identity');
          }
          staged[ident] = { source, resource, namespaced, object: sanitize(obj, key, resource) };
        }
        for (const [ident, entry] of Object.entries(staged)) snapshot.objects[ident] = entry;
        snapshot.coverage.push({ source, resource, namespaced, state: 'ok', count: Object.keys(staged).length, finished_at: now() });
      } catch (error) {
        problem(snapshot, source, resource, errorMessage(error), namespaced);
      }
    }
  }
  if (options.helm) collectHelm(snapshot, options, key, context, source);
}

function collectHelm(
  snapshot: Snapshot, options: CollectionOptions, key: Buffer, context: string, parentSource: string,
): void {
  const source = `${parentSource}-helm`;
  const info: SourceInfo = { context, listed: false };
  snapshot.sources[source] = info;
  const base = ['helm', '--kube-context', context];
  if (options.kubeconfig) base.push('--kubeconfig', options.kubeconfig);
  const releases: JsonObject[] = [];
  try {
    let finished = false;
    for (let offset = 0; offset < 200_000; offset += 200) {
      const page = executeJson([...base, 'list', '-A', '--all', '--max', '200', '--offset', String(offset), '-o', 'json'], options.timeout);
      if (!Array.isArray(page) || page.some(item => !isRecord(item))) throw new CompareError('invalid_helm_list');
      releases.push(...page);
      if (page.length < 200) { finished = true; break; }
    }
    if (!finished) throw new CompareError('helm_pagination_limit');
    info.listed = true;
  } catch (error) {
    problem(snapshot, source, 'helm-release', errorMessage(error));
    return;
  }
  let failed = false;
  const seen = new Set<string>();
  for (const release of releases) {
    const name = release.name, ns = release.namespace;
    if (typeof name !== 'string' || typeof ns !== 'string' || !name || !ns || name.startsWith('-') || ns.startsWith('-')) {
      problem(snapshot, source, 'helm-release', 'invalid_helm_identity');
      failed = true;
      continue;
    }
    const releaseId = JSON.stringify([ns, name]);
    if (seen.has(releaseId)) {
      problem(snapshot, source, 'helm-release', 'duplicate_helm_release');
      failed = true;
      continue;
    }
    seen.add(releaseId);
    try {
      const args = [...base, 'get', 'values', name, '-n', ns, '-o', 'json'];
      const user = cleanAnnotations(optionalMap(executeJson(args, options.timeout), 'invalid_helm_values'));
      const computed = cleanAnnotations(optionalMap(executeJson([...args, '--all'], options.timeout), 'invalid_helm_values'));
      const manifest = execute([...base, 'get', 'manifest', name, '-n', ns], options.timeout);
      const hooks = execute([...base, 'get', 'hooks', name, '-n', ns], options.timeout);
      const obj: JsonObject = {
        apiVersion: 'compare.local/v1', kind: 'HelmRelease', metadata: { namespace: ns, name },
        chart: release.chart ?? null, appVersion: release.app_version ?? null,
        userValues: options.helmValuesPlain ? user : hashLeaves(user, key),
        computedValues: options.helmValuesPlain ? computed : hashLeaves(computed, key),
        manifestHmac: digest(key, manifest), hooksHmac: digest(key, hooks),
      };
      const ident = objectId(source, obj);
      if (Object.hasOwn(snapshot.objects, ident)) throw new CompareError('duplicate_object_identity');
      snapshot.objects[ident] = { source, resource: 'helm-release', namespaced: true, object: obj };
    } catch (error) {
      problem(snapshot, source, 'helm-release', errorMessage(error));
      failed = true;
    }
  }
  if (!failed) snapshot.coverage.push({ source, resource: 'helm-release', state: 'ok', count: releases.length, namespaced: true, finished_at: now() });
}

export function finishSnapshot(snapshot: Snapshot, directory: string): Snapshot {
  snapshot.finished_at = now();
  for (const [ident, entry] of Object.entries(snapshot.objects)) {
    writeJson(objectFile(join(directory, 'observed'), ident), entry.object);
  }
  writeJson(join(directory, 'snapshot.json'), snapshot);
  return snapshot;
}

// -----------------------------------------------------------------------------
// nodes
// -----------------------------------------------------------------------------
const FILE_LIMIT = 10 * 1024 * 1024;
const TOTAL_LIMIT = 32 * 1024 * 1024;
const RESPONSE_LIMIT = 64 * 1024 * 1024;
const RESULT_LIMIT = 10000;
const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

type PathSelection = { glob: string; mode: 'hmac' | 'text' };
type RemotePattern = { glob: string; error?: string; matched_count?: number; file_count?: number };
type RemoteFile = { glob: string; path: string; mode: 'hmac' | 'text'; data?: string; error?: string };
const READ_ERRORS = new Set(['permission_denied', 'file_disappeared', 'not_regular', 'file_too_large', 'total_limit', 'read_failed']);
const GLOB_ERRORS = new Set(['permission_denied', 'glob_failed', 'selection_limit']);

/** Fixed JavaScript program: user selections travel only on stdin, never in shell code.
 * Node.js >=18 is required on the SSH target. Symlinks are intentionally followed,
 * but fstat() must confirm a regular file before its contents are read. */
export const NODE_REMOTE_SCRIPT = String.raw`
'use strict';
const fs = require('node:fs');
const path = require('node:path').posix;
const LIMIT = 10 * 1024 * 1024, TOTAL = 32 * 1024 * 1024, RESULTS = 10000;
const out = {patterns: [], files: []};
let used = 0;
function fail(code) { const e = new Error(); e.safeCode = code; throw e; }
// Component matcher uses dynamic programming, avoiding exponential regex backtracking.
function match(pattern, value) {
  const p = Array.from(pattern), s = Array.from(value), tokens = [];
  for (let i = 0; i < p.length; i++) {
    if (p[i] === '*' || p[i] === '?') { tokens.push({type:p[i]}); continue; }
    if (p[i] === '[') {
      let end = i + 1;
      if (p[end] === '!') end++;
      if (p[end] === ']') end++;
      while (end < p.length && p[end] !== ']') end++;
      if (end < p.length) {
        let chars = p.slice(i + 1, end), negate = chars[0] === '!';
        if (negate) chars = chars.slice(1);
        tokens.push({type:'class', chars, negate}); i = end; continue;
      }
    }
    tokens.push({type:'literal', value:p[i]});
  }
  let previous = new Uint8Array(s.length + 1); previous[0] = 1;
  for (const token of tokens) {
    const next = new Uint8Array(s.length + 1);
    if (token.type === '*') {
      next[0] = previous[0];
      for (let j = 1; j <= s.length; j++) next[j] = previous[j] || next[j - 1];
    } else {
      for (let j = 1; j <= s.length; j++) {
        if (!previous[j - 1]) continue;
        let yes = token.type === '?' || (token.type === 'literal' && token.value === s[j - 1]);
        if (token.type === 'class') {
          let hit = false;
          for (let c = 0; c < token.chars.length; c++) {
            if (c + 2 < token.chars.length && token.chars[c + 1] === '-') {
              hit ||= s[j - 1] >= token.chars[c] && s[j - 1] <= token.chars[c + 2]; c += 2;
            } else hit ||= s[j - 1] === token.chars[c];
          }
          yes = token.negate ? !hit : hit;
        }
        if (yes) next[j] = 1;
      }
    }
    previous = next;
  }
  return previous[s.length] === 1;
}
function expand(pattern) {
  let parents = ['/'];
  for (const part of pattern.split('/').filter(Boolean)) {
    const found = new Set();
    for (const parent of parents) {
      try {
        if (/[*?\[]/.test(part)) {
          for (const entry of fs.readdirSync(parent, {withFileTypes:true})) {
            if (entry.name.startsWith('.') && !part.startsWith('.')) continue;
            if (match(part, entry.name)) found.add(path.join(parent, entry.name));
            if (found.size > 5000) fail('selection_limit');
          }
        } else {
          const candidate = path.join(parent, part);
          fs.lstatSync(candidate); found.add(candidate);
          if (found.size > 5000) fail('selection_limit');
        }
      } catch (error) {
        if (error.code === 'ENOENT' || error.code === 'ENOTDIR') continue;
        if (error.code === 'EACCES' || error.code === 'EPERM') fail('permission_denied');
        throw error;
      }
    }
    parents = [...found];
  }
  return parents.sort();
}
function readRegular(file) {
  let fd;
  try {
    fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NONBLOCK);
    const info = fs.fstatSync(fd);
    if (!info.isFile()) fail('not_regular');
    if (info.size > LIMIT) fail('file_too_large');
    if (used + info.size > TOTAL) fail('total_limit');
    const chunks = []; let size = 0;
    while (true) {
      const chunk = Buffer.allocUnsafe(Math.min(65536, LIMIT + 1 - size));
      const count = fs.readSync(fd, chunk, 0, chunk.length, null);
      if (!count) break;
      size += count;
      if (size > LIMIT) fail('file_too_large');
      if (used + size > TOTAL) fail('total_limit');
      chunks.push(chunk.subarray(0, count));
    }
    used += size;
    return Buffer.concat(chunks, size).toString('base64');
  } finally { if (fd !== undefined) fs.closeSync(fd); }
}
try {
  const request = JSON.parse(fs.readFileSync(0, 'utf8'));
  if (!request || !Array.isArray(request.paths) || request.paths.length > 100) process.exit(2);
  for (const entry of request.paths) {
    const glob = entry.glob;
    let matches;
    try {
      matches = expand(glob);
      if (out.files.length + matches.length > RESULTS) fail('selection_limit');
    } catch (error) {
      out.patterns.push({glob, error:['permission_denied','selection_limit'].includes(error.safeCode) ? error.safeCode : 'glob_failed'});
      continue;
    }
    const result = {glob, matched_count:matches.length, file_count:0};
    for (const file of matches) {
      const item = {glob, path:file, mode:entry.mode};
      try { item.data = readRegular(file); result.file_count++; }
      catch (error) {
        item.error = error.code === 'EACCES' || error.code === 'EPERM' ? 'permission_denied' :
          error.code === 'ENOENT' ? 'file_disappeared' :
          ['not_regular','file_too_large','total_limit'].includes(error.safeCode) ? error.safeCode : 'read_failed';
      }
      out.files.push(item);
    }
    out.patterns.push(result);
  }
  process.stdout.write(JSON.stringify(out));
} catch { process.exitCode = 2; }
`;

function record(value: unknown): value is JsonObject {
  return value !== null && typeof value === 'object' && !Array.isArray(value) &&
    (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
}
function exactKeys(value: JsonObject, keys: string[]): boolean {
  const actual = Object.keys(value);
  return actual.length === keys.length && actual.every(k => keys.includes(k));
}
function validPath(value: unknown): value is string {
  return typeof value === 'string' && value.startsWith('/') && value.length <= 4096 &&
    !/[\x00-\x1f\x7f]/.test(value) && !value.includes('//') &&
    !value.split('/').some(p => p === '.' || p === '..') && (value === '/' || !value.endsWith('/'));
}
function pathMatches(pattern: string, path: string): boolean {
  const a = pattern.split('/'), b = path.split('/');
  return a.length === b.length && a.every((part, i) =>
    !(b[i].startsWith('.') && !part.startsWith('.')) && globMatch(part, b[i]));
}
function quoted(value: string): string { return "'" + value.replaceAll("'", "'\\''") + "'"; }
function hmac(key: Buffer, data: Buffer): string { return createHmac('sha256', key).update(data).digest('hex'); }

/** Read only selected files; data is HMACed before it enters the snapshot. */
export function collectNodes(snapshot: Snapshot, spec: unknown, side: Side, key: Buffer, timeout: number): void {
  snapshot.sources.nodes = { configured: true };
  const fail = (name: string, code: string, glob = '*'): void =>
    problem(snapshot, 'nodes', `node/${name}/@pattern/${glob}`, code, false);
  if (!record(spec) || !Array.isArray(spec.nodes)) {
    fail('', 'invalid_node_spec'); return;
  }
  if (!spec.nodes.some((node: unknown) => record(node) && node.side === side)) {
    problem(snapshot, 'nodes', '@selection', 'no_nodes_selected_for_side', false);
  }
  const seen = new Set<string>();
  for (const node of spec.nodes) {
    if (!record(node)) { fail('', 'invalid_node_entry'); continue; }
    if (node.side !== 'prod' && node.side !== 'stg') { fail('', 'invalid_node_side'); continue; }
    if (node.side !== side) continue;
    const name: unknown = node.name, host: unknown = node.host;
    if (typeof name !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(name)) {
      fail('', 'invalid_node_name'); continue;
    }
    if (seen.has(name)) { fail(name, 'duplicate_node_name'); continue; }
    seen.add(name);
    if (typeof host !== 'string' || host.length > 512 ||
      !/^(?:[A-Za-z0-9_][A-Za-z0-9_.-]*@)?(?:[A-Za-z0-9_][A-Za-z0-9_.-]*|\[[0-9A-Fa-f:]+\])$/.test(host)) {
      fail(name, 'invalid_ssh_host'); continue;
    }
    if (!Array.isArray(node.paths) || !node.paths.length || node.paths.length > 100 ||
      ('sudo' in node && typeof node.sudo !== 'boolean')) {
      fail(name, 'invalid_node_paths'); continue;
    }
    const selected: PathSelection[] = [];
    for (const item of node.paths) {
      if (!record(item) || !validPath(item.glob) || (item.mode !== undefined && item.mode !== 'hmac' && item.mode !== 'text')) break;
      selected.push({ glob: item.glob, mode: item.mode ?? 'hmac' });
    }
    if (selected.length !== node.paths.length || new Set(selected.map(p => p.glob)).size !== selected.length) {
      fail(name, 'invalid_node_paths'); continue;
    }
    const coverage = new Map<string, Coverage>();
    for (const item of selected) {
      const c: Coverage = { source: 'nodes', resource: `node/${name}/@pattern/${item.glob}`, state: 'failed',
        details: { node: name, glob: item.glob, status: 'failed' } };
      coverage.set(item.glob, c); snapshot.coverage.push(c);
    }
    const command = (node.sudo ? 'sudo -n ' : '') + 'node -e ' + quoted(NODE_REMOTE_SCRIPT);
    let output: Buffer;
    try {
      output = execute(['ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-o', 'ConnectTimeout=10',
        '-o', 'ServerAliveInterval=10', '-o', 'ServerAliveCountMax=2', host, command], timeout,
      Buffer.from(JSON.stringify({ paths: selected }), 'utf8'));
    } catch { fail(name, 'ssh_or_remote_failed'); continue; }
    const allowed = new Map(selected.map(p => [p.glob, p.mode]));
    let patterns: RemotePattern[], files: RemoteFile[];
    const decoded = new Map<RemoteFile, Buffer>();
    try {
      if (output.length > RESPONSE_LIMIT) throw new Error();
      const document: unknown = JSON.parse(decoder.decode(output));
      if (!record(document) || !exactKeys(document, ['patterns', 'files']) || !Array.isArray(document.patterns) ||
        !Array.isArray(document.files) || document.patterns.length !== selected.length || document.files.length > RESULT_LIMIT) throw new Error();
      patterns = document.patterns; files = document.files;
      const actualPatterns = new Set<string>();
      for (const item of patterns) {
        if (!record(item) || typeof item.glob !== 'string' || !allowed.has(item.glob) || actualPatterns.has(item.glob)) throw new Error();
        actualPatterns.add(item.glob);
        if (Object.hasOwn(item, 'error')) {
          if (!exactKeys(item, ['glob', 'error']) || typeof item.error !== 'string' || !GLOB_ERRORS.has(item.error)) throw new Error();
        } else if (!exactKeys(item, ['glob', 'matched_count', 'file_count']) || !Number.isSafeInteger(item.matched_count) ||
          !Number.isSafeInteger(item.file_count) || item.file_count! < 0 || item.matched_count! < item.file_count! || item.matched_count! > 5000) throw new Error();
      }
      const actualFiles = new Set<string>(), counts = new Map<string, {matched: number; read: number}>();
      let total = 0;
      for (const item of files) {
        if (!record(item) || typeof item.glob !== 'string' || !allowed.has(item.glob) || !validPath(item.path) ||
          !pathMatches(item.glob, item.path) || item.mode !== allowed.get(item.glob)) throw new Error();
        const identity = JSON.stringify([item.glob, item.path]);
        if (actualFiles.has(identity)) throw new Error();
        actualFiles.add(identity);
        const count = counts.get(item.glob) ?? {matched: 0, read: 0}; count.matched++;
        if (Object.hasOwn(item, 'error')) {
          if (!exactKeys(item, ['glob', 'path', 'mode', 'error']) || typeof item.error !== 'string' || !READ_ERRORS.has(item.error)) throw new Error();
        } else {
          if (!exactKeys(item, ['glob', 'path', 'mode', 'data']) || typeof item.data !== 'string' ||
            item.data.length > Math.ceil(FILE_LIMIT / 3) * 4 || (item.data.length % 4 !== 0 || /[^A-Za-z0-9+/=]/.test(item.data))) throw new Error();
          const bytes = Buffer.from(item.data, 'base64');
          total += bytes.length;
          if (bytes.length > FILE_LIMIT || total > TOTAL_LIMIT || bytes.toString('base64') !== item.data) throw new Error();
          decoded.set(item, bytes); count.read++;
        }
        counts.set(item.glob, count);
      }
      for (const item of patterns) {
        const count = counts.get(item.glob) ?? {matched: 0, read: 0};
        if (item.error ? count.matched !== 0 : count.matched !== item.matched_count || count.read !== item.file_count) throw new Error();
      }
    } catch { fail(name, 'invalid_remote_response'); continue; }
    const save = (resource: string, file: JsonObject): void => {
      const object = { apiVersion: 'compare.local/v1', kind: 'NodeFile', metadata: { name: resource }, file };
      const id = objectId('nodes', object);
      Object.defineProperty(snapshot.objects, id, { value: { source: 'nodes', resource, namespaced: false, node_name: name, object },
        writable: true, enumerable: true, configurable: true });
    };
    for (const item of patterns) {
      const c = coverage.get(item.glob)!;
      if (item.error) { fail(name, item.error, item.glob); continue; }
      c.details!.matched_count = item.matched_count; c.details!.file_count = item.file_count;
      c.state = item.matched_count === item.file_count ? 'ok' : 'failed'; c.details!.status = c.state;
      save(`node/${name}/@pattern/${item.glob}`, { glob: item.glob, matched_count: item.matched_count });
    }
    // If overlapping patterns observe inconsistent contents/modes, report an incomplete
    // capture instead of choosing which potentially sensitive representation to keep.
    const byPath = new Map<string, RemoteFile[]>();
    for (const item of files) {
      const group = byPath.get(item.path) ?? []; group.push(item); byPath.set(item.path, group);
    }
    for (const [path, group] of byPath) {
      const good = group.filter(item => !item.error);
      for (const item of group.filter(item => item.error)) fail(name, item.error!, item.glob);
      if (!good.length) continue;
      const first = good[0], bytes = decoded.get(first)!;
      const conflicting = good.some(item => item.mode !== first.mode || !decoded.get(item)!.equals(bytes));
      if (conflicting) {
        for (const item of good) {
          const c = coverage.get(item.glob)!; c.state = 'failed'; c.details!.status = 'failed';
          fail(name, 'overlapping_file_conflict', item.glob);
        }
        continue;
      }
      const file: JsonObject = { path, mode: first.mode, size: bytes.length };
      if (first.mode === 'text') {
        try { file.text = decoder.decode(bytes); }
        catch {
          for (const item of good) {
            const c = coverage.get(item.glob)!; c.state = 'failed'; c.details!.status = 'failed';
            fail(name, 'invalid_utf8', item.glob);
          }
          continue;
        }
      } else file.hmac_sha256 = hmac(key, bytes);
      save(`node/${name}/file/${path}`, file);
    }
    if ([...coverage.values()].some(c => c.state !== 'ok')) snapshot.complete = false;
  }
}

// -----------------------------------------------------------------------------
// comparison
// -----------------------------------------------------------------------------
const has = (object: object, key: PropertyKey): boolean => Object.hasOwn(object, key);
const isObject = (value: unknown): value is JsonObject => value !== null && typeof value === 'object' && !Array.isArray(value);
const clone = <T>(value: T): T => structuredClone(value);
const SIDES: Side[] = ['prod', 'stg'];
const SELECTOR_KEYS = ['source', 'resource', 'namespace', 'name', 'reason'];
const SECRET_POLICY = 'HMAC-SHA256 of decoded bytes; no Secret values saved';

function defaultRules(): Rules {
  return {
    namespace_map: { prod: {}, stg: {} }, value_map: { prod: {}, stg: {} },
    ignore_paths: [], exclude_objects: [], include_objects: { prod: [], stg: [] },
  };
}

function pointerParts(pointer: string): string[] {
  return pointer.split('/').slice(1).map(part => part.replaceAll('~1', '/').replaceAll('~0', '~'));
}

/** Accept only explicit supported rule fields; selectors operate on exact strings or globs. */
export function loadRules(path?: string): Rules {
  const rules = defaultRules();
  if (!path) return rules;
  const user = readJson(path);
  if (!isObject(user) || Object.keys(user).some(key => !has(rules, key))) {
    throw new CompareError('rulesに未知のトップレベルキーがあります。');
  }
  // Fixed, validated keys only; do not assign arbitrary input keys onto a prototype.
  for (const key of Object.keys(rules) as (keyof Rules)[]) {
    if (has(user, key)) (rules as unknown as JsonObject)[key] = user[key];
  }
  for (const field of ['namespace_map', 'value_map'] as const) {
    const mappings = rules[field];
    if (!isObject(mappings) || Object.keys(mappings).some(side => !SIDES.includes(side as Side))) {
      throw new CompareError('rulesのマッピングにはprod/stgを指定してください。');
    }
    for (const mapping of Object.values(mappings)) {
      if (!isObject(mapping) || Object.values(mapping).some(value => typeof value !== 'string')) {
        throw new CompareError('rulesのマッピングは文字列から文字列への辞書にしてください。');
      }
    }
    for (const side of SIDES) if (!has(mappings, side)) mappings[side] = {};
  }
  for (const field of ['ignore_paths', 'exclude_objects'] as const) {
    if (!Array.isArray(rules[field])) throw new CompareError('rulesの除外指定は配列にしてください。');
    for (const rule of rules[field]) {
      const allowed = new Set([...SELECTOR_KEYS, ...(field === 'ignore_paths' ? ['paths'] : [])]);
      if (!isObject(rule) || Object.keys(rule).some(key => !allowed.has(key)) ||
          !has(rule, 'reason') || typeof rule.reason !== 'string' || !rule.reason.trim()) {
        throw new CompareError('除外ルールにはreasonを指定し、未知のキーを除いてください。');
      }
      if (Object.entries(rule).some(([key, value]) => key !== 'paths' && typeof value !== 'string')) {
        throw new CompareError('除外ルールの選択条件は文字列にしてください。');
      }
      if (field === 'ignore_paths') {
        const paths: unknown = (rule as JsonObject).paths;
        if (!Array.isArray(paths) || !paths.length) throw new CompareError('ignore_pathsにはpaths配列が必要です。');
        for (const pointer of paths) {
          if (typeof pointer !== 'string' || !pointer.startsWith('/') || pointer === '/' || /~(?:[^01]|$)/.test(pointer)) {
            throw new CompareError('pathsにはルート以外のJSON Pointerを指定してください。');
          }
          const parts = pointerParts(pointer);
          const protectedPaths = [['metadata', 'name'], ['metadata', 'namespace'], ['apiVersion'], ['kind']];
          if (protectedPaths.some(target => parts.length <= target.length && parts.every((part, i) => part === '*' || part === target[i]))) {
            throw new CompareError('識別子の削除はできません。namespace_map/value_mapを使用してください。');
          }
        }
      }
    }
  }
  const includes = rules.include_objects;
  if (!isObject(includes) || Object.keys(includes).some(side => !SIDES.includes(side as Side))) {
    throw new CompareError('include_objectsにはprod/stgの配列を指定してください。');
  }
  for (const entries of Object.values(includes)) {
    if (!Array.isArray(entries)) throw new CompareError('include_objectsの環境ごとの指定は配列です。');
    for (const entry of entries) {
      if (!isObject(entry) || !has(entry, 'source') || typeof entry.source !== 'string' || !entry.source ||
          /[*?\[]/.test(entry.source) || Object.keys(entry).some(key => !SELECTOR_KEYS.includes(key)) ||
          Object.values(entry).some(value => typeof value !== 'string')) {
        throw new CompareError('include_objectsにはワイルドカードのないsourceと文字列の選択条件を指定してください。');
      }
    }
  }
  for (const side of SIDES) if (!has(includes, side)) includes[side] = [];
  return rules;
}

function normalize(original: JsonObject): JsonObject {
  const object = clone(original);
  delete object.status;
  function walk(value: unknown): void {
    if (Array.isArray(value)) {
      for (const item of value) walk(item);
    } else if (isObject(value)) {
      const meta = has(value, 'metadata') ? value.metadata : undefined;
      if (isObject(meta)) {
        for (const key of AUTO_META) delete meta[key];
        if (has(meta, 'ownerReferences') && Array.isArray(meta.ownerReferences)) {
          for (const owner of meta.ownerReferences) if (isObject(owner)) delete owner.uid;
        }
        if (has(meta, 'annotations') && isObject(meta.annotations)) {
          delete meta.annotations[LAST_APPLIED];
          if (Object.keys(meta.annotations).length === 0) delete meta.annotations;
        }
        if (has(meta, 'labels') && isObject(meta.labels) && Object.keys(meta.labels).length === 0) delete meta.labels;
      }
      for (const item of Object.values(value)) walk(item);
    }
  }
  walk(object);
  return object;
}

function mapValues(original: JsonObject, namespaceMap: Record<string, string>, valueMap: Record<string, string>): JsonObject {
  const object = clone(original);
  if (object.kind === 'Namespace' && object.apiVersion === 'v1') {
    const metadata = object.metadata;
    if (typeof metadata.name === 'string' && has(namespaceMap, metadata.name)) metadata.name = namespaceMap[metadata.name];
    const labels = has(metadata, 'labels') ? metadata.labels : undefined;
    if (isObject(labels) && has(labels, 'kubernetes.io/metadata.name')) {
      const name = labels['kubernetes.io/metadata.name'];
      if (typeof name === 'string' && has(namespaceMap, name)) labels['kubernetes.io/metadata.name'] = namespaceMap[name];
    }
  }
  function walk(value: unknown, field?: string): unknown {
    if (Array.isArray(value)) return value.map(item => walk(item, field));
    if (isObject(value)) return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, walk(item, key)]));
    if (typeof value === 'string' && !value.startsWith('hmac-sha256:')) {
      if (field === 'namespace' && has(namespaceMap, value)) return namespaceMap[value];
      if (has(valueMap, value)) return valueMap[value];
    }
    return value;
  }
  return walk(object) as JsonObject;
}

function matches(rule: Selector, entry: Entry, object: JsonObject): boolean {
  const metadata = object.metadata;
  const fields = {
    source: entry.source, resource: entry.resource,
    namespace: has(metadata, 'namespace') ? metadata.namespace : '', name: metadata.name,
  };
  return Object.entries(fields).every(([key, value]) =>
    globMatch(has(rule, key) ? String((rule as JsonObject)[key]) : '*', String(value)));
}

function removePointer(object: JsonObject, pointer: string): void {
  const parts = pointerParts(pointer);
  function visit(node: unknown, index: number): void {
    if (!isObject(node) && !Array.isArray(node)) return;
    for (const key of Object.keys(node)) {
      if (parts[index] !== '*' && parts[index] !== key) continue;
      if (index === parts.length - 1) {
        // Never splice or sort arrays: positions carry semantics.
        if (Array.isArray(node)) node[Number(key)] = '<ignored-by-rule>';
        else delete node[key];
      } else visit((node as JsonObject)[key], index + 1);
    }
  }
  visit(object, 0);
}

function runtimeReason(entry: Entry, object: JsonObject, includeRuntime: boolean): string | undefined {
  if (includeRuntime) return undefined;
  if (['events', 'events.events.k8s.io', 'leases.coordination.k8s.io'].includes(entry.resource) || entry.resource.endsWith('.metrics.k8s.io')) {
    return 'runtime resource (saved in observed)';
  }
  const metadata = object.metadata;
  if (['Pod', 'ReplicaSet', 'ControllerRevision'].includes(object.kind) &&
      has(metadata, 'ownerReferences') && Array.isArray(metadata.ownerReferences) && metadata.ownerReferences.length > 0) {
    return 'controller-owned runtime resource (saved in observed)';
  }
  if (entry.resource === 'endpointslices.discovery.k8s.io' && has(metadata, 'labels') && isObject(metadata.labels) &&
      metadata.labels['endpointslice.kubernetes.io/managed-by'] === 'endpointslice-controller.k8s.io') {
    return 'controller-managed EndpointSlice (saved in observed)';
  }
  if (object.kind === 'Secret' && object.type === 'helm.sh/release.v1') return 'Helm storage Secret (use --helm to inspect releases)';
  return undefined;
}

interface Prepared {
  entry: Entry;
  object: JsonObject;
  before: JsonObject;
  excluded?: string;
  reasons: string[];
}

function prepare(snapshot: Snapshot, side: Side, rules: Rules, includeRuntime: boolean): Map<string, Prepared> {
  const result = new Map<string, Prepared>();
  const includes = rules.include_objects[side] ?? [];
  const narrowedSources = new Set(includes.map(rule => rule.source));
  for (const entry of Object.values(snapshot.objects)) {
    // Include selection is side-specific and uses original identities. Other sources remain included.
    if (narrowedSources.has(entry.source) && !includes.some(rule => rule.source === entry.source && matches(rule, entry, entry.object))) continue;
    const object = mapValues(normalize(entry.object), rules.namespace_map[side] ?? {}, rules.value_map[side] ?? {});
    const ident = objectId(entry.source, object);
    if (result.has(ident)) throw new CompareError('環境名マッピングによりオブジェクト識別子が衝突しました。');
    let excluded = runtimeReason(entry, object, includeRuntime);
    for (const rule of rules.exclude_objects) if (matches(rule, entry, object)) excluded = rule.reason;
    const before = clone(object);
    const reasons: string[] = [];
    if (object.kind === 'Secret' && object.type === 'kubernetes.io/service-account-token' && !includeRuntime) {
      if (has(object, 'data') && isObject(object.data)) {
        for (const key of Object.keys(object.data)) object.data[key] = '<generated-service-account-value>';
      }
      const metadata = object.metadata;
      if (has(metadata, 'annotations') && isObject(metadata.annotations)) {
        delete metadata.annotations['kubernetes.io/service-account.uid'];
        if (Object.keys(metadata.annotations).length === 0) delete metadata.annotations;
      }
      reasons.push('ServiceAccount token values ignored; existence/type/keys compared');
    }
    for (const rule of rules.ignore_paths) {
      if (matches(rule, entry, object)) {
        for (const pointer of rule.paths) removePointer(object, pointer);
        reasons.push(rule.reason);
      }
    }
    result.set(ident, { entry, object, before, excluded, reasons });
  }
  return result;
}

function diffPaths(a: unknown, b: unknown, prefix = ''): string[] {
  if (Array.isArray(a) || Array.isArray(b)) {
    if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) return [prefix || '/'];
    return a.flatMap((value, index) => diffPaths(value, b[index], `${prefix}/${index}`));
  }
  if (isObject(a) || isObject(b)) {
    if (!isObject(a) || !isObject(b)) return [prefix || '/'];
    return [...new Set([...Object.keys(a), ...Object.keys(b)])].sort().flatMap(key => {
      const path = `${prefix}/${key.replaceAll('~', '~0').replaceAll('/', '~1')}`;
      return !has(a, key) || !has(b, key) ? [path] : diffPaths(a[key], b[key], path);
    });
  }
  return a === b ? [] : [prefix || '/'];
}

function counterpartKnown(snapshot: Snapshot, entry: Pick<Entry, 'source' | 'resource' | 'namespaced'> & Partial<Entry>): boolean {
  const coverage = snapshot.coverage.filter(record => record.source === entry.source && record.resource === entry.resource);
  if (coverage.some(record => record.state === 'failed')) return false;
  if (entry.source === 'nodes') {
    // A successful different node or a broader recursive glob never establishes absence here.
    const path = entry.object?.file?.path;
    const node = entry.node_name;
    if (typeof node !== 'string' || !node) return false;
    if (typeof path === 'string') {
      const relevant = snapshot.coverage.filter(record => record.source === 'nodes' &&
        record.details?.node === node && typeof record.details?.glob === 'string' && nodePathMatches(path, record.details.glob));
      return relevant.length > 0 && relevant.every(record => record.state === 'ok');
    }
    return coverage.some(record => record.state === 'ok' && record.details?.node === node);
  }
  if (coverage.some(record => record.state === 'ok')) return true;
  const info = has(snapshot.sources, entry.source) ? snapshot.sources[entry.source] : undefined;
  if (entry.source.endsWith('-helm')) return info?.listed === true;
  return info?.discovery?.[entry.namespaced ? 'namespaced' : 'cluster'] === true;
}

function validateSnapshot(snapshot: Snapshot): void {
  if (!isObject(snapshot) || !has(snapshot, 'schema_version') || snapshot.schema_version !== SCHEMA || !isObject(snapshot.objects)) {
    throw new CompareError('スナップショット形式が一致しません。Node.js版 schema 2 で採取し直してください。');
  }
  const required = ['objects', 'coverage', 'errors', 'sources', 'complete', 'hmac_key_id', 'secret_policy', 'helm_values_policy'];
  if (required.some(key => !has(snapshot, key)) || !Array.isArray(snapshot.coverage) || !Array.isArray(snapshot.errors) ||
      !isObject(snapshot.sources) || typeof snapshot.complete !== 'boolean' || typeof snapshot.hmac_key_id !== 'string' ||
      !/^[0-9a-f]{64}$/.test(snapshot.hmac_key_id) || snapshot.secret_policy !== SECRET_POLICY ||
      !['plain', 'hmac'].includes(snapshot.helm_values_policy)) {
    throw new CompareError('スナップショットが不完全な形式、または未対応の秘匿化方式です。');
  }
  for (const entry of Object.values(snapshot.objects)) {
    if (!isObject(entry) || ['source', 'resource', 'namespaced', 'object'].some(key => !has(entry, key)) ||
        typeof entry.source !== 'string' || !entry.source || typeof entry.resource !== 'string' || !entry.resource ||
        typeof entry.namespaced !== 'boolean' || !isObject(entry.object)) {
      throw new CompareError('スナップショット内のオブジェクト情報が不正です。');
    }
    const object = entry.object;
    if (!has(object, 'apiVersion') || typeof object.apiVersion !== 'string' || !object.apiVersion ||
        !has(object, 'kind') || typeof object.kind !== 'string' || !object.kind ||
        !has(object, 'metadata') || !isObject(object.metadata) || !has(object.metadata, 'name') ||
        typeof object.metadata.name !== 'string' || !object.metadata.name ||
        (has(object.metadata, 'namespace') && typeof object.metadata.namespace !== 'string')) {
      throw new CompareError('スナップショット内のオブジェクト識別子が不正です。');
    }
  }
  for (const coverage of [...snapshot.coverage, ...snapshot.errors]) {
    if (!isObject(coverage) || ['source', 'resource', 'state'].some(key => !has(coverage, key)) ||
        typeof coverage.source !== 'string' || typeof coverage.resource !== 'string' || !['ok', 'failed'].includes(coverage.state) ||
        (has(coverage, 'namespaced') && typeof coverage.namespaced !== 'boolean') ||
        (has(coverage, 'details') && !isObject(coverage.details))) {
      throw new CompareError('スナップショット内の取得状況が不正です。');
    }
  }
  for (const info of Object.values(snapshot.sources)) {
    if (!isObject(info) || (has(info, 'discovery') && (!isObject(info.discovery) ||
        !has(info.discovery, 'namespaced') || typeof info.discovery.namespaced !== 'boolean' ||
        !has(info.discovery, 'cluster') || typeof info.discovery.cluster !== 'boolean'))) {
      throw new CompareError('スナップショット内の収集対象が不正です。');
    }
  }
}

interface ComparisonRow {
  id: string;
  category: Category;
  paths: string[];
  reasons: string[];
  ignored_paths?: string[];
}

/** Write deterministic comparison files and return 0=same, 1=different, 2=incomplete. */
export function compareSnapshots(prod: Snapshot, stg: Snapshot, directory: string, rules: Rules, includeRuntime = false): number {
  validateSnapshot(prod);
  validateSnapshot(stg);
  if (prod.hmac_key_id !== stg.hmac_key_id) throw new CompareError('比較鍵が異なります。同じ鍵で採取し直してください。');
  if (prod.helm_values_policy !== stg.helm_values_policy) throw new CompareError('Helm valuesの秘匿化方式が異なります。');
  const left = prepare(prod, 'prod', rules, includeRuntime);
  const right = prepare(stg, 'stg', rules, includeRuntime);
  const rows: ComparisonRow[] = [];
  const counts: Record<Category, number> = { same: 0, different: 0, only_prod: 0, only_stg: 0, unknown: 0, ignored: 0 };
  for (const ident of [...new Set([...left.keys(), ...right.keys()])].sort()) {
    const a = left.get(ident), b = right.get(ident);
    const row: ComparisonRow = {
      id: ident, category: 'same', paths: [], reasons: [...new Set([...(a?.reasons ?? []), ...(b?.reasons ?? [])])].sort(),
    };
    const excluded = a?.excluded || b?.excluded;
    if (excluded) {
      row.category = 'ignored';
      row.reasons = [excluded];
    } else if (!a || !b) {
      const exists = a ?? b!;
      row.category = counterpartKnown(a ? stg : prod, exists.entry) ? (a ? 'only_prod' : 'only_stg') : 'unknown';
    } else {
      row.paths = diffPaths(a.object, b.object);
      row.category = row.paths.length ? 'different' : 'same';
      const paths = new Set(row.paths);
      const suppressed = diffPaths(a.before, b.before).filter(path => !paths.has(path)).sort();
      if (suppressed.length) {
        row.ignored_paths = [...new Set(suppressed)];
        if (!row.paths.length) row.category = 'ignored';
      }
    }
    counts[row.category]++;
    rows.push(row);
    if (!excluded) {
      for (const [side, prepared] of [['prod', a], ['stg', b]] as const) {
        if (prepared) {
          writeJson(objectFile(join(directory, 'normalized', side), ident), prepared.object);
          extractConfigmap(join(directory, 'configmap-files', side), ident, prepared.object);
        }
      }
    }
  }
  const choicesMatch = JSON.stringify(Object.keys(prod.sources).sort()) === JSON.stringify(Object.keys(stg.sources).sort());
  // User ignore rules must never turn collection errors into a complete comparison.
  let complete = prod.complete && stg.complete && !counts.unknown && choicesMatch &&
    prod.errors.length === 0 && stg.errors.length === 0 &&
    ![...prod.coverage, ...stg.coverage].some(record => record.state === 'failed');
  const apiRows: { source: string; resource: string; category: Category }[] = [];
  function coverageIndex(snapshot: Snapshot): Map<string, Coverage> {
    const index = new Map<string, Coverage>();
    for (const record of snapshot.coverage) {
      if (!record.resource.startsWith('@')) index.set(JSON.stringify([record.source, record.resource]), record);
    }
    return index;
  }
  const pc = coverageIndex(prod), sc = coverageIndex(stg);
  for (const key of [...new Set([...pc.keys(), ...sc.keys()])].sort()) {
    const [source, resource] = JSON.parse(key) as [string, string];
    if (source === 'nodes') continue;
    const x = pc.get(key), y = sc.get(key);
    if (!x || !y) {
      const present = (x ?? y)!;
      const known = counterpartKnown(x ? stg : prod, { source, resource, namespaced: present.namespaced ?? true });
      apiRows.push({ source, resource, category: known ? (x ? 'only_prod' : 'only_stg') : 'unknown' });
      if (!known) complete = false;
    }
  }
  const report = {
    schema_version: SCHEMA, created_at: now(), complete, summary: counts, comparisons: rows, api_differences: apiRows,
    coverage: { prod: prod.coverage, stg: stg.coverage }, errors: { prod: prod.errors, stg: stg.errors },
    rules, collection_choices_match: choicesMatch,
    limits: [
      'Not an atomic cluster snapshot; no PV data or external-store contents.',
      'Secret values protected; other resources and plaintext opt-ins may contain credentials.',
      'No arbitrary YAML parse of embedded ConfigMap files; exact string/byte comparison.',
    ],
  };
  writeJson(join(directory, 'report.json'), report);
  writeJson(join(directory, 'rules.applied.json'), rules);
  const lines = [
    '# Kubernetes / Rancher 比較結果', '',
    `取得完了: ${complete ? 'はい' : 'いいえ（差分なしとは判定できません）'}`, '',
    '| 判定 | 件数 |', '|---|---:|',
    ...Object.entries(counts).map(([category, count]) => `| ${category} | ${count} |`), '',
    'Secret値・差分前後の値はこのレポートには表示しません。詳細は保護されたnormalizedを参照してください。', '',
    '| オブジェクト | 判定 | 変更パス / 除外理由 |', '|---|---|---|',
  ];
  for (const row of rows) {
    if (row.category !== 'same') lines.push(`| ${mdText(row.id)} | ${row.category} | ${mdText((row.paths.length ? row.paths : row.reasons).join(', '))} |`);
  }
  lines.push('', '## API種別・取得エラー', '');
  for (const row of apiRows) lines.push(`- ${mdText(`${row.source}/${row.resource}: ${row.category}`)}`);
  for (const [side, snapshot] of [['prod', prod], ['stg', stg]] as const) {
    for (const error of snapshot.errors) lines.push(`- ${mdText(`${side}: ${error.source}/${error.resource} ${error.error ?? 'failed'}`)}`);
  }
  if (!choicesMatch) lines.push('- 収集対象レイヤーが両環境で一致しません。');
  writeFileSync(join(directory, 'report.md'), `${lines.join('\n')}\n`, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
  return !complete ? 2 : counts.different + counts.only_prod + counts.only_stg > 0 || apiRows.length > 0 ? 1 : 0;
}

// -----------------------------------------------------------------------------
// cli
// -----------------------------------------------------------------------------
const HELP = `Kubernetes / Rancher configuration comparison v${VERSION}
Usage: node k8s_rancher_compare.ts <command> [options]

  run       --prod-context NAME --stg-context NAME --out NEW_DIRECTORY
  snapshot  --context NAME --key-file KEY --out NEW_DIRECTORY [--side prod|stg]
  compare   --prod SNAPSHOT_DIRECTORY --stg SNAPSHOT_DIRECTORY --out NEW_DIRECTORY
  keygen    --out KEY_FILE

Collection options (run / snapshot):
  --kubeconfig FILE          Existing kubeconfig (never copied into output)
  --timeout SECONDS          Per-command timeout, default 60 (range 1..3600)
  --helm                    Include Helm values and manifest/hooks HMAC
  --helm-values-plain        Explicit opt-in to plaintext Helm values
  --node-files JSON          Optional SSH node-file selections (remote Node.js)
  --key-file KEY             Reusable private 32-byte key; run defaults to ephemeral key
  --prod-management-context  / --stg-management-context (run; provide both)
  --management-context NAME (snapshot)

Comparison options (run / compare):
  --rules JSON              Namespace mapping, selectors and explicit ignore rules
  --include-runtime         Include generated runtime objects in configuration view

Exit: 0 = complete/equal; 1 = complete/differences; 2 = incomplete/error
Node.js >=24.12 required; no npm dependencies, build, or package.json needed.

Examples:
  node k8s_rancher_compare.ts run --prod-context prod --stg-context stg --helm --out result
  node k8s_rancher_compare.ts keygen --out comparison.key
  node k8s_rancher_compare.ts snapshot --side prod --context prod --key-file comparison.key --out snapshot-prod
  node k8s_rancher_compare.ts snapshot --side stg --context stg --key-file comparison.key --out snapshot-stg
  node k8s_rancher_compare.ts compare --prod snapshot-prod --stg snapshot-stg --out compared

For separate Rancher management clusters, add both management-context options.
Secret values are HMACed before saving; other resources may contain plaintext
credentials. Treat the output as confidential. Read report.md / report.json.
Snapshots remain schema 2, compatible with the modular TypeScript version.
`;

const commonCollect = ['out', 'kubeconfig', 'timeout', 'helm', 'helm-values-plain', 'node-files', 'key-file'];
const allowed: Record<string, string[]> = {
  run: [...commonCollect, 'prod-context', 'stg-context', 'prod-management-context', 'stg-management-context', 'rules', 'include-runtime'],
  snapshot: [...commonCollect, 'context', 'management-context', 'side'],
  compare: ['prod', 'stg', 'out', 'rules', 'include-runtime'],
  keygen: ['out'],
};
const booleanOptions = new Set(['helm', 'helm-values-plain', 'include-runtime', 'help', 'version']);

function collect(options: CollectionOptions, context: string, management: string | undefined,
  directory: string, key: Buffer, side: Side): Snapshot {
  const snapshot = createSnapshot(options, key);
  console.log(`Collecting ${side}: workload`);
  collectCluster(snapshot, options, key, context, 'workload');
  if (management) {
    console.log(`Collecting ${side}: management`);
    collectCluster(snapshot, options, key, management, 'management');
  }
  if (options.nodeFiles) collectNodes(snapshot, readJson(options.nodeFiles), side, key, options.timeout);
  return finishSnapshot(snapshot, directory);
}

function main(): number {
  const [major, minor] = process.versions.node.split('.').map(Number);
  if ((major ?? 0) < 24 || (major === 24 && (minor ?? 0) < 12)) throw new CompareError('Node.js 24.12以上を使用してください。');
  process.umask(0o077);
  const args = process.argv.slice(2);
  if (!args.length || args[0] === '--help' || args[0] === '-h') { console.log(HELP); return 0; }
  if (args[0] === '--version') { console.log(VERSION); return 0; }
  const command = args.shift()!;
  if (!Object.hasOwn(allowed, command)) throw new CompareError('未知のサブコマンドです。--helpを参照してください。');
  const options = Object.fromEntries([...allowed[command]!, 'help'].map(name => [name,
    {type: booleanOptions.has(name) ? 'boolean' as const : 'string' as const, ...(name === 'help' ? {short: 'h'} : {})}]));
  let values: Record<string, string | boolean | undefined>;
  try {
    const parsed = parseArgs({args, options, strict: true, allowPositionals: false, tokens: true});
    // Reject duplicate options rather than silently allowing accidental context changes.
    const names = parsed.tokens.filter(t => t.kind === 'option').map(t => t.name);
    if (new Set(names).size !== names.length) throw new CompareError('同じオプションを複数回指定できません。');
    values = parsed.values as Record<string, string | boolean | undefined>;
  } catch (e) {
    if (e instanceof CompareError) throw e;
    throw new CompareError('コマンド引数が不正です。--helpを参照してください。');
  }
  if (values.help) { console.log(HELP); return 0; }
  const get = (name: string): string | undefined => typeof values[name] === 'string' ? values[name] as string : undefined;
  const required = (name: string): string => {
    const value = get(name);
    if (!value || value.startsWith('--')) throw new CompareError('--' + name + 'が必要です。');
    return value;
  };
  if (command === 'keygen') {
    const target = required('out');
    try { fs.writeFileSync(target, randomBytes(32), {flag: 'wx', mode: 0o600}); }
    catch { throw new CompareError('鍵を新規作成できません。既存ファイルは上書きしません。'); }
    console.log('Comparison key created (32 bytes, private).');
    return 0;
  }
  let code: number;
  if (command === 'compare') {
    const rules = loadRules(get('rules'));
    const prod = readJson(path.join(required('prod'), 'snapshot.json'));
    const stg = readJson(path.join(required('stg'), 'snapshot.json'));
    code = compareSnapshots(prod, stg, newDir(required('out')), rules, Boolean(values['include-runtime']));
  } else {
    const timeout = Number(get('timeout') ?? '60');
    if (!Number.isInteger(timeout) || timeout < 1 || timeout > 3600) throw new CompareError('timeoutは1〜3600秒の整数で指定してください。');
    const collectOptions: CollectionOptions = {kubeconfig: get('kubeconfig'), timeout,
      helm: Boolean(values.helm), helmValuesPlain: Boolean(values['helm-values-plain']), nodeFiles: get('node-files')};
    if (collectOptions.helmValuesPlain && !collectOptions.helm) throw new CompareError('--helm-values-plainには--helmが必要です。');
    requireExecutable('kubectl');
    if (collectOptions.helm) requireExecutable('helm');
    if (command === 'snapshot') {
      const context = required('context');
      const key = loadKey(required('key-file'));
      const side = get('side') ?? 'prod';
      if (side !== 'prod' && side !== 'stg') throw new CompareError('--sideはprodまたはstgです。');
      const snapshot = collect(collectOptions, context, get('management-context'), newDir(required('out')), key, side);
      code = snapshot.complete ? 0 : 2;
    } else {
      const prodContext = required('prod-context'), stgContext = required('stg-context');
      const prodManagement = get('prod-management-context'), stgManagement = get('stg-management-context');
      if (Boolean(prodManagement) !== Boolean(stgManagement)) throw new CompareError('管理用contextは両環境分を指定してください。');
      const rules = loadRules(get('rules'));
      const key = get('key-file') ? loadKey(get('key-file')!) : randomBytes(32);
      const out = newDir(required('out'));
      const prod = collect(collectOptions, prodContext, prodManagement, newDir(path.join(out, 'prod')), key, 'prod');
      const stg = collect(collectOptions, stgContext, stgManagement, newDir(path.join(out, 'stg')), key, 'stg');
      code = compareSnapshots(prod, stg, out, rules, Boolean(values['include-runtime']));
    }
  }
  console.log(`Finished: exit=${code} (0=equal, 1=differences, 2=incomplete/error)`);
  return code;
}

try { process.exitCode = main(); }
catch (error) {
  // No stack or local-data dump: a resource or auth plugin can contain credentials.
  console.error('ERROR: ' + (error instanceof CompareError ? error.message : 'unexpected error; no successful comparison produced'));
  process.exitCode = 2;
}