#!/usr/bin/env node
// Checks relative links, site-root links, and heading anchors across the docs
// site. External URLs are out of scope: they need the network and rot for
// reasons this repo cannot fix.
import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const skipDirectories = new Set(['.git', '.github', 'node_modules']);
const pageExtensions = new Set(['.md', '.mdx']);

function walk(directory) {
  const entries = [];
  for (const name of readdirSync(directory).sort()) {
    if (skipDirectories.has(name)) continue;
    const absolute = join(directory, name);
    if (statSync(absolute).isDirectory()) entries.push(...walk(absolute));
    else entries.push(absolute);
  }
  return entries;
}

const allFiles = walk(root);
const pages = allFiles.filter((file) => pageExtensions.has(file.slice(file.lastIndexOf('.'))));
const pageSet = new Set(pages.map((file) => relative(root, file)));

function headings(page) {
  const anchors = new Set();
  let inFence = false;
  for (const line of readFileSync(page, 'utf8').split('\n')) {
    if (/^\s*```/.test(line)) inFence = !inFence;
    if (inFence) continue;
    const match = /^(#{1,6})\s+(.*)$/.exec(line);
    if (!match) continue;
    const text = match[2]
      .replace(/[`*_~]/g, '')
      .replace(/\[([^\]]*)\]\([^)]*\)/g, '$1')
      .replace(/<[^>]+>/g, '')
      .trim()
      .toLowerCase()
      .replace(/[^\p{L}\p{N}\s-]/gu, '')
      .replace(/\s+/g, '-');
    anchors.add(text);
  }
  return anchors;
}

const headingCache = new Map();
function anchorsFor(page) {
  if (!headingCache.has(page)) headingCache.set(page, headings(page));
  return headingCache.get(page);
}

function resolvePage(page, pathname) {
  if (pathname.startsWith('/')) {
    const route = pathname.replace(/^\/+/, '');
    const candidates = route === ''
      ? ['index.mdx', 'index.md']
      : [route, `${route}.mdx`, `${route}.md`, `${route}/index.mdx`, `${route}/index.md`];
    for (const candidate of candidates) {
      if (pageSet.has(candidate)) return candidate;
    }
    return null;
  }
  const relativePath = relative(root, resolve(root, dirname(page), pathname));
  const candidates = [
    relativePath,
    `${relativePath}.mdx`,
    `${relativePath}.md`,
    `${relativePath}/index.mdx`,
    `${relativePath}/index.md`,
  ];
  for (const candidate of candidates) {
    if (pageSet.has(candidate)) return candidate;
  }
  return null;
}

const failures = [];
const linkPattern = /!?\[[^\]]*\]\(([^)\s]+)(?:\s+"[^"]*")?\)/g;
const hrefPattern = /\bhref=["']([^"']+)["']/g;

function checkTarget(page, lineNumber, rawTarget) {
  let target = rawTarget.trim();
  if (target === '' || target.startsWith('<')) return;
  if (/^(https?:|mailto:|tel:)/i.test(target)) return;
  if (target.includes('{') || target.includes('}')) return;
  target = target.replace(/^<|>$/g, '');
  const hashIndex = target.indexOf('#');
  const fragment = hashIndex === -1 ? '' : target.slice(hashIndex + 1);
  const withoutHash = hashIndex === -1 ? target : target.slice(0, hashIndex);
  const queryIndex = withoutHash.indexOf('?');
  const pathname = queryIndex === -1 ? withoutHash : withoutHash.slice(0, queryIndex);

  if (pathname === '') {
    if (fragment !== '' && !anchorsFor(page).has(fragment)) {
      failures.push(`${relative(root, page)}:${lineNumber} missing anchor #${fragment}`);
    }
    return;
  }

  let decoded;
  try {
    decoded = decodeURIComponent(pathname);
  } catch {
    failures.push(`${relative(root, page)}:${lineNumber} invalid encoding in ${pathname}`);
    return;
  }

  const resolvedPage = resolvePage(page, decoded);
  if (resolvedPage === null) {
    const assetPath = relative(root, resolve(root, decoded.replace(/^\/+/, '')));
    if (existsSync(join(root, assetPath))) return;
    failures.push(`${relative(root, page)}:${lineNumber} missing target ${rawTarget}`);
    return;
  }
  if (fragment !== '' && !anchorsFor(resolvedPage).has(fragment)) {
    failures.push(
      `${relative(root, page)}:${lineNumber} missing anchor #${fragment} in ${resolvedPage}`,
    );
  }
}

for (const page of pages) {
  let inFence = false;
  const lines = readFileSync(page, 'utf8').split('\n');
  for (const [index, line] of lines.entries()) {
    if (/^\s*```/.test(line)) inFence = !inFence;
    if (inFence) continue;
    for (const match of line.matchAll(linkPattern)) checkTarget(page, index + 1, match[1]);
    for (const match of line.matchAll(hrefPattern)) checkTarget(page, index + 1, match[1]);
  }
}

// The sidebar is a second set of links: a page key in docs.json with no file
// behind it is a 404 that no markdown link points at.
function collectPageKeys(node, keys = []) {
  if (!node || typeof node !== 'object') return keys;
  if (typeof node.page === 'string') keys.push(node.page);
  if (Array.isArray(node.pages)) {
    for (const item of node.pages) {
      if (typeof item === 'string') keys.push(item);
      else collectPageKeys(item, keys);
    }
  }
  for (const key of ['groups', 'tabs', 'anchors', 'dropdowns', 'versions', 'languages']) {
    if (Array.isArray(node[key])) node[key].forEach((child) => collectPageKeys(child, keys));
  }
  return keys;
}

const configPath = join(root, 'docs.json');
if (existsSync(configPath)) {
  let config = null;
  try {
    config = JSON.parse(readFileSync(configPath, 'utf8'));
  } catch (error) {
    failures.push(`docs.json is not valid JSON: ${error.message}`);
  }
  if (config !== null) {
    const keys = new Set(collectPageKeys(config.navigation ?? {}));
    for (const key of keys) {
      if (resolvePage(join(root, 'index.mdx'), `/${key}`) === null) {
        failures.push(`docs.json lists ${key}, which has no page file`);
      }
    }
    for (const redirect of Array.isArray(config.redirects) ? config.redirects : []) {
      if (typeof redirect?.destination !== 'string') continue;
      if (resolvePage(join(root, 'index.mdx'), redirect.destination) === null) {
        failures.push(`docs.json redirect ${redirect.source ?? '(no source)'} points at ${redirect.destination}, which has no page file`);
      }
    }
  }
}

if (failures.length > 0) {
  for (const failure of failures) console.error(failure);
  console.error(`\n${failures.length} broken link(s) across ${pages.length} pages`);
  process.exit(1);
}
console.log(`Link check passed: ${pages.length} pages plus the docs.json navigation, no broken targets`);
