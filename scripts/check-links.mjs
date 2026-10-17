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

if (failures.length > 0) {
  for (const failure of failures) console.error(failure);
  console.error(`\n${failures.length} broken link(s) across ${pages.length} pages`);
  process.exit(1);
}
console.log(`Link check passed: ${pages.length} pages, no broken internal links or anchors`);
