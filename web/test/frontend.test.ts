import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { parseAPIOrigin, parseSiteOrigin, contentSecurityPolicy, frontendHeaders, validatePageReferences } from '../frontend.mjs';
import { readFileSync } from 'node:fs';

test('the project footer link permits navigation without allowing external resources or other links', () => {
  const html = readFileSync(new URL('../index.html', import.meta.url), 'utf8');
  assert.doesNotThrow(() => validatePageReferences(html));
  for (const tag of [
    '<script src="https://nulliance.com/work/nullbin/"></script>',
    '<img src="https://nulliance.com/work/nullbin/">',
    '<link rel="stylesheet" href="https://nulliance.com/work/nullbin/">',
    '<a href="https://other.example/">Other</a>',
    '<img src="//other.example/image.png">',
  ]) assert.throws(() => validatePageReferences(html + tag), /another origin/);
  assert.throws(() => validatePageReferences(html.replace('rel="noopener noreferrer"', '')), /Project info link/);
});

test('static frontend API origin is explicit and rejects unsafe or ambiguous URLs', () => {
  assert.equal(parseAPIOrigin(''), '');
  assert.equal(parseAPIOrigin('https://api.example.com/'), 'https://api.example.com');
  // Characters a URL allows in a host name but that could act as
  // replacement patterns or end an attribute are refused.
  for (const bad of ["https://foo$&bar.example", "https://foo$'bar.example", 'https://foo`bar.example']) {
    assert.throws(() => parseAPIOrigin(bad), bad);
    assert.throws(() => parseSiteOrigin(bad), bad);
  }
  assert.equal(parseAPIOrigin('https://api-2.example.com:8443'), 'https://api-2.example.com:8443');
  assert.equal(parseAPIOrigin('https://api.example.com:8443'), 'https://api.example.com:8443');
  assert.throws(() => parseAPIOrigin('http://127.0.0.1:8000'), Error, 'plain HTTP only when the tests ask for it');
  process.env.NULLBIN_LOCAL_TEST_HTTP = '1';
  try {
    assert.equal(parseAPIOrigin('http://127.0.0.1:8000'), 'http://127.0.0.1:8000');
    assert.throws(() => parseAPIOrigin('http://api.example.com'), Error);
  } finally {
    delete process.env.NULLBIN_LOCAL_TEST_HTTP;
  }
  for (const value of ['*', '//api.example.com', 'http://api.example.com', 'https://u:p@api.example.com', 'https://api.example.com/api', 'https://api.example.com?x', 'https://api.example.com#x', 'https://api.example.com\n', 'https://API.example.com', 'https://api.example.com:443']) {
    assert.throws(() => parseAPIOrigin(value), Error, value);
  }
});

test('a build with a plain-HTTP API origin never writes web/dist or the embedded frontend', () => {
  const root = fileURLToPath(new URL('../..', import.meta.url));
  const env = { ...process.env, NULLBIN_LOCAL_TEST_HTTP: '1', NULLBIN_API_ORIGIN: 'http://127.0.0.1:8000' };
  // Each of these stops before anything is built or written.
  for (const args of [[], ['--frontend-only'], ['--frontend-only', '--out-dir=web/dist-test'], ['--frontend-only', `--out-dir=${root}`]]) {
    const run = spawnSync(process.execPath, ['web/build.mjs', ...args], { cwd: root, env, encoding: 'utf8' });
    assert.equal(run.status, 1, args.join(' '));
    assert.match(run.stderr, /for the browser tests only/);
  }
});

test('the site address for link previews is checked as strictly as the API address', () => {
  assert.equal(parseSiteOrigin(''), '');
  assert.equal(parseSiteOrigin('https://paste.example.com/'), 'https://paste.example.com');
  for (const value of ['http://paste.example.com', 'https://paste.example.com/x', 'https://paste.example.com"><script>', 'https://PASTE.example.com', 'javascript:alert(1)']) {
    assert.throws(() => parseSiteOrigin(value), Error, value);
  }
});

test('static frontend CSP grants only its own assets and its fixed API connection', () => {
  const api = parseAPIOrigin('https://api.example.com');
  const csp = contentSecurityPolicy(api);
  assert.ok(csp.includes("connect-src 'self' https://api.example.com;"));
  assert.ok(csp.includes("script-src 'self' 'wasm-unsafe-eval';"));
  assert.ok(!csp.includes("script-src 'self' https://api.example.com"));
  const h = frontendHeaders(api);
  assert.equal(h['Content-Security-Policy'], csp);
  assert.equal(h['Referrer-Policy'], 'no-referrer');
  assert.equal(h['X-Content-Type-Options'], 'nosniff');
  assert.equal(h['Cross-Origin-Resource-Policy'], 'same-origin');
});
