'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {
  normalizeRepo, validateScope, scopeKey, safePullRequestUrl, countChangedLines,
  validateListing, validateProposalResponse, mountRefactor
} = require('../public/assets/refactor.js');

const html = fs.readFileSync(path.join(__dirname, '../public/index.html'), 'utf8');
const scope = {
  repo: 'acme/buzz', files: ['src/a.js'], context_files: ['tests/a.js'],
  rules: '# Preserve behavior', max_files: 3, max_changed_lines: 100, consent: true
};
const listing = {
  repo: 'acme/buzz', branch: 'main', commit_sha: 'base-commit', rules: '# Repository rules', truncated: false,
  files: [
    { path: 'src/a.js', size: 50 }, { path: 'src/b.js', size: 60 },
    { path: 'tests/a.js', size: 70 }, { path: 'tests/b.js', size: 80 },
    { path: 'tests/c.js', size: 90 }, { path: 'tests/d.js', size: 100 }
  ]
};
function proposalResponse(overrides = {}) {
  return {
    repo: 'acme/buzz', branch: 'main', commit_sha: 'review-commit', review_token: 'review-only',
    proposal: { summary: 'Simplify a guard', rule: 'Preserve behavior', tradeoffs: 'Review callers', edits: [{ path: 'src/a.js', content: 'new\n' }] },
    originals: [{ path: 'src/a.js', content: 'old\n' }], changed_lines: 2, validation: 'unverified',
    ...overrides
  };
}

test('normalizes the existing repository input without accepting foreign URLs', () => {
  for (const value of ['acme/buzz', ' https://github.com/acme/buzz.git ', 'github.com/acme/buzz/', '/acme/buzz/']) {
    assert.equal(normalizeRepo(value), 'acme/buzz');
  }
  for (const value of ['', 'acme', 'acme/buzz/issues', 'https://evil.test/acme/buzz', 'acme/..', 'acme/buzz?token=x']) {
    assert.equal(normalizeRepo(value), '');
  }
});

test('bounds scope and keeps read-only context disjoint', () => {
  assert.equal(validateScope(scope), scope);
  for (const max_files of [0, 6, 1.5, NaN]) assert.throws(() => validateScope({ ...scope, max_files }));
  for (const max_changed_lines of [0, 501, 1.5, NaN]) assert.throws(() => validateScope({ ...scope, max_changed_lines }));
  assert.throws(() => validateScope({ ...scope, files: [] }));
  assert.throws(() => validateScope({ ...scope, files: ['a', 'b'], max_files: 1 }));
  assert.throws(() => validateScope({ ...scope, context_files: ['a', 'b', 'c', 'd'] }));
  assert.throws(() => validateScope({ ...scope, context_files: ['src/a.js'] }));
  assert.throws(() => validateScope({ ...scope, files: ['src/a.js', 'src/a.js'] }));
});

test('scope keys invalidate repo, rules, scope, selection and consent but not feedback', () => {
  for (const change of [
    { repo: 'acme/other' }, { rules: '# New rules' }, { files: ['src/b.js'] },
    { context_files: [] }, { max_files: 4 }, { max_changed_lines: 99 }, { consent: false }
  ]) assert.notEqual(scopeKey(scope), scopeKey({ ...scope, ...change }));
  assert.equal(scopeKey(scope), scopeKey({ ...scope, feedback: 'Try again', replacement: 'edited' }));
  assert.equal(scopeKey({ ...scope, files: ['b', 'a'] }), scopeKey({ ...scope, files: ['a', 'b'] }));
});

test('only HTTPS GitHub pull request links are allowed', () => {
  assert.equal(safePullRequestUrl('https://github.com/acme/buzz/pull/12'), 'https://github.com/acme/buzz/pull/12');
  for (const url of [
    'javascript:alert(1)', 'http://github.com/acme/buzz/pull/1', '//github.com/acme/buzz/pull/1',
    'https://github.com.evil.test/acme/buzz/pull/1', 'https://github.com@evil.test/acme/buzz/pull/1',
    'https://user@github.com/acme/buzz/pull/1', 'https://github.com:444/acme/buzz/pull/1',
    'https://github.com/login', 'https://github.com/acme/buzz/pull/0', null
  ]) assert.equal(safePullRequestUrl(url), null);
});

test('counts inserted and deleted lines, including newline-only edits, with a bound', () => {
  assert.equal(countChangedLines('same\n', 'same\n', 100), 0);
  assert.equal(countChangedLines('', 'a\nb\n', 100), 2);
  assert.equal(countChangedLines('a\nb\n', '', 100), 2);
  assert.equal(countChangedLines('a\nb\nc\n', 'a\nx\nc\n', 100), 2);
  assert.equal(countChangedLines('a\nb\nc\n', 'a\nc\n', 100), 1);
  assert.equal(countChangedLines('a', 'a\n', 100), 2);
  assert.equal(countChangedLines('a\nb\nc\n', 'x\ny\nz\n', 2), 3);
  assert.equal(countChangedLines('a\n'.repeat(5000), 'b\n'.repeat(5000), 500), 501);
});

test('bounded line counts agree with a small exhaustive LCS reference', () => {
  const strings = ['', 'a\n', 'b\n', 'a\na\n', 'a\nb\n', 'b\na\n', 'b\nb\n', 'a\nb\na\n'];
  function distance(a, b) {
    const left = a.match(/[^\n]*\n|[^\n]+$/g) || [];
    const right = b.match(/[^\n]*\n|[^\n]+$/g) || [];
    const rows = Array.from({ length: left.length + 1 }, () => Array(right.length + 1).fill(0));
    for (let i = 1; i <= left.length; i += 1) {
      for (let j = 1; j <= right.length; j += 1) {
        rows[i][j] = left[i - 1] === right[j - 1] ? rows[i - 1][j - 1] + 1 : Math.max(rows[i - 1][j], rows[i][j - 1]);
      }
    }
    return left.length + right.length - 2 * rows[left.length][right.length];
  }
  for (const a of strings) for (const b of strings) for (const limit of [0, 1, 2, 10]) {
    assert.equal(countChangedLines(a, b, limit), Math.min(distance(a, b), limit + 1));
  }
});

test('rejects malformed listing and out-of-scope or unpaired proposal edits', () => {
  assert.equal(validateListing(listing, scope.repo).files.length, 6);
  assert.throws(() => validateListing({ ...listing, repo: 'acme/other' }, scope.repo));
  assert.throws(() => validateListing({ ...listing, files: [listing.files[0], listing.files[0]] }, scope.repo));
  assert.throws(() => validateListing({ ...listing, files: [{ path: 'src/a.js', size: -1 }] }, scope.repo));
  assert.equal(validateProposalResponse(proposalResponse(), scope).reviewToken, 'review-only');
  for (const overrides of [
    { validation: 'passed' }, { repo: 'acme/other' }, { review_token: '' }, { changed_lines: 101 },
    { originals: [] }, { originals: [{ path: 'src/a.js', content: 12 }] },
    { proposal: { ...proposalResponse().proposal, edits: [{ path: 'tests/a.js', content: 'bad' }] } },
    { proposal: { ...proposalResponse().proposal, edits: [{ path: 'src/a.js', content: 'a' }, { path: 'src/a.js', content: 'b' }] } }
  ]) assert.throws(() => validateProposalResponse(proposalResponse(overrides), scope));
});

// A minimal DOM fixture exercises the real controller without a browser dependency.
// innerHTML throws so any new unsafe rendering is caught by these integration tests.
class FakeElement {
  constructor(tagName = 'div') {
    this.tagName = tagName.toUpperCase();
    this.children = [];
    this.handlers = new Map();
    this.attributes = new Map();
    this.value = '';
    this.checked = false;
    this.disabled = false;
    this.hidden = false;
    this.text = '';
    this.classes = new Set();
    this.classList = { toggle: (name, force) => force ? this.classes.add(name) : this.classes.delete(name) };
  }
  set innerHTML(_) { throw new Error('Unsafe HTML rendering is forbidden'); }
  set textContent(value) { this.text = String(value); this.children = []; }
  get textContent() { return this.text + this.children.map(child => child.textContent).join(''); }
  appendChild(child) { this.children.push(child); return child; }
  replaceChildren(...children) { this.text = ''; this.children = children; }
  setAttribute(key, value) { this.attributes.set(key, String(value)); }
  addEventListener(type, handler) {
    if (!this.handlers.has(type)) this.handlers.set(type, []);
    this.handlers.get(type).push(handler);
  }
  dispatchEvent(event) {
    for (const handler of this.handlers.get(event.type) || []) handler.call(this, { target: this, ...event });
  }
  focus() { this.focused = true; }
}

function fixture() {
  const nodes = new Map();
  for (const match of html.matchAll(/<([a-z][a-z0-9]*)\b[^>]*\bid="([^"]+)"[^>]*>/gi)) {
    const node = new FakeElement(match[1]);
    node.id = match[2];
    node.value = (match[0].match(/\bvalue="([^"]*)"/) || [])[1] || '';
    node.disabled = /\sdisabled(?:\s|>|\/)/.test(match[0]);
    node.hidden = /\shidden(?:\s|>|\/)/.test(match[0]);
    nodes.set(node.id, node);
  }
  const win = new FakeElement();
  const document = new FakeElement();
  document.getElementById = id => nodes.get(id);
  document.createElement = tag => new FakeElement(tag);
  const storage = new Map([['buzz_gh_token', 'existing-token']]);
  const timers = new Map();
  const requests = [];
  let nextTimer = 0;
  win.document = document;
  win.sessionStorage = { getItem: key => storage.get(key) || null };
  win.AbortController = AbortController;
  win.setTimeout = (handler, delay) => { const id = ++nextTimer; timers.set(id, { handler, delay }); return id; };
  win.clearTimeout = id => timers.delete(id);
  win.fetch = (url, options) => new Promise((resolve, reject) => {
    requests.push({ url, options, resolve: (data, status = 200) => resolve({ ok: status >= 200 && status < 300, status, json: async () => data }), reject });
  });
  win.buzzGoToStep = step => { win.step = step; win.dispatchEvent({ type: 'buzz:step-change', detail: { step } }); };
  nodes.get('repo-input').value = 'acme/buzz';
  mountRefactor(win);
  return {
    win, nodes, storage, timers, requests,
    get: id => nodes.get('refactor-' + id),
    click: id => nodes.get('refactor-' + id).dispatchEvent({ type: 'click' }),
    input: (id, value) => { const node = nodes.get('refactor-' + id); node.value = value; node.dispatchEvent({ type: 'input' }); },
    check: (id, checked = true) => { const node = nodes.get('refactor-' + id); node.checked = checked; node.dispatchEvent({ type: 'change' }); },
    select: (kind, index, checked = true) => {
      const node = nodes.get('refactor-' + kind).children[index].children[0];
      node.checked = checked;
      node.dispatchEvent({ type: 'change' });
      return node;
    }
  };
}
const settle = () => new Promise(resolve => setImmediate(resolve));
async function ready(overrides = {}) {
  const view = fixture();
  view.win.buzzOpenRefactor();
  view.requests[0].resolve({ ...listing, ...overrides });
  await settle();
  return view;
}
async function generated(response = proposalResponse()) {
  const view = await ready();
  view.select('files', 0);
  view.check('consent');
  view.click('generate-btn');
  view.requests[1].resolve(response);
  await settle();
  return view;
}
function replacement(view) { return view.get('edits').children[0].children[1].children[1].children[1]; }

test('step 5 lives in Buzz with the existing repo picker and pinned Supabase script', () => {
  assert.ok(html.indexOf('id="refactor-open-btn"') > html.indexOf('id="analyze-form"'));
  assert.ok(html.indexOf('id="wizard-step-5"') < html.indexOf('</main>'));
  assert.match(html, /\[1, 2, 3, 4, 5\]\.forEach/);
  assert.match(html, /src="\/assets\/refactor\.js" defer/);
  assert.match(html, /supabase-js@2\.45\.4\/dist\/umd\/supabase\.min\.js" integrity="sha384-GFr3yTh5lJznCbZfpTtXnwboFsxqtTQoeTZCRHhE0579KrRmlCzen5AA8ohaB5ug" crossorigin/);
  assert.match(html, /CustomEvent\('buzz:auth-change'\)/);
  assert.equal((html.match(/id="repo-input"/g) || []).length, 1);
});

test('server-protected files remain selectable only as read-only context', async () => {
  const view = await ready({ files: [{ path: 'src/a.js', size: 50, editable: true }, { path: 'package.json', size: 100, editable: false }] });
  assert.equal(view.get('files').children[1].children[0].disabled, true);
  const blocked = view.select('files', 1);
  assert.equal(blocked.checked, false);
  const context = view.select('context-files', 1);
  assert.equal(context.checked, true);
});

test('loads through existing session, applies defaults, and requires scope plus consent', async () => {
  const view = fixture();
  assert.equal(view.get('max-files').value, '3');
  assert.equal(view.get('max-lines').value, '100');
  view.win.buzzOpenRefactor();
  assert.equal(view.win.step, 5);
  assert.equal(view.requests[0].url, '/api/refactor?repo=acme%2Fbuzz');
  assert.equal(view.requests[0].options.headers['X-GitHub-Token'], 'existing-token');
  assert.equal(view.requests[0].options.cache, 'no-store');
  assert.equal(view.get('settings').disabled, true);
  assert.equal(Array.from(view.timers.values())[0].delay, 55000);
  view.requests[0].resolve(listing);
  await settle();
  assert.equal(view.get('rules').value, listing.rules);
  assert.equal(view.get('generate-btn').disabled, true);
  view.select('files', 0);
  assert.equal(view.get('generate-btn').disabled, true);
  view.select('context-files', 2);
  view.check('consent');
  assert.equal(view.get('generate-btn').disabled, false);
  view.click('generate-btn');
  const body = JSON.parse(view.requests[1].options.body);
  assert.deepEqual(body.files, ['src/a.js']);
  assert.deepEqual(body.context_files, ['tests/a.js']);
  assert.equal(body.consent, true);
  assert.equal(body.max_files, 3);
  assert.equal(body.max_changed_lines, 100);
  assert.equal(body.action, 'propose');
});

test('renders untrusted rules, metadata, originals and replacements only as text', async () => {
  const hostile = '<img src=x onerror=alert(1)></textarea><script>alert(2)</script>';
  const response = proposalResponse({
    proposal: { summary: hostile, rule: hostile, tradeoffs: hostile, edits: [{ path: 'src/a.js', content: hostile }] },
    originals: [{ path: 'src/a.js', content: hostile + '\noriginal' }]
  });
  const view = await generated(response);
  assert.equal(view.get('summary').textContent, hostile);
  assert.equal(view.get('rule').textContent, hostile);
  assert.equal(view.get('tradeoffs').textContent, hostile);
  assert.equal(replacement(view).value, hostile);
  const original = view.get('edits').children[0].children[1].children[0].children[1];
  assert.equal(original.textContent, hostile + '\noriginal');
  assert.equal(view.get('publish-btn').disabled, true);
  assert.equal(view.get('review').hidden, false);
});

test('replacement editing preserves the proposal, resets approval, and publishes the edited payload', async () => {
  const view = await generated();
  view.check('approve');
  assert.equal(view.get('publish-btn').disabled, false);
  const editor = replacement(view);
  editor.value = 'reviewed\n';
  editor.dispatchEvent({ type: 'input' });
  assert.equal(view.get('approve').checked, false);
  assert.equal(view.get('review').hidden, false);
  assert.equal(view.get('publish-btn').disabled, true);
  assert.match(view.get('changed-lines').textContent, /2 changed lines.*local estimate/);
  view.check('approve');
  view.click('publish-btn');
  assert.deepEqual(JSON.parse(view.requests[2].options.body), {
    action: 'publish', review_token: 'review-only', approved: true,
    proposal: { summary: 'Simplify a guard', rule: 'Preserve behavior', tradeoffs: 'Review callers', edits: [{ path: 'src/a.js', content: 'reviewed\n' }] }
  });
  assert.equal(editor.disabled, true);
  view.requests[2].resolve({ url: 'https://github.com/acme/buzz/pull/10', branch: 'refactor/review', draft: true, validation: 'unverified' });
  await settle();
  assert.equal(view.get('publish-controls').hidden, true);
  assert.equal(view.get('published').children[1].href, 'https://github.com/acme/buzz/pull/10');
  assert.equal(view.get('published').children[1].rel, 'noopener noreferrer');
  view.check('approve');
  view.click('publish-btn');
  assert.equal(view.requests.length, 3, 'a successful review token cannot be used again');
});

test('all scope changes invalidate review; feedback remains editable for regeneration', async () => {
  for (const id of ['rules', 'max-files', 'max-lines']) {
    const view = await generated();
    view.check('approve');
    view.input(id, id === 'rules' ? '# Changed rules' : '2');
    assert.equal(view.get('review').hidden, true, id);
    assert.equal(view.get('edits').children.length, 0, id);
    assert.equal(view.get('publish-btn').disabled, true, id);
  }
  const view = await generated();
  view.check('approve');
  view.input('feedback', 'Avoid the helper');
  assert.equal(view.get('review').hidden, false);
  assert.equal(view.get('approve').checked, false);
  view.click('regenerate-btn');
  assert.equal(JSON.parse(view.requests[2].options.body).feedback, 'Avoid the helper');
  assert.equal(view.get('review').hidden, true);
});

test('changing editable/context selection clears proposal and requires renewed consent', async () => {
  for (const kind of ['files', 'context-files']) {
    const view = await generated();
    view.select(kind, 1);
    assert.equal(view.get('review').hidden, true);
    assert.equal(view.get('consent').checked, false);
    assert.equal(view.get('generate-btn').disabled, true);
  }
});

test('caps optional read-only context at three and disallows selecting it for edits', async () => {
  const view = await ready();
  view.select('context-files', 2);
  view.select('context-files', 3);
  view.select('context-files', 4);
  assert.equal(view.get('context-files').children[5].children[0].disabled, true);
  assert.equal(view.get('files').children[2].children[0].disabled, true);
  const extra = view.select('context-files', 5);
  assert.equal(extra.checked, false);
  assert.match(view.get('context-count').textContent, /^3 \/ 3/);
});

test('repo or auth changes erase source and ignore late requests', async () => {
  for (const change of ['repo', 'auth']) {
    const view = await generated();
    view.click('regenerate-btn');
    if (change === 'repo') {
      view.nodes.get('repo-input').value = 'acme/other';
      view.nodes.get('repo-input').dispatchEvent({ type: 'input' });
    } else {
      view.storage.delete('buzz_gh_token');
      view.win.dispatchEvent({ type: 'buzz:auth-change' });
    }
    assert.equal(view.requests[2].options.signal.aborted, true);
    assert.equal(view.get('rules').value, '');
    assert.equal(view.get('feedback').value, '');
    assert.equal(view.get('files').children.length, 0);
    assert.equal(view.get('edits').children.length, 0);
    view.requests[2].resolve(proposalResponse());
    await settle();
    assert.equal(view.get('review').hidden, true);
  }
});

test('silently changed session token is checked again before action and response acceptance', async () => {
  const view = await generated();
  view.check('approve');
  view.storage.set('buzz_gh_token', 'replacement-token');
  view.click('publish-btn');
  assert.equal(view.requests.length, 2);
  assert.equal(view.get('review').hidden, true);
  view.click('load-btn');
  view.storage.delete('buzz_gh_token');
  view.requests[2].resolve(listing);
  await settle();
  assert.equal(view.get('files').children.length, 0);
  assert.equal(view.get('rules').value, '');
});

test('no-change proposals and locally reverted or oversized replacements cannot publish', async () => {
  const noChanges = await generated(proposalResponse({ proposal: { summary: 'Nothing worthwhile', rule: 'Keep behavior', tradeoffs: 'No change', edits: [] }, originals: [], changed_lines: 0 }));
  assert.equal(noChanges.get('no-changes').hidden, false);
  assert.equal(noChanges.get('publish-controls').hidden, true);
  noChanges.check('approve');
  noChanges.click('publish-btn');
  assert.equal(noChanges.requests.length, 2);
  const view = await generated();
  const editor = replacement(view);
  editor.value = 'old\n';
  editor.dispatchEvent({ type: 'input' });
  assert.equal(view.get('publish-controls').hidden, true);
  editor.value = 'new\n'.repeat(101);
  editor.dispatchEvent({ type: 'input' });
  assert.equal(view.get('approve').disabled, true);
  assert.match(view.get('changed-lines').textContent, /More than 100/);
  view.check('approve');
  view.click('publish-btn');
  assert.equal(view.requests.length, 2);
});

test('reject/reset and consent withdrawal clear proposal source memory', async () => {
  for (const action of ['reject', 'consent']) {
    const view = await generated();
    if (action === 'reject') view.click('reject-btn'); else view.check('consent', false);
    assert.equal(view.get('review').hidden, true);
    assert.equal(view.get('edits').children.length, 0);
    assert.equal(view.get('summary').textContent, '');
    assert.equal(view.get('publish-btn').disabled, true);
  }
});

test('timeout aborts at 55 seconds and HTTP errors use aria-live text', async () => {
  const view = fixture();
  view.win.buzzOpenRefactor();
  const timer = Array.from(view.timers.values())[0];
  assert.equal(timer.delay, 55000);
  timer.handler();
  assert.equal(view.requests[0].options.signal.aborted, true);
  view.requests[0].reject(new Error('aborted'));
  await settle();
  assert.match(view.get('status').textContent, /timed out after 55 seconds/);
  assert.equal(view.get('load-btn').disabled, false);
  view.click('load-btn');
  const error = '<img onerror=alert(1)> unavailable';
  view.requests[1].resolve({ error }, 500);
  await settle();
  assert.equal(view.get('status').textContent, error);
  assert.equal(view.get('status').classes.has('is-error'), true);
  assert.match(html, /id="refactor-status"[^>]*aria-live="polite"/);
});

test('invalid session responses clear source and an unsafe PR URL is never linked', async () => {
  const signedOut = await generated();
  signedOut.check('approve');
  signedOut.click('publish-btn');
  signedOut.requests[2].resolve({ error: 'Session expired' }, 401);
  await settle();
  assert.equal(signedOut.get('edits').children.length, 0);
  assert.equal(signedOut.get('rules').value, '');
  assert.match(signedOut.get('status').textContent, /existing GitHub login/);
  const view = await generated();
  view.check('approve');
  view.click('publish-btn');
  view.requests[2].resolve({ url: 'https://evil.test/pr', branch: 'refactor/review', draft: true, validation: 'unverified' });
  await settle();
  assert.equal(view.get('published').children.length, 0);
  assert.equal(view.get('approve').checked, false);
  assert.match(view.get('status').textContent, /No untrusted link/);
});

test('Back returns to step 2 and cancels in-flight work without accepting it later', async () => {
  const view = fixture();
  view.win.buzzOpenRefactor();
  view.click('back-btn');
  assert.equal(view.win.step, 2);
  assert.equal(view.requests[0].options.signal.aborted, true);
  view.requests[0].resolve(listing);
  await settle();
  assert.equal(view.get('files').children.length, 0);
  assert.equal(view.get('settings').disabled, false);
});

test('a stale-base rejection requires renewed approval and reports the backend error', async () => {
  const view = await generated();
  view.check('approve');
  view.click('publish-btn');
  view.requests[2].resolve({ error: 'The repository base is stale. Generate a new proposal.' }, 409);
  await settle();
  assert.equal(view.get('approve').checked, false);
  assert.equal(view.get('publish-btn').disabled, true);
  assert.match(view.get('status').textContent, /base is stale/);
  assert.match(view.get('status').textContent, /server rejected publishing/);
  assert.doesNotMatch(view.get('status').textContent, /may have completed/);
});

test('late responses cannot overwrite a newer repository load even after changing back', async () => {
  const view = fixture();
  view.win.buzzOpenRefactor();
  const repo = view.nodes.get('repo-input');
  repo.value = 'acme/other';
  repo.dispatchEvent({ type: 'input' });
  view.click('load-btn');
  repo.value = 'acme/buzz';
  repo.dispatchEvent({ type: 'input' });
  view.click('load-btn');
  view.requests[2].resolve({ ...listing, rules: '# Newest rules' });
  await settle();
  view.requests[0].resolve({ ...listing, rules: '# Old rules' });
  view.requests[1].resolve({ ...listing, repo: 'acme/other' });
  await settle();
  assert.equal(view.get('rules').value, '# Newest rules');
  assert.equal(view.get('repo').textContent, 'acme/buzz');
});

test('sign-out clears the existing token and broadcasts before awaiting Supabase', () => {
  const signOut = html.slice(html.indexOf('window.buzzSignOutGitHub ='), html.indexOf('window.buzzSelectRepo ='));
  assert.ok(signOut.indexOf("sessionStorage.removeItem('buzz_gh_token')") < signOut.indexOf('await supabaseClient.auth.signOut()'));
  assert.ok(signOut.indexOf('updateAuthBadge()') < signOut.indexOf('await supabaseClient.auth.signOut()'));
});

test('truncated lists are disclosed and custom Markdown rules survive a list reload', async () => {
  const view = await ready({ truncated: true, rules: null });
  assert.match(view.get('file-notice').textContent, /truncated/);
  assert.match(view.get('rules').value, /^# Refactor rules/);
  view.input('rules', '# My page-only rules');
  view.click('load-btn');
  view.requests[1].resolve(listing);
  await settle();
  assert.equal(view.get('rules').value, '# My page-only rules');
  view.win.dispatchEvent({ type: 'pagehide' });
  assert.equal(view.get('rules').value, '');
  assert.equal(view.get('files').children.length, 0);
});
