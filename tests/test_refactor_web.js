'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {
  normalizeRepo, validateScope, scopeKey, safePullRequestUrl, countChangedLines,
  validateListing, validateProposalResponse, suggestFiles, mountRefactor
} = require('../public/assets/refactor.js');

const html = fs.readFileSync(path.join(__dirname, '../public/index.html'), 'utf8');
const scope = {
  repo: 'acme/buzz', files: ['src/a.js'], context_files: ['tests/a.js'],
  rules: '# Preserve behavior', max_files: 1, max_changed_lines: 100, consent: true
};
const listing = {
  repo: 'acme/buzz', branch: 'main', commit_sha: 'base-commit', rules: '# Repository rules', truncated: false,
  files: [
    { path: 'src/a.js', size: 50, editable: true }, { path: 'src/b.js', size: 60, editable: true },
    { path: 'tests/a.js', size: 70, editable: false }, { path: 'tests/b.js', size: 80, editable: false },
    { path: 'tests/c.js', size: 90, editable: false }, { path: 'tests/d.js', size: 100, editable: false }
  ]
};
function proposalResponse(overrides = {}) {
  return {
    repo: 'acme/buzz', branch: 'main', commit_sha: 'review-commit', review_token: 'review-only',
    proposal: { summary: 'Simplify a guard', rule: 'Preserve behavior', tradeoffs: 'Review callers', edits: [{ path: 'src/a.js', content: 'new\n' }] },
    originals: [{ path: 'src/a.js', content: 'old\n' }], changed_lines: 2, validation: 'unverified', ...overrides
  };
}
const published = { url: 'https://github.com/acme/buzz/pull/10', branch: 'refactor/review', draft: true, validation: 'unverified' };

test('normalizes the existing repository input without accepting foreign URLs', () => {
  for (const value of ['acme/buzz', ' https://github.com/acme/buzz.git ', 'github.com/acme/buzz/', '/acme/buzz/']) assert.equal(normalizeRepo(value), 'acme/buzz');
  for (const value of ['', 'acme', 'acme/buzz/issues', 'https://evil.test/acme/buzz', 'acme/..', 'acme/buzz?token=x']) assert.equal(normalizeRepo(value), '');
});
test('bounds scope and keeps read-only context disjoint', () => {
  assert.equal(validateScope(scope), scope);
  for (const max_files of [0, 6, 1.5, NaN]) assert.throws(() => validateScope({ ...scope, max_files }));
  for (const max_changed_lines of [0, 501, 1.5, NaN]) assert.throws(() => validateScope({ ...scope, max_changed_lines }));
  for (const change of [{ files: [] }, { files: ['a', 'b'] }, { context_files: ['a', 'b', 'c', 'd'] }, { context_files: ['src/a.js'] }]) {
    assert.throws(() => validateScope({ ...scope, ...change }));
  }
});
test('scope keys include all publishing boundaries but not feedback', () => {
  for (const change of [{ repo: 'acme/other' }, { rules: '# New' }, { files: ['src/b.js'] }, { context_files: [] }, { max_files: 4 }, { max_changed_lines: 99 }, { consent: false }]) {
    assert.notEqual(scopeKey(scope), scopeKey({ ...scope, ...change }));
  }
  assert.equal(scopeKey(scope), scopeKey({ ...scope, feedback: 'Try again' }));
});
test('only HTTPS GitHub pull request links are allowed', () => {
  assert.equal(safePullRequestUrl(published.url), published.url);
  for (const url of ['javascript:alert(1)', 'http://github.com/acme/buzz/pull/1', '//github.com/acme/buzz/pull/1',
    'https://github.com.evil.test/acme/buzz/pull/1', 'https://github.com@evil.test/acme/buzz/pull/1',
    'https://user@github.com/acme/buzz/pull/1', 'https://github.com:444/acme/buzz/pull/1', 'https://github.com/login', null]) {
    assert.equal(safePullRequestUrl(url), null);
  }
});
test('bounded changed-line counts agree with a small exhaustive LCS reference', () => {
  const strings = ['', 'a', 'a\n', 'b\n', 'a\na\n', 'a\nb\n', 'b\na\n', 'b\nb\n', 'a\nb\na\n'];
  function distance(a, b) {
    const left = a.match(/[^\n]*\n|[^\n]+$/g) || [];
    const right = b.match(/[^\n]*\n|[^\n]+$/g) || [];
    const rows = Array.from({ length: left.length + 1 }, () => Array(right.length + 1).fill(0));
    for (let i = 1; i <= left.length; i += 1) for (let j = 1; j <= right.length; j += 1) {
      rows[i][j] = left[i - 1] === right[j - 1] ? rows[i - 1][j - 1] + 1 : Math.max(rows[i - 1][j], rows[i][j - 1]);
    }
    return left.length + right.length - 2 * rows[left.length][right.length];
  }
  for (const a of strings) for (const b of strings) for (const limit of [0, 1, 2, 10]) {
    assert.equal(countChangedLines(a, b, limit), Math.min(distance(a, b), limit + 1));
  }
  assert.equal(countChangedLines('a\n'.repeat(5000), 'b\n'.repeat(5000), 500), 501);
});
test('metadata suggestions are small, deterministic and never include protected files', () => {
  const files = [
    { path: 'AGENTS.md', size: 1200, editable: false }, { path: 'src/z.js', size: 2000, editable: true },
    { path: 'src/a.js', size: 1000, editable: true }, { path: 'src/large.js', size: 40001, editable: true },
    { path: 'src/empty.js', size: 0, editable: true }, { path: 'src/unknown.js', size: 1000 }
  ];
  assert.deepEqual(suggestFiles(files), ['src/a.js']);
  assert.deepEqual(suggestFiles(files.slice().reverse()), ['src/a.js']);
  assert.deepEqual(suggestFiles(files.filter(file => file.editable !== true)), []);
});
test('rejects malformed listings and unpaired or out-of-scope proposals', () => {
  assert.equal(validateListing(listing, scope.repo).files.length, 6);
  for (const change of [{ repo: 'acme/other' }, { files: [listing.files[0], listing.files[0]] }, { files: [{ path: 'src/a.js', size: 10 }] }]) {
    assert.throws(() => validateListing({ ...listing, ...change }, scope.repo));
  }
  assert.equal(validateProposalResponse(proposalResponse(), scope).reviewToken, 'review-only');
  for (const overrides of [{ validation: 'passed' }, { repo: 'acme/other' }, { review_token: '' }, { changed_lines: 101 },
    { originals: [] }, { originals: [{ path: 'src/a.js', content: 12 }] },
    { proposal: { ...proposalResponse().proposal, edits: [{ path: 'tests/a.js', content: 'bad' }] } }]) {
    assert.throws(() => validateProposalResponse(proposalResponse(overrides), scope));
  }
});

// Minimal dependency-free DOM fixture. Unsafe HTML rendering is always rejected.
class FakeElement {
  constructor(tagName = 'div') {
    this.tagName = tagName.toUpperCase(); this.children = []; this.handlers = new Map(); this.attributes = new Map();
    this.value = ''; this.checked = false; this.disabled = false; this.hidden = false; this.open = false; this.text = '';
    this.classes = new Set();
    this.classList = {
      toggle: (name, force) => force ? this.classes.add(name) : this.classes.delete(name),
      contains: name => this.classes.has(name)
    };
  }
  set innerHTML(_) { throw new Error('Unsafe HTML rendering is forbidden'); }
  set textContent(value) { this.text = String(value); this.children = []; }
  get textContent() { return this.text + this.children.map(child => child.textContent).join(''); }
  appendChild(child) { this.children.push(child); return child; }
  replaceChildren(...children) { this.text = ''; this.children = children; }
  setAttribute(key, value) { this.attributes.set(key, String(value)); }
  addEventListener(type, handler) { if (!this.handlers.has(type)) this.handlers.set(type, []); this.handlers.get(type).push(handler); }
  dispatchEvent(event) { for (const handler of this.handlers.get(event.type) || []) handler.call(this, { target: this, ...event }); }
  focus() { this.focused = true; }
}
function fixture(options = {}) {
  const nodes = new Map();
  for (const match of html.matchAll(/<([a-z][a-z0-9]*)\b[^>]*\bid="([^"]+)"[^>]*>/gi)) {
    const node = new FakeElement(match[1]); node.id = match[2];
    node.value = (match[0].match(/\bvalue="([^"]*)"/) || [])[1] || '';
    node.hidden = /\shidden(?:\s|>|\/)/.test(match[0]); nodes.set(node.id, node);
  }
  const win = new FakeElement(); const document = new FakeElement();
  document.getElementById = id => nodes.get(id); document.createElement = tag => new FakeElement(tag);
  const storage = options.storage || new Map([['buzz_gh_token', 'existing-token']]); const timers = new Map(); const requests = []; let nextTimer = 0;
  win.document = document;
  win.sessionStorage = { getItem: key => storage.get(key) || null, setItem: (key, value) => storage.set(key, value), removeItem: key => storage.delete(key) };
  win.AbortController = AbortController;
  win.setTimeout = (handler, delay) => { const id = ++nextTimer; timers.set(id, { handler, delay }); return id; };
  win.clearTimeout = id => timers.delete(id);
  win.fetch = (url, options) => new Promise((resolve, reject) => {
    requests.push({ url, options, resolve: (data, status = 200) => resolve({ ok: status >= 200 && status < 300, status, json: async () => data }), reject });
  });
  win.buzzGoToStep = step => {
    win.step = step;
    nodes.get('wizard-step-5').classList.toggle('active', step === 5);
    win.dispatchEvent({ type: 'buzz:step-change', detail: { step } });
  };
  nodes.get('repo-input').value = 'acme/buzz'; mountRefactor(win);
  return {
    win, nodes, storage, timers, requests, get: id => nodes.get('refactor-' + id),
    click: id => nodes.get('refactor-' + id).dispatchEvent({ type: 'click' }),
    input: (id, value) => { const node = nodes.get('refactor-' + id); node.value = value; node.dispatchEvent({ type: 'input' }); },
    select: (kind, index, checked = true) => { const node = nodes.get('refactor-' + kind).children[index].children[0]; node.checked = checked; node.dispatchEvent({ type: 'change' }); return node; }
  };
}
const settle = () => new Promise(resolve => setImmediate(resolve));
async function ready(overrides = {}) {
  const view = fixture(); view.win.buzzOpenRefactor(); view.requests[0].resolve({ ...listing, ...overrides }); await settle(); return view;
}
async function generated(response = proposalResponse()) {
  const view = await ready(); view.click('goal-next-btn'); view.click('generate-btn'); view.requests[1].resolve(response); await settle(); return view;
}
function afterColumn(view) { return view.get('edits').children[0].children[1].children[1]; }
function replacement(view) { return afterColumn(view).children[2]; }
function stage(view, name) {
  const stages = ['goal-stage', 'scope-stage', 'review', 'publish-stage', 'done-stage', 'working-stage'];
  assert.deepEqual(stages.filter(id => !view.get(id).hidden), [name]);
}

test('wizard reuses the repo/login and keeps custom inputs in collapsed optional controls', () => {
  assert.equal((html.match(/id="repo-input"/g) || []).length, 1);
  assert.match(html, /\[1, 2, 3, 4, 5\]\.forEach/);
  assert.match(html, /<details[^>]*id="refactor-advanced"/);
  assert.doesNotMatch(html, /id="refactor-(consent|approve)"/);
  const advanced = html.slice(html.indexOf('id="refactor-advanced"'), html.indexOf('</details>', html.indexOf('id="refactor-advanced"')));
  for (const id of ['rules', 'max-files', 'max-lines', 'files', 'context-files']) assert.ok(advanced.includes('id="refactor-' + id + '"'));
  const view = fixture(); stage(view, 'goal-stage'); assert.equal(view.get('advanced').open, false);
});
test('complete default wizard path requires clicks only and publishes only after final approval', async () => {
  const view = await ready(); stage(view, 'goal-stage');
  assert.equal(view.requests.length, 1, 'metadata load only');
  assert.equal(view.requests[0].options.headers['X-GitHub-Token'], 'existing-token');
  assert.equal(view.get('max-files').value, '1'); assert.equal(view.get('max-lines').value, '100');
  assert.equal(view.get('goal-cleanup').attributes.get('aria-pressed'), 'true');
  view.click('publish-btn'); assert.equal(view.requests.length, 1);
  view.click('goal-next-btn'); stage(view, 'scope-stage');
  assert.match(view.get('suggested-files').textContent, /src\/a.js/);
  assert.match(view.get('scope-summary').textContent, /1 source file.*100 changed lines.*0 read-only/);
  assert.equal(view.requests.length, 1, 'scope preview never uploads source');
  view.click('generate-btn'); stage(view, 'working-stage');
  const body = JSON.parse(view.requests[1].options.body);
  assert.deepEqual(body.files, ['src/a.js']); assert.deepEqual(body.context_files, []);
  assert.equal(body.consent, true); assert.match(body.feedback, /^Goal: Balanced cleanup/); assert.equal(body.rules, listing.rules);
  view.requests[1].resolve(proposalResponse()); await settle(); stage(view, 'review');
  assert.equal(replacement(view).hidden, true, 'review is read-only unless editing is requested');
  view.click('publish-btn'); assert.equal(view.requests.length, 2, 'cannot skip review continuation');
  view.click('review-next-btn'); stage(view, 'publish-stage');
  assert.equal(view.requests.length, 2, 'review acceptance does not publish');
  assert.equal(view.get('progress-publish').attributes.get('aria-current'), 'step');
  view.click('publish-btn'); stage(view, 'working-stage');
  assert.deepEqual(JSON.parse(view.requests[2].options.body), { action: 'publish', review_token: 'review-only', proposal: proposalResponse().proposal, approved: true });
  view.requests[2].resolve(published); await settle(); stage(view, 'done-stage');
  assert.equal(view.get('published').children[1].href, published.url);
  assert.equal(view.get('published').children[1].rel, 'noopener noreferrer');
  view.click('publish-btn'); assert.equal(view.requests.length, 3);
});
test('goal cards supply guidance without replacing repository rules', async () => {
  for (const [goal, pattern] of [['boilerplate', /Reduce repeated plumbing/], ['nesting', /Simplify nested conditionals/]]) {
    const view = await ready(); view.click('goal-' + goal); view.click('goal-next-btn');
    assert.equal(view.get('goal-' + goal).attributes.get('aria-pressed'), 'true');
    view.click('generate-btn'); const body = JSON.parse(view.requests[1].options.body);
    assert.equal(body.rules, listing.rules); assert.match(body.feedback, pattern);
  }
});
test('empty repository guidance falls back to defaults without asking the customer to write rules', async () => {
  for (const rules of [null, '', ' \n ']) {
    const view = await ready({ rules }); view.click('goal-next-btn');
    assert.match(view.get('rules').value, /^# Refactor rules/);
    assert.equal(view.get('generate-btn').disabled, false);
  }
});
test('AGENTS.md is never auto-added and remains optional read-only context', async () => {
  for (const selected of [false, true]) {
    const view = await ready({ files: [listing.files[0], { path: 'AGENTS.md', size: 300, editable: false }] });
    view.click('goal-next-btn'); assert.equal(view.get('files').children[1].children[0].disabled, true);
    assert.equal(view.get('context-files').children[1].children[0].checked, false);
    if (selected) view.select('context-files', 1);
    assert.equal(view.requests.length, 1);
    view.click('generate-btn');
    assert.deepEqual(JSON.parse(view.requests[1].options.body).context_files, selected ? ['AGENTS.md'] : []);
  }
});
test('optional file controls honor protected paths, overlap and three-context limit', async () => {
  const view = await ready(); view.click('goal-next-btn');
  assert.equal(view.select('files', 2).checked, false);
  for (const index of [2, 3, 4]) view.select('context-files', index);
  assert.equal(view.select('context-files', 5).checked, false);
  assert.equal(view.get('context-files').children[0].children[0].disabled, true);
  assert.match(view.get('context-count').textContent, /^3 \/ 3/);
});
test('optional rules and scope changes invalidate review and show the updated scope', async () => {
  for (const [id, value] of [['rules', '# Custom'], ['max-files', '2'], ['max-lines', '90']]) {
    const view = await generated(); view.click('review-next-btn'); view.input(id, value);
    stage(view, 'scope-stage'); assert.equal(view.get('edits').children.length, 0);
    view.click('publish-btn'); assert.equal(view.requests.length, 2);
    view.click('generate-btn'); assert.equal(view.requests.length, 3);
    assert.equal(JSON.parse(view.requests[2].options.body).consent, true);
  }
});
test('changing the goal after scope review preserves custom rules and requires confirmation', async () => {
  const view = await ready(); view.click('goal-next-btn'); view.input('rules', '# My rules');
  view.click('scope-back-btn'); stage(view, 'goal-stage'); view.click('goal-nesting');
  view.click('goal-next-btn'); view.click('generate-btn');
  assert.equal(JSON.parse(view.requests[1].options.body).rules, '# My rules');
  assert.match(JSON.parse(view.requests[1].options.body).feedback, /Simplify nested/);
});
test('proposal content is rendered as text, not executable HTML', async () => {
  const hostile = '<img src=x onerror=alert(1)></textarea><script>alert(2)</script>';
  const view = await generated(proposalResponse({ proposal: { summary: hostile, rule: hostile, tradeoffs: hostile, edits: [{ path: 'src/a.js', content: hostile }] }, originals: [{ path: 'src/a.js', content: hostile + 'original' }] }));
  for (const key of ['summary', 'rule', 'tradeoffs']) assert.equal(view.get(key).textContent, hostile);
  assert.equal(afterColumn(view).children[1].textContent, hostile); assert.equal(replacement(view).value, hostile);
});
test('editing is optional and the final approval publishes the edited replacement', async () => {
  const view = await generated(); const editor = replacement(view); const toggle = afterColumn(view).children[3];
  assert.equal(editor.hidden, true); toggle.dispatchEvent({ type: 'click' }); assert.equal(editor.hidden, false);
  editor.value = 'reviewed\n'; editor.dispatchEvent({ type: 'input' });
  assert.equal(afterColumn(view).children[1].textContent, 'reviewed\n');
  assert.match(view.get('changed-lines').textContent, /2 changed lines.*local estimate/);
  view.click('review-next-btn'); view.click('publish-btn');
  assert.equal(JSON.parse(view.requests[2].options.body).proposal.edits[0].content, 'reviewed\n');
});
test('back to review or an edit after continuation requires another review step', async () => {
  const view = await generated(); view.click('review-next-btn'); view.click('review-back-btn'); stage(view, 'review');
  view.click('publish-btn'); assert.equal(view.requests.length, 2);
  view.click('review-next-btn'); replacement(view).value = 'edited\n'; replacement(view).dispatchEvent({ type: 'input' });
  stage(view, 'review'); view.click('publish-btn'); assert.equal(view.requests.length, 2);
});
test('quick revision buttons supply feedback and return to confirmed scope without typing', async () => {
  for (const [button, expected] of [['smaller-btn', /smaller change/], ['inline-btn', /logic inline/]]) {
    const view = await generated(); view.click(button); stage(view, 'scope-stage');
    assert.equal(view.requests.length, 2, 'revision is not an implicit upload');
    assert.equal(view.get('edits').children.length, 0); view.click('generate-btn');
    assert.match(JSON.parse(view.requests[2].options.body).feedback, expected);
  }
});
test('custom feedback remains optional and is included on regeneration', async () => {
  const view = await generated(); view.input('feedback', 'Keep explicit guards'); view.click('regenerate-btn');
  stage(view, 'scope-stage'); view.click('generate-btn'); assert.match(JSON.parse(view.requests[2].options.body).feedback, /Customer feedback:\nKeep explicit guards$/);
});
test('goal guidance does not overflow valid maximum-length rules and oversized feedback stays editable', async () => {
  const view = await ready({ rules: 'r'.repeat(12000) }); view.click('goal-next-btn'); view.click('generate-btn');
  assert.equal(JSON.parse(view.requests[1].options.body).rules.length, 12000);
  view.requests[1].resolve(proposalResponse()); await settle();
  view.input('feedback', 'é'.repeat(4000)); view.click('regenerate-btn');
  stage(view, 'review'); assert.match(view.get('status').textContent, /Shorten.*feedback/);
  assert.equal(view.requests.length, 2);
  view.input('feedback', 'Use a guard'); view.click('regenerate-btn'); stage(view, 'scope-stage');
});
test('no-change, reverted and oversized proposals cannot advance to publication', async () => {
  const none = await generated(proposalResponse({ proposal: { summary: 'No change', rule: 'Preserve', tradeoffs: 'None', edits: [] }, originals: [], changed_lines: 0 }));
  stage(none, 'review'); assert.equal(none.get('no-changes').hidden, false); assert.equal(none.get('review-next-btn').disabled, true);
  none.click('review-next-btn'); none.click('publish-btn'); assert.equal(none.requests.length, 2);
  const view = await generated();
  for (const value of ['old\n', 'new\n'.repeat(101)]) {
    replacement(view).value = value; replacement(view).dispatchEvent({ type: 'input' });
    assert.equal(view.get('review-next-btn').disabled, true); view.click('review-next-btn'); stage(view, 'review');
  }
});
test('empty repositories explain the absence of suggestions without requiring typing', async () => {
  const view = await ready({ files: [listing.files[2]] }); view.click('goal-next-btn'); stage(view, 'scope-stage');
  assert.equal(view.get('generate-btn').disabled, true); assert.match(view.get('suggested-files').textContent, /No eligible source/);
  view.click('generate-btn'); assert.equal(view.requests.length, 1);
});
test('discard clears source and returns to goal selection', async () => {
  const view = await generated(); view.click('reject-btn'); stage(view, 'goal-stage');
  assert.equal(view.get('edits').children.length, 0); assert.equal(view.get('summary').textContent, '');
});
test('repo and auth changes erase source and reject late responses', async () => {
  for (const identity of ['repo', 'auth']) {
    const view = await generated(); view.click('smaller-btn'); view.click('generate-btn');
    if (identity === 'repo') { view.nodes.get('repo-input').value = 'acme/other'; view.nodes.get('repo-input').dispatchEvent({ type: 'input' }); }
    else { view.storage.delete('buzz_gh_token'); view.win.dispatchEvent({ type: 'buzz:auth-change' }); }
    assert.equal(view.requests[2].options.signal.aborted, true); stage(view, 'goal-stage');
    for (const id of ['rules', 'feedback']) assert.equal(view.get(id).value, '');
    assert.equal(view.get('files').children.length, 0); assert.equal(view.get('edits').children.length, 0);
    view.requests[2].resolve(proposalResponse()); await settle(); stage(view, 'goal-stage');
  }
});
test('silent session token changes are rechecked before final approval', async () => {
  const view = await generated(); view.click('review-next-btn'); view.storage.set('buzz_gh_token', 'different'); view.click('publish-btn');
  assert.equal(view.requests.length, 2); stage(view, 'goal-stage'); assert.equal(view.get('edits').children.length, 0);
});
test('timeouts and errors restore the appropriate step with a usable retry', async () => {
  const view = await ready(); view.click('goal-next-btn'); view.click('generate-btn');
  const timer = Array.from(view.timers.values())[0]; assert.equal(timer.delay, 55000); timer.handler();
  assert.equal(view.requests[1].options.signal.aborted, true); view.requests[1].reject(new Error('aborted')); await settle();
  stage(view, 'scope-stage'); assert.match(view.get('status').textContent, /timed out after 55 seconds/);
  assert.equal(view.get('generate-btn').disabled, false); view.click('generate-btn');
  view.requests[2].resolve({ error: '<img onerror=alert(1)> unavailable' }, 500); await settle();
  stage(view, 'scope-stage'); assert.match(view.get('status').textContent, /<img/); assert.ok(view.get('status').classes.has('is-error'));
});
test('cancel and back ignore late responses while preserving honest publication warnings', async () => {
  const view = await ready(); view.click('goal-next-btn'); view.click('generate-btn'); view.click('cancel-btn');
  stage(view, 'scope-stage'); assert.equal(view.requests[1].options.signal.aborted, true);
  view.requests[1].resolve(proposalResponse()); await settle(); stage(view, 'scope-stage');
  const publishView = await generated(); publishView.click('review-next-btn'); publishView.click('publish-btn'); publishView.click('cancel-btn');
  stage(publishView, 'publish-stage'); assert.match(publishView.get('status').textContent, /may already have created/);
  const loading = fixture(); loading.win.buzzOpenRefactor(); loading.click('back-btn'); assert.equal(loading.win.step, 2);
  assert.equal(loading.requests[0].options.signal.aborted, true); loading.requests[0].resolve(listing); await settle();
  assert.equal(loading.get('files').children.length, 0);
});
test('partial publication retries require another explicit action and reuse exact payload', async () => {
  const view = await generated(); view.click('review-next-btn'); view.click('publish-btn'); const first = view.requests[2].options.body;
  view.requests[2].resolve({ error: 'Branch is ready; retry to recover draft.' }, 502); await settle(); stage(view, 'publish-stage');
  assert.equal(view.requests.length, 3); assert.match(view.get('status').textContent, /Approve again/);
  view.click('publish-btn'); assert.equal(view.requests[3].options.body, first); view.requests[3].resolve(published); await settle(); stage(view, 'done-stage');
});
test('stale-base rejection is shown and returns to final confirmation', async () => {
  const view = await generated(); view.click('review-next-btn'); view.click('publish-btn');
  view.requests[2].resolve({ error: 'The base is stale. Generate a new proposal.' }, 409); await settle();
  stage(view, 'publish-stage'); assert.match(view.get('status').textContent, /base is stale/);
  view.click('review-back-btn'); view.click('smaller-btn'); stage(view, 'scope-stage');
});
test('invalid sessions clear source and unsafe PR URLs cannot be linked', async () => {
  const expired = await generated(); expired.click('review-next-btn'); expired.click('publish-btn');
  expired.requests[2].resolve({ error: 'Session expired' }, 401); await settle(); stage(expired, 'goal-stage');
  assert.equal(expired.get('edits').children.length, 0); assert.equal(expired.get('rules').value, '');
  const view = await generated(); view.click('review-next-btn'); view.click('publish-btn');
  view.requests[2].resolve({ ...published, url: 'https://evil.test/pr' }); await settle(); stage(view, 'publish-stage');
  assert.equal(view.get('published').children.length, 0); assert.match(view.get('status').textContent, /No untrusted link/);
});
test('truncation is disclosed and custom rules survive metadata reload', async () => {
  const view = await ready({ truncated: true, rules: null }); assert.match(view.get('file-notice').textContent, /truncated/);
  assert.match(view.get('rules').value, /^# Refactor rules/); view.click('goal-next-btn'); view.input('rules', '# My custom rules');
  stage(view, 'scope-stage');
  assert.equal(view.get('load-btn').hidden, false);
  assert.equal(view.get('load-btn').disabled, false);
  assert.equal(view.get('load-btn').textContent, 'REFRESH REPOSITORY FILES');
  view.click('load-btn'); view.requests[1].resolve(listing); await settle(); assert.equal(view.get('rules').value, '# My custom rules');
  view.win.dispatchEvent({ type: 'pagehide' }); assert.equal(view.get('rules').value, ''); assert.equal(view.get('files').children.length, 0);
});
test('stale file selections can recover through the visible refresh action without uploading again', async () => {
  const view = await ready(); view.click('goal-next-btn'); view.click('generate-btn');
  view.requests[1].resolve({ error: 'The selected file no longer exists: src/a.js' }, 400); await settle();
  stage(view, 'scope-stage');
  assert.equal(view.get('load-btn').hidden, false);
  assert.equal(view.get('load-btn').disabled, false);
  const header = html.slice(html.indexOf('<header class="refactor-header">'), html.indexOf('</header>', html.indexOf('<header class="refactor-header">')));
  assert.match(header, /id="refactor-load-btn"/, 'refresh remains outside hidden or collapsed stages');
  view.click('load-btn');
  assert.equal(view.get('load-btn').hidden, true);
  assert.equal(view.requests[2].options.method, 'GET');
  assert.equal(view.requests[2].options.body, undefined);
  view.requests[2].resolve({ ...listing, commit_sha: 'new-base', files: [listing.files[1]] }); await settle();
  stage(view, 'goal-stage'); view.click('goal-next-btn');
  assert.match(view.get('suggested-files').textContent, /src\/b.js/);
  assert.doesNotMatch(view.get('suggested-files').textContent, /src\/a.js/);
  assert.match(view.get('base').textContent, /new-base/);
  assert.equal(view.requests.length, 3, 'refresh never generates without renewed scope confirmation');
  view.click('generate-btn');
  assert.deepEqual(JSON.parse(view.requests[3].options.body).files, ['src/b.js']);
  assert.equal(JSON.parse(view.requests[3].options.body).consent, true);
});
test('refresh failures provide a visible metadata retry instead of stale selections', async () => {
  const view = await ready(); view.click('goal-next-btn'); view.click('load-btn');
  view.requests[1].resolve({ error: 'Repository unavailable' }, 503); await settle();
  stage(view, 'goal-stage');
  assert.equal(view.get('load-btn').hidden, false);
  assert.equal(view.get('load-btn').disabled, false);
  assert.equal(view.get('load-btn').textContent, 'TRY LOADING AGAIN');
  assert.equal(view.get('goal-next-btn').disabled, true);
  assert.equal(view.get('files').children.length, 0);
});
test('fresh passes discard old feedback while deliberate revisions retain and disclose it', async () => {
  for (const reset of ['discard', 'new', 'refresh', 'goal']) {
    const view = await generated();
    view.click('inline-btn');
    const feedback = view.get('feedback').value;
    stage(view, 'scope-stage');
    assert.equal(view.get('revision-note').hidden, false);
    assert.equal(view.get('revision-feedback').textContent, feedback);
    view.click('generate-btn');
    assert.match(JSON.parse(view.requests[2].options.body).feedback, /Customer feedback:/);
    view.requests[2].resolve(proposalResponse()); await settle();
    if (reset === 'discard') {
      view.click('reject-btn');
    } else if (reset === 'new') {
      view.click('review-next-btn'); view.click('publish-btn'); view.requests[3].resolve(published); await settle();
      view.click('new-btn'); view.requests[4].resolve(listing); await settle();
    } else {
      view.click('smaller-btn');
      if (reset === 'refresh') { view.click('load-btn'); view.requests[3].resolve(listing); await settle(); }
      else { view.click('scope-back-btn'); view.click('goal-boilerplate'); }
    }
    assert.equal(view.get('feedback').value, '', reset);
    assert.equal(view.get('revision-note').hidden, true, reset);
    assert.equal(view.get('feedback-options').open, false, reset);
    view.click('goal-next-btn'); view.click('generate-btn');
    assert.doesNotMatch(JSON.parse(view.requests[view.requests.length - 1].options.body).feedback, /Customer feedback:/, reset);
  }
});
test('revision feedback can be removed from scope without typing and is rendered as text', async () => {
  const view = await generated();
  const feedback = '<script>alert(1)</script> Keep the guard';
  view.input('feedback', feedback); view.click('regenerate-btn');
  stage(view, 'scope-stage');
  assert.equal(view.get('revision-note').hidden, false);
  assert.equal(view.get('revision-feedback').textContent, feedback);
  view.click('clear-feedback-btn');
  assert.equal(view.get('revision-note').hidden, true);
  assert.equal(view.get('feedback').value, '');
  view.click('generate-btn'); assert.doesNotMatch(JSON.parse(view.requests[2].options.body).feedback, /Customer feedback:/);
});
test('late metadata replies cannot replace a newer load after switching repositories back', async () => {
  const view = fixture(); view.win.buzzOpenRefactor(); const input = view.nodes.get('repo-input');
  input.value = 'acme/other'; input.dispatchEvent({ type: 'input' }); view.click('load-btn');
  input.value = 'acme/buzz'; input.dispatchEvent({ type: 'input' }); view.click('load-btn');
  view.requests[2].resolve({ ...listing, rules: '# Newest' }); await settle();
  view.requests[0].resolve(listing); view.requests[1].resolve({ ...listing, repo: 'acme/other' }); await settle();
  assert.equal(view.get('rules').value, '# Newest'); assert.equal(view.get('repo').textContent, 'acme/buzz');
});
test('missing GitHub authorization offers an in-place connection instead of a disabled retry', () => {
  const view = fixture({ storage: new Map([['buzz_gh_user', 'public-user'], ['buzz_sb_uid', 'supabase-only']]) });
  view.win.buzzOpenRefactor();
  assert.equal(view.win.step, 5);
  assert.equal(view.requests.length, 0);
  assert.equal(view.get('auth').hidden, false);
  assert.equal(view.get('connect-btn').disabled, false);
  assert.equal(view.get('load-btn').hidden, true);
  assert.equal(view.get('goal-next-btn').disabled, true);
  assert.match(view.get('status').textContent, /Connect GitHub below/);
  view.click('generate-btn'); view.click('publish-btn');
  assert.equal(view.requests.length, 0);
});
test('connect reuses OAuth and persists only a bounded repository and goal return intent', async () => {
  const view = fixture({ storage: new Map() }); view.win.buzzOpenRefactor(); view.click('goal-nesting');
  let finish; const calls = [];
  view.win.buzzConnectGitHub = options => { calls.push(options); return new Promise(resolve => { finish = resolve; }); };
  view.click('connect-btn'); view.click('connect-btn');
  assert.equal(calls.length, 1);
  assert.deepEqual(calls[0], { requireRepoAccess: true });
  assert.equal(view.get('connect-btn').disabled, true);
  const saved = JSON.parse(view.storage.get('buzz_refactor_return'));
  assert.deepEqual(Object.keys(saved).sort(), ['createdAt', 'goal', 'repo']);
  assert.equal(saved.repo, 'acme/buzz'); assert.equal(saved.goal, 'nesting');
  assert.ok(Number.isSafeInteger(saved.createdAt));
  finish(); await settle();
  assert.equal(view.get('connect-btn').disabled, false);
  assert.equal(view.requests.length, 0, 'connecting never sends source or publishes');
  view.win.dispatchEvent({ type: 'pagehide' });
  assert.equal(JSON.parse(view.storage.get('buzz_refactor_return')).goal, 'nesting');
});
test('OAuth return restores the repo and goal, loads metadata once and still requires scope consent', async () => {
  const storage = new Map([
    ['buzz_refactor_return', JSON.stringify({ repo: 'acme/other', goal: 'boilerplate', createdAt: Date.now() })]
  ]);
  const view = fixture({ storage });
  assert.equal(view.win.step, 5); assert.equal(view.nodes.get('repo-input').value, 'acme/other');
  assert.equal(view.requests.length, 0);
  storage.set('buzz_gh_token', 'fresh-token');
  view.win.dispatchEvent({ type: 'buzz:auth-change' });
  view.win.dispatchEvent({ type: 'buzz:auth-change' });
  view.win.dispatchEvent({ type: 'focus' });
  assert.equal(view.requests.length, 1);
  assert.equal(storage.has('buzz_refactor_return'), false);
  assert.equal(view.requests[0].options.method, 'GET');
  assert.equal(view.requests[0].options.headers['X-GitHub-Token'], 'fresh-token');
  assert.equal(view.requests[0].url, '/api/refactor?repo=acme%2Fother');
  view.requests[0].resolve({ ...listing, repo: 'acme/other' }); await settle();
  stage(view, 'goal-stage'); assert.equal(view.get('auth').hidden, true);
  assert.equal(view.get('goal-boilerplate').attributes.get('aria-pressed'), 'true');
  assert.equal(view.get('goal-next-btn').disabled, false);
  assert.equal(view.requests.length, 1, 'never generates or publishes on return');
});
test('OAuth return works when the session is restored before the wizard mounts', async () => {
  const view = fixture({ storage: new Map([
    ['buzz_gh_token', 'restored-token'],
    ['buzz_refactor_return', JSON.stringify({ repo: 'acme/buzz', goal: 'nesting', createdAt: Date.now() })]
  ]) });
  assert.equal(view.win.step, 5); assert.equal(view.requests.length, 1);
  view.requests[0].resolve(listing); await settle();
  assert.equal(view.get('goal-nesting').attributes.get('aria-pressed'), 'true');
  assert.equal(view.storage.has('buzz_refactor_return'), false);
});
test('invalid or stale OAuth navigation intent is discarded without navigation or requests', () => {
  const valid = { repo: 'acme/buzz', goal: 'cleanup', createdAt: Date.now() };
  const values = ['not-json', null, { ...valid, repo: 'https://evil.test/steal' }, { ...valid, repo: '' },
    { ...valid, goal: '__proto__' }, { ...valid, createdAt: Date.now() - 11 * 60 * 1000 },
    { ...valid, createdAt: Date.now() + 60000 }, { ...valid, createdAt: 'today' }];
  for (const value of values) {
    const view = fixture({ storage: new Map([['buzz_refactor_return', typeof value === 'string' ? value : JSON.stringify(value)]]) });
    assert.equal(view.win.step, undefined);
    assert.equal(view.requests.length, 0);
    assert.equal(view.storage.has('buzz_refactor_return'), false);
  }
});
test('expired GitHub credentials expose reconnect and stop retries with the rejected token', async () => {
  const view = fixture(); view.win.buzzOpenRefactor();
  view.requests[0].resolve({ error: 'Bad credentials' }, 401); await settle();
  assert.equal(view.get('auth').hidden, false);
  assert.equal(view.get('connect-btn').textContent, 'RECONNECT GITHUB');
  assert.equal(view.get('load-btn').hidden, true);
  view.click('load-btn'); view.win.buzzOpenRefactor();
  assert.equal(view.requests.length, 1);
  view.win.buzzConnectGitHub = async () => {
    view.storage.set('buzz_gh_token', 'new-token');
    view.win.dispatchEvent({ type: 'buzz:auth-change' });
  };
  view.click('connect-btn'); await settle();
  assert.equal(view.requests.length, 2);
  assert.equal(view.requests[1].options.headers['X-GitHub-Token'], 'new-token');
  view.requests[1].resolve(listing); await settle();
  assert.equal(view.get('auth').hidden, true);
  assert.equal(view.get('goal-next-btn').disabled, false);
});
test('failed sign-in keeps a usable reconnect action and never falls back to a username form', async () => {
  const view = fixture({ storage: new Map() }); view.win.buzzOpenRefactor();
  view.win.buzzConnectGitHub = async options => {
    assert.equal(options.requireRepoAccess, true);
    throw new Error('GitHub provider unavailable');
  };
  view.click('connect-btn'); await settle();
  assert.match(view.get('status').textContent, /GitHub provider unavailable/);
  assert.equal(view.get('auth').hidden, false);
  assert.equal(view.get('connect-btn').disabled, false);
  assert.equal(view.storage.has('buzz_refactor_return'), false);
  assert.equal(view.requests.length, 0);
});
test('back to repositories cancels OAuth navigation intent', async () => {
  const view = fixture({ storage: new Map() }); view.win.buzzOpenRefactor();
  view.win.buzzConnectGitHub = async () => {};
  view.click('connect-btn'); await settle();
  view.click('back-btn');
  assert.equal(view.win.step, 2); assert.equal(view.storage.has('buzz_refactor_return'), false);
  view.storage.set('buzz_gh_token', 'new-token'); view.win.dispatchEvent({ type: 'buzz:auth-change' });
  assert.equal(view.win.step, 2); assert.equal(view.requests.length, 0);
});
function authFixture({ session = null, oauthError = null, hash = '', configured = true } = {}) {
  const view = fixture({ storage: new Map() });
  const calls = []; let resolveConfig; let onAuth; let prompts = 0;
  view.win.location = { origin: 'http://localhost:3001', search: '', hash };
  view.win.document.body = new FakeElement();
  view.nodes.get('github-signout-btn').style = {};
  view.win.prompt = () => { prompts += 1; return 'public-user'; };
  view.win.supabase = { createClient: () => ({ auth: {
    onAuthStateChange: handler => { onAuth = handler; },
    getSession: async () => ({ data: { session } }),
    signInWithOAuth: async options => { calls.push(options); return { error: oauthError }; }
  } }) };
  const config = new Promise(resolve => { resolveConfig = resolve; });
  const source = html.slice(html.indexOf('// 5. Supabase GitHub OAuth & HTMX Header Bridge'), html.indexOf('      authReady = initSupabaseAuth();')) +
    'authReady = initSupabaseAuth();';
  vm.runInNewContext(source, {
    window: view.win, document: view.win.document, sessionStorage: view.win.sessionStorage, URLSearchParams,
    CustomEvent: class { constructor(type, options = {}) { this.type = type; Object.assign(this, options); } },
    fetch: () => config
  });
  return Object.assign(view, {
    calls, resolveConfig: () => resolveConfig({ ok: true, json: async () => configured ? { supabase_url: 'https://example.supabase.co', supabase_anon_key: 'public-test-key' } : {} }),
    emitAuth: (event, data) => onAuth(event, data), promptCount: () => prompts
  });
}
test('real auth bridge waits for configuration and requests repo access on the current origin', async () => {
  const view = authFixture();
  const connecting = view.win.buzzConnectGitHub({ requireRepoAccess: true });
  assert.equal(view.calls.length, 0); assert.equal(view.promptCount(), 0);
  view.resolveConfig(); await connecting;
  assert.equal(view.calls.length, 1);
  assert.equal(view.calls[0].provider, 'github');
  assert.equal(view.calls[0].options.scopes, 'read:user repo');
  assert.equal(view.calls[0].options.redirectTo, 'http://localhost:3001');
  assert.equal(view.promptCount(), 0);
});
test('real auth bridge never treats username-only or Supabase-only sessions as repository access', async () => {
  const view = authFixture({ session: { user: { id: 'supabase-user', user_metadata: { user_name: 'octocat' } } } });
  view.resolveConfig(); await settle();
  assert.equal(view.storage.has('buzz_gh_token'), false);
  assert.equal(view.nodes.get('github-auth-label').textContent, 'RECONNECT GITHUB FOR REPOSITORY ACCESS');
  view.win.buzzOpenRefactor(); assert.equal(view.get('auth').hidden, false); assert.equal(view.requests.length, 0);
});
test('real OAuth callback preserves the refactor return and forwards the provider token once', async () => {
  const view = authFixture({ hash: '#access_token=test-callback' });
  view.storage.set('buzz_refactor_return', JSON.stringify({ repo: 'acme/buzz', goal: 'nesting', createdAt: Date.now() }));
  view.resolveConfig(); await settle();
  const session = { provider_token: 'oauth-provider-token', user: { id: 'supabase-user', user_metadata: { user_name: 'octocat' } } };
  view.emitAuth('SIGNED_IN', session);
  view.emitAuth('SIGNED_IN', session);
  assert.equal(view.win.step, 5);
  assert.equal(view.requests.length, 1);
  assert.equal(view.requests[0].options.headers['X-GitHub-Token'], 'oauth-provider-token');
  assert.equal(view.storage.has('buzz_refactor_return'), false);
  assert.equal(view.nodes.get('github-auth-label').textContent, 'GITHUB CONNECTED: @octocat');
  view.requests[0].resolve(listing); await settle();
  assert.equal(view.get('goal-nesting').attributes.get('aria-pressed'), 'true');
});
test('later auth events do not repeatedly navigate away after the initial OAuth return', async () => {
  const session = { provider_token: 'oauth-provider-token', user: { id: 'supabase-user' } };
  const view = authFixture({ hash: '#access_token=test-callback', session });
  view.resolveConfig(); await settle();
  assert.equal(view.win.step, 2);
  view.win.buzzGoToStep(4);
  view.emitAuth('SIGNED_IN', session);
  assert.equal(view.win.step, 4);
});
test('real reconnect clears a rejected token before redirect and preserves the return intent', async () => {
  const view = authFixture(); view.resolveConfig(); await settle();
  view.emitAuth('SIGNED_IN', { provider_token: 'rejected-token', user: { id: 'supabase-user' } });
  view.win.buzzOpenRefactor();
  view.requests[0].resolve({ error: 'Expired' }, 401); await settle();
  view.click('connect-btn'); await settle();
  assert.equal(view.calls.length, 1);
  assert.equal(view.storage.has('buzz_gh_token'), false);
  assert.equal(view.storage.has('buzz_refactor_return'), true);
  assert.equal(view.requests.length, 1, 'never retries with a rejected token during redirect');
  view.emitAuth('SIGNED_IN', { provider_token: 'fresh-token', user: { id: 'supabase-user' } });
  assert.equal(view.storage.has('buzz_refactor_return'), false);
  assert.equal(view.requests.length, 2);
  assert.equal(view.requests[1].options.headers['X-GitHub-Token'], 'fresh-token');
});
test('real strict OAuth errors do not fall through to the legacy token or username prompt', async () => {
  for (const options of [{ configured: false }, { oauthError: { message: 'OAuth temporarily unavailable' } }]) {
    const view = authFixture(options); view.resolveConfig();
    await assert.rejects(view.win.buzzConnectGitHub({ requireRepoAccess: true }), /unavailable/);
    assert.equal(view.promptCount(), 0);
    assert.equal(view.storage.has('buzz_gh_token'), false);
  }
});
test('sign-out clears token and broadcasts before waiting for Supabase', () => {
  const signOut = html.slice(html.indexOf('window.buzzSignOutGitHub ='), html.indexOf('window.buzzSelectRepo ='));
  assert.ok(signOut.indexOf("sessionStorage.removeItem('buzz_gh_token')") < signOut.indexOf('await supabaseClient.auth.signOut()'));
  assert.ok(signOut.indexOf('updateAuthBadge()') < signOut.indexOf('await supabaseClient.auth.signOut()'));
});
