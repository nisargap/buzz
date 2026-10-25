(function (root, factory) {
  'use strict';
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  if (root && root.document) api.mountRefactor(root);
})(typeof window === 'undefined' ? null : window, function () {
  'use strict';

  const REQUEST_TIMEOUT_MS = 55000;
  const AUTH_RETURN_KEY = 'buzz_refactor_return';
  const AUTH_RETURN_TTL_MS = 10 * 60 * 1000;
  const DEFAULT_RULES = '# Refactor rules\n\n- Preserve behavior, public interfaces, errors, and side effects.\n- Follow the repository\'s existing conventions.\n- Prefer one small, worthwhile simplification over a rewrite.\n- Do not change dependencies, configuration, or tests.\n- If context is insufficient or no change is worthwhile, propose no edits.';
  const GOALS = {
    cleanup: { title: 'Balanced cleanup', rule: 'Find one small readability improvement. Remove redundant plumbing without introducing unnecessary helpers.' },
    boilerplate: { title: 'Less boilerplate', rule: 'Reduce repeated plumbing using existing helpers and language idioms. Avoid new abstractions for trivial code.' },
    nesting: { title: 'Flatter logic', rule: 'Simplify nested conditionals or deep call chains when clearer. Preserve evaluation order, errors, and side effects; do not chase a fixed complexity score.' }
  };

  function normalizeRepo(value) {
    const repo = String(value || '').trim()
      .replace(/^https?:\/\/github\.com\//i, '').replace(/^github\.com\//i, '')
      .replace(/^\/+|\/+$/g, '').replace(/\.git$/i, '');
    return /^[a-z0-9][a-z0-9-]{0,38}\/[a-z0-9._-]{1,100}$/i.test(repo) &&
      !['.', '..'].includes(repo.split('/')[1]) ? repo : '';
  }

  function validateScope(scope) {
    if (!Number.isInteger(scope.max_files) || scope.max_files < 1 || scope.max_files > 5) {
      throw new Error('Max editable files must be a whole number from 1 to 5.');
    }
    if (!Number.isInteger(scope.max_changed_lines) || scope.max_changed_lines < 1 || scope.max_changed_lines > 500) {
      throw new Error('Max changed lines must be a whole number from 1 to 500.');
    }
    if (!Array.isArray(scope.files) || !scope.files.length || scope.files.length > scope.max_files) {
      throw new Error('Select at least one editable file, within your max files limit.');
    }
    if (!Array.isArray(scope.context_files) || scope.context_files.length > 3) {
      throw new Error('Select no more than 3 read-only context files.');
    }
    const paths = scope.files.concat(scope.context_files);
    if (paths.some(function (path) { return typeof path !== 'string' || !path; }) || new Set(paths).size !== paths.length) {
      throw new Error('Editable files and read-only context must be separate, unique files.');
    }
    return scope;
  }

  // Metadata-based starting point, not a claim that a file is complex or unsafe.
  function suggestFiles(files) {
    function score(file) {
      return (/^(src|lib|app|api)\//.test(file.path) ? 4 : 0) +
        (file.size >= 200 && file.size <= 16000 ? 3 : 0) -
        (/(^|\/)(index|types|main)\.[^.]+$/.test(file.path) ? 1 : 0);
    }
    return files.filter(function (file) { return file.editable === true && file.size > 0 && file.size <= 40000; })
      .sort(function (a, b) { return score(b) - score(a) || a.path.localeCompare(b.path); })
      .slice(0, 1).map(function (file) { return file.path; });
  }

  function scopeKey(scope, goal) {
    return JSON.stringify([scope.repo, scope.rules, scope.max_files, scope.max_changed_lines,
      scope.files.slice().sort(), scope.context_files.slice().sort(), scope.consent, goal]);
  }

  function safePullRequestUrl(value) {
    if (typeof value !== 'string') return null;
    try {
      const url = new URL(value);
      if (url.protocol !== 'https:' || url.hostname !== 'github.com' || url.port || url.username || url.password ||
          !/^\/[a-z0-9-]+\/[a-z0-9._-]+\/pull\/[1-9][0-9]*\/?$/i.test(url.pathname)) return null;
      return url.href;
    } catch (_) { return null; }
  }

  // Bounded Myers line distance: additions + deletions, not a claim of validation.
  // Keep terminators so trailing-newline changes count. limit + 1 means over limit.
  function countChangedLines(before, after, limit) {
    if (before === after) return 0;
    const a = before.match(/[^\n]*\n|[^\n]+$/g) || [];
    const b = after.match(/[^\n]*\n|[^\n]+$/g) || [];
    let start = 0;
    while (start < a.length && start < b.length && a[start] === b[start]) start += 1;
    let aEnd = a.length;
    let bEnd = b.length;
    while (aEnd > start && bEnd > start && a[aEnd - 1] === b[bEnd - 1]) { aEnd -= 1; bEnd -= 1; }
    const n = aEnd - start;
    const m = bEnd - start;
    if (!n || !m) return Math.min(n + m, limit + 1);
    if (Math.abs(n - m) > limit) return limit + 1;
    let frontier = new Map([[1, 0]]);
    for (let distance = 0; distance <= limit; distance += 1) {
      const next = new Map();
      for (let diagonal = -distance; diagonal <= distance; diagonal += 2) {
        const left = frontier.get(diagonal - 1) ?? -Infinity;
        const right = frontier.get(diagonal + 1) ?? -Infinity;
        let x = diagonal === -distance || (diagonal !== distance && left < right) ? right : left + 1;
        let y = x - diagonal;
        while (x < n && y < m && a[start + x] === b[start + y]) { x += 1; y += 1; }
        if (x >= n && y >= m) return distance;
        next.set(diagonal, x);
      }
      frontier = next;
    }
    return limit + 1;
  }

  function validBase(data, repo) {
    return data && typeof data.repo === 'string' && normalizeRepo(data.repo).toLowerCase() === repo.toLowerCase() &&
      typeof data.branch === 'string' && data.branch.length > 0 &&
      typeof data.commit_sha === 'string' && data.commit_sha.length > 0;
  }

  function validateListing(data, repo) {
    if (!validBase(data, repo) || !Array.isArray(data.files) ||
        !(data.rules === null || typeof data.rules === 'string') || typeof data.truncated !== 'boolean') {
      throw new Error('The server returned an invalid file list. Try loading again.');
    }
    const seen = new Set();
    const files = data.files.map(function (file) {
      if (!file || typeof file.path !== 'string' || !file.path || seen.has(file.path) ||
          !Number.isSafeInteger(file.size) || file.size < 0 || typeof file.editable !== 'boolean') {
        throw new Error('The server returned an invalid or duplicate file entry.');
      }
      seen.add(file.path);
      return { path: file.path, size: file.size, editable: file.editable };
    });
    return { repo: data.repo, branch: data.branch, commit_sha: data.commit_sha, files: files, rules: data.rules, truncated: data.truncated };
  }

  function validateProposalResponse(data, scope) {
    const proposal = data && data.proposal;
    if (!validBase(data, scope.repo) || data.validation !== 'unverified' ||
        typeof data.review_token !== 'string' || !data.review_token ||
        !Number.isSafeInteger(data.changed_lines) || data.changed_lines < 0 || data.changed_lines > scope.max_changed_lines ||
        !proposal || !['summary', 'rule', 'tradeoffs'].every(function (key) { return typeof proposal[key] === 'string'; }) ||
        !Array.isArray(proposal.edits) || proposal.edits.length > scope.max_files || !Array.isArray(data.originals)) {
      throw new Error('The server returned an invalid proposal. Generate again; nothing can be approved.');
    }
    const originals = new Map();
    data.originals.forEach(function (original) {
      if (!original || !scope.files.includes(original.path) || originals.has(original.path) || typeof original.content !== 'string') {
        throw new Error('The proposal contains invalid original files. Generate again.');
      }
      originals.set(original.path, original.content);
    });
    const seen = new Set();
    const edits = proposal.edits.map(function (edit) {
      if (!edit || !scope.files.includes(edit.path) || seen.has(edit.path) ||
          !originals.has(edit.path) || typeof edit.content !== 'string') {
        throw new Error('The proposal contains missing originals or edits outside the selected scope.');
      }
      seen.add(edit.path);
      return { path: edit.path, content: edit.content };
    });
    return {
      proposal: { summary: proposal.summary, rule: proposal.rule, tradeoffs: proposal.tradeoffs, edits: edits },
      originals: originals, reviewToken: data.review_token, changedLines: data.changed_lines,
      branch: data.branch, commit: data.commit_sha
    };
  }

  function mountRefactor(win) {
    const doc = win.document;
    const root = doc.getElementById('wizard-step-5');
    const repoInput = doc.getElementById('repo-input');
    if (!root || !repoInput) return;
    const ui = {};
    [
      'open-btn', 'back-btn', 'load-btn', 'auth', 'connect-btn', 'repo', 'base', 'status', 'settings', 'rules', 'max-files', 'max-lines',
      'file-notice', 'selected-count', 'context-count', 'files', 'context-files', 'feedback', 'generate-btn',
      'review', 'review-heading', 'proposal-base', 'summary', 'rule', 'tradeoffs', 'no-changes', 'changed-lines',
      'edits', 'regenerate-btn', 'reject-btn', 'publish-btn', 'published', 'heading', 'advanced',
      'goal-stage', 'scope-stage', 'publish-stage', 'done-stage', 'working-stage', 'working-message',
      'goal-heading', 'scope-heading', 'publish-heading', 'done-heading', 'working-heading',
      'goal-cleanup', 'goal-boilerplate', 'goal-nesting', 'goal-next-btn', 'scope-back-btn',
      'suggested-files', 'scope-summary', 'goal-summary', 'review-next-btn', 'review-back-btn',
      'publish-summary', 'publish-files', 'smaller-btn', 'inline-btn', 'new-btn', 'cancel-btn',
      'progress-goal', 'progress-scope', 'progress-review', 'progress-publish',
      'revision-note', 'revision-feedback', 'clear-feedback-btn', 'feedback-options'
    ].forEach(function (id) { ui[id] = doc.getElementById('refactor-' + id); });

    const state = {
      sourceValue: null, repo: '', token: '', listing: null, files: new Set(), context: new Set(),
      choices: new Map(), editors: [], rulesDirty: false, proposal: null, originals: new Map(),
      reviewToken: '', proposalKey: '', changedLines: 0, manuallyEdited: false, published: false, request: null,
      stage: 'goal', goal: 'cleanup', consent: false, reviewAccepted: false, authRequired: false, connecting: false
    };

    function readToken() {
      try { return win.sessionStorage.getItem('buzz_gh_token') || ''; } catch (_) { return ''; }
    }
    function clearAuthReturn() {
      try { win.sessionStorage.removeItem(AUTH_RETURN_KEY); } catch (_) {}
    }
    function readAuthReturn() {
      try {
        const value = JSON.parse(win.sessionStorage.getItem(AUTH_RETURN_KEY));
        if (value && typeof value.repo === 'string' && value.repo === normalizeRepo(value.repo) && value.repo &&
            Object.prototype.hasOwnProperty.call(GOALS, value.goal) && Number.isSafeInteger(value.createdAt) &&
            Date.now() >= value.createdAt && Date.now() - value.createdAt < AUTH_RETURN_TTL_MS) return value;
      } catch (_) {}
      clearAuthReturn();
      return null;
    }
    function resumeAfterAuth() {
      const saved = readAuthReturn();
      if (!saved) return false;
      repoInput.value = saved.repo;
      syncIdentity();
      state.goal = saved.goal;
      win.buzzGoToStep(5);
      updateControls();
      if (state.token && !state.authRequired) {
        clearAuthReturn();
        if (!state.listing && !state.request) loadFiles();
      }
      return true;
    }
    function authChanged() {
      const changed = syncIdentity();
      if (resumeAfterAuth()) return;
      if (changed && root.classList.contains('active') && state.repo && state.token && !state.authRequired && !state.request) loadFiles();
    }
    async function connectGitHub() {
      syncIdentity();
      if (state.request || state.connecting) return;
      if (!state.repo) { status('Choose a repository before connecting GitHub.', true); return; }
      state.connecting = true;
      status('Opening GitHub sign-in. We will bring you back to this repository and goal.');
      updateControls();
      try {
        // Keep only navigation intent across OAuth, never code, credentials, or approval.
        win.sessionStorage.setItem(AUTH_RETURN_KEY, JSON.stringify({ repo: state.repo, goal: state.goal, createdAt: Date.now() }));
        if (typeof win.buzzConnectGitHub !== 'function') throw new Error('GitHub sign-in is still loading. Please try again.');
        await win.buzzConnectGitHub({ requireRepoAccess: true });
        authChanged();
      } catch (error) {
        clearAuthReturn();
        status(error instanceof Error ? error.message : 'Could not start GitHub sign-in. Please try again.', true);
      } finally {
        state.connecting = false;
        updateControls();
      }
    }
    function status(message, isError) {
      ui.status.textContent = message;
      ui.status.classList.toggle('is-error', Boolean(isError));
    }
    function element(tag, className, text) {
      const node = doc.createElement(tag);
      if (className) node.className = className;
      if (text !== undefined) node.textContent = text;
      return node;
    }
    function setStage(stage, focus) {
      state.stage = stage;
      const stages = { goal: 'goal-stage', scope: 'scope-stage', review: 'review', publish: 'publish-stage', done: 'done-stage', working: 'working-stage' };
      Object.keys(stages).forEach(function (name) { ui[stages[name]].hidden = name !== stage; });
      const steps = ['goal', 'scope', 'review', 'publish'];
      const progress = stage === 'working' ? (state.request && state.request.kind === 'publish' ? 'publish' : 'scope') : stage;
      const index = progress === 'done' ? steps.length : steps.indexOf(progress);
      steps.forEach(function (name, i) {
        const step = ui['progress-' + name];
        step.setAttribute('aria-current', i === index ? 'step' : 'false');
        step.classList.toggle('is-current', i === index);
        step.classList.toggle('is-complete', i < index);
      });
      updateLoadControl();
      if (focus !== false) ui[stage + '-heading'].focus();
    }
    function updateLoadControl() {
      const needsAuth = !state.token || state.authRequired;
      ui.auth.hidden = !needsAuth;
      ui['connect-btn'].disabled = Boolean(state.request) || state.connecting || !state.repo;
      ui['connect-btn'].textContent = state.connecting ? 'OPENING GITHUB…' : state.authRequired ? 'RECONNECT GITHUB' : 'CONNECT GITHUB TO CONTINUE';
      ui['load-btn'].hidden = needsAuth || state.connecting || Boolean(state.request) || !['goal', 'scope'].includes(state.stage);
      ui['load-btn'].disabled = Boolean(state.request) || state.connecting || !state.repo || needsAuth;
      ui['load-btn'].textContent = state.listing ? 'REFRESH REPOSITORY FILES' : 'TRY LOADING AGAIN';
    }
    function cancelRequest() {
      const request = state.request;
      state.request = null;
      if (request) { win.clearTimeout(request.timer); request.controller.abort(); }
      return request;
    }
    function clearProposal() {
      state.proposal = null;
      state.originals.clear();
      state.reviewToken = '';
      state.proposalKey = '';
      state.changedLines = 0;
      state.manuallyEdited = false;
      state.published = false;
      state.reviewAccepted = false;
      state.editors = [];
      ui.published.replaceChildren();
      ui.edits.replaceChildren();
      ui['publish-files'].replaceChildren();
      ['summary', 'rule', 'tradeoffs', 'proposal-base', 'changed-lines', 'publish-summary'].forEach(function (id) { ui[id].textContent = ''; });
    }
    function clearFeedback() {
      ui.feedback.value = '';
      ui['feedback-options'].open = false;
      ui['revision-note'].hidden = true;
      ui['revision-feedback'].textContent = '';
    }
    function clearRepository() {
      cancelRequest();
      clearProposal();
      state.listing = null;
      state.files.clear();
      state.context.clear();
      state.choices.clear();
      state.rulesDirty = false;
      state.goal = 'cleanup';
      state.consent = false;
      ui.rules.value = '';
      clearFeedback();
      ui['max-files'].value = '1';
      ui['max-lines'].value = '100';
      ui.advanced.open = false;
      ui.files.replaceChildren();
      ui['context-files'].replaceChildren();
      ui['suggested-files'].replaceChildren();
      ui.base.textContent = '';
      ui['file-notice'].textContent = '';
      setStage('goal', false);
    }
    function syncIdentity() {
      const sourceValue = repoInput.value.trim();
      const token = readToken();
      if (sourceValue === state.sourceValue && token === state.token) return false;
      if (token !== state.token) state.authRequired = false;
      clearRepository();
      state.sourceValue = sourceValue;
      state.repo = normalizeRepo(sourceValue);
      state.token = token;
      ui.repo.textContent = state.repo || sourceValue || 'No repository selected';
      const needsAuth = !token || state.authRequired;
      status(needsAuth ? 'Connect GitHub below to continue with this repository.' :
        !state.repo ? 'Go back and choose a repository.' : 'Choose a goal. Buzz will handle the setup.', needsAuth || !state.repo);
      updateControls();
      return true;
    }
    function getScope() {
      return {
        repo: state.repo, files: Array.from(state.files), context_files: Array.from(state.context),
        rules: ui.rules.value,
        max_files: Number(ui['max-files'].value), max_changed_lines: Number(ui['max-lines'].value), consent: state.consent
      };
    }
    function getFeedback() {
      return 'Goal: ' + GOALS[state.goal].title + '\n' + GOALS[state.goal].rule +
        (ui.feedback.value.trim() ? '\n\nCustomer feedback:\n' + ui.feedback.value : '');
    }
    function byteLength(value) {
      return new TextEncoder().encode(value).length;
    }
    function generationError(requireConsent) {
      if (!state.token || state.authRequired) return 'Connect GitHub below before continuing.';
      if (!state.repo) return 'Go back to choose a repository first.';
      if (!state.listing) return 'Buzz needs to load the repository first. Try loading again.';
      try { validateScope(getScope()); } catch (error) { return error.message; }
      if (!ui.rules.value.trim()) return 'The custom rules are empty. Restore them before continuing.';
      if (byteLength(ui.rules.value) > 12000) return 'Shorten the optional rules to 12,000 UTF-8 bytes or fewer.';
      if (byteLength(getFeedback()) > 8000) return 'Shorten the optional feedback; the goal and feedback must fit within 8,000 UTF-8 bytes.';
      if (requireConsent && !state.consent) return 'Confirm the displayed scope before sending code to Gemini.';
      return '';
    }
    function changedEdits() {
      return state.proposal ? state.proposal.edits.filter(function (edit) { return edit.content !== state.originals.get(edit.path); }) : [];
    }
    function reviewMetrics() {
      const edits = changedEdits();
      const limit = Number(ui['max-lines'].value);
      let count = state.manuallyEdited ? 0 : state.changedLines;
      if (state.manuallyEdited) {
        for (const edit of edits) {
          count += countChangedLines(state.originals.get(edit.path), edit.content, Math.max(0, limit - count));
          if (count > limit) break;
        }
      }
      return { hasChanges: edits.length > 0, count: count, overLimit: count > limit, limit: limit };
    }
    function currentReview() {
      const metrics = reviewMetrics();
      return Boolean(state.proposal && state.reviewToken && !state.published && metrics.hasChanges &&
        !metrics.overLimit && !generationError(true) && state.proposalKey === scopeKey(getScope(), state.goal));
    }
    function renderScope() {
      ui['revision-note'].hidden = !ui.feedback.value.trim();
      ui['revision-feedback'].textContent = ui.feedback.value;
      ui['goal-summary'].textContent = GOALS[state.goal].title + ' · Preserve behavior · No dependency or test changes';
      ui['scope-summary'].textContent = state.files.size + ' source file' + (state.files.size === 1 ? '' : 's') +
        ' · up to ' + ui['max-lines'].value + ' changed lines · ' + state.context.size + ' read-only context files';
      ui['suggested-files'].replaceChildren();
      state.files.forEach(function (path) { ui['suggested-files'].appendChild(element('li', 'refactor-scope-file', path + ' — may be simplified')); });
      state.context.forEach(function (path) { ui['suggested-files'].appendChild(element('li', 'refactor-scope-file', path + ' — read only')); });
      if (!state.files.size) ui['suggested-files'].appendChild(element('li', '', 'No eligible source file is selected. Choose another repo or use optional customization.'));
    }
    function updateControls() {
      const busy = Boolean(state.request) || state.connecting;
      ui.settings.disabled = busy;
      root.setAttribute('aria-busy', String(busy));
      ui['open-btn'].disabled = busy;
      updateLoadControl();
      ui['goal-next-btn'].disabled = busy || !state.listing;
      Object.keys(GOALS).forEach(function (goal) {
        ui['goal-' + goal].disabled = busy;
        ui['goal-' + goal].setAttribute('aria-pressed', String(goal === state.goal));
      });
      ui['generate-btn'].disabled = busy || Boolean(generationError(false));
      ['scope-back-btn', 'review-back-btn', 'reject-btn', 'new-btn', 'clear-feedback-btn'].forEach(function (id) { ui[id].disabled = busy; });
      ['regenerate-btn', 'smaller-btn', 'inline-btn'].forEach(function (id) { ui[id].disabled = busy || !state.proposal || state.published; });
      ui['selected-count'].textContent = state.files.size + ' / ' + ui['max-files'].value + ' selected';
      ui['context-count'].textContent = state.context.size + ' / 3 selected; never edited';
      state.choices.forEach(function (choice, path) {
        choice.edit.checked = state.files.has(path);
        choice.context.checked = state.context.has(path);
        choice.edit.disabled = !choice.editable || busy || state.context.has(path) || (!state.files.has(path) && state.files.size >= Number(ui['max-files'].value));
        choice.context.disabled = busy || state.files.has(path) || (!state.context.has(path) && state.context.size >= 3);
      });
      state.editors.forEach(function (editor) { editor.input.disabled = busy || state.published; editor.button.disabled = busy || state.published; });
      ui['review-next-btn'].disabled = busy || !currentReview();
      ui['publish-btn'].disabled = busy || !currentReview() || !state.reviewAccepted;
      if (state.proposal) {
        const metrics = reviewMetrics();
        ui['no-changes'].hidden = metrics.hasChanges;
        ui['no-changes'].textContent = state.proposal.edits.length ? 'No code changes remain. Nothing to publish.' :
          'No worthwhile change was found in this scope. Nothing was changed. You can try another approach or discard this proposal.';
        ui['changed-lines'].textContent = (metrics.overLimit ? 'More than ' + metrics.limit : metrics.count) + ' changed lines / ' + metrics.limit + ' allowed' +
          (state.manuallyEdited ? ' (local estimate; the server rechecks on publish).' : ' (reported by the server).');
        ui['changed-lines'].classList.toggle('is-error', metrics.overLimit);
      }
      renderScope();
    }
    function invalidateProposal(message) {
      cancelRequest();
      clearProposal();
      state.consent = false;
      setStage('scope', false);
      status(message || 'Your scope changed. Confirm it again before generating.');
      updateControls();
    }
    function isCurrent(request) {
      syncIdentity();
      if (state.request !== request) return false;
      if (request.scope && request.scope !== scopeKey(getScope(), state.goal)) {
        invalidateProposal('The scope changed during the request. Confirm the new scope.');
        return false;
      }
      return true;
    }
    async function requestJSON(kind, body, accept) {
      const request = {
        kind: kind, returnStage: kind === 'publish' ? 'publish' : kind === 'load' ? 'goal' : 'scope',
        controller: new win.AbortController(), scope: kind === 'load' ? null : scopeKey(getScope(), state.goal),
        timedOut: false, timer: null
      };
      state.request = request;
      request.timer = win.setTimeout(function () { request.timedOut = true; request.controller.abort(); }, REQUEST_TIMEOUT_MS);
      if (kind !== 'load') {
        ui['working-heading'].textContent = kind === 'publish' ? 'Opening your draft…' : 'Looking for a small improvement…';
        ui['working-message'].textContent = kind === 'publish' ? 'Creating or recovering the reviewed branch and draft PR. Nothing will be merged.' :
          'Gemini is reviewing the confirmed files. Tests are not running and your repository is unchanged.';
        setStage('working');
      }
      updateControls();
      try {
        const options = { method: body ? 'POST' : 'GET', headers: { Accept: 'application/json', 'X-GitHub-Token': state.token },
          signal: request.controller.signal, cache: 'no-store', credentials: 'same-origin' };
        if (body) { options.headers['Content-Type'] = 'application/json'; options.body = JSON.stringify(body); }
        const response = await win.fetch('/api/refactor' + (body ? '' : '?repo=' + encodeURIComponent(state.repo)), options);
        if (!isCurrent(request)) return;
        let data;
        try { data = await response.json(); } catch (_) { throw new Error('The server did not return valid JSON. Please try again.'); }
        if (!isCurrent(request)) return;
        if (request.timedOut) throw new Error('Request timed out.');
        if (!response.ok) {
          const message = data && typeof data.error === 'string' ? data.error : 'Refactor request failed (HTTP ' + response.status + ').';
          if (response.status === 401) {
            clearRepository();
            state.authRequired = true;
            status('Your GitHub access has expired or was revoked. Reconnect below to continue.' +
              (kind === 'publish' ? ' Check GitHub for an existing draft before trying again.' : ''), true);
            updateControls();
            return;
          }
          throw new Error(message);
        }
        accept(data);
      } catch (error) {
        if (!isCurrent(request)) return;
        setStage(request.returnStage);
        const message = request.timedOut ? 'The request timed out after 55 seconds.' : error instanceof Error ? error.message : 'The refactor request failed.';
        status(message + (kind === 'publish' ? ' Check GitHub before retrying. Approve again to recover or open the same reviewed draft.' :
          kind === 'propose' ? ' If the repository changed, use Refresh repository files to get a new scope.' : ''), true);
      } finally {
        win.clearTimeout(request.timer);
        if (state.request === request) { state.request = null; updateControls(); }
      }
    }
    function renderFileLists() {
      ui.files.replaceChildren();
      ui['context-files'].replaceChildren();
      state.choices.clear();
      state.listing.files.forEach(function (file) {
        const choice = { editable: file.editable };
        ['edit', 'context'].forEach(function (kind) {
          const label = element('label', 'refactor-file-choice');
          const input = element('input');
          input.type = 'checkbox';
          const description = element('span', '', file.path + (kind === 'edit' && !file.editable ? ' (read only)' : ''));
          description.appendChild(element('small', 'refactor-file-size', file.size.toLocaleString() + ' bytes'));
          label.appendChild(input);
          label.appendChild(description);
          (kind === 'edit' ? ui.files : ui['context-files']).appendChild(label);
          choice[kind] = input;
          input.addEventListener('change', function () {
            if (syncIdentity() || state.request) return;
            const selected = kind === 'edit' ? state.files : state.context;
            const other = kind === 'edit' ? state.context : state.files;
            const max = kind === 'edit' ? Number(ui['max-files'].value) : 3;
            if (input.checked && ((kind === 'edit' && !file.editable) || other.has(file.path) || (!selected.has(file.path) && selected.size >= max))) {
              input.checked = false;
              status('This selection exceeds the scope limit or overlaps with read-only context.', true);
              return;
            }
            if (input.checked) selected.add(file.path); else selected.delete(file.path);
            invalidateProposal();
          });
        });
        state.choices.set(file.path, choice);
      });
    }
    function loadFiles() {
      syncIdentity();
      if (state.request) return;
      if (!state.repo || !state.token || state.authRequired) {
        status(!state.repo ? 'Go back and choose a repository.' : 'Connect GitHub below to load this repository.', true);
        updateControls();
        return;
      }
      clearProposal();
      clearFeedback();
      state.listing = null;
      state.files.clear();
      state.context.clear();
      state.choices.clear();
      state.consent = false;
      ui.files.replaceChildren();
      ui['context-files'].replaceChildren();
      ui.base.textContent = '';
      setStage('goal', false);
      status('Loading repository metadata and rules. No source is being sent to Gemini.');
      requestJSON('load', null, function (data) {
        state.listing = validateListing(data, state.repo);
        if (!state.rulesDirty) ui.rules.value = !state.listing.rules || !state.listing.rules.trim() ? DEFAULT_RULES : state.listing.rules;
        state.files = new Set(suggestFiles(state.listing.files));
        ui.base.textContent = 'Branch: ' + state.listing.branch + ' · Listed commit: ' + state.listing.commit_sha;
        ui['file-notice'].textContent = state.listing.files.length + ' eligible files listed.' +
          (state.listing.truncated ? ' This list is truncated; suggestions use only the listed files.' : '');
        renderFileLists();
        status(state.files.size ? 'Ready. Choose a goal or continue with a quick cleanup.' : 'No non-empty editable files were found. Try another repository.');
      });
    }
    function renderProposal() {
      const proposal = state.proposal;
      ['summary', 'rule', 'tradeoffs'].forEach(function (key) { ui[key].textContent = proposal[key]; });
      ui.edits.replaceChildren();
      state.editors = [];
      proposal.edits.forEach(function (edit, index) {
        const card = element('section', 'refactor-edit-card');
        card.appendChild(element('h3', 'refactor-file-title', edit.path));
        const columns = element('div', 'refactor-diff');
        const originalColumn = element('div');
        const originalLabel = element('h4', 'refactor-label', 'BEFORE');
        originalLabel.id = 'refactor-original-label-' + index;
        const original = element('pre', 'refactor-code', state.originals.get(edit.path));
        original.tabIndex = 0;
        original.setAttribute('aria-labelledby', originalLabel.id);
        originalColumn.appendChild(originalLabel);
        originalColumn.appendChild(original);
        const afterColumn = element('div');
        const afterLabel = element('h4', 'refactor-label', 'PROPOSED');
        afterLabel.id = 'refactor-after-label-' + index;
        const preview = element('pre', 'refactor-code', edit.content);
        preview.tabIndex = 0;
        preview.setAttribute('aria-labelledby', afterLabel.id);
        const input = element('textarea', 'refactor-code');
        input.id = 'refactor-replacement-' + index;
        input.setAttribute('aria-label', 'Edit proposed replacement for ' + edit.path);
        input.value = edit.content;
        input.hidden = true;
        input.spellcheck = false;
        input.wrap = 'off';
        input.setAttribute('autocapitalize', 'off');
        input.setAttribute('autocomplete', 'off');
        const button = element('button', 'pixel-btn pixel-btn-sm refactor-edit-btn', 'EDIT THIS CHANGE');
        button.type = 'button';
        button.setAttribute('aria-controls', input.id);
        button.setAttribute('aria-expanded', 'false');
        button.addEventListener('click', function () {
          if (syncIdentity() || state.request || state.published || state.proposal !== proposal) return;
          input.hidden = !input.hidden;
          preview.hidden = !input.hidden;
          button.textContent = input.hidden ? 'EDIT THIS CHANGE' : 'DONE EDITING';
          button.setAttribute('aria-expanded', String(!input.hidden));
          if (!input.hidden) input.focus();
        });
        input.addEventListener('input', function () {
          if (syncIdentity() || state.request || state.proposal !== proposal || state.published) return;
          edit.content = input.value;
          preview.textContent = input.value;
          state.manuallyEdited = true;
          state.reviewAccepted = false;
          setStage('review', false);
          status('Change updated. Review it before continuing.');
          updateControls();
        });
        state.editors.push({ input: input, button: button });
        afterColumn.appendChild(afterLabel);
        afterColumn.appendChild(preview);
        afterColumn.appendChild(input);
        afterColumn.appendChild(button);
        columns.appendChild(originalColumn);
        columns.appendChild(afterColumn);
        card.appendChild(columns);
        ui.edits.appendChild(card);
      });
      setStage('review');
    }
    function generate() {
      syncIdentity();
      if (state.request || state.stage !== 'scope') return;
      const error = generationError(false);
      if (error) { status(error, true); return; }
      // This explicitly labelled action consents to the visible, fully listed scope.
      state.consent = true;
      const scope = getScope();
      const goal = state.goal;
      clearProposal();
      status('Generating an unverified proposal for the confirmed scope.');
      requestJSON('propose', Object.assign({ action: 'propose', feedback: getFeedback() }, scope), function (data) {
        const result = validateProposalResponse(data, scope);
        state.proposal = result.proposal;
        state.originals = result.originals;
        state.reviewToken = result.reviewToken;
        state.changedLines = result.changedLines;
        state.proposalKey = scopeKey(scope, goal);
        ui['proposal-base'].textContent = 'Review base: ' + result.branch + ' · Commit: ' + result.commit;
        renderProposal();
        status(state.proposal.edits.length ? 'Review the change. Nothing has been published.' : 'No worthwhile change was proposed. Your repository is unchanged.');
      });
    }
    function reviewNext() {
      if (syncIdentity() || state.request || state.stage !== 'review' || !currentReview()) return;
      state.reviewAccepted = true;
      const edits = changedEdits();
      ui['publish-summary'].textContent = edits.length + ' file' + (edits.length === 1 ? '' : 's') + ' in ' + state.repo + '. ' + state.proposal.summary;
      ui['publish-files'].replaceChildren();
      edits.forEach(function (edit) { ui['publish-files'].appendChild(element('li', 'refactor-scope-file', edit.path)); });
      setStage('publish');
      status('One last confirmation. This opens a draft; it does not merge anything.');
      updateControls();
    }
    function publish() {
      if (syncIdentity() || state.request || state.stage !== 'publish') return;
      if (!currentReview() || !state.reviewAccepted) { status('Review a current, in-scope change before opening a draft PR.', true); return; }
      const proposal = { summary: state.proposal.summary, rule: state.proposal.rule, tradeoffs: state.proposal.tradeoffs,
        edits: changedEdits().map(function (edit) { return { path: edit.path, content: edit.content }; }) };
      status('Opening the approved draft PR. Tests are not being run.');
      requestJSON('publish', { action: 'publish', review_token: state.reviewToken, proposal: proposal, approved: true }, function (data) {
        const url = data && safePullRequestUrl(data.url);
        if (!url || data.draft !== true || data.validation !== 'unverified' || typeof data.branch !== 'string' || !data.branch) {
          throw new Error('The server returned an invalid draft PR response. No untrusted link was displayed.');
        }
        state.published = true;
        state.reviewToken = '';
        ui.published.replaceChildren();
        ui.published.appendChild(element('p', 'refactor-help', 'Branch: ' + data.branch + '. UNVERIFIED — tests have not run.'));
        const link = element('a', 'pixel-btn pixel-btn-primary', 'VIEW DRAFT PR ON GITHUB');
        link.href = url;
        link.target = '_blank';
        link.rel = 'noopener noreferrer';
        ui.published.appendChild(link);
        setStage('done');
        status('Draft ready. Use your normal CI and review before merging.');
      });
    }
    function revise(feedback) {
      if (syncIdentity() || state.request || !state.proposal || state.published) return;
      if (feedback) ui.feedback.value = feedback;
      if (byteLength(getFeedback()) > 8000) {
        status('Shorten the optional feedback; the goal and feedback must fit within 8,000 UTF-8 bytes.', true);
        return;
      }
      invalidateProposal('Ready for another approach. Confirm the scope to generate again.');
      setStage('scope');
    }

    win.buzzOpenRefactor = function () {
      syncIdentity();
      win.buzzGoToStep(5);
      ui.heading.focus();
      if (state.repo && state.token && !state.authRequired && !state.listing && !state.request) loadFiles();
    };
    Object.keys(GOALS).forEach(function (goal) {
      ui['goal-' + goal].addEventListener('click', function () {
        if (syncIdentity() || state.request || state.stage !== 'goal') return;
        if (state.goal !== goal) { clearProposal(); clearFeedback(); state.consent = false; state.goal = goal; }
        updateControls();
      });
    });
    ui['goal-next-btn'].addEventListener('click', function () {
      if (syncIdentity() || state.request || !state.listing || state.stage !== 'goal') return;
      setStage('scope');
      status('Confirm this small scope. Customization is optional.');
      updateControls();
    });
    ui['scope-back-btn'].addEventListener('click', function () { if (!state.request) setStage('goal'); });
    ui['review-back-btn'].addEventListener('click', function () { if (!state.request && state.proposal) { state.reviewAccepted = false; setStage('review'); updateControls(); } });
    ui['back-btn'].addEventListener('click', function () { clearAuthReturn(); win.buzzGoToStep(2); });
    ui['connect-btn'].addEventListener('click', connectGitHub);
    ui['load-btn'].addEventListener('click', loadFiles);
    ui['generate-btn'].addEventListener('click', generate);
    ui['review-next-btn'].addEventListener('click', reviewNext);
    ui['publish-btn'].addEventListener('click', publish);
    ui['regenerate-btn'].addEventListener('click', function () { revise(); });
    ui['smaller-btn'].addEventListener('click', function () { revise('Make a smaller change. Keep the same behavior and focus on just one local simplification.'); });
    ui['inline-btn'].addEventListener('click', function () { revise('Keep the logic inline. Avoid introducing new helpers or extra call layers.'); });
    ui['reject-btn'].addEventListener('click', function () {
      if (syncIdentity() || state.request) return;
      clearFeedback();
      invalidateProposal('Proposal discarded. Nothing was published.');
      setStage('goal');
    });
    ui['clear-feedback-btn'].addEventListener('click', function () {
      if (syncIdentity() || state.request || state.stage !== 'scope') return;
      clearFeedback();
      invalidateProposal('Revision feedback removed. Confirm this scope to start a fresh proposal.');
    });
    ui['new-btn'].addEventListener('click', loadFiles);
    ui['cancel-btn'].addEventListener('click', function () {
      const request = cancelRequest();
      if (!request) return;
      setStage(request.returnStage);
      status(request.kind === 'publish' ? 'Stopped waiting. GitHub may already have created the draft; check before retrying.' : 'Stopped waiting. No repository changes were made.');
      updateControls();
    });
    ui.feedback.addEventListener('input', function () {
      syncIdentity();
      state.reviewAccepted = false;
      updateControls();
      if (byteLength(getFeedback()) > 8000) status('Shorten the optional feedback; the goal and feedback must fit within 8,000 UTF-8 bytes.', true);
    });
    ['rules', 'max-files', 'max-lines'].forEach(function (id) {
      ui[id].addEventListener('input', function () {
        if (syncIdentity()) return;
        if (id === 'rules') state.rulesDirty = true;
        invalidateProposal();
        const error = generationError(false);
        if (error) status(error, true);
      });
    });
    repoInput.addEventListener('input', syncIdentity);
    repoInput.addEventListener('change', syncIdentity);
    win.addEventListener('buzz:auth-change', authChanged);
    win.addEventListener('storage', function (event) { if (!event.key || event.key === 'buzz_gh_token') authChanged(); });
    win.addEventListener('focus', authChanged);
    win.addEventListener('pageshow', authChanged);
    doc.addEventListener('visibilitychange', authChanged);
    win.addEventListener('buzz:step-change', function (event) {
      syncIdentity();
      if (event.detail.step !== 5 && state.request) {
        const request = cancelRequest();
        setStage(request.returnStage, false);
        status(request.kind === 'publish' ? 'Stopped waiting for publication. Check GitHub before retrying.' : 'Request cancelled. You can continue when ready.');
        updateControls();
      }
    });
    win.addEventListener('pagehide', function () { clearRepository(); updateControls(); });
    syncIdentity();
    resumeAfterAuth();
  }

  return {
    normalizeRepo: normalizeRepo, validateScope: validateScope, scopeKey: scopeKey,
    safePullRequestUrl: safePullRequestUrl, countChangedLines: countChangedLines,
    validateListing: validateListing, validateProposalResponse: validateProposalResponse,
    suggestFiles: suggestFiles, mountRefactor: mountRefactor
  };
});
