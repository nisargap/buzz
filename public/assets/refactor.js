(function (root, factory) {
  'use strict';
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  if (root && root.document) api.mountRefactor(root);
})(typeof window === 'undefined' ? null : window, function () {
  'use strict';

  const REQUEST_TIMEOUT_MS = 55000;
  const DEFAULT_RULES = '# Refactor rules\n\n- Preserve behavior, public interfaces, errors, and side effects.\n- Follow the repository\'s existing conventions.\n- Prefer one small, worthwhile simplification over a rewrite.\n- Do not change dependencies, configuration, or tests.\n- If context is insufficient or no change is worthwhile, propose no edits.';

  function normalizeRepo(value) {
    const repo = String(value || '').trim()
      .replace(/^https?:\/\/github\.com\//i, '')
      .replace(/^github\.com\//i, '')
      .replace(/^\/+|\/+$/g, '')
      .replace(/\.git$/i, '');
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

  // Feedback and replacement contents are deliberately not part of the scope.
  function scopeKey(scope) {
    return JSON.stringify([
      scope.repo, scope.rules, scope.max_files, scope.max_changed_lines,
      scope.files.slice().sort(), scope.context_files.slice().sort(), scope.consent
    ]);
  }

  function safePullRequestUrl(value) {
    if (typeof value !== 'string') return null;
    try {
      const url = new URL(value);
      if (url.protocol !== 'https:' || url.hostname !== 'github.com' || url.port || url.username || url.password ||
          !/^\/[a-z0-9-]+\/[a-z0-9._-]+\/pull\/[1-9][0-9]*\/?$/i.test(url.pathname)) return null;
      return url.href;
    } catch (_) {
      return null;
    }
  }

  // Bounded Myers line distance: additions + deletions, not a claim of validation.
  // Keep line terminators so a trailing-newline change is counted too.
  // A result of limit + 1 means "over limit", not an exact count.
  function countChangedLines(before, after, limit) {
    if (before === after) return 0;
    const a = before.match(/[^\n]*\n|[^\n]+$/g) || [];
    const b = after.match(/[^\n]*\n|[^\n]+$/g) || [];
    let start = 0;
    while (start < a.length && start < b.length && a[start] === b[start]) start += 1;
    let aEnd = a.length;
    let bEnd = b.length;
    while (aEnd > start && bEnd > start && a[aEnd - 1] === b[bEnd - 1]) {
      aEnd -= 1;
      bEnd -= 1;
    }
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
        while (x < n && y < m && a[start + x] === b[start + y]) {
          x += 1;
          y += 1;
        }
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
      throw new Error('The server returned an invalid file list. Reload the list before continuing.');
    }
    const seen = new Set();
    const files = data.files.map(function (file) {
      if (!file || typeof file.path !== 'string' || !file.path || seen.has(file.path) ||
          !Number.isSafeInteger(file.size) || file.size < 0) {
        throw new Error('The server returned an invalid or duplicate file entry.');
      }
      seen.add(file.path);
      return { path: file.path, size: file.size, editable: file.editable !== false };
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
      originals: originals,
      reviewToken: data.review_token,
      changedLines: data.changed_lines,
      branch: data.branch,
      commit: data.commit_sha
    };
  }

  function mountRefactor(win) {
    const doc = win.document;
    const root = doc.getElementById('wizard-step-5');
    const repoInput = doc.getElementById('repo-input');
    if (!root || !repoInput) return;
    const ui = {};
    [
      'open-btn', 'back-btn', 'load-btn', 'repo', 'base', 'status', 'settings', 'rules', 'max-files', 'max-lines',
      'file-notice', 'selected-count', 'context-count', 'files', 'context-files', 'feedback', 'consent', 'generate-btn',
      'review', 'review-heading', 'proposal-base', 'summary', 'rule', 'tradeoffs', 'no-changes', 'changed-lines',
      'edits', 'regenerate-btn', 'reject-btn', 'publish-controls', 'approve', 'publish-btn', 'published', 'heading'
    ].forEach(function (id) { ui[id] = doc.getElementById('refactor-' + id); });

    const state = {
      sourceValue: null, repo: '', token: '', listing: null, files: new Set(), context: new Set(),
      choices: new Map(), editors: [], rulesDirty: false, proposal: null, originals: new Map(),
      reviewToken: '', proposalKey: '', changedLines: 0, manuallyEdited: false, published: false, request: null
    };

    function readToken() {
      try { return win.sessionStorage.getItem('buzz_gh_token') || ''; } catch (_) { return ''; }
    }

    function status(message, isError) {
      ui.status.textContent = message;
      ui.status.classList.toggle('is-error', Boolean(isError));
    }

    function cancelRequest() {
      const request = state.request;
      state.request = null;
      if (request) {
        win.clearTimeout(request.timer);
        request.controller.abort();
      }
    }

    function clearProposal() {
      state.proposal = null;
      state.originals.clear();
      state.reviewToken = '';
      state.proposalKey = '';
      state.changedLines = 0;
      state.manuallyEdited = false;
      state.published = false;
      state.editors = [];
      ui.approve.checked = false;
      ui.review.hidden = true;
      ui['publish-controls'].hidden = true;
      ui.published.hidden = true;
      ui.published.replaceChildren();
      ui.edits.replaceChildren();
      ['summary', 'rule', 'tradeoffs', 'proposal-base', 'changed-lines'].forEach(function (id) { ui[id].textContent = ''; });
    }

    function clearRepository() {
      cancelRequest();
      clearProposal();
      state.listing = null;
      state.files.clear();
      state.context.clear();
      state.choices.clear();
      state.rulesDirty = false;
      ui.rules.value = '';
      ui.feedback.value = '';
      ui.consent.checked = false;
      ui.files.replaceChildren();
      ui['context-files'].replaceChildren();
      ui.base.textContent = '';
      ui['file-notice'].textContent = 'Load the file list to select editable source files and optional read-only context.';
    }

    // Check both at every action and after every await. Programmatic repo changes
    // and token changes in this tab cannot make an old response current again.
    function syncIdentity() {
      const sourceValue = repoInput.value.trim();
      const token = readToken();
      if (sourceValue === state.sourceValue && token === state.token) return false;
      const authChanged = token !== state.token;
      clearRepository();
      state.sourceValue = sourceValue;
      state.repo = normalizeRepo(sourceValue);
      state.token = token;
      ui.repo.textContent = state.repo || sourceValue || 'No repository selected';
      status(!token ? 'Use Back to sign in with GitHub using the existing Buzz connection.' :
        !state.repo ? 'Use Back to choose a valid owner/repo in the existing repository field.' :
        authChanged ? 'GitHub session changed. Load the file list to start a new review.' :
          'Load the file list for this repository. Previous proposals have been cleared.', !token || !state.repo);
      updateControls();
      return true;
    }

    function getScope() {
      return {
        repo: state.repo,
        files: Array.from(state.files),
        context_files: Array.from(state.context),
        rules: ui.rules.value,
        max_files: Number(ui['max-files'].value),
        max_changed_lines: Number(ui['max-lines'].value),
        consent: ui.consent.checked
      };
    }

    function generationError() {
      if (!state.token) return 'Use Back to sign in with GitHub first.';
      if (!state.repo) return 'Use Back to select a valid repository first.';
      if (!state.listing) return 'Load the repository file list first.';
      try { validateScope(getScope()); } catch (error) { return error.message; }
      if (!ui.rules.value.trim()) return 'Enter Markdown refactor rules before generating.';
      if (!ui.consent.checked) return 'Consent is required before sending the selected code to Gemini.';
      return '';
    }

    function changedEdits() {
      return state.proposal ? state.proposal.edits.filter(function (edit) {
        return edit.content !== state.originals.get(edit.path);
      }) : [];
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

    function updateControls() {
      const busy = Boolean(state.request);
      ui.settings.disabled = busy;
      root.setAttribute('aria-busy', String(busy));
      ui['open-btn'].disabled = busy;
      ui['load-btn'].disabled = busy || !state.repo || !state.token;
      ui['generate-btn'].disabled = busy || Boolean(generationError());
      ui['regenerate-btn'].disabled = busy || Boolean(generationError());
      ui['reject-btn'].disabled = busy;
      ui['selected-count'].textContent = state.files.size + ' / ' + ui['max-files'].value + ' selected';
      ui['context-count'].textContent = state.context.size + ' / 3 selected; never edited';
      state.choices.forEach(function (choice, path) {
        choice.edit.checked = state.files.has(path);
        choice.context.checked = state.context.has(path);
        choice.edit.disabled = !choice.editable || busy || state.context.has(path) || (!state.files.has(path) && state.files.size >= Number(ui['max-files'].value));
        choice.context.disabled = busy || state.files.has(path) || (!state.context.has(path) && state.context.size >= 3);
      });
      state.editors.forEach(function (editor) { editor.disabled = busy || state.published; });
      const metrics = reviewMetrics();
      const canPublish = Boolean(state.proposal && state.reviewToken && !state.published && metrics.hasChanges &&
        !metrics.overLimit && !generationError() && state.proposalKey === scopeKey(getScope()));
      ui['publish-controls'].hidden = !state.proposal || !metrics.hasChanges || state.published;
      ui.approve.disabled = busy || !canPublish;
      ui['publish-btn'].disabled = busy || !canPublish || !ui.approve.checked;
      if (state.proposal) {
        ui['no-changes'].hidden = metrics.hasChanges;
        ui['no-changes'].textContent = state.proposal.edits.length ?
          'No code changes remain. No draft PR can be opened.' : 'No worthwhile change was proposed. No draft PR can be opened.';
        ui['changed-lines'].textContent = (metrics.overLimit ? 'More than ' + metrics.limit : metrics.count) +
          ' changed lines / ' + metrics.limit + ' allowed' +
          (state.manuallyEdited ? ' (local estimate; the server rechecks on publish).' : ' (reported by the server).') +
          (metrics.overLimit ? ' Reduce the replacement changes before approving.' : '');
        ui['changed-lines'].classList.toggle('is-error', metrics.overLimit);
      }
    }

    function invalidateProposal(message) {
      cancelRequest();
      clearProposal();
      status(message || 'Rules or scope changed. Generate a new proposal before approving.');
      updateControls();
    }

    function isCurrent(request) {
      syncIdentity();
      if (state.request !== request) return false;
      if (request.scope && request.scope !== scopeKey(getScope())) {
        invalidateProposal('The scope changed during the request. Generate again.');
        return false;
      }
      return true;
    }

    async function requestJSON(kind, body, accept) {
      const request = {
        controller: new win.AbortController(),
        scope: kind === 'load' ? null : scopeKey(getScope()),
        timedOut: false,
        serverRejected: false,
        timer: null
      };
      state.request = request;
      request.timer = win.setTimeout(function () {
        request.timedOut = true;
        request.controller.abort();
      }, REQUEST_TIMEOUT_MS);
      updateControls();
      try {
        const options = {
          method: body ? 'POST' : 'GET',
          headers: { Accept: 'application/json', 'X-GitHub-Token': state.token },
          signal: request.controller.signal,
          cache: 'no-store',
          credentials: 'same-origin'
        };
        if (body) {
          options.headers['Content-Type'] = 'application/json';
          options.body = JSON.stringify(body);
        }
        const response = await win.fetch('/api/refactor' + (body ? '' : '?repo=' + encodeURIComponent(state.repo)), options);
        if (!isCurrent(request)) return;
        let data;
        try { data = await response.json(); } catch (_) { throw new Error('The server did not return valid JSON. Please try again.'); }
        if (!isCurrent(request)) return;
        if (request.timedOut) throw new Error('Request timed out.');
        if (!response.ok) {
          request.serverRejected = true;
          const message = data && typeof data.error === 'string' ? data.error : 'Refactor request failed (HTTP ' + response.status + ').';
          if (response.status === 401) {
            clearRepository();
            status(message + ' Use Back to reconnect with the existing GitHub login.', true);
            updateControls();
            return;
          }
          throw new Error(message);
        }
        accept(data);
      } catch (error) {
        if (!isCurrent(request)) return;
        ui.approve.checked = false;
        const message = request.timedOut ? 'The request timed out after 55 seconds.' :
          error instanceof Error ? error.message : 'The refactor request failed.';
        status(message + (kind === 'publish' ? request.serverRejected ?
          ' The server rejected publishing. Review the error and generate a fresh proposal if the base is stale. Approval has been cleared.' :
          ' Publishing may have completed; check GitHub before retrying. Approval has been cleared.' : ''), true);
      } finally {
        win.clearTimeout(request.timer);
        if (state.request === request) {
          state.request = null;
          updateControls();
        }
      }
    }

    function element(tag, className, text) {
      const node = doc.createElement(tag);
      if (className) node.className = className;
      if (text !== undefined) node.textContent = text;
      return node;
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
          const description = element('span', '', file.path + (kind === 'edit' && !file.editable ? ' (read-only context)' : ''));
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
            if (input.checked && ((kind === 'edit' && !file.editable) || other.has(file.path) || selected.size >= max)) {
              input.checked = false;
              status('This selection exceeds the scope limit or overlaps with read-only context.', true);
              return;
            }
            if (input.checked) selected.add(file.path); else selected.delete(file.path);
            ui.consent.checked = false;
            invalidateProposal('File selection changed. Review the selection and consent before generating.');
          });
        });
        state.choices.set(file.path, choice);
      });
    }

    function loadFiles() {
      syncIdentity();
      if (state.request) return;
      if (!state.repo || !state.token) {
        status('Use Back to select a repository and sign in with the existing GitHub connection.', true);
        return;
      }
      clearProposal();
      state.listing = null;
      state.files.clear();
      state.context.clear();
      state.choices.clear();
      ui.files.replaceChildren();
      ui['context-files'].replaceChildren();
      ui.consent.checked = false;
      ui.base.textContent = '';
      ui['file-notice'].textContent = 'Loading repository file metadata...';
      status('Loading the file list and repository rules...');
      requestJSON('load', null, function (data) {
        state.listing = validateListing(data, state.repo);
        if (!state.rulesDirty) ui.rules.value = state.listing.rules === null ? DEFAULT_RULES : state.listing.rules;
        ui.base.textContent = 'Default branch: ' + state.listing.branch + ' | Listed commit: ' + state.listing.commit_sha;
        ui['file-notice'].textContent = state.listing.files.length + ' files available.' +
          (state.listing.truncated ? ' This repository list is truncated; only the files shown can be selected.' : '') +
          ' Editable files and read-only context cannot overlap.';
        renderFileLists();
        status(state.listing.files.length ? 'Review the Markdown rules, select files, and consent to generate.' : 'No eligible files were returned for this repository.');
      });
    }

    function renderProposal() {
      const proposal = state.proposal;
      ui.review.hidden = false;
      ['summary', 'rule', 'tradeoffs'].forEach(function (key) { ui[key].textContent = proposal[key]; });
      ui.edits.replaceChildren();
      state.editors = [];
      proposal.edits.forEach(function (edit, index) {
        const card = element('section', 'refactor-edit-card');
        card.appendChild(element('h3', 'refactor-file-title', edit.path));
        const columns = element('div', 'refactor-diff');
        const originalColumn = element('div');
        const originalLabel = element('h4', 'refactor-label', 'ORIGINAL (READ ONLY)');
        originalLabel.id = 'refactor-original-label-' + index;
        const original = element('pre', 'refactor-code', state.originals.get(edit.path));
        original.tabIndex = 0;
        original.setAttribute('aria-labelledby', originalLabel.id);
        originalColumn.appendChild(originalLabel);
        originalColumn.appendChild(original);
        const replacementColumn = element('div');
        const replacementLabel = element('label', 'refactor-label', 'PROPOSED (EDITABLE)');
        replacementLabel.htmlFor = 'refactor-replacement-' + index;
        const replacement = element('textarea', 'refactor-code');
        replacement.id = replacementLabel.htmlFor;
        replacement.value = edit.content;
        replacement.spellcheck = false;
        replacement.wrap = 'off';
        replacement.setAttribute('autocapitalize', 'off');
        replacement.setAttribute('autocomplete', 'off');
        replacement.addEventListener('input', function () {
          if (syncIdentity() || state.request || state.proposal !== proposal || state.published) return;
          edit.content = replacement.value;
          state.manuallyEdited = true;
          ui.approve.checked = false;
          status('Replacement edited. Review the changed code and approve again before publishing.');
          updateControls();
        });
        state.editors.push(replacement);
        replacementColumn.appendChild(replacementLabel);
        replacementColumn.appendChild(replacement);
        columns.appendChild(originalColumn);
        columns.appendChild(replacementColumn);
        card.appendChild(columns);
        ui.edits.appendChild(card);
      });
      ui['review-heading'].focus();
    }

    function generate() {
      syncIdentity();
      if (state.request) return;
      const error = generationError();
      if (error) { status(error, true); return; }
      const scope = getScope();
      clearProposal();
      status('Sending only the selected scope and guidance to Gemini. Generating an unverified proposal...');
      requestJSON('propose', Object.assign({ action: 'propose', feedback: ui.feedback.value }, scope), function (data) {
        const result = validateProposalResponse(data, scope);
        state.proposal = result.proposal;
        state.originals = result.originals;
        state.reviewToken = result.reviewToken;
        state.changedLines = result.changedLines;
        state.proposalKey = scopeKey(scope);
        ui['proposal-base'].textContent = 'Review base: ' + result.branch + ' | Commit: ' + result.commit;
        renderProposal();
        status(state.proposal.edits.length ? 'Proposal ready for review. Tests have not run. No draft PR has been requested.' :
          'No worthwhile change was proposed. Adjust the scope or feedback if needed; no PR can be opened.');
      });
    }

    function publish() {
      syncIdentity();
      if (state.request) return;
      if (state.proposal && state.proposalKey !== scopeKey(getScope())) {
        invalidateProposal('The review scope changed. Generate a fresh proposal before approving.');
        return;
      }
      const metrics = reviewMetrics();
      if (!state.proposal || !state.reviewToken || state.published || generationError() || !metrics.hasChanges || metrics.overLimit || !ui.approve.checked) {
        status('Review a current, in-scope proposal and check the approval box before opening a draft PR.', true);
        return;
      }
      const proposal = {
        summary: state.proposal.summary, rule: state.proposal.rule, tradeoffs: state.proposal.tradeoffs,
        edits: changedEdits().map(function (edit) { return { path: edit.path, content: edit.content }; })
      };
      ui.approve.checked = false;
      status('Opening the explicitly approved draft PR. Tests are not being run.');
      requestJSON('publish', { action: 'publish', review_token: state.reviewToken, proposal: proposal, approved: true }, function (data) {
        const url = data && safePullRequestUrl(data.url);
        if (!url || data.draft !== true || data.validation !== 'unverified' || typeof data.branch !== 'string' || !data.branch) {
          throw new Error('The server returned an invalid draft PR response. No untrusted link was displayed.');
        }
        state.published = true;
        state.reviewToken = '';
        ui.published.replaceChildren();
        ui.published.appendChild(element('p', 'refactor-help', 'Draft PR opened on branch ' + data.branch + '. UNVERIFIED — tests have not run.'));
        const link = element('a', '', 'VIEW DRAFT PR ON GITHUB');
        link.href = url;
        link.target = '_blank';
        link.rel = 'noopener noreferrer';
        ui.published.appendChild(link);
        ui.published.hidden = false;
        status('Draft PR opened. UNVERIFIED — tests have not run; review and test it on GitHub before merging.');
      });
    }

    win.buzzOpenRefactor = function () {
      syncIdentity();
      win.buzzGoToStep(5);
      ui.heading.focus();
      if (state.repo && state.token && !state.listing && !state.request) loadFiles();
    };
    ui['back-btn'].addEventListener('click', function () { win.buzzGoToStep(2); });
    ui['load-btn'].addEventListener('click', loadFiles);
    ui['generate-btn'].addEventListener('click', generate);
    ui['regenerate-btn'].addEventListener('click', generate);
    ui['publish-btn'].addEventListener('click', publish);
    ui['reject-btn'].addEventListener('click', function () {
      syncIdentity();
      if (state.request) return;
      invalidateProposal('Proposal cleared. Generate again when ready. Existing draft PRs, if any, are unchanged.');
    });
    ui.approve.addEventListener('change', function () { syncIdentity(); updateControls(); });
    ui.feedback.addEventListener('input', function () {
      syncIdentity();
      ui.approve.checked = false;
      updateControls();
    });
    ['rules', 'max-files', 'max-lines'].forEach(function (id) {
      ui[id].addEventListener('input', function () {
        if (syncIdentity()) return;
        if (id === 'rules') state.rulesDirty = true;
        invalidateProposal();
        const error = generationError();
        if (error) status(error, true);
      });
    });
    ui.consent.addEventListener('change', function () {
      if (syncIdentity()) return;
      invalidateProposal(ui.consent.checked ? 'Consent recorded for the selected scope. Ready to generate when the rules and scope are complete.' :
        'Consent withdrawn. The proposal and source contents have been cleared.');
    });
    repoInput.addEventListener('input', syncIdentity);
    repoInput.addEventListener('change', syncIdentity);
    win.addEventListener('buzz:auth-change', syncIdentity);
    win.addEventListener('storage', function (event) {
      if (!event.key || event.key === 'buzz_gh_token') syncIdentity();
    });
    win.addEventListener('focus', syncIdentity);
    win.addEventListener('pageshow', syncIdentity);
    doc.addEventListener('visibilitychange', syncIdentity);
    win.addEventListener('buzz:step-change', function (event) {
      syncIdentity();
      if (event.detail.step !== 5 && state.request) {
        const publishing = state.request.scope && state.proposal;
        cancelRequest();
        ui.approve.checked = false;
        status(publishing ? 'Request cancelled. If publishing was in progress, check GitHub before retrying.' : 'Request cancelled. You can try again when ready.');
        updateControls();
      }
    });
    win.addEventListener('pagehide', function () {
      clearRepository();
      updateControls();
    });
    syncIdentity();
  }

  return {
    normalizeRepo: normalizeRepo,
    validateScope: validateScope,
    scopeKey: scopeKey,
    safePullRequestUrl: safePullRequestUrl,
    countChangedLines: countChangedLines,
    validateListing: validateListing,
    validateProposalResponse: validateProposalResponse,
    mountRefactor: mountRefactor
  };
});
