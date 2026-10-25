# Markdown-Driven Refactoring Agent

## Plan in one paragraph

Add Auto-Refactor to Buzz's existing web app, reusing GitHub login and the repository picker. Customers edit Markdown guidance, select a small scope, generate a language-aware proposal, and review or revise the code before opening a draft pull request. The server enforces scope independently of the model; existing repository CI validates published changes, while the optional local runner can execute approved checks before review. Web proposals are explicitly unverified until checks actually run. The goal is clearer code with preserved behavior—not a fixed complexity score, new login flow, or automatic merging.

## Feature breakdown

1. **Existing repo selection** — Reuse Buzz's Supabase GitHub session and repo picker. Load eligible source files from a pinned commit; no separate setup or credentials.
2. **Editable Markdown rules** — `.refactor/RULES.md` describes what to improve, what to preserve, and local exceptions. Customers can reuse shared guidance and tailor it per repository.
3. **Refactoring agent** — Inspect relevant code, callers, and tests; propose one coherent improvement. Explain which rule it follows and the trade-off introduced. Preserve public behavior and skip changes that offer no clear benefit.
4. **Enforced scope controls** — The runner restricts allowed paths and changed files/lines in an isolated workspace. Limits are customer-configurable, not quality targets. Stop when a change needs more scope; never weaken tests or safeguards to fit.
5. **Verification and evidence** — Web proposals are labeled unverified; draft PRs go through the repo's existing CI. No arbitrary builds execute in a Vercel function. The local runner supports baseline/candidate checks. Neither path invents complexity scores or claims proof of equivalent behavior.
6. **Customer review and feedback** — Show original/proposed code and rationale in Buzz. Customers can edit, reject, or regenerate with feedback; explicit approval creates a draft PR containing those exact edits. The server revalidates scope and base revision before publishing, using only the connected user's token.

## First-version boundary

One integrated web flow and one candidate at a time, with an optional standalone local runner. Prove scope/validation behavior on multiple languages. Publish only on new branches, preserve customer edits, and require normal review/checks before merging. Defer automatic merging, repository-wide rewrites, and hosted execution of untrusted code.

**Success:** a customer can steer a useful refactor, understand its trade-offs, and review its evidence; the runner blocks out-of-scope changes and leaves unverifiable changes unmerged.
