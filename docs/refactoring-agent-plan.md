# Auto-Refactor Web Flow

## Scope

Use Buzz's existing GitHub login and repository picker. Customers supply optional Markdown instructions in the wizard, generate a refactor, review the proposed code, and open a draft pull request.

## Implementation

- The wizard calls the Rust `/api/refactor` endpoint.
- Rust fetches the selected repository files and calls Gemini with the source and Markdown guidance.
- The wizard displays the original and proposed code for review.
- Rust creates a branch and draft PR containing the reviewed changes through GitHub's API.
- Repository `.refactor/RULES.md` guidance can load into the wizard; editing it is optional.

## Boundaries

No standalone CLI, Python runner, or separate login flow. The current service calls Gemini directly; it is not a persistent local agent worker. Repository builds and tests do not run inside the Vercel function, so proposals remain unverified until the repository's normal CI runs. No automatic merging.
