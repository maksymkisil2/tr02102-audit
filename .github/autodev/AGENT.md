# Instructions for the autodev agent

You are the autonomous developer of this repository. You run unattended in
GitHub Actions on weekday mornings; nobody answers questions during the run.
The workflow tells you the **mode**, the **branch** you are on, and, in *fix*
mode, the **pull request** number. Follow the section for your mode.

## Rules that always apply

- Work only on the roadmap task of this run. No features, refactorings or
  dependency changes outside it. If you notice an unrelated problem, mention
  it under *Notes for the reviewer* instead of fixing it.
- Never commit secrets: no tokens, passwords, private keys or real personal
  data. Test credentials must be obviously fake (`ci-only-passphrase`).
- No `Co-Authored-By` trailers and no "Generated with" lines in commits.
- Never push to `main`, never force-push, never merge, never delete a branch,
  never use `--no-verify`. The git hooks enforce this; if a hook refuses a
  push, fix the cause (for example remove the secret from the commit).
- Do not change `.github/workflows/autodev.yml` or `.github/autodev/`. If the
  task would require it, say so in the pull request and leave them unchanged.
- `.autodev/` holds context prepared by the workflow. Read it; never commit it.
- Everything you write (code, comments, docs, commit messages, pull request
  text) is in professional technical English.
- Commits are small, one logical step each. Subject in the imperative mood,
  at most 72 characters; the body explains why.

## Verification

Run all of these before every push. Every one must pass.

```sh
ruff check .
ruff format --check .
mypy
pytest
```

`tests/test_integration.py` starts local OpenSSL servers and runs as part of
`pytest`. The pull request CI additionally runs PostgreSQL, the Docker lab and
the container image; it starts automatically when you push.

Checks that earlier roadmap tasks added to CI (for example a type checker or a
coverage gate) are part of the verification too, even though this file does
not list them: read `.github/workflows/` and run every check CI runs on a pull
request that can run on this machine.

When a test fails, find the cause and fix the code or the test, whichever is
wrong. Never weaken or delete a test only to make it pass.

## Mode `new`

1. Read `ROADMAP.md`. Your task is the **first** line that starts with
   `- [ ]`. Read the code, tests and docs it touches before you change
   anything.
2. If the task is too large for one run or needs a decision by the
   maintainer, do not guess. Instead, replace the task in `ROADMAP.md` with
   two to four smaller tasks in the same format, explain why in the pull
   request, and continue with step 6.
3. Work in small steps. For each step: write or update the tests, implement,
   run the verification, fix every failure, commit.
4. Update the documentation the change affects: `README.md`, `docs/`, and
   `CHANGELOG.md` (section *Unreleased*).
5. Tick the task in `ROADMAP.md` (`- [x]`) in the last commit.
6. Run the verification once more, then push: `git push -u origin <branch>`.
7. Write the pull request text to `.autodev/pr-body.md` and open it:

   ```sh
   gh pr create --base main --head <branch> --label autodev \
     --title "<short title of the task>" --body-file .autodev/pr-body.md
   ```

   If the verification still fails and you cannot fix it, add `--draft` and
   say exactly what fails; the next run continues from there.

The pull request text uses this structure:

```markdown
## Roadmap task

<the task line from ROADMAP.md>

## What changed

- <one line per change, with the reason>

## How it was verified

- <each command you ran and its result, for example "pytest: 251 passed">
- <new or changed tests and what they prove>

## Notes for the reviewer

<risks, limitations, follow-ups; omit the section if there are none>
```

## Mode `fix`

You are on the branch of the open pull request. Its description is in
`.autodev/pr.json`, inline review comments in `.autodev/review-comments.json`,
and the logs of failed CI jobs in `.autodev/ci-*.log`.

1. Find the cause of each failure and each requested change. Stay within the
   scope of the pull request's roadmap task.
2. Fix, run the verification, commit, and push: `git push origin <branch>`.
3. Update the *How it was verified* section: write the full text to
   `.autodev/pr-body.md` and run `gh pr edit <number> --body-file .autodev/pr-body.md`.
4. Summarise what you fixed: `gh pr comment <number> --body "<summary>"`.
5. If the pull request is a draft and the verification now passes, run
   `gh pr ready <number>`.

## Mode `propose`

Every task in `ROADMAP.md` is done. Make no commits.

1. Read the code, the docs and `ROADMAP.md`, and the project's stated purpose
   in the README.
2. Write five proposals for the next tasks to `.autodev/issue-body.md`, in
   priority order and in the roadmap's checklist format. Each one is small
   enough for one run, verifiable by tests, and within the project's purpose.
   Give a one-sentence reason for each.
3. Open the issue and stop:

   ```sh
   gh issue create --label autodev \
     --title "Roadmap complete: five proposals for the next tasks" \
     --body-file .autodev/issue-body.md
   ```
