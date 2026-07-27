# Issue tracker: GitHub

Issues and PRDs for this repo live as GitHub issues. Use the `gh` CLI for all operations.

## Conventions

- Create an issue: `gh issue create --title "..." --body "..."`.
- Read an issue: `gh issue view <number> --comments`.
- List issues: `gh issue list --state open --json number,title,body,labels,comments --jq '[.[] | {number, title, body, labels: [.labels[].name], comments: [.comments[].body]}]'`.
- Comment: `gh issue comment <number> --body "..."`.
- Apply / remove labels: `gh issue edit <number> --add-label "..."` / `--remove-label "..."`.
- Close: `gh issue close <number> --comment "..."`.

Infer the repo from `git remote -v` — `gh` does this automatically.

## Pull requests

PRs share the same number space as issues.
Resolve with `gh pr view <number>` then fall back to `gh issue view <number>`.
