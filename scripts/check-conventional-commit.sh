#!/usr/bin/env bash
# Enforce Conventional Commits format
# https://www.conventionalcommits.org/en/v1.0.0/

commit_msg_file="$1"
commit_msg=$(head -1 "$commit_msg_file")

# Allow merge commits
if echo "$commit_msg" | grep -qE '^Merge '; then
  exit 0
fi

# Conventional Commits pattern: type(optional scope): description
pattern='^(feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert)(\(.+\))?(!)?: .+'

if ! echo "$commit_msg" | grep -qE "$pattern"; then
  echo "ERROR: Commit message does not follow Conventional Commits format."
  echo ""
  echo "  Expected: <type>[optional scope]: <description>"
  echo ""
  echo "  Types: feat, fix, docs, style, refactor, perf, test, build, ci, chore, revert"
  echo ""
  echo "  Examples:"
  echo "    feat: add menu bar widget"
  echo "    fix(parser): handle empty input"
  echo "    docs: update README"
  echo "    chore!: drop support for macOS 13"
  echo ""
  echo "  Got: $commit_msg"
  exit 1
fi
