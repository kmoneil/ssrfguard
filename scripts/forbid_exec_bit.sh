#!/usr/bin/env bash
# Reject files recorded as executable in the git INDEX.
#
# Index-based, not filesystem-based, on purpose. A `test -x` check reports whatever the working
# tree happens to say, which on some mounts is "everything is executable" -- a hook that fails on
# every file is a hook people learn to skip. Git's index mode is the thing that actually gets
# committed, and it is what a reviewer on another machine will see.
#
# **The allowlist is empty and should stay empty.** This distribution is a library: a wheel of
# `.py` files, a `py.typed` marker and a licence. Nothing in it is exec'd, so nothing in it needs
# the bit, and an executable file arriving in the index is therefore a mistake rather than a
# feature -- a stray `chmod` from a local experiment, or something that was never meant to ship.
# Add an entry only if a file genuinely has to be executable in the distribution, and say why.
set -euo pipefail

ALLOWED=()

mapfile -t executables < <(git ls-files --stage | awk '$1 == "100755" { print $4 }')

violations=()
for file in "${executables[@]:-}"; do
  [[ -z "$file" ]] && continue
  allowed=false
  for permitted in "${ALLOWED[@]:-}"; do
    if [[ "$file" == "$permitted" ]]; then
      allowed=true
      break
    fi
  done
  if [[ "$allowed" == false ]]; then
    violations+=("$file")
  fi
done

if ((${#violations[@]} > 0)); then
  echo "error: files are marked executable in the git index:" >&2
  printf '  %s\n' "${violations[@]}" >&2
  echo >&2
  echo "Fix with:  git update-index --chmod=-x <file>" >&2
  echo "If a file genuinely needs the bit, add it to ALLOWED in $0." >&2
  exit 1
fi
