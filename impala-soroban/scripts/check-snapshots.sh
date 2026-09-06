#!/usr/bin/env bash
# Snapshot orphan check for impala-soroban/integration-test.
#
# `Env::default()` tests rewrite test_snapshots/<module>/<test>.N.json on
# every run, but nothing deletes the snapshot of a test that was renamed or
# removed. An orphan is a snapshot whose test function no longer exists in
# integration-test/src/*.rs.
#
# Usage: scripts/check-snapshots.sh [--delete]
#   exit 0  no orphans (or all orphans deleted with --delete)
#   exit 1  orphans found (listed on stderr)
#   exit 2  usage / layout error
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/.." && pwd)"
crate="$root/integration-test"
snapdir="$crate/test_snapshots"

delete=0
case "${1:-}" in
  "") ;;
  --delete) delete=1 ;;
  *) echo "usage: $0 [--delete]" >&2; exit 2 ;;
esac

if [[ ! -d "$crate/src" ]]; then
  echo "error: $crate/src not found" >&2
  exit 2
fi
if [[ ! -d "$snapdir" ]]; then
  echo "ok: no snapshot directory at $snapdir"
  exit 0
fi

orphans=()
while IFS= read -r -d '' f; do
  base="$(basename "$f")"
  # strip any `.N.json` suffix (also plain `.json`)
  name="$(printf '%s' "$base" | sed -E 's/\.[0-9]+\.json$//; s/\.json$//')"
  if ! grep -qE "fn ${name}\(" "$crate"/src/*.rs; then
    orphans+=("$f")
  fi
done < <(find "$snapdir" -type f -name '*.json' -print0 | sort -z)

if (( ${#orphans[@]} == 0 )); then
  echo "ok: no orphan snapshots under $snapdir"
  exit 0
fi

for f in "${orphans[@]}"; do
  if (( delete )); then
    rm -f -- "$f"
    echo "deleted orphan: ${f#"$root/"}"
  else
    echo "orphan snapshot: ${f#"$root/"}" >&2
  fi
done

if (( delete )); then
  # prune now-empty directories
  find "$snapdir" -type d -empty -delete 2>/dev/null || true
  exit 0
fi
echo "error: ${#orphans[@]} orphan snapshot(s); run $0 --delete to remove" >&2
exit 1
