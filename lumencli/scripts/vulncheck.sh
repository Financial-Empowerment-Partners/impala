#!/bin/sh
# =============================================================================
# vulncheck.sh — symbol-level govulncheck gate with an explicit accept list.
#
# A permanently-red vulnerability job trains everyone to ignore it, so known,
# assessed, unfixable findings are accepted HERE, each with its justification,
# and anything not on the list still fails the gate.
#
# Accepted:
#   GO-2026-4316  Open redirect in github.com/go-chi/chi's RedirectSlashes
#                 middleware. Reached only through package init of the Stellar
#                 SDK's transitive dependency — lumencli runs no HTTP server
#                 and never invokes chi middleware. No fixed v4 release exists
#                 (the fix lives in the chi/v5 module path); revisit when the
#                 SDK moves to chi/v5.
#
# Requires: go, jq, network access (the vulnerability database).
# =============================================================================
set -eu

ACCEPTED="GO-2026-4316"
GOVULNCHECK="golang.org/x/vuln/cmd/govulncheck@v1.1.4"

command -v jq >/dev/null || { echo "error: jq is required" >&2; exit 2; }

TMP="$(mktemp)"
ERR="$(mktemp)"
trap 'rm -f "$TMP" "$ERR"' EXIT

# govulncheck exits 0 when clean, 3 when it found something; anything else is
# a run failure (network, bad module) that must not read as a pass.
code=0
go run "$GOVULNCHECK" -format json ./... >"$TMP" 2>"$ERR" || code=$?
if [ "$code" != 0 ] && [ "$code" != 3 ]; then
  cat "$ERR" >&2
  echo "error: govulncheck failed to run (exit $code)" >&2
  exit "$code"
fi

# Symbol-level findings only: a finding whose innermost trace frame names a
# function is code this binary can actually reach.
ids="$(jq -r 'select(.finding != null) | .finding
              | select(.trace and .trace[0].function != null) | .osv' <"$TMP" | sort -u)"

bad=""
for id in $ids; do
  case " $ACCEPTED " in
    *" $id "*) ;;
    *) bad="$bad $id" ;;
  esac
done

if [ -n "$bad" ]; then
  echo "vulncheck: UNACCEPTED vulnerabilities:$bad" >&2
  echo "full report follows (go run $GOVULNCHECK ./...):" >&2
  go run "$GOVULNCHECK" ./... >&2 || true
  exit 1
fi

if [ -n "$ids" ]; then
  echo "vulncheck: ok — only accepted findings present:$(printf ' %s' $ids)"
else
  echo "vulncheck: ok — no reachable vulnerabilities"
fi
