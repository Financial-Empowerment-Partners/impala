#!/bin/sh
# =============================================================================
# vulncheck.sh — symbol-level govulncheck gate with an explicit accept list.
#
# A permanently-red vulnerability job trains everyone to ignore it, so known,
# assessed, unfixable findings are accepted HERE, each with its justification,
# and anything not on the list still fails the gate.
#
# An accept entry is keyed on OSV id + module path + fixed version, not on the
# OSV id alone, so it expires by itself: the moment a fixed release exists, or
# the vulnerable code arrives via a different module path, the key stops
# matching and the gate goes red again.
#
# Accepted:
#   GO-2026-4316|github.com/go-chi/chi|none
#                 Open redirect in the RedirectSlashes middleware of
#                 github.com/go-chi/chi (the pre-modules import path, required
#                 at v4.1.2+incompatible).
#                 Reachability: the sole trace is package init —
#                 lumencli/internal/stellar -> the Stellar SDK's
#                 protocols/horizon/operations -> support/render/hal ->
#                 support/http/httpdecode -> chi.init. lumencli is an
#                 outbound-only CLI: it serves no HTTP, constructs no chi
#                 router and never installs RedirectSlashes, so the vulnerable
#                 middleware cannot execute.
#                 No upgrade path: the advisory lists chi, chi/v2, chi/v3 and
#                 chi/v4 as affected from version 0 with NO fixed release; the
#                 fix exists only on the github.com/go-chi/chi/v5 module path
#                 (>= v5.2.4), which is a different module. The newest Stellar
#                 SDK (v0.7.3, checked 2026-09-08) still requires
#                 chi v4.1.2+incompatible, so upgrading the SDK does not help.
#                 Re-check trigger: the "none" in the key is the finding's
#                 fixed version — a fixed chi release, or a move to chi/v5,
#                 changes the key and fails this gate. The weekly scheduled
#                 workflow run re-evaluates it with no code change.
#
# Requires: go, jq, network access (the vulnerability database).
# =============================================================================
# -f: the accept keys below are compared after unquoted word splitting;
# disable globbing so a key is never expanded against the filesystem.
set -euf

ACCEPTED="GO-2026-4316|github.com/go-chi/chi|none"
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
# function is code this binary can actually reach. Each is reduced to the
# accept key "<osv>|<module>|<fixed version, or none>".
keys="$(jq -r 'select(.finding != null) | .finding
              | select(.trace and .trace[0].function != null)
              | [.osv, .trace[0].module, (.fixed_version // "none")]
              | join("|")' <"$TMP" | sort -u)"

bad=""
for key in $keys; do
  case " $ACCEPTED " in
    *" $key "*) ;;
    *) bad="$bad $key" ;;
  esac
done

if [ -n "$bad" ]; then
  echo "vulncheck: UNACCEPTED vulnerabilities:$bad" >&2
  echo "full report follows (go run $GOVULNCHECK ./...):" >&2
  go run "$GOVULNCHECK" ./... >&2 || true
  exit 1
fi

if [ -n "$keys" ]; then
  echo "vulncheck: ok — only accepted findings present:$(printf ' %s' $keys)"
else
  echo "vulncheck: ok — no reachable vulnerabilities"
fi
