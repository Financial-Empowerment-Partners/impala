#!/usr/bin/env bash
# Prepare .env (generated secrets), the build contexts and the demo keys. Idempotent. Never modifies the
# source trees: the bridge is built from ../impala-bridge (its .dockerignore excludes target/), the UI
# assets are copied world-readable, the Payala stub's seed is rendered from the ids in .env and the demo keys.
set -euo pipefail
umask 022
. "$(dirname "$0")/lib.sh"
require_cmd git tar openssl jq curl od

# ---------------------------------------------------------------- .env first (secrets), then load it
if [ ! -f "$DEMO_DIR/.env" ]; then
  info "creating .env from .env.example with generated secrets"
  ( umask 077; sed \
    -e "s|^JWT_SECRET=.*|JWT_SECRET=$(openssl rand -hex 32)|" \
    -e "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=$(openssl rand -hex 16)|" \
    -e "s|^REDIS_PASSWORD=.*|REDIS_PASSWORD=$(openssl rand -hex 16)|" \
    -e "s|^IMPALA_ADMIN_PASSWORD=.*|IMPALA_ADMIN_PASSWORD=$(openssl rand -hex 12)|" \
    -e "s|^IMPALA_AGENT_PASSWORD=.*|IMPALA_AGENT_PASSWORD=$(openssl rand -hex 12)|" \
    -e "s|^IMPALA_BENEFICIARY_PASSWORD=.*|IMPALA_BENEFICIARY_PASSWORD=$(openssl rand -hex 12)|" \
    -e "s|^IMPALA_HOLDER_PASSWORD=.*|IMPALA_HOLDER_PASSWORD=$(openssl rand -hex 12)|" \
    -e "s|^IMPALA_ISSUE_KMK=.*|IMPALA_ISSUE_KMK=$(openssl rand -hex 16)|" \
    "$DEMO_DIR/.env.example" > "$DEMO_DIR/.env" )
else
  ok ".env exists (kept)"
fi
load_env
require_env JWT_SECRET POSTGRES_PASSWORD REDIS_PASSWORD IMPALA_ISSUE_KMK
[ "${#JWT_SECRET}" -ge 32 ] || die "JWT_SECRET must be at least 32 characters"
[ -d "$REPO_DIR/impala-bridge/src" ] || die "$REPO_DIR/impala-bridge/src not found: run from a checkout of the impala monorepo"

# Persist the detected engine so compose.yaml and every script agree from now on.
if [ -z "${CONTAINER_ENGINE:-}" ]; then
  det="$(detect_engine)"
  if [ -n "$det" ]; then
    sed -e "s|^CONTAINER_ENGINE=.*|CONTAINER_ENGINE=$det|" "$DEMO_DIR/.env" > "$DEMO_DIR/.env.tmp" && mv "$DEMO_DIR/.env.tmp" "$DEMO_DIR/.env" && chmod 600 "$DEMO_DIR/.env"
    export CONTAINER_ENGINE="$det"
    # shellcheck disable=SC2034  # ENGINE is read by lib.sh's compose/engine helpers
    ENGINE="$det"
    ok "container engine: $det (auto-detected, written to .env)"
  else
    warn "no container engine reachable yet; CONTAINER_ENGINE stays empty (auto-detect at run time)"
  fi
else
  ok "container engine: $CONTAINER_ENGINE"
fi
if stack_running 2>/dev/null; then
  warn "the stack is running: build/ is replaced under live bind mounts; run scripts/up.sh afterwards so nginx sees the new files"
fi
mkdir -p "$BUILD_DIR" "$STATE_DIR/keys" "$RECORDS_DIR" "$ARTIFACTS_DIR"

# ---------------------------------------------------------------- impala-bridge Containerfile (generated from the repo Dockerfile)
# Podman needs fully qualified FROM lines and no BuildKit syntax directive; the digest pins are kept
# verbatim, so the image is the repo's image. Regenerated on every run: it cannot drift from the source.
info "generating build/impala-bridge.Containerfile from impala-bridge/Dockerfile"
sed \
  -e '/^# syntax=/d' \
  -e 's#^FROM rust:#FROM docker.io/library/rust:#' \
  -e 's#^FROM debian:#FROM docker.io/library/debian:#' \
  "$REPO_DIR/impala-bridge/Dockerfile" > "$BUILD_DIR/impala-bridge.Containerfile"
grep -q '^FROM docker.io/library/rust:.*@sha256:' "$BUILD_DIR/impala-bridge.Containerfile" || die "Containerfile rewrite failed (no pinned rust FROM line)"
grep -q '^FROM docker.io/library/debian:.*@sha256:' "$BUILD_DIR/impala-bridge.Containerfile" || die "Containerfile rewrite failed (no pinned debian FROM line)"
[ -f "$REPO_DIR/impala-bridge/.dockerignore" ] && grep -q '^target/' "$REPO_DIR/impala-bridge/.dockerignore" || die "impala-bridge/.dockerignore must exclude target/ (the build context is the source tree)"
git -C "$REPO_DIR" rev-parse HEAD > "$BUILD_DIR/impala-bridge.source-commit" 2>/dev/null || printf 'unknown\n' > "$BUILD_DIR/impala-bridge.source-commit"

# ---------------------------------------------------------------- impala-ui assets (world-readable copies; config.js overridden to testnet only)
info "staging impala-ui assets -> build/impala-ui"
rm -rf "$BUILD_DIR/impala-ui"; mkdir -p "$BUILD_DIR/impala-ui"
cp -R "$REPO_DIR/impala-ui/html" "$BUILD_DIR/impala-ui/html"
cp "$REPO_DIR/impala-ui/nginx.conf" "$BUILD_DIR/impala-ui/nginx.conf"
cp "$DEMO_DIR/config/impala-ui/config.js" "$BUILD_DIR/impala-ui/html/config.js"

# ---------------------------------------------------------------- demo P-256 card signing keys for the Payala stub's users (an Order's sender_public_key must equal the seeded card key)
for r in mint admin agent beneficiary sync holder; do
  if [ ! -f "$STATE_DIR/keys/$r.pem" ]; then
    ( umask 077; openssl ecparam -name prime256v1 -genkey -noout -out "$STATE_DIR/keys/$r.pem" )
  fi
  # raw 64-byte X||Y = the last 64 bytes of the DER SubjectPublicKeyInfo (LibreSSL and OpenSSL 3)
  openssl ec -in "$STATE_DIR/keys/$r.pem" -pubout -outform DER 2>/dev/null | tail -c 64 | bin_to_hex > "$STATE_DIR/keys/$r.pub.hex"
  [ "$(wc -c < "$STATE_DIR/keys/$r.pub.hex" | tr -d ' ')" = "128" ] || die "unexpected public key length for $r"
done
ok "demo keys: state/keys (6 P-256 keys)"

# ---------------------------------------------------------------- Payala stub seed (ids from .env + the card keys above; read once by the payala-stub container)
# The proprietary Payala API is not part of the demo: payala-stub/server.mjs seeds these six users (balances in
# cents, the mint holds 1 000 000 000) on its first start and never resets an existing user. The card id is the
# user id with its first digit replaced by 2 (the ids of .env.example give 2000…000N).
require_env PAYALA_MINT_ID PAYALA_ADMIN_ID PAYALA_AGENT_ID PAYALA_BENEFICIARY_ID PAYALA_SYNC_ID DEMO_HOLDER_ID
rm -rf "$BUILD_DIR/payala-api" "$BUILD_DIR/initdb"   # build contexts of the kit's earlier Payala profile, if any
mkdir -p "$BUILD_DIR/payala-stub"
seed_user() { # <id> <role> <given> <family> <phone> <balance_cents> <key role>
  jq -cn --arg id "$1" --arg role "$2" --arg g "$3" --arg f "$4" --arg p "$5" --argjson b "$6" --arg k "$(cat "$STATE_DIR/keys/$7.pub.hex")" \
    '{id:$id, role:$role, given_name:$g, family_name:$f, phone_nr:$p, balance:$b, currency:"USD", card:{id:($id|sub("^.";"2")), signing_public_key_hex:$k}}'
}
{
  seed_user "$PAYALA_MINT_ID"        admin Payala  Mint        +15550100001 1000000000 mint
  seed_user "$PAYALA_ADMIN_ID"       admin Demo    Admin       +15550100002 0 admin
  seed_user "$PAYALA_AGENT_ID"       agent Ada     Agent       +15550100003 0 agent
  seed_user "$PAYALA_BENEFICIARY_ID" user  Ben     Beneficiary +15550100004 0 beneficiary
  seed_user "$PAYALA_SYNC_ID"        sync  Stellar Bridge      +15550100005 0 sync
  seed_user "$DEMO_HOLDER_ID"        user  Cara    Holder      +15550100006 0 holder
} | jq -s '{users: .}' > "$BUILD_DIR/payala-stub/seed.json.tmp" && mv "$BUILD_DIR/payala-stub/seed.json.tmp" "$BUILD_DIR/payala-stub/seed.json"
[ "$(jq '.users|length' "$BUILD_DIR/payala-stub/seed.json")" = 6 ] || die "payala stub seed: expected 6 users"
[ "$(jq '[.users[].card.id]|unique|length' "$BUILD_DIR/payala-stub/seed.json")" = 6 ] || die "payala stub seed: card ids collide (user ids must differ beyond their first character)"
ok "payala stub seed: build/payala-stub/seed.json (6 users with cards; the mint holds 1 000 000 000 cents)"

# ---------------------------------------------------------------- permissions (host umask may be 027; containers read as uid 70/101)
chmod -R a+rX "$BUILD_DIR" "$DEMO_DIR/config" "$DEMO_DIR/payala-stub"
chmod 755 "$DEMO_DIR"/scripts/*.sh "$DEMO_DIR"/scripts/payala/*.sh 2>/dev/null || true
chmod 600 "$DEMO_DIR/.env" "$STATE_DIR"/keys/*.pem

ok "prepared:"
log "  build/impala-bridge.Containerfile   (repo Dockerfile, podman-safe; source $(cut -c1-7 "$BUILD_DIR/impala-bridge.source-commit"))"
log "  build/impala-ui                     (assets + testnet-only config.js)"
log "  .env                                (engine ${CONTAINER_ENGINE:-auto}; secrets generated once)"
log "next: scripts/build.sh"
