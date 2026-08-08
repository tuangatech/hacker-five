#!/usr/bin/env bash
# Signs up two unrelated crAPI accounts and exports their auth tokens as
# CRAPI_OWNER_TOKEN / CRAPI_OTHER_TOKEN, so the Phase 1a IDOR integration
# test (and manual `hackerfive scan` runs) don't require a manual signup
# step against a freshly-provisioned crAPI instance.
#
# Usage: source this script (not execute it) so the exports land in your
# shell:
#   source tests/integration/scripts/crapi_setup.sh
set -euo pipefail

: "${CRAPI_BASE_URL:=http://localhost:8888}"

signup_and_login() {
	local role="$1"
	local email="hackerfive-${role}-$$@example.com"
	local password="Passw0rd!"

	curl -sf -X POST "${CRAPI_BASE_URL}/identity/api/auth/signup" \
		-H "Content-Type: application/json" \
		-d "{\"name\":\"HackerFive ${role}\",\"email\":\"${email}\",\"number\":\"1234567890\",\"password\":\"${password}\"}" \
		>/dev/null

	curl -sf -X POST "${CRAPI_BASE_URL}/identity/api/auth/login" \
		-H "Content-Type: application/json" \
		-d "{\"email\":\"${email}\",\"password\":\"${password}\"}" \
		| jq -r '.token'
}

export CRAPI_OWNER_TOKEN
CRAPI_OWNER_TOKEN="$(signup_and_login owner)"
export CRAPI_OTHER_TOKEN
CRAPI_OTHER_TOKEN="$(signup_and_login other)"

echo "CRAPI_OWNER_TOKEN and CRAPI_OTHER_TOKEN exported." >&2
