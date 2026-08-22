#!/usr/bin/env bash
# Signs up two unrelated crAPI accounts and exports their auth tokens as
# CRAPI_OWNER_TOKEN / CRAPI_OTHER_TOKEN, so the Phase 1a IDOR integration
# test (and manual `hackerfive scan` runs) don't require a manual signup
# step against a freshly-provisioned crAPI instance.
#
# Usage: source this script (not execute it) so the exports land in your
# shell:
#   source tests/integration/scripts/crapi_setup.sh
#
# Deliberately does NOT use `set -e`: sourcing applies shell options to the
# CURRENT shell, not a subshell, so `set -e` here would kill your actual
# login shell (not just this script) the moment any curl call failed —
# e.g. because crAPI's identity service hadn't finished starting yet.
# Errors are instead handled explicitly via crapi_setup_fail below, which
# `return`s (sourced) or `exit`s (executed directly) as appropriate.
set -uo pipefail

(return 0 2>/dev/null) && crapi_setup_sourced=1 || crapi_setup_sourced=0

crapi_setup_fail() {
	echo "crapi_setup.sh: $*" >&2
	if [ "$crapi_setup_sourced" = 1 ]; then
		return 1
	else
		exit 1
	fi
}

: "${CRAPI_BASE_URL:=http://localhost:8888}"

signup_and_login() {
	local role="$1"
	local email="hackerfive-${role}-$$@example.com"
	local password="Passw0rd!"

	curl -sf -X POST "${CRAPI_BASE_URL}/identity/api/auth/signup" \
		-H "Content-Type: application/json" \
		-d "{\"name\":\"HackerFive ${role}\",\"email\":\"${email}\",\"number\":\"1234567890\",\"password\":\"${password}\"}" \
		>/dev/null \
		|| { echo "signup failed for the ${role} account — is crAPI up at ${CRAPI_BASE_URL}? (check: docker compose ps, wait for crapi-identity to be healthy)" >&2; return 1; }

	local token
	token=$(curl -sf -X POST "${CRAPI_BASE_URL}/identity/api/auth/login" \
		-H "Content-Type: application/json" \
		-d "{\"email\":\"${email}\",\"password\":\"${password}\"}" \
		| jq -r '.token') \
		|| { echo "login failed for the ${role} account right after signup — is crAPI healthy?" >&2; return 1; }

	if [ -z "$token" ] || [ "$token" = "null" ]; then
		echo "login for the ${role} account returned no token — crAPI may still be starting up" >&2
		return 1
	fi

	printf '%s' "$token"
}

CRAPI_OWNER_TOKEN=$(signup_and_login owner) || crapi_setup_fail "could not create/log in the owner account"
CRAPI_OTHER_TOKEN=$(signup_and_login other) || crapi_setup_fail "could not create/log in the other account"
export CRAPI_OWNER_TOKEN CRAPI_OTHER_TOKEN

echo "CRAPI_OWNER_TOKEN and CRAPI_OTHER_TOKEN exported." >&2
