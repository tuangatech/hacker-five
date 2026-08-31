#!/usr/bin/env bash
# Signs up two unrelated crAPI accounts and exports their auth tokens as
# CRAPI_OWNER_TOKEN / CRAPI_OTHER_TOKEN, so the Phase 1a IDOR integration
# test (and manual `hackerfive scan` runs) don't require a manual signup
# step against a freshly-provisioned crAPI instance. Also exports the
# accounts' emails/password (CRAPI_OWNER_EMAIL/CRAPI_OTHER_EMAIL/
# CRAPI_PASSWORD) so you can log into crAPI's own web UI as either account,
# e.g. to submit a "Contact Mechanic" report for the IDOR scan to find.
#
# Usage: source this script (not execute it) so the exports land in your
# shell:
#   source tests/integration/scripts/crapi_setup.sh
#
# Deliberately does NOT use `set -e`: sourcing applies shell options to the
# CURRENT shell, not a subshell, so `set -e` here would kill your actual
# login shell (not just this script) the moment any curl call failed —
# e.g. because crAPI's identity service hadn't finished starting yet.
# Failures are instead handled explicitly below: `return 1` stops just this
# script when sourced (the normal/documented usage); `2>/dev/null || exit 1`
# is the fallback for the unsupported case of running it directly.
set -uo pipefail

: "${CRAPI_BASE_URL:=http://localhost:8888}"
CRAPI_PASSWORD="Passw0rd!"

# Prints the account's email on the first line and its auth token on the
# second — command substitution runs in a subshell, so this is how values
# get back to the sourcing shell instead of via (subshell-local) variable
# assignment inside the function.
signup_and_login() {
	local role="$1"
	# Fixed and memorable on purpose — these are throwaway @example.com
	# accounts on your own local container, nothing confidential about them.
	# Signup failing here is NOT treated as fatal: it just means this email
	# already has an account from an earlier run against a database that
	# was never wiped, in which case login below with the same fixed
	# password still succeeds against that existing account. This makes
	# re-running the script idempotent instead of erroring on a collision.
	local email="hackerfive-${role}@example.com"
	# crAPI enforces unique phone numbers per account too, but the number
	# itself is never used again after signup (unlike the email, nothing
	# references it later) — so it stays random rather than fixed, to avoid
	# a 403 "Number already registered" on signup when the account doesn't
	# actually already exist. $RANDOM is reseeded fresh per shell/script
	# invocation and read twice below, so owner/other calls still differ.
	local number
	number=$(printf '%010d' $(( (RANDOM * 100000 + RANDOM) % 10000000000 )))

	curl -sf -X POST "${CRAPI_BASE_URL}/identity/api/auth/signup" \
		-H "Content-Type: application/json" \
		-d "{\"name\":\"HackerFive ${role}\",\"email\":\"${email}\",\"number\":\"${number}\",\"password\":\"${CRAPI_PASSWORD}\"}" \
		>/dev/null 2>&1 || true   # failure here just means the account already exists — login below is the real check

	# crAPI's identity service has a real eventual-consistency race: signup
	# can return 200 before the account is actually visible to login, which
	# then 401s with "Given Email is not registered!" for a moment. Retry a
	# few times with a short backoff instead of treating the first failure
	# as fatal.
	local token attempt
	for attempt in 1 2 3 4 5; do
		token=$(curl -s -X POST "${CRAPI_BASE_URL}/identity/api/auth/login" \
			-H "Content-Type: application/json" \
			-d "{\"email\":\"${email}\",\"password\":\"${CRAPI_PASSWORD}\"}" \
			| jq -r '.token')
		[ -n "$token" ] && [ "$token" != "null" ] && break
		sleep 1
	done

	if [ -z "$token" ] || [ "$token" = "null" ]; then
		echo "login for the ${role} account returned no token after ${attempt} attempts — crAPI may still be starting up" >&2
		return 1
	fi

	printf '%s\n%s' "$email" "$token"
}

owner_out=$(signup_and_login owner) || { echo "crapi_setup.sh: aborting — could not create/log in the owner account" >&2; return 1 2>/dev/null || exit 1; }
CRAPI_OWNER_EMAIL=$(printf '%s' "$owner_out" | head -n1)
CRAPI_OWNER_TOKEN=$(printf '%s' "$owner_out" | tail -n1)

other_out=$(signup_and_login other) || { echo "crapi_setup.sh: aborting — could not create/log in the other account" >&2; return 1 2>/dev/null || exit 1; }
CRAPI_OTHER_EMAIL=$(printf '%s' "$other_out" | head -n1)
CRAPI_OTHER_TOKEN=$(printf '%s' "$other_out" | tail -n1)

export CRAPI_OWNER_TOKEN CRAPI_OTHER_TOKEN CRAPI_OWNER_EMAIL CRAPI_OTHER_EMAIL CRAPI_PASSWORD

echo "CRAPI_OWNER_TOKEN and CRAPI_OTHER_TOKEN exported." >&2
echo "Web UI login (${CRAPI_BASE_URL}) — owner: ${CRAPI_OWNER_EMAIL} / other: ${CRAPI_OTHER_EMAIL} / password: ${CRAPI_PASSWORD}" >&2
