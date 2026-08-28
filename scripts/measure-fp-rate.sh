#!/usr/bin/env bash
# Runs a real scan against every live target whose env var is set, diffs each
# finding's ID against a hand-curated expected-ID-prefix list (built from
# this project's own live-verified results — see
# tests/fixtures/expected-findings/*.json), and reports a false-positive
# rate per target and overall. This is a measurement tool for a human to
# review, not a pass/fail gate — an "unexpected" finding might be a real new
# bug the fixture hasn't caught up to yet, not necessarily a false positive.
#
# Opt-in per target, same convention as the integration tests: set
# CRAPI_BASE_URL/CRAPI_OWNER_TOKEN/CRAPI_OTHER_TOKEN, DVWA_BASE_URL,
# JUICESHOP_BASE_URL, and/or VAPI_BASE_URL for whichever targets are up; a
# target with no env var set is skipped, not failed. See
# docs/20-setup-testing-targets.md for bringing each one up.
#
# Optional, finer-grained additions (each opt-in on its own, skipped if
# unset rather than failing the whole run):
#   DVWA_COOKIE          - a PHPSESSID value from a logged-in, Security:Low
#                           DVWA session, so the xss/sqli templates' real
#                           session-gated targets actually get exercised
#                           instead of hitting a 302 login redirect.
#   VAPI_OWNER_TOKEN/VAPI_OTHER_TOKEN - two vAPI accounts' api1 credentials,
#                           pre-encoded as base64(username:password), to
#                           also measure the authbypass detector against
#                           vAPI (not just misconfig).
set -euo pipefail

cd "$(dirname "$0")/.."

command -v jq >/dev/null || { echo "error: jq is required (see docs/20-setup-testing-targets.md's crAPI section, which already depends on it)" >&2; exit 1; }

TEMPLATES_DIR="./templates/"
if [ -d ".nuclei-templates-cache" ]; then
	TEMPLATES_DIR=".nuclei-templates-cache"
fi

echo "Building ./hackerfive..."
go build -o hackerfive ./cmd/hackerfive

total_findings=0
total_unexpected=0

# measure runs one scan and reports its FP rate against expected_file.
measure() {
	local name="$1" expected_file="$2"
	shift 2
	local scan_args=("$@")

	echo
	echo "=== $name ==="
	local output
	output=$(./hackerfive "${scan_args[@]}" 2>/dev/null || echo "[]")

	# jq, not grep/sed: findings' own Evidence maps commonly carry their own
	# nested "id" key (e.g. idor's Evidence["id"] is the bare candidate ID,
	# "1"/"2"/...) which a naive '"id": *"[^"]*"' text match would also pick
	# up alongside the real top-level Finding.ID — found live, see doc10 Step 4.
	local ids
	ids=$(echo "$output" | jq -r '.[].id')
	local count unexpected=0
	count=$(echo "$ids" | grep -c . || true)

	local prefixes
	prefixes=$(jq -r '.expected_id_prefixes[]' "$expected_file")

	while IFS= read -r id; do
		[ -z "$id" ] && continue
		local matched=0
		while IFS= read -r prefix; do
			[ -z "$prefix" ] && continue
			case "$id" in
			"$prefix"*) matched=1 ;;
			esac
		done <<<"$prefixes"
		if [ "$matched" -eq 0 ]; then
			unexpected=$((unexpected + 1))
			echo "  unexpected: $id"
		fi
	done <<<"$ids"

	echo "  $name: $count findings, $unexpected unexpected (candidate FPs)"
	total_findings=$((total_findings + count))
	total_unexpected=$((total_unexpected + unexpected))
}

ran_any=0

if [ -n "${CRAPI_BASE_URL:-}" ] && [ -n "${CRAPI_OWNER_TOKEN:-}" ] && [ -n "${CRAPI_OTHER_TOKEN:-}" ]; then
	measure "crAPI" "tests/fixtures/expected-findings/crapi.json" \
		scan -t "$CRAPI_BASE_URL" --detector idor \
		--endpoint '/workshop/api/mechanic/mechanic_report?report_id={{id}}' \
		--auth-token "$CRAPI_OWNER_TOKEN" --other-auth-token "$CRAPI_OTHER_TOKEN" \
		--templates "$TEMPLATES_DIR"
	ran_any=1

	# Same two accounts, authbypass's own lens — protected-paths list is the
	# real OpenAPI-spec-driven set docs/11-implementation-plan-ph2.md Step 5
	# and docs/20-setup-testing-targets.md's crAPI section live-verified
	# (2026-08-28): 2 identity endpoints plus 8 more spanning community/
	# workshop, confirmed to trigger real alg:none/token-reuse/missing-auth
	# findings, not guessed paths.
	measure "crAPI (authbypass)" "tests/fixtures/expected-findings/crapi-authbypass.json" \
		scan -t "$CRAPI_BASE_URL" --detector authbypass \
		--auth-token "$CRAPI_OWNER_TOKEN" --other-auth-token "$CRAPI_OTHER_TOKEN" \
		--login-paths '/identity/api/auth/login' \
		--protected-paths '/identity/api/v2/user/dashboard,/identity/api/v2/vehicle/vehicles,/identity/api/v2/user/videos/convert_video,/community/api/v2/community/posts/recent,/workshop/api/shop/products,/workshop/api/shop/orders/all,/workshop/api/management/users/all,/workshop/api/mechanic/,/workshop/api/mechanic/service_requests,/workshop/api/shop/return_qr_code'
	ran_any=1
fi

if [ -n "${DVWA_BASE_URL:-}" ]; then
	dvwa_header=()
	if [ -n "${DVWA_COOKIE:-}" ]; then
		# Without a cookie, DVWA's own auth gate hides the xss/sqli templates'
		# real targets behind a 302 login redirect — measuring FP rate without
		# it would silently skip exercising them at all, not prove they're
		# clean. See docs/20-setup-testing-targets.md's DVWA section for how
		# to obtain one (log in, set Security: Low, read PHPSESSID).
		dvwa_header=(--header "Cookie: ${DVWA_COOKIE}; security=low")
	fi
	measure "DVWA" "tests/fixtures/expected-findings/dvwa.json" \
		scan -t "$DVWA_BASE_URL" --detector misconfig --templates "$TEMPLATES_DIR" "${dvwa_header[@]}"
	ran_any=1
fi

if [ -n "${JUICESHOP_BASE_URL:-}" ]; then
	measure "Juice Shop" "tests/fixtures/expected-findings/juiceshop.json" \
		scan -t "$JUICESHOP_BASE_URL" --detector misconfig --templates "$TEMPLATES_DIR"
	ran_any=1
fi

if [ -n "${VAPI_BASE_URL:-}" ]; then
	# Deliberately NOT $TEMPLATES_DIR: vAPI's dev-mode Laravel server can't
	# handle the full synced corpus (~2,500 templates) in reasonable time —
	# a live run still hadn't finished after 20 minutes, vs. ~140s for DVWA/
	# Juice Shop. Real, observed constraint of this target, not the engine —
	# see docs/20-setup-testing-targets.md's vAPI section and
	# tests/integration/vapi_auth_test.go's same fix.
	measure "vAPI" "tests/fixtures/expected-findings/vapi.json" \
		scan -t "$VAPI_BASE_URL" --detector misconfig --templates ./templates/
	ran_any=1

	# vAPI's api1 module uses a custom Authorization-Token: base64(username:password)
	# header, not a session token — VAPI_OWNER_TOKEN/VAPI_OTHER_TOKEN are
	# expected pre-encoded that way (see docs/20-setup-testing-targets.md's
	# vAPI section for how to sign up two accounts and build these).
	# jwt/user (JustWeakTokenController) needs a different token shape
	# entirely (a real JWT from its own /vapi/jwt/user registration) so it's
	# deliberately not included here — measuring it would need a third,
	# incompatible --auth-header-name/--auth-token pair mid-scan, which this
	# script's single-scan-per-target shape can't express.
	if [ -n "${VAPI_OWNER_TOKEN:-}" ] && [ -n "${VAPI_OTHER_TOKEN:-}" ]; then
		measure "vAPI (authbypass)" "tests/fixtures/expected-findings/vapi-authbypass.json" \
			scan -t "$VAPI_BASE_URL" --detector authbypass \
			--auth-token "$VAPI_OWNER_TOKEN" --other-auth-token "$VAPI_OTHER_TOKEN" \
			--auth-header-name 'Authorization-Token' --auth-header-format '{token}' \
			--protected-paths '/vapi/api1/user/5,/vapi/api1/user/6'
	fi
fi

if [ "$ran_any" -eq 0 ]; then
	echo "No target env vars set (CRAPI_BASE_URL+tokens, DVWA_BASE_URL, JUICESHOP_BASE_URL, VAPI_BASE_URL) — nothing to measure."
	echo "See docs/20-setup-testing-targets.md for bringing targets up."
	exit 0
fi

echo
echo "=== Overall ==="
if [ "$total_findings" -eq 0 ]; then
	echo "0 findings across all targets run."
else
	python3 -c "print(f'{$total_unexpected}/{$total_findings} unexpected ({100*$total_unexpected/$total_findings:.1f}% candidate FP rate)')" 2>/dev/null \
		|| echo "$total_unexpected/$total_findings unexpected"
fi
