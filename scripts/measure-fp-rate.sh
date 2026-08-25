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
fi

if [ -n "${DVWA_BASE_URL:-}" ]; then
	measure "DVWA" "tests/fixtures/expected-findings/dvwa.json" \
		scan -t "$DVWA_BASE_URL" --detector misconfig --templates "$TEMPLATES_DIR"
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
