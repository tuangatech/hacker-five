#!/usr/bin/env bash
# Sparse-checks out the pinned nuclei-templates commit's 7 curated http/
# category directories into .nuclei-templates-cache/ (gitignored) — never
# committed to this repo. See docs/10-implementation-plan-ph1b.md Step 2's
# "Pinning, explicitly" note. http/vulnerabilities (full dir, not just
# generic/) added 2026-09-03 alongside http/cves, http/exposures, and
# http/default-logins — see docs/15-implementation-plan-ph6.md's Step 2
# addendum: cves/ measured at 72.3% real load-success against this
# project's own template validator before adding; exposures/ is the
# category covering leaked AWS/GCP/Azure/GitHub/etc. credentials and
# config files (http/exposures/tokens/, /configs/, /files/) — a wholly
# separate, unsupported "cloud:" protocol directory (cloud/aws, cloud/gcp,
# ...) was considered and rejected: it shells out to cloud-provider CLIs
# via a `code:` block, which this project's loader rejects outright, and
# needs cloud IAM credentials as an input this project has no concept of.
#
# Re-run explicitly (make templates-sync) whenever COMMIT below is bumped —
# never automatically on HEAD, so an upstream compromise between pins can't
# silently reach a scan run.
set -euo pipefail

# Pinned via `git ls-remote https://github.com/projectdiscovery/nuclei-templates.git HEAD`
# on 2026-08-24, per CLAUDE.md's "search for current versions, don't guess" rule.
# Re-pin (bump this and re-run `make templates-sync`) whenever the curated
# categories need refreshing — never automatically, see the note above.
COMMIT="0aa256a344d5b53648575163c61517ac67f57961"

REPO="https://github.com/projectdiscovery/nuclei-templates.git"
CACHE_DIR=".nuclei-templates-cache"
CATEGORIES=("http/exposed-panels" "http/misconfiguration" "http/technologies" "http/vulnerabilities" "http/cves" "http/exposures" "http/default-logins")

if [ "$COMMIT" = "REPLACE_WITH_PINNED_COMMIT_SHA" ]; then
	echo "error: COMMIT is still the placeholder — pin a real commit SHA first (see comment above)." >&2
	exit 1
fi

rm -rf "$CACHE_DIR"
mkdir -p "$CACHE_DIR"

git clone --filter=blob:none --no-checkout "$REPO" "$CACHE_DIR"
cd "$CACHE_DIR"
git sparse-checkout init --cone
git sparse-checkout set "${CATEGORIES[@]}"
git checkout "$COMMIT"

echo "Synced nuclei-templates @ $COMMIT into $CACHE_DIR:"
for category in "${CATEGORIES[@]}"; do
	count=$(find "$category" -name '*.yaml' -o -name '*.yml' | wc -l)
	echo "  $category: $count templates"
done
