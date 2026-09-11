package recon

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/scanner/scope"
)

// --- extractJSEndpoints -----------------------------------------------

func TestExtractJSEndpoints_PlantedRouteFound(t *testing.T) {
	body := `fetch("/api/v2/internal/reports")`
	got := extractJSEndpoints("https://target.example/static/app.js", body)
	assert.Contains(t, got, "https://target.example/api/v2/internal/reports")
}

func TestExtractJSEndpoints_AbsoluteURLFound(t *testing.T) {
	body := `const u = "https://target.example/api/v2/admin/users";`
	got := extractJSEndpoints("https://target.example/static/app.js", body)
	assert.Contains(t, got, "https://target.example/api/v2/admin/users")
}

// TestExtractJSEndpoints_DecoysRejected guards the false-positive side of
// LT-85/IsNonRouteAssetPath reuse: none of these common minified-JS quoted
// strings should ever become an endpoint candidate.
func TestExtractJSEndpoints_DecoysRejected(t *testing.T) {
	decoys := []string{
		`"/"`,                          // bare root, not interesting
		`"//"`,                         // protocol-relative junk
		`"/static/logo.png"`,           // static asset
		`"/node_modules/foo/index.js"`, // dependency tree
		`"/library/ideabox/'+e.query"`, // LT-85 JS-syntax fragment
		`"application/json"`,           // MIME type, not a path
		`'MM/DD/YYYY'`,                 // date-format string, no leading slash
	}
	for _, d := range decoys {
		got := extractJSEndpoints("https://target.example/static/app.js", d)
		assert.Empty(t, got, "decoy %q must not be extracted as an endpoint", d)
	}
}

func TestExtractJSEndpoints_DedupedWithinOneAsset(t *testing.T) {
	body := `a("/api/foo"); b("/api/foo");`
	got := extractJSEndpoints("https://target.example/app.js", body)
	assert.Len(t, got, 1)
}

// --- extractJSSecrets ---------------------------------------------------

func TestExtractJSSecrets_AWSAccessKey(t *testing.T) {
	body := `const key = "AKIAABCDEFGHIJKLMNOP";`
	got := extractJSSecrets("https://target.example/app.js", body)
	require.Len(t, got, 1)
	assert.Equal(t, "aws-access-key", got[0].Kind)
	assert.Equal(t, "high", got[0].Severity)
	assert.NotContains(t, got[0].Redacted, "ABCDEFGHIJKLMNOP", "the real secret value must never appear unredacted")
	assert.Equal(t, 1, got[0].Line)
}

func TestExtractJSSecrets_GoogleAPIKey(t *testing.T) {
	// Split across concatenation so no contiguous token-shaped literal sits
	// in the source (GitHub secret scanning flags the shape on sight, even
	// for an obviously-fake fixture value never used against a real API).
	fakeKey := "AIzaSyD-9tSrke72PouQMnMX" + "-a7eZSW0jkFMBWY"
	body := `apiKey: "` + fakeKey + `"`
	got := extractJSSecrets("https://target.example/app.js", body)
	require.Len(t, got, 1)
	assert.Equal(t, "google-api-key", got[0].Kind)
}

func TestExtractJSSecrets_SlackToken(t *testing.T) {
	// Split across concatenation so no contiguous token-shaped literal sits
	// in the source (GitHub push protection flags the shape on sight, even
	// for an obviously-fake fixture value).
	fakeToken := "xoxb-1234567890-" + "abcdefghijklmnop"
	body := `token: "` + fakeToken + `"`
	got := extractJSSecrets("https://target.example/app.js", body)
	require.Len(t, got, 1)
	assert.Equal(t, "slack-token", got[0].Kind)
}

func TestExtractJSSecrets_GitHubToken(t *testing.T) {
	body := `const t = "ghp_1234567890abcdefghijklmnopqrstuvwxyz";` // 36 chars after ghp_
	got := extractJSSecrets("https://target.example/app.js", body)
	require.Len(t, got, 1)
	assert.Equal(t, "github-token", got[0].Kind)
	assert.Equal(t, "critical", got[0].Severity)
}

func TestExtractJSSecrets_PrivateKeyHeader(t *testing.T) {
	body := "-----BEGIN RSA PRIVATE KEY-----\nMIIC...\n-----END RSA PRIVATE KEY-----"
	got := extractJSSecrets("https://target.example/config.js", body)
	require.Len(t, got, 1)
	assert.Equal(t, "private-key", got[0].Kind)
}

func TestExtractJSSecrets_LineNumberTracksNewlines(t *testing.T) {
	body := "line one\nline two\nconst key = \"AKIAABCDEFGHIJKLMNOP\";\n"
	got := extractJSSecrets("https://target.example/app.js", body)
	require.Len(t, got, 1)
	assert.Equal(t, 3, got[0].Line)
}

func TestExtractJSSecrets_BearerToken_HighEntropyAccepted(t *testing.T) {
	body := `headers: {"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.aZ9kLp3mQwErTyUiOpAsDfGh"}`
	got := extractJSSecrets("https://target.example/app.js", body)
	require.Len(t, got, 1)
	assert.Equal(t, "hardcoded-bearer-token", got[0].Kind)
}

// TestExtractJSSecrets_DecoysRejected covers the FP-reduction machinery
// (placeholder-word screen + entropy floor) for the one shape-only pattern —
// the four vendor-prefixed patterns need no such screen (see the patterns'
// own doc comment).
func TestExtractJSSecrets_DecoysRejected(t *testing.T) {
	decoys := []string{
		`Authorization: "Bearer YOUR_TOKEN_HERE_PLEASE_REPLACE"`, // placeholder marker
		`Authorization: "Bearer aaaaaaaaaaaaaaaaaaaaaaaa"`,       // low entropy
		`const example = "just a normal string of some length"`,  // no pattern at all
		`aki_but_not_aws_key_shaped_string_here_1234567890`,      // near-miss, not a real prefix match
	}
	for _, d := range decoys {
		got := extractJSSecrets("https://target.example/app.js", d)
		assert.Empty(t, got, "decoy %q must not be reported as a secret", d)
	}
}

func TestRedactSecret_NeverExposesFullValue(t *testing.T) {
	r := redactSecret("AKIAABCDEFGHIJKLMNOP")
	assert.NotEqual(t, "AKIAABCDEFGHIJKLMNOP", r)
	assert.True(t, strings.HasPrefix(r, "AKIA"))
	assert.True(t, strings.HasSuffix(r, "MNOP"))
}

// --- extractCloudBucketRefs ---------------------------------------------

func TestExtractCloudBucketRefs_S3HostStyle(t *testing.T) {
	refs := extractCloudBucketRefs(`img src="https://my-app-uploads.s3.amazonaws.com/logo.png"`)
	require.Len(t, refs, 1)
	assert.Equal(t, "s3", refs[0].kind)
	assert.Equal(t, "https://my-app-uploads.s3.amazonaws.com/", refs[0].url)
}

func TestExtractCloudBucketRefs_S3PathStyle(t *testing.T) {
	refs := extractCloudBucketRefs(`"https://s3.amazonaws.com/my-app-uploads/logo.png"`)
	require.Len(t, refs, 1)
	assert.Equal(t, "s3", refs[0].kind)
	assert.Equal(t, "https://s3.amazonaws.com/my-app-uploads/", refs[0].url)
}

func TestExtractCloudBucketRefs_GCSHostStyle(t *testing.T) {
	refs := extractCloudBucketRefs(`"https://my-gcs-bucket.storage.googleapis.com/file.pdf"`)
	require.Len(t, refs, 1)
	assert.Equal(t, "gcp", refs[0].kind)
}

func TestExtractCloudBucketRefs_NoBucket_Empty(t *testing.T) {
	refs := extractCloudBucketRefs(`just some ordinary JS with no cloud references at all`)
	assert.Empty(t, refs)
}

func TestExtractCloudBucketRefs_DedupedWithinOneCall(t *testing.T) {
	text := `"https://bucket.s3.amazonaws.com/a" "https://bucket.s3.amazonaws.com/b"`
	refs := extractCloudBucketRefs(text)
	assert.Len(t, refs, 1)
}

// --- end-to-end: runJSStaticAnalysis via a full recon Run ----------------

// TestRunWave3_JSStaticAnalysis_EndpointsSecretsAndCloudFact exercises the
// whole Phase 8 Step 3 pass through a real recon.Run: katana's own JSONL
// output already carries the fetched .js body (no -omit-body flag is
// passed), and this recon run must turn it into an endpoint candidate, a
// redacted secret fact, and an actionable "s3" TechFact — all without any
// extra request beyond the one katana already made.
func TestRunWave3_JSStaticAnalysis_EndpointsSecretsAndCloudFact(t *testing.T) {
	jsBody := `fetch("/api/v2/internal/reports");` +
		`const key = "AKIAABCDEFGHIJKLMNOP";` +
		`const bucket = "https://my-app-uploads.s3.amazonaws.com/asset.png";`
	jsBodyJSON, err := json.Marshal(jsBody)
	require.NoError(t, err)

	target := "https://target.example"
	responses := map[string]string{
		"katana": `{"request":{"endpoint":"` + target + `/static/app.js","method":"GET"},` +
			`"response":{"status_code":200,"headers":{"content-type":"application/javascript"},"body":` + string(jsBodyJSON) + `}}`,
	}
	_, fake := recordingRun(t, responses)

	r := New(newTestClient(), withRun(fake))
	result, err := r.Run(context.Background(), target, DepthFull)
	require.NoError(t, err)

	require.Len(t, result.Secrets, 1)
	assert.Equal(t, "aws-access-key", result.Secrets[0].Kind)
	assert.NotContains(t, result.Secrets[0].Redacted, "ABCDEFGHIJKLMNOP")

	foundJSStaticEndpoint := false
	foundBucketEndpoint := false
	for _, ep := range result.Endpoints {
		if ep.Source == "js-static" && ep.URL == target+"/api/v2/internal/reports" {
			foundJSStaticEndpoint = true
		}
		if ep.Source == "js-static-cloud" && ep.URL == "https://my-app-uploads.s3.amazonaws.com/" {
			foundBucketEndpoint = true
		}
	}
	assert.True(t, foundJSStaticEndpoint, "expected a js-static EndpointFact from the fetch() call, got: %+v", result.Endpoints)
	assert.True(t, foundBucketEndpoint, "expected a js-static-cloud EndpointFact for the discovered bucket, got: %+v", result.Endpoints)

	foundCloudTech := false
	for _, tf := range result.TechStack {
		if tf.Name == "s3" {
			foundCloudTech = true
			assert.Equal(t, "my-app-uploads.s3.amazonaws.com", tf.Host, "the cloud TechFact must attach to the bucket's own host — the corpus's bucket-exposure templates need to run against the bucket itself")
		}
	}
	assert.True(t, foundCloudTech, "expected an 's3' TechFact from the bucket reference, got: %+v", result.TechStack)

	// The whole result, secrets and all, must still satisfy the frozen schema.
	schema := compileReconSchema(t)
	raw, err := json.Marshal(result)
	require.NoError(t, err)
	var asAny any
	require.NoError(t, json.Unmarshal(raw, &asAny))
	assert.NoError(t, schema.Validate(asAny), "ReconResult with secrets must satisfy docs/schema/recon-result.schema.json: %s", raw)
}

// TestRunWave3_JSStaticAnalysis_OutOfScopeBucket_NotDispatched guards the
// scope boundary: a bucket URL mentioned in JS never becomes a scannable
// EndpointFact or a dispatchable TechFact unless it independently clears
// --scope — a page can reference any third party's bucket, so a mention
// alone must never earn a scan or a fact about anything.
func TestRunWave3_JSStaticAnalysis_OutOfScopeBucket_NotDispatched(t *testing.T) {
	jsBody := `const bucket = "https://someones-bucket.s3.amazonaws.com/asset.png";`
	jsBodyJSON, err := json.Marshal(jsBody)
	require.NoError(t, err)

	target := "https://target.example"
	responses := map[string]string{
		"katana": `{"request":{"endpoint":"` + target + `/static/app.js","method":"GET"},` +
			`"response":{"status_code":200,"body":` + string(jsBodyJSON) + `}}`,
	}
	_, fake := recordingRun(t, responses)

	s, err := scope.New([]string{"target.example"}) // the bucket host is NOT in scope
	require.NoError(t, err)
	r := New(newTestClient(), withRun(fake), WithScope(s))
	result, err := r.Run(context.Background(), target, DepthFull)
	require.NoError(t, err)

	for _, ep := range result.Endpoints {
		assert.NotContains(t, ep.URL, "someones-bucket", "an out-of-scope bucket must never become a dispatchable endpoint")
	}
	assert.Contains(t, result.OutOfScope, "someones-bucket.s3.amazonaws.com")

	for _, tf := range result.TechStack {
		assert.NotEqual(t, "s3", tf.Name, "an out-of-scope bucket mention must never produce a dispatchable TechFact")
	}
}

// TestRunWave3_JSStaticAnalysis_OutOfScopeAbsoluteEndpoint_NotDispatched is
// LT-144's regression guard (docs/follow-up.md): extractJSEndpoints's
// absolute-URL branch only checks path *shape*, so a page can carry an
// absolute URL on an unrelated third-party domain (live-observed: an
// "xmlns=\"http://www.w3.org/1999/xhtml\"" namespace declaration, not a
// link) and that host must clear --scope exactly like a cloud-bucket
// reference already does, rather than becoming a real js-static
// EndpointFact that registry.Resolve can turn into a dispatchable leaf
// against a host nobody authorized.
func TestRunWave3_JSStaticAnalysis_OutOfScopeAbsoluteEndpoint_NotDispatched(t *testing.T) {
	jsBody := `const u = "https://evil.example/api/v2/admin/users";`
	jsBodyJSON, err := json.Marshal(jsBody)
	require.NoError(t, err)

	target := "https://target.example"
	responses := map[string]string{
		"katana": `{"request":{"endpoint":"` + target + `/static/app.js","method":"GET"},` +
			`"response":{"status_code":200,"body":` + string(jsBodyJSON) + `}}`,
	}
	_, fake := recordingRun(t, responses)

	s, err := scope.New([]string{"target.example"}) // evil.example is NOT in scope
	require.NoError(t, err)
	r := New(newTestClient(), withRun(fake), WithScope(s))
	result, err := r.Run(context.Background(), target, DepthFull)
	require.NoError(t, err)

	for _, ep := range result.Endpoints {
		assert.NotContains(t, ep.URL, "evil.example", "an out-of-scope absolute endpoint must never become a dispatchable EndpointFact")
	}
	assert.Contains(t, result.OutOfScope, "evil.example")
}
