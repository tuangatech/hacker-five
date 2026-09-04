package recon

import "testing"

func TestWordPressPluginFacts_ExtractsSlugAndVersionFromCrawledURL(t *testing.T) {
	endpoints := []EndpointFact{
		{URL: "https://example.com/wp-content/plugins/contact-form-7/includes/js/scripts.js?ver=5.7.1", Method: "GET", StatusCode: 200, Source: "wave3-crawl"},
	}

	facts := wordPressPluginFacts(endpoints)

	if len(facts) != 1 {
		t.Fatalf("got %d facts, want 1: %+v", len(facts), facts)
	}
	if facts[0].Name != "contact-form-7:5.7.1" {
		t.Fatalf("got Name=%q, want %q", facts[0].Name, "contact-form-7:5.7.1")
	}
	if facts[0].Host != "example.com" {
		t.Fatalf("got Host=%q, want %q", facts[0].Host, "example.com")
	}
	if facts[0].Source != "recon-wp-plugin-path" {
		t.Fatalf("got Source=%q, want %q", facts[0].Source, "recon-wp-plugin-path")
	}
}

func TestWordPressPluginFacts_NoVersionParam_StillProducesUnversionedFact(t *testing.T) {
	endpoints := []EndpointFact{
		{URL: "https://example.com/wp-content/plugins/elementor/style.css", Method: "GET", StatusCode: 200, Source: "wave3-crawl"},
	}

	facts := wordPressPluginFacts(endpoints)

	if len(facts) != 1 || facts[0].Name != "elementor" {
		t.Fatalf("got %+v, want one unversioned %q fact", facts, "elementor")
	}
}

func TestWordPressPluginFacts_DedupesSameSlugKeepsFirstVersion(t *testing.T) {
	endpoints := []EndpointFact{
		{URL: "https://example.com/wp-content/plugins/woocommerce/assets/js/frontend/cart.js?ver=8.1.0", Method: "GET", StatusCode: 200, Source: "wave3-crawl"},
		{URL: "https://example.com/wp-content/plugins/woocommerce/assets/css/woocommerce.css?ver=8.1.0", Method: "GET", StatusCode: 200, Source: "wave3-crawl"},
		{URL: "https://example.com/wp-content/plugins/woocommerce/assets/js/checkout.js", Method: "GET", StatusCode: 200, Source: "wave3-crawl"}, // no ?ver= — must not blank out the version already found
	}

	facts := wordPressPluginFacts(endpoints)

	if len(facts) != 1 {
		t.Fatalf("got %d facts, want exactly 1 deduped woocommerce fact: %+v", len(facts), facts)
	}
	if facts[0].Name != "woocommerce:8.1.0" {
		t.Fatalf("got Name=%q, want %q", facts[0].Name, "woocommerce:8.1.0")
	}
}

func TestWordPressPluginFacts_DifferentHosts_ProduceSeparateFacts(t *testing.T) {
	endpoints := []EndpointFact{
		{URL: "https://a.example.com/wp-content/plugins/yoast-seo/style.css?ver=20.1", Method: "GET", StatusCode: 200, Source: "wave3-crawl"},
		{URL: "https://b.example.com/wp-content/plugins/yoast-seo/style.css?ver=19.0", Method: "GET", StatusCode: 200, Source: "wave3-crawl"},
	}

	facts := wordPressPluginFacts(endpoints)

	if len(facts) != 2 {
		t.Fatalf("got %d facts, want 2 (same slug, different hosts): %+v", len(facts), facts)
	}
}

func TestWordPressPluginFacts_NonPluginPath_Ignored(t *testing.T) {
	endpoints := []EndpointFact{
		{URL: "https://example.com/about-us", Method: "GET", StatusCode: 200, Source: "wave3-crawl"},
		{URL: "https://example.com/wp-includes/js/jquery/jquery.js?ver=3.6.0", Method: "GET", StatusCode: 200, Source: "wave3-crawl"}, // wp-includes, not wp-content/plugins|themes
	}

	facts := wordPressPluginFacts(endpoints)

	if len(facts) != 0 {
		t.Fatalf("got %d facts, want 0: %+v", len(facts), facts)
	}
}

func TestWordPressPluginFacts_ThemePath_AlsoExtracted(t *testing.T) {
	endpoints := []EndpointFact{
		{URL: "https://example.com/wp-content/themes/astra/style.css?ver=4.6.5", Method: "GET", StatusCode: 200, Source: "wave3-crawl"},
	}

	facts := wordPressPluginFacts(endpoints)

	if len(facts) != 1 || facts[0].Name != "astra:4.6.5" {
		t.Fatalf("got %+v, want one %q fact", facts, "astra:4.6.5")
	}
}
