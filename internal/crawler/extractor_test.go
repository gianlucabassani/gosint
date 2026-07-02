package crawler

import "testing"

func TestExtractEmails_DropsHashLocalParts(t *testing.T) {
	// 32-hex local part = MD5-style tracking/cache-buster noise → must be dropped.
	text := "reach real@company.io — ignore 5d41402abc4b2a76b9719d911017c592@tracking.io"
	got := ExtractEmails(text)
	if len(got) != 1 || got[0] != "real@company.io" {
		t.Fatalf("expected only real@company.io, got %v", got)
	}
}

func TestExtractEmails_ExcludesAssetsAndKnownDomains(t *testing.T) {
	text := "asset logo@banner.png junk foo@example.com keep hi@keepme.dev"
	got := ExtractEmails(text)
	if len(got) != 1 || got[0] != "hi@keepme.dev" {
		t.Fatalf("expected only hi@keepme.dev, got %v", got)
	}
}
